use std::sync::Arc;

use aci_protocol::types::SourceProvenance;
use anyhow::Context;
use axum::{Router, http::StatusCode, routing::get};
use hiro_proxy::{
    attestation::evidence::{ServiceConfig, now_secs},
    attestation::{InferenceVerifier, verify_before_listening},
    config::Config,
    inference::upstream::InferenceBackend,
    services::documents::{DocumentGateway, VisionGateway},
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
#[allow(
    clippy::too_many_lines,
    reason = "startup assembles the confidential service dependencies before listening"
)]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("TLS provider already initialized"))?;
    init_tracing();
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => {}
        [command] if command == "serve" => {}
        [command] if command == "evidence" => {
            return hiro_proxy::attestation::worker::run(
                hiro_proxy::attestation::worker::Config::from_env()?,
            )
            .await;
        }
        [command] if command == "evidence-health" => {
            return hiro_proxy::attestation::worker::health();
        }
        _ => anyhow::bail!("usage: hiro-proxy [serve|evidence|evidence-health]"),
    }
    let config = Config::from_env().context("invalid configuration")?;
    let jwt_verifier = hiro_proxy::auth::JwtVerifier::new(&config.auth)
        .context("invalid authentication configuration")?;

    let oak_keys =
        Arc::new(hiro_proxy::attestation::keys::OakKeys::new(&config.dstack_endpoint).await?);

    let verifier = Arc::new(InferenceVerifier::new(&config)?);

    let upstream = Arc::new(
        InferenceBackend::new(
            &config.phala_base_url,
            config.phala_api_key.clone(),
            config.connect_timeout.as_secs(),
            config.read_timeout.as_secs(),
        )
        .context("failed to construct Phala inference backend")?,
    );

    let service = hiro_proxy::services::inference::Service::new(
        oak_keys.clone(),
        upstream.clone(),
        verifier.clone(),
        ServiceConfig {
            source_provenance: SourceProvenance {
                repo_url: Some(config.source_repository.clone()),
                repo_commit: Some(config.source_commit.clone()),
                image_digest: config.image_digest.clone(),
                image_provenance: None,
            },
            keyset_not_after: now_secs().saturating_add(config.keyset_ttl.as_secs()),
            subject: config.subject.clone(),
            receipt_ttl_seconds: config.receipt_ttl.as_secs(),
        },
    )
    .context("failed to seal Hiro ACI service identity")?;
    let keyset_digest = service.workload_keyset_digest().to_owned();

    // Hiro's HTTP handlers are in-process only. Oak's method/path/header
    // allowlist gates every request; this router is never served on a listener.
    let service = Arc::new(service);
    // Bootstrap is independent of supporting evidence, database connectivity and
    // upstream attestation. It exposes only public challenge-bound reports.
    let socket =
        std::env::var("HIRO_EVIDENCE_SOCKET").context("HIRO_EVIDENCE_SOCKET is required")?;
    let mut bootstrap =
        hiro_proxy::attestation::bootstrap::start(std::path::Path::new(&socket), service.clone())
            .await?;
    let evidence_path =
        std::env::var("HIRO_OAK_EVIDENCE_PATH").context("HIRO_OAK_EVIDENCE_PATH is required")?;
    let state =
        std::env::var("HIRO_EVIDENCE_STATE_DIR").context("HIRO_EVIDENCE_STATE_DIR is required")?;
    let trust =
        std::env::var("HIRO_TRUST_CONFIG_PATH").context("HIRO_TRUST_CONFIG_PATH is required")?;
    let roots = std::env::var("HIRO_SIGSTORE_ROOTS_PATH")
        .context("HIRO_SIGSTORE_ROOTS_PATH is required")?;
    let authority = hiro_proxy::attestation::snapshot::Authority::open(
        std::path::Path::new(&state),
        std::path::Path::new(&trust),
        std::path::Path::new(&roots),
    )?;
    let (evidence, mut evidence_task) = hiro_proxy::attestation::gate::Gate::start(
        evidence_path.into(),
        authority,
        service.clone(),
    );
    verify_before_listening(&verifier, &config.phala_base_url).await?;
    let chat = Arc::new(
        hiro_proxy::services::chat::ChatService::new(service.clone(), config.inference.clone())
            .await?,
    );
    let mut oak_inner = hiro_proxy::api::inference::router(chat);
    if let Ok(document_url) = std::env::var("DOCUMENT_ROUTER_URL") {
        let token = std::env::var("DOCUMENT_VISION_BROKER_TOKEN")
            .context("DOCUMENT_VISION_BROKER_TOKEN is required")?;
        anyhow::ensure!(
            token.len() >= 32,
            "document vision token must have at least 32 bytes"
        );
        let model = std::env::var("DOCUMENT_VISION_MODEL")
            .context("DOCUMENT_VISION_MODEL must select a TEE vision model")?;
        anyhow::ensure!(
            !model.trim().is_empty(),
            "document vision model cannot be empty"
        );
        let bind = std::env::var("DOCUMENT_VISION_BIND").unwrap_or_else(|_| "0.0.0.0:8082".into());
        let broker_listener = TcpListener::bind(&bind)
            .await
            .context("bind private vision listener")?;
        let broker = VisionGateway {
            backend: upstream,
            verifier,
            model,
            token,
            slots: Arc::new(tokio::sync::Semaphore::new(2)),
        };
        tokio::spawn(async move {
            if let Err(error) = axum::serve(
                broker_listener,
                hiro_proxy::api::documents::vision_router(broker),
            )
            .await
            {
                tracing::error!(error = %error, "private vision listener failed");
            }
        });
        let documents = DocumentGateway::new(document_url)?;
        oak_inner = oak_inner.merge(hiro_proxy::api::documents::document_router(documents));
    }
    let oak = hiro_proxy::transport::oak::Gateway::new(
        service,
        oak_keys.binding.clone(),
        hiro_proxy::auth::protect(oak_inner, jwt_verifier),
        evidence.clone(),
    )?;
    let app = Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route(
            "/ready",
            get(move || {
                let evidence = evidence.clone();
                async move {
                    if evidence.ready().await {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }
            }),
        )
        .merge(oak.router());
    let listener = TcpListener::bind(config.bind_address)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_address))?;

    info!(
        address = %config.bind_address,
        keyset_digest,
        upstream = %config.phala_base_url,
        "Hiro Oak gateway listening"
    );
    let result = tokio::select! {
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()) => result.context("HTTP server failed"),
        result = &mut bootstrap => {
            result.context("private evidence task panicked")??;
            Err(anyhow::anyhow!("private evidence task stopped"))
        },
        result = &mut evidence_task => {
            result.context("evidence verification task panicked")?;
            Err(anyhow::anyhow!("evidence verification task stopped"))
        },
    };
    bootstrap.abort();
    evidence_task.abort();
    result
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("hiro_proxy=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .init();
}
