//! Public evidence only, on a filesystem-protected Unix socket. No key operations.
use crate::services::inference::Service;
use anyhow::{Context, ensure};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::get,
};
use serde::Deserialize;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{net::UnixListener, sync::Semaphore, task::JoinHandle};

#[derive(Clone)]
struct Bootstrap {
    service: Arc<Service>,
    quotes: Arc<Semaphore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    nonce: String,
}

async fn report(
    State(state): State<Bootstrap>,
    Query(query): Query<Challenge>,
) -> Result<Json<aci_protocol::types::AttestationReport>, StatusCode> {
    if query.nonce.len() != 64
        || !query
            .nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let _permit = state
        .quotes
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    tokio::time::timeout(
        Duration::from_secs(20),
        state.service.attestation_report(Some(query.nonce)),
    )
    .await
    .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
    .map(Json)
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// Start before application dependency initialization; does not require a snapshot.
/// The parent directory must be owned/provisioned by the deployment and shared only
/// with the worker. The socket exposes no arbitrary report-data or key derivation.
/// Start the private evidence listener.
///
/// # Errors
/// Returns an error for unsafe socket paths or permissions, an active socket, or filesystem/bind failures.
#[expect(
    clippy::verbose_bit_mask,
    reason = "POSIX octal mask names the forbidden other-user permissions"
)]
pub async fn start(
    path: &Path,
    service: Arc<Service>,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    ensure!(
        path.is_absolute(),
        "bootstrap socket must be an absolute path"
    );
    let parent = path.parent().context("bootstrap socket has no parent")?;
    let parent_meta =
        std::fs::metadata(parent).context("bootstrap socket directory must be provisioned")?;
    ensure!(
        parent_meta.is_dir() && parent_meta.permissions().mode() & 0o007 == 0,
        "bootstrap directory must exclude access by other users (use 0770 or 0700)"
    );
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        ensure!(
            meta.file_type().is_socket(),
            "bootstrap path is not a socket"
        );
        ensure!(
            tokio::net::UnixStream::connect(path).await.is_err(),
            "bootstrap socket already active"
        );
        std::fs::remove_file(path).context("remove stale bootstrap socket")?;
    }
    let listener = UnixListener::bind(path).context("bind private evidence socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    let router = Router::new()
        .route("/v1/report", get(report))
        .route("/health", get(|| async { StatusCode::OK }))
        .with_state(Bootstrap {
            service,
            quotes: Arc::new(Semaphore::new(1)),
        });
    Ok(tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .context("private evidence listener failed")
    }))
}
