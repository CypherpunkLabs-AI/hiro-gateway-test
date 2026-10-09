//! Fetch and verify public evidence. This command never initializes application
//! configuration, a database, inference credentials, or a dstack key client.
use super::snapshot::{Authority, MAX_DOCUMENT, Metadata, Validity, atomic_write};
use anyhow::{Context, ensure};
use reqwest::{Client, Url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

pub struct Config {
    pub socket: PathBuf,
    pub output: PathBuf,
    pub state: PathBuf,
    pub trust: PathBuf,
    pub roots: PathBuf,
    pub release_base: Url,
    pub policy: Url,
    pub kms: Url,
    pub pccs: String,
}

fn required(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .with_context(|| format!("{name} is required"))
}

fn https(value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "evidence source must be HTTPS without credentials or fragments"
    );
    Ok(url)
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let release_base = https(&required("HIRO_RELEASE_BASE_URL")?)?;
        ensure!(
            release_base.path().ends_with('/') && release_base.query().is_none(),
            "release base URL must end with / and have no query"
        );
        Ok(Self {
            socket: required("HIRO_EVIDENCE_SOCKET")?.into(),
            output: required("HIRO_OAK_EVIDENCE_PATH")?.into(),
            state: required("HIRO_EVIDENCE_STATE_DIR")?.into(),
            trust: required("HIRO_TRUST_CONFIG_PATH")?.into(),
            roots: required("HIRO_SIGSTORE_ROOTS_PATH")?.into(),
            release_base,
            policy: https(&required("HIRO_POLICY_URL")?)?,
            kms: https(&required("HIRO_KMS_EVIDENCE_URL")?)?,
            pccs: https(&required("HIRO_PCCS_URL")?)?.to_string(),
        })
    }
}

async fn bytes(response: reqwest::Response, max: usize) -> anyhow::Result<Vec<u8>> {
    let mut response = response
        .error_for_status()
        .context("evidence source returned an error")?;
    ensure!(
        response.content_length().is_none_or(|n| n <= max as u64),
        "response exceeds limit"
    );
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            data.len().saturating_add(chunk.len()) <= max,
            "response exceeds limit"
        );
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

async fn fetch(client: &Client, url: Url) -> anyhow::Result<Value> {
    let response = client.get(url).send().await?;
    Ok(serde_json::from_slice(
        &bytes(response, MAX_DOCUMENT).await?,
    )?)
}

/// Adapt the existing HTTP library to QVL's transport trait, with the same
/// response-size, HTTPS, no-redirect and timeout limits as artifact retrieval.
struct CollateralHttp(Client);
impl dcap_qvl::http::HttpClient for CollateralHttp {
    async fn get(&self, url: &str) -> anyhow::Result<dcap_qvl::http::HttpResponse> {
        let response = self.0.get(https(url)?).send().await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| Ok((k.to_string(), v.to_str()?.to_owned())))
            .collect::<anyhow::Result<_>>()?;
        Ok(dcap_qvl::http::HttpResponse {
            status,
            headers,
            body: bytes(response, MAX_DOCUMENT).await?,
        })
    }
}

pub async fn local_report(client: &Client, nonce: &str) -> anyhow::Result<Value> {
    let response = client
        .get("http://localhost/v1/report")
        .query(&[("nonce", nonce)])
        .send()
        .await?;
    Ok(serde_json::from_slice(
        &bytes(response, MAX_DOCUMENT).await?,
    )?)
}

fn quote(value: &Value) -> anyhow::Result<Vec<u8>> {
    let value = value.as_str().context("quote must be a hex string")?;
    ensure!(value.len() <= 256 * 1024, "quote exceeds limit");
    Ok(hex::decode(value.strip_prefix("0x").unwrap_or(value))?)
}

/// Foreground worker, supervised independently by Compose. Failed attempts never
/// replace evidence.json. Signed policy advances are published separately so a
/// revocation is not hidden by a later release/collateral retrieval failure.
pub async fn run(config: Config) -> anyhow::Result<()> {
    ensure!(
        config.output.is_absolute() && config.socket.is_absolute(),
        "evidence paths must be absolute"
    );
    let parent = config.output.parent().context("output has no parent")?;
    ensure!(
        parent.is_dir(),
        "provision the shared evidence directory before starting the worker"
    );
    let mut authority = Authority::open(&config.state, &config.trust, &config.roots)?;
    let network = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let local = Client::builder()
        .unix_socket(config.socket.clone())
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(25))
        .build()?;
    let mut current: Option<Validity> = None;
    let mut failures: u32 = 0;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    stop(&config)?;
    loop {
        let revision = authority.revision;
        let refresh = tokio::time::timeout(Duration::from_secs(110), async {
            let policy = fetch(&network, config.policy.clone()).await?;
            let nonce = authority.begin(&policy)?;
            atomic_write(
                &config.output.with_file_name("policy.json"),
                &serde_json::to_vec(&policy)?,
                0o644,
            )?;
            let report = local_report(&local, &nonce).await?;
            let compose = report["attestation"]["evidence"]["app_compose"]
                .as_str()
                .context("local report lacks composition")?;
            ensure!(compose.len() <= 256 * 1024, "composition exceeds limit");
            let digest = hex::encode(Sha256::digest(compose.as_bytes()));
            let release_url = config.release_base.join(&format!("{digest}.json"))?;
            let (release, mut kms) = tokio::try_join!(
                fetch(&network, release_url),
                fetch(&network, config.kms.clone())
            )?;
            let local_quote = quote(&report["attestation"]["evidence"]["quote"])?;
            let kms_quote = quote(&kms["quote"])?;
            let collateral_client = dcap_qvl::collateral::CollateralClient::<
                dcap_qvl::configs::RustCryptoConfig,
                _,
            >::new(
                CollateralHttp(network.clone()), &config.pccs
            );
            let (collateral, kms_collateral) = tokio::try_join!(
                collateral_client.fetch(&local_quote),
                collateral_client.fetch(&kms_quote)
            )?;
            kms.as_object_mut()
                .context("KMS evidence must be an object")?
                .insert("collateral".into(), serde_json::to_value(kms_collateral)?);
            let metadata = Metadata {
                schema: 1,
                collateral: serde_json::to_value(collateral)?,
                release,
                policy,
                kms,
            };
            // Fetching collateral can exceed a short challenge lifetime. Start a
            // new challenge and obtain a fresh report immediately before appraisal.
            let nonce = authority.begin(&metadata.policy)?;
            let report = local_report(&local, &nonce).await?;
            ensure!(
                report["attestation"]["evidence"]["app_compose"]
                    .as_str()
                    .map(|v| hex::encode(Sha256::digest(v.as_bytes())))
                    == Some(digest),
                "composition changed during collection"
            );
            let validity = authority.verify(&metadata.with_report(report)?)?;
            ensure!(validity.is_current(), "evidence expired before publication");
            atomic_write(&config.output, &serde_json::to_vec(&metadata)?, 0o644)?;
            Ok::<_, anyhow::Error>(validity)
        });
        let result = tokio::select! {
            result = refresh => result,
            _ = terminate.recv() => return stop(&config),
            _ = tokio::signal::ctrl_c() => return stop(&config),
        };
        let delay = match result {
            Ok(Ok(validity)) => {
                let delay = (validity.remaining() / 3)
                    .min(Duration::from_secs(30))
                    .max(Duration::from_millis(100));
                current = Some(validity);
                failures = 0;
                tracing::info!("verified supporting evidence published");
                delay
            }
            _ => {
                if authority.revision != revision {
                    current = None;
                }
                failures = failures.saturating_add(1);
                // Bounded exponential backoff with jitter; no evidence/key/URL payloads in logs.
                let mut random = [0u8; 1];
                getrandom::getrandom(&mut random)?;
                tracing::warn!(
                    failures,
                    "evidence refresh failed; previous snapshot was not overwritten"
                );
                Duration::from_millis((1u64 << failures.min(5)) * 1000 + u64::from(random[0]) * 4)
            }
        };
        let status = json!({"schema":1, "ready": current.as_ref().is_some_and(Validity::is_current),
            "expires_at":current.as_ref().map_or(0, |v| v.expires), "updated_at":super::evidence::now_secs()});
        atomic_write(
            &config.state.join("status.json"),
            &serde_json::to_vec(&status)?,
            0o600,
        )?;
        let sleep =
            tokio::time::sleep_until(tokio::time::Instant::from_std(Instant::now() + delay));
        tokio::select! {
            () = sleep => {},
            _ = terminate.recv() => return stop(&config),
            _ = tokio::signal::ctrl_c() => return stop(&config),
        }
    }
}

fn stop(config: &Config) -> anyhow::Result<()> {
    atomic_write(
        &config.state.join("status.json"),
        br#"{"schema":1,"ready":false,"expires_at":0,"updated_at":0}"#,
        0o600,
    )
}

/// Container health check. Status is operational only, never attestation authority.
pub fn health() -> anyhow::Result<()> {
    let path = PathBuf::from(required("HIRO_EVIDENCE_STATE_DIR")?).join("status.json");
    let status: Value = serde_json::from_slice(&super::snapshot::read_bounded(&path, 4096)?)?;
    let now = super::evidence::now_secs();
    let updated = status["updated_at"]
        .as_u64()
        .context("invalid worker status")?;
    ensure!(
        status["schema"] == 1
            && status["ready"] == true
            && status["expires_at"]
                .as_u64()
                .is_some_and(|expiry| now < expiry)
            && updated <= now
            && now - updated <= 150,
        "evidence worker is not ready"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_sources_cannot_select_plaintext_or_credentialed_urls() {
        for url in [
            "http://example.com/evidence",
            "file:///evidence",
            "https://user:secret@example.com/evidence",
            "https://example.com/evidence#fragment",
        ] {
            assert!(https(url).is_err());
        }
        assert!(https("https://example.com/evidence").is_ok());
    }

    #[test]
    fn rejects_unbounded_and_malformed_quotes_before_collateral_fetch() {
        assert!(quote(&json!("f".repeat(256 * 1024 + 2))).is_err());
        assert!(quote(&json!("not-hex")).is_err());
        assert!(quote(&json!({"quote":"00"})).is_err());
    }
}
