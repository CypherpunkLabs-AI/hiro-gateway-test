use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, bail};

#[derive(Debug, Clone)]
pub struct Config {
    pub inference: crate::inference::config::Config,
    pub auth: crate::auth::AuthConfig,
    pub bind_address: SocketAddr,
    pub tls: crate::tls::Config,
    pub tdx_report_dir: PathBuf,
    pub attestation_dir: PathBuf,
    pub phala_base_url: String,
    pub phala_api_key: String,
    pub accepted_subjects: Vec<String>,
    pub accepted_kms_root_public_keys: Vec<String>,
    pub pccs_url: Option<String>,
    pub verifier_cache_ttl: Duration,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub read_timeout: Duration,
    pub keyset_ttl: Duration,
    pub receipt_ttl: Duration,
    pub source_repository: String,
    pub source_commit: String,
    pub image_digest: Option<String>,
    pub subject: Option<String>,
}

impl Config {
    /// Loads immutable trust policy and runtime settings.
    ///
    /// Trust anchors deliberately have no defaults. A deployment cannot start
    /// until the remote Phala inference identity and its KMS root are pinned.
    /// These settings do not provision or attest the local GCP guest.
    /// # Errors
    /// Rejects invalid configuration or unavailable required confidential services.
    pub fn from_env() -> anyhow::Result<Self> {
        let bind_address = value_or("HIRO_BIND_ADDRESS", "0.0.0.0:8443")
            .parse()
            .context("HIRO_BIND_ADDRESS must be a socket address")?;
        let phala_base_url = required("PHALA_ACI_BASE_URL")?
            .trim_end_matches('/')
            .to_owned();
        if !phala_base_url.starts_with("https://") {
            bail!("PHALA_ACI_BASE_URL must use https");
        }

        let accepted_subjects = list("PHALA_ACI_ACCEPTED_SUBJECTS");
        if accepted_subjects.is_empty() {
            bail!("PHALA_ACI_ACCEPTED_SUBJECTS cannot be empty");
        }
        let accepted_kms_root_public_keys = list("PHALA_ACI_ACCEPTED_KMS_ROOT_KEYS");
        if accepted_kms_root_public_keys.is_empty() {
            bail!("PHALA_ACI_ACCEPTED_KMS_ROOT_KEYS cannot be empty");
        }

        Ok(Self {
            inference: crate::inference::config::Config::from_env()?,
            auth: crate::auth::AuthConfig::from_env()?,
            bind_address,
            tls: crate::tls::Config::new(
                required("HIRO_TLS_DOMAIN")?,
                &value_or("HIRO_ACME_ENVIRONMENT", "production"),
            )?,
            tdx_report_dir: value_or("HIRO_TDX_REPORT_DIR", "/run/hiro/tdx-report").into(),
            attestation_dir: value_or("HIRO_ATTESTATION_DIR", "/run/hiro/attestation").into(),
            phala_base_url,
            phala_api_key: required("PHALA_API_KEY")?,
            accepted_subjects,
            accepted_kms_root_public_keys,
            pccs_url: optional("PHALA_ACI_PCCS_URL"),
            verifier_cache_ttl: seconds("PHALA_ACI_VERIFIER_CACHE_SECONDS", 300, 1, 3_600)?,
            connect_timeout: seconds("PHALA_CONNECT_TIMEOUT_SECONDS", 10, 1, 60)?,
            request_timeout: seconds("PHALA_ATTESTATION_TIMEOUT_SECONDS", 20, 1, 120)?,
            read_timeout: seconds("PHALA_READ_TIMEOUT_SECONDS", 600, 10, 3_600)?,
            keyset_ttl: seconds("HIRO_KEYSET_TTL_SECONDS", 2_592_000, 3_600, 31_536_000)?,
            receipt_ttl: seconds("HIRO_RECEIPT_TTL_SECONDS", 3_600, 60, 86_400)?,
            source_repository: required("HIRO_SOURCE_REPOSITORY")?,
            source_commit: required("HIRO_SOURCE_COMMIT")?,
            image_digest: optional("HIRO_IMAGE_DIGEST"),
            subject: optional("HIRO_ATTESTED_SUBJECT"),
        })
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    optional(name).with_context(|| format!("{name} is required"))
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn value_or(name: &str, default: &str) -> String {
    optional(name).unwrap_or_else(|| default.to_owned())
}

fn list(name: &str) -> Vec<String> {
    optional(name)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn seconds(name: &str, default: u64, min: u64, max: u64) -> anyhow::Result<Duration> {
    let value = value_or(name, &default.to_string())
        .parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned integer"))?;
    if !(min..=max).contains(&value) {
        bail!("{name} must be between {min} and {max}");
    }
    Ok(Duration::from_secs(value))
}
