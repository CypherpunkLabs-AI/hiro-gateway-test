//! Explicit trust preparation using pinned upstream dstack-verifier and strict DCAP appraisal.
use anyhow::{Context, ensure};
use dstack_attest::attestation::AttestationVerifier;
use dstack_verifier::{CvmVerifier, VerificationRequest};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    id: String,
    os_image_hash: String,
    app_id: String,
    compose_sha256: String,
    #[serde(default)]
    allow_smt: bool,
    #[serde(default)]
    allow_dynamic_platform: bool,
    #[serde(default)]
    allow_cached_keys: bool,
    #[serde(default)]
    kms: Option<ExpectedKms>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedKms {
    id: String,
    endpoint: String,
    root_public_key: String,
    ca_public_key_sha256: String,
}

fn field(value: &Value, name: &str) -> anyhow::Result<String> {
    Ok(value[name]
        .as_str()
        .with_context(|| format!("missing {name}"))?
        .to_owned())
}

struct PreparedEvidence {
    request: VerificationRequest,
    quote: Vec<u8>,
    certificate_binding: Option<String>,
    kms_approval: Value,
}

fn prepare_request(input: &Value, expected: &Expected) -> anyhow::Result<PreparedEvidence> {
    let mut certificate_binding = None;
    let mut kms_approval = Value::Null;
    let (request, quote) = if let Some(certificate) = input["certificate"].as_str() {
        let leaf = hex::decode(certificate)?;
        let decoded = super::kms::decode_certificate(&leaf)?;
        let kms = expected
            .kms
            .as_ref()
            .context("certificate preparation requires reviewed KMS identities")?;
        let ca = hex::decode(field(input, "ca_certificate")?)?;
        ensure!(
            hex::encode(Sha256::digest(super::kms::ca_key(&ca)?)) == kms.ca_public_key_sha256
                && field(input, "root_public_key")? == kms.root_public_key,
            "KMS roots differ from reviewed pins"
        );
        super::kms::verify_certificate(&ca, &leaf, &kms.endpoint, super::evidence::now_secs())?;
        certificate_binding = Some(hex::encode(decoded.report_data));
        kms_approval = json!({"id": kms.id, "endpoint": kms.endpoint,
            "root_public_key": kms.root_public_key, "ca_public_key_sha256": kms.ca_public_key_sha256,
            "app_id": expected.app_id, "compose_sha256": expected.compose_sha256, "platform_id": expected.id});
        (
            VerificationRequest {
                attestation: Some(decoded.attestation),
                quote: None,
                event_log: None,
                vm_config: None,
            },
            decoded.quote,
        )
    } else {
        ensure!(
            expected.kms.is_none(),
            "KMS preparation requires its RA-TLS certificate"
        );
        let quote = hex::decode(field(input, "quote")?.trim_start_matches("0x"))?;
        (
            VerificationRequest {
                quote: Some(quote.clone()),
                event_log: Some(field(input, "event_log")?),
                vm_config: Some(field(input, "vm_config")?),
                attestation: None,
            },
            quote,
        )
    };
    Ok(PreparedEvidence {
        request,
        quote,
        certificate_binding,
        kms_approval,
    })
}

// The pinned dstack dependency graph is intentionally isolated from the
// application's QVL dependencies. Its Tokio reactor must be isolated too.
async fn upstream_runtime<T, F>(future: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        dstack_tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(future)
    })
    .await?
}

// A reviewed production-image hash is the policy authority for both TDX
// formats. Lite binds its measurement document to that hash and deliberately
// leaves upstream's image metadata unset; a missing metadata field is not a
// failed measurement check. Reject a known development image in either case.
fn approved_os(image_hash: &[u8], is_dev: Option<bool>, expected: &str) -> anyhow::Result<()> {
    ensure!(is_dev != Some(true), "development OS image is forbidden");
    ensure!(
        hex::encode(image_hash) == expected,
        "unapproved production OS identity"
    );
    Ok(())
}

async fn verify_platform(
    request: VerificationRequest,
    expected_os: String,
) -> anyhow::Result<dstack_verifier::VerificationResponse> {
    // Upstream verifies both full-image and lite measurement material against
    // the image identity, quoted MRs, VM shape and runtime event log.
    let cache =
        std::env::var("HIRO_OS_IMAGE_CACHE").unwrap_or_else(|_| "/tmp/hiro-os-images".into());
    upstream_runtime(async move {
        let verifier = CvmVerifier::new(
            cache,
            "https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz".into(),
            Duration::from_mins(5),
            Arc::new(AttestationVerifier::new_prod(None).map_err(|error| {
                anyhow::anyhow!("dstack verifier initialization failed: {error}")
            })?),
        );
        let result = verifier
            .verify(request)
            .await
            .map_err(|error| anyhow::anyhow!("dstack verification failed: {error}"))?;
        if result.is_valid {
            let app = result
                .details
                .app_info
                .as_ref()
                .context("missing OS identity")?;
            approved_os(
                &app.os_image_hash,
                result.details.os_image_is_dev,
                &expected_os,
            )?;
        }
        Ok(result)
    })
    .await
}

/// Verify a captured quote or RA-TLS certificate before exporting a platform
/// profile. EXPECTED must contain independently selected OS and application identities.
///
/// # Errors
/// Rejects malformed evidence, unapproved identities, nonproduction OS, or failed cryptographic checks.
pub async fn prepare(input: &Path, expected: &Path, output: &Path) -> anyhow::Result<()> {
    let input: Value =
        serde_json::from_slice(&super::snapshot::read_bounded(input, 4 * 1024 * 1024)?)?;
    let expected: Expected =
        serde_json::from_slice(&super::snapshot::read_bounded(expected, 8192)?)?;
    ensure!(
        !expected.id.is_empty() && expected.id.len() <= 128,
        "invalid profile ID"
    );
    for (value, length) in [
        (&expected.os_image_hash, 32),
        (&expected.app_id, 20),
        (&expected.compose_sha256, 32),
    ] {
        ensure!(
            value.len() == length * 2 && hex::decode(value)?.len() == length,
            "invalid expected identity"
        );
    }
    let prepared = prepare_request(&input, &expected)?;
    let result = verify_platform(prepared.request, expected.os_image_hash.clone()).await?;
    ensure!(
        result.is_valid
            && result.details.quote_verified
            && result.details.event_log_verified
            && result.details.os_image_hash_verified
            && result.details.acpi_tables_verified,
        "dstack platform verification failed: {:?}",
        result.reason
    );
    ensure!(
        result.details.tcb_status.as_deref() == Some("UpToDate"),
        "KMS/workload TCB must be UpToDate"
    );
    if let Some(binding) = prepared.certificate_binding {
        ensure!(
            result.details.report_data.as_deref() == Some(binding.as_str()),
            "KMS quote is not bound to its TLS certificate"
        );
    }
    let app = result
        .details
        .app_info
        .context("dstack app identity missing")?;
    ensure!(
        hex::encode(&app.os_image_hash) == expected.os_image_hash
            && hex::encode(&app.app_id) == expected.app_id
            && hex::encode(&app.compose_hash) == expected.compose_sha256,
        "attested OS or application differs from reviewed identities"
    );
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let collateral_client =
        dcap_qvl::collateral::CollateralClient::<dcap_qvl::configs::RustCryptoConfig, _>::new(
            super::worker::CollateralHttp(client),
            "https://pccs.phala.network",
        );
    let collateral = collateral_client.fetch(&prepared.quote).await?;
    let profile = super::verification::profile_from_quote(
        &prepared.quote,
        &collateral,
        expected.id,
        super::evidence::now_secs(),
        expected.allow_smt,
        expected.allow_dynamic_platform,
        expected.allow_cached_keys,
    )?;
    let document = json!({"schema": 1, "platform": profile, "kms": prepared.kms_approval, "os_image_hash": expected.os_image_hash,
        "app_id": expected.app_id, "compose_sha256": expected.compose_sha256,
        "verifier_revision": "3c877847e71a205a1d036965b8f5d671b3740103"});
    super::snapshot::atomic_write(output, &serde_json::to_vec_pretty(&document)?, 0o644)
}

/// Collect authenticated public KMS evidence for trust preparation.
///
/// # Errors
/// Rejects a mismatched CA, nonproduction KMS configuration or missing RA-TLS evidence.
pub async fn collect_kms(origin: &str, ca_path: &Path, output: &Path) -> anyhow::Result<()> {
    let ca = super::kms::ca_der(&super::snapshot::read_bounded(ca_path, 16 * 1024)?)?;
    let evidence = super::kms::collect(
        &super::kms::client(&ca)?,
        &super::kms::endpoint(origin)?,
        &ca,
    )
    .await?;
    super::snapshot::atomic_write(output, &serde_json::to_vec_pretty(&evidence)?, 0o644)
}

#[cfg(test)]
mod tests {
    #[test]
    fn lite_and_legacy_must_match_the_reviewed_production_image() {
        let image = [42u8; 32];
        let expected = hex::encode(image);
        for metadata in [None, Some(false)] {
            assert!(super::approved_os(&image, metadata, &expected).is_ok());
            assert!(super::approved_os(&image, metadata, &"00".repeat(32)).is_err());
        }
        assert!(super::approved_os(&image, Some(true), &expected).is_err());
    }

    #[tokio::test]
    async fn isolated_upstream_reactor_can_drive_network_timers() {
        let result = super::upstream_runtime(async {
            dstack_tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            Ok(42)
        })
        .await
        .unwrap();
        assert_eq!(result, 42);
    }
}
