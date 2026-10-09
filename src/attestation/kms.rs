//! KMS RA-TLS evidence. Collection and independent appraisal use the same decoder.
use anyhow::{Context, ensure};
use dstack_attest::attestation::{AttestationQuote, QuoteContentType};
use reqwest::{Client, Url};
use rustls::{
    RootCertStore,
    client::WebPkiServerVerifier,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

pub(crate) const MAX_CERTIFICATE: usize = 256 * 1024;

pub(crate) struct CertificateEvidence {
    pub quote: Vec<u8>,
    pub event_log: String,
    pub report_data: [u8; 64],
    pub attestation: Vec<u8>,
}

fn certificate(der: &[u8]) -> anyhow::Result<X509Certificate<'_>> {
    ensure!(
        !der.is_empty() && der.len() <= MAX_CERTIFICATE,
        "invalid certificate size"
    );
    let (rest, certificate) = X509Certificate::from_der(der)?;
    ensure!(rest.is_empty(), "trailing certificate data");
    certificate
        .extensions_map()
        .context("duplicate certificate extensions")?;
    Ok(certificate)
}

pub(crate) fn ca_der(pem: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(pem.len() <= 16 * 1024, "KMS CA exceeds limit");
    let (rest, pem) = x509_parser::pem::parse_x509_pem(pem)?;
    ensure!(
        rest.iter().all(u8::is_ascii_whitespace) && pem.label == "CERTIFICATE",
        "expected one CA certificate"
    );
    certificate(&pem.contents)?;
    Ok(pem.contents)
}

pub(crate) fn ca_key(der: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(certificate(der)?.public_key().raw.to_vec())
}

pub(crate) fn endpoint(value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "KMS endpoint must be an HTTPS origin"
    );
    Ok(url)
}

pub(crate) fn decode_certificate(der: &[u8]) -> anyhow::Result<CertificateEvidence> {
    let cert = certificate(der)?;
    let versioned = ra_tls::attestation::from_der(der)
        .map_err(|error| anyhow::anyhow!("invalid KMS certificate evidence: {error}"))?
        .context("KMS certificate has no RA-TLS attestation")?;
    let encoded = versioned
        .to_bytes()
        .map_err(|error| anyhow::anyhow!("invalid attestation encoding: {error}"))?;
    let attestation = versioned
        .into_v1()
        .try_into_legacy()
        .map_err(|error| anyhow::anyhow!("unsupported KMS attestation profile: {error}"))?;
    let AttestationQuote::DstackTdx(tdx) = attestation.quote else {
        anyhow::bail!("KMS evidence requires native Intel TDX");
    };
    ensure!(tdx.quote.len() <= 64 * 1024, "KMS quote exceeds limit");
    ensure!(
        !attestation.runtime_events.is_empty() && attestation.runtime_events.len() <= 2048,
        "invalid KMS event count"
    );
    let events: Vec<Value> = attestation
        .runtime_events
        .iter()
        .map(|event| {
            json!({
                "imr": 3, "event_type": event.cc_event_type(),
                "digest": hex::encode(event.sha384_digest()), "event": event.event,
                "event_payload": hex::encode(&event.payload),
            })
        })
        .collect();
    Ok(CertificateEvidence {
        quote: tdx.quote,
        event_log: serde_json::to_string(&events)?,
        report_data: QuoteContentType::RaTlsCert.to_report_data(cert.public_key().raw),
        attestation: encoded,
    })
}

/// Authenticate the issuer, hostname, usages and lifetime independently of the
/// worker. The caller must first match the CA public key against signed policy.
pub(crate) fn verify_certificate(
    ca: &[u8],
    leaf: &[u8],
    origin: &str,
    now: u64,
) -> anyhow::Result<u64> {
    use rustls::client::danger::ServerCertVerifier;
    let url = endpoint(origin)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.to_vec()))?;
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()?;
    let name = ServerName::try_from(url.host_str().context("missing KMS host")?.to_owned())?;
    verifier.verify_server_cert(
        &CertificateDer::from(leaf.to_vec()),
        &[],
        &name,
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(now)),
    )?;
    let expiry = certificate(leaf)?.validity().not_after.timestamp();
    Ok(u64::try_from(expiry)?)
}

pub(crate) fn client(ca: &[u8]) -> anyhow::Result<Client> {
    Ok(Client::builder()
        .https_only(true)
        .no_proxy()
        .tls_certs_only([reqwest::Certificate::from_der(ca)?])
        .tls_info(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?)
}

pub(crate) async fn collect(client: &Client, origin: &Url, ca: &[u8]) -> anyhow::Result<Value> {
    let response = client
        .get(origin.join("/prpc/KMS.GetMeta?json")?)
        .send()
        .await?;
    let leaf = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .context("KMS transport did not expose its authenticated certificate")?
        .to_vec();
    verify_certificate(ca, &leaf, origin.as_str(), super::evidence::now_secs())?;
    decode_certificate(&leaf)?;
    let meta: Value = serde_json::from_slice(&super::worker::bytes(response, 1024 * 1024).await?)?;
    let root = validate_meta(&meta, ca)?;
    Ok(
        json!({"kind": "dstack-ratls-v1", "certificate": hex::encode(leaf),
        "ca_certificate": hex::encode(ca), "root_public_key": root}),
    )
}

fn validate_meta(meta: &Value, ca: &[u8]) -> anyhow::Result<String> {
    ensure!(
        meta["is_dev"] == false && meta["allow_any_upgrade"] == false,
        "KMS must use production authorization"
    );
    // GetMeta's optional os_image_verification flag describes the KMS's local
    // image reconstruction, not its separate boot-authorization policy. Phala
    // Cloud delegates authorization to its managed backend. Do not substitute
    // this metadata flag for appraisal of the KMS's own attested OS and code:
    // provisioning verifies those with dstack-verifier, and the session gate
    // checks the certificate quote against the resulting signed-policy pins.
    let returned_ca = ca_der(
        meta["ca_cert"]
            .as_str()
            .context("KMS CA missing")?
            .as_bytes(),
    )?;
    ensure!(
        ca_key(&returned_ca)? == ca_key(ca)?,
        "KMS response changed its CA identity"
    );
    let root = meta["k256_pubkey"]
        .as_str()
        .context("KMS root missing")?
        .trim_start_matches("0x");
    ensure!(
        root.len() == 66 && hex::decode(root)?.len() == 33,
        "invalid KMS root key"
    );
    Ok(root.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    const CA: &[u8] = include_bytes!("testdata/kms-ca.der");
    const LEAF: &[u8] = include_bytes!("testdata/kms-cert.der");
    const ORIGIN: &str = "https://kms.dstack-pha-prod10.phala.network";
    const NOW: u64 = 1_791_540_000;

    #[test]
    fn authenticates_real_kms_chain_without_public_web_pki_or_bootstrap_info() {
        assert!(verify_certificate(CA, LEAF, ORIGIN, NOW).is_ok());
        let decoded = decode_certificate(LEAF).unwrap();
        assert!(!decoded.quote.is_empty());
        assert!(!decoded.attestation.is_empty());
        assert!(decoded.event_log.contains("compose-hash"));
    }

    #[test]
    fn rejects_certificate_substitution_wrong_host_expiry_and_ambiguous_der() {
        assert!(verify_certificate(CA, LEAF, "https://attacker.example", NOW).is_err());
        assert!(verify_certificate(CA, LEAF, ORIGIN, 2_200_000_000).is_err());
        let mut changed = LEAF.to_vec();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(verify_certificate(CA, &changed, ORIGIN, NOW).is_err());
        let mut trailing = LEAF.to_vec();
        trailing.push(0);
        assert!(decode_certificate(&trailing).is_err());
        assert!(decode_certificate(CA).is_err());
    }

    #[test]
    fn rejects_untrusted_endpoint_forms() {
        for value in [
            "http://kms.example",
            "https://user@kms.example",
            "https://kms.example/path",
            "https://kms.example?x=1",
            "https://kms.example#fragment",
        ] {
            assert!(endpoint(value).is_err());
        }
    }
    #[test]
    fn cloud_metadata_does_not_confuse_local_image_check_with_authorization() {
        use base64::Engine;
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(CA)
        );
        let mut meta = json!({"ca_cert": pem, "k256_pubkey": "0334c76e0c3f52ec64cbf9bbf5c910c272330166fd656c0a86bb330963e46910e1",
            "is_dev": false, "allow_any_upgrade": false, "os_image_verification": true, "bootstrap_info": null});
        assert!(validate_meta(&meta, CA).is_ok());
        for field in ["is_dev", "allow_any_upgrade"] {
            let before = meta[field].clone();
            meta[field] = Value::Null;
            assert!(validate_meta(&meta, CA).is_err());
            meta[field] = before;
        }
        meta["os_image_verification"] = json!(false);
        assert!(validate_meta(&meta, CA).is_ok());
        meta.as_object_mut()
            .unwrap()
            .remove("os_image_verification");
        assert!(validate_meta(&meta, CA).is_ok());
        for field in ["is_dev", "allow_any_upgrade"] {
            meta[field] = json!(true);
            assert!(validate_meta(&meta, CA).is_err());
            meta[field] = json!(false);
        }
    }
}
