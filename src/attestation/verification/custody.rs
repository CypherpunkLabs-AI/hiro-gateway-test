//! dstack KMS RA-TLS identity and selected-key derivation chains.

use aci_protocol::types::WorkloadKeyset;
use evidence_k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::Value;
use sha3::{Digest, Keccak256};

use super::{
    Error, Result, encoding, measurement,
    model::{KmsApproval, KmsEvidence, PlatformProfile, RecipientProfile},
    quote,
};

pub(crate) fn verify_kms(
    evidence: &KmsEvidence,
    approval: &KmsApproval,
    platform: &PlatformProfile,
    now: u64,
) -> Result<u64> {
    use crate::attestation::kms;
    if evidence.kind != "dstack-ratls-v1"
        || evidence.root_public_key != approval.root_public_key
        || evidence.ca_certificate.len() > 32 * 1024
        || evidence.certificate.len() > kms::MAX_CERTIFICATE * 2
    {
        return Err(Error::Custody);
    }
    let ca = hex::decode(&evidence.ca_certificate).map_err(|_| Error::Encoding)?;
    let leaf = hex::decode(&evidence.certificate).map_err(|_| Error::Encoding)?;
    let ca_key = kms::ca_key(&ca).map_err(|_| Error::Custody)?;
    if encoding::digest(&ca_key) != approval.ca_public_key_sha256 {
        return Err(Error::Custody);
    }
    let certificate_expiry =
        kms::verify_certificate(&ca, &leaf, &approval.endpoint, now).map_err(|_| Error::Custody)?;
    let decoded = kms::decode_certificate(&leaf).map_err(|_| Error::Custody)?;
    let verified = quote::verify(&decoded.quote, &evidence.collateral, platform, now)?;
    if verified.report.report_data != decoded.report_data {
        return Err(Error::Custody);
    }
    measurement::verify_identity(
        &serde_json::json!({"event_log": decoded.event_log}),
        &verified.report.rt_mr3,
        &approval.app_id,
        &approval.compose_sha256,
    )?;
    Ok(verified.expires_at.min(certificate_expiry))
}

pub(crate) fn verify_keys(
    evidence: &Value,
    keyset: &WorkloadKeyset,
    app_id: &str,
    root: &str,
    profile: RecipientProfile,
    recipient_hex: &str,
) -> Result<()> {
    let app_id = encoding::hex_array::<20>(app_id)?;
    let custody = evidence.get("key_custody").ok_or(Error::Custody)?;
    if custody.get("provider").and_then(Value::as_str) != Some("dstack-kms") {
        return Err(Error::Custody);
    }
    let keys = custody
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(Error::Custody)?;
    if keys.is_empty() || keys.len() > 8 {
        return Err(Error::Custody);
    }
    for entry in keys.iter().filter(|entry| {
        matches!(entry.get("role").and_then(Value::as_str), Some("receipt"))
            || entry.get("role").and_then(Value::as_str) == Some(profile.role())
    }) {
        preflight_chain(entry)?;
    }
    // The shared ACI mechanism validates receipt role/purpose and both recoveries.
    if keys
        .iter()
        .filter(|key| key.get("role").and_then(Value::as_str) == Some("receipt"))
        .count()
        != 1
        || aci_verify::dstack::verify_dstack_kms_receipt_chain(evidence, keyset, &app_id)
            .map_err(|_| Error::Custody)?
            != root
    {
        return Err(Error::Custody);
    }
    let mut matching = keys
        .iter()
        .filter(|key| key.get("role").and_then(Value::as_str) == Some(profile.role()));
    let selected = matching.next().ok_or(Error::Custody)?;
    if matching.next().is_some() {
        return Err(Error::Custody);
    }
    let field = |name: &str| {
        selected
            .get(name)
            .and_then(Value::as_str)
            .ok_or(Error::Custody)
    };
    if field("public_key")? != recipient_hex
        || field("purpose")? != profile.purpose()
        || field("algo")? != profile.algorithm()
    {
        return Err(Error::Custody);
    }
    let derived = aci_verify::dstack::compressed_k256_public_key_hex(field("kms_public_key")?)
        .map_err(|_| Error::Custody)?;
    let chain = selected
        .get("signature_chain")
        .and_then(Value::as_array)
        .ok_or(Error::Custody)?;
    if chain.len() != 2 {
        return Err(Error::Custody);
    }
    let purpose_signature = chain
        .first()
        .and_then(Value::as_str)
        .ok_or(Error::Custody)?;
    let app_signature = chain.get(1).and_then(Value::as_str).ok_or(Error::Custody)?;
    // Same dstack recovery protocol as aci-verify, extended to the actual
    // encryption key rather than accepting only its sibling receipt key.
    let purpose_message = format!("{}:{derived}", profile.purpose());
    let app_key = recover(purpose_message.as_bytes(), purpose_signature)?;
    let root_message = [
        b"dstack-kms-issued:".as_slice(),
        &app_id,
        &app_key.to_sec1_bytes(),
    ]
    .concat();
    let recovered = recover(&root_message, app_signature)?;
    if hex::encode(recovered.to_sec1_bytes()) != root {
        return Err(Error::Custody);
    }
    Ok(())
}

fn preflight_chain(entry: &Value) -> Result<()> {
    // Bound and validate both selected chains before the upstream helper
    // decodes any caller-controlled key/signature strings.
    let public = entry
        .get("kms_public_key")
        .and_then(Value::as_str)
        .ok_or(Error::Custody)?;
    match public.len() {
        66 => {
            encoding::hex_array::<33>(public)?;
        }
        130 => {
            encoding::hex_array::<65>(public)?;
        }
        _ => return Err(Error::Custody),
    }
    let chain = entry
        .get("signature_chain")
        .and_then(Value::as_array)
        .ok_or(Error::Custody)?;
    if chain.len() != 2 {
        return Err(Error::Custody);
    }
    for signature in chain {
        encoding::hex_array::<65>(signature.as_str().ok_or(Error::Custody)?)?;
    }
    if entry.get("role").and_then(Value::as_str) == Some("receipt")
        && entry.get("algo").and_then(Value::as_str) != Some("ed25519")
    {
        return Err(Error::Custody);
    }
    Ok(())
}

fn recover(message: &[u8], encoded: &str) -> Result<VerifyingKey> {
    let signature = encoding::hex_array::<65>(encoded)?;
    let mut recovery = signature[64];
    if (27..=30).contains(&recovery) {
        recovery -= 27;
    }
    let recovery = RecoveryId::from_byte(recovery).ok_or(Error::Custody)?;
    let signature = Signature::from_slice(&signature[..64]).map_err(|_| Error::Custody)?;
    VerifyingKey::recover_from_digest(Keccak256::new_with_prefix(message), &signature, recovery)
        .map_err(|_| Error::Custody)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::kms;

    #[test]
    fn authenticates_live_rtls_quote_and_rejects_key_or_identity_substitution() {
        let ca = include_bytes!("../testdata/kms-ca.der");
        let leaf = include_bytes!("../testdata/kms-cert.der");
        let collateral =
            serde_json::from_slice(include_bytes!("../testdata/kms-collateral.json")).unwrap();
        let decoded = kms::decode_certificate(leaf).unwrap();
        let now = 1_791_540_000;
        let profile = quote::profile_from_quote(
            &decoded.quote,
            &collateral,
            "kms-test".into(),
            now,
            true,
            true,
            true,
        )
        .unwrap();
        let events: Vec<Value> = serde_json::from_str(&decoded.event_log).unwrap();
        let event = |name: &str| {
            events.iter().find(|e| e["event"] == name).unwrap()["event_payload"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let mut approval = KmsApproval {
            id: "kms".into(),
            endpoint: "https://kms.dstack-pha-prod10.phala.network".into(),
            root_public_key: "0334c76e0c3f52ec64cbf9bbf5c910c272330166fd656c0a86bb330963e46910e1"
                .into(),
            ca_public_key_sha256: encoding::digest(&kms::ca_key(ca).unwrap()),
            app_id: event("app-id"),
            compose_sha256: event("compose-hash"),
            platform_id: "kms-test".into(),
        };
        let evidence = KmsEvidence {
            kind: "dstack-ratls-v1".into(),
            certificate: hex::encode(leaf),
            ca_certificate: hex::encode(ca),
            collateral,
            root_public_key: approval.root_public_key.clone(),
        };
        assert!(verify_kms(&evidence, &approval, &profile, now).is_ok());
        approval.ca_public_key_sha256 = "00".repeat(32);
        assert!(verify_kms(&evidence, &approval, &profile, now).is_err());
        approval.ca_public_key_sha256 = encoding::digest(&kms::ca_key(ca).unwrap());
        approval.compose_sha256 = "00".repeat(32);
        assert!(verify_kms(&evidence, &approval, &profile, now).is_err());
    }
}
