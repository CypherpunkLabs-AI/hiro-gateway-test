//! dstack KMS bootstrap provenance and selected-key derivation chains.

use aci_protocol::types::WorkloadKeyset;
use evidence_k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::Value;
use sha3::{Digest, Keccak256};

use super::{
    Error, Result, encoding, measurement,
    model::{KmsApproval, KmsEvidence, PlatformProfile, RecipientProfile},
    quote,
};

pub(crate) fn verify_bootstrap(
    evidence: &KmsEvidence,
    approval: &KmsApproval,
    platform: &PlatformProfile,
    now: u64,
) -> Result<u64> {
    if evidence.root_public_key != approval.root_public_key || evidence.ca_public_key.len() > 2048 {
        return Err(Error::Custody);
    }
    let root = encoding::hex_array::<33>(&evidence.root_public_key)?;
    VerifyingKey::from_sec1_bytes(&root).map_err(|_| Error::Custody)?;
    let ca = hex::decode(&evidence.ca_public_key).map_err(|_| Error::Custody)?;
    if encoding::digest(&ca) != approval.ca_public_key_sha256 {
        return Err(Error::Custody);
    }
    let raw_quote = quote::decode_quote(&evidence.quote)?;
    let verified = quote::verify(&raw_quote, &evidence.collateral, platform, now)?;
    // Exact dstack KMS bootstrap encoding, including upstream's "genereted" spelling.
    // Source: dstack/kms/src/onboard_service.rs::attest_keys.
    let message = format!(
        "dstack-kms-genereted-keys-v1:{};{};",
        hex::encode(ca),
        hex::encode(root)
    );
    let hash = Keccak256::digest(message.as_bytes());
    let mut report_data = [0; 64];
    report_data[..32].copy_from_slice(&hash);
    if verified.report.report_data != report_data {
        return Err(Error::Custody);
    }
    let measured =
        serde_json::json!({"event_log": evidence.event_log, "app_compose": evidence.app_compose});
    measurement::verify(
        &measured,
        &verified.report.rt_mr3,
        &approval.app_id,
        &approval.compose_sha256,
    )?;
    Ok(verified.expires_at)
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
    VerifyingKey::recover_from_digest(
        Keccak256::new_with_prefix(message),
        &signature,
        recovery,
    )
    .map_err(|_| Error::Custody)
}
