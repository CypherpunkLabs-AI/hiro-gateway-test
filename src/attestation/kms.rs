//! Convert dstack's public KMS.GetMeta response into verifier input. Decoding
//! does not grant trust: Authority verifies the quote, keys and signed policy.
use anyhow::{Context, bail, ensure};
use dstack_attest::attestation::{AttestationQuote, VersionedAttestation};
use serde_json::{Value, json};

fn hex_bytes(value: &Value, limit: usize) -> anyhow::Result<Vec<u8>> {
    let encoded = value.as_str().context("KMS bytes must be hex encoded")?;
    let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
    ensure!(encoded.len() <= limit * 2, "KMS field exceeds limit");
    Ok(hex::decode(encoded)?)
}

pub(super) fn decode_meta(meta: &Value) -> anyhow::Result<Value> {
    ensure!(
        meta["is_dev"] == false && meta["allow_any_upgrade"] == false,
        "KMS must use production mode and restricted upgrades"
    );
    let bootstrap = meta
        .get("bootstrap_info")
        .context("KMS has no bootstrap evidence")?;
    let root = hex_bytes(&bootstrap["k256_pubkey"], 33)?;
    let ca = hex_bytes(&bootstrap["ca_pubkey"], 1024)?;
    ensure!(
        root.len() == 33 && !ca.is_empty(),
        "invalid KMS public keys"
    );
    ensure!(
        root == hex_bytes(&meta["k256_pubkey"], 33)?,
        "KMS root changed"
    );
    let encoded = hex_bytes(&bootstrap["attestation"], 2 * 1024 * 1024)?;
    let attestation = VersionedAttestation::from_bytes(&encoded)
        .map_err(|error| anyhow::anyhow!("invalid dstack bootstrap envelope: {error}"))?
        .into_v1()
        .try_into_legacy()
        .map_err(|error| anyhow::anyhow!("unsupported dstack bootstrap profile: {error}"))?;
    let AttestationQuote::DstackTdx(tdx) = attestation.quote else {
        bail!("KMS evidence requires native Intel TDX");
    };
    ensure!(tdx.quote.len() <= 128 * 1024, "KMS quote exceeds limit");
    ensure!(
        !attestation.runtime_events.is_empty() && attestation.runtime_events.len() <= 2048,
        "invalid KMS event count"
    );
    // The upstream envelope may strip runtime events from the platform log;
    // its stack runtime_events retain the complete RTMR3 sequence. Use dstack's
    // own digest implementation. The verifier independently replays this log.
    let events: Vec<Value> = attestation
        .runtime_events
        .iter()
        .map(|event| {
            json!({
                "imr": 3,
                "event_type": event.cc_event_type(),
                "digest": hex::encode(event.sha384_digest()),
                "event": event.event,
                "event_payload": hex::encode(&event.payload),
            })
        })
        .collect();
    Ok(json!({
        "quote": hex::encode(tdx.quote),
        "event_log": serde_json::to_string(&events)?,
        "ca_public_key": hex::encode(ca),
        "root_public_key": hex::encode(root),
    }))
}
