//! Product evidence assembly. Cryptographic encodings come from aci-protocol.
use crate::{attestation::VerifiedUpstream, attestation::keys::OakKeys};
use aci_protocol::{digest, identity, receipt::receipt_signing_input, types::*};
use anyhow::{Result, ensure};
use serde_json::{Value, json};

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}

pub struct ServiceConfig {
    pub source_provenance: SourceProvenance,
    pub keyset_not_after: u64,
    pub subject: Option<String>,
    pub receipt_ttl_seconds: u64,
}

pub fn validate_source_provenance(value: &SourceProvenance) -> Result<()> {
    ensure!(
        value.repo_url.as_ref().is_some_and(|s| !s.is_empty())
            && value.repo_commit.as_ref().is_some_and(|s| !s.is_empty())
            || value.image_digest.as_ref().is_some_and(|s| !s.is_empty()),
        "source provenance required"
    );
    Ok(())
}

pub struct Keyset {
    value: WorkloadKeyset,
    json: Value,
    digest: String,
}
impl Keyset {
    pub fn new(value: WorkloadKeyset) -> Result<Self> {
        let json = serde_json::to_value(&value)?;
        let digest = identity::workload_keyset_digest(&json)?;
        Ok(Self {
            value,
            json,
            digest,
        })
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn keyset(&self) -> &WorkloadKeyset {
        &self.value
    }
    pub fn to_value(&self) -> Value {
        self.json.clone()
    }
}

#[derive(Clone)]
pub struct AttestedSession {
    id: String,
    bytes: Vec<u8>,
    pub expires_at: u64,
}
impl AttestedSession {
    pub(crate) fn new(event: &VerifiedUpstream, expires_at: u64) -> Result<Self> {
        ensure!(
            event.established_at < expires_at,
            "expired upstream evidence"
        );
        let unknown = json!({"status":"unknown"});
        let value = json!({
            "api_version":"aci/1", "upstream_name":event.upstream_name,
            "endpoint":event.url_origin, "verifier_id":event.verifier_id,
            "established_at":event.established_at, "expires_at":expires_at,
            "identity":null, "channel_binding":event.channel_bindings,
            "claims":{
                "tee_attested":{"status":"asserted", "source":"verifier_derived",
                    "reason":"Verified TDX quote, measured application, KMS custody and TLS key binding"},
                "gpu_attested":unknown, "tcb_up_to_date":unknown,
                "os_known_good":unknown, "serving_software_known_good":unknown,
                "model_weights_provenance":unknown
            },
            "evidence":event.evidence,
        });
        let bytes = digest::jcs_bytes(&value)?;
        ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "upstream evidence exceeds limit"
        );
        let id = hex::encode(digest::sha256_raw(&bytes));
        Ok(Self {
            id,
            bytes,
            expires_at,
        })
    }
    pub fn session_id(&self) -> &str {
        &self.id
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct SignedReceipt {
    pub receipt_id: String,
    pub document: Vec<u8>,
}

pub(crate) struct ReceiptRequest<'a> {
    pub id: &'a str,
    pub model: Option<&'a str>,
    pub keyset: &'a str,
    pub path: &'a str,
    pub received: &'a [u8],
    pub forwarded: &'a [u8],
}

/// A receipt can only be constructed from an authorized forwarding decision.
/// Completion consumes it once after the response body has been fully hashed.
pub(crate) struct Receipt {
    document: Value,
}
impl Receipt {
    pub fn new(
        request: ReceiptRequest<'_>,
        event: &VerifiedUpstream,
        session: &AttestedSession,
    ) -> Result<Self> {
        let ReceiptRequest {
            id,
            model,
            keyset,
            path,
            received,
            forwarded,
        } = request;
        ensure!(
            event.is_current() && event.required,
            "upstream authority expired"
        );
        let document = json!({
            "api_version":"aci/1", "receipt_id":id, "chat_id":null,
            "model":model, "workload_keyset_digest":keyset, "endpoint":path,
            "method":"POST", "served_at":now_secs(),
            "event_log":[
                {"type":"request.received", "body_hash":digest::sha256_hex(received)},
                {"type":"request.forwarded", "body_hash":digest::sha256_hex(forwarded)},
                {"type":"upstream.verified", "result":"verified", "required":true,
                    "model_id":event.model_id, "session_id":session.session_id()}
            ]
        });
        Ok(Self { document })
    }
    pub fn finish(mut self, response_hash: String, keys: &OakKeys) -> Result<SignedReceipt> {
        self.document["event_log"]
            .as_array_mut()
            .expect("receipt event array")
            .push(json!({"type":"response.returned", "body_hash":response_hash}));
        let key = keys.receipt_keys().remove(0);
        self.document["key_id"] = json!(key.key_id);
        let signature = keys.sign_receipt(&key.key_id, &receipt_signing_input(&self.document)?)?;
        self.document["signature"] = json!(hex::encode(signature));
        Ok(SignedReceipt {
            receipt_id: self.document["receipt_id"]
                .as_str()
                .expect("receipt id")
                .to_owned(),
            document: digest::jcs_bytes(&self.document)?,
        })
    }
}
