//! Oak binding and receipt keys, released directly by the official dstack SDK.
use aci_protocol::{identity::report_data_slot, types::KeyedPublicKey};
use anyhow::{Context, ensure};
use dstack_sdk::dstack_client::DstackClient;
use ed25519_dalek::{Signer, SigningKey};
pub struct Quote {
    pub raw_quote: Vec<u8>,
    pub report_data: Vec<u8>,
    pub event_log: Value,
    pub vm_config: Value,
    pub app_compose: Option<String>,
}
use serde_json::{Value, json};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

const RECEIPT_ID: &str = "dstack-kms-receipt-ed25519-v1";
const BINDING_ID: &str = "dstack-kms-oak-session-v1";
const BINDING_ALGORITHM: &str = "oak-session-v1-ed25519";

pub struct OakKeys {
    client: DstackClient,
    receipt: SigningKey,
    pub binding: Arc<SigningKey>,
    custody: Value,
}

impl OakKeys {
    /// Obtain only the two persistent keys used by the Oak service.
    /// # Errors
    /// Rejects an invalid endpoint, failed KMS release or missing custody proof.
    pub async fn new(endpoint: &str) -> anyhow::Result<Self> {
        let endpoint = endpoint.trim();
        let endpoint = endpoint
            .strip_prefix("unix://")
            .or_else(|| endpoint.strip_prefix("unix:"))
            .unwrap_or(endpoint);
        ensure!(!endpoint.is_empty(), "dstack endpoint is empty");
        let client = DstackClient::new(Some(endpoint));
        let (receipt, receipt_custody) = release_key(
            &client,
            "receipt",
            "aci/receipt-ed25519/v1",
            "aci.receipt.ed25519.v1",
            "ed25519",
        )
        .await?;
        let (binding, binding_custody) = release_key(
            &client,
            "oak-session-binding",
            "oak/session-binding-ed25519/v1",
            "oak.session.binding.ed25519.v1",
            BINDING_ALGORITHM,
        )
        .await?;
        ensure!(
            receipt.verifying_key() != binding.verifying_key(),
            "dstack returned the same key for distinct roles"
        );
        Ok(Self {
            client,
            receipt,
            binding: Arc::new(binding),
            custody: json!({
                "provider": "dstack-kms",
                "keys": [receipt_custody, binding_custody],
            }),
        })
    }

    async fn quote(&self, report_data: [u8; 64]) -> anyhow::Result<Quote> {
        let response = self
            .client
            .get_quote(report_data.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("dstack quote request failed"))?;
        let raw_quote = response
            .decode_quote()
            .map_err(|_| anyhow::anyhow!("invalid dstack quote encoding"))?;
        let returned = hex::decode(
            response
                .report_data
                .strip_prefix("0x")
                .unwrap_or(&response.report_data),
        )
        .map_err(|_| anyhow::anyhow!("invalid dstack report data"))?;
        if returned != report_data {
            return Err(anyhow::anyhow!("dstack report data mismatch"));
        }
        let info = self
            .client
            .info()
            .await
            .map_err(|_| anyhow::anyhow!("dstack info request failed"))?;
        let event_log = serde_json::to_string(&info.tcb_info.event_log)
            .map_err(|_| anyhow::anyhow!("invalid dstack event log"))?;
        Ok(Quote {
            raw_quote,
            report_data: returned,
            event_log: Value::String(event_log),
            vm_config: Value::String(response.vm_config),
            app_compose: Some(info.tcb_info.app_compose),
        })
    }
}

// dstack signs the secp256k1 counterpart of the released seed. Publish that
// custody proof unchanged; the approved workload binds its Ed25519 use.
async fn release_key(
    client: &DstackClient,
    role: &str,
    path: &str,
    purpose: &str,
    algorithm: &str,
) -> anyhow::Result<(SigningKey, Value)> {
    let mut response = client
        .get_key(Some(path.into()), Some(purpose.into()))
        .await
        .map_err(|_| anyhow::anyhow!("dstack KMS release failed for {role}"))?;
    let decoded = response.decode_key().map(Zeroizing::new);
    response.key.zeroize();
    let decoded = decoded.map_err(|_| anyhow::anyhow!("invalid dstack KMS key encoding"))?;
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(decoded.as_slice()).context("invalid dstack KMS key length")?,
    );
    ensure!(
        response.signature_chain.len() == 2,
        "invalid dstack KMS custody chain"
    );
    let counterpart = k256::ecdsa::SigningKey::from_slice(seed.as_slice())
        .context("invalid dstack custody scalar")?;
    let key = SigningKey::from_bytes(&seed);
    ensure!(!key.verifying_key().is_weak(), "weak dstack signing key");
    let custody = json!({
        "role": role, "path": path, "purpose": purpose, "algo": algorithm,
        "public_key": hex::encode(key.verifying_key().as_bytes()),
        "kms_public_key": hex::encode(counterpart.verifying_key().to_sec1_bytes()),
        "signature_chain": response.signature_chain,
    });
    Ok((key, custody))
}

impl OakKeys {
    pub async fn get_quote(&self, report_data: [u8; 32]) -> anyhow::Result<Quote> {
        self.quote(report_data_slot(report_data)).await
    }
    pub fn receipt_keys(&self) -> Vec<KeyedPublicKey> {
        vec![KeyedPublicKey {
            key_id: RECEIPT_ID.into(),
            algo: "ed25519".into(),
            public_key_hex: hex::encode(self.receipt.verifying_key().as_bytes()),
        }]
    }
    pub fn sign_receipt(&self, id: &str, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        if id != RECEIPT_ID {
            return Err(anyhow::anyhow!("unknown receipt key"));
        }
        Ok(self.receipt.sign(payload).to_bytes().to_vec())
    }
    pub fn binding_keys(&self) -> Vec<KeyedPublicKey> {
        vec![KeyedPublicKey {
            key_id: BINDING_ID.into(),
            algo: BINDING_ALGORITHM.into(),
            public_key_hex: hex::encode(self.binding.verifying_key().as_bytes()),
        }]
    }
    pub fn key_custody_evidence(&self) -> Value {
        self.custody.clone()
    }
}
