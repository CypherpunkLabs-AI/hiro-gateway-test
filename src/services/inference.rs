//! Oak service dispatch with direct inference verification and signed completion.
use crate::attestation::keys::OakKeys;
use crate::storage::completions::CompletionStore;
use crate::{
    attestation::evidence::{
        AttestedSession, Keyset, Receipt, ServiceConfig, SignedReceipt, now_secs,
        validate_source_provenance,
    },
    attestation::{InferenceVerifier, VerificationRequest},
    inference::upstream::{InferenceBackend, UpstreamRequest},
};
use aci_protocol::{
    digest,
    identity::{attestation_statement, report_data},
    types::{AttestationEnvelope, AttestationReport, ServiceCapabilities, WorkloadKeyset},
};
use anyhow::{Context, ensure};
use axum::{body::Body, response::Response};
use futures_util::StreamExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const MAX_BODY: usize = 64 * 1024 * 1024;

pub struct Service {
    keys: Arc<OakKeys>,
    keyset: Keyset,
    config: ServiceConfig,
    upstream: Arc<InferenceBackend>,
    verifier: Arc<InferenceVerifier>,
    completions: CompletionStore,
}

impl Service {
    /// Seal the keyset supplied by the direct dstack adapter.
    /// # Errors
    /// Rejects invalid source provenance, expired identity or unexpected key roles.
    pub fn new(
        keys: Arc<OakKeys>,
        upstream: Arc<InferenceBackend>,
        verifier: Arc<InferenceVerifier>,
        config: ServiceConfig,
    ) -> anyhow::Result<Self> {
        validate_source_provenance(&config.source_provenance)?;
        ensure!(
            config.keyset_not_after > now_secs(),
            "expired service identity"
        );
        let receipts = keys.receipt_keys();
        let bindings = keys.binding_keys();
        ensure!(
            receipts.len() == 1
                && bindings.len() == 1
                && receipts[0].algo == "ed25519"
                && bindings[0].algo == "oak-session-v1-ed25519"
                && receipts[0].key_id != bindings[0].key_id
                && receipts[0].public_key_hex != bindings[0].public_key_hex,
            "invalid key roles"
        );
        // OakKeys owns validated SigningKeys; callers cannot supply arbitrary
        // public descriptors or an alternative provider to this constructor.
        let keyset = Keyset::new(WorkloadKeyset {
            subject: config.subject.clone(),
            not_after: config.keyset_not_after,
            receipt_signing_keys: receipts,
            e2ee_public_keys: bindings,
            tls_public_keys: Vec::new(),
        })?;
        Ok(Self {
            keys,
            keyset,
            config,
            upstream,
            verifier,
            completions: CompletionStore::default(),
        })
    }

    pub fn workload_keyset_digest(&self) -> &str {
        self.keyset.digest()
    }

    /// Produce challenge-bound evidence using the established ACI encoding.
    /// # Errors
    /// Rejects malformed challenges, expired identity or failed dstack quotes.
    pub async fn attestation_report(
        &self,
        nonce: Option<String>,
    ) -> anyhow::Result<AttestationReport> {
        ensure!(
            now_secs() < self.config.keyset_not_after,
            "expired service identity"
        );
        let nonce = nonce.context("challenge required")?;
        ensure!(
            nonce.len() == 64
                && nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid challenge"
        );
        let statement = attestation_statement(self.keyset.digest(), Some(&nonce))?;
        let data = report_data(&statement);
        let quote = self.keys.get_quote(data).await?;
        Ok(AttestationReport {
            api_version: "aci/1".into(),
            workload_keyset_digest: self.keyset.digest().into(),
            attestation: AttestationEnvelope {
                tee_type: "tdx".into(),
                workload_keyset: self.keyset.to_value(),
                report_data_hex: hex::encode(data),
                source_provenance: self.config.source_provenance.clone(),
                evidence: json!({"quote":hex::encode(quote.raw_quote), "quote_report_data":hex::encode(quote.report_data),
                    "event_log":quote.event_log, "vm_config":quote.vm_config, "app_compose":quote.app_compose,
                    "key_custody":self.keys.key_custody_evidence()}),
            },
            service_capabilities: ServiceCapabilities::default(),
        })
    }

    /// Consume the receipt and cited session exactly once for Oak completion.
    pub fn take_completion(&self, id: &str) -> Option<(SignedReceipt, AttestedSession)> {
        self.completions.take_completion(id)
    }

    /// Open a transformed application request through the same verified backend.
    pub(crate) async fn open_inference(
        &self,
        path: &str,
        requested_model: Option<&str>,
        received: &[u8],
        forwarded: Vec<u8>,
    ) -> anyhow::Result<(crate::inference::upstream::StreamResponse, PendingReceipt)> {
        ensure!(
            now_secs() < self.config.keyset_not_after,
            "expired service identity"
        );
        let prepared = self.upstream.prepare(UpstreamRequest {
            body: forwarded,
            path: Some("/v1/chat/completions".into()),
            ..Default::default()
        })?;
        let event = self
            .verifier
            .verify(VerificationRequest {
                upstream_name: prepared.upstream_name.clone(),
                url_origin: prepared.url_origin.clone(),
                model_id: prepared.model_id.clone(),
                forwarded_body_hash: digest::sha256_hex(&prepared.request.body),
                path: "/v1/chat/completions".into(),
                required: true,
            })
            .await?;
        let session = self.completions.session(
            &event,
            self.config.receipt_ttl_seconds,
            self.config.keyset_not_after,
        )?;
        let id = uuid::Uuid::new_v4().to_string();
        let receipt = Receipt::new(
            crate::attestation::evidence::ReceiptRequest {
                id: &id,
                model: requested_model,
                keyset: self.keyset.digest(),
                path,
                received,
                forwarded: &prepared.request.body,
            },
            &event,
            &session,
        )?;
        let response = self
            .upstream
            .forward_stream_verified_prepared(prepared, &event)
            .await?;
        Ok((
            response,
            PendingReceipt {
                id,
                receipt,
                session,
            },
        ))
    }

    /// Hash the actual application response, including SSE keepalive bytes.
    /// Publishing only after clean body completion prevents authenticating truncation.
    pub(crate) fn sign_response(
        self: Arc<Self>,
        pending: PendingReceipt,
        response: Response,
    ) -> Response {
        let (mut parts, body) = response.into_parts();
        parts
            .headers
            .insert("x-receipt-id", pending.id.parse().expect("UUID header"));
        parts
            .headers
            .insert("cache-control", "no-store".parse().expect("static header"));
        let mut chunks = body.into_data_stream();
        let body = async_stream::try_stream! {
            let mut hash = Sha256::new();
            let mut length = 0usize;
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk.map_err(|_| std::io::Error::other("inference response interrupted"))?;
                length = length.checked_add(chunk.len()).ok_or_else(|| std::io::Error::other("response exceeds limit"))?;
                if length > MAX_BODY { Err(std::io::Error::other("response exceeds limit"))?; }
                hash.update(&chunk);
                yield chunk;
            }
            let signed = pending.receipt.finish(&format!("sha256:{}", hex::encode(hash.finalize())), self.keys.as_ref())
                .map_err(|_| std::io::Error::other("receipt signing failed"))?;
            self.completions.store_completion(signed, pending.session)?;
        };
        let body: std::pin::Pin<
            Box<dyn futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send>,
        > = Box::pin(body);
        Response::from_parts(parts, Body::from_stream(body))
    }
}

pub(crate) struct PendingReceipt {
    id: String,
    receipt: Receipt,
    session: AttestedSession,
}
