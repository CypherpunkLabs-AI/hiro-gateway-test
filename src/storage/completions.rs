//! Single-use completion proofs and expiring upstream sessions.
use crate::attestation::{
    VerifiedUpstream,
    evidence::{AttestedSession, SignedReceipt, now_secs},
};
use aci_protocol::digest;
use anyhow::ensure;
use serde_json::json;
use std::{collections::HashMap, sync::Mutex};

const MAX_PROOFS: usize = 32;

#[derive(Default)]
pub(crate) struct CompletionStore {
    sessions: Mutex<HashMap<String, AttestedSession>>,
    proofs: Mutex<HashMap<String, (SignedReceipt, AttestedSession, u64)>>,
}
impl CompletionStore {
    /// Consume the receipt and cited session exactly once for Oak completion.
    pub fn take_completion(&self, id: &str) -> Option<(SignedReceipt, AttestedSession)> {
        let (receipt, session, expiry) = self.proofs.lock().ok()?.remove(id)?;
        (now_secs() < expiry).then_some((receipt, session))
    }

    pub(crate) fn store_completion(
        &self,
        receipt: SignedReceipt,
        session: AttestedSession,
    ) -> std::io::Result<()> {
        let now = now_secs();
        let mut proofs = self
            .proofs
            .lock()
            .map_err(|_| std::io::Error::other("receipt state unavailable"))?;
        proofs.retain(|_, (_, _, expiry)| *expiry > now);
        if proofs.len() >= MAX_PROOFS {
            return Err(std::io::Error::other("receipt capacity exceeded"));
        }
        proofs.insert(
            receipt.receipt_id.clone(),
            (receipt, session, now.saturating_add(60)),
        );
        Ok(())
    }

    pub(crate) fn session(
        &self,
        event: &VerifiedUpstream,
        receipt_ttl_seconds: u64,
        keyset_not_after: u64,
    ) -> anyhow::Result<AttestedSession> {
        ensure!(
            event.is_current() && event.required,
            "upstream verification required"
        );
        let fingerprint = digest::sha256_hex(&digest::jcs_bytes(&json!({
            "upstream":event.upstream_name, "origin":event.url_origin,
            "bindings":event.channel_bindings, "evidence":event.evidence,
            "established_at":event.established_at, "expires_at":event.expires_at,
        }))?);
        let now = now_secs();
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session state unavailable"))?;
        sessions.retain(|_, session| session.expires_at > now);
        if let Some(session) = sessions.get(&fingerprint) {
            return Ok(session.clone());
        }
        ensure!(sessions.len() < MAX_PROOFS, "session capacity exceeded");
        let expires = now
            .saturating_add(receipt_ttl_seconds)
            .min(keyset_not_after)
            .min(event.expires_at);
        let session = AttestedSession::new(event, expires)?;
        sessions.insert(fingerprint, session.clone());
        Ok(session)
    }
}
