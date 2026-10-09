//! Single-use challenges, complete evidence appraisal, and capability lifecycle.

use std::collections::BTreeSet;

use aci_verify::report::validate_aci_report_binding;
use serde::Serialize;

use super::{
    Checkpoint, Error, RecipientProfile, Result, custody, encoding, measurement, model, policy,
    quote,
};

/// Host clock reading. Sample both values together on every call.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    /// Trusted wall time, seconds since the Unix epoch.
    pub unix_seconds: u64,
    /// Monotonic milliseconds from a fixed origin for this verifier's lifetime.
    pub monotonic_millis: u64,
}

#[derive(Clone, Copy)]
struct Challenge {
    nonce: [u8; 32],
    started: Clock,
}

/// Stateful verification authority. Not serializable or cloneable.
///
/// Use one per service, serialize access, and atomically persist checkpoints
/// across process restarts. A new challenge invalidates old recipients.
pub struct Verifier {
    trust: policy::Trust,
    checkpoint: Checkpoint,
    persisted_checkpoint_json: Option<String>,
    policy: Option<ActivePolicy>,
    pending_policy: Option<PendingPolicy>,
    instance: [u8; 32],
    generation: u64,
    last_clock: Clock,
    challenge: Option<Challenge>,
    pending_checkpoint: Option<String>,
    ready: bool,
}

struct ActivePolicy {
    authenticated: policy::AuthenticatedPolicy,
    monotonic_deadline: u64,
}

/// Authenticated policy awaiting durable adoption, independent of any recipient.
/// Dropping this handle does not discard the verifier's observed rollback floor.
pub struct PendingPolicy {
    instance: [u8; 32],
    generation: u64,
    checkpoint_json: String,
    previous_checkpoint_json: Option<String>,
}

/// Validated evidence awaiting persistence. Cannot expose a usable recipient key.
/// This type has no public constructor, clone, or deserializer.
pub struct PendingRecipient {
    recipient: VerifiedRecipient,
    checkpoint: Checkpoint,
    checkpoint_json: String,
    previous_checkpoint_json: Option<String>,
}

/// Opaque capability activated only by [`Verifier::commit`].
/// It cannot be constructed, cloned, deserialized, or restored from a summary.
pub struct VerifiedRecipient {
    instance: [u8; 32],
    generation: u64,
    summary: VerificationSummary,
    monotonic_deadline: u64,
}

/// Non-secret diagnostics, never accepted as an authorization token.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationSummary {
    /// Expected logical service from independently provisioned policy.
    pub service: String,
    /// Authorized transport-specific key profile.
    pub profile: RecipientProfile,
    /// Attested key identifier scoped to the service and keyset.
    pub key_id: String,
    /// SHA-256 of the exact evidence document supplied to the verifier.
    pub evidence_sha256: String,
    /// SHA-256 of the trusted configuration used for this verification.
    pub trust_config_sha256: String,
    /// Authorized policy sequence.
    pub policy_sequence: u64,
    /// Authorized release sequence.
    pub release_sequence: u64,
    /// SHA-256 of the exact signed release manifest.
    pub release_sha256: String,
    /// Time at which all evidence was appraised.
    pub verified_at: u64,
    /// Exclusive wall-clock expiry, also constrained by a monotonic deadline.
    pub expires_at: u64,
}

impl Verifier {
    /// Load application-provisioned trust and a protected persisted checkpoint.
    ///
    /// Trust must come from authenticated application delivery, not the evidence
    /// endpoint. `None` is for first install; clearing stored state discards the
    /// additional locally observed rollback floor.
    ///
    /// # Errors
    /// Rejects invalid policy/state, root digest mismatch, expired trust, clock
    /// rollback, or unavailable secure randomness.
    pub fn new(
        config: &[u8],
        sigstore_roots: &[u8],
        checkpoint: Option<&[u8]>,
        now: Clock,
    ) -> Result<Self> {
        let trust = policy::Trust::new(config, sigstore_roots)?;
        let persisted = checkpoint;
        let checkpoint = match persisted {
            Some(bytes) => trust.read_checkpoint(bytes)?,
            None => trust.initial_checkpoint(),
        };
        let persisted_checkpoint_json = persisted
            .map(|bytes| {
                std::str::from_utf8(bytes)
                    .map(str::to_owned)
                    .map_err(|_| Error::Encoding)
            })
            .transpose()?;
        if now.unix_seconds < checkpoint.trusted_time {
            return Err(Error::Clock);
        }
        if now.unix_seconds < trust.config.not_before || now.unix_seconds >= trust.config.not_after
        {
            return Err(Error::Expired);
        }
        let mut instance = [0; 32];
        getrandom::getrandom(&mut instance).map_err(|_| Error::Entropy)?;
        Ok(Self {
            trust,
            checkpoint,
            persisted_checkpoint_json,
            policy: None,
            pending_policy: None,
            instance,
            generation: 0,
            last_clock: now,
            challenge: None,
            pending_checkpoint: None,
            ready: false,
        })
    }

    /// Authenticate a signed policy wrapper (`artifact`, `bundle`) without a quote.
    /// Immediately invalidates old handles and retains the observed policy floor.
    /// Persist and acknowledge the returned checkpoint before starting a challenge.
    ///
    /// # Errors
    /// Rejects malformed, unauthenticated, expired, conflicting or older policy.
    pub fn verify_policy(&mut self, signed_policy: &[u8], now: Clock) -> Result<PendingPolicy> {
        self.observe_clock(now)?;
        let signed: model::SignedArtifact = encoding::parse(signed_policy, encoding::MAX_DOCUMENT)?;
        let policy = self
            .trust
            .verify_policy(&signed, &self.checkpoint, now.unix_seconds)?;
        self.stage_policy(policy, now)?;
        self.pending_policy().ok_or(Error::State)
    }

    /// Recover a pending policy write after evidence rejection or a dropped handle.
    /// Repeated handles refer to the same single-use update, not new authority.
    #[must_use]
    pub fn pending_policy(&self) -> Option<PendingPolicy> {
        self.pending_policy.as_ref().map(|pending| PendingPolicy {
            instance: pending.instance,
            generation: pending.generation,
            checkpoint_json: pending.checkpoint_json.clone(),
            previous_checkpoint_json: pending.previous_checkpoint_json.clone(),
        })
    }

    /// Acknowledge a durable policy checkpoint without activating a recipient.
    /// An expired policy can still record its rollback floor; fresh verification
    /// is required before a recipient can be accepted. Failed acknowledgement
    /// retains the pending update and blocks recipient use.
    ///
    /// # Errors
    /// Rejects stale/foreign handles, wrong persisted bytes, or invalid clocks.
    pub fn commit_policy(
        &mut self,
        pending: PendingPolicy,
        persisted_checkpoint: &[u8],
        now: Clock,
    ) -> Result<()> {
        self.observe_clock(now)?;
        let current = self.pending_policy.as_ref().ok_or(Error::State)?;
        if pending.instance != self.instance
            || pending.generation != current.generation
            || pending.checkpoint_json != current.checkpoint_json
            || persisted_checkpoint != current.checkpoint_json.as_bytes()
        {
            return Err(Error::State);
        }
        self.persisted_checkpoint_json = Some(pending.checkpoint_json);
        self.pending_policy = None;
        Ok(())
    }

    fn stage_policy(&mut self, policy: policy::AuthenticatedPolicy, now: Clock) -> Result<()> {
        self.invalidate();
        self.generation = self.generation.checked_add(1).ok_or(Error::State)?;
        let mut monotonic_deadline = now.monotonic_millis.saturating_add(
            policy
                .deadline
                .checked_sub(now.unix_seconds)
                .ok_or(Error::Expired)?
                .checked_mul(1000)
                .ok_or(Error::Expired)?,
        );
        if let Some(previous) = &self.policy
            && previous.authenticated.checkpoint.policy_digest == policy.checkpoint.policy_digest
        {
            // Replaying the same signed policy cannot renew its monotonic
            // lifetime while the host wall clock is stalled.
            monotonic_deadline = monotonic_deadline.min(previous.monotonic_deadline);
        }
        let checkpoint_json =
            serde_json::to_string(&policy.checkpoint).map_err(|_| Error::State)?;
        self.checkpoint = policy.checkpoint.clone();
        self.policy = Some(ActivePolicy {
            authenticated: policy,
            monotonic_deadline,
        });
        self.pending_policy = Some(PendingPolicy {
            instance: self.instance,
            generation: self.generation,
            checkpoint_json,
            previous_checkpoint_json: self.persisted_checkpoint_json.clone(),
        });
        Ok(())
    }

    fn current_policy(&self, now: Clock) -> Result<&ActivePolicy> {
        if self.pending_policy.is_some() {
            return Err(Error::PolicyPending);
        }
        let policy = self.policy.as_ref().ok_or(Error::State)?;
        if now.unix_seconds >= policy.authenticated.deadline
            || now.monotonic_millis >= policy.monotonic_deadline
        {
            return Err(Error::Expired);
        }
        Ok(policy)
    }

    /// Generate a single-use nonce for `/v1/aci/attestation?nonce=<hex>`.
    /// Invalidates all previous recipient handles from this verifier.
    ///
    /// # Errors
    /// Rejects clock rollback, expired trust, exhausted counters, or failed entropy.
    pub fn begin(&mut self, now: Clock) -> Result<String> {
        self.invalidate();
        self.observe_clock(now)?;
        self.current_policy(now)?;
        self.generation = self.generation.checked_add(1).ok_or(Error::State)?;
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Entropy)?;
        self.challenge = Some(Challenge {
            nonce,
            started: now,
        });
        Ok(hex::encode(nonce))
    }

    /// Validate complete evidence and prepare a persistence update.
    /// Every attempt consumes the challenge, including failed attempts.
    ///
    /// # Errors
    /// Rejects missing, malformed, stale, unauthorized, invalid, or mismatched
    /// evidence at the corresponding verification gate. No partial acceptance.
    pub fn verify(&mut self, evidence: &[u8], now: Clock) -> Result<PendingRecipient> {
        let challenge = self.challenge.take();
        self.ready = false;
        self.pending_checkpoint = None;
        let challenge = challenge.ok_or(Error::Challenge)?;
        self.observe_clock(now)?;
        // Authenticate policy before decoding recipient-specific evidence. A valid
        // newer revocation survives malformed quotes, collateral, or releases.
        let value: serde_json::Value = encoding::parse(evidence, encoding::MAX_DOCUMENT)?;
        let signed: model::SignedArtifact =
            serde_json::from_value(value.get("policy").ok_or(Error::Encoding)?.clone())
                .map_err(|_| Error::Encoding)?;
        let policy = self
            .trust
            .verify_policy(&signed, &self.checkpoint, now.unix_seconds)?;
        if policy.checkpoint.policy_digest != self.checkpoint.policy_digest || self.policy.is_none()
        {
            self.stage_policy(policy, now)?;
            return Err(Error::PolicyPending);
        }
        self.current_policy(now)?;
        let elapsed = now
            .monotonic_millis
            .checked_sub(challenge.started.monotonic_millis)
            .ok_or(Error::Clock)?;
        if elapsed >= self.trust.config.max_challenge_age_seconds * 1000
            || now
                .unix_seconds
                .saturating_sub(challenge.started.unix_seconds)
                >= self.trust.config.max_challenge_age_seconds
        {
            return Err(Error::Expired);
        }
        let decoded: model::Evidence =
            serde_json::from_value(value).map_err(|_| Error::Encoding)?;
        let result = self.verify_evidence(&decoded, evidence, now, challenge)?;
        self.pending_checkpoint = Some(encoding::digest(result.checkpoint_json.as_bytes()));
        Ok(result)
    }

    /// Acknowledge an atomic durable write of the pending checkpoint.
    ///
    /// Host storage must compare-and-swap `previous_checkpoint_json()` to
    /// `checkpoint_json()` before this call. Matching bytes acknowledge storage;
    /// they are not cryptographic proof that a write completed.
    ///
    /// # Errors
    /// Rejects wrong-instance, superseded, expired, or already consumed results,
    /// wrong persisted bytes, and clock rollback.
    pub fn commit(
        &mut self,
        pending: PendingRecipient,
        persisted_checkpoint: &[u8],
        now: Clock,
    ) -> Result<VerifiedRecipient> {
        self.observe_clock(now)?;
        self.ready = false;
        self.current_policy(now)?;
        let digest = encoding::digest(pending.checkpoint_json.as_bytes());
        if self.pending_checkpoint.take().as_deref() != Some(&digest)
            || persisted_checkpoint != pending.checkpoint_json.as_bytes()
            || pending.recipient.instance != self.instance
            || pending.recipient.generation != self.generation
        {
            return Err(Error::State);
        }
        pending.recipient.check_time(now)?;
        self.persisted_checkpoint_json = Some(pending.checkpoint_json);
        self.checkpoint = pending.checkpoint;
        self.ready = true;
        Ok(pending.recipient)
    }

    /// Recheck expiry and invalidation immediately before using a recipient key.
    ///
    /// # Errors
    /// Rejects uncommitted, revoked, superseded, wrong-instance, or expired handles.
    pub fn authorize(&mut self, recipient: &VerifiedRecipient, now: Clock) -> Result<()> {
        self.observe_clock(now)?;
        self.current_policy(now)?;
        if !self.ready
            || recipient.instance != self.instance
            || recipient.generation != self.generation
        {
            return Err(Error::State);
        }
        recipient.check_time(now)?;
        Ok(())
    }

    /// Revoke recipient capabilities. An observed policy update and its rollback
    /// floor survive invalidation; they must still be durably acknowledged.
    pub fn invalidate(&mut self) {
        self.ready = false;
        self.challenge = None;
        self.pending_checkpoint = None;
    }

    fn observe_clock(&mut self, now: Clock) -> Result<()> {
        if now.unix_seconds < self.last_clock.unix_seconds
            || now.monotonic_millis < self.last_clock.monotonic_millis
            || now.unix_seconds < self.checkpoint.trusted_time
        {
            self.invalidate();
            return Err(Error::Clock);
        }
        self.last_clock = now;
        if now.unix_seconds < self.trust.config.not_before
            || now.unix_seconds >= self.trust.config.not_after
        {
            self.invalidate();
            return Err(Error::Expired);
        }
        Ok(())
    }

    fn verify_evidence(
        &self,
        evidence: &model::Evidence,
        raw: &[u8],
        now: Clock,
        challenge: Challenge,
    ) -> Result<PendingRecipient> {
        if evidence.schema != 1 || evidence.report.attestation.tee_type != "tdx" {
            return Err(Error::Encoding);
        }
        let policy = self.current_policy(now)?;
        if encoding::digest(evidence.policy.artifact.as_bytes()) != self.checkpoint.policy_digest {
            return Err(Error::State);
        }
        let authorization = self.trust.authorize(
            &policy.authenticated,
            &evidence.release,
            &self.checkpoint,
            now.unix_seconds,
        )?;
        let manifest = &authorization.manifest;
        let nonce = hex::encode(challenge.nonce);
        let binding =
            validate_aci_report_binding(&evidence.report, Some(&nonce), now.unix_seconds, None)
                .map_err(|_| Error::Binding)?;
        if binding.keyset.subject.as_deref() != Some(&self.trust.config.workload_subject) {
            return Err(Error::Binding);
        }
        let key = select_recipient(&binding.keyset, manifest.recipient)?;
        let key_bytes = encoding::hex_array::<32>(&key.public_key_hex)?;
        validate_recipient_key(key_bytes)?;
        let platform = policy
            .authenticated
            .snapshot
            .platforms
            .iter()
            .find(|p| p.id == manifest.platform_id)
            .ok_or(Error::Platform)?;
        let app_evidence = &evidence.report.attestation.evidence;
        let quote_hex = app_evidence
            .get("quote")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Quote)?;
        let raw_quote = quote::decode_quote(quote_hex)?;
        let quote = quote::verify(&raw_quote, &evidence.collateral, platform, now.unix_seconds)?;
        aci_verify::quote::quote_binds_report_data(
            app_evidence,
            &quote.report.report_data,
            binding.report_data,
        )
        .map_err(|_| Error::Binding)?;
        measurement::verify(
            app_evidence,
            &quote.report.rt_mr3,
            &manifest.app_id,
            &manifest.compose_sha256,
        )?;
        measurement::containers(app_evidence, &manifest.containers)?;
        let kms = policy
            .authenticated
            .snapshot
            .kms
            .iter()
            .find(|k| k.id == manifest.kms_id)
            .ok_or(Error::Custody)?;
        let kms_platform = policy
            .authenticated
            .snapshot
            .platforms
            .iter()
            .find(|p| p.id == kms.platform_id)
            .ok_or(Error::Platform)?;
        let kms_expiry =
            custody::verify_bootstrap(&evidence.kms, kms, kms_platform, now.unix_seconds)?;
        custody::verify_keys(
            app_evidence,
            &binding.keyset,
            &manifest.app_id,
            &kms.root_public_key,
            manifest.recipient,
            &key.public_key_hex,
        )?;
        let recipient = RecipientData {
            id: key.key_id.clone(),
            not_after: quote
                .expires_at
                .min(kms_expiry)
                .min(binding.keyset.not_after),
        };
        self.prepare_result(raw, now, challenge, authorization, recipient)
    }

    fn prepare_result(
        &self,
        raw: &[u8],
        now: Clock,
        challenge: Challenge,
        authorization: policy::Authorization,
        key: RecipientData,
    ) -> Result<PendingRecipient> {
        let manifest = &authorization.manifest;
        let expires_at = authorization.deadline.min(key.not_after).min(
            challenge
                .started
                .unix_seconds
                .checked_add(self.trust.config.max_recipient_age_seconds)
                .ok_or(Error::Expired)?,
        );
        let remaining = expires_at
            .checked_sub(now.unix_seconds)
            .filter(|seconds| *seconds > 0)
            .ok_or(Error::Expired)?;
        let monotonic_deadline = now
            .monotonic_millis
            .checked_add(remaining.checked_mul(1000).ok_or(Error::Expired)?)
            .ok_or(Error::Expired)?
            .min(
                challenge
                    .started
                    .monotonic_millis
                    .checked_add(self.trust.config.max_recipient_age_seconds * 1000)
                    .ok_or(Error::Expired)?,
            );
        let summary = VerificationSummary {
            service: manifest.service.clone(),
            profile: manifest.recipient,
            key_id: key.id,
            evidence_sha256: encoding::digest(raw),
            trust_config_sha256: self.trust.identity.clone(),
            policy_sequence: authorization.checkpoint.policy_sequence,
            release_sequence: manifest.sequence,
            release_sha256: authorization.checkpoint.release_digest.clone(),
            verified_at: now.unix_seconds,
            expires_at,
        };
        let recipient = VerifiedRecipient {
            instance: self.instance,
            generation: self.generation,
            summary,
            monotonic_deadline,
        };
        recipient.check_time(now)?;
        let checkpoint_json =
            serde_json::to_string(&authorization.checkpoint).map_err(|_| Error::State)?;
        let previous_checkpoint_json = self.persisted_checkpoint_json.clone();
        Ok(PendingRecipient {
            recipient,
            checkpoint: authorization.checkpoint,
            checkpoint_json,
            previous_checkpoint_json,
        })
    }
}

fn select_recipient(
    keyset: &aci_protocol::types::WorkloadKeyset,
    profile: RecipientProfile,
) -> Result<&aci_protocol::types::KeyedPublicKey> {
    if keyset.receipt_signing_keys.len() != 1
        || keyset.e2ee_public_keys.len() != 1
        || keyset.tls_public_keys.len() > 16
    {
        return Err(Error::Binding);
    }
    let receipt = keyset.receipt_signing_keys.first().ok_or(Error::Binding)?;
    if receipt.algo != "ed25519" {
        return Err(Error::Binding);
    }
    validate_recipient_key(encoding::hex_array::<32>(&receipt.public_key_hex)?)?;
    let mut ids = BTreeSet::new();
    let mut materials = BTreeSet::new();
    for key in keyset
        .receipt_signing_keys
        .iter()
        .chain(&keyset.e2ee_public_keys)
    {
        encoding::text(&key.key_id, 128)?;
        if ![64, 66, 130].contains(&key.public_key_hex.len())
            || !key
                .public_key_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::Binding);
        }
        if !ids.insert(&key.key_id) || !materials.insert(&key.public_key_hex) {
            return Err(Error::Binding);
        }
    }
    let mut matching = keyset
        .e2ee_public_keys
        .iter()
        .filter(|key| key.algo == profile.algorithm());
    let key = matching.next().ok_or(Error::Binding)?;
    if matching.next().is_some() {
        return Err(Error::Binding);
    }
    Ok(key)
}

impl PendingPolicy {
    /// Exact policy checkpoint to persist with atomic compare-and-swap.
    #[must_use]
    pub fn checkpoint_json(&self) -> &str {
        &self.checkpoint_json
    }

    /// Exact previous stored bytes, or absence on first use.
    #[must_use]
    pub fn previous_checkpoint_json(&self) -> Option<&str> {
        self.previous_checkpoint_json.as_deref()
    }
}

impl PendingRecipient {
    /// Exact new checkpoint to write durably with compare-and-swap.
    #[must_use]
    pub fn checkpoint_json(&self) -> &str {
        &self.checkpoint_json
    }

    /// Expected old record; `None` means absent on first use.
    #[must_use]
    pub fn previous_checkpoint_json(&self) -> Option<&str> {
        self.previous_checkpoint_json.as_deref()
    }
}

impl VerifiedRecipient {
    /// Diagnostics; use `Verifier::authorize` to check current validity.
    #[must_use]
    pub fn summary(&self) -> &VerificationSummary {
        &self.summary
    }

    fn check_time(&self, now: Clock) -> Result<()> {
        if now.unix_seconds < self.summary.verified_at
            || now.unix_seconds >= self.summary.expires_at
            || now.monotonic_millis >= self.monotonic_deadline
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

struct RecipientData {
    id: String,
    not_after: u64,
}

fn validate_recipient_key(key_bytes: [u8; 32]) -> Result<()> {
    let signing_key =
        ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|_| Error::Binding)?;
    if signing_key.is_weak() {
        return Err(Error::Binding);
    }
    Ok(())
}
