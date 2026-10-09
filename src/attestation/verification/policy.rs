//! Application-provisioned trust, signed authorization, and rollback state.

use std::collections::BTreeSet;

use attestation_verify::{
    CheckpointOriginPolicy, CommitSha, GithubPolicy, RefPolicy, RepositoryIdentity, SignerPolicy,
    SourcePolicy, TrustStore, WorkflowPath, WorkflowRevisionPolicy,
};
use serde::{Deserialize, Serialize};

use super::{
    Error, Result, encoding,
    model::{RecipientProfile, Release, SignedArtifact, Snapshot},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustConfig {
    pub schema: u32,
    pub policy_id: String,
    pub service: String,
    pub workload_subject: String,
    pub recipient: RecipientProfile,
    pub trust_root_sha256: String,
    pub minimum_policy_sequence: u64,
    pub minimum_release_sequence: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub max_policy_age_seconds: u64,
    pub max_challenge_age_seconds: u64,
    pub max_recipient_age_seconds: u64,
    pub policy_ref: String,
    pub policy_publisher: Publisher,
    pub release_publisher: Publisher,
    pub checkpoint_origins: Vec<LogOrigin>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Publisher {
    pub repository: String,
    pub owner_id: u64,
    pub repository_id: u64,
    pub workflow: String,
    pub workflow_commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogOrigin {
    pub log_id: String,
    pub origin: String,
}

/// Non-secret state the host must persist atomically in protected storage.
/// This is a rollback floor, never a substitute for evidence verification.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub(crate) schema: u32,
    pub(crate) policy_id: String,
    pub(crate) policy_sequence: u64,
    pub(crate) policy_digest: String,
    pub(crate) release_sequence: u64,
    pub(crate) release_digest: String,
    // Older checkpoints lack this field; their accepted-release floor survives.
    #[serde(default)]
    pub(crate) minimum_release_sequence: u64,
    pub(crate) trusted_time: u64,
}

pub(crate) struct Trust {
    pub config: TrustConfig,
    pub identity: String,
    roots: TrustStore,
    origins: CheckpointOriginPolicy,
}

impl Trust {
    pub fn new(config_bytes: &[u8], root_bytes: &[u8]) -> Result<Self> {
        if root_bytes.len() > 256 * 1024 {
            return Err(Error::Limit);
        }
        let config: TrustConfig = encoding::parse(config_bytes, 64 * 1024)?;
        if config.schema != 1
            || encoding::digest(root_bytes) != config.trust_root_sha256
            || config.minimum_policy_sequence == 0
            || config.minimum_release_sequence == 0
            || config.not_before >= config.not_after
            || !(1..=604_800).contains(&config.max_policy_age_seconds)
            || !(1..=120).contains(&config.max_challenge_age_seconds)
            || !(1..=300).contains(&config.max_recipient_age_seconds)
            || config.checkpoint_origins.is_empty()
            || config.checkpoint_origins.len() > 16
        {
            return Err(Error::Policy);
        }
        encoding::text(&config.policy_id, 128)?;
        encoding::text(&config.service, 256)?;
        encoding::text(&config.workload_subject, 256)?;
        encoding::text(&config.policy_ref, 256)?;
        if !config.policy_ref.starts_with("refs/heads/") {
            return Err(Error::Policy);
        }
        encoding::parse::<serde_json::Value>(root_bytes, 256 * 1024)?;
        let roots = TrustStore::from_json(root_bytes).map_err(|_| Error::Policy)?;
        let mut origins = CheckpointOriginPolicy::builder();
        for binding in &config.checkpoint_origins {
            let id = encoding::hex_array::<32>(&binding.log_id)?;
            encoding::text(&binding.origin, 256)?;
            let log = roots
                .tlogs
                .iter()
                .find(|log| log.log_id_key_id == id)
                .ok_or(Error::Policy)?;
            origins = origins
                .allow_origin(log, &binding.origin)
                .map_err(|_| Error::Policy)?;
        }
        let origins = origins.build().map_err(|_| Error::Policy)?;
        config.policy_publisher.policy(&config.policy_ref, None)?;
        config
            .release_publisher
            .policy("refs/tags/config-validation", None)?;
        Ok(Self {
            identity: encoding::digest(config_bytes),
            config,
            roots,
            origins,
        })
    }

    pub fn initial_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            schema: 1,
            policy_id: self.config.policy_id.clone(),
            policy_sequence: 0,
            policy_digest: String::new(),
            release_sequence: 0,
            release_digest: String::new(),
            minimum_release_sequence: self.config.minimum_release_sequence,
            trusted_time: self.config.not_before,
        }
    }

    pub fn read_checkpoint(&self, bytes: &[u8]) -> Result<Checkpoint> {
        let state: Checkpoint = encoding::parse(bytes, 4096)?;
        if state.schema != 1
            || state.policy_id != self.config.policy_id
            || state.policy_sequence == 0
            || (state.release_sequence == 0 && !state.release_digest.is_empty())
        {
            return Err(Error::State);
        }
        encoding::hex_array::<32>(&state.policy_digest)?;
        if state.release_sequence != 0 {
            encoding::hex_array::<32>(&state.release_digest)?;
        }
        Ok(state)
    }

    pub fn authenticate(
        &self,
        artifact: &SignedArtifact,
        publisher: &Publisher,
        source_ref: &str,
        commit: Option<&str>,
    ) -> Result<u64> {
        if artifact.artifact.len() > 256 * 1024 || artifact.bundle.len() > 1024 * 1024 {
            return Err(Error::Limit);
        }
        // The dependency also rejects duplicate JSON fields inside base64 payloads.
        let bundle = attestation_verify::Bundle::from_json(artifact.bundle.as_bytes())
            .map_err(|_| Error::Signature)?;
        let verifier = attestation_verify::Verifier::builder()
            .trust_store(self.roots.clone())
            .github_policy(publisher.policy(source_ref, commit)?)
            .checkpoint_origin_policy(self.origins.clone())
            .build()
            .map_err(|_| Error::Policy)?;
        let attestation = verifier
            .verify_bytes(artifact.artifact.as_bytes(), &bundle)
            .map_err(|_| Error::Signature)?;
        Ok(attestation.transparency.integrated_time)
    }

    pub fn verify_policy(
        &self,
        policy: &SignedArtifact,
        previous: &Checkpoint,
        now: u64,
    ) -> Result<AuthenticatedPolicy> {
        let cfg = &self.config;
        if now < cfg.not_before || now >= cfg.not_after {
            return Err(Error::Expired);
        }
        if now < previous.trusted_time {
            return Err(Error::Clock);
        }
        let integrated = self.authenticate(policy, &cfg.policy_publisher, &cfg.policy_ref, None)?;
        let snapshot: Snapshot = encoding::parse(policy.artifact.as_bytes(), 256 * 1024)?;
        let policy_digest = encoding::digest(policy.artifact.as_bytes());
        validate_snapshot(&snapshot, cfg, integrated, now)?;
        check_version(
            snapshot.sequence,
            &policy_digest,
            cfg.minimum_policy_sequence.max(previous.policy_sequence),
            &previous.policy_digest,
            previous.policy_sequence,
        )?;
        let deadline = snapshot.expires_at.min(cfg.not_after).min(
            integrated
                .checked_add(cfg.max_policy_age_seconds)
                .ok_or(Error::Expired)?,
        );
        let checkpoint = Checkpoint {
            policy_sequence: snapshot.sequence,
            policy_digest,
            minimum_release_sequence: previous
                .minimum_release_sequence
                .max(cfg.minimum_release_sequence)
                .max(snapshot.minimum_release_sequence),
            trusted_time: now,
            ..previous.clone()
        };
        Ok(AuthenticatedPolicy {
            snapshot,
            checkpoint,
            deadline,
        })
    }

    pub fn authorize(
        &self,
        policy: &AuthenticatedPolicy,
        release: &SignedArtifact,
        previous: &Checkpoint,
        now: u64,
    ) -> Result<Authorization> {
        let cfg = &self.config;
        let snapshot = &policy.snapshot;
        if now >= policy.deadline || now < previous.trusted_time {
            return Err(Error::Expired);
        }
        if snapshot.sequence != previous.policy_sequence
            || policy.checkpoint.policy_digest != previous.policy_digest
        {
            return Err(Error::State);
        }
        let release_digest = encoding::digest(release.artifact.as_bytes());
        if !snapshot.approved_releases.contains(&release_digest)
            || snapshot.revoked_releases.contains(&release_digest)
        {
            return Err(Error::Release);
        }
        let manifest: Release = encoding::parse(release.artifact.as_bytes(), 256 * 1024)?;
        encoding::hex_array::<20>(&manifest.source_commit)?;
        encoding::text(&manifest.tag, 128)?;
        if !manifest
            .tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
            || manifest.tag.contains("..")
        {
            return Err(Error::Release);
        }
        let logged = self.authenticate(
            release,
            &cfg.release_publisher,
            &format!("refs/tags/{}", manifest.tag),
            Some(&manifest.source_commit),
        )?;
        if manifest.schema != 1
            || manifest.service != cfg.service
            || manifest.recipient != cfg.recipient
        {
            return Err(Error::Release);
        }
        if logged > now
            || manifest.issued_at > logged
            || manifest.expires_at <= now
            || manifest.expires_at <= manifest.issued_at
        {
            return Err(Error::Expired);
        }
        check_version(
            manifest.sequence,
            &release_digest,
            cfg.minimum_release_sequence
                .max(snapshot.minimum_release_sequence)
                .max(previous.minimum_release_sequence)
                .max(previous.release_sequence),
            &previous.release_digest,
            previous.release_sequence,
        )?;
        encoding::hex_array::<20>(&manifest.app_id)?;
        encoding::hex_array::<32>(&manifest.compose_sha256)?;
        if manifest.containers.is_empty() || manifest.containers.len() > 64 {
            return Err(Error::Release);
        }
        for (name, image) in &manifest.containers {
            encoding::text(name, 128)?;
            encoding::text(image, 512)?;
            let (repository, digest) = image.rsplit_once("@sha256:").ok_or(Error::Release)?;
            if repository.is_empty() || repository.contains('@') {
                return Err(Error::Release);
            }
            encoding::hex_array::<32>(digest)?;
        }
        let deadline = policy.deadline.min(manifest.expires_at);
        let checkpoint = Checkpoint {
            release_sequence: manifest.sequence,
            release_digest,
            trusted_time: now,
            ..previous.clone()
        };
        Ok(Authorization {
            manifest,
            checkpoint,
            deadline,
        })
    }
}

impl Publisher {
    fn policy(&self, git_ref: &str, commit: Option<&str>) -> Result<GithubPolicy> {
        encoding::hex_array::<20>(&self.workflow_commit)?;
        if self.owner_id == 0
            || self.repository_id == 0
            || !self.workflow.starts_with(".github/workflows/")
            || self.workflow.contains("..")
        {
            return Err(Error::Policy);
        }
        let repository = RepositoryIdentity::parse(&self.repository).map_err(|_| Error::Policy)?;
        GithubPolicy::builder()
            .source(SourcePolicy {
                repository: repository
                    .clone()
                    .with_owner_id(self.owner_id)
                    .with_repository_id(self.repository_id),
                git_ref: RefPolicy::Exact(git_ref.to_owned()),
                commit: commit
                    .map(CommitSha::new)
                    .transpose()
                    .map_err(|_| Error::Policy)?,
            })
            .signer(SignerPolicy {
                // Fulcio authenticates numeric IDs for the source repository,
                // not the signer. This backend rejects unenforceable signer IDs.
                repository,
                path: WorkflowPath::new(&self.workflow).map_err(|_| Error::Policy)?,
                revision: WorkflowRevisionPolicy::Sha(
                    CommitSha::new(&self.workflow_commit).map_err(|_| Error::Policy)?,
                ),
            })
            .build()
            .map_err(|_| Error::Policy)
    }
}

pub(crate) struct AuthenticatedPolicy {
    pub snapshot: Snapshot,
    pub checkpoint: Checkpoint,
    pub deadline: u64,
}

pub(crate) struct Authorization {
    pub manifest: Release,
    pub checkpoint: Checkpoint,
    pub deadline: u64,
}

fn check_version(
    version: u64,
    digest: &str,
    floor: u64,
    previous_digest: &str,
    previous_version: u64,
) -> Result<()> {
    if version < floor || (version == previous_version && digest != previous_digest) {
        return Err(Error::Rollback);
    }
    Ok(())
}

fn bounded_unique(values: &[String], max: usize) -> Result<()> {
    if values.len() > max || values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(Error::Policy);
    }
    Ok(())
}

fn unique_names<'a>(values: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        encoding::text(value, 128)?;
        if !seen.insert(value) {
            return Err(Error::Policy);
        }
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &Snapshot,
    cfg: &TrustConfig,
    integrated: u64,
    now: u64,
) -> Result<()> {
    if integrated > now
        || now.saturating_sub(integrated) >= cfg.max_policy_age_seconds
        || snapshot.issued_at > integrated
        || snapshot.expires_at <= now
        || snapshot.expires_at <= snapshot.issued_at
        || snapshot.expires_at - snapshot.issued_at > cfg.max_policy_age_seconds
    {
        return Err(Error::Expired);
    }
    if snapshot.schema != 1
        || snapshot.policy_id != cfg.policy_id
        || snapshot.minimum_release_sequence == 0
    {
        return Err(Error::Policy);
    }
    bounded_unique(&snapshot.approved_releases, 256)?;
    bounded_unique(&snapshot.revoked_releases, 256)?;
    for digest in snapshot
        .approved_releases
        .iter()
        .chain(&snapshot.revoked_releases)
    {
        encoding::hex_array::<32>(digest)?;
    }
    if snapshot.platforms.len() > 32 || snapshot.kms.len() > 16 {
        return Err(Error::Policy);
    }
    unique_names(snapshot.platforms.iter().map(|p| p.id.as_str()))?;
    unique_names(snapshot.kms.iter().map(|p| p.id.as_str()))?;
    for profile in &snapshot.platforms {
        super::quote::validate_profile(profile)?;
    }
    for kms in &snapshot.kms {
        let root = encoding::hex_array::<33>(&kms.root_public_key)?;
        evidence_k256::ecdsa::VerifyingKey::from_sec1_bytes(&root).map_err(|_| Error::Policy)?;
        encoding::hex_array::<32>(&kms.ca_public_key_sha256)?;
        encoding::hex_array::<20>(&kms.app_id)?;
        encoding::hex_array::<32>(&kms.compose_sha256)?;
        if !snapshot
            .platforms
            .iter()
            .any(|profile| profile.id == kms.platform_id)
        {
            return Err(Error::Policy);
        }
    }
    Ok(())
}
