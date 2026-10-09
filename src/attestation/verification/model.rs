//! Versioned evidence and signed metadata. These are untrusted wire types.

use std::collections::BTreeMap;

use aci_protocol::types::AttestationReport;
use dcap_qvl::QuoteCollateralV3;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Evidence {
    pub schema: u32,
    pub report: AttestationReport,
    pub collateral: QuoteCollateralV3,
    pub release: SignedArtifact,
    pub policy: SignedArtifact,
    pub kms: KmsEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedArtifact {
    // Preserve the exact artifact bytes authenticated by the Sigstore subject.
    pub artifact: String,
    pub bundle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub schema: u32,
    pub policy_id: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub minimum_release_sequence: u64,
    pub approved_releases: Vec<String>,
    pub revoked_releases: Vec<String>,
    pub platforms: Vec<PlatformProfile>,
    pub kms: Vec<KmsApproval>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Release {
    pub schema: u32,
    pub service: String,
    pub sequence: u64,
    pub tag: String,
    pub source_commit: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub app_id: String,
    pub compose_sha256: String,
    pub platform_id: String,
    pub kms_id: String,
    pub recipient: RecipientProfile,
    pub containers: BTreeMap<String, String>,
}

/// Attested key use. This identifies a key; it does not implement a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
pub enum RecipientProfile {
    /// Dedicated Ed25519 key authenticating an Oak Session handshake.
    #[serde(rename = "oak-session-v1-ed25519")]
    OakSessionV1Ed25519,
}

impl RecipientProfile {
    pub(crate) const fn algorithm(self) -> &'static str {
        match self {
            Self::OakSessionV1Ed25519 => "oak-session-v1-ed25519",
        }
    }
    pub(crate) const fn purpose(self) -> &'static str {
        match self {
            Self::OakSessionV1Ed25519 => "oak.session.binding.ed25519.v1",
        }
    }
    pub(crate) const fn role(self) -> &'static str {
        match self {
            Self::OakSessionV1Ed25519 => "oak-session-binding",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlatformProfile {
    pub id: String,
    pub mr_td: String,
    pub rt_mr0: String,
    pub rt_mr1: String,
    pub rt_mr2: String,
    pub mr_seam: String,
    pub mr_signer_seam: String,
    pub mr_config_id: String,
    pub mr_owner: String,
    pub mr_owner_config: String,
    pub td_attributes: String,
    pub seam_attributes: String,
    pub xfam: String,
    pub minimum_tee_tcb_svn: String,
    pub minimum_tcb_evaluation: u32,
    pub allowed_advisories: Vec<String>,
    pub allow_smt: bool,
    pub allow_dynamic_platform: bool,
    pub allow_cached_keys: bool,
    // A reviewed machine set is mandatory, not an optional evidence hint.
    pub accepted_ppid_sha256: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KmsApproval {
    pub id: String,
    pub root_public_key: String,
    pub ca_public_key_sha256: String,
    pub app_id: String,
    pub compose_sha256: String,
    pub platform_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KmsEvidence {
    pub quote: String,
    pub event_log: String,
    pub collateral: QuoteCollateralV3,
    pub ca_public_key: String,
    pub root_public_key: String,
}
