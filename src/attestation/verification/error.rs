//! Stable failures without evidence, key material, or upstream error strings.

/// A failed verification never produces a recipient capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A platform cryptographic random source is unavailable.
    #[error("secure randomness unavailable")]
    Entropy,
    /// Input exceeds the supported resource budget.
    #[error("verification input exceeds resource limits")]
    Limit,
    /// Invalid encoding, duplicate field, or unsupported schema.
    #[error("invalid or unsupported evidence encoding")]
    Encoding,
    /// The application supplied an incomplete or inconsistent trust policy.
    #[error("invalid trusted policy")]
    Policy,
    /// An authenticated policy update must be persisted before recipient use.
    #[error("authenticated policy update requires durable acknowledgement")]
    PolicyPending,
    /// A release or policy artifact failed Sigstore verification.
    #[error("release signature or publisher identity rejected")]
    Signature,
    /// An artifact is not currently authorized.
    #[error("release is not authorized by the current policy")]
    Release,
    /// Metadata is older than the trusted floor or conflicts at the same version.
    #[error("rollback or conflicting metadata rejected")]
    Rollback,
    /// Evidence, policy, challenge, or key is no longer valid.
    #[error("verification has expired or is not yet valid")]
    Expired,
    /// The supplied clock moved backwards.
    #[error("clock rollback rejected")]
    Clock,
    /// Challenge is absent, reused, mismatched, or already consumed.
    #[error("fresh verification challenge required")]
    Challenge,
    /// Intel certificate, revocation, collateral, or quote verification failed.
    #[error("Intel TDX quote verification failed")]
    Quote,
    /// An authentic quote does not satisfy the accepted platform profile.
    #[error("platform security policy rejected the quote")]
    Platform,
    /// Measured application identity, composition, or event log does not match.
    #[error("application measurements rejected")]
    Measurement,
    /// Recipient key, role, service, or nonce does not match the quote.
    #[error("attested recipient binding rejected")]
    Binding,
    /// KMS bootstrap evidence or key derivation chain was rejected.
    #[error("key custody verification failed")]
    Custody,
    /// Persistent metadata has not been acknowledged or the handle is stale.
    #[error("verification state is uncommitted or invalidated")]
    State,
}

/// Result used throughout the verifier and proxy evidence collection.
pub type Result<T> = core::result::Result<T, Error>;
