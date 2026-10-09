//! Ephemeral guest identity, direct TDX evidence, and verified remote inference.
pub mod evidence;
pub mod keys;
pub mod tdx;
mod upstream;
pub use upstream::{InferenceVerifier, VerificationRequest, VerifiedUpstream};
