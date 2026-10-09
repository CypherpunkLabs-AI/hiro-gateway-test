//! dstack keys, evidence assembly and upstream hardware acceptance.
pub mod bootstrap;
pub mod evidence;
pub mod gate;
pub mod keys;
mod kms;
pub mod provisioning;
pub mod snapshot;
mod upstream;
pub mod worker;
pub use upstream::{
    InferenceVerifier, VerificationRequest, VerifiedUpstream, verify_before_listening,
};

pub(crate) mod verification;
