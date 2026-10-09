//! Proxy evidence appraisal: signed authorization, TDX measurements, custody,
//! challenge freshness and durable rollback floors. No client transport or
//! inference receipt-audit API is included.
#![forbid(unsafe_code)]

#[cfg(target_endian = "big")]
compile_error!("the pinned dstack event-log verifier requires little-endian targets");

mod custody;
mod encoding;
mod error;
mod measurement;
mod model;
mod policy;
mod quote;
mod session;

use error::{Error, Result};
use model::RecipientProfile;
use policy::Checkpoint;
pub(crate) use session::{Clock, Verifier};
