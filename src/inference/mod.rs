//! Verified inference forwarding and attested TLS enforcement.
pub(crate) mod tls;
pub mod upstream;
pub mod config;
pub(crate) mod error;
pub(crate) mod request;
pub(crate) mod rate_limit;
pub(crate) mod stream;
pub(crate) mod usage;
pub(crate) use stream::UsageMetrics;
pub const GLM_MODEL: &str = "z-ai/glm-5.3-flash";
pub const KIMI_MODEL: &str = "moonshotai/kimi-k3";
