//! Bounded, expiring in-memory receipt and upstream-session storage.
//! Durable application repositories belong here when the backend is ported.
pub(crate) mod completions;
pub(crate) mod quota;
