//! Independent proxy-side verification; a worker-written file is never authority.
use super::snapshot::{Authority, MAX_DOCUMENT, Metadata, Validity, read_bounded};
use crate::services::inference::Service;
use anyhow::Context;
use serde_json::Value;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{sync::RwLock, task::JoinHandle};

#[derive(Clone, Default)]
pub struct Gate(Arc<RwLock<Option<(Metadata, Validity)>>>);
impl Gate {
    /// Read independently verified evidence that is still current.
    ///
    /// # Errors
    /// Returns an error when evidence is absent or expired.
    pub async fn metadata(&self) -> anyhow::Result<Metadata> {
        let current = self.0.read().await;
        let (metadata, validity) = current.as_ref().context("evidence not ready")?;
        anyhow::ensure!(validity.is_current(), "evidence expired");
        Ok(metadata.clone())
    }
    pub async fn ready(&self) -> bool {
        self.0
            .read()
            .await
            .as_ref()
            .is_some_and(|(_, validity)| validity.is_current())
    }

    pub fn start(
        path: PathBuf,
        mut authority: Authority,
        service: Arc<Service>,
    ) -> (Self, JoinHandle<()>) {
        let gate = Self::default();
        let state = gate.clone();
        let task = tokio::spawn(async move {
            let mut last_bytes = Vec::new();
            let mut last_policy = Vec::new();
            loop {
                let path_copy = path.clone();
                let revision = authority.revision;
                let result = async {
                    let (metadata_bytes, policy_bytes) = tokio::task::spawn_blocking(move || {
                        // Read policy first, even if no complete snapshot has been published.
                        let policy_path = path_copy.with_file_name("policy.json");
                        let policy = match read_bounded(&policy_path, MAX_DOCUMENT) {
                            Ok(bytes) => Some(bytes),
                            Err(e)
                                if e.downcast_ref::<std::io::Error>().is_some_and(|io| {
                                    io.kind() == std::io::ErrorKind::NotFound
                                }) =>
                            {
                                None
                            }
                            Err(e) => return Err(e),
                        };
                        Ok::<_, anyhow::Error>((read_bounded(&path_copy, MAX_DOCUMENT), policy))
                    })
                    .await??;
                    // A fresh signed revocation must be adopted even when snapshot reading fails.
                    let mut nonce = None;
                    if let Some(bytes) = &policy_bytes
                        && bytes != &last_policy
                    {
                        nonce = Some(authority.begin(&serde_json::from_slice::<Value>(bytes)?)?);
                        last_policy.clone_from(bytes);
                        if authority.revision != revision {
                            *state.0.write().await = None;
                        }
                    }
                    let bytes = metadata_bytes?;
                    let mut metadata: Metadata = serde_json::from_slice(&bytes)?;
                    anyhow::ensure!(metadata.schema == 1, "unsupported metadata schema");
                    if let Some(policy) = policy_bytes {
                        metadata.policy = serde_json::from_slice(&policy)?;
                    }
                    let combined = serde_json::to_vec(&metadata)?;
                    let reusable = {
                        let current = state.0.read().await;
                        current.as_ref().is_some_and(|(_, validity)| {
                            validity.is_current() && validity.remaining() > Duration::from_secs(30)
                        })
                    };
                    if combined == last_bytes && authority.revision == revision && reusable {
                        return Ok(());
                    }
                    if nonce.is_none() {
                        nonce = Some(authority.begin(&metadata.policy)?);
                        if authority.revision != revision {
                            *state.0.write().await = None;
                        }
                    }
                    let report = tokio::time::timeout(
                        Duration::from_secs(20),
                        service.attestation_report(nonce),
                    )
                    .await??;
                    let evidence = metadata.with_report(serde_json::to_value(report)?)?;
                    let validity = authority.verify(&evidence)?;
                    *state.0.write().await = Some((metadata, validity));
                    last_bytes = combined;
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if result.is_err() {
                    // Never retain authorization across a newly authenticated policy change.
                    if authority.revision != revision {
                        *state.0.write().await = None;
                    }
                    tracing::debug!(
                        "supporting evidence unavailable or rejected; readiness follows last valid snapshot expiry"
                    );
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        (gate, task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_proxy_without_evidence_is_unready() {
        let gate = Gate::default();
        assert!(!gate.ready().await);
        assert!(gate.metadata().await.is_err());
    }
}
