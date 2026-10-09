//! Reuse the client verifier for worker publication and independent proxy appraisal.
use super::verification::{Clock, Verifier};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const MAX_DOCUMENT: usize = 4 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub schema: u32,
    pub collateral: Value,
    pub release: Value,
    pub policy: Value,
    pub kms: Value,
}

impl Metadata {
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let result: Self = serde_json::from_slice(&read_bounded(path, MAX_DOCUMENT)?)?;
        ensure!(result.schema == 1, "unsupported evidence schema");
        Ok(result)
    }
    pub fn with_report(&self, report: Value) -> anyhow::Result<Vec<u8>> {
        let mut doc = serde_json::to_value(self)?;
        doc.as_object_mut()
            .context("invalid evidence")?
            .insert("report".into(), report);
        let bytes = serde_json::to_vec(&doc)?;
        ensure!(bytes.len() <= MAX_DOCUMENT, "evidence exceeds limit");
        Ok(bytes)
    }
}

pub fn read_bounded(path: &Path, max: usize) -> anyhow::Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt;
    // A worker-controlled FIFO/device/symlink must not block a verification task
    // or turn a metadata read into access to another proxy file.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= max as u64,
        "expected a bounded regular file"
    );
    let mut data = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut data)?;
    ensure!(data.len() <= max, "file exceeds size limit");
    Ok(data)
}

/// Same-directory rename plus file/directory fsync; never expose a partial snapshot.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().context("file has no parent")?;
    let temporary = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

/// One locked state directory per process role; the worker never writes proxy state.
pub struct Authority {
    verifier: Verifier,
    origin: Instant,
    checkpoint: PathBuf,
    _lock: File,
    /// Changes even when a newer authenticated policy rejects the recipient.
    pub revision: u64,
}

impl Authority {
    pub fn open(state: &Path, trust: &Path, roots: &Path) -> anyhow::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(state.join("authority.lock"))?;
        lock.try_lock()
            .context("evidence authority state already in use")?;
        let checkpoint = state.join("checkpoint.json");
        let persisted = match read_bounded(&checkpoint, 4096) {
            Ok(bytes) => Some(bytes),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        let now = Clock {
            unix_seconds: super::evidence::now_secs(),
            monotonic_millis: 0,
        };
        let verifier = Verifier::new(
            &read_bounded(trust, 65536)?,
            &read_bounded(roots, 262144)?,
            persisted.as_deref(),
            now,
        )?;
        Ok(Self {
            verifier,
            origin: Instant::now(),
            checkpoint,
            _lock: lock,
            revision: 0,
        })
    }

    fn clock(&self) -> Clock {
        Clock {
            unix_seconds: super::evidence::now_secs(),
            monotonic_millis: u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Adopt authenticated policy floors before attempting recipient verification.
    pub fn begin(&mut self, policy: &Value) -> anyhow::Result<String> {
        let pending = self
            .verifier
            .verify_policy(&serde_json::to_vec(policy)?, self.clock())?;
        let checkpoint = pending.checkpoint_json().as_bytes().to_vec();
        let old: Option<Value> = pending
            .previous_checkpoint_json()
            .map(serde_json::from_str)
            .transpose()?;
        let next: Value = serde_json::from_slice(&checkpoint)?;
        if old.as_ref().map(|v| &v["policy_digest"]) != Some(&next["policy_digest"]) {
            self.revision = self.revision.saturating_add(1);
        }
        // A failed durable write is fatal to this attempt, not an acknowledgement.
        atomic_write(&self.checkpoint, &checkpoint, 0o600)?;
        self.verifier
            .commit_policy(pending, &checkpoint, self.clock())?;
        Ok(self.verifier.begin(self.clock())?)
    }

    pub fn verify(&mut self, bytes: &[u8]) -> anyhow::Result<Validity> {
        let pending = self.verifier.verify(bytes, self.clock())?;
        let checkpoint = pending.checkpoint_json().as_bytes().to_vec();
        let old: Option<Value> = pending
            .previous_checkpoint_json()
            .map(serde_json::from_str)
            .transpose()?;
        let next: Value = serde_json::from_slice(&checkpoint)?;
        if old.as_ref().map(|v| &v["release_digest"]) != Some(&next["release_digest"]) {
            self.revision = self.revision.saturating_add(1);
        }
        atomic_write(&self.checkpoint, &checkpoint, 0o600)?;
        let recipient = self.verifier.commit(pending, &checkpoint, self.clock())?;
        self.verifier.authorize(&recipient, self.clock())?;
        let expires = recipient.summary().expires_at;
        Ok(Validity {
            expires,
            verified_at: recipient.summary().verified_at,
            deadline: Instant::now()
                + Duration::from_secs(expires.saturating_sub(super::evidence::now_secs())),
        })
    }
}

#[derive(Clone)]
pub struct Validity {
    pub expires: u64,
    verified_at: u64,
    deadline: Instant,
}
impl Validity {
    pub fn is_current(&self) -> bool {
        let now = super::evidence::now_secs();
        Instant::now() < self.deadline && now >= self.verified_at && now < self.expires
    }
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_replacement_never_exposes_partial_json() {
        let dir = std::env::temp_dir().join(format!("hiro-snapshot-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("evidence.json");
        let small = br#"{"generation":1}"#.to_vec();
        let large =
            serde_json::to_vec(&serde_json::json!({"generation":2,"body":"a".repeat(32768)}))
                .unwrap();
        atomic_write(&path, &small, 0o644).unwrap();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            for _ in 0..100 {
                let value: Value =
                    serde_json::from_slice(&read_bounded(&reader_path, MAX_DOCUMENT).unwrap())
                        .unwrap();
                assert!(value["generation"] == 1 || value["generation"] == 2);
            }
        });
        for _ in 0..10 {
            atomic_write(&path, &large, 0o644).unwrap();
            atomic_write(&path, &small, 0o644).unwrap();
        }
        reader.join().unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert!(read_bounded(&path, 2).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wall_clock_rollback_and_each_expiry_clock_reject_authority() {
        let now = super::super::evidence::now_secs();
        let mut valid = Validity {
            verified_at: now,
            expires: now + 60,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        assert!(valid.is_current());
        valid.verified_at = now + 60;
        assert!(!valid.is_current());
        valid.verified_at = now;
        valid.expires = now;
        assert!(!valid.is_current());
        valid.expires = now + 60;
        valid.deadline = Instant::now();
        assert!(!valid.is_current());
    }

    #[test]
    fn injected_authorization_fields_are_not_accepted_as_metadata() {
        let data = serde_json::json!({"schema":1,"collateral":{},"release":{},"policy":{},"kms":{},"ready":true});
        assert!(serde_json::from_value::<Metadata>(data).is_err());
    }

    #[test]
    fn metadata_reader_rejects_symlinks() {
        let dir = std::env::temp_dir().join(format!("hiro-symlink-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("private"), "private data").unwrap();
        std::os::unix::fs::symlink(dir.join("private"), dir.join("evidence.json")).unwrap();
        assert!(read_bounded(&dir.join("evidence.json"), MAX_DOCUMENT).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
