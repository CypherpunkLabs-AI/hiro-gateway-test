//! Direct Linux TSM evidence collection; acceptance belongs to the client.
use anyhow::{Context, ensure};
use dcap_qvl::quote::Quote;
use evidence_sha2::{Digest, Sha384};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;

pub const PROFILE: &str = "hiro.gcp-tdx.v1";
const RELEASE_DOMAIN: &[u8] = b"hiro.release.v1\0";
const MAX_QUOTE: usize = 128 * 1024;
const MAX_RELEASE: usize = 256 * 1024;
const MAX_CCEL: usize = 1024 * 1024;

#[derive(Clone)]
pub struct Attester {
    report_dir: PathBuf,
    evidence_dir: PathBuf,
    slot: Arc<Semaphore>,
}

impl Attester {
    /// Use a dedicated, guest-provisioned configfs TSM report entry.
    /// # Errors
    /// Rejects relative paths. Missing hardware fails at evidence collection.
    pub fn new(report_dir: PathBuf, evidence_dir: PathBuf) -> anyhow::Result<Self> {
        ensure!(
            report_dir.is_absolute() && evidence_dir.is_absolute(),
            "attestation paths must be absolute"
        );
        Ok(Self {
            report_dir,
            evidence_dir,
            slot: Arc::new(Semaphore::new(1)),
        })
    }

    /// Return a fresh TDX quote binding the caller's challenge and service keys.
    /// # Errors
    /// Rejects unavailable hardware, concurrent requests, stale reports and an
    /// unmeasured release. This is evidence collection, not DCAP verification.
    pub async fn evidence(&self, report_data: [u8; 64]) -> anyhow::Result<Value> {
        let permit = self
            .slot
            .clone()
            .try_acquire_owned()
            .context("attester busy")?;
        let this = self.clone();
        let task = tokio::task::spawn_blocking(move || {
            // A timed-out request must not release the slot while a kernel read
            // is still running, or another request could overwrite its nonce.
            let _permit = permit;
            this.collect(report_data)
        });
        tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .context("TDX quote timeout")?
            .context("TDX collector failed")?
    }

    fn collect(&self, report_data: [u8; 64]) -> anyhow::Result<Value> {
        let release = read_bounded(&self.evidence_dir.join("release.json"), MAX_RELEASE)?;
        validate_release(&release)?;
        let ccel = read_bounded(&self.evidence_dir.join("ccel.bin"), MAX_CCEL)?;
        ensure!(!ccel.is_empty(), "missing CCEL boot event log");
        let initial_generation = generation(&self.report_dir)?;
        OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.report_dir.join("inblob"))?
            .write_all(&report_data)?;
        let raw = read_bounded(&self.report_dir.join("outblob"), MAX_QUOTE)?;
        let provider = read_bounded(&self.report_dir.join("provider"), 128)?;
        ensure!(
            provider.trim_ascii() == b"tdx_guest",
            "not a TDX report provider"
        );
        ensure!(
            Some(generation(&self.report_dir)?) == initial_generation.checked_add(1),
            "TSM report changed concurrently"
        );
        validate_quote(&raw, &report_data, &release)?;
        Ok(json!({
            "profile": PROFILE,
            "quote": hex::encode(raw),
            "quote_report_data": hex::encode(report_data),
            "ccel": hex::encode(ccel),
            "release_manifest": String::from_utf8(release)?,
            "release_measurement": {
                "register": "RTMR3",
                "algorithm": "sha384",
                "domain_hex": hex::encode(RELEASE_DOMAIN),
                "initial_value": "00".repeat(48),
                "extends": 1
            }
        }))
    }
}

fn generation(dir: &Path) -> anyhow::Result<u64> {
    let value = read_bounded(&dir.join("generation"), 32)?;
    Ok(std::str::from_utf8(&value)?.trim().parse()?)
}

fn read_bounded(path: &Path, max: usize) -> anyhow::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "evidence must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "evidence exceeds size limit");
    Ok(bytes)
}

fn validate_release(bytes: &[u8]) -> anyhow::Result<()> {
    let release: Value = serde_json::from_slice(bytes)?;
    ensure!(
        release["schema"] == 1 && release["profile"] == PROFILE,
        "unsupported measured release"
    );
    let compose = release["compose_sha256"]
        .as_str()
        .context("missing Compose digest")?;
    ensure!(lower_hex(compose, 64), "invalid Compose digest");
    let containers = release["containers"]
        .as_object()
        .context("missing release containers")?;
    ensure!(containers.contains_key("hiro-proxy"), "release omits proxy");
    for image in containers.values() {
        let (name, digest) = image
            .as_str()
            .and_then(|s| s.split_once("@sha256:"))
            .context("container must be pinned by digest")?;
        ensure!(
            !name.is_empty()
                && !name.contains('@')
                && !name.chars().any(char::is_whitespace)
                && lower_hex(digest, 64),
            "invalid container pin"
        );
    }
    Ok(())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn release_rtmr(release: &[u8]) -> [u8; 48] {
    let mut event = Sha384::new();
    event.update(RELEASE_DOMAIN);
    event.update(release);
    let mut register = Sha384::new();
    register.update([0_u8; 48]);
    register.update(event.finalize());
    register.finalize().into()
}

fn validate_quote(raw: &[u8], report_data: &[u8; 64], release: &[u8]) -> anyhow::Result<()> {
    let quote = Quote::parse(raw).context("invalid TDX quote")?;
    let td = quote.report.as_td10().context("quote is not TDX")?;
    ensure!(td.td_attributes[0] & 1 == 0, "debug TDX guest");
    ensure!(
        &td.report_data == report_data,
        "quote challenge/key binding mismatch"
    );
    ensure!(
        td.rt_mr3 == release_rtmr(release),
        "release is not measured in RTMR3"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_requires_immutable_container_identity() {
        let mut release = json!({"schema":1,"profile":PROFILE,"compose_sha256":"a".repeat(64),"containers":{"hiro-proxy":format!("ghcr.io/example/proxy@sha256:{}", "b".repeat(64))}});
        let bytes = serde_json::to_vec(&release).unwrap();
        validate_release(&bytes).unwrap();
        let mut modified = bytes.clone();
        modified.push(b'\n');
        assert_ne!(release_rtmr(&bytes), release_rtmr(&modified));
        release["containers"]["hiro-proxy"] = json!("ghcr.io/example/proxy:latest");
        assert!(validate_release(&serde_json::to_vec(&release).unwrap()).is_err());
        assert!(validate_quote(&[], &[0; 64], &bytes).is_err());
    }

    // The public DCAP fixture supplies the wire format only. Mutated quotes
    // deliberately have invalid signatures; clients must still verify DCAP.
    #[test]
    fn quote_must_bind_nonce_keys_release_and_production_guest() {
        let mut raw = include_bytes!("testdata/tdx-quote.bin").to_vec();
        assert_eq!(&raw[..2], &[4, 0]);
        let release = b"exact release bytes";
        let data = [42_u8; 64];
        // Intel quote v4: 48-byte header, 584-byte TDREPORT10 body.
        raw[48 + 120] &= !1;
        raw[48 + 472..48 + 520].copy_from_slice(&release_rtmr(release));
        raw[48 + 520..48 + 584].copy_from_slice(&data);
        validate_quote(&raw, &data, release).unwrap();
        assert!(validate_quote(&raw, &[43; 64], release).is_err());
        assert!(validate_quote(&raw, &data, b"different release").is_err());
        raw[48 + 120] |= 1;
        assert!(validate_quote(&raw, &data, release).is_err());
    }

    #[test]
    fn evidence_files_are_bounded_and_symlinks_rejected() {
        let dir = std::env::temp_dir().join(format!("hiro-evidence-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("file");
        std::fs::write(&file, b"12345").unwrap();
        assert!(read_bounded(&file, 4).is_err());
        assert_eq!(read_bounded(&file, 5).unwrap(), b"12345");
        std::os::unix::fs::symlink(&file, dir.join("link")).unwrap();
        assert!(read_bounded(&dir.join("link"), 5).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn no_hardware_never_becomes_successful_evidence() {
        let missing = PathBuf::from(format!("/nonexistent-hiro-{}", uuid::Uuid::new_v4()));
        let attester = Attester::new(missing.clone(), missing).unwrap();
        assert!(attester.evidence([0; 64]).await.is_err());
        assert!(Attester::new("relative".into(), "/run/hiro".into()).is_err());
    }
}
