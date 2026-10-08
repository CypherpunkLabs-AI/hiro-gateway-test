//! Phala inference appraisal using the policy-neutral ACI mechanisms and DCAP QVL.
use crate::attestation::evidence::{now_secs, validate_source_provenance};
use aci_protocol::{digest, types::AttestationReport};
use aci_verify::{channel::declared_tls_pins, dstack, quote, report};
use anyhow::{Context, Result, ensure};
use dcap_qvl::{
    configs::RustCryptoConfig, policy::QuotePolicy, quote::Report, verify::QuoteVerifier,
};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct VerificationRequest {
    pub upstream_name: String,
    pub url_origin: Option<String>,
    pub model_id: String,
    pub forwarded_body_hash: String,
    pub path: String,
    pub required: bool,
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ChannelBinding {
    TlsSpkiSha256 { origin: String, spki_sha256: String },
}

/// Not deserializable or constructible outside this module. Forwarding requires
/// this authority, bound to the exact body, endpoint, model and freshness window.
pub struct VerifiedUpstream {
    pub(crate) upstream_name: String,
    pub(crate) url_origin: Option<String>,
    pub(crate) model_id: String,
    pub(crate) verifier_id: String,
    pub(crate) required: bool,
    pub(crate) evidence: Value,
    pub(crate) channel_bindings: Vec<ChannelBinding>,
    pub(crate) established_at: u64,
    pub(crate) expires_at: u64,
    deadline: Instant,
    body_hash: String,
    path: String,
}
impl VerifiedUpstream {
    pub(crate) fn is_current(&self) -> bool {
        let now = now_secs();
        now >= self.established_at && now < self.expires_at && Instant::now() < self.deadline
    }
    pub(crate) fn authorize(
        &self,
        origin: &str,
        path: &str,
        model: &str,
        body: &[u8],
    ) -> Result<Vec<String>> {
        ensure!(
            self.is_current()
                && self.required
                && self.url_origin.as_deref() == Some(origin)
                && self.path == path
                && self.model_id == model
                && self.body_hash == digest::sha256_hex(body),
            "invalid upstream forwarding authority"
        );
        let pins = self
            .channel_bindings
            .iter()
            .map(|binding| match binding {
                ChannelBinding::TlsSpkiSha256 {
                    origin: bound,
                    spki_sha256,
                } => {
                    ensure!(bound == origin, "upstream origin mismatch");
                    Ok(spki_sha256.clone())
                }
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!pins.is_empty(), "missing attested TLS key");
        Ok(pins)
    }
}

#[derive(Clone)]
struct CachedReport {
    established_at: u64,
    expires_at: u64,
    deadline: Instant,
    evidence: Value,
    pins: Vec<String>,
}

pub struct InferenceVerifier {
    client: reqwest::Client,
    origin: String,
    pccs: String,
    subjects: BTreeSet<String>,
    roots: BTreeSet<String>,
    ttl: Duration,
    timeout: Duration,
    cache: Mutex<Option<CachedReport>>,
}
impl InferenceVerifier {
    pub fn new(config: &crate::config::Config) -> Result<Self> {
        crate::inference::upstream::validate_origin(&config.phala_base_url)?;
        let subjects = config
            .accepted_subjects
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(!subjects.is_empty(), "upstream identity policy is empty");
        for subject in &subjects {
            let app = subject
                .strip_prefix("app-id:0x")
                .context("expected measured app-id subject")?;
            ensure!(
                !app.is_empty()
                    && app.len() % 2 == 0
                    && app
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid app-id subject"
            );
        }
        let roots = config
            .accepted_kms_root_public_keys
            .iter()
            .map(|root| dstack::compressed_k256_public_key_hex(root).map_err(anyhow::Error::msg))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(!roots.is_empty(), "upstream KMS policy is empty");
        let pccs = config
            .pccs_url
            .clone()
            .unwrap_or_else(|| dcap_qvl::PHALA_PCCS_URL.into());
        let pccs_url = reqwest::Url::parse(&pccs)?;
        ensure!(
            pccs_url.scheme() == "https"
                && pccs_url.host_str().is_some()
                && pccs_url.username().is_empty()
                && pccs_url.password().is_none(),
            "invalid PCCS URL"
        );
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(config.connect_timeout)
                .timeout(config.request_timeout)
                .build()?,
            origin: config.phala_base_url.clone(),
            pccs,
            subjects,
            roots,
            ttl: config.verifier_cache_ttl,
            timeout: config.request_timeout,
            cache: Mutex::new(None),
        })
    }

    pub async fn verify(&self, request: VerificationRequest) -> Result<VerifiedUpstream> {
        ensure!(
            request.required
                && request.upstream_name == "phala-aci"
                && request.url_origin.as_deref() == Some(&self.origin),
            "invalid upstream verification target"
        );
        tokio::time::timeout(self.timeout, async {
            // Serialize cache misses; a failed refresh never falls back to stale evidence.
            let mut cache = self.cache.lock().await;
            let now = now_secs();
            if !cache.as_ref().is_some_and(|c| {
                now >= c.established_at && now < c.expires_at && Instant::now() < c.deadline
            }) {
                *cache = None;
                *cache = Some(self.fetch().await?);
            }
            let verified = cache.as_ref().context("missing verified upstream report")?;
            Ok(VerifiedUpstream {
                upstream_name: request.upstream_name,
                url_origin: request.url_origin,
                model_id: request.model_id,
                verifier_id: "phala-tdx/v1".into(),
                required: true,
                evidence: verified.evidence.clone(),
                channel_bindings: verified
                    .pins
                    .iter()
                    .map(|pin| ChannelBinding::TlsSpkiSha256 {
                        origin: self.origin.clone(),
                        spki_sha256: pin.clone(),
                    })
                    .collect(),
                established_at: verified.established_at,
                expires_at: verified.expires_at,
                deadline: verified.deadline,
                body_hash: request.forwarded_body_hash,
                path: request.path,
            })
        })
        .await
        .context("upstream verification deadline exceeded")?
    }

    async fn fetch(&self) -> Result<CachedReport> {
        let started = Instant::now();
        let verified_at = now_secs();
        ensure!(verified_at > 0, "invalid system clock");
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| anyhow::anyhow!("challenge entropy unavailable"))?;
        let nonce = hex::encode(nonce);
        let response = self
            .client
            .get(format!("{}/v1/aci/attestation", self.origin))
            .query(&[("nonce", &nonce)])
            .send()
            .await
            .context("attestation fetch failed")?;
        ensure!(response.status().is_success(), "attestation HTTP failure");
        let body = crate::inference::upstream::bounded_body(response, 2 * 1024 * 1024).await?;
        let report: AttestationReport = serde_json::from_slice(&body)?;
        ensure!(
            report.attestation.tee_type == "tdx",
            "TDX inference required"
        );
        let binding =
            report::validate_aci_report_binding(&report, Some(&nonce), verified_at, None)?;
        validate_source_provenance(&report.attestation.source_provenance)?;
        let evidence = &report.attestation.evidence;
        let raw = quote::quote_bytes(evidence)?;
        ensure!(raw.len() <= 128 * 1024, "oversized TDX quote");
        let collateral = dcap_qvl::collateral::CollateralClient::with_default_http(&self.pccs)?
            .with_config::<RustCryptoConfig>()
            .fetch(&raw)
            .await?;
        let claims = tokio::task::spawn_blocking(move || {
            // Hardware verification is delegated to QVL, with explicit appraisal.
            // Keep platform configuration admissible as before; require UpToDate TCB.
            let policy = QuotePolicy::strict(verified_at)
                .allow_smt(true)
                .allow_dynamic_platform(true)
                .allow_cached_keys(true);
            QuoteVerifier::new_prod()
                .with_config::<RustCryptoConfig>()
                .verify_with_policy(&raw, &collateral, verified_at, &policy)
        })
        .await??;
        let td = match &claims.report {
            Report::TD10(td) => td,
            Report::TD15(td) => &td.base,
            _ => anyhow::bail!("TDX report required"),
        };
        quote::quote_binds_report_data(evidence, &td.report_data, binding.report_data)?;
        let events = dstack::verify_dstack_event_log(evidence, Some(&td.rt_mr3))
            .map_err(anyhow::Error::msg)?;
        dstack::verify_dstack_compose_measurement(evidence, &events).map_err(anyhow::Error::msg)?;
        let app_id = dstack::dstack_app_id(&events).map_err(anyhow::Error::msg)?;
        let subject = format!("app-id:0x{}", hex::encode(&app_id));
        ensure!(
            self.subjects.contains(&subject)
                && binding
                    .keyset
                    .subject
                    .as_ref()
                    .is_none_or(|declared| declared == &subject),
            "unapproved measured application"
        );
        let root = dstack::verify_dstack_kms_receipt_chain(evidence, &binding.keyset, &app_id)?;
        ensure!(self.roots.contains(&root), "unapproved KMS root");
        let pins = declared_tls_pins(&binding.keyset, evidence, &self.origin)?;
        ensure!(!pins.is_empty(), "missing attested TLS key");
        let expires_at = verified_at
            .saturating_add(self.ttl.as_secs())
            .min(binding.keyset.not_after)
            .min(claims.earliest_expiration_date);
        let now = now_secs();
        ensure!(
            now >= verified_at && now < expires_at,
            "upstream evidence expired during verification"
        );
        let deadline = started + Duration::from_secs(expires_at - verified_at);
        ensure!(Instant::now() < deadline, "upstream verification expired");
        Ok(CachedReport {
            established_at: verified_at,
            expires_at,
            deadline,
            evidence: report::raw_evidence(&body, "application/json", None),
            pins,
        })
    }
}

pub async fn verify_before_listening(
    verifier: &Arc<InferenceVerifier>,
    origin: &str,
) -> Result<()> {
    verifier
        .verify(VerificationRequest {
            upstream_name: "phala-aci".into(),
            url_origin: Some(origin.into()),
            model_id: "startup-preflight".into(),
            forwarded_body_hash: String::new(),
            path: String::new(),
            required: true,
        })
        .await?;
    Ok(())
}
