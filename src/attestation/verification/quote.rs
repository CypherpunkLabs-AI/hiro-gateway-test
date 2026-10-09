//! Production Intel DCAP verification and explicit dstack platform acceptance.

use dcap_qvl::{
    QuoteCollateralV3,
    configs::RustCryptoConfig,
    policy::QuotePolicy,
    quote::{Report, TDReport10},
    verify::QuoteVerifier,
};

use super::{Error, Result, encoding, model::PlatformProfile};

/// Validate every published profile when adopting policy, not just the one used
/// by a successful recipient. An empty profile list can represent deny-all.
pub(crate) fn validate_profile(profile: &PlatformProfile) -> Result<()> {
    for value in [
        &profile.mr_td,
        &profile.rt_mr0,
        &profile.rt_mr1,
        &profile.rt_mr2,
        &profile.mr_seam,
        &profile.mr_signer_seam,
        &profile.mr_config_id,
        &profile.mr_owner,
        &profile.mr_owner_config,
    ] {
        encoding::hex_array::<48>(value)?;
    }
    if encoding::hex_array::<8>(&profile.td_attributes)?[0] & 1 != 0 {
        return Err(Error::Policy);
    }
    encoding::hex_array::<8>(&profile.seam_attributes)?;
    encoding::hex_array::<8>(&profile.xfam)?;
    encoding::hex_array::<16>(&profile.minimum_tee_tcb_svn)?;
    if profile.minimum_tcb_evaluation == 0
        || profile.accepted_ppid_sha256.is_empty()
        || profile.accepted_ppid_sha256.len() > 512
        || profile.allowed_advisories.len() > 64
    {
        return Err(Error::Policy);
    }
    let mut seen = std::collections::BTreeSet::new();
    for ppid in &profile.accepted_ppid_sha256 {
        encoding::hex_array::<32>(ppid)?;
        if !seen.insert(ppid) {
            return Err(Error::Policy);
        }
    }
    seen.clear();
    for advisory in &profile.allowed_advisories {
        encoding::text(advisory, 128)?;
        if !seen.insert(advisory) {
            return Err(Error::Policy);
        }
    }
    Ok(())
}

pub(crate) struct VerifiedQuote {
    pub report: TDReport10,
    pub expires_at: u64,
}

pub(crate) fn verify(
    raw: &[u8],
    collateral: &QuoteCollateralV3,
    profile: &PlatformProfile,
    now: u64,
) -> Result<VerifiedQuote> {
    preflight(raw)?;
    // Reject parser ambiguities before signed collateral enters the QVL.
    encoding::parse::<serde_json::Value>(collateral.tcb_info.as_bytes(), 1024 * 1024)?;
    encoding::parse::<serde_json::Value>(collateral.qe_identity.as_bytes(), 64 * 1024)?;
    validate_profile(profile)?;
    let policy = QuotePolicy::strict(now)
        .min_tcb_eval_data_number(profile.minimum_tcb_evaluation)
        .allow_smt(profile.allow_smt)
        .allow_dynamic_platform(profile.allow_dynamic_platform)
        .allow_cached_keys(profile.allow_cached_keys);
    // Never use the one-shot `verify`: in QVL 0.6 it returns unappraised claims.
    let claims = QuoteVerifier::new_prod()
        .with_config::<RustCryptoConfig>()
        .verify_with_policy(raw, collateral, now, &policy)
        .map_err(|_| Error::Quote)?;
    if claims.platform.pck.ppid.len() != 16
        || claims.qe.tcb_eval_data_number < profile.minimum_tcb_evaluation
        || claims
            .tcb
            .advisory_ids
            .iter()
            .any(|id| !profile.allowed_advisories.contains(id))
        || !profile
            .accepted_ppid_sha256
            .contains(&encoding::digest(&claims.platform.pck.ppid))
    {
        return Err(Error::Platform);
    }
    let Report::TD10(report) = claims.report else {
        return Err(Error::Platform);
    };
    let measurements = [
        (&profile.mr_td, report.mr_td),
        (&profile.rt_mr0, report.rt_mr0),
        (&profile.rt_mr1, report.rt_mr1),
        (&profile.rt_mr2, report.rt_mr2),
        (&profile.mr_seam, report.mr_seam),
        (&profile.mr_signer_seam, report.mr_signer_seam),
        (&profile.mr_config_id, report.mr_config_id),
        (&profile.mr_owner, report.mr_owner),
        (&profile.mr_owner_config, report.mr_owner_config),
    ];
    for (expected, actual) in measurements {
        if encoding::hex_array::<48>(expected)? != actual {
            return Err(Error::Platform);
        }
    }
    for (expected, actual) in [
        (&profile.td_attributes, report.td_attributes),
        (&profile.seam_attributes, report.seam_attributes),
        (&profile.xfam, report.xfam),
    ] {
        if encoding::hex_array::<8>(expected)? != actual {
            return Err(Error::Platform);
        }
    }
    // Pin attributes exactly and unconditionally disallow DEBUG (bit 0).
    if report.td_attributes[0] & 1 != 0 {
        return Err(Error::Platform);
    }
    let floor = encoding::hex_array::<16>(&profile.minimum_tee_tcb_svn)?;
    if report
        .tee_tcb_svn
        .iter()
        .zip(floor)
        .any(|(actual, minimum)| *actual < minimum)
    {
        return Err(Error::Platform);
    }
    let expires_at = claims
        .earliest_expiration_date
        .min(claims.qe_iden_earliest_expiration_date);
    if expires_at <= now {
        return Err(Error::Expired);
    }
    Ok(VerifiedQuote { report, expires_at })
}

/// Create a candidate only after independent dstack OS verification. The caller
/// supplies explicit platform feature allowances; strict TCB appraisal remains mandatory.
pub(crate) fn profile_from_quote(
    raw: &[u8],
    collateral: &QuoteCollateralV3,
    id: String,
    now: u64,
    allow_smt: bool,
    allow_dynamic_platform: bool,
    allow_cached_keys: bool,
) -> Result<PlatformProfile> {
    preflight(raw)?;
    let policy = QuotePolicy::strict(now)
        .allow_smt(allow_smt)
        .allow_dynamic_platform(allow_dynamic_platform)
        .allow_cached_keys(allow_cached_keys);
    let claims = QuoteVerifier::new_prod()
        .with_config::<RustCryptoConfig>()
        .verify_with_policy(raw, collateral, now, &policy)
        .map_err(|_| Error::Quote)?;
    let Report::TD10(r) = claims.report else {
        return Err(Error::Platform);
    };
    let profile = PlatformProfile {
        id,
        mr_td: hex::encode(r.mr_td),
        rt_mr0: hex::encode(r.rt_mr0),
        rt_mr1: hex::encode(r.rt_mr1),
        rt_mr2: hex::encode(r.rt_mr2),
        mr_seam: hex::encode(r.mr_seam),
        mr_signer_seam: hex::encode(r.mr_signer_seam),
        mr_config_id: hex::encode(r.mr_config_id),
        mr_owner: hex::encode(r.mr_owner),
        mr_owner_config: hex::encode(r.mr_owner_config),
        td_attributes: hex::encode(r.td_attributes),
        seam_attributes: hex::encode(r.seam_attributes),
        xfam: hex::encode(r.xfam),
        minimum_tee_tcb_svn: hex::encode(r.tee_tcb_svn),
        minimum_tcb_evaluation: claims
            .tcb
            .eval_data_number
            .min(claims.qe.tcb_eval_data_number),
        allowed_advisories: claims.tcb.advisory_ids,
        allow_smt,
        allow_dynamic_platform,
        allow_cached_keys,
        accepted_ppid_sha256: vec![encoding::digest(&claims.platform.pck.ppid)],
    };
    verify(raw, collateral, &profile, now)?;
    Ok(profile)
}

pub(crate) fn decode_quote(value: &str) -> Result<Vec<u8>> {
    if value.len() > 128 * 1024 || !value.len().is_multiple_of(2) {
        return Err(Error::Limit);
    }
    hex::decode(value).map_err(|_| Error::Encoding)
}

/// Validate every nested length before a dependency can allocate from it.
/// Supported profile: ECDSA P-256, TDX 1.0, v4 or v5, embedded PCK chain.
fn preflight(raw: &[u8]) -> Result<()> {
    if raw.len() > 64 * 1024 {
        return Err(Error::Limit);
    }
    let mut cursor = Cursor(raw);
    let version = cursor.u16()?;
    if ![4, 5].contains(&version) || cursor.u16()? != 2 || cursor.u32()? != 0x81 {
        return Err(Error::Quote);
    }
    cursor.take(40)?;
    if version == 5 && (cursor.u16()? != 2 || cursor.u32()? != 584) {
        return Err(Error::Quote);
    }
    cursor.take(584)?;
    let auth_len = cursor.u32()?;
    let mut auth = Cursor(cursor.take(auth_len)?);
    // Some dstack providers return a zero-filled buffer tail after the quote's
    // declared length. It is outside the signed body. Reject nonzero suffixes
    // and keep every nested authentication/certificate boundary exact.
    if cursor.0.len() > 1024 || cursor.0.iter().any(|byte| *byte != 0) {
        return Err(Error::Quote);
    }
    auth.take(128)?; // Quote signature and attestation public key.
    if auth.u16()? != 6 {
        return Err(Error::Quote);
    }
    let cert_len = auth.u32()?;
    let mut qe = Cursor(auth.take(cert_len)?);
    auth.end()?;
    qe.take(384 + 64)?;
    let qe_auth_len = usize::from(qe.u16()?);
    if qe_auth_len > 1024 {
        return Err(Error::Limit);
    }
    qe.take(qe_auth_len)?;
    if qe.u16()? != 5 {
        return Err(Error::Quote);
    }
    let chain_len = qe.u32()?;
    if chain_len > 24 * 1024 {
        return Err(Error::Limit);
    }
    qe.take(chain_len)?;
    qe.end()
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let value = self.0.get(..length).ok_or(Error::Quote)?;
        self.0 = self.0.get(length..).ok_or(Error::Quote)?;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Quote)?,
        ))
    }
    fn u32(&mut self) -> Result<usize> {
        usize::try_from(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Quote)?,
        ))
        .map_err(|_| Error::Quote)
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Quote)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_provider_zero_padding_but_rejects_hidden_suffixes() {
        let decoded =
            crate::attestation::kms::decode_certificate(include_bytes!("../testdata/kms-cert.der"))
                .unwrap();
        assert!(preflight(&decoded.quote).is_ok());
        let mut nonzero = decoded.quote.clone();
        nonzero.push(1);
        assert!(preflight(&nonzero).is_err());
        let mut excessive = decoded.quote;
        excessive.extend_from_slice(&[0; 1025]);
        assert!(preflight(&excessive).is_err());
    }
}
