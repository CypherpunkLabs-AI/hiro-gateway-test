//! TLS authentication rooted in a verified attestation's SPKI, not public PKI.
use anyhow::{Result, ensure};
use rustls::{
    CertificateError, DigitallySignedStruct, Error, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct AttestedCertificate {
    host: String,
    pins: Vec<[u8; 32]>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}
impl ServerCertVerifier for AttestedCertificate {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let rejected =
            || Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
        let expected = ServerName::try_from(self.host.as_str()).map_err(|_| rejected())?;
        if name != &expected {
            return Err(rejected());
        }
        let (remaining, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let digest: [u8; 32] = Sha256::digest(parsed.public_key().raw).into();
        if !remaining.is_empty() || !self.pins.contains(&digest) {
            return Err(rejected());
        }
        // Self-signed certificates are allowed ONLY for the attested key at the
        // verified host. TLS CertificateVerify still proves possession below.
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) fn pinned_client(
    origin: &str,
    pins: &[String],
    connect: Duration,
    read: Duration,
) -> Result<reqwest::Client> {
    ensure!(
        !pins.is_empty() && pins.len() <= 32,
        "invalid attested TLS pin set"
    );
    let url = reqwest::Url::parse(origin)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing TLS host"))?
        .to_owned();
    let pins = pins
        .iter()
        .map(|pin| {
            let bytes = hex::decode(pin)?;
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(anyhow::Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AttestedCertificate {
            host,
            pins,
            provider,
        }))
        .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect)
        .read_timeout(read)
        .use_preconfigured_tls(tls)
        .build()?)
}
