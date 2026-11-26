use std::{io, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use subtle::ConstantTimeEq;

use crate::config::tls::{TlsClientOptions, TlsVersion};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(super) fn provider(
    groups: &crate::config::TlsKeyExchangeGroups,
    options: &TlsClientOptions,
) -> io::Result<Arc<rustls::crypto::CryptoProvider>> {
    let chrome =
        options.client_fingerprint == Some(crate::config::tls::TlsClientFingerprint::Chrome);
    let mut provider = if chrome {
        super::browser::validate_policy(groups, options)?;
        super::browser::provider()
    } else {
        (*super::crypto_provider_with_groups(groups)).clone()
    };
    if !options.cipher_suites.is_empty() {
        let mut selected = Vec::with_capacity(options.cipher_suites.len());
        for name in &options.cipher_suites {
            let canonical = match name.as_str() {
                "TLS_AES_128_GCM_SHA256" => "TLS13_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384" => "TLS13_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256" => "TLS13_CHACHA20_POLY1305_SHA256",
                other => other,
            };
            // Debug deliberately omits some names; as_str covers all IANA values.
            let suite = provider
                .cipher_suites
                .iter()
                .copied()
                .chain(aerobox_crypto::legacy_cbc::suites())
                .chain(aerobox_crypto::legacy_rsa::suites())
                .find(|suite| suite.suite().as_str() == Some(canonical))
                .ok_or_else(|| {
                    invalid(format!("unsupported pure Rust TLS cipher suite: {name}"))
                })?;
            if selected
                .iter()
                .any(|s: &rustls::SupportedCipherSuite| s.suite() == suite.suite())
            {
                return Err(invalid(format!("duplicate TLS cipher suite: {name}")));
            }
            selected.push(suite);
        }
        if chrome
            && selected
                .iter()
                .map(|s| u16::from(s.suite()))
                .collect::<Vec<_>>()
                != super::browser::CIPHERS
        {
            return Err(invalid(
                "Chrome133 conflicts with the explicit cipher suite policy",
            ));
        }
        provider.cipher_suites = selected;
    }
    Ok(Arc::new(provider))
}

pub(super) fn versions(
    options: &TlsClientOptions,
    tls13_only: bool,
) -> io::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    let min = options.min_version.unwrap_or(TlsVersion::V12);
    let max = options.max_version.unwrap_or(TlsVersion::V13);
    if min > max {
        return Err(invalid("TLS min_version exceeds max_version"));
    }
    if tls13_only && max < TlsVersion::V13 {
        return Err(invalid("this transport or key exchange requires TLS 1.3"));
    }
    let mut versions = Vec::new();
    if max == TlsVersion::V13 {
        versions.push(&rustls::version::TLS13);
    }
    if min == TlsVersion::V12 && !tls13_only {
        versions.push(&rustls::version::TLS12);
    }
    Ok(versions)
}

pub(super) fn roots(options: &TlsClientOptions) -> io::Result<Arc<rustls::RootCertStore>> {
    if options.root_certificates.is_empty() {
        return Ok(super::get_root_cert_store());
    }
    let mut store = rustls::RootCertStore::empty();
    for pem in &options.root_certificates {
        let mut count = 0;
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert =
                cert.map_err(|error| invalid(format!("invalid TLS trust certificate: {error}")))?;
            store
                .add(cert)
                .map_err(|error| invalid(format!("invalid TLS trust certificate: {error}")))?;
            count += 1;
        }
        if count == 0 {
            return Err(invalid("TLS trust root contains no PEM certificate"));
        }
    }
    Ok(Arc::new(store))
}

pub(super) fn pin_verifier(
    inner: Arc<dyn ServerCertVerifier>,
    options: &TlsClientOptions,
) -> io::Result<Arc<dyn ServerCertVerifier>> {
    if options.certificate_sha256.is_empty()
        && options.certificate_chain_sha256.is_empty()
        && options.certificate_public_key_sha256.is_empty()
    {
        return Ok(inner);
    }
    let certificate_pins = decode_pins(&options.certificate_sha256, "certificate_sha256")?;
    let chain_pins = decode_pins(
        &options.certificate_chain_sha256,
        "certificate_chain_sha256",
    )?;
    let public_key_pins = decode_pins(
        &options.certificate_public_key_sha256,
        "certificate_public_key_sha256",
    )?;
    Ok(Arc::new(PinnedVerifier {
        inner,
        certificate_pins,
        chain_pins,
        public_key_pins,
    }))
}

fn decode_pins(values: &[String], field: &str) -> io::Result<Vec<[u8; 32]>> {
    values
        .iter()
        .map(|pin| {
            let decoded = STANDARD
                .decode(pin)
                .map_err(|_| invalid(format!("{field} must use base64")))?;
            <[u8; 32]>::try_from(decoded)
                .map_err(|_| invalid(format!("{field} must contain 32 bytes")))
        })
        .collect()
}

#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    certificate_pins: Vec<[u8; 32]>,
    chain_pins: Vec<[u8; 32]>,
    public_key_pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, name, ocsp, now)?;
        let hash = aerobox_primitives::digest::digest(
            &aerobox_primitives::digest::SHA256,
            end_entity.as_ref(),
        );
        if matches_pin(&self.certificate_pins, hash.as_ref())
            || matches_pin(&self.chain_pins, hash.as_ref())
        {
            return Ok(ServerCertVerified::assertion());
        }
        if !self.chain_pins.is_empty() {
            for (index, ca) in intermediates.iter().enumerate() {
                let hash = aerobox_primitives::digest::digest(
                    &aerobox_primitives::digest::SHA256,
                    ca.as_ref(),
                );
                if matches_pin(&self.chain_pins, hash.as_ref()) {
                    let mut roots = rustls::RootCertStore::empty();
                    roots.add(ca.clone())?;
                    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                        Arc::new(roots),
                        aerobox_crypto::shared_provider(),
                    )
                    .build()
                    .map_err(|error| rustls::Error::General(error.to_string()))?;
                    return verifier.verify_server_cert(
                        end_entity,
                        &intermediates[..index],
                        name,
                        ocsp,
                        now,
                    );
                }
            }
        }
        let (remaining, cert) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        if !remaining.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let hash = aerobox_primitives::digest::digest(
            &aerobox_primitives::digest::SHA256,
            cert.public_key().raw,
        );
        if matches_pin(&self.public_key_pins, hash.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "TLS certificate pin mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn matches_pin(pins: &[[u8; 32]], hash: &[u8]) -> bool {
    bool::from(pins.iter().fold(subtle::Choice::from(0), |found, pin| {
        found | pin.as_slice().ct_eq(hash)
    }))
}

#[cfg(test)]
mod tests;

pub(super) fn ech_verifier(
    inner: Arc<dyn ServerCertVerifier>,
    public: Option<Arc<rustls::client::WebPkiServerVerifier>>,
) -> Arc<dyn ServerCertVerifier> {
    match public {
        Some(public) => Arc::new(EchVerifier { inner, public }),
        None => inner,
    }
}
#[derive(Debug)]
struct EchVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    public: Arc<rustls::client::WebPkiServerVerifier>,
}
impl ServerCertVerifier for EchVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(cert, chain, name, ocsp, now)
    }
    fn verify_ech_rejection_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.public.verify_server_cert(cert, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
