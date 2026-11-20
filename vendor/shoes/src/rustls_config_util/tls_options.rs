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
    let mut provider = (*super::crypto_provider_with_groups(groups)).clone();
    if !options.cipher_suites.is_empty() {
        let mut selected = Vec::with_capacity(options.cipher_suites.len());
        for name in &options.cipher_suites {
            // rustls uses a TLS13_ prefix internally; configuration accepts
            // the IANA names used by Android/sing-box as well as that spelling.
            let canonical = match name.as_str() {
                "TLS_AES_128_GCM_SHA256" => "TLS13_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384" => "TLS13_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256" => "TLS13_CHACHA20_POLY1305_SHA256",
                other => other,
            };
            let suite = provider
                .cipher_suites
                .iter()
                .copied()
                .find(|suite| format!("{:?}", suite.suite()) == canonical)
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
    if options.certificate_public_key_sha256.is_empty() {
        return Ok(inner);
    }
    let pins = options
        .certificate_public_key_sha256
        .iter()
        .map(|pin| {
            let decoded = STANDARD
                .decode(pin)
                .map_err(|_| invalid("certificate_public_key_sha256 must use base64"))?;
            <[u8; 32]>::try_from(decoded)
                .map_err(|_| invalid("certificate_public_key_sha256 must contain 32 bytes"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Arc::new(PinnedVerifier { inner, pins }))
}

#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    pins: Vec<[u8; 32]>,
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
        let matches = self
            .pins
            .iter()
            .fold(subtle::Choice::from(0), |found, pin| {
                found | pin.as_slice().ct_eq(hash.as_ref())
            });
        if bool::from(matches) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "TLS certificate public key pin mismatch".into(),
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

#[cfg(test)]
mod tests;
