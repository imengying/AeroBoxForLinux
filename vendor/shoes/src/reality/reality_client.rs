use std::io;
use std::sync::Arc;

use rustls::pki_types::ServerName;

use super::CipherSuite;
use super::reality_rustls_adapter::{client_authentication, provider};
use crate::crypto::{TlsConnection, tls_error};

#[derive(Clone)]
pub struct RealityClientConfig {
    pub client_fingerprint: Option<crate::config::tls::TlsClientFingerprint>,
    pub alpn_protocols: Option<Vec<String>>,
    pub mldsa65_verify: Option<super::reality_mldsa::VerifyKey>,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub server_name: ServerName<'static>,
    pub cipher_suites: Vec<CipherSuite>,
}

impl RealityClientConfig {
    pub fn create_connection(self) -> io::Result<TlsConnection> {
        let crypto =
            if self.client_fingerprint == Some(crate::config::tls::TlsClientFingerprint::Chrome) {
                crate::rustls_config_util::browser::validate_reality_suites(&self.cipher_suites)?;
                crate::rustls_config_util::browser::provider()
            } else {
                provider(&self.cipher_suites)
            };
        let schemes = crypto.signature_verification_algorithms.supported_schemes();
        self.create_connection_with_options(crypto, schemes, Arc::new(rustls::NoKeyLog {}))
    }

    pub(super) fn create_connection_with_options(
        self,
        crypto: rustls::crypto::CryptoProvider,
        schemes: Vec<rustls::SignatureScheme>,
        key_log: Arc<dyn rustls::KeyLog>,
    ) -> io::Result<TlsConnection> {
        let (hooks, verifier) = client_authentication(&self, schemes);
        let mut tls = rustls::ClientConfig::builder_with_details(
            Arc::new(crypto),
            crate::clock::time_provider(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
        tls.alpn_protocols = self
            .alpn_protocols
            .unwrap_or_else(|| vec!["h2".into(), "http/1.1".into()])
            .into_iter()
            .map(String::into_bytes)
            .collect();
        if self.client_fingerprint != Some(crate::config::tls::TlsClientFingerprint::Chrome) {
            tls.cert_decompressors.clear();
        }
        tls.key_log = key_log;
        match self.client_fingerprint {
            Some(crate::config::tls::TlsClientFingerprint::Chrome) => {
                crate::rustls_config_util::browser::configure(&mut tls, true)?;
            }
            Some(crate::config::tls::TlsClientFingerprint::Firefox) => {
                tls.client_hello_profile = Some(rustls::client::ClientHelloProfile::Firefox);
                // REALITY authenticates with the independent X25519 exchange;
                // the target may negotiate either offered group for TLS.
                tls.initial_key_share_groups = vec![
                    rustls::NamedGroup::X25519MLKEM768,
                    rustls::NamedGroup::X25519,
                ];
            }
            None => {}
        }
        let connection =
            rustls::ClientConnection::new_reality(Arc::new(tls), self.server_name, Box::new(hooks))
                .map_err(tls_error)?;
        Ok(TlsConnection::new_reality(connection))
    }
}
