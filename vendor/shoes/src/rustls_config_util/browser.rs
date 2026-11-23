//! Explicit, version-pinned browser policy shared by stream TLS and REALITY.
use std::io;

use crate::config::tls::{TlsClientOptions, TlsKeyExchangeGroup, TlsKeyExchangeGroups, TlsVersion};
use rustls::{
    ClientConfig, NamedGroup,
    client::{ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout},
};

pub(super) const CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];

pub(super) fn validate_policy(
    groups: &TlsKeyExchangeGroups,
    options: &TlsClientOptions,
) -> io::Result<()> {
    let expected = [
        TlsKeyExchangeGroup::X25519MLKEM768,
        TlsKeyExchangeGroup::X25519,
        TlsKeyExchangeGroup::SecP256r1,
        TlsKeyExchangeGroup::SecP384r1,
    ];
    if options.min_version.is_some_and(|v| v != TlsVersion::V12)
        || options.max_version.is_some_and(|v| v != TlsVersion::V13)
        || groups.groups().is_some_and(|g| g != expected)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Chrome133 conflicts with the explicit TLS version or key exchange policy",
        ));
    }
    Ok(())
}

pub(crate) fn validate_reality_suites(suites: &[crate::reality::CipherSuite]) -> io::Result<()> {
    use crate::reality::CipherSuite;
    if !suites.is_empty()
        && suites
            != [
                CipherSuite::AES_128_GCM_SHA256,
                CipherSuite::AES_256_GCM_SHA384,
                CipherSuite::CHACHA20_POLY1305_SHA256,
            ]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Chrome133 conflicts with the explicit REALITY cipher suite policy",
        ));
    }
    Ok(())
}

pub(crate) fn provider() -> rustls::crypto::CryptoProvider {
    let mut provider = aerobox_crypto::provider();
    let available: Vec<_> = provider
        .cipher_suites
        .iter()
        .copied()
        .chain(aerobox_crypto::legacy_cbc::suites())
        .chain(aerobox_crypto::legacy_rsa::suites())
        .collect();
    provider.cipher_suites = CIPHERS
        .iter()
        .map(|id| {
            *available
                .iter()
                .find(|suite| u16::from(suite.suite()) == *id)
                .expect("compiled Chrome133 cipher implementation")
        })
        .collect();
    provider.kx_groups = [
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ]
    .into_iter()
    .map(crate::crypto::rustcrypto_kx::group)
    .collect();
    provider
}

pub(crate) fn configure(config: &mut ClientConfig, reality: bool) -> io::Result<()> {
    if config.alpn_protocols.is_empty() {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    // The pinned uTLS wrapper overrides ALPN while retaining the h2 ALPS offer.
    config.application_settings = Some(
        ApplicationSettings::new(
            ApplicationSettingsCodepoint::Chrome,
            vec![(b"h2".to_vec(), vec![])],
        )
        .map_err(io::Error::other)?,
    );
    config.cert_compressors.clear();
    config.cert_decompressors = vec![rustls::compress::BROTLI_DECOMPRESSOR];
    config.initial_key_share_groups = if reality {
        vec![NamedGroup::X25519]
    } else {
        vec![NamedGroup::X25519MLKEM768, NamedGroup::X25519]
    };
    config.client_hello_layout = Some(ClientHelloLayout::Chrome133);
    config.enable_tls12_renegotiation = !reality;
    // sing-box's pinned wrapper does not configure a client session cache.
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(())
}

#[cfg(test)]
mod tests;
