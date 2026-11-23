//! Observe serialized records, then complete the handshake with those exact
//! records. This catches layouts that look correct in structs but break the
//! transcript, PSK binder, or an actual second key exchange.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use rustls::client::ClientHelloProfile as FirefoxProfile;
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, HandshakeKind, NamedGroup, ProtocolVersion, RootCertStore,
    ServerConfig, ServerConnection, SupportedProtocolVersion,
};
use shoes::config::tls::{TlsClientFingerprint as ClientHelloProfile, TlsClientOptions};

const PROFILES: [ClientHelloProfile; 2] = [ClientHelloProfile::Chrome, ClientHelloProfile::Firefox];

#[derive(Debug)]
struct WireHello {
    ciphers: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
    handshake_len: usize,
}

impl WireHello {
    fn read(records: &[u8]) -> Self {
        let mut remaining = records;
        let mut handshake = Vec::new();
        while !remaining.is_empty() {
            let header = take(&mut remaining, 5);
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let payload = take(&mut remaining, len);
            if header[0] == 22 {
                handshake.extend_from_slice(payload);
            }
        }
        assert_eq!(handshake[0], 1);
        let length = (usize::from(handshake[1]) << 16)
            | (usize::from(handshake[2]) << 8)
            | usize::from(handshake[3]);
        assert_eq!(handshake.len(), length + 4);
        let mut body = &handshake[4..];
        take(&mut body, 34); // legacy_version and random
        let sid_len = usize::from(take(&mut body, 1)[0]);
        take(&mut body, sid_len);
        let cipher_len = usize::from(number(&mut body));
        let ciphers = numbers(take(&mut body, cipher_len));
        let compression_len = usize::from(take(&mut body, 1)[0]);
        assert_eq!(take(&mut body, compression_len), &[0]);
        let extension_len = usize::from(number(&mut body));
        assert_eq!(extension_len, body.len());
        let mut extensions = Vec::new();
        while !body.is_empty() {
            let kind = number(&mut body);
            let len = usize::from(number(&mut body));
            assert!(!extensions.iter().any(|(existing, _)| *existing == kind));
            extensions.push((kind, take(&mut body, len).to_vec()));
        }
        Self {
            ciphers,
            extensions,
            handshake_len: handshake.len(),
        }
    }

    fn extension(&self, kind: u16) -> &[u8] {
        &self
            .extensions
            .iter()
            .find(|(typ, _)| *typ == kind)
            .unwrap()
            .1
    }

    fn shares(&self) -> Vec<(u16, Vec<u8>)> {
        let mut body = self.extension(51);
        let len = usize::from(number(&mut body));
        assert_eq!(len, body.len());
        let mut shares = Vec::new();
        while !body.is_empty() {
            let group = number(&mut body);
            let len = usize::from(number(&mut body));
            shares.push((group, take(&mut body, len).to_vec()));
        }
        shares
    }
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> &'a [u8] {
    let (front, rest) = input.split_at(len);
    *input = rest;
    front
}

fn number(input: &mut &[u8]) -> u16 {
    u16::from_be_bytes(take(input, 2).try_into().unwrap())
}

fn numbers(mut input: &[u8]) -> Vec<u16> {
    let mut values = Vec::new();
    while !input.is_empty() {
        values.push(number(&mut input));
    }
    values
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}

fn classical_provider() -> CryptoProvider {
    aerobox_crypto::provider()
}

fn chrome_template() -> ClientConfig {
    shoes::try_create_client_config_with_options(
        false,
        vec![],
        vec![],
        true,
        None,
        false,
        &Default::default(),
        &TlsClientOptions {
            client_fingerprint: Some(ClientHelloProfile::Chrome),
            ..Default::default()
        },
    )
    .unwrap()
}
fn profile_provider(profile: ClientHelloProfile) -> CryptoProvider {
    match profile {
        ClientHelloProfile::Chrome => chrome_template().crypto_provider().as_ref().clone(),
        ClientHelloProfile::Firefox => classical_provider(),
    }
}
fn apply_profile(config: &mut ClientConfig, profile: ClientHelloProfile, reality: bool) {
    match profile {
        ClientHelloProfile::Chrome => {
            let template = chrome_template();
            config.client_hello_layout = template.client_hello_layout;
            config.application_settings = template.application_settings;
            config.initial_key_share_groups = if reality {
                vec![NamedGroup::X25519]
            } else {
                template.initial_key_share_groups
            };
            config.alpn_protocols = template.alpn_protocols;
            config.cert_decompressors = template.cert_decompressors;
            config.enable_tls12_renegotiation = !reality;
            config.resumption = rustls::client::Resumption::disabled();
        }
        ClientHelloProfile::Firefox => config.client_hello_profile = Some(FirefoxProfile::Firefox),
    }
}

fn configs(
    client_provider: &CryptoProvider,
    server_provider: &CryptoProvider,
    versions: &[&'static SupportedProtocolVersion],
) -> (ClientConfig, ServerConfig) {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(identity.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(Arc::new(client_provider.clone()))
        .with_protocol_versions(
            if versions.len() == 1 && versions[0].version == ProtocolVersion::TLSv1_2 {
                rustls::ALL_VERSIONS
            } else {
                versions
            },
        )
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(Arc::new(server_provider.clone()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.cert.der().clone()],
            PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
        )
        .unwrap();
    (client, server)
}

fn pair(config: ClientConfig, server_config: ServerConfig) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap(),
        ServerConnection::new(Arc::new(server_config)).unwrap(),
    )
}

fn do_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..32 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        feed_server(server, &wire);
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        feed_client(client, &wire);
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }
    panic!("TLS handshake made no progress");
}

fn feed_client(client: &mut ClientConnection, wire: &[u8]) {
    let mut remaining = wire;
    while !remaining.is_empty() {
        assert!(client.read_tls(&mut remaining).unwrap() > 0);
        client.process_new_packets().unwrap();
    }
}

fn feed_server(server: &mut ServerConnection, wire: &[u8]) {
    let mut remaining = wire;
    while !remaining.is_empty() {
        assert!(server.read_tls(&mut remaining).unwrap() > 0);
        server.process_new_packets().unwrap();
    }
}

#[test]
fn profile_wire_contains_real_capabilities_and_browser_layout() {
    for profile in PROFILES {
        let crypto = profile_provider(profile);
        let (mut config, server_config) = configs(&crypto, &crypto, rustls::ALL_VERSIONS);
        apply_profile(&mut config, profile, false);
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let (mut client, _) = pair(config, server_config);
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        let hello = WireHello::read(&wire);
        for suite in hello.ciphers.iter().filter(|suite| !is_grease(**suite)) {
            assert!(
                crypto
                    .cipher_suites
                    .iter()
                    .any(|cs| u16::from(cs.suite()) == *suite)
            );
        }
        assert_eq!(
            hello.extension(0),
            &[
                0, 12, 0, 0, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't'
            ]
        );
        assert_eq!(hello.extension(16), b"\x00\x0c\x02h2\x08http/1.1");
        assert_eq!(hello.extension(0xff01), &[0]);
        let mut ech = hello.extension(0xfe0d);
        assert_eq!(take(&mut ech, 1), [0]); // outer GREASE ECH
        assert_eq!(number(&mut ech), 1); // HKDF-SHA256
        let aead = number(&mut ech);
        assert!(aead == 1 || (profile == ClientHelloProfile::Firefox && aead == 3));
        take(&mut ech, 1); // random config ID
        assert_eq!(number(&mut ech), 32);
        take(&mut ech, 32); // encapsulated key
        let payload_len = usize::from(number(&mut ech));
        assert_eq!(ech.len(), payload_len);
        match profile {
            ClientHelloProfile::Chrome => {
                assert!([144, 176, 208, 240].contains(&payload_len));
                assert_eq!(hello.extension(27), [2, 0, 2]); // Brotli
            }
            ClientHelloProfile::Firefox => {
                assert_eq!(payload_len, 239);
                assert!(!hello.extensions.iter().any(|(kind, _)| *kind == 27));
            }
        }
        let shares = hello.shares();
        let groups = numbers(&hello.extension(10)[2..]);
        assert!(shares.iter().all(|(group, _)| groups.contains(group)));
        let real_groups: Vec<_> = groups
            .into_iter()
            .filter(|group| !is_grease(*group))
            .collect();
        assert_eq!(
            real_groups,
            if profile == ClientHelloProfile::Chrome {
                vec![4588, 29, 23, 24]
            } else {
                vec![29, 23, 24, 25]
            }
        );
        let signatures = numbers(&hello.extension(13)[2..]);
        assert_eq!(signatures[0], 0x0403);
        match profile {
            ClientHelloProfile::Chrome => {
                assert!(is_grease(hello.ciphers[0]));
                assert_eq!(&hello.ciphers[1..4], &[0x1301, 0x1302, 0x1303]);
                assert!(is_grease(hello.extensions[0].0));
                assert_eq!(
                    hello
                        .extensions
                        .iter()
                        .filter(|(typ, _)| is_grease(*typ))
                        .count(),
                    2
                );
                assert!(is_grease(shares[0].0));
                assert_eq!(shares[0].1, [0]);
                assert_eq!(shares[1].0, 4588);
                assert_eq!(shares[1].1.len(), 1216);
                assert_eq!(shares[2].0, 29);
                assert_eq!(shares[2].1.len(), 32);
                assert_ne!(&shares[1].1[1184..], shares[2].1);
                assert_eq!(hello.ciphers.len(), 16);
                assert_eq!(hello.extension(17613), b"\x00\x03\x02h2");
                assert!(is_grease(u16::from_be_bytes(
                    hello.extension(43)[1..3].try_into().unwrap()
                )));
                assert!(hello.extension(18).is_empty());
                assert_eq!(&signatures[..3], &[0x0403, 0x0804, 0x0401]);
                assert!(!(256..512).contains(&hello.handshake_len));
            }
            ClientHelloProfile::Firefox => {
                assert_eq!(&hello.ciphers[..3], &[0x1301, 0x1303, 0x1302]);
                assert!(!hello.extensions.iter().any(|(typ, _)| is_grease(*typ)));
                assert_eq!(
                    shares.iter().map(|(group, _)| *group).collect::<Vec<_>>(),
                    [29, 23]
                );
                assert_eq!(shares[0].1.len(), 32);
                assert_eq!(shares[1].1.len(), 65);
                assert_eq!(signatures[1], 0x0503);
                let expected = [0, 23, 0xff01, 10, 11, 35, 16, 5, 51, 43, 13, 45];
                let actual: Vec<_> = hello
                    .extensions
                    .iter()
                    .map(|(typ, _)| *typ)
                    .filter(|typ| expected.contains(typ))
                    .collect();
                let expected: Vec<_> = expected
                    .into_iter()
                    .filter(|typ| actual.contains(typ))
                    .collect();
                assert_eq!(actual, expected);
            }
        }
    }
}

#[test]
fn profile_handshakes_and_resumes_tls12_and_tls13() {
    for profile in PROFILES {
        let crypto = profile_provider(profile);
        for version in rustls::ALL_VERSIONS {
            let (mut config, server_config) = configs(&crypto, &crypto, &[version]);
            apply_profile(&mut config, profile, false);
            for expected in [
                HandshakeKind::Full,
                if profile == ClientHelloProfile::Chrome {
                    HandshakeKind::Full
                } else {
                    HandshakeKind::Resumed
                },
            ] {
                let (mut client, mut server) = pair(config.clone(), server_config.clone());
                let mut wire = Vec::new();
                client.write_tls(&mut wire).unwrap();
                if expected == HandshakeKind::Resumed && version.version == ProtocolVersion::TLSv1_3
                {
                    assert_eq!(WireHello::read(&wire).extensions.last().unwrap().0, 41);
                }
                feed_server(&mut server, &wire);
                do_handshake(&mut client, &mut server);
                assert_eq!(client.protocol_version(), Some(version.version));
                assert_eq!(client.handshake_kind(), Some(expected));
                client.writer().write_all(b"profile roundtrip").unwrap();
                let mut wire = Vec::new();
                client.write_tls(&mut wire).unwrap();
                feed_server(&mut server, &wire);
                let mut plain = [0; 17];
                server.reader().read_exact(&mut plain).unwrap();
                assert_eq!(&plain, b"profile roundtrip");
            }
        }
    }
}

#[test]
fn firefox_second_share_completes_without_retry() {
    let crypto = classical_provider();
    let mut server_crypto = crypto.clone();
    server_crypto
        .kx_groups
        .retain(|group| group.name() == NamedGroup::secp256r1);
    let (mut config, server_config) = configs(&crypto, &server_crypto, &[&rustls::version::TLS13]);
    config.client_hello_profile = Some(FirefoxProfile::Firefox);
    let (mut client, mut server) = pair(config, server_config);
    do_handshake(&mut client, &mut server);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp256r1
    );
}

#[derive(Debug)]
struct CountingBrotli(std::sync::atomic::AtomicUsize);

impl rustls::compress::CertDecompressor for CountingBrotli {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), rustls::compress::DecompressionFailed> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        rustls::compress::BROTLI_DECOMPRESSOR.decompress(input, output)
    }

    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::compress::BROTLI_DECOMPRESSOR.algorithm()
    }
}

#[test]
fn chrome_hybrid_shares_and_brotli_certificates_complete_a_real_handshake() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DECOMPRESSOR: CountingBrotli = CountingBrotli(AtomicUsize::new(0));
    let template = chrome_template();
    let crypto = template.crypto_provider().as_ref().clone();
    for selected in [NamedGroup::X25519MLKEM768, NamedGroup::X25519] {
        let mut server_crypto = crypto.clone();
        server_crypto
            .kx_groups
            .retain(|group| group.name() == selected);
        let (mut config, mut server_config) =
            configs(&crypto, &server_crypto, &[&rustls::version::TLS13]);
        config.client_hello_layout = template.client_hello_layout;
        config.application_settings = template.application_settings.clone();
        config.initial_key_share_groups = template.initial_key_share_groups.clone();
        config.alpn_protocols = template.alpn_protocols.clone();
        config.cert_decompressors = vec![&DECOMPRESSOR];
        server_config.cert_compressors = vec![rustls::compress::BROTLI_COMPRESSOR];
        let before = DECOMPRESSOR.0.load(Ordering::Relaxed);
        let (mut client, mut server) = pair(config, server_config);
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        let hello = WireHello::read(&wire);
        let shares: Vec<_> = hello
            .shares()
            .into_iter()
            .filter(|(group, _)| !is_grease(*group))
            .collect();
        assert_eq!(
            shares
                .iter()
                .map(|(group, data)| (*group, data.len()))
                .collect::<Vec<_>>(),
            [(4588, 1216), (29, 32)]
        );
        assert_ne!(&shares[0].1[1184..], shares[1].1);
        feed_server(&mut server, &wire);
        do_handshake(&mut client, &mut server);
        assert_eq!(
            client.negotiated_key_exchange_group().unwrap().name(),
            selected
        );
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(DECOMPRESSOR.0.load(Ordering::Relaxed), before + 1);
        server
            .writer()
            .write_all(b"hybrid and Brotli roundtrip")
            .unwrap();
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        feed_client(&mut client, &wire);
        let mut received = [0; 27];
        client.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, b"hybrid and Brotli roundtrip");
    }
}

#[test]
fn profile_retry_preserves_layout_and_replaces_shares() {
    for profile in PROFILES {
        let crypto = profile_provider(profile);
        let mut server_crypto = crypto.clone();
        server_crypto
            .kx_groups
            .retain(|group| group.name() == NamedGroup::secp384r1);
        let (mut config, server_config) =
            configs(&crypto, &server_crypto, &[&rustls::version::TLS13]);
        apply_profile(&mut config, profile, false);
        let (mut client, mut server) = pair(config, server_config);
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        let initial = WireHello::read(&wire);
        feed_server(&mut server, &wire);
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        feed_client(&mut client, &wire);
        wire.clear();
        client.write_tls(&mut wire).unwrap();
        let retry = WireHello::read(&wire);
        assert_eq!(retry.ciphers, initial.ciphers);
        assert_eq!(retry.extension(10), initial.extension(10));
        assert_eq!(retry.extension(43), initial.extension(43));
        let stable = |hello: &WireHello| {
            hello
                .extensions
                .iter()
                .filter(|(kind, _)| ![21, 51].contains(kind))
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(stable(&retry), stable(&initial));
        assert_eq!(
            retry
                .shares()
                .iter()
                .map(|(group, _)| *group)
                .collect::<Vec<_>>(),
            [24]
        );
        assert_eq!(retry.shares()[0].1.len(), 97);
        feed_server(&mut server, &wire);
        do_handshake(&mut client, &mut server);
        assert_eq!(
            client.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_eq!(
            client.negotiated_key_exchange_group().unwrap().name(),
            NamedGroup::secp384r1
        );
    }
}

#[derive(Debug)]
struct RealityHooks(Arc<Mutex<Vec<u8>>>);

impl rustls::reality::ClientHooks for RealityHooks {
    fn start_key_exchange(
        &mut self,
        group: &'static dyn SupportedKxGroup,
    ) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        group.start()
    }

    fn session_id(&mut self, hello: &[u8]) -> Result<[u8; 32], rustls::Error> {
        assert_eq!(hello[0], 1);
        assert_eq!(hello[38], 32);
        Ok([0xa7; 32])
    }

    fn server_hello(&mut self, client: &[u8], _server: &[u8]) -> Result<(), rustls::Error> {
        *self.0.lock().unwrap() = client.to_vec();
        Ok(())
    }
}

#[test]
fn profile_preserves_reality_final_hello_and_authentication_exchange() {
    for profile in PROFILES {
        let crypto = profile_provider(profile);
        let (mut config, server_config) = configs(&crypto, &crypto, &[&rustls::version::TLS13]);
        apply_profile(&mut config, profile, true);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let mut client = ClientConnection::new_reality(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
            Box::new(RealityHooks(captured.clone())),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        let hello = WireHello::read(&wire);
        assert_eq!(&wire[44..76], &[0xa7; 32]);
        // No unrelated P-256 exchange can supersede REALITY's authenticated
        // exchange. GREASE may precede the one real X25519 share.
        let shares: Vec<_> = hello
            .shares()
            .into_iter()
            .filter(|(group, _)| !is_grease(*group))
            .collect();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].0, 29);
        feed_server(&mut server, &wire);
        do_handshake(&mut client, &mut server);
        assert_eq!(*captured.lock().unwrap(), wire[5..]);
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    }
}

#[test]
fn firefox_explicit_shares_never_offer_an_automatic_untracked_exchange() {
    let crypto = classical_provider();
    let mut server_crypto = crypto.clone();
    server_crypto
        .kx_groups
        .retain(|g| g.name() == NamedGroup::secp256r1);
    let (mut config, server_config) = configs(&crypto, &server_crypto, &[&rustls::version::TLS13]);
    config.client_hello_profile = Some(FirefoxProfile::Firefox);
    config.initial_key_share_groups = vec![NamedGroup::X25519];
    let (mut client, mut server) = pair(config, server_config);
    let mut wire = vec![];
    client.write_tls(&mut wire).unwrap();
    assert_eq!(
        WireHello::read(&wire)
            .shares()
            .iter()
            .map(|s| s.0)
            .collect::<Vec<_>>(),
        [29]
    );
    feed_server(&mut server, &wire);
    do_handshake(&mut client, &mut server);
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(
        client.negotiated_key_exchange_group().unwrap().name(),
        NamedGroup::secp256r1
    );
}

#[derive(Debug, Default)]
struct HandshakeSecret(Mutex<Vec<u8>>);
impl rustls::KeyLog for HandshakeSecret {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
            *self.0.lock().unwrap() = secret.to_vec();
        }
    }
}

#[test]
fn firefox_rejects_compressed_certificates_it_did_not_offer() {
    use rustls::ContentType;
    use rustls::crypto::{
        cipher::{InboundOpaqueMessage, OutboundPlainMessage},
        tls13::OkmBlock,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    static DECOMPRESSOR: CountingBrotli = CountingBrotli(AtomicUsize::new(0));
    let mut crypto = classical_provider();
    crypto
        .cipher_suites
        .retain(|s| s.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
    let suite = crypto.cipher_suites[0].tls13().unwrap();
    let (mut config, mut server_config) = configs(&crypto, &crypto, &[&rustls::version::TLS13]);
    config.client_hello_profile = Some(FirefoxProfile::Firefox);
    config.cert_decompressors = vec![&DECOMPRESSOR];
    let secrets = Arc::new(HandshakeSecret::default());
    server_config.key_log = secrets.clone();
    server_config.cert_compressors.clear();
    let (mut client, mut server) = pair(config, server_config);
    let mut wire = vec![];
    client.write_tls(&mut wire).unwrap();
    assert!(!WireHello::read(&wire).extensions.iter().any(|e| e.0 == 27));
    feed_server(&mut server, &wire);
    wire.clear();
    server.write_tls(&mut wire).unwrap();
    // Simulate a server that sends a compressed certificate without permission.
    // Re-encrypt its flight with the authentic handshake traffic secret; changing
    // ClientHello would instead produce an unrelated record decryption failure.
    let expander = suite
        .hkdf_provider
        .expander_for_okm(&OkmBlock::new(&secrets.0.lock().unwrap()));
    let mut key = [0; 32];
    let mut iv = [0; 12];
    expander
        .expand_slice(&[b"\x00\x20\x09tls13 key\x00"], &mut key)
        .unwrap();
    expander
        .expand_slice(&[b"\x00\x0c\x08tls13 iv\x00"], &mut iv)
        .unwrap();
    let mut decrypt = suite.aead_alg.decrypter(key.into(), iv.into());
    let mut encrypt = suite.aead_alg.encrypter(key.into(), iv.into());
    let mut input = wire.as_slice();
    let mut output = vec![];
    let mut sequence = 0;
    let mut replaced = false;
    while !input.is_empty() {
        let header = take(&mut input, 5);
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let body = take(&mut input, length);
        if header[0] != 23 {
            output.extend_from_slice(header);
            output.extend_from_slice(body);
            continue;
        }
        let mut body = body.to_vec();
        let plain = decrypt
            .decrypt(
                InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    &mut body,
                ),
                sequence,
            )
            .unwrap();
        let mut messages = plain.payload;
        let mut modified = vec![];
        while !messages.is_empty() {
            let header = take(&mut messages, 4);
            let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
            let body = take(&mut messages, length);
            if header[0] == 11 {
                let compressed = rustls::compress::BROTLI_COMPRESSOR
                    .compress(
                        body.to_vec(),
                        rustls::compress::CompressionLevel::Interactive,
                    )
                    .unwrap();
                let mut certificate = vec![0, 2];
                certificate.extend_from_slice(&(length as u32).to_be_bytes()[1..]);
                certificate.extend_from_slice(&(compressed.len() as u32).to_be_bytes()[1..]);
                certificate.extend_from_slice(&compressed);
                modified.push(25);
                modified.extend_from_slice(&(certificate.len() as u32).to_be_bytes()[1..]);
                modified.extend_from_slice(&certificate);
                replaced = true;
            } else {
                modified.extend_from_slice(header);
                modified.extend_from_slice(body);
            }
        }
        output.extend_from_slice(
            &encrypt
                .encrypt(
                    OutboundPlainMessage {
                        typ: ContentType::Handshake,
                        version: ProtocolVersion::TLSv1_3,
                        payload: modified.as_slice().into(),
                    },
                    sequence,
                )
                .unwrap()
                .encode(),
        );
        sequence += 1;
    }
    assert!(replaced);
    let before = DECOMPRESSOR.0.load(Ordering::Relaxed);
    let mut input = output.as_slice();
    let error = loop {
        assert!(!input.is_empty());
        assert!(client.read_tls(&mut input).unwrap() > 0);
        if let Err(error) = client.process_new_packets() {
            break error;
        }
    };
    assert!(
        matches!(error, rustls::Error::InappropriateHandshakeMessage { .. }),
        "{error:?}"
    );
    assert_eq!(DECOMPRESSOR.0.load(Ordering::Relaxed), before);
}
