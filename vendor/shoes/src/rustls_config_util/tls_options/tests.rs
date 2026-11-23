use super::*;
use crate::rustls_config_util::{try_create_client_config_with_options, try_create_server_config};

fn fixture() -> (String, String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.cert.der()).unwrap();
    let pin = STANDARD.encode(aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        parsed.public_key().raw,
    ));
    (cert.cert.pem(), cert.signing_key.serialize_pem(), pin)
}

fn client(
    options: &TlsClientOptions,
    verify: bool,
    quic: bool,
) -> io::Result<rustls::ClientConfig> {
    try_create_client_config_with_options(
        verify,
        vec![],
        vec![],
        true,
        None,
        quic,
        &Default::default(),
        options,
    )
}

#[test]
fn chrome_uses_independent_hybrid_shares_and_rejects_conflicting_groups() {
    use crate::config::{TlsKeyExchangeGroups, tls::TlsClientFingerprint};
    let options = TlsClientOptions {
        client_fingerprint: Some(TlsClientFingerprint::Chrome),
        ..Default::default()
    };
    let config = client(&options, false, false).unwrap();
    assert_eq!(
        config.crypto_provider().kx_groups[0].name(),
        rustls::NamedGroup::X25519MLKEM768
    );
    let explicit: TlsKeyExchangeGroups = serde_yaml::from_str("[SecP384r1]").unwrap();
    assert!(
        try_create_client_config_with_options(
            false,
            vec![],
            vec![],
            true,
            None,
            false,
            &explicit,
            &options,
        )
        .is_err()
    );
    assert_eq!(
        config.initial_key_share_groups,
        [
            rustls::NamedGroup::X25519MLKEM768,
            rustls::NamedGroup::X25519
        ]
    );
}

fn handshake(
    config: rustls::ClientConfig,
    cert: &str,
    key: &str,
    name: &str,
) -> Result<(rustls::ClientConnection, rustls::ServerConnection), rustls::Error> {
    let mut client =
        rustls::ClientConnection::new(Arc::new(config), name.to_owned().try_into().unwrap())?;
    let mut server = rustls::ServerConnection::new(Arc::new(
        try_create_server_config(
            cert.as_bytes(),
            key.as_bytes(),
            vec![],
            &[],
            &[],
            &Default::default(),
        )
        .unwrap(),
    ))?;
    for _ in 0..12 {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        for fragment in bytes.chunks(23) {
            server.read_tls(&mut &fragment[..]).unwrap();
            server.process_new_packets()?;
        }
        bytes.clear();
        server.write_tls(&mut bytes).unwrap();
        for fragment in bytes.chunks(23) {
            client.read_tls(&mut &fragment[..]).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            return Ok((client, server));
        }
    }
    panic!("TLS options handshake did not converge")
}

#[test]
fn custom_roots_and_leaf_spki_pins_both_apply() {
    let (cert, key, pin) = fixture();
    let (_, _, other_pin) = fixture();
    let options = TlsClientOptions {
        root_certificates: vec![cert.clone()],
        certificate_public_key_sha256: vec![other_pin.clone(), pin],
        ..Default::default()
    };
    handshake(
        client(&options, true, false).unwrap(),
        &cert,
        &key,
        "localhost",
    )
    .unwrap();
    assert!(
        handshake(
            client(&options, true, false).unwrap(),
            &cert,
            &key,
            "wrong.test"
        )
        .is_err()
    );
    let mut wrong_pin = options.clone();
    wrong_pin.certificate_public_key_sha256 = vec![other_pin];
    assert!(
        handshake(
            client(&wrong_pin, true, false).unwrap(),
            &cert,
            &key,
            "localhost"
        )
        .is_err()
    );
    assert!(
        handshake(
            client(&wrong_pin, false, false).unwrap(),
            &cert,
            &key,
            "localhost"
        )
        .is_err()
    );
    let mut wrong_roots = options.clone();
    wrong_roots.root_certificates = vec![fixture().0];
    assert!(
        handshake(
            client(&wrong_roots, true, false).unwrap(),
            &cert,
            &key,
            "localhost"
        )
        .is_err()
    );
    // Explicit verify:false skips PKI/name validation but never bypasses pins.
    handshake(
        client(&wrong_roots, false, false).unwrap(),
        &cert,
        &key,
        "wrong.test",
    )
    .unwrap();
}

#[test]
fn disabling_sni_preserves_certificate_name_validation_and_tls_bounds() {
    let (cert, key, _) = fixture();
    for (version, suite, expected) in [
        (
            TlsVersion::V12,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            rustls::ProtocolVersion::TLSv1_2,
        ),
        (
            TlsVersion::V13,
            "TLS_AES_256_GCM_SHA384",
            rustls::ProtocolVersion::TLSv1_3,
        ),
        (
            TlsVersion::V13,
            "TLS_CHACHA20_POLY1305_SHA256",
            rustls::ProtocolVersion::TLSv1_3,
        ),
    ] {
        let options = TlsClientOptions {
            root_certificates: vec![cert.clone()],
            min_version: Some(version),
            max_version: Some(version),
            cipher_suites: vec![suite.into()],
            disable_sni: true,
            ..Default::default()
        };
        let config = client(&options, true, false).unwrap();
        assert!(!config.enable_sni);
        assert_eq!(config.crypto_provider().cipher_suites.len(), 1);
        let (connection, server) = handshake(config, &cert, &key, "localhost").unwrap();
        assert_eq!(connection.protocol_version(), Some(expected));
        assert_eq!(server.server_name(), None);
        assert!(
            handshake(
                client(&options, true, false).unwrap(),
                &cert,
                &key,
                "wrong.test"
            )
            .is_err()
        );
        if version == TlsVersion::V13 {
            quinn::crypto::rustls::QuicClientConfig::with_initial(
                Arc::new(client(&options, true, true).unwrap()),
                aerobox_crypto::TLS13_AES_128_GCM_SHA256
                    .quic_suite()
                    .unwrap(),
            )
            .unwrap();
        }
    }
}

#[test]
fn invalid_tls_policies_fail_before_any_connection() {
    for json in [r#"{"min_version":"1.1"}"#, r#"{"unknown_option":true}"#] {
        assert!(serde_json::from_str::<TlsClientOptions>(json).is_err());
    }
    for json in [
        r#"{"min_version":"1.3","max_version":"1.2"}"#,
        r#"{"root_certificates":["not a PEM certificate"]}"#,
        r#"{"certificate_public_key_sha256":["invalid base64"]}"#,
        r#"{"certificate_public_key_sha256":["AQID"]}"#,
        r#"{"cipher_suites":["TLS_RSA_WITH_RC4_128_SHA"]}"#,
        r#"{"cipher_suites":["TLS_AES_128_GCM_SHA256","TLS13_AES_128_GCM_SHA256"]}"#,
        r#"{"min_version":"1.3","cipher_suites":["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"]}"#,
    ] {
        let options: TlsClientOptions = serde_json::from_str(json).unwrap();
        assert!(client(&options, false, false).is_err(), "{json}");
    }
    assert!(
        client(
            &TlsClientOptions {
                max_version: Some(TlsVersion::V12),
                ..Default::default()
            },
            false,
            true
        )
        .is_err()
    );
}

#[tokio::test]
async fn named_and_file_roots_are_embedded_and_validated() {
    let (cert, _, pin) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root.pem");
    std::fs::write(&path, &cert).unwrap();
    for root in ["named-root".to_owned(), path.to_string_lossy().to_string()] {
        let entries = serde_json::json!([
            {"pem":"named-root", "data":cert},
            {"address":"127.0.0.1:19080", "protocol":{"type":"socks"}, "rules":[{
                "mask":"0.0.0.0/0", "action":"allow", "client_chain":[{
                    "address":"127.0.0.1:443", "protocol":{"type":"tls", "sni_hostname":"localhost", "options":{
                        "root_certificates":[root], "certificate_public_key_sha256":[pin], "disable_sni":true
                    }, "protocol":{"type":"socks"}}
                }]
            }]}
        ]);
        crate::embedding::EmbeddedCore::check_json(&entries.to_string())
            .await
            .unwrap();
    }
}

#[test]
fn explicit_cbc_and_rsa_suites_are_available_without_changing_default_policy() {
    let ordinary = client(&Default::default(), true, false).unwrap();
    assert_eq!(ordinary.crypto_provider().cipher_suites.len(), 9);
    for (suite, identifier) in [
        ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xc013),
        ("TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009c),
        ("TLS_RSA_WITH_AES_256_CBC_SHA", 0x0035),
    ] {
        let policy = TlsClientOptions {
            max_version: Some(TlsVersion::V12),
            cipher_suites: vec![suite.into()],
            ..Default::default()
        };
        let configured = client(&policy, true, false).unwrap();
        assert_eq!(configured.crypto_provider().cipher_suites.len(), 1);
        assert_eq!(
            u16::from(configured.crypto_provider().cipher_suites[0].suite()),
            identifier
        );
    }
}
