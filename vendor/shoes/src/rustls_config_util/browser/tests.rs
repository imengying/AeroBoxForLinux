use super::*;
use crate::config::tls::TlsClientFingerprint;
use crate::rustls_config_util::try_create_client_config_with_options;
use std::sync::Arc;

fn options() -> TlsClientOptions {
    TlsClientOptions {
        client_fingerprint: Some(TlsClientFingerprint::Chrome),
        ..Default::default()
    }
}
fn client(options: &TlsClientOptions, tls13: bool) -> io::Result<ClientConfig> {
    try_create_client_config_with_options(
        true,
        vec![],
        vec![],
        true,
        None,
        tls13,
        &Default::default(),
        options,
    )
}
#[test]
fn explicit_profile_preserves_default_tls_and_rejects_conflicting_policy() {
    let ordinary = client(&Default::default(), false).unwrap();
    assert!(ordinary.client_hello_layout.is_none());
    assert!(!ordinary.enable_tls12_renegotiation);
    assert!(ordinary.alpn_protocols.is_empty());
    let chrome = client(&options(), false).unwrap();
    assert!(chrome.enable_tls12_renegotiation);
    assert_eq!(
        chrome.alpn_protocols,
        [b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert_eq!(chrome.cert_decompressors.len(), 1);
    for bad in [
        TlsClientOptions {
            min_version: Some(TlsVersion::V13),
            ..options()
        },
        TlsClientOptions {
            max_version: Some(TlsVersion::V12),
            ..options()
        },
        TlsClientOptions {
            cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
            ..options()
        },
    ] {
        assert!(client(&bad, false).is_err());
    }
    let groups = serde_json::from_str::<TlsKeyExchangeGroups>("[\"X25519\"]").unwrap();
    assert!(
        try_create_client_config_with_options(
            true,
            vec![],
            vec![],
            true,
            None,
            false,
            &groups,
            &options()
        )
        .is_err()
    );
}

fn pair(
    mut client: ClientConfig,
    tls12: bool,
    name: &str,
    cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> Result<(), rustls::Error> {
    client.resumption = rustls::client::Resumption::disabled();
    let mut client =
        rustls::ClientConnection::new(Arc::new(client), name.to_owned().try_into().unwrap())?;
    let server = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
        .with_protocol_versions(&[if tls12 {
            &rustls::version::TLS12
        } else {
            &rustls::version::TLS13
        }])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server))?;
    for _ in 0..12 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets()?;
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        for chunk in wire.chunks(23) {
            client.read_tls(&mut chunk.as_ref()).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("Chrome handshake did not converge")
}
#[test]
fn chrome_keeps_certificate_pin_sni_and_vision_tls13_enforcement() {
    use base64::Engine;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.cert.der()).unwrap();
    let pin = base64::engine::general_purpose::STANDARD.encode(aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        parsed.public_key().raw,
    ));
    let mut policy = TlsClientOptions {
        root_certificates: vec![cert.cert.pem()],
        certificate_public_key_sha256: vec![pin],
        ..options()
    };
    for tls13_only in [false, true] {
        pair(
            client(&policy, tls13_only).unwrap(),
            false,
            "localhost",
            &cert,
        )
        .unwrap();
        assert!(
            pair(
                client(&policy, tls13_only).unwrap(),
                false,
                "wrong.test",
                &cert
            )
            .is_err()
        );
    }
    pair(client(&policy, false).unwrap(), true, "localhost", &cert).unwrap();
    assert!(pair(client(&policy, true).unwrap(), true, "localhost", &cert).is_err());
    policy.disable_sni = true;
    pair(client(&policy, false).unwrap(), false, "localhost", &cert).unwrap();
    policy.certificate_public_key_sha256 =
        vec![base64::engine::general_purpose::STANDARD.encode([0; 32])];
    assert!(pair(client(&policy, false).unwrap(), false, "localhost", &cert).is_err());
}

#[tokio::test]
async fn native_compiler_keeps_profile_and_rejects_quic_and_reality_conflicts() {
    use serde_json::json;
    async fn compile(client: serde_json::Value) -> io::Result<crate::config::ValidatedConfigs> {
        crate::config::compile_configs(
            serde_json::from_value(json!([{
                "address":"127.0.0.1:0", "protocol":{"type":"socks"},
                "rules":[{"conditions":{"any_destination":true},"client_chain":client}]
            }]))
            .map_err(io::Error::other)?,
        )
        .await
    }
    let protocol = json!({"type":"tls","sni_hostname":"localhost","options":{"client_fingerprint":"chrome"},"protocol":{"type":"noop"}});
    let validated = compile(json!({"address":"127.0.0.1:443","protocol":protocol}))
        .await
        .unwrap();
    let crate::config::ResolvedConfig::Server(server) = &validated.configs[0] else {
        panic!("expected server");
    };
    let crate::config::ResolvedRuleActionConfig::Allow { client_chains, .. } =
        &server.rules.iter().next().unwrap().action
    else {
        panic!("expected allow rule")
    };
    let crate::config::ResolvedClientHop::Single(client) = client_chains
        .iter()
        .next()
        .unwrap()
        .hops
        .iter()
        .next()
        .unwrap()
    else {
        panic!("expected single hop")
    };
    let crate::config::ResolvedClientProxyConfig::Tls(tls) = &client.protocol else {
        panic!("expected TLS client");
    };
    assert_eq!(
        tls.options.client_fingerprint,
        Some(TlsClientFingerprint::Chrome)
    );
    assert!(compile(json!({"address":"127.0.0.1:443","transport":"quic","quic_settings":{"options":{"client_fingerprint":"chrome"}},"protocol":{"type":"noop"}})).await.is_err());
    let mut reality = json!({"address":"127.0.0.1:443","protocol":{"type":"reality","client_fingerprint":"chrome","sni_hostname":"cover.test","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0101010101010101","protocol":{"type":"noop"}}});
    compile(reality.clone()).await.unwrap();
    reality["protocol"]["cipher_suites"] = json!(["TLS_AES_128_GCM_SHA256"]);
    assert!(compile(reality).await.is_err());
}

mod interop;

#[test]
fn chrome_tls12_renegotiation_cannot_be_silently_lost_in_kernel_handoff() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let opts = TlsClientOptions {
        root_certificates: vec![cert.cert.pem()],
        kernel_tx: true,
        ..options()
    };
    let config = client(&opts, false).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut client =
        rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
    for _ in 0..12 {
        let mut wire = vec![];
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut wire.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        if !client.is_handshaking() && !server.is_handshaking() {
            assert!(
                client
                    .dangerous_into_kernel_connection()
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("renegotiation prevents kernel handoff")
            );
            return;
        }
    }
    panic!("TLS 1.2 handshake did not converge")
}
