use super::*;
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn exercise(
    version: &'static rustls::SupportedProtocolVersion,
    cipher: rustls::CipherSuite,
    tx: bool,
    rx: bool,
    update: bool,
    truncated: bool,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut provider = aerobox_crypto::provider();
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == cipher);
    let provider = Arc::new(provider);
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.enable_secret_extraction = true;
    client.alpn_protocols = vec![b"h2".to_vec()];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let is_tls13 = version.version == ProtocolVersion::TLSv1_3;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(server))
            .accept(socket)
            .await
            .unwrap();
        for n in 0..3u8 {
            if is_tls13 && update {
                tls.get_mut().1.refresh_traffic_keys().unwrap();
            }
            tls.write_all(&[n]).await.unwrap();
            tls.flush().await.unwrap();
            let mut ack = [0];
            tls.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack, [n]);
        }
        let mut input = Vec::new();
        tls.read_to_end(&mut input).await.unwrap();
        assert_eq!(input.len(), 256 * 1024);
        if is_tls13 && update {
            // A half-closed client must still install receive keys, without
            // trying to send a KeyUpdate response after close_notify.
            tls.get_mut().1.refresh_traffic_keys().unwrap();
        }
        tls.write_all(&input).await.unwrap();
        if truncated {
            tls.flush().await.unwrap();
        } else {
            tls.shutdown().await.unwrap();
        }
    });
    let session =
        rustls::ClientConnection::new(Arc::new(client), "localhost".try_into().unwrap()).unwrap();
    let mut tls = CryptoTlsStream::handshake(
        socket,
        TlsConnection::new(session),
        TlsReadMode::ExactRecords,
        &[],
    )
    .await
    .unwrap();
    tls.enable_kernel(tx, rx)
        .unwrap_or_else(|e| panic!("{cipher:?} TX={tx} RX={rx}: {e}"));
    assert_eq!(tls.alpn_protocol(), Some(&b"h2"[..]));
    for n in 0..3u8 {
        let mut value = [0];
        tls.read_exact(&mut value).await.unwrap();
        assert_eq!(value, [n]);
        tls.write_all(&[n]).await.unwrap();
        // A small request should reach the peer without an explicit flush.
    }
    let data: Vec<_> = (0..256 * 1024).map(|n| (n % 251) as u8).collect();
    tls.write_all(&data).await.unwrap();
    tls.shutdown().await.unwrap();
    let mut received = Vec::new();
    let result = tls.read_to_end(&mut received).await;
    if truncated {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            tls.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    } else {
        result.unwrap();
    }
    assert_eq!(received, data);
    assert!(tls.write_all(b"late").await.is_err());
    server.await.unwrap();
}

#[tokio::test]
async fn linux_tls_offload_all_ciphers_directions_and_half_close() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for (version, ciphers) in [
            (
                &rustls::version::TLS13,
                [
                    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                ],
            ),
            (
                &rustls::version::TLS12,
                [
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                ],
            ),
        ] {
            for cipher in ciphers {
                for (tx, rx) in [(true, false), (false, true), (true, true)] {
                    exercise(version, cipher, tx, rx, false, false).await;
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires Linux 6.14+ kTLS rekey socket API"]
async fn linux_tls13_key_updates() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for cipher in [
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ] {
            for (tx, rx) in [(true, false), (false, true), (true, true)] {
                exercise(&rustls::version::TLS13, cipher, tx, rx, true, false).await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn linux_tls_truncated_transport_is_not_clean_eof() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for (tx, rx) in [(true, false), (false, true), (true, true)] {
            exercise(
                &rustls::version::TLS13,
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                tx,
                rx,
                false,
                true,
            )
            .await;
        }
    })
    .await
    .unwrap();
}
