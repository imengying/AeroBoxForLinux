mod support;

use aerobox_for_linux::protocol;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    sync::{Arc, mpsc},
    time::Duration,
};

fn node(quic: bool) -> Value {
    json!({"type":"naive", "tag":"naive", "server":"127.0.0.1", "server_port":443,
        "quic":quic, "tls":{"enabled":true,"server_name":"localhost"}})
}

#[test]
fn http2_receive_windows_are_sent_on_the_wire_with_cronet_semantics() {
    let _serial = support::runtime_lock();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let config = Arc::new(config);
    for (window, expected_connection) in [
        (None, 128 * 1024 * 1024),
        (Some(json!(0)), 128 * 1024 * 1024),
        (Some(json!("")), 128 * 1024 * 1024),
        (Some(json!(2097153)), 2097153),
    ] {
        let tls = config.clone();
        let (tx, rx) = mpsc::channel();
        let peer = support::Server::spawn(move |socket| {
            let session = rustls::ServerConnection::new(tls.clone()).unwrap();
            let mut stream = rustls::StreamOwned::new(session, socket);
            let mut preface = [0; 24];
            stream.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            // Independent HTTP/2 framing: SETTINGS_INITIAL_WINDOW_SIZE and
            // stream-zero WINDOW_UPDATE determine the advertised credits.
            stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).unwrap();
            stream.flush().unwrap();
            let mut window = None;
            let mut connection = 65535u32;
            for _ in 0..16 {
                let mut header = [0; 9];
                stream.read_exact(&mut header).unwrap();
                let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
                assert!(length <= 65536);
                let mut payload = vec![0; length];
                stream.read_exact(&mut payload).unwrap();
                if header[3] == 4 && header[4] == 0 {
                    assert!(length.is_multiple_of(6));
                    for setting in payload.as_chunks::<6>().0 {
                        if setting[..2] == [0, 4] {
                            window = Some(u32::from_be_bytes(setting[2..].try_into().unwrap()));
                        }
                    }
                }
                if header[3] == 8 && header[5..] == [0, 0, 0, 0] {
                    connection += u32::from_be_bytes(payload.try_into().unwrap()) & 0x7fff_ffff;
                }
                if let Some(window) = window
                    && connection > 65535
                {
                    tx.send((window, connection)).unwrap();
                    return;
                }
            }
            panic!("Naive did not advertise its flow control windows");
        });
        let app = support::App::new();
        let mut source = node(false);
        source["server_port"] = peer.address.port().into();
        source["tls"]["certificate"] = certified.cert.pem().into();
        if let Some(window) = window {
            source["stream_receive_window"] = window;
        }
        app.import("Naive windows", vec![source]);
        app.service.start().unwrap();
        // The test peer ends after recording SETTINGS; it is not an HTTP origin.
        assert!(support::request(&app.service, "http://192.0.2.1/").is_err());
        let actual = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(actual, (expected_connection / 2, expected_connection));
    }
}

#[test]
fn naive_windows_validate_protocol_specific_fields_and_memory_limits() {
    for (quic, field, value) in [
        (false, "quic_session_receive_window", json!("1 MiB")),
        (false, "stream_receive_window", json!(32767)),
        (false, "stream_receive_window", json!(128 * 1024 * 1024 + 1)),
        (true, "stream_receive_window", json!(16383)),
        (true, "stream_receive_window", json!(64 * 1024 * 1024 + 1)),
        (
            true,
            "quic_session_receive_window",
            json!(128 * 1024 * 1024 + 1),
        ),
    ] {
        let mut value_node = node(quic);
        value_node[field] = value;
        let error = protocol::convert_outbound(value_node, "node").unwrap_err();
        assert_eq!(error.path, format!("node.{field}"));
    }
    for quic in [false, true] {
        let mut value = node(quic);
        value["insecure_concurrency"] = 0.into();
        value["quic_congestion_control"] = "".into();
        value["stream_receive_window"] = 0.into();
        value["quic_session_receive_window"] = 0.into();
        protocol::validate(&value).unwrap();
    }
}
