mod support;

use serde_json::json;
use std::{
    io::{Read, Write},
    net::UdpSocket,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use support::{App, Server, runtime_lock};

#[test]
fn a_closed_vless_peer_reports_response_progress_direction_and_selected_route() {
    let _serial = runtime_lock();
    // Accept the VLESS request, then close after only one response header byte.
    let node = Server::spawn(|mut stream| {
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        stream.write_all(&[0]).unwrap();
        // Drain whatever the client already sent before closing. Unread data in
        // the receive buffer turns close() into a reset, so the client would
        // report ConnectionReset instead of the unexpected end of stream this
        // check asserts. Only already-queued bytes are drained, so this never
        // waits for more input.
        stream
            .set_nonblocking(true)
            .expect("fixture socket is non-blocking");
        let mut drain = [0; 1024];
        while matches!(stream.read(&mut drain), Ok(read) if read > 0) {}
    });
    let app = App::new();
    app.import("diagnostic fixture", vec![json!({
        "type":"vless", "tag":"chosen-node", "server":"127.0.0.1", "server_port":node.address.port(),
        "uuid":"00000000-0000-4000-8000-000000000001"
    })]);
    app.service.start().unwrap();
    assert!(support::request(&app.service, "http://192.0.2.1/").is_err());
    let deadline = Instant::now() + Duration::from_secs(2);
    let logs = loop {
        let logs = app.service.logs();
        if logs.contains("stage=vless_response") || Instant::now() >= deadline {
            break logs;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    for field in [
        "ERROR connection",
        "stage=relay_download",
        "stage=vless_response",
        "received=1 expected=2",
        "node-0",
        "192.0.2.1:80",
        "UnexpectedEof",
    ] {
        assert!(logs.contains(field), "missing {field}: {logs}");
    }
    assert!(
        !logs.contains("00000000-0000-4000-8000-000000000001"),
        "credentials in logs"
    );
}

fn await_log(app: &App, text: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let logs = app.service.logs();
        if logs.contains(text) {
            return logs;
        }
        assert!(Instant::now() < deadline, "missing {text}: {logs}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn dns_negative_answers_and_failures_use_distinct_levels_and_obey_live_settings() {
    let _serial = runtime_lock();
    for (rcode, expected) in [(3, "DEBUG connection"), (2, "WARN connection")] {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut packet = [0u8; 4096];
            while !stopping.load(Ordering::Relaxed) {
                if let Ok((length, peer)) = socket.recv_from(&mut packet) {
                    assert!(length >= 12);
                    packet[2] = 0x81;
                    packet[3] = 0x80 | rcode;
                    packet[6..12].fill(0);
                    socket.send_to(&packet[..length], peer).unwrap();
                }
            }
        });
        let app = App::new();
        app.import(
            "unused",
            vec![support::socks_node(
                "unused",
                "127.0.0.1:9".parse().unwrap(),
            )],
        );
        app.service
            .update(|state| {
                state.settings.direct_dns = format!("udp://{address}");
                state.settings.log_level = "debug".into();
                Ok(())
            })
            .unwrap();
        support::route_all_direct(&app);
        app.service.start().unwrap();
        assert!(support::request(&app.service, "http://audit.example.test/").is_err());
        let logs = await_log(&app, expected);
        assert!(logs.contains("stage=dns"), "{logs}");
        assert!(!logs.contains("ERROR connection"), "{logs}");

        let mut settings = app.service.snapshot().settings;
        settings.log_level = "error".into();
        app.service.apply_settings(settings).unwrap();
        app.service.clear_logs();
        assert!(support::request(&app.service, "http://audit.example.test/").is_err());
        app.service.stop().unwrap();
        assert!(
            !app.service.logs().contains("connection peer="),
            "{}",
            app.service.logs()
        );
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
    }
}

#[test]
fn closing_live_connections_is_a_debug_lifecycle_event() {
    let _serial = runtime_lock();
    let peer = support::echo_server();
    let proxy = support::socks_forward();
    let app = App::new();
    app.service
        .update(|state| {
            state.settings.log_level = "debug".into();
            Ok(())
        })
        .unwrap();
    app.import("echo", vec![support::socks_node("echo", proxy.address)]);
    app.service.start().unwrap();
    let mut tunnel = support::echo_tunnel(&app.service, peer.address);
    tunnel.write_all(b"alive").unwrap();
    let mut response = [0; 5];
    tunnel.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"alive");
    app.service.close_all_connections().unwrap();
    drop(tunnel);
    let logs = await_log(&app, "flow cancelled");
    assert!(logs.contains("DEBUG connection"), "{logs}");
    assert!(
        !logs.contains("ERROR connection") && !logs.contains("WARN connection"),
        "{logs}"
    );
}

#[test]
fn tls_without_close_notify_is_reported_without_masking_protocol_truncation() {
    let _serial = runtime_lock();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    let config = Arc::new(config);
    for complete_header in [true, false] {
        let tls = config.clone();
        let peer = Server::spawn(move |socket| {
            let session = rustls::ServerConnection::new(tls.clone()).unwrap();
            let mut stream = rustls::StreamOwned::new(session, socket);
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            if complete_header {
                stream
                    .write_all(b"\0\0HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .unwrap();
            } else {
                stream.write_all(&[0]).unwrap();
            }
            stream.flush().unwrap();
            // Wait for the client to finish reading before dropping. Dropping
            // straight after `flush` races the peer's read: when TCP delivers
            // FIN ahead of the payload, the client sees EOF with bytes still
            // queued and reports truncation, which made this check flaky.
            // Keeping the socket open until the client closes preserves the
            // intended case (no TLS close_notify) without that race, at the
            // cost of one bounded wait that the 5 s fixture timeout caps.
            stream
                .sock
                .set_read_timeout(Some(Duration::from_millis(150)))
                .expect("fixture socket accepts a read timeout");
            let mut drain = [0; 64];
            while matches!(stream.read(&mut drain), Ok(read) if read > 0) {}
            // Intentionally drop without a TLS close_notify.
        });
        let app = App::new();
        app.service
            .update(|state| {
                state.settings.log_level = "warn".into();
                Ok(())
            })
            .unwrap();
        app.import("TLS fixture", vec![json!({
            "type":"vless", "tag":"tls-node", "server":"127.0.0.1", "server_port":peer.address.port(),
            "uuid":"00000000-0000-4000-8000-000000000001",
            "tls":{"enabled":true,"server_name":"localhost","certificate":certified.cert.pem()}
        })]);
        app.service.start().unwrap();
        let response = support::request(&app.service, "http://192.0.2.1/");
        if complete_header {
            assert_eq!(response.unwrap(), "ok");
        } else {
            assert!(response.is_err());
        }
        let logs = await_log(
            &app,
            if complete_header {
                "WARN connection"
            } else {
                "ERROR connection"
            },
        );
        assert!(logs.contains("UnexpectedEof"), "{logs}");
        if !complete_header {
            assert!(logs.contains("stage=vless_response"), "{logs}");
        }
    }
}
