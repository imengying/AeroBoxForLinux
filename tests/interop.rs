//! Optional interoperability against an independently implemented local server.
//! Run with AEROBOX_TEST_PEER=/path/to/sing-box cargo test --test interop -- --ignored.
//! The application and ordinary test suite never invoke this executable.
mod support;
#[path = "support/udp_policy.rs"]
mod udp_policy;

use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};
use support::App;

const UUID: &str = "00000000-0000-4000-8000-000000000001";
const SS2022_KEY: &str = "EREREREREREREREREREREQ==";

struct Peer {
    child: Child,
    log: PathBuf,
}
impl Peer {
    fn start(executable: &Path, dir: &Path, config: &serde_json::Value, ready: u16) -> Self {
        let config_path = dir.join("peer.json");
        let log = dir.join("peer.log");
        fs::write(&config_path, serde_json::to_vec_pretty(config).unwrap()).unwrap();
        let output = fs::File::create(&log).unwrap();
        let mut peer = Self {
            child: Command::new(executable)
                .args(["run", "--disable-color", "-c"])
                .arg(&config_path)
                .current_dir(dir)
                .stdin(Stdio::null())
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .expect("cannot start the independent protocol peer"),
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = peer.child.try_wait().unwrap() {
                panic!("independent peer exited: {status}\n{}", peer.logs());
            }
            if TcpStream::connect_timeout(
                &([127, 0, 0, 1], ready).into(),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                return peer;
            }
            assert!(
                Instant::now() < deadline,
                "independent peer did not become ready:\n{}",
                peer.logs()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn logs(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn https_echo(certified: &rcgen::CertifiedKey<rcgen::KeyPair>) -> support::Server {
    let tls = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    let tls = Arc::new(tls);
    support::Server::spawn(move |socket| {
        let session = rustls::ServerConnection::new(tls.clone()).unwrap();
        let mut stream = rustls::StreamOwned::new(session, socket);
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 16 * 1024);
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        let header = String::from_utf8(header).unwrap();
        assert!(header.starts_with("POST /tls-echo "));
        let length: usize = header
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        assert!(length <= 1024 * 1024);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        stream.write_all(&body).unwrap();
        stream.conn.send_close_notify();
        stream.flush().unwrap();
    })
}

#[test]
#[ignore = "requires an explicitly supplied independent server in AEROBOX_TEST_PEER"]
fn legacy_vmess_authentication_carries_tcp_and_udp_over_plain_tls_and_stream_transports() {
    let _serial = support::runtime_lock();
    let executable = PathBuf::from(
        std::env::var_os("AEROBOX_TEST_PEER")
            .expect("set AEROBOX_TEST_PEER to a sing-box executable"),
    )
    .canonicalize()
    .expect("AEROBOX_TEST_PEER is not an existing executable");
    let dir = tempfile::tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = certified.cert.pem();
    let certificate_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    fs::write(&certificate_path, &certificate).unwrap();
    fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();
    // UUID version/variant bits are part of the VMess identity, not a v4
    // eligibility check. Independent authentication verifies their exact bytes.
    for (name, aid, identity, cipher, tls, transport, xudp) in [
        (
            "tcp-aes-gcm",
            64,
            "6ba7b810-9dad-31d1-80b4-00c04fd430c8",
            "aes-128-gcm",
            false,
            None,
            false,
        ),
        (
            "tcp-chacha",
            1,
            "6ba7b810-9dad-31d1-c0b4-00c04fd430c8",
            "chacha20-poly1305",
            false,
            None,
            false,
        ),
        (
            "tcp-none",
            64,
            "00000000-0000-0000-0000-000000000000",
            "none",
            false,
            None,
            false,
        ),
        (
            "tls-auto",
            64,
            "6ba7b810-9dad-51d1-80b4-00c04fd430c8",
            "auto",
            true,
            None,
            false,
        ),
        (
            "ws-tls",
            64,
            UUID,
            "aes-128-gcm",
            true,
            Some(json!({"type":"ws","path":"/legacy"})),
            false,
        ),
        (
            "grpc-tls-xudp",
            64,
            "6BA7B8109DAD11D180B400C04FD430C8",
            "chacha20-poly1305",
            true,
            Some(json!({"type":"grpc","service_name":"legacy"})),
            true,
        ),
    ] {
        let case = dir.path().join(name);
        fs::create_dir(&case).unwrap();
        let port = support::free_port();
        let ready = loop {
            let candidate = support::free_port();
            if candidate != port {
                break candidate;
            }
        };
        let mut inbound = json!({"type":"vmess", "tag":"legacy-vmess", "listen":"127.0.0.1", "listen_port":port, "users":[{"name":"fixture", "uuid":identity, "alterId":aid}]});
        let mut node = json!({"type":"vmess", "tag":name, "server":"127.0.0.1", "server_port":port, "uuid":identity, "alter_id":aid, "security":cipher});
        if tls {
            inbound["tls"] = json!({"enabled":true,"server_name":"localhost","certificate_path":certificate_path,"key_path":key_path});
            node["tls"] =
                json!({"enabled":true,"server_name":"localhost","certificate":certificate});
        }
        if let Some(transport) = transport {
            inbound["transport"] = transport.clone();
            node["transport"] = transport;
        }
        if xudp {
            node["packet_encoding"] = "xudp".into();
        }
        let config = json!({
            "log":{"level":"error"},
            "inbounds":[inbound,{"type":"mixed","tag":"readiness","listen":"127.0.0.1","listen_port":ready}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"final":"direct"}
        });
        let body = format!("legacy-{name}:{}", "AeroBox-数据-".repeat(8192));
        let (origin, hits) = support::http(body.as_bytes().to_vec());
        let peer = Peer::start(&executable, &case, &config, ready);
        let app = App::new();
        app.import(name, vec![node]);
        app.service
            .start()
            .unwrap_or_else(|error| panic!("{name}: {error:#}"));
        for entry in ["http", "socks5h"] {
            let result = support::request_via(
                &app.service,
                &format!("http://{}/legacy", origin.address),
                entry,
            );
            assert_eq!(
                result.unwrap_or_else(|error| panic!(
                    "legacy {name}/{entry}: {error:#}\nclient:\n{}\npeer:\n{}",
                    app.service.logs(),
                    peer.logs()
                )),
                body
            );
        }
        assert_eq!(hits.load(Ordering::Relaxed), 2);
        // Exercise request encryption/framing past the first packet too.
        let echo = support::Server::spawn(|mut stream| {
            let header = support::headers(&mut stream).unwrap();
            let length: usize = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            assert!(length <= 1024 * 1024);
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).unwrap();
            support::respond(&mut stream, &bytes).unwrap();
        });
        let payload: Vec<_> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
        let response = reqwest::blocking::Client::builder()
            .no_proxy()
            .proxy(
                reqwest::Proxy::all(format!(
                    "socks5h://127.0.0.1:{}",
                    app.service.snapshot().settings.mixed_port
                ))
                .unwrap(),
            )
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .post(format!("http://{}/echo", echo.address))
            .body(payload.clone())
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::bytes)
            .unwrap_or_else(|error| {
                panic!(
                    "legacy {name} upload: {error:#}\nclient:\n{}\npeer:\n{}",
                    app.service.logs(),
                    peer.logs()
                )
            });
        assert_eq!(response.as_ref(), payload);
        support::udp_roundtrip(app.service.snapshot().settings.mixed_port).unwrap_or_else(
            |error| {
                panic!(
                    "legacy {name} UDP: {error}\nclient:\n{}\npeer:\n{}",
                    app.service.logs(),
                    peer.logs()
                )
            },
        );
        app.service.stop().unwrap();
        let _released =
            std::net::TcpListener::bind(("127.0.0.1", app.service.snapshot().settings.mixed_port))
                .unwrap();
        eprintln!("independent legacy VMess peer: {name}, alterId={aid}, TCP/UDP payload passed");
    }
}

#[test]
#[ignore = "requires an explicitly supplied independent server in AEROBOX_TEST_PEER"]
fn android_protocols_exchange_payload_with_an_independent_server() {
    let _serial = support::runtime_lock();
    let executable = PathBuf::from(
        std::env::var_os("AEROBOX_TEST_PEER")
            .expect("set AEROBOX_TEST_PEER to a sing-box executable"),
    )
    .canonicalize()
    .expect("AEROBOX_TEST_PEER is not an existing executable");
    let dir = tempfile::tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = certified.cert.pem();
    let certificate_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    fs::write(&certificate_path, &certificate).unwrap();
    fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();

    // sing-box provides no Naive server inbound; its independent HTTP/2 and
    // HTTP/3 peer lives in naive_interop.rs.
    for kind in [
        "shadowsocks",
        "ss2022",
        "vmess",
        "vmess-xudp",
        "vless",
        "vless-raw",
        "trojan",
        "anytls",
        "hysteria2",
        "tuic",
        "tuic-quic",
        "tuic-uot",
        "socks",
        "http",
    ] {
        let case = dir.path().join(kind);
        fs::create_dir(&case).unwrap();
        let quic = matches!(kind, "hysteria2" | "tuic" | "tuic-quic" | "tuic-uot");
        let port = if quic {
            UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        } else {
            support::free_port()
        };
        let ready = loop {
            let ready = support::free_port();
            if ready != port {
                break ready;
            }
        };
        let protocol = match kind {
            "ss2022" => "shadowsocks",
            "vmess-xudp" => "vmess",
            "vless-raw" => "vless",
            "tuic-quic" | "tuic-uot" => "tuic",
            _ => kind,
        };
        let mut inbound = json!({"type":protocol,"tag":"tested-protocol","listen":"127.0.0.1","listen_port":port});
        let mut node = json!({"type":protocol,"tag":format!("independent {kind}"),"server":"127.0.0.1","server_port":port});
        match kind {
            "shadowsocks" | "ss2022" => {
                let method = if kind == "ss2022" {
                    "2022-blake3-aes-128-gcm"
                } else {
                    "aes-128-gcm"
                };
                let password = if kind == "ss2022" {
                    SS2022_KEY
                } else {
                    "interop-password"
                };
                inbound["method"] = method.into();
                inbound["password"] = password.into();
                node["method"] = method.into();
                node["password"] = password.into();
            }
            "vmess" | "vless" | "vmess-xudp" | "vless-raw" => {
                inbound["users"] = json!([{"name":"fixture","uuid":UUID}]);
                node["uuid"] = UUID.into();
                if protocol == "vmess" {
                    node["security"] = "auto".into();
                }
                if kind == "vmess-xudp" {
                    node["packet_encoding"] = "xudp".into();
                } else if kind == "vless-raw" {
                    node["packet_encoding"] = "".into();
                }
            }
            "trojan" | "anytls" | "hysteria2" => {
                inbound["users"] = json!([{"name":"fixture","password":"interop-password"}]);
                node["password"] = "interop-password".into();
            }
            "tuic" | "tuic-quic" | "tuic-uot" => {
                inbound["users"] =
                    json!([{"name":"fixture","uuid":UUID,"password":"interop-password"}]);
                node["uuid"] = UUID.into();
                node["password"] = "interop-password".into();
                if kind == "tuic-quic" {
                    node["udp_relay_mode"] = "quic".into();
                } else if kind == "tuic-uot" {
                    node["udp_over_stream"] = true.into();
                }
            }
            "socks" | "http" => {
                inbound["users"] = json!([{"username":"fixture","password":"interop-password"}]);
                node["username"] = "fixture".into();
                node["password"] = "interop-password".into();
            }
            _ => unreachable!(),
        }
        if matches!(protocol, "trojan" | "anytls" | "hysteria2" | "tuic") {
            inbound["tls"] = json!({"enabled":true,"server_name":"localhost","certificate_path":certificate_path,"key_path":key_path});
            node["tls"] =
                json!({"enabled":true,"server_name":"localhost","certificate":certificate});
            if quic {
                inbound["tls"]["alpn"] = json!(["h3"]);
                node["tls"]["alpn"] = json!(["h3"]);
            }
        }
        let config = json!({
            "log":{"level":"error"},
            "inbounds":[inbound,{"type":"mixed","tag":"readiness","listen":"127.0.0.1","listen_port":ready}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"final":"direct"}
        });
        let body = format!("independent peer {kind}:{}", "AeroBox-数据-".repeat(8192));
        let (origin, hits) = support::http(body.as_bytes().to_vec());
        let peer = Peer::start(&executable, &case, &config, ready);
        let app = App::new();
        app.import(kind, vec![node]);
        app.service
            .start()
            .unwrap_or_else(|error| panic!("{kind}: start failed: {error:#}"));
        for entry in ["http", "socks5h"] {
            let url = format!("http://{}/interop/{kind}", origin.address);
            let result = support::request_via(&app.service, &url, entry);
            assert_eq!(
                result.unwrap_or_else(|error| panic!(
                    "{kind} through {entry}: {error:?}\nclient:\n{}\npeer:\n{}",
                    app.service.logs(),
                    peer.logs()
                )),
                body,
                "{kind} through {entry} changed the payload"
            );
        }
        assert_eq!(
            hits.load(Ordering::Relaxed),
            2,
            "{kind} did not reach the local origin twice"
        );
        if kind != "http" {
            support::udp_roundtrip(app.service.snapshot().settings.mixed_port).unwrap_or_else(
                |error| {
                    panic!(
                        "{kind} UDP: {error}\nclient:\n{}\npeer:\n{}",
                        app.service.logs(),
                        peer.logs()
                    )
                },
            );
        }
        app.service.stop().unwrap();
        let _released =
            std::net::TcpListener::bind(("127.0.0.1", app.service.snapshot().settings.mixed_port))
                .unwrap();
        eprintln!("independent peer: {kind} TCP and supported UDP payload passed");
    }
}

#[test]
#[ignore = "requires an explicitly supplied independent server in AEROBOX_TEST_PEER"]
fn subscription_transports_exchange_payload_with_an_independent_server() {
    let _serial = support::runtime_lock();
    let executable = PathBuf::from(
        std::env::var_os("AEROBOX_TEST_PEER")
            .expect("set AEROBOX_TEST_PEER to a sing-box executable"),
    )
    .canonicalize()
    .expect("AEROBOX_TEST_PEER is not an existing executable");
    let dir = tempfile::tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = certified.cert.pem();
    let certificate_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    fs::write(&certificate_path, &certificate).unwrap();
    fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();

    let transports = [
        (
            "ws",
            json!({"type":"ws","path":"/aerobox","headers":{"Host":"localhost"}}),
        ),
        (
            "ws-early-data",
            json!({"type":"ws","path":"/aerobox","headers":{"Host":"localhost"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}),
        ),
        ("grpc", json!({"type":"grpc","service_name":"aerobox"})),
        (
            "httpupgrade",
            json!({"type":"httpupgrade","host":"localhost","path":"/aerobox"}),
        ),
        (
            "http2",
            json!({"type":"http","host":["localhost"],"path":"/aerobox"}),
        ),
        (
            "http1",
            json!({"type":"http","host":["localhost"],"path":"/aerobox"}),
        ),
    ];
    let mut cases = Vec::new();
    for kind in ["vmess", "vless", "trojan"] {
        for (name, transport) in &transports {
            if kind != "trojan" || *name != "http1" {
                cases.push((kind, *name, Some(transport.clone()), None));
            }
        }
    }
    cases.push(("vless", "vision", None, None));
    cases.push(("vless", "reality", None, None));
    cases.push(("vless", "reality-vision", None, None));
    for name in [
        "smux",
        "smux-tcp-only",
        "yamux",
        "yamux-tcp-only",
        "h2mux",
        "h2mux-tcp-only",
    ] {
        cases.push(("trojan", name, None, None));
    }
    let keys = Command::new(&executable)
        .args(["generate", "reality-keypair"])
        .output()
        .expect("cannot generate the local REALITY fixture key");
    assert!(
        keys.status.success(),
        "cannot generate the REALITY fixture key"
    );
    let keys = String::from_utf8(keys.stdout).unwrap();
    let key = |name: &str| {
        keys.lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .trim()
            .to_owned()
    };
    let private_key = key("PrivateKey:");
    let public_key = key("PublicKey:");
    for fingerprint in ["chrome", "firefox"] {
        for (kind, transport_name, transport) in [
            ("vless", "ws", Some(transports[0].1.clone())),
            ("vless", "ws-early-data", Some(transports[1].1.clone())),
            ("vless", "grpc", Some(transports[2].1.clone())),
            ("vless", "httpupgrade", Some(transports[3].1.clone())),
            ("vless", "http2", Some(transports[4].1.clone())),
            ("vless", "vision", None),
            ("vless", "reality-vision", None),
            ("vless", "reality-vision-alpn", None),
            ("vless", "reality-vision-empty-id", None),
            ("anytls", "tls", None),
            ("http", "tls", None),
        ] {
            cases.push((kind, transport_name, transport, Some(fingerprint)));
        }
    }
    for (kind, transport_name, transport, fingerprint) in cases {
        let name = format!(
            "{kind}-{transport_name}{}",
            fingerprint
                .map(|name| format!("-{name}"))
                .unwrap_or_default()
        );
        let case = dir.path().join(&name);
        fs::create_dir(&case).unwrap();
        let port = support::free_port();
        let ready = loop {
            let ready = support::free_port();
            if ready != port {
                break ready;
            }
        };
        let mut inbound =
            json!({"type":kind,"tag":"tested-protocol","listen":"127.0.0.1","listen_port":port});
        let mut node = json!({"type":kind,"tag":&name,"server":"127.0.0.1","server_port":port});
        if kind == "http" {
            inbound["users"] = json!([{"username":"fixture","password":"transport-password"}]);
            node["username"] = "fixture".into();
            node["password"] = "transport-password".into();
        } else if matches!(kind, "trojan" | "anytls") {
            inbound["users"] = json!([{"name":"fixture","password":"transport-password"}]);
            node["password"] = "transport-password".into();
        } else {
            inbound["users"] = json!([{"name":"fixture","uuid":UUID}]);
            node["uuid"] = UUID.into();
            if kind == "vmess" {
                node["security"] = "auto".into();
            }
        }
        if transport_name != "http1" {
            inbound["tls"] = json!({"enabled":true,"server_name":"localhost","certificate_path":certificate_path,"key_path":key_path});
            node["tls"] =
                json!({"enabled":true,"server_name":"localhost","certificate":certificate});
        }
        if let Some(transport) = transport {
            // Inbound WebSocket configuration uses the same host and early
            // data headers as the subscription's outbound transport.
            inbound["transport"] = transport.clone();
            node["transport"] = transport;
        } else if kind == "trojan" {
            inbound["multiplex"] = json!({"enabled":true});
            node["multiplex"] =
                json!({"enabled":true,"protocol":transport_name.trim_end_matches("-tcp-only")});
            if transport_name.ends_with("-tcp-only") {
                node["network"] = "tcp".into();
            }
        } else if kind == "vless" && transport_name != "reality" {
            inbound["users"][0]["flow"] = "xtls-rprx-vision".into();
            node["flow"] = "xtls-rprx-vision".into();
        }
        let mut config = json!({
            "log":{"level":"error"},
            "inbounds":[inbound,{"type":"mixed","tag":"readiness","listen":"127.0.0.1","listen_port":ready}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"final":"direct"}
        });
        if transport_name.starts_with("reality") {
            let template_port = loop {
                let candidate = support::free_port();
                if candidate != port && candidate != ready {
                    break candidate;
                }
            };
            config["inbounds"][0]["tls"] = json!({
                "enabled":true,"server_name":"localhost",
                "reality":{"enabled":true,"handshake":{"server":"127.0.0.1","server_port":template_port},"private_key":private_key,"short_id":["0123456789abcdef"]}
            });
            config["inbounds"].as_array_mut().unwrap().push(json!({
                "type":"http","tag":"tls-template","listen":"127.0.0.1","listen_port":template_port,
                "tls":{"enabled":true,"server_name":"localhost","min_version":"1.3","certificate_path":certificate_path,"key_path":key_path}
            }));
            node["tls"] = json!({
                "enabled":true,"server_name":"localhost",
                "reality":{"enabled":true,"public_key":public_key,"short_id":"0123456789abcdef"}
            });
            if transport_name.ends_with("-alpn") {
                // Exercise an explicit ALPN/cipher policy against a template
                // that permits only HTTP/1.1 and requires TLS 1.3.
                config["inbounds"][2]["tls"]["alpn"] = json!(["http/1.1"]);
                node["tls"]["alpn"] = json!(["http/1.1"]);
                if fingerprint != Some("chrome") {
                    node["tls"]["cipher_suites"] = json!(["TLS_AES_128_GCM_SHA256"]);
                    node["tls"]["min_version"] = "1.3".into();
                }
            }
            if transport_name.ends_with("-empty-id") {
                config["inbounds"][0]["tls"]["reality"]["short_id"] = json!([""]);
                node["tls"]["reality"]
                    .as_object_mut()
                    .unwrap()
                    .remove("short_id");
            }
        }
        if let Some(fingerprint) = fingerprint {
            node["tls"]["utls"] = json!({"enabled":true,"fingerprint":fingerprint});
        }
        // Cross flow-control and framing boundaries instead of testing only
        // whether a successful HTTP status can fit in the first packet.
        let body = format!("{name}:{}", "AeroBox-传输-".repeat(16384));
        let (origin, hits) = support::http(body.as_bytes().to_vec());
        let peer = Peer::start(&executable, &case, &config, ready);
        let app = App::new();
        app.import(&name, vec![node]);
        app.service
            .start()
            .unwrap_or_else(|error| panic!("{name}: start failed: {error:#}"));
        for entry in ["http", "socks5h"] {
            let result = support::request_via(
                &app.service,
                &format!("http://{}/interop/{name}", origin.address),
                entry,
            );
            assert_eq!(
                result.unwrap_or_else(|error| panic!(
                    "{name} through {entry}: {error:?}\nclient:\n{}\npeer:\n{}",
                    app.service.logs(),
                    peer.logs()
                )),
                body,
                "{name} through {entry} changed the payload"
            );
        }
        assert_eq!(hits.load(Ordering::Relaxed), 2, "{name}");
        let echo = support::Server::spawn(|mut stream| {
            let header = support::headers(&mut stream).unwrap();
            let length: usize = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            assert!(length <= 1024 * 1024);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            support::respond(&mut stream, &body).unwrap();
            stream.flush().unwrap();
        });
        let upload: Vec<_> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let response = reqwest::blocking::Client::builder()
            .no_proxy()
            .proxy(
                reqwest::Proxy::all(format!(
                    "socks5h://127.0.0.1:{}",
                    app.service.snapshot().settings.mixed_port
                ))
                .unwrap(),
            )
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .post(format!("http://{}/echo", echo.address))
            .body(upload.clone())
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::bytes)
            .unwrap_or_else(|error| {
                panic!(
                    "{name} upload: {error}\nclient:\n{}\npeer:\n{}",
                    app.service.logs(),
                    peer.logs()
                )
            });
        assert_eq!(
            response.as_ref(),
            upload,
            "{name} upload/echo changed the payload"
        );
        if kind == "vless" && (transport_name == "vision" || transport_name.starts_with("reality"))
        {
            // Browsers and DoH put another TLS session inside VLESS. Plain
            // HTTP payloads do not exercise Vision's inner-TLS detection.
            let https = https_echo(&certified);
            for entry in ["http", "socks5h"] {
                let response = reqwest::blocking::Client::builder()
                    .no_proxy()
                    .proxy(
                        reqwest::Proxy::all(format!(
                            "{entry}://127.0.0.1:{}",
                            app.service.snapshot().settings.mixed_port
                        ))
                        .unwrap(),
                    )
                    .tls_certs_only([
                        reqwest::Certificate::from_pem(certificate.as_bytes()).unwrap()
                    ])
                    .timeout(Duration::from_secs(8))
                    .build()
                    .unwrap()
                    .post(format!(
                        "https://localhost:{}/tls-echo",
                        https.address.port()
                    ))
                    .body(upload.clone())
                    .send()
                    .and_then(reqwest::blocking::Response::error_for_status)
                    .and_then(reqwest::blocking::Response::bytes)
                    .unwrap_or_else(|error| {
                        panic!(
                            "{name} HTTPS through {entry}: {error:?}\nclient:\n{}\npeer:\n{}",
                            app.service.logs(),
                            peer.logs()
                        )
                    });
                assert_eq!(
                    response.as_ref(),
                    upload,
                    "{name} HTTPS changed the payload"
                );
            }
        }
        let udp_result = if kind == "http" || transport_name.ends_with("-tcp-only") {
            udp_policy::assert_udp_blocked(app.service.snapshot().settings.mixed_port)
        } else {
            support::udp_roundtrip(app.service.snapshot().settings.mixed_port)
        };
        udp_result.unwrap_or_else(|error| {
            panic!(
                "{name} UDP: {error}\nclient:\n{}\npeer:\n{}",
                app.service.logs(),
                peer.logs()
            )
        });
        app.service.stop().unwrap();
        let _released =
            std::net::TcpListener::bind(("127.0.0.1", app.service.snapshot().settings.mixed_port))
                .unwrap();
        eprintln!("independent peer: {name} TCP payload and UDP policy passed");
    }
}
