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
    sync::atomic::Ordering,
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
        "socks",
        "http",
    ] {
        let case = dir.path().join(kind);
        fs::create_dir(&case).unwrap();
        let quic = matches!(kind, "hysteria2" | "tuic");
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
            "tuic" => {
                inbound["users"] =
                    json!([{"name":"fixture","uuid":UUID,"password":"interop-password"}]);
                node["uuid"] = UUID.into();
                node["password"] = "interop-password".into();
            }
            "socks" | "http" => {
                inbound["users"] = json!([{"username":"fixture","password":"interop-password"}]);
                node["username"] = "fixture".into();
                node["password"] = "interop-password".into();
            }
            _ => unreachable!(),
        }
        if matches!(kind, "trojan" | "anytls" | "hysteria2" | "tuic") {
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
                cases.push((kind, *name, Some(transport.clone())));
            }
        }
    }
    cases.push(("vless", "vision", None));
    cases.push(("vless", "reality", None));
    cases.push(("vless", "reality-vision", None));
    for name in [
        "smux",
        "smux-tcp-only",
        "yamux",
        "yamux-tcp-only",
        "h2mux",
        "h2mux-tcp-only",
    ] {
        cases.push(("trojan", name, None));
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
    for (kind, transport_name, transport) in cases {
        let name = format!("{kind}-{transport_name}");
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
        if kind == "trojan" {
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
        } else if transport_name != "reality" {
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
        let udp_result = if transport_name.ends_with("-tcp-only") {
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
