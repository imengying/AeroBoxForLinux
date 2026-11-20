//! Optional interoperability against an independently implemented local server.
//! Run with AEROBOX_TEST_PEER=/path/to/sing-box cargo test --test interop -- --ignored.
//! The application and ordinary test suite never invoke this executable.
mod support;

use serde_json::json;
use std::{
    fs,
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

    // sing-box provides no Naive server inbound; Naive is exercised by the
    // built-in protocol suite instead of claiming an independent peer here.
    for kind in [
        "shadowsocks",
        "ss2022",
        "vmess",
        "vless",
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
        let protocol = if kind == "ss2022" {
            "shadowsocks"
        } else {
            kind
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
            "vmess" | "vless" => {
                inbound["users"] = json!([{"name":"fixture","uuid":UUID}]);
                node["uuid"] = UUID.into();
                if kind == "vmess" {
                    node["security"] = "auto".into();
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
