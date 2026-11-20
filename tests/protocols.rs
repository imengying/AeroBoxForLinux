//! Each Android protocol carries real traffic through the compiled-in stack.
//! These local peers test framing, encryption, authentication and lifecycle;
//! interoperability with independent implementations is tested separately.
mod support;
use aerobox_for_linux::protocol;
use serde_json::json;
use shoes::embedding::EmbeddedCore;
use std::{
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    time::Duration,
};

const UUID: &str = "00000000-0000-4000-8000-000000000001";
fn tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn android_protocols_carry_tcp_and_udp_payloads_and_release_listeners() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    for kind in [
        "socks",
        "http",
        "shadowsocks",
        "ss2022",
        "vmess",
        "vless",
        "trojan",
        "anytls",
        "hysteria2",
        "tuic",
        "naive",
    ] {
        let inbound = tcp_port();
        let quic = matches!(kind, "hysteria2" | "tuic");
        let peer = if quic {
            UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        } else {
            tcp_port()
        };
        let mut node =
            json!({"tag":"test-node","type":kind,"server":"127.0.0.1","server_port":peer});
        let mut server = json!({"address":format!("127.0.0.1:{peer}"),"rules":[{"conditions":{"any_destination":true},"action":"allow"}]});
        let mut inner = match kind {
            "socks" | "http" => {
                node["username"] = "user".into();
                node["password"] = "pass".into();
                json!({"type":kind,"username":"user","password":"pass"})
            }
            "shadowsocks" | "ss2022" => {
                let cipher = if kind == "ss2022" {
                    "2022-blake3-aes-128-gcm"
                } else {
                    "aes-128-gcm"
                };
                let password = if kind == "ss2022" {
                    "EREREREREREREREREREREQ=="
                } else {
                    "pass"
                };
                node["type"] = "shadowsocks".into();
                node["method"] = cipher.into();
                node["password"] = password.into();
                json!({"type":"shadowsocks","cipher":cipher,"password":password})
            }
            "vmess" | "vless" => {
                node["uuid"] = UUID.into();
                let mut protocol = json!({"type":kind,"user_id":UUID});
                if kind == "vmess" {
                    node["security"] = "auto".into();
                    protocol["cipher"] = "any".into();
                }
                protocol
            }
            "trojan" | "hysteria2" => {
                node["password"] = "pass".into();
                json!({"type":kind,"password":"pass"})
            }
            "anytls" => {
                node["password"] = "pass".into();
                json!({"type":"anytls","users":[{"name":"test","password":"pass"}]})
            }
            "tuic" => {
                node["uuid"] = UUID.into();
                node["password"] = "pass".into();
                json!({"type":"tuic","uuid":UUID,"password":"pass"})
            }
            "naive" => {
                node["type"] = "naive".into();
                node["quic"] = false.into();
                node["username"] = "user".into();
                node["password"] = "pass".into();
                json!({"type":"naiveproxy","users":[{"username":"user","password":"pass"}]})
            }
            _ => unreachable!(),
        };
        if matches!(kind, "trojan" | "anytls" | "hysteria2" | "tuic" | "naive") {
            node["tls"] = json!({"enabled":true,"server_name":"localhost","certificate":certified.cert.pem()});
            if quic {
                server["transport"] = "quic".into();
                server["quic_settings"] = json!({"cert":cert,"key":key,"alpn_protocols":["h3"]});
                node["tls"]["alpn"] = json!(["h3"]);
            } else {
                let mut target = json!({"cert":cert,"key":key,"protocol":inner});
                if kind == "naive" {
                    target["alpn_protocols"] = json!(["h2"]);
                }
                inner = json!({"type":"tls","tls_targets":{"localhost":target}});
            }
        }
        server["protocol"] = inner;
        // The native peer exposes SS and Naive datagrams as UoT. Native SS UDP
        // is covered by the independent-server interoperability test.
        if matches!(kind, "shadowsocks" | "ss2022" | "naive") {
            node["udp_over_tcp"] = json!({"enabled":true,"version":2});
        }
        protocol::validate(&node).unwrap_or_else(|e| panic!("{kind} import: {e:#}"));
        let config = json!([protocol::convert_outbound(node,"node").unwrap(),server,{"address":format!("127.0.0.1:{inbound}"),"protocol":{"type":"mixed"},"rules":[{"conditions":{"any_destination":true},"action":"allow","client_chain":"test-node"}]}]);
        let core = rt
            .block_on(EmbeddedCore::start_json(&config.to_string(), None))
            .unwrap_or_else(|e| panic!("{kind} start: {e}"));
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = origin.local_addr().unwrap();
        origin.set_nonblocking(true).unwrap();
        let worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(12);
            let mut stream = loop {
                match origin.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "origin never received payload"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut data = [0; 4096];
            let count = stream.read(&mut data).unwrap();
            assert!(String::from_utf8_lossy(&data[..count]).starts_with("GET /protocol "));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nAeroBox",
                )
                .unwrap();
        });
        let result = reqwest::blocking::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{inbound}")).unwrap())
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap()
            .get(format!("http://{address}/protocol"))
            .send()
            .and_then(|r| r.text());
        let udp = if kind != "http" {
            Some(support::udp_roundtrip(inbound))
        } else {
            None
        };
        let stopped = rt.block_on(core.shutdown());
        assert_eq!(
            result.unwrap_or_else(|e| panic!("{kind} transfer: {e:?}")),
            "AeroBox",
            "{kind}"
        );
        stopped.unwrap();
        worker.join().unwrap();
        if let Some(result) = udp {
            result.unwrap_or_else(|error| panic!("{kind} UDP: {error}"));
        }
        assert!(
            TcpListener::bind(("127.0.0.1", inbound)).is_ok(),
            "{kind} leaked listener"
        );
    }
}

#[test]
fn bundled_srs_rules_roundtrip_without_losing_conditions() {
    for rule in aerobox_for_linux::model::builtin_resources() {
        let bytes = aerobox_for_linux::model::builtin_seed(&rule.id).unwrap();
        shoes::rule_set::validate_bytes(bytes, true).unwrap();
        let source = shoes::rule_set::decompile_srs(bytes).unwrap();
        let encoded = serde_json::to_vec(&source).unwrap();
        shoes::rule_set::validate_bytes(&encoded, false).unwrap();
        assert!(!source["rules"].as_array().unwrap().is_empty());
        let dir = tempfile::tempdir().unwrap();
        let binary_path = dir.path().join("original.srs");
        let json_path = dir.path().join("exported.json");
        std::fs::write(&binary_path, bytes).unwrap();
        std::fs::write(&json_path, encoded).unwrap();
        let compile = |path, format| {
            let input = serde_json::from_value(json!({"path":path,"format":format})).unwrap();
            shoes::rule_set::load_source(&input, &mut shoes::rules::Compiler::default()).unwrap()
        };
        let binary = compile(binary_path, "srs");
        let exported = compile(json_path, "singbox_json");
        for host in [
            None,
            Some("baidu.com"),
            Some("www.baidu.com"),
            Some("google.com"),
            Some("doubleclick.net"),
            Some("ad.doubleclick.net"),
            Some("unmatched.invalid"),
        ] {
            for ip in [
                None,
                Some("223.5.5.5".parse().unwrap()),
                Some("1.1.1.1".parse().unwrap()),
                Some("2400:3200::1".parse().unwrap()),
                Some("::1".parse().unwrap()),
            ] {
                for port in [0, 53, 80, 443, 65535] {
                    assert_eq!(
                        binary.evaluate(host, ip, port),
                        exported.evaluate(host, ip, port),
                        "{} {host:?} {ip:?}:{port}",
                        rule.name
                    );
                }
            }
        }
    }
}
