//! A node's payload-network restriction survives transport decorators and
//! selection. Real UDP sockets catch both proxy forwarding and direct leaks.
mod support;
#[path = "support/udp_policy.rs"]
mod udp_policy;

use aerobox_for_linux::protocol;
use serde_json::{Value, json};
use shoes::embedding::EmbeddedCore;
use std::{net::TcpListener, path::Path, time::Duration};

struct Running<'a> {
    core: EmbeddedCore,
    runtime: &'a tokio::runtime::Runtime,
}
impl Drop for Running<'_> {
    fn drop(&mut self) {
        let _ = self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), self.core.shutdown()).await
        });
    }
}

fn case(kind: &str, transport: &str, cert: &str, directory: &Path) -> (Value, Value) {
    let peer = support::free_port();
    let mut node = json!({
        "tag":"policy-node", "type":kind, "server":"127.0.0.1", "server_port":peer,
        "password":"password"
    });
    let inner = match kind {
        "socks" => {
            node["username"] = "user".into();
            json!({"type":"socks", "username":"user", "password":"password"})
        }
        "trojan" => json!({"type":"trojan", "password":"password"}),
        "naive" => {
            node["username"] = "user".into();
            json!({"type":"naiveproxy", "users":[{"username":"user", "password":"password"}]})
        }
        _ => unreachable!(),
    };
    let server_protocol = if kind == "socks" {
        inner
    } else {
        node["tls"] = json!({"enabled":true, "server_name":"localhost", "certificate":cert});
        let mut target = json!({
            "cert":directory.join("cert.pem"), "key":directory.join("key.pem"),
            "protocol":inner
        });
        if kind == "naive" {
            target["alpn_protocols"] = json!(["h2"]);
        }
        json!({"type":"tls", "tls_targets":{"localhost":target}})
    };
    match transport {
        "uot1" | "uot2" => {
            node["udp_over_tcp"] =
                json!({"enabled":true,"version":if transport=="uot1" {1} else {2}});
        }
        "h2mux" => {
            node["multiplex"] = json!({"enabled":true, "protocol":transport});
        }
        "native" | "tcp" => {}
        _ => unreachable!(),
    }
    let server = json!({
        "address":format!("127.0.0.1:{peer}"), "protocol":server_protocol,
        "rules":[{"conditions":{"any_destination":true},"action":"allow"}]
    });
    (node, server)
}

#[test]
fn tcp_only_nodes_keep_tcp_and_never_fall_back_for_udp() {
    let _serial = support::runtime_lock();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = certified.cert.pem();
    std::fs::write(directory.path().join("cert.pem"), &certificate).unwrap();
    std::fs::write(
        directory.path().join("key.pem"),
        certified.signing_key.serialize_pem(),
    )
    .unwrap();
    let (origin, _) = support::http(b"TCP remains available".to_vec());
    for (kind, transport) in [
        ("socks", "native"),
        ("socks", "uot1"),
        ("socks", "uot2"),
        ("trojan", "native"),
        // The local Trojan peer accepts H2Mux TCP sessions only. Independent
        // sing-box interoperability tests cover smux/yamux/H2Mux UDP as well.
        ("trojan", "h2mux"),
        ("naive", "tcp"),
        ("naive", "uot1"),
        ("naive", "uot2"),
    ] {
        let (default_node, server) = case(kind, transport, &certificate, directory.path());
        for tcp_only in [false, true] {
            let description = format!("{kind}/{transport}, tcp_only={tcp_only}");
            let mut node = default_node.clone();
            if tcp_only {
                node["network"] = "tcp".into();
            }
            protocol::validate(&node).unwrap_or_else(|error| panic!("{description}: {error:#}"));
            let mut alternate = default_node.clone();
            alternate["tag"] = "available-node".into();
            let inbound = support::free_port();
            let config = json!([
                protocol::convert_outbound(node, "node").unwrap(),
                protocol::convert_outbound(alternate, "alternate").unwrap(),
                server,
                {"client_group":"choice", "type":"selector", "default":"policy-node", "client_chains":[
                    {"chain":["policy-node"]}, {"chain":["available-node"]}, {"chain":["direct"]}
                ]},
                {"address":format!("127.0.0.1:{inbound}"), "protocol":{"type":"mixed"},
                 "rules":[{"conditions":{"any_destination":true},"action":"allow","client_chain":"choice"}]}
            ]);
            let core = runtime
                .block_on(EmbeddedCore::start_json(&config.to_string(), None))
                .unwrap_or_else(|error| panic!("{description} startup: {error}"));
            let running = Running {
                core,
                runtime: &runtime,
            };
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{inbound}")).unwrap())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();
            for _ in 0..2 {
                assert_eq!(
                    client
                        .get(format!("http://{}/policy", origin.address))
                        .send()
                        .and_then(|response| response.text())
                        .unwrap_or_else(|error| panic!("{description} TCP: {error}")),
                    "TCP remains available",
                    "{description}"
                );
                // The local Trojan H2Mux server disables UDP regardless of
                // client policy; default UDP interoperability uses sing-box.
                if tcp_only || transport == "tcp" || transport == "h2mux" {
                    udp_policy::assert_udp_blocked(inbound)
                        .unwrap_or_else(|error| panic!("{description} UDP rejection: {error}"));
                } else {
                    support::udp_roundtrip(inbound)
                        .unwrap_or_else(|error| panic!("{description} default UDP: {error}"));
                }
            }
            // A selectable direct member exists and works, but was not used
            // while the chosen proxy had disabled UDP. The control catalog
            // exposes the built-in "direct" configuration as "DIRECT".
            runtime
                .block_on(running.core.select("choice".into(), "DIRECT".into()))
                .unwrap();
            support::udp_roundtrip(inbound).unwrap();
            runtime
                .block_on(running.core.select("choice".into(), "policy-node".into()))
                .unwrap();
            if tcp_only {
                udp_policy::assert_udp_blocked(inbound).unwrap();
            }
            runtime.block_on(running.core.shutdown()).unwrap();
            TcpListener::bind(("127.0.0.1", inbound)).expect("mixed listener released");
        }
    }
}

#[test]
fn udp_only_nodes_keep_datagrams_and_block_tcp_without_switching_nodes() {
    let _serial = support::runtime_lock();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = certified.cert.pem();
    std::fs::write(directory.path().join("cert.pem"), &certificate).unwrap();
    std::fs::write(
        directory.path().join("key.pem"),
        certified.signing_key.serialize_pem(),
    )
    .unwrap();
    let (origin, requests) = support::http(b"must not arrive".to_vec());
    for (kind, transport) in [
        ("socks", "native"),
        ("socks", "uot1"),
        ("socks", "uot2"),
        ("trojan", "native"),
        ("naive", "uot2"),
    ] {
        let (mut node, server) = case(kind, transport, &certificate, directory.path());
        node["network"] = "udp".into();
        let inbound = support::free_port();
        let client = protocol::convert_outbound(node.clone(), "node").unwrap();
        for selector in [false, true] {
            let mut config = json!([client, server]);
            if selector {
                config.as_array_mut().unwrap().push(
                    json!({"client_group":"choice", "type":"selector", "default":"policy-node",
                    "client_chains":[{"chain":["policy-node"]},{"chain":["direct"]}]}),
                );
            }
            config.as_array_mut().unwrap().push(json!({"address":format!("127.0.0.1:{inbound}"), "protocol":{"type":"mixed"},
                "rules":[{"conditions":{"any_destination":true},"action":"allow","client_chain":if selector {"choice"} else {"policy-node"}}]}));
            let running = Running {
                core: runtime
                    .block_on(EmbeddedCore::start_json(&config.to_string(), None))
                    .unwrap(),
                runtime: &runtime,
            };
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{inbound}")).unwrap())
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            for _ in 0..2 {
                assert!(
                    client
                        .get(format!("http://{}/blocked", origin.address))
                        .send()
                        .is_err(),
                    "{kind}/{transport}, selector={selector}"
                );
                support::udp_roundtrip(inbound).unwrap_or_else(|error| {
                    panic!("{kind}/{transport}, selector={selector}: {error}")
                });
            }
            drop(running);
        }
    }
    assert_eq!(requests.load(std::sync::atomic::Ordering::Relaxed), 0);
}
