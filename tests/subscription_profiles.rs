mod support;

use aerobox_for_linux::{
    model::{Store, Subscription},
    protocol, subscription,
};
use serde_json::{Value, json};

const UUID: &str = "00000000-0000-4000-8000-000000000001";
const REALITY_KEY: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";

// Matches the reported Clash subscription's parameter combinations, using
// synthetic hosts and credentials. Global Clash DNS/groups are not node data.
fn clash_sample() -> Value {
    json!({"mixed-port":7890,"mode":"rule","dns":{"enable":true},"proxies":[
        {"name":"reality-default","type":"vless","server":"offline.invalid","port":443,
         "uuid":UUID,"encryption":"none","flow":"xtls-rprx-vision","network":"tcp",
         "alterId":0,"cipher":"auto","udp":true,"tls":true,"client-fingerprint":"safari","servername":"offline.invalid",
         "reality-opts":{"public-key":REALITY_KEY}},
        {"name":"websocket-firefox","type":"vless","server":"offline.invalid","port":443,
         "uuid":UUID,"network":"ws","udp":true,"tls":true,"client-fingerprint":"firefox",
         "servername":"offline.invalid","ws-opts":{"path":"/fixture","headers":{"Host":"offline.invalid"}}},
        {"name":"shadowsocks","type":"ss","server":"offline.invalid","port":443,
         "cipher":"aes-256-gcm","password":"fixture-password","udp":true,"client-fingerprint":"chrome"},
        {"name":"anytls-chrome","type":"anytls","server":"offline.invalid","port":443,
         "password":"fixture-password","client-fingerprint":"chrome","udp":true,"udp-over-tcp":true,
         "idle-session-check-interval":30,"idle-session-timeout":30,"min-idle-session":0,
         "sni":"offline.invalid","alpn":["h2","http/1.1"],"skip-cert-verify":true}
    ]})
}

#[test]
fn clash_browser_profiles_only_apply_when_tls_is_enabled() {
    for kind in ["ss", "vmess", "vless", "socks5", "http"] {
        let mut plain = json!({"type":kind,"name":"plain","server":"offline.invalid","port":443});
        match kind {
            "ss" => {
                plain["cipher"] = "aes-256-gcm".into();
                plain["password"] = "fixture-password".into();
            }
            "vmess" | "vless" => plain["uuid"] = UUID.into(),
            _ => {}
        }
        let source = |node: Value| json!({"proxies":[node]}).to_string();
        let expected = subscription::parse(&source(plain.clone())).unwrap();
        for tls in [None, Some(false)] {
            let mut node = plain.clone();
            if let Some(tls) = tls {
                node["tls"] = tls.into();
            }
            for fingerprint in ["", "chrome", "firefox", "random", "unused-profile"] {
                node["client-fingerprint"] = fingerprint.into();
                let body = source(node.clone());
                let (imported, skipped) = subscription::parse_with_skips(&body)
                    .unwrap_or_else(|error| panic!("{kind}, {tls:?}, {fingerprint}: {error:#}"));
                assert!(skipped.is_empty());
                assert_eq!(imported, expected);
                assert_eq!(subscription::parse(&body).unwrap(), expected);
            }
            for invalid in [json!(true), json!(1), json!([]), json!({}), Value::Null] {
                node["client-fingerprint"] = invalid;
                let error = subscription::parse(&source(node.clone())).unwrap_err();
                assert!(format!("{error:#}").contains("client-fingerprint"));
            }
        }
        plain["tls"] = true.into();
        for fingerprint in [
            None,
            Some(""),
            Some("chrome"),
            Some("firefox"),
            Some("safari"),
            Some("random"),
        ] {
            if let Some(fingerprint) = fingerprint {
                plain["client-fingerprint"] = fingerprint.into();
            } else {
                plain.as_object_mut().unwrap().remove("client-fingerprint");
            }
            let imported = subscription::parse(&source(plain.clone())).unwrap();
            let converted = protocol::convert_outbound(imported[0].clone(), "fixture").unwrap();
            assert_eq!(
                converted["client_chains"][0]["chain"][0]["protocol"]["options"]["client_fingerprint"],
                if fingerprint == Some("chrome") {
                    "chrome"
                } else {
                    "firefox"
                }
            );
        }
    }
}

#[test]
fn mixed_clash_profiles_survive_download_storage_and_node_listing() {
    let _serial = support::runtime_lock();
    let sample = clash_sample();
    let (server, _) = support::http(sample.to_string());
    let app = support::App::new();
    let sub = Subscription {
        source: format!("http://{}/subscription", server.address),
        ..Default::default()
    };
    let id = sub.id.clone();
    app.service.import_subscription(sub).unwrap();
    let saved = app.service.snapshot();
    let sub = saved.subscriptions.iter().find(|sub| sub.id == id).unwrap();
    assert!(sub.import_issues.is_empty(), "{:?}", sub.import_issues);
    assert_eq!(sub.nodes.len(), 4);
    assert_eq!(
        sub.nodes
            .iter()
            .map(|node| node["type"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["vless", "vless", "shadowsocks", "anytls"]
    );
    let reality = protocol::convert_outbound(sub.nodes[0].clone(), "fixture").unwrap();
    assert_eq!(
        reality["client_chains"][0]["chain"][0]["protocol"]["client_fingerprint"],
        "firefox"
    );
    assert_eq!(
        reality["client_chains"][0]["chain"][0]["protocol"]["vision"],
        true
    );
    assert_eq!(
        reality["client_chains"][0]["chain"][0]["protocol"]["protocol"]["udp_enabled"],
        true
    );
    let anytls = protocol::convert_outbound(sub.nodes[3].clone(), "fixture").unwrap();
    assert_eq!(
        anytls["client_chains"][0]["chain"][0]["protocol"]["options"]["client_fingerprint"],
        "chrome"
    );
    assert_eq!(
        anytls["client_chains"][0]["chain"][0]["protocol"]["protocol"]["type"],
        "anytls"
    );
    assert_eq!(
        anytls["client_chains"][0]["chain"][0]["protocol"]["protocol"]["idle_session_timeout_secs"],
        30
    );
    assert_eq!(
        anytls["client_chains"][0]["chain"][0]["protocol"]["protocol"]["udp_enabled"],
        true
    );
    let reopened = support::service(Store::open(Some(app.dir.path().into())).unwrap());
    let listed = reopened.subscription_nodes(&id).unwrap();
    assert_eq!(listed.len(), 4);
    assert_eq!(
        listed
            .iter()
            .filter(|node| node.protocol == "vless")
            .count(),
        2
    );
}

#[test]
fn vless_subscription_template_imports_every_node_with_default_firefox() {
    let _serial = support::runtime_lock();
    let mut sample = clash_sample();
    let servers = ["192.0.2.1", "198.51.100.2", "2001:db8::1", "2001:db8:1::2"];
    let short_ids = [
        "fd3e710308",
        "01fb66541f5df40f",
        "3d74b0e5793841",
        "3ccfe96d",
    ];
    sample["proxies"] = (0..31)
        .map(|index| {
            let mut node = sample["proxies"][0].clone();
            node["name"] = format!("节点 {index}").into();
            node["server"] = servers[index % servers.len()].into();
            node["skip-cert-verify"] = false.into();
            node["reality-opts"]["short-id"] = short_ids[index % short_ids.len()].into();
            node
        })
        .collect();
    let (server, _) = support::http(serde_yaml_ng::to_string(&sample).unwrap());
    let app = support::App::new();
    let sub = Subscription {
        source: format!("http://{}/subscription", server.address),
        ..Default::default()
    };
    let id = sub.id.clone();
    app.service.import_subscription(sub).unwrap();
    let saved = Store::open(Some(app.dir.path().into())).unwrap();
    let sub = saved
        .state
        .subscriptions
        .iter()
        .find(|sub| sub.id == id)
        .unwrap();
    assert_eq!(sub.nodes.len(), 31);
    assert!(sub.import_issues.is_empty());
    for (index, node) in sub.nodes.iter().enumerate() {
        assert_eq!(node["server"], servers[index % servers.len()]);
        assert_eq!(node["encryption"], "none");
        for field in ["alter_id", "alterId", "cipher", "security"] {
            assert!(node.get(field).is_none(), "unexpected VLESS field {field}");
        }
        let converted = protocol::convert_outbound(node.clone(), "fixture").unwrap();
        let reality = &converted["client_chains"][0]["chain"][0]["protocol"];
        assert_eq!(reality["type"], "reality");
        assert_eq!(reality["client_fingerprint"], "firefox");
        assert_eq!(reality["vision"], true);
        assert_eq!(reality["public_key"], REALITY_KEY);
        assert_eq!(reality["short_id"], short_ids[index % short_ids.len()]);
        assert_eq!(reality["protocol"]["udp_enabled"], true);
    }
    let reopened = support::service(saved);
    assert_eq!(reopened.subscription_nodes(&id).unwrap().len(), 31);
}

#[test]
fn import_reports_are_persisted_and_replaced_after_successful_refresh() {
    let _serial = support::runtime_lock();
    let mut sample = clash_sample();
    sample["proxies"][0]["client-fingerprint"] = true.into();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("subscription.yaml");
    std::fs::write(&path, sample.to_string()).unwrap();
    let app = support::App::new();
    let sub = Subscription {
        source: path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let id = sub.id.clone();
    app.service.import_subscription(sub).unwrap();
    let loaded = Store::open(Some(app.dir.path().into())).unwrap();
    assert_eq!(loaded.state.subscriptions[0].nodes.len(), 3);
    let issues = &loaded.state.subscriptions[0].import_issues;
    assert_eq!(issues.len(), 1);
    assert!(issues[0].contains("fingerprint"));
    assert!(!issues[0].contains(REALITY_KEY));
    assert!(!issues[0].contains(UUID));
    std::fs::write(&path, clash_sample().to_string()).unwrap();
    app.service.update_subscription(&id).unwrap();
    let loaded = Store::open(Some(app.dir.path().into())).unwrap();
    assert!(loaded.state.subscriptions[0].import_issues.is_empty());
    assert_eq!(loaded.state.subscriptions[0].nodes.len(), 4);
}

#[test]
fn share_links_keep_browser_profiles_and_anytls_udp_policy() {
    for fingerprint in ["", "firefox", "chrome", "safari"] {
        let link = format!(
            "vless://{UUID}@offline.invalid:443?security=tls&fp={fingerprint}&type=ws&path=%2Ffixture#vless"
        );
        let nodes = subscription::parse(&link).unwrap();
        let converted = protocol::convert_outbound(nodes[0].clone(), "fixture").unwrap();
        let tls = &converted["client_chains"][0]["chain"][0]["protocol"];
        assert_eq!(
            tls["options"]["client_fingerprint"],
            if fingerprint == "chrome" {
                "chrome"
            } else {
                "firefox"
            }
        );
        assert_eq!(tls["alpn_protocols"], json!(["http/1.1"]));
    }
    let mut sample = clash_sample();
    sample["proxies"][3]["udp-over-tcp"] = false.into();
    let nodes = subscription::parse(&sample.to_string()).unwrap();
    let anytls = protocol::convert_outbound(nodes[3].clone(), "fixture").unwrap();
    assert_eq!(
        anytls["client_chains"][0]["chain"][0]["protocol"]["protocol"]["udp_enabled"],
        false
    );
    sample["proxies"][3]["udp-over-tcp"] = true.into();
    sample["proxies"][3]["udp"] = false.into();
    let nodes = subscription::parse(&sample.to_string()).unwrap();
    let anytls = protocol::convert_outbound(nodes[3].clone(), "fixture").unwrap();
    assert_eq!(
        anytls["client_chains"][0]["chain"][0]["protocol"]["protocol"]["udp_enabled"],
        false
    );
}

#[test]
fn disabling_a_browser_profile_keeps_tls_enabled() {
    let nodes = subscription::parse(
        &json!({"outbounds":[{
            "type":"vless","tag":"disabled-profile","server":"offline.invalid","server_port":443,
            "uuid":UUID,"tls":{"enabled":true,"server_name":"offline.invalid",
                "utls":{"enabled":false,"fingerprint":"chrome"}}
        }]})
        .to_string(),
    )
    .unwrap();
    let converted = protocol::convert_outbound(nodes[0].clone(), "fixture").unwrap();
    let tls = &converted["client_chains"][0]["chain"][0]["protocol"];
    assert_eq!(tls["type"], "tls");
    assert_eq!(tls["verify"], true);
    assert!(tls["options"]["client_fingerprint"].is_null());
}

#[test]
fn transport_alpn_defaults_override_browser_defaults_and_keep_explicit_values() {
    for (transport, expected) in [
        (Value::Null, json!(["h2", "http/1.1"])),
        (json!({"type":"ws","path":"/"}), json!(["http/1.1"])),
        (
            json!({"type":"httpupgrade","path":"/"}),
            json!(["http/1.1"]),
        ),
        (json!({"type":"grpc","service_name":"test"}), json!(["h2"])),
        (json!({"type":"http","path":"/"}), json!(["h2"])),
    ] {
        for fingerprint in [
            None,
            Some(""),
            Some("chrome"),
            Some("firefox"),
            Some("safari"),
        ] {
            for alpn in [None, Some(json!([])), Some(json!(["custom-protocol"]))] {
                let mut node = json!({
                    "type":"vless","tag":"alpn","server":"offline.invalid","server_port":443,
                    "uuid":UUID,"tls":{"enabled":true,"server_name":"offline.invalid"}
                });
                if let Some(fingerprint) = fingerprint {
                    node["tls"]["utls"] = json!({"enabled":true,"fingerprint":fingerprint});
                }
                if !transport.is_null() {
                    node["transport"] = transport.clone();
                }
                if let Some(alpn) = &alpn {
                    node["tls"]["alpn"] = alpn.clone();
                }
                let converted = protocol::convert_outbound(node, "fixture").unwrap();
                let tls = &converted["client_chains"][0]["chain"][0]["protocol"];
                assert_eq!(
                    tls["alpn_protocols"],
                    alpn.filter(|value| value != &json!([]))
                        .unwrap_or_else(|| expected.clone()),
                    "transport={transport}, fingerprint={fingerprint:?}"
                );
                assert_eq!(
                    tls["options"]["client_fingerprint"],
                    if fingerprint == Some("chrome") {
                        "chrome"
                    } else {
                        "firefox"
                    }
                );
            }
        }
    }
}

#[test]
fn reality_preserves_explicit_alpn_and_tls13_cipher_selection() {
    let node = json!({
        "type":"vless","tag":"reality","server":"offline.invalid","server_port":443,
        "uuid":UUID,"flow":"xtls-rprx-vision",
        "tls":{"enabled":true,"server_name":"offline.invalid","alpn":["http/1.1"],
            "min_version":"1.2","max_version":"1.3",
            "cipher_suites":["TLS_AES_128_GCM_SHA256"],
            "utls":{"enabled":true,"fingerprint":"firefox"},
            "reality":{"enabled":true,"public_key":REALITY_KEY}}
    });
    let nodes = subscription::parse(&json!({"outbounds":[node]}).to_string()).unwrap();
    let converted = protocol::convert_outbound(nodes[0].clone(), "fixture").unwrap();
    let tls = &converted["client_chains"][0]["chain"][0]["protocol"];
    assert_eq!(tls["type"], "reality");
    assert_eq!(tls["alpn_protocols"], json!(["http/1.1"]));
    assert_eq!(tls["cipher_suites"], json!(["TLS_AES_128_GCM_SHA256"]));
}

#[test]
fn http_proxy_and_naive_keep_their_application_protocol_with_browser_profiles() {
    for (kind, expected) in [("http", "http/1.1"), ("naive", "h2")] {
        let node = json!({"type":kind,"tag":kind,"server":"offline.invalid","server_port":443,
            "tls":{"enabled":true,"server_name":"offline.invalid","utls":{"enabled":true}}});
        let converted = protocol::convert_outbound(node, "fixture").unwrap();
        assert_eq!(
            converted["client_chains"][0]["chain"][0]["protocol"]["alpn_protocols"],
            json!([expected])
        );
    }
}

#[test]
fn all_supported_protocols_remain_visible_after_reopening() {
    let _serial = support::runtime_lock();
    let mut nodes = Vec::new();
    for kind in [
        "shadowsocks",
        "vmess",
        "vless",
        "trojan",
        "anytls",
        "hysteria2",
        "tuic",
        "naive",
        "socks",
        "http",
    ] {
        let mut node = json!({"type":kind,"tag":kind,"server":"offline.invalid","server_port":443});
        match kind {
            "shadowsocks" => {
                node["method"] = "aes-256-gcm".into();
                node["password"] = "fixture-password".into();
            }
            "vmess" | "vless" => {
                node["uuid"] = UUID.into();
            }
            "tuic" => {
                node["uuid"] = UUID.into();
                node["password"] = "fixture-password".into();
            }
            "trojan" | "anytls" | "hysteria2" | "naive" => {
                node["password"] = "fixture-password".into();
            }
            _ => {}
        }
        if matches!(kind, "trojan" | "anytls" | "hysteria2" | "tuic" | "naive") {
            node["tls"] = json!({"enabled":true,"server_name":"offline.invalid"});
        }
        nodes.push(node);
    }
    let (server, _) = support::http(json!({"outbounds":nodes}).to_string());
    let app = support::App::new();
    let sub = Subscription {
        source: format!("http://{}/subscription", server.address),
        ..Default::default()
    };
    let id = sub.id.clone();
    app.service.import_subscription(sub).unwrap();
    let reopened = support::service(Store::open(Some(app.dir.path().into())).unwrap());
    let listed = reopened.subscription_nodes(&id).unwrap();
    assert_eq!(listed.len(), 10);
    for node in nodes {
        assert!(
            listed
                .iter()
                .any(|entry| entry.protocol == node["type"].as_str().unwrap())
        );
    }
}
