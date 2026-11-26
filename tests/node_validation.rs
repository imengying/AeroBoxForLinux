//! Subscription admission uses the core's static validators without a runtime
//! or network access, so one invalid node cannot poison all usable nodes.
use aerobox_for_linux::{
    model::{Store, Subscription},
    protocol, subscription,
};
use serde_json::{Value, json};

const UUID: &str = "00000000-0000-4000-8000-000000000001";
const REALITY_KEY: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";

fn node(kind: &str) -> Value {
    let mut node = json!({
        "type":kind, "tag":format!("{kind}-fixture"),
        "server":"offline.invalid", "server_port":443
    });
    match kind {
        "shadowsocks" => {
            node["method"] = "aes-128-gcm".into();
            node["password"] = "fixture-password".into();
        }
        "vmess" | "vless" => node["uuid"] = UUID.into(),
        "tuic" => {
            node["uuid"] = UUID.into();
            node["password"] = "fixture-password".into();
        }
        "trojan" | "anytls" | "hysteria2" | "naive" => {
            node["password"] = "fixture-password".into();
        }
        "socks" | "http" => {}
        _ => unreachable!(),
    }
    if matches!(kind, "trojan" | "anytls" | "hysteria2" | "tuic" | "naive") {
        node["tls"] = json!({"enabled":true,"server_name":"offline.invalid"});
    }
    node
}

fn invalid_nodes() -> Vec<(Value, &'static str)> {
    let mut cases = Vec::new();
    for kind in ["vmess", "vless", "tuic"] {
        let mut invalid = node(kind);
        invalid["uuid"] = "".into();
        cases.push((invalid, "uuid"));
    }
    let mut invalid = node("vmess");
    invalid["security"] = "invalid-cipher".into();
    cases.push((invalid, "cipher"));
    let mut invalid = node("vless");
    invalid["tls"] = json!({"enabled":true,"server_name":"offline.invalid",
        "reality":{"enabled":true,"public_key":"AQID","short_id":"ab"}});
    cases.push((invalid.clone(), "key"));
    invalid["tls"]["reality"]["public_key"] = REALITY_KEY.into();
    invalid["tls"]["reality"]["short_id"] = "not-hex".into();
    cases.push((invalid, "short_id"));
    for kind in ["trojan", "hysteria2"] {
        let mut invalid = node(kind);
        invalid["tls"]["min_version"] = "1.3".into();
        invalid["tls"]["max_version"] = "1.2".into();
        cases.push((invalid, "min_version"));
        let mut invalid = node(kind);
        invalid["tls"]["certificate_public_key_sha256"] = "aW52YWxpZA==".into();
        cases.push((invalid, "32 bytes"));
        let mut invalid = node(kind);
        invalid["tls"]["server_name"] = "invalid host name".into();
        cases.push((invalid, "server name"));
    }
    let mut invalid = node("trojan");
    invalid["tls"]["certificate"] =
        "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----".into();
    cases.push((invalid, "certificate"));
    let mut invalid = node("trojan");
    invalid["tls"]["client_certificate_path"] = "/missing/client.pem".into();
    cases.push((invalid, "both client cert and key"));
    let mut invalid = node("trojan");
    invalid["multiplex"] = json!({"enabled":true,"max_connections":65});
    cases.push((invalid, "multiplex limits"));
    let mut invalid = node("hysteria2");
    invalid["obfs"] = json!({"type":"salamander","password":"x"});
    cases.push((invalid, "4 bytes"));
    let mut invalid = node("hysteria2");
    invalid["server_ports"] = json!(["100:90"]);
    cases.push((invalid, "hopping ports"));
    let mut invalid = node("tuic");
    invalid["heartbeat"] = "31s".into();
    cases.push((invalid, "heartbeat"));
    let mut invalid = node("naive");
    invalid["insecure_concurrency"] = 17.into();
    cases.push((invalid, "concurrency"));
    let mut invalid = node("http");
    invalid["headers"] = json!({"X-Bad":"line\nbreak"});
    cases.push((invalid, "header"));
    cases
}

#[test]
fn malformed_parameters_are_rejected_before_runtime_creation() {
    for (invalid, expected) in invalid_nodes() {
        let error = protocol::validate(&invalid).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains(invalid["tag"].as_str().unwrap()), "{error}");
        assert!(
            error.to_lowercase().contains(expected),
            "expected {expected}: {error}"
        );
    }
}

#[test]
fn offline_validation_keeps_all_protocols_and_defers_certificate_files() {
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
        protocol::validate(&node(kind)).unwrap_or_else(|error| panic!("{kind}: {error:#}"));
    }
    let mut ss2022 = node("shadowsocks");
    ss2022["method"] = "2022-blake3-aes-128-gcm".into();
    ss2022["password"] = "EREREREREREREREREREREQ==".into();
    protocol::validate(&ss2022).unwrap();
    let mut reality = node("vless");
    reality["tls"] = json!({"enabled":true,"server_name":"offline.invalid",
        "reality":{"enabled":true,"public_key":REALITY_KEY,"short_id":"ab"}});
    protocol::validate(&reality).unwrap();
    let mut empty_sni = node("vmess");
    empty_sni["tls"] = json!({"enabled":true,"server_name":""});
    protocol::validate(&empty_sni).unwrap();

    let directory = tempfile::tempdir().unwrap();
    for kind in ["trojan", "hysteria2", "naive"] {
        let mut with_files = node(kind);
        with_files["tls"]["certificate_path"] = json!(directory.path().join("missing-root.pem"));
        with_files["tls"]["client_certificate_path"] =
            json!(directory.path().join("missing-client.pem"));
        with_files["tls"]["client_key_path"] = json!(directory.path().join("missing-client.key"));
        if kind == "naive" {
            with_files["quic"] = true.into();
        }
        protocol::validate(&with_files).unwrap();
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    let certified = rcgen::generate_simple_self_signed(vec!["offline.invalid".into()]).unwrap();
    let mut inline = node("trojan");
    inline["tls"]["certificate"] = certified.cert.pem().into();
    inline["tls"]["client_certificate"] = certified.cert.pem().into();
    inline["tls"]["client_key"] = certified.signing_key.serialize_pem().into();
    protocol::validate(&inline).unwrap();
    let mut lines = inline.clone();
    for field in ["certificate", "client_certificate", "client_key"] {
        lines["tls"][field] = json!(
            inline["tls"][field]
                .as_str()
                .unwrap()
                .lines()
                .collect::<Vec<_>>()
        );
    }
    // Inline PEM takes precedence over a path and line arrays form one PEM.
    lines["tls"]["certificate_path"] = "/not-loaded/root.pem".into();
    lines["tls"]["client_certificate_path"] = "/not-loaded/client.pem".into();
    lines["tls"]["client_key_path"] = "/not-loaded/client.key".into();
    lines["tls"]["curve_preferences"] = json!(["X25519", "P256", "P384", "P521"]);
    lines["tls"]["alpn"] = "h2".into();
    lines["tls"]["min_version"] = "".into();
    lines["tls"]["max_version"] = "".into();
    protocol::validate(&lines).unwrap();
    lines["tls"]["curve_preferences"] = json!([]);
    protocol::validate(&lines).unwrap();
    // A source edit must not reuse the prior successful validation result.
    inline["tls"]["client_key"] = "not a private key".into();
    assert!(protocol::validate(&inline).is_err());
    for (inline_field, path_field, valid, invalid) in [
        (
            "client_certificate",
            "client_key_path",
            certified.cert.pem(),
            "not a certificate",
        ),
        (
            "client_key",
            "client_certificate_path",
            certified.signing_key.serialize_pem(),
            "not a private key",
        ),
    ] {
        let mut mixed = node("trojan");
        mixed["tls"][inline_field] = valid.into();
        mixed["tls"][path_field] = json!(directory.path().join("not-loaded.pem"));
        protocol::validate(&mixed).unwrap();
        mixed["tls"][inline_field] = invalid.into();
        assert!(
            protocol::validate(&mixed).is_err(),
            "accepted invalid inline {inline_field}"
        );
    }
}

#[test]
fn subscription_refresh_keeps_good_nodes_and_reports_bad_parameters() {
    let good = node("socks");
    let invalid: Vec<_> = invalid_nodes()
        .into_iter()
        .map(|(value, _)| value)
        .collect();
    let mut all = invalid.clone();
    all.insert(2, good.clone());
    let source = json!({"outbounds":all}).to_string();
    assert!(subscription::parse(&source).is_err());
    let (accepted, skipped) = subscription::parse_with_skips(&source).unwrap();
    assert_eq!(accepted, vec![good]);
    assert_eq!(skipped.len(), invalid.len());
    for (node, reason) in invalid.iter().zip(&skipped) {
        assert!(reason.contains(node["tag"].as_str().unwrap()), "{reason}");
    }
    for source in [
        "vless://@offline.invalid:443#bad-vless\nsocks5://offline.invalid:1080#good".to_owned(),
        json!({"proxies":[
            {"name":"bad-vmess","type":"vmess","server":"offline.invalid","port":443,"uuid":""},
            {"name":"good","type":"socks5","server":"offline.invalid","port":1080}
        ]})
        .to_string(),
    ] {
        let (nodes, skipped) = subscription::parse_with_skips(&source).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["tag"], "good");
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].to_lowercase().contains("uuid"));
    }
}

#[test]
fn invalid_edit_does_not_replace_cached_valid_node_or_saved_state() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(Some(directory.path().into())).unwrap();
    let good = node("vless");
    store
        .update(|state| {
            state.subscriptions.push(Subscription {
                nodes: vec![good.clone()],
                ..Subscription::default()
            });
            Ok(())
        })
        .unwrap();
    let saved = std::fs::read(directory.path().join("state.json")).unwrap();
    assert!(
        store
            .update(|state| {
                state.subscriptions[0].nodes[0]["uuid"] = "".into();
                Ok(())
            })
            .is_err()
    );
    assert_eq!(store.state.subscriptions[0].nodes, vec![good]);
    assert_eq!(
        std::fs::read(directory.path().join("state.json")).unwrap(),
        saved
    );
}
