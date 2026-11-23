use aerobox_for_linux::{protocol, subscription};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

const UUID: &str = "00000000-0000-4000-8000-000000000001";

fn raw() -> Value {
    json!({"type":"vmess", "tag":"legacy", "server":"offline.invalid", "server_port":443, "uuid":UUID, "security":"auto"})
}
fn clash() -> Value {
    json!({"type":"vmess", "name":"legacy", "server":"offline.invalid", "port":443, "uuid":UUID, "cipher":"auto"})
}
fn link(value: Option<Value>) -> String {
    let mut body = json!({"v":"2", "ps":"legacy", "add":"offline.invalid", "port":"443", "id":UUID, "net":"tcp", "type":"none", "tls":"", "scy":"auto"});
    if let Some(value) = value {
        body["aid"] = value;
    }
    format!("vmess://{}", STANDARD.encode(body.to_string()))
}

#[test]
fn vmess_alter_id_is_preserved_in_every_import_format() {
    for aid in [0u16, 1, 64, u16::MAX] {
        let mut native = raw();
        native["alter_id"] = aid.into();
        for encoded in [json!(aid), json!(aid.to_string())] {
            let mut clash = clash();
            clash["alterId"] = encoded.clone();
            for source in [
                json!([native]).to_string(),
                json!({"proxies":[clash]}).to_string(),
                link(Some(encoded)),
            ] {
                let nodes = subscription::parse(&source).unwrap();
                assert_eq!(nodes[0]["alter_id"], aid, "{source}");
                let config = protocol::convert_outbound(nodes[0].clone(), "fixture").unwrap();
                assert_eq!(
                    config["client_chains"][0]["chain"][0]["protocol"]["alter_id"],
                    aid
                );
            }
        }
    }
    for source in [link(None), json!({"proxies":[clash()]}).to_string()] {
        assert_eq!(subscription::parse(&source).unwrap()[0]["alter_id"], 0);
    }
    assert_eq!(
        protocol::convert_outbound(raw(), "fixture").unwrap()["client_chains"][0]["chain"][0]["protocol"]
            ["alter_id"],
        0
    );
}

fn uuid_imports(kind: &str, identity: &str, aid: u16) -> [String; 3] {
    let mut native = json!({"type":kind,"tag":"uuid-fixture","server":"offline.invalid","server_port":443,"uuid":identity});
    let mut clash = json!({"type":kind,"name":"uuid-fixture","server":"offline.invalid","port":443,"uuid":identity});
    let uri = if kind == "vmess" {
        native["alter_id"] = aid.into();
        clash["alterId"] = aid.into();
        let body = json!({"v":"2","ps":"uuid-fixture","add":"offline.invalid","port":"443","id":identity,"aid":aid,"net":"tcp"});
        format!("vmess://{}", STANDARD.encode(body.to_string()))
    } else {
        format!("vless://{identity}@offline.invalid:443#uuid-fixture")
    };
    [
        json!([native]).to_string(),
        json!({"proxies":[clash]}).to_string(),
        uri,
    ]
}

#[test]
fn vmess_and_vless_accept_uuid_identity_bytes_without_version_or_variant_restrictions() {
    for identity in [
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8", // Version 1.
        "6ba7b810-9dad-31d1-80b4-00c04fd430c8", // Version 3, common in subscriptions.
        "6ba7b810-9dad-51d1-80b4-00c04fd430c8", // Version 5.
        "6ba7b810-9dad-31d1-c0b4-00c04fd430c8", // Non-RFC variant.
        "00000000-0000-0000-0000-000000000000", // Nil is still a 16-byte identity.
        "6BA7B8109DAD31D180B400C04FD430C8",     // Compact uppercase form.
    ] {
        for (kind, aid) in [("vmess", 0), ("vmess", 64), ("vless", 0)] {
            for source in uuid_imports(kind, identity, aid) {
                let node = subscription::parse(&source).unwrap().remove(0);
                assert_eq!(node["uuid"], identity);
                let converted = protocol::convert_outbound(node, "fixture").unwrap();
                assert_eq!(
                    converted["client_chains"][0]["chain"][0]["protocol"]["user_id"],
                    identity
                );
            }
        }
    }
}

#[test]
fn malformed_uuid_spellings_are_rejected_without_exposing_credentials() {
    for identity in [
        "c0ffee0-09dad-31d1-80b4-00c04fd430c8", // Four dashes in the wrong positions.
        "c0ffee00--9dad-31d1-80b4-00c04fd430c8",
        "c0ffee00-9dad-31d1-80b4-00c04fd430c", // Missing hex digit.
        "c0ffee009dad31d180b400c04fd430",      // Missing byte.
        "c0ffee009dad31d180b400c04fd430c800",  // Extra byte.
        "c0ffee00-9dad-31d1-80b4-00c04fd430zz", // Non-hex digits.
    ] {
        for kind in ["vmess", "vless"] {
            for source in uuid_imports(kind, identity, 64) {
                for error in [
                    subscription::parse(&source).unwrap_err(),
                    subscription::parse_with_skips(&source).unwrap_err(),
                ] {
                    let message = format!("{error:#}");
                    assert!(message.to_ascii_lowercase().contains("uuid"), "{message}");
                    assert!(
                        !message.contains(identity),
                        "error exposed the UUID credential"
                    );
                    assert!(!message.contains("c0ffee"), "error exposed a UUID prefix");
                }
            }
        }
    }
}

#[test]
fn malformed_alter_ids_cannot_silently_select_aead_authentication() {
    let good = json!({"type":"socks", "tag":"good", "server":"127.0.0.1", "server_port":1080});
    for invalid in [
        json!(-1),
        json!(65536),
        json!(1.5),
        json!(true),
        Value::Null,
        json!(""),
        json!(" "),
        json!("-1"),
        json!("1.0"),
        json!("1e2"),
        json!("65536"),
        json!("wrong"),
        json!([]),
        json!({}),
    ] {
        let mut clash = clash();
        clash["alterId"] = invalid.clone();
        let mut native = raw();
        native["alter_id"] = invalid;
        for (source, field) in [
            (json!({"proxies":[clash]}).to_string(), "alterId"),
            (link(Some(native["alter_id"].clone())), "aid"),
            (json!([native.clone()]).to_string(), "alter_id"),
        ] {
            let error = format!("{:#}", subscription::parse(&source).unwrap_err());
            assert!(error.contains(field), "{error}");
            assert!(error.contains("65535"), "{error}");
        }
        let (accepted, skipped) =
            subscription::parse_with_skips(&json!([native, good]).to_string()).unwrap();
        assert_eq!(accepted, vec![good.clone()]);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("alter_id"));
    }
    // The app's JSON format is typed; only external share formats accept text.
    let mut raw_string = raw();
    raw_string["alter_id"] = "64".into();
    assert!(protocol::validate(&raw_string).is_err());
}

#[test]
fn common_inactive_clash_fields_do_not_hide_live_settings() {
    let mut node = clash();
    node["alterId"] = 64.into();
    node["tls"] = false.into();
    node["skip-cert-verify"] = false.into();
    node["sni"] = "".into();
    node["servername"] = "".into();
    node["alpn"] = json!([]);
    node["client-fingerprint"] = "".into();
    node["tfo"] = false.into();
    node["mptcp"] = false.into();
    let source = |node: Value| json!({"proxies":[node]}).to_string();
    let imported = subscription::parse(&source(node.clone())).unwrap();
    assert_eq!(imported[0]["alter_id"], 64);
    assert!(imported[0].get("tls").is_none());
    for (field, value) in [
        ("skip-cert-verify", json!(true)),
        ("skip-cert-verify", json!("false")),
        ("sni", json!("front.example")),
        ("servername", json!("front.example")),
        ("alpn", json!(["h2"])),
        ("alpn", json!("")),
        ("client-fingerprint", json!("chrome")),
        ("tfo", json!("true")),
        ("mptcp", json!("true")),
    ] {
        let mut invalid = node.clone();
        invalid[field] = value;
        assert!(
            subscription::parse(&source(invalid)).is_err(),
            "silently ignored {field}"
        );
    }
    node["tls"] = true.into();
    node["sni"] = "front.example".into();
    let imported = subscription::parse(&source(node.clone())).unwrap();
    assert_eq!(imported[0]["tls"]["server_name"], "front.example");
    assert!(imported[0]["tls"].get("utls").is_none());
    node["servername"] = "conflicting.example".into();
    assert!(subscription::parse(&source(node)).is_err());
}

#[test]
fn skipped_node_reports_keep_names_fields_and_actionable_reasons() {
    let mut invalid = clash();
    invalid["alterId"] = "broken".into();
    let mut plugin = json!({"type":"ss", "name":"plugin-node", "server":"offline.invalid", "port":443, "cipher":"aes-128-gcm", "password":"secret", "plugin":"unknown-plugin"});
    let body = json!({"proxies":[invalid, plugin]}).to_string();
    let error = format!("{:#}", subscription::parse_with_skips(&body).unwrap_err());
    for expected in ["legacy", "alterId", "65535", "plugin-node", "plugin"] {
        assert!(error.contains(expected), "{error}");
    }
    let messages = vec![
        "节点「a」：Clash 节点 不支持参数: test_option".into(),
        "节点「b」：Clash 节点 不支持参数: test_option".into(),
        "节点「c」.alter_id: expected an integer in 0..65535".into(),
    ];
    let summary = subscription::skipped_summary(&messages);
    assert_eq!(summary.matches("test_option").count(), 1);
    assert!(summary.contains("alter_id: expected an integer in 0..65535"));
    assert!(summary.contains("跳过 3 个节点"));
    assert!(
        subscription::skipped_summary(&["错误".repeat(1000)])
            .chars()
            .count()
            < 230
    );
    // A supported node survives, while the rejection identifies the exact field.
    plugin.as_object_mut().unwrap().remove("plugin");
    let (kept, skipped) =
        subscription::parse_with_skips(&json!({"proxies":[invalid, plugin]}).to_string()).unwrap();
    assert_eq!(kept.len(), 1);
    let summary = subscription::skipped_summary(&skipped);
    assert!(
        summary.contains("alterId") && summary.contains("65535"),
        "{summary}"
    );
}
