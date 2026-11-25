mod support;

use aerobox_for_linux::{
    model::{self, RuleSet, Store},
    subscription,
};
use serde_json::{Value, json};
use std::fs;
use support::{App, socks_node};

fn setup() -> App {
    let app = App::new();
    app.import(
        "fixture",
        vec![socks_node("fixture", "127.0.0.1:9".parse().unwrap())],
    );
    app
}

#[test]
fn native_runtime_validates_dns_transports_and_domain_bootstrap() {
    let _serial = support::runtime_lock();
    let app = setup();
    for address in [
        "udp://127.0.0.1:5353",
        "tcp://127.0.0.1:5353",
        "tls://127.0.0.1:5353",
        "https://127.0.0.1:5353/dns-query",
        "quic://127.0.0.1:5353",
        "tls://dns.alidns.com",
        "https://cloudflare-dns.com/dns-query",
        "quic://dns.adguard-dns.com",
    ] {
        let mut settings = app.service.snapshot().settings;
        settings.remote_dns = address.into();
        settings.direct_dns = "tls://dns.alidns.com".into();
        app.service.apply_settings(settings).unwrap();
        app.service
            .check_current()
            .unwrap_or_else(|error| panic!("{address}: {error:#}"));
    }
}

#[test]
fn invalid_dns_ports_and_themes_cannot_replace_saved_settings() {
    let app = setup();
    let before = app.service.snapshot().settings;
    let state_path = app.dir.path().join("state.json");
    let saved = fs::read(&state_path).unwrap();
    for address in [
        "udp://127.0.0.1:0",
        "tcp://[::1]:0",
        "tls://dns.example.test:0",
        "https://dns.example.test:0/dns-query",
        "quic://[::1]:0",
    ] {
        for direct in [true, false] {
            let mut settings = before.clone();
            if direct {
                settings.direct_dns = address.into();
            } else {
                settings.remote_dns = address.into();
            }
            let error = app.service.apply_settings(settings).unwrap_err();
            assert!(error.to_string().contains("DNS 端口"), "{error:#}");
            assert_eq!(app.service.snapshot().settings, before);
            assert_eq!(fs::read(&state_path).unwrap(), saved);
        }
    }
    let mut settings = before.clone();
    settings.theme = "unknown".into();
    assert!(app.service.apply_settings(settings).is_err());
    assert_eq!(app.service.snapshot().settings, before);
    assert_eq!(fs::read(state_path).unwrap(), saved);
}

#[test]
fn android_rule_seeds_are_accepted_without_an_external_compiler() {
    let _serial = support::runtime_lock();
    let app = setup();
    app.service
        .update(|state| {
            state.settings.routing_mode = "rule".into();
            state.rulesets = model::builtin_resources();
            for rule in &mut state.rulesets {
                rule.source.clear();
            }
            Ok(())
        })
        .unwrap();
    app.service.check_current().unwrap();
    app.service
        .apply_ruleset_enabled(model::BUILTIN_ADS_ID, true)
        .unwrap();
    let generated = app.service.generate_current().unwrap();
    let sources: Vec<_> = generated
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry.get("rule_source_group").is_some())
        .collect();
    assert_eq!(sources.len(), 3);
    for source in sources {
        assert!(
            fs::read(source["rules"][0]["path"].as_str().unwrap())
                .unwrap()
                .starts_with(b"SRS")
        );
    }
    app.service.check(&generated).unwrap();
    let source = app.service.rule_source(model::BUILTIN_ADS_ID).unwrap();
    assert!(serde_json::from_str::<Value>(&source).unwrap()["rules"].is_array());
    let updated = r#"{"version":3,"rules":[{"domain_suffix":["ads.example.test"]}]}"#;
    app.service
        .save_rule_source(model::BUILTIN_ADS_ID, updated)
        .unwrap();
    let rule = app
        .service
        .snapshot()
        .rulesets
        .into_iter()
        .find(|rule| rule.id == model::BUILTIN_ADS_ID)
        .unwrap();
    assert!(!rule.binary, "editing SRS must persist portable JSON rules");
    assert_eq!(
        rule.content["rules"][0]["domain_suffix"][0],
        "ads.example.test"
    );
    app.service.check_current().unwrap();
}

#[test]
fn native_modes_and_network_settings_validate_without_binding_privileged_interfaces() {
    let _serial = support::runtime_lock();
    let app = setup();
    let original = app.service.snapshot().subscriptions;
    for mode in ["rule", "global"] {
        for ipv6 in [false, true] {
            for tun_enabled in [false, true] {
                let mut settings = app.service.snapshot().settings;
                settings.routing_mode = mode.into();
                settings.ipv6 = ipv6;
                settings.tun_enabled = tun_enabled;
                settings.dns_cache = false;
                settings.sniff = false;
                settings.dns_hijack = false;
                app.service.apply_settings(settings).unwrap();
                let config = app.service.generate_current().unwrap();
                assert!(config.is_array());
                let listener = config
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|entry| entry["name"] == "mixed-in")
                    .unwrap();
                assert_eq!(
                    listener["address"],
                    format!("127.0.0.1:{}", app.service.local_proxy_port())
                );
                let saved = serde_json::to_value(&app.service.snapshot().settings).unwrap();
                assert!(saved.get("allow_lan").is_none() && saved.get("mixed_port").is_none());
                app.service
                    .check(&config)
                    .unwrap_or_else(|e| panic!("{mode}, ipv6={ipv6}, TUN={tun_enabled}: {e:#}"));
                assert!(!app.service.status().running);
            }
        }
    }
    assert_eq!(app.service.snapshot().subscriptions, original);
    let before = app.service.snapshot().settings;
    assert!(app.service.set_routing_mode("direct").is_err());
    let mut invalid = before.clone();
    invalid.routing_mode = "direct".into();
    assert!(app.service.apply_settings(invalid).is_err());
    assert_eq!(app.service.snapshot().settings, before);
}

#[test]
fn invalid_stored_data_is_reported_without_overwriting_it() {
    let app = setup();
    let mut state = app.service.snapshot();
    state.rulesets.push(RuleSet::default());
    let original = serde_json::to_value(state).unwrap();
    let mut invalid = vec![
        {
            let mut v = original.clone();
            v["settings"]["unknown_option"] = json!(120);
            v
        },
        {
            let mut v = original.clone();
            v["settings"]["theme"] = json!("unknown");
            v
        },
    ];
    for (path, field) in [
        ("/settings", "ipv6"),
        ("/settings", "system_proxy"),
        ("/subscriptions/0", "id"),
        ("/subscriptions/0", "nodes"),
        ("/subscriptions/0", "import_issues"),
        ("/rulesets/0", "id"),
        ("/rulesets/0", "enabled"),
        ("/rulesets/0", "content"),
    ] {
        let mut value = original.clone();
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        invalid.push(value);
    }
    for data in invalid {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let bytes = serde_json::to_vec(&data).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(Store::open(Some(directory.path().into())).is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "invalid data must never be rewritten"
        );
    }
}

#[test]
fn imported_group_metadata_is_not_stored_as_connectable_nodes() {
    let app = App::new();
    let nodes = subscription::parse(
        r#"{"outbounds":[
      {"type":"direct","tag":"direct"},
      {"type":"selector","tag":"proxy","outbounds":["one"]},
      {"type":"urltest","tag":"automatic","outbounds":["one"]},
      {"type":"socks","tag":"one","server":"127.0.0.1","server_port":1080}
    ]}"#,
    )
    .unwrap();
    let id = app.import("imported", nodes);
    assert_eq!(app.service.subscription_nodes(&id).unwrap().len(), 1);
    assert_eq!(app.service.snapshot().subscriptions[0].nodes.len(), 1);
    assert!(app.service.select_subscription_node(&id, "proxy").is_err());
}

#[test]
fn invalid_or_unsupported_nodes_cannot_replace_a_saved_subscription() {
    let app = setup();
    let original = app.service.snapshot().subscriptions[0].clone();
    for invalid in [
        json!({"type":"socks","tag":"bad","server":"127.0.0.1","server_port":"invalid"}),
        json!({"type":"socks","tag":"bad","server":"127.0.0.1","server_port":1080,"unknown_security_option":true}),
        json!({"type":"snell","tag":"bad","server":"127.0.0.1","server_port":443,"psk":"secret"}),
        json!({"type":"shadowtls","tag":"bad","server":"127.0.0.1","server_port":443,"password":"secret"}),
    ] {
        assert!(
            app.service
                .save_subscription_nodes(&original, vec![invalid])
                .is_err()
        );
        assert_eq!(app.service.snapshot().subscriptions[0], original);
    }
}

#[test]
fn vless_vision_validates_over_tls_and_reality_and_rejects_incompatible_transports() {
    let _serial = support::runtime_lock();
    let app = App::new();
    let base = json!({
        "type":"vless", "tag":"Vision", "server":"127.0.0.1", "server_port":443,
        "uuid":"00000000-0000-4000-8000-000000000001", "flow":"xtls-rprx-vision",
        "tls":{"enabled":true,"server_name":"localhost"}
    });
    let id = app.import("Vision", vec![base.clone()]);
    app.service.check_current().unwrap();
    let original = app.service.snapshot().subscriptions[0].clone();
    let mut reality = base.clone();
    reality["tls"]["reality"] = json!({
        "enabled":true,
        "public_key":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
        "short_id":"0123456789abcdef"
    });
    app.service
        .save_subscription_nodes(&original, vec![reality])
        .unwrap();
    app.service.check_current().unwrap();
    assert_eq!(app.service.snapshot().settings.active_subscription, id);

    for patch in [
        json!({"tls":{"enabled":false}}),
        json!({"transport":{"type":"ws","path":"/ws"}}),
        json!({"transport":{"type":"quic"}}),
        json!({"multiplex":{"enabled":true}}),
    ] {
        let mut invalid = base.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        assert!(
            subscription::parse(&json!({"outbounds":[invalid]}).to_string()).is_err(),
            "Vision with {patch} must fail during import"
        );
    }
}

#[test]
fn disabled_rules_are_not_loaded_and_invalid_route_actions_are_rejected() {
    let _serial = support::runtime_lock();
    let app = setup();
    let rule = RuleSet {
        name: "disabled".into(),
        binary: true,
        enabled: false,
        ..RuleSet::default()
    };
    app.service.save_ruleset(rule).unwrap();
    app.service.set_routing_mode("rule").unwrap();
    app.service.check_current().unwrap();
    let invalid = RuleSet {
        action: "unknown".into(),
        content: json!({"version":3,"rules":[]}),
        ..RuleSet::default()
    };
    assert!(app.service.save_ruleset(invalid).is_err());
}

#[test]
fn invalid_json_rules_are_rejected_while_stopped_even_when_disabled() {
    let app = setup();
    let before = serde_json::to_value(app.service.snapshot()).unwrap();
    for enabled in [false, true] {
        for content in [
            json!({"version":3,"rules":"not an array"}),
            json!({"version":3,"rules":[{"process_name":["unsupported"]}]}),
            json!({"version":3,"rules":[{"domain":["example.test"],"unsupported_field":true}]}),
            json!({"version":3,"rules":[{"ip_cidr":["invalid CIDR"]}]}),
        ] {
            assert!(
                app.service
                    .save_ruleset(RuleSet {
                        enabled,
                        content,
                        ..RuleSet::default()
                    })
                    .is_err()
            );
            assert_eq!(
                serde_json::to_value(app.service.snapshot()).unwrap(),
                before
            );
            assert_eq!(
                serde_json::from_slice::<Value>(
                    &fs::read(app.dir.path().join("state.json")).unwrap()
                )
                .unwrap(),
                before
            );
        }
    }
}
