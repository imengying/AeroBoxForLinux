use aerobox_for_linux::{protocol, subscription};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

const UUID: &str = "00000000-0000-4000-8000-000000000001";
const PUBLIC_KEY: &str = "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn imported_protocol(source: &str) -> Value {
    let nodes = subscription::parse(source).unwrap();
    assert_eq!(nodes.len(), 1);
    protocol::convert_outbound(nodes[0].clone(), "fixture").unwrap()["client_chains"][0]["chain"][0]
        ["protocol"]
        .clone()
}

#[test]
fn vmess_padding_authenticated_lengths_and_ciphers_survive_import() {
    for cipher in [
        "auto",
        "aes-128-gcm",
        "chacha20-poly1305",
        "aes-128-cfb",
        "none",
        "zero",
    ] {
        for padding in [false, true] {
            for auth in [false, true] {
                let link = json!({"v":"2","ps":"fixture","add":"offline.invalid","port":"443","id":UUID,"net":"tcp","scy":cipher,"global_padding":padding,"authenticated_length":auth});
                let clash = json!({"proxies":[{"name":"fixture","type":"vmess","server":"offline.invalid","port":443,"uuid":UUID,"cipher":cipher,"global-padding":padding,"authenticated-length":auth}]});
                let native = json!({"outbounds":[{"tag":"fixture","type":"vmess","server":"offline.invalid","server_port":443,"uuid":UUID,"security":cipher,"global_padding":padding,"authenticated_length":auth}]});
                for source in [
                    format!("vmess://{}", STANDARD.encode(link.to_string())),
                    clash.to_string(),
                    native.to_string(),
                ] {
                    let protocol = imported_protocol(&source);
                    assert_eq!(protocol["global_padding"], padding);
                    assert_eq!(protocol["authenticated_length"], auth);
                    assert_eq!(
                        protocol["cipher"],
                        if cipher == "auto" { "any" } else { cipher }
                    );
                }
            }
        }
    }
}

#[test]
fn vless_encryption_is_preserved_in_links_clash_and_native_subscriptions() {
    for mode in ["native", "xorpub", "random"] {
        for rtt in ["0rtt", "1rtt"] {
            let encryption = format!("mlkem768x25519plus.{mode}.{rtt}.{PUBLIC_KEY}");
            for vision in [false, true] {
                let flow = if vision { "xtls-rprx-vision" } else { "" };
                let link = format!(
                    "vless://{UUID}@offline.invalid:443?encryption={encryption}&flow={flow}#fixture"
                );
                let clash = json!({"proxies":[{"name":"fixture","type":"vless","server":"offline.invalid","port":443,"uuid":UUID,"encryption":encryption,"flow":flow}]});
                let native = json!({"outbounds":[{"tag":"fixture","type":"vless","server":"offline.invalid","server_port":443,"uuid":UUID,"encryption":encryption,"flow":flow}]});
                for source in [link, clash.to_string(), native.to_string()] {
                    let protocol = imported_protocol(&source);
                    assert_eq!(protocol["encryption"], encryption);
                    assert_eq!(protocol["vision"], vision);
                    assert_eq!(protocol["packet_encoding"], "xudp");
                }
            }
        }
    }
}

#[test]
fn anytls_metadata_survives_import_and_cannot_inject_settings() {
    let clash = json!({"proxies":[{"name":"fixture","type":"anytls","server":"offline.invalid","port":443,"password":"test","client-metadata":"AeroBox/test=2"}]});
    let native = json!({"outbounds":[{"tag":"fixture","type":"anytls","server":"offline.invalid","server_port":443,"password":"test","client_metadata":"AeroBox/test=2","tls":{"enabled":true}}]});
    for source in [
        clash.to_string(),
        native.to_string(),
        "anytls://test@offline.invalid:443?client_metadata=AeroBox%2Ftest%3D2#fixture".into(),
    ] {
        assert_eq!(
            imported_protocol(&source)["protocol"]["client_metadata"],
            "AeroBox/test=2"
        );
    }
    for metadata in [
        "test\nv=1".to_owned(),
        "test\rv=1".to_owned(),
        "x".repeat(65536),
    ] {
        let mut invalid = native.clone();
        invalid["outbounds"][0]["client_metadata"] = metadata.into();
        assert!(subscription::parse(&invalid.to_string()).is_err());
    }
}

#[test]
fn tls_handshake_timeout_reaches_tls_reality_and_quic() {
    for transport in ["tls", "reality", "quic"] {
        let mut node = json!({"type":"vless","tag":"fixture","server":"offline.invalid","server_port":443,"uuid":UUID,
            "tls":{"enabled":true,"server_name":"offline.invalid","handshake_timeout":"1.25s"}});
        if transport == "reality" {
            node["tls"]["reality"] = json!({"enabled":true,"public_key":PUBLIC_KEY});
        } else if transport == "quic" {
            node["type"] = "hysteria2".into();
            node.as_object_mut().unwrap().remove("uuid");
            node["password"] = "test".into();
        }
        let nodes = subscription::parse(&json!({"outbounds":[node.clone()]}).to_string()).unwrap();
        let converted = protocol::convert_outbound(nodes[0].clone(), "fixture").unwrap();
        let client = &converted["client_chains"][0]["chain"][0];
        let value = match transport {
            "reality" => &client["protocol"]["handshake_timeout_ms"],
            "quic" => &client["quic_settings"]["options"]["handshake_timeout_ms"],
            _ => &client["protocol"]["options"]["handshake_timeout_ms"],
        };
        assert_eq!(value, 1250);
        for timeout in ["-1s", "0.1ms", "4294967296ms"] {
            node["tls"]["handshake_timeout"] = timeout.into();
            assert!(subscription::parse(&json!({"outbounds":[node.clone()]}).to_string()).is_err());
        }
    }
}

#[test]
fn hysteria2_clash_ranges_and_bandwidth_reach_the_runtime() {
    let clash = json!({"proxies":[{"name":"fixture","type":"hysteria2","server":"offline.invalid",
        "port":0,"password":"test","ports":"443, 1000-1002","hop-interval":"15-30",
        "up":"750 Kbps","down":"1.5 Gbps","handshake-timeout":30}]});
    let protocol = imported_protocol(&clash.to_string());
    assert_eq!(
        protocol["hopping"],
        json!({"ports":"443,1000-1002","min_interval_secs":15,"max_interval_secs":30})
    );
    assert_eq!(protocol["up_mbps"], 0.75);
    assert_eq!(protocol["down_mbps"], 1500.0);
    let node = subscription::parse(&clash.to_string()).unwrap().remove(0);
    assert!(aerobox_for_linux::model::is_connection_node(&node));
    let client = protocol::convert_outbound(node, "fixture").unwrap();
    assert_eq!(
        client["client_chains"][0]["chain"][0]["quic_settings"]["options"]["handshake_timeout_ms"],
        30_000
    );
    let link = "hy2://test@offline.invalid:443?mport=443,1000-1002#fixture";
    assert_eq!(imported_protocol(link)["hopping"]["ports"], "443,1000-1002");
    for ports in [json!("1000:1002"), json!(["1000:1002"])] {
        let source = json!({"outbounds":[{"type":"hysteria2","tag":"range","server":"localhost",
            "server_ports":ports,"hop_interval":"","password":"test","tls":{"enabled":true}}]});
        assert_eq!(
            imported_protocol(&source.to_string())["hopping"]["ports"],
            "1000-1002"
        );
    }
    let no_hopping = json!({"outbounds":[{"type":"hysteria2","tag":"single","server":"localhost",
        "server_port":443,"server_ports":[],"hop_interval":"0s","password":"test","tls":{"enabled":true}}]});
    assert!(
        imported_protocol(&no_hopping.to_string())
            .get("hopping")
            .is_none()
    );
    for (field, invalid) in [
        ("ports", json!("443-1")),
        ("ports", json!("0")),
        ("hop-interval", json!("30-15")),
        ("hop-interval", json!("2")),
        ("up", json!("-1 Mbps")),
        ("up", json!(-1)),
        ("down", json!("NaN")),
        ("down", json!("1.0 wrong-unit")),
    ] {
        let mut invalid_node = clash.clone();
        invalid_node["proxies"][0][field] = invalid;
        assert!(
            subscription::parse(&invalid_node.to_string()).is_err(),
            "{field}"
        );
    }
    let mut single = clash;
    single["proxies"][0]
        .as_object_mut()
        .unwrap()
        .remove("ports");
    single["proxies"][0]["port"] = 443.into();
    assert!(
        subscription::parse(&single.to_string()).is_err(),
        "interval without hopping ports must not be ignored"
    );
}

#[test]
fn quic_transport_fields_validate_windows_durations_and_packet_overhead() {
    let base = json!({"type":"hysteria2","tag":"quic","server":"offline.invalid",
        "server_port":443,"password":"test","tls":{"enabled":true},
        "initial_packet_size":1280,"disable_path_mtu_discovery":true,
        "idle_timeout":"45s","keep_alive_period":"1.25s",
        "stream_receive_window":"64 KiB","connection_receive_window":"256 KiB",
        "max_concurrent_streams":8});
    for kind in ["hysteria2", "tuic"] {
        let mut node = base.clone();
        node["type"] = kind.into();
        if kind == "tuic" {
            node["uuid"] = UUID.into();
        }
        protocol::validate(&node).unwrap();
        for (field, value) in [
            ("initial_packet_size", json!(1199)),
            ("initial_packet_size", json!(1453)),
            ("idle_timeout", json!("-1s")),
            ("keep_alive_period", json!("0.1ms")),
            ("stream_receive_window", json!("65 MiB")),
            ("connection_receive_window", json!("129 MiB")),
            ("max_concurrent_streams", json!(1025)),
        ] {
            let mut invalid = node.clone();
            invalid[field] = value;
            assert!(protocol::validate(&invalid).is_err(), "{kind} {field}");
        }
        for (field, value) in [
            ("initial_packet_size", json!(0)),
            ("idle_timeout", json!("")),
            ("keep_alive_period", json!("0s")),
            ("stream_receive_window", json!("")),
            ("connection_receive_window", json!(0)),
            ("max_concurrent_streams", json!(0)),
        ] {
            node[field] = value;
        }
        protocol::validate(&node).unwrap();
    }
    let mut obfs = base;
    obfs["obfs"] = json!({"type":"salamander","password":"secret"});
    obfs["initial_packet_size"] = 1444.into();
    protocol::validate(&obfs).unwrap();
    obfs["initial_packet_size"] = 1452.into();
    assert!(protocol::validate(&obfs).is_err());
}

#[test]
fn clash_client_credentials_certificate_pins_and_mux_survive_import() {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let source = json!({"proxies":[{"name":"fixture","type":"trojan","server":"localhost","port":443,
        "password":"test","certificate":identity.cert.pem(),"private-key":identity.signing_key.serialize_pem(),
        "fingerprint":"00:".repeat(31)+"00",
        "smux":{"enabled":true,"protocol":"smux","max-connections":2,"min-streams":1,"max-streams":4,"padding":true}}]});
    let converted = imported_protocol(&source.to_string());
    assert_eq!(converted["cert"], identity.cert.pem());
    assert_eq!(converted["key"], identity.signing_key.serialize_pem());
    assert_eq!(converted["verify"], false);
    assert_eq!(
        converted["options"]["certificate_chain_sha256"],
        json!([STANDARD.encode([0; 32])])
    );
    assert_eq!(converted["protocol"]["h2mux"]["max_connections"], 2);
    let mut disabled = source;
    disabled["proxies"][0]["smux"]["enabled"] = false.into();
    assert!(
        imported_protocol(&disabled.to_string())["protocol"]
            .get("h2mux")
            .is_none()
    );
    let uot = json!({"proxies":[{"name":"fixture","type":"socks5","server":"localhost","port":1080,
        "udp-over-tcp":true,"udp-over-tcp-version":2}]});
    assert_eq!(imported_protocol(&uot.to_string())["type"], "udp_over_tcp");
}

#[test]
fn tuic_uot_is_distinct_from_native_relay_and_preserves_millisecond_heartbeat() {
    let native = json!({"outbounds":[{"tag":"fixture","type":"tuic","server":"offline.invalid",
        "server_port":443,"uuid":UUID,"password":"test","udp_over_stream":true,
        "heartbeat":"1.25s","tls":{"enabled":true}}]});
    let clash = json!({"proxies":[{"name":"fixture","type":"tuic","server":"offline.invalid",
        "port":443,"uuid":UUID,"password":"test","udp-over-stream":true,"heartbeat-interval":1250}]});
    for source in [
        native.to_string(),
        clash.to_string(),
        format!(
            "tuic://{UUID}:test@offline.invalid:443?udp_over_stream=1&heartbeat=1250ms#fixture"
        ),
    ] {
        let protocol = imported_protocol(&source);
        assert_eq!(protocol["udp_over_stream"], true);
        assert!(protocol.get("udp_relay_mode").is_none());
        assert_eq!(protocol["heartbeat_interval_ms"], 1250);
    }
    for mode in ["native", "quic"] {
        let mut node = native.clone();
        node["outbounds"][0]["udp_relay_mode"] = mode.into();
        assert!(subscription::parse(&node.to_string()).is_err());
        node["outbounds"][0]["udp_over_stream"] = false.into();
        let protocol = imported_protocol(&node.to_string());
        assert_eq!(protocol["udp_relay_mode"], mode);
        assert_eq!(protocol["udp_over_stream"], false);
    }
    for heartbeat in ["0.1ms", "-1s", "31s"] {
        let mut node = native.clone();
        node["outbounds"][0]["heartbeat"] = heartbeat.into();
        assert!(subscription::parse(&node.to_string()).is_err());
    }
    let mut default = native;
    default["outbounds"][0]["heartbeat"] = "0s".into();
    assert!(
        imported_protocol(&default.to_string())
            .get("heartbeat_interval_ms")
            .is_none()
    );
}
