use aerobox_for_linux::{protocol, subscription};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

const UUID: &str = "01010101-0101-4101-8101-010101010101";

fn trojan() -> Value {
    json!({"type":"trojan","tag":"optional","server":"secret.test","server_port":443,
        "password":"test","tls":{"enabled":true}})
}

fn config() -> (String, String) {
    let (key, _) = aerobox_crypto::hpke::ALL_SUPPORTED_SUITES[0]
        .generate_key_pair()
        .unwrap();
    let mut contents = vec![42, 0, 32];
    contents.extend_from_slice(&(key.0.len() as u16).to_be_bytes());
    contents.extend_from_slice(&key.0);
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0, 11]);
    contents.extend_from_slice(b"public.test");
    contents.extend_from_slice(&[0, 0]);
    let mut list = ((contents.len() + 4) as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&[0xfe, 0x0d]);
    list.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    list.extend(contents);
    let encoded = STANDARD.encode(list);
    (
        format!("-----BEGIN ECH CONFIGS-----\n{encoded}\n-----END ECH CONFIGS-----\n"),
        encoded,
    )
}
fn convert(node: Value) -> Value {
    protocol::validate(&node).unwrap();
    protocol::convert_outbound(node, "test").unwrap()["client_chains"][0]["chain"][0].clone()
}

#[test]
fn optional_socket_and_tls_fields_survive_clash_and_json_import() {
    let (pem, encoded) = config();
    let input = json!({"type":"trojan","tag":"optional","server":"secret.test","server_port":443,"password":"test",
        "tcp_fast_open":true,"tcp_multi_path":true,"udp_fragment":true,
        "tls":{"enabled":true,"server_name":"secret.test","ech":{"enabled":true,"config":pem},
        "fragment":true,"record_fragment":true,"fragment_fallback_delay":"1ms","kernel_tx":true,"kernel_rx":true}});
    let clash = json!({"proxies":[{"name":"optional","type":"trojan","server":"secret.test","port":443,"password":"test",
        "tfo":true,"mptcp":true,"udp-fragment":true,"servername":"secret.test",
        "ech-opts":{"enable":true,"config":encoded},"tls-fragment":true,"tls-record-fragment":true,"tls-fragment-fallback-delay":"1ms","kernel-tx":true,"kernel-rx":true}]});
    let mut uri = url::Url::parse("trojan://test@secret.test:443#optional").unwrap();
    uri.query_pairs_mut().extend_pairs([
        ("tcp_fast_open", "true"),
        ("tcp_multi_path", "true"),
        ("udp_fragment", "true"),
        ("sni", "secret.test"),
        ("ech", encoded.as_str()),
        ("fragment", "true"),
        ("record_fragment", "true"),
        ("fragment_fallback_delay", "1ms"),
        ("kernel_tx", "true"),
        ("kernel_rx", "true"),
    ]);
    let mut clients = Vec::new();
    for body in [
        json!([input]).to_string(),
        clash.to_string(),
        uri.to_string(),
    ] {
        let nodes = subscription::parse(&body).unwrap();
        assert_eq!(nodes.len(), 1);
        let client = convert(nodes[0].clone());
        assert_eq!(
            client["dial_options"],
            json!({"tcp_fast_open":true,"tcp_multi_path":true,"udp_fragment":true})
        );
        assert_eq!(client["protocol"]["options"]["ech"]["config"], pem);
        assert_eq!(client["protocol"]["options"]["kernel_tx"], true);
        assert_eq!(client["protocol"]["options"]["kernel_rx"], true);
        assert_eq!(
            client["protocol"]["options"]["fragmentation"]["record_fragment"],
            true
        );
        clients.push(client);
    }
    assert_eq!(clients[0], clients[1]);
    assert_eq!(clients[0], clients[2]);
}

#[test]
fn tuic_reduce_rtt_survives_import_and_invalid_combinations_fail() {
    let source = json!({"proxies":[{"name":"early","type":"tuic","server":"secret.test","port":443,
        "uuid":"01010101-0101-4101-8101-010101010101","password":"test","reduce-rtt":true}]});
    let nodes = subscription::parse(&source.to_string()).unwrap();
    let client = convert(nodes[0].clone());
    assert_eq!(client["protocol"]["zero_rtt_handshake"], true);
    for (field, value) in [
        ("kernel_tx", json!(true)),
        ("kernel_rx", json!(true)),
        ("fragment", json!(true)),
        ("record_fragment", json!(true)),
        ("fragment_fallback_delay", json!("0s")),
    ] {
        let mut invalid = nodes[0].clone();
        invalid["tls"][field] = value;
        assert!(protocol::validate(&invalid).is_err());
    }
    for field in ["tcp_fast_open", "tcp_multi_path"] {
        let mut invalid = nodes[0].clone();
        invalid[field] = true.into();
        assert!(protocol::validate(&invalid).is_err());
        invalid[field] = false.into();
        protocol::validate(&invalid).unwrap();
    }
    for field in ["zero_rtt_handshake", "zero-rtt-handshake", "0rtt"] {
        for enabled in [true, false] {
            let uri = format!("tuic://{UUID}:test@secret.test:443?{field}={enabled}#early");
            let nodes = subscription::parse(&uri).unwrap();
            assert_eq!(
                convert(nodes[0].clone())["protocol"]["zero_rtt_handshake"],
                enabled
            );
        }
    }
    let uri =
        "socks5://127.0.0.1:1080?tcp_fast_open=true&tcp_multi_path=true&udp_fragment=false#test";
    let nodes = subscription::parse(uri).unwrap();
    assert_eq!(
        convert(nodes[0].clone())["dial_options"],
        json!({"tcp_fast_open":true,"tcp_multi_path":true,"udp_fragment":false})
    );
}

#[test]
fn ech_disabled_settings_are_consumed_without_enabling_or_loading_them() {
    let (pem, encoded) = config();
    let mut disabled = trojan();
    disabled["tls"]["ech"] = json!({"enabled":false,"config":pem,
        "config_path":"/does-not-exist/ech.pem","query_server_name":"config.test"});
    let clash = json!({"proxies":[{"type":"trojan","name":"optional","server":"secret.test",
        "port":443,"password":"test","ech-opts":{"enable":false,"config":encoded,
        "config-path":"/does-not-exist/ech.pem","query-server-name":"config.test"}}]});
    for source in [json!([disabled.clone()]).to_string(), clash.to_string()] {
        let node = subscription::parse(&source).unwrap().remove(0);
        assert!(convert(node)["protocol"]["options"].get("ech").is_none());
    }
    disabled["tls"]["ech"]["typo"] = true.into();
    assert!(protocol::validate(&disabled).is_err());
}

#[test]
fn ech_inline_file_and_dns_settings_reach_tcp_and_quic() {
    let (pem, _) = config();
    for quic in [false, true] {
        for options in [
            json!({"enabled":true,"config":pem.lines().collect::<Vec<_>>(),
                "config_path":"/does-not-exist/ignored.pem"}),
            json!({"enabled":true,"config_path":"/does-not-exist/ech.pem"}),
            json!({"enabled":true,"query_server_name":"config.test"}),
        ] {
            let mut node = trojan();
            if quic {
                node["type"] = "hysteria2".into();
            }
            node["tls"]["ech"] = options.clone();
            let client = convert(node);
            let tls = if quic {
                &client["quic_settings"]
            } else {
                &client["protocol"]
            };
            let ech = &tls["options"]["ech"];
            if options.get("config").is_some() {
                assert_eq!(ech["config"], pem.trim_end());
                assert!(
                    ech.get("config_path").is_none(),
                    "inline ECH takes precedence over its path"
                );
            } else {
                let mut expected = options;
                expected.as_object_mut().unwrap().remove("enabled");
                assert_eq!(ech, &expected);
            }
        }
    }
    let mut uri = url::Url::parse("trojan://test@secret.test:443#optional").unwrap();
    uri.query_pairs_mut().extend_pairs([
        ("ech", "1"),
        ("ech_config_path", "/does-not-exist/ech.pem"),
        ("ech_query_server_name", "config.test"),
    ]);
    let node = subscription::parse(uri.as_str()).unwrap().remove(0);
    assert_eq!(
        convert(node)["protocol"]["options"]["ech"],
        json!({
            "config_path":"/does-not-exist/ech.pem","query_server_name":"config.test"
        })
    );
}

#[test]
fn vmess_tls_and_socket_options_survive_the_share_link() {
    let (pem, encoded) = config();
    let source = json!({"v":"2","ps":"optional","add":"secret.test","port":443,
        "id":UUID,"net":"tcp","tls":"tls","ech":encoded,
        "fragment":true,"record_fragment":true,"fragment_fallback_delay":"1ms",
        "kernel_tx":true,"kernel_rx":false,"tcp_fast_open":true,"tcp_multi_path":true,"udp_fragment":false});
    let uri = format!("vmess://{}", STANDARD.encode(source.to_string()));
    let client = convert(subscription::parse(&uri).unwrap().remove(0));
    assert_eq!(client["protocol"]["options"]["ech"]["config"], pem);
    assert_eq!(
        client["protocol"]["options"]["fragmentation"],
        json!({
            "fragment":true,"record_fragment":true,"fragment_fallback_delay":"1ms"
        })
    );
    assert_eq!(client["protocol"]["options"]["kernel_tx"], true);
    assert_eq!(
        client["dial_options"],
        json!({"tcp_fast_open":true,"tcp_multi_path":true,"udp_fragment":false})
    );
}

#[test]
fn optional_fields_reject_bad_types_conflicting_aliases_and_incompatible_tls() {
    for (field, value) in [
        ("config", json!(123)),
        ("config", json!([123])),
        ("config", json!("invalid PEM")),
        ("config_path", json!(false)),
        ("query_server_name", json!(123)),
        ("query_server_name", json!("127.0.0.1")),
        ("query_server_name", json!("invalid name.test")),
    ] {
        let mut node = trojan();
        node["tls"]["ech"] = json!({"enabled":true});
        node["tls"]["ech"][field] = value;
        assert!(protocol::validate(&node).is_err(), "{field}");
    }
    for (field, value) in [
        ("disable_sni", json!(true)),
        ("max_version", json!("1.2")),
        (
            "reality",
            json!({"enabled":true,"public_key":"CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        ),
    ] {
        let mut node = trojan();
        node["tls"]["ech"] = json!({"enabled":true});
        node["tls"][field] = value;
        assert!(protocol::validate(&node).is_err(), "{field}");
    }
    for query in [
        "fragment=true&tls-fragment=false",
        "record_fragment=true&record-fragment=false",
        "ech=true&ech_enabled=false",
        "ech_config_path=a.pem&ech-config-path=b.pem",
        "kernel_tx=invalid",
    ] {
        assert!(subscription::parse(&format!("trojan://test@secret.test:443?{query}")).is_err());
    }
    let duplicate = format!("tuic://{UUID}:test@secret.test:443?zero_rtt_handshake=1&0rtt=0");
    assert!(subscription::parse(&duplicate).is_err());
    for aliases in [
        json!({"tfo":true,"tcp_fast_open":false}),
        json!({"mptcp":true,"tcp_multi_path":false}),
        json!({"udp-fragment":true,"udp_fragment":false}),
        json!({"tls-fragment":true,"fragment":false}),
    ] {
        let mut node = json!({"type":"trojan","name":"optional","server":"secret.test","port":443,"password":"test"});
        node.as_object_mut()
            .unwrap()
            .extend(aliases.as_object().unwrap().clone());
        assert!(subscription::parse(&json!({"proxies":[node]}).to_string()).is_err());
    }
}
