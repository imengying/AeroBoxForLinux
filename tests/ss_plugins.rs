use aerobox_for_linux::{protocol, subscription};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

fn client(source: &str) -> Value {
    let nodes = subscription::parse(source).unwrap();
    assert_eq!(nodes.len(), 1);
    protocol::convert_outbound(nodes[0].clone(), "fixture").unwrap()["client_chains"][0]["chain"][0]
        .clone()
}

#[test]
fn sip003_transports_survive_links_clash_and_native_import() {
    for (name, opts, clash_opts, mode) in [
        (
            "obfs-local",
            "obfs=http;obfs-host=cdn.example",
            json!({"mode":"http","host":"cdn.example"}),
            "http",
        ),
        (
            "obfs-local",
            "obfs=tls;obfs-host=cdn.example",
            json!({"mode":"tls","host":"cdn.example"}),
            "tls",
        ),
        (
            "v2ray-plugin",
            "mode=websocket;host=cdn.example;path=/a\\;b;tls;mux=0",
            json!({"mode":"websocket","host":"cdn.example","path":"/a;b","tls":true,"mux":false}),
            "websocket",
        ),
        (
            "v2ray-plugin",
            "mode=quic;host=cdn.example;tls;mux=8",
            json!({"mode":"quic","host":"cdn.example","tls":true,"mux":8}),
            "quic",
        ),
    ] {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("plugin", &format!("{name};{opts}"))
            .finish();
        let modern = format!(
            "ss://{}@offline.invalid:443/?{query}#fixture",
            STANDARD.encode("aes-128-gcm:test")
        );
        let encoded = format!(
            "ss://{}?{query}#fixture",
            STANDARD.encode("aes-128-gcm:test@offline.invalid:443")
        );
        let clash = json!({"proxies":[{"name":"fixture","type":"ss","server":"offline.invalid","port":443,"cipher":"aes-128-gcm","password":"test","plugin":if name == "obfs-local" { "obfs" } else { name },"plugin-opts":clash_opts}]});
        let native = json!({"outbounds":[{"tag":"fixture","type":"shadowsocks","server":"offline.invalid","server_port":443,"method":"aes-128-gcm","password":"test","plugin":name,"plugin_opts":opts}]});
        let expected = client(&native.to_string());
        for source in [modern, encoded, clash.to_string(), native.to_string()] {
            let actual = client(&source);
            assert_eq!(actual["protocol"]["plugin"], expected["protocol"]["plugin"]);
            assert_eq!(actual["protocol"]["plugin"]["mode"], mode);
            assert_eq!(
                actual.get("transport").and_then(Value::as_str),
                if mode == "quic" { Some("quic") } else { None }
            );
        }
    }
}

#[test]
fn plugin_certificate_paths_are_validated_at_startup_not_subscription_import() {
    let node = json!({"type":"shadowsocks","tag":"fixture","server":"offline.invalid","server_port":443,"method":"aes-128-gcm","password":"test","plugin":"v2ray-plugin","plugin_opts":"tls;host=cdn.example;cert=/run/aerobox-test-missing-ca.pem"});
    protocol::validate(&node).unwrap();
    let mut invalid = node;
    invalid["plugin_opts"] = "tls;certRaw=invalid-certificate".into();
    assert!(protocol::validate(&invalid).is_err());
}

#[test]
fn plugin_errors_do_not_drop_other_protocols_or_expose_passwords() {
    let source = json!({"proxies":[
        {"name":"ss","type":"ss","server":"offline.invalid","port":443,"cipher":"aes-128-gcm","password":"fixture-private-password","plugin":"v2ray-plugin","plugin-opts":{"mode":"websocket","host":"cdn.example","path":"/ws","tls":false,"mux":true}},
        {"name":"invalid","type":"ss","server":"offline.invalid","port":443,"cipher":"aes-128-gcm","password":"fixture-private-password","plugin":"obfs","plugin-opts":{"mode":"unsupported"}},
        {"name":"vless","type":"vless","server":"offline.invalid","port":443,"uuid":"00000000-0000-4000-8000-000000000001"}
    ]});
    let (nodes, errors) = subscription::parse_with_skips(&source.to_string()).unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[1]["type"], "vless");
    assert_eq!(errors.len(), 1);
    assert!(!errors[0].contains("fixture-private-password"));
}
