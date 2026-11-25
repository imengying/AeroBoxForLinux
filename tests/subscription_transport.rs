mod support;
use aerobox_for_linux::{protocol, subscription};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{sync::mpsc, time::Duration};

const UUID: &str = "00000000-0000-4000-8000-000000000001";

fn vmess_link(network: &str, port: u16, empty: bool) -> String {
    let mut node =
        json!({"v":"2","ps":"vmess","add":"127.0.0.1","port":port,"id":UUID,"net":network});
    if network == "h2" {
        node["tls"] = "tls".into();
    }
    if empty {
        node["path"] = "".into();
        node["host"] = "".into();
    }
    format!("vmess://{}", STANDARD.encode(node.to_string()))
}

#[test]
fn omitted_and_empty_transport_defaults_are_importable() {
    for empty in [false, true] {
        for network in ["ws", "http", "h2", "httpupgrade"] {
            let mut source = format!("vless://{UUID}@127.0.0.1:443?type={network}");
            if network == "h2" {
                source.push_str("&security=tls");
            }
            if empty {
                source.push_str("&path=&host=");
            }
            subscription::parse(&source).unwrap_or_else(|e| panic!("{network}/{empty}: {e:#}"));
            if network != "httpupgrade" {
                subscription::parse(&vmess_link(network, 443, empty)).unwrap();
            }
        }
    }
}

#[test]
fn imported_websocket_links_send_default_path_and_server_host() {
    let _serial = support::runtime_lock();
    for empty in [false, true] {
        for kind in ["vless", "vmess"] {
            let (sender, receiver) = mpsc::channel();
            let peer = support::Server::spawn(move |mut stream| {
                let header = support::headers(&mut stream).unwrap();
                sender.send(header).unwrap();
                // A rejected handshake is enough: assert the actual bytes the
                // imported node sends, without another WebSocket implementation.
                support::respond(&mut stream, b"handshake fixture").unwrap();
            });
            let source = if kind == "vmess" {
                vmess_link("ws", peer.address.port(), empty)
            } else {
                format!(
                    "vless://{UUID}@{}?type=ws{}",
                    peer.address,
                    if empty { "&path=&host=" } else { "" }
                )
            };
            let app = support::App::new();
            app.import("link", subscription::parse(&source).unwrap());
            app.service.start().unwrap();
            let port = app.service.local_proxy_port();
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).unwrap())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();
            assert!(client.get("http://192.0.2.1/default-path").send().is_err());
            let header = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(header.starts_with("GET / HTTP/1.1\r\n"), "{header}");
            let expected_host = format!("Host: {}", peer.address);
            assert!(header.lines().any(|line| line == expected_host), "{header}");
            app.service.stop().unwrap();
        }
    }
}

fn clash(network: &str) -> Value {
    json!({"type":"vmess","name":"fixture","server":"127.0.0.1","port":443,"uuid":UUID,"network":network})
}

fn check_clash(node: Value) -> anyhow::Result<Vec<Value>> {
    subscription::parse(&json!({"proxies":[node]}).to_string())
}

#[test]
fn malformed_clash_fields_cannot_silently_revert_to_defaults() {
    for (network, field, options) in [
        ("ws", "ws-opts", json!({"path":12})),
        ("http", "http-opts", json!({"path":[12]})),
        ("http", "http-opts", json!({"path":["/one","/two"]})),
        ("http", "http-opts", json!({"method":false})),
        ("http", "http-opts", json!({"headers":["ignored"]})),
        ("httpupgrade", "http-opts", json!({"path":false})),
        ("httpupgrade", "http-opts", json!({"headers":{"Host":12}})),
        (
            "h2",
            "h2-opts",
            json!({"host":"first.example","headers":{"Host":["other.example"]}}),
        ),
        (
            "http",
            "http-opts",
            json!({"headers":{"Host":"first.example","host":"other.example"}}),
        ),
    ] {
        let mut node = clash(network);
        node[field] = options;
        assert!(check_clash(node.clone()).is_err(), "accepted {node}");
    }
    let mut node = clash("tcp");
    node["cipher"] = 12.into();
    assert!(check_clash(node).is_err());

    for options in [
        json!({"udp-over-tcp":true,"udp-over-tcp-version":"broken"}),
        json!({"udp-over-tcp":true,"udp_over_tcp":false}),
        json!({"udp-over-tcp":{"enabled":true,"version":1},"udp-over-tcp-version":2}),
        json!({"udp-over-tcp-version":3}),
    ] {
        let mut node = json!({"type":"ss","name":"ss","server":"127.0.0.1","port":443,"cipher":"aes-128-gcm","password":"test"});
        node.as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        assert!(check_clash(node.clone()).is_err(), "accepted {node}");
    }

    // Empty/default options exported by GUI clients remain usable.
    for (network, field, options) in [
        ("ws", "ws-opts", json!({"path":"","headers":{"Host":""}})),
        (
            "http",
            "http-opts",
            json!({"path":[""],"method":"","host":"","headers":{}}),
        ),
        (
            "httpupgrade",
            "http-opts",
            json!({"path":["/"],"headers":{"Host":["edge.example"]}}),
        ),
    ] {
        let mut node = clash(network);
        node["cipher"] = "".into();
        node[field] = options;
        check_clash(node).unwrap();
    }
    for version in [1, 2] {
        let mut node = json!({"type":"ss","name":"ss","server":"127.0.0.1","port":443,"cipher":"aes-128-gcm","password":"test","udp-over-tcp-version":version});
        for enabled in [false, true] {
            node["udp-over-tcp"] = enabled.into();
            let parsed = check_clash(node.clone()).unwrap().remove(0);
            assert_eq!(
                parsed["udp_over_tcp"],
                json!({"enabled":enabled,"version":version})
            );
        }
    }
}

#[test]
fn transport_specific_options_cannot_be_accepted_and_ignored() {
    let mut node = json!({"type":"vless","tag":"transport","server":"127.0.0.1","server_port":443,"uuid":UUID});
    for transport in [
        json!({"type":"grpc","path":"/ignored"}),
        json!({"type":"grpc","method":"DELETE"}),
        json!({"type":"http","service_name":"ignored"}),
        json!({"type":"httpupgrade","method":"DELETE"}),
        json!({"type":"httpupgrade","service_name":"ignored"}),
    ] {
        node["transport"] = transport;
        assert!(protocol::validate(&node).is_err(), "accepted {node}");
    }
    for transport in [
        json!({"type":"grpc","path":"/","method":"POST"}),
        json!({"type":"http","path":"","host":"","method":"","service_name":""}),
        json!({"type":"httpupgrade","method":"GET","service_name":""}),
    ] {
        node["transport"] = transport;
        protocol::validate(&node).unwrap();
    }
}

#[test]
fn ordinary_websocket_handshakes_validate_paths_and_headers() {
    let mut node = json!({"type":"vless","tag":"ws-validation","server":"127.0.0.1","server_port":443,"uuid":UUID});
    for options in [
        json!({"path":"/ws\r\nInjected: value"}),
        json!({"path":"not-an-absolute-path"}),
        json!({"path":"/has space"}),
        json!({"path":"/ws#fragment"}),
        json!({"headers":{"X-Test":"value\r\nInjected: value"}}),
        json!({"headers":{"Bad Header":"value"}}),
        json!({"headers":{"Host":"edge.example","host":"other.example"}}),
        json!({"headers":{"Host":"user@edge.example"}}),
        json!({"headers":{"Sec-WebSocket-Key":"overridden"}}),
        json!({"headers":{"Connection":"close"}}),
        json!({"headers":{"Transfer-Encoding":"chunked"}}),
    ] {
        let mut transport = json!({"type":"ws"});
        transport
            .as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        node["transport"] = transport;
        assert!(protocol::validate(&node).is_err(), "accepted {node}");
    }
    // Ordinary upgrades allow query strings, server-derived Host, and an
    // explicit subprotocol. None of these requires enabling early data.
    for transport in [
        json!({"type":"ws"}),
        json!({"type":"ws","path":"/ws?token=fixture"}),
        json!({"type":"ws","headers":{"X-Test":"value","Sec-WebSocket-Protocol":"chat"}}),
        json!({"type":"ws","headers":{"Host":"[::1]:443"}}),
    ] {
        node["transport"] = transport;
        protocol::validate(&node).unwrap();
    }
}

#[test]
fn empty_socks_credentials_use_no_authentication_and_nonempty_credentials_fit_the_wire_format() {
    let _serial = support::runtime_lock();
    let (peer, _) = support::socks_http(b"no authentication".to_vec());
    let app = support::App::new();
    let nodes = subscription::parse(
        &json!({"proxies":[{"type":"socks5","name":"no-auth","server":"127.0.0.1","port":peer.address.port(),"username":"","password":""}]}).to_string(),
    )
    .unwrap();
    app.import("empty credentials", nodes);
    app.service.start().unwrap();
    assert_eq!(
        support::request(&app.service, "http://192.0.2.1/auth").unwrap(),
        "no authentication"
    );
    app.service.stop().unwrap();

    let mut node =
        json!({"type":"socks","tag":"auth-validation","server":"127.0.0.1","server_port":443});
    for (username, password) in [
        ("user".to_owned(), "".to_owned()),
        ("".to_owned(), "pass".to_owned()),
        ("u".repeat(256), "pass".to_owned()),
        ("user".to_owned(), "p".repeat(256)),
        ("密".repeat(86), "pass".to_owned()),
    ] {
        node["username"] = username.into();
        node["password"] = password.into();
        assert!(
            protocol::validate(&node).is_err(),
            "accepted overlong or incomplete authentication"
        );
    }
    node["username"] = "u".repeat(255).into();
    node["password"] = "密".repeat(85).into();
    protocol::validate(&node).unwrap();
    for kind in ["socks", "http"] {
        node["type"] = kind.into();
        node["username"] = "".into();
        node["password"] = "".into();
        let config = protocol::convert_outbound(node.clone(), "auth").unwrap();
        let native = &config["client_chains"][0]["chain"][0]["protocol"];
        assert!(native.get("username").is_none());
        assert!(native.get("password").is_none());
    }
}
