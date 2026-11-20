mod support;

use aerobox_for_linux::model::{RuleSet, Subscription};
use serde_json::json;
use std::{
    io::Write,
    net::UdpSocket,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use support::{App, Server, runtime_lock, socks_node};

struct Dns {
    port: u16,
    queries: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Dns {
    fn new(answer: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let queries = Arc::new(AtomicUsize::new(0));
        let count = queries.clone();
        let worker = thread::spawn(move || {
            let mut data = [0; 4096];
            while !done.load(Ordering::Relaxed) {
                if let Ok((n, peer)) = socket.recv_from(&mut data) {
                    assert!(n >= 12);
                    count.fetch_add(1, Ordering::Relaxed);
                    let mut end = 12;
                    while data[end] != 0 {
                        end += data[end] as usize + 1;
                    }
                    end += 1;
                    let query_type = u16::from_be_bytes([data[end], data[end + 1]]);
                    let has_answer = answer && query_type == 1;
                    let mut response = data[..end + 4].to_vec();
                    response[2] = 0x81;
                    response[3] = if answer { 0x80 } else { 0x83 };
                    response[6] = 0;
                    response[7] = u8::from(has_answer);
                    response[8..12].fill(0);
                    if has_answer {
                        response.extend_from_slice(&[
                            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1,
                        ]);
                    }
                    let _ = socket.send_to(&response, peer);
                }
            }
        });
        Self {
            port,
            queries,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Dns {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn node_hostnames_use_the_configured_direct_resolver() {
    let _serial = runtime_lock();
    let app = App::new();
    let direct_dns = Dns::new(true);
    let remote_dns = Dns::new(false);
    let (node, hits) = support::socks_http(b"resolved node".to_vec());
    let hostname = format!("proxy-{}.example.test", uuid::Uuid::new_v4());
    let mut settings = app.service.snapshot().settings;
    settings.direct_dns = format!("udp://127.0.0.1:{}", direct_dns.port);
    settings.remote_dns = format!("udp://127.0.0.1:{}", remote_dns.port);
    settings.test_url = "http://1.1.1.1:12345/probe".into();
    app.service.apply_settings(settings).unwrap();
    let id = app.import("domain node", vec![json!({"type":"socks","tag":"resolved","server":hostname,"server_port":node.address.port()})]);
    app.service.start().unwrap();
    assert_eq!(
        support::request(&app.service, "http://127.0.0.1:12345/probe").unwrap(),
        "resolved node"
    );
    let delay = app.service.test_subscription_node(&id, "resolved").unwrap();
    assert!(delay > 0);
    assert_eq!(
        app.service.subscription_nodes(&id).unwrap()[0].delay_ms,
        Some(delay)
    );
    assert_eq!(
        hits.load(Ordering::Relaxed),
        2,
        "measurement must traverse the selected hostname node"
    );
    assert!(direct_dns.queries.load(Ordering::Relaxed) > 0);
    assert_eq!(remote_dns.queries.load(Ordering::Relaxed), 0);

    // When the probe URL happens to equal the node endpoint, the named DNS
    // context must still enforce the probe's ban on loopback destinations.
    let mut settings = app.service.snapshot().settings;
    settings.test_url = format!("http://{hostname}:{}/probe", node.address.port());
    app.service.apply_settings(settings).unwrap();
    assert!(app.service.test_subscription_node(&id, "resolved").is_err());
    assert_eq!(
        hits.load(Ordering::Relaxed),
        2,
        "named DNS bypassed probe destination policy"
    );
}

#[test]
fn http_nodes_receive_authentication_and_connect_the_requested_destination() {
    let _serial = runtime_lock();
    let app = App::new();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let node = Server::spawn(move |mut stream| {
        let Ok(connect) = support::headers(&mut stream) else {
            return;
        };
        observed.lock().unwrap().push(connect);
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        if let Ok(request) = support::headers(&mut stream) {
            observed.lock().unwrap().push(request);
            let _ = support::respond(&mut stream, b"authenticated HTTP node");
        }
    });
    app.import("HTTP", vec![json!({"type":"http","tag":"HTTP","server":"127.0.0.1","server_port":node.address.port(),"username":"fixture","password":"secret"})]);
    app.service.start().unwrap();
    let url = "http://127.0.0.1:12345/probe";
    assert_eq!(
        support::request(&app.service, url).unwrap(),
        "authenticated HTTP node"
    );
    let requests = requests.lock().unwrap();
    assert!(requests[0].starts_with("CONNECT 127.0.0.1:12345 HTTP/1.1"));
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("proxy-authorization: basic zml4dhvyztpzzwnyzxq=")
    );
    assert!(requests[1].starts_with("GET /probe HTTP/1.1"));
}

#[test]
fn subscription_and_rule_downloads_follow_the_running_proxy_then_use_direct_when_stopped() {
    let _serial = runtime_lock();
    let app = App::new();
    let origin_body = r#"{"outbounds":[{"type":"socks","tag":"downloaded directly","server":"127.0.0.1","server_port":9}]}"#;
    let (origin, origin_hits) = support::http(origin_body.as_bytes().to_vec());
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let node = Server::spawn(move |mut stream| {
        if support::socks_handshake(&mut stream).is_err() {
            return;
        }
        let Ok(request) = support::headers(&mut stream) else {
            return;
        };
        counted.fetch_add(1, Ordering::Relaxed);
        let body = if request.contains("/rules") {
            r#"{"version":3,"rules":[{"domain":["proxied.example.test"]}]}"#
        } else {
            r#"{"outbounds":[{"type":"socks","tag":"downloaded through proxy","server":"127.0.0.1","server_port":9}]}"#
        };
        let _ = support::respond(&mut stream, body.as_bytes());
    });
    let original = app.import("connected", vec![socks_node("connected", node.address)]);
    app.service.start().unwrap();
    let rule = RuleSet {
        name: "downloaded rule".into(),
        source: format!("http://{}/rules", origin.address),
        enabled: false,
        ..RuleSet::default()
    };
    let rule_id = rule.id.clone();
    app.service.save_ruleset(rule).unwrap();
    app.service.update_ruleset(&rule_id).unwrap();
    assert_eq!(
        app.service.snapshot().rulesets[0].content["rules"][0]["domain"][0],
        "proxied.example.test"
    );
    app.service
        .import_subscription(Subscription {
            source: format!("http://{}/proxied", origin.address),
            ..Subscription::default()
        })
        .unwrap();
    assert_eq!(
        app.service.snapshot().subscriptions[1].nodes[0]["tag"],
        "downloaded through proxy"
    );
    assert_eq!(requests.load(Ordering::Relaxed), 2);
    assert_eq!(origin_hits.load(Ordering::Relaxed), 0);
    app.service.select_subscription(&original).unwrap();
    app.service.stop().unwrap();
    app.service
        .import_subscription(Subscription {
            source: format!("http://{}/direct", origin.address),
            ..Subscription::default()
        })
        .unwrap();
    assert_eq!(
        app.service.snapshot().subscriptions[2].nodes[0]["tag"],
        "downloaded directly"
    );
    assert_eq!(origin_hits.load(Ordering::Relaxed), 1);
    assert_eq!(requests.load(Ordering::Relaxed), 2);
}

#[test]
fn failed_proxy_downloads_do_not_fall_back_to_direct() {
    let _serial = runtime_lock();
    let app = App::new();
    let (origin, hits) = support::http(br#"{"outbounds":[]}"#.to_vec());
    let node = Server::spawn(|mut stream| {
        let _ = support::socks_handshake(&mut stream);
    });
    app.import("broken proxy", vec![socks_node("broken", node.address)]);
    app.service.start().unwrap();
    assert!(
        app.service
            .import_subscription(Subscription {
                source: format!("http://{}/must-use-proxy", origin.address),
                ..Subscription::default()
            })
            .is_err()
    );
    assert_eq!(hits.load(Ordering::Relaxed), 0);
    assert_eq!(app.service.snapshot().subscriptions.len(), 1);
}

#[test]
fn exit_ip_detection_uses_the_selected_proxy_and_respects_disabled_ipv6() {
    let _serial = runtime_lock();
    let app = App::new();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let observed = targets.clone();
    let node = Server::spawn(move |mut stream| {
        if let Ok(target) = support::socks_handshake(&mut stream) {
            observed.lock().unwrap().push(target);
        }
    });
    app.import("ip probe", vec![socks_node("probe", node.address)]);
    app.service.start().unwrap();
    // The fixture rejects TLS, so this checks routing without reaching public
    // IP services or trusting a test certificate in the application.
    assert!(app.service.network_info().is_err());
    let targets = targets.lock().unwrap();
    assert!(
        targets
            .iter()
            .any(|(host, port)| host == "api4.ipify.org" && *port == 443)
    );
    assert!(
        targets
            .iter()
            .any(|(host, port)| host == "ipv4.icanhazip.com" && *port == 443)
    );
    assert!(
        targets
            .iter()
            .all(|(host, _)| !host.contains("api6") && !host.contains("ipv6"))
    );
}
