mod support;

use aerobox_for_linux::{
    engine::Service,
    model::{self, RuleSet},
};
use serde_json::{Value, json};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::{App, Server, runtime_lock, socks_node};

struct Dns {
    server: Server,
    queries: Arc<Mutex<Vec<(String, u16)>>>,
    reject: Arc<AtomicBool>,
}
impl Dns {
    fn new(ipv4: [u8; 4]) -> Self {
        let queries = Arc::new(Mutex::new(Vec::new()));
        let observed = queries.clone();
        let reject = Arc::new(AtomicBool::new(false));
        let rejected = reject.clone();
        let server = Server::spawn(move |mut stream| {
            while let Ok(query) = frame(&mut stream) {
                let (name, kind, end) = question(&query);
                observed.lock().unwrap().push((name, kind));
                let refused = rejected.load(Ordering::Relaxed);
                // A recursive upstream need not have an answer cached for RD=0.
                // Model that response so generated policy lookups exercise RD.
                let code = if refused {
                    3
                } else if query[2] & 1 == 0 {
                    2
                } else {
                    0
                };
                let mut reply = query[..end].to_vec();
                reply[2..4].copy_from_slice(&[0x80 | (query[2] & 1), 0x80 | code]);
                reply[6..12].copy_from_slice(&[0, u8::from(code == 0), 0, 0, 0, 0]);
                if code == 0 {
                    reply.extend_from_slice(&[0xc0, 0x0c]);
                    reply.extend_from_slice(&kind.to_be_bytes());
                    reply.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
                    let address = if kind == 28 {
                        "2001:db8::42"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets()
                            .to_vec()
                    } else {
                        assert_eq!(kind, 1);
                        ipv4.to_vec()
                    };
                    reply.extend_from_slice(&(address.len() as u16).to_be_bytes());
                    reply.extend_from_slice(&address);
                }
                if write_frame(&mut stream, &reply).is_err() {
                    break;
                }
            }
        });
        Self {
            server,
            queries,
            reject,
        }
    }
    fn count(&self) -> usize {
        self.queries.lock().unwrap().len()
    }
    fn url(&self) -> String {
        format!("tcp://{}", self.server.address)
    }
}
fn question(query: &[u8]) -> (String, u16, usize) {
    assert!(query.len() >= 12);
    let mut end = 12;
    let mut labels = Vec::new();
    while query[end] != 0 {
        let length = query[end] as usize;
        labels.push(std::str::from_utf8(&query[end + 1..end + 1 + length]).unwrap());
        end += length + 1;
    }
    end += 1;
    (
        labels.join("."),
        u16::from_be_bytes([query[end], query[end + 1]]),
        end + 4,
    )
}
fn frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut length = [0; 2];
    stream.read_exact(&mut length)?;
    let mut bytes = vec![0; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(&(bytes.len() as u16).to_be_bytes())?;
    stream.write_all(bytes)
}
fn node(remote: &Dns) -> (Server, Arc<AtomicUsize>) {
    let address = remote.server.address;
    let forwarded_dns = Arc::new(AtomicUsize::new(0));
    let observed = forwarded_dns.clone();
    let node = Server::spawn(move |mut client| {
        let Ok((host, port)) = support::socks_handshake(&mut client) else {
            return;
        };
        if (host.as_str(), port) == ("127.0.0.1", address.port()) {
            observed.fetch_add(1, Ordering::Relaxed);
            let mut upstream = TcpStream::connect(address).unwrap();
            upstream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            upstream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            while let Ok(query) = frame(&mut client) {
                if write_frame(&mut upstream, &query).is_err() {
                    break;
                }
                let Ok(response) = frame(&mut upstream) else {
                    break;
                };
                if write_frame(&mut client, &response).is_err() {
                    break;
                }
            }
        } else if support::headers(&mut client).is_ok() {
            let _ = support::respond(&mut client, b"through-node");
        }
    });
    (node, forwarded_dns)
}
fn configure(app: &App, node: &Server, direct: &Dns, remote: &Dns) {
    app.import("DNS policy", vec![socks_node("selected", node.address)]);
    let mut settings = app.service.snapshot().settings;
    settings.routing_mode = "rule".into();
    settings.direct_dns = direct.url();
    settings.remote_dns = remote.url();
    settings.dns_hijack = true;
    settings.ipv6 = false;
    app.service.apply_settings(settings).unwrap();
}
fn rule(name: &str, action: &str, rules: Value) -> RuleSet {
    RuleSet {
        name: name.into(),
        action: action.into(),
        content: json!({"version":3,"rules":rules}),
        ..RuleSet::default()
    }
}
fn query(name: &str, kind: u16) -> Vec<u8> {
    let mut bytes = vec![0xa4, 0x52, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1]);
    bytes
}
fn ask(service: &Service, name: &str, kind: u16, udp: bool) -> Vec<u8> {
    let query = query(name, kind);
    let response = if udp {
        let mut control =
            TcpStream::connect(("127.0.0.1", service.snapshot().settings.mixed_port)).unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        control.write_all(&[5, 1, 0]).unwrap();
        let mut greeting = [0; 2];
        control.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 0]);
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut reply = [0; 10];
        control.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut packet = vec![0, 0, 0, 1, 203, 0, 113, 53, 0, 53];
        packet.extend_from_slice(&query);
        socket.send_to(&packet, ("127.0.0.1", relay_port)).unwrap();
        let mut buffer = [0; 4096];
        let (n, _) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..10], &packet[..10]);
        buffer[10..n].to_vec()
    } else {
        let mut tunnel = support::echo_tunnel(service, "203.0.113.53:53".parse().unwrap());
        write_frame(&mut tunnel, &query).unwrap();
        let response = frame(&mut tunnel).unwrap();
        let _ = tunnel.shutdown(Shutdown::Both);
        response
    };
    assert_eq!(&response[..2], &query[..2]);
    response
}
fn dns_choice(app: &App, direct: &Dns, remote: &Dns, name: &str, choice: &str) {
    for udp in [false, true] {
        let before = [direct.count(), remote.count()];
        let response = ask(&app.service, name, 1, udp);
        assert_eq!(
            response[3] & 15,
            if choice == "reject" { 3 } else { 0 },
            "{name}: {response:?}"
        );
        assert_eq!(
            u16::from_be_bytes([response[6], response[7]]),
            u16::from(choice != "reject")
        );
        let delta = [direct.count() - before[0], remote.count() - before[1]];
        assert_eq!(
            delta,
            match choice {
                "direct" => [1, 0],
                "proxy" => [0, 1],
                _ => [0, 0],
            },
            "DNS routing for {name} via UDP={udp}"
        );
    }
}

#[test]
fn policy_lookups_request_recursion_for_both_address_families() {
    let _serial = runtime_lock();
    let direct = Dns::new([127, 0, 0, 1]);
    let remote = Dns::new([203, 0, 113, 2]);
    let (node, forwarded_dns) = node(&remote);
    let app = App::new();
    configure(&app, &node, &direct, &remote);
    let mut settings = app.service.snapshot().settings;
    settings.ipv6 = true;
    app.service.apply_settings(settings).unwrap();
    // Force domain requests through IP-based routing, as the built-in China
    // IP rules do. The proxy must receive traffic after remote DNS succeeds.
    app.service
        .save_ruleset(rule(
            "IP route",
            "proxy",
            json!([{"ip_cidr":["203.0.113.0/24", "2001:db8::/32"]}]),
        ))
        .unwrap();
    app.service.start().unwrap();
    for entry in ["http", "socks5h"] {
        let name = format!("{entry}.recursive.example.test");
        assert_eq!(
            support::request_via(&app.service, &format!("http://{name}/"), entry)
                .unwrap_or_else(|error| panic!("{error:#}\n{}", app.service.logs())),
            "through-node"
        );
        let queries = remote.queries.lock().unwrap();
        for kind in [1, 28] {
            assert!(queries.contains(&(name.clone(), kind)), "{queries:?}");
        }
    }
    assert!(forwarded_dns.load(Ordering::Relaxed) > 0);
    assert_eq!(direct.count(), 0, "remote lookup leaked to direct DNS");
}

#[test]
fn custom_rules_control_dns_and_traffic_before_builtin_lists() {
    let _serial = runtime_lock();
    let direct = Dns::new([127, 0, 0, 1]);
    let remote = Dns::new([203, 0, 113, 2]);
    let (node, forwarded_dns) = node(&remote);
    let (origin, _) = support::http(b"direct-origin".to_vec());
    let app = App::new();
    configure(&app, &node, &direct, &remote);
    // Insert built-in IDs first, as in a fresh profile. Custom choices must
    // still override these broad defaults in both DNS and connection routing.
    let mut builtin = rule(
        "domestic",
        "direct",
        json!([{"domain_suffix":["example.test"]}]),
    );
    builtin.id = model::BUILTIN_DOMESTIC_ID.into();
    app.service.save_ruleset(builtin).unwrap();
    let mut builtin_ip = rule("domestic IP", "direct", json!([{"ip_cidr":["0.0.0.0/0"]}]));
    builtin_ip.id = model::BUILTIN_CHINA_IP_ID.into();
    app.service.save_ruleset(builtin_ip).unwrap();
    app.service
        .save_ruleset(rule(
            "custom proxy",
            "proxy",
            json!([{"domain":["proxy.example.test"]}]),
        ))
        .unwrap();
    let blocked = rule(
        "blocked",
        "reject",
        json!([{"domain":["blocked.example.test"]}]),
    );
    let blocked_id = blocked.id.clone();
    app.service.save_ruleset(blocked).unwrap();
    app.service.start().unwrap();
    for (name, choice) in [
        ("local.example.test", "direct"),
        ("proxy.example.test", "proxy"),
        ("blocked.example.test", "reject"),
        ("BlOcKeD.ExAmPlE.TeSt", "reject"),
        ("other.test", "proxy"),
    ] {
        dns_choice(&app, &direct, &remote, name, choice);
    }
    for (name, expected) in [
        ("local.example.test", "direct-origin"),
        ("proxy.example.test", "through-node"),
    ] {
        assert_eq!(
            support::request(
                &app.service,
                &format!("http://{name}:{}/", origin.address.port())
            )
            .unwrap(),
            expected
        );
    }
    assert!(
        support::request(
            &app.service,
            &format!("http://blocked.example.test:{}/", origin.address.port())
        )
        .is_err()
    );
    assert!(forwarded_dns.load(Ordering::Relaxed) > 0);
    app.service
        .apply_ruleset_enabled(&blocked_id, false)
        .unwrap();
    dns_choice(&app, &direct, &remote, "blocked.example.test", "direct");
    app.service
        .apply_ruleset_enabled(&blocked_id, true)
        .unwrap();
    for (mode, choice) in [
        ("global", "proxy"),
        ("direct", "direct"),
        ("rule", "reject"),
    ] {
        app.service.set_routing_mode(mode).unwrap();
        dns_choice(&app, &direct, &remote, "blocked.example.test", choice);
    }
}

#[test]
fn mixed_json_and_srs_rules_never_guess_destination_ip_or_port_for_dns() {
    let _serial = runtime_lock();
    let direct = Dns::new([127, 0, 0, 1]);
    let remote = Dns::new([203, 0, 113, 2]);
    let (node, _) = node(&remote);
    let app = App::new();
    configure(&app, &node, &direct, &remote);
    for binary in [false, true] {
        let mut mixed = rule("mixed", "direct", json!([]));
        mixed.binary = binary;
        if binary {
            let path = app.dir.path().join("mixed.srs");
            std::fs::write(&path, include_bytes!("fixtures/dns-routing.srs")).unwrap();
            mixed.source = path.display().to_string();
        } else {
            mixed.content =
                serde_json::from_slice(include_bytes!("fixtures/dns-routing.json")).unwrap();
        }
        app.service
            .update(|state| {
                state.rulesets = vec![mixed];
                Ok(())
            })
            .unwrap();
        app.service.start().unwrap();
        for (name, choice) in [
            ("direct.example.test", "direct"),
            ("a.either.example.test", "direct"),
            ("a.port.example.test", "proxy"),
            ("a.both.example.test", "proxy"),
            ("a.negative.example.test", "proxy"),
            ("not-port.example.test", "proxy"),
            ("special-keyword.example.test", "direct"),
            ("regex27.example.test", "direct"),
            ("a.except.example.test", "direct"),
            ("blocked.except.example.test", "proxy"),
            ("unmatched.test", "proxy"),
        ] {
            dns_choice(&app, &direct, &remote, name, choice);
        }
        app.service.stop().unwrap();
    }
}

#[test]
fn ipv6_toggle_controls_aaaa_responses_without_querying_upstream_when_disabled() {
    let _serial = runtime_lock();
    let direct = Dns::new([127, 0, 0, 1]);
    let remote = Dns::new([203, 0, 113, 2]);
    let (node, _) = node(&remote);
    let app = App::new();
    configure(&app, &node, &direct, &remote);
    app.service.start().unwrap();
    for mode in ["rule", "global", "direct"] {
        app.service.set_routing_mode(mode).unwrap();
        for ipv6 in [false, true, false] {
            let mut settings = app.service.snapshot().settings;
            settings.ipv6 = ipv6;
            app.service.apply_settings(settings).unwrap();
            for udp in [false, true] {
                let before = [direct.count(), remote.count()];
                let reply = ask(&app.service, "ipv6.example.test", 28, udp);
                assert_eq!(reply[3] & 15, 0);
                assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), u16::from(ipv6));
                let delta = [direct.count() - before[0], remote.count() - before[1]];
                assert_eq!(
                    delta,
                    if !ipv6 {
                        [0, 0]
                    } else if mode == "direct" {
                        [1, 0]
                    } else {
                        [0, 1]
                    }
                );
                if ipv6 {
                    assert!(
                        reply.ends_with(
                            &"2001:db8::42"
                                .parse::<std::net::Ipv6Addr>()
                                .unwrap()
                                .octets()
                        )
                    );
                }
            }
        }
    }
}

#[test]
fn remote_rule_updates_change_dns_policy_and_keep_cached_behavior_after_restart() {
    let _serial = runtime_lock();
    let direct = Dns::new([127, 0, 0, 1]);
    let remote = Dns::new([203, 0, 113, 2]);
    let node = support::socks_forward();
    let body = Arc::new(Mutex::new(
        br#"{"version":3,"rules":[{"domain":["old.example.test"]}]}"#.to_vec(),
    ));
    let served = body.clone();
    let source = Server::spawn(move |mut stream| {
        if support::headers(&mut stream).is_ok() {
            let _ = support::respond(&mut stream, &served.lock().unwrap());
        }
    });
    let app = App::new();
    configure(&app, &node, &direct, &remote);
    let remote_rule = RuleSet {
        name: "online DNS rule".into(),
        source: format!("http://{}/rules.json", source.address),
        ..RuleSet::default()
    };
    let id = remote_rule.id.clone();
    app.service.save_ruleset(remote_rule).unwrap();
    app.service.start().unwrap();
    dns_choice(&app, &direct, &remote, "old.example.test", "direct");
    *body.lock().unwrap() = br#"{"version":3,"rules":[{"domain":["new.example.test"]}]}"#.to_vec();
    app.service.update_ruleset(&id).unwrap();
    dns_choice(&app, &direct, &remote, "old.example.test", "proxy");
    dns_choice(&app, &direct, &remote, "new.example.test", "direct");
    app.service.stop().unwrap();
    drop(source);
    app.service.start().unwrap();
    dns_choice(&app, &direct, &remote, "old.example.test", "proxy");
    dns_choice(&app, &direct, &remote, "new.example.test", "direct");
    // A selected resolver's failure must not silently change the routing policy.
    direct.reject.store(true, Ordering::Relaxed);
    let before = remote.count();
    let reply = ask(&app.service, "new.example.test", 1, false);
    assert_eq!(reply[3] & 15, 3);
    assert_eq!(remote.count(), before);
}
