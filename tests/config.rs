use aerobox_for_linux::{
    engine::Service,
    model::{Settings, Store},
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn setup(service: &Service) {
    service
        .update(|state| {
            state.settings.system_proxy = false;
            let sub = aerobox_for_linux::model::Subscription {
                nodes: vec![
                    json!({"type":"socks","tag":"fixture","server":"127.0.0.1","server_port":9}),
                ],
                ..Default::default()
            };
            state.settings.active_subscription = sub.id.clone();
            state.subscriptions.push(sub);
            Ok(())
        })
        .unwrap();
}

#[test]
fn real_core_remote_rules_start_from_seed_update_in_background_and_reuse_cache() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(Store::open(Some(dir.path().into())).unwrap());
    setup(&service);
    let rules = TcpListener::bind("127.0.0.1:0").unwrap();
    let source = format!("http://{}/rules.json", rules.local_addr().unwrap());
    rules.set_nonblocking(true).unwrap();
    let allow_response = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicUsize::new(0));
    let response_gate = allow_response.clone();
    let worker_done = done.clone();
    let worker_hits = hits.clone();
    let worker = thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(12);
        while !worker_done.load(Ordering::Relaxed) && Instant::now() < until {
            match rules.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let _ = stream.read(&mut [0; 4096]);
                    worker_hits.fetch_add(1, Ordering::Relaxed);
                    while !response_gate.load(Ordering::Relaxed)
                        && !worker_done.load(Ordering::Relaxed)
                        && Instant::now() < until
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    let body = r#"{"version":3,"rules":[{"ip_cidr":"127.0.0.1/32"}]}"#;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    let remote_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_port = remote_listener.local_addr().unwrap().port();
    drop(remote_listener);
    let remote_config = dir.path().join("remote.json");
    std::fs::write(&remote_config,serde_json::to_vec(&json!({"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":remote_port}],"outbounds":[{"type":"direct","tag":"direct"}]})).unwrap()).unwrap();
    let _remote = CoreGuard(
        Command::new(&binary)
            .args(["run", "-c"])
            .arg(&remote_config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    thread::sleep(Duration::from_millis(150));
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    let mixed = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_address = mixed.local_addr().unwrap();
    drop((api, mixed));
    service
        .update(|state| {
            state.settings.core_path = binary;
            state
                .rulesets
                .iter_mut()
                .find(|r| r.id == aerobox_for_linux::model::BUILTIN_ADS_ID)
                .unwrap()
                .enabled = true;
            state.settings.bypass_lan = false;
            state.settings.sniff = false;
            for rule in &mut state.rulesets {
                rule.source.clear();
                rule.binary = false;
                rule.binary = false;
            }
            let ads = state
                .rulesets
                .iter_mut()
                .find(|r| r.id == aerobox_for_linux::model::BUILTIN_ADS_ID)
                .unwrap();
            ads.id = aerobox_for_linux::model::id();
            ads.source = source;
            ads.content = json!({"version":3,"rules":[]});
            ads.update_interval_hours = 6;
            state.settings.mixed_port = proxy_address.port();
            state.settings.api_port = api_address.port();
            state.subscriptions[0].nodes[0]["server_port"] = json!(remote_port);
            Ok(())
        })
        .unwrap();
    let generated = service.generate_current().unwrap();
    let remote = generated["route"]["rule_set"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["type"] == "remote")
        .unwrap();
    assert_eq!(remote["update_interval"], "6h");
    assert!(std::path::Path::new(remote["initial_path"].as_str().unwrap()).is_file());
    service.check(&generated).unwrap();
    let started = Instant::now();
    service.start().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "startup waited for rule download"
    );
    let until = Instant::now() + Duration::from_secs(3);
    while hits.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(10));
    }
    // The initial empty seed permits TCP to a bound listener. A deliberately
    // incomplete HTTP server times out, whereas the updated ad rule rejects
    // before connecting and returns a proxy HTTP error immediately.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    origin.set_nonblocking(true).unwrap();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_address}")).unwrap())
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let url = format!(
        "http://127.0.0.1:{}/policy",
        origin.local_addr().unwrap().port()
    );
    let _ = client.get(&url).send();
    assert!(
        origin.accept().is_ok(),
        "empty seed unexpectedly rejected loopback request"
    );
    allow_response.store(true, Ordering::Relaxed);
    let until = Instant::now() + Duration::from_secs(4);
    loop {
        if client
            .get(&url)
            .send()
            .is_ok_and(|r| r.status().is_server_error())
        {
            break;
        }
        while origin.accept().is_ok() {}
        assert!(
            Instant::now() < until,
            "background rule update did not change routing: {}",
            service.logs()
        );
        thread::sleep(Duration::from_millis(30));
    }
    service.set_routing_mode("direct").unwrap();
    assert_eq!(
        service
            .api("GET", "/proxies/aerobox-rule-download", None)
            .unwrap()["now"],
        "direct"
    );
    service.set_routing_mode("rule").unwrap();
    assert_eq!(
        service
            .api("GET", "/proxies/aerobox-rule-download", None)
            .unwrap()["now"],
        "proxy"
    );
    service.stop().unwrap();
    done.store(true, Ordering::Relaxed);
    worker.join().unwrap();
    let requests = hits.load(Ordering::Relaxed);
    // Source is now offline. Re-generating the seed must not replace the
    // downloaded cache, and startup must not wait for that offline source.
    service.set_routing_mode("direct").unwrap();
    let started = Instant::now();
    service.start().unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(service.runtime_mode().unwrap(), "direct");
    assert_eq!(
        service
            .api("GET", "/proxies/aerobox-rule-download", None)
            .unwrap()["now"],
        "direct"
    );
    service.set_routing_mode("rule").unwrap();
    assert!(client.get(&url).send().unwrap().status().is_server_error());
    assert_eq!(hits.load(Ordering::Relaxed), requests);
    assert_eq!(
        service
            .snapshot()
            .rulesets
            .iter()
            .find(|r| r.name == "广告拦截")
            .unwrap()
            .updated,
        0
    );
    service.stop().unwrap();
}

#[test]
fn android_builtins_have_binary_seeds_and_only_enabled_policies_are_generated() {
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(Store::open(Some(dir.path().into())).unwrap());
    setup(&service);
    let first = service.generate_current().unwrap();
    assert_eq!(first["route"]["rule_set"].as_array().unwrap().len(), 2);
    let ads = aerobox_for_linux::model::BUILTIN_ADS_ID;
    service.apply_ruleset_enabled(ads, true).unwrap();
    let generated = service.generate_current().unwrap();
    assert_eq!(generated["route"]["rule_set"].as_array().unwrap().len(), 3);
    for rule in generated["route"]["rule_set"].as_array().unwrap() {
        assert_eq!(rule["format"], "binary");
        assert_eq!(rule["type"], "remote");
        assert_eq!(rule["update_interval"], "24h");
        let path = std::path::Path::new(rule["initial_path"].as_str().unwrap());
        assert!(std::fs::read(path).unwrap().starts_with(b"SRS"));
    }
    let dns = &generated["dns"]["rules"];
    assert!(
        !dns.as_array()
            .unwrap()
            .iter()
            .any(|r| r["rule_set"] == "中国大陆 IP")
    );
    assert!(
        dns.as_array()
            .unwrap()
            .iter()
            .any(|r| r["rule_set"] == "广告拦截" && r["action"] == "reject")
    );
    let mut custom = aerobox_for_linux::model::RuleSet {
        name: "自定义".into(),
        action: "proxy".into(),
        content: json!({"version":3,"rules":[{"domain_suffix":"example.net"}]}),
        ..Default::default()
    };
    service.save_ruleset(custom.clone()).unwrap();
    let generated = service.generate_current().unwrap();
    assert!(
        generated["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["rule_set"] == "自定义" && r["outbound"] == "proxy")
    );
    custom.action = "unsupported".into();
    assert!(service.save_ruleset(custom).is_err());
}

#[test]
fn real_core_accepts_builtin_modes_and_network_controls() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(Store::open(Some(dir.path().into())).unwrap());
    setup(&service);
    let mut state = service.snapshot();
    let original = state.subscriptions[0].nodes.clone();
    for mode in ["rule", "global", "direct"] {
        for ipv6 in [false, true] {
            for stack in [None, Some("system"), Some("gvisor"), Some("mixed")] {
                state.settings = Settings {
                    routing_mode: mode.into(),
                    ipv6,
                    tun_enabled: stack.is_some(),
                    tun_stack: stack.unwrap_or("system").into(),
                    allow_lan: true,
                    dns_cache: false,
                    sniff: false,
                    dns_hijack: false,
                    active_subscription: state.settings.active_subscription.clone(),
                    ..Settings::default()
                };
                {
                    let profile = state.current_profile().unwrap();
                    let config = service.generate_profile(&state, &profile).unwrap();
                    let path = dir.path().join("check.json");
                    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
                    let output = std::process::Command::new(&binary)
                        .args(["check", "-c"])
                        .arg(&path)
                        .output()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "{} / {mode} / ipv6={ipv6} / {stack:?}: {}",
                        profile.name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
    }
    assert_eq!(state.subscriptions[0].nodes, original);
}

struct CoreGuard(Child);
impl Drop for CoreGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn real_core_dns_modes_override_ads_and_flush_cached_answers() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(Store::open(Some(dir.path().into())).unwrap());
    setup(&service);
    let mut state = service.snapshot();
    state
        .rulesets
        .iter_mut()
        .find(|r| r.id == aerobox_for_linux::model::BUILTIN_ADS_ID)
        .unwrap()
        .enabled = true;
    state.settings.ipv6 = false;
    for rule in &mut state.rulesets {
        rule.source.clear();
        rule.binary = false;
    }
    state
        .rulesets
        .iter_mut()
        .find(|r| r.id == aerobox_for_linux::model::BUILTIN_ADS_ID)
        .unwrap()
        .content = json!({"version":3,"rules":[{"domain_suffix":"ads.example"}]});
    let mut config = service
        .generate_profile(&state, &state.current_profile().unwrap())
        .unwrap();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    let inbound = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dns_address = inbound.local_addr().unwrap();
    config["inbounds"] = json!([{"type":"direct","tag":"dns-test","listen":"127.0.0.1","listen_port":dns_address.port(),"network":"udp","override_address":"127.0.0.1","override_port":53}]);
    config["experimental"]["clash_api"]["external_controller"] = json!(api_address.to_string());
    config["experimental"]["cache_file"]["enabled"] = json!(false);
    let mode_server = |mode: &str| -> String {
        config["dns"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["clash_mode"] == mode)
            .unwrap()["server"]
            .as_str()
            .unwrap()
            .into()
    };
    let direct_dns = mode_server("direct");
    let global_dns = mode_server("global");
    // Keep the generated routing rules. Replace public resolvers with distinct
    // local hosts answers so this checks live DNS policy without internet I/O.
    for server in config["dns"]["servers"].as_array_mut().unwrap() {
        let tag = server["tag"].as_str().unwrap().to_owned();
        let address = if tag == direct_dns {
            "192.0.2.10"
        } else if tag == global_dns {
            "192.0.2.20"
        } else {
            "192.0.2.30"
        };
        *server =
            json!({"type":"hosts","tag":tag,"predefined":{"ads.example":[address,"2001:db8::1"]}});
    }
    let path = dir.path().join("dns-check.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let log_path = dir.path().join("core.log");
    let log = std::fs::File::create(&log_path).unwrap();
    drop((api, inbound));
    let mut core = CoreGuard(
        Command::new(binary)
            .args(["run", "-c"])
            .arg(&path)
            .arg("-D")
            .arg(dir.path())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let endpoint = format!("http://{api_address}/configs");
    let secret = config["experimental"]["clash_api"]["secret"]
        .as_str()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if client
            .get(&endpoint)
            .bearer_auth(secret)
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            break;
        }
        assert!(
            Instant::now() < until && core.0.try_wait().unwrap().is_none(),
            "{}",
            std::fs::read_to_string(&log_path).unwrap()
        );
        thread::sleep(Duration::from_millis(20));
    }
    let query = |kind: u16| -> Vec<u8> {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut packet = vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'a', b'd', b's', 7, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0,
        ];
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&[0, 1]);
        socket.send_to(&packet, dns_address).unwrap();
        let mut response = vec![0; 2048];
        let size = socket.recv(&mut response).unwrap();
        response.truncate(size);
        assert!(response.len() >= 12);
        response
    };
    for (mode, expected) in [
        ("direct", Some(10)),
        ("global", Some(20)),
        ("rule", None),
        ("direct", Some(10)),
    ] {
        client
            .patch(&endpoint)
            .bearer_auth(secret)
            .json(&json!({"mode":mode}))
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();
        let response = query(1);
        if let Some(last) = expected {
            assert_eq!(response[3] & 15, 0, "{mode}: {response:?}");
            assert!(
                response.ends_with(&[192, 0, 2, last]),
                "{mode}: {response:?}"
            );
        } else {
            assert_ne!(response[3] & 15, 0, "rule mode must reject the ad domain");
            assert_eq!(&response[6..8], &[0, 0]);
        }
        let ipv6 = query(28);
        assert_eq!(ipv6[3] & 15, 0, "disabled IPv6 returns NOERROR in {mode}");
        assert_eq!(
            &ipv6[6..8],
            &[0, 0],
            "disabled IPv6 must not leak AAAA answers in {mode}"
        );
    }
}

#[test]
fn a_new_remote_binary_rule_does_not_require_a_manual_download() {
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(Store::open(Some(dir.path().into())).unwrap());
    setup(&service);
    service
        .save_ruleset(aerobox_for_linux::model::RuleSet {
            name: "自建在线规则".into(),
            binary: true,
            source: "http://127.0.0.1:9/rules.srs".into(),
            ..Default::default()
        })
        .unwrap();
    let config = service.generate_current().unwrap();
    let remote = config["route"]["rule_set"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tag"] == "自建在线规则")
        .unwrap();
    assert_eq!(remote["type"], "remote");
    assert!(remote.get("initial_path").is_none());
}

#[test]
fn real_core_accepts_converted_shadowsocks_sip003_plugins() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(Store::open(Some(dir.path().into())).unwrap());
    service
        .update(|s| {
            s.settings.system_proxy = false;
            s.settings.core_path = binary;
            Ok(())
        })
        .unwrap();
    for (plugin, options) in [
        ("obfs", json!({"mode":"http","host":"example.com"})),
        (
            "v2ray-plugin",
            json!({"mode":"websocket","host":"example.com","tls":true}),
        ),
    ] {
        let source = json!({"proxies":[{"name":"fixture","type":"ss","server":"127.0.0.1","port":443,"cipher":"aes-128-gcm","password":"fixture-secret","plugin":plugin,"plugin-opts":options}]});
        let nodes = aerobox_for_linux::subscription::parse(&source.to_string()).unwrap();
        service
            .import_subscription(aerobox_for_linux::model::Subscription {
                nodes,
                ..Default::default()
            })
            .unwrap();
        service.check_current().unwrap();
    }
}
