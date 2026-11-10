use aerobox_for_linux::{
    engine::Service,
    model::{self, Profile, RuleSet, Store, Subscription},
};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn service() -> (tempfile::TempDir, Arc<Service>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(Some(dir.path().to_owned())).unwrap();
    (dir, Service::new(store))
}
#[test]
fn native_generation_resolves_resources_without_mutating_source() {
    let (_dir, s) = service();
    let sub = Subscription {
        nodes: vec![json!({"type":"socks","tag":"node","server":"localhost","server_port":1080})],
        ..Subscription::default()
    };
    let rule = RuleSet::default();
    let mut p = Profile::new("test");
    p.subscriptions.push(sub.id.clone());
    p.rulesets.push(rule.id.clone());
    p.script = "async function onGenerate(config){config.log.level='debug';return config}".into();
    let id = p.id.clone();
    s.update(|state| {
        state.subscriptions.push(sub);
        state.rulesets.push(rule);
        state.profiles.push(p);
        Ok(())
    })
    .unwrap();
    let result = s.generate(&id).unwrap();
    assert_eq!(result["outbounds"][0]["outbounds"], json!(["node"]));
    assert_eq!(result["log"]["level"], "debug");
    assert!(
        result["route"]["rule_set"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with(".json")
    );
    assert_eq!(
        s.snapshot().profiles.last().unwrap().config["log"]["level"],
        "info"
    );
}
#[test]
fn duplicate_node_names_fail_before_start() {
    let (_d, s) = service();
    s.update(|state| {
        let sub = Subscription {
            nodes: vec![json!({"type":"direct","tag":"direct"})],
            ..Subscription::default()
        };
        state.profiles[0].subscriptions.push(sub.id.clone());
        state.subscriptions.push(sub);
        Ok(())
    })
    .unwrap();
    assert!(s.generate(&s.snapshot().settings.active_profile).is_err());
}
#[test]
fn subscription_updates_are_atomic_and_run_transform() {
    let (_d, s) = service();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0; 4096];
        let _ = stream.read(&mut buf);
        let body = r#"{"outbounds":[{"type":"socks","tag":"keep","server":"localhost","server_port":1080},{"type":"socks","tag":"drop","server":"localhost","server_port":1080}]}"#;
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSubscription-Userinfo: upload=10;download=20;total=100\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap()
    });
    let sub = Subscription {
        source: format!("http://{address}"),
        include: "keep".into(),
        prefix: "new-".into(),
        script: "async function onSubscribe(nodes){nodes[0].tag+='-script';return nodes}".into(),
        ..Subscription::default()
    };
    let id = sub.id.clone();
    s.update(|state| {
        state.subscriptions.push(sub);
        Ok(())
    })
    .unwrap();
    s.update_subscription(&id).unwrap();
    worker.join().unwrap();
    let sub = s.snapshot().subscriptions[0].clone();
    assert_eq!(sub.nodes.len(), 1);
    assert_eq!(sub.nodes[0]["tag"], "new-keep-script");
    assert_eq!(sub.total, 100);
}
#[test]
fn process_stops_and_is_reaped() {
    let (dir, s) = service();
    let bin = dir.path().join("core-test");
    fs::write(&bin,"#!/bin/sh\nif [ \"$1\" = check ]; then exit 0; fi\necho ready\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n").unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    s.update(|state| {
        state.settings.core_path = bin.to_string_lossy().to_string();
        Ok(())
    })
    .unwrap();
    s.start().unwrap();
    let pid = s.status().pid.unwrap();
    assert!(s.start().is_err());
    s.stop().unwrap();
    assert!(!s.status().running);
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}
#[test]
fn real_core_roundtrip() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let (_d, s) = service();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let proxy_socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_address = proxy_socket.local_addr().unwrap();
    drop(proxy_socket);
    s.update(|state| {
        state.settings.core_path = binary;
        state.profiles[0].config["inbounds"] = json!([{
            "type":"mixed", "listen":"127.0.0.1", "listen_port":proxy_address.port()
        }]);
        state.profiles[0].config["experimental"]["clash_api"]["external_controller"] =
            json!(address.to_string());
        Ok(())
    })
    .unwrap();
    s.check_profile(&s.snapshot().settings.active_profile)
        .unwrap();
    s.start().unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while s.api("GET", "/version", None).is_err() {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(20))
    }
    let proxies = s.api("GET", "/proxies", None).unwrap();
    assert!(proxies["proxies"].get("proxy").is_some());
    s.api("PUT", "/proxies/proxy", Some(&json!({"name":"direct"})))
        .unwrap();
    let traffic = s.traffic().unwrap();
    assert_eq!(
        (traffic.download, traffic.upload, traffic.connections),
        (0, 0, 0)
    );

    // A completed proxied request must still count towards session totals.
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_address = server.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        let body = "x".repeat(16 * 1024);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_address}")).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!("http://{server_address}/traffic-check"))
            .send()
            .unwrap()
            .bytes()
            .unwrap()
            .len(),
        16 * 1024
    );
    worker.join().unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let traffic = s.traffic().unwrap();
        if traffic.download >= 16 * 1024 && traffic.upload > 0 && traffic.connections == 0 {
            break;
        }
        assert!(
            Instant::now() < until,
            "completed request missing from traffic totals: {traffic:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    s.reload().unwrap();
    assert!(s.status().running);
    s.stop().unwrap();

    assert!(s.traffic().is_err());

    let ruleset = RuleSet {
        binary: true,
        ..RuleSet::default()
    };
    let ruleset_id = ruleset.id.clone();
    s.update(|state| {
        state.rulesets.push(ruleset);
        Ok(())
    })
    .unwrap();
    assert!(s.rule_source(&ruleset_id).unwrap().contains("rules"));
    s.save_rule_source(
        &ruleset_id,
        r#"{"version":3,"rules":[{"domain_suffix":["example.com"]}]}"#,
    )
    .unwrap();
    let restored: serde_json::Value =
        serde_json::from_str(&s.rule_source(&ruleset_id).unwrap()).unwrap();
    let suffix = &restored["rules"][0]["domain_suffix"];
    // sing-box normalizes single-element lists to their equivalent scalar form.
    assert!(suffix == "example.com" || suffix == &json!(["example.com"]));
}
#[test]
fn polling_does_not_race_startup_failure() {
    let (dir, s) = service();
    let bin = dir.path().join("core-test");
    fs::write(
        &bin,
        "#!/bin/sh\nif [ \"$1\" = check ]; then exit 0; fi\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    s.update(|state| {
        state.settings.core_path = bin.to_string_lossy().into_owned();
        Ok(())
    })
    .unwrap();
    let worker_service = s.clone();
    let worker = thread::spawn(move || {
        let until = Instant::now() + Duration::from_millis(350);
        while Instant::now() < until {
            worker_service.poll();
            thread::sleep(Duration::from_millis(2));
        }
    });
    assert!(s.start().is_err());
    worker.join().unwrap();
    assert!(!s.status().running);
    s.shutdown().unwrap();
    assert!(s.start().is_err());
}
#[test]
fn resource_deletion_removes_references() {
    let mut state = model::State::default();
    let sub = Subscription::default();
    let id = sub.id.clone();
    state.profiles[0].subscriptions.push(id.clone());
    state.subscriptions.push(sub);
    model::remove_resource(&mut state, "subscriptions", &id).unwrap();
    assert!(state.profiles[0].subscriptions.is_empty());
    state.validate().unwrap()
}
