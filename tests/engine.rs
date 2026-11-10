use aerobox_for_linux::{
    engine::Service,
    model::{self, Profile, RuleSet, Settings, Store, Subscription},
};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
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
    assert_eq!(result["log"]["level"], "info");
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
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    let api_worker = thread::spawn(move || {
        let (mut stream, _) = api.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        let size = stream.read(&mut request).unwrap();
        assert!(String::from_utf8_lossy(&request[..size]).starts_with("PATCH /configs "));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let bin = dir.path().join("core-test");
    fs::write(&bin,"#!/bin/sh\nif [ \"$1\" = check ]; then exit 0; fi\necho ready\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n").unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    s.update(|state| {
        state.settings.core_path = bin.to_string_lossy().to_string();
        state.profiles[0].config["experimental"]["clash_api"]["external_controller"] =
            json!(api_address.to_string());
        Ok(())
    })
    .unwrap();
    s.start()
        .unwrap_or_else(|error| panic!("{error:#}\n{}", s.logs()));
    api_worker.join().unwrap();
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
    s.start()
        .unwrap_or_else(|error| panic!("{error:#}\n{}", s.logs()));
    assert!(s.memory_usage().core_bytes.is_some_and(|bytes| bytes > 0));
    let until = Instant::now() + Duration::from_secs(5);
    while s.api("GET", "/version", None).is_err() {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(20))
    }
    let proxies = s.api("GET", "/proxies", None).unwrap();
    assert!(proxies["proxies"].get("proxy").is_some());
    let pid = s.status().pid;
    for mode in ["direct", "global", "rule"] {
        s.set_routing_mode(mode).unwrap();
        assert_eq!(s.snapshot().settings.routing_mode, mode);
        assert_eq!(s.api("GET", "/configs", None).unwrap()["mode"], mode);
        assert_eq!(s.status().pid, pid, "mode change must not restart the core");
    }
    assert!(s.set_routing_mode("unsupported").is_err());
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
    // The core cache contains "direct", but the next startup must obey the
    // app's mode selection made while it is stopped.
    s.set_routing_mode("direct").unwrap();
    s.stop().unwrap();
    s.set_routing_mode("global").unwrap();
    s.start()
        .unwrap_or_else(|error| panic!("{error:#}\n{}", s.logs()));
    assert_eq!(s.api("GET", "/configs", None).unwrap()["mode"], "global");
    s.set_routing_mode("rule").unwrap();
    assert_eq!(s.api("GET", "/configs", None).unwrap()["mode"], "rule");
    s.set_routing_mode("global").unwrap();

    // If persistence fails after the API accepted the new mode, restore the
    // previous live mode and preserve the last successfully saved settings.
    let state_path = s.dir().join("state.json");
    let backup_path = s.dir().join("state.saved");
    fs::rename(&state_path, &backup_path).unwrap();
    fs::create_dir(&state_path).unwrap();
    let save_result = s.set_routing_mode("direct");
    fs::remove_dir(&state_path).unwrap();
    fs::rename(&backup_path, &state_path).unwrap();
    assert!(save_result.is_err());
    assert_eq!(s.snapshot().settings.routing_mode, "global");
    assert_eq!(s.api("GET", "/configs", None).unwrap()["mode"], "global");

    let pid = s.status().pid;
    let mut settings = s.snapshot().settings;
    settings.theme = "dark".into();
    s.apply_settings(settings.clone()).unwrap();
    assert_eq!(
        s.status().pid,
        pid,
        "appearance changes must not restart the core"
    );
    settings.core_path = "/no/such/sing-box".into();
    assert!(s.apply_settings(settings).is_err());
    assert_eq!(
        s.status().pid,
        pid,
        "failed preflight must leave the current core running"
    );
    assert_eq!(s.snapshot().settings.theme, "dark");

    // A valid executable which fails only at startup exercises rollback after
    // the old core has been stopped, not just validation errors.
    let failing_core = s.dir().join("fails-on-start");
    fs::write(
        &failing_core,
        "#!/bin/sh\nif [ \"$1\" = check ]; then exit 0; fi\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&failing_core, fs::Permissions::from_mode(0o700)).unwrap();
    let mut settings = s.snapshot().settings;
    let old_binary = settings.core_path.clone();
    settings.core_path = failing_core.to_string_lossy().into_owned();
    assert!(s.apply_settings(settings).is_err());
    assert!(s.status().running);
    assert_eq!(s.snapshot().settings.core_path, old_binary);
    assert_eq!(s.api("GET", "/configs", None).unwrap()["mode"], "global");
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
fn offline_settings_save_without_an_installed_core() {
    let (_dir, s) = service();
    let settings = Settings {
        core_path: "/not/installed/sing-box".into(),
        theme: "dark".into(),
        tun_enabled: true,
        ..s.snapshot().settings
    };
    s.apply_settings(settings).unwrap();
    assert_eq!(s.snapshot().settings.theme, "dark");
    assert!(s.snapshot().settings.tun_enabled);
    assert!(!s.status().running);
    let mut invalid = s.snapshot().settings;
    invalid.test_url = "file:///tmp/not-a-network-test".into();
    assert!(s.apply_settings(invalid).is_err());
}

#[test]
fn real_core_downloads_follow_runtime_mode_and_stopped_downloads_are_direct() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let (_dir, service) = service();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    drop(api);
    let mixed = TcpListener::bind("127.0.0.1:0").unwrap();
    let mixed_address = mixed.local_addr().unwrap();
    drop(mixed);
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable_port = unavailable.local_addr().unwrap().port();
    drop(unavailable);
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_address = origin.local_addr().unwrap();
    origin.set_nonblocking(true).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicUsize::new(0));
    let worker_done = done.clone();
    let worker_hits = hits.clone();
    let worker = thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(20);
        while !worker_done.load(Ordering::Relaxed) && Instant::now() < until {
            match origin.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = [0; 4096];
                    assert!(stream.read(&mut request).unwrap() > 0);
                    let body = r#"{"outbounds":[{"type":"socks","tag":"downloaded-node","server":"127.0.0.1","server_port":1080}]}"#;
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                    worker_hits.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("origin server: {error}"),
            }
        }
    });
    let subscription = Subscription {
        source: format!("http://{origin_address}/subscription"),
        ..Subscription::default()
    };
    let subscription_id = subscription.id.clone();
    service.update(|state| {
        state.settings.core_path = binary;
        state.settings.bypass_lan = false;
        state.settings.sniff = false;
        state.settings.dns_hijack = false;
        let config = &mut state.profiles[0].config;
        config["inbounds"] = json!([{"type":"mixed","listen":"127.0.0.1","listen_port":mixed_address.port()}]);
        config["experimental"]["clash_api"]["external_controller"] = json!(api_address.to_string());
        config["route"]["final"] = json!("direct");
        config["outbounds"] = json!([
            {"type":"selector","tag":"proxy","outbounds":["unavailable"]},
            {"type":"socks","tag":"unavailable","server":"127.0.0.1","server_port":unavailable_port},
            {"type":"direct","tag":"direct"}
        ]);
        state.subscriptions.push(subscription);
        Ok(())
    }).unwrap();
    service
        .start()
        .unwrap_or_else(|error| panic!("{error:#}\n{}", service.logs()));
    service.set_routing_mode("direct").unwrap();
    service.update_subscription(&subscription_id).unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert!(
        service.traffic().unwrap().download > 0,
        "download must traverse the running core"
    );

    service.set_routing_mode("global").unwrap();
    assert!(
        service.update_subscription(&subscription_id).is_err(),
        "a failed outbound must not fall back to a direct download"
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1);

    service.set_routing_mode("rule").unwrap();
    // Editing a profile without applying it must not change the app's live
    // download listener; requests still use the running configuration.
    service
        .update(|state| {
            state.profiles[0].config["inbounds"][0]["listen_port"] = json!(1);
            Ok(())
        })
        .unwrap();
    service.update_subscription(&subscription_id).unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 2);
    service.stop().unwrap();
    service.update_subscription(&subscription_id).unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 3);
    done.store(true, Ordering::Relaxed);
    worker.join().unwrap();
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
