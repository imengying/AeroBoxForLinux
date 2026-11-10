use aerobox_for_linux::{
    engine::Service,
    model::{self, Profile, RuleSet, Settings, Store, Subscription},
};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    process::{Command, Stdio},
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
    assert_eq!(result["log"]["level"], "error");
    assert!(
        result["route"]["rule_set"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with(".json")
    );
    assert_eq!(
        s.snapshot().profiles.last().unwrap().config["log"]["level"],
        "error"
    );
}
#[test]
fn duplicate_node_names_are_disambiguated_without_changing_subscriptions() {
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
    let before = s.snapshot();
    let generated = s.generate(&before.settings.active_profile).unwrap();
    let tags: Vec<_> = generated["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| node["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags.len(),
        tags.iter().collect::<std::collections::HashSet<_>>().len()
    );
    assert_eq!(s.snapshot().subscriptions[0].nodes[0]["tag"], "direct");
    assert_eq!(
        s.generate(&before.settings.active_profile).unwrap(),
        generated
    );
}

#[test]
fn duplicate_subscription_groups_rewrite_their_own_member_default_and_detour_tags() {
    let (_dir, service) = service();
    let original = vec![
        json!({"type":"selector","tag":"proxy","outbounds":["direct","node"],"default":"direct"}),
        json!({"type":"direct","tag":"direct"}),
        json!({"type":"socks","tag":"node","server":"127.0.0.1","server_port":1080,"detour":"direct"}),
        json!({"type":"urltest","tag":"auto","outbounds":["node"]}),
    ];
    let first = Subscription {
        nodes: original.clone(),
        ..Subscription::default()
    };
    let second = Subscription {
        nodes: original.clone(),
        ..Subscription::default()
    };
    service
        .update(|state| {
            state.profiles[0].subscriptions = vec![first.id.clone(), second.id.clone()];
            state.subscriptions = vec![first, second];
            Ok(())
        })
        .unwrap();
    let state = service.snapshot();
    let generated = service.generate(&state.settings.active_profile).unwrap();
    let outbounds = generated["outbounds"].as_array().unwrap();
    for (index, sub) in state.subscriptions.iter().enumerate() {
        let suffix = &sub.id[..8];
        let proxy = format!("proxy · {suffix}");
        let direct = format!("direct · {suffix}");
        let node = if index == 0 {
            "node".into()
        } else {
            format!("node · {suffix}")
        };
        let auto = if index == 0 {
            "auto".into()
        } else {
            format!("auto · {suffix}")
        };
        let group = outbounds.iter().find(|item| item["tag"] == proxy).unwrap();
        assert_eq!(group["outbounds"], json!([direct, node]));
        assert_eq!(group["default"], direct);
        assert_eq!(
            outbounds.iter().find(|item| item["tag"] == node).unwrap()["detour"],
            direct
        );
        assert_eq!(
            outbounds.iter().find(|item| item["tag"] == auto).unwrap()["outbounds"],
            json!([node])
        );
        assert_eq!(service.snapshot().subscriptions[index].nodes, original);
    }
    if let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") {
        service
            .update(|state| {
                state.settings.core_path = binary;
                Ok(())
            })
            .unwrap();
        service.check(&generated).unwrap();
    }
}

#[test]
fn failed_subscription_downloads_do_not_expose_url_credentials_in_errors_or_logs() {
    let (_dir, service) = service();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let sub = Subscription {
        source: format!("http://user:private-password@{address}/subscription?token=private-token"),
        ..Subscription::default()
    };
    let id = sub.id.clone();
    service
        .update(|state| {
            state.subscriptions.push(sub);
            Ok(())
        })
        .unwrap();
    let error = format!("{:#}", service.update_subscription(&id).unwrap_err());
    for output in [error, service.logs()] {
        assert!(!output.contains("private-token"));
        assert!(!output.contains("private-password"));
    }
}
#[test]
fn subscription_updates_preserve_all_original_node_names() {
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
    assert_eq!(sub.nodes.len(), 2);
    assert_eq!(sub.nodes[0]["tag"], "keep");
    assert_eq!(sub.nodes[1]["tag"], "drop");
    assert_eq!(sub.total, 100);
}

#[test]
fn update_all_subscriptions_skips_local_content_and_updates_remote_sources() {
    let (_dir, service) = service();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = Subscription {
        source: format!("http://{}", server.local_addr().unwrap()),
        ..Subscription::default()
    };
    let local = Subscription {
        source: "  ".into(),
        nodes: vec![json!({"type":"direct","tag":"local"})],
        ..Subscription::default()
    };
    let local_id = local.id.clone();
    let worker = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        let body = r#"{"outbounds":[{"type":"socks","tag":"downloaded","server":"127.0.0.1","server_port":1080}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    service
        .update(|state| {
            state.subscriptions = vec![local, remote];
            Ok(())
        })
        .unwrap();
    assert_eq!(service.update_all_subscriptions().unwrap(), 1);
    worker.join().unwrap();
    let state = service.snapshot();
    assert_eq!(state.subscriptions[0].nodes[0]["tag"], "local");
    assert_eq!(state.subscriptions[0].updated, 0);
    assert_eq!(state.subscriptions[1].nodes[0]["tag"], "downloaded");
    assert!(service.update_subscription(&local_id).is_err());
}

#[test]
fn subscription_import_commits_only_valid_nodes_and_uses_optional_server_defaults() {
    let (_dir, service) = service();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let source = format!("http://{}", server.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        let body = r#"{"outbounds":[{"type":"socks","tag":"one","server":"127.0.0.1","server_port":1080}]}"#;
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nProfile-Title: base64:RXhhbXBsZQ==\r\nProfile-Update-Interval: 12\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    });
    service
        .import_subscription(Subscription {
            source: source.clone(),
            ..Subscription::default()
        })
        .unwrap();
    worker.join().unwrap();
    let state = service.snapshot();
    assert_eq!(state.subscriptions.len(), 1);
    assert_eq!(state.subscriptions[0].name, "Example");
    assert_eq!(state.subscriptions[0].update_interval_hours, 12);
    assert!(
        state
            .profiles
            .iter()
            .all(|profile| profile.subscriptions.is_empty())
    );
    assert!(
        service
            .import_subscription(Subscription {
                source,
                ..Subscription::default()
            })
            .unwrap_err()
            .to_string()
            .contains("已导入")
    );
    assert!(
        service
            .import_subscription(Subscription {
                source: "/not/a/subscription".into(),
                ..Subscription::default()
            })
            .is_err()
    );
    assert!(
        service
            .import_subscription(Subscription::default())
            .is_err()
    );
    assert_eq!(service.snapshot().subscriptions.len(), 1);
}
#[test]
fn process_stops_and_is_reaped() {
    let (dir, s) = service();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    let api_worker = thread::spawn(move || {
        for method in ["PATCH", "GET"] {
            let (mut stream, _) = api.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            let size = stream.read(&mut request).unwrap();
            assert!(
                String::from_utf8_lossy(&request[..size])
                    .starts_with(&format!("{method} /configs "))
            );
            let body = if method == "GET" {
                r#"{"mode":"rule"}"#
            } else {
                ""
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
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
    let stopped_info = s.core_info().unwrap();
    assert!(!stopped_info.status.running);
    assert!(!stopped_info.version.is_empty());
    assert_eq!(stopped_info.routing_mode, "rule");
    s.restart()
        .unwrap_or_else(|error| panic!("{error:#}\n{}", s.logs()));
    let running_info = s.core_info().unwrap();
    assert_eq!(running_info.binary, stopped_info.binary);
    assert_eq!(running_info.version, stopped_info.version);
    assert!(running_info.status.running);
    assert!(s.memory_usage().total_bytes.is_some_and(|bytes| bytes > 0));
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
    s.select_outbound("proxy", "direct").unwrap();
    assert!(s.select_outbound("proxy", "missing").is_err());
    assert!(s.select_outbound("direct", "direct").is_err());
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
    s.restart().unwrap();
    assert!(s.status().running);
    assert_ne!(s.status().pid, pid);
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

    // The current API state can differ from the saved preference. A failed
    // change must restore that actual state, not the preference.
    s.api("PATCH", "/configs", Some(&json!({"mode":"rule"})))
        .unwrap();
    assert_eq!(s.runtime_mode().unwrap(), "rule");
    assert_eq!(s.snapshot().settings.routing_mode, "global");

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
    assert_eq!(s.api("GET", "/configs", None).unwrap()["mode"], "rule");
    s.set_routing_mode("global").unwrap();

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
    s.api("PATCH", "/configs", Some(&json!({"mode":"direct"})))
        .unwrap();
    assert!(s.apply_settings(settings).is_err());
    assert!(s.status().running);
    assert_eq!(s.snapshot().settings.core_path, old_binary);
    assert_eq!(s.api("GET", "/configs", None).unwrap()["mode"], "direct");
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
fn real_core_survives_the_starting_worker_thread() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let (_dir, service) = service();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    drop((api, proxy));
    service
        .update(|state| {
            state.settings.core_path = binary;
            state.settings.auto_restart = false;
            state.profiles[0].config["inbounds"][0]["listen_port"] = json!(proxy_address.port());
            state.profiles[0].config["experimental"]["clash_api"]["external_controller"] =
                json!(api_address.to_string());
            Ok(())
        })
        .unwrap();
    let worker_service = service.clone();
    thread::spawn(move || worker_service.start())
        .join()
        .unwrap()
        .unwrap();
    let until = Instant::now() + Duration::from_millis(800);
    while Instant::now() < until {
        thread::sleep(Duration::from_millis(20));
        service.poll();
    }
    let active = service.status().running && service.api("GET", "/version", None).is_ok();
    service.stop().unwrap();
    assert!(
        active,
        "core died when its starting worker exited:\n{}",
        service.logs()
    );
}

#[test]
fn core_crash_test_helper() {
    let Ok(directory) = std::env::var("AEROBOX_TEST_CRASH_DIRECTORY") else {
        return;
    };
    let service = Service::new(Store::open(Some(directory.clone().into())).unwrap());
    let worker = service.clone();
    thread::spawn(move || worker.start())
        .join()
        .unwrap()
        .unwrap();
    fs::write(
        std::path::Path::new(&directory).join("core.pid"),
        service.status().pid.unwrap().to_string(),
    )
    .unwrap();
    thread::sleep(Duration::from_secs(15));
    service.stop().unwrap();
}

#[test]
fn real_core_terminates_when_the_application_is_killed() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let (dir, service) = service();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    drop((api, proxy));
    service
        .update(|state| {
            state.settings.core_path = binary;
            state.profiles[0].config["inbounds"][0]["listen_port"] = json!(proxy_address.port());
            state.profiles[0].config["experimental"]["clash_api"]["external_controller"] =
                json!(api_address.to_string());
            Ok(())
        })
        .unwrap();
    let mut application = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "core_crash_test_helper", "--nocapture"])
        .env("AEROBOX_TEST_CRASH_DIRECTORY", dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let path = dir.path().join("core.pid");
    while !path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if !path.exists() {
        let _ = application.kill();
        let _ = application.wait();
        panic!("crash test core did not start");
    }
    let pid: u32 = fs::read_to_string(path).unwrap().parse().unwrap();
    application.kill().unwrap();
    application.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(4);
    let alive = || {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|stat| !stat.split(") ").nth(1).unwrap_or("").starts_with('Z'))
    };
    while alive() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    let survived = alive();
    if survived {
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
    assert!(!survived, "core survived SIGKILL of its application");
}

#[test]
fn pidfd_guardian_stops_a_core_without_parent_death_signals() {
    fn pidfd(pid: u32) -> OwnedFd {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        assert!(raw >= 0);
        let original = unsafe { OwnedFd::from_raw_fd(raw) };
        let duplicate = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        assert!(duplicate >= 0);
        unsafe { OwnedFd::from_raw_fd(duplicate) }
    }
    let mut parent = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let mut core = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let parent_fd = pidfd(parent.id());
    let core_fd = pidfd(core.id());
    let p = parent_fd.as_raw_fd();
    let c = core_fd.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_AeroBox"));
    command
        .arg("--watch-core")
        .env("AEROBOX_WATCH_PARENT_FD", p.to_string())
        .env("AEROBOX_WATCH_CORE_FD", c.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(p, libc::F_SETFD, 0) < 0 || libc::fcntl(c, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut guardian = command.spawn().unwrap();
    let mut output = guardian.stdout.take().unwrap();
    let mut descriptor = libc::pollfd {
        fd: output.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut descriptor, 1, 3000) } <= 0 {
        let _ = parent.kill();
        let _ = parent.wait();
        let _ = core.kill();
        let _ = core.wait();
        let _ = guardian.kill();
        let _ = guardian.wait();
        panic!("guardian failed to acknowledge readiness");
    }
    let mut ready = [0_u8; 1];
    output.read_exact(&mut ready).unwrap();
    assert_eq!(ready, b"R"[0..1]);
    parent.kill().unwrap();
    parent.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut exited = false;
    while Instant::now() < deadline {
        if core.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    if !exited {
        let _ = core.kill();
        let _ = guardian.kill();
    }
    core.wait().unwrap();
    assert!(guardian.wait().unwrap().success());
    assert!(
        exited,
        "guardian did not terminate a core after parent exit"
    );
}

#[test]
fn real_core_applies_new_subscription_nodes_and_preserves_them_on_invalid_update() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let (dir, service) = service();
    let source = dir.path().join("nodes.json");
    let sub = Subscription {
        source: source.to_string_lossy().into_owned(),
        nodes: vec![json!({"type":"direct","tag":"old-node"})],
        ..Subscription::default()
    };
    let id = sub.id.clone();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    drop((api, proxy));
    service
        .update(|state| {
            state.settings.core_path = binary;
            state.profiles[0].subscriptions.push(id.clone());
            state.subscriptions.push(sub);
            state.profiles[0].config["inbounds"][0]["listen_port"] = json!(proxy_address.port());
            state.profiles[0].config["experimental"]["clash_api"]["external_controller"] =
                json!(api_address.to_string());
            Ok(())
        })
        .unwrap();
    service.start().unwrap();
    fs::write(
        &source,
        r#"{"outbounds":[{"type":"direct","tag":"new-node"}]}"#,
    )
    .unwrap();
    let updater = service.clone();
    thread::spawn(move || updater.update_due_subscriptions())
        .join()
        .unwrap()
        .unwrap();
    assert!(
        service.api("GET", "/proxies", None).unwrap()["proxies"]
            .get("new-node")
            .is_some()
    );
    let pid = service.status().pid;
    fs::write(
        &source,
        r#"{"outbounds":[{"type":"invalid-core-protocol","tag":"broken"}]}"#,
    )
    .unwrap();
    assert!(service.update_subscription(&id).is_err());
    assert_eq!(service.status().pid, pid);
    assert_eq!(
        service.snapshot().subscriptions[0].nodes[0]["tag"],
        "new-node"
    );
    assert!(service.api("GET", "/version", None).is_ok());
    service.stop().unwrap();
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
fn stopped_system_proxy_preference_is_saved_without_changing_the_desktop() {
    let (_dir, service) = service();
    service.set_system_proxy_enabled(true).unwrap();
    assert!(service.snapshot().settings.system_proxy);
    assert!(!service.status().proxy);
    service.set_system_proxy_enabled(false).unwrap();
    assert!(!service.snapshot().settings.system_proxy);
    assert!(!service.status().proxy);
}

#[test]
fn automatic_updates_obey_intervals_preserve_failed_nodes_and_back_off() {
    let (dir, service) = service();
    let source = dir.path().join("subscription.json");
    fs::write(
        &source,
        r#"{"outbounds":[{"type":"socks","tag":"new","server":"127.0.0.1","server_port":1080}]}"#,
    )
    .unwrap();
    let old_nodes =
        vec![json!({"type":"socks","tag":"old","server":"127.0.0.1","server_port":1080})];
    let due = Subscription {
        source: source.to_string_lossy().into_owned(),
        nodes: old_nodes.clone(),
        updated: model::now() - 3601,
        update_interval_hours: 1,
        ..Subscription::default()
    };
    let id = due.id.clone();
    let disabled = Subscription {
        auto_update: false,
        ..due.clone()
    };
    let fresh = Subscription {
        updated: model::now(),
        ..due.clone()
    };
    service
        .update(|state| {
            state.subscriptions = vec![
                due,
                Subscription {
                    id: model::id(),
                    ..disabled
                },
                Subscription {
                    id: model::id(),
                    ..fresh
                },
            ];
            Ok(())
        })
        .unwrap();
    assert_eq!(service.update_due_subscriptions().unwrap(), 1);
    assert_eq!(service.subscription_revision(), 1);
    assert_eq!(service.snapshot().subscriptions[0].nodes[0]["tag"], "new");
    assert_eq!(service.snapshot().subscriptions[1].nodes, old_nodes);
    assert_eq!(service.snapshot().subscriptions[2].nodes, old_nodes);
    service
        .update(|state| {
            state.subscriptions[0].updated = 0;
            Ok(())
        })
        .unwrap();
    fs::write(&source, "invalid content").unwrap();
    assert_eq!(service.update_due_subscriptions().unwrap(), 0);
    assert_eq!(service.subscription_revision(), 1);
    assert_eq!(service.snapshot().subscriptions[0].nodes[0]["tag"], "new");
    let failed_logs = service.logs();
    assert!(failed_logs.contains("更新失败"));
    fs::write(
        &source,
        r#"{"outbounds":[{"type":"socks","tag":"retry","server":"127.0.0.1","server_port":1080}]}"#,
    )
    .unwrap();
    assert_eq!(service.update_due_subscriptions().unwrap(), 0);
    assert_eq!(
        service.logs(),
        failed_logs,
        "backoff should not produce another request or log"
    );
    service.update_subscription(&id).unwrap();
    assert_eq!(service.snapshot().subscriptions[0].nodes[0]["tag"], "retry");
    assert_eq!(service.subscription_revision(), 2);
}

#[test]
fn concurrent_manual_and_automatic_updates_do_not_override_an_edit() {
    let (_dir, service) = service();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = server.local_addr().unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let server_worker = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let body = r#"{"outbounds":[{"type":"socks","tag":"stale","server":"127.0.0.1","server_port":1080}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let sub = Subscription {
        source: format!("http://{address}"),
        ..Subscription::default()
    };
    let id = sub.id.clone();
    service
        .update(|state| {
            state.subscriptions.push(sub);
            Ok(())
        })
        .unwrap();
    let worker_service = service.clone();
    let worker_id = id.clone();
    let update = thread::spawn(move || worker_service.update_subscription(&worker_id));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(service.update_due_subscriptions().unwrap(), 0);
    assert!(
        service
            .update_subscription(&id)
            .unwrap_err()
            .to_string()
            .contains("正在更新")
    );
    service
        .update(|state| {
            state.subscriptions[0].source = "edited.json".into();
            Ok(())
        })
        .unwrap();
    release_tx.send(()).unwrap();
    assert!(update.join().unwrap().is_err());
    server_worker.join().unwrap();
    assert!(service.snapshot().subscriptions[0].nodes.is_empty());
    assert_eq!(service.snapshot().subscriptions[0].source, "edited.json");
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
        state.settings.bypass_lan = true;
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

// Keep a real proxied connection open so control tests can observe socket
// teardown, rather than only trusting a successful API response.
fn open_echo_tunnel(proxy: std::net::SocketAddr) -> (TcpStream, thread::JoinHandle<()>) {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = origin.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = origin.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0];
        loop {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => stream.write_all(&byte).unwrap(),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("origin echo: {error}"),
            }
        }
    });
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
        assert!(response.len() < 4096);
    }
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    echo_byte(&mut stream);
    (stream, worker)
}

fn echo_byte(stream: &mut TcpStream) {
    stream.write_all(b"q").unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"q");
}

fn assert_tunnel_closed(mut stream: TcpStream, worker: thread::JoinHandle<()>) {
    match stream.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("old connection was not closed: {other:?}"),
    }
    worker.join().unwrap();
}

#[test]
fn real_core_modes_override_policy_and_switches_close_old_connections() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let (_dir, service) = service();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    let mixed = TcpListener::bind("127.0.0.1:0").unwrap();
    let mixed_address = mixed.local_addr().unwrap();
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable_port = unavailable.local_addr().unwrap().port();
    drop((api, mixed, unavailable));
    let group = "出口 / 自动";
    service.update(|state| {
        state.settings.core_path = binary;
        state.settings.bypass_lan = false;
        state.settings.block_ads = true;
        state.settings.sniff = false;
        state.settings.routing_mode = "global".into();
        // A local test rule replaces the ad list; no public DNS or traffic.
        state.rulesets.iter_mut().find(|r| r.id == model::BUILTIN_ADS_ID).unwrap().content =
            json!({"version":3,"rules":[{"ip_cidr":"127.0.0.0/8"}]});
        let config = &mut state.profiles[0].config;
        config["inbounds"] = json!([{"type":"mixed","listen":"127.0.0.1","listen_port":mixed_address.port()}]);
        config["experimental"]["clash_api"]["external_controller"] = json!(api_address.to_string());
        config["route"]["final"] = json!(group);
        config["outbounds"] = json!([
            {"type":"selector","tag":group,"outbounds":["first","second"],"default":"first","interrupt_exist_connections":false},
            {"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":unavailable_port},
            {"type":"direct","tag":"first"},
            {"type":"direct","tag":"second"}
        ]);
        Ok(())
    }).unwrap();
    service
        .start()
        .unwrap_or_else(|e| panic!("{e:#}\n{}", service.logs()));
    let pid = service.status().pid;
    // Global uses route.final's selected member, not the unrelated dead node
    // named "proxy", and bypasses the rejecting ad rule.
    let (connection, worker) = open_echo_tunnel(mixed_address);
    service.set_routing_mode("rule").unwrap();
    assert_tunnel_closed(connection, worker);

    let rejected_origin = TcpListener::bind("127.0.0.1:0").unwrap();
    rejected_origin.set_nonblocking(true).unwrap();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::http(format!("http://{mixed_address}")).unwrap())
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    assert!(
        client
            .get(format!("http://{}", rejected_origin.local_addr().unwrap()))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .is_err()
    );
    assert!(
        matches!(rejected_origin.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );

    service.set_routing_mode("direct").unwrap();
    let (connection, worker) = open_echo_tunnel(mixed_address);
    service.set_routing_mode("global").unwrap();
    assert_tunnel_closed(connection, worker);

    let (mut connection, worker) = open_echo_tunnel(mixed_address);
    assert!(service.select_outbound(group, "missing").is_err());
    echo_byte(&mut connection);
    service.select_outbound(group, "second").unwrap();
    assert_tunnel_closed(connection, worker);
    assert_eq!(service.status().pid, pid);
    let group_path = format!(
        "/proxies/{}",
        percent_encoding::utf8_percent_encode(group, percent_encoding::NON_ALPHANUMERIC)
    );
    assert_eq!(
        service.api("GET", &group_path, None).unwrap()["now"],
        "second"
    );
    let (connection, worker) = open_echo_tunnel(mixed_address);
    service.restart().unwrap();
    assert_tunnel_closed(connection, worker);
    assert_ne!(service.status().pid, pid);
    assert_eq!(service.runtime_mode().unwrap(), "global");
    assert_eq!(
        service.api("GET", &group_path, None).unwrap()["now"],
        "second"
    );
    service.stop().unwrap();
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
