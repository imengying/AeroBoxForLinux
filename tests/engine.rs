mod support;

use aerobox_for_linux::{
    engine::Service,
    model::{self, RuleSet, Settings, Store, Subscription},
};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::{Arc, atomic::Ordering, mpsc},
    thread,
    time::Duration,
};
use support::{App, BlockStateWrite, Server, request, runtime_lock, socks_node};

fn service() -> (tempfile::TempDir, Arc<Service>) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(Some(dir.path().into())).unwrap();
    store
        .update(|state| {
            state.settings.system_proxy = false;
            state.settings.mixed_port = support::free_port();
            state.settings.bypass_lan = false;
            state.settings.sniff = false;
            state.rulesets.clear();
            Ok(())
        })
        .unwrap();
    (dir, Service::new(store))
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
        nodes: vec![json!({"type":"socks","tag":"local","server":"127.0.0.1","server_port":1080})],
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
    assert_eq!(state.subscriptions[0].update_interval_minutes, 720);
    assert_eq!(
        state.settings.active_subscription,
        state.subscriptions[0].id
    );
    assert_eq!(state.subscriptions[0].selected_node.as_deref(), Some("one"));
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
fn offline_settings_are_saved_without_starting_networking() {
    let (_dir, s) = service();
    let settings = Settings {
        theme: "dark".into(),
        tun_enabled: true,
        ..s.snapshot().settings
    };
    s.apply_settings(settings).unwrap();
    assert_eq!(s.snapshot().settings.theme, "dark");
    assert!(s.snapshot().settings.tun_enabled);
    assert!(!s.status().running);
    let mut invalid = s.snapshot().settings;
    for url in [
        "file:///tmp/not-a-network-test",
        "http://user@:80",
        "not a URL",
    ] {
        invalid.test_url = url.into();
        assert!(s.apply_settings(invalid.clone()).is_err(), "accepted {url}");
    }
    invalid.test_url = "https://www.gstatic.com/generate_204".into();
    for timeout in [0, 499, 60_001] {
        invalid.test_timeout = timeout;
        assert!(
            s.apply_settings(invalid.clone()).is_err(),
            "accepted {timeout}"
        );
    }
    invalid.test_timeout = 60_000;
    s.apply_settings(invalid).unwrap();
    assert_eq!(s.snapshot().settings.test_timeout, 60_000);
}

#[test]
fn subscription_form_preserves_live_download_data_and_rejects_stale_edits() {
    let (_dir, service) = service();
    let sub = Subscription {
        name: "原始名称".into(),
        source: "original.json".into(),
        nodes: vec![json!({"type":"socks","tag":"old","server":"127.0.0.1","server_port":1080})],
        selected_node: Some("old".into()),
        updated: 10,
        ..Subscription::default()
    };
    let id = sub.id.clone();
    service
        .update(|state| {
            state.subscriptions.push(sub);
            Ok(())
        })
        .unwrap();
    let original = service.snapshot().subscriptions[0].clone();
    service
        .update(|state| {
            let current = &mut state.subscriptions[0];
            current.nodes =
                vec![json!({"type":"socks","tag":"fresh","server":"127.0.0.1","server_port":1081})];
            current.selected_node = Some("fresh".into());
            current.updated = 20;
            current.upload = 1;
            current.download = 2;
            current.total = 3;
            current.expires = 4;
            Ok(())
        })
        .unwrap();
    let mut form = original.clone();
    form.name = "新名称".into();
    form.source = "new.json".into();
    form.auto_update = false;
    form.update_interval_minutes = 720;
    form.nodes.clear();
    form.selected_node = None;
    form.updated = 0;
    form.upload = 0;
    form.download = 0;
    form.total = 0;
    form.expires = 0;
    service.save_subscription(&original, form).unwrap();
    let saved = &service.snapshot().subscriptions[0];
    assert_eq!(saved.name, "新名称");
    assert_eq!(saved.source, "new.json");
    assert!(!saved.auto_update);
    assert_eq!(saved.update_interval_minutes, 720);
    assert_eq!(saved.nodes[0]["tag"], "fresh");
    assert_eq!(saved.selected_node.as_deref(), Some("fresh"));
    assert_eq!(saved.updated, 0, "a changed source must be refreshed");
    assert_eq!(
        (saved.upload, saved.download, saved.total, saved.expires),
        (1, 2, 3, 4)
    );
    let mut stale = original.clone();
    stale.name = "过期表单".into();
    assert!(
        service
            .save_subscription(&original, stale)
            .unwrap_err()
            .to_string()
            .contains("重新打开编辑器")
    );
    service.delete_resource("subscriptions", &id).unwrap();
    assert!(
        service
            .save_subscription(&original, original.clone())
            .unwrap_err()
            .to_string()
            .contains("已被删除")
    );
}

#[test]
fn stale_subscription_source_edits_cannot_replace_a_newer_download() {
    let (_dir, service) = service();
    let sub = Subscription {
        nodes: vec![json!({"type":"socks","tag":"one","server":"127.0.0.1","server_port":1080})],
        selected_node: Some("one".into()),
        updated: 10,
        ..Subscription::default()
    };
    service
        .update(|state| {
            state.subscriptions.push(sub);
            Ok(())
        })
        .unwrap();
    let original = service.snapshot().subscriptions[0].clone();
    service
        .update(|state| {
            let sub = &mut state.subscriptions[0];
            sub.nodes =
                vec![json!({"type":"socks","tag":"two","server":"127.0.0.1","server_port":1081})];
            sub.selected_node = Some("two".into());
            sub.updated = 20;
            Ok(())
        })
        .unwrap();
    let before = service.snapshot();
    assert!(
        service
            .save_subscription_nodes(
                &original,
                vec![json!({"type":"socks","tag":"stale","server":"127.0.0.1","server_port":1082})]
            )
            .is_err()
    );
    assert_eq!(
        serde_json::to_value(service.snapshot()).unwrap(),
        serde_json::to_value(before).unwrap()
    );
}

#[test]
fn failed_rule_commit_restores_the_previous_cached_file() {
    let (_dir, service) = service();
    let source = service.dir().join("source.json");
    fs::write(
        &source,
        r#"{"version":3,"rules":[{"domain":"new.example"}]}"#,
    )
    .unwrap();
    let rule = RuleSet {
        name: "回滚规则".into(),
        source: source.to_string_lossy().into_owned(),
        content: json!({"version":3,"rules":[{"domain":"old.example"}]}),
        enabled: false,
        ..RuleSet::default()
    };
    let id = rule.id.clone();
    service
        .update(|state| {
            state.rulesets.push(rule);
            Ok(())
        })
        .unwrap();
    let cache = service.dir().join("rules").join(format!("{id}.json"));
    fs::create_dir_all(cache.parent().unwrap()).unwrap();
    fs::write(&cache, b"original cache").unwrap();
    let before = service.snapshot();
    let state = service.dir().join("state.json");
    let saved = service.dir().join("state.saved");
    fs::rename(&state, &saved).unwrap();
    fs::create_dir(&state).unwrap();
    let result = service.update_ruleset(&id);
    fs::remove_dir(&state).unwrap();
    fs::rename(&saved, &state).unwrap();
    assert!(result.is_err());
    assert_eq!(fs::read(&cache).unwrap(), b"original cache");
    assert_eq!(
        serde_json::to_value(service.snapshot()).unwrap(),
        serde_json::to_value(before).unwrap()
    );
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
        update_interval_minutes: 60,
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
fn isolated_autostart_form_failure_helper() {
    let Ok(directory) = std::env::var("AEROBOX_TEST_AUTOSTART_DIRECTORY") else {
        return;
    };
    let service = Service::new(Store::open(Some(directory.clone().into())).unwrap());
    let previous = service.snapshot().settings;
    let mut next = previous.clone();
    next.font_size = 15;
    service.save_form(previous.clone(), next, true).unwrap_err();
    assert!(!aerobox_for_linux::platform::autostart_enabled());
    assert_eq!(service.snapshot().settings, previous);
    fs::remove_file(
        std::path::PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").unwrap()).join("autostart"),
    )
    .unwrap();
    let saved = service.dir().join("state.json");
    let copy = service.dir().join("state.saved");
    fs::rename(&saved, &copy).unwrap();
    fs::create_dir(&saved).unwrap();
    let result = service.save_form(previous.clone(), previous.clone(), true);
    fs::remove_dir(&saved).unwrap();
    fs::rename(&copy, &saved).unwrap();
    assert!(result.is_err());
    assert_eq!(service.snapshot().settings, previous);
    assert!(aerobox_for_linux::platform::autostart_enabled());
    println!("autostart failures preserve application state; partial startup changes are visible");
}

#[test]
fn autostart_form_failures_do_not_change_application_state() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let config = dir.path().join("config");
    fs::create_dir_all(&config).unwrap();
    fs::write(config.join("autostart"), b"not a directory").unwrap();
    let service = Service::new(Store::open(Some(data.clone())).unwrap());
    service
        .update(|state| {
            state.settings.system_proxy = false;
            Ok(())
        })
        .unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "isolated_autostart_form_failure_helper",
            "--nocapture",
        ])
        .env("AEROBOX_TEST_AUTOSTART_DIRECTORY", data)
        .env("XDG_CONFIG_HOME", config)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn selected_nodes_subscriptions_and_modes_change_actual_traffic() {
    let _serial = runtime_lock();
    let app = App::new();
    let (node_a, hits_a) = support::socks_http(b"node A".to_vec());
    let (node_b, hits_b) = support::socks_http(b"node B".to_vec());
    let (node_c, _) = support::socks_http(b"node C".to_vec());
    let (origin, direct_hits) = support::http(b"direct".to_vec());
    let url = format!("http://{}/choice", origin.address);
    let first = app.import(
        "first",
        vec![
            socks_node("A", node_a.address),
            socks_node("B", node_b.address),
        ],
    );
    let second = app.import("second", vec![socks_node("C", node_c.address)]);
    app.service.select_subscription(&first).unwrap();
    app.service.start().unwrap();
    let generation = app.service.status().generation;
    assert!(generation.is_some());
    assert_eq!(request(&app.service, &url).unwrap(), "node A");
    assert_eq!(
        support::request_via(&app.service, &url, "socks5h").unwrap(),
        "node A"
    );
    app.service.select_subscription_node(&first, "B").unwrap();
    assert_eq!(request(&app.service, &url).unwrap(), "node B");
    assert_eq!(app.service.status().generation, generation);
    assert!(app.service.subscription_nodes_runtime(&first).unwrap()[1].selected);

    app.service.set_routing_mode("rule").unwrap();
    assert_eq!(request(&app.service, &url).unwrap(), "node B");
    let rule = RuleSet {
        name: "local destination".into(),
        action: "direct".into(),
        content: json!({"version":3,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}),
        ..RuleSet::default()
    };
    let rule_id = rule.id.clone();
    app.service.save_ruleset(rule).unwrap();
    assert_eq!(request(&app.service, &url).unwrap(), "direct");
    app.service.apply_ruleset_enabled(&rule_id, false).unwrap();
    assert_eq!(request(&app.service, &url).unwrap(), "node B");
    app.service.set_routing_mode("direct").unwrap();
    app.service.select_subscription_node(&first, "A").unwrap();
    assert_eq!(request(&app.service, &url).unwrap(), "direct");
    app.service.set_routing_mode("global").unwrap();
    assert_eq!(request(&app.service, &url).unwrap(), "node A");
    app.service.select_subscription(&second).unwrap();
    assert_eq!(request(&app.service, &url).unwrap(), "node C");
    assert!(
        app.service
            .subscription_nodes_runtime(&first)
            .unwrap()
            .iter()
            .all(|node| !node.available && !node.selected)
    );
    assert!(app.service.subscription_nodes_runtime(&second).unwrap()[0].selected);
    app.service.restart().unwrap();
    assert_ne!(app.service.status().generation, generation);
    assert_eq!(request(&app.service, &url).unwrap(), "node C");
    assert!(hits_a.load(Ordering::Relaxed) >= 3);
    assert!(hits_b.load(Ordering::Relaxed) >= 3);
    assert_eq!(direct_hits.load(Ordering::Relaxed), 2);
    app.service.stop().unwrap();
    let reopened = Service::new(Store::open(Some(app.dir.path().into())).unwrap());
    assert_eq!(reopened.snapshot().settings.active_subscription, second);
    assert_eq!(reopened.runtime_mode().unwrap(), "global");
    reopened.start().unwrap();
    assert_eq!(request(&reopened, &url).unwrap(), "node C");
    reopened.shutdown().unwrap();
}

#[test]
fn failed_persistence_restores_runtime_selection_modes_and_settings() {
    let _serial = runtime_lock();
    let app = App::new();
    let (node_a, _) = support::socks_http(b"original".to_vec());
    let (node_b, _) = support::socks_http(b"changed".to_vec());
    let (origin, _) = support::http(b"direct".to_vec());
    let url = format!("http://{}/rollback", origin.address);
    let first = app.import(
        "first",
        vec![
            socks_node("A", node_a.address),
            socks_node("B", node_b.address),
        ],
    );
    let second = app.import("second", vec![socks_node("B", node_b.address)]);
    app.service.select_subscription(&first).unwrap();
    app.service.start().unwrap();
    let before = app.service.snapshot();
    let revision = app.service.subscription_revision();
    let saved = fs::read(app.dir.path().join("state.json")).unwrap();
    let blocked = BlockStateWrite::new(app.dir.path());
    let mut settings = before.settings.clone();
    settings.mixed_port = support::free_port();
    settings.routing_mode = "direct".into();
    for operation in 0..4 {
        let result = match operation {
            0 => app.service.select_subscription_node(&first, "B"),
            1 => app.service.set_routing_mode("direct"),
            2 => app.service.select_subscription(&second),
            _ => app.service.apply_settings(settings.clone()),
        };
        assert!(result.is_err());
        assert_eq!(
            serde_json::to_value(app.service.snapshot()).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        assert_eq!(app.service.runtime_mode().unwrap(), "global");
        assert_eq!(app.service.subscription_revision(), revision);
        assert_eq!(request(&app.service, &url).unwrap(), "original");
    }
    drop(blocked);
    assert_eq!(fs::read(app.dir.path().join("state.json")).unwrap(), saved);
    app.service.select_subscription_node(&first, "B").unwrap();
    assert_eq!(request(&app.service, &url).unwrap(), "changed");
}

#[test]
fn stopping_a_speed_test_discards_its_result_and_restart_can_measure_again() {
    let _serial = runtime_lock();
    let app = App::new();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release = std::sync::Mutex::new(release_rx);
    let requests = std::sync::atomic::AtomicUsize::new(0);
    let node = Server::spawn(move |mut stream| {
        if support::socks_handshake(&mut stream).is_err() || support::headers(&mut stream).is_err()
        {
            return;
        }
        if requests.fetch_add(1, Ordering::Relaxed) == 0 {
            entered_tx.send(()).unwrap();
            release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
        let _ = support::respond(&mut stream, b"probe");
    });
    let id = app.import("measured", vec![socks_node("slow", node.address)]);
    let mut settings = app.service.snapshot().settings;
    settings.test_url = "http://1.1.1.1:12345/probe".into();
    app.service.apply_settings(settings).unwrap();
    app.service.start().unwrap();
    let worker = app.service.clone();
    let measured_id = id.clone();
    let measurement = thread::spawn(move || worker.test_subscription_node(&measured_id, "slow"));
    if let Err(error) = entered_rx.recv_timeout(Duration::from_secs(4)) {
        let result = measurement.join().unwrap();
        panic!(
            "probe did not reach fixture: {error}; result: {result:?}\n{}",
            app.service.logs()
        );
    }
    app.service.stop().unwrap();
    release_tx.send(()).unwrap();
    assert!(measurement.join().unwrap().is_err());
    assert!(
        app.service.subscription_nodes(&id).unwrap()[0]
            .delay_ms
            .is_none()
    );
    app.service.start().unwrap();
    let delay = app.service.test_subscription_node(&id, "slow").unwrap();
    assert_eq!(
        app.service.subscription_nodes(&id).unwrap()[0].delay_ms,
        Some(delay)
    );
}

#[test]
fn closing_connections_and_stopping_releases_live_tunnels_and_the_proxy_port() {
    let _serial = runtime_lock();
    let app = App::new();
    app.import(
        "fixture",
        vec![socks_node("unused", "127.0.0.1:9".parse().unwrap())],
    );
    app.service.set_routing_mode("direct").unwrap();
    let origin = support::echo_server();
    let port = app.service.snapshot().settings.mixed_port;
    let mut previous_generation = None;
    for cycle in 0..3 {
        app.service.start().unwrap();
        assert_ne!(app.service.status().generation, previous_generation);
        previous_generation = app.service.status().generation;
        let mut stream = support::echo_tunnel(&app.service, origin.address);
        stream.write_all(b"hello").unwrap();
        let mut reply = [0; 5];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"hello");
        support::wait_for(|| {
            let traffic = app.service.traffic().unwrap();
            traffic.upload >= 5 && traffic.download >= 5
        });
        support::wait_for(|| {
            !app.service.connections().unwrap()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        });
        match cycle {
            0 => {
                let connections = app.service.connections().unwrap();
                let id = connections["connections"][0]["id"].as_str().unwrap();
                app.service.close_connection(id).unwrap();
            }
            1 => app.service.close_all_connections().unwrap(),
            _ => app.service.stop().unwrap(),
        }
        let closed = stream.read(&mut [0; 1]);
        assert!(
            matches!(closed, Ok(0))
                || closed.as_ref().is_err_and(|e| matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                )),
            "connection survived close: {closed:?}"
        );
        app.service.stop().unwrap();
        app.service.stop().unwrap();
        assert!(!app.service.status().running);
        assert!(app.service.status().generation.is_none());
        let available = TcpListener::bind(("127.0.0.1", port)).unwrap();
        drop(available);
    }
}

#[test]
fn connection_rows_use_node_names_and_can_close_the_reported_connection_id() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    app.import("shown", vec![socks_node("香港 · 日常", node.address)]);
    app.service.start().unwrap();
    let origin = support::echo_server();
    let mut tunnel = support::echo_tunnel(&app.service, origin.address);
    tunnel.write_all(b"x").unwrap();
    tunnel.read_exact(&mut [0; 1]).unwrap();
    support::wait_for(|| {
        !app.service.connections().unwrap()["connections"]
            .as_array()
            .unwrap()
            .is_empty()
    });
    let connections = app.service.connections().unwrap();
    let row = &connections["connections"][0];
    let chains = row["chains"].as_array().unwrap();
    assert!(
        chains.iter().any(|name| name == "香港 · 日常"),
        "connection did not show the selected node: {chains:?}"
    );
    assert!(
        chains
            .iter()
            .filter_map(serde_json::Value::as_str)
            .all(|name| !name.starts_with("node-"))
    );
    app.service
        .close_connection(row["id"].as_str().unwrap())
        .unwrap();
    let closed = tunnel.read(&mut [0; 1]);
    assert!(
        matches!(closed, Ok(0))
            || closed.as_ref().is_err_and(|error| matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            )),
        "reported connection id did not close its stream: {closed:?}"
    );
}
