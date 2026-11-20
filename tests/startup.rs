mod support;

use aerobox_for_linux::model::RuleSet;
use std::{
    net::TcpListener,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use support::{App, Server, runtime_lock, socks_node};

type PendingRule = (Server, mpsc::Receiver<()>, mpsc::Sender<()>);
fn pending_rule() -> PendingRule {
    pending_rule_body(include_bytes!("../resources/rules/geoip-cn.srs").to_vec())
}
fn pending_rule_body(body: Vec<u8>) -> PendingRule {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release = Mutex::new(release_rx);
    let first = AtomicBool::new(true);
    let source = Server::spawn(move |mut stream| {
        if support::headers(&mut stream).is_err() {
            return;
        }
        let _ = entered_tx.send(());
        if !first.swap(false, Ordering::Relaxed)
            || release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(8))
                .is_ok()
        {
            let _ = support::respond(&mut stream, &body);
        }
    });
    (source, entered_rx, release_tx)
}

fn configure_rule(app: &App, source: &Server, node: &Server) {
    app.import("rule fetch", vec![socks_node("forwarder", node.address)]);
    app.service.set_routing_mode("rule").unwrap();
    app.service
        .save_ruleset(RuleSet {
            name: "first download".into(),
            source: format!("http://{}/rules.srs", source.address),
            binary: true,
            ..RuleSet::default()
        })
        .unwrap();
}

#[test]
fn first_remote_rule_download_finishes_before_start_reports_success() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    let (source, entered, release) = pending_rule();
    configure_rule(&app, &source, &node);
    let service = app.service.clone();
    let (finished_tx, finished_rx) = mpsc::channel();
    let starting = thread::spawn(move || {
        finished_tx.send(service.start()).unwrap();
    });
    if let Err(error) = entered.recv_timeout(Duration::from_secs(4)) {
        panic!(
            "no rule download: {error}; startup: {:?}; logs: {}",
            finished_rx.try_recv(),
            app.service.logs()
        );
    }
    assert!(matches!(
        finished_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    release.send(()).unwrap();
    let result = finished_rx.recv_timeout(Duration::from_secs(8)).unwrap();
    starting.join().unwrap();
    result.unwrap_or_else(|error| {
        panic!(
            "first rule download failed: {error:#}\n{}",
            app.service.logs()
        )
    });
    assert!(app.service.status().running);
    let rule = app.service.snapshot().rulesets[0].clone();
    let source = app.service.rule_source(&rule.id).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&source).unwrap()["rules"].is_array());
    app.service.stop().unwrap();
    let backup_path = app.dir.path().join("downloaded-rules-backup.json");
    app.service.export_backup(&backup_path).unwrap();
    let (_, files) = aerobox_for_linux::backup::read(&backup_path).unwrap();
    assert_eq!(
        files[&rule.id],
        include_bytes!("../resources/rules/geoip-cn.srs")
    );
}

#[test]
fn stopping_during_first_rule_download_cancels_without_waiting_for_the_server() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    let (source, entered, release) = pending_rule();
    configure_rule(&app, &source, &node);
    let service = app.service.clone();
    let starting = thread::spawn(move || service.start());
    if let Err(error) = entered.recv_timeout(Duration::from_secs(4)) {
        if starting.is_finished() {
            panic!(
                "no rule download: {error}; startup: {:?}; logs: {}",
                starting.join().unwrap(),
                app.service.logs()
            );
        }
        panic!(
            "no rule download: {error}; startup still pending; logs: {}",
            app.service.logs()
        );
    }
    let service = app.service.clone();
    let (stopped_tx, stopped_rx) = mpsc::channel();
    let began = Instant::now();
    let stopping = thread::spawn(move || {
        stopped_tx.send(service.stop()).unwrap();
    });
    let result = stopped_rx.recv_timeout(Duration::from_secs(2));
    let elapsed = began.elapsed();
    // Always unblock the fixture before asserting, including regressions.
    release.send(()).unwrap();
    stopping.join().unwrap();
    let started = starting.join().unwrap();
    assert!(
        result.is_ok(),
        "stopping waited for the remote rule response: {elapsed:?}"
    );
    result.unwrap().unwrap();
    assert!(started.is_err(), "a cancelled startup reported success");
    assert!(!app.service.status().running);
    assert!(!app.service.status().proxy);
    let port = app.service.snapshot().settings.mixed_port;
    let _available = TcpListener::bind(("127.0.0.1", port)).unwrap();
}

#[test]
fn occupied_proxy_port_fails_cleanly_then_can_start_and_shutdown() {
    let _serial = runtime_lock();
    let app = App::new();
    app.import(
        "unused",
        vec![socks_node("unused", "127.0.0.1:9".parse().unwrap())],
    );
    app.service.set_routing_mode("direct").unwrap();
    let port = app.service.snapshot().settings.mixed_port;
    let occupied = TcpListener::bind(("127.0.0.1", port)).unwrap();
    assert!(app.service.start().is_err());
    assert!(!app.service.status().running);
    assert!(app.service.status().generation.is_none());
    drop(occupied);
    app.service.start().unwrap();
    let (origin, _) = support::http(b"started after collision".to_vec());
    assert_eq!(
        support::request(&app.service, &format!("http://{}/", origin.address)).unwrap(),
        "started after collision"
    );
    app.service.shutdown().unwrap();
    assert!(app.service.start().is_err());
    assert!(!app.service.status().running);
    let _available = TcpListener::bind(("127.0.0.1", port)).unwrap();
}

#[test]
fn first_remote_json_download_is_applied_before_start_and_preserved_for_offline_use() {
    let _serial = runtime_lock();
    let app = App::new();
    let (node, _) = support::socks_http(b"proxy without rule".to_vec());
    let (origin, _) = support::http(b"direct with downloaded rule".to_vec());
    let body = br#"{"version":3,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}"#;
    let (source, entered, release) = pending_rule_body(body.to_vec());
    app.import("JSON download", vec![socks_node("proxy", node.address)]);
    app.service.set_routing_mode("rule").unwrap();
    let rule = RuleSet {
        name: "online JSON".into(),
        source: format!("http://{}/rules.json", source.address),
        ..RuleSet::default()
    };
    let rule_id = rule.id.clone();
    app.service.save_ruleset(rule).unwrap();
    let service = app.service.clone();
    let (finished_tx, finished_rx) = mpsc::channel();
    let starting = thread::spawn(move || {
        finished_tx.send(service.start()).unwrap();
    });
    if let Err(error) = entered.recv_timeout(Duration::from_secs(4)) {
        panic!(
            "no JSON download: {error}; startup: {:?}; logs: {}",
            finished_rx.try_recv(),
            app.service.logs()
        );
    }
    assert!(
        matches!(finished_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "startup reported success before receiving the online JSON rule"
    );
    release.send(()).unwrap();
    finished_rx
        .recv_timeout(Duration::from_secs(8))
        .unwrap()
        .unwrap();
    starting.join().unwrap();
    let url = format!("http://{}/rule-match", origin.address);
    assert_eq!(
        support::request(&app.service, &url).unwrap(),
        "direct with downloaded rule"
    );
    let expected: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&app.service.rule_source(&rule_id).unwrap())
            .unwrap(),
        expected
    );
    app.service.stop().unwrap();
    drop(source);
    app.service.start().unwrap();
    assert_eq!(
        support::request(&app.service, &url).unwrap(),
        "direct with downloaded rule"
    );
    app.service.stop().unwrap();
    let path = app.dir.path().join("online-json-backup.json");
    app.service.export_backup(&path).unwrap();
    let (restored, _) = aerobox_for_linux::backup::read(&path).unwrap();
    assert_eq!(restored.rulesets[0].content, expected);
}

#[test]
fn stopping_cancels_an_online_rule_edit_and_keeps_the_saved_rules() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    app.import("connected", vec![socks_node("forwarder", node.address)]);
    app.service.set_routing_mode("rule").unwrap();
    app.service.start().unwrap();
    let before = serde_json::to_value(app.service.snapshot()).unwrap();
    let saved = std::fs::read(app.dir.path().join("state.json")).unwrap();
    let (source, entered, release) = pending_rule();
    let rule = RuleSet {
        name: "pending edit".into(),
        source: format!("http://{}/pending.srs", source.address),
        binary: true,
        ..RuleSet::default()
    };
    let service = app.service.clone();
    let (edited_tx, edited_rx) = mpsc::channel();
    let editing = thread::spawn(move || {
        edited_tx.send(service.save_ruleset(rule)).unwrap();
    });
    if let Err(error) = entered.recv_timeout(Duration::from_secs(4)) {
        panic!(
            "no pending rule request: {error}; edit: {:?}; logs: {}",
            edited_rx.try_recv(),
            app.service.logs()
        );
    }
    let service = app.service.clone();
    let (stopped_tx, stopped_rx) = mpsc::channel();
    let stopping = thread::spawn(move || {
        stopped_tx.send(service.stop()).unwrap();
    });
    let stopped = stopped_rx.recv_timeout(Duration::from_secs(2));
    release.send(()).unwrap();
    stopping.join().unwrap();
    editing.join().unwrap();
    assert!(stopped.is_ok(), "stop waited for a rule edit download");
    stopped.unwrap().unwrap();
    assert!(
        edited_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .is_err()
    );
    assert!(!app.service.status().running);
    assert_eq!(
        serde_json::to_value(app.service.snapshot()).unwrap(),
        before
    );
    assert_eq!(
        std::fs::read(app.dir.path().join("state.json")).unwrap(),
        saved
    );
    let _port =
        TcpListener::bind(("127.0.0.1", app.service.snapshot().settings.mixed_port)).unwrap();
}

#[test]
fn checking_a_new_online_rule_fetches_it_without_starting_the_proxy() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    let (source, _) = support::http(include_bytes!("../resources/rules/geoip-cn.srs").to_vec());
    configure_rule(&app, &source, &node);
    app.service.check_current().unwrap();
    assert!(!app.service.status().running);
    assert!(!app.service.status().proxy);
    let port = app.service.snapshot().settings.mixed_port;
    let _available = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let id = app.service.snapshot().rulesets[0].id.clone();
    assert!(app.service.rule_source(&id).unwrap().contains("ip_cidr"));
}

#[test]
fn consecutive_manual_rule_updates_cannot_reuse_an_older_runtime_cache() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    app.import("rule refresh", vec![socks_node("peer", node.address)]);
    app.service.set_routing_mode("rule").unwrap();
    let generation = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1));
    let next = generation.clone();
    let source = Server::spawn(move |mut stream| {
        if support::headers(&mut stream).is_ok() {
            let index = next.load(Ordering::Relaxed);
            let body = serde_json::to_vec(&serde_json::json!({"version":3,"rules":[{"domain":[format!("revision-{index}.test")]}]})).unwrap();
            let _ = support::respond(&mut stream, &body);
        }
    });
    let rule = RuleSet {
        source: format!("http://{}/rules.json", source.address),
        // Clock skew reproduces a same-second identity collision deterministically.
        updated: aerobox_for_linux::model::now() + 60,
        ..RuleSet::default()
    };
    let id = rule.id.clone();
    app.service.save_ruleset(rule).unwrap();
    for index in [1, 2] {
        generation.store(index, Ordering::Relaxed);
        app.service.update_ruleset(&id).unwrap();
        app.service.check_current().unwrap();
        let content: serde_json::Value =
            serde_json::from_str(&app.service.rule_source(&id).unwrap()).unwrap();
        assert_eq!(
            content["rules"][0]["domain"][0],
            format!("revision-{index}.test")
        );
    }
}
