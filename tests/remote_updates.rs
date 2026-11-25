mod support;

use aerobox_for_linux::model::RuleSet;
use serde_json::json;
use shoes::embedding::EmbeddedCore;
use std::{
    fs,
    io::Read,
    net::TcpListener,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use support::{App, Server, runtime_lock, socks_node};

const NEW_RULE: &[u8] = br#"{"version":3,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}"#;

fn config(app: &App, node: &Server, source: &Server) -> (serde_json::Value, PathBuf) {
    app.import("rules", vec![socks_node("forwarder", node.address)]);
    app.service.set_routing_mode("rule").unwrap();
    app.service
        .save_ruleset(RuleSet {
            name: "slow automatic update".into(),
            source: format!("http://{}/rules.json", source.address),
            content: json!({"version":3,"rules":[{"ip_cidr":["192.0.2.1/32"]}]}),
            updated: 1,
            ..Default::default()
        })
        .unwrap();
    let mut config = app.service.generate_current().unwrap();
    let source = config
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry.get("rule_source_group").is_some())
        .unwrap();
    // Exercise the application's generated configuration without waiting for
    // its one-minute minimum user-facing update interval in a regression test.
    source["rules"][0]["update_interval"] = "1s".into();
    source["rules"][0]["download"]["client_chain"] = "direct".into();
    let path = PathBuf::from(source["rules"][0]["path"].as_str().unwrap());
    (config, path)
}

fn executor() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn status_polling_does_not_restart_slow_automatic_rule_downloads() {
    let _serial = runtime_lock();
    let app = App::new();
    let (node, _) = support::socks_http(b"old proxy route".to_vec());
    let (entered, pending) = mpsc::channel();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let source = Server::spawn(move |mut stream| {
        if support::headers(&mut stream).is_ok() {
            count.fetch_add(1, Ordering::Relaxed);
            let _ = entered.send(());
            thread::sleep(Duration::from_millis(1500));
            let _ = support::respond(&mut stream, NEW_RULE);
        }
    });
    let (config, cache) = config(&app, &node, &source);
    let executor = executor();
    let core = executor
        .block_on(EmbeddedCore::start_json(&config.to_string(), None))
        .unwrap();
    let (origin, hits) = support::http(b"updated direct rule".to_vec());
    let url = format!("http://{}/", origin.address);
    assert_eq!(
        support::request(&app.service, &url).unwrap(),
        "old proxy route"
    );
    assert_eq!(hits.load(Ordering::Relaxed), 0);
    pending.recv_timeout(Duration::from_secs(5)).unwrap();
    let before = fs::read(&cache).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let updated = loop {
        // The home page and connection view send these commands while a slow
        // download is pending. They must not drop and recreate its HTTP future.
        executor.block_on(core.stats()).unwrap();
        executor.block_on(core.connections()).unwrap();
        if fs::read(&cache).unwrap() != before {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(30));
    };
    let downloads = requests.load(Ordering::Relaxed);
    let traffic = updated.then(|| {
        // Wait for the actor to finish activating the downloaded rules.
        executor.block_on(core.stats()).unwrap();
        support::request(&app.service, &url)
    });
    executor.block_on(core.shutdown()).unwrap();
    assert!(
        updated,
        "status polling prevented the automatic rule update"
    );
    assert_eq!(downloads, 1, "the slow rule download was restarted");
    assert_eq!(traffic.unwrap().unwrap(), "updated direct rule");
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert_eq!(fs::read(&cache).unwrap(), NEW_RULE);
}

#[test]
fn stopping_cancels_a_pending_automatic_rule_download_and_keeps_its_cache() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    let (entered, pending) = mpsc::channel();
    let (closed, disconnected) = mpsc::channel();
    let source = Server::spawn(move |mut stream| {
        if support::headers(&mut stream).is_ok() {
            let _ = entered.send(());
            let result = stream.read(&mut [0]);
            let _ = closed.send(matches!(result, Ok(0)));
        }
    });
    let (config, cache) = config(&app, &node, &source);
    let before = fs::read(&cache).unwrap();
    let executor = executor();
    let core = executor
        .block_on(EmbeddedCore::start_json(&config.to_string(), None))
        .unwrap();
    pending.recv_timeout(Duration::from_secs(5)).unwrap();
    executor.block_on(core.stats()).unwrap();
    let began = Instant::now();
    executor.block_on(core.shutdown()).unwrap();
    assert!(began.elapsed() < Duration::from_secs(2));
    assert!(disconnected.recv_timeout(Duration::from_secs(2)).unwrap());
    assert_eq!(fs::read(&cache).unwrap(), before);
    assert!(!core.is_running());
    let _port = TcpListener::bind(("127.0.0.1", app.service.local_proxy_port())).unwrap();
}

#[test]
fn editing_rule_sources_refreshes_content_and_failed_edits_preserve_actual_routes() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    let (origin, _) = support::http(b"direct after source change".to_vec());
    let (source, fetched) = support::http(NEW_RULE.to_vec());
    app.import("source edit", vec![socks_node("forwarder", node.address)]);
    app.service.set_routing_mode("rule").unwrap();
    let rule = RuleSet {
        name: "changing source".into(),
        action: "reject".into(),
        content: json!({"version":3,"rules":[{"ip_cidr":["192.0.2.1/32"]}]}),
        ..Default::default()
    };
    app.service.save_ruleset(rule.clone()).unwrap();
    app.service.start().unwrap();
    let url = format!("http://{}/", origin.address);
    assert_eq!(
        support::request(&app.service, &url).unwrap(),
        "direct after source change"
    );
    let mut changed = rule;
    changed.source = format!("http://{}/changed.json", source.address);
    app.service.save_ruleset(changed).unwrap();
    assert_eq!(
        fetched.load(Ordering::Relaxed),
        1,
        "the edited source was not fetched"
    );
    assert!(
        support::request(&app.service, &url).is_err(),
        "old rules survived a source edit"
    );

    let before = serde_json::to_value(app.service.snapshot()).unwrap();
    let mut changed = app.service.snapshot().rulesets[0].clone();
    let (invalid, _) = support::http(b"not a rule set".to_vec());
    changed.source = format!("http://{}/invalid.json", invalid.address);
    assert!(app.service.save_ruleset(changed).is_err());
    assert_eq!(
        serde_json::to_value(app.service.snapshot()).unwrap(),
        before
    );
    assert!(support::request(&app.service, &url).is_err());
    app.service.stop().unwrap();

    // An offline edit to a local SRS file must also replace cached JSON and
    // validate the selected format before the next start.
    let local = app.dir.path().join("source.srs");
    fs::write(&local, include_bytes!("fixtures/dns-routing.srs")).unwrap();
    let mut changed = app.service.snapshot().rulesets[0].clone();
    changed.source = local.to_str().unwrap().into();
    changed.binary = true;
    app.service.save_ruleset(changed).unwrap();
    let backup = app.dir.path().join("edited-source-backup.json");
    app.service.export_backup(&backup).unwrap();
    let (state, bytes) = aerobox_for_linux::backup::read(&backup).unwrap();
    assert_eq!(
        bytes[&state.rulesets[0].id],
        include_bytes!("fixtures/dns-routing.srs")
    );
    app.service.start().unwrap();
    assert!(support::request(&app.service, &url).is_ok());
    app.service.stop().unwrap();
}

#[test]
fn failed_rule_save_cannot_leave_candidate_cache_for_the_next_retry() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    app.import("rollback", vec![socks_node("forwarder", node.address)]);
    app.service.set_routing_mode("rule").unwrap();
    let old = json!({"version":3,"rules":[{"ip_cidr":["192.0.2.1/32"]}]});
    let body = Arc::new(Mutex::new(old.to_string().into_bytes()));
    let served = body.clone();
    let source = Server::spawn(move |mut stream| {
        if support::headers(&mut stream).is_ok() {
            let bytes = served.lock().unwrap().clone();
            let _ = support::respond(&mut stream, &bytes);
        }
    });
    let rule = RuleSet {
        name: "retry cache".into(),
        source: format!("http://{}/rules.json", source.address),
        action: "reject".into(),
        content: old.clone(),
        // Force both failed and retried candidates to have the same timestamp,
        // as happens when a user retries within one second or the clock changes.
        updated: aerobox_for_linux::model::now() + 3600,
        ..Default::default()
    };
    let id = rule.id.clone();
    app.service.save_ruleset(rule).unwrap();
    app.service.start().unwrap();
    *body.lock().unwrap() = NEW_RULE.to_vec();
    let state_path = app.dir.path().join("state.json");
    let saved_path = app.dir.path().join("state.saved");
    fs::rename(&state_path, &saved_path).unwrap();
    fs::create_dir(&state_path).unwrap();
    let failed = app.service.update_ruleset(&id);
    fs::remove_dir(&state_path).unwrap();
    fs::rename(&saved_path, &state_path).unwrap();
    assert!(failed.is_err());
    assert_eq!(app.service.snapshot().rulesets[0].content, old);
    let (origin, _) = support::http(b"old rule restored".to_vec());
    let url = format!("http://{}/", origin.address);
    assert!(support::request(&app.service, &url).is_ok());

    let retry = json!({"version":3,"rules":[{"ip_cidr":["192.0.2.3/32"]}]});
    *body.lock().unwrap() = retry.to_string().into_bytes();
    app.service.update_ruleset(&id).unwrap();
    assert_eq!(app.service.snapshot().rulesets[0].content, retry);
    let actual: serde_json::Value =
        serde_json::from_str(&app.service.rule_source(&id).unwrap()).unwrap();
    assert_eq!(
        actual, retry,
        "the failed candidate's cache survived the retry"
    );
    assert!(support::request(&app.service, &url).is_ok());
    app.service.stop().unwrap();
    drop(source);
    app.service.start().unwrap();
    assert!(support::request(&app.service, &url).is_ok());
    app.service.stop().unwrap();
}

#[test]
fn retrying_an_edited_remote_rule_never_reuses_a_rejected_content_seed() {
    let _serial = runtime_lock();
    let app = App::new();
    let node = support::socks_forward();
    app.import("editor retry", vec![socks_node("forwarder", node.address)]);
    app.service.set_routing_mode("rule").unwrap();
    let rule = RuleSet {
        name: "editor retry".into(),
        source: "http://127.0.0.1:9/unused.json".into(),
        action: "reject".into(),
        content: json!({"version":3,"rules":[{"ip_cidr":["192.0.2.1/32"]}]}),
        updated: aerobox_for_linux::model::now() + 3600,
        ..Default::default()
    };
    app.service.save_ruleset(rule.clone()).unwrap();
    app.service.start().unwrap();
    let mut edited = rule.clone();
    edited.content = serde_json::from_slice(NEW_RULE).unwrap();
    let state_path = app.dir.path().join("state.json");
    let saved_path = app.dir.path().join("state.saved");
    fs::rename(&state_path, &saved_path).unwrap();
    fs::create_dir(&state_path).unwrap();
    let result = app.service.save_ruleset(edited.clone());
    fs::remove_dir(&state_path).unwrap();
    fs::rename(&saved_path, &state_path).unwrap();
    assert!(result.is_err());
    let (origin, _) = support::http(b"kept direct rule".to_vec());
    let url = format!("http://{}/", origin.address);
    assert!(support::request(&app.service, &url).is_ok());
    edited.content = json!({"version":3,"rules":[{"ip_cidr":["192.0.2.3/32"]}]});
    app.service.save_ruleset(edited.clone()).unwrap();
    let actual: serde_json::Value =
        serde_json::from_str(&app.service.rule_source(&rule.id).unwrap()).unwrap();
    assert_eq!(actual, edited.content);
    assert!(support::request(&app.service, &url).is_ok());
    app.service.stop().unwrap();
}
