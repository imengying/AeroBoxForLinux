mod support;

use aerobox_for_linux::{
    backup,
    engine::Service,
    model::{RuleSet, Settings, Store, Subscription},
};
use serde_json::{Value, json};
use std::{fs, sync::Arc};

const SRS: &[u8] = include_bytes!("../resources/rules/geoip-cn.srs");

fn json_eq<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

fn state() -> aerobox_for_linux::model::State {
    let mut state = aerobox_for_linux::model::State {
        rulesets: vec![],
        ..Default::default()
    };
    state.settings.system_proxy = false;
    state.subscriptions = vec![Subscription {
        name: "测试订阅".into(),
        nodes: vec![json!({
            "type": "socks", "tag": "fixture", "server": "127.0.0.1",
            "server_port": 1080, "username": "user", "password": "secret"
        })],
        selected_node: Some("fixture".into()),
        ..Default::default()
    }];
    state.settings.active_subscription = state.subscriptions[0].id.clone();
    state
}

fn service() -> (tempfile::TempDir, Arc<Service>) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(Some(dir.path().into())).unwrap();
    store
        .update(|state| {
            state.settings.system_proxy = false;
            state.rulesets.clear();
            Ok(())
        })
        .unwrap();
    (dir, support::service(store))
}

#[test]
fn backup_round_trip_retains_credentials_rules_and_dns() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("backup.json");
    let mut original = state();
    original.settings.direct_dns = "tcp://223.5.5.5:5353".into();
    original.settings.remote_dns = "quic://dns.adguard-dns.com".into();
    original.rulesets = vec![
        RuleSet {
            name: "本地规则".into(),
            binary: true,
            ..Default::default()
        },
        RuleSet {
            name: "JSON 规则".into(),
            content: json!({"version":3,"rules":[{"domain_suffix":"example.com"}]}),
            ..Default::default()
        },
    ];
    let bytes = SRS.to_vec();
    backup::export(&path, &original, |rule| {
        assert_eq!(rule.name, "本地规则");
        Some(bytes.clone())
    })
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("secret"));
    let (imported, original_files) = backup::read(&path).unwrap();
    assert_eq!(
        json_eq(&imported.subscriptions),
        json_eq(&original.subscriptions)
    );
    assert_eq!(imported.settings.direct_dns, original.settings.direct_dns);
    assert_eq!(imported.settings.remote_dns, original.settings.remote_dns);
    assert_eq!(original_files.get(&original.rulesets[0].id), Some(&bytes));

    let mut current = state();
    current.settings.width = 1320;
    current.settings.height = 860;
    let (merged, mapped_files) =
        backup::merge(&current, imported.clone(), original_files.clone()).unwrap();
    assert_eq!(merged.subscriptions.len(), 2);
    assert_eq!(merged.rulesets.len(), 2);
    assert_eq!(
        json_eq(&merged.subscriptions[0]),
        json_eq(&current.subscriptions[0])
    );
    assert_ne!(merged.subscriptions[1].id, imported.subscriptions[0].id);
    assert_eq!(merged.subscriptions[1].name, "测试订阅（备份 2）");
    assert_eq!(
        merged.settings.active_subscription,
        merged.subscriptions[1].id
    );
    assert_eq!((merged.settings.width, merged.settings.height), (1320, 860));
    assert_eq!(mapped_files.len(), 1);
    let (merged_twice, _) = backup::merge(&merged, imported, original_files).unwrap();
    assert_eq!(merged_twice.subscriptions.len(), 3);
    let names: Vec<_> = merged_twice
        .subscriptions
        .iter()
        .map(|sub| sub.name.as_str())
        .collect();
    assert_eq!(
        names,
        ["测试订阅", "测试订阅（备份 2）", "测试订阅（备份 3）"]
    );
    assert_eq!(merged_twice.rulesets.len(), 4);
    let names: Vec<_> = merged_twice
        .rulesets
        .iter()
        .map(|rule| rule.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "本地规则",
            "JSON 规则",
            "本地规则（备份 2）",
            "JSON 规则（备份 2）"
        ]
    );
}

#[test]
fn malformed_and_incomplete_backups_are_rejected_before_merging() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("backup.json");
    for content in [b"not json".as_slice(), br#"{}"#] {
        fs::write(&path, content).unwrap();
        assert!(backup::read(&path).is_err());
    }
    let original = state();
    backup::export(&path, &original, |_| None).unwrap();
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["settings"]["remote_dns"] = json!("http://insecure.example/dns-query");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        backup::read(&path)
            .unwrap_err()
            .to_string()
            .contains("备份内容未通过校验")
    );

    let mut with_rule = original.clone();
    with_rule.rulesets = vec![RuleSet {
        binary: true,
        ..Default::default()
    }];
    assert!(backup::export(&path, &with_rule, |_| None).is_err());
    let remote = RuleSet {
        binary: true,
        source: "https://example.com/rules.srs".into(),
        ..Default::default()
    };
    with_rule.rulesets = vec![remote];
    backup::export(&path, &with_rule, |_| Some(SRS.to_vec())).unwrap();
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["rulesets"][0]["binary_data"] = Value::Null;
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        backup::read(&path)
            .unwrap_err()
            .to_string()
            .contains("缺少二进制数据")
    );
    backup::export(&path, &with_rule, |_| Some(SRS.to_vec())).unwrap();
    let (imported, mut files) = backup::read(&path).unwrap();
    files.clear();
    assert!(backup::merge(&state(), imported, files).is_err());
    assert!(backup::read(dir.path()).is_err());
}

#[test]
fn incomplete_backups_and_invalid_selections_cannot_change_saved_data() {
    let (_dir, service) = service();
    let mut original = state();
    original.rulesets.push(RuleSet::default());
    let path = service.dir().join("backup.json");
    backup::export(&path, &original, |_| None).unwrap();
    let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let saved = fs::read(service.dir().join("state.json")).unwrap();
    let before = json_eq(&service.snapshot());
    let mut invalid = vec![];
    for (path, field) in [
        ("/settings", "direct_dns"),
        ("/subscriptions/0", "id"),
        ("/subscriptions/0", "nodes"),
        ("/rulesets/0", "enabled"),
    ] {
        let mut incomplete = value.clone();
        incomplete
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        invalid.push(incomplete);
    }
    let mut missing_subscription = value.clone();
    let missing_id = aerobox_for_linux::model::id();
    missing_subscription["settings"]["active_subscription"] = json!(missing_id);
    invalid.push(missing_subscription);
    let mut missing_node = value;
    missing_node["subscriptions"][0]["selected_node"] = json!("missing");
    invalid.push(missing_node);
    for invalid in invalid {
        fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(service.restore_backup(&path).is_err());
        assert_eq!(json_eq(&service.snapshot()), before);
        assert_eq!(fs::read(service.dir().join("state.json")).unwrap(), saved);
    }
}

#[test]
fn restoring_an_unselected_backup_does_not_choose_an_existing_subscription() {
    let (_dir, service) = service();
    service
        .import_subscription(state().subscriptions.remove(0))
        .unwrap();
    assert!(
        service.snapshot().settings.active_subscription.is_empty(),
        "导入不应自动选用订阅"
    );
    let mut imported = state();
    imported.settings.active_subscription.clear();
    let path = service.dir().join("unselected.json");
    backup::export(&path, &imported, |_| None).unwrap();
    service.restore_backup(&path).unwrap();
    let restored = Store::open(Some(service.dir())).unwrap().state;
    assert_eq!(restored.subscriptions.len(), 2);
    assert!(restored.settings.active_subscription.is_empty());
    assert!(
        restored
            .subscriptions
            .iter()
            .all(|sub| { sub.selected_node.as_deref() == Some("fixture") && sub.nodes.len() == 1 })
    );
}

#[test]
fn service_export_restore_persists_files_and_does_not_overwrite_existing_data() {
    let (_source_dir, source) = service();
    let mut sub = Subscription {
        name: "凭据订阅".into(),
        nodes: vec![json!({
            "type":"socks", "tag":"secret node", "server":"127.0.0.1", "server_port":1080,
            "username":"fixture-user", "password":"fixture-password"
        })],
        ..Default::default()
    };
    sub.selected_node = Some("secret node".into());
    source.import_subscription(sub).unwrap();
    let rule = RuleSet {
        name: "便携 SRS".into(),
        binary: true,
        ..Default::default()
    };
    let id = rule.id.clone();
    source
        .update(|state| {
            state.rulesets.push(rule);
            state.settings.direct_dns = "tls://dns.alidns.com".into();
            Ok(())
        })
        .unwrap();
    fs::create_dir_all(source.dir().join("rules")).unwrap();
    fs::write(source.dir().join("rules").join(format!("{id}.srs")), SRS).unwrap();
    let path = source.dir().join("backup.json");
    source.export_backup(&path).unwrap();

    let (_target_dir, target) = service();
    let original = target.snapshot();
    assert_eq!(target.restore_backup(&path).unwrap(), (1, 1));
    let restored = target.snapshot();
    assert_eq!(
        restored.subscriptions.len(),
        original.subscriptions.len() + 1
    );
    assert_eq!(restored.rulesets.len(), original.rulesets.len() + 1);
    assert_eq!(restored.settings.direct_dns, "tls://dns.alidns.com");
    assert!(
        restored
            .subscriptions
            .iter()
            .any(|sub| sub.nodes[0]["password"] == "fixture-password")
    );
    let rule = restored
        .rulesets
        .iter()
        .find(|rule| rule.name == "便携 SRS")
        .unwrap();
    assert_eq!(
        fs::read(target.dir().join("rules").join(format!("{}.srs", rule.id))).unwrap(),
        SRS
    );
    let reopened = support::service(Store::open(Some(target.dir().to_path_buf())).unwrap());
    assert_eq!(json_eq(&reopened.snapshot()), json_eq(&restored));

    assert_eq!(reopened.restore_backup(&path).unwrap(), (1, 1));
    assert_eq!(reopened.snapshot().subscriptions.len(), 2);
    assert_eq!(reopened.snapshot().rulesets.len(), 2);
    assert!(
        reopened
            .snapshot()
            .subscriptions
            .iter()
            .any(|sub| sub.name == "凭据订阅（备份 2）")
    );
    fs::write(&path, b"invalid").unwrap();
    let before = reopened.snapshot();
    assert!(reopened.restore_backup(&path).is_err());
    assert_eq!(json_eq(&reopened.snapshot()), json_eq(&before));
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(reopened.dir().join("state.json")).unwrap())
            .unwrap(),
        serde_json::to_value(before).unwrap()
    );
}

#[test]
fn restoring_an_empty_remote_json_snapshot_works_offline() {
    let _serial = support::runtime_lock();
    let source = support::App::new();
    let node = support::socks_forward();
    source.import(
        "empty rules",
        vec![support::socks_node("forwarder", node.address)],
    );
    source.service.set_routing_mode("rule").unwrap();
    let (server, fetched) = support::http(br#"{"version":3,"rules":[]}"#.to_vec());
    source
        .service
        .save_ruleset(RuleSet {
            name: "empty remote snapshot".into(),
            source: format!("http://{}/empty.json", server.address),
            ..Default::default()
        })
        .unwrap();
    source.service.start().unwrap();
    source.service.stop().unwrap();
    assert_eq!(fetched.load(std::sync::atomic::Ordering::Relaxed), 1);
    let path = source.dir.path().join("empty-backup.json");
    source.service.export_backup(&path).unwrap();
    drop(server);
    let restored = support::App::new();
    restored.service.restore_backup(&path).unwrap();
    assert_eq!(restored.service.snapshot().rulesets[0].updated, 0);
    restored.service.start().unwrap();
    let (origin, _) = support::http(b"restored offline".to_vec());
    assert_eq!(
        support::request(&restored.service, &format!("http://{}/", origin.address)).unwrap(),
        "restored offline"
    );
    restored.service.stop().unwrap();
}

#[test]
fn new_local_rule_files_are_imported_and_backed_up_before_starting() {
    let (_directory, service) = service();
    for binary in [false, true] {
        let path = service
            .dir()
            .join(if binary { "input.srs" } else { "input.json" });
        let bytes = if binary {
            SRS.to_vec()
        } else {
            br#"{"version":3,"rules":[{"domain":["local.example.test"]}]}"#.to_vec()
        };
        fs::write(&path, &bytes).unwrap();
        let rule = RuleSet {
            name: if binary {
                "imported SRS"
            } else {
                "imported JSON"
            }
            .into(),
            source: path.to_str().unwrap().into(),
            binary,
            ..Default::default()
        };
        let id = rule.id.clone();
        service.save_ruleset(rule).unwrap();
        fs::remove_file(path).unwrap();
        let content: Value = serde_json::from_str(&service.rule_source(&id).unwrap()).unwrap();
        assert!(!content["rules"].as_array().unwrap().is_empty());
        let backup = service.dir().join("local-files.json");
        service.export_backup(&backup).unwrap();
        let (state, files) = backup::read(&backup).unwrap();
        if binary {
            assert_eq!(files[&id], bytes);
        } else {
            assert_eq!(state.rulesets[0].content, content);
        }
    }
    assert!(!service.status().running);
}

#[test]
fn restore_commit_failure_removes_new_rule_files_and_preserves_existing_files() {
    let (_dir, target) = service();
    let existing = RuleSet {
        name: "原有规则".into(),
        binary: true,
        enabled: false,
        ..Default::default()
    };
    let rules_dir = target.dir().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    let existing_path = rules_dir.join(format!("{}.srs", existing.id));
    fs::write(&existing_path, SRS).unwrap();
    target
        .update(|state| {
            state.rulesets.push(existing);
            Ok(())
        })
        .unwrap();
    let before = target.snapshot();
    let mut imported = state();
    imported.rulesets = ["新增规则一", "新增规则二"]
        .into_iter()
        .map(|name| RuleSet {
            name: name.into(),
            binary: true,
            enabled: false,
            ..Default::default()
        })
        .collect();
    let backup_path = target.dir().join("backup.json");
    backup::export(&backup_path, &imported, |_| Some(SRS.to_vec())).unwrap();

    // Rule writes succeed, but the final atomic state replacement must fail.
    // Using a directory also works when the tests run with root privileges.
    let state_path = target.dir().join("state.json");
    let saved_path = target.dir().join("state.saved");
    let saved_bytes = fs::read(&state_path).unwrap();
    fs::rename(&state_path, &saved_path).unwrap();
    fs::create_dir(&state_path).unwrap();
    let result = target.restore_backup(&backup_path);
    fs::remove_dir(&state_path).unwrap();
    fs::rename(&saved_path, &state_path).unwrap();

    let error = result.unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::IsADirectory
    );
    assert_eq!(json_eq(&target.snapshot()), json_eq(&before));
    assert_eq!(fs::read(&state_path).unwrap(), saved_bytes);
    assert_eq!(fs::read(&existing_path).unwrap(), SRS);
    let remaining = fs::read_dir(&rules_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(remaining, vec![existing_path]);
}

#[test]
fn resizing_with_settings_open_preserves_edits_and_the_latest_window_size() {
    let (dir, service) = service();
    let resize = |width, height| {
        service
            .update(|state| {
                state.settings.width = width;
                state.settings.height = height;
                Ok(())
            })
            .unwrap();
    };
    let baseline = service.snapshot().settings;
    let mut edited = baseline.clone();
    edited.direct_dns = "tls://dns.example.com".into();
    resize(1280, 800);
    service.apply_settings_form(baseline, edited).unwrap();
    let saved = service.snapshot().settings;
    assert_eq!(saved.direct_dns, "tls://dns.example.com");
    assert_eq!((saved.width, saved.height), (1280, 800));

    resize(1120, 700);
    service.reset_settings(saved).unwrap();
    let reopened = Store::open(Some(dir.path().into())).unwrap().state.settings;
    assert_eq!(reopened.direct_dns, Settings::default().direct_dns);
    assert_eq!((reopened.width, reopened.height), (1120, 700));
}

#[test]
fn stale_settings_form_cannot_overwrite_newer_state() {
    let (_dir, service) = service();
    let previous = service.snapshot().settings;
    let mut form = previous.clone();
    form.direct_dns = "tcp://223.5.5.5".into();
    form.font_size = 15;
    let mut newer = previous.clone();
    newer.dns_cache = !previous.dns_cache;
    service.apply_settings(newer.clone()).unwrap();
    assert!(
        service
            .apply_settings_form(previous.clone(), form)
            .unwrap_err()
            .to_string()
            .contains("重新打开设置页")
    );
    assert_eq!(service.snapshot().settings, newer);
    let mut live = newer.clone();
    live.routing_mode = "global".into();
    service
        .update(|state| {
            state.settings.routing_mode = live.routing_mode.clone();
            Ok(())
        })
        .unwrap();
    let mut form = live.clone();
    form.remote_dns = "tcp://1.1.1.1".into();
    service
        .apply_settings_form(live.clone(), form.clone())
        .unwrap();
    assert_eq!(service.snapshot().settings, form);
    let mut valid = form.clone();
    valid.direct_dns = "tcp://223.5.5.5".into();
    service.apply_settings_form(form, valid.clone()).unwrap();
    assert_eq!(service.snapshot().settings, valid);
    let default = Settings::default();
    assert_eq!(default.direct_dns, "udp://223.5.5.5");
}

#[test]
fn reset_settings_preserves_resources_selection_and_window() {
    let (_dir, service) = service();
    let mut sub = Subscription {
        name: "保留的订阅".into(),
        nodes: vec![json!({"type":"socks","tag":"chosen","server":"127.0.0.1","server_port":1080})],
        selected_node: Some("chosen".into()),
        ..Default::default()
    };
    let id = sub.id.clone();
    sub.selected_node = Some("chosen".into());
    service.import_subscription(sub).unwrap();
    service
        .update(|state| {
            state.settings.active_subscription = id.clone();
            state.settings.routing_mode = "global".into();
            state.settings.width = 1440;
            state.settings.height = 920;
            Ok(())
        })
        .unwrap();
    let before = service.snapshot();
    let mut form = before.settings.clone();
    form.direct_dns = "tcp://223.5.5.5".into();
    form.font_size = 18;
    service
        .apply_settings_form(before.settings.clone(), form)
        .unwrap();
    service.reset_settings(before.settings.clone()).unwrap_err();
    let saved = service.snapshot().settings;
    service.reset_settings(saved).unwrap();
    let after = service.snapshot();
    assert_eq!(
        json_eq(&after.subscriptions),
        json_eq(&before.subscriptions)
    );
    assert_eq!(json_eq(&after.rulesets), json_eq(&before.rulesets));
    assert_eq!(after.settings.active_subscription, id);
    assert_eq!(after.settings.routing_mode, "global");
    assert_eq!((after.settings.width, after.settings.height), (1440, 920));
    assert_eq!(after.settings.font_size, Settings::default().font_size);
    assert_eq!(after.settings.direct_dns, Settings::default().direct_dns);
}

#[test]
fn running_restore_failure_rolls_back_rule_files_and_actual_traffic() {
    let _serial = support::runtime_lock();
    let app = support::App::new();
    let (node, _) = support::socks_http(b"original proxy".to_vec());
    let (origin, _) = support::http(b"direct destination".to_vec());
    let url = format!("http://{}/backup", origin.address);
    app.import(
        "original",
        vec![support::socks_node("original", node.address)],
    );
    let rule = RuleSet {
        name: "original binary rule".into(),
        binary: true,
        enabled: false,
        ..RuleSet::default()
    };
    let rule_id = rule.id.clone();
    app.service.save_ruleset(rule).unwrap();
    let rules_dir = app.dir.path().join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    let original_file = rules_dir.join(format!("{rule_id}.srs"));
    let rule_bytes = include_bytes!("../resources/rules/geoip-cn.srs");
    fs::write(&original_file, rule_bytes).unwrap();
    app.service.start().unwrap();
    let before = app.service.snapshot();
    let path = app.dir.path().join("backup.json");
    app.service.export_backup(&path).unwrap();
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["settings"]["routing_mode"] = json!("rule");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let generation = app.service.status().generation;
    let block = support::BlockStateWrite::new(app.dir.path());
    app.service.restore_backup(&path).unwrap_err();
    drop(block);
    assert_eq!(app.service.status().generation, generation);
    assert_eq!(app.service.runtime_mode(), "global");
    assert_eq!(json_eq(&app.service.snapshot()), json_eq(&before));
    assert_eq!(
        support::request(&app.service, &url).unwrap(),
        "original proxy"
    );
    let remaining = fs::read_dir(&rules_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    assert_eq!(remaining, vec![original_file.clone()]);
    assert_eq!(fs::read(&original_file).unwrap(), rule_bytes);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(app.dir.path().join("state.json")).unwrap())
            .unwrap(),
        json_eq(&before)
    );
}

#[test]
fn corrupted_binary_rule_backups_are_rejected_without_changing_saved_data() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (_dir, service) = service();
    let mut imported = state();
    imported.rulesets.push(RuleSet {
        name: "binary rule".into(),
        binary: true,
        enabled: false,
        ..RuleSet::default()
    });
    let path = service.dir().join("corrupt-backup.json");
    backup::export(&path, &imported, |_| Some(SRS.to_vec())).unwrap();
    let valid: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let before = json_eq(&service.snapshot());
    let saved = fs::read(service.dir().join("state.json")).unwrap();
    for bytes in [
        b"SRS".as_slice(),
        b"SRS\x01broken payload",
        &SRS[..SRS.len() / 2],
    ] {
        let mut invalid = valid.clone();
        invalid["rulesets"][0]["binary_data"] = json!(STANDARD.encode(bytes));
        fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        let error = service.restore_backup(&path).unwrap_err();
        assert!(format!("{error:#}").contains("SRS 规则数据无效"));
        assert_eq!(json_eq(&service.snapshot()), before);
        assert_eq!(fs::read(service.dir().join("state.json")).unwrap(), saved);
        assert!(!service.dir().join("rules").exists());
    }
}
