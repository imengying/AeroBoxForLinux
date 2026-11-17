use aerobox_for_linux::{
    backup,
    engine::Service,
    model::{RuleSet, Settings, Store, Subscription},
};
use serde_json::{Value, json};
use std::{fs, sync::Arc};

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
    (dir, Service::new(store))
}

#[test]
fn backup_round_trip_retains_credentials_rules_and_dns() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("backup.json");
    let mut original = state();
    original.settings.direct_dns = "tcp://223.5.5.5:5353".into();
    original.settings.remote_dns = "quic://dns.adguard-dns.com".into();
    original.settings.auto_start = true;
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
    let bytes = b"SRS\x01portable fixture".to_vec();
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
    current.settings.auto_start = false;
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
    assert!(!merged.settings.auto_start);
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
    for content in [
        b"not json".as_slice(),
        br#"{}"#,
        br#"{"format":"other","version":1}"#,
        br#"{"format":"aerobox-android-backup","version":1}"#,
        br#"{"format":"aerobox-linux-backup","version":0}"#,
        br#"{"format":"aerobox-linux-backup","version":2}"#,
    ] {
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
    backup::export(&path, &with_rule, |_| Some(b"SRS fixture".to_vec())).unwrap();
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["rulesets"][0]["binary_data"] = Value::Null;
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        backup::read(&path)
            .unwrap_err()
            .to_string()
            .contains("缺少二进制数据")
    );
    backup::export(&path, &with_rule, |_| Some(b"SRS fixture".to_vec())).unwrap();
    let (imported, mut files) = backup::read(&path).unwrap();
    files.clear();
    assert!(backup::merge(&state(), imported, files).is_err());
    assert!(backup::read(dir.path()).is_err());
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
    fs::write(
        source.dir().join("rules").join(format!("{id}.srs")),
        b"SRS service fixture",
    )
    .unwrap();
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
        b"SRS service fixture"
    );
    let reopened = Service::new(Store::open(Some(target.dir().to_path_buf())).unwrap());
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
fn stale_settings_form_cannot_overwrite_newer_state() {
    let (_dir, service) = service();
    let previous = service.snapshot().settings;
    let mut form = previous.clone();
    form.direct_dns = "tcp://223.5.5.5".into();
    form.font_size = 15;
    let mut newer = previous.clone();
    newer.mixed_port = previous.mixed_port + 1;
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
fn running_restore_failure_rolls_back_new_rule_files_and_preserves_the_core() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let (dir, source) = service();
    source
        .update(|state| {
            state.settings.core_path = binary;
            state.settings.routing_mode = "global".into();
            Ok(())
        })
        .unwrap();
    source
        .import_subscription(Subscription {
            nodes: vec![
                json!({"type":"socks","tag":"fixture","server":"127.0.0.1","server_port":9}),
            ],
            ..Default::default()
        })
        .unwrap();
    let rule = RuleSet {
        name: "回滚检查".into(),
        binary: true,
        enabled: false,
        ..Default::default()
    };
    let rule_id = rule.id.clone();
    source
        .update(|state| {
            state.rulesets.push(rule);
            Ok(())
        })
        .unwrap();
    fs::create_dir_all(source.dir().join("rules")).unwrap();
    fs::write(
        source.dir().join("rules").join(format!("{rule_id}.srs")),
        include_bytes!("../resources/rules/geoip-cn.srs"),
    )
    .unwrap();
    source.start().unwrap();
    source
        .api("PATCH", "/configs", Some(&json!({"mode":"direct"})))
        .unwrap();
    assert_eq!(source.runtime_mode().unwrap(), "direct");
    assert_eq!(source.snapshot().settings.routing_mode, "global");
    let pid = source.status().pid;
    let before = source.snapshot();
    let path = dir.path().join("running-backup.json");
    source.export_backup(&path).unwrap();
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["subscriptions"][0]["nodes"][0]["server_port"] = json!("not-a-port");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    source.restore_backup(&path).unwrap_err();
    assert_eq!(source.status().pid, pid);
    assert_eq!(source.runtime_mode().unwrap(), "direct");
    assert_eq!(json_eq(&source.snapshot()), json_eq(&before));
    assert_eq!(fs::read_dir(source.dir().join("rules")).unwrap().count(), 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(source.dir().join("state.json")).unwrap())
            .unwrap(),
        serde_json::to_value(before).unwrap()
    );
    source.stop().unwrap();
}
