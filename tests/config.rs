use aerobox_for_linux::{
    engine::Service,
    model::{Settings, Store},
};
use serde_json::json;

#[test]
fn builtins_generate_with_editable_rules_and_leave_source_intact() {
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(Store::open(Some(dir.path().into())).unwrap());
    service
        .update(|state| {
            state.settings.block_ads = true;
            state.rulesets[2].name = "自定义广告".into();
            state.rulesets[2].content["rules"] = json!([{"domain_suffix":"ads.example"}]);
            Ok(())
        })
        .unwrap();
    let state = service.snapshot();
    let generated = service.generate(&state.settings.active_profile).unwrap();
    assert!(
        generated["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["rule_set"] == "自定义广告" && r["action"] == "reject")
    );
    assert!(
        generated["dns"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["rule_set"] == "自定义广告" && r["action"] == "reject")
    );
    let ad_file = generated["route"]["rule_set"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tag"] == "自定义广告")
        .unwrap()["path"]
        .as_str()
        .unwrap();
    let content: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ad_file).unwrap()).unwrap();
    assert_eq!(content["rules"][0]["domain_suffix"], "ads.example");
    assert_eq!(
        service.snapshot().profiles[0].config,
        state.profiles[0].config
    );
}

/// Parsing every generated combination through the real core catches schema
/// mistakes. This test never starts TUN or modifies host routes.
#[test]
fn real_core_accepts_builtin_modes_and_network_controls() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(Store::open(Some(dir.path().into())).unwrap());
    let mut state = service.snapshot();
    let original: Vec<_> = state.profiles.iter().map(|p| p.config.clone()).collect();
    for mode in ["rule", "global", "direct"] {
        for ipv6 in [false, true] {
            for stack in [None, Some("system"), Some("gvisor"), Some("mixed")] {
                state.settings = Settings {
                    routing_mode: mode.into(),
                    ipv6,
                    tun_enabled: stack.is_some(),
                    tun_stack: stack.unwrap_or("system").into(),
                    allow_lan: true,
                    block_ads: true,
                    dns_cache: false,
                    sniff: false,
                    dns_hijack: false,
                    ..Settings::default()
                };
                for profile in &state.profiles {
                    let config = service.generate_profile(&state, profile).unwrap();
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
    assert_eq!(
        state
            .profiles
            .iter()
            .map(|p| p.config.clone())
            .collect::<Vec<_>>(),
        original
    );
}
