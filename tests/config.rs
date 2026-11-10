use aerobox_for_linux::{
    engine::Service,
    model::{Settings, Store},
};
use serde_json::json;
use std::{
    net::{TcpListener, UdpSocket},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

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
    let mut state = service.snapshot();
    state.settings.block_ads = true;
    state.settings.ipv6 = false;
    state
        .rulesets
        .iter_mut()
        .find(|r| r.id == aerobox_for_linux::model::BUILTIN_ADS_ID)
        .unwrap()
        .content = json!({"version":3,"rules":[{"domain_suffix":"ads.example"}]});
    let mut config = service
        .generate_profile(&state, &state.profiles[0])
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
