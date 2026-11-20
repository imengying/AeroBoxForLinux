mod support;
use aerobox_for_linux::{
    engine::Service,
    model::{Store, Subscription},
};
use serde_json::json;
use std::{io::Write, process::Command, time::Duration};

/// Explicit privileged validation; all routes and nft rules live in a fresh
/// user/network namespace, never in the desktop's network namespace.
#[test]
#[ignore = "requires Linux user/network namespaces, iproute2, nftables and /dev/net/tun"]
fn managed_tun_routes_traffic_and_restores_network_in_namespace() {
    let result = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "tun_namespace_worker",
            "--nocapture",
        ])
        .env("AEROBOX_TUN_TEST_NAMESPACE", "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
#[ignore = "internal namespace test worker"]
fn tun_namespace_worker() {
    assert_eq!(
        std::env::var("AEROBOX_TUN_TEST_NAMESPACE").as_deref(),
        Ok("1")
    );
    for args in [
        vec!["link", "set", "lo", "up"],
        vec!["link", "add", "underlay0", "type", "dummy"],
        vec!["addr", "add", "198.51.100.1/24", "dev", "underlay0"],
        vec!["link", "set", "underlay0", "up"],
        vec![
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/64",
            "dev",
            "underlay0",
            "nodad",
        ],
        vec![
            "-6",
            "route",
            "add",
            "default",
            "via",
            "2001:db8:1::fe",
            "dev",
            "underlay0",
        ],
        vec![
            "route",
            "add",
            "default",
            "via",
            "198.51.100.254",
            "dev",
            "underlay0",
        ],
    ] {
        assert!(Command::new("ip").args(args).status().unwrap().success());
    }
    let node = support::Server::spawn(|mut stream| {
        if support::headers(&mut stream).is_err() {
            return;
        }
        if stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .is_err()
        {
            return;
        }
        if support::headers(&mut stream).is_err() {
            return;
        }
        let _ = support::respond(&mut stream, b"through-tun");
    });
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(Some(dir.path().into())).unwrap();
    let sub = Subscription {
        nodes: vec![
            json!({"type":"http","tag":"peer","server":"127.0.0.1","server_port":node.address.port()}),
        ],
        ..Subscription::default()
    };
    store
        .update(|s| {
            s.settings.system_proxy = false;
            s.settings.tun_enabled = true;
            s.settings.ipv6 = false;
            s.settings.routing_mode = "global".into();
            s.settings.sniff = false;
            s.settings.remote_dns = "tcp://1.1.1.1".into();
            s.settings.mixed_port = support::free_port();
            s.rulesets.clear();
            s.settings.active_subscription = sub.id.clone();
            s.subscriptions.push(sub);
            Ok(())
        })
        .unwrap();
    let service = Service::new(store);
    assert!(service.tun_available().unwrap());
    for ipv6 in [false, true] {
        let mut settings = service.snapshot().settings;
        settings.ipv6 = ipv6;
        service.apply_settings(settings).unwrap();
        service
            .start()
            .unwrap_or_else(|e| panic!("TUN start: {e:#}\n{}", service.logs()));
        let response = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .get(if ipv6 {
                "http://[2001:db8:2::10]/payload"
            } else {
                "http://203.0.113.10/payload"
            })
            .send()
            .and_then(|r| r.text());
        let stopped = service.stop();
        assert_eq!(
            response.unwrap_or_else(|e| panic!("TUN request {e:?}\n{}", service.logs())),
            "through-tun"
        );
        stopped.unwrap();
        let links = Command::new("ip")
            .args(["link", "show", "aerobox0"])
            .output()
            .unwrap();
        assert!(!links.status.success(), "TUN device leaked after stop");
        let rules = Command::new("nft")
            .args(["list", "tables"])
            .output()
            .unwrap();
        assert!(rules.status.success());
        assert!(!String::from_utf8_lossy(&rules.stdout).contains("shoes_"));
        let routes = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&routes.stdout).contains("198.51.100.254"));
        let routes = Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&routes.stdout).contains("2001:db8:1::fe"));
    }
}
