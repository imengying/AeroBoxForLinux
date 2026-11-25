mod support;
#[path = "support/tun_peer.rs"]
mod tun_peer;

use aerobox_for_linux::{
    engine::Service,
    model::{Store, Subscription},
};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tun_peer::{BootstrapDns, Peer};

/// All routes and firewall rules live in a fresh user/network namespace.
#[test]
#[ignore = "requires Linux user/network namespaces, iproute2, nftables and /dev/net/tun"]
fn managed_tun_routes_traffic_and_restores_network_in_namespace() {
    let result = Command::new("timeout")
        .args([
            "--kill-after=5s",
            "90s",
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
        ])
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

fn ip(args: &[&str]) -> String {
    let result = Command::new("ip").args(args).output().unwrap();
    assert!(
        result.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

fn firewall() -> Value {
    let result = Command::new("nft")
        .args(["-j", "list", "tables"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut value: Value = serde_json::from_slice(&result.stdout).unwrap();
    value["nftables"]
        .as_array_mut()
        .unwrap()
        .retain(|item| item.get("table").is_some());
    value
}

fn identity() -> Value {
    let links: Value = serde_json::from_str(&ip(&["-j", "link", "show", "aerobox0"])).unwrap();
    serde_json::json!({"index":links[0]["ifindex"],"alias":links[0]["ifalias"],"tables":firewall()})
}

fn defaults(action: &str, v4: &str, v6: &str) {
    for args in [
        vec!["route", action, "default", "via", v4, "dev", "underlay0"],
        vec![
            "-6",
            "route",
            action,
            "default",
            "via",
            v6,
            "dev",
            "underlay0",
        ],
    ] {
        ip(&args);
    }
}

fn store(directory: &Path, peer: &Peer, bootstrap: &BootstrapDns) -> Store {
    let mut store = Store::open(Some(directory.into())).unwrap();
    let sub = Subscription {
        nodes: vec![support::socks_node("peer", peer.address())],
        ..Subscription::default()
    };
    store
        .update(|s| {
            s.settings.system_proxy = false;
            s.settings.tun_enabled = true;
            s.settings.ipv6 = true;
            s.settings.routing_mode = "global".into();
            s.settings.sniff = false;
            s.settings.dns_cache = false;
            s.settings.dns_hijack = true;
            s.settings.log_level = "warn".into();
            s.settings.direct_dns = format!("udp://{}", bootstrap.address());
            s.settings.remote_dns = format!("udp://resolver-{}.example.test", uuid::Uuid::new_v4());
            s.rulesets.clear();
            s.settings.active_subscription = sub.id.clone();
            s.subscriptions.push(sub);
            Ok(())
        })
        .unwrap();
    store
}

fn http(ipv6: bool) -> reqwest::Result<String> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?
        .get(if ipv6 {
            "http://[2001:db8:2::10]/payload"
        } else {
            "http://203.0.113.10/payload"
        })
        .send()?
        .text()
}

fn udp(ipv6: bool) {
    let target: SocketAddr = if ipv6 {
        "[2001:db8:2::10]:19123"
    } else {
        "203.0.113.10:19123"
    }
    .parse()
    .unwrap();
    let socket = UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" }).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // Reuse one flow across distinct payload sizes, including an empty datagram.
    for length in [64, 0, 1200, 1400] {
        let payload: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
        socket.send_to(&payload, target).unwrap();
        let mut buffer = [0; 4096];
        let (n, source) = socket
            .recv_from(&mut buffer)
            .unwrap_or_else(|e| panic!("TUN UDP {target}, size {length}: {e}"));
        assert_eq!(source, target);
        assert_eq!(&buffer[..n], payload);
    }
}

fn dns_response(ipv6: bool, tcp: bool, onlink: bool) -> Vec<u8> {
    let target: SocketAddr = match (ipv6, onlink) {
        (false, false) => "203.0.113.53:53",
        (false, true) => "198.51.100.254:53",
        (true, false) => "[2001:db8:2::53]:53",
        (true, true) => "[2001:db8:1::fe]:53",
    }
    .parse()
    .unwrap();
    let query = tun_peer::dns_query(ipv6);
    let response = if tcp {
        let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(&query).unwrap();
        let mut length = [0; 2];
        stream.read_exact(&mut length).unwrap();
        let mut data = vec![0; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut data).unwrap();
        data
    } else {
        let socket = UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" }).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket.send_to(&query, target).unwrap();
        let mut buffer = [0; 4096];
        let (n, source) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(source, target);
        buffer[..n].to_vec()
    };
    assert_eq!(&response[..2], &query[..2], "DNS transaction ID changed");
    response
}

fn dns(peer: &Peer, ipv6: bool, tcp: bool, onlink: bool) {
    let before = peer.dns_targets().len();
    let response = dns_response(ipv6, tcp, onlink);
    assert_eq!(response[3] & 15, 0, "DNS query failed");
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
    let answer = if ipv6 {
        "2001:db8:2::42"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()
    } else {
        vec![203, 0, 113, 42]
    };
    assert!(
        response.ends_with(&answer),
        "unexpected DNS answer: {response:?}"
    );
    let observed = peer.dns_targets();
    assert!(
        observed.len() > before,
        "DNS request never reached the selected node"
    );
    assert!(
        observed[before..]
            .iter()
            .all(|address| address == "9.9.9.9:53"),
        "DNS bypassed configured resolver: {observed:?}"
    );
}

fn wait_until(label: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if predicate() {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(30));
    }
}

fn echo(stream: &mut TcpStream) {
    stream.write_all(b"ping").unwrap();
    let mut response = [0; 4];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"ping");
}

fn live_flow() -> TcpStream {
    let mut stream = TcpStream::connect_timeout(
        &"203.0.113.10:19123".parse().unwrap(),
        Duration::from_secs(2),
    )
    .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    echo(&mut stream);
    stream
}

fn closed(stream: &mut TcpStream) -> bool {
    match stream.read(&mut [0]) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

fn recover_network(service: &Service, peer: &Peer, bootstrap: &BootstrapDns) {
    let original = identity();
    let mut existing = live_flow();
    ip(&["link", "add", "unrelated0", "type", "dummy"]);
    ip(&["link", "set", "unrelated0", "up"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "unrelated0"]);
    thread::sleep(Duration::from_secs(2));
    echo(&mut existing);
    ip(&["link", "del", "unrelated0"]);
    defaults("replace", "198.51.100.253", "2001:db8:1::fd");
    wait_until("old flow closing on gateway change", || {
        closed(&mut existing)
    });
    wait_until("traffic after gateway change", || {
        http(false).is_ok_and(|s| s == "through-tun")
    });
    assert_eq!(
        identity(),
        original,
        "handover unnecessarily recreated TUN/firewall"
    );
    udp(false);
    udp(true);
    let mut existing = live_flow();
    ip(&["route", "del", "default"]);
    ip(&["-6", "route", "del", "default"]);
    wait_until("old flow closing while offline", || closed(&mut existing));
    let client = reqwest::blocking::Client::builder()
        .proxy(
            reqwest::Proxy::http(format!("http://127.0.0.1:{}", service.local_proxy_port()))
                .unwrap(),
        )
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    assert!(
        client.get("http://203.0.113.10/offline").send().is_err(),
        "proxy listeners stayed active without an underlay"
    );
    assert_eq!(
        identity(),
        original,
        "capture was removed during network loss"
    );
    // DNS is initialized on demand. A failed bootstrap must not prevent network
    // recovery; subsequent queries must recover while the homepage polls stats.
    bootstrap.set_failed(true);
    defaults("add", "198.51.100.254", "2001:db8:1::fe");
    wait_until("IP traffic while DNS bootstrap fails", || {
        http(false).is_ok_and(|s| s == "through-tun")
    });
    assert_eq!(
        dns_response(false, false, true)[3] & 15,
        2,
        "unavailable DNS bootstrap did not return SERVFAIL"
    );
    let stop_polling = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop_polling.load(Ordering::Relaxed) && Instant::now() < deadline {
                let _ = service.traffic();
                thread::sleep(Duration::from_millis(100));
            }
        });
        bootstrap.set_failed(false);
        wait_until("DNS recovery while polling stats", || {
            dns_response(false, false, true)[3] & 15 == 0
        });
        stop_polling.store(true, Ordering::Relaxed);
    });
    assert_eq!(identity(), original);
    assert_eq!(http(true).unwrap(), "through-tun");
    udp(false);
    udp(true);
    dns(peer, false, false, true);
    dns(peer, true, true, true);
}

fn clean(directory: &Path, initial_rules: &[String; 2]) {
    assert!(
        !Command::new("ip")
            .args(["link", "show", "aerobox0"])
            .output()
            .unwrap()
            .status
            .success(),
        "TUN device leaked after stop"
    );
    assert!(
        firewall()["nftables"].as_array().unwrap().is_empty(),
        "firewall leaked after stop"
    );
    assert_eq!(
        &[ip(&["rule", "show"]), ip(&["-6", "rule", "show"])],
        initial_rules
    );
    assert!(ip(&["route", "show", "default"]).contains("198.51.100.254"));
    assert!(ip(&["-6", "route", "show", "default"]).contains("2001:db8:1::fe"));
    assert!(
        !std::fs::read_dir(directory.join("network"))
            .unwrap()
            .any(|file| file
                .unwrap()
                .path()
                .extension()
                .is_some_and(|e| e == "json")),
        "network journal survived successful cleanup"
    );
}

struct RunningChild(Child);
impl Drop for RunningChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn recover_crash(peer: &Peer, bootstrap: &BootstrapDns, initial_rules: &[String; 2]) {
    let dir = tempfile::tempdir().unwrap();
    drop(store(dir.path(), peer, bootstrap));
    let ready = dir.path().join("ready");
    let mut child = RunningChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "tun_crash_worker", "--nocapture"])
            .env("AEROBOX_TUN_CRASH_DIRECTORY", dir.path())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_until("child TUN startup", || {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before ready"
        );
        ready.exists()
    });
    let stale = firewall();
    udp(false);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert_eq!(firewall(), stale, "crash did not leave rules to recover");
    let service = support::service(Store::open(Some(dir.path().into())).unwrap());
    service
        .start()
        .unwrap_or_else(|e| panic!("restart after SIGKILL: {e:#}\n{}", service.logs()));
    assert_ne!(firewall(), stale, "stale firewall was reused");
    assert_eq!(http(false).unwrap(), "through-tun");
    udp(true);
    dns(peer, false, false, true);
    service.stop().unwrap();
    clean(dir.path(), initial_rules);
}

#[test]
#[ignore = "internal namespace crash test worker"]
fn tun_crash_worker() {
    assert_eq!(
        std::env::var("AEROBOX_TUN_TEST_NAMESPACE").as_deref(),
        Ok("1")
    );
    let directory =
        std::path::PathBuf::from(std::env::var_os("AEROBOX_TUN_CRASH_DIRECTORY").unwrap());
    let service = support::service(Store::open(Some(directory.clone())).unwrap());
    service.start().unwrap();
    std::fs::write(directory.join("ready"), b"ready").unwrap();
    loop {
        thread::park();
    }
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
    ] {
        ip(&args);
    }
    defaults("add", "198.51.100.254", "2001:db8:1::fe");
    let initial_rules = [ip(&["rule", "show"]), ip(&["-6", "rule", "show"])];
    let peer = Peer::new();
    let bootstrap = BootstrapDns::new();
    let dir = tempfile::tempdir().unwrap();
    let service: Arc<Service> = support::service(store(dir.path(), &peer, &bootstrap));
    assert!(service.tun_available().unwrap());
    for ipv6 in [false, true] {
        let mut settings = service.snapshot().settings;
        settings.ipv6 = ipv6;
        service.apply_settings(settings).unwrap();
        service
            .start()
            .unwrap_or_else(|e| panic!("TUN start: {e:#}\n{}", service.logs()));
        assert_eq!(http(ipv6).unwrap(), "through-tun");
        udp(ipv6);
        for tcp in [false, true] {
            for onlink in [false, true] {
                dns(&peer, ipv6, tcp, onlink);
            }
        }
        if ipv6 {
            recover_network(&service, &peer, &bootstrap);
            let mut existing = live_flow();
            ip(&["route", "del", "default"]);
            ip(&["-6", "route", "del", "default"]);
            wait_until("offline shutdown", || closed(&mut existing));
        }
        service.stop().unwrap();
        if ipv6 {
            assert!(ip(&["route", "show", "default"]).is_empty());
            assert!(ip(&["-6", "route", "show", "default"]).is_empty());
            defaults("add", "198.51.100.254", "2001:db8:1::fe");
        }
        clean(dir.path(), &initial_rules);
        println!(
            "TUN IPv{} TCP/UDP/DNS and cleanup passed",
            if ipv6 { 6 } else { 4 }
        );
    }
    drop(service);
    recover_crash(&peer, &bootstrap, &initial_rules);
    println!("TUN gateway changes, offline recovery and SIGKILL recovery passed");
}
