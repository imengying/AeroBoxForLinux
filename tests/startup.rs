use aerobox_for_linux::{
    engine::Service,
    model::{RuleSet, Store, Subscription},
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn service(binary: &str, source: String) -> (tempfile::TempDir, Arc<Service>) {
    let dir = tempfile::tempdir().unwrap();
    let service = Service::new(Store::open(Some(dir.path().into())).unwrap());
    service
        .update(|state| {
            state.settings.core_path = binary.into();
            state.settings.system_proxy = false;
            state.settings.routing_mode = "direct".into();
            state.settings.mixed_port = free_port();
            state.rulesets.clear();
            Ok(())
        })
        .unwrap();
    service
        .import_subscription(Subscription {
            nodes: vec![
                json!({"type":"socks","tag":"fixture","server":"127.0.0.1","server_port":9}),
            ],
            ..Subscription::default()
        })
        .unwrap();
    service
        .save_ruleset(RuleSet {
            name: "first download".into(),
            source,
            binary: true,
            ..RuleSet::default()
        })
        .unwrap();
    (dir, service)
}

fn accept_with_deadline(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok((stream, _)) = listener.accept() {
            return stream;
        }
        assert!(
            Instant::now() < deadline,
            "core did not request remote rules"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn real_core_waits_for_a_slow_first_rule_download() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (_dir, service) = service(
        &binary,
        format!("http://{}/rules.srs", listener.local_addr().unwrap()),
    );
    let config = service.generate_current().unwrap();
    assert!(config["route"]["rule_set"][0].get("initial_path").is_none());
    let server = thread::spawn(move || {
        let mut stream = accept_with_deadline(&listener);
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let _ = stream.read(&mut [0; 4096]);
        thread::sleep(Duration::from_secs(5));
        let rules = include_bytes!("../resources/rules/geoip-cn.srs");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            rules.len()
        )
        .unwrap();
        stream.write_all(rules).unwrap();
    });
    let result = service.start();
    let running = service.status().running;
    let mode = service.runtime_mode();
    let logs = service.logs();
    service.shutdown().unwrap();
    server.join().unwrap();
    assert!(
        result.is_ok(),
        "slow first download failed: {result:?}\n{logs}"
    );
    assert!(running);
    assert_eq!(mode.unwrap(), "direct");
}

#[test]
fn real_core_can_cancel_startup_while_rules_are_downloading() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (_dir, service) = service(
        &binary,
        format!("http://{}/rules.srs", listener.local_addr().unwrap()),
    );
    let (started_tx, started_rx) = mpsc::channel();
    let worker = service.clone();
    let startup = thread::spawn(move || {
        let _ = started_tx.send(worker.start());
    });
    let _pending_download = accept_with_deadline(&listener);
    let began = Instant::now();
    service.stop().unwrap();
    let result = started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    startup.join().unwrap();
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "cancelling startup waited for rule download"
    );
    assert!(result.unwrap_err().to_string().contains("取消"));
    assert!(!service.status().running);
    assert!(!service.status().proxy);
}
