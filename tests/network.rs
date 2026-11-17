use aerobox_for_linux::{
    engine::Service,
    model::{Store, Subscription},
    subscription,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct Core(Child);
impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_core(binary: &str, dir: &Path, name: &str, config: &Value, port: u16) -> Core {
    let path = dir.join(format!("{name}.json"));
    let log_path = dir.join(format!("{name}.log"));
    fs::write(&path, serde_json::to_vec(config).unwrap()).unwrap();
    let log = fs::File::create(&log_path).unwrap();
    let mut core = Core(
        Command::new(binary)
            .args(["run", "-c"])
            .arg(path)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < deadline && core.0.try_wait().unwrap().is_none(),
            "{name} failed to start: {}",
            fs::read_to_string(&log_path).unwrap()
        );
        thread::sleep(Duration::from_millis(10));
    }
    core
}

struct Worker {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Worker {
    fn spawn(work: impl FnOnce(Arc<AtomicBool>) + Send + 'static) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        Self {
            stop,
            thread: Some(thread::spawn(move || work(worker_stop))),
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.thread.take().unwrap().join();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn origin() -> (u16, Worker) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let worker = Worker::spawn(move |stop| {
        while !stop.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                if stream.read(&mut [0; 4096]).unwrap_or(0) > 0 {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    );
                }
            } else {
                thread::sleep(Duration::from_millis(10));
            }
        }
    });
    (port, worker)
}

fn service(dir: &Path, binary: &str) -> Arc<Service> {
    let service = Service::new(Store::open(Some(dir.join("app"))).unwrap());
    service
        .update(|state| {
            state.settings.core_path = binary.into();
            state.settings.system_proxy = false;
            state.settings.ipv6 = false;
            state.settings.routing_mode = "global".into();
            state.settings.mixed_port = free_port();
            state.rulesets.clear();
            Ok(())
        })
        .unwrap();
    service
}

fn proxy_request(port: u16, origin_port: u16) -> reqwest::Result<String> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))?)
        .timeout(Duration::from_secs(3))
        .build()?
        .get(format!("http://127.0.0.1:{origin_port}/"))
        .send()?
        .error_for_status()?
        .text()
}

/// Check the imported node against a real server that rejects the wrong Host,
/// path or method. All traffic stays on loopback, including TLS.
#[test]
fn real_core_connects_through_clash_http_and_h2_nodes() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-keyout"
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let (origin_port, _origin) = origin();
    let service = service(dir.path(), &binary);
    let uuid = "00000000-0000-4000-8000-000000000001";
    for network in ["h2", "http"] {
        let port = free_port();
        let mut inbound = json!({
            "type":"vless", "listen":"127.0.0.1", "listen_port":port,
            "users":[{"uuid":uuid}],
            "transport":{"type":"http","host":["front.example.test"],"path":"/secret","method":"GET"}
        });
        let mut node = json!({
            "name":network, "type":"vless", "server":"127.0.0.1", "port":port,
            "uuid":uuid, "network":network
        });
        if network == "h2" {
            inbound["tls"] = json!({"enabled":true,"certificate_path":cert,"key_path":key});
            inbound["transport"]["method"] = json!("PUT");
            node["tls"] = json!(true);
            node["skip-cert-verify"] = json!(true);
            node["h2-opts"] = json!({"host":["front.example.test"],"path":"/secret"});
        } else {
            node["http-opts"] = json!({"path":["/secret","/alternate"],"headers":{"Host":["front.example.test"],"X-Token":["fixture"]}});
        }
        let config =
            json!({"log":{"level":"error"},"inbounds":[inbound],"outbounds":[{"type":"direct"}]});
        let _node = start_core(&binary, dir.path(), "node", &config, port);
        let nodes = subscription::parse(&json!({"proxies":[node]}).to_string()).unwrap();
        let subscription = Subscription {
            name: network.into(),
            nodes,
            ..Subscription::default()
        };
        let id = subscription.id.clone();
        service.import_subscription(subscription).unwrap();
        service.select_subscription(&id).unwrap();
        let mut generated = service.generate_current().unwrap();
        generated["experimental"]["cache_file"]["enabled"] = json!(false);
        let proxy_port = service.snapshot().settings.mixed_port;
        let _client = start_core(&binary, dir.path(), "client", &generated, proxy_port);
        let result = proxy_request(proxy_port, origin_port);
        assert!(
            result.is_ok(),
            "{network}: {result:?}\n{}",
            fs::read_to_string(dir.path().join("client.log")).unwrap()
        );
        assert_eq!(result.unwrap(), "OK");
    }
}

fn dns(answer: bool) -> (u16, Arc<AtomicUsize>, Worker) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let queries = count.clone();
    let worker = Worker::spawn(move |stop| {
        let mut data = [0; 4096];
        while !stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = socket.recv_from(&mut data) {
                assert!(n >= 12);
                queries.fetch_add(1, Ordering::Relaxed);
                let mut response = data[..n].to_vec();
                response[2] = 0x81;
                response[3] = if answer { 0x80 } else { 0x83 };
                response[6] = 0;
                response[7] = u8::from(answer);
                response[8..12].fill(0);
                if answer {
                    response.extend_from_slice(&[
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1,
                    ]);
                }
                let _ = socket.send_to(&response, peer);
            }
        }
    });
    (port, count, worker)
}

#[test]
fn real_core_resolves_node_hostnames_using_the_configured_direct_dns() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (default_port, default_queries, _default_dns) = dns(false);
    let (custom_port, custom_queries, _custom_dns) = dns(true);
    let (origin_port, _origin) = origin();
    let node_port = free_port();
    let config = json!({"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":node_port}],"outbounds":[{"type":"direct"}]});
    let _node = start_core(&binary, dir.path(), "node", &config, node_port);
    let service = service(dir.path(), &binary);
    service
        .update(|state| {
            state.settings.direct_dns = format!("udp://127.0.0.1:{custom_port}");
            Ok(())
        })
        .unwrap();
    service.import_subscription(Subscription {
        name:"domain node".into(),
        nodes:vec![json!({"type":"socks","tag":"fixture","server":"private-proxy.example.test","server_port":node_port})],
        ..Subscription::default()
    }).unwrap();
    let mut generated = service.generate_current().unwrap();
    // Make a wrong resolver fail locally instead of querying public DNS.
    for server in generated["dns"]["servers"].as_array_mut().unwrap() {
        if server["tag"] == "dns-local" || server["tag"] == "aerobox-dns-proxy" {
            *server = json!({"type":"udp","tag":server["tag"],"server":"127.0.0.1","server_port":default_port});
        }
    }
    generated["experimental"]["cache_file"]["enabled"] = json!(false);
    let proxy_port = service.snapshot().settings.mixed_port;
    let _client = start_core(&binary, dir.path(), "client", &generated, proxy_port);
    assert_eq!(proxy_request(proxy_port, origin_port).unwrap(), "OK");
    assert!(custom_queries.load(Ordering::Relaxed) > 0);
    assert_eq!(default_queries.load(Ordering::Relaxed), 0);
}
