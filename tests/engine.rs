use aerobox_for_linux::{
    engine::Service,
    model::{self, RuleSet, Settings, Store, Subscription},
};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
fn service() -> (tempfile::TempDir, Arc<Service>) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(Some(dir.path().into())).unwrap();
    store
        .update(|state| {
            state.settings.system_proxy = false;
            state.settings.mixed_port = free_port();
            state.settings.api_port = free_port();
            state.settings.bypass_lan = false;
            state.settings.sniff = false;
            state.rulesets.clear();
            Ok(())
        })
        .unwrap();
    (dir, Service::new(store))
}
fn dummy_subscription(service: &Service) -> String {
    let sub = Subscription {
        nodes: vec![json!({"type":"socks","tag":"fixture","server":"127.0.0.1","server_port":9})],
        ..Subscription::default()
    };
    let id = sub.id.clone();
    service.import_subscription(sub).unwrap();
    id
}
struct FixtureProcess(std::process::Child);
impl Drop for FixtureProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn controlled_node(binary: &str, address: &str) -> (tempfile::TempDir, FixtureProcess, u16) {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = json!({"log":{"level":"error"},"dns":{"servers":[{"type":"hosts","tag":"fixture-dns","predefined":{"choice.example":address,"aerobox.proxy.test":address}}],"final":"fixture-dns"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":port}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_domain_resolver":"fixture-dns","final":"direct"}});
    let path = dir.path().join("core.json");
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut child = FixtureProcess(
        Command::new(binary)
            .args(["run", "-c"])
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline && child.0.try_wait().unwrap().is_none());
        thread::sleep(Duration::from_millis(10));
    }
    (dir, child, port)
}

fn local_tls_probe(dir: &std::path::Path, binary: &str) -> (String, u16, FixtureProcess) {
    use std::io::BufRead;
    let certificate = dir.join("test-ca.pem");
    let key = dir.join("test-key.pem");
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
                "-addext",
                "subjectAltName=IP:127.0.0.1,DNS:aerobox.proxy.test",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-keyout"
            ])
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let code = r#"import http.server,ssl,sys,time
class Handler(http.server.BaseHTTPRequestHandler):
 def do_HEAD(self):
  time.sleep(0.01);self.send_response(204);self.end_headers()
 def do_GET(self):
  body=b'AEROBOX_HTTPS_CHAIN_OK';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args): pass
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(sys.argv[1],sys.argv[2])
server.socket=context.wrap_socket(server.socket,server_side=True)
print(server.server_port,flush=True);server.serve_forever()
"#;
    let mut process = FixtureProcess(
        Command::new("python3")
            .arg("-c")
            .arg(code)
            .arg(&certificate)
            .arg(key)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut port = String::new();
    std::io::BufReader::new(process.0.stdout.take().unwrap())
        .read_line(&mut port)
        .unwrap();
    let wrapper = dir.join("test-core");
    let quote = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexport SSL_CERT_FILE={}\nexec {} \"$@\"\n",
            quote(&certificate.to_string_lossy()),
            quote(binary)
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    (
        wrapper.to_string_lossy().into_owned(),
        port.trim().parse().unwrap(),
        process,
    )
}

fn open_echo_tunnel(proxy: std::net::SocketAddr) -> (TcpStream, thread::JoinHandle<()>) {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = origin.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = origin.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0];
        loop {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => stream.write_all(&byte).unwrap(),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("origin echo: {error}"),
            }
        }
    });
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
        assert!(response.len() < 4096);
    }
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    echo_byte(&mut stream);
    (stream, worker)
}
fn echo_byte(stream: &mut TcpStream) {
    stream.write_all(b"q").unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"q");
}
fn assert_tunnel_closed(mut stream: TcpStream, worker: thread::JoinHandle<()>) {
    match stream.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("old connection was not closed: {other:?}"),
    }
    worker.join().unwrap();
}
#[test]
fn failed_subscription_downloads_do_not_expose_url_credentials_in_errors_or_logs() {
    let (_dir, service) = service();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let sub = Subscription {
        source: format!("http://user:private-password@{address}/subscription?token=private-token"),
        ..Subscription::default()
    };
    let id = sub.id.clone();
    service
        .update(|state| {
            state.subscriptions.push(sub);
            Ok(())
        })
        .unwrap();
    let error = format!("{:#}", service.update_subscription(&id).unwrap_err());
    for output in [error, service.logs()] {
        assert!(!output.contains("private-token"));
        assert!(!output.contains("private-password"));
    }
}

#[test]
fn subscription_updates_preserve_all_original_node_names() {
    let (_d, s) = service();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0; 4096];
        let _ = stream.read(&mut buf);
        let body = r#"{"outbounds":[{"type":"socks","tag":"keep","server":"localhost","server_port":1080},{"type":"socks","tag":"drop","server":"localhost","server_port":1080}]}"#;
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSubscription-Userinfo: upload=10;download=20;total=100\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap()
    });
    let sub = Subscription {
        source: format!("http://{address}"),
        ..Subscription::default()
    };
    let id = sub.id.clone();
    s.update(|state| {
        state.subscriptions.push(sub);
        Ok(())
    })
    .unwrap();
    s.update_subscription(&id).unwrap();
    worker.join().unwrap();
    let sub = s.snapshot().subscriptions[0].clone();
    assert_eq!(sub.nodes.len(), 2);
    assert_eq!(sub.nodes[0]["tag"], "keep");
    assert_eq!(sub.nodes[1]["tag"], "drop");
    assert_eq!(sub.total, 100);
}

#[test]
fn update_all_subscriptions_skips_local_content_and_updates_remote_sources() {
    let (_dir, service) = service();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = Subscription {
        source: format!("http://{}", server.local_addr().unwrap()),
        ..Subscription::default()
    };
    let local = Subscription {
        source: "  ".into(),
        nodes: vec![json!({"type":"direct","tag":"local"})],
        ..Subscription::default()
    };
    let local_id = local.id.clone();
    let worker = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        let body = r#"{"outbounds":[{"type":"socks","tag":"downloaded","server":"127.0.0.1","server_port":1080}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    service
        .update(|state| {
            state.subscriptions = vec![local, remote];
            Ok(())
        })
        .unwrap();
    assert_eq!(service.update_all_subscriptions().unwrap(), 1);
    worker.join().unwrap();
    let state = service.snapshot();
    assert_eq!(state.subscriptions[0].nodes[0]["tag"], "local");
    assert_eq!(state.subscriptions[0].updated, 0);
    assert_eq!(state.subscriptions[1].nodes[0]["tag"], "downloaded");
    assert!(service.update_subscription(&local_id).is_err());
}

#[test]
fn subscription_import_commits_only_valid_nodes_and_uses_optional_server_defaults() {
    let (_dir, service) = service();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let source = format!("http://{}", server.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        let body = r#"{"outbounds":[{"type":"socks","tag":"one","server":"127.0.0.1","server_port":1080}]}"#;
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nProfile-Title: base64:RXhhbXBsZQ==\r\nProfile-Update-Interval: 12\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    });
    service
        .import_subscription(Subscription {
            source: source.clone(),
            ..Subscription::default()
        })
        .unwrap();
    worker.join().unwrap();
    let state = service.snapshot();
    assert_eq!(state.subscriptions.len(), 1);
    assert_eq!(state.subscriptions[0].name, "Example");
    assert_eq!(state.subscriptions[0].update_interval_hours, 12);
    assert_eq!(
        state.settings.active_subscription,
        state.subscriptions[0].id
    );
    assert_eq!(state.subscriptions[0].selected_node.as_deref(), Some("one"));
    assert!(
        service
            .import_subscription(Subscription {
                source,
                ..Subscription::default()
            })
            .unwrap_err()
            .to_string()
            .contains("已导入")
    );
    assert!(
        service
            .import_subscription(Subscription {
                source: "/not/a/subscription".into(),
                ..Subscription::default()
            })
            .is_err()
    );
    assert!(
        service
            .import_subscription(Subscription::default())
            .is_err()
    );
    assert_eq!(service.snapshot().subscriptions.len(), 1);
}

#[test]
fn core_crash_test_helper() {
    let Ok(directory) = std::env::var("AEROBOX_TEST_CRASH_DIRECTORY") else {
        return;
    };
    let service = Service::new(Store::open(Some(directory.clone().into())).unwrap());
    let worker = service.clone();
    thread::spawn(move || worker.start())
        .join()
        .unwrap()
        .unwrap();
    fs::write(
        std::path::Path::new(&directory).join("core.pid"),
        service.status().pid.unwrap().to_string(),
    )
    .unwrap();
    thread::sleep(Duration::from_secs(15));
    service.stop().unwrap();
}

#[test]
fn real_core_terminates_when_the_application_is_killed() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let (dir, service) = service();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api.local_addr().unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    drop((api, proxy));
    service
        .update(|state| {
            state.settings.core_path = binary;
            state.settings.mixed_port = proxy_address.port();
            state.settings.api_port = api_address.port();
            Ok(())
        })
        .unwrap();
    dummy_subscription(&service);
    let mut application = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "core_crash_test_helper", "--nocapture"])
        .env("AEROBOX_TEST_CRASH_DIRECTORY", dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let path = dir.path().join("core.pid");
    while !path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if !path.exists() {
        let _ = application.kill();
        let _ = application.wait();
        panic!("crash test core did not start");
    }
    let pid: u32 = fs::read_to_string(path).unwrap().parse().unwrap();
    application.kill().unwrap();
    application.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(4);
    let alive = || {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|stat| !stat.split(") ").nth(1).unwrap_or("").starts_with('Z'))
    };
    while alive() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    let survived = alive();
    if survived {
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
    assert!(!survived, "core survived SIGKILL of its application");
}

#[test]
fn pidfd_guardian_stops_a_core_without_parent_death_signals() {
    fn pidfd(pid: u32) -> OwnedFd {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        assert!(raw >= 0);
        let original = unsafe { OwnedFd::from_raw_fd(raw) };
        let duplicate = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        assert!(duplicate >= 0);
        unsafe { OwnedFd::from_raw_fd(duplicate) }
    }
    let mut parent = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let mut core = Command::new("/bin/sleep").arg("20").spawn().unwrap();
    let parent_fd = pidfd(parent.id());
    let core_fd = pidfd(core.id());
    let p = parent_fd.as_raw_fd();
    let c = core_fd.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_AeroBox"));
    command
        .arg("--watch-core")
        .env("AEROBOX_WATCH_PARENT_FD", p.to_string())
        .env("AEROBOX_WATCH_CORE_FD", c.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(p, libc::F_SETFD, 0) < 0 || libc::fcntl(c, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut guardian = command.spawn().unwrap();
    let mut output = guardian.stdout.take().unwrap();
    let mut descriptor = libc::pollfd {
        fd: output.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut descriptor, 1, 3000) } <= 0 {
        let _ = parent.kill();
        let _ = parent.wait();
        let _ = core.kill();
        let _ = core.wait();
        let _ = guardian.kill();
        let _ = guardian.wait();
        panic!("guardian failed to acknowledge readiness");
    }
    let mut ready = [0_u8; 1];
    output.read_exact(&mut ready).unwrap();
    assert_eq!(ready, b"R"[0..1]);
    parent.kill().unwrap();
    parent.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut exited = false;
    while Instant::now() < deadline {
        if core.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    if !exited {
        let _ = core.kill();
        let _ = guardian.kill();
    }
    core.wait().unwrap();
    assert!(guardian.wait().unwrap().success());
    assert!(
        exited,
        "guardian did not terminate a core after parent exit"
    );
}

#[test]
fn offline_settings_save_without_an_installed_core() {
    let (_dir, s) = service();
    let settings = Settings {
        core_path: "/not/installed/sing-box".into(),
        theme: "dark".into(),
        tun_enabled: true,
        ..s.snapshot().settings
    };
    s.apply_settings(settings).unwrap();
    assert_eq!(s.snapshot().settings.theme, "dark");
    assert!(s.snapshot().settings.tun_enabled);
    assert!(!s.status().running);
    let mut invalid = s.snapshot().settings;
    invalid.test_url = "file:///tmp/not-a-network-test".into();
    assert!(s.apply_settings(invalid).is_err());
}

#[test]
fn stopped_system_proxy_preference_is_saved_without_changing_the_desktop() {
    let (_dir, service) = service();
    service.set_system_proxy_enabled(true).unwrap();
    assert!(service.snapshot().settings.system_proxy);
    assert!(!service.status().proxy);
    service.set_system_proxy_enabled(false).unwrap();
    assert!(!service.snapshot().settings.system_proxy);
    assert!(!service.status().proxy);
}

#[test]
fn automatic_updates_obey_intervals_preserve_failed_nodes_and_back_off() {
    let (dir, service) = service();
    let source = dir.path().join("subscription.json");
    fs::write(
        &source,
        r#"{"outbounds":[{"type":"socks","tag":"new","server":"127.0.0.1","server_port":1080}]}"#,
    )
    .unwrap();
    let old_nodes =
        vec![json!({"type":"socks","tag":"old","server":"127.0.0.1","server_port":1080})];
    let due = Subscription {
        source: source.to_string_lossy().into_owned(),
        nodes: old_nodes.clone(),
        updated: model::now() - 3601,
        update_interval_hours: 1,
        ..Subscription::default()
    };
    let id = due.id.clone();
    let disabled = Subscription {
        auto_update: false,
        ..due.clone()
    };
    let fresh = Subscription {
        updated: model::now(),
        ..due.clone()
    };
    service
        .update(|state| {
            state.subscriptions = vec![
                due,
                Subscription {
                    id: model::id(),
                    ..disabled
                },
                Subscription {
                    id: model::id(),
                    ..fresh
                },
            ];
            Ok(())
        })
        .unwrap();
    assert_eq!(service.update_due_subscriptions().unwrap(), 1);
    assert_eq!(service.subscription_revision(), 1);
    assert_eq!(service.snapshot().subscriptions[0].nodes[0]["tag"], "new");
    assert_eq!(service.snapshot().subscriptions[1].nodes, old_nodes);
    assert_eq!(service.snapshot().subscriptions[2].nodes, old_nodes);
    service
        .update(|state| {
            state.subscriptions[0].updated = 0;
            Ok(())
        })
        .unwrap();
    fs::write(&source, "invalid content").unwrap();
    assert_eq!(service.update_due_subscriptions().unwrap(), 0);
    assert_eq!(service.subscription_revision(), 1);
    assert_eq!(service.snapshot().subscriptions[0].nodes[0]["tag"], "new");
    let failed_logs = service.logs();
    assert!(failed_logs.contains("更新失败"));
    fs::write(
        &source,
        r#"{"outbounds":[{"type":"socks","tag":"retry","server":"127.0.0.1","server_port":1080}]}"#,
    )
    .unwrap();
    assert_eq!(service.update_due_subscriptions().unwrap(), 0);
    assert_eq!(
        service.logs(),
        failed_logs,
        "backoff should not produce another request or log"
    );
    service.update_subscription(&id).unwrap();
    assert_eq!(service.snapshot().subscriptions[0].nodes[0]["tag"], "retry");
    assert_eq!(service.subscription_revision(), 2);
}

#[test]
fn concurrent_manual_and_automatic_updates_do_not_override_an_edit() {
    let (_dir, service) = service();
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = server.local_addr().unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let server_worker = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let body = r#"{"outbounds":[{"type":"socks","tag":"stale","server":"127.0.0.1","server_port":1080}]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let sub = Subscription {
        source: format!("http://{address}"),
        ..Subscription::default()
    };
    let id = sub.id.clone();
    service
        .update(|state| {
            state.subscriptions.push(sub);
            Ok(())
        })
        .unwrap();
    let worker_service = service.clone();
    let worker_id = id.clone();
    let update = thread::spawn(move || worker_service.update_subscription(&worker_id));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(service.update_due_subscriptions().unwrap(), 0);
    assert!(
        service
            .update_subscription(&id)
            .unwrap_err()
            .to_string()
            .contains("正在更新")
    );
    service
        .update(|state| {
            state.subscriptions[0].source = "edited.json".into();
            Ok(())
        })
        .unwrap();
    release_tx.send(()).unwrap();
    assert!(update.join().unwrap().is_err());
    server_worker.join().unwrap();
    assert!(service.snapshot().subscriptions[0].nodes.is_empty());
    assert_eq!(service.snapshot().subscriptions[0].source, "edited.json");
}

#[test]
fn gnome_system_proxy_reaches_a_node_from_chromium_and_restores_the_session() {
    if std::env::var("SINGBOX_TEST_CORE").is_err() {
        return;
    }
    for program in ["dbus-run-session", "gsettings", "chromium"] {
        if !Command::new("which")
            .arg(program)
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            return;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut command = Command::new("dbus-run-session");
    command
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "isolated_gnome_proxy_browser_helper",
            "--nocapture",
        ])
        .env("AEROBOX_TEST_GNOME_DIRECTORY", dir.path())
        .env("XDG_CURRENT_DESKTOP", "GNOME")
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("GSETTINGS_BACKEND", "dconf");
    for key in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ] {
        command.env_remove(key);
    }
    let output = aerobox_for_linux::engine::run_command(command, Duration::from_secs(45)).unwrap();
    assert!(output.contains("Chromium system proxy -> AeroBox -> SOCKS node -> origin succeeded"));
}

#[test]
fn subscription_is_the_only_source_and_offline_choices_are_persisted() {
    let (dir, service) = service();
    assert!(service.start().is_err());
    let first = Subscription {
        nodes: vec![
            json!({"type":"direct","tag":"helper"}),
            json!({"type":"selector","tag":"group","outbounds":["proxy"]}),
            json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":10001}),
        ],
        ..Subscription::default()
    };
    let a = first.id.clone();
    service.import_subscription(first.clone()).unwrap();
    assert_eq!(service.snapshot().settings.active_subscription, a);
    assert_eq!(service.subscription_nodes(&a).unwrap().len(), 1);
    let second = Subscription {
        nodes: vec![json!({"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":10002})],
        ..Subscription::default()
    };
    let b = second.id.clone();
    service.import_subscription(second).unwrap();
    assert_eq!(service.snapshot().settings.active_subscription, b);
    service.select_subscription(&a).unwrap();
    let generated = service.generate_current().unwrap();
    let target = generated["outbounds"][0]["default"].as_str().unwrap();
    assert_ne!(target, "proxy");
    assert_eq!(
        generated["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["tag"] == target)
            .unwrap()["server_port"],
        10001
    );
    assert_eq!(service.snapshot().subscriptions[0].nodes, first.nodes);
    assert!(service.select_subscription_node(&a, "group").is_err());
    service.select_subscription_node(&b, "proxy").unwrap();
    let reopened = Service::new(Store::open(Some(dir.path().into())).unwrap());
    assert_eq!(reopened.snapshot().settings.active_subscription, b);
    assert!(reopened.subscription_nodes(&b).unwrap()[0].selected);
    reopened.delete_resource("subscriptions", &b).unwrap();
    assert_eq!(reopened.snapshot().settings.active_subscription, a);
    reopened.delete_resource("subscriptions", &a).unwrap();
    assert!(reopened.start().is_err());
}

#[test]
fn real_subscription_selection_reloads_atomically_and_keeps_nodes_across_restart() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let origin_a = TcpListener::bind("127.0.0.2:0").unwrap();
    let port = origin_a.local_addr().unwrap().port();
    let origin_b = TcpListener::bind(("127.0.0.3", port)).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let workers:Vec<_>=[(origin_a,"A"),(origin_b,"B")].into_iter().map(|(listener,body)| {
        listener.set_nonblocking(true).unwrap();let done=done.clone();
        thread::spawn(move||{let until=Instant::now()+Duration::from_secs(35);while !done.load(Ordering::Relaxed)&&Instant::now()<until {
            match listener.accept(){Ok((mut stream,_))=>{stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();let _=stream.read(&mut[0;4096]);let _=write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{body}");},Err(e)if e.kind()==std::io::ErrorKind::WouldBlock=>thread::sleep(Duration::from_millis(5)),Err(e)=>panic!("{e}")}
        }})
    }).collect();
    let (_ad, _an, ap) = controlled_node(&binary, "127.0.0.2");
    let (_bd, _bn, bp) = controlled_node(&binary, "127.0.0.3");
    let (dir, service) = service();
    let (wrapper, tls_port, _tls) = local_tls_probe(dir.path(), &binary);
    service
        .update(|s| {
            s.settings.core_path = wrapper;
            s.settings.test_url = format!("https://127.0.0.1:{tls_port}/latency");
            s.settings.test_timeout = 2000;
            Ok(())
        })
        .unwrap();
    let a = Subscription {
        nodes: vec![
            json!({"type":"socks","tag":"one","server":"127.0.0.1","server_port":ap}),
            json!({"type":"socks","tag":"two","server":"127.0.0.1","server_port":bp}),
        ],
        ..Subscription::default()
    };
    let a_id = a.id.clone();
    service.import_subscription(a).unwrap();
    let worker = service.clone();
    thread::spawn(move || worker.start())
        .join()
        .unwrap()
        .unwrap();
    thread::sleep(Duration::from_millis(150));
    service.poll();
    assert!(
        service.status().running,
        "short startup worker killed the core"
    );
    let mixed = format!("127.0.0.1:{}", service.snapshot().settings.mixed_port);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!("http://{mixed}")).unwrap())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let response = || {
        client
            .get(format!("http://choice.example:{port}/probe"))
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .unwrap()
    };
    assert_eq!(response(), "A");
    service.set_routing_mode("global").unwrap();
    assert_eq!(response(), "A");
    let certificate =
        reqwest::Certificate::from_pem(&fs::read(dir.path().join("test-ca.pem")).unwrap()).unwrap();
    for scheme in ["http", "socks5h"] {
        let tls_client = reqwest::blocking::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("{scheme}://{mixed}")).unwrap())
            .add_root_certificate(certificate.clone())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        assert_eq!(
            tls_client
                .get(format!("https://127.0.0.1:{tls_port}/request"))
                .send()
                .unwrap()
                .text()
                .unwrap(),
            "AEROBOX_HTTPS_CHAIN_OK"
        );
    }
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let original_port = service.snapshot().settings.mixed_port;
    let mut broken = service.snapshot().settings;
    broken.mixed_port = taken.local_addr().unwrap().port();
    assert!(service.apply_settings(broken).is_err());
    assert_eq!(service.snapshot().settings.mixed_port, original_port);
    assert_eq!(response(), "A");

    let pid = service.status().pid;
    let (connection, echo) = open_echo_tunnel(mixed.parse().unwrap());
    service.select_subscription_node(&a_id, "two").unwrap();
    assert_tunnel_closed(connection, echo);
    assert_eq!(service.status().pid, pid);
    assert_eq!(response(), "B");
    assert!(service.test_subscription_node(&a_id, "one").unwrap() > 0);
    assert_eq!(response(), "B");
    let path = dir.path().join("state.json");
    let backup = dir.path().join("saved");
    fs::rename(&path, &backup).unwrap();
    fs::create_dir(&path).unwrap();
    let failed = service.select_subscription_node(&a_id, "one");
    fs::remove_dir(&path).unwrap();
    fs::rename(&backup, &path).unwrap();
    assert!(failed.is_err());
    assert_eq!(response(), "B");
    assert!(service.subscription_nodes_runtime(&a_id).unwrap()[1].selected);
    service
        .api("PUT", "/proxies/proxy", Some(&json!({"name":"one"})))
        .unwrap();
    assert!(service.subscription_nodes_runtime(&a_id).unwrap()[0].selected);
    service.restart().unwrap();
    assert_eq!(response(), "B");
    assert_eq!(service.runtime_mode().unwrap(), "global");
    let bad = Subscription {
        nodes: vec![
            json!({"type":"shadowsocks","tag":"bad","server":"127.0.0.1","server_port":443,"method":"invalid-cipher","password":"fixture"}),
        ],
        ..Subscription::default()
    };
    assert!(service.import_subscription(bad).is_err());
    assert_eq!(service.snapshot().subscriptions.len(), 1);
    assert_eq!(response(), "B");
    let b = Subscription {
        nodes: vec![json!({"type":"socks","tag":"one","server":"127.0.0.1","server_port":ap})],
        ..Subscription::default()
    };
    let b_id = b.id.clone();
    service.import_subscription(b).unwrap();
    assert_eq!(service.snapshot().settings.active_subscription, b_id);
    assert_eq!(response(), "A");
    service.select_subscription(&a_id).unwrap();
    assert_eq!(response(), "B");
    let source = dir.path().join("update.json");
    fs::write(&source,serde_json::to_vec(&json!({"outbounds":[{"type":"socks","tag":"replacement","server":"127.0.0.1","server_port":ap}]})).unwrap()).unwrap();
    service
        .update(|s| {
            s.subscriptions
                .iter_mut()
                .find(|s| s.id == a_id)
                .unwrap()
                .source = source.to_string_lossy().into_owned();
            Ok(())
        })
        .unwrap();
    service.update_subscription(&a_id).unwrap();
    assert_eq!(
        service.snapshot().subscriptions[0].selected_node.as_deref(),
        Some("replacement")
    );
    assert_eq!(response(), "A");
    let reject = RuleSet {
        name: "拒绝测试".into(),
        content: json!({"version":3,"rules":[{"domain":"choice.example"}]}),
        action: "reject".into(),
        ..RuleSet::default()
    };
    let reject_id = reject.id.clone();
    service.save_ruleset(reject).unwrap();
    assert_eq!(response(), "A", "global overrides rule sets");
    service.set_routing_mode("rule").unwrap();
    assert!(
        client
            .get(format!("http://choice.example:{port}/probe"))
            .send()
            .unwrap()
            .status()
            .is_server_error()
    );
    service
        .save_rule_source(&reject_id, r#"{"version":3,"rules":[]}"#)
        .unwrap();
    assert_eq!(response(), "A");
    assert!(
        service
            .save_rule_source(
                &reject_id,
                r#"{"version":3,"rules":[{"unsupported":"field"}]}"#
            )
            .is_err()
    );
    assert_eq!(response(), "A");
    service.apply_ruleset_enabled(&reject_id, false).unwrap();
    assert_eq!(response(), "A");
    service.delete_resource("subscriptions", &a_id).unwrap();
    assert_eq!(service.snapshot().settings.active_subscription, b_id);
    assert_eq!(response(), "A");
    service.delete_resource("subscriptions", &b_id).unwrap();
    assert!(!service.status().running);
    done.store(true, Ordering::Relaxed);
    for w in workers {
        w.join().unwrap();
    }
}

#[test]
fn isolated_gnome_proxy_browser_helper() {
    let Ok(root) = std::env::var("AEROBOX_TEST_GNOME_DIRECTORY") else {
        return;
    };
    let binary = std::env::var("SINGBOX_TEST_CORE").unwrap();
    let root = std::path::PathBuf::from(root);
    let (_rd, _remote, remote_port) = controlled_node(&binary, "127.0.0.1");
    let (_dir, app) = service();
    let (_, tls_port, _tls) = local_tls_probe(&root, &binary);
    let get = |schema: &str, key: &str| {
        String::from_utf8(
            Command::new("gsettings")
                .args(["get", schema, key])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned()
    };
    let before = get("org.gnome.system.proxy", "mode");
    app.update(|s| {
        s.settings.core_path = binary;
        s.settings.system_proxy = true;
        s.settings.routing_mode = "global".into();
        Ok(())
    })
    .unwrap();
    app.import_subscription(Subscription {
        nodes: vec![
            json!({"type":"socks","tag":"node","server":"127.0.0.1","server_port":remote_port}),
        ],
        ..Subscription::default()
    })
    .unwrap();
    app.start().unwrap();
    let port = app.snapshot().settings.mixed_port;
    let endpoint = format!("127.0.0.1:{port}");
    assert!(aerobox_for_linux::platform::verify_proxy(&endpoint, "mixed").unwrap());
    assert_eq!(get("org.gnome.system.proxy", "mode"), "'manual'");
    for kind in ["http", "https", "socks"] {
        assert_eq!(
            get(&format!("org.gnome.system.proxy.{kind}"), "port"),
            port.to_string()
        );
    }
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    origin.set_nonblocking(true).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let finished = done.clone();
    let worker = thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(30);
        while !finished.load(Ordering::Relaxed) && Instant::now() < until {
            match origin.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let _ = stream.read(&mut [0; 4096]);
                    let body = "<html>AEROBOX_GNOME_PROXY_CHAIN_OK</html>";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    let mut browser = Command::new("chromium");
    browser
        .args([
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-sync",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-quic",
            "--dump-dom",
        ])
        .arg(format!(
            "--user-data-dir={}",
            root.join("browser").display()
        ))
        .arg(format!(
            "http://aerobox.proxy.test:{origin_port}/through-system-proxy"
        ));
    let output = aerobox_for_linux::engine::run_command(browser, Duration::from_secs(25));
    done.store(true, Ordering::Relaxed);
    worker.join().unwrap();
    assert!(output.unwrap().contains("AEROBOX_GNOME_PROXY_CHAIN_OK"));
    assert!(app.traffic().unwrap().download > 0);
    let mut browser = Command::new("chromium");
    browser
        .args([
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-sync",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-quic",
            "--ignore-certificate-errors",
            "--dump-dom",
        ])
        .arg(format!(
            "--user-data-dir={}",
            root.join("browser-tls").display()
        ))
        .arg(format!(
            "https://aerobox.proxy.test:{tls_port}/through-system-proxy"
        ));
    let output = aerobox_for_linux::engine::run_command(browser, Duration::from_secs(20)).unwrap();
    assert!(output.contains("AEROBOX_HTTPS_CHAIN_OK"));
    Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.https", "port", "9"])
        .status()
        .unwrap();
    assert!(!aerobox_for_linux::platform::verify_proxy(&endpoint, "mixed").unwrap());
    app.set_system_proxy_enabled(true).unwrap();
    assert!(aerobox_for_linux::platform::verify_proxy(&endpoint, "mixed").unwrap());
    app.stop().unwrap();
    assert_eq!(get("org.gnome.system.proxy", "mode"), before);
    println!(
        "Chromium system proxy -> AeroBox -> SOCKS node -> origin succeeded; HTTP/HTTPS/SOCKS readback verified; overwritten setting detected; previous mode restored"
    );
}

#[test]
fn real_shadowsocks_import_carries_https_through_http_and_socks_entries() {
    let Ok(binary) = std::env::var("SINGBOX_TEST_CORE") else {
        return;
    };
    let (dir, service) = service();
    let (_, tls_port, _tls) = local_tls_probe(dir.path(), &binary);
    let ss_port = free_port();
    let fixture = dir.path().join("ss-server.json");
    fs::write(&fixture,serde_json::to_vec(&json!({"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":ss_port,"method":"aes-128-gcm","password":"fixture-secret"}],"outbounds":[{"type":"direct","tag":"direct"}]})).unwrap()).unwrap();
    let _remote = FixtureProcess(
        Command::new(&binary)
            .args(["run", "-c"])
            .arg(fixture)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    service
        .update(|s| {
            s.settings.core_path = binary;
            s.settings.routing_mode = "global".into();
            Ok(())
        })
        .unwrap();
    let source = json!({"proxies":[{"name":"SS fixture","type":"ss","server":"127.0.0.1","port":ss_port,"cipher":"aes-128-gcm","password":"fixture-secret","udp":true}]});
    service
        .import_subscription(Subscription {
            nodes: aerobox_for_linux::subscription::parse(&source.to_string()).unwrap(),
            ..Subscription::default()
        })
        .unwrap();
    service.start().unwrap();
    let port = service.snapshot().settings.mixed_port;
    let certificate =
        reqwest::Certificate::from_pem(&fs::read(dir.path().join("test-ca.pem")).unwrap()).unwrap();
    for scheme in ["http", "socks5h"] {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("{scheme}://127.0.0.1:{port}")).unwrap())
            .add_root_certificate(certificate.clone())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        assert_eq!(
            client
                .get(format!("https://127.0.0.1:{tls_port}/tls"))
                .send()
                .unwrap()
                .text()
                .unwrap(),
            "AEROBOX_HTTPS_CHAIN_OK"
        );
    }
    assert!(service.logs().contains("shadowsocks"));
    service.stop().unwrap();
}
