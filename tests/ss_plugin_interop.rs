mod support;

use aerobox_for_linux::subscription;
use serde_json::json;
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires AEROBOX_OBFS_PEER built from vendor/shoes/tests/fixtures/obfs-peer"]
fn imported_plugins_carry_payload_through_the_application() {
    let _serial = support::runtime_lock();
    let executable = std::env::var_os("AEROBOX_OBFS_PEER").expect("set AEROBOX_OBFS_PEER");
    for (mode, tls, mux) in [
        ("http", false, 0),
        ("tls", false, 0),
        ("ws", false, 0),
        ("wsmux", true, 8),
        ("quic", true, 8),
    ] {
        eprintln!("application plugin: {mode}, TLS={tls}, mux={mux}");
        let certificates = tempfile::tempdir().unwrap();
        let mut command = Command::new(&executable);
        command
            .args([mode, "aes-128-gcm"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if tls {
            command
                .env("AEROBOX_PEER_TLS", "1")
                .env("AEROBOX_PEER_CERT_DIR", certificates.path());
        }
        let mut peer = Peer(command.spawn().unwrap());
        let output = peer.0.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(BufReader::new(output).lines().next());
        });
        let port: u16 = receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap()
            .unwrap()
            .parse()
            .unwrap();
        let obfs = matches!(mode, "http" | "tls");
        let mut options = if obfs {
            json!({"mode":mode,"host":"cdn.example"})
        } else {
            json!({"mode":if mode == "quic" {"quic"} else {"websocket"},"host":"localhost","path":"/tunnel","tls":tls,"mux":mux})
        };
        if tls {
            options["cert"] = certificates
                .path()
                .join("ca.pem")
                .to_string_lossy()
                .into_owned()
                .into();
        }
        let source = json!({"proxies":[{"name":"fixture","type":"ss","server":"127.0.0.1","port":port,"cipher":"aes-128-gcm","password":"aerobox-reference","plugin":if obfs {"obfs"} else {"v2ray-plugin"},"plugin-opts":options}]});
        let app = support::App::new();
        app.service
            .import_subscription(subscription::import_input(&source.to_string()).unwrap())
            .unwrap();
        // Importing only adds data; the fixture selects the subscription it
        // just created before starting the connection.
        let id = app.service.snapshot().subscriptions[0].id.clone();
        app.service.select_subscription(&id).unwrap();
        app.service.start().unwrap();
        let mut stream = support::echo_tunnel(&app.service, "192.0.2.1:443".parse().unwrap());
        for size in [1, 1400, 32768] {
            let sent: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            stream.write_all(&sent).unwrap();
            let mut received = vec![0; size];
            stream
                .read_exact(&mut received)
                .unwrap_or_else(|error| panic!("{mode}: {error}"));
            assert_eq!(received, sent, "{mode}");
        }
        app.service.stop().unwrap();
    }
}
