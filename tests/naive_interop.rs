//! Optional Service-level interoperability with the independent Go Naive peer.
//! Build vendor/shoes/tests/fixtures/naive-peer, then set AEROBOX_NAIVE_PEER and
//! run `cargo test --test naive_interop -- --ignored --nocapture`.
mod support;
#[path = "support/udp_policy.rs"]
mod udp_policy;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

struct Peer {
    child: Child,
    reader: Option<thread::JoinHandle<()>>,
    log: PathBuf,
}
impl Peer {
    fn start(executable: &Path, directory: &Path) -> (Self, Value) {
        let log = directory.join("naive-peer.log");
        let mut child = Command::new(executable)
            .current_dir(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .expect("cannot start AEROBOX_NAIVE_PEER");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout.take(64 * 1024))
                .read_line(&mut line)
                .map(|_| line);
            let _ = tx.send(result);
        });
        let peer = Self {
            child,
            reader: Some(reader),
            log,
        };
        let line = rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|error| {
                panic!(
                    "Naive peer did not report readiness: {error}\n{}",
                    peer.logs()
                )
            })
            .expect("cannot read Naive peer readiness");
        let settings = serde_json::from_str(&line).unwrap_or_else(|error| {
            panic!("invalid Naive peer readiness: {error}\n{}", peer.logs())
        });
        (peer, settings)
    }
    fn logs(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn certificate_pem(encoded: &str) -> String {
    let certificate = STANDARD
        .decode(encoded)
        .expect("invalid peer DER certificate");
    let encoded = STANDARD.encode(certificate);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn socks_echo(port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(8)))?;
    stream.write_all(&[5, 1, 0])?;
    let mut method = [0; 2];
    stream.read_exact(&mut method)?;
    assert_eq!(method, [5, 0]);
    let host = b"echo.test";
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443u16.to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply)?;
    assert_eq!(&reply[..3], &[5, 0, 0], "SOCKS CONNECT failed: {reply:?}");
    let length = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0];
            stream.read_exact(&mut length)?;
            length[0] as usize
        }
        other => panic!("unexpected SOCKS address type {other}"),
    };
    stream.read_exact(&mut vec![0; length + 2])?;
    Ok(stream)
}

fn exchange_and_half_close(mut stream: TcpStream, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut writer = stream.try_clone()?;
    thread::scope(|scope| {
        let upload = scope.spawn(move || -> io::Result<()> {
            // Vary write boundaries so framing cannot rely on one socket write
            // corresponding to one HTTP frame or one Naive padding frame.
            for part in payload.chunks(7919) {
                writer.write_all(part)?;
            }
            writer.flush()?;
            writer.shutdown(Shutdown::Write)
        });
        let mut echoed = Vec::new();
        let downloaded = stream.read_to_end(&mut echoed);
        let uploaded = upload.join().unwrap();
        downloaded?;
        uploaded?;
        Ok(echoed)
    })
}

#[test]
#[ignore = "requires the independent Go fixture executable in AEROBOX_NAIVE_PEER"]
fn service_naive_http2_and_http3_preserve_large_payloads_and_half_close() {
    let _serial = support::runtime_lock();
    let executable = PathBuf::from(
        std::env::var_os("AEROBOX_NAIVE_PEER")
            .expect("set AEROBOX_NAIVE_PEER to the built Go fixture"),
    )
    .canonicalize()
    .expect("AEROBOX_NAIVE_PEER does not exist");
    let directory = tempfile::tempdir().unwrap();
    let (peer, settings) = Peer::start(&executable, directory.path());
    let certificate = certificate_pem(settings["certificate"].as_str().unwrap());
    for quic in [false, true] {
        let protocol = if quic { "HTTP/3" } else { "HTTP/2" };
        let port =
            u16::try_from(settings[if quic { "h3" } else { "h2" }].as_u64().unwrap()).unwrap();
        for tcp_only in [false, true] {
            let description = format!("{protocol}, tcp_only={tcp_only}");
            let app = support::App::new();
            app.service
                .update(|state| {
                    // Every endpoint is local or handled by the peer. No public DNS
                    // or origin connection is needed for this interoperability case.
                    state.settings.direct_dns = "udp://127.0.0.1:9".into();
                    state.settings.remote_dns = "tcp://127.0.0.1:9".into();
                    Ok(())
                })
                .unwrap();
            let mut node = json!({
                "type":"naive", "tag":protocol, "server":"127.0.0.1", "server_port":port,
                "username":"user", "password":"pass", "quic":quic,
                "tls":{"enabled":true,"server_name":"localhost","certificate":certificate}
            });
            if tcp_only {
                node["network"] = "tcp".into();
                // UoT availability must not override the selected payload network,
                // including the HTTP/3 connector which bypasses the TCP factory.
                node["udp_over_tcp"] = json!({"enabled":true,"version":2});
            }
            app.import(&description, vec![node]);
            app.service
                .start()
                .unwrap_or_else(|error| panic!("{description} start: {error:#}"));
            let inbound = app.service.snapshot().settings.mixed_port;
            // A small stream and a larger stream exercise reuse and cross many
            // HTTP flow-control windows; EOF must propagate after half-close.
            for length in [4097, 512 * 1024] {
                let payload: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
                let result = socks_echo(inbound)
                    .and_then(|stream| exchange_and_half_close(stream, &payload));
                assert_eq!(
                    result.unwrap_or_else(|error| panic!(
                        "{description}, {length} bytes: {error}\nclient:\n{}\npeer:\n{}",
                        app.service.logs(),
                        peer.logs()
                    )),
                    payload,
                    "{description} truncated or changed the echoed payload"
                );
                if tcp_only {
                    udp_policy::assert_udp_blocked(inbound).unwrap_or_else(|error| {
                        panic!(
                            "{description} UDP rejection: {error}\n{}",
                            app.service.logs()
                        )
                    });
                }
            }
            app.service.stop().unwrap();
            let _available = TcpListener::bind(("127.0.0.1", inbound)).unwrap();
            eprintln!("independent Naive {description}: Service TCP payload and half-close passed");
        }
    }
}
