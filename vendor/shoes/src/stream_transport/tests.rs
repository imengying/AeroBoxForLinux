use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
fn handler(kind: Kind) -> Handler {
    Handler::new(
        Config {
            kind,
            host: Some("edge.example".into()),
            path: "/tunnel?q=1".into(),
            method: "PUT".into(),
            service_name: "GunService".into(),
            headers: HashMap::new(),
            idle_timeout_ms: None,
            ping_timeout_ms: None,
            permit_without_stream: false,
            protocol: Box::new(()),
        },
        "ignored:443".into(),
        Box::new(crate::port_forward_handler::PortForwardClientHandler),
    )
    .unwrap()
}
async fn head(stream: &mut tokio::io::DuplexStream) -> String {
    let mut data = Vec::new();
    while !data.ends_with(b"\r\n\r\n") {
        data.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(data).unwrap()
}
#[tokio::test]
async fn http_upgrade_preserves_coalesced_bytes_and_checks_tokens() {
    for valid in [true, false] {
        let (client, mut server) = duplex(64);
        let peer = tokio::spawn(async move {
            let request = head(&mut server).await;
            assert!(request.starts_with("GET /tunnel?q=1 HTTP/1.1\r\nHost: edge.example\r\n"));
            let connection = if valid {
                "keep-alive, Upgrade"
            } else {
                "keep-alive"
            };
            server.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nConnection: {connection}\r\nUpgrade: WebSocket\r\n\r\npayload").as_bytes()).await.unwrap();
        });
        let result = handler(Kind::HttpUpgrade).wrap(Box::new(client)).await;
        if valid {
            let mut bytes = Vec::new();
            result.unwrap().read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"payload");
        } else {
            assert!(result.is_err());
        }
        peer.await.unwrap();
    }
}
#[tokio::test]
async fn http1_upload_precedes_response_and_uses_raw_stream() {
    let (client, mut server) = duplex(64);
    let peer = tokio::spawn(async move {
        assert!(
            head(&mut server)
                .await
                .starts_with("PUT /tunnel?q=1 HTTP/1.1")
        );
        let mut payload = [0; 3];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"abc");
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nraw-reply")
            .await
            .unwrap();
    });
    let mut stream = handler(Kind::Http1).wrap(Box::new(client)).await.unwrap();
    stream.write_all(b"abc").await.unwrap();
    stream.flush().await.unwrap();
    let mut output = Vec::new();
    stream.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, b"raw-reply");
    peer.await.unwrap();
}
#[tokio::test]
async fn grpc_wire_frame_partial_io_and_malformed_input() {
    // Independent wire fixture: gRPC envelope, protobuf field 1, "abc".
    const FRAME: &[u8] = b"\x00\x00\x00\x00\x05\x0a\x03abc";
    let (client, mut peer) = duplex(1);
    let task = tokio::spawn(async move {
        let mut received = [0; 10];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, FRAME);
        peer.write_all(FRAME).await.unwrap();
    });
    let mut stream = grpc::GrpcStream::new(client);
    stream.write_all(b"abc").await.unwrap();
    stream.flush().await.unwrap();
    let mut out = [0; 3];
    for byte in &mut out {
        *byte = stream.read_u8().await.unwrap();
    }
    assert_eq!(&out, b"abc");
    task.await.unwrap();
    for bad in [
        &b"\x01\x00\x00\x00\x05\x0a\x03abc"[..],
        &b"\x00\x00\x00\x00\x04\x0a\x03abc"[..],
        &FRAME[..8],
    ] {
        let mut stream = grpc::GrpcStream::new(bad);
        let mut out = Vec::new();
        assert!(stream.read_to_end(&mut out).await.is_err());
    }
}
#[tokio::test]
async fn h2_and_grpc_do_not_wait_for_headers_before_upload() {
    for grpc in [false, true] {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (client, server) = duplex(1024);
            let peer = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server).await.unwrap();
                let (request, mut response) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.method(), if grpc { "POST" } else { "PUT" });
                assert_eq!(
                    request.uri().path(),
                    if grpc { "/GunService/Tun" } else { "/tunnel" }
                );
                let mut recv = request.into_body();
                // Drive the connection while the application waits for request data.
                let job = tokio::spawn(async move {
                    let bytes = recv.data().await.unwrap().unwrap();
                    assert_eq!(
                        &bytes[..],
                        if grpc {
                            &b"\x00\x00\x00\x00\x05\x0a\x03abc"[..]
                        } else {
                            &b"abc"[..]
                        }
                    );
                    recv.flow_control().release_capacity(bytes.len()).unwrap();
                    let mut reply = http::Response::builder().status(200);
                    if grpc {
                        reply = reply.header("content-type", "application/grpc");
                    }
                    let mut send = response
                        .send_response(reply.body(()).unwrap(), false)
                        .unwrap();
                    send.send_data(bytes, false).unwrap();
                    let mut trailers = http::HeaderMap::new();
                    if grpc {
                        trailers.insert("grpc-status", "0".parse().unwrap());
                    }
                    send.send_trailers(trailers).unwrap();
                    while let Some(data) = recv.data().await {
                        let data = data.unwrap();
                        recv.flow_control().release_capacity(data.len()).unwrap();
                    }
                });
                // accept() keeps polling IO until the client drops the connection.
                while connection.accept().await.is_some() {}
                job.await.unwrap();
            });
            let kind = if grpc { Kind::Grpc } else { Kind::Http2 };
            let mut stream = handler(kind).wrap(Box::new(client)).await.unwrap();
            stream.write_all(b"abc").await.unwrap();
            stream.flush().await.unwrap();
            let mut output = [0; 3];
            stream.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"abc");
            assert_eq!(
                stream.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            stream.shutdown().await.unwrap();
            drop(stream);
            peer.abort();
        })
        .await
        .expect("late response must not deadlock upload");
    }
}
#[test]
fn injected_headers_are_rejected() {
    let mut config = handler(Kind::HttpUpgrade).options;
    config
        .headers
        .insert("X-Test".into(), "value\r\nInjected: yes".into());
    assert!(config.validate().is_err());
    config.headers.clear();
    config.path = "/ HTTP/1.1\r\n".into();
    assert!(config.validate().is_err());
    config.path = "/".into();
    config.headers.insert("Content-Length".into(), "3".into());
    assert!(config.validate().is_err());
}

#[tokio::test(start_paused = true)]
async fn zero_and_absent_ping_timeout_use_fifteen_seconds() {
    for kind in [Kind::Grpc, Kind::Http2] {
        for ping_timeout_ms in [None, Some(0)] {
            let (client, peer) = duplex(8192);
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                let connection = h2::server::handshake(peer).await.unwrap();
                ready_tx.send(()).unwrap();
                std::future::pending::<()>().await;
                drop(connection);
            });
            let mut handler = handler(kind);
            handler.options.idle_timeout_ms = Some(5_000);
            handler.options.ping_timeout_ms = ping_timeout_ms;
            let mut stream = handler.wrap(Box::new(client)).await.unwrap();
            ready_rx.await.unwrap();
            tokio::time::sleep(Duration::from_secs(6)).await;
            assert!(
                tokio::time::timeout(Duration::from_secs(1), stream.read_u8())
                    .await
                    .is_err(),
                "default PING deadline must not expire early"
            );
            let error = tokio::time::timeout(Duration::from_secs(14), stream.read_u8())
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::TimedOut,
                "kind={kind:?}, ping_timeout_ms={ping_timeout_ms:?}: {error}"
            );
            peer.abort();
            let _ = peer.await;
        }
    }
}
