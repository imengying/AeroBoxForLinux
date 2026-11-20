use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[tokio::test(start_paused = true)]
async fn configured_keepalive_respects_idle_sessions_and_disabled_checks() {
    for (enabled, permit) in [(true, false), (true, true), (false, true)] {
        let (client, peer) = tokio::io::duplex(8192);
        let (ready_tx, ready_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let connection = h2::server::handshake(peer).await.unwrap();
            ready_tx.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(connection);
        });
        let session = H2ClientSession::with_keepalive(
            Box::new(client),
            KeepAlive {
                idle_timeout: enabled.then_some(Duration::from_secs(5)),
                ping_timeout: Duration::from_secs(2),
                permit_without_stream: permit,
            },
        )
        .await
        .unwrap();
        ready_rx.await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(
            session.is_ready(),
            !enabled || !permit,
            "enabled={enabled}, permit={permit}"
        );
        if !permit || !enabled {
            let reservation = session.reserve();
            tokio::time::sleep(Duration::from_secs(10)).await;
            assert_eq!(
                session.is_ready(),
                !enabled,
                "active session, enabled={enabled}"
            );
            drop(reservation);
        }
        server.abort();
        let _ = server.await;
    }
}

async fn frame(peer: &mut DuplexStream, kind: u8, flags: u8, id: u32, bytes: &[u8]) {
    peer.write_all(&(bytes.len() as u32).to_be_bytes()[1..])
        .await
        .unwrap();
    peer.write_all(&[kind, flags]).await.unwrap();
    peer.write_all(&id.to_be_bytes()).await.unwrap();
    peer.write_all(bytes).await.unwrap();
}

async fn read_frame(peer: &mut DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0; 9];
    peer.read_exact(&mut header).await.unwrap();
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let id = u32::from_be_bytes(header[5..].try_into().unwrap());
    let mut data = vec![0; length];
    peer.read_exact(&mut data).await.unwrap();
    (header[3], header[4], id, data)
}

async fn next_ping(peer: &mut DuplexStream) -> Vec<u8> {
    loop {
        let (kind, flags, id, data) = read_frame(peer).await;
        if kind == 6 {
            assert_eq!((flags, id, data.len()), (0, 0, 8));
            return data;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn incoming_frames_postpone_ping_and_missing_pong_closes_active_tunnel() {
    let (client, mut peer) = tokio::io::duplex(8192);
    let session = H2ClientSession::with_keepalive(
        Box::new(client),
        KeepAlive {
            idle_timeout: Some(Duration::from_secs(5)),
            ping_timeout: Duration::from_secs(2),
            permit_without_stream: false,
        },
    )
    .await
    .unwrap();
    let mut stream = session
        .reserve()
        .open_late(
            Request::builder()
                .method("PUT")
                .uri("https://example.com/tunnel")
                .body(())
                .unwrap(),
            false,
        )
        .await
        .unwrap();
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    frame(&mut peer, 4, 0, 0, &[]).await;
    let stream_id = loop {
        let (kind, flags, id, _) = read_frame(&mut peer).await;
        if kind == 4 && flags == 0 {
            frame(&mut peer, 4, 1, 0, &[]).await;
        }
        if kind == 1 {
            break id;
        }
    };
    // HPACK's indexed :status=200. No dependency on the client's H2 encoder.
    frame(&mut peer, 1, 4, stream_id, &[0x88]).await;
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_secs(4)).await;
        frame(&mut peer, 0, 0, stream_id, b"x").await;
        assert_eq!(stream.read_u8().await.unwrap(), b'x');
        assert!(
            tokio::time::timeout(Duration::from_millis(1), next_ping(&mut peer))
                .await
                .is_err(),
            "received DATA must postpone the next PING"
        );
    }
    let ping = tokio::time::timeout(Duration::from_secs(6), next_ping(&mut peer))
        .await
        .unwrap();
    frame(&mut peer, 6, 1, 0, &ping).await;
    // Reading another DATA ensures both PONG and DATA have reached the driver.
    frame(&mut peer, 0, 0, stream_id, b"y").await;
    assert_eq!(stream.read_u8().await.unwrap(), b'y');
    assert!(session.is_ready());
    let _unacknowledged = tokio::time::timeout(Duration::from_secs(6), next_ping(&mut peer))
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(3), stream.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
    assert!(!session.is_ready());
    assert!(session.driver_handle.driver.is_finished());
}
