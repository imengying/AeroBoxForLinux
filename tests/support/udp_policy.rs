use std::{
    io::{self, Read, Write},
    net::{TcpStream, UdpSocket},
    time::Duration,
};

/// Observe both ends: a disabled node must neither relay UDP nor leak it to a
/// direct/alternate route. Keep the SOCKS association alive for the assertion.
pub fn assert_udp_blocked(inbound: u16) -> io::Result<()> {
    let origin = UdpSocket::bind("127.0.0.1:0")?;
    origin.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut association = TcpStream::connect(("127.0.0.1", inbound))?;
    association.set_read_timeout(Some(Duration::from_secs(3)))?;
    association.set_write_timeout(Some(Duration::from_secs(3)))?;
    association.write_all(&[5, 1, 0])?;
    let mut hello = [0; 2];
    association.read_exact(&mut hello)?;
    assert_eq!(hello, [5, 0]);
    association.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let mut reply = [0; 10];
    association.read_exact(&mut reply)?;
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend_from_slice(&origin.local_addr()?.port().to_be_bytes());
    packet.extend_from_slice(b"TCP-only node must reject this datagram");
    socket.send_to(
        &packet,
        ("127.0.0.1", u16::from_be_bytes([reply[8], reply[9]])),
    )?;
    assert_no_datagram(origin.recv_from(&mut [0; 128]), "UDP target");
    assert_no_datagram(socket.recv_from(&mut [0; 128]), "SOCKS client");
    Ok(())
}

fn assert_no_datagram<T: std::fmt::Debug>(result: io::Result<T>, endpoint: &str) {
    assert!(
        matches!(&result, Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)),
        "UDP unexpectedly reached {endpoint}: {result:?}"
    );
}
