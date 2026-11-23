//! Per-outbound socket policy. Android uses the same Linux socket options;
//! unsupported requested capabilities fail before a connection is created.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::{io, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialDuration(pub Duration);

impl DialDuration {
    /// Parse positive Go-style duration components without floating point.
    /// Zero means the dialer's default; negative settings are rejected.
    pub fn parse(value: &str) -> io::Result<Self> {
        let value = value.strip_prefix('+').unwrap_or(value);
        if value == "0" {
            return Ok(Self(Duration::ZERO));
        }
        if value.is_empty() || value.len() > 256 || value.starts_with('-') {
            return Err(invalid("expected a non-negative duration with units"));
        }
        let mut remaining = value;
        let mut total = 0u128;
        while !remaining.is_empty() {
            let digits = remaining.bytes().take_while(u8::is_ascii_digit).count();
            let whole: u128 = if digits == 0 {
                0
            } else {
                remaining[..digits]
                    .parse()
                    .map_err(|_| invalid("duration overflow"))?
            };
            remaining = &remaining[digits..];
            let mut fraction = 0u128;
            let mut scale = 1u128;
            let mut fractional_digits = 0;
            if let Some(after_dot) = remaining.strip_prefix('.') {
                fractional_digits = after_dot.bytes().take_while(u8::is_ascii_digit).count();
                if fractional_digits == 0 {
                    return Err(invalid("missing digits after decimal point"));
                }
                for digit in after_dot.bytes().take(fractional_digits.min(18)) {
                    fraction = fraction * 10 + u128::from(digit - b'0');
                    scale *= 10;
                }
                remaining = &after_dot[fractional_digits..];
            }
            if digits == 0 && fractional_digits == 0 {
                return Err(invalid("missing duration number"));
            }
            let (unit, multiplier) = [
                ("ns", 1u128),
                ("us", 1_000),
                ("µs", 1_000),
                ("μs", 1_000),
                ("ms", 1_000_000),
                ("s", 1_000_000_000),
                ("m", 60_000_000_000),
                ("h", 3_600_000_000_000),
            ]
            .into_iter()
            .find(|(unit, _)| remaining.starts_with(unit))
            .ok_or_else(|| invalid("expected ns/us/µs/ms/s/m/h duration unit"))?;
            remaining = &remaining[unit.len()..];
            let component = whole
                .checked_mul(multiplier)
                .and_then(|value| value.checked_add(fraction * multiplier / scale))
                .ok_or_else(|| invalid("duration overflow"))?;
            total = total
                .checked_add(component)
                .filter(|total| *total <= i64::MAX as u128)
                .ok_or_else(|| invalid("duration exceeds Go's signed nanosecond range"))?;
        }
        Ok(Self(Duration::from_nanos(total as u64)))
    }
}

impl Serialize for DialDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{}ns", self.0.as_nanos()))
    }
}
impl<'de> Deserialize<'de> for DialDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DialOptions {
    pub tcp_fast_open: bool,
    pub tcp_multi_path: bool,
    pub udp_fragment: Option<bool>,
}
impl DialOptions {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&self) -> io::Result<()> {
        #[cfg(not(target_os = "linux"))]
        if self.tcp_fast_open || self.tcp_multi_path || self.udp_fragment.is_some() {
            return Err(unsupported("socket options require Linux"));
        }
        Ok(())
    }
    pub fn apply_tcp(&self, socket: SockRef<'_>) -> io::Result<()> {
        self.validate()?;
        #[cfg(target_os = "linux")]
        if self.tcp_fast_open {
            set_int(&socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT, 1)?;
        }
        Ok(())
    }
    pub fn tcp_socket(&self, is_ipv6: bool) -> io::Result<Socket> {
        self.validate()?;
        let protocol = if self.tcp_multi_path {
            #[cfg(target_os = "linux")]
            {
                Protocol::from(libc::IPPROTO_MPTCP)
            }
            #[cfg(not(target_os = "linux"))]
            return Err(unsupported(
                "MPTCP sockets are unavailable on this platform",
            ));
        } else {
            Protocol::TCP
        };
        let socket = Socket::new(
            if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 },
            Type::STREAM,
            Some(protocol),
        )?;
        socket.set_nonblocking(true)?;
        self.apply_tcp(SockRef::from(&socket))?;
        Ok(socket)
    }

    pub fn apply_udp(&self, socket: SockRef<'_>, is_ipv6: bool) -> io::Result<()> {
        self.validate()?;
        #[cfg(target_os = "linux")]
        {
            let discovery = if self.udp_fragment.unwrap_or(false) {
                libc::IP_PMTUDISC_DONT
            } else {
                libc::IP_PMTUDISC_DO
            };
            // IPv6 sockets may also send IPv4-mapped packets, so configure both.
            set_int(&socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, discovery)?;
            if is_ipv6 {
                set_int(
                    &socket,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    discovery,
                )?;
                set_int(
                    &socket,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_DONTFRAG,
                    i32::from(!self.udp_fragment.unwrap_or(false)),
                )?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (socket, is_ipv6);
        Ok(())
    }

    /// Quinn initializes its own PMTU/DF policy while wrapping a socket. Apply
    /// explicit overrides afterwards, through a temporary duplicate, and keep
    /// the reported fragmentation capability consistent with the OS state.
    pub fn wrap_quic_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<std::sync::Arc<dyn quinn::AsyncUdpSocket>> {
        self.validate()?;
        let Some(fragmentation) = self.udp_fragment else {
            return quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket);
        };
        socket.set_nonblocking(true)?;
        let policy_socket = socket.try_clone()?;
        let is_ipv6 = policy_socket.local_addr()?.is_ipv6();
        let inner = quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)?;
        self.apply_udp(SockRef::from(&policy_socket), is_ipv6)?;
        Ok(std::sync::Arc::new(QuicPolicySocket {
            inner,
            fragmentation,
        }))
    }
}
#[derive(Debug)]
struct QuicPolicySocket {
    inner: std::sync::Arc<dyn quinn::AsyncUdpSocket>,
    fragmentation: bool,
}
impl quinn::AsyncUdpSocket for QuicPolicySocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buffers: &mut [io::IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, buffers, metadata)
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.fragmentation
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
#[cfg(not(target_os = "linux"))]
fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(target_os = "linux")]
fn set_int(
    socket: &SockRef<'_>,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: socket owns a live descriptor; value is an initialized c_int,
    // and its pointer/length remain valid for the synchronous OS call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn get(fd: &impl AsRawFd, level: i32, option: i32) -> i32 {
        let mut value = 0i32;
        let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: owning descriptor and initialized, correctly sized output buffer.
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    level,
                    option,
                    (&mut value as *mut i32).cast(),
                    &mut size,
                )
            },
            0
        );
        value
    }
    #[tokio::test]
    async fn mptcp_socket_exchanges_data_with_plain_tcp_peer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let options = DialOptions {
            tcp_multi_path: true,
            ..Default::default()
        };
        let socket = options.tcp_socket(false).unwrap();
        assert_eq!(
            get(&socket, libc::SOL_SOCKET, libc::SO_PROTOCOL),
            libc::IPPROTO_MPTCP
        );
        let socket = tokio::net::TcpSocket::from_std_stream(socket.into());
        let mut client = socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        client.write_all(b"MPTCP").await.unwrap();
        let mut data = [0; 5];
        server.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"MPTCP");
    }
    #[tokio::test]
    async fn udp_and_quic_fragmentation_policy_matches_ipv4_and_ipv6_sockets() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            for fragment in [false, true] {
                let socket = std::net::UdpSocket::bind(address).unwrap();
                let duplicate = socket.try_clone().unwrap();
                let options = DialOptions {
                    udp_fragment: Some(fragment),
                    ..Default::default()
                };
                let wrapped = options.wrap_quic_socket(socket).unwrap();
                assert_eq!(wrapped.may_fragment(), fragment);
                assert_eq!(
                    get(&duplicate, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
                    if fragment {
                        libc::IP_PMTUDISC_DONT
                    } else {
                        libc::IP_PMTUDISC_DO
                    }
                );
                if address.starts_with('[') {
                    assert_eq!(
                        get(&duplicate, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG),
                        i32::from(!fragment)
                    );
                }
            }
        }
    }
}
