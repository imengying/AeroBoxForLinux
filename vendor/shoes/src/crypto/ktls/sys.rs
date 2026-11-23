//! Linux TLS ULP ABI. No raw descriptor escapes the owning TCP stream.
use rustls::{ConnectionTrafficSecrets, ProtocolVersion};
use std::{io, os::fd::AsRawFd};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

const SOL_TLS: i32 = 282;

fn set(tcp: &TcpStream, level: i32, option: i32, bytes: &[u8]) -> io::Result<()> {
    // SAFETY: the live socket and initialized slice remain valid for the syscall.
    let result = unsafe {
        libc::setsockopt(
            tcp.as_raw_fd(),
            level,
            option,
            bytes.as_ptr().cast(),
            bytes.len() as _,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn enable(tcp: &TcpStream) -> io::Result<()> {
    set(tcp, libc::IPPROTO_TCP, libc::TCP_ULP, b"tls\0")
}

pub(super) fn keys(
    tcp: &TcpStream,
    tx: bool,
    version: ProtocolVersion,
    seq: u64,
    secret: &ConnectionTrafficSecrets,
) -> io::Result<()> {
    let (cipher, key, iv) = match secret {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (51u16, key.as_ref(), iv.as_ref()),
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (52u16, key.as_ref(), iv.as_ref()),
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            (54u16, key.as_ref(), iv.as_ref())
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported kTLS cipher",
            ));
        }
    };
    // linux/tls.h: u16 version, u16 cipher, IV, key, salt, big-endian sequence.
    let mut bytes = Zeroizing::new(Vec::with_capacity(64));
    bytes.extend_from_slice(&u16::from(version).to_ne_bytes());
    bytes.extend_from_slice(&cipher.to_ne_bytes());
    bytes.extend_from_slice(if cipher == 54 { iv } else { &iv[4..] });
    bytes.extend_from_slice(key);
    if cipher != 54 {
        bytes.extend_from_slice(&iv[..4]);
    }
    bytes.extend_from_slice(&seq.to_be_bytes());
    set(tcp, SOL_TLS, if tx { 1 } else { 2 }, &bytes).map_err(|error| {
        if error.raw_os_error() == Some(libc::EBUSY) && version == ProtocolVersion::TLSv1_3 {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "this Linux kernel lacks kTLS TLS 1.3 KeyUpdate support (requires Linux 6.14+)",
            )
        } else {
            error
        }
    })
}

pub(super) fn send(tcp: &TcpStream, kind: u8, data: &[u8]) -> io::Result<usize> {
    // usize alignment is sufficient for cmsghdr on both supported architectures.
    let mut control = [0usize; 8];
    let mut vector = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    // SAFETY: msghdr is a plain C struct with a valid all-zero representation.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut vector;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    // SAFETY: control is aligned and larger than CMSG_SPACE(1); all pointers refer
    // to live buffers. sendmsg reads data and control for this call only.
    let result = unsafe {
        msg.msg_controllen = libc::CMSG_SPACE(1) as usize;
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_level = SOL_TLS;
        (*header).cmsg_type = 1;
        (*header).cmsg_len = libc::CMSG_LEN(1) as usize;
        *libc::CMSG_DATA(header) = kind;
        libc::sendmsg(
            tcp.as_raw_fd(),
            &msg,
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

pub(super) fn receive(tcp: &TcpStream, data: &mut [u8]) -> io::Result<(usize, u8)> {
    let mut control = [0usize; 8];
    let mut vector = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    // SAFETY: all-zero msghdr is valid; output buffers below are fully sized.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut vector;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control);
    // SAFETY: exclusive output buffers and owning socket live for this syscall.
    let result = unsafe { libc::recvmsg(tcp.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated kTLS record/control data",
        ));
    }
    let mut kind = 23;
    // SAFETY: libc walks only the initialized control area written by recvmsg.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            if (*header).cmsg_level == SOL_TLS && (*header).cmsg_type == 2 {
                if (*header).cmsg_len < libc::CMSG_LEN(1) as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid kTLS record type",
                    ));
                }
                kind = *libc::CMSG_DATA(header);
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    Ok((result as usize, kind))
}
