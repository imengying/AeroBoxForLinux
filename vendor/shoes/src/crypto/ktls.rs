//! TLS record offload with rustls retaining ownership of key derivation and tickets.
//! A direction may stay in userspace; both paths share the same control-message
//! parser, record limits, cancellation-safe output and close-notify handling.
mod sys;
use super::tls_deframer::TlsDeframer;
use crate::async_stream::AsyncStream;
use bytes::{Buf, Bytes, BytesMut};
use rustls::crypto::cipher::{
    InboundOpaqueMessage, MessageDecrypter, MessageEncrypter, OutboundPlainMessage,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion, SupportedCipherSuite};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{Interest, ReadBuf},
    net::TcpStream,
};

type Kernel = rustls::kernel::KernelConnection<rustls::client::ClientConnectionData>;
const MAX_PLAIN: usize = 16384;
const MAX_HANDSHAKE: usize = 128 * 1024;

pub(crate) struct Connection {
    kernel: Kernel,
    tx_kernel: bool,
    rx_kernel: bool,
    encrypter: Option<Box<dyn MessageEncrypter>>,
    decrypter: Option<Box<dyn MessageDecrypter>>,
    tx_seq: u64,
    rx_seq: u64,
    rx_budget: u64,
    limit: u64,
    pending: Bytes,
    pending_kind: u8,
    rekey_after_write: bool,
    rekey_request: Option<bool>,
    requested_rx_update: bool,
    input: TlsDeframer,
    plaintext: Bytes,
    handshake: BytesMut,
    read_closed: bool,
    write_closed: bool,
    failed: Option<io::ErrorKind>,
    pub alpn: Option<Vec<u8>>,
    pub group: Option<rustls::NamedGroup>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn tcp<IO: AsyncStream>(io: &IO) -> io::Result<&TcpStream> {
    io.plain_tcp().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "kTLS requires a direct TCP carrier",
        )
    })
}

impl Connection {
    pub fn new<IO: AsyncStream>(
        io: &IO,
        secrets: rustls::ExtractedSecrets,
        kernel: Kernel,
        tx: bool,
        rx: bool,
        alpn: Option<Vec<u8>>,
        group: Option<rustls::NamedGroup>,
    ) -> io::Result<Self> {
        let socket = tcp(io)?;
        let version = kernel.protocol_version();
        let suite = kernel.negotiated_cipher_suite();
        sys::enable(socket)
            .map_err(|error| io::Error::new(error.kind(), format!("enable Linux kTLS: {error}")))?;
        if tx {
            sys::keys(socket, true, version, secrets.tx.0, &secrets.tx.1)?;
        }
        if rx {
            sys::keys(socket, false, version, secrets.rx.0, &secrets.rx.1)?;
        }
        let (tx_seq, tx_secret) = secrets.tx;
        let (rx_seq, rx_secret) = secrets.rx;
        Ok(Self {
            encrypter: if tx {
                None
            } else {
                Some(encrypter(suite, tx_secret)?)
            },
            decrypter: if rx {
                None
            } else {
                Some(decrypter(suite, rx_secret)?)
            },
            limit: match suite {
                SupportedCipherSuite::Tls13(s) => s.common.confidentiality_limit,
                SupportedCipherSuite::Tls12(s) => s.common.confidentiality_limit,
            }
            .saturating_sub(2),
            kernel,
            tx_kernel: tx,
            rx_kernel: rx,
            tx_seq,
            rx_seq,
            rx_budget: rx_seq,
            pending: Bytes::new(),
            pending_kind: 23,
            rekey_after_write: false,
            rekey_request: None,
            requested_rx_update: false,
            input: TlsDeframer::new(),
            plaintext: Bytes::new(),
            handshake: BytesMut::new(),
            read_closed: false,
            write_closed: false,
            failed: None,
            alpn,
            group,
        })
    }
    fn check(&self) -> io::Result<()> {
        self.failed.map_or(Ok(()), |kind| {
            Err(io::Error::new(kind, "kTLS connection failed"))
        })
    }
    fn queue(&mut self, kind: u8, data: &[u8]) -> io::Result<()> {
        debug_assert!(self.pending.is_empty());
        self.pending_kind = kind;
        self.pending = if let Some(cipher) = &mut self.encrypter {
            cipher
                .encrypt(
                    OutboundPlainMessage {
                        typ: ContentType::from(kind),
                        version: ProtocolVersion::TLSv1_2,
                        payload: data.into(),
                    },
                    self.tx_seq,
                )
                .map_err(io::Error::other)?
                .encode()
                .into()
        } else {
            Bytes::copy_from_slice(data)
        };
        self.tx_seq = self
            .tx_seq
            .checked_add(if self.tx_kernel {
                data.len().max(1) as u64
            } else {
                1
            })
            .ok_or_else(|| invalid("TLS write sequence exhausted"))?;
        Ok(())
    }
    fn flush<IO: AsyncStream>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            while !self.pending.is_empty() {
                let written = if self.tx_kernel {
                    let socket = tcp(io)?;
                    loop {
                        ready!(socket.poll_write_ready(cx))?;
                        match socket.try_io(Interest::WRITABLE, || {
                            sys::send(socket, self.pending_kind, &self.pending)
                        }) {
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                            result => break result?,
                        }
                    }
                } else {
                    ready!(Pin::new(&mut *io).poll_write(cx, &self.pending))?
                };
                if written == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.pending.advance(written);
            }
            if self.rekey_after_write {
                let (seq, secret) = self.kernel.update_tx_secret().map_err(io::Error::other)?;
                if self.tx_kernel {
                    sys::keys(tcp(io)?, true, self.kernel.protocol_version(), seq, &secret)?;
                } else {
                    self.encrypter =
                        Some(encrypter(self.kernel.negotiated_cipher_suite(), secret)?);
                }
                self.tx_seq = seq;
                self.rekey_after_write = false;
            }
            if let Some(request) = self.rekey_request.take() {
                if self.write_closed {
                    return Poll::Ready(Err(invalid("key update after write shutdown")));
                }
                self.queue(22, &[24, 0, 0, 1, u8::from(request)])?;
                self.rekey_after_write = true;
                continue;
            }
            return Pin::new(io).poll_flush(cx);
        }
    }
    fn control<IO: AsyncStream>(&mut self, io: &IO, kind: u8, bytes: &[u8]) -> io::Result<()> {
        if kind != 22 && !self.handshake.is_empty() {
            return Err(invalid("interleaved TLS handshake records"));
        }
        if bytes.len() > MAX_PLAIN {
            return Err(invalid("oversized TLS plaintext record"));
        }
        match kind {
            23 => self.plaintext = Bytes::copy_from_slice(bytes),
            21 => {
                if bytes == [1, 0] || bytes == [2, 0] {
                    self.read_closed = true;
                } else {
                    return Err(invalid("peer sent a TLS alert"));
                }
            }
            22 => {
                if self.handshake.len() + bytes.len() > MAX_HANDSHAKE {
                    return Err(invalid("TLS handshake message too large"));
                }
                self.handshake.extend_from_slice(bytes);
                while self.handshake.len() >= 4 {
                    let size = u32::from_be_bytes([
                        0,
                        self.handshake[1],
                        self.handshake[2],
                        self.handshake[3],
                    ]) as usize;
                    if size > MAX_HANDSHAKE - 4 {
                        return Err(invalid("TLS handshake message too large"));
                    }
                    if self.handshake.len() < size + 4 {
                        break;
                    }
                    let message = self.handshake.split_to(size + 4);
                    match message[0] {
                        4 => self
                            .kernel
                            .handle_new_session_ticket(&message[4..])
                            .map_err(io::Error::other)?,
                        24 => {
                            if size != 1 || message[4] > 1 || !self.handshake.is_empty() {
                                return Err(invalid("invalid TLS KeyUpdate"));
                            }
                            let (seq, secret) =
                                self.kernel.update_rx_secret().map_err(io::Error::other)?;
                            if self.rx_kernel {
                                sys::keys(
                                    tcp(io)?,
                                    false,
                                    self.kernel.protocol_version(),
                                    seq,
                                    &secret,
                                )?;
                            } else {
                                self.decrypter =
                                    Some(decrypter(self.kernel.negotiated_cipher_suite(), secret)?);
                            }
                            self.rx_seq = seq;
                            self.rx_budget = 0;
                            self.requested_rx_update = false;
                            if message[4] == 1 && !self.write_closed {
                                self.rekey_request = Some(false);
                            }
                        }
                        _ => return Err(invalid("unexpected post-handshake TLS message")),
                    }
                }
            }
            _ => return Err(invalid("unexpected TLS content type")),
        }
        Ok(())
    }
    fn read<IO: AsyncStream>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if !self.plaintext.is_empty() {
                let size = out.remaining().min(self.plaintext.len());
                out.put_slice(&self.plaintext[..size]);
                self.plaintext.advance(size);
                return Poll::Ready(Ok(()));
            }
            if self.read_closed {
                return Poll::Ready(Ok(()));
            }
            if self.rekey_request.is_some() || self.rekey_after_write {
                ready!(self.flush(io, cx))?;
            }
            if self.rx_budget >= self.limit {
                return Poll::Ready(Err(invalid("TLS receive confidentiality limit reached")));
            }
            let mut data = [0; MAX_PLAIN];
            if self.rx_kernel {
                let socket = tcp(io)?;
                let (size, kind) = loop {
                    ready!(socket.poll_read_ready(cx))?;
                    match socket.try_io(Interest::READABLE, || sys::receive(socket, &mut data)) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        result => break result?,
                    }
                };
                if size == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                // recvmsg may coalesce application records. Bytes bound the number
                // of nonempty records conservatively, avoiding an undercount.
                self.rx_budget = self.rx_budget.saturating_add(size as u64);
                self.control(io, kind, &data[..size])?;
            } else {
                let record = ready!(self.input.poll_read_record(io, cx, &mut data, false))?
                    .ok_or(io::ErrorKind::UnexpectedEof)?;
                let mut payload = record[5..].to_vec();
                let decoded = self
                    .decrypter
                    .as_mut()
                    .unwrap()
                    .decrypt(
                        InboundOpaqueMessage::new(
                            ContentType::from(record[0]),
                            ProtocolVersion::from(u16::from_be_bytes([record[1], record[2]])),
                            &mut payload,
                        ),
                        self.rx_seq,
                    )
                    .map_err(io::Error::other)?;
                self.rx_seq = self
                    .rx_seq
                    .checked_add(1)
                    .ok_or_else(|| invalid("TLS read sequence exhausted"))?;
                self.rx_budget += 1;
                self.control(io, u8::from(decoded.typ), decoded.payload)?;
            }
            if self.rx_budget >= self.limit / 2
                && !self.requested_rx_update
                && !self.write_closed
                && self.kernel.protocol_version() == ProtocolVersion::TLSv1_3
            {
                self.rekey_request = Some(true);
                self.requested_rx_update = true;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    pub fn poll_read<IO: AsyncStream>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = self.read(io, cx, out);
        if let Poll::Ready(Err(error)) = &result {
            self.failed = Some(error.kind());
        }
        result
    }
    pub fn poll_write<IO: AsyncStream>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        if self.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let additional = if self.tx_kernel {
            MAX_PLAIN.min(data.len()) as u64
        } else {
            1
        };
        if self.tx_seq.saturating_add(additional) >= self.limit {
            if self.kernel.protocol_version() != ProtocolVersion::TLSv1_3 {
                return Poll::Ready(Err(invalid("TLS transmit confidentiality limit reached")));
            }
            self.rekey_request = Some(false);
        }
        ready!(self.poll_flush(io, cx))?;
        let size = MAX_PLAIN.min(data.len());
        if let Err(error) = self.queue(23, &data[..size]) {
            self.failed = Some(error.kind());
            return Poll::Ready(Err(error));
        }
        // Try to send accepted bytes immediately, just like the userspace TLS
        // stream. Keep unsent output owned by the connection on backpressure.
        if let Poll::Ready(Err(error)) = self.poll_flush(io, cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(size))
    }
    pub fn poll_flush<IO: AsyncStream>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        let result = self.flush(io, cx);
        if let Poll::Ready(Err(error)) = &result {
            self.failed = Some(error.kind());
        }
        result
    }
    pub fn poll_shutdown<IO: AsyncStream>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_flush(io, cx))?;
        if !self.write_closed {
            self.queue(21, &[1, 0])?;
            self.write_closed = true;
        }
        ready!(self.poll_flush(io, cx))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

fn split(
    secret: ConnectionTrafficSecrets,
) -> io::Result<(rustls::crypto::cipher::AeadKey, rustls::crypto::cipher::Iv)> {
    match secret {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => Ok((key, iv)),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported kTLS cipher",
        )),
    }
}
fn encrypter(
    suite: SupportedCipherSuite,
    secret: ConnectionTrafficSecrets,
) -> io::Result<Box<dyn MessageEncrypter>> {
    let (key, iv) = split(secret)?;
    Ok(match suite {
        SupportedCipherSuite::Tls13(suite) => suite.aead_alg.encrypter(key, iv),
        SupportedCipherSuite::Tls12(suite) => {
            let shape = suite.aead_alg.key_block_shape();
            suite.aead_alg.encrypter(
                key,
                &iv.as_ref()[..shape.fixed_iv_len],
                &iv.as_ref()[shape.fixed_iv_len..][..shape.explicit_nonce_len],
            )
        }
    })
}
fn decrypter(
    suite: SupportedCipherSuite,
    secret: ConnectionTrafficSecrets,
) -> io::Result<Box<dyn MessageDecrypter>> {
    let (key, iv) = split(secret)?;
    Ok(match suite {
        SupportedCipherSuite::Tls13(suite) => suite.aead_alg.decrypter(key, iv),
        SupportedCipherSuite::Tls12(suite) => suite.aead_alg.decrypter(
            key,
            &iv.as_ref()[..suite.aead_alg.key_block_shape().fixed_iv_len],
        ),
    })
}

#[cfg(test)]
mod tests;
