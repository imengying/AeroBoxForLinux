//! V2Ray stream transports, independent of the inner proxy protocol.
mod grpc;
mod h2_stream;
mod http1;
#[cfg(test)] mod tests;
use std::{collections::HashMap, io};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::{address::ResolvedLocation, async_stream::{AsyncStream, AsyncMessageStream}, tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult, ClientTransport}};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind { Grpc, HttpUpgrade, Http2, Http1 }
fn default_path() -> String { "/".into() }
fn default_method() -> String { "PUT".into() }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config<P> {
    pub kind: Kind,
    #[serde(default)] pub host: Option<String>,
    #[serde(default = "default_path")] pub path: String,
    #[serde(default = "default_method")] pub method: String,
    #[serde(default)] pub service_name: String,
    #[serde(default)] pub headers: HashMap<String, String>,
    pub protocol: Box<P>,
}
impl<P> Config<P> {
    pub fn validate(&self) -> io::Result<()> {
        if !self.path.starts_with('/') || self.path.contains(['\r', '\n', ' ']) || self.path.len() > 8192 {
            return Err(invalid("invalid HTTP transport path"));
        }
        self.path.parse::<http::uri::PathAndQuery>().map_err(io::Error::other)?;
        self.method.parse::<http::Method>().map_err(io::Error::other)?;
        if let Some(host) = &self.host { host.parse::<http::uri::Authority>().map_err(io::Error::other)?; }
        if self.service_name.len() > 1024 { return Err(invalid("gRPC service name exceeds 1024 bytes")); }
        let mut total = 0;
        for (name, value) in &self.headers {
            let name = name.parse::<http::HeaderName>().map_err(io::Error::other)?;
            value.parse::<http::HeaderValue>().map_err(io::Error::other)?;
            if matches!(name.as_str(), "content-length" | "transfer-encoding" | "connection" | "upgrade" | "host") { return Err(invalid("reserved HTTP transport header")); }
            total += name.as_str().len() + value.len();
        }
        if total > 16384 { return Err(invalid("HTTP transport headers exceed 16 KiB")); }
        Ok(())
    }
    pub(crate) fn map<T>(self, f: impl FnOnce(P) -> T) -> Config<T> {
        Config { kind: self.kind, host: self.host, path: self.path, method: self.method, service_name: self.service_name, headers: self.headers, protocol: Box::new(f(*self.protocol)) }
    }
}
fn invalid(message: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }

#[derive(Debug)]
pub struct Handler { options: Config<()>, authority: String, inner: Box<dyn TcpClientHandler> }
impl Handler {
    pub fn new<P>(options: Config<P>, authority: String, inner: Box<dyn TcpClientHandler>) -> io::Result<Self> {
        options.validate()?;
        Ok(Self { options: options.map(|_| ()), authority, inner })
    }
    async fn wrap(&self, mut stream: Box<dyn AsyncStream>) -> io::Result<Box<dyn AsyncStream>> {
        let host = self.options.host.as_deref().unwrap_or(&self.authority);
        if self.options.kind == Kind::HttpUpgrade {
            let mut request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n", self.options.path, host);
            for (key, value) in &self.options.headers { request.push_str(&format!("{key}: {value}\r\n")); }
            request.push_str("\r\n");
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            // Read precisely through the header so coalesced tunnel bytes stay in the stream.
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                if header.len() >= 16384 { return Err(invalid("HTTP upgrade response exceeds 16 KiB")); }
                header.push(stream.read_u8().await?);
            }
            let mut fields = [httparse::EMPTY_HEADER; 64];
            let mut response = httparse::Response::new(&mut fields);
            response.parse(&header).map_err(io::Error::other)?;
            let token = |name: &str, expected: &str| response.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name)).any(|h| std::str::from_utf8(h.value).unwrap_or("").split(',').any(|v| v.trim().eq_ignore_ascii_case(expected)));
            if response.code != Some(101) || !token("connection", "upgrade") || !token("upgrade", "websocket") { return Err(invalid("HTTP transport upgrade rejected")); }
            return Ok(stream);
        }
        if self.options.kind == Kind::Http1 {
            let mut request = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", self.options.method, self.options.path, host);
            for (key, value) in &self.options.headers { request.push_str(&format!("{key}: {value}\r\n")); }
            request.push_str("\r\n");
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            return Ok(Box::new(http1::Http1Stream::new(stream)));
        }
        let grpc = self.options.kind == Kind::Grpc;
        let path = if grpc {
            format!("/{}/Tun", percent_encoding::utf8_percent_encode(&self.options.service_name, percent_encoding::NON_ALPHANUMERIC))
        } else { self.options.path.clone() };
        let method = if grpc { "POST" } else { &self.options.method };
        let mut request = http::Request::builder().method(method).uri(format!("https://{host}{path}"));
        for (name, value) in &self.options.headers { request = request.header(name, value); }
        if grpc { request = request.header("content-type", "application/grpc").header("te", "trailers").header("user-agent", "grpc-go/1.48.0"); }
        let request = request.body(()).map_err(io::Error::other)?;
        let session = crate::http2::client::H2ClientSession::new(stream).await?;
        let stream = session.reserve().open_late(request, grpc).await?;
        Ok(if grpc { Box::new(grpc::GrpcStream::new(stream)) } else { Box::new(stream) })
    }
}
#[async_trait]
impl TcpClientHandler for Handler {
    fn has_session_pool(&self) -> bool { self.inner.has_session_pool() }
    fn supports_udp_over_tcp(&self) -> bool { self.inner.supports_udp_over_tcp() }
    async fn prepare_target(&self, target: ResolvedLocation, resolver: &std::sync::Arc<dyn crate::resolver::Resolver>) -> io::Result<ResolvedLocation> { self.inner.prepare_target(target, resolver).await }
    async fn connect_client_tcp(&self, transport: ClientTransport<'_>, target: ResolvedLocation) -> io::Result<TcpClientSetupResult> {
        self.inner.connect_client_tcp(transport.wrap(|s| self.wrap(s)), target).await
    }
    async fn connect_client_udp(&self, transport: ClientTransport<'_>, target: ResolvedLocation) -> io::Result<Box<dyn AsyncMessageStream>> {
        self.inner.connect_client_udp(transport.wrap(|s| self.wrap(s)), target).await
    }
    async fn setup_client_tcp_stream(&self, stream: Box<dyn AsyncStream>, target: ResolvedLocation) -> io::Result<TcpClientSetupResult> { self.inner.setup_client_tcp_stream(self.wrap(stream).await?, target).await }
    async fn setup_client_udp_bidirectional(&self, stream: Box<dyn AsyncStream>, target: ResolvedLocation) -> io::Result<Box<dyn AsyncMessageStream>> { self.inner.setup_client_udp_bidirectional(self.wrap(stream).await?, target).await }
}

pub(crate) use h2_stream::LateH2Stream;
