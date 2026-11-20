//! Preserve every TCP capability while enforcing the node's payload policy.
//! The factory applies this outside transport and multiplexing decorators, so
//! a decorator cannot turn a disabled UDP network back on.
use std::{io, sync::Arc};

use async_trait::async_trait;

use super::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult};
use crate::{
    address::ResolvedLocation,
    async_stream::{AsyncMessageStream, AsyncStream},
    resolver::Resolver,
};

#[derive(Debug)]
pub(super) struct TcpOnlyHandler(pub Box<dyn TcpClientHandler>);

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "UDP is disabled for this node",
    )
}

#[async_trait]
impl TcpClientHandler for TcpOnlyHandler {
    fn has_session_pool(&self) -> bool {
        self.0.has_session_pool()
    }

    fn validate_alpn(&self, alpn: Option<&[u8]>) -> io::Result<()> {
        self.0.validate_alpn(alpn)
    }

    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<ResolvedLocation> {
        self.0.prepare_target(target, resolver).await
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> io::Result<Option<TcpClientSetupResult>> {
        self.0.try_reuse_tcp_stream(target).await
    }

    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        self.0.connect_client_tcp(transport, target).await
    }

    async fn setup_client_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        self.0.setup_client_tcp_stream(stream, target).await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        false
    }

    async fn connect_client_udp(
        &self,
        _transport: ClientTransport<'_>,
        _target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        // Reject before polling the future that would open a proxy connection.
        Err(denied())
    }

    async fn setup_client_udp_bidirectional(
        &self,
        _stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        Err(denied())
    }
}
