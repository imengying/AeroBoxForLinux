use std::{fmt::Debug, io, sync::Arc};

use async_trait::async_trait;

use crate::{
    address::ResolvedLocation,
    async_stream::{AsyncMessageStream, AsyncStream},
    quic_endpoint::QuicEndpoint,
};

/// Identity of the selected route, not merely its destination. Connector instances
/// are retained by the dialer, so their addresses cannot be recycled while pooled.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouteKey(pub Vec<usize>);

pub struct QuicCarrier {
    pub connection: quinn::Connection,
    pub(crate) _endpoint: Arc<QuicEndpoint>,
}

#[async_trait]
pub trait CarrierDialer: Debug + Send + Sync {
    fn route_key(&self) -> &RouteKey;
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>>;
    /// Datagram carrier through this selected route prefix. `None` uses the
    /// proxy endpoint; SOCKS UDP ASSOCIATE supplies the returned relay address.
    async fn open_datagram(
        &self,
        _target: Option<ResolvedLocation>,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "route has no datagram carrier",
        ))
    }
    async fn open_quic(&self) -> io::Result<QuicCarrier> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native QUIC requires a first-hop QUIC carrier",
        ))
    }
}
