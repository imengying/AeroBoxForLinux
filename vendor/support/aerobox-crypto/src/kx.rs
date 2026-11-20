//! Additional TLS key-share validation around the upstream alpha provider.

use std::sync::OnceLock;

use rustls::{
    Error, NamedGroup, PeerMisbehaved,
    crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup},
};
use subtle::ConstantTimeEq;

static X25519: CheckedGroup = CheckedGroup(NamedGroup::X25519);
static P256: CheckedGroup = CheckedGroup(NamedGroup::secp256r1);
static P384: CheckedGroup = CheckedGroup(NamedGroup::secp384r1);

pub(super) fn groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![&X25519, &P256, &P384]
}

#[derive(Debug)]
struct CheckedGroup(NamedGroup);

impl SupportedKxGroup for CheckedGroup {
    fn name(&self) -> NamedGroup {
        self.0
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        static UPSTREAM: OnceLock<Vec<&'static dyn SupportedKxGroup>> = OnceLock::new();
        let upstream = UPSTREAM.get_or_init(|| rustls_rustcrypto::provider().kx_groups);
        let group = upstream
            .iter()
            .find(|group| group.name() == self.0)
            .ok_or_else(|| Error::General("missing RustCrypto key exchange group".into()))?;
        Ok(Box::new(CheckedExchange {
            inner: group.start()?,
            group: self.0,
        }))
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}

struct CheckedExchange {
    inner: Box<dyn ActiveKeyExchange>,
    group: NamedGroup,
}

impl ActiveKeyExchange for CheckedExchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        // TLS uses uncompressed SEC1 points for NIST curves, not the compressed
        // form that the general-purpose RustCrypto parser also accepts.
        let encoding_valid = match self.group {
            NamedGroup::X25519 => peer.len() == 32,
            NamedGroup::secp256r1 => peer.len() == 65 && peer.first() == Some(&4),
            NamedGroup::secp384r1 => peer.len() == 97 && peer.first() == Some(&4),
            _ => false,
        };
        if !encoding_valid {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let secret = self.inner.complete(peer)?;
        // RFC 8446 section 7.4.2 requires rejecting X25519's all-zero result.
        // Do not expose the upstream alpha's unchecked shared secret to TLS.
        if self.group == NamedGroup::X25519 && bool::from(secret.secret_bytes().ct_eq(&[0; 32])) {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(secret)
    }

    fn pub_key(&self) -> &[u8] {
        self.inner.pub_key()
    }

    fn group(&self) -> NamedGroup {
        self.group
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}
