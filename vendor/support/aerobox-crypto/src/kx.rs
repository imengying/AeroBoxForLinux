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
static P521: P521Group = P521Group;

pub(super) fn groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![&X25519, &P256, &P384, &P521]
}

#[derive(Debug)]
struct P521Group;
impl SupportedKxGroup for P521Group {
    fn name(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        self.start_with_seed_source(super::signing::fill_seed)
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}
impl P521Group {
    fn start_with_seed_source(
        &self,
        source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        use p521::elliptic_curve::sec1::ToEncodedPoint;
        let mut rng = super::signing::seeded_rng_with(source)?;
        let secret = p521::ecdh::EphemeralSecret::random(&mut rng);
        let public = secret.public_key().to_encoded_point(false);
        Ok(Box::new(P521Exchange { secret, public }))
    }
}
struct P521Exchange {
    secret: p521::ecdh::EphemeralSecret,
    public: p521::EncodedPoint,
}
impl ActiveKeyExchange for P521Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if peer.len() != 133 || peer[0] != 4 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let public =
            p521::PublicKey::from_sec1_bytes(peer).map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        let secret = self.secret.diffie_hellman(&public);
        Ok(SharedSecret::from(&secret.raw_secret_bytes()[..]))
    }
    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p521_key_exchange_returns_entropy_failure_and_uses_one_seed() {
        let failed = P521.start_with_seed_source(|seed| {
            seed[..16].fill(0x66);
            Err(Error::FailedToGetRandomBytes)
        });
        assert!(matches!(failed, Err(Error::FailedToGetRandomBytes)));

        let calls = std::cell::Cell::new(0);
        let local = P521
            .start_with_seed_source(|seed| {
                calls.set(calls.get() + 1);
                seed.fill(0x25);
                Ok(())
            })
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(local.pub_key().len(), 133);
        assert_eq!(local.pub_key()[0], 4);
        let peer = P521.start().unwrap();
        let peer_public = peer.pub_key().to_vec();
        let peer_secret = peer.complete(local.pub_key()).unwrap();
        assert_eq!(
            local.complete(&peer_public).unwrap().secret_bytes(),
            peer_secret.secret_bytes()
        );
    }
}
