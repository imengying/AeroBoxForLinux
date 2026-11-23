//! RSA TLS signatures with fallible entropy acquisition and blinded private
//! key operations. This replaces the alpha provider's direct OS RNG calls.
use super::{
    Error, PrivateKeyDer, SignatureAlgorithm, SignatureScheme, Signer, SigningKey,
    SubjectPublicKeyInfoDer,
};
use ::rsa::{
    RsaPrivateKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, EncodePublicKey, der::Decode},
    traits::PublicKeyParts,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::sync::Arc;

// Match the upstream provider's preference exactly, independent of the
// ordering of peer-offered schemes.
const SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

pub(super) fn load(der: &PrivateKeyDer<'_>) -> Result<Option<Arc<dyn SigningKey>>, Error> {
    let bad_key = || Error::General("invalid RSA signing key".into());
    let (encoded, pkcs8) = match der {
        PrivateKeyDer::Pkcs1(key) => (key.secret_pkcs1_der(), false),
        PrivateKeyDer::Pkcs8(key) => {
            let info = match ::rsa::pkcs8::PrivateKeyInfo::from_der(key.secret_pkcs8_der()) {
                Ok(info) => info,
                Err(_) => return Ok(None),
            };
            if info.algorithm.oid != ::rsa::pkcs1::ALGORITHM_OID {
                return Ok(None);
            }
            (key.secret_pkcs8_der(), true)
        }
        _ => return Ok(None),
    };
    // A two-prime RSA-8192 PKCS#1/PKCS#8 private key is under 5 KiB.
    // Avoid passing unbounded malformed key components to bigint arithmetic.
    if encoded.len() > 6144 {
        return Err(bad_key());
    }
    let key = if pkcs8 {
        RsaPrivateKey::from_pkcs8_der(encoded).map_err(|_| bad_key())?
    } else {
        RsaPrivateKey::from_pkcs1_der(encoded).map_err(|_| bad_key())?
    };
    if !(2048..=8192).contains(&key.n().bits()) {
        return Err(Error::General(
            "RSA signing requires a 2048..8192-bit key".into(),
        ));
    }
    let spki = key
        .to_public_key()
        .to_public_key_der()
        .map_err(|_| bad_key())?
        .as_bytes()
        .to_vec();
    Ok(Some(Arc::new(Key {
        key: Arc::new(key),
        spki,
    })))
}

struct Key {
    key: Arc<RsaPrivateKey>,
    spki: Vec<u8>,
}
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaSigningKey")
    }
}
impl SigningKey for Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        SCHEMES
            .iter()
            .find(|scheme| offered.contains(scheme))
            .map(|&scheme| {
                Box::new(RsaSigner {
                    key: self.key.clone(),
                    scheme,
                }) as Box<dyn Signer>
            })
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.as_slice().into())
    }
}

struct RsaSigner {
    key: Arc<RsaPrivateKey>,
    scheme: SignatureScheme,
}
impl std::fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}
impl Signer for RsaSigner {
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_with_seed_source(message, super::fill_seed)
    }
}
impl RsaSigner {
    fn sign_with_seed_source(
        &self,
        message: &[u8],
        source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        let mut rng = super::seeded_rng_with(source)?;
        macro_rules! pkcs1 {
            ($hash:ty) => {
                self.key.sign_with_rng(
                    &mut rng,
                    ::rsa::Pkcs1v15Sign::new::<$hash>(),
                    &<$hash>::digest(message),
                )
            };
        }
        macro_rules! pss {
            ($hash:ty) => {
                // `new_blinded` masks the private exponentiation; it emits
                // ordinary PSS with a digest-sized salt, as required by TLS.
                self.key.sign_with_rng(
                    &mut rng,
                    ::rsa::Pss::new_blinded::<$hash>(),
                    &<$hash>::digest(message),
                )
            };
        }
        match self.scheme {
            SignatureScheme::RSA_PSS_SHA512 => pss!(Sha512),
            SignatureScheme::RSA_PSS_SHA384 => pss!(Sha384),
            SignatureScheme::RSA_PSS_SHA256 => pss!(Sha256),
            SignatureScheme::RSA_PKCS1_SHA512 => pkcs1!(Sha512),
            SignatureScheme::RSA_PKCS1_SHA384 => pkcs1!(Sha384),
            SignatureScheme::RSA_PKCS1_SHA256 => pkcs1!(Sha256),
            _ => return Err(Error::General("unsupported RSA signature scheme".into())),
        }
        .map_err(|_| Error::General("RSA signing failed".into()))
    }
}

#[cfg(test)]
mod tests;
