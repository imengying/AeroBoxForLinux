//! Retain RustCrypto's randomized ECDSA while making OS entropy errors fallible.
use super::*;

macro_rules! implementation {
    ($curve:ident, $key:ident, $signer:ident, $scheme:ident) => {
        struct $key {
            key: Arc<$curve::ecdsa::SigningKey>,
            spki: Vec<u8>,
        }
        impl std::fmt::Debug for $key {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($key))
            }
        }
        impl $key {
            fn load(der: &PrivateKeyDer<'_>) -> Option<Self> {
                let key = match der {
                    PrivateKeyDer::Sec1(k) => {
                        $curve::SecretKey::from_sec1_der(k.secret_sec1_der()).ok()
                    }
                    PrivateKeyDer::Pkcs8(k) => {
                        $curve::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok()
                    }
                    _ => None,
                }?;
                let spki = key
                    .public_key()
                    .to_public_key_der()
                    .ok()?
                    .as_bytes()
                    .to_vec();
                let bytes = zeroize::Zeroizing::new(key.to_bytes());
                let key = Arc::new($curve::ecdsa::SigningKey::from_bytes(&bytes).ok()?);
                Some(Self { key, spki })
            }
        }
        impl SigningKey for $key {
            fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
                offered
                    .contains(&SignatureScheme::$scheme)
                    .then(|| Box::new($signer(self.key.clone())) as Box<dyn Signer>)
            }
            fn algorithm(&self) -> SignatureAlgorithm {
                SignatureAlgorithm::ECDSA
            }
            fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
                Some(self.spki.as_slice().into())
            }
        }
        struct $signer(Arc<$curve::ecdsa::SigningKey>);
        impl std::fmt::Debug for $signer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($signer))
            }
        }
        impl Signer for $signer {
            fn scheme(&self) -> SignatureScheme {
                SignatureScheme::$scheme
            }
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
                self.sign_with_seed_source(message, fill_seed)
            }
        }
        impl $signer {
            fn sign_with_seed_source(
                &self,
                message: &[u8],
                source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
            ) -> Result<Vec<u8>, Error> {
                use $curve::ecdsa::signature::RandomizedSigner;
                let mut rng = seeded_rng_with(source)?;
                let signature: $curve::ecdsa::Signature = self
                    .0
                    .try_sign_with_rng(&mut rng, message)
                    .map_err(|_| Error::General("ECDSA signing failed".into()))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
    };
}
implementation!(p256, P256Key, P256Signer, ECDSA_NISTP256_SHA256);
implementation!(p384, P384Key, P384Signer, ECDSA_NISTP384_SHA384);

pub(super) fn load(der: &PrivateKeyDer<'_>) -> Option<Arc<dyn SigningKey>> {
    P256Key::load(der)
        .map(|key| Arc::new(key) as Arc<dyn SigningKey>)
        .or_else(|| P384Key::load(der).map(|key| Arc::new(key) as Arc<dyn SigningKey>))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{ecdsa::signature::Verifier, pkcs8::EncodePrivateKey};
    macro_rules! check {
        ($name:ident, $curve:ident, $key:ident, $signer:ident, $bytes:expr) => {
            #[test]
            fn $name() {
                let secret = $curve::SecretKey::from_slice(&$bytes).unwrap();
                let der = secret.to_pkcs8_der().unwrap();
                let der = PrivateKeyDer::Pkcs8(der.as_bytes().to_vec().into());
                let key = $key::load(&der).unwrap();
                let signer = $signer(key.key.clone());
                assert!(matches!(
                    signer.sign_with_seed_source(b"test", |seed| {
                        seed[..16].fill(1);
                        Err(Error::FailedToGetRandomBytes)
                    }),
                    Err(Error::FailedToGetRandomBytes)
                ));
                let calls = std::cell::Cell::new(0);
                let signature = signer
                    .sign_with_seed_source(b"test", |seed| {
                        calls.set(calls.get() + 1);
                        seed.fill(2);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(calls.get(), 1);
                let signature = $curve::ecdsa::Signature::from_der(&signature).unwrap();
                key.key.verifying_key().verify(b"test", &signature).unwrap();
                assert!(
                    key.key
                        .verifying_key()
                        .verify(b"changed", &signature)
                        .is_err()
                );
                let loaded = Provider.load_private_key(der).unwrap();
                assert_eq!(loaded.algorithm(), SignatureAlgorithm::ECDSA);
                assert_eq!(loaded.public_key().unwrap().as_ref(), key.spki);
                assert_eq!(
                    loaded.choose_scheme(&[signer.scheme()]).unwrap().scheme(),
                    signer.scheme()
                );
                assert!(
                    loaded
                        .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                        .is_none()
                );
            }
        };
    }
    check!(
        p256_entropy_error_and_seeded_nonce,
        p256,
        P256Key,
        P256Signer,
        [1u8; 32]
    );
    check!(
        p384_entropy_error_and_seeded_nonce,
        p384,
        P384Key,
        P384Signer,
        [1u8; 48]
    );
}
