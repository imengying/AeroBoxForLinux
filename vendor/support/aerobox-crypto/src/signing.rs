//! Preserve the public half of signing keys so rustls can reject mismatched
//! certificate/key pairs. The upstream alpha omitted SigningKey::public_key.
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rustls::{
    Error, SignatureAlgorithm, SignatureScheme,
    crypto::KeyProvider,
    pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer},
    sign::{Signer, SigningKey},
};
use std::sync::Arc;
mod ecdsa;
mod rsa;
#[derive(Debug)]
pub(super) struct Provider;
impl KeyProvider for Provider {
    fn supports_rsa_key_exchange(&self) -> bool {
        true
    }
    fn encrypt_tls12_rsa_premaster(
        &self,
        certificate: &rustls::pki_types::CertificateDer<'_>,
        version: rustls::ProtocolVersion,
    ) -> Result<(Vec<u8>, rustls::crypto::SharedSecret), Error> {
        crate::legacy_rsa::encrypt(certificate, version)
    }
    fn load_private_key(&self, der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        if let Some(key) = rsa::load(&der)? {
            return Ok(key);
        }
        if let Some(key) = ecdsa::load(&der) {
            return Ok(key);
        }
        if let Some(key) = match &der {
            PrivateKeyDer::Sec1(k) => p521::SecretKey::from_sec1_der(k.secret_sec1_der()).ok(),
            PrivateKeyDer::Pkcs8(k) => p521::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok(),
            _ => None,
        } {
            let spki = key
                .public_key()
                .to_public_key_der()
                .map_err(|_| Error::General("invalid P-521 public key".into()))?
                .as_bytes()
                .to_vec();
            let bytes = zeroize::Zeroizing::new(key.to_bytes());
            let key = p521::ecdsa::SigningKey::from_bytes(&bytes)
                .map_err(|_| Error::General("invalid P-521 private key".into()))?;
            return Ok(Arc::new(P521Key {
                key: Arc::new(key),
                spki,
            }));
        }
        let inner = rustls_rustcrypto::provider()
            .key_provider
            .load_private_key(der.clone_key())?;
        let spki = public_key(&der)
            .ok_or_else(|| Error::General("cannot derive signing key public component".into()))?;
        Ok(Arc::new(WithPublic { inner, spki }))
    }
}

struct P521Key {
    key: Arc<p521::ecdsa::SigningKey>,
    spki: Vec<u8>,
}
impl std::fmt::Debug for P521Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("P521SigningKey")
    }
}
impl SigningKey for P521Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP521_SHA512)
            .then(|| Box::new(P521Signer(self.key.clone())) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.as_slice().into())
    }
}
struct P521Signer(Arc<p521::ecdsa::SigningKey>);
impl std::fmt::Debug for P521Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("P521Signer")
    }
}
impl Signer for P521Signer {
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP521_SHA512
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_with_seed_source(message, fill_seed)
    }
}
impl P521Signer {
    fn sign_with_seed_source(
        &self,
        message: &[u8],
        source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        use p521::ecdsa::signature::RandomizedSigner;
        let mut rng = seeded_rng_with(source)?;
        let signature: p521::ecdsa::Signature = self
            .0
            .try_sign_with_rng(&mut rng, message)
            .map_err(|_| Error::General("P-521 signing failed".into()))?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
struct WithPublic {
    inner: Arc<dyn SigningKey>,
    spki: Vec<u8>,
}
impl std::fmt::Debug for WithPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSigningKey")
            .field("algorithm", &self.inner.algorithm())
            .finish_non_exhaustive()
    }
}
impl SigningKey for WithPublic {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.inner.choose_scheme(offered)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.as_slice().into())
    }
}
fn public_key(der: &PrivateKeyDer<'_>) -> Option<Vec<u8>> {
    if let Some(key) = match der {
        PrivateKeyDer::Sec1(k) => p256::SecretKey::from_sec1_der(k.secret_sec1_der()).ok(),
        PrivateKeyDer::Pkcs8(k) => p256::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok(),
        _ => None,
    } {
        return key
            .public_key()
            .to_public_key_der()
            .ok()
            .map(|v| v.as_bytes().to_vec());
    }
    if let Some(key) = match der {
        PrivateKeyDer::Sec1(k) => p384::SecretKey::from_sec1_der(k.secret_sec1_der()).ok(),
        PrivateKeyDer::Pkcs8(k) => p384::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok(),
        _ => None,
    } {
        return key
            .public_key()
            .to_public_key_der()
            .ok()
            .map(|v| v.as_bytes().to_vec());
    }
    if let PrivateKeyDer::Pkcs8(k) = der
        && let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(k.secret_pkcs8_der())
    {
        return key
            .verifying_key()
            .to_public_key_der()
            .ok()
            .map(|v| v.as_bytes().to_vec());
    }
    None
}

pub(super) fn fill_seed(seed: &mut [u8; 32]) -> Result<(), Error> {
    rand_core::OsRng
        .try_fill_bytes(seed)
        .map_err(|_| Error::FailedToGetRandomBytes)
}

pub(super) fn seeded_rng_with(
    source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
) -> Result<ChaCha20Rng, Error> {
    // RSA padding/blinding and P-521 nonce/key generation call infallible
    // RngCore methods. Only this fallible OS request supplies entropy; the
    // local CSPRNG cannot panic because an OS request failed mid-signature.
    // The temporary seed is erased. rand_chacha 0.3 does not provide wiping
    // of its internal state/buffer, so those copies are not guaranteed erased.
    let mut seed = zeroize::Zeroizing::new([0; 32]);
    source(&mut seed)?;
    Ok(ChaCha20Rng::from_seed(*seed))
}
