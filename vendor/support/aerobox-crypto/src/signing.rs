//! Preserve the public half of signing keys so rustls can reject mismatched
//! certificate/key pairs. The upstream alpha omitted SigningKey::public_key.
use std::sync::Arc;
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme, crypto::KeyProvider, pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer}, sign::{Signer,SigningKey}};
#[derive(Debug)]
pub(super) struct Provider;
impl KeyProvider for Provider {
    fn load_private_key(&self,der:PrivateKeyDer<'static>)->Result<Arc<dyn SigningKey>,Error> {
        let inner=rustls_rustcrypto::provider().key_provider.load_private_key(der.clone_key())?;
        let spki=public_key(&der).ok_or_else(||Error::General("cannot derive signing key public component".into()))?;
        Ok(Arc::new(WithPublic {inner,spki}))
    }
}
struct WithPublic {inner:Arc<dyn SigningKey>,spki:Vec<u8>}
impl std::fmt::Debug for WithPublic {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("RustCryptoSigningKey").field("algorithm",&self.inner.algorithm()).finish_non_exhaustive()}}
impl SigningKey for WithPublic {
    fn choose_scheme(&self,offered:&[SignatureScheme])->Option<Box<dyn Signer>> {self.inner.choose_scheme(offered)}
    fn algorithm(&self)->SignatureAlgorithm {self.inner.algorithm()}
    fn public_key(&self)->Option<SubjectPublicKeyInfoDer<'_>> {Some(self.spki.as_slice().into())}
}
fn public_key(der:&PrivateKeyDer<'_>)->Option<Vec<u8>> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    if let Ok(key)=match der {PrivateKeyDer::Pkcs1(k)=>rsa::RsaPrivateKey::from_pkcs1_der(k.secret_pkcs1_der()).map_err(|_|()),PrivateKeyDer::Pkcs8(k)=>rsa::RsaPrivateKey::from_pkcs8_der(k.secret_pkcs8_der()).map_err(|_|()),_=>Err(())} {
        return key.to_public_key().to_public_key_der().ok().map(|v|v.as_bytes().to_vec());
    }
    if let Some(key)=match der {PrivateKeyDer::Sec1(k)=>p256::SecretKey::from_sec1_der(k.secret_sec1_der()).ok(),PrivateKeyDer::Pkcs8(k)=>p256::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok(),_=>None} {return key.public_key().to_public_key_der().ok().map(|v|v.as_bytes().to_vec());}
    if let Some(key)=match der {PrivateKeyDer::Sec1(k)=>p384::SecretKey::from_sec1_der(k.secret_sec1_der()).ok(),PrivateKeyDer::Pkcs8(k)=>p384::SecretKey::from_pkcs8_der(k.secret_pkcs8_der()).ok(),_=>None} {return key.public_key().to_public_key_der().ok().map(|v|v.as_bytes().to_vec());}
    if let PrivateKeyDer::Pkcs8(k)=der {if let Ok(key)=ed25519_dalek::SigningKey::from_pkcs8_der(k.secret_pkcs8_der()) {return key.verifying_key().to_public_key_der().ok().map(|v|v.as_bytes().to_vec());}}
    None
}
