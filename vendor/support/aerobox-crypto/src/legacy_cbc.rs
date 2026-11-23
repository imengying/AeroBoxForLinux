//! TLS 1.2 CBC suites used by browser compatibility profiles. Explicit opt-in;
//! the ordinary provider continues to advertise only its existing AEAD suites.
//!
//! RFC 5246 sections 6.2.3.2 and 6.3: independent HMAC keys, unpredictable
//! explicit IV, MAC over sequence/type/version/length/plaintext, TLS padding.
//!
//! The explicit IV is AES-256(iv_key, zeroes[8] || sequence_be). An HMAC-SHA256
//! KDF with its own domain label derives iv_key from both directional traffic
//! keys. It is distinct from the record encryption key. Handshake key entropy
//! supplies unpredictability; rustls never repeats a sequence within a key
//! epoch, so this permutation also avoids IV collisions in that epoch. This
//! meets RFC 5246's unpredictable-IV requirement without fallible per-record
//! entropy calls (the rustls record sender expects encryption to be infallible).
//!
//! Owned MAC keys, derived IV-key buffers and AES expanded schedules are wiped
//! on drop. RustCrypto hmac 0.12's transient ipad/opad buffers and digest states
//! do not implement zeroization; this module does not claim those are erased.
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::{CipherSuite, Error, SupportedCipherSuite, Tls12CipherSuite};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

const BLOCK: usize = 16;
const MAC_SIZE: usize = 20;
const MAX_PLAIN: usize = 16384;
const IV_KEY_LABEL: &[u8] = b"aerobox/tls12-cbc-explicit-iv-key/v1\0";
static AES128: Algorithm = Algorithm(16);
static AES256: Algorithm = Algorithm(32);

pub static TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    &AES128,
);
pub static TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    &AES256,
);
pub static TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    &super::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &AES128,
);
pub static TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    &super::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &AES256,
);
/// CBC-SHA uses HMAC-SHA1 on records but the TLS 1.2 PRF/transcript uses SHA256.
const fn suite(
    id: CipherSuite,
    base: &'static Tls12CipherSuite,
    alg: &'static Algorithm,
) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: id,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: 1 << 24,
        },
        prf_provider: base.prf_provider,
        kx: base.kx,
        sign: base.sign,
        aead_alg: alg,
    }
}
/// These are available for an explicit legacy suite/profile, never as a default.
pub fn suites() -> [SupportedCipherSuite; 4] {
    [
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
    ]
}
struct Algorithm(usize);
impl Tls12AeadAlgorithm for Algorithm {
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.0,
            fixed_iv_len: 0,
            explicit_nonce_len: 0,
        }
    }
    fn mac_key_len(&self) -> usize {
        MAC_SIZE
    }
    fn encrypter(&self, _: AeadKey, _: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Invalid)
    }
    fn decrypter(&self, _: AeadKey, _: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Invalid)
    }
    fn encrypter_with_mac(
        &self,
        key: AeadKey,
        iv: &[u8],
        extra: &[u8],
        mac: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        match Cipher::new(self.0, key, iv, mac).filter(|_| extra.is_empty()) {
            Some(cipher) => Box::new(cipher),
            None => Box::new(Invalid),
        }
    }
    fn decrypter_with_mac(&self, key: AeadKey, iv: &[u8], mac: &[u8]) -> Box<dyn MessageDecrypter> {
        match Cipher::new(self.0, key, iv, mac) {
            Some(cipher) => Box::new(cipher),
            None => Box::new(Invalid),
        }
    }
    fn extract_keys(
        &self,
        _: AeadKey,
        _: &[u8],
        _: &[u8],
    ) -> Result<rustls::ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}
struct Invalid;
impl MessageEncrypter for Invalid {
    fn encrypt(
        &mut self,
        _: OutboundPlainMessage<'_>,
        _: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }
    fn encrypted_payload_len(&self, n: usize) -> usize {
        wire_len(n)
    }
}
impl MessageDecrypter for Invalid {
    fn decrypt<'a>(
        &mut self,
        _: InboundOpaqueMessage<'a>,
        _: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}
#[allow(clippy::large_enum_variant)]
enum Aes {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}
struct Cipher {
    aes: Aes,
    mac: Zeroizing<[u8; MAC_SIZE]>,
    iv_prf: aes::Aes256,
}
impl Cipher {
    fn new(length: usize, key: AeadKey, iv: &[u8], mac: &[u8]) -> Option<Self> {
        Self::from_slices(length, key.as_ref(), iv, mac)
    }
    fn from_slices(length: usize, key: &[u8], iv: &[u8], mac: &[u8]) -> Option<Self> {
        if key.len() != length || !iv.is_empty() || mac.len() != MAC_SIZE {
            return None;
        }
        let aes = match length {
            16 => Aes::Aes128(aes::Aes128::new_from_slice(key).ok()?),
            32 => Aes::Aes256(aes::Aes256::new_from_slice(key).ok()?),
            _ => return None,
        };
        let mut derive = <Hmac<sha2::Sha256> as Mac>::new_from_slice(mac).ok()?;
        derive.update(IV_KEY_LABEL);
        derive.update(&(length as u16).to_be_bytes());
        derive.update(key);
        let mut iv_key = Zeroizing::new([0u8; 32]);
        // Finalize directly into the zeroizing buffer, without another owned
        // output-key copy. HMAC's internal state has the limitation noted above.
        sha2::digest::FixedOutput::finalize_into(derive, (&mut *iv_key).into());
        let iv_prf = aes::Aes256::new_from_slice(iv_key.as_ref()).ok()?;
        Some(Self {
            aes,
            mac: Zeroizing::new(mac.try_into().ok()?),
            iv_prf,
        })
    }
    fn explicit_iv(&self, seq: u64) -> [u8; BLOCK] {
        let mut iv = [0u8; BLOCK];
        iv[8..].copy_from_slice(&seq.to_be_bytes());
        self.iv_prf.encrypt_block((&mut iv).into());
        iv
    }
    fn tag(
        &self,
        seq: u64,
        typ: rustls::ContentType,
        version: rustls::ProtocolVersion,
        plain: &[u8],
    ) -> [u8; MAC_SIZE] {
        let mut hmac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(self.mac.as_ref())
            .expect("fixed HMAC key length");
        hmac.update(&make_tls12_aad(seq, typ, version, plain.len()));
        hmac.update(plain);
        hmac.finalize().into_bytes().into()
    }
    fn encrypt_blocks(&self, plaintext: &mut [u8], mut previous: [u8; BLOCK]) {
        for block in plaintext.as_chunks_mut::<BLOCK>().0 {
            for (byte, old) in block.iter_mut().zip(previous) {
                *byte ^= old;
            }
            match &self.aes {
                Aes::Aes128(aes) => aes.encrypt_block((&mut *block).into()),
                Aes::Aes256(aes) => aes.encrypt_block((&mut *block).into()),
            }
            previous.copy_from_slice(block);
        }
    }
    fn decrypt_blocks(&self, ciphertext: &mut [u8], mut previous: [u8; BLOCK]) {
        for block in ciphertext.as_chunks_mut::<BLOCK>().0 {
            let next = *block;
            match &self.aes {
                Aes::Aes128(aes) => aes.decrypt_block((&mut *block).into()),
                Aes::Aes256(aes) => aes.decrypt_block((&mut *block).into()),
            }
            for (byte, old) in block.iter_mut().zip(previous) {
                *byte ^= old;
            }
            previous = next;
        }
    }
}
fn wire_len(n: usize) -> usize {
    BLOCK + (n + MAC_SIZE + 1).div_ceil(BLOCK) * BLOCK
}
impl MessageEncrypter for Cipher {
    fn encrypted_payload_len(&self, n: usize) -> usize {
        wire_len(n)
    }
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let length = msg.payload.len();
        if length > MAX_PLAIN || msg.version != rustls::ProtocolVersion::TLSv1_2 {
            return Err(Error::EncryptError);
        }
        let total = wire_len(length);
        let mut payload = PrefixedPayload::with_capacity(total);
        let iv = self.explicit_iv(seq);
        payload.extend_from_slice(&iv);
        payload.extend_from_chunks(&msg.payload);
        let tag = self.tag(seq, msg.typ, msg.version, &payload.as_ref()[BLOCK..]);
        payload.extend_from_slice(&tag);
        let pad = total - BLOCK - length - MAC_SIZE;
        let padding = [(pad - 1) as u8; BLOCK];
        payload.extend_from_slice(&padding[..pad]);
        self.encrypt_blocks(&mut payload.as_mut()[BLOCK..], iv);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }
}
impl MessageDecrypter for Cipher {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let length = msg.payload.len();
        // All early bounds depend only on the public ciphertext, never padding.
        if msg.version != rustls::ProtocolVersion::TLSv1_2
            || !(BLOCK * 3..=BLOCK + MAX_PLAIN + MAC_SIZE + 256).contains(&length)
            || !length.is_multiple_of(BLOCK)
        {
            return Err(Error::DecryptError);
        }
        let iv: [u8; BLOCK] = msg.payload[..BLOCK].try_into().unwrap();
        self.decrypt_blocks(&mut msg.payload[BLOCK..], iv);
        let decrypted = &msg.payload[BLOCK..];
        let n = decrypted.len();
        let mut valid = Choice::from(0);
        let mut chosen = 0u32;
        // Evaluate EVERY structurally possible padding/MAC position. Work and
        // memory access depend only on ciphertext length; secret padding never
        // chooses a hash input length or an address (Lucky13/padding oracle).
        // This bounded compatibility path deliberately favors auditability over
        // throughput. Ordinary connections retain AEAD and do not execute it.
        for pad in 1usize..=256 {
            let Some(plain_len) = n.checked_sub(MAC_SIZE + pad) else {
                continue;
            };
            if plain_len > MAX_PLAIN {
                continue;
            }
            let expected = (pad - 1) as u8;
            let mut padding_ok = Choice::from(1);
            for byte in &decrypted[n - pad..] {
                padding_ok &= byte.ct_eq(&expected);
            }
            let tag = self.tag(seq, msg.typ, msg.version, &decrypted[..plain_len]);
            let accepted = padding_ok & tag.ct_eq(&decrypted[plain_len..plain_len + MAC_SIZE]);
            chosen = u32::conditional_select(&chosen, &(plain_len as u32), accepted);
            valid |= accepted;
        }
        if !bool::from(valid) {
            return Err(Error::DecryptError);
        }
        Ok(msg.into_plain_message_range(BLOCK..BLOCK + chosen as usize))
    }
}

#[cfg(test)]
mod tests;
