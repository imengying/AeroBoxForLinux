//! Legacy VMess header authentication. Payload framing and AEAD ciphers are
//! shared with modern VMess; only the request and response headers differ.
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;

use super::md5::compute_md5;

pub(super) fn alter_key(user_id: &[u8]) -> [u8; 16] {
    let mut input = user_id.to_vec();
    input.extend_from_slice(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81");
    loop {
        let derived = compute_md5(&input);
        if derived != user_id {
            return derived;
        }
        input.extend_from_slice(b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2");
    }
}

pub(super) fn request(
    auth_key: &[u8; 16],
    instruction_key: &[u8; 16],
    timestamp: u64,
    header: &mut [u8],
) -> Vec<u8> {
    let time = timestamp.to_be_bytes();
    let mut auth = Hmac::<Md5>::new_from_slice(auth_key).expect("HMAC accepts a 16-byte key");
    auth.update(&time);
    let iv = compute_md5(&time.repeat(4));
    cfb_mode::Encryptor::<aes::Aes128>::new(instruction_key.into(), (&iv).into()).encrypt(header);
    let mut request = Vec::with_capacity(16 + header.len());
    request.extend_from_slice(&auth.finalize().into_bytes());
    request.extend_from_slice(header);
    request
}

pub(super) fn response(key: &[u8; 16], iv: &[u8; 16], header: &mut [u8; 4]) {
    cfb_mode::Decryptor::<aes::Aes128>::new(key.into(), iv.into()).decrypt(header);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_independent_go_vector() {
        let user = crate::uuid_util::parse_uuid("00000000-0000-4000-8000-000000000001").unwrap();
        let mut material = user.clone();
        material.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let key = compute_md5(&material);
        let mut header: Vec<u8> = (0..57).collect();
        let request = request(&alter_key(&user), &key, 1_700_000_000, &mut header);
        assert_eq!(
            request
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            include_str!("../../tests/fixtures/vmess-legacy/request.hex").trim()
        );
    }
}
