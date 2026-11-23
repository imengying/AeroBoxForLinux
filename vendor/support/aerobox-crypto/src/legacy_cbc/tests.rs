use super::*;

fn cipher(bits: usize) -> Cipher {
    Cipher::from_slices(bits / 8, &vec![0x11; bits / 8], &[], &[0x22; MAC_SIZE]).unwrap()
}
fn encoded(bits: usize, plain: &[u8], pad: usize) -> Vec<u8> {
    let cipher = cipher(bits);
    assert!((plain.len() + MAC_SIZE + pad).is_multiple_of(BLOCK));
    assert!((1..=256).contains(&pad));
    let iv = [0x33; BLOCK];
    let mut output = Vec::from(iv);
    output.extend_from_slice(plain);
    output.extend_from_slice(&cipher.tag(
        42,
        rustls::ContentType::ApplicationData,
        rustls::ProtocolVersion::TLSv1_2,
        plain,
    ));
    output.extend(std::iter::repeat_n((pad - 1) as u8, pad));
    cipher.encrypt_blocks(&mut output[BLOCK..], iv);
    output
}
fn decrypt<'a>(cipher: &mut Cipher, bytes: &'a mut [u8], seq: u64) -> Result<&'a [u8], Error> {
    cipher
        .decrypt(
            InboundOpaqueMessage::new(
                rustls::ContentType::ApplicationData,
                rustls::ProtocolVersion::TLSv1_2,
                bytes,
            ),
            seq,
        )
        .map(|m| m.payload)
}
#[test]
fn both_key_sizes_round_trip_boundary_lengths_and_unique_explicit_iv() {
    for bits in [128, 256] {
        let mut enc = cipher(bits);
        let mut dec = cipher(bits);
        for (index, length) in [0, 1, 11, 12, 15, 16, 17, 255, 1024, 16384]
            .into_iter()
            .enumerate()
        {
            let plain: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let message = || OutboundPlainMessage {
                typ: rustls::ContentType::ApplicationData,
                version: rustls::ProtocolVersion::TLSv1_2,
                payload: plain.as_slice().into(),
            };
            let sequence = (index as u64) * 2;
            let one = enc.encrypt(message(), sequence).unwrap();
            let two = enc.encrypt(message(), sequence + 1).unwrap();
            let mut bytes = one.payload.as_ref().to_vec();
            assert_eq!(bytes.len(), enc.encrypted_payload_len(length));
            assert_ne!(&bytes[..16], &two.payload.as_ref()[..16]);
            assert_eq!(decrypt(&mut dec, &mut bytes, sequence).unwrap(), plain);
            let mut bytes = two.payload.as_ref().to_vec();
            assert_eq!(decrypt(&mut dec, &mut bytes, sequence + 1).unwrap(), plain);
        }
    }
}

#[test]
fn iv_permutation_separates_keys_directions_and_sequence_boundaries() {
    for bits in [128, 256] {
        let key = vec![0x11; bits / 8];
        let original = Cipher::from_slices(bits / 8, &key, &[], &[0x22; MAC_SIZE]).unwrap();
        let other_mac = Cipher::from_slices(bits / 8, &key, &[], &[0x23; MAC_SIZE]).unwrap();
        let other_key =
            Cipher::from_slices(bits / 8, &vec![0x12; bits / 8], &[], &[0x22; MAC_SIZE]).unwrap();
        let mut ivs = std::collections::HashSet::new();
        for seq in [
            0,
            1,
            255,
            256,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX,
        ] {
            let iv = original.explicit_iv(seq);
            assert!(ivs.insert(iv));
            assert_ne!(iv, other_mac.explicit_iv(seq));
            assert_ne!(iv, other_key.explicit_iv(seq));
            // The IV must not expose the sequence, or use the record cipher
            // directly under its traffic encryption key.
            let mut counter = [0u8; BLOCK];
            counter[8..].copy_from_slice(&seq.to_be_bytes());
            assert_ne!(iv, counter);
            match &original.aes {
                Aes::Aes128(aes) => aes.encrypt_block((&mut counter).into()),
                Aes::Aes256(aes) => aes.encrypt_block((&mut counter).into()),
            }
            assert_ne!(iv, counter);
        }
    }
}
#[test]
fn all_tls_padding_lengths_are_accepted_and_invalid_padding_never_exposes_plaintext() {
    for pad in 1usize..=256 {
        let length = (BLOCK - (MAC_SIZE + pad) % BLOCK) % BLOCK;
        let plain = vec![0x5a; length];
        let mut bytes = encoded(128, &plain, pad);
        assert_eq!(decrypt(&mut cipher(128), &mut bytes, 42).unwrap(), plain);
        let mut bytes = encoded(128, &plain, pad);
        // Corrupt the last padding byte while keeping the content/MAC equal.
        let iv: [u8; BLOCK] = bytes[..BLOCK].try_into().unwrap();
        cipher(128).decrypt_blocks(&mut bytes[BLOCK..], iv);
        *bytes.last_mut().unwrap() ^= 1;
        cipher(128).encrypt_blocks(&mut bytes[BLOCK..], iv);
        assert!(matches!(
            decrypt(&mut cipher(128), &mut bytes, 42),
            Err(Error::DecryptError)
        ));
    }
}
#[test]
fn mac_iv_sequence_record_type_and_lengths_cannot_be_forged() {
    let good = encoded(256, b"abcdefghijkl", 16);
    for offset in [0, 15, 16, 31, good.len() - 1] {
        let mut bytes = good.clone();
        bytes[offset] ^= 0x80;
        assert!(matches!(
            decrypt(&mut cipher(256), &mut bytes, 42),
            Err(Error::DecryptError)
        ));
    }
    for length in 0..48 {
        let mut bytes = vec![0; length];
        assert!(decrypt(&mut cipher(128), &mut bytes, 42).is_err());
    }
    let mut bytes = vec![0; BLOCK + MAX_PLAIN + MAC_SIZE + 257];
    assert!(decrypt(&mut cipher(128), &mut bytes, 42).is_err());
    assert!(decrypt(&mut cipher(256), &mut good.clone(), 43).is_err());
    let mut bytes = good.clone();
    assert!(
        cipher(256)
            .decrypt(
                InboundOpaqueMessage::new(
                    rustls::ContentType::Handshake,
                    rustls::ProtocolVersion::TLSv1_2,
                    &mut bytes
                ),
                42
            )
            .is_err()
    );
}
#[test]
fn suites_are_opt_in_and_key_schedule_requires_independent_mac_keys() {
    for suite in suites() {
        assert!(!crate::provider().cipher_suites.contains(&suite));
    }
    assert_eq!(AES128.mac_key_len(), 20);
    assert_eq!(AES256.mac_key_len(), 20);
    let mut decoder = AES128.decrypter(AeadKey::from([0; 32]), &[]);
    assert!(
        decoder
            .decrypt(
                InboundOpaqueMessage::new(
                    rustls::ContentType::ApplicationData,
                    rustls::ProtocolVersion::TLSv1_2,
                    &mut [0; 48]
                ),
                0
            )
            .is_err()
    );
}
