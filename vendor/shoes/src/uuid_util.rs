use std::fmt::Write;

use aerobox_primitives::rand::{SecureRandom, SystemRandom};

/// Parse a protocol's 128-bit identity in compact or canonical UUID notation.
/// VMess/VLESS identifiers need not have v4 or RFC variant bits. Reject syntax
/// errors without including the credential in diagnostics.
#[inline]
pub fn parse_uuid(uuid_str: &str) -> std::io::Result<Vec<u8>> {
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid UUID: expected 32 hexadecimal digits or canonical 8-4-4-4-12 notation",
        )
    };
    if !matches!(uuid_str.len(), 32 | 36) {
        return Err(invalid());
    }
    uuid::Uuid::parse_str(uuid_str)
        .map(|id| id.as_bytes().to_vec())
        .map_err(|_| invalid())
}

/// Generate a random UUID v4 and return it as a formatted string.
#[inline]
pub fn generate_uuid() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).expect("RNG failed");

    // Set version (4) in bits 12-15 of byte 6
    bytes[6] = (bytes[6] & 0x0f) | 0x40;

    // Set variant (RFC 4122) in bits 6-7 of byte 8
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let mut s = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_uuid_format() {
        let uuid = generate_uuid();
        // Check format: 8-4-4-4-12
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().nth(8), Some('-'));
        assert_eq!(uuid.chars().nth(13), Some('-'));
        assert_eq!(uuid.chars().nth(18), Some('-'));
        assert_eq!(uuid.chars().nth(23), Some('-'));

        // Check version (4) at position 14
        assert_eq!(uuid.chars().nth(14), Some('4'));

        // Check variant at position 19 (must be 8, 9, a, or b)
        let variant_char = uuid.chars().nth(19).unwrap();
        assert!(
            variant_char == '8'
                || variant_char == '9'
                || variant_char == 'a'
                || variant_char == 'b'
        );
    }

    #[test]
    fn test_generate_uuid_roundtrip() {
        let uuid = generate_uuid();
        let bytes = parse_uuid(&uuid).unwrap();
        assert_eq!(bytes.len(), 16);

        // Verify version nibble
        assert_eq!(bytes[6] >> 4, 4);

        // Verify variant bits
        assert_eq!(bytes[8] >> 6, 2);
    }

    #[test]
    fn test_parse_uuid_with_dashes() {
        // Valid v4 UUID (version=4, variant=10xx)
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let bytes = parse_uuid(uuid).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x0e);
    }

    #[test]
    fn test_parse_uuid_without_dashes() {
        // Valid v4 UUID (version=4, variant=10xx)
        let uuid = "550e8400e29b41d4a716446655440000";
        let bytes = parse_uuid(uuid).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x0e);
    }

    #[test]
    fn test_parse_uuid_accepts_non_v4() {
        // Version 1 UUID (version nibble = 1)
        let uuid = "550e8400-e29b-11d4-a716-446655440000";
        assert_eq!(parse_uuid(uuid).unwrap().len(), 16);
    }

    #[test]
    fn test_parse_uuid_accepts_non_rfc_variant() {
        // Wrong variant (upper 2 bits of byte 8 = 11 instead of 10)
        let uuid = "550e8400-e29b-41d4-c716-446655440000";
        assert_eq!(parse_uuid(uuid).unwrap().len(), 16);
    }
}

#[cfg(test)]
mod malformed_tests {
    use super::parse_uuid;

    #[test]
    fn malformed_identities_do_not_expose_secrets() {
        for input in [
            "secret-value",
            "550e8400e29b41d4a71644665544000",
            "550e8400-e29b41d4-a716-446655440000",
            "-550e8400e29b41d4a716446655440000---",
            "550e8400-e29b-41d4-a716-44665544000z",
        ] {
            let error = parse_uuid(input).unwrap_err();
            assert!(!error.to_string().contains(input));
        }
    }
}
