//! Extend ECDSA with P-521/SHA-512 and enforce explicit RSA key size bounds.
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id},
};
use sha2::Digest;
use std::sync::OnceLock;

mod rsa;

macro_rules! verifier {
    ($name:ident, $curve:ident, $public_id:ident, $hash:ident, $signature_id:ident) => {
        #[derive(Debug)]
        struct $name;
        impl SignatureVerificationAlgorithm for $name {
            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$public_id
            }
            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                alg_id::$signature_id
            }
            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                let key = $curve::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let signature =
                    $curve::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                let digest = sha2::$hash::digest(message);
                // ECDSA interprets shorter digests as an integer with leading
                // zeroes. RustCrypto rejects SHA-256's 32 bytes for P-521
                // before doing that padding (its minimum is 66 / 2 bytes).
                let mut padded = [0u8; 66];
                let hash = if alg_id::$public_id == alg_id::ECDSA_P521 {
                    padded[66 - digest.len()..].copy_from_slice(&digest);
                    padded.as_slice()
                } else {
                    &digest[..]
                };
                key.verify_prehash(hash, &signature)
                    .map_err(|_| InvalidSignature)
            }
        }
    };
}
verifier!(P521Sha256, p521, ECDSA_P521, Sha256, ECDSA_SHA256);
verifier!(P521Sha384, p521, ECDSA_P521, Sha384, ECDSA_SHA384);
verifier!(P521Sha512, p521, ECDSA_P521, Sha512, ECDSA_SHA512);
verifier!(P256Sha512, p256, ECDSA_P256, Sha512, ECDSA_SHA512);
verifier!(P384Sha512, p384, ECDSA_P384, Sha512, ECDSA_SHA512);

pub(super) fn algorithms() -> WebPkiSupportedAlgorithms {
    static ALGORITHMS: OnceLock<WebPkiSupportedAlgorithms> = OnceLock::new();
    *ALGORITHMS.get_or_init(|| {
        let base = rustls_rustcrypto::provider().signature_verification_algorithms;
        let replace = |algorithm: &'static dyn SignatureVerificationAlgorithm| {
            if algorithm.public_key_alg_id() == alg_id::RSA_ENCRYPTION {
                rsa::replacement(algorithm.signature_alg_id()).unwrap_or(algorithm)
            } else {
                algorithm
            }
        };
        let mut all: Vec<_> = base.all.iter().copied().map(replace).collect();
        all.extend_from_slice(&[
            &P521Sha256,
            &P521Sha384,
            &P521Sha512,
            &P256Sha512,
            &P384Sha512,
        ]);
        let mut mapping = base.mapping.to_vec();
        for (scheme, algorithms) in &mut mapping {
            if algorithms
                .iter()
                .any(|v| v.public_key_alg_id() == alg_id::RSA_ENCRYPTION)
            {
                *algorithms = Box::leak(
                    algorithms
                        .iter()
                        .copied()
                        .map(replace)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                );
            }
            let extra: Option<&'static dyn SignatureVerificationAlgorithm> = match scheme {
                SignatureScheme::ECDSA_NISTP256_SHA256 => Some(&P521Sha256),
                SignatureScheme::ECDSA_NISTP384_SHA384 => Some(&P521Sha384),
                _ => None,
            };
            if let Some(extra) = extra {
                let mut extended = algorithms.to_vec();
                extended.push(extra);
                *algorithms = Box::leak(extended.into_boxed_slice());
            }
        }
        // TLS 1.3 takes the first algorithm (fixed curve); TLS 1.2 can try all.
        mapping.push((
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[&P521Sha512, &P256Sha512, &P384Sha512],
        ));
        WebPkiSupportedAlgorithms {
            all: Box::leak(all.into_boxed_slice()),
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    })
}
