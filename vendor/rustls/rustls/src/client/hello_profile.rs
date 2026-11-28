//! Capability-constrained Firefox ClientHello preferences.
//! Chrome133 uses the separately validated ClientHelloLayout policy.
use crate::crypto::SecureRandom;
use crate::msgs::base::{PayloadU8, PayloadU16};
use crate::msgs::enums::{ExtensionType, HpkeAead, HpkeKdf};
use crate::msgs::handshake::{
    ClientHelloPayload, EncryptedClientHello, EncryptedClientHelloOuter, HpkeSymmetricCipherSuite,
};
use crate::{CipherSuite, Error};
use alloc::vec;

/// Browser wire preferences constrained to configured cryptographic capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientHelloProfile {
    /// Firefox 120 style ordering and an independent P-256 key share.
    Firefox,
}

impl ClientHelloProfile {
    pub(crate) fn grease_ech(
        self,
        random: &dyn SecureRandom,
    ) -> Result<EncryptedClientHello, Error> {
        let mut choice = [0; 2];
        random.fill(&mut choice)?;
        let mut enc = vec![0; 32];
        random.fill(&mut enc)?;
        enc[31] &= 0x7f;
        let mut payload = vec![0; 239];
        random.fill(&mut payload)?;
        Ok(EncryptedClientHello::Outer(EncryptedClientHelloOuter {
            cipher_suite: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: if choice[1] & 1 != 0 {
                    HpkeAead::CHACHA20_POLY_1305
                } else {
                    HpkeAead::AES_128_GCM
                },
            },
            config_id: choice[0],
            enc: PayloadU16::new(enc),
            payload: PayloadU16::new(payload),
        }))
    }
    pub(crate) fn apply(self, hello: &mut ClientHelloPayload) {
        hello
            .cipher_suites
            .retain(|s| *s != CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        hello.cipher_suites.sort_by_key(|s| {
            rank(
                &[
                    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
                ],
                u16::from(*s),
            )
        });
        hello.renegotiation_info = Some(PayloadU8::empty());
        hello.extensions.hello_profile = Some(self);
        if let Some(groups) = &mut hello.named_groups {
            groups
                .sort_by_key(|group| rank(&[0x11ec, 29, 23, 24, 25, 256, 257], u16::from(*group)));
        }
        hello.certificate_compression_algorithms = None;
        if let Some(schemes) = &mut hello.signature_schemes {
            schemes.sort_by_key(|scheme| {
                rank(
                    &[
                        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
                    ],
                    u16::from(*scheme),
                )
            });
        }
        if let (Some(groups), Some(shares)) = (
            &hello.extensions.named_groups,
            &mut hello.extensions.key_shares,
        ) {
            shares.sort_by_key(|share| {
                groups
                    .iter()
                    .position(|g| *g == share.group)
            });
        }
    }
    pub(crate) fn order_extensions(self, extensions: &mut [ExtensionType]) {
        extensions.sort_by_key(|kind| {
            rank(
                &[0, 23, 0xff01, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28],
                u16::from(*kind),
            )
        });
    }
}
fn rank(order: &[u16], value: u16) -> usize {
    order
        .iter()
        .position(|v| *v == value)
        .unwrap_or(order.len())
}
