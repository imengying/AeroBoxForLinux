//! Controlled ClientHello construction before transcript hashing.
use super::{ClientConfig, hs::ClientContext};
use crate::crypto::SecureRandom;
use crate::msgs::base::{PayloadU8, PayloadU16};
use crate::msgs::enums::{ExtensionType, HpkeAead, HpkeKdf};
use crate::msgs::handshake::{
    ClientHelloPayload, ClientSessionTicket, EncryptedClientHello, EncryptedClientHelloOuter,
    HpkeSymmetricCipherSuite, KeyShareEntry,
};
use crate::{CipherSuite, Error, NamedGroup, ProtocolVersion, SignatureScheme};
use alloc::{vec, vec::Vec};

/// A wire construction policy, separate from certificate authentication.
///
/// This is not an application-level browser compatibility promise. TLS 1.2
/// renegotiation requires separate validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientHelloLayout {
    /// The initial Chrome 133 ClientHello structure pinned by AeroBox.
    /// Requires all listed cryptographic capabilities, TLS 1.2/1.3, Brotli,
    /// ALPS 17613 for h2 and independent hybrid/X25519 initial shares.
    /// ECH keeps this outer layout and uses a TLS 1.3 inner hello. This does
    /// not prescribe the browser's private inner-hello encoding. REALITY
    /// authenticates with the independent X25519 share. QUIC is rejected.
    Chrome133,
}

pub(super) const CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const SIGNATURES: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const GROUPS: &[u16] = &[4588, 29, 23, 24];
const EXTENSIONS: &[u16] = &[
    0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17613, 65037,
];

fn invalid() -> Error {
    Error::General("Chrome133 ClientHello layout conflicts with configured TLS capabilities".into())
}
impl ClientHelloLayout {
    pub(super) fn permits_group(self, group: NamedGroup) -> bool {
        GROUPS.contains(&u16::from(group))
    }

    pub(super) fn permits_signature(self, scheme: SignatureScheme) -> bool {
        SIGNATURES.contains(&u16::from(scheme))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct WireEncoding {
    pub(crate) grease: [u16; 5],
    pub(crate) extensions: Vec<ExtensionType>,
}

pub(super) struct LayoutState {
    encoding: WireEncoding,
    ech: Option<EncryptedClientHello>,
    reality: bool,
}
impl LayoutState {
    pub(super) fn new(
        config: &ClientConfig,
        cx: &ClientContext<'_>,
    ) -> Result<Option<Self>, Error> {
        let Some(ClientHelloLayout::Chrome133) = config.client_hello_layout else {
            return Ok(None);
        };
        let signatures = config
            .verifier
            .supported_verify_schemes();
        let reality = cx.data.reality.is_some();
        let initial_groups: &[NamedGroup] = if reality {
            &[NamedGroup::X25519]
        } else {
            &[NamedGroup::X25519MLKEM768, NamedGroup::X25519]
        };
        if config.client_hello_profile.is_some()
            || cx.common.is_quic()
            || matches!(config.ech_mode, Some(super::EchMode::Grease(_)))
            || !config
                .versions
                .contains(ProtocolVersion::TLSv1_3)
            || config.initial_key_share_groups != initial_groups
            || CIPHERS.iter().any(|suite| {
                !config
                    .provider
                    .cipher_suites
                    .iter()
                    .any(|s| u16::from(s.suite()) == *suite)
            })
            || SIGNATURES
                .iter()
                .any(|scheme| !signatures.contains(&SignatureScheme::from(*scheme)))
            || GROUPS.iter().any(|group| {
                if reality && *group == 4588 {
                    return false;
                }
                config
                    .find_kx_group(NamedGroup::from(*group), ProtocolVersion::TLSv1_3)
                    .is_none()
            })
            || config.cert_decompressors.len() != 1
            || u16::from(config.cert_decompressors[0].algorithm()) != 2
            || !config
                .application_settings
                .as_ref()
                .is_some_and(|s| {
                    s.codepoint == super::ApplicationSettingsCodepoint::Chrome
                        && s.settings(b"h2").is_some()
                })
            || config.alpn_protocols.is_empty()
            || config.send_ticket_request.is_some()
        {
            return Err(invalid());
        }
        let rng = config.provider.secure_random;
        let mut random = [0; 7];
        rng.fill(&mut random)?;
        let mut grease = [0; 5];
        for (value, byte) in grease.iter_mut().zip(&random) {
            let byte = u16::from((byte & 0xf0) | 0x0a);
            *value = byte | (byte << 8);
        }
        if grease[2] == grease[3] {
            grease[3] ^= 0x1010;
        }
        let mut extensions: Vec<_> = EXTENSIONS
            .iter()
            .map(|v| ExtensionType::from(*v))
            .collect();
        // Match the pinned uTLS shuffle's fixed first/last GREASE slots: a
        // sampled swap involving slot zero is skipped. Entropy errors fail.
        for slot in (1..=extensions.len()).rev() {
            let next = choose(rng, slot + 1)?;
            if next != 0 {
                extensions.swap(slot - 1, next - 1);
            }
        }
        let ech = if config.ech_mode.is_none() {
            let group = config
                .find_kx_group(NamedGroup::X25519, ProtocolVersion::TLSv1_3)
                .ok_or_else(invalid)?;
            let encapsulated = group.start()?.pub_key().to_vec();
            let mut payload = vec![0; 144 + usize::from(random[5] & 3) * 32];
            rng.fill(&mut payload)?;
            Some(EncryptedClientHello::Outer(EncryptedClientHelloOuter {
                cipher_suite: HpkeSymmetricCipherSuite {
                    kdf_id: HpkeKdf::from(1),
                    aead_id: HpkeAead::from(1),
                },
                config_id: random[6],
                enc: PayloadU16::new(encapsulated),
                payload: PayloadU16::new(payload),
            }))
        } else {
            None
        };
        Ok(Some(Self {
            encoding: WireEncoding { grease, extensions },
            ech,
            reality,
        }))
    }

    pub(super) fn apply(
        &self,
        hello: &mut ClientHelloPayload,
        changed_group: bool,
    ) -> Result<(), Error> {
        hello.cipher_suites = core::iter::once(CipherSuite::from(self.encoding.grease[0]))
            .chain(
                CIPHERS
                    .iter()
                    .map(|v| CipherSuite::from(*v)),
            )
            .collect();
        hello.named_groups = Some(
            core::iter::once(NamedGroup::from(self.encoding.grease[1]))
                .chain(
                    GROUPS
                        .iter()
                        .filter(|group| !self.reality || **group != 4588)
                        .map(|v| NamedGroup::from(*v)),
                )
                .collect(),
        );
        hello.signature_schemes = Some(
            SIGNATURES
                .iter()
                .map(|v| SignatureScheme::from(*v))
                .collect(),
        );
        hello.renegotiation_info = Some(PayloadU8::new(vec![]));
        hello.sct_request = Some(());
        if !hello
            .application_settings
            .as_ref()
            .is_some_and(|names| names.len() == 1 && names[0].as_ref() == b"h2")
        {
            return Err(invalid());
        }
        // Chrome requests TLS 1.2 tickets even without a client-side cache.
        if hello.session_ticket.is_none() {
            hello.session_ticket = Some(ClientSessionTicket::Request);
        }
        if !changed_group {
            hello
                .key_shares
                .as_mut()
                .ok_or_else(invalid)?
                .insert(
                    0,
                    KeyShareEntry::new(NamedGroup::from(self.encoding.grease[1]), &[0]),
                );
        }
        // The cover hello retains the pinned TLS 1.2/1.3 offer. ECH's inner
        // hello and the actual version policy remain TLS 1.3 only.
        if let Some(versions) = &mut hello.supported_versions {
            versions.tls12 = true;
        }
        if let Some(ech) = &self.ech {
            hello.encrypted_client_hello = Some(ech.clone());
        }
        // Never discard a caller's non-template extension silently.
        if hello.collect_used().iter().any(|typ| {
            !self.encoding.extensions.contains(typ)
                && !matches!(
                    typ,
                    ExtensionType::Cookie | ExtensionType::PreSharedKey | ExtensionType::EarlyData
                )
        }) {
            return Err(invalid());
        }
        hello.wire_encoding = Some(self.encoding.clone());
        Ok(())
    }
}
fn choose(rng: &dyn SecureRandom, upper: usize) -> Result<usize, Error> {
    let limit = 256 - (256 % upper);
    loop {
        let mut byte = [0];
        rng.fill(&mut byte)?;
        let value = usize::from(byte[0]);
        if value < limit {
            return Ok(value % upper);
        }
    }
}
