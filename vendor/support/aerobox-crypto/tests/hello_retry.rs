//! Untrusted HelloRetryRequest fields must fail before changing cryptographic state.
use rustls::{
    ClientConfig, ClientConnection, Error, NamedGroup, PeerMisbehaved, RootCertStore,
    client::{
        ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout, ClientHelloProfile,
        EchConfig,
    },
    pki_types::EchConfigListBytes,
};
use std::sync::Arc;

#[path = "../../../shoes/src/crypto/rustcrypto_kx.rs"]
mod production_hybrid;

fn config(chrome: bool, ech: bool) -> ClientConfig {
    let mut provider = aerobox_crypto::provider();
    if chrome {
        provider
            .cipher_suites
            .extend(aerobox_crypto::legacy_cbc::suites());
        provider
            .cipher_suites
            .extend(aerobox_crypto::legacy_rsa::suites());
        provider
            .kx_groups
            .insert(0, production_hybrid::group(NamedGroup::X25519MLKEM768));
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(include_bytes!("fixtures/rsa-cert.der").as_slice().into())
        .unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if chrome {
        config.alpn_protocols = vec![b"h2".to_vec()];
        config.application_settings = Some(
            ApplicationSettings::new(
                ApplicationSettingsCodepoint::Chrome,
                vec![(b"h2".to_vec(), vec![])],
            )
            .unwrap(),
        );
        config.initial_key_share_groups = vec![NamedGroup::X25519MLKEM768, NamedGroup::X25519];
        config.client_hello_layout = Some(ClientHelloLayout::Chrome133);
    }
    if ech {
        let suite = aerobox_crypto::hpke::ALL_SUPPORTED_SUITES[0];
        let (public, _) = suite.generate_key_pair().unwrap();
        let mut contents = vec![42, 0, 32];
        contents.extend(vector(&public.0));
        contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0, 11]);
        contents.extend_from_slice(b"public.test");
        contents.extend_from_slice(&[0, 0]);
        let mut encoded = vec![0xfe, 0x0d];
        encoded.extend(vector(&contents));
        config
            .set_ech_config(
                EchConfig::new(
                    EchConfigListBytes::from(vector(&encoded)),
                    aerobox_crypto::hpke::ALL_SUPPORTED_SUITES,
                )
                .unwrap(),
            )
            .unwrap();
    }
    config
}

fn vector(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    encoded.extend_from_slice(bytes);
    encoded
}

fn client(config: ClientConfig) -> (ClientConnection, Vec<u8>) {
    let mut client =
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    (client, hello)
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (value, remaining) = input.split_at(n);
    *input = remaining;
    value
}

fn read_vector<'a>(input: &mut &'a [u8], width: usize) -> &'a [u8] {
    let n = take(input, width)
        .iter()
        .fold(0usize, |n, byte| (n << 8) | usize::from(*byte));
    take(input, n)
}

fn hello_body(wire: &[u8]) -> &[u8] {
    let mut wire = wire;
    assert_eq!(take(&mut wire, 1), [22]);
    take(&mut wire, 2);
    let mut record = read_vector(&mut wire, 2);
    assert_eq!(take(&mut record, 1), [1]);
    read_vector(&mut record, 3)
}

fn shares(wire: &[u8]) -> Vec<u8> {
    // The retry ClientHello may be preceded by the compatibility CCS.
    let wire = if wire.first() == Some(&20) {
        &wire[6..]
    } else {
        wire
    };
    let mut hello = hello_body(wire);
    take(&mut hello, 34);
    read_vector(&mut hello, 1);
    read_vector(&mut hello, 2);
    read_vector(&mut hello, 1);
    let mut extensions = read_vector(&mut hello, 2);
    while !extensions.is_empty() {
        let typ = take(&mut extensions, 2);
        let value = read_vector(&mut extensions, 2);
        if typ == [0, 51] {
            return value.to_vec();
        }
    }
    panic!("missing client key shares");
}

fn retry(hello: &[u8], suite: u16, group: Option<u16>, cookie: bool, version: u16) -> Vec<u8> {
    const RANDOM: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    let mut hello = hello_body(hello);
    take(&mut hello, 34);
    let id = read_vector(&mut hello, 1);
    let mut extensions = vec![0, 43, 0, 2, 3, 4];
    if let Some(group) = group {
        extensions.extend_from_slice(&[0, 51, 0, 2]);
        extensions.extend_from_slice(&group.to_be_bytes());
    }
    if cookie {
        extensions.extend_from_slice(&[0, 44, 0, 3, 0, 1, 42]);
    }
    let mut body = version.to_be_bytes().to_vec();
    body.extend_from_slice(&RANDOM);
    body.push(id.len() as u8);
    body.extend_from_slice(id);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    body.extend(vector(&extensions));
    let mut handshake = vec![2];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend(body);
    let mut record = vec![22, 3, 3];
    record.extend(vector(&handshake));
    record
}

fn receive(client: &mut ClientConnection, mut message: &[u8]) -> Result<(), Error> {
    client.read_tls(&mut message).unwrap();
    client.process_new_packets().map(|_| ())
}

#[test]
fn hrr_rejects_tls12_ciphers_before_ech_confirmation_without_panicking() {
    for chrome in [false, true] {
        for ech in [false, true] {
            let (mut client, hello) = client(config(chrome, ech));
            let message = retry(&hello, 0xc02f, None, true, 0x0303);
            assert_eq!(
                receive(&mut client, &message),
                Err(PeerMisbehaved::SelectedUnusableCipherSuiteForVersion.into())
            );
            assert!(
                client.process_new_packets().is_err(),
                "failure must remain terminal"
            );
        }
    }
}

#[test]
fn hrr_rejects_offered_primary_and_firefox_shares_even_with_a_cookie() {
    for firefox in [false, true] {
        for explicit in [false, true] {
            for group in [29, 23] {
                if group == 23 && !firefox && !explicit {
                    continue;
                }
                for cookie in [false, true] {
                    let mut config = config(false, false);
                    config.client_hello_profile = firefox.then_some(ClientHelloProfile::Firefox);
                    if explicit {
                        config.initial_key_share_groups =
                            vec![NamedGroup::X25519, NamedGroup::secp256r1];
                    }
                    let (mut client, hello) = client(config);
                    let message = retry(&hello, 0x1301, Some(group), cookie, 0x0303);
                    assert_eq!(
                        receive(&mut client, &message),
                        Err(PeerMisbehaved::IllegalHelloRetryRequestWithOfferedGroup.into()),
                        "firefox={firefox} explicit={explicit} group={group} cookie={cookie}"
                    );
                }
            }
        }
    }
}

#[test]
fn cookie_only_hrr_retains_firefox_and_explicit_shares() {
    for firefox in [false, true] {
        for explicit in [false, true] {
            let mut config = config(false, false);
            config.client_hello_profile = firefox.then_some(ClientHelloProfile::Firefox);
            if explicit {
                config.initial_key_share_groups = vec![NamedGroup::X25519, NamedGroup::secp256r1];
            }
            let (mut client, hello) = client(config);
            let message = retry(&hello, 0x1301, None, true, 0x0303);
            receive(&mut client, &message).unwrap();
            let mut next = Vec::new();
            client.write_tls(&mut next).unwrap();
            assert_eq!(shares(&hello), shares(&next));
        }
    }
}

#[test]
fn hrr_rejects_invalid_legacy_version_and_unoffered_cipher() {
    for version in [0x0301, 0x0302, 0x0304] {
        let (mut client, hello) = client(config(false, false));
        let message = retry(&hello, 0x1301, None, true, version);
        assert_eq!(
            receive(&mut client, &message),
            Err(PeerMisbehaved::IllegalHelloRetryRequestWithUnsupportedVersion.into())
        );
    }
    let (mut client, hello) = client(config(false, false));
    let message = retry(&hello, 0x1304, None, true, 0x0303);
    assert_eq!(
        receive(&mut client, &message),
        Err(PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedCipherSuite.into())
    );
}
