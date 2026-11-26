//! Transport-related configuration types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::address::{NetLocation, NetLocationPortRange};
use crate::option_util::{NoneOrOne, NoneOrSome, OneOrSome};

use super::common::default_true;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BindLocation {
    #[serde(alias = "addresses")]
    Address(OneOrSome<NetLocationPortRange>),
    Path(PathBuf),
    #[serde(untagged)]
    Unspecified {},
}

impl std::fmt::Display for BindLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindLocation::Address(addresses) => {
                for (index, address) in addresses.iter().enumerate() {
                    if index > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{address}")?;
                }
                Ok(())
            }
            BindLocation::Path(p) => write!(f, "{}", p.display()),
            BindLocation::Unspecified {} => f.write_str("no listener"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Tcp,
    Quic,
    Udp,
}

impl Transport {
    /// Returns true if this is the default transport (TCP)
    pub fn is_default(&self) -> bool {
        matches!(self, Transport::Tcp)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TcpConfig {
    #[serde(default = "default_true")]
    pub no_delay: bool,
    #[serde(default = "default_true")]
    pub keep_alive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_alive_time_secs: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_alive_interval_secs: Option<u16>,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            no_delay: true,
            keep_alive: true,
            keep_alive_time_secs: None,
            keep_alive_interval_secs: None,
        }
    }
}

impl TcpConfig {
    pub(crate) fn validate(&self) -> std::io::Result<()> {
        for (name, value) in [
            ("keep_alive_time_secs", self.keep_alive_time_secs),
            ("keep_alive_interval_secs", self.keep_alive_interval_secs),
        ] {
            if value.is_some_and(|value| !(1..=32767).contains(&value)) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{name} must be in 1..32767 seconds"),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn keepalive_durations(
        &self,
        default_time: u16,
        default_interval: u16,
    ) -> (std::time::Duration, std::time::Duration) {
        if !self.keep_alive {
            return (std::time::Duration::ZERO, std::time::Duration::ZERO);
        }
        (
            std::time::Duration::from_secs(
                self.keep_alive_time_secs.unwrap_or(default_time).into(),
            ),
            std::time::Duration::from_secs(
                self.keep_alive_interval_secs
                    .unwrap_or(default_interval)
                    .into(),
            ),
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerQuicConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_source: Option<String>,
    #[serde(skip)]
    pub certificate_binding: Option<std::sync::Arc<crate::certificates::Source>>,
    #[serde(
        default,
        skip_serializing_if = "super::tls::TlsKeyExchangeGroups::is_default"
    )]
    pub key_exchange_groups: super::tls::TlsKeyExchangeGroups,
    #[serde(default)]
    pub cert: String,
    #[serde(default)]
    pub key: String,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(alias = "client_ca_cert", default)]
    pub client_ca_certs: NoneOrSome<String>,
    #[serde(alias = "client_fingerprint", default)]
    pub client_fingerprints: NoneOrSome<String>,
    // num_endpoints of 0 will use the number of threads as the default value.
    #[serde(default)]
    pub num_endpoints: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientQuicConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<ClientQuicTransportConfig>,
    #[serde(
        default,
        skip_serializing_if = "super::tls::TlsClientOptions::is_default"
    )]
    pub options: super::tls::TlsClientOptions,
    #[serde(
        default,
        skip_serializing_if = "super::tls::TlsKeyExchangeGroups::is_default"
    )]
    pub key_exchange_groups: super::tls::TlsKeyExchangeGroups,
    #[serde(default = "default_true")]
    pub verify: bool,
    #[serde(alias = "server_fingerprint", default)]
    pub server_fingerprints: NoneOrSome<String>,
    #[serde(default)]
    pub sni_hostname: NoneOrOne<String>,
    #[serde(alias = "alpn_protocol", default)]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
}

impl Default for ClientQuicConfig {
    fn default() -> Self {
        Self {
            transport: None,
            options: Default::default(),
            key_exchange_groups: Default::default(),
            verify: true,
            server_fingerprints: NoneOrSome::Unspecified,
            sni_hostname: NoneOrOne::Unspecified,
            alpn_protocols: NoneOrSome::Unspecified,
            key: None,
            cert: None,
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientQuicTransportConfig {
    pub initial_packet_size: u16,
    pub disable_path_mtu_discovery: bool,
    pub idle_timeout_ms: u32,
    pub keep_alive_period_ms: u32,
    pub stream_receive_window: u32,
    pub connection_receive_window: u32,
    pub max_concurrent_streams: u32,
}

impl ClientQuicTransportConfig {
    pub(crate) fn validate(&self, overhead: u16) -> std::io::Result<()> {
        for (field, value, min, max) in [
            (
                "initial_packet_size",
                u32::from(self.initial_packet_size),
                1200,
                u32::from(1452 - overhead),
            ),
            (
                "stream_receive_window",
                self.stream_receive_window,
                16 * 1024,
                64 * 1024 * 1024,
            ),
            (
                "connection_receive_window",
                self.connection_receive_window,
                16 * 1024,
                128 * 1024 * 1024,
            ),
            (
                "max_concurrent_streams",
                self.max_concurrent_streams,
                1,
                1024,
            ),
        ] {
            if value != 0 && !(min..=max).contains(&value) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("QUIC {field} must be zero (default) or {min}..{max}"),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn apply(
        &self,
        config: &mut quinn::TransportConfig,
        overhead: u16,
    ) -> std::io::Result<()> {
        self.validate(overhead)?;
        if self.initial_packet_size != 0 {
            config.initial_mtu(self.initial_packet_size);
        }
        if self.disable_path_mtu_discovery {
            config.mtu_discovery_config(None);
        }
        if self.idle_timeout_ms != 0 {
            config.max_idle_timeout(Some(quinn::VarInt::from_u32(self.idle_timeout_ms).into()));
        }
        if self.keep_alive_period_ms != 0 {
            config.keep_alive_interval(Some(std::time::Duration::from_millis(
                self.keep_alive_period_ms.into(),
            )));
        }
        if self.stream_receive_window != 0 {
            config.stream_receive_window(self.stream_receive_window.into());
        }
        if self.connection_receive_window != 0 {
            config.receive_window(self.connection_receive_window.into());
        }
        if self.max_concurrent_streams != 0 {
            // sing-quic applies this field to peer-initiated bidirectional streams.
            config.max_concurrent_bidi_streams(self.max_concurrent_streams.into());
        }
        Ok(())
    }
}

impl From<NetLocation> for BindLocation {
    fn from(loc: NetLocation) -> Self {
        BindLocation::Address(OneOrSome::One(loc.into()))
    }
}
