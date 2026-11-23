//! Client configuration types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::address::NetLocation;
use crate::h2mux::{H2MuxOptions, MuxProtocol};
use crate::option_util::{NoneOrOne, NoneOrSome};

use super::common::{
    default_reality_client_short_id, default_true, is_false, is_true, unspecified_address,
};
use super::server::WebsocketPingType;
use super::shadowsocks::ShadowsocksConfig;
use super::transport::{ClientQuicConfig, TcpConfig, Transport};

/// Payload framing inside VMess/VLESS UDP streams. This is independent of
/// the carrier and of the administrative `udp_enabled` switch.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum PacketEncoding {
    #[default]
    #[serde(rename = "")]
    Raw,
    #[serde(rename = "xudp")]
    Xudp,
    #[serde(rename = "packetaddr")]
    PacketAddr,
}
impl PacketEncoding {
    pub fn is_raw(&self) -> bool {
        *self == Self::Raw
    }
    pub(crate) fn is_xudp(self) -> bool {
        self == Self::Xudp
    }
}

/// Configuration for h2mux (HTTP/2 multiplexing) on protocols that support it.
///
/// H2MUX multiplexes multiple proxy streams over a single HTTP/2 connection,
/// reducing connection overhead and improving performance for many concurrent streams.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct H2MuxConfig {
    #[serde(default)]
    pub protocol: MuxProtocol,
    /// Maximum number of connections to maintain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,

    /// Minimum number of streams before opening a new connection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_streams: Option<u32>,

    /// Maximum number of streams per connection (0 = unlimited)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<u32>,

    /// Enable padding for traffic obfuscation
    #[serde(default, skip_serializing_if = "is_false")]
    pub padding: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MultiplexConfig<P> {
    pub settings: H2MuxConfig,
    pub protocol: Box<P>,
}
impl<P> MultiplexConfig<P> {
    pub fn validate(&self) -> std::io::Result<()> {
        self.settings.validate()
    }
    pub(crate) fn map<T>(self, f: impl FnOnce(P) -> T) -> MultiplexConfig<T> {
        MultiplexConfig {
            settings: self.settings,
            protocol: Box::new(f(*self.protocol)),
        }
    }
}
impl H2MuxConfig {
    pub fn validate(&self) -> std::io::Result<()> {
        if self.max_connections.is_some_and(|n| n > 64) || self.max_streams.is_some_and(|n| n > 128)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "multiplex limits: at most 64 connections and 128 streams per connection",
            ));
        }
        Ok(())
    }

    /// Converts this config to H2MuxOptions for the client handler.
    pub fn to_options(&self) -> H2MuxOptions {
        H2MuxOptions {
            protocol: self.protocol,
            max_connections: self.max_connections.unwrap_or(4),
            min_streams: self.min_streams.unwrap_or(4),
            max_streams: self.max_streams.unwrap_or(0),
            padding: self.padding,
        }
    }
}

/// Custom deserializer for ClientProxyConfig::Shadowsocks
fn deserialize_shadowsocks_client<'de, D>(
    deserializer: D,
) -> Result<(ShadowsocksConfig, bool, Option<crate::ss_plugin::Config>), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowsocksClientTemp {
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        #[serde(default)]
        plugin: Option<crate::ss_plugin::Config>,
    }

    let temp = ShadowsocksClientTemp::deserialize(deserializer)?;
    let config = ShadowsocksConfig::from_client_fields(&temp.cipher, &temp.password)
        .map_err(Error::custom)?;

    Ok((config, temp.udp_enabled, temp.plugin))
}

/// Custom serializer for ClientProxyConfig::Shadowsocks - flattens config fields
fn serialize_shadowsocks_client<S>(
    config: &ShadowsocksConfig,
    udp_enabled: &bool,
    plugin: &Option<crate::ss_plugin::Config>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeStruct;

    // Only serialize udp_enabled if it's not the default (true)
    let field_count = (if *udp_enabled { 2 } else { 3 }) + usize::from(plugin.is_some());
    let mut state = serializer.serialize_struct("Shadowsocks", field_count)?;
    config.serialize_fields(&mut state)?;
    if !*udp_enabled {
        state.serialize_field("udp_enabled", udp_enabled)?;
    }
    if let Some(plugin) = plugin {
        state.serialize_field("plugin", plugin)?;
    }
    state.end()
}

/// Custom deserializer for ClientProxyConfig::Snell - flattens config fields
fn deserialize_snell_client<'de, D>(deserializer: D) -> Result<(ShadowsocksConfig, bool), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SnellClientTemp {
        cipher: String,
        password: String,
        #[serde(default = "default_true")]
        udp_enabled: bool,
    }

    let temp = SnellClientTemp::deserialize(deserializer)?;
    let config =
        ShadowsocksConfig::from_fields(&temp.cipher, &temp.password).map_err(Error::custom)?;

    Ok((config, temp.udp_enabled))
}

/// Custom serializer for ClientProxyConfig::Snell - flattens config fields
fn serialize_snell_client<S>(
    config: &ShadowsocksConfig,
    udp_enabled: &bool,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeStruct;

    // Only serialize udp_enabled if it's not the default (true)
    let field_count = if *udp_enabled { 2 } else { 3 };
    let mut state = serializer.serialize_struct("Snell", field_count)?;
    config.serialize_fields(&mut state)?;
    if !*udp_enabled {
        state.serialize_field("udp_enabled", udp_enabled)?;
    }
    state.end()
}

/// Custom deserializer for TlsClientConfig that handles deprecated shadowtls_password field
fn deserialize_tls_client_config<'de, D>(deserializer: D) -> Result<TlsClientConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TlsClientConfigTemp {
        #[serde(default)]
        options: super::tls::TlsClientOptions,
        #[serde(default)]
        key_exchange_groups: super::tls::TlsKeyExchangeGroups,
        #[serde(default = "default_true")]
        verify: bool,
        #[serde(alias = "server_fingerprint", default)]
        server_fingerprints: NoneOrSome<String>,
        #[serde(default)]
        sni_hostname: NoneOrOne<String>,
        #[serde(alias = "alpn_protocol", default)]
        alpn_protocols: NoneOrSome<String>,
        #[serde(default)]
        tls_buffer_size: Option<usize>,
        #[serde(default)]
        key: Option<String>,
        #[serde(default)]
        cert: Option<String>,
        #[serde(default)]
        shadowtls_password: Option<String>,
        #[serde(default)]
        vision: bool,
        protocol: Box<ClientProxyConfig>,
    }

    let temp = TlsClientConfigTemp::deserialize(deserializer)?;

    // Check for mutually exclusive fields
    if temp.vision && temp.shadowtls_password.is_some() {
        return Err(Error::custom(
            "TLS client config cannot have both vision=true and shadowtls_password set. \
             Vision and ShadowTLS are incompatible. \
             Use either 'vision: true' with regular TLS, or 'type: shadowtls' for ShadowTLS.",
        ));
    }

    // Check if deprecated shadowtls_password was used
    if let Some(password) = temp.shadowtls_password {
        if !temp.key_exchange_groups.is_default() || !temp.options.is_default() {
            return Err(Error::custom(
                "key_exchange_groups and options require ordinary TLS, not deprecated shadowtls_password",
            ));
        }
        log::warn!(
            "The 'shadowtls_password' field in TLS client configuration is deprecated. \
             Please use 'type: shadowtls' with 'password' field instead. \
             This field will be removed in a future version."
        );

        // Transform to ShadowTLS variant internally by wrapping protocol
        return Ok(TlsClientConfig {
            options: temp.options,
            key_exchange_groups: temp.key_exchange_groups,
            verify: temp.verify,
            server_fingerprints: temp.server_fingerprints,
            sni_hostname: temp.sni_hostname.clone(),
            alpn_protocols: temp.alpn_protocols,
            tls_buffer_size: temp.tls_buffer_size,
            key: temp.key,
            cert: temp.cert,
            vision: false,
            protocol: Box::new(ClientProxyConfig::ShadowTls {
                password,
                sni_hostname: temp.sni_hostname.into_option(),
                protocol: temp.protocol,
            }),
        });
    }

    // Normal case - no shadowtls_password
    Ok(TlsClientConfig {
        options: temp.options,
        key_exchange_groups: temp.key_exchange_groups,
        verify: temp.verify,
        server_fingerprints: temp.server_fingerprints,
        sni_hostname: temp.sni_hostname,
        alpn_protocols: temp.alpn_protocols,
        tls_buffer_size: temp.tls_buffer_size,
        key: temp.key,
        cert: temp.cert,
        vision: temp.vision,
        protocol: temp.protocol,
    })
}

/// Variant deserializer for Tls in ClientProxyConfig enum
fn deserialize_tls_variant<'de, D>(deserializer: D) -> Result<TlsClientConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_tls_client_config(deserializer)
}

fn deserialize_shadowtls_variant<'de, D>(
    deserializer: D,
) -> Result<(String, Option<String>, Box<ClientProxyConfig>), D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowTlsFields {
        password: String,
        #[serde(default)]
        sni_hostname: Option<String>,
        protocol: Box<ClientProxyConfig>,
    }
    let fields = ShadowTlsFields::deserialize(deserializer)?;
    Ok((fields.password, fields.sni_hostname, fields.protocol))
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientRecord<P> {
    #[serde(skip)]
    pub name: Option<String>,
    #[serde(skip)]
    pub control: Option<crate::control::catalog::MemberOrigin>,
    #[serde(default, skip_serializing_if = "NoneOrOne::is_unspecified")]
    pub bind_interface: NoneOrOne<String>,
    #[serde(
        default = "unspecified_address",
        skip_serializing_if = "NetLocation::is_unspecified"
    )]
    pub address: NetLocation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_resolver: Option<super::dns::DomainResolverConfig>,
    /// Total socket dial deadline, including DNS and all address attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<std::num::NonZeroU32>,
    #[serde(
        default,
        skip_serializing_if = "crate::dial_options::DialOptions::is_default"
    )]
    pub dial_options: crate::dial_options::DialOptions,
    pub protocol: P,
    #[serde(default, skip_serializing_if = "Transport::is_default")]
    pub transport: Transport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_settings: Option<TcpConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_settings: Option<ClientQuicConfig>,
}

pub type ClientConfig = ClientRecord<ClientProxyConfig>;

impl<'de> Deserialize<'de> for ClientConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        fn explicit_transport<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Transport>, D::Error> {
            Transport::deserialize(deserializer).map(Some)
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            bind_interface: NoneOrOne<String>,
            #[serde(default = "unspecified_address")]
            address: NetLocation,
            #[serde(default)]
            domain_resolver: Option<super::dns::DomainResolverConfig>,
            #[serde(default)]
            connect_timeout_ms: Option<std::num::NonZeroU32>,
            #[serde(default)]
            dial_options: crate::dial_options::DialOptions,
            protocol: ClientProxyConfig,
            #[serde(default, deserialize_with = "explicit_transport")]
            transport: Option<Transport>,
            tcp_settings: Option<TcpConfig>,
            quic_settings: Option<ClientQuicConfig>,
        }
        let fields = Fields::deserialize(deserializer)?;
        let transport = fields.transport.unwrap_or_else(|| {
            if fields.protocol.is_wireguard() {
                Transport::Udp
            } else if fields.protocol.is_native_quic()
                || crate::ss_plugin::quic::source(&fields.protocol).is_some()
            {
                Transport::Quic
            } else {
                Transport::Tcp
            }
        });
        Ok(Self {
            name: fields.name,
            control: None,
            bind_interface: fields.bind_interface,
            address: fields.address,
            domain_resolver: fields.domain_resolver,
            connect_timeout_ms: fields.connect_timeout_ms,
            dial_options: fields.dial_options,
            protocol: fields.protocol,
            transport,
            tcp_settings: fields.tcp_settings,
            quic_settings: fields.quic_settings,
        })
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            name: None,
            control: None,
            bind_interface: NoneOrOne::None,
            address: unspecified_address(),
            domain_resolver: None,
            connect_timeout_ms: None,
            dial_options: Default::default(),
            protocol: ClientProxyConfig::Direct,
            transport: Transport::default(),
            tcp_settings: None,
            quic_settings: None,
        }
    }
}

impl ClientConfig {
    pub fn validate_quic_key_exchange(&self, initial_hop: bool) -> std::io::Result<()> {
        self.validate_quic_key_exchange_settings(initial_hop, self.protocol.is_direct())?;
        if let Some(quic) = &self.quic_settings
            && let ClientProxyConfig::Tuic(settings) = &self.protocol
        {
            quic.key_exchange_groups
                .validate_zero_rtt(settings.zero_rtt_handshake)?;
        }
        Ok(())
    }
}

impl crate::config::resolved::ResolvedClientConfig {
    pub fn validate_quic_key_exchange(&self, initial_hop: bool) -> std::io::Result<()> {
        self.validate_quic_key_exchange_settings(initial_hop, self.protocol.is_direct())?;
        if let Some(quic) = &self.quic_settings
            && let ResolvedClientProxyConfig::Tuic(settings) = &self.protocol
        {
            quic.key_exchange_groups
                .validate_zero_rtt(settings.zero_rtt_handshake)?;
        }
        Ok(())
    }
}

impl<P> ClientRecord<P> {
    fn validate_quic_key_exchange_settings(
        &self,
        initial_hop: bool,
        direct: bool,
    ) -> std::io::Result<()> {
        let explicit_groups = self.quic_settings.as_ref().is_some_and(|settings| {
            !settings.key_exchange_groups.is_default() || !settings.options.is_default()
        });
        if explicit_groups && (!initial_hop || direct || self.transport != Transport::Quic) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "QUIC key_exchange_groups/options require a non-direct client at chain hop 0 with transport: quic",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpVersion {
    #[default]
    H1,
    H2,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientProxyConfig {
    #[serde(rename = "sudoku_mask")]
    SudokuMask(crate::sudoku_mask::SudokuMaskConfig<ClientProxyConfig>),
    Direct,
    Wireguard(Box<super::wireguard::WireguardClientConfig>),
    #[serde(alias = "hy2")]
    Hysteria2(super::quic_client::Hysteria2ClientConfig),
    #[serde(alias = "tuicv5")]
    Tuic(super::quic_client::TuicClientConfig),
    Http {
        #[serde(default)]
        settings: crate::http_handler::HttpClientOptions,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        /// When true, resolve hostnames to IP addresses before passing to HTTP CONNECT.
        /// Used when the upstream proxy blocks by hostname.
        #[serde(default, skip_serializing_if = "is_false")]
        resolve_hostname: bool,
        #[serde(default)]
        http_version: HttpVersion,
    },
    #[serde(alias = "socks5")]
    Socks {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
    },
    #[serde(
        alias = "ss",
        deserialize_with = "deserialize_shadowsocks_client",
        serialize_with = "serialize_shadowsocks_client"
    )]
    Shadowsocks {
        config: ShadowsocksConfig,
        udp_enabled: bool,
        plugin: Option<crate::ss_plugin::Config>,
    },
    #[serde(
        deserialize_with = "deserialize_snell_client",
        serialize_with = "serialize_snell_client"
    )]
    Snell {
        config: ShadowsocksConfig,
        udp_enabled: bool,
    },
    Vless {
        user_id: String,
        #[serde(
            default,
            skip_serializing_if = "super::vless::VlessEncryptionSetting::is_disabled"
        )]
        encryption: super::vless::VlessEncryptionSetting,
        #[serde(
            default,
            rename = "decryption",
            skip_serializing,
            deserialize_with = "super::vless::reject_client_decryption"
        )]
        _invalid_decryption: (),
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        vision: bool,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        #[serde(default, skip_serializing_if = "PacketEncoding::is_raw")]
        packet_encoding: PacketEncoding,
        /// H2MUX multiplexing configuration
        #[serde(default, skip_serializing_if = "Option::is_none")]
        h2mux: Option<H2MuxConfig>,
    },
    Trojan {
        password: String,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shadowsocks: Option<ShadowsocksConfig>,
        /// H2MUX multiplexing configuration
        #[serde(default, skip_serializing_if = "Option::is_none")]
        h2mux: Option<H2MuxConfig>,
    },
    Reality {
        #[serde(
            default,
            skip_serializing_if = "crate::tls_fragment::TlsFragmentOptions::is_default"
        )]
        fragmentation: crate::tls_fragment::TlsFragmentOptions,
        #[serde(default)]
        handshake_timeout_ms: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mldsa65_verify: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_fingerprint: Option<super::tls::TlsClientFingerprint>,
        #[serde(default, skip_serializing_if = "NoneOrSome::is_unspecified")]
        alpn_protocols: NoneOrSome<String>,
        public_key: String,
        #[serde(default = "default_reality_client_short_id")]
        short_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni_hostname: Option<String>,

        /// TLS 1.3 cipher suites to use (optional)
        /// Valid values: "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"
        /// If empty or not specified, all three cipher suites are offered.
        #[serde(
            alias = "cipher_suite",
            default,
            skip_serializing_if = "NoneOrSome::is_unspecified"
        )]
        cipher_suites: NoneOrSome<crate::reality::CipherSuite>,

        /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
        /// When enabled, the inner protocol MUST be VLESS.
        #[serde(default, skip_serializing_if = "is_false")]
        vision: bool,

        protocol: Box<ClientProxyConfig>,
    },
    #[serde(
        alias = "shadowtls",
        deserialize_with = "deserialize_shadowtls_variant"
    )]
    ShadowTls {
        /// ShadowTLS password for authentication
        password: String,

        /// Optional SNI hostname override
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni_hostname: Option<String>,

        /// Inner protocol (typically VLESS, Trojan, etc.)
        protocol: Box<ClientProxyConfig>,
    },
    #[serde(deserialize_with = "deserialize_tls_variant")]
    Tls(TlsClientConfig),
    Vmess {
        cipher: String,
        user_id: String,
        #[serde(default)]
        alter_id: u16,
        #[serde(default, skip_serializing_if = "is_false")]
        global_padding: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        authenticated_length: bool,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        #[serde(default, skip_serializing_if = "PacketEncoding::is_raw")]
        packet_encoding: PacketEncoding,
        /// H2MUX multiplexing configuration
        #[serde(default, skip_serializing_if = "Option::is_none")]
        h2mux: Option<H2MuxConfig>,
    },
    #[serde(alias = "ws")]
    Websocket(WebsocketClientConfig),
    #[serde(rename = "stream_transport")]
    StreamTransport(crate::stream_transport::Config<ClientProxyConfig>),
    #[serde(rename = "udp_over_tcp")]
    Uot(crate::uot::client::Config<ClientProxyConfig>),
    Multiplex(MultiplexConfig<ClientProxyConfig>),
    #[serde(alias = "splithttp")]
    Xhttp(super::xhttp::XhttpClientConfig),
    #[serde(alias = "noop")]
    PortForward,
    /// AnyTLS outbound protocol
    Anytls {
        /// Authentication password
        password: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        client_metadata: String,
        /// UDP over TCP support (default: true)
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        /// Custom padding scheme (optional, uses default if not specified)
        /// Each line is a key=value pair like "stop=8" or "0=30-30"
        #[serde(default, skip_serializing_if = "Option::is_none")]
        padding_scheme: Option<Vec<String>>,
        /// Values <= 5 use the reference default of 30 seconds.
        #[serde(default = "default_anytls_idle_secs")]
        idle_session_check_interval_secs: u32,
        #[serde(default = "default_anytls_idle_secs")]
        idle_session_timeout_secs: u32,
        /// Retention floor, not proactive dialing or a connection limit.
        #[serde(default)]
        min_idle_session: usize,
        #[serde(default, skip_serializing_if = "is_false")]
        disable_reuse: bool,
    },
    /// NaiveProxy client protocol (HTTP/2 CONNECT with padding)
    #[serde(alias = "naive")]
    Naiveproxy {
        #[serde(default)]
        settings: crate::naiveproxy::options::Options,
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        udp_enabled: bool,
        /// Username for Basic Auth
        username: String,
        /// Password for Basic Auth
        password: String,
        /// Enable padding protocol (default: true)
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        padding: bool,
    },
}

fn default_anytls_idle_secs() -> u32 {
    30
}

impl ClientProxyConfig {
    pub fn is_native_quic(&self) -> bool {
        matches!(self, Self::Hysteria2(_) | Self::Tuic(_))
            || matches!(self,Self::Naiveproxy{settings,..} if settings.quic)
    }

    pub fn is_wireguard(&self) -> bool {
        matches!(self, Self::Wireguard(_))
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, ClientProxyConfig::Direct)
    }

    /// Returns the protocol name for display/error messages
    pub fn protocol_name(&self) -> &str {
        match self {
            ClientProxyConfig::SudokuMask(_) => "Sudoku mask",
            ClientProxyConfig::Direct => "Direct",
            ClientProxyConfig::Wireguard(_) => "WireGuard",
            ClientProxyConfig::Hysteria2(_) => "Hysteria2",
            ClientProxyConfig::Tuic(_) => "TUIC",
            ClientProxyConfig::Http { .. } => "HTTP",
            ClientProxyConfig::Socks { .. } => "SOCKS5",
            ClientProxyConfig::Shadowsocks { .. } => "Shadowsocks",
            ClientProxyConfig::Snell { .. } => "Snell",
            ClientProxyConfig::Vless { .. } => "VLESS",
            ClientProxyConfig::Trojan { .. } => "Trojan",
            ClientProxyConfig::Reality { .. } => "Reality",
            ClientProxyConfig::Tls(..) => "TLS",
            ClientProxyConfig::ShadowTls { .. } => "ShadowTLS",
            ClientProxyConfig::Vmess { .. } => "VMess",
            ClientProxyConfig::Websocket(..) => "WebSocket",
            ClientProxyConfig::Uot(..) => "UDP over TCP",
            ClientProxyConfig::Multiplex(..) => "Multiplex",
            ClientProxyConfig::StreamTransport(..) => "HTTP stream transport",
            ClientProxyConfig::Xhttp(..) => "XHTTP",
            ClientProxyConfig::PortForward => "PortForward",
            ClientProxyConfig::Anytls { .. } => "AnyTLS",
            ClientProxyConfig::Naiveproxy { .. } => "NaiveProxy",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsClientRecord<P> {
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
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub verify: bool,
    #[serde(
        alias = "server_fingerprint",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub server_fingerprints: NoneOrSome<String>,
    #[serde(default, skip_serializing_if = "NoneOrOne::is_unspecified")]
    pub sni_hostname: NoneOrOne<String>,
    #[serde(
        alias = "alpn_protocol",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub alpn_protocols: NoneOrSome<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_buffer_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,

    /// Enable XTLS-Vision protocol for TLS-in-TLS optimization.
    /// When enabled, the inner protocol MUST be VLESS.
    /// Requires TLS 1.3.
    #[serde(default, skip_serializing_if = "is_false")]
    pub vision: bool,

    pub protocol: Box<P>,
}

pub type TlsClientConfig = TlsClientRecord<ClientProxyConfig>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebsocketClientRecord<P> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matching_headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "crate::websocket::is_zero")]
    pub max_early_data: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data_header_name: Option<String>,
    #[serde(default, skip_serializing_if = "WebsocketPingType::is_default")]
    pub ping_type: WebsocketPingType,
    pub protocol: Box<P>,
}

pub type WebsocketClientConfig = WebsocketClientRecord<ClientProxyConfig>;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ResolvedClientProxyConfig {
    #[serde(rename = "sudoku_mask")]
    SudokuMask(crate::sudoku_mask::SudokuMaskConfig<ResolvedClientProxyConfig>),
    Direct,
    Wireguard(Box<crate::config::resolved::ResolvedWireguardClientConfig>),
    Hysteria2(super::quic_client::Hysteria2ClientConfig),
    Tuic(super::quic_client::TuicClientConfig),
    Http {
        #[serde(default)]
        settings: crate::http_handler::HttpClientOptions,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(skip_serializing_if = "is_false")]
        resolve_hostname: bool,
        http_version: HttpVersion,
    },
    Socks {
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(skip_serializing_if = "is_true")]
        udp_enabled: bool,
    },
    #[serde(serialize_with = "serialize_shadowsocks_client")]
    Shadowsocks {
        config: ShadowsocksConfig,
        udp_enabled: bool,
        plugin: Option<crate::ss_plugin::Config>,
    },
    #[serde(serialize_with = "serialize_snell_client")]
    Snell {
        config: ShadowsocksConfig,
        udp_enabled: bool,
    },
    Vless {
        user_id: String,
        #[serde(skip_serializing_if = "super::vless::VlessEncryptionSetting::is_disabled")]
        encryption: super::vless::VlessEncryptionSetting,
        #[serde(rename = "decryption", skip_serializing)]
        _invalid_decryption: (),
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        vision: bool,
        #[serde(skip_serializing_if = "is_true")]
        udp_enabled: bool,
        #[serde(skip_serializing_if = "PacketEncoding::is_raw")]
        packet_encoding: PacketEncoding,
        #[serde(skip_serializing_if = "Option::is_none")]
        h2mux: Option<H2MuxConfig>,
    },
    Trojan {
        password: String,
        #[serde(skip_serializing_if = "is_true")]
        udp_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        shadowsocks: Option<ShadowsocksConfig>,
        #[serde(skip_serializing_if = "Option::is_none")]
        h2mux: Option<H2MuxConfig>,
    },
    Reality {
        #[serde(skip_serializing_if = "crate::tls_fragment::TlsFragmentOptions::is_default")]
        fragmentation: crate::tls_fragment::TlsFragmentOptions,
        handshake_timeout_ms: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        mldsa65_verify: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_fingerprint: Option<super::tls::TlsClientFingerprint>,
        #[serde(skip_serializing_if = "NoneOrSome::is_unspecified")]
        alpn_protocols: NoneOrSome<String>,
        public_key: String,
        short_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni_hostname: Option<String>,

        #[serde(skip_serializing_if = "NoneOrSome::is_unspecified")]
        cipher_suites: NoneOrSome<crate::reality::CipherSuite>,

        #[serde(skip_serializing_if = "is_false")]
        vision: bool,

        protocol: Box<ResolvedClientProxyConfig>,
    },
    ShadowTls {
        password: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        sni_hostname: Option<String>,

        protocol: Box<ResolvedClientProxyConfig>,
    },
    Tls(crate::config::resolved::ResolvedTlsClientConfig),
    Vmess {
        cipher: String,
        user_id: String,
        alter_id: u16,
        #[serde(skip_serializing_if = "is_false")]
        global_padding: bool,
        #[serde(skip_serializing_if = "is_false")]
        authenticated_length: bool,
        #[serde(skip_serializing_if = "is_true")]
        udp_enabled: bool,
        #[serde(skip_serializing_if = "PacketEncoding::is_raw")]
        packet_encoding: PacketEncoding,
        #[serde(skip_serializing_if = "Option::is_none")]
        h2mux: Option<H2MuxConfig>,
    },
    Websocket(crate::config::resolved::ResolvedWebsocketClientConfig),
    #[serde(rename = "stream_transport")]
    StreamTransport(crate::stream_transport::Config<ResolvedClientProxyConfig>),
    #[serde(rename = "udp_over_tcp")]
    Uot(crate::uot::client::Config<ResolvedClientProxyConfig>),
    Multiplex(MultiplexConfig<ResolvedClientProxyConfig>),
    Xhttp(crate::config::resolved::ResolvedXhttpClientConfig),
    PortForward,
    Anytls {
        password: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        client_metadata: String,
        #[serde(skip_serializing_if = "is_true")]
        udp_enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        padding_scheme: Option<Vec<String>>,
        idle_session_check_interval_secs: u32,
        idle_session_timeout_secs: u32,
        min_idle_session: usize,
        #[serde(skip_serializing_if = "is_false")]
        disable_reuse: bool,
    },
    Naiveproxy {
        #[serde(default)]
        settings: crate::naiveproxy::options::Options,
        #[serde(skip_serializing_if = "is_true")]
        udp_enabled: bool,
        username: String,
        password: String,
        #[serde(skip_serializing_if = "is_true")]
        padding: bool,
    },
}

impl ResolvedClientProxyConfig {
    /// Administrative UDP policy is separate from protocol capability. An
    /// encapsulation such as UoT or multiplexing must not enable a disabled
    /// payload network just because its carrier uses TCP.
    pub(crate) fn udp_enabled(&self) -> bool {
        match self {
            Self::Socks { udp_enabled, .. }
            | Self::Shadowsocks { udp_enabled, .. }
            | Self::Snell { udp_enabled, .. }
            | Self::Vless { udp_enabled, .. }
            | Self::Trojan { udp_enabled, .. }
            | Self::Vmess { udp_enabled, .. }
            | Self::Anytls { udp_enabled, .. }
            | Self::Naiveproxy { udp_enabled, .. } => *udp_enabled,
            Self::Tls(config) => config.protocol.udp_enabled(),
            Self::Websocket(config) => config.protocol.udp_enabled(),
            Self::StreamTransport(config) => config.protocol.udp_enabled(),
            Self::Uot(config) => config.protocol.udp_enabled(),
            Self::Multiplex(config) => config.protocol.udp_enabled(),
            Self::Xhttp(config) => config.protocol.udp_enabled(),
            Self::SudokuMask(config) => config.protocol.udp_enabled(),
            Self::Reality { protocol, .. } | Self::ShadowTls { protocol, .. } => {
                protocol.udp_enabled()
            }
            Self::Direct
            | Self::Wireguard(_)
            | Self::Hysteria2(_)
            | Self::Tuic(_)
            | Self::Http { .. }
            | Self::PortForward => true,
        }
    }

    pub fn is_native_quic(&self) -> bool {
        matches!(self, Self::Hysteria2(_) | Self::Tuic(_))
            || matches!(self,Self::Naiveproxy{settings,..} if settings.quic)
    }

    pub fn is_wireguard(&self) -> bool {
        matches!(self, Self::Wireguard(_))
    }

    pub fn is_direct(&self) -> bool {
        matches!(self, ResolvedClientProxyConfig::Direct)
    }

    /// Returns the protocol name for display/error messages
    pub fn protocol_name(&self) -> &str {
        match self {
            ResolvedClientProxyConfig::SudokuMask(_) => "Sudoku mask",
            ResolvedClientProxyConfig::Direct => "Direct",
            ResolvedClientProxyConfig::Wireguard(_) => "WireGuard",
            ResolvedClientProxyConfig::Hysteria2(_) => "Hysteria2",
            ResolvedClientProxyConfig::Tuic(_) => "TUIC",
            ResolvedClientProxyConfig::Http { .. } => "HTTP",
            ResolvedClientProxyConfig::Socks { .. } => "SOCKS5",
            ResolvedClientProxyConfig::Shadowsocks { .. } => "Shadowsocks",
            ResolvedClientProxyConfig::Snell { .. } => "Snell",
            ResolvedClientProxyConfig::Vless { .. } => "VLESS",
            ResolvedClientProxyConfig::Trojan { .. } => "Trojan",
            ResolvedClientProxyConfig::Reality { .. } => "Reality",
            ResolvedClientProxyConfig::Tls(..) => "TLS",
            ResolvedClientProxyConfig::ShadowTls { .. } => "ShadowTLS",
            ResolvedClientProxyConfig::Vmess { .. } => "VMess",
            ResolvedClientProxyConfig::Websocket(..) => "WebSocket",
            ResolvedClientProxyConfig::Uot(..) => "UDP over TCP",
            ResolvedClientProxyConfig::Multiplex(..) => "Multiplex",
            ResolvedClientProxyConfig::StreamTransport(..) => "HTTP stream transport",
            ResolvedClientProxyConfig::Xhttp(..) => "XHTTP",
            ResolvedClientProxyConfig::PortForward => "PortForward",
            ResolvedClientProxyConfig::Anytls { .. } => "AnyTLS",
            ResolvedClientProxyConfig::Naiveproxy { .. } => "NaiveProxy",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_client_config() -> ClientConfig {
        ClientConfig {
            domain_resolver: None,
            connect_timeout_ms: None,
            dial_options: Default::default(),
            name: None,
            control: None,
            bind_interface: NoneOrOne::One("eth0".to_string()),
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1080),
            protocol: ClientProxyConfig::Socks {
                username: Some("client_user".to_string()),
                password: Some("client_pass".to_string()),
                udp_enabled: true,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
        }
    }

    #[test]
    fn test_client_config_serialization() {
        let original = create_test_client_config();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        println!("Client config YAML:\n{yaml_str}");
        let deserialized: ClientConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.protocol,
            ClientProxyConfig::Socks { .. }
        ));
    }

    #[test]
    fn test_rejects_unknown_field_in_vmess_client() {
        // Test ClientProxyConfig::Vmess directly
        let yaml = r#"
type: vmess
cipher: aes-128-gcm
user_id: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
unknown_option: true
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `unknown_option`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_tls_client_config() {
        // Test ClientProxyConfig::Tls directly
        let yaml = r#"
type: tls
verify: true
wrong_field: "oops"
protocol:
  type: socks
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `wrong_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_client_config() {
        // Test ClientConfig directly
        let yaml = r#"
address: "127.0.0.1:9090"
protocol:
  type: socks
invalid_client_field: "bad"
"#;
        let result: Result<ClientConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `invalid_client_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_client_proxy_config_direct() {
        let yaml = r#"
type: direct
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(result.unwrap().is_direct());
    }

    #[test]
    fn test_client_proxy_config_socks() {
        let yaml = r#"
type: socks
username: "user"
password: "pass"
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ClientProxyConfig::Socks { .. }));
    }

    #[test]
    fn test_client_proxy_config_http() {
        let yaml = r#"
type: http
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ClientProxyConfig::Http { .. }));
    }

    #[test]
    fn test_websocket_client_config() {
        let yaml = r#"
type: websocket
matching_path: "/ws"
protocol:
  type: direct
"#;
        let result: Result<ClientProxyConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ClientProxyConfig::Websocket(_)));
    }
}
