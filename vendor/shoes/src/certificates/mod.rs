mod quic;
mod runtime;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use rustls::pki_types::pem::PemObject;
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};

use crate::config::{Config, PemSource, ServerProxyConfig};

pub(crate) use quic::quic_config;
#[allow(unused_imports)]
pub(crate) use runtime::Registry;

const MAX_PEM_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NamedSource {
    pub certificate_source: String,
    #[serde(flatten)]
    pub source: SourceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceConfig {
    Files { cert: PathBuf, key: PathBuf },
}

impl NamedSource {
    pub(crate) fn validate_file_paths(&self) -> io::Result<()> {
        let validate = |field: &str, path: &Path| {
            let value = path.to_string_lossy();
            if value.trim_start().starts_with("-----BEGIN") || value.contains(['\r', '\n']) {
                return Err(invalid(&format!(
                    "certificate source {}: {field} requires a file path, not inline material",
                    self.certificate_source
                )));
            }
            Ok(())
        };
        match &self.source {
            SourceConfig::Files { cert, key } => {
                validate("cert", cert)?;
                validate("key", key)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Input {
    File(PathBuf),
    Inline(String),
}

impl Input {
    fn read(&self, role: &str) -> io::Result<String> {
        match self {
            Self::File(path) => read_text(path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("{role} file '{}': {error}", path.display()),
                )
            }),
            Self::Inline(data) => Ok(data.clone()),
        }
    }

    fn location(&self) -> String {
        match self {
            Self::File(path) => format!("file '{}'", path.display()),
            Self::Inline(_) => "inline data".into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Spec {
    cert: Input,
    key: Input,
}

pub struct Source {
    name: String,
    spec: Spec,
    material: RwLock<Option<Material>>,
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateSource")
            .field("name", &self.name)
            .field("ready", &self.current().is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct Material {
    key: Arc<CertifiedKey>,
    not_before: i64,
    not_after: i64,
    digest: Vec<u8>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub(crate) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn read_text(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(MAX_PEM_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_PEM_BYTES {
        return Err(invalid("certificate state exceeds 1 MiB"));
    }
    Ok(text)
}

impl Material {
    fn parse(cert: &str, key: &str) -> io::Result<Self> {
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(cert.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("invalid certificate PEM"))?;
        if certs.is_empty() {
            return Err(invalid("empty certificate chain"));
        }
        let mut parsed_certs = Vec::with_capacity(certs.len());
        let mut not_before = i64::MIN;
        let mut not_after = i64::MAX;
        for cert in &certs {
            let (rest, parsed) = x509_parser::parse_x509_certificate(cert)
                .map_err(|_| invalid("invalid X.509 certificate"))?;
            if !rest.is_empty() {
                return Err(invalid("trailing X.509 data"));
            }
            not_before = not_before.max(parsed.validity().not_before.timestamp());
            not_after = not_after.min(parsed.validity().not_after.timestamp());
            parsed_certs.push(parsed);
        }
        for pair in parsed_certs.windows(2) {
            let child = &pair[0];
            let issuer = &pair[1];
            let key = issuer.public_key();
            let verified = aerobox_crypto::provider()
                .signature_verification_algorithms
                .all
                .iter()
                .any(|algorithm| {
                    algorithm_matches(algorithm.public_key_alg_id(), &key.algorithm)
                        && algorithm_matches(
                            algorithm.signature_alg_id(),
                            &child.signature_algorithm,
                        )
                        && algorithm
                            .verify_signature(
                                &key.subject_public_key.data,
                                child.tbs_certificate.as_ref(),
                                &child.signature_value.data,
                            )
                            .is_ok()
                });
            if child.issuer() != issuer.subject() || !verified {
                return Err(invalid("invalid certificate chain signature or order"));
            }
        }
        if now() < not_before || now() >= not_after {
            return Err(invalid("certificate is not currently valid"));
        }
        let private_key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes())
            .map_err(|_| invalid("invalid private key PEM"))?;
        let key = CertifiedKey::from_der(certs, private_key, &aerobox_crypto::provider())
            .map_err(|_| invalid("invalid or mismatched certificate/private key"))?;
        // Hash the public chain only; a matching private key cannot change independently.
        let digest = aerobox_primitives::digest::digest(
            &aerobox_primitives::digest::SHA256,
            cert.as_bytes(),
        )
        .as_ref()
        .to_vec();
        Ok(Self {
            key: Arc::new(key),
            not_before,
            not_after,
            digest,
        })
    }
}

fn algorithm_matches(
    supported: rustls::pki_types::AlgorithmIdentifier,
    actual: &x509_parser::x509::AlgorithmIdentifier<'_>,
) -> bool {
    use x509_parser::asn1_rs::{Any, FromDer, Oid};
    // rustls stores the AlgorithmIdentifier contents without the enclosing SEQUENCE.
    let Ok((parameters, oid)) = Oid::from_der(supported.as_ref()) else {
        return false;
    };
    if oid != actual.algorithm {
        return false;
    }
    match &actual.parameters {
        None => parameters.is_empty(),
        Some(actual) => Any::from_der(parameters)
            .is_ok_and(|(rest, expected)| rest.is_empty() && expected == *actual),
    }
}

impl Source {
    fn new(name: String, spec: Spec) -> io::Result<Arc<Self>> {
        let source = Arc::new(Self {
            name,
            spec,
            material: RwLock::new(None),
        });
        source.refresh_files().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("certificate source {}: {error}", source.name),
            )
        })?;
        Ok(source)
    }

    fn refresh_files(&self) -> io::Result<bool> {
        let Spec { cert, key } = &self.spec;
        let material = Material::parse(&cert.read("certificate")?, &key.read("private key")?)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "certificate {} and private key {}: {error}",
                        cert.location(),
                        key.location()
                    ),
                )
            })?;
        Ok(self.publish(material))
    }

    fn publish(&self, material: Material) -> bool {
        let mut current = self.material.write();
        if current
            .as_ref()
            .is_some_and(|old| old.digest == material.digest)
        {
            return false;
        }
        *current = Some(material);
        true
    }

    fn current(&self) -> Option<Arc<CertifiedKey>> {
        let material = self.material.read();
        let material = material.as_ref()?;
        (now() >= material.not_before && now() < material.not_after).then(|| material.key.clone())
    }

    pub(crate) fn snapshot(&self, base: &rustls::ServerConfig) -> Arc<rustls::ServerConfig> {
        let current = self.material.read();
        let current = current
            .as_ref()
            .filter(|material| now() >= material.not_before && now() < material.not_after);
        let mut config = base.clone();
        config.cert_resolver = Arc::new(FixedCertificate(
            current.map(|material| material.key.clone()),
        ));
        config.session_storage = Arc::new(SessionCache {
            generation: current.map(|material| (material.digest.clone(), material.not_after)),
            inner: base.session_storage.clone(),
        });
        Arc::new(config)
    }
}

impl rustls::server::ResolvesServerCert for Source {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current()
    }
}

#[derive(Debug)]
struct FixedCertificate(Option<Arc<CertifiedKey>>);

impl rustls::server::ResolvesServerCert for FixedCertificate {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.clone()
    }
}

#[derive(Debug)]
struct SessionCache {
    generation: Option<(Vec<u8>, i64)>,
    inner: Arc<dyn rustls::server::StoresServerSessions>,
}

impl SessionCache {
    fn key(&self, key: &[u8]) -> Option<Vec<u8>> {
        let (digest, expires) = self.generation.as_ref()?;
        if now() >= *expires {
            return None;
        }
        let mut combined = digest.clone();
        combined.extend_from_slice(key);
        Some(combined)
    }
}

impl rustls::server::StoresServerSessions for SessionCache {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.key(&key).is_some_and(|key| self.inner.put(key, value))
    }
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(&self.key(key)?)
    }
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.take(&self.key(key)?)
    }
    fn can_cache(&self) -> bool {
        self.key(&[]).is_some() && self.inner.can_cache()
    }
}

type Visitor<'a> = dyn FnMut(&mut Option<Arc<Source>>, Option<&str>, &str, &str, Option<&str>) -> io::Result<()>
    + 'a;

fn visit_proxy(protocol: &mut ServerProxyConfig, visitor: &mut Visitor<'_>) -> io::Result<()> {
    match protocol {
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            for (sni, target) in tls_targets
                .iter_mut()
                .map(|(sni, target)| (Some(sni.as_str()), target))
                .chain(
                    default_tls_target
                        .iter_mut()
                        .map(|target| (None, target.as_mut())),
                )
            {
                visitor(
                    &mut target.certificate_binding,
                    target.certificate_source.as_deref(),
                    &target.cert,
                    &target.key,
                    sni,
                )?;
                visit_proxy(&mut target.protocol, visitor)?;
            }
            for target in shadowtls_targets.values_mut() {
                visit_proxy(&mut target.protocol, visitor)?;
            }
            for target in reality_targets.values_mut() {
                visit_proxy(&mut target.protocol, visitor)?;
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for target in targets.iter_mut() {
                visit_proxy(&mut target.protocol, visitor)?;
            }
        }
        ServerProxyConfig::SudokuMask(target) => visit_proxy(&mut target.protocol, visitor)?,
        ServerProxyConfig::Xhttp(target) => visit_proxy(&mut target.protocol, visitor)?,
        _ => {}
    }
    Ok(())
}

fn visit(configs: &mut [Config], visitor: &mut Visitor<'_>) -> io::Result<()> {
    for config in configs {
        if let Config::Server(server) = config {
            if let Some(quic) = &mut server.quic_settings {
                visitor(
                    &mut quic.certificate_binding,
                    quic.certificate_source.as_deref(),
                    &quic.cert,
                    &quic.key,
                    None,
                )?;
            }
            visit_proxy(&mut server.protocol, visitor)?;
        }
    }
    Ok(())
}

fn visit_resolved_proxy(
    protocol: &mut crate::config::ResolvedServerProxyConfig,
    visitor: &mut Visitor<'_>,
) -> io::Result<()> {
    match protocol {
        crate::config::ResolvedServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            for (sni, target) in tls_targets
                .iter_mut()
                .map(|(sni, target)| (Some(sni.as_str()), target))
                .chain(
                    default_tls_target
                        .iter_mut()
                        .map(|target| (None, target.as_mut())),
                )
            {
                visitor(
                    &mut target.certificate_binding,
                    target.certificate_source.as_deref(),
                    &target.cert,
                    &target.key,
                    sni,
                )?;
                visit_resolved_proxy(&mut target.protocol, visitor)?;
            }
            for target in shadowtls_targets.values_mut() {
                visit_resolved_proxy(&mut target.protocol, visitor)?;
            }
            for target in reality_targets.values_mut() {
                visit_resolved_proxy(&mut target.protocol, visitor)?;
            }
        }
        crate::config::ResolvedServerProxyConfig::Websocket { targets } => {
            for target in targets.iter_mut() {
                visit_resolved_proxy(&mut target.protocol, visitor)?;
            }
        }
        crate::config::ResolvedServerProxyConfig::SudokuMask(target) => {
            visit_resolved_proxy(&mut target.protocol, visitor)?
        }
        crate::config::ResolvedServerProxyConfig::Xhttp(target) => {
            visit_resolved_proxy(&mut target.protocol, visitor)?
        }
        _ => {}
    }
    Ok(())
}

fn visit_resolved(
    configs: &mut [crate::config::ResolvedConfig],
    visitor: &mut Visitor<'_>,
) -> io::Result<()> {
    for config in configs {
        if let crate::config::ResolvedConfig::Server(server) = config {
            if let Some(quic) = &mut server.quic_settings {
                visitor(
                    &mut quic.certificate_binding,
                    quic.certificate_source.as_deref(),
                    &quic.cert,
                    &quic.key,
                    None,
                )?;
            }
            visit_resolved_proxy(&mut server.protocol, visitor)?;
        }
    }
    Ok(())
}

/// Attach certificate sources before PEM expansion erases file identity.
pub(crate) fn configure(configs: &mut [Config]) -> io::Result<Vec<Arc<Source>>> {
    let mut sources: HashMap<String, Arc<Source>> = HashMap::new();
    visit(configs, &mut |binding, _, _, _, _| {
        if let Some(source) = binding {
            sources.insert(source.name.clone(), source.clone());
        }
        Ok(())
    })?;
    let mut names = HashSet::new();
    let mut pems = HashMap::new();
    for config in configs.iter() {
        match config {
            Config::NamedPem(pem) => {
                if pems.insert(pem.pem.clone(), pem.source.clone()).is_some() {
                    return Err(invalid(&format!("named pem already exists: {}", pem.pem)));
                }
            }
            Config::CertificateSource(named) => {
                named.validate_file_paths()?;
                let name = &named.certificate_source;
                if name.is_empty()
                    || name.len() > 128
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    || !names.insert(name.clone())
                {
                    return Err(invalid(&format!(
                        "invalid or duplicate certificate_source name: {name}"
                    )));
                }
                let spec = match &named.source {
                    SourceConfig::Files { cert, key } => {
                        if cert.as_os_str().is_empty() || key.as_os_str().is_empty() {
                            return Err(invalid("file source requires cert/key paths"));
                        }
                        Spec {
                            cert: Input::File(cert.clone()),
                            key: Input::File(key.clone()),
                        }
                    }
                };
                if !sources.contains_key(name) {
                    sources.insert(name.clone(), Source::new(name.clone(), spec)?);
                }
            }
            _ => {}
        }
    }
    let resolve = |value: &str| -> Input {
        match pems.get(value) {
            Some(PemSource::Path(path)) => Input::File(path.into()),
            Some(PemSource::Data(data)) => Input::Inline(data.clone()),
            None if crate::config::is_pem_file_path(value) => Input::File(value.into()),
            None => Input::Inline(value.into()),
        }
    };
    visit(configs, &mut |binding, name, cert, key, _| {
        if let Some(name) = name {
            if !cert.is_empty() || !key.is_empty() {
                return Err(invalid(
                    "certificate_source cannot be combined with cert/key",
                ));
            }
            *binding = Some(
                sources
                    .get(name)
                    .ok_or_else(|| {
                        invalid(&format!("unknown certificate_source reference: {name}"))
                    })?
                    .clone(),
            );
        } else if binding.is_none() {
            if cert.is_empty() || key.is_empty() {
                return Err(invalid(
                    "TLS/QUIC requires both cert and key, or certificate_source",
                ));
            }
            let cert = resolve(cert);
            let key = resolve(key);
            if matches!(cert, Input::File(_)) || matches!(key, Input::File(_)) {
                let spec = Spec { cert, key };
                let source = sources.values().find(|source| source.spec == spec).cloned();
                let source = match source {
                    Some(source) => source,
                    None => {
                        let name = format!("@files-{}", sources.len());
                        let source = Source::new(name.clone(), spec)?;
                        sources.insert(name, source.clone());
                        source
                    }
                };
                *binding = Some(source);
            }
        }
        Ok(())
    })?;
    Ok(sources.into_values().collect())
}
