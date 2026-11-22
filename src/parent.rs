//! Parent proxy definitions, prepared credentials and TLS trust.
//!
//! Parent definitions and their credentials/CA are restart-required. The
//! loader reads and validates them once at startup; reload reuses the prepared
//! values and never opens the secret files again.

use std::fmt;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::HeaderValue;
use rustls::client::Resumption;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, NoKeyLog, RootCertStore};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::config::Listener;
use crate::target::{CanonicalTarget, Host};

/// Maximum credentials file size.
pub const MAX_PARENT_CREDENTIALS_BYTES: u64 = 65_536;
/// Maximum custom CA bundle size.
pub const MAX_PARENT_CA_BYTES: u64 = 1_048_576;
/// Default system trust bundle on the target Linux distribution.
pub const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Parent transport to the next hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParentTransport {
    /// Plain HTTP/1.1 to the parent.
    Http,
    /// HTTP/1.1 inside a verified TLS session to the parent.
    Https,
}

impl ParentTransport {
    /// Parses the config spelling.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }

    /// Stable config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// One validated parent endpoint. The host is also the TLS verification name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentEndpoint {
    host: Host,
    port: u16,
}

impl ParentEndpoint {
    /// Parses `host:port`, including bracketed IPv6 literals.
    pub(crate) fn parse(value: &str) -> Result<Self, ParentPrepError> {
        let target = CanonicalTarget::parse(&http::Method::CONNECT, value)
            .map_err(|_| ParentPrepError::new("endpoint", "must be host:port"))?;
        Ok(Self {
            host: target.host().clone(),
            port: target.port(),
        })
    }

    /// Host used for DNS and TLS verification.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Parent TCP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Canonical `host:port` authority, with IPv6 brackets.
    pub fn authority(&self) -> String {
        match &self.host {
            Host::Domain(domain) => format!("{}:{}", domain.as_str(), self.port),
            Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
            Host::Ip(IpAddr::V4(ip)) => format!("{ip}:{}", self.port),
        }
    }
}

/// One parent definition as read from the main TOML.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentDefinition {
    id: String,
    endpoint: ParentEndpoint,
    transport: ParentTransport,
    credentials_file: Option<PathBuf>,
    ca_file: Option<PathBuf>,
}

impl ParentDefinition {
    /// Creates a definition from already parsed values.
    pub(crate) fn new(
        id: String,
        endpoint: ParentEndpoint,
        transport: ParentTransport,
        credentials_file: Option<PathBuf>,
        ca_file: Option<PathBuf>,
    ) -> Self {
        Self {
            id,
            endpoint,
            transport,
            credentials_file,
            ca_file,
        }
    }

    /// Stable parent identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Configured endpoint.
    pub fn endpoint(&self) -> &ParentEndpoint {
        &self.endpoint
    }

    /// Configured transport.
    pub fn transport(&self) -> ParentTransport {
        self.transport
    }

    /// Resolved credentials-file path.
    pub fn credentials_file(&self) -> Option<&Path> {
        self.credentials_file.as_deref()
    }

    /// Resolved custom CA path.
    pub fn ca_file(&self) -> Option<&Path> {
        self.ca_file.as_deref()
    }
}

/// Prepared Basic credentials for the parent hop.
#[derive(Clone)]
pub(crate) struct ParentCredentials {
    username: String,
    password: Zeroizing<String>,
}

impl ParentCredentials {
    fn authorization(&self) -> HeaderValue {
        let mut raw = Zeroizing::new(Vec::with_capacity(
            self.username.len() + self.password.len() + 1,
        ));
        raw.extend_from_slice(self.username.as_bytes());
        raw.push(b':');
        raw.extend_from_slice(self.password.as_bytes());
        let encoded = Zeroizing::new(BASE64.encode(raw.as_slice()));
        let mut value = HeaderValue::from_str(&format!("Basic {}", encoded.as_str()))
            .expect("base64 Basic credentials are a valid header value");
        value.set_sensitive(true);
        value
    }
}

impl fmt::Debug for ParentCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParentCredentials(<redacted>)")
    }
}

/// A validated parent with its immutable prepared credentials and TLS state.
#[derive(Clone)]
pub struct PreparedParent {
    definition: ParentDefinition,
    credentials: Option<ParentCredentials>,
    tls: Option<Arc<ClientConfig>>,
}

impl PreparedParent {
    /// Parent definition.
    pub fn definition(&self) -> &ParentDefinition {
        &self.definition
    }

    /// Stable parent identifier.
    pub fn id(&self) -> &str {
        self.definition.id()
    }

    /// Configured endpoint.
    pub fn endpoint(&self) -> &ParentEndpoint {
        self.definition.endpoint()
    }

    /// Configured transport.
    pub fn transport(&self) -> ParentTransport {
        self.definition.transport()
    }

    /// Whether a credentials file was configured.
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// Whether TLS trust was prepared.
    pub fn has_tls(&self) -> bool {
        self.tls.is_some()
    }

    pub(crate) fn authorization(&self) -> Option<HeaderValue> {
        self.credentials
            .as_ref()
            .map(ParentCredentials::authorization)
    }

    pub(crate) fn tls_config(&self) -> Option<Arc<ClientConfig>> {
        self.tls.as_ref().map(Arc::clone)
    }
}

impl fmt::Debug for PreparedParent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedParent")
            .field("id", &self.definition.id)
            .field("transport", &self.definition.transport)
            .field("credentials", &self.credentials.is_some())
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

/// Safe parent preparation error. Values and secret content never appear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParentPrepError {
    field: String,
    message: &'static str,
}

impl ParentPrepError {
    pub(crate) fn new(field: impl Into<String>, message: &'static str) -> Self {
        Self {
            field: field.into(),
            message,
        }
    }

    pub(crate) fn field(&self) -> &str {
        &self.field
    }

    pub(crate) fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for ParentPrepError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ParentPrepError {}

/// Reads and validates one parent's credentials and TLS trust.
pub(crate) fn prepare(
    definition: ParentDefinition,
    field_prefix: &str,
) -> Result<Arc<PreparedParent>, ParentPrepError> {
    let credential_field = format!("{field_prefix}.credentials_file");
    let credentials = match definition.credentials_file() {
        Some(path) => Some(read_credentials(path, &credential_field)?),
        None => None,
    };
    let tls = match definition.transport() {
        ParentTransport::Http => {
            if definition.ca_file().is_some() {
                return Err(ParentPrepError::new(
                    format!("{field_prefix}.ca_file"),
                    "ca_file is only valid for https parents",
                ));
            }
            None
        }
        ParentTransport::Https => {
            let field = format!("{field_prefix}.ca_file");
            let roots = match definition.ca_file() {
                Some(path) => load_roots(path, &field, false)?,
                None => load_roots(Path::new(SYSTEM_CA_BUNDLE), &field, true)?,
            };
            let provider = rustls::crypto::ring::default_provider();
            let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .map_err(|_| ParentPrepError::new(field.clone(), "cannot build TLS client config"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            config.resumption = Resumption::disabled();
            config.enable_early_data = false;
            config.enable_secret_extraction = false;
            config.key_log = Arc::new(NoKeyLog);
            Some(Arc::new(config))
        }
    };
    Ok(Arc::new(PreparedParent {
        definition,
        credentials,
        tls,
    }))
}

/// Returns true for an obvious parent-to-own-listener route.
///
/// This is intentionally conservative and offline. It catches exact binds,
/// loopback parents on a loopback/wildcard listener port, and `localhost`
/// domains. A wildcard listener with a non-loopback local address is checked
/// again before dial.
pub(crate) fn is_obvious_self_route(endpoint: &ParentEndpoint, listeners: &[Listener]) -> bool {
    match endpoint.host() {
        Host::Ip(ip) => is_self_route_addr(SocketAddr::new(*ip, endpoint.port()), listeners),
        Host::Domain(domain) => {
            domain.as_str() == "localhost"
                && listeners.iter().any(|listener| {
                    listener.bind().port() == endpoint.port()
                        && (listener.bind().ip().is_loopback()
                            || listener.bind().ip().is_unspecified())
                })
        }
    }
}

/// Runtime self-route check for one resolved parent address.
pub(crate) fn is_self_route_addr(address: SocketAddr, listeners: &[Listener]) -> bool {
    listeners.iter().any(|listener| {
        if listener.bind().port() != address.port() {
            return false;
        }
        let bind = listener.bind().ip();
        bind == address.ip()
            || (bind.is_unspecified() && address.ip().is_loopback())
            || (bind.is_loopback() && address.ip().is_loopback())
    })
}

/// Runtime check that also covers a wildcard listener on a local interface IP.
///
/// This is deliberately separate from the offline `check` path: a safe UDP
/// connect probe observes the selected local address without sending traffic.
pub(crate) fn is_self_route_addr_runtime(address: SocketAddr, listeners: &[Listener]) -> bool {
    is_self_route_addr(address, listeners)
        || listeners.iter().any(|listener| {
            listener.bind().port() == address.port()
                && listener.bind().ip().is_unspecified()
                && is_local_ip(address.ip())
        })
}

fn is_local_ip(ip: IpAddr) -> bool {
    let bind = match ip {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
    };
    let Ok(socket) = std::net::UdpSocket::bind(bind) else {
        return false;
    };
    if socket.connect(SocketAddr::new(ip, 9)).is_err() {
        return false;
    }
    socket
        .local_addr()
        .map(|local| local.ip() == ip)
        .unwrap_or(false)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredentials {
    version: i64,
    username: String,
    password: String,
}

fn read_credentials(path: &Path, field: &str) -> Result<ParentCredentials, ParentPrepError> {
    let bytes = read_bounded(path, field, MAX_PARENT_CREDENTIALS_BYTES, true)?;
    let input = std::str::from_utf8(&bytes)
        .map_err(|_| ParentPrepError::new(field, "credentials file is not UTF-8"))?;
    let raw: RawCredentials = toml::from_str(input)
        .map_err(|_| ParentPrepError::new(field, "invalid credentials TOML"))?;
    if raw.version != 1 {
        return Err(ParentPrepError::new(field, "credentials version must be 1"));
    }
    validate_credential_part(&raw.username, field, 255)?;
    validate_credential_part(&raw.password, field, 4096)?;
    Ok(ParentCredentials {
        username: raw.username,
        password: Zeroizing::new(raw.password),
    })
}

fn validate_credential_part(value: &str, field: &str, max: usize) -> Result<(), ParentPrepError> {
    if value.is_empty()
        || value.len() > max
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0x7f)
    {
        return Err(ParentPrepError::new(
            field,
            "credentials contain an invalid username or password",
        ));
    }
    Ok(())
}

fn load_roots(
    path: &Path,
    field: &str,
    system_default: bool,
) -> Result<RootCertStore, ParentPrepError> {
    let bytes = read_bounded(path, field, MAX_PARENT_CA_BYTES, false).map_err(|error| {
        if system_default {
            ParentPrepError::new(field, "cannot read the system CA bundle")
        } else {
            error
        }
    })?;
    let mut roots = RootCertStore::empty();
    let mut count = 0_usize;
    for certificate in CertificateDer::pem_slice_iter(&bytes) {
        let certificate = certificate.map_err(|_| {
            if system_default {
                ParentPrepError::new(field, "system CA bundle is not valid PEM")
            } else {
                ParentPrepError::new(field, "CA file is not valid PEM")
            }
        })?;
        roots.add(certificate).map_err(|_| {
            if system_default {
                ParentPrepError::new(field, "system CA bundle contains an invalid certificate")
            } else {
                ParentPrepError::new(field, "CA file contains an invalid certificate")
            }
        })?;
        count += 1;
    }
    if count == 0 {
        return Err(ParentPrepError::new(
            field,
            if system_default {
                "system CA bundle contains no certificates"
            } else {
                "CA file contains no certificates"
            },
        ));
    }
    Ok(roots)
}

fn read_bounded(
    path: &Path,
    field: &str,
    limit: u64,
    secret: bool,
) -> Result<Vec<u8>, ParentPrepError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| ParentPrepError::new(field, "cannot open parent file"))?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)
        .map_err(|_| ParentPrepError::new(field, "cannot open parent file"))?;

    let metadata = file
        .metadata()
        .map_err(|_| ParentPrepError::new(field, "cannot inspect parent file"))?;
    if !metadata.is_file() {
        return Err(ParentPrepError::new(
            field,
            "parent file must be a regular file",
        ));
    }
    if metadata.len() > limit {
        return Err(ParentPrepError::new(
            field,
            "parent file exceeds its size limit",
        ));
    }
    if secret {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 {
                return Err(ParentPrepError::new(
                    field,
                    "credentials file must not be accessible by group or others",
                ));
            }
            #[cfg(target_os = "linux")]
            {
                let owner = metadata.uid();
                let effective = effective_uid()
                    .ok_or_else(|| ParentPrepError::new(field, "cannot determine effective UID"))?;
                if owner != 0 && owner != effective {
                    return Err(ParentPrepError::new(
                        field,
                        "credentials owner must be root or the service UID",
                    ));
                }
            }
        }
    }

    let mut bytes = Vec::new();
    let read = file
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ParentPrepError::new(field, "cannot read parent file"))?;
    if read as u64 > limit {
        return Err(ParentPrepError::new(
            field,
            "parent file exceeds its size limit",
        ));
    }
    Ok(bytes)
}

fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let _real = fields.next()?;
        return fields.next()?.parse().ok();
    }
    None
}
