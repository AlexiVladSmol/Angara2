//! Prepared TLS listener state and strict certificate/key loading.
//!
//! Certificate and key files are read once into the immutable configuration
//! snapshot. Errors are safe classes and never include PEM/DER or file content.

use std::fmt;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

#[cfg(not(unix))]
use std::fs::File;

use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::{NoServerSessionStorage, ProducesTickets};
use rustls::{NoKeyLog, ServerConfig};
use zeroize::Zeroizing;

/// Maximum certificate-chain or private-key file size.
pub const MAX_TLS_FILE_BYTES: u64 = 1_048_576;
/// Maximum certificates in one chain.
pub const MAX_CERTIFICATES: usize = 16;
/// Application write buffer limit for each TLS connection.
pub const TLS_APP_BUFFER_BYTES: usize = 64 * 1024;

/// A prepared rustls server configuration for one HTTPS listener.
#[derive(Clone)]
pub(crate) struct PreparedTls {
    config: Arc<ServerConfig>,
}

impl PreparedTls {
    pub(crate) fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }
}

impl fmt::Debug for PreparedTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedTls(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TlsFileKind {
    CertificateChain,
    PrivateKey,
}

impl TlsFileKind {
    fn field(self) -> &'static str {
        match self {
            Self::CertificateChain => "cert_chain_file",
            Self::PrivateKey => "private_key_file",
        }
    }
}

/// Safe TLS preparation error. The field identifies the config path segment.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TlsPrepError {
    field: &'static str,
    class: TlsErrorClass,
}

impl TlsPrepError {
    fn new(field: &'static str, class: TlsErrorClass) -> Self {
        Self { field, class }
    }

    pub(crate) fn field(self) -> &'static str {
        self.field
    }
}

impl fmt::Display for TlsPrepError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.class.message())
    }
}

impl std::error::Error for TlsPrepError {}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Clone, Copy, Debug)]
enum TlsErrorClass {
    Open,
    Metadata,
    NotRegular,
    Read,
    TooLarge,
    UnsafePermissions,
    UnsafeOwner,
    OwnerUnavailable,
    InvalidPem,
    InvalidChain,
    InvalidKey,
    KeyMismatch,
    Config,
}

impl TlsErrorClass {
    fn message(self) -> &'static str {
        match self {
            Self::Open => "cannot open TLS file",
            Self::Metadata => "cannot inspect TLS file",
            Self::NotRegular => "TLS file must be a regular file",
            Self::Read => "cannot read TLS file",
            Self::TooLarge => "TLS file exceeds 1 MiB",
            Self::UnsafePermissions => "TLS file has unsafe permissions",
            Self::UnsafeOwner => "TLS file owner must be the service UID or root",
            Self::OwnerUnavailable => "cannot determine the effective UID for TLS owner check",
            Self::InvalidPem => "TLS file is not valid PEM",
            Self::InvalidChain => "certificate chain must contain 1..=16 valid CERTIFICATE blocks",
            Self::InvalidKey => {
                "private key file must contain exactly one supported unencrypted key"
            }
            Self::KeyMismatch => "private key does not match the leaf certificate",
            Self::Config => "cannot build TLS server configuration",
        }
    }
}

/// Builds the immutable rustls configuration for one listener.
pub(crate) fn prepare_listener(
    cert_chain_path: &Path,
    private_key_path: &Path,
) -> Result<PreparedTls, TlsPrepError> {
    let cert_bytes = read_tls_file(cert_chain_path, TlsFileKind::CertificateChain)?;
    let key_bytes = read_tls_file(private_key_path, TlsFileKind::PrivateKey)?;
    let chain = parse_certificate_chain(&cert_bytes)?;
    let key = parse_private_key(&key_bytes)?;

    let provider = rustls::crypto::ring::default_provider();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsPrepError::new("tls", TlsErrorClass::Config))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|_| {
            TlsPrepError::new(TlsFileKind::PrivateKey.field(), TlsErrorClass::KeyMismatch)
        })?;

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.ticketer = Arc::new(NoTickets);
    config.send_tls13_tickets = 0;
    config.send_half_rtt_data = false;
    config.max_early_data_size = 0;
    config.enable_secret_extraction = false;
    config.key_log = Arc::new(NoKeyLog);
    config.cert_compressors = Vec::new();
    config.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
    config.cert_decompressors = Vec::new();

    Ok(PreparedTls {
        config: Arc::new(config),
    })
}

#[derive(Debug)]
struct NoTickets;

impl ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

fn read_tls_file(path: &Path, kind: TlsFileKind) -> Result<Zeroizing<Vec<u8>>, TlsPrepError> {
    let field = kind.field();
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| TlsPrepError::new(field, TlsErrorClass::Open))?
    };
    #[cfg(not(unix))]
    let file = File::open(path).map_err(|_| TlsPrepError::new(field, TlsErrorClass::Open))?;

    let metadata = file
        .metadata()
        .map_err(|_| TlsPrepError::new(field, TlsErrorClass::Metadata))?;
    if !metadata.is_file() {
        return Err(TlsPrepError::new(field, TlsErrorClass::NotRegular));
    }
    if metadata.len() > MAX_TLS_FILE_BYTES {
        return Err(TlsPrepError::new(field, TlsErrorClass::TooLarge));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let forbidden = match kind {
            TlsFileKind::CertificateChain => 0o022,
            TlsFileKind::PrivateKey => 0o027,
        };
        if metadata.mode() & forbidden != 0 {
            return Err(TlsPrepError::new(field, TlsErrorClass::UnsafePermissions));
        }
        #[cfg(target_os = "linux")]
        {
            let owner = metadata.uid();
            if owner != 0 {
                let effective = effective_uid()
                    .ok_or_else(|| TlsPrepError::new(field, TlsErrorClass::OwnerUnavailable))?;
                if owner != effective {
                    return Err(TlsPrepError::new(field, TlsErrorClass::UnsafeOwner));
                }
            }
        }
    }

    let mut bytes = Zeroizing::new(Vec::new());
    let read = file
        .take(MAX_TLS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TlsPrepError::new(field, TlsErrorClass::Read))?;
    if read as u64 > MAX_TLS_FILE_BYTES {
        return Err(TlsPrepError::new(field, TlsErrorClass::TooLarge));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
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

fn parse_certificate_chain(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsPrepError> {
    let field = TlsFileKind::CertificateChain.field();
    let mut chain = Vec::new();
    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(bytes) {
        let (kind, der) = item.map_err(|_| TlsPrepError::new(field, TlsErrorClass::InvalidPem))?;
        if kind != SectionKind::Certificate {
            return Err(TlsPrepError::new(field, TlsErrorClass::InvalidChain));
        }
        if chain.len() == MAX_CERTIFICATES {
            return Err(TlsPrepError::new(field, TlsErrorClass::InvalidChain));
        }
        match x509_parser::parse_x509_certificate(der.as_slice()) {
            Ok(([], _)) => {}
            _ => return Err(TlsPrepError::new(field, TlsErrorClass::InvalidChain)),
        }
        chain.push(CertificateDer::from(der));
    }
    if chain.is_empty() {
        return Err(TlsPrepError::new(field, TlsErrorClass::InvalidPem));
    }
    Ok(chain)
}

fn parse_private_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, TlsPrepError> {
    let field = TlsFileKind::PrivateKey.field();
    let mut key = None;
    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(bytes) {
        let (kind, der) = item.map_err(|_| TlsPrepError::new(field, TlsErrorClass::InvalidKey))?;
        let next = match kind {
            SectionKind::RsaPrivateKey => PrivateKeyDer::from(PrivatePkcs1KeyDer::from(der)),
            SectionKind::PrivateKey => PrivateKeyDer::from(PrivatePkcs8KeyDer::from(der)),
            SectionKind::EcPrivateKey => PrivateKeyDer::from(PrivateSec1KeyDer::from(der)),
            _ => return Err(TlsPrepError::new(field, TlsErrorClass::InvalidKey)),
        };
        if key.is_some() {
            return Err(TlsPrepError::new(field, TlsErrorClass::InvalidKey));
        }
        key = Some(next);
    }
    let key = key.ok_or_else(|| TlsPrepError::new(field, TlsErrorClass::InvalidKey))?;
    if rustls::crypto::ring::sign::any_supported_type(&key).is_err() {
        return Err(TlsPrepError::new(field, TlsErrorClass::InvalidKey));
    }
    Ok(key)
}
