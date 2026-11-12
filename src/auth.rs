//! Local users, HTTP Basic credential parsing and bounded Argon2id verification.
//!
//! The module deliberately exposes no plaintext password constructor for an
//! identity. A [`VerifiedIdentity`] can only be produced by a successful
//! [`AuthService`] verification against one loaded users snapshot.

use std::collections::HashMap;
use std::fmt;
#[cfg(not(unix))]
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier as _, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::header::PROXY_AUTHORIZATION;
use http::{HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_path_to_error::{Path as SerdePath, Segment as SerdeSegment};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

/// Maximum users file size accepted from one open regular-file handle.
pub const MAX_USERS_FILE_BYTES: u64 = 1_048_576;
/// Maximum number of users in one snapshot.
pub const MAX_USERS: usize = 1_024;
/// Maximum username length in bytes.
pub const MAX_USERNAME_BYTES: usize = 64;
/// Maximum password length in UTF-8 bytes before and after NFC.
pub const MAX_PASSWORD_BYTES: usize = 1_024;
/// Maximum Proxy-Authorization field value accepted for Basic parsing.
pub const MAX_AUTH_HEADER_VALUE_BYTES: usize = 1_536;
/// Maximum decoded `user:password` size accepted for Basic parsing.
pub const MAX_DECODED_CREDENTIAL_BYTES: usize = 1_089;
/// Maximum PHC string length in bytes.
pub const MAX_PHC_BYTES: usize = 256;

/// Fixed Argon2id memory cost in KiB.
pub const ARGON2_M_COST: u32 = 19_456;
/// Fixed Argon2id iteration count.
pub const ARGON2_T_COST: u32 = 2;
/// Fixed Argon2id parallelism.
pub const ARGON2_P_COST: u32 = 1;
/// Fixed Argon2id salt length.
pub const ARGON2_SALT_BYTES: usize = 16;
/// Fixed Argon2id output length.
pub const ARGON2_OUTPUT_BYTES: usize = 32;

/// Synthetic dummy verifier hash with the fixed profile.
///
/// The decoded output is all zeroes and cannot correspond to a real user.
/// It is validated during snapshot loading before it is ever used.
const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAECAwQFBgcICQoLDA0ODw$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Listener authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Anonymous laboratory mode.
    None,
    /// RFC 7617 Basic credentials are required for every request.
    Basic,
}

/// A single validated local account.
#[derive(Clone)]
pub(crate) struct UserRecord {
    pub(crate) username: String,
    pub(crate) password_hash: PasswordHashValue,
    pub(crate) disabled: bool,
}

impl fmt::Debug for UserRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserRecord")
            .field("username", &self.username)
            .field("disabled", &self.disabled)
            .finish_non_exhaustive()
    }
}

/// A PHC string treated as sensitive data and cleared on drop.
#[derive(Clone)]
pub(crate) struct PasswordHashValue(Zeroizing<String>);

impl PasswordHashValue {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for PasswordHashValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHashValue(<redacted>)")
    }
}

static NEXT_SNAPSHOT_ID: AtomicU64 = AtomicU64::new(1);

/// One immutable users snapshot. Snapshots are never merged.
pub struct UsersSnapshot {
    id: u64,
    users: HashMap<String, UserRecord>,
    dummy: PasswordHashValue,
}

impl fmt::Debug for UsersSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UsersSnapshot")
            .field("id", &self.id)
            .field("users", &self.users.len())
            .finish_non_exhaustive()
    }
}

impl UsersSnapshot {
    /// Loads and fully validates one users file.
    pub(crate) fn load(path: &Path) -> Result<Self, UsersFileError> {
        let bytes = read_bounded_file(path)?;
        let text = match String::from_utf8(bytes) {
            Ok(text) => Zeroizing::new(text),
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                return Err(UsersFileError::InvalidUtf8);
            }
        };
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self, UsersFileError> {
        let deserializer =
            toml::de::Deserializer::parse(text).map_err(|error| UsersFileError::Toml {
                position: error.span().map(|span| line_column(text, span.start)),
                path: None,
                message: sanitize_users_message(error.message()),
            })?;
        let raw: RawUsersFile =
            serde_path_to_error::deserialize(deserializer).map_err(|error| {
                let path = sanitize_users_path(error.path());
                let inner = error.into_inner();
                UsersFileError::Toml {
                    position: inner.span().map(|span| line_column(text, span.start)),
                    path,
                    message: sanitize_users_message(inner.message()),
                }
            })?;

        if raw.version != 1 {
            return Err(UsersFileError::Version);
        }
        if raw.users.len() > MAX_USERS {
            return Err(UsersFileError::TooManyUsers);
        }

        let dummy = PasswordHashValue::new(DUMMY_PHC.to_owned());
        validate_phc(dummy.as_str())
            .map_err(|_| UsersFileError::Internal("dummy PHC is invalid"))?;

        let mut users = HashMap::with_capacity(raw.users.len());
        for (index, raw_user) in raw.users.into_iter().enumerate() {
            let username = raw_user.username;
            if !is_valid_username(&username) {
                return Err(UsersFileError::InvalidUsername { index });
            }
            let password_hash = Zeroizing::new(raw_user.password_hash);
            validate_phc(&password_hash)
                .map_err(|_| UsersFileError::InvalidPasswordHash { index })?;
            if users.contains_key(&username) {
                return Err(UsersFileError::DuplicateUsername { index });
            }
            users.insert(
                username.clone(),
                UserRecord {
                    username,
                    password_hash: PasswordHashValue(password_hash),
                    disabled: raw_user.disabled,
                },
            );
        }

        Ok(Self {
            id: NEXT_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed),
            users,
            dummy,
        })
    }

    /// Snapshot identifier used only for pool isolation.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    fn enabled_user(&self, username: &str) -> Option<&UserRecord> {
        self.users.get(username).filter(|record| !record.disabled)
    }
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, UsersFileError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| UsersFileError::Open)?
    };
    #[cfg(not(unix))]
    let file = File::open(path).map_err(|_| UsersFileError::Open)?;
    let metadata = file.metadata().map_err(|_| UsersFileError::Metadata)?;
    if !metadata.is_file() {
        return Err(UsersFileError::NotRegular);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o027 != 0 {
            return Err(UsersFileError::UnsafePermissions);
        }
        #[cfg(target_os = "linux")]
        {
            let owner = metadata.uid();
            let effective = if owner == 0 {
                None
            } else {
                Some(effective_uid().ok_or(UsersFileError::OwnerUnavailable)?)
            };
            if !owner_is_allowed(owner, effective) {
                return Err(UsersFileError::UnsafeOwner);
            }
        }
    }
    if metadata.len() > MAX_USERS_FILE_BYTES {
        return Err(UsersFileError::TooLarge);
    }

    let mut bytes = Zeroizing::new(Vec::new());
    let read = file
        .take(MAX_USERS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UsersFileError::Read)?;
    if read as u64 > MAX_USERS_FILE_BYTES {
        return Err(UsersFileError::TooLarge);
    }
    Ok(std::mem::take(&mut *bytes))
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

#[cfg(target_os = "linux")]
fn owner_is_allowed(owner: u32, effective: Option<u32>) -> bool {
    owner == 0 || effective == Some(owner)
}

/// Whether a string uses the local account ASCII namespace.
pub(crate) fn is_valid_username(username: &str) -> bool {
    let bytes = username.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_USERNAME_BYTES {
        return false;
    }
    let Some(first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_phc(phc: &str) -> Result<(), PhcError> {
    if phc.is_empty() || phc.len() > MAX_PHC_BYTES || !phc.is_ascii() {
        return Err(PhcError::Shape);
    }
    if phc
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(PhcError::Shape);
    }

    let parsed = PasswordHash::new(phc).map_err(|_| PhcError::Parse)?;
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return Err(PhcError::Algorithm);
    }
    if parsed.version != Some(Version::V0x13 as u32) {
        return Err(PhcError::Version);
    }

    let mut saw_m = false;
    let mut saw_t = false;
    let mut saw_p = false;
    for (name, value) in parsed.params.iter() {
        match name.as_str() {
            "m" if value.as_str() == "19456" => {
                if saw_m {
                    return Err(PhcError::Parameters);
                }
                saw_m = true;
            }
            "t" if value.as_str() == "2" => {
                if saw_t {
                    return Err(PhcError::Parameters);
                }
                saw_t = true;
            }
            "p" if value.as_str() == "1" => {
                if saw_p {
                    return Err(PhcError::Parameters);
                }
                saw_p = true;
            }
            _ => return Err(PhcError::Parameters),
        }
    }
    if !saw_m || !saw_t || !saw_p || parsed.params.iter().count() != 3 {
        return Err(PhcError::Parameters);
    }

    let salt = parsed.salt.as_ref().ok_or(PhcError::Salt)?;
    let mut salt_bytes = [0_u8; 64];
    let decoded_salt = salt
        .decode_b64(&mut salt_bytes)
        .map_err(|_| PhcError::Salt)?;
    if decoded_salt.len() != ARGON2_SALT_BYTES {
        return Err(PhcError::Salt);
    }
    let output = parsed.hash.as_ref().ok_or(PhcError::Output)?;
    if output.len() != ARGON2_OUTPUT_BYTES {
        return Err(PhcError::Output);
    }
    Ok(())
}

#[derive(Debug)]
enum PhcError {
    Shape,
    Parse,
    Algorithm,
    Version,
    Parameters,
    Salt,
    Output,
}

/// A safe users-file loading error.
#[derive(Debug)]
pub(crate) enum UsersFileError {
    Open,
    Metadata,
    NotRegular,
    Read,
    TooLarge,
    InvalidUtf8,
    #[cfg(unix)]
    UnsafePermissions,
    #[cfg(all(unix, target_os = "linux"))]
    UnsafeOwner,
    #[cfg(all(unix, target_os = "linux"))]
    OwnerUnavailable,
    Toml {
        position: Option<(usize, usize)>,
        path: Option<String>,
        message: String,
    },
    Version,
    TooManyUsers,
    InvalidUsername {
        index: usize,
    },
    InvalidPasswordHash {
        index: usize,
    },
    DuplicateUsername {
        index: usize,
    },
    Internal(&'static str),
}

impl fmt::Display for UsersFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => formatter.write_str("cannot open users file"),
            Self::Metadata => formatter.write_str("cannot inspect users file"),
            Self::NotRegular => formatter.write_str("users file must be a regular file"),
            Self::Read => formatter.write_str("cannot read users file"),
            Self::TooLarge => formatter.write_str("users file exceeds 1 MiB"),
            Self::InvalidUtf8 => formatter.write_str("users file is not valid UTF-8"),
            #[cfg(unix)]
            Self::UnsafePermissions => formatter.write_str(
                "users file has unsafe permissions; group write and all world permissions are forbidden",
            ),
            #[cfg(all(unix, target_os = "linux"))]
            Self::UnsafeOwner => {
                formatter.write_str("users file owner must be the service UID or root")
            }
            #[cfg(all(unix, target_os = "linux"))]
            Self::OwnerUnavailable => {
                formatter.write_str("cannot determine the effective UID for users file owner check")
            }
            Self::Toml {
                position,
                path,
                message,
            } => {
                formatter.write_str("users file is not valid TOML")?;
                if let Some((line, column)) = position {
                    write!(formatter, " at line {line}, column {column}")?;
                }
                if let Some(path) = path {
                    let path = crate::config::escape_control(path, 160);
                    write!(formatter, ", field `{path}`")?;
                }
                let message = crate::config::escape_control(message, 240);
                write!(formatter, ": {message}")
            }
            Self::Version => formatter.write_str("users file version must be 1"),
            Self::TooManyUsers => formatter.write_str("users file exceeds 1024 users"),
            Self::InvalidUsername { index } => {
                write!(formatter, "users[{index}].username is invalid")
            }
            Self::InvalidPasswordHash { index } => {
                write!(formatter, "users[{index}].password_hash is invalid")
            }
            Self::DuplicateUsername { index } => {
                write!(formatter, "users[{index}].username is duplicated")
            }
            Self::Internal(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for UsersFileError {}

fn line_column(input: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(input.len());
    let mut line = 1;
    let mut column = 1;
    for (index, character) in input.char_indices() {
        if index >= offset {
            break;
        }
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

const USERS_FIELDS: [&str; 5] = ["version", "users", "username", "password_hash", "disabled"];

fn sanitize_users_path(path: &SerdePath) -> Option<String> {
    let mut sanitized = String::new();
    let mut has_segment = false;
    for segment in path.iter() {
        match segment {
            SerdeSegment::Seq { index } => {
                sanitized.push('[');
                sanitized.push_str(&index.to_string());
                sanitized.push(']');
            }
            SerdeSegment::Map { key } => {
                if has_segment {
                    sanitized.push('.');
                }
                if USERS_FIELDS.contains(&key.as_str()) {
                    sanitized.push_str(key);
                } else {
                    sanitized.push_str("<unknown>");
                }
                has_segment = true;
            }
            SerdeSegment::Enum { .. } | SerdeSegment::Unknown => {
                if has_segment {
                    sanitized.push('.');
                }
                sanitized.push_str("<unknown>");
                has_segment = true;
            }
        }
    }
    has_segment.then_some(sanitized)
}

fn sanitize_users_message(message: &str) -> String {
    if message.contains("unknown field") {
        "unknown field".to_owned()
    } else if message.contains("missing field") {
        "missing field".to_owned()
    } else if message.contains("invalid type") {
        "invalid type".to_owned()
    } else if message.contains("invalid value") {
        "invalid value".to_owned()
    } else if message.contains("duplicate field") {
        "duplicate field".to_owned()
    } else {
        "invalid users TOML".to_owned()
    }
}

/// A verified identity bound to one loaded snapshot.
#[derive(Clone)]
pub struct VerifiedIdentity {
    snapshot: Arc<UsersSnapshot>,
    username: String,
}

impl VerifiedIdentity {
    fn new(snapshot: Arc<UsersSnapshot>, username: String) -> Self {
        Self { snapshot, username }
    }

    /// Verified local username.
    pub fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn belongs_to(&self, snapshot: &Arc<UsersSnapshot>) -> bool {
        Arc::ptr_eq(&self.snapshot, snapshot)
    }

    pub(crate) fn snapshot_id(&self) -> u64 {
        self.snapshot.id()
    }
}

impl PartialEq for VerifiedIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username && Arc::ptr_eq(&self.snapshot, &other.snapshot)
    }
}

impl Eq for VerifiedIdentity {}

impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedIdentity")
            .field("username", &"<verified>")
            .finish_non_exhaustive()
    }
}

/// Authentication failures. Messages never contain credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// Missing, duplicated, malformed or incorrect credentials.
    InvalidCredentials,
    /// The shared verification budget is full.
    Busy,
    /// The verification deadline elapsed.
    Timeout,
    /// The verifier failed safely.
    Internal,
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCredentials => "proxy credentials are missing or invalid",
            Self::Busy => "password verification budget is exhausted",
            Self::Timeout => "password verification timed out",
            Self::Internal => "password verification failed",
        })
    }
}

impl std::error::Error for AuthError {}

/// A safe verifier failure without credential details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyError;

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("password verification failed")
    }
}

impl std::error::Error for VerifyError {}

/// Password verifier seam used by tests and the production Argon2id backend.
pub trait PasswordVerifier: Send + Sync + 'static {
    /// Returns `Ok(true)` only when `password` matches `phc`.
    fn verify(&self, phc: &str, password: &str) -> Result<bool, VerifyError>;
}

/// Production Argon2id verifier with the fixed M05 profile.
#[derive(Debug, Default)]
pub struct Argon2Verifier;

impl PasswordVerifier for Argon2Verifier {
    fn verify(&self, phc: &str, password: &str) -> Result<bool, VerifyError> {
        validate_phc(phc).map_err(|_| VerifyError)?;
        let parsed = PasswordHash::new(phc).map_err(|_| VerifyError)?;
        let password = Zeroizing::new(password.nfc().collect::<String>());
        let params = Params::new(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(ARGON2_OUTPUT_BYTES),
        )
        .map_err(|_| VerifyError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        match argon2.verify_password(password.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(_) => Err(VerifyError),
        }
    }
}

/// One per-server authentication service.
#[derive(Clone)]
pub struct AuthService {
    snapshot: Arc<UsersSnapshot>,
    permits: Arc<Semaphore>,
    verify_timeout: Duration,
    verifier: Arc<dyn PasswordVerifier>,
}

impl fmt::Debug for AuthService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthService")
            .field("max_verifying", &self.permits.available_permits())
            .field("verify_timeout", &self.verify_timeout)
            .finish_non_exhaustive()
    }
}

impl AuthService {
    /// Builds the production service from a prepared configuration.
    pub fn from_config(config: &crate::config::Config) -> Option<Self> {
        Self::from_config_with_verifier(config, Arc::new(Argon2Verifier))
    }

    /// Builds a service with an injected verifier for deterministic tests.
    #[doc(hidden)]
    pub fn from_config_with_verifier(
        config: &crate::config::Config,
        verifier: Arc<dyn PasswordVerifier>,
    ) -> Option<Self> {
        config.auth().map(|auth| Self {
            snapshot: Arc::clone(auth.snapshot()),
            permits: Arc::new(Semaphore::new(auth.max_verifying())),
            verify_timeout: auth.verify_timeout(),
            verifier,
        })
    }

    /// Number of verification permits currently available.
    #[doc(hidden)]
    pub fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// Parses exactly one Basic field and verifies it under the shared budget.
    pub async fn authenticate_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<VerifiedIdentity, AuthError> {
        let credentials = parse_basic_credentials(headers)?;
        self.authenticate(credentials).await
    }

    async fn authenticate(
        &self,
        credentials: BasicCredentials,
    ) -> Result<VerifiedIdentity, AuthError> {
        let enabled = self.snapshot.enabled_user(&credentials.username);
        let is_real = enabled.is_some();
        let hash = match enabled {
            Some(record) => record.password_hash.clone(),
            None => self.snapshot.dummy.clone(),
        };
        let username = credentials.username;
        let password = credentials.password;
        let verifier = Arc::clone(&self.verifier);
        let deadline = tokio::time::Instant::now() + self.verify_timeout;

        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthError::Busy)?;
        let task = tokio::task::spawn_blocking(move || {
            let permit: OwnedSemaphorePermit = permit;
            let result = verifier.verify(hash.as_str(), password.as_str());
            // Release the shared budget only after the verifier and both
            // application-owned secret buffers are gone.
            drop(hash);
            drop(password);
            drop(permit);
            result
        });

        match tokio::time::timeout_at(deadline, task).await {
            Ok(Ok(Ok(true))) if is_real => {
                Ok(VerifiedIdentity::new(Arc::clone(&self.snapshot), username))
            }
            Ok(Ok(Ok(_))) => Err(AuthError::InvalidCredentials),
            Ok(Ok(Err(_))) | Ok(Err(_)) => Err(AuthError::Internal),
            Err(_) => Err(AuthError::Timeout),
        }
    }
}

struct BasicCredentials {
    username: String,
    password: Zeroizing<String>,
}

fn parse_basic_credentials(headers: &HeaderMap) -> Result<BasicCredentials, AuthError> {
    let mut values = headers.get_all(PROXY_AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(AuthError::InvalidCredentials);
    };
    if values.next().is_some() {
        return Err(AuthError::InvalidCredentials);
    }
    parse_basic_value(value)
}

fn parse_basic_value(value: &HeaderValue) -> Result<BasicCredentials, AuthError> {
    if value.as_bytes().len() > MAX_AUTH_HEADER_VALUE_BYTES {
        return Err(AuthError::InvalidCredentials);
    }
    let value = value.to_str().map_err(|_| AuthError::InvalidCredentials)?;
    let value = value.trim_matches([' ', '\t']);
    let Some(rest) = value.get(..5) else {
        return Err(AuthError::InvalidCredentials);
    };
    if !rest.eq_ignore_ascii_case("Basic") {
        return Err(AuthError::InvalidCredentials);
    }
    let mut remainder = &value[5..];
    if !remainder.starts_with(' ') {
        return Err(AuthError::InvalidCredentials);
    }
    remainder = remainder.trim_start_matches(' ');
    if remainder.is_empty()
        || remainder
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b',')
    {
        return Err(AuthError::InvalidCredentials);
    }
    if remainder.len() > 1_452 {
        return Err(AuthError::InvalidCredentials);
    }

    let decoded = STANDARD
        .decode(remainder.as_bytes())
        .map_err(|_| AuthError::InvalidCredentials)?;
    let decoded = Zeroizing::new(decoded);
    if decoded.is_empty() || decoded.len() > MAX_DECODED_CREDENTIAL_BYTES {
        return Err(AuthError::InvalidCredentials);
    }
    let Some(colon) = decoded.iter().position(|byte| *byte == b':') else {
        return Err(AuthError::InvalidCredentials);
    };
    let user_bytes = &decoded[..colon];
    let password_bytes = &decoded[colon + 1..];
    if user_bytes.is_empty()
        || user_bytes.len() > MAX_USERNAME_BYTES
        || password_bytes.is_empty()
        || password_bytes.len() > MAX_PASSWORD_BYTES
    {
        return Err(AuthError::InvalidCredentials);
    }

    let user = std::str::from_utf8(user_bytes).map_err(|_| AuthError::InvalidCredentials)?;
    let password =
        std::str::from_utf8(password_bytes).map_err(|_| AuthError::InvalidCredentials)?;
    if user.chars().any(char::is_control) || password.chars().any(char::is_control) {
        return Err(AuthError::InvalidCredentials);
    }

    let username = normalize_username(user)?;
    let password = prepare_password(password).map_err(|_| AuthError::InvalidCredentials)?;
    Ok(BasicCredentials { username, password })
}

fn normalize_username(user: &str) -> Result<String, AuthError> {
    let normalized = user.nfc().collect::<String>();
    if normalized.is_empty() || normalized.len() > MAX_USERNAME_BYTES {
        return Err(AuthError::InvalidCredentials);
    }
    Ok(normalized)
}

/// Password input validation and NFC preparation shared by HTTP and CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordError {
    /// The password is empty.
    Empty,
    /// The password exceeds 1024 UTF-8 bytes before or after NFC.
    TooLong,
    /// The password contains a control character.
    ControlCharacter,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "password must not be empty",
            Self::TooLong => "password must be at most 1024 UTF-8 bytes",
            Self::ControlCharacter => "password must not contain control characters",
        })
    }
}

impl std::error::Error for PasswordError {}

/// Validates a UTF-8 password and returns its NFC form in a zeroizing buffer.
pub fn prepare_password(password: &str) -> Result<Zeroizing<String>, PasswordError> {
    if password.is_empty() {
        return Err(PasswordError::Empty);
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordError::TooLong);
    }
    if password.chars().any(char::is_control) {
        return Err(PasswordError::ControlCharacter);
    }
    let normalized = Zeroizing::new(password.nfc().collect::<String>());
    if normalized.is_empty() {
        return Err(PasswordError::Empty);
    }
    if normalized.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordError::TooLong);
    }
    if normalized.chars().any(char::is_control) {
        return Err(PasswordError::ControlCharacter);
    }
    Ok(normalized)
}

/// Random-salt generation or hashing failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashError;

impl fmt::Display for HashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cannot generate a password hash")
    }
}

impl std::error::Error for HashError {}

/// Generates 16 CSPRNG bytes for one salt.
pub fn generate_salt() -> Result<[u8; ARGON2_SALT_BYTES], HashError> {
    generate_salt_with(&mut OsRng)
}

/// Generates a salt from an injected random source.
///
/// This is a test seam for reproducible RNG-failure handling. Production code
/// uses [`generate_salt`] with the operating-system CSPRNG.
#[doc(hidden)]
pub fn generate_salt_with<R: RngCore>(rng: &mut R) -> Result<[u8; ARGON2_SALT_BYTES], HashError> {
    let mut salt = [0_u8; ARGON2_SALT_BYTES];
    rng.try_fill_bytes(&mut salt).map_err(|_| HashError)?;
    Ok(salt)
}

/// Hashes a password with the fixed profile.
///
/// The input is validated and NFC-normalized here, so callers cannot create a
/// hash for a non-normalized variant of a password.
pub fn hash_password(password: &str, salt: &[u8; ARGON2_SALT_BYTES]) -> Result<String, HashError> {
    let password = prepare_password(password).map_err(|_| HashError)?;
    let salt = SaltString::encode_b64(salt).map_err(|_| HashError)?;
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_BYTES),
    )
    .map_err(|_| HashError)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
    let hash = argon2
        .hash_password_customized(
            password.as_bytes(),
            Some(Algorithm::Argon2id.ident()),
            Some(Version::V0x13 as u32),
            params,
            &salt,
        )
        .map_err(|_| HashError)?;
    let phc = hash.to_string();
    validate_phc(&phc).map_err(|_| HashError)?;
    Ok(phc)
}

/// Password bytes rejected by the CLI input limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordInputError {
    /// The input did not contain a password.
    Empty,
    /// The input exceeded 1027 bytes including the line terminator.
    TooLong,
    /// The input contained more than one line or extra bytes.
    ExtraInput,
    /// The input was not valid UTF-8.
    InvalidUtf8,
    /// Reading stdin failed.
    Read,
    /// The password itself failed shared validation.
    Password(PasswordError),
}

impl fmt::Display for PasswordInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "password input is empty",
            Self::TooLong => "password input exceeds the 1027-byte limit",
            Self::ExtraInput => "password input must contain exactly one line",
            Self::InvalidUtf8 => "password input is not valid UTF-8",
            Self::Read => "cannot read password input",
            Self::Password(error) => return error.fmt(formatter),
        })
    }
}

impl std::error::Error for PasswordInputError {}

/// Parses the bounded stdin representation: one line, optional final LF/CRLF.
pub fn parse_password_stdin(input: &[u8]) -> Result<Zeroizing<String>, PasswordInputError> {
    if input.len() > MAX_PASSWORD_BYTES + 3 {
        return Err(PasswordInputError::TooLong);
    }
    let mut line = input;
    if let Some(without_lf) = line.strip_suffix(b"\n") {
        line = without_lf;
        if let Some(without_crlf) = line.strip_suffix(b"\r") {
            line = without_crlf;
        }
    }
    if line.contains(&b'\n') {
        return Err(PasswordInputError::ExtraInput);
    }
    if line.is_empty() {
        return Err(PasswordInputError::Empty);
    }
    let text = std::str::from_utf8(line).map_err(|_| PasswordInputError::InvalidUtf8)?;
    prepare_password(text).map_err(PasswordInputError::Password)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUsersFile {
    version: i64,
    users: Vec<RawUser>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUser {
    username: String,
    password_hash: String,
    #[serde(default)]
    disabled: bool,
}

#[cfg(test)]
pub(crate) fn test_identity(username: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        snapshot: Arc::new(UsersSnapshot {
            id: 0,
            users: HashMap::new(),
            dummy: PasswordHashValue::new(DUMMY_PHC.to_owned()),
        }),
        username: username.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct MockVerifier {
        calls: Arc<AtomicUsize>,
        delay: Duration,
        result: Result<bool, VerifyError>,
        panic: bool,
    }

    impl PasswordVerifier for MockVerifier {
        fn verify(&self, _phc: &str, _password: &str) -> Result<bool, VerifyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.panic {
                panic!("synthetic verifier panic");
            }
            if !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
            self.result
        }
    }

    fn snapshot_with_users(users: &str) -> Arc<UsersSnapshot> {
        Arc::new(UsersSnapshot::parse(users).expect("valid users snapshot"))
    }

    fn mock_service(
        snapshot: Arc<UsersSnapshot>,
        verifier: Arc<dyn PasswordVerifier>,
        max_verifying: usize,
        verify_timeout: Duration,
    ) -> AuthService {
        AuthService {
            snapshot,
            permits: Arc::new(Semaphore::new(max_verifying)),
            verify_timeout,
            verifier,
        }
    }

    fn user_file(username: &str, disabled: bool) -> String {
        format!(
            "version = 1\n\n[[users]]\nusername = \"{username}\"\npassword_hash = \"{DUMMY_PHC}\"\ndisabled = {disabled}\n"
        )
    }

    fn header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(PROXY_AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    fn basic(user: &str, password: &str) -> HeaderMap {
        let encoded = STANDARD.encode(format!("{user}:{password}"));
        header(&format!("Basic {encoded}"))
    }

    #[test]
    fn users_diagnostics_redact_unknown_keys_at_both_levels() {
        let root = "version = 1\nusers = []\n\"REVIEW_SYNTHETIC_SECRET_71\" = 1\n";
        let nested = format!(
            "version = 1\n\n[[users]]\nusername = \"alice\"\npassword_hash = \"{DUMMY_PHC}\"\n\"REVIEW_SYNTHETIC_SECRET_72\" = \"$argon2id$secret\"\n"
        );
        let backtick = "version = 1\nusers = []\n\"prefix`REVIEW_SYNTHETIC_SECRET_93\" = 1\n";
        let nested_backtick = format!(
            "version = 1\n\n[[users]]\nusername = \"alice\"\npassword_hash = \"{DUMMY_PHC}\"\n\"prefix`REVIEW_SYNTHETIC_SECRET_95\" = 1\n"
        );
        let quote = "version = 1\nusers = []\n\"prefix\\\"REVIEW_SYNTHETIC_SECRET_94\\\"\" = 1\n";
        let fake_index = "version = 1\nusers = []\n\"users[971135791357913579]\" = 1\n";
        for text in [
            root,
            nested.as_str(),
            backtick,
            nested_backtick.as_str(),
            quote,
            fake_index,
        ] {
            let error = UsersSnapshot::parse(text).expect_err("unknown key must fail");
            let display = error.to_string();
            let debug = format!("{error:?}");
            for (label, rendered) in [("display", &display), ("debug", &debug)] {
                assert!(
                    !rendered.contains("REVIEW_SYNTHETIC_SECRET"),
                    "{label}: {rendered}"
                );
                assert!(!rendered.contains("$argon2"), "{label}: {rendered}");
                assert!(
                    !rendered.contains("971135791357913579"),
                    "{label}: {rendered}"
                );
                assert!(rendered.contains("unknown field"), "{label}: {rendered}");
            }
        }
        let error = UsersSnapshot::parse(root).expect_err("unknown key must fail");
        assert!(error.to_string().contains("<unknown>"), "{error}");
    }

    #[test]
    fn username_namespace_is_strict_ascii() {
        for valid in ["a", "alice", "A1._-", "0user"] {
            assert!(is_valid_username(valid), "{valid}");
        }
        for invalid in ["", "_alice", ".alice", "-alice", "ali ce", "алиса", "a/b"] {
            assert!(!is_valid_username(invalid), "{invalid}");
        }
        assert!(!is_valid_username(&"a".repeat(MAX_USERNAME_BYTES + 1)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn users_file_owner_must_be_root_or_the_service_uid() {
        assert!(owner_is_allowed(0, None));
        assert!(owner_is_allowed(0, Some(1_000)));
        assert!(owner_is_allowed(1_000, Some(1_000)));
        assert!(!owner_is_allowed(1_000, Some(1_001)));
        assert!(!owner_is_allowed(1_000, None));
    }

    #[test]
    fn password_preparation_keeps_spaces_and_normalizes_nfc() {
        let decomposed = "cafe\u{301} : pass ";
        let prepared = prepare_password(decomposed).expect("valid password");
        assert_eq!(prepared.as_str(), "café : pass ");
        assert!(prepare_password("").is_err());
        assert!(prepare_password("line\rbreak").is_err());
        assert!(prepare_password(&"a".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }

    #[test]
    fn stdin_parser_handles_lf_crlf_eof_and_extra_input() {
        assert_eq!(
            parse_password_stdin(b"secret\n").unwrap().as_str(),
            "secret"
        );
        assert_eq!(
            parse_password_stdin(b"secret\r\n").unwrap().as_str(),
            "secret"
        );
        assert_eq!(parse_password_stdin(b"secret").unwrap().as_str(), "secret");
        assert_eq!(
            parse_password_stdin(b"a b:c \n").unwrap().as_str(),
            "a b:c "
        );
        assert!(matches!(
            parse_password_stdin(b"one\ntwo\n"),
            Err(PasswordInputError::ExtraInput)
        ));
        assert!(matches!(
            parse_password_stdin(b"\n"),
            Err(PasswordInputError::Empty)
        ));
        assert!(matches!(
            parse_password_stdin(&[0xff, b'\n']),
            Err(PasswordInputError::InvalidUtf8)
        ));
        assert!(matches!(
            parse_password_stdin(&[b'a'; MAX_PASSWORD_BYTES + 4]),
            Err(PasswordInputError::TooLong)
        ));
    }

    #[test]
    fn phc_profile_validation_rejects_other_costs_and_malformed_values() {
        let salt = SaltString::encode_b64(&[1_u8; 16]).unwrap();
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None).unwrap();
        let hash = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password(b"secret", &salt)
            .unwrap()
            .to_string();
        assert!(
            validate_phc(&hash).is_ok(),
            "{:?} {hash}",
            validate_phc(&hash).err()
        );

        for mutated in [
            hash.replace("m=19456", "m=19457"),
            hash.replace("m=19456", "m=4294967295"),
            hash.replace("t=2", "t=3"),
            hash.replace("t=2", "t=4294967295"),
            hash.replace("p=1", "p=2"),
            hash.replace("p=1", "p=4294967295"),
            hash.replace("m=19456,t=2,p=1", "m=19456,t=2,p=1,data=x"),
            hash.replace("m=19456,t=2,p=1", "m=19456,t=2,p=1,m=19456"),
            hash.replace("argon2id", "argon2i"),
            hash.replace("argon2id", "argon2d"),
            hash.replace("v=19", "v=16"),
            hash.replace("$v=19", ""),
        ] {
            assert!(validate_phc(&mutated).is_err(), "{mutated}");
        }
        assert!(validate_phc("").is_err());
        assert!(validate_phc("$argon2id$v=19$m=19456,t=2,p=1$bad$bad").is_err());
        assert!(validate_phc(&format!("{hash}\n")).is_err());
        assert!(validate_phc(&"x".repeat(MAX_PHC_BYTES + 1)).is_err());

        let (without_output, output) = hash.rsplit_once('$').expect("output field");
        let (prefix, _salt) = without_output.rsplit_once('$').expect("salt field");
        let short_salt = format!("{prefix}$AA${output}");
        assert!(validate_phc(&short_salt).is_err(), "{short_salt}");
        let short_output = format!("{without_output}$AA");
        assert!(validate_phc(&short_output).is_err());
        let truncated_output = format!("{without_output}$");
        assert!(validate_phc(&truncated_output).is_err());
    }

    #[test]
    fn basic_parser_accepts_expected_forms() {
        let credentials = parse_basic_credentials(&basic("alice", "p:a ss")).unwrap();
        assert_eq!(credentials.username, "alice");
        assert_eq!(credentials.password.as_str(), "p:a ss");

        let mut case = HeaderMap::new();
        case.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_str(&format!("bAsIc   {}", STANDARD.encode("bob:x"))).unwrap(),
        );
        assert_eq!(
            parse_basic_credentials(&case).unwrap().username.as_str(),
            "bob"
        );
    }

    #[test]
    fn basic_parser_rejects_malformed_and_duplicate_fields() {
        for value in [
            "",
            "Basic",
            "Basic ",
            "Bearer abc",
            "Basic !!!",
            "Basic YWxpY2U6cA", // missing padding
            "Basic YWxpY2U6cA==,",
            "Basic YWxpY2U6cA== extra",
            "Basic YWxpY2U6cA==,Qm9i",
        ] {
            assert!(parse_basic_credentials(&header(value)).is_err(), "{value}");
        }

        let mut duplicate = basic("alice", "x");
        duplicate.append(PROXY_AUTHORIZATION, HeaderValue::from_static("Basic YTpi"));
        assert!(parse_basic_credentials(&duplicate).is_err());

        let no_colon = STANDARD.encode("alice");
        assert!(parse_basic_credentials(&header(&format!("Basic {no_colon}"))).is_err());
        let empty_user = STANDARD.encode(":password");
        assert!(parse_basic_credentials(&header(&format!("Basic {empty_user}"))).is_err());
        let empty_password = STANDARD.encode("alice:");
        assert!(parse_basic_credentials(&header(&format!("Basic {empty_password}"))).is_err());
        let control = STANDARD.encode("alice:pass\rword");
        assert!(parse_basic_credentials(&header(&format!("Basic {control}"))).is_err());
    }

    #[test]
    fn basic_parser_enforces_header_and_decoded_limits() {
        let long_value = format!("Basic {}", "A".repeat(MAX_AUTH_HEADER_VALUE_BYTES));
        assert!(parse_basic_credentials(&header(&long_value)).is_err());

        let password = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(parse_basic_credentials(&basic("alice", &password)).is_err());
        let username = "a".repeat(MAX_USERNAME_BYTES + 1);
        assert!(parse_basic_credentials(&basic(&username, "x")).is_err());
    }

    #[test]
    fn real_hash_verifies_and_salts_differ() {
        let password = prepare_password("synthetic password").unwrap();
        let salt_a = [1_u8; 16];
        let salt_b = [2_u8; 16];
        let hash_a = hash_password(&password, &salt_a).unwrap();
        let hash_b = hash_password(&password, &salt_b).unwrap();
        assert_ne!(hash_a, hash_b);
        let verifier = Argon2Verifier;
        assert!(verifier.verify(&hash_a, password.as_str()).unwrap());
        assert!(!verifier.verify(&hash_a, "wrong").unwrap());
    }

    #[test]
    fn users_snapshot_parses_empty_base_and_rejects_duplicates() {
        let empty = UsersSnapshot::parse("version = 1\nusers = []\n").unwrap();
        assert!(empty.users.is_empty());

        let password_hash = hash_password(&prepare_password("x").unwrap(), &[9_u8; 16]).unwrap();
        let text = format!(
            "version = 1\n\n[[users]]\nusername = \"alice\"\npassword_hash = \"{password_hash}\"\n\n[[users]]\nusername = \"alice\"\npassword_hash = \"{password_hash}\"\n"
        );
        assert!(matches!(
            UsersSnapshot::parse(&text),
            Err(UsersFileError::DuplicateUsername { index: 1 })
        ));
        assert!(matches!(
            UsersSnapshot::parse("version = 2\nusers = []\n"),
            Err(UsersFileError::Version)
        ));
        assert!(matches!(
            UsersSnapshot::parse("version = 1\n"),
            Err(UsersFileError::Toml { .. })
        ));
        assert!(matches!(
            UsersSnapshot::parse("version = 1\nusers = []\nsecret = \"MARKER\"\n"),
            Err(UsersFileError::Toml { .. })
        ));
    }

    #[tokio::test]
    async fn unknown_disabled_and_dummy_never_create_identity() {
        let snapshot = snapshot_with_users(&user_file("alice", true));
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier = Arc::new(MockVerifier {
            calls: Arc::clone(&calls),
            delay: Duration::ZERO,
            result: Ok(true),
            panic: false,
        });
        let service = mock_service(snapshot, verifier, 2, Duration::from_secs(1));

        for user in ["alice", "nobody"] {
            let result = service.authenticate_headers(&basic(user, "anything")).await;
            assert_eq!(result.unwrap_err(), AuthError::InvalidCredentials);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn busy_does_not_queue_and_timeout_keeps_the_owned_permit() {
        let snapshot = snapshot_with_users(&user_file("alice", false));
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier = Arc::new(MockVerifier {
            calls: Arc::clone(&calls),
            delay: Duration::from_millis(250),
            result: Ok(true),
            panic: false,
        });
        let service = mock_service(snapshot, verifier, 1, Duration::from_millis(100));

        let first = service
            .authenticate_headers(&basic("alice", "secret"))
            .await;
        assert_eq!(first.unwrap_err(), AuthError::Timeout);
        assert_eq!(service.available_permits(), 0);

        let second = service
            .authenticate_headers(&basic("alice", "secret"))
            .await;
        assert_eq!(second.unwrap_err(), AuthError::Busy);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while service.available_permits() != 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "verifier permit was not released after the actual job finished"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn internal_error_and_panic_release_the_permit() {
        for panic in [false, true] {
            let snapshot = snapshot_with_users(&user_file("alice", false));
            let verifier = Arc::new(MockVerifier {
                calls: Arc::new(AtomicUsize::new(0)),
                delay: Duration::ZERO,
                result: Err(VerifyError),
                panic,
            });
            let service = mock_service(snapshot, verifier, 1, Duration::from_secs(1));
            let result = service
                .authenticate_headers(&basic("alice", "secret"))
                .await;
            assert_eq!(result.unwrap_err(), AuthError::Internal);
            assert_eq!(service.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn successful_real_account_creates_snapshot_bound_identity() {
        let password = prepare_password("secret").unwrap();
        let phc = hash_password(&password, &[3_u8; 16]).unwrap();
        let users =
            format!("version = 1\n\n[[users]]\nusername = \"alice\"\npassword_hash = \"{phc}\"\n");
        let snapshot = snapshot_with_users(&users);
        let service = mock_service(
            Arc::clone(&snapshot),
            Arc::new(Argon2Verifier),
            2,
            Duration::from_secs(2),
        );
        let identity = service
            .authenticate_headers(&basic("alice", "secret"))
            .await
            .expect("verified");
        assert_eq!(identity.username(), "alice");
        assert!(identity.belongs_to(&snapshot));

        let other = snapshot_with_users(&users);
        assert!(!identity.belongs_to(&other));
    }

    #[test]
    fn hash_password_normalizes_nfc_and_rng_failure_is_safe() {
        let decomposed = "cafe\u{301} : pass ";
        let composed = "café : pass ";
        let phc = hash_password(decomposed, &[7_u8; 16]).expect("hash");
        assert!(Argon2Verifier.verify(&phc, composed).expect("verify"));
        assert!(Argon2Verifier.verify(&phc, decomposed).expect("verify NFC"));

        struct FailingRng;
        impl RngCore for FailingRng {
            fn next_u32(&mut self) -> u32 {
                unreachable!()
            }
            fn next_u64(&mut self) -> u64 {
                unreachable!()
            }
            fn fill_bytes(&mut self, _dest: &mut [u8]) {
                unreachable!()
            }
            fn try_fill_bytes(
                &mut self,
                _dest: &mut [u8],
            ) -> Result<(), argon2::password_hash::rand_core::Error> {
                Err(argon2::password_hash::rand_core::Error::from(
                    std::num::NonZeroU32::new(1).expect("nonzero"),
                ))
            }
        }
        assert!(generate_salt_with(&mut FailingRng).is_err());
    }

    #[tokio::test]
    async fn malformed_credentials_do_not_reach_the_verifier() {
        let snapshot = snapshot_with_users(&user_file("alice", false));
        let calls = Arc::new(AtomicUsize::new(0));
        let verifier = Arc::new(MockVerifier {
            calls: Arc::clone(&calls),
            delay: Duration::ZERO,
            result: Ok(false),
            panic: false,
        });
        let service = mock_service(snapshot, verifier, 1, Duration::from_secs(1));
        for value in ["", "Basic", "Bearer abc", "Basic !!!", "Basic YWxpY2U6cA"] {
            assert_eq!(
                service
                    .authenticate_headers(&header(value))
                    .await
                    .unwrap_err(),
                AuthError::InvalidCredentials
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(service.available_permits(), 1);
    }
}
