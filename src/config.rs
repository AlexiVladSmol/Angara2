//! Strict TOML configuration for Angara.
//!
//! The schema is intentionally closed: unknown keys are rejected rather than
//! ignored. Features that are not implemented in M01 (TLS, auth, ACL, egress,
//! cache, admin API) therefore cannot be mistaken for supported settings.

use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};

/// The only configuration schema version supported by this build.
pub const SCHEMA_VERSION: u32 = 1;

/// Upper bound for explicit and resolved Tokio worker threads.
pub const MAX_WORKERS: usize = 64;

/// Upper bound for listener definitions in one configuration.
pub const MAX_LISTENERS: usize = 64;

/// Upper bound for `limits.max_connections`.
pub const MAX_CONNECTIONS_LIMIT: u32 = 65_535;

/// Upper bound for `limits.max_header_bytes` (1 MiB).
pub const MAX_HEADER_BYTES_LIMIT: u32 = 1_048_576;

/// Upper bound for `limits.header_read_timeout_ms` (5 minutes).
pub const HEADER_READ_TIMEOUT_MS_LIMIT: u64 = 300_000;

/// Upper bound for `limits.idle_timeout_ms` (1 hour).
pub const IDLE_TIMEOUT_MS_LIMIT: u64 = 3_600_000;

/// Upper bound for `limits.shutdown_timeout_ms` (5 minutes).
pub const SHUTDOWN_TIMEOUT_MS_LIMIT: u64 = 300_000;

const MIN_MAX_CONNECTIONS: i64 = 1;
const MIN_MAX_HEADER_BYTES: i64 = 1_024;
const MIN_HEADER_READ_TIMEOUT_MS: i64 = 100;
const MIN_IDLE_TIMEOUT_MS: i64 = 1_000;
const MIN_SHUTDOWN_TIMEOUT_MS: i64 = 1;
const WORKER_THREADS_EXPECTED: &str = "must be `auto` or an integer from 1 to 64";

/// A validated Angara configuration.
///
/// Values can only be produced through [`Config::parse`] or [`Config::load`],
/// so a `Config` always satisfies the schema and cross-field invariants.
#[derive(Debug)]
pub struct Config {
    schema_version: u32,
    runtime: RuntimeConfig,
    limits: Limits,
    listeners: Vec<Listener>,
}

impl Config {
    /// Parses and validates a configuration from TOML text.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let deserializer = toml::de::Deserializer::parse(input)
            .map_err(|error| ConfigError::from_toml(input, None, error))?;
        let raw: RawConfig = serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let path = error.path().to_string();
            let path = (path != ".").then_some(path);
            ConfigError::from_toml(input, path, error.into_inner())
        })?;
        validate(raw)
    }

    /// Reads, parses and validates a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let input = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&input)
    }

    /// The validated schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Runtime settings.
    pub fn runtime(&self) -> &RuntimeConfig {
        &self.runtime
    }

    /// Resource limits shared by listeners.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Validated listener definitions in configuration order.
    pub fn listeners(&self) -> &[Listener] {
        &self.listeners
    }
}

/// Runtime section.
#[derive(Debug)]
pub struct RuntimeConfig {
    worker_threads: WorkerThreads,
}

impl RuntimeConfig {
    /// Configured worker-thread policy.
    pub fn worker_threads(&self) -> WorkerThreads {
        self.worker_threads
    }
}

/// Worker-thread policy for the multi-threaded Tokio runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerThreads {
    /// Use the parallelism available to the process, clamped to [`MAX_WORKERS`].
    Auto,
    /// Use exactly this number of worker threads.
    Fixed(usize),
}

impl WorkerThreads {
    /// Resolves the policy against the parallelism available to this process.
    pub fn resolve(self) -> usize {
        let available = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        self.resolve_with(available)
    }

    /// Resolves the policy against an explicit available parallelism.
    ///
    /// This is public so callers and tests can reason about the policy without
    /// depending on the machine running the process. `Auto` never returns zero
    /// and never exceeds [`MAX_WORKERS`].
    pub fn resolve_with(self, available: usize) -> usize {
        match self {
            Self::Auto => available.clamp(1, MAX_WORKERS),
            Self::Fixed(workers) => workers,
        }
    }
}

impl fmt::Display for WorkerThreads {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => formatter.write_str("auto"),
            Self::Fixed(workers) => write!(formatter, "{workers}"),
        }
    }
}

/// Bounded resource limits.
#[derive(Debug)]
pub struct Limits {
    max_connections: u32,
    max_header_bytes: u32,
    header_read_timeout: Duration,
    idle_timeout: Duration,
    shutdown_timeout: Duration,
}

impl Limits {
    /// Maximum accepted connections across all listeners.
    pub fn max_connections(&self) -> u32 {
        self.max_connections
    }

    /// Maximum bytes accepted in one HTTP header block.
    pub fn max_header_bytes(&self) -> u32 {
        self.max_header_bytes
    }

    /// Maximum time allowed to receive a complete HTTP header block.
    pub fn header_read_timeout(&self) -> Duration {
        self.header_read_timeout
    }

    /// Maximum idle time of a client connection.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Maximum time given to runtime shutdown before remaining tasks are dropped.
    pub fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }
}

/// One listener definition.
///
/// M01 supports only the `http` transport. An IPv6 listener is IPv6-only; the
/// future socket bind must set `IPV6_V6ONLY` so that `[::]` does not capture
/// IPv4 traffic. Consequently an IPv4 wildcard and an IPv6 wildcard on the same
/// port are not a configuration conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    id: String,
    bind: SocketAddr,
    transport: Transport,
}

impl Listener {
    /// Stable listener identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Numeric bind address and port.
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Listener transport.
    pub fn transport(&self) -> Transport {
        self.transport
    }
}

/// Listener transports supported by this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plain HTTP listener (the only transport implemented in M01).
    Http,
}

/// A configuration loading or validation error.
///
/// Messages never contain configuration values; they identify the field path
/// and, for parse errors, the line and column instead.
#[derive(Debug)]
pub enum ConfigError {
    /// The configuration file could not be read.
    Read {
        /// Path supplied by the user.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// The document is not valid TOML or does not match the schema.
    Toml {
        /// One-based line and column, when TOML provides a span.
        position: Option<(usize, usize)>,
        /// Dotted field path, when serde provides one.
        path: Option<String>,
        /// Sanitized diagnostic message.
        message: String,
    },
    /// The document is valid TOML but violates a semantic invariant.
    Validation {
        /// Dotted field path.
        path: String,
        /// Description of the violated invariant.
        message: String,
    },
}

impl ConfigError {
    fn from_toml(input: &str, path: Option<String>, error: toml::de::Error) -> Self {
        let position = error.span().map(|span| line_column(input, span.start));
        let message = sanitize_message(error.message());
        Self::Toml {
            position,
            path,
            message,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(
                    formatter,
                    "cannot read configuration file `{}`: {source}",
                    path.display()
                )
            }
            Self::Toml {
                position,
                path,
                message,
            } => {
                if let Some((line, column)) = position {
                    write!(
                        formatter,
                        "invalid configuration at line {line}, column {column}"
                    )?;
                } else {
                    formatter.write_str("invalid configuration")?;
                }
                if let Some(path) = path {
                    write!(formatter, ", field `{path}`")?;
                }
                write!(formatter, ": {message}")
            }
            Self::Validation { path, message } => {
                write!(
                    formatter,
                    "invalid configuration, field `{path}`: {message}"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Toml { .. } | Self::Validation { .. } => None,
        }
    }
}

fn validation(path: impl Into<String>, message: impl Into<String>) -> ConfigError {
    ConfigError::Validation {
        path: path.into(),
        message: message.into(),
    }
}

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

/// Removes string values from a serde/TOML diagnostic.
///
/// Serde renders unexpected string values between double quotes, so a secret
/// that was placed in a wrong field cannot reach stdout, stderr or CI logs.
/// Field names and expected tokens are preserved.
fn sanitize_message(message: &str) -> String {
    if let Some(rest) = message.strip_prefix("unknown field `")
        && let Some((field, _)) = rest.split_once('`')
    {
        return if is_future_feature_field(field) {
            format!("field `{field}` is not supported in M01")
        } else {
            format!("unknown field `{field}`")
        };
    }

    let mut sanitized = String::with_capacity(message.len());
    let mut characters = message.chars();
    while let Some(character) = characters.next() {
        if character == '`' {
            // Backtick-quoted tokens are field names and expected literals,
            // not user values. Copy them as-is so diagnostics stay useful.
            sanitized.push(character);
            for inner in characters.by_ref() {
                sanitized.push(inner);
                if inner == '`' {
                    break;
                }
            }
        } else if character == '"' {
            sanitized.push_str("\"<redacted>\"");
            let mut escaped = false;
            for character in characters.by_ref() {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    break;
                }
            }
        } else {
            sanitized.push(character);
        }
    }

    let mut single_line = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
    if single_line.chars().count() > 240 {
        single_line = single_line.chars().take(240).collect::<String>();
        single_line.push_str("...");
    }
    single_line
}

fn is_future_feature_field(field: &str) -> bool {
    matches!(
        field,
        "acl"
            | "admin"
            | "auth"
            | "cache"
            | "control"
            | "dns"
            | "egress"
            | "logging"
            | "logs"
            | "metrics"
            | "parent"
            | "policy"
            | "routing"
            | "telemetry"
            | "tls"
            | "upstream"
            | "users"
    )
}

fn validate(raw: RawConfig) -> Result<Config, ConfigError> {
    if raw.schema_version != i64::from(SCHEMA_VERSION) {
        return Err(validation(
            "schema_version",
            format!(
                "unsupported schema_version {}; this build supports {SCHEMA_VERSION}",
                raw.schema_version
            ),
        ));
    }

    let limits = validate_limits(raw.limits)?;
    let listeners = validate_listeners(raw.listeners)?;

    Ok(Config {
        schema_version: SCHEMA_VERSION,
        runtime: RuntimeConfig {
            worker_threads: raw.runtime.worker_threads,
        },
        limits,
        listeners,
    })
}

fn validate_limits(raw: RawLimits) -> Result<Limits, ConfigError> {
    let max_connections = bounded(
        "limits.max_connections",
        raw.max_connections,
        MIN_MAX_CONNECTIONS,
        i64::from(MAX_CONNECTIONS_LIMIT),
    )?;
    let max_header_bytes = bounded(
        "limits.max_header_bytes",
        raw.max_header_bytes,
        MIN_MAX_HEADER_BYTES,
        i64::from(MAX_HEADER_BYTES_LIMIT),
    )?;
    let header_read_timeout_ms = bounded(
        "limits.header_read_timeout_ms",
        raw.header_read_timeout_ms,
        MIN_HEADER_READ_TIMEOUT_MS,
        HEADER_READ_TIMEOUT_MS_LIMIT as i64,
    )?;
    let idle_timeout_ms = bounded(
        "limits.idle_timeout_ms",
        raw.idle_timeout_ms,
        MIN_IDLE_TIMEOUT_MS,
        IDLE_TIMEOUT_MS_LIMIT as i64,
    )?;
    let shutdown_timeout_ms = bounded(
        "limits.shutdown_timeout_ms",
        raw.shutdown_timeout_ms,
        MIN_SHUTDOWN_TIMEOUT_MS,
        SHUTDOWN_TIMEOUT_MS_LIMIT as i64,
    )?;

    Ok(Limits {
        max_connections: max_connections as u32,
        max_header_bytes: max_header_bytes as u32,
        header_read_timeout: Duration::from_millis(header_read_timeout_ms as u64),
        idle_timeout: Duration::from_millis(idle_timeout_ms as u64),
        shutdown_timeout: Duration::from_millis(shutdown_timeout_ms as u64),
    })
}

fn bounded(path: &str, value: i64, minimum: i64, maximum: i64) -> Result<i64, ConfigError> {
    if (minimum..=maximum).contains(&value) {
        Ok(value)
    } else {
        Err(validation(
            path,
            format!("must be in {minimum}..={maximum}"),
        ))
    }
}

fn validate_listeners(raw: Vec<RawListener>) -> Result<Vec<Listener>, ConfigError> {
    if raw.is_empty() {
        return Err(validation("listeners", "at least one listener is required"));
    }
    if raw.len() > MAX_LISTENERS {
        return Err(validation(
            "listeners",
            format!("at most {MAX_LISTENERS} listeners are supported"),
        ));
    }

    let mut listeners = Vec::with_capacity(raw.len());
    for (index, listener) in raw.into_iter().enumerate() {
        validate_listener_id(&listener.id, index)?;
        validate_listener_address(listener.bind.0, index)?;
        listeners.push(Listener {
            id: listener.id,
            bind: listener.bind.0,
            transport: listener.transport,
        });
    }

    for first in 0..listeners.len() {
        for second in (first + 1)..listeners.len() {
            let left = &listeners[first];
            let right = &listeners[second];

            if left.id == right.id {
                return Err(validation(
                    format!("listeners[{second}].id"),
                    format!(
                        "duplicate listener id `{}` (already used by listeners[{first}].id)",
                        left.id
                    ),
                ));
            }

            if left.bind.port() != right.bind.port() || left.bind.is_ipv4() != right.bind.is_ipv4()
            {
                continue;
            }

            if left.bind == right.bind {
                return Err(validation(
                    format!("listeners[{second}].bind"),
                    format!(
                        "duplicate listener address `{}` (already used by listeners[{first}].bind)",
                        right.bind
                    ),
                ));
            }

            if left.bind.ip().is_unspecified() || right.bind.ip().is_unspecified() {
                return Err(validation(
                    format!("listeners[{second}].bind"),
                    format!(
                        "wildcard conflict: listeners[{first}] `{}` = `{}` and listeners[{second}] `{}` = `{}` share an IP family and port",
                        left.id, left.bind, right.id, right.bind
                    ),
                ));
            }
        }
    }

    Ok(listeners)
}

fn validate_listener_id(id: &str, index: usize) -> Result<(), ConfigError> {
    let path = format!("listeners[{index}].id");
    if id.is_empty() || id.len() > 64 {
        return Err(validation(path, "must be 1..=64 ASCII characters"));
    }
    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(validation(
            path,
            "must contain only ASCII letters, digits, '-', '_' or '.'",
        ));
    }
    Ok(())
}

fn validate_listener_address(address: SocketAddr, index: usize) -> Result<(), ConfigError> {
    let path = format!("listeners[{index}].bind");
    if address.port() == 0 {
        return Err(validation(path, "port 0 is not allowed; choose 1..=65535"));
    }

    if let SocketAddr::V6(address) = address {
        if address.ip().to_ipv4_mapped().is_some() {
            return Err(validation(
                path,
                "IPv4-mapped IPv6 addresses are not allowed; use the IPv4 form",
            ));
        }
        if address.scope_id() != 0 {
            return Err(validation(
                path,
                "scoped IPv6 listener addresses are not supported in M01",
            ));
        }
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: i64,
    runtime: RawRuntime,
    limits: RawLimits,
    listeners: Vec<RawListener>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntime {
    worker_threads: WorkerThreads,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_connections: i64,
    max_header_bytes: i64,
    header_read_timeout_ms: i64,
    idle_timeout_ms: i64,
    shutdown_timeout_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListener {
    id: String,
    bind: ListenerAddress,
    transport: Transport,
}

struct ListenerAddress(SocketAddr);

impl<'de> Deserialize<'de> for ListenerAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse::<SocketAddr>().map(Self).map_err(|_| {
            de::Error::custom("must be a numeric IP:port such as `127.0.0.1:3128` or `[::1]:3128`")
        })
    }
}

impl<'de> Deserialize<'de> for Transport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "http" => Ok(Self::Http),
            _ => Err(de::Error::custom(
                "unsupported transport; M01 supports only `http`",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for WorkerThreads {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WorkerThreadsVisitor;

        impl Visitor<'_> for WorkerThreadsVisitor {
            type Value = WorkerThreads;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(WORKER_THREADS_EXPECTED)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == "auto" {
                    Ok(WorkerThreads::Auto)
                } else {
                    Err(E::custom(WORKER_THREADS_EXPECTED))
                }
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let workers = usize::try_from(value)
                    .ok()
                    .filter(|workers| (1..=MAX_WORKERS).contains(workers));
                workers
                    .map(WorkerThreads::Fixed)
                    .ok_or_else(|| E::custom(WORKER_THREADS_EXPECTED))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let workers = usize::try_from(value)
                    .ok()
                    .filter(|workers| (1..=MAX_WORKERS).contains(workers));
                workers
                    .map(WorkerThreads::Fixed)
                    .ok_or_else(|| E::custom(WORKER_THREADS_EXPECTED))
            }

            fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::custom(WORKER_THREADS_EXPECTED))
            }

            fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::custom(WORKER_THREADS_EXPECTED))
            }

            fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::custom(WORKER_THREADS_EXPECTED))
            }

            fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::custom(WORKER_THREADS_EXPECTED))
            }
        }

        deserializer.deserialize_any(WorkerThreadsVisitor)
    }
}
