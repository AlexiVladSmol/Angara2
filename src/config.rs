//! Strict TOML configuration for Angara.
//!
//! The schema is intentionally closed: unknown keys are rejected rather than
//! ignored. Features that are not implemented in this milestone (TLS, auth,
//! cache, admin API, parent proxy) therefore cannot be mistaken for supported
//! settings.

use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::Method;
use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};

use crate::target::{DomainName, parse_method};

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

/// Maximum number of entries in a rule/profile/selector list.
pub const MAX_POLICY_LIST_ITEMS: usize = 256;

/// Maximum identifier length for listeners, rules, and egress profiles.
pub const MAX_ID_BYTES: usize = 64;

const MIN_MAX_CONNECTIONS: i64 = 1;
const MIN_MAX_HEADER_BYTES: i64 = 1_024;
const MIN_HEADER_READ_TIMEOUT_MS: i64 = 100;
const MIN_IDLE_TIMEOUT_MS: i64 = 1_000;
const MIN_SHUTDOWN_TIMEOUT_MS: i64 = 1;
const MIN_DNS_TIMEOUT_MS: i64 = 100;
const MAX_DNS_TIMEOUT_MS: i64 = 30_000;
const MIN_DNS_MAX_IN_FLIGHT: i64 = 1;
const MAX_DNS_MAX_IN_FLIGHT: i64 = 64;
const MIN_DNS_MAX_ANSWERS: i64 = 1;
const MAX_DNS_MAX_ANSWERS: i64 = 64;
const MIN_TOTAL_TIMEOUT_MS: i64 = 100;
const MAX_TOTAL_TIMEOUT_MS: i64 = 120_000;
const MIN_CONNECT_TIMEOUT_MS: i64 = 100;
const MAX_CONNECT_TIMEOUT_MS: i64 = 30_000;
const MIN_CONNECT_ATTEMPTS: i64 = 1;
const MAX_CONNECT_ATTEMPTS: i64 = 8;
const MIN_CONNECTING: i64 = 1;
const MAX_CONNECTING: i64 = 256;
const DEFAULT_DNS_TIMEOUT_MS: i64 = 3_000;
const DEFAULT_DNS_MAX_IN_FLIGHT: i64 = 4;
const DEFAULT_DNS_MAX_ANSWERS: i64 = 16;
const DEFAULT_TOTAL_TIMEOUT_MS: i64 = 10_000;
const DEFAULT_CONNECT_TIMEOUT_MS: i64 = 3_000;
const DEFAULT_CONNECT_ATTEMPTS: i64 = 3;
const DEFAULT_CONNECTING_CAP: i64 = 32;
const MAX_DIAGNOSTIC_PATH_CHARS: usize = 160;
const MAX_DIAGNOSTIC_MESSAGE_CHARS: usize = 240;
const MAX_UNKNOWN_FIELD_CHARS: usize = 80;
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
    access: AccessConfig,
    dns: DnsConfig,
    transport: TransportConfig,
    egress: Vec<EgressProfile>,
    routing: RoutingConfig,
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

    /// Source gate, request ACL, and destination IP policy.
    pub fn access(&self) -> &AccessConfig {
        &self.access
    }

    /// System resolver limits.
    pub fn dns(&self) -> &DnsConfig {
        &self.dns
    }

    /// Outbound connect limits.
    pub fn transport(&self) -> &TransportConfig {
        &self.transport
    }

    /// Validated egress profiles.
    pub fn egress(&self) -> &[EgressProfile] {
        &self.egress
    }

    /// Egress routing rules.
    pub fn routing(&self) -> &RoutingConfig {
        &self.routing
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

/// Source gate, pre-DNS request ACL, and destination IP policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessConfig {
    source_allow: Vec<IpNet>,
    rules: Vec<AccessRule>,
    ip_rules: Vec<IpRule>,
    ip_default: IpDefault,
}

impl AccessConfig {
    /// CIDRs allowed to act as clients. An empty list denies every source.
    pub fn source_allow(&self) -> &[IpNet] {
        &self.source_allow
    }

    /// Ordered pre-DNS request rules.
    pub fn rules(&self) -> &[AccessRule] {
        &self.rules
    }

    /// Ordered destination IP rules.
    pub fn ip_rules(&self) -> &[IpRule] {
        &self.ip_rules
    }

    /// Default when no destination IP rule matches.
    pub fn ip_default(&self) -> IpDefault {
        self.ip_default
    }
}

/// Default policy for a destination IP with no matching rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpDefault {
    /// Allow only ordinary global unicast addresses.
    PublicOnly,
    /// Deny every address without an explicit allow rule.
    Deny,
}

/// First-match request rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Allow the request to continue to DNS and dial.
    Allow,
    /// Deny the request before DNS.
    Deny,
}

/// One pre-DNS request rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRule {
    id: String,
    action: RuleAction,
    selectors: Selectors,
}

impl AccessRule {
    /// Stable rule identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Allow or deny.
    pub fn action(&self) -> RuleAction {
        self.action
    }

    /// Rule selectors.
    pub fn selectors(&self) -> &Selectors {
        &self.selectors
    }
}

/// One destination IP rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRule {
    id: String,
    action: RuleAction,
    networks: Vec<IpNet>,
    allow_special: bool,
}

impl IpRule {
    /// Stable rule identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Allow or deny.
    pub fn action(&self) -> RuleAction {
        self.action
    }

    /// CIDRs matched by this rule.
    pub fn networks(&self) -> &[IpNet] {
        &self.networks
    }

    /// Whether an allow rule may permit a special-purpose address.
    pub fn allow_special(&self) -> bool {
        self.allow_special
    }
}

/// Selectors shared by request ACL and routing rules.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Selectors {
    listeners: Option<Vec<String>>,
    sources: Option<Vec<IpNet>>,
    methods: Option<Vec<Method>>,
    ports: Option<Vec<u16>>,
    hosts: HostSelectors,
}

impl Selectors {
    /// Listener IDs when the selector is present.
    pub fn listeners(&self) -> Option<&[String]> {
        self.listeners.as_deref()
    }

    /// Source CIDRs when the selector is present.
    pub fn sources(&self) -> Option<&[IpNet]> {
        self.sources.as_deref()
    }

    /// Methods when the selector is present.
    pub fn methods(&self) -> Option<&[Method]> {
        self.methods.as_deref()
    }

    /// Ports when the selector is present.
    pub fn ports(&self) -> Option<&[u16]> {
        self.ports.as_deref()
    }

    /// Host selectors.
    pub fn hosts(&self) -> &HostSelectors {
        &self.hosts
    }
}

/// Host part of selectors.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HostSelectors {
    /// Any host.
    #[default]
    Any,
    /// Exact normalized domains.
    Exact(Vec<DomainName>),
    /// Normalized domain suffixes, including the domain itself.
    Suffix(Vec<DomainName>),
}

/// One outbound egress profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressProfile {
    id: String,
    mode: EgressMode,
}

impl EgressProfile {
    /// Stable egress identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Egress mode.
    pub fn mode(&self) -> &EgressMode {
        &self.mode
    }
}

/// How an egress profile selects the outbound socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressMode {
    /// Use the operating system's normal routing.
    System,
    /// Bind the outbound socket to this specific source IP.
    BindIp(IpAddr),
}

/// Ordered egress routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingConfig {
    default_egress: String,
    rules: Vec<RoutingRule>,
}

impl RoutingConfig {
    /// Egress used when no rule matches.
    pub fn default_egress(&self) -> &str {
        &self.default_egress
    }

    /// Ordered routing rules.
    pub fn rules(&self) -> &[RoutingRule] {
        &self.rules
    }
}

/// One routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRule {
    id: String,
    egress_id: String,
    selectors: Selectors,
}

impl RoutingRule {
    /// Stable rule identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Selected egress identifier.
    pub fn egress_id(&self) -> &str {
        &self.egress_id
    }

    /// Rule selectors.
    pub fn selectors(&self) -> &Selectors {
        &self.selectors
    }
}

/// System resolver limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsConfig {
    timeout: Duration,
    max_in_flight: usize,
    max_answers: usize,
}

impl DnsConfig {
    /// DNS timeout for one lookup.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Maximum number of actual blocking lookups in flight.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// Maximum unique addresses accepted from one lookup.
    pub fn max_answers(&self) -> usize {
        self.max_answers
    }
}

/// Outbound connect limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportConfig {
    total_timeout: Duration,
    connect_timeout: Duration,
    max_connect_attempts: usize,
    max_connecting: usize,
}

impl TransportConfig {
    /// Total deadline for one `open_outbound` call.
    pub fn total_timeout(&self) -> Duration {
        self.total_timeout
    }

    /// Per-attempt connect timeout.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Maximum sequential connect attempts.
    pub fn max_connect_attempts(&self) -> usize {
        self.max_connect_attempts
    }

    /// Maximum simultaneous connect attempts.
    pub fn max_connecting(&self) -> usize {
        self.max_connecting
    }
}

/// One listener definition.
///
/// This build supports only the `http` transport. An IPv6 listener is IPv6-only;
/// the future socket bind must set `IPV6_V6ONLY` so that `[::]` does not capture
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
    /// Plain HTTP listener (the only listener transport implemented here).
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
                let path = escape_control(&path.to_string_lossy(), MAX_DIAGNOSTIC_PATH_CHARS);
                let source = escape_control(&source.to_string(), MAX_DIAGNOSTIC_MESSAGE_CHARS);
                write!(
                    formatter,
                    "cannot read configuration file `{path}`: {source}"
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
                    let path = escape_control(path, MAX_DIAGNOSTIC_PATH_CHARS);
                    write!(formatter, ", field `{path}`")?;
                }
                let message = escape_control(message, MAX_DIAGNOSTIC_MESSAGE_CHARS);
                write!(formatter, ": {message}")
            }
            Self::Validation { path, message } => {
                let path = escape_control(path, MAX_DIAGNOSTIC_PATH_CHARS);
                let message = escape_control(message, MAX_DIAGNOSTIC_MESSAGE_CHARS);
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

/// Removes string values from a serde/TOML diagnostic and escapes control
/// characters so one error always occupies exactly one log record.
///
/// Serde renders unexpected string values between double quotes, so a secret
/// that was placed in a wrong field cannot reach stdout, stderr or CI logs.
/// Field names and expected tokens are preserved, but are escaped and length
/// limited before they are inserted into the message.
fn sanitize_message(message: &str) -> String {
    let normalized = if let Some(rest) = message.strip_prefix("unknown field `")
        && let Some((field, _)) = rest.split_once('`')
    {
        let future_feature = is_future_feature_field(field);
        let field = escape_control(field, MAX_UNKNOWN_FIELD_CHARS);
        if future_feature {
            format!("field `{field}` is not supported by this build")
        } else {
            format!("unknown field `{field}`")
        }
    } else {
        redact_double_quoted(message)
    };

    escape_control(&normalized, MAX_DIAGNOSTIC_MESSAGE_CHARS)
}

fn redact_double_quoted(message: &str) -> String {
    let mut sanitized = String::with_capacity(message.len().min(512));
    let mut characters = message.chars();
    while let Some(character) = characters.next() {
        if character == '`' {
            // Backtick-quoted tokens are field names and expected literals,
            // not user values. Copy them as-is so diagnostics stay useful;
            // control characters are escaped afterwards.
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
    sanitized
}

fn escape_control(input: &str, max_chars: usize) -> String {
    let mut output = String::new();
    let mut count = 0;
    for character in input.chars() {
        if count >= max_chars {
            output.push_str("...");
            break;
        }

        let escaped = match character {
            '\n' => "\\n".to_owned(),
            '\r' => "\\r".to_owned(),
            '\t' => "\\t".to_owned(),
            character
                if character.is_control()
                    || matches!(
                        character,
                        '\u{200e}'
                            | '\u{200f}'
                            | '\u{202a}'..='\u{202e}'
                            | '\u{2066}'..='\u{2069}'
                    ) =>
            {
                format!("\\u{{{:x}}}", u32::from(character))
            }
            character => character.to_string(),
        };
        count += escaped.chars().count();
        output.push_str(&escaped);
    }
    output
}

fn is_future_feature_field(field: &str) -> bool {
    matches!(
        field,
        "acl"
            | "admin"
            | "auth"
            | "cache"
            | "control"
            | "logging"
            | "logs"
            | "metrics"
            | "parent"
            | "policy"
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
    let listener_ids = listeners.iter().map(Listener::id).collect::<Vec<&str>>();

    let access = validate_access(raw.access, &listener_ids)?;
    let dns = validate_dns(raw.dns)?;
    let transport = validate_transport(raw.transport, &limits)?;
    let (egress, routing) = validate_egress_routing(raw.egress, raw.routing, &listener_ids)?;

    Ok(Config {
        schema_version: SCHEMA_VERSION,
        runtime: RuntimeConfig {
            worker_threads: raw.runtime.worker_threads,
        },
        limits,
        listeners,
        access,
        dns,
        transport,
        egress,
        routing,
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

fn bounded_optional(
    path: &str,
    value: Option<i64>,
    minimum: i64,
    maximum: i64,
    default: i64,
) -> Result<i64, ConfigError> {
    bounded(path, value.unwrap_or(default), minimum, maximum)
}

fn validate_policy_id(value: &str, path: &str) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES {
        return Err(validation(path, "must be 1..=64 ASCII characters"));
    }
    if !value
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

fn validate_list_len<T>(items: &[T], path: &str) -> Result<(), ConfigError> {
    if items.len() > MAX_POLICY_LIST_ITEMS {
        return Err(validation(
            path,
            format!("at most {MAX_POLICY_LIST_ITEMS} entries are supported"),
        ));
    }
    Ok(())
}

fn parse_cidr(value: &str, path: &str) -> Result<IpNet, ConfigError> {
    let network = value
        .parse::<IpNet>()
        .map_err(|_| validation(path, "must be a valid CIDR"))?;
    if network.addr() != network.network() {
        return Err(validation(path, "CIDR must have zero host bits"));
    }

    // IPv4-mapped IPv6 destinations are normalized to IPv4 before policy
    // matching. Normalize the corresponding CIDR too; otherwise a deny rule
    // written in mapped form would be accepted but never match.
    if let IpNet::V6(network) = network
        && let Some(ipv4) = network.addr().to_ipv4_mapped()
    {
        if network.prefix_len() < 96 {
            return Err(validation(
                path,
                "IPv4-mapped IPv6 CIDR must have a prefix of at least 96; use the IPv4 form",
            ));
        }
        let prefix = network.prefix_len() - 96;
        let network = Ipv4Net::new(ipv4, prefix)
            .map_err(|_| validation(path, "CIDR must have zero host bits"))?;
        return Ok(IpNet::V4(network));
    }

    Ok(network)
}

fn parse_cidr_list(
    values: &[String],
    path: &str,
    allow_empty: bool,
) -> Result<Vec<IpNet>, ConfigError> {
    validate_list_len(values, path)?;
    if values.is_empty() && !allow_empty {
        return Err(validation(path, "must not be empty"));
    }

    let mut networks = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        networks.push(parse_cidr(value, &format!("{path}[{index}]"))?);
    }
    Ok(networks)
}

fn parse_domain_list(values: &[String], path: &str) -> Result<Vec<DomainName>, ConfigError> {
    validate_list_len(values, path)?;
    if values.is_empty() {
        return Err(validation(path, "must not be empty"));
    }

    let mut domains = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        domains.push(
            DomainName::parse(value).map_err(|_| {
                validation(format!("{path}[{index}]"), "must be a valid domain name")
            })?,
        );
    }
    Ok(domains)
}

fn parse_method_list(values: &[String], path: &str) -> Result<Vec<Method>, ConfigError> {
    validate_list_len(values, path)?;
    if values.is_empty() {
        return Err(validation(path, "must not be empty"));
    }

    let mut methods = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        methods.push(parse_method(value).map_err(|_| {
            validation(
                format!("{path}[{index}]"),
                "must be a valid HTTP method token",
            )
        })?);
    }
    Ok(methods)
}

fn parse_port_list(values: &[i64], path: &str) -> Result<Vec<u16>, ConfigError> {
    validate_list_len(values, path)?;
    if values.is_empty() {
        return Err(validation(path, "must not be empty"));
    }

    let mut ports = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        if !(1..=i64::from(u16::MAX)).contains(value) {
            return Err(validation(
                format!("{path}[{index}]"),
                "port must be in 1..=65535",
            ));
        }
        ports.push(*value as u16);
    }
    Ok(ports)
}

fn parse_listener_refs(
    values: &[String],
    path: &str,
    listener_ids: &[&str],
) -> Result<Vec<String>, ConfigError> {
    validate_list_len(values, path)?;
    if values.is_empty() {
        return Err(validation(path, "must not be empty"));
    }

    for (index, value) in values.iter().enumerate() {
        validate_policy_id(value, &format!("{path}[{index}]"))?;
        if !listener_ids.contains(&value.as_str()) {
            return Err(validation(
                format!("{path}[{index}]"),
                "unknown listener id",
            ));
        }
    }
    Ok(values.to_vec())
}

#[allow(clippy::too_many_arguments)]
fn validate_selectors(
    path: &str,
    listeners: Option<Vec<String>>,
    sources: Option<Vec<String>>,
    methods: Option<Vec<String>>,
    ports: Option<Vec<i64>>,
    host_exact: Option<Vec<String>>,
    host_suffix: Option<Vec<String>>,
    listener_ids: &[&str],
) -> Result<Selectors, ConfigError> {
    if host_exact.is_some() && host_suffix.is_some() {
        return Err(validation(
            format!("{path}.host_suffix"),
            "host_exact and host_suffix are mutually exclusive",
        ));
    }

    let listeners = listeners
        .map(|values| parse_listener_refs(&values, &format!("{path}.listeners"), listener_ids))
        .transpose()?;
    let sources = sources
        .map(|values| parse_cidr_list(&values, &format!("{path}.sources"), false))
        .transpose()?;
    let methods = methods
        .map(|values| parse_method_list(&values, &format!("{path}.methods")))
        .transpose()?;
    let ports = ports
        .map(|values| parse_port_list(&values, &format!("{path}.ports")))
        .transpose()?;
    let hosts = if let Some(values) = host_exact {
        HostSelectors::Exact(parse_domain_list(&values, &format!("{path}.host_exact"))?)
    } else if let Some(values) = host_suffix {
        HostSelectors::Suffix(parse_domain_list(&values, &format!("{path}.host_suffix"))?)
    } else {
        HostSelectors::Any
    };

    Ok(Selectors {
        listeners,
        sources,
        methods,
        ports,
        hosts,
    })
}

fn validate_action(value: &str, path: &str) -> Result<RuleAction, ConfigError> {
    match value {
        "allow" => Ok(RuleAction::Allow),
        "deny" => Ok(RuleAction::Deny),
        _ => Err(validation(path, "must be `allow` or `deny`")),
    }
}

fn validate_access(
    raw: Option<RawAccess>,
    listener_ids: &[&str],
) -> Result<AccessConfig, ConfigError> {
    let raw = raw.unwrap_or_default();
    let source_allow = parse_cidr_list(&raw.source_allow, "access.source_allow", true)?;
    let ip_default = match raw.ip_default.as_deref() {
        None | Some("public_only") => IpDefault::PublicOnly,
        Some("deny") => IpDefault::Deny,
        Some(_) => {
            return Err(validation(
                "access.ip_default",
                "must be `public_only` or `deny`",
            ));
        }
    };

    validate_list_len(&raw.rules, "access.rules")?;
    validate_list_len(&raw.ip_rules, "access.ip_rules")?;

    let mut rules = Vec::with_capacity(raw.rules.len());
    for (index, rule) in raw.rules.into_iter().enumerate() {
        let path = format!("access.rules[{index}]");
        validate_policy_id(&rule.id, &format!("{path}.id"))?;
        let action = validate_action(&rule.action, &format!("{path}.action"))?;
        let selectors = validate_selectors(
            &path,
            rule.listeners,
            rule.sources,
            rule.methods,
            rule.ports,
            rule.host_exact,
            rule.host_suffix,
            listener_ids,
        )?;
        rules.push(AccessRule {
            id: rule.id,
            action,
            selectors,
        });
    }
    for first in 0..rules.len() {
        for second in (first + 1)..rules.len() {
            if rules[first].id == rules[second].id {
                return Err(validation(
                    format!("access.rules[{second}].id"),
                    format!("access.rules[{second}].id duplicates access.rules[{first}].id"),
                ));
            }
        }
    }

    let mut ip_rules = Vec::with_capacity(raw.ip_rules.len());
    for (index, rule) in raw.ip_rules.into_iter().enumerate() {
        let path = format!("access.ip_rules[{index}]");
        validate_policy_id(&rule.id, &format!("{path}.id"))?;
        let action = validate_action(&rule.action, &format!("{path}.action"))?;
        if action == RuleAction::Deny && rule.allow_special {
            return Err(validation(
                format!("{path}.allow_special"),
                "only allow rules may set allow_special",
            ));
        }
        let networks = parse_cidr_list(&rule.networks, &format!("{path}.networks"), false)?;
        ip_rules.push(IpRule {
            id: rule.id,
            action,
            networks,
            allow_special: rule.allow_special,
        });
    }
    for first in 0..ip_rules.len() {
        for second in (first + 1)..ip_rules.len() {
            if ip_rules[first].id == ip_rules[second].id {
                return Err(validation(
                    format!("access.ip_rules[{second}].id"),
                    format!("access.ip_rules[{second}].id duplicates access.ip_rules[{first}].id"),
                ));
            }
        }
    }

    Ok(AccessConfig {
        source_allow,
        rules,
        ip_rules,
        ip_default,
    })
}

fn validate_dns(raw: Option<RawDns>) -> Result<DnsConfig, ConfigError> {
    let raw = raw.unwrap_or_default();
    let timeout = bounded_optional(
        "dns.timeout_ms",
        raw.timeout_ms,
        MIN_DNS_TIMEOUT_MS,
        MAX_DNS_TIMEOUT_MS,
        DEFAULT_DNS_TIMEOUT_MS,
    )?;
    let max_in_flight = bounded_optional(
        "dns.max_in_flight",
        raw.max_in_flight,
        MIN_DNS_MAX_IN_FLIGHT,
        MAX_DNS_MAX_IN_FLIGHT,
        DEFAULT_DNS_MAX_IN_FLIGHT,
    )?;
    let max_answers = bounded_optional(
        "dns.max_answers",
        raw.max_answers,
        MIN_DNS_MAX_ANSWERS,
        MAX_DNS_MAX_ANSWERS,
        DEFAULT_DNS_MAX_ANSWERS,
    )?;

    Ok(DnsConfig {
        timeout: Duration::from_millis(timeout as u64),
        max_in_flight: max_in_flight as usize,
        max_answers: max_answers as usize,
    })
}

fn validate_transport(
    raw: Option<RawTransport>,
    limits: &Limits,
) -> Result<TransportConfig, ConfigError> {
    let raw = raw.unwrap_or_default();
    let total_timeout = bounded_optional(
        "transport.total_timeout_ms",
        raw.total_timeout_ms,
        MIN_TOTAL_TIMEOUT_MS,
        MAX_TOTAL_TIMEOUT_MS,
        DEFAULT_TOTAL_TIMEOUT_MS,
    )?;
    let connect_timeout = bounded_optional(
        "transport.connect_timeout_ms",
        raw.connect_timeout_ms,
        MIN_CONNECT_TIMEOUT_MS,
        MAX_CONNECT_TIMEOUT_MS,
        DEFAULT_CONNECT_TIMEOUT_MS,
    )?;
    if connect_timeout > total_timeout {
        return Err(validation(
            "transport.connect_timeout_ms",
            "must not exceed transport.total_timeout_ms",
        ));
    }

    let max_connect_attempts = bounded_optional(
        "transport.max_connect_attempts",
        raw.max_connect_attempts,
        MIN_CONNECT_ATTEMPTS,
        MAX_CONNECT_ATTEMPTS,
        DEFAULT_CONNECT_ATTEMPTS,
    )?;
    let max_connections = i64::from(limits.max_connections());
    let max_connecting_limit = MAX_CONNECTING.min(max_connections);
    let default_connecting = DEFAULT_CONNECTING_CAP.min(max_connections);
    let max_connecting = bounded_optional(
        "transport.max_connecting",
        raw.max_connecting,
        MIN_CONNECTING,
        max_connecting_limit,
        default_connecting,
    )?;

    Ok(TransportConfig {
        total_timeout: Duration::from_millis(total_timeout as u64),
        connect_timeout: Duration::from_millis(connect_timeout as u64),
        max_connect_attempts: max_connect_attempts as usize,
        max_connecting: max_connecting as usize,
    })
}

fn validate_egress_routing(
    raw_egress: Option<Vec<RawEgress>>,
    raw_routing: Option<RawRouting>,
    listener_ids: &[&str],
) -> Result<(Vec<EgressProfile>, RoutingConfig), ConfigError> {
    let egress = if let Some(raw_egress) = raw_egress {
        if raw_egress.is_empty() {
            return Err(validation("egress", "must not be empty when present"));
        }
        validate_list_len(&raw_egress, "egress")?;

        let mut profiles = Vec::with_capacity(raw_egress.len());
        for (index, raw) in raw_egress.into_iter().enumerate() {
            let path = format!("egress[{index}]");
            validate_policy_id(&raw.id, &format!("{path}.id"))?;
            let mode = match raw.mode.as_str() {
                "system" => {
                    if raw.bind_ip.is_some() {
                        return Err(validation(
                            format!("{path}.bind_ip"),
                            "bind_ip is not allowed for system mode",
                        ));
                    }
                    EgressMode::System
                }
                "bind_ip" => {
                    let Some(bind_ip) = raw.bind_ip else {
                        return Err(validation(
                            format!("{path}.bind_ip"),
                            "bind_ip is required for bind_ip mode",
                        ));
                    };
                    let bind_ip = bind_ip.parse::<IpAddr>().map_err(|_| {
                        validation(
                            format!("{path}.bind_ip"),
                            "must be a specific outgoing IP address",
                        )
                    })?;
                    validate_bind_ip(bind_ip, &format!("{path}.bind_ip"))?;
                    EgressMode::BindIp(bind_ip)
                }
                _ => {
                    return Err(validation(
                        format!("{path}.mode"),
                        "must be `system` or `bind_ip`",
                    ));
                }
            };
            profiles.push(EgressProfile { id: raw.id, mode });
        }
        for first in 0..profiles.len() {
            for second in (first + 1)..profiles.len() {
                if profiles[first].id == profiles[second].id {
                    return Err(validation(
                        format!("egress[{second}].id"),
                        format!("egress[{second}].id duplicates egress[{first}].id"),
                    ));
                }
            }
        }
        profiles
    } else {
        vec![EgressProfile {
            id: "system".to_owned(),
            mode: EgressMode::System,
        }]
    };

    let egress_ids = egress.iter().map(EgressProfile::id).collect::<Vec<&str>>();
    let raw_routing = raw_routing.unwrap_or_default();
    let default_egress = raw_routing
        .default_egress
        .unwrap_or_else(|| "system".to_owned());
    validate_policy_id(&default_egress, "routing.default_egress")?;
    if !egress_ids.contains(&default_egress.as_str()) {
        return Err(validation("routing.default_egress", "unknown egress id"));
    }

    validate_list_len(&raw_routing.rules, "routing.rules")?;
    let mut rules = Vec::with_capacity(raw_routing.rules.len());
    for (index, raw) in raw_routing.rules.into_iter().enumerate() {
        let path = format!("routing.rules[{index}]");
        validate_policy_id(&raw.id, &format!("{path}.id"))?;
        validate_policy_id(&raw.egress_id, &format!("{path}.egress_id"))?;
        if !egress_ids.contains(&raw.egress_id.as_str()) {
            return Err(validation(format!("{path}.egress_id"), "unknown egress id"));
        }
        let selectors = validate_selectors(
            &path,
            raw.listeners,
            raw.sources,
            raw.methods,
            raw.ports,
            raw.host_exact,
            raw.host_suffix,
            listener_ids,
        )?;
        rules.push(RoutingRule {
            id: raw.id,
            egress_id: raw.egress_id,
            selectors,
        });
    }
    for first in 0..rules.len() {
        for second in (first + 1)..rules.len() {
            if rules[first].id == rules[second].id {
                return Err(validation(
                    format!("routing.rules[{second}].id"),
                    format!("routing.rules[{second}].id duplicates routing.rules[{first}].id"),
                ));
            }
        }
    }

    Ok((
        egress,
        RoutingConfig {
            default_egress,
            rules,
        },
    ))
}

fn validate_bind_ip(ip: IpAddr, path: &str) -> Result<(), ConfigError> {
    let invalid = match ip {
        IpAddr::V4(ipv4) => ipv4.is_unspecified() || ipv4.is_multicast() || ipv4.is_broadcast(),
        IpAddr::V6(ipv6) => {
            ipv6.is_unspecified() || ipv6.is_multicast() || ipv6.to_ipv4_mapped().is_some()
        }
    };
    if invalid {
        return Err(validation(
            path,
            "must be a specific unicast outgoing IP address",
        ));
    }
    Ok(())
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
                    format!("listeners[{second}].id duplicates listeners[{first}].id"),
                ));
            }

            if left.bind.port() != right.bind.port() || left.bind.is_ipv4() != right.bind.is_ipv4()
            {
                continue;
            }

            if left.bind == right.bind {
                return Err(validation(
                    format!("listeners[{second}].bind"),
                    format!("listeners[{second}].bind duplicates listeners[{first}].bind"),
                ));
            }

            if left.bind.ip().is_unspecified() || right.bind.ip().is_unspecified() {
                return Err(validation(
                    format!("listeners[{second}].bind"),
                    format!(
                        "wildcard conflict between listeners[{first}].bind and listeners[{second}].bind on the same IP family and port"
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
    #[serde(default)]
    access: Option<RawAccess>,
    #[serde(default)]
    dns: Option<RawDns>,
    #[serde(default)]
    transport: Option<RawTransport>,
    #[serde(default)]
    egress: Option<Vec<RawEgress>>,
    #[serde(default)]
    routing: Option<RawRouting>,
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

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawAccess {
    #[serde(default)]
    source_allow: Vec<String>,
    #[serde(default)]
    ip_default: Option<String>,
    #[serde(default)]
    rules: Vec<RawAccessRule>,
    #[serde(default)]
    ip_rules: Vec<RawIpRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccessRule {
    id: String,
    action: String,
    #[serde(default)]
    listeners: Option<Vec<String>>,
    #[serde(default)]
    sources: Option<Vec<String>>,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    ports: Option<Vec<i64>>,
    #[serde(default)]
    host_exact: Option<Vec<String>>,
    #[serde(default)]
    host_suffix: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIpRule {
    id: String,
    action: String,
    networks: Vec<String>,
    #[serde(default)]
    allow_special: bool,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawDns {
    #[serde(default)]
    timeout_ms: Option<i64>,
    #[serde(default)]
    max_in_flight: Option<i64>,
    #[serde(default)]
    max_answers: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawTransport {
    #[serde(default)]
    total_timeout_ms: Option<i64>,
    #[serde(default)]
    connect_timeout_ms: Option<i64>,
    #[serde(default)]
    max_connect_attempts: Option<i64>,
    #[serde(default)]
    max_connecting: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEgress {
    id: String,
    mode: String,
    #[serde(default)]
    bind_ip: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawRouting {
    #[serde(default)]
    default_egress: Option<String>,
    #[serde(default)]
    rules: Vec<RawRoutingRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoutingRule {
    id: String,
    egress_id: String,
    #[serde(default)]
    listeners: Option<Vec<String>>,
    #[serde(default)]
    sources: Option<Vec<String>>,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    ports: Option<Vec<i64>>,
    #[serde(default)]
    host_exact: Option<Vec<String>>,
    #[serde(default)]
    host_suffix: Option<Vec<String>>,
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
