//! Strict TOML configuration for Angara.
//!
//! The schema is intentionally closed: unknown keys are rejected rather than
//! ignored. Features that are not implemented in this milestone (cache, admin
//! API) therefore cannot be mistaken for supported settings.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http::Method;
use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};

use crate::auth::{self, AuthMode, UsersSnapshot};
use crate::parent::{
    ParentDefinition, ParentEndpoint, ParentTransport, PreparedParent, is_obvious_self_route,
    prepare as prepare_parent,
};
use crate::target::{DomainName, parse_method};
use crate::tls::{PreparedTls, prepare_listener};

/// Prepared TLS snapshots keyed by listener id.
type PreparedTlsMap = HashMap<String, Arc<PreparedTls>>;

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
const DEFAULT_HTTP_MAX_HEADERS: i64 = 100;
const DEFAULT_HTTP_RESPONSE_HEADER_TIMEOUT_MS: i64 = 30_000;
const DEFAULT_HTTP_POOL_IDLE_TIMEOUT_MS: i64 = 15_000;
const MAX_HTTP_MAX_HEADERS: i64 = 256;
const MIN_HTTP_RESPONSE_HEADER_TIMEOUT_MS: i64 = 100;
const MAX_HTTP_RESPONSE_HEADER_TIMEOUT_MS: i64 = 300_000;
const MAX_HTTP_POOL_IDLE: i64 = 1_024;
const MIN_HTTP_POOL_IDLE_TIMEOUT_MS: i64 = 100;
const MAX_HTTP_POOL_IDLE_TIMEOUT_MS: i64 = 300_000;
const MIN_CONNECT_HALF_CLOSE_TIMEOUT_MS: i64 = 100;
const MAX_CONNECT_HALF_CLOSE_TIMEOUT_MS: i64 = 300_000;
const DEFAULT_CONNECT_HALF_CLOSE_TIMEOUT_MS: i64 = 5_000;
const DEFAULT_CONNECT_ALLOWED_PORT: i64 = 443;
const MAX_CONNECT_ALLOWED_PORTS: usize = 64;
const MIN_AUTH_MAX_VERIFYING: i64 = 1;
const MAX_AUTH_MAX_VERIFYING: i64 = 16;
const DEFAULT_AUTH_MAX_VERIFYING: i64 = 2;
const MIN_AUTH_VERIFY_TIMEOUT_MS: i64 = 100;
const MAX_AUTH_VERIFY_TIMEOUT_MS: i64 = 30_000;
const DEFAULT_AUTH_VERIFY_TIMEOUT_MS: i64 = 2_000;
const MIN_TLS_MAX_HANDSHAKING: i64 = 1;
const MAX_TLS_MAX_HANDSHAKING: i64 = 256;
const DEFAULT_TLS_MAX_HANDSHAKING: i64 = 32;
const MIN_TLS_HANDSHAKE_TIMEOUT_MS: i64 = 100;
const MAX_TLS_HANDSHAKE_TIMEOUT_MS: i64 = 60_000;
const DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS: i64 = 5_000;
const MIN_RELOAD_TIMEOUT_MS: i64 = 100;
const MAX_RELOAD_TIMEOUT_MS: i64 = 60_000;
const DEFAULT_RELOAD_TIMEOUT_MS: i64 = 5_000;
const MIN_LOG_QUEUE_CAPACITY: i64 = 64;
const MAX_LOG_QUEUE_CAPACITY: i64 = 8_192;
const DEFAULT_LOG_QUEUE_CAPACITY: i64 = 1_024;
const MIN_METRICS_INTERVAL_MS: i64 = 1_000;
const MAX_METRICS_INTERVAL_MS: i64 = 600_000;
const DEFAULT_METRICS_INTERVAL_MS: i64 = 30_000;
/// Maximum size of the main TOML document.
pub const MAX_CONFIG_BYTES: u64 = 1_048_576;
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
    http: HttpConfig,
    connect: ConnectConfig,
    egress: Vec<EgressProfile>,
    parents: Vec<Arc<PreparedParent>>,
    routing: RoutingConfig,
    auth: Option<AuthConfig>,
    tls: TlsConfig,
    operations: OperationsConfig,
    observability: ObservabilityConfig,
    prepared_tls: HashMap<String, Arc<PreparedTls>>,
}

impl Config {
    /// Parses and validates a configuration from TOML text without a file
    /// context. Configurations that declare `[auth]` are rejected: their
    /// `users_file` may only be resolved relative to the main TOML directory.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        Self::parse_inner(input, None)
    }

    /// Parses a configuration and resolves a relative `users_file` against
    /// `base_dir`.
    pub fn parse_with_base_dir(input: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        Self::parse_inner(input, Some(base_dir))
    }

    /// Reads, parses and validates a configuration file.
    ///
    /// A relative `[auth].users_file` is resolved against the directory that
    /// contains this configuration file, not the process working directory.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = read_config_bytes(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let input = String::from_utf8(bytes).map_err(|_| ConfigError::Read {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "configuration is not UTF-8"),
        })?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new(""));
        Self::parse_inner(&input, Some(base_dir))
    }

    /// Loads a reload candidate, reusing prepared TLS state from `previous`.
    ///
    /// TLS certificate/key files are never opened here. A listener or static
    /// TLS change is rejected as restart-required before any file is read.
    pub fn load_for_reload(path: &Path, previous: &Self) -> Result<Self, ConfigError> {
        let bytes = read_config_bytes(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let input = String::from_utf8(bytes).map_err(|_| ConfigError::Read {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "configuration is not UTF-8"),
        })?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new(""));
        let deserializer = toml::de::Deserializer::parse(&input)
            .map_err(|error| ConfigError::from_toml(&input, None, error))?;
        let raw: RawConfig = serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let path = error.path().to_string();
            let path = (path != ".").then_some(path);
            ConfigError::from_toml(&input, path, error.into_inner())
        })?;
        let config = validate_with(raw, Some(base_dir), Some(previous))?;
        if let Some(path) = config.static_mismatch(previous) {
            return Err(ConfigError::RestartRequired {
                path: path.to_owned(),
                message: "restart-required field changed".to_owned(),
            });
        }
        Ok(config)
    }

    fn parse_inner(input: &str, base_dir: Option<&Path>) -> Result<Self, ConfigError> {
        if input.len() as u64 > MAX_CONFIG_BYTES {
            return Err(validation("config", "configuration exceeds 1 MiB"));
        }
        let deserializer = toml::de::Deserializer::parse(input)
            .map_err(|error| ConfigError::from_toml(input, None, error))?;
        let raw: RawConfig = serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let path = error.path().to_string();
            let path = (path != ".").then_some(path);
            ConfigError::from_toml(input, path, error.into_inner())
        })?;
        validate(raw, base_dir)
    }

    /// Returns the first restart-required field that differs. Hot-only
    /// fields (`access`, `routing`, users-file content, live caps and the
    /// listed timeouts) are intentionally absent.
    pub(crate) fn static_mismatch(&self, other: &Self) -> Option<&'static str> {
        if self.schema_version != other.schema_version {
            return Some("schema_version");
        }
        if self.runtime != other.runtime {
            return Some("runtime");
        }
        if !same_listeners(&self.listeners, &other.listeners) {
            return Some("listeners");
        }
        if self.tls != other.tls {
            return Some("tls");
        }
        if self.dns != other.dns {
            return Some("dns");
        }
        if !same_egress(&self.egress, &other.egress) {
            return Some("egress");
        }
        if !same_parents(&self.parents, &other.parents) {
            return Some("parents");
        }
        if self.operations != other.operations {
            return Some("operations");
        }
        if self.observability != other.observability {
            return Some("observability");
        }
        if self.http.max_headers() != other.http.max_headers() {
            return Some("http.max_headers");
        }
        if self.http.pool_max_idle() != other.http.pool_max_idle() {
            return Some("http.pool_max_idle");
        }
        if self.http.pool_max_idle_per_key() != other.http.pool_max_idle_per_key() {
            return Some("http.pool_max_idle_per_key");
        }
        if self.http.pool_idle_timeout() != other.http.pool_idle_timeout() {
            return Some("http.pool_idle_timeout_ms");
        }
        if self.transport.max_connecting() != other.transport.max_connecting() {
            return Some("transport.max_connecting");
        }
        if self.limits.max_header_bytes() != other.limits.max_header_bytes() {
            return Some("limits.max_header_bytes");
        }
        if self.limits.header_read_timeout() != other.limits.header_read_timeout() {
            return Some("limits.header_read_timeout_ms");
        }
        if self.limits.idle_timeout() != other.limits.idle_timeout() {
            return Some("limits.idle_timeout_ms");
        }
        match (self.auth.as_ref(), other.auth.as_ref()) {
            (None, None) => None,
            (Some(left), Some(right)) => {
                if left.max_verifying != right.max_verifying {
                    Some("auth.max_verifying")
                } else if left.verify_timeout != right.verify_timeout {
                    Some("auth.verify_timeout_ms")
                } else {
                    None
                }
            }
            _ => Some("auth"),
        }
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

    /// HTTP ingress, pool, and header limits.
    pub fn http(&self) -> &HttpConfig {
        &self.http
    }

    /// CONNECT tunnel policy and half-close drain.
    pub fn connect(&self) -> &ConnectConfig {
        &self.connect
    }

    /// Validated egress profiles.
    pub fn egress(&self) -> &[EgressProfile] {
        &self.egress
    }

    /// Egress routing rules.
    pub fn routing(&self) -> &RoutingConfig {
        &self.routing
    }

    /// Validated and prepared parent definitions in configuration order.
    pub fn parents(&self) -> &[Arc<PreparedParent>] {
        &self.parents
    }

    /// Finds a prepared parent by its stable identifier.
    pub fn parent(&self, id: &str) -> Option<&Arc<PreparedParent>> {
        self.parents.iter().find(|parent| parent.id() == id)
    }

    /// Prepared local users and verification limits, if `[auth]` is declared.
    pub fn auth(&self) -> Option<&AuthConfig> {
        self.auth.as_ref()
    }

    /// Finds a listener by its stable identifier.
    pub fn listener(&self, id: &str) -> Option<&Listener> {
        self.listeners.iter().find(|listener| listener.id == id)
    }

    /// Global TLS handshake limits.
    pub fn tls(&self) -> &TlsConfig {
        &self.tls
    }

    /// Reload/control limits.
    pub fn operations(&self) -> &OperationsConfig {
        &self.operations
    }

    /// Operational logging and metrics settings.
    pub fn observability(&self) -> &ObservabilityConfig {
        &self.observability
    }

    pub(crate) fn prepared_tls(&self, listener_id: &str) -> Option<&Arc<PreparedTls>> {
        self.prepared_tls.get(listener_id)
    }
}

fn same_listeners(left: &[Listener], right: &[Listener]) -> bool {
    left.len() == right.len()
        && left.iter().all(|item| {
            right
                .iter()
                .find(|candidate| candidate.id == item.id)
                .is_some_and(|candidate| candidate == item)
        })
}

fn same_egress(left: &[EgressProfile], right: &[EgressProfile]) -> bool {
    left.len() == right.len()
        && left.iter().all(|item| {
            right
                .iter()
                .find(|candidate| candidate.id == item.id)
                .is_some_and(|candidate| candidate == item)
        })
}

fn same_parents(left: &[Arc<PreparedParent>], right: &[Arc<PreparedParent>]) -> bool {
    left.len() == right.len()
        && left.iter().all(|item| {
            right
                .iter()
                .find(|candidate| candidate.id() == item.id())
                .is_some_and(|candidate| candidate.definition() == item.definition())
        })
}

/// Global TLS handshake limits shared by all HTTPS listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsConfig {
    max_handshaking: usize,
    handshake_timeout: Duration,
}

impl TlsConfig {
    /// Maximum simultaneous TLS handshakes for this server instance.
    pub fn max_handshaking(&self) -> usize {
        self.max_handshaking
    }

    /// Absolute handshake deadline measured from TCP accept.
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }
}

/// Reload/control timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationsConfig {
    reload_timeout: Duration,
}

impl OperationsConfig {
    /// Absolute preparation+publication deadline for one reload operation.
    pub fn reload_timeout(&self) -> Duration {
        self.reload_timeout
    }
}

/// Logging and metrics policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityConfig {
    log_level: LogLevel,
    log_queue_capacity: usize,
    metrics_enabled: bool,
    metrics_interval: Duration,
}

impl ObservabilityConfig {
    /// Configured log level.
    pub fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Maximum number of queued log records.
    pub fn log_queue_capacity(&self) -> usize {
        self.log_queue_capacity
    }

    /// Whether detailed metrics are collected and summarized.
    pub fn metrics_enabled(&self) -> bool {
        self.metrics_enabled
    }

    /// Periodic metrics summary interval.
    pub fn metrics_interval(&self) -> Duration {
        self.metrics_interval
    }
}

/// Finite JSON log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// No operational output worker.
    Off,
    /// Errors only.
    Error,
    /// Errors and warnings.
    Warn,
    /// All configured operational records.
    Info,
}

/// Prepared authentication settings and immutable users snapshot.
pub struct AuthConfig {
    max_verifying: usize,
    verify_timeout: Duration,
    users_file: PathBuf,
    snapshot: std::sync::Arc<UsersSnapshot>,
}

impl AuthConfig {
    /// Maximum simultaneous Argon2 verifications across all listeners.
    pub fn max_verifying(&self) -> usize {
        self.max_verifying
    }

    /// Time allowed to wait for one verification result.
    pub fn verify_timeout(&self) -> Duration {
        self.verify_timeout
    }

    pub(crate) fn snapshot(&self) -> &std::sync::Arc<UsersSnapshot> {
        &self.snapshot
    }

    /// Resolved users file path used by this snapshot.
    pub fn users_file(&self) -> &Path {
        &self.users_file
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field("max_verifying", &self.max_verifying)
            .field("verify_timeout", &self.verify_timeout)
            .field("users_file", &self.users_file)
            .field("snapshot", &self.snapshot)
            .finish()
    }
}

/// Runtime section.
#[derive(Debug, PartialEq, Eq)]
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
#[derive(Debug, PartialEq, Eq)]
pub struct Limits {
    max_connections: u32,
    max_client_connections: u32,
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

    /// Maximum accepted client sockets across all listeners.
    pub fn max_client_connections(&self) -> u32 {
        self.max_client_connections
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
    users: Option<Vec<String>>,
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

    /// Local usernames when the selector is present.
    pub fn users(&self) -> Option<&[String]> {
        self.users.as_deref()
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
    default_parent: Option<String>,
    rules: Vec<RoutingRule>,
}

impl RoutingConfig {
    /// Egress used when no rule matches.
    pub fn default_egress(&self) -> &str {
        &self.default_egress
    }

    /// Parent used when no rule matches and no explicit direct route is set.
    pub fn default_parent(&self) -> Option<&str> {
        self.default_parent.as_deref()
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
    next_hop: Option<String>,
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

    /// Explicit next hop, or `None` to inherit `default_parent`.
    ///
    /// `Some("direct")` means an explicit direct route. A parent ID selects
    /// that configured parent.
    pub fn next_hop(&self) -> Option<&str> {
        self.next_hop.as_deref()
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

/// HTTP ingress, response, and origin-pool limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpConfig {
    max_headers: usize,
    response_header_timeout: Duration,
    pool_max_idle: usize,
    pool_max_idle_per_key: usize,
    pool_idle_timeout: Duration,
}

impl HttpConfig {
    /// Maximum fields in each request/response/interim/trailer section.
    pub fn max_headers(&self) -> usize {
        self.max_headers
    }

    /// Time from starting upstream request headers to final response headers.
    pub fn response_header_timeout(&self) -> Duration {
        self.response_header_timeout
    }

    /// Maximum idle origin connections across the pool.
    pub fn pool_max_idle(&self) -> usize {
        self.pool_max_idle
    }

    /// Maximum idle origin connections per pool key.
    pub fn pool_max_idle_per_key(&self) -> usize {
        self.pool_max_idle_per_key
    }

    /// Maximum time a socket may remain idle in the pool.
    pub fn pool_idle_timeout(&self) -> Duration {
        self.pool_idle_timeout
    }
}

/// CONNECT tunnel policy.
#[derive(Debug, PartialEq, Eq)]
pub struct ConnectConfig {
    allowed_ports: Vec<u16>,
    half_close_timeout: Duration,
}

impl ConnectConfig {
    /// Ports that CONNECT may dial. An empty list denies every CONNECT.
    pub fn allowed_ports(&self) -> &[u16] {
        &self.allowed_ports
    }

    /// Whether the destination port is explicitly allowed.
    pub fn allows_port(&self, port: u16) -> bool {
        self.allowed_ports.binary_search(&port).is_ok()
    }

    /// Absolute drain deadline after the first tunnel read EOF.
    pub fn half_close_timeout(&self) -> Duration {
        self.half_close_timeout
    }
}

/// Resolved certificate and key paths for one HTTPS listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsListenerConfig {
    cert_chain_file: PathBuf,
    private_key_file: PathBuf,
}

impl TlsListenerConfig {
    /// Resolved certificate-chain path.
    pub fn cert_chain_file(&self) -> &Path {
        &self.cert_chain_file
    }

    /// Resolved private-key path.
    pub fn private_key_file(&self) -> &Path {
        &self.private_key_file
    }
}

/// One listener definition.
///
/// A listener is either plain HTTP or HTTPS. An IPv6 listener is IPv6-only;
/// the socket bind sets `IPV6_V6ONLY` so that `[::]` does not capture IPv4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    id: String,
    bind: SocketAddr,
    transport: Transport,
    auth: AuthMode,
    allow_insecure_basic: bool,
    tls: Option<TlsListenerConfig>,
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

    /// Required client authentication mode.
    pub fn auth(&self) -> AuthMode {
        self.auth
    }

    /// Explicit opt-in for plain Basic on a non-loopback bind.
    pub fn allow_insecure_basic(&self) -> bool {
        self.allow_insecure_basic
    }

    /// Prepared certificate/key paths for an HTTPS listener.
    pub fn tls(&self) -> Option<&TlsListenerConfig> {
        self.tls.as_ref()
    }
}

/// Listener transports supported by this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plain HTTP listener.
    Http,
    /// TLS listener carrying HTTP/1.1.
    Https,
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
    /// A valid change cannot be applied without restarting the process.
    RestartRequired {
        /// Dotted field path.
        path: String,
        /// Safe reason.
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
            Self::RestartRequired { path, message } => {
                let path = escape_control(path, MAX_DIAGNOSTIC_PATH_CHARS);
                write!(
                    formatter,
                    "configuration requires restart, field `{path}`: {message}"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Toml { .. } | Self::Validation { .. } | Self::RestartRequired { .. } => None,
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
pub(crate) fn sanitize_message(message: &str) -> String {
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

pub(crate) fn escape_control(input: &str, max_chars: usize) -> String {
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
            | "cache"
            | "control"
            | "logging"
            | "logs"
            | "metrics"
            | "parent"
            | "policy"
            | "telemetry"
            | "upstream"
            | "users"
    )
}

fn read_config_bytes(path: &Path) -> io::Result<Vec<u8>> {
    // Reject directories, devices and FIFOs before opening. O_NONBLOCK below
    // protects the race where the path is replaced, but a device open can
    // still have side effects.
    let initial = std::fs::metadata(path)?;
    if !initial.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration must be a regular file",
        ));
    }
    if initial.len() > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration exceeds 1 MiB",
        ));
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)?;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration must be a regular file",
        ));
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration exceeds 1 MiB",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "configuration has unsafe permissions",
            ));
        }
        #[cfg(target_os = "linux")]
        if metadata.uid() != 0 {
            let effective = effective_uid().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "cannot determine effective UID for configuration owner check",
                )
            })?;
            if metadata.uid() != effective {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "configuration owner must be the service UID or root",
                ));
            }
        }
    }
    let mut bytes = Vec::new();
    let read = file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    if read as u64 > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration exceeds 1 MiB",
        ));
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

fn validate(raw: RawConfig, base_dir: Option<&Path>) -> Result<Config, ConfigError> {
    validate_with(raw, base_dir, None)
}

fn validate_with(
    raw: RawConfig,
    base_dir: Option<&Path>,
    previous: Option<&Config>,
) -> Result<Config, ConfigError> {
    if raw.schema_version != i64::from(SCHEMA_VERSION) {
        return Err(validation(
            "schema_version",
            format!(
                "unsupported schema_version {}; this build supports {SCHEMA_VERSION}",
                raw.schema_version
            ),
        ));
    }
    if raw.auth.is_some() && base_dir.is_none() {
        return Err(validation(
            "auth",
            "requires a configuration file context; use Config::load or Config::parse_with_base_dir",
        ));
    }

    let limits = validate_limits(raw.limits)?;
    let tls = validate_tls(raw.tls)?;
    if let Some(previous) = previous
        && previous.tls != tls
    {
        return Err(ConfigError::RestartRequired {
            path: "tls".to_owned(),
            message: "TLS admission settings changed".to_owned(),
        });
    }
    let operations = validate_operations(raw.operations)?;
    let observability = validate_observability(raw.observability)?;
    let (listeners, prepared_tls) = validate_listeners(raw.listeners, base_dir, previous)?;
    let listener_ids = listeners.iter().map(Listener::id).collect::<Vec<&str>>();
    let auth = validate_auth(raw.auth, base_dir)?;
    for (index, listener) in listeners.iter().enumerate() {
        if listener.auth == AuthMode::Basic && auth.is_none() {
            return Err(validation(
                format!("listeners[{index}].auth"),
                "listener requests Basic authentication but the [auth] table is missing",
            ));
        }
        if listener.auth == AuthMode::Basic
            && listener.transport == Transport::Http
            && !listener.allow_insecure_basic
            && !is_loopback_ip(listener.bind.ip())
        {
            return Err(validation(
                format!("listeners[{index}].bind"),
                "plain Basic on a non-loopback bind requires listeners[].allow_insecure_basic = true",
            ));
        }
    }

    let access = validate_access(raw.access, &listener_ids)?;
    let dns = validate_dns(raw.dns)?;
    let transport = validate_transport(raw.transport, &limits)?;
    let http = validate_http(raw.http, &limits)?;
    let connect = validate_connect(raw.connect)?;
    let parents = validate_parents(raw.parents, base_dir, previous, &listeners)?;
    let parent_ids = parents
        .iter()
        .map(|parent| parent.id())
        .collect::<Vec<&str>>();
    let (egress, routing) =
        validate_egress_routing(raw.egress, raw.routing, &listener_ids, &parent_ids)?;

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
        http,
        connect,
        egress,
        parents,
        routing,
        auth,
        tls,
        operations,
        observability,
        prepared_tls,
    })
}

fn validate_auth(
    raw: Option<RawAuth>,
    base_dir: Option<&Path>,
) -> Result<Option<AuthConfig>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.users_file.is_empty() {
        return Err(validation("auth.users_file", "must not be empty"));
    }
    let max_verifying = bounded_optional(
        "auth.max_verifying",
        raw.max_verifying,
        MIN_AUTH_MAX_VERIFYING,
        MAX_AUTH_MAX_VERIFYING,
        DEFAULT_AUTH_MAX_VERIFYING,
    )?;
    let verify_timeout_ms = bounded_optional(
        "auth.verify_timeout_ms",
        raw.verify_timeout_ms,
        MIN_AUTH_VERIFY_TIMEOUT_MS,
        MAX_AUTH_VERIFY_TIMEOUT_MS,
        DEFAULT_AUTH_VERIFY_TIMEOUT_MS,
    )?;

    let declared = Path::new(&raw.users_file);
    let resolved = if declared.is_absolute() {
        declared.to_path_buf()
    } else {
        base_dir
            .ok_or_else(|| {
                validation(
                    "auth",
                    "requires a configuration file context to resolve users_file",
                )
            })?
            .join(declared)
    };
    let snapshot = UsersSnapshot::load(&resolved)
        .map_err(|error| validation("auth.users_file", error.to_string()))?;

    Ok(Some(AuthConfig {
        max_verifying: max_verifying as usize,
        verify_timeout: Duration::from_millis(verify_timeout_ms as u64),
        users_file: resolved,
        snapshot: std::sync::Arc::new(snapshot),
    }))
}

fn resolve_path(base_dir: &Path, declared: &str) -> PathBuf {
    let declared = Path::new(declared);
    if declared.is_absolute() {
        declared.to_path_buf()
    } else {
        base_dir.join(declared)
    }
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

fn validate_limits(raw: RawLimits) -> Result<Limits, ConfigError> {
    let max_connections = bounded(
        "limits.max_connections",
        raw.max_connections,
        MIN_MAX_CONNECTIONS,
        i64::from(MAX_CONNECTIONS_LIMIT),
    )?;
    let max_client_connections = bounded_optional(
        "limits.max_client_connections",
        raw.max_client_connections,
        MIN_MAX_CONNECTIONS,
        i64::from(MAX_CONNECTIONS_LIMIT),
        max_connections,
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
        max_client_connections: max_client_connections as u32,
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
    users: Option<Vec<String>>,
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
    let users = users
        .map(|values| parse_user_list(&values, &format!("{path}.users")))
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
        users,
    })
}

fn parse_user_list(values: &[String], path: &str) -> Result<Vec<String>, ConfigError> {
    validate_list_len(values, path)?;
    if values.is_empty() {
        return Err(validation(path, "must not be empty"));
    }
    for (index, value) in values.iter().enumerate() {
        if !auth::is_valid_username(value) {
            return Err(validation(
                format!("{path}[{index}]"),
                "must be a local username of 1..=64 ASCII characters",
            ));
        }
        if values[..index].contains(value) {
            return Err(validation(format!("{path}[{index}]"), "duplicate username"));
        }
    }
    Ok(values.to_vec())
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
            rule.users,
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

fn validate_http(raw: Option<RawHttp>, limits: &Limits) -> Result<HttpConfig, ConfigError> {
    let raw = raw.unwrap_or_default();
    let max_headers = bounded_optional(
        "http.max_headers",
        raw.max_headers,
        1,
        MAX_HTTP_MAX_HEADERS,
        DEFAULT_HTTP_MAX_HEADERS,
    )?;
    let response_header_timeout_ms = bounded_optional(
        "http.response_header_timeout_ms",
        raw.response_header_timeout_ms,
        MIN_HTTP_RESPONSE_HEADER_TIMEOUT_MS,
        MAX_HTTP_RESPONSE_HEADER_TIMEOUT_MS,
        DEFAULT_HTTP_RESPONSE_HEADER_TIMEOUT_MS,
    )?;

    let max_connections = i64::from(limits.max_connections());
    let max_pool_idle_limit = MAX_HTTP_POOL_IDLE.min(max_connections);
    let default_pool_idle = 16.min(max_connections);
    let pool_max_idle = bounded_optional(
        "http.pool_max_idle",
        raw.pool_max_idle,
        0,
        max_pool_idle_limit,
        default_pool_idle,
    )?;
    let pool_max_idle_per_key = match raw.pool_max_idle_per_key {
        None => {
            if pool_max_idle == 0 {
                0
            } else {
                2.min(pool_max_idle)
            }
        }
        Some(value) if pool_max_idle == 0 => {
            if value == 0 {
                0
            } else {
                return Err(validation(
                    "http.pool_max_idle_per_key",
                    "must be 0 when http.pool_max_idle is 0",
                ));
            }
        }
        Some(value) => bounded("http.pool_max_idle_per_key", value, 1, pool_max_idle)?,
    };
    let pool_idle_timeout_ms = bounded_optional(
        "http.pool_idle_timeout_ms",
        raw.pool_idle_timeout_ms,
        MIN_HTTP_POOL_IDLE_TIMEOUT_MS,
        MAX_HTTP_POOL_IDLE_TIMEOUT_MS,
        DEFAULT_HTTP_POOL_IDLE_TIMEOUT_MS,
    )?;

    Ok(HttpConfig {
        max_headers: max_headers as usize,
        response_header_timeout: Duration::from_millis(response_header_timeout_ms as u64),
        pool_max_idle: pool_max_idle as usize,
        pool_max_idle_per_key: pool_max_idle_per_key as usize,
        pool_idle_timeout: Duration::from_millis(pool_idle_timeout_ms as u64),
    })
}

fn validate_connect(raw: Option<RawConnect>) -> Result<ConnectConfig, ConfigError> {
    let raw = raw.unwrap_or_default();
    let mut allowed_ports = match raw.allowed_ports {
        Some(ports) => {
            if ports.len() > MAX_CONNECT_ALLOWED_PORTS {
                return Err(validation(
                    "connect.allowed_ports",
                    format!("at most {MAX_CONNECT_ALLOWED_PORTS} ports are supported"),
                ));
            }
            let mut parsed = Vec::with_capacity(ports.len());
            for (index, port) in ports.into_iter().enumerate() {
                let path = format!("connect.allowed_ports[{index}]");
                if !(1..=i64::from(u16::MAX)).contains(&port) {
                    return Err(validation(path, "must be an integer from 1 to 65535"));
                }
                let port = port as u16;
                if parsed.contains(&port) {
                    return Err(validation(path, "duplicate CONNECT port"));
                }
                parsed.push(port);
            }
            parsed
        }
        None => vec![DEFAULT_CONNECT_ALLOWED_PORT as u16],
    };
    allowed_ports.sort_unstable();

    let half_close_timeout_ms = bounded_optional(
        "connect.half_close_timeout_ms",
        raw.half_close_timeout_ms,
        MIN_CONNECT_HALF_CLOSE_TIMEOUT_MS,
        MAX_CONNECT_HALF_CLOSE_TIMEOUT_MS,
        DEFAULT_CONNECT_HALF_CLOSE_TIMEOUT_MS,
    )?;

    Ok(ConnectConfig {
        allowed_ports,
        half_close_timeout: Duration::from_millis(half_close_timeout_ms as u64),
    })
}

fn validate_parents(
    raw: Option<Vec<RawParent>>,
    base_dir: Option<&Path>,
    previous: Option<&Config>,
    listeners: &[Listener],
) -> Result<Vec<Arc<PreparedParent>>, ConfigError> {
    let raw = raw.unwrap_or_default();
    if raw.is_empty() {
        if previous.is_some_and(|config| !config.parents.is_empty()) {
            return Err(ConfigError::RestartRequired {
                path: "parents".to_owned(),
                message: "parent definitions changed".to_owned(),
            });
        }
        return Ok(Vec::new());
    }
    validate_list_len(&raw, "parents")?;

    let mut definitions = Vec::with_capacity(raw.len());
    for (index, raw) in raw.into_iter().enumerate() {
        let path = format!("parents[{index}]");
        validate_policy_id(&raw.id, &format!("{path}.id"))?;
        if raw.id == "direct" {
            return Err(validation(
                format!("{path}.id"),
                "`direct` is reserved for an explicit direct route",
            ));
        }
        let endpoint = ParentEndpoint::parse(&raw.endpoint)
            .map_err(|_| validation(format!("{path}.endpoint"), "must be host:port"))?;
        let transport = ParentTransport::parse(&raw.transport)
            .ok_or_else(|| validation(format!("{path}.transport"), "must be `http` or `https`"))?;
        let credentials_file = match raw.credentials_file {
            Some(value) => Some(resolve_parent_path(
                &path,
                "credentials_file",
                &value,
                base_dir,
            )?),
            None => None,
        };
        let ca_file = match raw.ca_file {
            Some(value) => Some(resolve_parent_path(&path, "ca_file", &value, base_dir)?),
            None => None,
        };
        if transport == ParentTransport::Http && ca_file.is_some() {
            return Err(validation(
                format!("{path}.ca_file"),
                "ca_file is only valid for https parents",
            ));
        }
        if is_obvious_self_route(&endpoint, listeners) {
            return Err(validation(
                format!("{path}.endpoint"),
                "parent endpoint points to an own listener",
            ));
        }
        definitions.push(ParentDefinition::new(
            raw.id,
            endpoint,
            transport,
            credentials_file,
            ca_file,
        ));
    }
    for first in 0..definitions.len() {
        for second in (first + 1)..definitions.len() {
            if definitions[first].id() == definitions[second].id() {
                return Err(validation(
                    format!("parents[{second}].id"),
                    format!("parents[{second}].id duplicates parents[{first}].id"),
                ));
            }
        }
    }

    if let Some(previous) = previous {
        let unchanged = previous.parents.len() == definitions.len()
            && definitions
                .iter()
                .zip(&previous.parents)
                .all(|(definition, prepared)| definition == prepared.definition());
        if !unchanged {
            return Err(ConfigError::RestartRequired {
                path: "parents".to_owned(),
                message: "parent definitions changed".to_owned(),
            });
        }
        return Ok(previous.parents.clone());
    }

    let mut parents = Vec::with_capacity(definitions.len());
    for (index, definition) in definitions.into_iter().enumerate() {
        let path = format!("parents[{index}]");
        match prepare_parent(definition, &path) {
            Ok(parent) => parents.push(parent),
            Err(error) => {
                return Err(validation(
                    error.field().to_owned(),
                    error.message().to_owned(),
                ));
            }
        }
    }
    Ok(parents)
}

fn resolve_parent_path(
    path: &str,
    field: &str,
    value: &str,
    base_dir: Option<&Path>,
) -> Result<PathBuf, ConfigError> {
    if value.is_empty() {
        return Err(validation(format!("{path}.{field}"), "must not be empty"));
    }
    let declared = Path::new(value);
    if declared.is_absolute() {
        return Ok(declared.to_path_buf());
    }
    let base_dir = base_dir.ok_or_else(|| {
        validation(
            format!("{path}.{field}"),
            "requires a configuration file context",
        )
    })?;
    Ok(resolve_path(base_dir, value))
}

fn validate_egress_routing(
    raw_egress: Option<Vec<RawEgress>>,
    raw_routing: Option<RawRouting>,
    listener_ids: &[&str],
    parent_ids: &[&str],
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

    let default_parent = match raw_routing.default_parent {
        Some(value) => {
            validate_policy_id(&value, "routing.default_parent")?;
            if value == "direct" {
                None
            } else {
                if !parent_ids.contains(&value.as_str()) {
                    return Err(validation("routing.default_parent", "unknown parent id"));
                }
                Some(value)
            }
        }
        None => None,
    };

    validate_list_len(&raw_routing.rules, "routing.rules")?;
    let mut rules = Vec::with_capacity(raw_routing.rules.len());
    for (index, raw) in raw_routing.rules.into_iter().enumerate() {
        let path = format!("routing.rules[{index}]");
        validate_policy_id(&raw.id, &format!("{path}.id"))?;
        validate_policy_id(&raw.egress_id, &format!("{path}.egress_id"))?;
        if !egress_ids.contains(&raw.egress_id.as_str()) {
            return Err(validation(format!("{path}.egress_id"), "unknown egress id"));
        }
        let next_hop = match raw.next_hop {
            Some(value) => {
                validate_policy_id(&value, &format!("{path}.next_hop"))?;
                if value == "direct" {
                    Some(value)
                } else {
                    if !parent_ids.contains(&value.as_str()) {
                        return Err(validation(format!("{path}.next_hop"), "unknown parent id"));
                    }
                    Some(value)
                }
            }
            None => None,
        };
        let selectors = validate_selectors(
            &path,
            raw.listeners,
            raw.sources,
            raw.methods,
            raw.ports,
            raw.users,
            raw.host_exact,
            raw.host_suffix,
            listener_ids,
        )?;
        rules.push(RoutingRule {
            id: raw.id,
            egress_id: raw.egress_id,
            next_hop,
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
            default_parent,
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

fn validate_tls(raw: Option<RawTls>) -> Result<TlsConfig, ConfigError> {
    let raw = raw.unwrap_or_default();
    let max_handshaking = bounded_optional(
        "tls.max_handshaking",
        raw.max_handshaking,
        MIN_TLS_MAX_HANDSHAKING,
        MAX_TLS_MAX_HANDSHAKING,
        DEFAULT_TLS_MAX_HANDSHAKING,
    )?;
    let handshake_timeout_ms = bounded_optional(
        "tls.handshake_timeout_ms",
        raw.handshake_timeout_ms,
        MIN_TLS_HANDSHAKE_TIMEOUT_MS,
        MAX_TLS_HANDSHAKE_TIMEOUT_MS,
        DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
    )?;
    Ok(TlsConfig {
        max_handshaking: max_handshaking as usize,
        handshake_timeout: Duration::from_millis(handshake_timeout_ms as u64),
    })
}

fn validate_operations(raw: Option<RawOperations>) -> Result<OperationsConfig, ConfigError> {
    let raw = raw.unwrap_or_default();
    let reload_timeout_ms = bounded_optional(
        "operations.reload_timeout_ms",
        raw.reload_timeout_ms,
        MIN_RELOAD_TIMEOUT_MS,
        MAX_RELOAD_TIMEOUT_MS,
        DEFAULT_RELOAD_TIMEOUT_MS,
    )?;
    Ok(OperationsConfig {
        reload_timeout: Duration::from_millis(reload_timeout_ms as u64),
    })
}

fn validate_observability(
    raw: Option<RawObservability>,
) -> Result<ObservabilityConfig, ConfigError> {
    let raw = raw.unwrap_or_default();
    let log_level = match raw.log_level.as_deref() {
        None | Some("info") => LogLevel::Info,
        Some("off") => LogLevel::Off,
        Some("error") => LogLevel::Error,
        Some("warn") => LogLevel::Warn,
        Some(_) => {
            return Err(validation(
                "observability.log_level",
                "must be `off`, `error`, `warn` or `info`",
            ));
        }
    };
    let log_queue_capacity = bounded_optional(
        "observability.log_queue_capacity",
        raw.log_queue_capacity,
        MIN_LOG_QUEUE_CAPACITY,
        MAX_LOG_QUEUE_CAPACITY,
        DEFAULT_LOG_QUEUE_CAPACITY,
    )?;
    let metrics_interval_ms = bounded_optional(
        "observability.metrics_interval_ms",
        raw.metrics_interval_ms,
        MIN_METRICS_INTERVAL_MS,
        MAX_METRICS_INTERVAL_MS,
        DEFAULT_METRICS_INTERVAL_MS,
    )?;
    Ok(ObservabilityConfig {
        log_level,
        log_queue_capacity: log_queue_capacity as usize,
        metrics_enabled: raw.metrics_enabled.unwrap_or(true),
        metrics_interval: Duration::from_millis(metrics_interval_ms as u64),
    })
}

fn validate_listeners(
    raw: Vec<RawListener>,
    base_dir: Option<&Path>,
    previous: Option<&Config>,
) -> Result<(Vec<Listener>, PreparedTlsMap), ConfigError> {
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
    let mut prepared_tls = HashMap::new();
    for (index, listener) in raw.into_iter().enumerate() {
        validate_listener_id(&listener.id, index)?;
        validate_listener_address(listener.bind.0, index)?;
        let auth = listener.auth.unwrap_or(AuthMode::None);
        if listener.allow_insecure_basic && auth != AuthMode::Basic {
            return Err(validation(
                format!("listeners[{index}].allow_insecure_basic"),
                "is only allowed with auth = \"basic\"",
            ));
        }
        if listener.transport == Transport::Https && listener.allow_insecure_basic {
            return Err(validation(
                format!("listeners[{index}].allow_insecure_basic"),
                "is meaningless for an HTTPS listener",
            ));
        }
        let tls = match (listener.transport, listener.tls) {
            (Transport::Http, None) => None,
            (Transport::Http, Some(_)) => {
                return Err(validation(
                    format!("listeners[{index}].tls"),
                    "is only allowed for transport = \"https\"",
                ));
            }
            (Transport::Https, None) => {
                return Err(validation(
                    format!("listeners[{index}].tls"),
                    "is required for transport = \"https\"",
                ));
            }
            (Transport::Https, Some(tls)) => {
                if tls.cert_chain_file.is_empty() || tls.private_key_file.is_empty() {
                    return Err(validation(
                        format!("listeners[{index}].tls"),
                        "certificate and private-key paths must not be empty",
                    ));
                }
                let Some(base_dir) = base_dir else {
                    return Err(validation(
                        format!("listeners[{index}].tls"),
                        "requires a configuration file context; use Config::load or Config::parse_with_base_dir",
                    ));
                };
                let cert_chain_file = resolve_path(base_dir, &tls.cert_chain_file);
                let private_key_file = resolve_path(base_dir, &tls.private_key_file);
                let listener_tls = TlsListenerConfig {
                    cert_chain_file,
                    private_key_file,
                };
                if let Some(previous) = previous {
                    let previous_listener = previous.listener(&listener.id).ok_or_else(|| {
                        ConfigError::RestartRequired {
                            path: format!("listeners[{index}].id"),
                            message: "adding an HTTPS listener requires restart".to_owned(),
                        }
                    })?;
                    if previous_listener.transport() != Transport::Https
                        || previous_listener.bind() != listener.bind.0
                        || previous_listener.auth() != auth
                        || previous_listener.allow_insecure_basic() != listener.allow_insecure_basic
                        || previous_listener.tls() != Some(&listener_tls)
                    {
                        return Err(ConfigError::RestartRequired {
                            path: format!("listeners[{index}]"),
                            message: "listener or TLS path changed".to_owned(),
                        });
                    }
                    let prepared =
                        previous
                            .prepared_tls(&listener.id)
                            .cloned()
                            .ok_or_else(|| ConfigError::RestartRequired {
                                path: format!("listeners[{index}].tls"),
                                message: "prepared TLS state is unavailable".to_owned(),
                            })?;
                    prepared_tls.insert(listener.id.clone(), prepared);
                    Some(listener_tls)
                } else {
                    let prepared = prepare_listener(
                        &listener_tls.cert_chain_file,
                        &listener_tls.private_key_file,
                    )
                    .map_err(|error| {
                        validation(
                            format!("listeners[{index}].tls.{}", error.field()),
                            error.to_string(),
                        )
                    })?;
                    prepared_tls.insert(listener.id.clone(), Arc::new(prepared));
                    Some(listener_tls)
                }
            }
        };
        listeners.push(Listener {
            id: listener.id,
            bind: listener.bind.0,
            transport: listener.transport,
            auth,
            allow_insecure_basic: listener.allow_insecure_basic,
            tls,
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

    Ok((listeners, prepared_tls))
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
    http: Option<RawHttp>,
    #[serde(default)]
    connect: Option<RawConnect>,
    #[serde(default)]
    egress: Option<Vec<RawEgress>>,
    #[serde(default)]
    parents: Option<Vec<RawParent>>,
    #[serde(default)]
    routing: Option<RawRouting>,
    #[serde(default)]
    auth: Option<RawAuth>,
    #[serde(default)]
    tls: Option<RawTls>,
    #[serde(default)]
    operations: Option<RawOperations>,
    #[serde(default)]
    observability: Option<RawObservability>,
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
    #[serde(default)]
    max_client_connections: Option<i64>,
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
    #[serde(default)]
    auth: Option<AuthMode>,
    #[serde(default)]
    allow_insecure_basic: bool,
    #[serde(default)]
    tls: Option<RawListenerTls>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawTls {
    #[serde(default)]
    max_handshaking: Option<i64>,
    #[serde(default)]
    handshake_timeout_ms: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawOperations {
    #[serde(default)]
    reload_timeout_ms: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawObservability {
    #[serde(default)]
    log_level: Option<String>,
    #[serde(default)]
    log_queue_capacity: Option<i64>,
    #[serde(default)]
    metrics_enabled: Option<bool>,
    #[serde(default)]
    metrics_interval_ms: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListenerTls {
    cert_chain_file: String,
    private_key_file: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawAuth {
    users_file: String,
    #[serde(default)]
    max_verifying: Option<i64>,
    #[serde(default)]
    verify_timeout_ms: Option<i64>,
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
    users: Option<Vec<String>>,
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

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawHttp {
    #[serde(default)]
    max_headers: Option<i64>,
    #[serde(default)]
    response_header_timeout_ms: Option<i64>,
    #[serde(default)]
    pool_max_idle: Option<i64>,
    #[serde(default)]
    pool_max_idle_per_key: Option<i64>,
    #[serde(default)]
    pool_idle_timeout_ms: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawConnect {
    #[serde(default)]
    allowed_ports: Option<Vec<i64>>,
    #[serde(default)]
    half_close_timeout_ms: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEgress {
    id: String,
    mode: String,
    #[serde(default)]
    bind_ip: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawParent {
    id: String,
    endpoint: String,
    transport: String,
    #[serde(default)]
    credentials_file: Option<String>,
    #[serde(default)]
    ca_file: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawRouting {
    #[serde(default)]
    default_egress: Option<String>,
    #[serde(default)]
    default_parent: Option<String>,
    #[serde(default)]
    rules: Vec<RawRoutingRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoutingRule {
    id: String,
    egress_id: String,
    #[serde(default)]
    next_hop: Option<String>,
    #[serde(default)]
    listeners: Option<Vec<String>>,
    #[serde(default)]
    sources: Option<Vec<String>>,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    ports: Option<Vec<i64>>,
    #[serde(default)]
    users: Option<Vec<String>>,
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

impl<'de> Deserialize<'de> for AuthMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "none" => Ok(Self::None),
            "basic" => Ok(Self::Basic),
            _ => Err(de::Error::custom("must be `none` or `basic`")),
        }
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
            "https" => Ok(Self::Https),
            _ => Err(de::Error::custom("must be `http` or `https`")),
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

#[cfg(test)]
mod tests {
    use super::is_loopback_ip;

    #[test]
    fn loopback_detection_normalizes_ipv4_mapped_addresses() {
        assert!(is_loopback_ip("127.0.0.1".parse().expect("v4")));
        assert!(is_loopback_ip("::1".parse().expect("v6")));
        assert!(is_loopback_ip("::ffff:127.0.0.1".parse().expect("mapped")));
        assert!(!is_loopback_ip("192.0.2.10".parse().expect("public v4")));
        assert!(!is_loopback_ip(
            "::ffff:192.0.2.10".parse().expect("mapped public")
        ));
        assert!(!is_loopback_ip("2001:db8::1".parse().expect("public v6")));
    }
}
