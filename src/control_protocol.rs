//! Versioned local control protocol shared by the proxy read server, the
//! privileged writer and the TUI client.
//!
//! The wire format is one JSON object per line. It deliberately contains no
//! generic shell, file-write or signal operation.

use std::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::connections::ConnectionRow;
pub use crate::control::{AccessSummary, BlockStatus, StatusSnapshot, UserStatus};

/// Published protocol version.
pub const API_VERSION: u32 = 1;
/// Maximum request or response line, including the trailing newline.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Maximum page size for every list operation.
pub const MAX_PAGE: usize = 100;
/// Default page size.
pub const DEFAULT_PAGE: usize = 50;
/// Maximum simultaneous control clients accepted by one server.
pub const MAX_CLIENTS: usize = 16;
/// Maximum simultaneous event subscribers.
pub const MAX_SUBSCRIBERS: usize = 8;
/// Bounded event history retained for cursor catch-up.
pub const EVENT_RING: usize = 512;
/// Per-subscriber queue before the connection is considered lagged.
pub const SUBSCRIBER_QUEUE: usize = 64;
/// Read/status request deadline.
pub const READ_TIMEOUT_SECS: u64 = 5;
/// Maximum time a control client may hold a slot without sending a request.
pub const CLIENT_IDLE_TIMEOUT_SECS: u64 = 30;
/// Mutating request deadline, including Argon2 hashing and fsync.
pub const WRITE_TIMEOUT_SECS: u64 = 60;

/// One control operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Op {
    /// Protocol and server identity.
    #[serde(rename = "hello")]
    Hello,
    /// Composite generation/version snapshot.
    #[serde(rename = "snapshot")]
    Snapshot,
    /// Process/resources status.
    #[serde(rename = "status")]
    Status,
    /// Active connections page.
    #[serde(rename = "connections")]
    Connections,
    /// Users page.
    #[serde(rename = "users")]
    Users,
    /// Active blocks page.
    #[serde(rename = "blocks")]
    Blocks,
    /// Access summary or ordered rule page.
    #[serde(rename = "access")]
    Access,
    /// Disk/active configuration state.
    #[serde(rename = "config")]
    Config,
    /// Event history after a cursor.
    #[serde(rename = "events")]
    Events,
    /// Follow events after a cursor.
    #[serde(rename = "subscribe")]
    Subscribe,
    /// Add one local user.
    #[serde(rename = "user.add")]
    UserAdd,
    /// Replace one user's password hash.
    #[serde(rename = "user.password")]
    UserPassword,
    /// Set a permanent or temporary block.
    #[serde(rename = "block.set")]
    BlockSet,
    /// Clear a permanent or temporary block.
    #[serde(rename = "block.clear")]
    BlockClear,
    /// Validate one ACL edit without writing.
    #[serde(rename = "access.preview")]
    AccessPreview,
    /// Apply one ACL edit.
    #[serde(rename = "access.apply")]
    AccessApply,
    /// Validate the configuration currently on disk.
    #[serde(rename = "config.validate")]
    ConfigValidate,
    /// Reload the configuration on disk with an expected generation.
    #[serde(rename = "config.apply")]
    ConfigApply,
    /// Internal writer-to-proxy reload request.
    #[serde(rename = "reload")]
    Reload,
}

impl Op {
    /// Whether the operation changes persistent or active state.
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::UserAdd
                | Self::UserPassword
                | Self::BlockSet
                | Self::BlockClear
                | Self::AccessApply
                | Self::ConfigValidate
                | Self::ConfigApply
                | Self::Reload
        )
    }

    /// Whether this operation is valid on the public writer socket.
    pub fn is_public(self) -> bool {
        self != Self::Reload
    }
}

/// One request line. Fields are optional and checked per operation so an
/// unknown combination is rejected instead of silently ignored.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Protocol version.
    pub v: u32,
    /// Client-chosen request identifier echoed in the response.
    pub id: u64,
    /// Operation.
    pub op: Op,
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default)]
    pub expected_version: Option<String>,
    #[serde(default)]
    pub expected_generation: Option<u64>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<PasswordInput>,
    #[serde(default)]
    pub password_confirm: Option<PasswordInput>,
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub permanent: Option<bool>,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub change: Option<Value>,
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("v", &self.v)
            .field("id", &self.id)
            .field("op", &self.op)
            .field("cursor", &self.cursor)
            .field("offset", &self.offset)
            .field("limit", &self.limit)
            .field("section", &self.section)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("until", &self.until)
            .field("permanent", &self.permanent)
            .finish_non_exhaustive()
    }
}

impl Request {
    /// Clears secret buffers as soon as the handler is done.
    pub fn zeroize_secrets(&mut self) {
        self.password = None;
        self.password_confirm = None;
    }

    /// Read a password without copying it into a plain `String`.
    pub fn take_password(&mut self) -> Option<Zeroizing<String>> {
        self.password.take().map(|field| field.0)
    }

    /// Read the confirmation field.
    pub fn take_password_confirm(&mut self) -> Option<Zeroizing<String>> {
        self.password_confirm.take().map(|field| field.0)
    }
}

/// Password field that never appears in `Debug` and zeroizes on drop.
pub struct PasswordInput(Zeroizing<String>);

impl PasswordInput {
    /// Borrow the secret.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for PasswordInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordInput(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for PasswordInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PasswordVisitor;

        impl<'de> Visitor<'de> for PasswordVisitor {
            type Value = PasswordInput;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a password string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > crate::auth::MAX_PASSWORD_BYTES * 2 {
                    return Err(E::custom("password field is too long"));
                }
                Ok(PasswordInput(Zeroizing::new(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > crate::auth::MAX_PASSWORD_BYTES * 2 {
                    return Err(E::custom("password field is too long"));
                }
                Ok(PasswordInput(Zeroizing::new(value)))
            }
        }

        deserializer.deserialize_str(PasswordVisitor)
    }
}

/// Stable error code. Messages are safe summaries; fields carry paths only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed or unsupported request fields.
    InvalidRequest,
    /// Protocol version is not supported.
    UnsupportedVersion,
    /// The caller may not perform this operation.
    Unauthorized,
    /// Object does not exist.
    NotFound,
    /// Expected file version or generation is stale.
    Conflict,
    /// Candidate failed validation.
    InvalidCandidate,
    /// Candidate needs a restart.
    RestartRequired,
    /// Another expensive operation is running.
    Busy,
    /// The operation deadline elapsed.
    Timeout,
    /// The proxy or writer is unavailable.
    Unavailable,
    /// Request or page exceeds a limit.
    TooLarge,
    /// Shutdown has begun.
    ShuttingDown,
    /// Unknown operation outcome after a possible write.
    UnknownResult,
    /// Event cursor is older than the retained ring.
    ResyncRequired,
    /// Local failure.
    Internal,
}

/// One safe error object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable code.
    pub code: ErrorCode,
    /// Short safe message.
    pub message: String,
    /// Safe field paths, at most 16.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// Current content version when a conflict was detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
    /// Current active generation when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_generation: Option<u64>,
    /// Whether a write had already reached disk before the failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved: Option<bool>,
}

impl ApiError {
    /// Builds one bounded error.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into().chars().take(200).collect(),
            fields: Vec::new(),
            current_version: None,
            current_generation: None,
            saved: None,
        }
    }

    /// Adds safe field paths.
    pub fn with_fields(mut self, fields: Vec<String>) -> Self {
        self.fields = fields
            .into_iter()
            .take(16)
            .map(|field| field.chars().take(160).collect())
            .collect();
        self
    }
}

/// One response line.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    /// Protocol version.
    pub v: u32,
    /// Request identifier.
    pub id: u64,
    /// Whether `result` is present.
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
    /// Writer event cursor at response time.
    pub event_cursor: u64,
}

impl Response {
    /// Successful response.
    pub fn ok(id: u64, event_cursor: u64, result: impl Serialize) -> Self {
        Self {
            v: API_VERSION,
            id,
            ok: true,
            result: serde_json::to_value(result).ok(),
            error: None,
            event_cursor,
        }
    }

    /// Error response.
    pub fn error(id: u64, event_cursor: u64, error: ApiError) -> Self {
        Self {
            v: API_VERSION,
            id,
            ok: false,
            result: None,
            error: Some(error),
            event_cursor,
        }
    }
}

/// One event kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Disk configuration changed.
    ConfigSaved,
    /// The proxy published a generation.
    ConfigApplied,
    /// Reload or validation was rejected.
    ConfigRejected,
    /// Users file changed.
    UsersSaved,
    /// A temporary block expired according to the server clock.
    BlockExpired,
    /// A client must fetch a new snapshot.
    Resync,
}

/// Bounded safe event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic event cursor.
    pub cursor: u64,
    /// Event category.
    pub kind: EventKind,
    /// RFC 3339 UTC time.
    pub at: String,
    /// Active generation observed when the event was produced.
    pub generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One subscription line after the initial snapshot response.
#[derive(Debug, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Protocol version.
    pub v: u32,
    /// Event, or `None` for a resync notice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<Event>,
    /// Latest cursor for a resync notice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resync_cursor: Option<u64>,
}

/// Composite proxy snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxySnapshot {
    /// Stable protocol identity.
    pub api_version: u32,
    /// Server-created instance identifier.
    pub instance_id: String,
    /// Active policy generation.
    pub generation: u64,
    /// Exact configuration version.
    pub config_version: String,
    /// Exact users-file version, when `[auth]` is configured.
    pub users_version: Option<String>,
    /// Main configuration path.
    pub config_path: String,
    /// Resolved users-file path.
    pub users_path: Option<String>,
    /// Process status.
    pub status: StatusSnapshot,
    /// Safe access counts and source allow-list.
    pub access: AccessSummary,
    /// Default routing binding.
    pub routing: RoutingSummary,
    /// Selected bounded counters and error totals.
    pub counters: CounterSummary,
    /// Number of configured users.
    pub user_count: usize,
    /// Number of active blocks at the server clock.
    pub block_count: usize,
    /// Tracked connections.
    pub connection_count: usize,
    /// Published limits for clients.
    pub limits: ApiLimits,
}

/// Selected counters exposed to the overview screen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterSummary {
    pub tcp_accepted: u64,
    pub tcp_rejected: u64,
    pub http_completed: u64,
    pub http_cancelled: u64,
    pub http_4xx: u64,
    pub http_5xx: u64,
    pub connect_completed: u64,
    pub connect_error: u64,
    pub auth_ok: u64,
    pub auth_invalid: u64,
    pub dns_error: u64,
    pub reload_applied: u64,
    pub reload_rejected: u64,
    pub cache_hit: u64,
    pub cache_miss: u64,
    pub log_dropped: u64,
}

/// Safe routing summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingSummary {
    /// Default egress profile.
    pub default_egress: String,
    /// Default parent, when configured.
    pub default_parent: Option<String>,
    /// Number of ordered routing rules.
    pub rule_count: usize,
}

/// Published protocol limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiLimits {
    /// Maximum request line.
    pub max_line_bytes: usize,
    /// Maximum page size.
    pub max_page: usize,
    /// Maximum clients.
    pub max_clients: usize,
    /// Maximum subscribers.
    pub max_subscribers: usize,
    /// Retained events.
    pub event_ring: usize,
    /// Per-subscriber queue.
    pub subscriber_queue: usize,
}

impl Default for ApiLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: MAX_LINE_BYTES,
            max_page: MAX_PAGE,
            max_clients: MAX_CLIENTS,
            max_subscribers: MAX_SUBSCRIBERS,
            event_ring: EVENT_RING,
            subscriber_queue: SUBSCRIBER_QUEUE,
        }
    }
}

/// Writer-level snapshot with the current event cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(flatten)]
    pub proxy: ProxySnapshot,
    /// Event cursor at snapshot time.
    pub event_cursor: u64,
    /// Whether this connection may perform writes.
    pub writable: bool,
}

/// One page of users.
#[derive(Debug, Serialize, Deserialize)]
pub struct UsersPage {
    pub users: Vec<UserStatus>,
    pub offset: usize,
    pub total: usize,
}

/// One page of active blocks.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlocksPage {
    pub blocks: Vec<BlockStatus>,
    pub offset: usize,
    pub total: usize,
}

/// One page of tracked connections.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionsPage {
    pub connections: Vec<ConnectionRow>,
    pub offset: usize,
    pub total: usize,
}

/// One page of events.
#[derive(Debug, Serialize, Deserialize)]
pub struct EventsPage {
    pub events: Vec<Event>,
    /// Cursor to use for the next call.
    pub next_cursor: u64,
    /// Whether the requested cursor was older than the retained ring.
    pub resync_required: bool,
}

/// Safe configuration state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigState {
    pub config_path: String,
    pub users_path: Option<String>,
    pub active_config_version: String,
    pub disk_config_version: Option<String>,
    pub active_users_version: Option<String>,
    pub disk_users_version: Option<String>,
    pub generation: u64,
    pub last_reload: Option<crate::control::ReloadOutcome>,
    pub writable: bool,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Access view selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessSection {
    Summary,
    Source,
    Rules,
    IpRules,
}

/// One request rule projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRuleView {
    pub id: String,
    pub action: String,
    pub listeners: Option<Vec<String>>,
    pub sources: Option<Vec<String>>,
    pub methods: Option<Vec<String>>,
    pub ports: Option<Vec<u16>>,
    pub users: Option<Vec<String>>,
    pub host_exact: Option<Vec<String>>,
    pub host_suffix: Option<Vec<String>>,
}

/// One destination-IP rule projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpRuleView {
    pub id: String,
    pub action: String,
    pub networks: Vec<String>,
    pub allow_special: bool,
}

/// One access page.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessPage {
    pub section: AccessSection,
    pub source_allow: Vec<String>,
    pub rules: Vec<AccessRuleView>,
    pub ip_rules: Vec<IpRuleView>,
    pub ip_default: String,
    pub offset: usize,
    pub total: usize,
}

/// Safe outcome of a write or reload operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteOutcome {
    /// `checked`, `saved`, `applied`, `rejected`, `restart_required`,
    /// `conflict` or `unknown`.
    pub state: String,
    /// Whether the file was replaced.
    pub saved: bool,
    /// New file version after a successful save.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Active generation after the operation.
    pub generation: u64,
    /// Whether the active root matches the saved file.
    pub applied: bool,
    /// Short safe detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One request rule draft used by preview/apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRuleDraft {
    pub id: String,
    pub action: String,
    #[serde(default)]
    pub listeners: Option<Vec<String>>,
    #[serde(default)]
    pub sources: Option<Vec<String>>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    #[serde(default)]
    pub users: Option<Vec<String>>,
    #[serde(default)]
    pub host_exact: Option<Vec<String>>,
    #[serde(default)]
    pub host_suffix: Option<Vec<String>>,
}

/// One destination-IP rule draft.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpRuleDraft {
    pub id: String,
    pub action: String,
    pub networks: Vec<String>,
    #[serde(default)]
    pub allow_special: bool,
}

/// One typed ACL edit. Indices are zero-based positions in the current array.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccessChange {
    /// Add one source CIDR at an optional position.
    SourceAdd {
        value: String,
        #[serde(default)]
        index: Option<usize>,
    },
    /// Remove one source CIDR.
    SourceRemove { index: usize },
    /// Replace the whole source allow-list.
    SourceReplace { values: Vec<String> },
    /// Insert one ordered request rule.
    RuleCreate {
        #[serde(default)]
        index: Option<usize>,
        rule: AccessRuleDraft,
    },
    /// Replace one request rule.
    RuleUpdate { index: usize, rule: AccessRuleDraft },
    /// Delete one request rule.
    RuleDelete { index: usize },
    /// Move one request rule.
    RuleMove { from: usize, to: usize },
    /// Insert one destination-IP rule.
    IpCreate {
        #[serde(default)]
        index: Option<usize>,
        rule: IpRuleDraft,
    },
    /// Replace one destination-IP rule.
    IpUpdate { index: usize, rule: IpRuleDraft },
    /// Delete one destination-IP rule.
    IpDelete { index: usize },
    /// Move one destination-IP rule.
    IpMove { from: usize, to: usize },
    /// Set `access.ip_default` to `public_only` or `deny`.
    IpDefault { value: String },
}

/// Preview of one ACL edit.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessPreview {
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor_after: Option<String>,
    pub valid: bool,
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedVersion => "unsupported_version",
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::InvalidCandidate => "invalid_candidate",
            Self::RestartRequired => "restart_required",
            Self::Busy => "busy",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::TooLarge => "too_large",
            Self::ShuttingDown => "shutting_down",
            Self::UnknownResult => "unknown_result",
            Self::ResyncRequired => "resync_required",
            Self::Internal => "internal",
        })
    }
}

/// Reads a request page size, clamped to the published maximum.
pub fn page_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)
}

/// Reads a page offset without arithmetic overflow.
pub fn page_offset(offset: Option<usize>) -> usize {
    offset.unwrap_or(0)
}

/// Deserializes one request line.
pub fn parse_request(line: &str) -> Result<Request, ApiError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(ApiError::new(
            ErrorCode::TooLarge,
            "request line is too long",
        ));
    }
    serde_json::from_str(line)
        .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "request is not valid JSON"))
}

/// Serializes one line with a trailing newline and enforces the line cap.
pub fn encode_line<T: Serialize>(value: &T) -> Result<String, ApiError> {
    let mut line = serde_json::to_string(value)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "cannot encode response"))?;
    if line.len() + 1 > MAX_LINE_BYTES {
        return Err(ApiError::new(
            ErrorCode::TooLarge,
            "response line exceeds the protocol limit",
        ));
    }
    line.push('\n');
    Ok(line)
}
