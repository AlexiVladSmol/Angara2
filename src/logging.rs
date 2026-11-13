//! Bounded typed JSON Lines operational logging.
//!
//! Producers serialize only allow-listed scalar fields. The bounded channel
//! uses `try_send` so a full queue or blocked stderr sink never applies
//! backpressure to the proxy data plane.

use std::io::Write;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::LogLevel;
use crate::telemetry::Telemetry;

/// Maximum serialized record size.
pub const MAX_LOG_RECORD_BYTES: usize = 4096;
/// Fixed JSON schema version.
pub const LOG_SCHEMA_VERSION: u8 = 1;

/// Finite operational event enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    /// Service startup completed.
    ServiceStarted,
    /// Reload candidate applied.
    ReloadApplied,
    /// Reload candidate rejected.
    ReloadRejected,
    /// Drain started.
    ShutdownStarted,
    /// Service stopped.
    ServiceStopped,
    /// One HTTP exchange terminal outcome.
    RequestFinished,
    /// One CONNECT tunnel terminal outcome.
    TunnelFinished,
    /// Periodic global metrics summary.
    MetricsSummary,
}

impl Event {
    fn severity(self) -> LogLevel {
        match self {
            Self::ReloadRejected => LogLevel::Warn,
            Self::ShutdownStarted | Self::ServiceStopped => LogLevel::Info,
            Self::ServiceStarted
            | Self::ReloadApplied
            | Self::RequestFinished
            | Self::TunnelFinished
            | Self::MetricsSummary => LogLevel::Info,
        }
    }
}

/// Finite terminal outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Completed successfully.
    Success,
    /// Local or upstream failure.
    Failed,
    /// Cancelled by timeout/shutdown/client.
    Cancelled,
    /// Configuration candidate was invalid.
    Invalid,
    /// Configuration needs a restart.
    RestartRequired,
    /// Expected generation conflicted.
    Conflict,
    /// Preparation was busy.
    Busy,
    /// Generation root budget was exhausted.
    GenerationBusy,
    /// Deadline elapsed.
    TimedOut,
    /// Service is shutting down.
    ShuttingDown,
}

/// Finite safe reason class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Normal completion.
    Completed,
    /// Client disconnected or reset.
    ClientClosed,
    /// Origin closed or reset.
    OriginClosed,
    /// Idle deadline.
    Idle,
    /// Local timeout.
    Timeout,
    /// Policy/auth rejection.
    Rejected,
    /// Transport or protocol error.
    Error,
    /// Forced shutdown.
    Forced,
    /// Shutdown request.
    Shutdown,
    /// Generation overflow.
    Exhausted,
}

/// One safe, owned log record.
#[derive(Clone, Debug, Serialize)]
pub struct LogRecord {
    /// Fixed schema version.
    pub schema_version: u8,
    /// UNIX epoch milliseconds (wall clock).
    pub timestamp_ms: u64,
    /// Event kind.
    pub event: Event,
    /// Terminal outcome when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    /// Configuration generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// Server-created connection ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<u64>,
    /// Server-created request ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u64>,
    /// Configured listener ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener_id: Option<String>,
    /// Configured local listener bindings at startup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listeners: Option<Vec<String>>,
    /// Configured egress ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_id: Option<String>,
    /// Configured matched rule ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// HTTP status if one was produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Monotonic elapsed milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    /// Observed request application DATA bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_bytes: Option<u64>,
    /// Observed response application DATA bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_bytes: Option<u64>,
    /// Observed plaintext tunnel bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_bytes: Option<u64>,
    /// Safe reason class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// Periodic global metrics values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsSummary>,
    /// Whether an input list was truncated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

/// Small global metrics subset for the JSON summary.
#[derive(Clone, Debug, Serialize)]
pub struct MetricsSummary {
    /// Accepted TCP connections.
    pub tcp_accepted: u64,
    /// Active client connections.
    pub client_active: u64,
    /// Completed HTTP exchanges.
    pub http_completed: u64,
    /// Active CONNECT tunnels.
    pub connect_active: u64,
    /// Current generation.
    pub generation: u64,
    /// Retained published roots.
    pub live_generations: u64,
    /// Dropped log records.
    pub log_dropped: u64,
}

impl LogRecord {
    /// Starts one record with a fresh wall-clock timestamp.
    pub fn new(event: Event) -> Self {
        Self {
            schema_version: LOG_SCHEMA_VERSION,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0),
            event,
            outcome: None,
            generation: None,
            connection_id: None,
            request_id: None,
            listener_id: None,
            listeners: None,
            egress_id: None,
            rule_id: None,
            status: None,
            elapsed_ms: None,
            request_body_bytes: None,
            response_body_bytes: None,
            tunnel_bytes: None,
            reason: None,
            metrics: None,
            truncated: None,
        }
    }
}

/// Cloneable bounded logger.
#[derive(Clone)]
pub struct Logger {
    sender: Option<SyncSender<String>>,
    level: LogLevel,
    telemetry: Arc<Telemetry>,
}

impl Logger {
    /// Library/test logger that drops all records without a worker/thread.
    pub fn disabled(telemetry: Arc<Telemetry>) -> Self {
        Self {
            sender: None,
            level: LogLevel::Off,
            telemetry,
        }
    }

    /// Creates a bounded logger and the matching blocking consumer channel.
    pub fn channel(
        capacity: usize,
        level: LogLevel,
        telemetry: Arc<Telemetry>,
    ) -> (Self, std::sync::mpsc::Receiver<String>) {
        let (sender, receiver) = sync_channel(capacity.max(64));
        (
            Self {
                sender: Some(sender),
                level,
                telemetry,
            },
            receiver,
        )
    }

    /// Serializes and enqueues without waiting for capacity or I/O.
    pub fn log(&self, record: LogRecord) {
        if self.level == LogLevel::Off || self.sender.is_none() {
            return;
        }
        if !level_allows(self.level, record.event.severity()) {
            return;
        }
        let Ok(bytes) = serde_json::to_vec(&record) else {
            self.telemetry.log_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if bytes.len() > MAX_LOG_RECORD_BYTES {
            self.telemetry.log_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            self.telemetry.log_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(sender) = self.sender.as_ref() else {
            return;
        };
        match sender.try_send(text) {
            Ok(()) => {
                self.telemetry.log_queued.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.telemetry.log_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn level_allows(configured: LogLevel, severity: LogLevel) -> bool {
    match configured {
        LogLevel::Off => false,
        LogLevel::Error => severity == LogLevel::Error,
        LogLevel::Warn => matches!(severity, LogLevel::Error | LogLevel::Warn),
        LogLevel::Info => true,
    }
}

/// Starts the one CLI-owned, process-lifetime stderr writer thread.
///
/// The thread is intentionally detached: a stderr pipe without a reader can
/// block `write`, but that must not extend the CLI shutdown deadline or make
/// Drop wait. The OS ends the thread at process exit. Library servers never
/// call this function.
pub fn spawn_stderr_worker(receiver: std::sync::mpsc::Receiver<String>, telemetry: Arc<Telemetry>) {
    std::thread::Builder::new()
        .name("angara-log".to_owned())
        .spawn(move || {
            let mut stderr = std::io::stderr().lock();
            while let Ok(mut record) = receiver.recv() {
                record.push('\n');
                if stderr.write_all(record.as_bytes()).is_err() {
                    telemetry.log_sink_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let _ = stderr.flush();
            }
        })
        .ok();
}

use std::sync::atomic::Ordering;
