//! Shared bounded metrics. Counters live for the service lifetime and are
//! never reset by a configuration reload.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

/// Number of fixed histogram buckets including the overflow bucket.
pub const HISTOGRAM_BUCKETS: usize = 9;

const HTTP_BUCKETS_MS: [u64; 8] = [1, 5, 10, 25, 50, 100, 500, 1_000];
const HANDSHAKE_BUCKETS_MS: [u64; 8] = [1, 5, 10, 25, 50, 100, 500, 1_000];
const AUTH_BUCKETS_MS: [u64; 8] = [1, 5, 10, 25, 50, 100, 500, 1_000];

/// One fixed-bucket duration histogram.
#[derive(Debug)]
pub struct Histogram {
    buckets: Mutex<[u64; HISTOGRAM_BUCKETS]>,
    bounds: [u64; 8],
}

impl Histogram {
    fn new(bounds: [u64; 8]) -> Self {
        Self {
            buckets: Mutex::new([0; HISTOGRAM_BUCKETS]),
            bounds,
        }
    }

    /// Records one duration in milliseconds.
    pub fn observe(&self, duration: Duration) {
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let index = self
            .bounds
            .iter()
            .position(|bound| millis <= *bound)
            .unwrap_or(HISTOGRAM_BUCKETS - 1);
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets[index] = buckets[index].saturating_add(1);
        }
    }

    fn snapshot(&self) -> Vec<u64> {
        self.buckets
            .lock()
            .map(|buckets| buckets.to_vec())
            .unwrap_or_else(|poison| poison.into_inner().to_vec())
    }
}

/// Fixed histogram bounds in milliseconds.
pub fn http_buckets() -> [u64; 8] {
    HTTP_BUCKETS_MS
}

/// Fixed handshake histogram bounds in milliseconds.
pub fn handshake_buckets() -> [u64; 8] {
    HANDSHAKE_BUCKETS_MS
}

/// Fixed auth histogram bounds in milliseconds.
pub fn auth_buckets() -> [u64; 8] {
    AUTH_BUCKETS_MS
}

/// One weak count that is decremented on drop.
pub struct GaugeGuard {
    gauge: &'static str,
    value: &'static AtomicU64,
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.value.fetch_sub(1, Ordering::AcqRel);
        let _ = self.gauge;
    }
}

/// Shared process/server telemetry counters and gauges.
pub struct Telemetry {
    pub tcp_accepted: AtomicU64,
    pub tcp_rejected: AtomicU64,
    pub client_active: AtomicU64,
    pub tls_active: AtomicU64,
    pub tls_success: AtomicU64,
    pub tls_error: AtomicU64,
    pub tls_timeout: AtomicU64,
    pub tls_busy: AtomicU64,
    pub http_started: AtomicU64,
    pub http_completed: AtomicU64,
    pub http_cancelled: AtomicU64,
    pub http_2xx: AtomicU64,
    pub http_3xx: AtomicU64,
    pub http_4xx: AtomicU64,
    pub http_5xx: AtomicU64,
    pub connect_started: AtomicU64,
    pub connect_active: AtomicU64,
    pub connect_finished: AtomicU64,
    pub connect_complete: AtomicU64,
    pub connect_idle: AtomicU64,
    pub connect_timeout: AtomicU64,
    pub connect_error: AtomicU64,
    pub connect_cancelled: AtomicU64,
    pub auth_active: AtomicU64,
    pub auth_ok: AtomicU64,
    pub auth_invalid: AtomicU64,
    pub auth_busy: AtomicU64,
    pub auth_timeout: AtomicU64,
    pub dns_active: AtomicU64,
    pub dns_timeout: AtomicU64,
    pub dns_error: AtomicU64,
    pub outbound_active: AtomicU64,
    pub outbound_connecting: AtomicU64,
    pub pool_idle: AtomicU64,
    pub pool_leased: AtomicU64,
    pub reload_attempts: AtomicU64,
    pub reload_applied: AtomicU64,
    pub reload_invalid: AtomicU64,
    pub reload_restart: AtomicU64,
    pub reload_conflict: AtomicU64,
    pub reload_busy: AtomicU64,
    pub reload_generation_busy: AtomicU64,
    pub reload_timeout: AtomicU64,
    pub live_generations: AtomicU64,
    pub preparation_busy: AtomicU64,
    pub log_queued: AtomicU64,
    pub log_dropped: AtomicU64,
    pub log_sink_errors: AtomicU64,
    pub shutdown_started: AtomicU64,
    pub forced_shutdowns: AtomicU64,
    http_histogram: Histogram,
    handshake_histogram: Histogram,
    auth_histogram: Histogram,
    detailed: bool,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            tcp_accepted: AtomicU64::new(0),
            tcp_rejected: AtomicU64::new(0),
            client_active: AtomicU64::new(0),
            tls_active: AtomicU64::new(0),
            tls_success: AtomicU64::new(0),
            tls_error: AtomicU64::new(0),
            tls_timeout: AtomicU64::new(0),
            tls_busy: AtomicU64::new(0),
            http_started: AtomicU64::new(0),
            http_completed: AtomicU64::new(0),
            http_cancelled: AtomicU64::new(0),
            http_2xx: AtomicU64::new(0),
            http_3xx: AtomicU64::new(0),
            http_4xx: AtomicU64::new(0),
            http_5xx: AtomicU64::new(0),
            connect_started: AtomicU64::new(0),
            connect_active: AtomicU64::new(0),
            connect_finished: AtomicU64::new(0),
            connect_complete: AtomicU64::new(0),
            connect_idle: AtomicU64::new(0),
            connect_timeout: AtomicU64::new(0),
            connect_error: AtomicU64::new(0),
            connect_cancelled: AtomicU64::new(0),
            auth_active: AtomicU64::new(0),
            auth_ok: AtomicU64::new(0),
            auth_invalid: AtomicU64::new(0),
            auth_busy: AtomicU64::new(0),
            auth_timeout: AtomicU64::new(0),
            dns_active: AtomicU64::new(0),
            dns_timeout: AtomicU64::new(0),
            dns_error: AtomicU64::new(0),
            outbound_active: AtomicU64::new(0),
            outbound_connecting: AtomicU64::new(0),
            pool_idle: AtomicU64::new(0),
            pool_leased: AtomicU64::new(0),
            reload_attempts: AtomicU64::new(0),
            reload_applied: AtomicU64::new(0),
            reload_invalid: AtomicU64::new(0),
            reload_restart: AtomicU64::new(0),
            reload_conflict: AtomicU64::new(0),
            reload_busy: AtomicU64::new(0),
            reload_generation_busy: AtomicU64::new(0),
            reload_timeout: AtomicU64::new(0),
            live_generations: AtomicU64::new(1),
            preparation_busy: AtomicU64::new(0),
            log_queued: AtomicU64::new(0),
            log_dropped: AtomicU64::new(0),
            log_sink_errors: AtomicU64::new(0),
            shutdown_started: AtomicU64::new(0),
            forced_shutdowns: AtomicU64::new(0),
            http_histogram: Histogram::new(HTTP_BUCKETS_MS),
            handshake_histogram: Histogram::new(HANDSHAKE_BUCKETS_MS),
            auth_histogram: Histogram::new(AUTH_BUCKETS_MS),
            detailed: true,
        }
    }
}

impl Telemetry {
    /// Creates shared telemetry with detailed histograms enabled.
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Creates shared telemetry with the configured detail policy.
    pub fn with_detailed(detailed: bool) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            detailed,
            ..Self::default()
        })
    }

    /// Increments a counter and returns a gauge guard for the matching gauge.
    pub fn gauge(value: &'static AtomicU64) -> GaugeGuard {
        value.fetch_add(1, Ordering::AcqRel);
        GaugeGuard {
            gauge: "gauge",
            value,
        }
    }

    /// Records an HTTP exchange duration when detailed telemetry is enabled.
    pub fn observe_http(&self, duration: Duration) {
        if self.detailed {
            self.http_histogram.observe(duration);
        }
    }

    /// Records a TLS handshake duration when detailed telemetry is enabled.
    pub fn observe_handshake(&self, duration: Duration) {
        if self.detailed {
            self.handshake_histogram.observe(duration);
        }
    }

    /// Records an auth verification duration when detailed telemetry is enabled.
    pub fn observe_auth(&self, duration: Duration) {
        if self.detailed {
            self.auth_histogram.observe(duration);
        }
    }

    /// Owned bounded metrics snapshot.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            tcp_accepted: load(&self.tcp_accepted),
            tcp_rejected: load(&self.tcp_rejected),
            client_active: load(&self.client_active),
            tls_active: load(&self.tls_active),
            tls_success: load(&self.tls_success),
            tls_error: load(&self.tls_error),
            tls_timeout: load(&self.tls_timeout),
            tls_busy: load(&self.tls_busy),
            http_started: load(&self.http_started),
            http_completed: load(&self.http_completed),
            http_cancelled: load(&self.http_cancelled),
            http_2xx: load(&self.http_2xx),
            http_3xx: load(&self.http_3xx),
            http_4xx: load(&self.http_4xx),
            http_5xx: load(&self.http_5xx),
            connect_started: load(&self.connect_started),
            connect_active: load(&self.connect_active),
            connect_finished: load(&self.connect_finished),
            connect_complete: load(&self.connect_complete),
            connect_idle: load(&self.connect_idle),
            connect_timeout: load(&self.connect_timeout),
            connect_error: load(&self.connect_error),
            connect_cancelled: load(&self.connect_cancelled),
            auth_active: load(&self.auth_active),
            auth_ok: load(&self.auth_ok),
            auth_invalid: load(&self.auth_invalid),
            auth_busy: load(&self.auth_busy),
            auth_timeout: load(&self.auth_timeout),
            dns_active: load(&self.dns_active),
            dns_timeout: load(&self.dns_timeout),
            dns_error: load(&self.dns_error),
            outbound_active: load(&self.outbound_active),
            outbound_connecting: load(&self.outbound_connecting),
            pool_idle: load(&self.pool_idle),
            pool_leased: load(&self.pool_leased),
            reload_attempts: load(&self.reload_attempts),
            reload_applied: load(&self.reload_applied),
            reload_invalid: load(&self.reload_invalid),
            reload_restart: load(&self.reload_restart),
            reload_conflict: load(&self.reload_conflict),
            reload_busy: load(&self.reload_busy),
            reload_generation_busy: load(&self.reload_generation_busy),
            reload_timeout: load(&self.reload_timeout),
            live_generations: load(&self.live_generations),
            preparation_busy: load(&self.preparation_busy),
            log_queued: load(&self.log_queued),
            log_dropped: load(&self.log_dropped),
            log_sink_errors: load(&self.log_sink_errors),
            shutdown_started: load(&self.shutdown_started),
            forced_shutdowns: load(&self.forced_shutdowns),
            http_histogram: self.http_histogram.snapshot(),
            handshake_histogram: self.handshake_histogram.snapshot(),
            auth_histogram: self.auth_histogram.snapshot(),
        }
    }
}

fn load(value: &AtomicU64) -> u64 {
    value.load(Ordering::Relaxed)
}

/// Owned metrics snapshot safe for public status.
#[derive(Clone, Debug, Serialize)]
pub struct MetricsSnapshot {
    pub tcp_accepted: u64,
    pub tcp_rejected: u64,
    pub client_active: u64,
    pub tls_active: u64,
    pub tls_success: u64,
    pub tls_error: u64,
    pub tls_timeout: u64,
    pub tls_busy: u64,
    pub http_started: u64,
    pub http_completed: u64,
    pub http_cancelled: u64,
    pub http_2xx: u64,
    pub http_3xx: u64,
    pub http_4xx: u64,
    pub http_5xx: u64,
    pub connect_started: u64,
    pub connect_active: u64,
    pub connect_finished: u64,
    pub connect_complete: u64,
    pub connect_idle: u64,
    pub connect_timeout: u64,
    pub connect_error: u64,
    pub connect_cancelled: u64,
    pub auth_active: u64,
    pub auth_ok: u64,
    pub auth_invalid: u64,
    pub auth_busy: u64,
    pub auth_timeout: u64,
    pub dns_active: u64,
    pub dns_timeout: u64,
    pub dns_error: u64,
    pub outbound_active: u64,
    pub outbound_connecting: u64,
    pub pool_idle: u64,
    pub pool_leased: u64,
    pub reload_attempts: u64,
    pub reload_applied: u64,
    pub reload_invalid: u64,
    pub reload_restart: u64,
    pub reload_conflict: u64,
    pub reload_busy: u64,
    pub reload_generation_busy: u64,
    pub reload_timeout: u64,
    pub live_generations: u64,
    pub preparation_busy: u64,
    pub log_queued: u64,
    pub log_dropped: u64,
    pub log_sink_errors: u64,
    pub shutdown_started: u64,
    pub forced_shutdowns: u64,
    pub http_histogram: Vec<u64>,
    pub handshake_histogram: Vec<u64>,
    pub auth_histogram: Vec<u64>,
}
