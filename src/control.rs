//! Typed in-process control operations: status, validation, reload and
//! shutdown. No network administration transport is exposed in M07.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Semaphore;

use crate::config::{Config, ConfigError};
use crate::http::forward::Proxy;
use crate::http::server::ShutdownHandle;
use crate::snapshot::{MAX_LIVE_GENERATIONS, PublishError, SnapshotStore};
use crate::telemetry::{MetricsSnapshot, Telemetry};

/// Service lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Normal operation and reload allowed.
    Running,
    /// New accepts/exchanges are closed; reload publication is forbidden.
    Draining,
    /// Shutdown completed.
    Stopped,
}

impl Lifecycle {
    fn load(value: &AtomicU8) -> Self {
        match value.load(Ordering::Acquire) {
            0 => Self::Running,
            1 => Self::Draining,
            _ => Self::Stopped,
        }
    }

    fn store(self, value: &AtomicU8) {
        value.store(
            match self {
                Self::Running => 0,
                Self::Draining => 1,
                Self::Stopped => 2,
            },
            Ordering::Release,
        );
    }
}

/// Why shutdown was requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    /// SIGTERM/SIGINT or CLI shutdown.
    Signal,
    /// Library/server API.
    Server,
    /// Typed control API.
    Control,
}

/// Safe typed control outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum ReloadOutcome {
    /// Candidate was published with a new generation.
    Applied {
        /// New published generation.
        generation: u64,
    },
    /// Candidate is valid; nothing was published.
    Valid {
        /// Current unchanged generation.
        generation: u64,
    },
    /// Candidate is malformed or violates the schema.
    Invalid {
        /// At most 16 safe field paths.
        fields: Vec<String>,
        /// More paths were present than the report keeps.
        truncated: bool,
    },
    /// Candidate contains a restart-required change.
    RestartRequired {
        /// At most 16 safe field paths.
        fields: Vec<String>,
        /// More paths were present than the report keeps.
        truncated: bool,
    },
    /// Expected generation no longer matches.
    Conflict {
        /// Current generation.
        current: u64,
    },
    /// Another preparation is still running.
    Busy,
    /// The maximum number of live published roots is reached.
    GenerationBusy,
    /// The absolute operation deadline elapsed.
    TimedOut,
    /// The permanent `operations.reload_timeout_ms` was reached.
    Cancelled,
    /// Shutdown has begun; publication is forbidden.
    ShuttingDown,
    /// Unexpected local failure.
    Internal,
}

/// Bounded listener projection.
#[derive(Clone, Debug, Serialize)]
pub struct ListenerStatus {
    /// Configured listener ID.
    pub id: String,
    /// Configured local bind address.
    pub bind: String,
    /// `http` or `https`.
    pub transport: &'static str,
}

/// Bounded egress projection. Only configured local bind data is exposed.
#[derive(Clone, Debug, Serialize)]
pub struct EgressStatus {
    /// Configured egress ID.
    pub id: String,
    /// `system` or `bind_ip`.
    pub mode: &'static str,
    /// Configured local source IP for `bind_ip`.
    pub bind_ip: Option<String>,
}

/// Owned safe status projection.
#[derive(Clone, Debug, Serialize)]
pub struct StatusSnapshot {
    /// Current lifecycle.
    pub lifecycle: Lifecycle,
    /// Published generation.
    pub generation: u64,
    /// Actually retained published roots.
    pub live_generations: usize,
    /// Service uptime in milliseconds.
    pub uptime_ms: u64,
    /// Configured/resolved worker count.
    pub worker_threads: usize,
    /// Configured listeners.
    pub listeners: Vec<ListenerStatus>,
    /// Configured egress profiles.
    pub egress: Vec<EgressStatus>,
    /// Configured global client cap.
    pub max_client_connections: u32,
    /// Configured global outbound cap.
    pub max_connections: u32,
    /// Active accepted client sockets.
    pub client_active: u64,
    /// Active outbound sockets.
    pub outbound_active: u64,
    /// Active TLS handshakes.
    pub tls_active: u64,
    /// Active CONNECT tunnels.
    pub connect_active: u64,
    /// Active Argon2 jobs.
    pub auth_active: u64,
    /// Active DNS jobs.
    pub dns_active: u64,
    /// Idle pooled origin sockets.
    pub pool_idle: u64,
    /// Leased origin sockets.
    pub pool_leased: u64,
    /// Whether a preparation currently owns the single slot.
    pub reload_busy: bool,
    /// Last safe reload/validation outcome.
    pub last_reload: Option<ReloadOutcome>,
}

/// In-process typed control handle.
pub struct ControlState {
    snapshots: Arc<SnapshotStore>,
    telemetry: Arc<Telemetry>,
    proxy: Weak<Proxy>,
    shutdown: ShutdownHandle,
    config_path: Option<PathBuf>,
    preparation: Arc<Semaphore>,
    lifecycle: AtomicU8,
    publication: Mutex<()>,
    started: Instant,
    last_reload: Mutex<Option<ReloadOutcome>>,
    test_preparation_delay: Mutex<Option<Duration>>,
}

impl ControlState {
    /// Builds a control handle bound to one running server.
    pub fn new(
        snapshots: Arc<SnapshotStore>,
        telemetry: Arc<Telemetry>,
        proxy: Weak<Proxy>,
        shutdown: ShutdownHandle,
        config_path: Option<PathBuf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshots,
            telemetry,
            proxy,
            shutdown,
            config_path,
            preparation: Arc::new(Semaphore::new(1)),
            lifecycle: AtomicU8::new(0),
            publication: Mutex::new(()),
            started: Instant::now(),
            last_reload: Mutex::new(None),
            test_preparation_delay: Mutex::new(None),
        })
    }

    fn lifecycle(&self) -> Lifecycle {
        Lifecycle::load(&self.lifecycle)
    }

    /// Owned status without config/users/secret Arcs.
    pub fn status(&self) -> StatusSnapshot {
        let root = self.snapshots.load();
        let config = root.config();
        let listeners = config
            .listeners()
            .iter()
            .map(|listener| ListenerStatus {
                id: listener.id().to_owned(),
                bind: listener.bind().to_string(),
                transport: match listener.transport() {
                    crate::config::Transport::Http => "http",
                    crate::config::Transport::Https => "https",
                },
            })
            .collect();
        let egress = config
            .egress()
            .iter()
            .map(|profile| EgressStatus {
                id: profile.id().to_owned(),
                mode: match profile.mode() {
                    crate::config::EgressMode::System => "system",
                    crate::config::EgressMode::BindIp(_) => "bind_ip",
                },
                bind_ip: match profile.mode() {
                    crate::config::EgressMode::System => None,
                    crate::config::EgressMode::BindIp(ip) => Some(ip.to_string()),
                },
            })
            .collect();
        let telemetry = self.telemetry.snapshot();
        StatusSnapshot {
            lifecycle: self.lifecycle(),
            generation: root.generation(),
            live_generations: self.snapshots.live_generations(),
            uptime_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            worker_threads: config.runtime().worker_threads().resolve(),
            listeners,
            egress,
            max_client_connections: config.limits().max_client_connections(),
            max_connections: config.limits().max_connections(),
            client_active: telemetry.client_active,
            outbound_active: telemetry.outbound_active,
            tls_active: telemetry.tls_active,
            connect_active: telemetry.connect_active,
            auth_active: telemetry.auth_active,
            dns_active: telemetry.dns_active,
            pool_idle: telemetry.pool_idle,
            pool_leased: telemetry.pool_leased,
            reload_busy: telemetry.preparation_busy != 0
                || self.preparation.available_permits() == 0,
            last_reload: self
                .last_reload
                .lock()
                .ok()
                .and_then(|outcome| outcome.clone()),
        }
    }

    /// Owned bounded metrics snapshot.
    pub fn metrics(&self) -> MetricsSnapshot {
        let mut snapshot = self.telemetry.snapshot();
        snapshot.live_generations =
            u64::try_from(self.snapshots.live_generations()).unwrap_or(u64::MAX);
        snapshot.preparation_busy = u64::from(
            self.telemetry.preparation_busy.load(Ordering::Relaxed) != 0
                || self.preparation.available_permits() == 0,
        );
        snapshot
    }

    /// Test seam: hold the single preparation slot for a controlled duration.
    #[doc(hidden)]
    pub fn set_test_preparation_delay(&self, delay: Option<Duration>) {
        if let Ok(mut current) = self.test_preparation_delay.lock() {
            *current = delay;
        }
    }

    /// Test seam: retain a strong published root for generation-cap checks.
    #[doc(hidden)]
    pub fn snapshot_for_test(&self) -> Arc<crate::snapshot::RuntimeSnapshot> {
        self.snapshots.load()
    }

    /// Validates a candidate from the startup config path without publishing.
    pub async fn validate_on_disk(&self, expected_generation: u64) -> ReloadOutcome {
        self.prepare(expected_generation, false).await
    }

    /// Re-reads and atomically publishes one complete candidate.
    pub async fn reload(&self, expected_generation: u64) -> ReloadOutcome {
        self.prepare(expected_generation, true).await
    }

    async fn prepare(&self, expected_generation: u64, publish: bool) -> ReloadOutcome {
        if self.lifecycle() != Lifecycle::Running {
            return ReloadOutcome::ShuttingDown;
        }
        if self.snapshots.generation() != expected_generation {
            return self.record(ReloadOutcome::Conflict {
                current: self.snapshots.generation(),
            });
        }
        let Some(path) = self.config_path.clone() else {
            return ReloadOutcome::Internal;
        };
        let Ok(permit) = self.preparation.clone().try_acquire_owned() else {
            return self.record(ReloadOutcome::Busy);
        };
        let preparation_gauge = PreparationGauge::new(Arc::clone(&self.telemetry));
        let previous = self.snapshots.load();
        let previous_caps = Arc::clone(&previous);
        let timeout = previous.config().operations().reload_timeout();
        let delay = self
            .test_preparation_delay
            .lock()
            .ok()
            .and_then(|delay| *delay);
        let deadline = tokio::time::Instant::now() + timeout;
        if publish {
            self.telemetry
                .reload_attempts
                .fetch_add(1, Ordering::Relaxed);
        }
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _gauge = preparation_gauge;
            if let Some(delay) = delay {
                std::thread::sleep(delay);
            }
            Config::load_for_reload(&path, previous.config())
        });
        let prepared = match tokio::time::timeout_at(deadline, task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => return self.record(ReloadOutcome::Internal),
            Err(_) => {
                return self.record(ReloadOutcome::TimedOut);
            }
        };
        let candidate = match prepared {
            Ok(candidate) => candidate,
            Err(error) => {
                let outcome = classify(error);
                return self.record(outcome);
            }
        };
        let publication = self
            .publication
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if self.lifecycle() != Lifecycle::Running {
            drop(publication);
            return self.record(ReloadOutcome::ShuttingDown);
        }
        if self.snapshots.generation() != expected_generation {
            let current = self.snapshots.generation();
            drop(publication);
            return self.record(ReloadOutcome::Conflict { current });
        }
        if tokio::time::Instant::now() >= deadline {
            drop(publication);
            return self.record(ReloadOutcome::TimedOut);
        }
        if !publish {
            drop(publication);
            return self.record(ReloadOutcome::Valid {
                generation: expected_generation,
            });
        }
        if expected_generation == u64::MAX {
            drop(publication);
            return self.record(ReloadOutcome::Internal);
        }
        if self.snapshots.live_generations() >= MAX_LIVE_GENERATIONS {
            drop(publication);
            return self.record(ReloadOutcome::GenerationBusy);
        }
        let candidate = Arc::new(candidate);
        let proxy = self.proxy.upgrade();
        if let Some(proxy) = &proxy {
            // Caps are global admission state: publish them before the root so
            // a post-publish request cannot be admitted under a stale higher
            // cap. A failed publication restores the previous values below.
            proxy.set_published_caps(&candidate);
        }
        let published = self
            .snapshots
            .publish(expected_generation, Arc::clone(&candidate));
        let outcome = match published {
            Ok(generation) => {
                if let Some(proxy) = &proxy {
                    proxy.retire_published_pool(generation);
                }
                self.telemetry.live_generations.store(
                    u64::try_from(self.snapshots.live_generations()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                self.record(ReloadOutcome::Applied { generation })
            }
            Err(PublishError::Conflict) => {
                if let Some(proxy) = &proxy {
                    proxy.set_published_caps(previous_caps.config());
                }
                self.record(ReloadOutcome::Conflict {
                    current: self.snapshots.generation(),
                })
            }
            Err(PublishError::GenerationBusy) => {
                if let Some(proxy) = &proxy {
                    proxy.set_published_caps(previous_caps.config());
                }
                self.record(ReloadOutcome::GenerationBusy)
            }
            Err(PublishError::Exhausted) => {
                if let Some(proxy) = &proxy {
                    proxy.set_published_caps(previous_caps.config());
                }
                self.record(ReloadOutcome::Internal)
            }
        };
        drop(publication);
        outcome
    }

    fn record(&self, outcome: ReloadOutcome) -> ReloadOutcome {
        match &outcome {
            ReloadOutcome::Applied { .. } => {
                self.telemetry
                    .reload_applied
                    .fetch_add(1, Ordering::Relaxed);
            }
            ReloadOutcome::Invalid { .. } => {
                self.telemetry
                    .reload_invalid
                    .fetch_add(1, Ordering::Relaxed);
            }
            ReloadOutcome::RestartRequired { .. } => {
                self.telemetry
                    .reload_restart
                    .fetch_add(1, Ordering::Relaxed);
            }
            ReloadOutcome::Conflict { .. } => {
                self.telemetry
                    .reload_conflict
                    .fetch_add(1, Ordering::Relaxed);
            }
            ReloadOutcome::Busy => {
                self.telemetry.reload_busy.fetch_add(1, Ordering::Relaxed);
            }
            ReloadOutcome::GenerationBusy => {
                self.telemetry
                    .reload_generation_busy
                    .fetch_add(1, Ordering::Relaxed);
            }
            ReloadOutcome::TimedOut => {
                self.telemetry
                    .reload_timeout
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        if let Ok(mut last) = self.last_reload.lock() {
            *last = Some(outcome.clone());
        }
        outcome
    }

    /// Marks lifecycle as draining. Idempotent.
    pub fn begin_shutdown(&self, _reason: ShutdownReason) {
        let _publication = self
            .publication
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous = Lifecycle::load(&self.lifecycle);
        if previous == Lifecycle::Running {
            self.telemetry
                .shutdown_started
                .fetch_add(1, Ordering::Relaxed);
        }
        Lifecycle::Draining.store(&self.lifecycle);
    }

    /// Marks lifecycle as stopped after the shutdown coordinator completed.
    pub fn mark_stopped(&self) {
        let _publication = self
            .publication
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        Lifecycle::Stopped.store(&self.lifecycle);
    }

    /// Typed idempotent shutdown using the current absolute deadline.
    pub async fn shutdown(&self, reason: ShutdownReason) {
        self.begin_shutdown(reason);
        let timeout = self.snapshots.load().config().limits().shutdown_timeout();
        let deadline = Instant::now() + timeout;
        if self.shutdown.begin(deadline).await {
            self.mark_stopped();
        }
    }

    /// Configured single absolute shutdown budget.
    pub fn shutdown_timeout(&self) -> Duration {
        self.snapshots.load().config().limits().shutdown_timeout()
    }

    /// Maximum live generation cap for status/documentation.
    pub fn max_live_generations(&self) -> usize {
        MAX_LIVE_GENERATIONS
    }
}

fn classify(error: ConfigError) -> ReloadOutcome {
    let fields = match error {
        ConfigError::RestartRequired { path, .. } => {
            return ReloadOutcome::RestartRequired {
                fields: bounded_fields(path),
                truncated: false,
            };
        }
        ConfigError::Validation { path, .. } => bounded_fields(path),
        ConfigError::Toml { path, .. } => path.map(bounded_fields).unwrap_or_default(),
        ConfigError::Read { .. } => vec!["config".to_owned()],
    };
    ReloadOutcome::Invalid {
        fields,
        truncated: false,
    }
}

fn bounded_fields(path: String) -> Vec<String> {
    vec![path.chars().take(160).collect()]
}

struct PreparationGauge {
    telemetry: Arc<Telemetry>,
}

impl PreparationGauge {
    fn new(telemetry: Arc<Telemetry>) -> Self {
        telemetry.preparation_busy.store(1, Ordering::Release);
        Self { telemetry }
    }
}

impl Drop for PreparationGauge {
    fn drop(&mut self) {
        self.telemetry.preparation_busy.store(0, Ordering::Release);
    }
}

impl std::fmt::Debug for ControlState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlState")
            .field("generation", &self.snapshots.generation())
            .field("lifecycle", &self.lifecycle())
            .field("config_path", &self.config_path.is_some())
            .finish()
    }
}
