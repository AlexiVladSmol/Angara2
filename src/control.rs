//! Typed in-process control operations: status, validation, reload and
//! shutdown. No network administration transport is exposed in M07.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::auth::{BlockState, format_blocked_until};
use crate::config::{Config, ConfigError};
use crate::http::forward::Proxy;
use crate::http::server::ShutdownHandle;
use crate::snapshot::{MAX_LIVE_GENERATIONS, PublishError, SnapshotStore};
use crate::telemetry::{MetricsSnapshot, Telemetry};

/// Service lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub(crate) fn load(value: &AtomicU8) -> Self {
        match value.load(Ordering::Acquire) {
            0 => Self::Running,
            1 => Self::Draining,
            _ => Self::Stopped,
        }
    }

    pub(crate) fn store(self, value: &AtomicU8) {
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListenerStatus {
    /// Configured listener ID.
    pub id: String,
    /// Configured local bind address.
    pub bind: String,
    /// `http` or `https`.
    pub transport: String,
    /// `basic` or `none`.
    pub auth: String,
}

/// Bounded egress projection. Only configured local bind data is exposed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EgressStatus {
    /// Configured egress ID.
    pub id: String,
    /// `system` or `bind_ip`.
    pub mode: String,
    /// Configured local source IP for `bind_ip`.
    pub bind_ip: Option<String>,
}

/// Owned safe status projection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusSnapshot {
    /// Current lifecycle.
    pub lifecycle: Lifecycle,
    /// Published generation.
    pub generation: u64,
    /// SHA-256 of the configuration bytes represented by the active root.
    pub config_version: String,
    /// SHA-256 of the users file represented by the active root.
    pub users_version: Option<String>,
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

/// Read-only account projection. Never contains a password hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserStatus {
    /// Login.
    pub username: String,
    /// `active`, `permanent` or `temporary`.
    pub block: String,
    /// Absolute UTC end for a temporary block.
    pub blocked_until: Option<String>,
    /// Whole seconds remaining for a temporary block.
    pub remaining_seconds: Option<u64>,
}

/// Read-only active block projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockStatus {
    /// Login.
    pub username: String,
    /// `permanent` or `temporary`.
    pub kind: String,
    /// Absolute UTC end for a temporary block.
    pub blocked_until: Option<String>,
    /// Whole seconds remaining for a temporary block.
    pub remaining_seconds: Option<u64>,
}

/// Bounded access summary without per-rule host data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessSummary {
    /// Configured source CIDRs.
    pub source_allow: Vec<String>,
    /// Number of ordered request rules.
    pub rule_count: usize,
    /// Number of ordered destination-IP rules.
    pub ip_rule_count: usize,
    /// `public_only` or `deny`.
    pub ip_default: String,
}

/// In-process typed control handle.
pub struct ControlState {
    snapshots: Arc<SnapshotStore>,
    telemetry: Arc<Telemetry>,
    proxy: Weak<Proxy>,
    shutdown: ShutdownHandle,
    config_path: Option<PathBuf>,
    preparation: Arc<Semaphore>,
    lifecycle: Arc<AtomicU8>,
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
        lifecycle: Arc<AtomicU8>,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshots,
            telemetry,
            proxy,
            shutdown,
            config_path,
            preparation: Arc::new(Semaphore::new(1)),
            lifecycle,
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
                }
                .to_owned(),
                auth: match listener.auth() {
                    crate::auth::AuthMode::None => "none",
                    crate::auth::AuthMode::Basic => "basic",
                }
                .to_owned(),
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
                }
                .to_owned(),
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
            config_version: config.version().to_owned(),
            users_version: config.users_version().map(str::to_owned),
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

    /// Configuration path used by this server, when started from a file.
    pub fn config_path(&self) -> Option<&std::path::Path> {
        self.config_path.as_deref()
    }

    /// Resolved users-file path from the active root.
    pub fn users_path(&self) -> Option<PathBuf> {
        self.snapshots
            .load()
            .config()
            .auth()
            .map(|auth| auth.users_file().to_path_buf())
    }

    /// Number of configured accounts in the active root.
    pub fn user_count(&self) -> usize {
        self.snapshots
            .load()
            .config()
            .auth()
            .map(|auth| auth.snapshot().user_count())
            .unwrap_or(0)
    }

    /// Number of blocks active at `now` in the active root.
    pub fn block_count(&self, now: DateTime<Utc>) -> usize {
        self.snapshots
            .load()
            .config()
            .auth()
            .map(|auth| auth.snapshot().block_count(now))
            .unwrap_or(0)
    }

    /// Filtered users page with explicit block state at `now`.
    pub fn users(
        &self,
        query: &str,
        offset: usize,
        limit: usize,
        now: DateTime<Utc>,
    ) -> (Vec<UserStatus>, usize) {
        let root = self.snapshots.load();
        let config = root.config();
        let Some(auth) = config.auth() else {
            return (Vec::new(), 0);
        };
        let needle = query.to_lowercase();
        let mut users = auth
            .snapshot()
            .records()
            .filter(|record| needle.is_empty() || record.username.to_lowercase().contains(&needle))
            .map(|record| {
                let (block, blocked_until, remaining_seconds) = match &record.block {
                    BlockState::Active => ("active".to_owned(), None, None),
                    BlockState::Permanent => ("permanent".to_owned(), None, None),
                    BlockState::Until(until) if now < *until => (
                        "temporary".to_owned(),
                        Some(format_blocked_until(until.to_owned())),
                        Some(until.signed_duration_since(now).num_seconds().max(0) as u64),
                    ),
                    BlockState::Until(_) => ("active".to_owned(), None, None),
                };
                UserStatus {
                    username: record.username.clone(),
                    block,
                    blocked_until,
                    remaining_seconds,
                }
            })
            .collect::<Vec<_>>();
        users.sort_by(|left, right| left.username.cmp(&right.username));
        let total = users.len();
        let page = users.into_iter().skip(offset).take(limit).collect();
        (page, total)
    }

    /// Active blocks page. Expired temporary blocks are omitted without a
    /// filesystem write.
    pub fn blocks(
        &self,
        query: &str,
        offset: usize,
        limit: usize,
        now: DateTime<Utc>,
    ) -> (Vec<BlockStatus>, usize) {
        let root = self.snapshots.load();
        let config = root.config();
        let Some(auth) = config.auth() else {
            return (Vec::new(), 0);
        };
        let needle = query.to_lowercase();
        let mut blocks = auth
            .snapshot()
            .records()
            .filter(|record| needle.is_empty() || record.username.to_lowercase().contains(&needle))
            .filter_map(|record| match &record.block {
                BlockState::Permanent => Some(BlockStatus {
                    username: record.username.clone(),
                    kind: "permanent".to_owned(),
                    blocked_until: None,
                    remaining_seconds: None,
                }),
                BlockState::Until(until) if now < *until => Some(BlockStatus {
                    username: record.username.clone(),
                    kind: "temporary".to_owned(),
                    blocked_until: Some(format_blocked_until(until.to_owned())),
                    remaining_seconds: Some(
                        until.signed_duration_since(now).num_seconds().max(0) as u64
                    ),
                }),
                BlockState::Active | BlockState::Until(_) => None,
            })
            .collect::<Vec<_>>();
        blocks.sort_by(|left, right| left.username.cmp(&right.username));
        let total = blocks.len();
        let page = blocks.into_iter().skip(offset).take(limit).collect();
        (page, total)
    }

    /// Safe access summary from the active policy.
    pub fn access_summary(&self) -> AccessSummary {
        let root = self.snapshots.load();
        let access = root.config().access();
        AccessSummary {
            source_allow: access
                .source_allow()
                .iter()
                .map(ToString::to_string)
                .collect(),
            rule_count: access.rules().len(),
            ip_rule_count: access.ip_rules().len(),
            ip_default: match access.ip_default() {
                crate::config::IpDefault::PublicOnly => "public_only",
                crate::config::IpDefault::Deny => "deny",
            }
            .to_owned(),
        }
    }

    /// One safe access page for the TUI and independent clients.
    pub fn access_page(
        &self,
        section: crate::control_protocol::AccessSection,
        offset: usize,
        limit: usize,
    ) -> crate::control_protocol::AccessPage {
        use crate::config::{HostSelectors, RuleAction};
        use crate::control_protocol::{AccessPage, AccessRuleView, AccessSection, IpRuleView};
        let root = self.snapshots.load();
        let access = root.config().access();
        let action = |action: RuleAction| match action {
            RuleAction::Allow => "allow".to_owned(),
            RuleAction::Deny => "deny".to_owned(),
        };
        let source_allow = access
            .source_allow()
            .iter()
            .map(ToString::to_string)
            .collect();
        let ip_default = match access.ip_default() {
            crate::config::IpDefault::PublicOnly => "public_only",
            crate::config::IpDefault::Deny => "deny",
        }
        .to_owned();
        let mut page = AccessPage {
            section,
            source_allow,
            rules: Vec::new(),
            ip_rules: Vec::new(),
            ip_default,
            offset,
            total: 0,
        };
        match section {
            AccessSection::Summary => {
                page.total = access.rules().len() + access.ip_rules().len();
            }
            AccessSection::Source => {
                let all = std::mem::take(&mut page.source_allow);
                page.total = all.len();
                page.source_allow = all.into_iter().skip(offset).take(limit).collect();
            }
            AccessSection::Rules => {
                page.total = access.rules().len();
                page.rules = access
                    .rules()
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|rule| {
                        let selectors = rule.selectors();
                        let (host_exact, host_suffix) = match selectors.hosts() {
                            HostSelectors::Any => (None, None),
                            HostSelectors::Exact(hosts) => {
                                (Some(hosts.iter().map(ToString::to_string).collect()), None)
                            }
                            HostSelectors::Suffix(hosts) => {
                                (None, Some(hosts.iter().map(ToString::to_string).collect()))
                            }
                        };
                        AccessRuleView {
                            id: rule.id().to_owned(),
                            action: action(rule.action()),
                            listeners: selectors.listeners().map(|values| values.to_vec()),
                            sources: selectors
                                .sources()
                                .map(|values| values.iter().map(ToString::to_string).collect()),
                            methods: selectors
                                .methods()
                                .map(|values| values.iter().map(ToString::to_string).collect()),
                            ports: selectors.ports().map(|values| values.to_vec()),
                            users: selectors.users().map(|values| values.to_vec()),
                            host_exact,
                            host_suffix,
                        }
                    })
                    .collect();
            }
            AccessSection::IpRules => {
                page.total = access.ip_rules().len();
                page.ip_rules = access
                    .ip_rules()
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|rule| IpRuleView {
                        id: rule.id().to_owned(),
                        action: action(rule.action()),
                        networks: rule.networks().iter().map(ToString::to_string).collect(),
                        allow_special: rule.allow_special(),
                    })
                    .collect();
            }
        }
        page
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
        let slot = OperationSlot::new(permit, Arc::clone(&self.telemetry));
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
            let guard = SlotGuard {
                _slot: Arc::clone(&slot),
            };
            if let Some(delay) = delay {
                std::thread::sleep(delay);
            }
            PreparedCandidate {
                result: Config::load_for_reload(&path, previous.config()),
                _guard: guard,
            }
        });
        let prepared = match tokio::time::timeout_at(deadline, task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => return self.record(ReloadOutcome::Internal),
            Err(_) => {
                return self.record(ReloadOutcome::TimedOut);
            }
        };
        let PreparedCandidate {
            result: prepared,
            _guard: operation_guard,
        } = prepared;
        let _operation_guard = operation_guard;
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

    /// Marks lifecycle as draining. Idempotent and monotonic: a stopped
    /// service can never return to draining.
    pub fn begin_shutdown(&self, _reason: ShutdownReason) {
        let _publication = self
            .publication
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut current = self.lifecycle.load(Ordering::Acquire);
        loop {
            match current {
                0 => {
                    match self
                        .lifecycle
                        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    {
                        Ok(_) => {
                            self.telemetry
                                .shutdown_started
                                .fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        Err(actual) => current = actual,
                    }
                }
                1 => return,
                _ => return,
            }
        }
    }

    /// Marks lifecycle as stopped after the shutdown coordinator completed.
    pub fn mark_stopped(&self) {
        let _publication = self
            .publication
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        Lifecycle::Stopped.store(&self.lifecycle);
    }

    /// Typed idempotent shutdown using the current absolute deadline. The
    /// service-owned coordinator finishes cleanup even if this caller is
    /// cancelled.
    pub async fn shutdown(&self, reason: ShutdownReason) {
        self.begin_shutdown(reason);
        let timeout = self.snapshots.load().config().limits().shutdown_timeout();
        let deadline = Instant::now() + timeout;
        self.shutdown.begin(deadline).await;
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

/// One admitted reload operation. The permit is deliberately owned here, not
/// by the async caller: it stays held while the native job runs and while a
/// ready candidate is stored in the JoinHandle result.
struct OperationSlot {
    permit: Option<OwnedSemaphorePermit>,
    telemetry: Arc<Telemetry>,
}

impl OperationSlot {
    fn new(permit: OwnedSemaphorePermit, telemetry: Arc<Telemetry>) -> Arc<Self> {
        telemetry.preparation_busy.store(1, Ordering::Release);
        Arc::new(Self {
            permit: Some(permit),
            telemetry,
        })
    }
}

impl Drop for OperationSlot {
    fn drop(&mut self) {
        self.permit.take();
        self.telemetry.preparation_busy.store(0, Ordering::Release);
    }
}

struct SlotGuard {
    _slot: Arc<OperationSlot>,
}

struct PreparedCandidate {
    result: Result<Config, ConfigError>,
    _guard: SlotGuard,
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
