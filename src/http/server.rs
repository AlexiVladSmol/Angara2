//! Listener startup, accept loops, client budget, and bounded shutdown.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::config::{Config, Transport};
use crate::http::connect::{TunnelEnd, TunnelProgress, TunnelSetup};
use crate::http::forward::{ClientInfo, ExchangeMeta, Proxy};
use crate::http::headers;
use crate::http::idle::IdleState;
use crate::http::interim::{InterimHub, SplitIo, TransportProgress, writer_loop};
use crate::http::{BodyCompletion, BodyOutcome, ConnectionOutput, ExchangeBody, ResponseBody};
use crate::limits::{CapController, CapPermit};
use crate::logging::{Event, LogRecord, MetricsSummary};
use crate::policy;
use crate::tls::TLS_APP_BUFFER_BYTES;
use http_body_util::BodyExt;

/// HTTP server startup error.
#[derive(Debug)]
pub struct ServerError {
    detail: &'static str,
}

impl ServerError {
    /// Creates a safe startup error without peer or config values.
    pub(crate) fn new(detail: &'static str) -> Self {
        Self { detail }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.detail)
    }
}

impl std::error::Error for ServerError {}

/// A running HTTP server with all listeners bound.
pub struct HttpServer {
    addresses: Vec<(String, SocketAddr)>,
    shutdown: ShutdownHandle,
    control: std::sync::Arc<crate::control::ControlState>,
    _proxy: Arc<Proxy>,
}

/// Cloneable bounded shutdown coordinator shared by CLI signals and control.
#[derive(Clone)]
pub struct ShutdownHandle {
    drain: watch::Sender<bool>,
    force: watch::Sender<bool>,
    tasks: TaskTracker,
    proxy: Arc<Proxy>,
    lifecycle: Arc<AtomicU8>,
    state: Arc<ShutdownState>,
}

struct ShutdownState {
    started: AtomicBool,
    done_tx: watch::Sender<bool>,
    done_rx: watch::Receiver<bool>,
}

impl ShutdownHandle {
    /// Starts the one absolute drain/force deadline. The coordinator is a
    /// service-owned task, so aborting the caller does not cancel cleanup.
    /// Repeated calls wait for the same coordinator; the first deadline wins.
    pub async fn begin(&self, deadline: std::time::Instant) -> bool {
        if crate::control::Lifecycle::load(&self.lifecycle) == crate::control::Lifecycle::Stopped {
            let _ = self.state.done_tx.send(true);
            return false;
        }

        let leader = !self.state.started.swap(true, Ordering::AcqRel);
        if leader {
            let this = self.clone();
            let deadline = tokio::time::Instant::from_std(deadline);
            tokio::spawn(async move {
                this.run(deadline).await;
            });
        }

        let mut done = self.state.done_rx.clone();
        while !*done.borrow() {
            if done.changed().await.is_err() {
                break;
            }
        }
        leader
    }

    async fn run(self, deadline: tokio::time::Instant) {
        self.proxy.begin_shutdown();
        self.proxy.clear_idle_origins();
        let _ = self.drain.send(true);
        if !self.tasks.wait_until(deadline).await {
            self.proxy
                .telemetry()
                .forced_shutdowns
                .fetch_add(1, Ordering::Relaxed);
            let _ = self.force.send(true);
            self.tasks.abort_all();
            self.tasks.reap_after_abort().await;
        }
        let _ = self.proxy.shutdown_origins().await;
        crate::control::Lifecycle::Stopped.store(&self.lifecycle);
        let _ = self.state.done_tx.send(true);
    }

    /// Best-effort immediate cancellation for Drop.
    pub fn force_now(&self) {
        let _ = self.force.send(true);
        self.tasks.abort_all();
        crate::control::Lifecycle::Stopped.store(&self.lifecycle);
        let _ = self.state.done_tx.send(true);
    }

    /// Current configured shutdown budget. Reload can change this before the
    /// first shutdown begins; an already-started coordinator keeps its
    /// original absolute deadline.
    pub fn timeout(&self) -> Duration {
        self.proxy
            .snapshots()
            .load()
            .config()
            .limits()
            .shutdown_timeout()
    }
}

impl HttpServer {
    /// Binds every configured listener before accepting any connection.
    pub async fn bind(config: Arc<Config>) -> Result<Self, ServerError> {
        Self::bind_inner(config, false, None, None, None).await
    }

    /// Binds from a real config path and enables typed reload operations.
    pub async fn bind_with_path(
        config: Arc<Config>,
        config_path: std::path::PathBuf,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, false, None, None, Some(config_path)).await
    }

    /// Test/library API that binds configured listeners with ephemeral ports.
    #[doc(hidden)]
    pub async fn bind_ephemeral(config: Arc<Config>) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, None, None, None).await
    }

    /// Ephemeral bind with a config path for reload tests.
    #[doc(hidden)]
    pub async fn bind_ephemeral_with_path(
        config: Arc<Config>,
        config_path: std::path::PathBuf,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, None, None, Some(config_path)).await
    }

    /// Test/library API with an injected resolver and dialer.
    #[doc(hidden)]
    pub async fn bind_ephemeral_with_components(
        config: Arc<Config>,
        resolver: Arc<dyn crate::resolver::Resolver>,
        dialer: Arc<dyn crate::transport::Dialer>,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, Some((resolver, dialer)), None, None).await
    }

    /// Test/library API with an injected password verifier.
    #[doc(hidden)]
    pub async fn bind_ephemeral_with_verifier(
        config: Arc<Config>,
        verifier: Arc<dyn crate::auth::PasswordVerifier>,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, None, Some(verifier), None).await
    }

    /// Test/library API with injected components and a password verifier.
    #[doc(hidden)]
    pub async fn bind_ephemeral_with_components_and_verifier(
        config: Arc<Config>,
        resolver: Arc<dyn crate::resolver::Resolver>,
        dialer: Arc<dyn crate::transport::Dialer>,
        verifier: Arc<dyn crate::auth::PasswordVerifier>,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, Some((resolver, dialer)), Some(verifier), None).await
    }

    /// Test/library API with a startup config path and injected verifier.
    #[doc(hidden)]
    pub async fn bind_ephemeral_with_path_and_verifier(
        config: Arc<Config>,
        config_path: std::path::PathBuf,
        verifier: Arc<dyn crate::auth::PasswordVerifier>,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, None, Some(verifier), Some(config_path)).await
    }

    async fn bind_inner(
        config: Arc<Config>,
        ephemeral: bool,
        components: Option<(
            Arc<dyn crate::resolver::Resolver>,
            Arc<dyn crate::transport::Dialer>,
        )>,
        verifier: Option<Arc<dyn crate::auth::PasswordVerifier>>,
        config_path: Option<std::path::PathBuf>,
    ) -> Result<Self, ServerError> {
        let mut listeners = Vec::new();
        let mut addresses = Vec::new();
        for listener in config.listeners() {
            let mut address = listener.bind();
            if ephemeral {
                address.set_port(0);
            }
            let socket = bind_socket(address).map_err(|_| ServerError {
                detail: "cannot bind configured listener",
            })?;
            let local = socket.local_addr().map_err(|_| ServerError {
                detail: "cannot read listener address",
            })?;
            let tls = match listener.transport() {
                Transport::Http => None,
                Transport::Https => {
                    let prepared = config.prepared_tls(listener.id()).ok_or(ServerError {
                        detail: "HTTPS listener has no prepared TLS state",
                    })?;
                    Some(TlsAcceptor::from(prepared.server_config()))
                }
            };
            listeners.push((listener.id().to_owned(), socket, tls));
            addresses.push((listener.id().to_owned(), local));
        }

        let proxy = match (components, verifier) {
            (Some((resolver, dialer)), Some(verifier)) => {
                Proxy::with_components_and_verifier(Arc::clone(&config), resolver, dialer, verifier)
            }
            (Some((resolver, dialer)), None) => {
                Proxy::with_components(Arc::clone(&config), resolver, dialer)
            }
            (None, Some(verifier)) => Proxy::with_verifier(Arc::clone(&config), verifier),
            (None, None) => Proxy::new(Arc::clone(&config)),
        };
        let permits = proxy.client_caps();
        let handshake_permits = Arc::new(Semaphore::new(config.tls().max_handshaking()));
        let handshake_timeout = config.tls().handshake_timeout();
        let (drain, drain_rx) = watch::channel(false);
        let (force, force_rx) = watch::channel(false);
        let tasks = TaskTracker::new();
        tasks.spawn(pool_maintenance(
            Arc::clone(&proxy),
            config.http().pool_idle_timeout(),
            drain_rx.clone(),
            force_rx.clone(),
        ));
        if config.observability().metrics_enabled() {
            tasks.spawn(metrics_loop(
                Arc::clone(&proxy),
                config.observability().metrics_interval(),
                drain_rx.clone(),
                force_rx.clone(),
            ));
        }

        for (id, listener, tls) in listeners {
            let proxy = Arc::clone(&proxy);
            let permits = Arc::clone(&permits);
            let handshake_permits = Arc::clone(&handshake_permits);
            let tasks_for_accept = tasks.clone();
            let drain_rx = drain_rx.clone();
            let force_rx = force_rx.clone();
            let config_for_connection = Arc::clone(&config);
            tasks.spawn(async move {
                accept_loop(
                    listener,
                    id,
                    proxy,
                    permits,
                    handshake_permits,
                    tls,
                    handshake_timeout,
                    tasks_for_accept,
                    config_for_connection,
                    drain_rx,
                    force_rx,
                )
                .await;
            });
        }

        let lifecycle = Arc::new(AtomicU8::new(0));
        let (done_tx, done_rx) = watch::channel(false);
        let shutdown = ShutdownHandle {
            drain,
            force,
            tasks,
            proxy: Arc::clone(&proxy),
            lifecycle: Arc::clone(&lifecycle),
            state: Arc::new(ShutdownState {
                started: AtomicBool::new(false),
                done_tx,
                done_rx,
            }),
        };
        let control = crate::control::ControlState::new(
            proxy.snapshots(),
            proxy.telemetry(),
            Arc::downgrade(&proxy),
            shutdown.clone(),
            config_path,
            lifecycle,
        );
        Ok(Self {
            addresses,
            shutdown,
            control,
            _proxy: proxy,
        })
    }

    /// Typed in-process control handle.
    pub fn control(&self) -> Arc<crate::control::ControlState> {
        Arc::clone(&self.control)
    }

    /// Shared bounded shutdown coordinator.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.shutdown.clone()
    }

    /// Shared telemetry counters.
    pub fn telemetry(&self) -> Arc<crate::telemetry::Telemetry> {
        self._proxy.telemetry()
    }

    /// Installs the caller-owned logger sink.
    pub fn set_logger(&self, logger: crate::logging::Logger) {
        self._proxy.set_logger(logger);
    }

    /// Actual listener IDs and local addresses after all binds succeeded.
    pub fn addresses(&self) -> &[(String, SocketAddr)] {
        &self.addresses
    }

    /// Free password-verification slots, if authentication is configured.
    #[doc(hidden)]
    pub fn auth_available_permits(&self) -> Option<usize> {
        self._proxy.auth_available_permits()
    }

    /// Stops accepting, drains active work up to the configured deadline, then
    /// forces remaining tracked tasks closed.
    pub async fn shutdown(self) {
        let deadline = std::time::Instant::now() + self.shutdown.timeout();
        self.shutdown_until(deadline).await;
    }

    /// Stops the server before one absolute shutdown deadline.
    ///
    /// The deadline is shared with the runtime and CLI; no phase gets a fresh
    /// full window after it has elapsed.
    #[doc(hidden)]
    pub async fn shutdown_until(self, deadline: std::time::Instant) {
        self.control
            .begin_shutdown(crate::control::ShutdownReason::Server);
        self.shutdown.begin(deadline).await;
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        // Dropping a running server must not leave detached accept loops and
        // open listener sockets behind. Explicit `shutdown` remains the
        // graceful path; this is the bounded last-resort path.
        self.shutdown.force_now();
    }
}

/// Completes the final bridge/socket writer after the relay has ended. A relay
/// `Complete` is only successful when that writer also drains within the
/// existing first-EOF deadline.
///
/// A relay `Io` failure still drains the writer, bounded by
/// `half_close_timeout` from now: bytes the relay already handed to the bridge
/// were received from the origin/parent and belong to the client. The end
/// stays `Io` whether or not that drain succeeds.
async fn finalize_tunnel<W>(
    mut end: TunnelEnd,
    writer: &mut W,
    writer_done: bool,
    idle_timeout: Duration,
    half_close_timeout: Duration,
) -> (TunnelEnd, bool)
where
    W: Future<Output = std::io::Result<()>> + Unpin,
{
    if writer_done {
        return (end, writer_done);
    }
    match &end {
        TunnelEnd::Complete { drain_deadline } => {
            let drain = match drain_deadline {
                Some(deadline) => tokio::time::timeout_at(*deadline, writer).await,
                None => tokio::time::timeout(idle_timeout, writer).await,
            };
            match drain {
                Ok(Ok(())) => return (end, true),
                Ok(Err(_)) => end = TunnelEnd::Io,
                Err(_) => end = TunnelEnd::HalfCloseTimeout,
            }
        }
        TunnelEnd::Io => {
            if let Ok(Ok(())) = tokio::time::timeout(half_close_timeout, writer).await {
                return (end, true);
            }
        }
        TunnelEnd::Idle | TunnelEnd::HalfCloseTimeout | TunnelEnd::Cancelled => {}
    }
    (end, writer_done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relay_complete_waits_for_pending_writer_deadline() {
        let end = TunnelEnd::Complete {
            drain_deadline: Some(tokio::time::Instant::now() + Duration::from_millis(20)),
        };
        let mut writer = std::future::pending::<std::io::Result<()>>();
        let (final_end, done) = finalize_tunnel(
            end,
            &mut writer,
            false,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(final_end, TunnelEnd::HalfCloseTimeout));
        assert!(!done);
    }

    #[tokio::test]
    async fn relay_complete_succeeds_after_writer_drain() {
        let end = TunnelEnd::Complete {
            drain_deadline: Some(tokio::time::Instant::now() + Duration::from_secs(1)),
        };
        let mut writer = Box::pin(async { Ok(()) });
        let (final_end, done) = finalize_tunnel(
            end,
            &mut writer,
            false,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(final_end, TunnelEnd::Complete { .. }));
        assert!(done);
    }

    #[tokio::test]
    async fn relay_complete_writer_io_is_failure() {
        let end = TunnelEnd::Complete {
            drain_deadline: Some(tokio::time::Instant::now() + Duration::from_secs(1)),
        };
        let mut writer = Box::pin(async { Err(std::io::Error::other("synthetic writer failure")) });
        let (final_end, done) = finalize_tunnel(
            end,
            &mut writer,
            false,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(final_end, TunnelEnd::Io));
        assert!(!done);
    }

    #[tokio::test]
    async fn relay_io_drains_pending_writer_and_stays_io() {
        let drained = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&drained);
        let mut writer = Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            flag.store(true, Ordering::Release);
            Ok(())
        });
        let (final_end, done) = finalize_tunnel(
            TunnelEnd::Io,
            &mut writer,
            false,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(final_end, TunnelEnd::Io));
        assert!(done);
        assert!(drained.load(Ordering::Acquire), "writer was not drained");
    }

    #[tokio::test]
    async fn relay_io_writer_drain_is_bounded_by_half_close_timeout() {
        let mut writer = std::future::pending::<std::io::Result<()>>();
        let started = tokio::time::Instant::now();
        let (final_end, done) = finalize_tunnel(
            TunnelEnd::Io,
            &mut writer,
            false,
            Duration::from_secs(30),
            Duration::from_millis(50),
        )
        .await;
        assert!(matches!(final_end, TunnelEnd::Io));
        assert!(!done);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn relay_io_writer_failure_stays_io() {
        let mut writer = Box::pin(async { Err(std::io::Error::other("synthetic writer failure")) });
        let (final_end, done) = finalize_tunnel(
            TunnelEnd::Io,
            &mut writer,
            false,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(final_end, TunnelEnd::Io));
        assert!(!done);
    }

    #[tokio::test]
    async fn relay_io_after_writer_error_does_not_wait() {
        let mut writer = std::future::pending::<std::io::Result<()>>();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            finalize_tunnel(
                TunnelEnd::Io,
                &mut writer,
                true,
                Duration::from_secs(30),
                Duration::from_secs(30),
            ),
        )
        .await;
        let (final_end, done) = result.expect("finalize waited on a finished writer");
        assert!(matches!(final_end, TunnelEnd::Io));
        assert!(done);
    }

    #[tokio::test]
    async fn relay_cancelled_does_not_drain_writer() {
        let mut writer = std::future::pending::<std::io::Result<()>>();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            finalize_tunnel(
                TunnelEnd::Cancelled,
                &mut writer,
                false,
                Duration::from_secs(30),
                Duration::from_secs(30),
            ),
        )
        .await;
        let (final_end, done) = result.expect("cancelled relay waited on the writer");
        assert!(matches!(final_end, TunnelEnd::Cancelled));
        assert!(!done);
    }

    #[tokio::test]
    async fn relay_complete_gauge_stays_active_until_writer_timeout() {
        use crate::http::connect::TunnelGauge;
        use crate::logging::Logger;
        use crate::telemetry::Telemetry;

        let telemetry = Telemetry::with_detailed(false);
        let (logger, receiver) =
            Logger::channel(8, crate::config::LogLevel::Info, Arc::clone(&telemetry));
        let mut gauge = TunnelGauge::new(
            Arc::clone(&telemetry),
            logger,
            3,
            7,
            None,
            crate::logging::RouteKind::Direct,
        );
        assert_eq!(telemetry.snapshot().connect_active, 1);
        let end = TunnelEnd::Complete {
            drain_deadline: Some(tokio::time::Instant::now() + Duration::from_millis(20)),
        };
        let mut writer = std::future::pending::<std::io::Result<()>>();
        let (final_end, done) = finalize_tunnel(
            end,
            &mut writer,
            false,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(final_end, TunnelEnd::HalfCloseTimeout));
        assert!(!done);
        assert_eq!(telemetry.snapshot().connect_active, 1);
        gauge.finish(&final_end);
        let metrics = telemetry.snapshot();
        assert_eq!(metrics.connect_active, 0);
        assert_eq!(metrics.connect_finished, 1);
        assert_eq!(metrics.connect_timeout, 1);
        assert_eq!(metrics.connect_complete, 0);
        let record = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("tunnel record");
        let value: serde_json::Value = serde_json::from_str(&record).expect("JSON");
        assert_eq!(value["event"], "tunnel_finished");
        assert_eq!(value["outcome"], "failed");
        assert_eq!(value["reason"], "timeout");
        assert!(receiver.try_recv().is_err());
    }
}

struct ClientGauge(Arc<crate::telemetry::Telemetry>);

impl ClientGauge {
    fn new(telemetry: Arc<crate::telemetry::Telemetry>) -> Self {
        telemetry.client_active.fetch_add(1, Ordering::AcqRel);
        Self(telemetry)
    }
}

impl Drop for ClientGauge {
    fn drop(&mut self) {
        self.0.client_active.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn metrics_loop(
    proxy: Arc<Proxy>,
    interval: Duration,
    mut drain: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
) {
    let period = interval.max(Duration::from_millis(100));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = drain.changed() => break,
            _ = force.changed() => break,
            _ = ticker.tick() => {
                let telemetry = proxy.telemetry();
                let root = proxy.snapshots().load();
                let live_generations = u64::try_from(proxy.snapshots().live_generations())
                    .unwrap_or(u64::MAX);
                telemetry
                    .live_generations
                    .store(live_generations, Ordering::Relaxed);
                let snapshot = telemetry.snapshot();
                let mut record = LogRecord::new(Event::MetricsSummary);
                record.generation = Some(root.generation());
                record.metrics = Some(MetricsSummary {
                    tcp_accepted: snapshot.tcp_accepted,
                    client_active: snapshot.client_active,
                    http_completed: snapshot.http_completed,
                    connect_active: snapshot.connect_active,
                    generation: root.generation(),
                    live_generations,
                    log_dropped: snapshot.log_dropped,
                });
                proxy.logger().log(record);
            }
        }
    }
}

async fn pool_maintenance(
    proxy: Arc<Proxy>,
    interval: Duration,
    mut drain: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
) {
    let period = interval.max(Duration::from_millis(100));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = drain.changed() => break,
            _ = force.changed() => break,
            _ = ticker.tick() => {
                proxy.purge_pool();
                proxy.reap_origin_tasks().await;
            }
        }
    }
}

fn bind_socket(address: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = Domain::for_address(address);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener)
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    listener_id: String,
    proxy: Arc<Proxy>,
    permits: Arc<CapController>,
    handshake_permits: Arc<Semaphore>,
    tls: Option<TlsAcceptor>,
    handshake_timeout: Duration,
    tasks: TaskTracker,
    config: Arc<Config>,
    mut drain: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = drain.changed() => break,
            _ = force.changed() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let accepted_at = tokio::time::Instant::now();
                        proxy
                            .telemetry()
                            .tcp_accepted
                            .fetch_add(1, Ordering::Relaxed);
                        let Some(permit) = permits.try_acquire() else {
                            proxy
                                .telemetry()
                                .tcp_rejected
                                .fetch_add(1, Ordering::Relaxed);
                            drop(stream);
                            continue;
                        };
                        let proxy = Arc::clone(&proxy);
                        let config = Arc::clone(&config);
                        let listener_id = listener_id.clone();
                        let force = force.clone();
                        let drain = drain.clone();
                        let handshake_permits = Arc::clone(&handshake_permits);
                        let tls = tls.clone();
                        let telemetry = proxy.telemetry();
                        tasks.spawn(async move {
                            let _gauge = ClientGauge::new(telemetry);
                            if let Some(acceptor) = tls {
                                serve_tls_client(
                                    stream,
                                    peer,
                                    listener_id,
                                    proxy,
                                    permit,
                                    acceptor,
                                    accepted_at,
                                    handshake_permits,
                                    handshake_timeout,
                                    config,
                                    drain,
                                    force,
                                )
                                .await;
                            } else {
                                serve_client(
                                    stream, peer, listener_id, proxy, permit, config, None, drain,
                                    force,
                                )
                                .await;
                            }
                        });
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_tls_client(
    stream: TcpStream,
    peer: SocketAddr,
    listener_id: String,
    proxy: Arc<Proxy>,
    permit: CapPermit,
    acceptor: TlsAcceptor,
    accepted_at: tokio::time::Instant,
    handshake_permits: Arc<Semaphore>,
    handshake_timeout: Duration,
    config: Arc<Config>,
    mut drain: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
) {
    if policy::check_source(proxy.snapshots().load().config().access(), peer.ip()).is_err() {
        return;
    }
    let Ok(handshake_permit) = handshake_permits.try_acquire_owned() else {
        proxy.telemetry().tls_busy.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if *drain.borrow() || *force.borrow() {
        return;
    }
    let telemetry = proxy.telemetry();
    let handshake_started = tokio::time::Instant::now();
    telemetry.tls_active.fetch_add(1, Ordering::AcqRel);
    let idle_timeout = config.limits().idle_timeout();
    let idle_state = Arc::new(Mutex::new(IdleState::new(idle_timeout)));
    let tunnel_progress = TunnelProgress::new();
    let observer = TransportProgress::new(Arc::clone(&idle_state), tunnel_progress);
    let deadline = accepted_at + handshake_timeout;
    let accepted = tokio::select! {
        biased;
        _ = drain.changed() => None,
        _ = force.changed() => None,
        result = tokio::time::timeout_at(deadline, acceptor.accept(observer.observe(stream))) => {
            result.ok().and_then(Result::ok)
        }
    };
    drop(handshake_permit);
    telemetry.tls_active.fetch_sub(1, Ordering::AcqRel);
    let timed_out = handshake_started.elapsed() >= handshake_timeout;
    let Some(mut stream) = accepted else {
        if timed_out {
            telemetry.tls_timeout.fetch_add(1, Ordering::Relaxed);
        } else {
            telemetry.tls_error.fetch_add(1, Ordering::Relaxed);
        }
        return;
    };
    telemetry.tls_success.fetch_add(1, Ordering::Relaxed);
    telemetry.observe_handshake(handshake_started.elapsed());
    stream
        .get_mut()
        .1
        .set_buffer_limit(Some(TLS_APP_BUFFER_BYTES));
    observer.reset_idle();
    serve_client(
        stream,
        peer,
        listener_id,
        proxy,
        permit,
        config,
        Some(observer),
        drain,
        force,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn serve_client<S>(
    stream: S,
    peer: SocketAddr,
    listener_id: String,
    proxy: Arc<Proxy>,
    permit: CapPermit,
    config: Arc<Config>,
    observer: Option<Arc<TransportProgress>>,
    mut drain: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _client_permit = permit;
    let idle_timeout = config.limits().idle_timeout();
    let idle_state = observer
        .as_ref()
        .map(|observer| observer.idle_state())
        .unwrap_or_else(|| Arc::new(Mutex::new(IdleState::new(idle_timeout))));
    let tunnel_progress = observer
        .as_ref()
        .map(|observer| observer.tunnel_progress())
        .unwrap_or_else(TunnelProgress::new);
    let tunnel_mode = Arc::new(AtomicBool::new(false));
    let output = ConnectionOutput::new();
    let (io, write_half, bridge_reader) = SplitIo::with_tunnel_flag_and_idle(
        stream,
        Arc::clone(&idle_state),
        Arc::clone(&output),
        Arc::clone(&tunnel_mode),
    );
    let (hub, interim_receiver) = InterimHub::new(config.instance_id().to_owned());
    let connection_id = proxy.next_connection_id();
    let client = ClientInfo {
        peer: peer.ip(),
        listener_id,
        connection_id,
        request_id: 0,
    };
    let service_hub = hub.clone();
    let exchange_gate = Arc::new(Semaphore::new(1));
    let service_output = Arc::clone(&output);
    let tunnel_slot: Arc<Mutex<Option<TunnelSetup>>> = Arc::new(Mutex::new(None));
    let service_slot = Arc::clone(&tunnel_slot);
    let service = service_fn(move |mut request| {
        let proxy = Arc::clone(&proxy);
        let client = client.clone();
        let interim = service_hub.begin();
        let exchange_gate = Arc::clone(&exchange_gate);
        let service_output = Arc::clone(&service_output);
        let service_slot = Arc::clone(&service_slot);
        async move {
            let Ok(permit) = exchange_gate.acquire_owned().await else {
                return Ok::<_, Infallible>(headers::error_response(
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    true,
                ));
            };
            let mut request_client = client.clone();
            request_client.request_id = proxy.next_request_id();
            let exchange_started = tokio::time::Instant::now();
            let (response, setup) = if request.method() == http::Method::CONNECT {
                let on_upgrade = hyper::upgrade::on(&mut request);
                let connect_snapshot = proxy.snapshots().load();
                let mut connect_terminal = proxy.connect_terminal(
                    &request_client,
                    connect_snapshot.generation(),
                    exchange_started,
                );
                match proxy
                    .handle_connect(
                        request,
                        request_client,
                        on_upgrade,
                        &connect_snapshot,
                        &mut connect_terminal,
                    )
                    .await
                {
                    Ok((response, setup)) => {
                        // Ownership passes to the tunnel gauge only after a
                        // real 200 handoff.
                        connect_terminal.disarm();
                        (response, Some(setup))
                    }
                    Err(response) => {
                        connect_terminal.reject(response.status());
                        (response, None)
                    }
                }
            } else {
                (proxy.handle(request, request_client, interim).await, None)
            };
            let is_connect = setup.is_some();
            if let Some(setup) = setup {
                let Ok(mut slot) = service_slot.lock() else {
                    return Ok::<_, Infallible>(headers::error_response(
                        http::StatusCode::SERVICE_UNAVAILABLE,
                        true,
                    ));
                };
                if slot.is_some() {
                    return Ok::<_, Infallible>(headers::error_response(
                        http::StatusCode::SERVICE_UNAVAILABLE,
                        true,
                    ));
                }
                *slot = Some(setup);
            }
            let (parts, body) = response.into_parts();
            let completion: Option<BodyCompletion> = if is_connect {
                None
            } else {
                parts.extensions.get::<ExchangeMeta>().cloned().map(|meta| {
                    let proxy = Arc::clone(&proxy);
                    Box::new(move |outcome: BodyOutcome, bytes: u64| {
                        proxy.log_exchange(meta, outcome, bytes);
                    }) as BodyCompletion
                })
            };
            let body: ResponseBody =
                ExchangeBody::new(body, permit, service_output, completion).boxed();
            Ok::<_, Infallible>(http::Response::from_parts(parts, body))
        }
    });

    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .max_headers(config.http().max_headers())
        .max_header_size(config.limits().max_header_bytes() as usize)
        .header_read_timeout(config.limits().header_read_timeout())
        .max_buf_size(crate::http::forward::connection_buffer_size(&config))
        .timer(TokioTimer::new());
    let connection = builder
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades();
    let writer = writer_loop(
        write_half,
        bridge_reader,
        interim_receiver,
        idle_timeout,
        idle_state,
        observer,
        Arc::clone(&output),
        Arc::clone(&tunnel_mode),
        Arc::clone(&tunnel_progress),
    );
    let mut connection = Box::pin(connection);
    let mut writer = Box::pin(writer);

    let mut graceful = *drain.borrow();
    if graceful {
        connection.as_mut().graceful_shutdown();
    }

    loop {
        tokio::select! {
            biased;
            _ = force.changed() => break,
            changed = drain.changed(), if !graceful => {
                let _ = changed;
                graceful = true;
                connection.as_mut().graceful_shutdown();
            }
            _ = Arc::clone(&output).release_loop() => {}
            result = &mut connection => {
                let setup = tunnel_slot.lock().ok().and_then(|mut slot| slot.take());
                if result.is_ok()
                    && let Some(setup) = setup
                {
                    drop(connection);
                    drop(hub);
                    tunnel_mode.store(true, Ordering::Release);
                    let TunnelSetup {
                        on_upgrade,
                        origin,
                        origin_tls,
                        deadline,
                        idle_timeout,
                        half_close_timeout,
                        mut gauge,
                    } = setup;
                    gauge.attach_progress(Arc::clone(&tunnel_progress));
                    let upgraded = tokio::select! {
                        biased;
                        _ = force.changed() => None,
                        result = tokio::time::timeout_at(deadline, on_upgrade) => {
                            result.ok().and_then(Result::ok)
                        }
                    };
                    let Some(upgraded) = upgraded else {
                        // The gauge's Drop records the cancelled tunnel.
                        drop(gauge);
                        drop(writer);
                        output.close();
                        return;
                    };
                    let mut tunnel = Box::pin(crate::http::connect::run(
                        TokioIo::new(upgraded),
                        origin,
                        origin_tls,
                        idle_timeout,
                        half_close_timeout,
                        Arc::clone(&tunnel_progress),
                    ));
                    let mut writer_done = false;
                    let mut writer_error = false;
                    let relay = loop {
                        tokio::select! {
                            biased;
                            _ = force.changed() => break None,
                            result = &mut writer, if !writer_done => {
                                writer_done = true;
                                if result.is_err() {
                                    writer_error = true;
                                    break None;
                                }
                            }
                            outcome = &mut tunnel => break Some(outcome),
                        }
                    };
                    drop(tunnel);
                    let relay_end = match relay {
                        Some(end) => end,
                        None if writer_error => TunnelEnd::Io,
                        None => TunnelEnd::Cancelled,
                    };
                    let (final_end, _) = finalize_tunnel(
                        relay_end,
                        &mut writer,
                        writer_done,
                        idle_timeout,
                        half_close_timeout,
                    )
                    .await;
                    gauge.finish(&final_end);
                    drop(gauge);
                    drop(writer);
                    output.close();
                    return;
                }
                drop(setup);
                // Dropping the connection closes the bridge writer; the writer
                // then drains any response bytes already buffered in the duplex.
                drop(connection);
                let _ = &mut writer.await;
                drop(hub);
                output.close();
                return;
            }
            result = &mut writer => {
                let _ = result;
                drop(connection);
                drop(hub);
                output.close();
                return;
            }
        }
    }
    drop(connection);
    drop(writer);
    drop(hub);
    output.close();
}

#[derive(Clone)]
struct TaskTracker {
    inner: Arc<Mutex<TaskRegistry>>,
    notify: Arc<Notify>,
}

struct TaskRegistry {
    next_id: u64,
    stopped: bool,
    handles: HashMap<u64, JoinHandle<()>>,
}

impl TaskTracker {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TaskRegistry {
                next_id: 0,
                stopped: false,
                handles: HashMap::new(),
            })),
            notify: Arc::new(Notify::new()),
        }
    }

    fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let notify = Arc::clone(&self.notify);
        let handle = tokio::spawn(async move {
            let _notify_on_drop = NotifyOnDrop(notify);
            future.await;
        });
        let Ok(mut registry) = self.inner.lock() else {
            handle.abort();
            return;
        };
        if registry.stopped {
            handle.abort();
            return;
        }
        registry.handles.retain(|_, handle| !handle.is_finished());
        let id = registry.next_id;
        registry.next_id = registry.next_id.wrapping_add(1);
        registry.handles.insert(id, handle);
    }

    fn reap(&self) {
        if let Ok(mut registry) = self.inner.lock() {
            registry.handles.retain(|_, handle| !handle.is_finished());
        }
    }

    fn abort_all(&self) {
        if let Ok(mut registry) = self.inner.lock() {
            registry.stopped = true;
            for handle in registry.handles.values() {
                handle.abort();
            }
        }
        self.notify.notify_one();
    }

    async fn wait_until(&self, deadline: tokio::time::Instant) -> bool {
        loop {
            self.reap();
            let empty = self
                .inner
                .lock()
                .map(|registry| registry.handles.is_empty())
                .unwrap_or(true);
            if empty {
                return true;
            }
            let notified = self.notify.notified();
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                self.reap();
                return self
                    .inner
                    .lock()
                    .map(|registry| registry.handles.is_empty())
                    .unwrap_or(true);
            }
        }
    }

    /// Takes ownership of all aborted tasks and waits until they are actually
    /// dropped by the runtime. `abort` only schedules cancellation; awaiting
    /// the handles removes the tasks before shutdown returns.
    async fn reap_after_abort(&self) {
        let handles = if let Ok(mut registry) = self.inner.lock() {
            registry.stopped = true;
            registry
                .handles
                .drain()
                .map(|(_, handle)| handle)
                .collect::<Vec<_>>()
        } else {
            return;
        };
        for handle in handles {
            let _ = handle.await;
        }
    }
}

/// Notifies the tracker when a tracked future finishes or is cancelled.
///
/// The previous wrapper notified only after `future.await` returned normally,
/// so an aborted task could leave a waiter blocked until its deadline.
struct NotifyOnDrop(Arc<Notify>);

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}
