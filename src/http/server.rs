//! Listener startup, accept loops, client budget, and bounded shutdown.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::http::forward::{ClientInfo, Proxy};
use crate::http::headers;
use crate::http::idle::IdleState;
use crate::http::interim::{InterimHub, SplitIo, TransportProgress, writer_loop};
use crate::http::{ConnectionOutput, ExchangeBody, ResponseBody};
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
    drain: watch::Sender<bool>,
    force: watch::Sender<bool>,
    tasks: TaskTracker,
    shutdown_timeout: Duration,
    _proxy: Arc<Proxy>,
}

impl HttpServer {
    /// Binds every configured listener before accepting any connection.
    pub async fn bind(config: Arc<Config>) -> Result<Self, ServerError> {
        Self::bind_inner(config, false, None, None).await
    }

    /// Test/library API that binds configured listeners with ephemeral ports.
    #[doc(hidden)]
    pub async fn bind_ephemeral(config: Arc<Config>) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, None, None).await
    }

    /// Test/library API with an injected resolver and dialer.
    #[doc(hidden)]
    pub async fn bind_ephemeral_with_components(
        config: Arc<Config>,
        resolver: Arc<dyn crate::resolver::Resolver>,
        dialer: Arc<dyn crate::transport::Dialer>,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, Some((resolver, dialer)), None).await
    }

    /// Test/library API with an injected password verifier.
    #[doc(hidden)]
    pub async fn bind_ephemeral_with_verifier(
        config: Arc<Config>,
        verifier: Arc<dyn crate::auth::PasswordVerifier>,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, None, Some(verifier)).await
    }

    /// Test/library API with injected components and a password verifier.
    #[doc(hidden)]
    pub async fn bind_ephemeral_with_components_and_verifier(
        config: Arc<Config>,
        resolver: Arc<dyn crate::resolver::Resolver>,
        dialer: Arc<dyn crate::transport::Dialer>,
        verifier: Arc<dyn crate::auth::PasswordVerifier>,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, Some((resolver, dialer)), Some(verifier)).await
    }

    async fn bind_inner(
        config: Arc<Config>,
        ephemeral: bool,
        components: Option<(
            Arc<dyn crate::resolver::Resolver>,
            Arc<dyn crate::transport::Dialer>,
        )>,
        verifier: Option<Arc<dyn crate::auth::PasswordVerifier>>,
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
        let permits = Arc::new(Semaphore::new(
            config.limits().max_client_connections() as usize
        ));
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

        Ok(Self {
            addresses,
            drain,
            force,
            tasks,
            shutdown_timeout: config.limits().shutdown_timeout(),
            _proxy: proxy,
        })
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
        let deadline = std::time::Instant::now() + self.shutdown_timeout;
        self.shutdown_until(deadline).await;
    }

    /// Stops the server before one absolute shutdown deadline.
    ///
    /// The deadline is shared with the runtime and CLI; no phase gets a fresh
    /// full window after it has elapsed.
    #[doc(hidden)]
    pub async fn shutdown_until(self, deadline: std::time::Instant) {
        let deadline = tokio::time::Instant::from_std(deadline);
        self._proxy.begin_shutdown();
        let _ = self.drain.send(true);
        if !self.tasks.wait_until(deadline).await {
            let _ = self.force.send(true);
            self.tasks.abort_all();
            self.tasks.reap_after_abort().await;
        }
        let _ = self._proxy.shutdown_origins().await;
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        // Dropping a running server must not leave detached accept loops and
        // open listener sockets behind. Explicit `shutdown` remains the
        // graceful path; this is the bounded last-resort path.
        let _ = self.force.send(true);
        self.tasks.abort_all();
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
    permits: Arc<Semaphore>,
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
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
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
                        tasks.spawn(async move {
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
    permit: tokio::sync::OwnedSemaphorePermit,
    acceptor: TlsAcceptor,
    accepted_at: tokio::time::Instant,
    handshake_permits: Arc<Semaphore>,
    handshake_timeout: Duration,
    config: Arc<Config>,
    mut drain: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
) {
    if policy::check_source(config.access(), peer.ip()).is_err() {
        return;
    }
    let Ok(handshake_permit) = handshake_permits.try_acquire_owned() else {
        return;
    };
    if *drain.borrow() || *force.borrow() {
        return;
    }
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
    let Some(mut stream) = accepted else {
        return;
    };
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
    permit: tokio::sync::OwnedSemaphorePermit,
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
    let (hub, interim_receiver) = InterimHub::new();
    let client = ClientInfo {
        peer: peer.ip(),
        listener_id,
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
            let (response, setup) = if request.method() == http::Method::CONNECT {
                let on_upgrade = hyper::upgrade::on(&mut request);
                match proxy.handle_connect(request, client, on_upgrade).await {
                    Ok((response, setup)) => (response, Some(setup)),
                    Err(response) => (response, None),
                }
            } else {
                (proxy.handle(request, client, interim).await, None)
            };
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
            let body: ResponseBody = ExchangeBody::new(body, permit, service_output).boxed();
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
                        deadline,
                    } = setup;
                    let upgraded = tokio::select! {
                        biased;
                        _ = force.changed() => None,
                        result = tokio::time::timeout_at(deadline, on_upgrade) => {
                            result.ok().and_then(Result::ok)
                        }
                    };
                    let Some(upgraded) = upgraded else {
                        drop(writer);
                        output.close();
                        return;
                    };
                    let mut tunnel = Box::pin(crate::http::connect::run(
                        TokioIo::new(upgraded),
                        origin,
                        idle_timeout,
                        config.connect().half_close_timeout(),
                        Arc::clone(&tunnel_progress),
                    ));
                    let mut writer_done = false;
                    let outcome = loop {
                        tokio::select! {
                            biased;
                            _ = force.changed() => break None,
                            result = &mut writer, if !writer_done => {
                                writer_done = true;
                                if result.is_err() {
                                    break None;
                                }
                            }
                            outcome = &mut tunnel => break Some(outcome),
                        }
                    };
                    drop(tunnel);
                    match outcome {
                        Some(TunnelEnd::Complete { drain_deadline }) if !writer_done => {
                            if let Some(deadline) = drain_deadline {
                                let _ = tokio::time::timeout_at(deadline, &mut writer).await;
                            }
                            drop(writer);
                        }
                        _ => drop(writer),
                    }
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
