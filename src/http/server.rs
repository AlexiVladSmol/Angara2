//! Listener startup, accept loops, client budget, and bounded shutdown.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, watch};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::http::forward::{ClientInfo, Proxy};
use crate::http::headers;
use crate::http::interim::{InterimHub, SplitIo, writer_loop};
use crate::http::{ExchangeBody, ResponseBody};
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
        Self::bind_inner(config, false, None).await
    }

    /// Test/library API that binds configured listeners with ephemeral ports.
    #[doc(hidden)]
    pub async fn bind_ephemeral(config: Arc<Config>) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, None).await
    }

    /// Test/library API with an injected resolver and dialer.
    #[doc(hidden)]
    pub async fn bind_ephemeral_with_components(
        config: Arc<Config>,
        resolver: Arc<dyn crate::resolver::Resolver>,
        dialer: Arc<dyn crate::transport::Dialer>,
    ) -> Result<Self, ServerError> {
        Self::bind_inner(config, true, Some((resolver, dialer))).await
    }

    async fn bind_inner(
        config: Arc<Config>,
        ephemeral: bool,
        components: Option<(
            Arc<dyn crate::resolver::Resolver>,
            Arc<dyn crate::transport::Dialer>,
        )>,
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
            listeners.push((listener.id().to_owned(), socket));
            addresses.push((listener.id().to_owned(), local));
        }

        let proxy = match components {
            Some((resolver, dialer)) => {
                Proxy::with_components(Arc::clone(&config), resolver, dialer)
            }
            None => Proxy::new(Arc::clone(&config)),
        };
        let permits = Arc::new(Semaphore::new(
            config.limits().max_client_connections() as usize
        ));
        let (drain, drain_rx) = watch::channel(false);
        let (force, force_rx) = watch::channel(false);
        let tasks = TaskTracker::new();
        tasks.spawn(pool_maintenance(
            Arc::clone(&proxy),
            config.http().pool_idle_timeout(),
            drain_rx.clone(),
            force_rx.clone(),
        ));

        for (id, listener) in listeners {
            let proxy = Arc::clone(&proxy);
            let permits = Arc::clone(&permits);
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

    /// Stops accepting, drains active work up to the configured deadline, then
    /// forces remaining tracked tasks closed.
    pub async fn shutdown(self) {
        self._proxy.begin_shutdown();
        let _ = self.drain.send(true);
        if !self.tasks.wait(self.shutdown_timeout).await {
            let _ = self.force.send(true);
            self.tasks.abort_all();
            let _ = self.tasks.wait(Duration::from_secs(1)).await;
        }
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
            _ = ticker.tick() => proxy.purge_pool(),
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
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            drop(stream);
                            continue;
                        };
                        let proxy = Arc::clone(&proxy);
                        let config = Arc::clone(&config);
                        let listener_id = listener_id.clone();
                        let force = force.clone();
                        let drain = drain.clone();
                        tasks.spawn(async move {
                            serve_client(
                                stream, peer, listener_id, proxy, permit, config, drain, force,
                            )
                            .await;
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
async fn serve_client(
    stream: TcpStream,
    peer: SocketAddr,
    listener_id: String,
    proxy: Arc<Proxy>,
    permit: tokio::sync::OwnedSemaphorePermit,
    config: Arc<Config>,
    mut drain: watch::Receiver<bool>,
    mut force: watch::Receiver<bool>,
) {
    let _client_permit = permit;
    let idle_timeout = config.limits().idle_timeout();
    let (io, write_half, bridge_reader) = SplitIo::new(stream, idle_timeout);
    let (hub, interim_receiver) = InterimHub::new();
    let client = ClientInfo {
        peer: peer.ip(),
        listener_id,
    };
    let service_hub = hub.clone();
    let exchange_gate = Arc::new(Semaphore::new(1));
    let service = service_fn(move |request| {
        let proxy = Arc::clone(&proxy);
        let client = client.clone();
        let interim = service_hub.begin();
        let exchange_gate = Arc::clone(&exchange_gate);
        async move {
            let Ok(permit) = exchange_gate.acquire_owned().await else {
                return Ok::<_, Infallible>(headers::error_response(
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    true,
                ));
            };
            let response = proxy.handle(request, client, interim).await;
            let (parts, body) = response.into_parts();
            let body: ResponseBody = ExchangeBody::new(body, permit).boxed();
            Ok(http::Response::from_parts(parts, body))
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
    let connection = builder.serve_connection(TokioIo::new(io), service);
    let writer = writer_loop(write_half, bridge_reader, interim_receiver, idle_timeout);
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
            result = &mut connection => {
                let _ = result;
                // Dropping the connection closes the bridge writer; the writer
                // then drains any response bytes already buffered in the duplex.
                drop(connection);
                let _ = &mut writer.await;
                drop(hub);
                return;
            }
            result = &mut writer => {
                let _ = result;
                drop(connection);
                drop(hub);
                return;
            }
        }
    }
    drop(connection);
    drop(writer);
    drop(hub);
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
            future.await;
            notify.notify_one();
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
            handle.abort();
        }
        self.notify.notify_one();
    }

    async fn wait(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
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
}
