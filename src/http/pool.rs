//! Bounded HTTP/1.1 origin connection pool and lease tracking.

use std::collections::HashMap;
use std::error::Error;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::Response;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::outbound::OutboundPlan;
use crate::target::Host;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type PoolBody = BoxBody<Bytes, BoxError>;

/// Canonical pool isolation key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OriginKey {
    host: Host,
    port: u16,
    endpoint: std::net::SocketAddr,
    egress_id: String,
    generation: u64,
}

impl OriginKey {
    fn new(plan: &OutboundPlan, endpoint: std::net::SocketAddr) -> Self {
        Self {
            host: plan.target().host().clone(),
            port: plan.target().port(),
            endpoint,
            egress_id: plan.egress_id().to_owned(),
            generation: plan.generation(),
        }
    }
}

struct IdleConnection {
    sender: PooledSender,
    inserted: Instant,
}

struct PoolInner {
    idle: HashMap<OriginKey, Vec<IdleConnection>>,
    total: usize,
    max_idle: usize,
    max_idle_per_key: usize,
    idle_timeout: std::time::Duration,
}

impl PoolInner {
    fn purge(&mut self, now: Instant) {
        let timeout = self.idle_timeout;
        self.idle.retain(|_, entries| {
            entries.retain(|idle| now.saturating_duration_since(idle.inserted) < timeout);
            !entries.is_empty()
        });
        self.total = self.idle.values().map(Vec::len).sum();
    }
}

/// Shared bounded origin pool.
pub struct OriginPool {
    inner: Mutex<PoolInner>,
}

impl OriginPool {
    /// Creates a pool from validated HTTP limits.
    pub fn new(config: &Config) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PoolInner {
                idle: HashMap::new(),
                total: 0,
                max_idle: config.http().pool_max_idle(),
                max_idle_per_key: config.http().pool_max_idle_per_key(),
                idle_timeout: config.http().pool_idle_timeout(),
            }),
        })
    }

    /// Removes expired idle sockets.
    pub fn purge_expired(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.purge(Instant::now());
        }
    }

    /// Closes every idle socket. Active leases are unaffected.
    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.idle.clear();
            inner.total = 0;
        }
    }

    /// Takes a healthy idle connection whose endpoint is in the fresh plan.
    pub fn checkout(self: &Arc<Self>, plan: &OutboundPlan) -> Option<Lease> {
        let now = Instant::now();
        for endpoint in plan.endpoints() {
            let key = OriginKey::new(plan, *endpoint);
            let sender = {
                let mut inner = self.inner.lock().ok()?;
                inner.purge(now);
                let sender = inner
                    .idle
                    .get_mut(&key)
                    .and_then(|entries| entries.pop())
                    .map(|idle| idle.sender);
                if inner.idle.get(&key).is_some_and(Vec::is_empty) {
                    inner.idle.remove(&key);
                }
                inner.total = inner.idle.values().map(Vec::len).sum();
                sender
            };
            if let Some(sender) = sender
                && !sender.is_closed()
            {
                return Some(Lease::new(Arc::clone(self), key, sender));
            }
        }
        None
    }

    pub(crate) fn put(&self, key: OriginKey, sender: PooledSender) {
        let now = Instant::now();
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.purge(now);
        if inner.max_idle == 0 || inner.total >= inner.max_idle || sender.is_closed() {
            return;
        }
        let max_idle_per_key = inner.max_idle_per_key;
        let entries = inner.idle.entry(key).or_default();
        if entries.len() >= max_idle_per_key {
            return;
        }
        entries.push(IdleConnection {
            sender,
            inserted: now,
        });
        inner.total = inner.idle.values().map(Vec::len).sum();
    }

    pub(crate) fn new_lease(
        self: &Arc<Self>,
        plan: &OutboundPlan,
        endpoint: std::net::SocketAddr,
        sender: PooledSender,
    ) -> Lease {
        Lease::new(Arc::clone(self), OriginKey::new(plan, endpoint), sender)
    }
}

/// One connection lease. The sender returns to the pool only after both
/// directions complete successfully.
#[derive(Clone)]
pub struct Lease {
    pool: Arc<OriginPool>,
    key: OriginKey,
    state: Arc<Mutex<LeaseState>>,
}

struct LeaseState {
    sender: Option<PooledSender>,
    request_done: bool,
    response_done: bool,
    failed: bool,
}

impl Drop for LeaseState {
    fn drop(&mut self) {
        // The last lease clone dropping without a successful return owns the
        // only live sender; dropping it closes the origin socket and releases
        // its outbound permit.
        self.sender.take();
    }
}

impl Lease {
    fn new(pool: Arc<OriginPool>, key: OriginKey, sender: PooledSender) -> Self {
        Self {
            pool,
            key,
            state: Arc::new(Mutex::new(LeaseState {
                sender: Some(sender),
                request_done: false,
                response_done: false,
                failed: false,
            })),
        }
    }

    pub(crate) fn take_sender(&self) -> Option<PooledSender> {
        self.state.lock().ok()?.sender.take()
    }

    pub(crate) fn put_sender(&self, sender: PooledSender) {
        if let Ok(mut state) = self.state.lock() {
            if state.failed {
                drop(sender);
                return;
            }
            state.sender = Some(sender);
        }
        self.maybe_return();
    }

    pub(crate) fn request_complete(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.request_done = true;
        }
        self.maybe_return();
    }

    pub(crate) fn response_complete(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.response_done = true;
        }
        self.maybe_return();
    }

    pub(crate) fn abort(&self) {
        let sender = if let Ok(mut state) = self.state.lock() {
            state.failed = true;
            state.sender.take()
        } else {
            None
        };
        drop(sender);
    }

    fn maybe_return(&self) {
        let sender = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            if state.request_done && state.response_done && !state.failed {
                state.sender.take()
            } else {
                None
            }
        };
        if let Some(sender) = sender {
            self.pool.put(self.key.clone(), sender);
        }
    }

    /// Whether this exchange has been marked failed/evicted.
    pub(crate) fn is_failed(&self) -> bool {
        self.state.lock().map(|state| state.failed).unwrap_or(true)
    }
}

/// A checked-out hyper client sender plus its connection task.
pub struct PooledSender {
    sender: SendRequest<PoolBody>,
    _task: AbortOnDrop,
}

impl PooledSender {
    /// Creates a sender wrapper from a completed handshake.
    pub fn new(sender: SendRequest<PoolBody>, task: JoinHandle<()>) -> Self {
        Self {
            sender,
            _task: AbortOnDrop(task),
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.sender.is_closed() || !self.sender.is_ready()
    }

    pub(crate) async fn send_request(
        &mut self,
        request: http::Request<PoolBody>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        self.sender.send_request(request).await
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Request body wrapper that marks request completion/failure.
pub struct LeaseRequestBody {
    inner: Pin<Box<Incoming>>,
    lease: Lease,
    done: bool,
}

impl LeaseRequestBody {
    pub(crate) fn new(inner: Incoming, lease: Lease) -> Self {
        let empty = inner.is_end_stream();
        let body = Self {
            inner: Box::pin(inner),
            lease,
            done: empty,
        };
        if empty {
            body.lease.request_complete();
        }
        body
    }
}

impl Body for LeaseRequestBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match self.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(mut frame))) => {
                if let Some(trailers) = frame.trailers_mut() {
                    if crate::http::headers::filter_trailers(trailers).is_err() {
                        self.lease.abort();
                        self.done = true;
                        return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                            "invalid request trailers",
                        )))));
                    }
                    self.done = true;
                    self.lease.request_complete();
                } else if self.inner.as_ref().get_ref().is_end_stream() {
                    self.done = true;
                    self.lease.request_complete();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.lease.abort();
                self.done = true;
                Poll::Ready(Some(Err(Box::new(error))))
            }
            Poll::Ready(None) => {
                if !self.done {
                    self.done = true;
                    self.lease.request_complete();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().get_ref().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.as_ref().get_ref().size_hint()
    }
}

impl Drop for LeaseRequestBody {
    fn drop(&mut self) {
        if !self.done {
            if self.inner.as_ref().get_ref().is_end_stream() {
                self.lease.request_complete();
            } else {
                self.lease.abort();
            }
        }
    }
}

/// Response body wrapper that marks response completion/failure.
pub struct LeaseResponseBody {
    inner: Pin<Box<Incoming>>,
    lease: Lease,
    done: bool,
}

impl LeaseResponseBody {
    pub(crate) fn new(inner: Incoming, lease: Lease) -> Self {
        let empty = inner.is_end_stream();
        let body = Self {
            inner: Box::pin(inner),
            lease,
            done: empty,
        };
        if empty {
            body.lease.response_complete();
        }
        body
    }
}

impl Body for LeaseResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.lease.is_failed() {
            self.done = true;
            return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                "origin exchange was aborted",
            )))));
        }
        match self.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                let mut frame = frame;
                if let Some(trailers) = frame.trailers_mut() {
                    if crate::http::headers::filter_trailers(trailers).is_err() {
                        self.lease.abort();
                        self.done = true;
                        return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                            "invalid trailers",
                        )))));
                    }
                    self.done = true;
                    self.lease.response_complete();
                } else if self.inner.as_ref().get_ref().is_end_stream() {
                    self.done = true;
                    self.lease.response_complete();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.lease.abort();
                self.done = true;
                Poll::Ready(Some(Err(Box::new(error))))
            }
            Poll::Ready(None) => {
                if !self.done {
                    self.done = true;
                    self.lease.response_complete();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().get_ref().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.as_ref().get_ref().size_hint()
    }
}

impl Drop for LeaseResponseBody {
    fn drop(&mut self) {
        if !self.done {
            if self.inner.as_ref().get_ref().is_end_stream() {
                self.lease.response_complete();
            } else {
                self.lease.abort();
            }
        }
    }
}
