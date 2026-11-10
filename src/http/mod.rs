//! HTTP/1.1 ingress, forwarding and bounded origin pool.

use std::error::Error;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http_body::{Body, Frame, SizeHint};
use tokio::sync::{Notify, OwnedSemaphorePermit};
use tokio::task::{AbortHandle, JoinSet};

pub mod forward;
pub mod headers;
pub mod idle;
pub mod interim;
pub mod pool;
pub mod server;

pub use server::{HttpServer, ServerError};

/// Boxed response body used by the HTTP server.
pub type ResponseBody =
    http_body_util::combinators::BoxBody<bytes::Bytes, Box<dyn Error + Send + Sync>>;

/// Ordered-output barrier for one client connection.
///
/// Hyper writes final response bytes into the bridge and reports flushes; the
/// writer reports consumed bytes after the socket write. An exchange gate is
/// released only after the final response flush and the writer has consumed
/// every produced byte, so the next pipelined request cannot interleave its
/// interim head or final head into the previous body.
pub struct ConnectionOutput {
    state: Mutex<OutputState>,
    notify: Notify,
}

struct OutputState {
    produced: u64,
    consumed: u64,
    flush_seq: u64,
    armed: Option<OwnedSemaphorePermit>,
    armed_flush: u64,
    closed: bool,
}

impl ConnectionOutput {
    /// Creates one output barrier for a client connection.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(OutputState {
                produced: 0,
                consumed: 0,
                flush_seq: 0,
                armed: None,
                armed_flush: 0,
                closed: false,
            }),
            notify: Notify::new(),
        })
    }

    /// Records bytes handed by hyper to the bridge.
    pub fn produced(&self, bytes: usize) {
        if let Ok(mut state) = self.state.lock() {
            state.produced = state.produced.saturating_add(bytes as u64);
        }
        self.notify.notify_one();
    }

    /// Records bytes actually written to the client socket.
    pub fn consumed(&self, bytes: usize) {
        if let Ok(mut state) = self.state.lock() {
            state.consumed = state.consumed.saturating_add(bytes as u64);
        }
        self.notify.notify_one();
    }

    /// Records a completed flush of the bridge.
    pub fn flushed(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.flush_seq = state.flush_seq.saturating_add(1);
        }
        self.notify.notify_one();
    }

    /// Hands the exchange permit to the barrier. It is dropped only after the
    /// response bytes are flushed and consumed.
    pub fn arm(&self, permit: OwnedSemaphorePermit) {
        if let Ok(mut state) = self.state.lock() {
            if state.closed {
                drop(permit);
                return;
            }
            state.armed_flush = state.flush_seq;
            state.armed = Some(permit);
        }
        self.notify.notify_one();
    }

    fn release_ready(&self) {
        let permit = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            if state.armed.is_some()
                && state.flush_seq > state.armed_flush
                && state.consumed >= state.produced
            {
                state.armed.take()
            } else {
                None
            }
        };
        drop(permit);
    }

    /// Waits until armed permits can be released.
    pub async fn release_loop(self: Arc<Self>) {
        loop {
            self.notify.notified().await;
            self.release_ready();
            let closed = self.state.lock().map(|state| state.closed).unwrap_or(true);
            if closed {
                return;
            }
        }
    }

    /// Releases a pending permit and stops the barrier when the connection ends.
    pub fn close(&self) {
        let permit = if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.armed.take()
        } else {
            None
        };
        drop(permit);
        self.notify.notify_one();
    }
}

/// Response body that keeps the per-connection exchange gate until the final
/// response bytes have actually reached the client socket.
pub struct ExchangeBody {
    inner: ResponseBody,
    output: Arc<ConnectionOutput>,
    permit: Option<OwnedSemaphorePermit>,
}

impl ExchangeBody {
    /// Wraps a response body with the exchange permit and output barrier.
    pub fn new(
        inner: ResponseBody,
        permit: OwnedSemaphorePermit,
        output: Arc<ConnectionOutput>,
    ) -> Self {
        let mut body = Self {
            inner,
            output,
            permit: Some(permit),
        };
        if body.inner.is_end_stream() {
            body.arm();
        }
        body
    }

    fn arm(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.output.arm(permit);
        }
    }
}

impl Body for ExchangeBody {
    type Data = bytes::Bytes;
    type Error = Box<dyn Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                let final_frame = self.inner.is_end_stream() || frame.trailers_ref().is_some();
                if final_frame {
                    self.arm();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                self.arm();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                self.permit.take();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ExchangeBody {
    fn drop(&mut self) {
        // Dropping before a final frame aborts the exchange; do not delay the
        // gate for a response that will not be completed.
        self.permit.take();
    }
}

/// Registry of origin connection driver tasks.
///
/// Tasks are owned by the `JoinSet`; pool leases hold only abort handles. This
/// lets shutdown abort and then await actual task termination/socket close.
pub struct OriginTasks {
    inner: tokio::sync::Mutex<JoinSet<()>>,
}

impl OriginTasks {
    /// Creates an empty origin-task registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: tokio::sync::Mutex::new(JoinSet::new()),
        })
    }

    /// Spawns an origin driver and returns its abort handle.
    pub async fn spawn<F>(&self, future: F) -> AbortHandle
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut set = self.inner.lock().await;
        while set.try_join_next().is_some() {}
        set.spawn(future)
    }

    /// Reaps completed origin drivers.
    pub async fn reap(&self) {
        let mut set = self.inner.lock().await;
        while set.try_join_next().is_some() {}
    }

    /// Aborts all origin drivers and waits for their actual completion.
    pub async fn shutdown(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut set = self.inner.lock().await;
        set.abort_all();
        loop {
            match tokio::time::timeout_at(deadline, set.join_next()).await {
                Ok(Some(_)) => {}
                Ok(None) => return true,
                Err(_) => return set.is_empty(),
            }
        }
    }
}
