//! HTTP/1.1 ingress, forwarding and bounded origin pool.

use std::error::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use http_body::{Body, Frame, SizeHint};
use tokio::sync::OwnedSemaphorePermit;

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

/// Response body that keeps the per-connection exchange gate until it is
/// consumed or dropped. This preserves HTTP/1.1 response and interim ordering
/// for pipelined requests.
pub struct ExchangeBody {
    inner: ResponseBody,
    _permit: OwnedSemaphorePermit,
}

impl ExchangeBody {
    /// Wraps a response body with the exchange permit.
    pub fn new(inner: ResponseBody, permit: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            _permit: permit,
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
        Pin::new(&mut self.inner).poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
