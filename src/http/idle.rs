//! Bounded idle-I/O adapter.
//!
//! The adapter tracks real byte progress and fails a stalled direction after
//! `limits.idle_timeout_ms`. Polling without bytes is not progress.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until};

/// Shared idle deadline state.
pub struct IdleState {
    idle: Duration,
    last: Instant,
    sleep: Pin<Box<Sleep>>,
}

impl IdleState {
    /// Starts the idle deadline.
    pub fn new(idle: Duration) -> Self {
        let last = Instant::now();
        Self {
            idle,
            last,
            sleep: Box::pin(sleep_until(last + idle)),
        }
    }

    /// Records observable I/O progress.
    pub fn progress(&mut self) {
        self.last = Instant::now();
        self.sleep.as_mut().reset(self.last + self.idle);
    }

    /// Polls the idle deadline.
    pub fn poll_expired(&mut self, context: &mut Context<'_>) -> Poll<()> {
        self.sleep.as_mut().poll(context)
    }
}

/// Wraps an IO object and enforces idle progress in both directions.
pub struct IdleIo<T> {
    inner: T,
    idle: IdleState,
}

impl<T> IdleIo<T> {
    /// Creates the adapter.
    pub fn new(inner: T, idle: Duration) -> Self {
        Self {
            inner,
            idle: IdleState::new(idle),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().len() > before {
                    this.idle.progress();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if this.idle.poll_expired(context).is_ready() {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle read timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.idle.progress();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if this.idle.poll_expired(context).is_ready() {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle write timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(context) {
            Poll::Ready(Ok(())) => {
                this.idle.progress();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if this.idle.poll_expired(context).is_ready() {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle flush timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}
