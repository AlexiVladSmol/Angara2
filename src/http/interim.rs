//! Narrow bounded writer adapter for informational responses.
//!
//! Hyper's server API returns one final response. Interim heads are serialized
//! from typed `http` status/header values and queued to the single writer that
//! owns the client socket half. Hyper still parses and frames every HTTP
//! message; this adapter only orders bounded interim heads before the final
//! response.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;
use http::header::HeaderMap;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::mpsc;

use crate::http::ConnectionOutput;
use crate::http::connect::TunnelProgress;
use crate::http::headers;
use crate::http::idle::IdleState;

const MAX_INTERIM_HEADS: usize = 16;
const MAX_INTERIM_BYTES: usize = 64 * 1024;

/// Per-connection interim queue producer.
#[derive(Clone)]
pub struct InterimHub {
    sender: mpsc::Sender<Bytes>,
}

impl InterimHub {
    /// Creates the hub and the writer-loop receiver.
    pub fn new() -> (Self, mpsc::Receiver<Bytes>) {
        let (sender, receiver) = mpsc::channel(MAX_INTERIM_HEADS);
        (Self { sender }, receiver)
    }

    /// Creates the per-exchange sender and failure flag.
    pub fn begin(&self) -> InterimSender {
        InterimSender {
            sender: self.sender.clone(),
            bytes: Arc::new(AtomicUsize::new(0)),
            failed: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Per-exchange interim writer.
#[derive(Clone)]
pub struct InterimSender {
    sender: mpsc::Sender<Bytes>,
    bytes: Arc<AtomicUsize>,
    failed: Arc<AtomicBool>,
}

impl InterimSender {
    /// Sends a typed interim head.
    pub fn send_interim(&self, status: StatusCode, headers: &HeaderMap) -> bool {
        if status == StatusCode::SWITCHING_PROTOCOLS
            || status == StatusCode::CONTINUE
            || !status.is_informational()
        {
            self.failed.store(true, Ordering::Release);
            return false;
        }
        let mut headers = headers.clone();
        if headers::filter_hop_by_hop(&mut headers, false).is_err() {
            self.failed.store(true, Ordering::Release);
            return false;
        }
        headers::append_via(&mut headers);
        self.send_head(status, &headers)
    }

    /// Whether an interim send failed or an unsupported interim was seen.
    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn send_head(&self, status: StatusCode, headers: &HeaderMap) -> bool {
        if self.failed.load(Ordering::Acquire) {
            return false;
        }
        let bytes = serialize_head(status, headers);
        let previous = self.bytes.fetch_add(bytes.len(), Ordering::AcqRel);
        if previous + bytes.len() > MAX_INTERIM_BYTES {
            self.failed.store(true, Ordering::Release);
            return false;
        }
        if self.sender.try_send(bytes).is_err() {
            self.failed.store(true, Ordering::Release);
            return false;
        }
        true
    }
}

fn serialize_head(status: StatusCode, headers: &HeaderMap) -> Bytes {
    let reason = status.canonical_reason().unwrap_or("Informational");
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(b"HTTP/1.1 ");
    output.extend_from_slice(status.as_str().as_bytes());
    output.push(b' ');
    output.extend_from_slice(reason.as_bytes());
    output.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    Bytes::from(output)
}

/// Hyper-facing IO: reads from the client and writes into the bridge duplex.
pub struct SplitIo<R> {
    read: ReadHalf<R>,
    write: DuplexStream,
    idle: Arc<Mutex<IdleState>>,
    output: Arc<ConnectionOutput>,
    tunnel: Arc<AtomicBool>,
}

impl<R> SplitIo<R>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates the combined IO and returns the writer-loop side.
    pub fn new(
        stream: R,
        idle_timeout: Duration,
        output: Arc<ConnectionOutput>,
    ) -> (Self, WriteHalf<R>, DuplexStream) {
        Self::with_tunnel_flag(
            stream,
            idle_timeout,
            output,
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Creates the combined IO with a shared tunnel-mode flag.
    pub fn with_tunnel_flag(
        stream: R,
        idle_timeout: Duration,
        output: Arc<ConnectionOutput>,
        tunnel: Arc<AtomicBool>,
    ) -> (Self, WriteHalf<R>, DuplexStream) {
        let (read, write) = tokio::io::split(stream);
        let (bridge_writer, bridge_reader) = tokio::io::duplex(64 * 1024);
        (
            Self {
                read,
                write: bridge_writer,
                idle: Arc::new(Mutex::new(IdleState::new(idle_timeout))),
                output,
                tunnel,
            },
            write,
            bridge_reader,
        )
    }

    /// Shared idle/progress state for the single writer loop.
    ///
    /// Hyper's bridge can be full while the writer is still making real
    /// transport progress. The writer must therefore report actual socket
    /// writes/flushes into the same idle state that guards client reads.
    pub fn idle_state(&self) -> Arc<Mutex<IdleState>> {
        Arc::clone(&self.idle)
    }
}

impl<R> AsyncRead for SplitIo<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut this.read).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().len() > before {
                    idle_progress(&this.idle);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if !this.tunnel.load(Ordering::Acquire) && idle_expired(&this.idle, context) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle client read timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<R> AsyncWrite for SplitIo<R> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.write).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    idle_progress(&this.idle);
                    this.output.produced(written);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if !this.tunnel.load(Ordering::Acquire) && idle_expired(&this.idle, context) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle client write timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.write).poll_flush(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if !this.tunnel.load(Ordering::Acquire) && idle_expired(&this.idle, context) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle client flush timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(context)
    }
}

fn idle_progress(idle: &Mutex<IdleState>) {
    if let Ok(mut idle) = idle.lock() {
        idle.progress();
    }
}

fn idle_expired(idle: &Mutex<IdleState>, context: &mut Context<'_>) -> bool {
    idle.lock()
        .map(|mut idle| idle.poll_expired(context).is_ready())
        .unwrap_or(false)
}

/// Single owner of the client write half.
///
/// Interim heads are biased ahead of hyper's final bytes. The duplex bridge
/// bounds queued body bytes; `write_all` gives backpressure to hyper.
#[allow(clippy::too_many_arguments)]
pub async fn writer_loop<W>(
    mut socket: W,
    mut hyper_output: DuplexStream,
    mut interim: mpsc::Receiver<Bytes>,
    idle_timeout: Duration,
    idle: Arc<Mutex<IdleState>>,
    output: Arc<ConnectionOutput>,
    tunnel: Arc<AtomicBool>,
    progress: Arc<TunnelProgress>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut interim_open = true;
    loop {
        tokio::select! {
            biased;
            maybe_interim = interim.recv(), if interim_open => {
                match maybe_interim {
                    Some(bytes) => {
                        write_all_bounded(&mut socket, &bytes, idle_timeout, &idle, &tunnel, &progress).await?;
                        flush_bounded(&mut socket, idle_timeout, &idle, &tunnel).await?;
                        output.flushed();
                    }
                    None => interim_open = false,
                }
            }
            read = tokio::io::AsyncReadExt::read(&mut hyper_output, &mut buffer) => {
                let read = read?;
                if read == 0 {
                    break;
                }
                write_all_bounded(&mut socket, &buffer[..read], idle_timeout, &idle, &tunnel, &progress).await?;
                flush_bounded(&mut socket, idle_timeout, &idle, &tunnel).await?;
                output.consumed(read);
                output.flushed();
            }
        }
    }
    let _ = flush_bounded(&mut socket, idle_timeout, &idle, &tunnel).await;
    if tunnel.load(Ordering::Acquire) {
        let _ = socket.shutdown().await;
    } else {
        let _ = tokio::time::timeout(idle_timeout, socket.shutdown()).await;
    }
    Ok(())
}

async fn write_all_bounded<W>(
    socket: &mut W,
    bytes: &[u8],
    idle_timeout: Duration,
    idle: &Mutex<IdleState>,
    tunnel: &AtomicBool,
    progress: &TunnelProgress,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut written = 0;
    while written < bytes.len() {
        let count = if tunnel.load(Ordering::Acquire) {
            let count = socket.write(&bytes[written..]).await?;
            if count > 0 {
                progress.hit();
            }
            count
        } else {
            match tokio::time::timeout(idle_timeout, socket.write(&bytes[written..])).await {
                Ok(Ok(count)) => count,
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle client write timeout",
                    ));
                }
            }
        };
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "client socket stopped accepting bytes",
            ));
        }
        idle_progress(idle);
        written += count;
    }
    Ok(())
}

async fn flush_bounded<W>(
    socket: &mut W,
    idle_timeout: Duration,
    idle: &Mutex<IdleState>,
    tunnel: &AtomicBool,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if tunnel.load(Ordering::Acquire) {
        socket.flush().await
    } else {
        match tokio::time::timeout(idle_timeout, socket.flush()).await {
            Ok(result) => {
                if result.is_ok() {
                    idle_progress(idle);
                }
                result
            }
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "idle client flush timeout",
            )),
        }
    }
}
