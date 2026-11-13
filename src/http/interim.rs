//! Narrow bounded writer adapter for informational responses.
//!
//! Hyper's server API returns one final response. Interim heads are serialized
//! from typed `http` status/header values and queued to the single writer that
//! owns the client socket half. Hyper still parses and frames every HTTP
//! message; this adapter only orders bounded interim heads before the final
//! response.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
        Self::with_tunnel_flag_and_idle(
            stream,
            Arc::new(Mutex::new(IdleState::new(idle_timeout))),
            output,
            tunnel,
        )
    }

    /// Creates the combined IO with shared idle state and tunnel flag.
    pub fn with_tunnel_flag_and_idle(
        stream: R,
        idle: Arc<Mutex<IdleState>>,
        output: Arc<ConnectionOutput>,
        tunnel: Arc<AtomicBool>,
    ) -> (Self, WriteHalf<R>, DuplexStream) {
        let (read, write) = tokio::io::split(stream);
        let (bridge_writer, bridge_reader) = tokio::io::duplex(64 * 1024);
        (
            Self {
                read,
                write: bridge_writer,
                idle,
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

/// Bounded transport progress observer for pending application output.
///
/// The writer arms this observer immediately before writing/flushing
/// application bytes and disarms it afterwards. Positive ciphertext writes to
/// the underlying transport then count as progress for HTTP idle and CONNECT
/// relay limits. Handshake/control records or idle polls are not counted.
#[doc(hidden)]
pub struct TransportProgress {
    armed: AtomicBool,
    epoch: AtomicU64,
    last: Mutex<tokio::time::Instant>,
    idle: Arc<Mutex<IdleState>>,
    tunnel: Arc<TunnelProgress>,
}

impl TransportProgress {
    /// Creates an observer bound to the connection idle and tunnel progress.
    #[doc(hidden)]
    pub fn new(idle: Arc<Mutex<IdleState>>, tunnel: Arc<TunnelProgress>) -> Arc<Self> {
        Arc::new(Self {
            armed: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            last: Mutex::new(tokio::time::Instant::now()),
            idle,
            tunnel,
        })
    }

    /// Wraps a transport so ciphertext writes are observed.
    #[doc(hidden)]
    pub fn observe<T>(self: &Arc<Self>, inner: T) -> ObservedIo<T> {
        ObservedIo {
            inner,
            progress: Arc::clone(self),
        }
    }

    /// Shared connection idle state.
    #[doc(hidden)]
    pub fn idle_state(&self) -> Arc<Mutex<IdleState>> {
        Arc::clone(&self.idle)
    }

    /// Shared CONNECT relay progress.
    #[doc(hidden)]
    pub fn tunnel_progress(&self) -> Arc<TunnelProgress> {
        Arc::clone(&self.tunnel)
    }

    /// Enables progress observation for pending application output.
    #[doc(hidden)]
    pub fn arm(&self) {
        self.last
            .lock()
            .map(|mut last| *last = tokio::time::Instant::now())
            .ok();
        self.armed.store(true, Ordering::Release);
    }

    /// Disables progress observation after application output is flushed.
    #[doc(hidden)]
    pub fn disarm(&self) {
        self.armed.store(false, Ordering::Release);
    }

    /// Starts connection idle clocks after a TLS handshake.
    #[doc(hidden)]
    pub fn reset_idle(&self) {
        idle_progress(&self.idle);
    }

    /// Monotonic count of observed positive transport writes.
    #[doc(hidden)]
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// Time of the last actual positive transport write.
    fn last_progress(&self) -> tokio::time::Instant {
        match self.last.lock() {
            Ok(last) => *last,
            Err(poison) => *poison.into_inner(),
        }
    }

    fn record(&self) {
        if self.armed.load(Ordering::Acquire) {
            self.epoch.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut last) = self.last.lock() {
                *last = tokio::time::Instant::now();
            }
            idle_progress(&self.idle);
            self.tunnel.hit();
        }
    }
}

/// A transport wrapper that reports positive ciphertext writes.
#[doc(hidden)]
pub struct ObservedIo<T> {
    inner: T,
    progress: Arc<TransportProgress>,
}

impl<T> ObservedIo<T> {
    /// Creates an observed transport.
    #[doc(hidden)]
    pub fn new(inner: T, progress: Arc<TransportProgress>) -> Self {
        Self { inner, progress }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.progress.record();
                }
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

/// Bounds a wait by absence of observed transport progress.
async fn stall_bounded<F, T>(
    future: F,
    idle_timeout: Duration,
    progress: Option<&TransportProgress>,
) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    let Some(progress) = progress else {
        return match tokio::time::timeout(idle_timeout, future).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "idle client transport timeout",
            )),
        };
    };
    let mut future = std::pin::pin!(future);
    loop {
        let last = progress.last_progress();
        let deadline = last + idle_timeout;
        tokio::select! {
            biased;
            result = &mut future => return result,
            _ = tokio::time::sleep_until(deadline) => {
                if progress.last_progress() <= last {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle client transport timeout",
                    ));
                }
            }
        }
    }
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
    observer: Option<Arc<TransportProgress>>,
    output: Arc<ConnectionOutput>,
    tunnel: Arc<AtomicBool>,
    progress: Arc<TunnelProgress>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let observer = observer.as_deref();
    let mut buffer = [0_u8; 16 * 1024];
    let mut interim_open = true;
    loop {
        tokio::select! {
            biased;
            maybe_interim = interim.recv(), if interim_open => {
                match maybe_interim {
                    Some(bytes) => {
                        write_and_flush(&mut socket, &bytes, idle_timeout, &idle, &tunnel, &progress, observer).await?;
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
                write_and_flush(&mut socket, &buffer[..read], idle_timeout, &idle, &tunnel, &progress, observer).await?;
                output.consumed(read);
                output.flushed();
            }
        }
    }
    if let Some(observer) = observer {
        observer.arm();
    }
    let _ = flush_bounded(&mut socket, idle_timeout, &idle, &tunnel, observer).await;
    if let Some(observer) = observer {
        observer.disarm();
    }
    if tunnel.load(Ordering::Acquire) {
        let _ = socket.shutdown().await;
    } else {
        let _ = tokio::time::timeout(idle_timeout, socket.shutdown()).await;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn write_and_flush<W>(
    socket: &mut W,
    bytes: &[u8],
    idle_timeout: Duration,
    idle: &Mutex<IdleState>,
    tunnel: &AtomicBool,
    progress: &TunnelProgress,
    observer: Option<&TransportProgress>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if let Some(observer) = observer {
        observer.arm();
    }
    let result = async {
        write_all_bounded(
            socket,
            bytes,
            idle_timeout,
            idle,
            tunnel,
            progress,
            observer,
        )
        .await?;
        flush_bounded(socket, idle_timeout, idle, tunnel, observer).await
    }
    .await;
    if let Some(observer) = observer {
        observer.disarm();
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn write_all_bounded<W>(
    socket: &mut W,
    bytes: &[u8],
    idle_timeout: Duration,
    idle: &Mutex<IdleState>,
    tunnel: &AtomicBool,
    progress: &TunnelProgress,
    observer: Option<&TransportProgress>,
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
            stall_bounded(socket.write(&bytes[written..]), idle_timeout, observer).await?
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
    observer: Option<&TransportProgress>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if tunnel.load(Ordering::Acquire) {
        socket.flush().await
    } else {
        let result = stall_bounded(socket.flush(), idle_timeout, observer).await;
        if result.is_ok() {
            idle_progress(idle);
        }
        result
    }
}
