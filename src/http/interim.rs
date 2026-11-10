//! Narrow bounded writer adapter for informational responses.
//!
//! Hyper's server API returns one final response. Interim heads are serialized
//! from typed `http` status/header values and queued to the single writer that
//! owns the client socket half. Hyper still parses and frames every HTTP
//! message; this adapter only orders bounded interim heads before the final
//! response.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;
use http::header::HeaderMap;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

use crate::http::ConnectionOutput;
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
pub struct SplitIo {
    read: OwnedReadHalf,
    write: DuplexStream,
    idle: IdleState,
    output: Arc<ConnectionOutput>,
}

impl SplitIo {
    /// Creates the combined IO and returns the writer-loop side.
    pub fn new(
        stream: tokio::net::TcpStream,
        idle_timeout: Duration,
        output: Arc<ConnectionOutput>,
    ) -> (Self, OwnedWriteHalf, DuplexStream) {
        let (read, write) = stream.into_split();
        let (bridge_writer, bridge_reader) = tokio::io::duplex(64 * 1024);
        (
            Self {
                read,
                write: bridge_writer,
                idle: IdleState::new(idle_timeout),
                output,
            },
            write,
            bridge_reader,
        )
    }
}

impl AsyncRead for SplitIo {
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
                    this.idle.progress();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if this.idle.poll_expired(context).is_ready() {
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

impl AsyncWrite for SplitIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.write).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    this.idle.progress();
                    this.output.produced(written);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if this.idle.poll_expired(context).is_ready() {
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
            Poll::Ready(Ok(())) => {
                this.output.flushed();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if this.idle.poll_expired(context).is_ready() {
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

/// Single owner of the client write half.
///
/// Interim heads are biased ahead of hyper's final bytes. The duplex bridge
/// bounds queued body bytes; `write_all` gives backpressure to hyper.
pub async fn writer_loop(
    mut socket: OwnedWriteHalf,
    mut hyper_output: DuplexStream,
    mut interim: mpsc::Receiver<Bytes>,
    idle_timeout: Duration,
    output: Arc<ConnectionOutput>,
) -> io::Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    let mut interim_open = true;
    loop {
        tokio::select! {
            biased;
            maybe_interim = interim.recv(), if interim_open => {
                match maybe_interim {
                    Some(bytes) => {
                        write_all_bounded(&mut socket, &bytes, idle_timeout).await?;
                    }
                    None => interim_open = false,
                }
            }
            read = tokio::io::AsyncReadExt::read(&mut hyper_output, &mut buffer) => {
                let read = read?;
                if read == 0 {
                    break;
                }
                write_all_bounded(&mut socket, &buffer[..read], idle_timeout).await?;
                output.consumed(read);
            }
        }
    }
    let _ = tokio::time::timeout(idle_timeout, socket.shutdown()).await;
    Ok(())
}

async fn write_all_bounded(
    socket: &mut OwnedWriteHalf,
    bytes: &[u8],
    idle_timeout: Duration,
) -> io::Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        match tokio::time::timeout(idle_timeout, socket.write(&bytes[written..])).await {
            Ok(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "client socket stopped accepting bytes",
                ));
            }
            Ok(Ok(count)) => written += count,
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "idle client write timeout",
                ));
            }
        }
    }
    Ok(())
}
