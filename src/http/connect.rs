//! CONNECT tunnel relay with bounded buffers, shared progress and half-close.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::http::parent_client::BoxedIo;
use crate::logging::{Event, LogRecord, Logger, Outcome, Reason, RouteKind};
use crate::telemetry::Telemetry;

const RELAY_BUFFER_BYTES: usize = 16 * 1024;

/// CONNECT handoff state produced before the 200 response.
pub(crate) struct TunnelSetup {
    pub(crate) on_upgrade: OnUpgrade,
    pub(crate) origin: BoxedIo,
    pub(crate) origin_tls: bool,
    pub(crate) deadline: Instant,
    pub(crate) idle_timeout: Duration,
    pub(crate) half_close_timeout: Duration,
    pub(crate) gauge: TunnelGauge,
}

/// RAII CONNECT lifecycle accounting. `finish` records the observed end
/// reason; dropping without an explicit finish records a cancellation.
pub(crate) struct TunnelGauge {
    telemetry: Arc<Telemetry>,
    logger: Logger,
    generation: u64,
    connection_id: u64,
    parent_id: Option<String>,
    route: RouteKind,
    progress: Option<Arc<TunnelProgress>>,
    finished: bool,
}

impl TunnelGauge {
    pub(crate) fn new(
        telemetry: Arc<Telemetry>,
        logger: Logger,
        generation: u64,
        connection_id: u64,
        parent_id: Option<String>,
        route: RouteKind,
    ) -> Self {
        telemetry.connect_active.fetch_add(1, Ordering::AcqRel);
        Self {
            telemetry,
            logger,
            generation,
            connection_id,
            parent_id,
            route,
            progress: None,
            finished: false,
        }
    }

    pub(crate) fn attach_progress(&mut self, progress: Arc<TunnelProgress>) {
        self.progress = Some(progress);
    }

    pub(crate) fn finish(&mut self, end: &TunnelEnd) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.telemetry.connect_active.fetch_sub(1, Ordering::AcqRel);
        self.telemetry
            .connect_finished
            .fetch_add(1, Ordering::Relaxed);
        let (outcome, reason) = match end {
            TunnelEnd::Complete { .. } => {
                self.telemetry
                    .connect_complete
                    .fetch_add(1, Ordering::Relaxed);
                (Outcome::Success, Reason::Completed)
            }
            TunnelEnd::Idle => {
                self.telemetry.connect_idle.fetch_add(1, Ordering::Relaxed);
                (Outcome::Cancelled, Reason::Idle)
            }
            TunnelEnd::HalfCloseTimeout => {
                self.telemetry
                    .connect_timeout
                    .fetch_add(1, Ordering::Relaxed);
                (Outcome::Failed, Reason::Timeout)
            }
            TunnelEnd::Io => {
                self.telemetry.connect_error.fetch_add(1, Ordering::Relaxed);
                (Outcome::Failed, Reason::Error)
            }
            TunnelEnd::Cancelled => {
                self.telemetry
                    .connect_cancelled
                    .fetch_add(1, Ordering::Relaxed);
                (Outcome::Cancelled, Reason::Shutdown)
            }
        };
        let mut record = LogRecord::new(Event::TunnelFinished);
        record.outcome = Some(outcome);
        record.reason = Some(reason);
        record.generation = Some(self.generation);
        record.connection_id = Some(self.connection_id);
        record.parent_id = self.parent_id.clone();
        record.route = Some(self.route);
        record.tunnel_bytes = Some(
            self.progress
                .as_ref()
                .map(|progress| progress.total_bytes())
                .unwrap_or(0),
        );
        self.logger.log(record);
    }
}

impl Drop for TunnelGauge {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(&TunnelEnd::Cancelled);
        }
    }
}

/// How a tunnel session ended.
pub(crate) enum TunnelEnd {
    /// Both directions reached EOF and shut down their write halves. The
    /// optional deadline is the absolute first-EOF drain deadline, which still
    /// applies to the final bridge/socket writer drain.
    Complete { drain_deadline: Option<Instant> },
    /// No byte progress was observed in either direction before the idle limit.
    Idle,
    /// The first EOF was not followed by completion within the drain deadline.
    HalfCloseTimeout,
    /// A socket read/write failed or was reset.
    Io,
    /// The service was forced down before the tunnel could reach a normal end.
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    ClientToOrigin,
    OriginToClient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Read,
    Shutdown,
    Write,
}

struct CopyError {
    direction: Direction,
    operation: Operation,
    source: io::Error,
}

impl CopyError {
    fn new(direction: Direction, operation: Operation, source: io::Error) -> Self {
        Self {
            direction,
            operation,
            source,
        }
    }

    /// A TLS parent may close its read side without sending close_notify after
    /// the client has already ended its write side. The byte stream is complete
    /// at that point; the shutdown error is only the peer's half-close.
    fn is_tls_parent_shutdown(&self) -> bool {
        self.direction == Direction::ClientToOrigin
            && self.operation == Operation::Shutdown
            && matches!(
                self.source.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::UnexpectedEof
            )
    }

    /// Missing close_notify from a TLS parent is treated as EOF only after the
    /// client has finished its own direction. A reset before that point remains
    /// a failure.
    fn is_tls_parent_eof(&self, client_done: bool) -> bool {
        client_done
            && self.direction == Direction::OriginToClient
            && self.operation == Operation::Read
            && self.source.kind() == io::ErrorKind::UnexpectedEof
    }
}

pub(crate) async fn run(
    client: TokioIo<Upgraded>,
    origin: BoxedIo,
    origin_tls: bool,
    idle_timeout: Duration,
    half_close_timeout: Duration,
    progress: Arc<TunnelProgress>,
) -> TunnelEnd {
    let (client_read, client_write) = tokio::io::split(client);
    let (origin_read, origin_write) = tokio::io::split(origin);

    let state = Arc::new(CopyState::new());
    let mut client_to_origin = Box::pin(copy_direction(
        client_read,
        origin_write,
        Arc::clone(&progress),
        Arc::clone(&state),
        Direction::ClientToOrigin,
    ));
    let mut origin_to_client = Box::pin(copy_direction(
        origin_read,
        client_write,
        Arc::clone(&progress),
        Arc::clone(&state),
        Direction::OriginToClient,
    ));
    let idle = wait_idle(Arc::clone(&progress), idle_timeout);
    tokio::pin!(idle);
    let drain = wait_drain(Arc::clone(&state), half_close_timeout);
    tokio::pin!(drain);

    let mut client_done = false;
    let mut origin_done = false;
    loop {
        tokio::select! {
            biased;
            result = &mut client_to_origin, if !client_done => {
                client_done = true;
                if let Err(error) = result
                    && !(origin_tls && error.is_tls_parent_shutdown())
                {
                    return TunnelEnd::Io;
                }
            }
            result = &mut origin_to_client, if !origin_done => {
                origin_done = true;
                if let Err(error) = result
                    && !(origin_tls && error.is_tls_parent_eof(client_done))
                {
                    return TunnelEnd::Io;
                }
            }
            _ = &mut idle => return TunnelEnd::Idle,
            _ = &mut drain => return TunnelEnd::HalfCloseTimeout,
        }
        if client_done && origin_done {
            let drain_deadline = state.first_eof().map(|first| first + half_close_timeout);
            return TunnelEnd::Complete { drain_deadline };
        }
    }
}

async fn copy_direction<R, W>(
    mut reader: ReadHalf<R>,
    mut writer: WriteHalf<W>,
    progress: Arc<TunnelProgress>,
    state: Arc<CopyState>,
    direction: Direction,
) -> Result<(), CopyError>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    let mut buffer = [0_u8; RELAY_BUFFER_BYTES];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|source| CopyError::new(direction, Operation::Read, source))?;
        if read == 0 {
            state.mark_eof();
            writer
                .shutdown()
                .await
                .map_err(|source| CopyError::new(direction, Operation::Shutdown, source))?;
            return Ok(());
        }
        progress.add_bytes(read as u64);
        write_all_progress(&mut writer, &buffer[..read], &progress)
            .await
            .map_err(|source| CopyError::new(direction, Operation::Write, source))?;
    }
}

async fn write_all_progress<W>(
    writer: &mut W,
    mut bytes: &[u8],
    progress: &TunnelProgress,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while !bytes.is_empty() {
        let written = writer.write(bytes).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "tunnel peer stopped accepting bytes",
            ));
        }
        progress.hit();
        bytes = &bytes[written..];
    }
    Ok(())
}

async fn wait_idle(progress: Arc<TunnelProgress>, idle: Duration) {
    loop {
        let observed = progress.sequence.load(Ordering::Relaxed);
        let notified = progress.notify.notified();
        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep(idle) => {
                if progress.sequence.load(Ordering::Relaxed) == observed {
                    return;
                }
            }
        }
    }
}

async fn wait_drain(state: Arc<CopyState>, half_close_timeout: Duration) {
    let first = {
        let first_eof = state.first_eof.lock().expect("tunnel EOF state");
        *first_eof
    };
    let first = match first {
        Some(first) => first,
        None => {
            state.notify.notified().await;
            state
                .first_eof
                .lock()
                .expect("tunnel EOF state")
                .expect("EOF notification without state")
        }
    };
    tokio::time::sleep_until(first + half_close_timeout).await;
}

/// Shared tunnel byte-progress notifier.
#[doc(hidden)]
pub struct TunnelProgress {
    sequence: AtomicU64,
    bytes: AtomicU64,
    notify: Notify,
}

impl TunnelProgress {
    /// Creates a progress tracker.
    #[doc(hidden)]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sequence: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            notify: Notify::new(),
        })
    }

    pub(crate) fn hit(&self) {
        self.sequence.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_one();
    }

    pub(crate) fn add_bytes(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.hit();
    }

    /// Observed plaintext bytes across both directions.
    pub fn total_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

struct CopyState {
    first_eof: Mutex<Option<Instant>>,
    notify: Notify,
}

impl CopyState {
    fn new() -> Self {
        Self {
            first_eof: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    fn mark_eof(&self) {
        let first = {
            let mut first_eof = self.first_eof.lock().expect("tunnel EOF state");
            if first_eof.is_some() {
                false
            } else {
                *first_eof = Some(Instant::now());
                true
            }
        };
        if first {
            self.notify.notify_one();
        }
    }

    fn first_eof(&self) -> Option<Instant> {
        *self.first_eof.lock().expect("tunnel EOF state")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct ChunkWriter {
        max: usize,
    }

    impl AsyncWrite for ChunkWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buffer.len().min(self.max)))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn partial_writes_count_as_progress() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let progress = TunnelProgress::new();
            let mut writer = ChunkWriter { max: 3 };
            write_all_progress(&mut writer, &[1_u8; 10], &progress)
                .await
                .expect("write");
            assert_eq!(progress.sequence.load(Ordering::Relaxed), 4);
        });
    }

    #[test]
    fn idle_deadline_resets_on_partial_progress() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let progress = TunnelProgress::new();
            let waiter = tokio::spawn(wait_idle(Arc::clone(&progress), Duration::from_millis(300)));
            for _ in 0..5 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                progress.hit();
            }
            assert!(!waiter.is_finished(), "idle fired despite progress");
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(
                waiter.await.is_ok(),
                "idle did not fire after progress stopped"
            );
        });
    }
}
