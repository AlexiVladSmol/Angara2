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

use crate::outbound::Connected;

const RELAY_BUFFER_BYTES: usize = 16 * 1024;

/// CONNECT handoff state produced before the 200 response.
pub(crate) struct TunnelSetup {
    pub(crate) on_upgrade: OnUpgrade,
    pub(crate) origin: Connected,
    pub(crate) deadline: Instant,
}

/// How a tunnel session ended.
pub(crate) enum TunnelEnd {
    /// Both directions reached EOF and shut down their write halves.
    Complete,
    /// No byte progress was observed in either direction before the idle limit.
    Idle,
    /// The first EOF was not followed by completion within the drain deadline.
    HalfCloseTimeout,
    /// A socket read/write failed or was reset.
    Io,
}

pub(crate) async fn run(
    client: TokioIo<Upgraded>,
    origin: Connected,
    idle_timeout: Duration,
    half_close_timeout: Duration,
) -> TunnelEnd {
    let (client_read, client_write) = tokio::io::split(client);
    let (origin_read, origin_write) = tokio::io::split(origin);

    let progress = Arc::new(Progress::new());
    let state = Arc::new(CopyState::new());
    let mut client_to_origin = Box::pin(copy_direction(
        client_read,
        origin_write,
        Arc::clone(&progress),
        Arc::clone(&state),
    ));
    let mut origin_to_client = Box::pin(copy_direction(
        origin_read,
        client_write,
        Arc::clone(&progress),
        Arc::clone(&state),
    ));
    let idle = wait_idle(Arc::clone(&progress), idle_timeout);
    tokio::pin!(idle);
    let drain = wait_drain(state, half_close_timeout);
    tokio::pin!(drain);

    let mut client_done = false;
    let mut origin_done = false;
    loop {
        tokio::select! {
            _ = &mut idle => return TunnelEnd::Idle,
            _ = &mut drain => return TunnelEnd::HalfCloseTimeout,
            result = &mut client_to_origin, if !client_done => {
                client_done = true;
                if let Err(_error) = result {
                    return TunnelEnd::Io;
                }
            }
            result = &mut origin_to_client, if !origin_done => {
                origin_done = true;
                if let Err(_error) = result {
                    return TunnelEnd::Io;
                }
            }
        }
        if client_done && origin_done {
            return TunnelEnd::Complete;
        }
    }
}

async fn copy_direction<R, W>(
    mut reader: ReadHalf<R>,
    mut writer: WriteHalf<W>,
    progress: Arc<Progress>,
    state: Arc<CopyState>,
) -> io::Result<()>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    let mut buffer = [0_u8; RELAY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            state.mark_eof();
            writer.shutdown().await?;
            return Ok(());
        }
        progress.hit();
        writer.write_all(&buffer[..read]).await?;
        progress.hit();
    }
}

async fn wait_idle(progress: Arc<Progress>, idle: Duration) {
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

struct Progress {
    sequence: AtomicU64,
    notify: Notify,
}

impl Progress {
    fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    fn hit(&self) {
        self.sequence.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_one();
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
}
