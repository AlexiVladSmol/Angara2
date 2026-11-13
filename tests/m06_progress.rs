//! M06 transport-progress regression tests.
//!
//! These exercise the production writer against a real TLS1.3 handshake whose
//! underlying ciphertext transport accepts only small chunks at a fixed rate.

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use angara::http::ConnectionOutput;
use angara::http::connect::TunnelProgress;
use angara::http::idle::IdleState;
use angara::http::interim::{TransportProgress, writer_loop};
use common::m06;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep, sleep};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Throttled transport: accepts at most `chunk` ciphertext bytes every
/// `interval`, starting no earlier than one interval after the previous write.
struct SlowWriter<T> {
    inner: T,
    chunk: usize,
    interval: Duration,
    next: std::pin::Pin<Box<Sleep>>,
    stall_after: Arc<AtomicUsize>,
}

impl<T> SlowWriter<T> {
    fn new(inner: T, chunk: usize, interval: Duration, stall_after: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            chunk,
            interval,
            next: Box::pin(sleep(interval)),
            stall_after,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SlowWriter<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SlowWriter<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.stall_after.load(Ordering::Acquire) == 0 {
            return std::task::Poll::Pending;
        }
        if this.next.as_mut().poll(context).is_pending() {
            return std::task::Poll::Pending;
        }
        let length = buffer.len().min(this.chunk);
        match std::pin::Pin::new(&mut this.inner).poll_write(context, &buffer[..length]) {
            std::task::Poll::Ready(Ok(written)) => {
                if written > 0 {
                    let remaining = this.stall_after.load(Ordering::Acquire);
                    if remaining != usize::MAX {
                        this.stall_after
                            .store(remaining.saturating_sub(1), Ordering::Release);
                    }
                    this.next.as_mut().reset(Instant::now() + this.interval);
                }
                std::task::Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

struct TlsPair {
    server: tokio_rustls::server::TlsStream<
        angara::http::interim::ObservedIo<SlowWriter<DuplexStream>>,
    >,
    client: tokio_rustls::client::TlsStream<DuplexStream>,
    observer: Arc<TransportProgress>,
    idle: Arc<Mutex<IdleState>>,
    tunnel: Arc<TunnelProgress>,
    stall_after: Arc<AtomicUsize>,
}

async fn tls_pair(chunk: usize, interval: Duration, idle_ms: u64) -> TlsPair {
    let dir = common::TempDir::new("m06-progress");
    m06::generate_pki(dir.path());
    let acceptor = TlsAcceptor::from(m06::server_config(
        &dir.path().join("site_chain.pem"),
        &dir.path().join("site_key.pem"),
    ));
    let connector = TlsConnector::from(m06::client_config(&dir.path().join("site_ca.pem")));
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let idle = Arc::new(Mutex::new(IdleState::new(Duration::from_millis(idle_ms))));
    let tunnel = TunnelProgress::new();
    let observer = TransportProgress::new(Arc::clone(&idle), Arc::clone(&tunnel));
    let stall_after = Arc::new(AtomicUsize::new(usize::MAX));
    let server_io = observer.observe(SlowWriter::new(
        server_io,
        chunk,
        interval,
        Arc::clone(&stall_after),
    ));
    let server = acceptor.accept(server_io);
    let client = connector.connect(
        ServerName::try_from("localhost").expect("server name"),
        client_io,
    );
    let (server, client) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(server, client)
    })
    .await
    .expect("TLS handshake timeout");
    let server = server.expect("server handshake");
    let client = client.expect("client handshake");
    observer.reset_idle();
    TlsPair {
        server,
        client,
        observer,
        idle,
        tunnel,
        stall_after,
    }
}

#[allow(clippy::type_complexity)]
fn spawn_writer(
    pair: TlsPair,
    payload: Vec<u8>,
) -> (
    JoinHandle<std::io::Result<()>>,
    JoinHandle<std::io::Result<Vec<u8>>>,
    JoinHandle<std::io::Result<()>>,
) {
    let TlsPair {
        server,
        client,
        observer,
        idle,
        tunnel,
        stall_after: _,
    } = pair;
    let (read_half, write_half) = tokio::io::split(server);
    drop(read_half);
    let (mut bridge_writer, bridge_reader) = tokio::io::duplex(64 * 1024);
    let (interim_tx, interim_rx) = tokio::sync::mpsc::channel(1);
    drop(interim_tx);
    let output = ConnectionOutput::new();
    let tunnel_flag = Arc::new(AtomicBool::new(false));
    let writer = tokio::spawn(async move {
        writer_loop(
            write_half,
            bridge_reader,
            interim_rx,
            Duration::from_millis(1000),
            idle,
            Some(observer),
            output,
            tunnel_flag,
            tunnel,
        )
        .await
    });
    let feeder = tokio::spawn(async move {
        bridge_writer.write_all(&payload).await?;
        bridge_writer.shutdown().await
    });
    let mut client = client;
    let reader = tokio::spawn(async move {
        let mut received = Vec::new();
        client.read_to_end(&mut received).await?;
        Ok(received)
    });
    (writer, reader, feeder)
}

#[tokio::test]
async fn m06_r1_partial_ciphertext_progress_survives_pending_flush() {
    // 16 KiB at 256 bytes / 20 ms takes ~1.28 s, longer than the 1 s idle.
    let pair = tls_pair(256, Duration::from_millis(20), 1000).await;
    let payload = vec![0x5a; 16 * 1024];
    let started = Instant::now();
    let (writer, reader, feeder) = spawn_writer(pair, payload.clone());
    let writer_result = tokio::time::timeout(Duration::from_secs(10), writer)
        .await
        .expect("writer timeout")
        .expect("writer join");
    let received = tokio::time::timeout(Duration::from_secs(10), reader)
        .await
        .expect("reader timeout")
        .expect("reader join")
        .expect("client TLS read");
    assert!(
        writer_result.is_ok(),
        "writer failed despite positive ciphertext progress: {writer_result:?}"
    );
    assert_eq!(received, payload);
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "test did not exercise a pending encrypted flush: {:?}",
        started.elapsed()
    );
    eprintln!(
        "M06-R1 partial_progress elapsed_ms={} bytes={}",
        started.elapsed().as_millis(),
        received.len()
    );
    feeder.abort();
}

#[tokio::test]
async fn m06_r1_stalled_ciphertext_flush_is_bounded() {
    let pair = tls_pair(4096, Duration::from_millis(1), 1000).await;
    let (read_half, write_half) = tokio::io::split(pair.server);
    drop(read_half);
    let (mut bridge_writer, bridge_reader) = tokio::io::duplex(64 * 1024);
    let (interim_tx, interim_rx) = tokio::sync::mpsc::channel(1);
    drop(interim_tx);
    let output = ConnectionOutput::new();
    let tunnel = Arc::new(AtomicBool::new(false));
    let observer = Arc::clone(&pair.observer);
    let idle = Arc::clone(&pair.idle);
    let progress = Arc::clone(&pair.tunnel);
    let writer = tokio::spawn(async move {
        writer_loop(
            write_half,
            bridge_reader,
            interim_rx,
            Duration::from_millis(1000),
            idle,
            Some(observer),
            output,
            tunnel,
            progress,
        )
        .await
    });
    // Keep the client TLS stream alive but stop reading. A payload larger
    // than the duplex/TLS buffers guarantees a pending flush.
    let _client = pair.client;
    let started = Instant::now();
    let feeder = tokio::spawn(async move {
        let _ = bridge_writer.write_all(&vec![0x33; 256 * 1024]).await;
        let _ = bridge_writer.shutdown().await;
    });
    let result = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("stalled writer did not return")
        .expect("writer join");
    assert!(
        matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::TimedOut),
        "stalled transport was not bounded: {result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "stalled transport exceeded its bound: {:?}",
        started.elapsed()
    );
    feeder.abort();
}

#[tokio::test]
async fn m06_r1_early_progress_then_stall_uses_last_wire_progress() {
    let pair = tls_pair(256, Duration::from_millis(20), 1000).await;
    pair.stall_after.store(1, Ordering::SeqCst);
    let observer = Arc::clone(&pair.observer);
    let writer_observer = Arc::clone(&observer);
    let (read_half, write_half) = tokio::io::split(pair.server);
    drop(read_half);
    let (mut bridge_writer, bridge_reader) = tokio::io::duplex(64 * 1024);
    let (interim_tx, interim_rx) = tokio::sync::mpsc::channel(1);
    drop(interim_tx);
    let output = ConnectionOutput::new();
    let tunnel = Arc::new(AtomicBool::new(false));
    let idle = pair.idle;
    let progress = pair.tunnel;
    let _client = pair.client;
    let writer = tokio::spawn(async move {
        writer_loop(
            write_half,
            bridge_reader,
            interim_rx,
            Duration::from_millis(1000),
            idle,
            Some(writer_observer),
            output,
            tunnel,
            progress,
        )
        .await
    });
    let started = Instant::now();
    let feeder = tokio::spawn(async move {
        let _ = bridge_writer.write_all(&vec![0x44; 16 * 1024]).await;
        let _ = bridge_writer.shutdown().await;
    });
    let result = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("stalled writer did not return")
        .expect("writer join");
    assert!(
        matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::TimedOut),
        "early progress followed by stall was not bounded: {result:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "stall fired before the last real write deadline: {:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_millis(1600),
        "stall got a fresh idle window after the early write: {:?}",
        started.elapsed()
    );
    assert!(
        observer.epoch() >= 1,
        "test never observed the early transport write"
    );
    eprintln!(
        "M06-R1 early_progress_stall elapsed_ms={} epoch={}",
        started.elapsed().as_millis(),
        observer.epoch()
    );
    feeder.abort();
}

#[tokio::test]
async fn m06_r1_control_only_writes_do_not_advance_progress() {
    let idle = Arc::new(Mutex::new(IdleState::new(Duration::from_millis(1000))));
    let tunnel = TunnelProgress::new();
    let observer = TransportProgress::new(Arc::clone(&idle), tunnel);
    let mut io = observer.observe(tokio::io::sink());
    io.write_all(b"control-unarmed").await.expect("write");
    assert_eq!(observer.epoch(), 0, "disarmed control bytes counted");
    observer.arm();
    io.write_all(b"application-armed").await.expect("write");
    assert_eq!(observer.epoch(), 1, "armed application write not counted");
    observer.disarm();
    io.write_all(b"control-after").await.expect("write");
    assert_eq!(observer.epoch(), 1, "disarmed bytes counted");
}
