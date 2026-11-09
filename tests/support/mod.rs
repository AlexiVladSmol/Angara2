#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use angara::config::Config;
use angara::resolver::{ResolveError, ResolveFuture, Resolver};
use angara::transport::{DialError, DialFuture, Dialer, TcpDialer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

pub fn base_config() -> String {
    r#"
schema_version = 1

[runtime]
worker_threads = 2

[limits]
max_connections = 256
max_header_bytes = 32768
header_read_timeout_ms = 10000
idle_timeout_ms = 60000
shutdown_timeout_ms = 10000

[[listeners]]
id = "lab"
bind = "127.0.0.1:3128"
transport = "http"
"#
    .to_owned()
}

pub fn allow_loopback_access() -> &'static str {
    r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow-all"
action = "allow"

[[access.ip_rules]]
id = "allow-loopback"
action = "allow"
networks = ["127.0.0.0/8", "::1/128"]
allow_special = true
"#
}

pub fn system_egress() -> &'static str {
    r#"
[[egress]]
id = "system"
mode = "system"

[routing]
default_egress = "system"
"#
}

pub fn config(extra: &str) -> Config {
    Config::parse(&format!("{}{extra}", base_config())).expect("valid outbound config")
}

pub struct ScriptedResolver {
    answers: Answers,
    calls: Arc<AtomicUsize>,
    hosts: Arc<Mutex<Vec<String>>>,
}

type Answer = Result<Vec<IpAddr>, ResolveError>;
type Answers = Arc<Mutex<VecDeque<Answer>>>;

impl ScriptedResolver {
    pub fn new(answers: Vec<Result<Vec<IpAddr>, ResolveError>>) -> Self {
        Self {
            answers: Arc::new(Mutex::new(answers.into())),
            calls: Arc::new(AtomicUsize::new(0)),
            hosts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn hosts(&self) -> Vec<String> {
        self.hosts.lock().expect("hosts mutex").clone()
    }
}

impl Resolver for ScriptedResolver {
    fn resolve<'a>(&'a self, host: &'a str, _deadline: Instant) -> ResolveFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.hosts
                .lock()
                .expect("hosts mutex")
                .push(host.to_owned());
            self.answers
                .lock()
                .expect("answers mutex")
                .pop_front()
                .unwrap_or(Err(ResolveError::Failed))
        })
    }
}

pub struct RecordingDialer {
    attempts: Arc<Mutex<Vec<(SocketAddr, String)>>>,
    outcome: DialError,
}

impl RecordingDialer {
    pub fn new(outcome: DialError) -> Self {
        Self {
            attempts: Arc::new(Mutex::new(Vec::new())),
            outcome,
        }
    }

    pub fn attempts(&self) -> Vec<(SocketAddr, String)> {
        self.attempts.lock().expect("attempts mutex").clone()
    }
}

impl Dialer for RecordingDialer {
    fn connect<'a>(
        &'a self,
        endpoint: SocketAddr,
        egress: &'a angara::config::EgressProfile,
        _deadline: Instant,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            self.attempts
                .lock()
                .expect("attempts mutex")
                .push((endpoint, egress.id().to_owned()));
            Err(self.outcome)
        })
    }
}

pub struct GatedDialer {
    started: Arc<Notify>,
    release: Arc<Notify>,
    attempts: Arc<AtomicUsize>,
}

impl GatedDialer {
    pub fn new() -> Self {
        Self {
            started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            attempts: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn started(&self) -> Arc<Notify> {
        Arc::clone(&self.started)
    }

    pub fn release(&self) -> Arc<Notify> {
        Arc::clone(&self.release)
    }

    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl Dialer for GatedDialer {
    fn connect<'a>(
        &'a self,
        _endpoint: SocketAddr,
        _egress: &'a angara::config::EgressProfile,
        _deadline: Instant,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            self.release.notified().await;
            Err(DialError::ConnectFailed)
        })
    }
}

pub struct LateSuccessDialer {
    delay: Duration,
}

impl LateSuccessDialer {
    pub fn new(delay: Duration) -> Self {
        Self { delay }
    }
}

impl Dialer for LateSuccessDialer {
    fn connect<'a>(
        &'a self,
        endpoint: SocketAddr,
        egress: &'a angara::config::EgressProfile,
        deadline: Instant,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            let stream = TcpDialer.connect(endpoint, egress, deadline).await?;
            tokio::time::sleep(self.delay).await;
            Ok(stream)
        })
    }
}

pub struct DelayedDialer {
    attempts: Arc<AtomicUsize>,
}

impl DelayedDialer {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl Dialer for DelayedDialer {
    fn connect<'a>(
        &'a self,
        _endpoint: SocketAddr,
        _egress: &'a angara::config::EgressProfile,
        deadline: Instant,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !remaining.is_zero() {
                tokio::time::sleep(remaining + Duration::from_millis(1)).await;
            }
            Err(DialError::ConnectTimeout)
        })
    }
}

pub async fn spawn_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind echo");
    let address = listener.local_addr().expect("local address");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4];
                if stream.read_exact(&mut buffer).await.is_ok() {
                    let _ = stream.write_all(b"pong").await;
                }
            });
        }
    });
    (address, handle)
}

pub async fn spawn_echo_with_peers() -> (
    SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<IpAddr>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind echo");
    let address = listener.local_addr().expect("local address");
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, peer)) = listener.accept().await else {
                break;
            };
            let _ = sender.send(peer.ip());
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4];
                if stream.read_exact(&mut buffer).await.is_ok() {
                    let _ = stream.write_all(b"pong").await;
                }
            });
        }
    });
    (address, receiver, handle)
}

pub async fn echo_roundtrip<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(b"ping").await.expect("write ping");
    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await.expect("read pong");
    assert_eq!(&response, b"pong");
}
