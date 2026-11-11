//! M04 CONNECT test support: TCP echo/stream origins and raw tunnel helpers.

#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::common::m03::{IO_TIMEOUT, RawClient};

/// Bounded buffer used by test tunnels; production relay uses 16 KiB.
pub const TEST_TUNNEL_BUFFER: usize = 16 * 1024;

/// A TCP echo origin that records how many connections it accepted.
pub struct EchoOrigin {
    pub address: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    pub active: Arc<AtomicUsize>,
    pub peers: Arc<std::sync::Mutex<Vec<std::net::IpAddr>>>,
    pub received: Arc<std::sync::Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl Drop for EchoOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a TCP echo server. `greeting` is written once per connection before
/// echoing any client bytes.
pub async fn spawn_echo_origin(greeting: Option<Vec<u8>>) -> io::Result<EchoOrigin> {
    spawn_echo_origin_at("127.0.0.1:0".parse().expect("loopback"), greeting).await
}

/// Starts a TCP echo server on the requested bind address.
pub async fn spawn_echo_origin_at(
    bind: SocketAddr,
    greeting: Option<Vec<u8>>,
) -> io::Result<EchoOrigin> {
    let listener = TcpListener::bind(bind).await?;
    let address = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let peers = Arc::new(std::sync::Mutex::new(Vec::new()));
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let task_accepts = Arc::clone(&accepts);
    let task_active = Arc::clone(&active);
    let task_peers = Arc::clone(&peers);
    let task_received = Arc::clone(&received);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, peer)) = listener.accept().await else {
                return;
            };
            task_accepts.fetch_add(1, Ordering::AcqRel);
            task_active.fetch_add(1, Ordering::AcqRel);
            task_peers.lock().expect("echo peers").push(peer.ip());
            let greeting = greeting.clone();
            let received = Arc::clone(&task_received);
            let active = Arc::clone(&task_active);
            tokio::spawn(async move {
                if let Some(greeting) = greeting
                    && stream.write_all(&greeting).await.is_err()
                {
                    active.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                let mut buffer = [0_u8; TEST_TUNNEL_BUFFER];
                loop {
                    let read = match stream.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(read) => read,
                        Err(_) => break,
                    };
                    received
                        .lock()
                        .expect("echo received")
                        .extend_from_slice(&buffer[..read]);
                    if stream.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
                active.fetch_sub(1, Ordering::AcqRel);
            });
        }
    });
    Ok(EchoOrigin {
        address,
        accepts,
        active,
        peers,
        received,
        task,
    })
}

/// Sends one raw HTTP response head and optional body.
pub async fn send_raw_response(stream: &mut TcpStream, head: &str, body: &[u8]) -> io::Result<()> {
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Reads until the peer closes, returning the bytes observed.
pub async fn read_to_eof(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    stream.read_to_end(&mut output).await?;
    Ok(output)
}

/// Connects a raw client with bounded socket buffers for backpressure tests.
pub async fn connect_small_buffers(address: SocketAddr) -> io::Result<RawClient> {
    RawClient::connect_with_buffers(address, 4096).await
}

/// Waits until `condition` is true or the bounded timeout expires.
pub async fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    while !condition() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// A TCP origin that reads and discards all bytes.
pub struct SinkOrigin {
    pub address: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    pub received: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for SinkOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_sink_origin() -> io::Result<SinkOrigin> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    let task_received = Arc::clone(&received);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            task_accepts.fetch_add(1, Ordering::AcqRel);
            let received = Arc::clone(&task_received);
            tokio::spawn(async move {
                let mut buffer = [0_u8; TEST_TUNNEL_BUFFER];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            received.fetch_add(read, Ordering::AcqRel);
                        }
                    }
                }
            });
        }
    });
    Ok(SinkOrigin {
        address,
        accepts,
        received,
        task,
    })
}

/// A TCP origin that sends a fixed number of periodic chunks and closes.
pub struct PeriodicOrigin {
    pub address: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for PeriodicOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_periodic_origin(
    interval: Duration,
    chunk: Vec<u8>,
    count: usize,
) -> io::Result<PeriodicOrigin> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            task_accepts.fetch_add(1, Ordering::AcqRel);
            let chunk = chunk.clone();
            tokio::spawn(async move {
                for _ in 0..count {
                    if stream.write_all(&chunk).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(interval).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok(PeriodicOrigin {
        address,
        accepts,
        task,
    })
}

/// A TCP origin that waits for client EOF before sending its response.
pub struct EofReplyOrigin {
    pub address: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for EofReplyOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_eof_reply_origin(reply: Vec<u8>) -> io::Result<EofReplyOrigin> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            task_accepts.fetch_add(1, Ordering::AcqRel);
            let reply = reply.clone();
            tokio::spawn(async move {
                let mut buffer = [0_u8; TEST_TUNNEL_BUFFER];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
                let _ = stream.write_all(&reply).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok(EofReplyOrigin {
        address,
        accepts,
        task,
    })
}

/// A slow HTTP origin: sends final headers, waits, then sends the body.
pub struct SlowHttpOrigin {
    pub address: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for SlowHttpOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_slow_http_origin(delay: Duration) -> io::Result<SlowHttpOrigin> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            task_accepts.fetch_add(1, Ordering::AcqRel);
            let delay = delay;
            tokio::spawn(async move {
                let mut buffer = [0_u8; TEST_TUNNEL_BUFFER];
                let mut head = Vec::new();
                loop {
                    let read = match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => read,
                    };
                    head.extend_from_slice(&buffer[..read]);
                    if head.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(delay).await;
                let _ = stream.write_all(b"body").await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok(SlowHttpOrigin {
        address,
        accepts,
        task,
    })
}

/// A raw stream origin for tunnel backpressure tests.
pub struct LargeTunnelOrigin {
    pub address: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    pub active: Arc<AtomicUsize>,
    pub written: Arc<AtomicUsize>,
    pub max_written: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for LargeTunnelOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_large_tunnel_origin(total: usize) -> io::Result<LargeTunnelOrigin> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let written = Arc::new(AtomicUsize::new(0));
    let max_written = Arc::new(AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    let task_active = Arc::clone(&active);
    let task_written = Arc::clone(&written);
    let task_max = Arc::clone(&max_written);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            task_accepts.fetch_add(1, Ordering::AcqRel);
            task_active.fetch_add(1, Ordering::AcqRel);
            let active = Arc::clone(&task_active);
            let written = Arc::clone(&task_written);
            let max_written = Arc::clone(&task_max);
            tokio::spawn(async move {
                let chunk = vec![b'Z'; 64 * 1024];
                let mut sent = 0;
                while sent < total {
                    let take = chunk.len().min(total - sent);
                    if stream.write_all(&chunk[..take]).await.is_err() {
                        break;
                    }
                    sent += take;
                    written.fetch_add(take, Ordering::AcqRel);
                    max_written.fetch_max(sent, Ordering::AcqRel);
                }
                let _ = stream.shutdown().await;
                active.fetch_sub(1, Ordering::AcqRel);
            });
        }
    });
    Ok(LargeTunnelOrigin {
        address,
        accepts,
        active,
        written,
        max_written,
        task,
    })
}

/// A TCP origin that accepts and then deliberately stops reading.
pub struct HoldingOrigin {
    pub address: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for HoldingOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_holding_origin() -> io::Result<HoldingOrigin> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            task_accepts.fetch_add(1, Ordering::AcqRel);
            let _ = socket2::SockRef::from(&stream).set_recv_buffer_size(4096);
            tokio::spawn(async move {
                let _stream = stream;
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
        }
    });
    Ok(HoldingOrigin {
        address,
        accepts,
        task,
    })
}
