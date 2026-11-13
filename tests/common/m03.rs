//! M03 HTTP proxy test support: ephemeral servers, raw clients, recording origins.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use angara::config::Config;
use angara::http::HttpServer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimal M03 configuration with loopback access for tests.
pub fn config(bind: &str) -> String {
    format!(
        r#"
schema_version = 1

[runtime]
worker_threads = 2

[limits]
max_connections = 64
max_client_connections = 16
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 2000

[[listeners]]
id = "proxy"
bind = "{bind}"
transport = "http"

[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true

[transport]
total_timeout_ms = 5000
connect_timeout_ms = 2000
max_connect_attempts = 2
max_connecting = 8

[http]
max_headers = 64
response_header_timeout_ms = 5000
pool_max_idle = 4
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 2000
"#
    )
}

/// Configuration with a custom bind and an inserted TOML fragment.
pub fn config_with(bind: &str, extra: &str) -> String {
    format!("{}{extra}", config(bind))
}

/// Replaces the single default listener with one or more listener blocks.
pub fn config_with_listeners(listeners: &str) -> String {
    config("127.0.0.1:3128").replace(
        "[[listeners]]\nid = \"proxy\"\nbind = \"127.0.0.1:3128\"\ntransport = \"http\"",
        listeners,
    )
}

/// Starts an ephemeral proxy.
pub async fn start_proxy(text: &str) -> (HttpServer, SocketAddr) {
    let config = Arc::new(Config::parse(text).expect("test configuration is valid"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind ephemeral proxy");
    let address = server.addresses()[0].1;
    (server, address)
}

/// Free loopback TCP port.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local address")
        .port()
}

/// One parsed HTTP response head.
#[derive(Clone, Debug)]
pub struct RawHead {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub raw: Vec<u8>,
}

impl RawHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One final HTTP response, including buffered interim heads and trailers.
#[derive(Clone, Debug)]
pub struct RawResponse {
    pub head: RawHead,
    pub interim: Vec<RawHead>,
    pub trailers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RawResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.header(name)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Buffered raw client for exact HTTP/1.1 byte tests.
pub struct RawClient<S = TcpStream> {
    stream: S,
    buffer: Vec<u8>,
}

impl RawClient<TcpStream> {
    pub async fn connect(address: SocketAddr) -> io::Result<Self> {
        let stream = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
        Ok(Self {
            stream,
            buffer: Vec::new(),
        })
    }

    /// Connects with explicit socket buffers to make TCP backpressure
    /// reproducible in wire-order regressions.
    pub async fn connect_with_buffers(address: SocketAddr, size: u32) -> io::Result<Self> {
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_recv_buffer_size(size)?;
        socket.set_send_buffer_size(size)?;
        let stream = tokio::time::timeout(IO_TIMEOUT, socket.connect(address))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
        Ok(Self {
            stream,
            buffer: Vec::new(),
        })
    }
}

impl<S> RawClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wraps an already established stream, such as a TLS client stream.
    pub fn from_stream(stream: S) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    /// Returns the underlying stream. Any bytes already buffered by this
    /// client are discarded; only use this at a protocol boundary where no
    /// extra bytes are expected.
    pub fn into_inner(self) -> S {
        self.stream
    }

    pub async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await
    }

    pub async fn shutdown_write(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }

    /// Reads exactly `length` raw bytes from the tunnel.
    pub async fn read_exact_bytes(&mut self, length: usize) -> io::Result<Vec<u8>> {
        self.read_exact(length).await
    }

    /// Reads the remaining tunnel bytes until the peer closes.
    pub async fn read_until_eof(&mut self) -> io::Result<Vec<u8>> {
        let mut output = std::mem::take(&mut self.buffer);
        match tokio::time::timeout(IO_TIMEOUT, self.stream.read_to_end(&mut output)).await {
            Ok(Ok(_)) => Ok(output),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
        }
    }

    pub async fn read_head(&mut self) -> io::Result<RawHead> {
        loop {
            if let Some(position) = self
                .buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            {
                let raw: Vec<u8> = self.buffer.drain(..position + 4).collect();
                return parse_head(&raw);
            }
            self.fill().await?;
        }
    }

    pub async fn read_response(&mut self) -> io::Result<RawResponse> {
        self.read_response_for(false).await
    }

    pub async fn read_head_response(&mut self) -> io::Result<RawResponse> {
        self.read_response_for(true).await
    }

    /// Reads one chunked data chunk; `None` means the final chunk/trailers.
    pub async fn read_chunked_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        let line = self.read_line().await?;
        let size = line
            .split(';')
            .next()
            .and_then(|value| usize::from_str_radix(value.trim(), 16).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        if size == 0 {
            loop {
                let line = self.read_line().await?;
                if line.is_empty() {
                    return Ok(None);
                }
            }
        }
        let chunk = self.read_exact(size).await?;
        let ending = self.read_exact(2).await?;
        if ending != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad chunk ending",
            ));
        }
        Ok(Some(chunk))
    }

    async fn read_response_for(&mut self, body_forbidden: bool) -> io::Result<RawResponse> {
        let mut interim = Vec::new();
        let head = loop {
            let head = self.read_head().await?;
            if (100..200).contains(&head.status) {
                interim.push(head);
                continue;
            }
            break head;
        };

        let mut trailers = Vec::new();
        let body = if body_forbidden
            || head.status == 204
            || head.status == 304
            || (100..200).contains(&head.status)
        {
            Vec::new()
        } else if head
            .header("transfer-encoding")
            .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
        {
            self.read_chunked(&mut trailers).await?
        } else if let Some(length) = head.header("content-length") {
            let length = length
                .parse::<usize>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad content-length"))?;
            self.read_exact(length).await?
        } else {
            self.read_to_eof().await?
        };
        Ok(RawResponse {
            head,
            interim,
            trailers,
            body,
        })
    }

    async fn fill(&mut self) -> io::Result<()> {
        let mut chunk = [0_u8; 16 * 1024];
        let read = tokio::time::timeout(IO_TIMEOUT, self.stream.read(&mut chunk))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read timeout"))??;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before a complete message",
            ));
        }
        self.buffer.extend_from_slice(&chunk[..read]);
        Ok(())
    }

    async fn read_exact(&mut self, length: usize) -> io::Result<Vec<u8>> {
        while self.buffer.len() < length {
            self.fill().await?;
        }
        Ok(self.buffer.drain(..length).collect())
    }

    async fn read_line(&mut self) -> io::Result<String> {
        loop {
            if let Some(position) = self.buffer.windows(2).position(|window| window == b"\r\n") {
                let line: Vec<u8> = self.buffer.drain(..position + 2).collect();
                return String::from_utf8(line[..line.len() - 2].to_vec())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 line"));
            }
            self.fill().await?;
        }
    }

    async fn read_chunked(&mut self, trailers: &mut Vec<(String, String)>) -> io::Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let line = self.read_line().await?;
            let size = line
                .split(';')
                .next()
                .and_then(|value| usize::from_str_radix(value.trim(), 16).ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                loop {
                    let line = self.read_line().await?;
                    if line.is_empty() {
                        return Ok(body);
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        trailers.push((name.trim().to_owned(), value.trim().to_owned()));
                    }
                }
            }
            let mut chunk = self.read_exact(size).await?;
            let ending = self.read_exact(2).await?;
            if ending != b"\r\n" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad chunk ending",
                ));
            }
            body.append(&mut chunk);
        }
    }

    async fn read_to_eof(&mut self) -> io::Result<Vec<u8>> {
        match tokio::time::timeout(IO_TIMEOUT, self.stream.read_to_end(&mut self.buffer)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout")),
        }
        Ok(std::mem::take(&mut self.buffer))
    }
}

fn parse_head(raw: &[u8]) -> io::Result<RawHead> {
    let text = String::from_utf8(raw.to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 head"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default().to_owned();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;
    let reason = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad header line"))?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    Ok(RawHead {
        version,
        status,
        reason,
        headers,
        raw: raw.to_vec(),
    })
}

/// Parsed client request recorded by a test origin.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub peer: SocketAddr,
    pub raw_head: Vec<u8>,
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub trailers: Vec<(String, String)>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A raw TCP origin that records every request and returns handler responses.
pub struct TestOrigin {
    pub address: SocketAddr,
    pub requests: Arc<Mutex<Vec<RecordedRequest>>>,
    pub accepts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for TestOrigin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Spawns a recording origin. The handler receives the request and the
/// zero-based request index on that connection.
pub async fn spawn_origin<F>(handler: F) -> io::Result<TestOrigin>
where
    F: Fn(&RecordedRequest, usize) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let accepts = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(handler);
    let task_requests = Arc::clone(&requests);
    let task_accepts = Arc::clone(&accepts);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            task_accepts.fetch_add(1, Ordering::AcqRel);
            let requests = Arc::clone(&task_requests);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let _ = serve_origin_connection(stream, requests, handler).await;
            });
        }
    });
    Ok(TestOrigin {
        address,
        requests,
        accepts,
        task,
    })
}

async fn serve_origin_connection<F>(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    handler: Arc<F>,
) -> io::Result<()>
where
    F: Fn(&RecordedRequest, usize) -> Vec<u8> + Send + Sync + 'static,
{
    let peer = stream.peer_addr()?;
    let mut buffer = Vec::new();
    let mut index = 0;
    loop {
        let Some((mut request, consumed)) = read_recorded_request(&mut stream, &mut buffer).await?
        else {
            return Ok(());
        };
        request.peer = peer;
        let _ = consumed;
        let response = handler(&request, index);
        index += 1;
        requests.lock().unwrap().push(request);
        if response.is_empty() {
            return Ok(());
        }
        stream.write_all(&response).await?;
    }
}

async fn read_recorded_request(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<(RecordedRequest, usize)>> {
    loop {
        let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
            if fill_origin(stream, buffer).await? == 0 {
                if buffer.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete request head",
                ));
            }
            continue;
        };
        let head_len = position + 4;
        let head = buffer[..head_len].to_vec();
        let parsed = parse_request_head(&head)?;
        let chunked = parsed
            .header("transfer-encoding")
            .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));

        let framed = if chunked {
            try_chunked_frame(buffer, head_len)
        } else {
            let length = parsed
                .header("content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let total = head_len + length;
            (buffer.len() >= total).then(|| (total, buffer[head_len..total].to_vec(), Vec::new()))
        };

        let Some((total, body, trailers)) = framed else {
            if fill_origin(stream, buffer).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete request body",
                ));
            }
            continue;
        };

        let raw = buffer.drain(..total).collect::<Vec<u8>>();
        let mut request = parse_request_head(&raw[..head_len])?;
        request.body = body;
        request.trailers = trailers;
        return Ok(Some((request, total)));
    }
}

type ChunkedFrame = (usize, Vec<u8>, Vec<(String, String)>);

fn try_chunked_frame(buffer: &[u8], head_len: usize) -> Option<ChunkedFrame> {
    let mut cursor = head_len;
    let mut body = Vec::new();
    loop {
        let line_end = find_crlf(buffer, cursor).ok()??;
        let line = String::from_utf8_lossy(&buffer[cursor..line_end]).into_owned();
        cursor = line_end + 2;
        let size = line
            .split(';')
            .next()
            .and_then(|value| usize::from_str_radix(value.trim(), 16).ok())?;
        if size == 0 {
            let mut trailers = Vec::new();
            loop {
                let line_end = find_crlf(buffer, cursor).ok()??;
                if line_end == cursor {
                    return Some((cursor + 2, body, trailers));
                }
                let line = String::from_utf8_lossy(&buffer[cursor..line_end]).into_owned();
                if let Some((name, value)) = line.split_once(':') {
                    trailers.push((name.trim().to_owned(), value.trim().to_owned()));
                }
                cursor = line_end + 2;
            }
        }
        if buffer.len() < cursor + size + 2 {
            return None;
        }
        body.extend_from_slice(&buffer[cursor..cursor + size]);
        cursor += size + 2;
    }
}

async fn fill_origin(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> io::Result<usize> {
    let mut chunk = [0_u8; 16 * 1024];
    let read = stream.read(&mut chunk).await?;
    buffer.extend_from_slice(&chunk[..read]);
    Ok(read)
}

fn find_crlf(buffer: &[u8], from: usize) -> io::Result<Option<usize>> {
    Ok(buffer
        .get(from..)
        .and_then(|tail| tail.windows(2).position(|window| window == b"\r\n"))
        .map(|offset| from + offset))
}

fn request_body_shape(head: &RecordedRequest) -> (usize, bool) {
    let chunked = head
        .header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let length = head
        .header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    (length, chunked)
}

fn parse_request_head(head: &[u8]) -> io::Result<RecordedRequest> {
    let text = String::from_utf8(head.to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 request"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let version = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    Ok(RecordedRequest {
        peer: "0.0.0.0:0".parse().expect("placeholder peer"),
        raw_head: head.to_vec(),
        method,
        target,
        version,
        headers,
        body: Vec::new(),
        trailers: Vec::new(),
    })
}

/// Formats an absolute-form request for the proxy.
pub fn request(
    method: &str,
    address: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut output =
        format!("{method} http://{address}{path} HTTP/1.1\r\nHost: {address}\r\n").into_bytes();
    for (name, value) in headers {
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(body);
    output
}

/// Formats a simple fixed-length response.
pub fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut output = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (name, value) in headers {
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    output.extend_from_slice(body);
    output
}

/// Formats a chunked response with optional trailers.
pub fn chunked_response(
    status: &str,
    headers: &[(&str, &str)],
    chunks: &[&[u8]],
    trailers: &[(&str, &str)],
) -> Vec<u8> {
    let mut output = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (name, value) in headers {
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
    for chunk in chunks {
        output.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        output.extend_from_slice(chunk);
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"0\r\n");
    for (name, value) in trailers {
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output
}

/// Shared queue used by scripted origins.
#[derive(Clone, Default)]
pub struct Script {
    inner: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl Script {
    pub fn new(responses: Vec<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(responses.into())),
        }
    }

    pub fn next(&self) -> Vec<u8> {
        self.inner.lock().unwrap().pop_front().unwrap_or_default()
    }
}
