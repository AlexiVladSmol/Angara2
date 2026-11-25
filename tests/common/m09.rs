//! M09 parent proxy test support.
//!
//! The stand is a real HTTP/1.1 proxy using hyper. It records requests,
//! supports CONNECT upgrades, forwards absolute-form requests, and can return
//! deterministic rejection responses. A TLS variant uses the M06 PKI fixture.

#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HOST, PROXY_AUTHORIZATION};
use http::{Request, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestBody = BoxBody<Bytes, BoxError>;

/// Deterministic response used by rejection tests.
#[derive(Clone, Debug)]
pub struct FixedResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl FixedResponse {
    pub fn new(status: u16, body: &[u8]) -> Self {
        Self {
            status,
            body: body.to_vec(),
            headers: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// Parent behavior for one test.
#[derive(Clone, Debug)]
pub enum ParentMode {
    /// Forward absolute-form requests and CONNECT tunnels to their target.
    Forward,
    /// Return this response for every non-CONNECT request.
    Fixed(FixedResponse),
    /// Reject CONNECT with this response; other requests follow `Forward`.
    RejectConnect(FixedResponse),
    /// Wait before processing the request.
    Delay(Duration),
    /// Close the connection after recording a non-CONNECT request.
    Abort,
}

/// One request observed by the stand.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub uri: String,
    pub host: Option<String>,
    pub proxy_authorization: Option<String>,
    pub via: Vec<String>,
    pub peer: SocketAddr,
    pub body: Vec<u8>,
}

/// A local parent proxy stand.
pub struct ParentStand {
    pub address: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    pub requests: Arc<Mutex<Vec<RecordedRequest>>>,
    pub connects: Arc<AtomicUsize>,
    pub mode: Arc<Mutex<ParentMode>>,
    task: JoinHandle<()>,
}

impl ParentStand {
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("parent requests").clone()
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().expect("parent requests").len()
    }

    pub fn connect_count(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }

    pub fn set_mode(&self, mode: ParentMode) {
        *self.mode.lock().expect("parent mode") = mode;
    }

    pub fn clear(&self) {
        self.requests.lock().expect("parent requests").clear();
        self.connects.store(0, Ordering::SeqCst);
    }
}

impl Drop for ParentStand {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a plain HTTP parent stand.
pub async fn spawn_parent(mode: ParentMode) -> io::Result<ParentStand> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connects = Arc::new(AtomicUsize::new(0));
    let parent_mode = Arc::new(Mutex::new(mode));
    let task_accepts = Arc::clone(&accepts);
    let task_requests = Arc::clone(&requests);
    let task_connects = Arc::clone(&connects);
    let task_mode = Arc::clone(&parent_mode);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            task_accepts.fetch_add(1, Ordering::SeqCst);
            let requests = Arc::clone(&task_requests);
            let connects = Arc::clone(&task_connects);
            let mode = Arc::clone(&task_mode);
            tokio::spawn(async move {
                let _ = serve(stream, peer, requests, connects, mode).await;
            });
        }
    });
    Ok(ParentStand {
        address,
        accepts,
        requests,
        connects,
        mode: parent_mode,
        task,
    })
}

/// Starts a TLS parent stand using the supplied acceptor.
pub async fn spawn_tls_parent(acceptor: TlsAcceptor, mode: ParentMode) -> io::Result<ParentStand> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connects = Arc::new(AtomicUsize::new(0));
    let parent_mode = Arc::new(Mutex::new(mode));
    let task_accepts = Arc::clone(&accepts);
    let task_requests = Arc::clone(&requests);
    let task_connects = Arc::clone(&connects);
    let task_mode = Arc::clone(&parent_mode);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            task_accepts.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let requests = Arc::clone(&task_requests);
            let connects = Arc::clone(&task_connects);
            let mode = Arc::clone(&task_mode);
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let _ = serve(stream, peer, requests, connects, mode).await;
            });
        }
    });
    Ok(ParentStand {
        address,
        accepts,
        requests,
        connects,
        mode: parent_mode,
        task,
    })
}

/// How a one-shot raw TLS parent ends its CONNECT tunnel.
#[derive(Clone, Copy, Debug)]
pub enum TlsParentClose {
    /// Read the client half-close, send one payload, then drop the TLS stream
    /// without sending close_notify.
    AfterClientEofWithoutCloseNotify,
    /// Drop the TLS stream immediately after the 200 response.
    AbortAfterConnect,
    /// Send `tls_parent_payload(len)` right after the 200 response, then drop
    /// the TLS stream without close_notify before the client ends its side.
    SendThenDropWithoutCloseNotify(usize),
    /// Send payload, send close_notify, then close the TCP socket immediately
    /// without waiting for the client.
    SendThenCloseNotifyAndDrop(usize),
}

/// Deterministic payload sent by `TlsParentClose::SendThenDropWithoutCloseNotify`.
pub fn tls_parent_payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// One-shot TLS parent used to exercise missing close_notify handling.
pub struct OneShotTlsParent {
    pub address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for OneShotTlsParent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_one_shot_tls_parent(
    acceptor: TlsAcceptor,
    close: TlsParentClose,
) -> io::Result<OneShotTlsParent> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return;
        };
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match tls.read_exact(&mut byte).await {
                Ok(_) => head.push(byte[0]),
                Err(_) => return,
            }
        }
        if tls
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        match close {
            TlsParentClose::AbortAfterConnect => {
                drop(tls);
            }
            TlsParentClose::AfterClientEofWithoutCloseNotify => {
                let mut buffer = [0_u8; 4096];
                loop {
                    match tls.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                let _ = tls.write_all(b"parent-payload").await;
                drop(tls);
            }
            TlsParentClose::SendThenDropWithoutCloseNotify(len) => {
                let payload = tls_parent_payload(len);
                if tls.write_all(&payload).await.is_ok() {
                    let _ = tls.flush().await;
                }
                drop(tls);
            }
            TlsParentClose::SendThenCloseNotifyAndDrop(len) => {
                let payload = tls_parent_payload(len);
                if tls.write_all(&payload).await.is_ok() {
                    let _ = tls.flush().await;
                }
                let _ = tls.shutdown().await;
                drop(tls);
            }
        }
    });
    Ok(OneShotTlsParent { address, task })
}

async fn serve<S>(
    stream: S,
    peer: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    connects: Arc<AtomicUsize>,
    mode: Arc<Mutex<ParentMode>>,
) -> Result<(), BoxError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        handle(
            peer,
            Arc::clone(&requests),
            Arc::clone(&connects),
            Arc::clone(&mode),
            request,
        )
    });
    server_http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .map_err(|error| Box::new(error) as BoxError)
}

async fn handle(
    peer: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    connects: Arc<AtomicUsize>,
    mode: Arc<Mutex<ParentMode>>,
    request: Request<Incoming>,
) -> Result<Response<TestBody>, BoxError> {
    let method = request.method().clone();
    let uri = request.uri().to_string();
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let authorization = request
        .headers()
        .get(PROXY_AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let via = request
        .headers()
        .get_all(http::header::VIA)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect::<Vec<_>>();
    let mode_value = mode.lock().expect("parent mode").clone();

    if method == http::Method::CONNECT {
        requests
            .lock()
            .expect("parent requests")
            .push(RecordedRequest {
                method: method.to_string(),
                uri: uri.clone(),
                host,
                proxy_authorization: authorization,
                via,
                peer,
                body: Vec::new(),
            });
        if let ParentMode::Delay(delay) = mode_value {
            tokio::time::sleep(delay).await;
        }
        if let ParentMode::RejectConnect(response) = mode_value {
            return fixed_response(response);
        }
        let authority = uri
            .parse::<http::uri::Authority>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad CONNECT authority"))?;
        let target = TcpStream::connect(authority.as_str()).await?;
        connects.fetch_add(1, Ordering::SeqCst);
        let on_upgrade = hyper::upgrade::on(request);
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else {
                return;
            };
            let mut upgraded = TokioIo::new(upgraded);
            let mut target = target;
            let _ = copy_bidirectional(&mut upgraded, &mut target).await;
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_11)
            .body(empty_body())
            .expect("CONNECT 200 response"));
    }

    let request_uri = request.uri().clone();
    let request_method = request.method().clone();
    let request_headers = request.headers().clone();
    let body = request
        .into_body()
        .collect()
        .await
        .map_err(|error| Box::new(error) as BoxError)?
        .to_bytes();
    requests
        .lock()
        .expect("parent requests")
        .push(RecordedRequest {
            method: method.to_string(),
            uri: uri.clone(),
            host,
            proxy_authorization: authorization,
            via,
            peer,
            body: body.to_vec(),
        });

    if let ParentMode::Delay(delay) = mode_value {
        tokio::time::sleep(delay).await;
    }
    if matches!(mode_value, ParentMode::Abort) {
        return Err(io::Error::other("synthetic parent abort").into());
    }
    if let ParentMode::Fixed(response) = mode_value {
        return fixed_response(response);
    }

    forward_absolute(request_method, request_uri, request_headers, body).await
}

async fn forward_absolute(
    method: http::Method,
    uri: http::Uri,
    headers: http::HeaderMap,
    body: Bytes,
) -> Result<Response<TestBody>, BoxError> {
    let authority = uri
        .authority()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "absolute-form required"))?
        .clone();
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let mut origin_request = Request::builder()
        .method(method)
        .version(Version::HTTP_11)
        .uri(path)
        .body(Full::new(body))
        .map_err(|error| Box::new(error) as BoxError)?;
    *origin_request.headers_mut() = headers;
    origin_request.headers_mut().remove(PROXY_AUTHORIZATION);

    let stream = TcpStream::connect(authority.as_str().to_owned()).await?;
    let (mut sender, connection) = client_http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender.send_request(origin_request).await?;
    Ok(response.map(|body| body.map_err(|error| Box::new(error) as BoxError).boxed()))
}

fn fixed_response(response: FixedResponse) -> Result<Response<TestBody>, BoxError> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(response.status)?)
        .version(Version::HTTP_11);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    Ok(builder.body(full_body(response.body))?)
}

fn empty_body() -> TestBody {
    full_body(Vec::new())
}

fn full_body(body: Vec<u8>) -> TestBody {
    Full::new(Bytes::from(body))
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed()
}
