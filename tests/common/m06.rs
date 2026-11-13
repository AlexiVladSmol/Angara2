//! TLS test support for M06: private PKI, TLS clients, and a real local TLS site.

#![allow(dead_code)]

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, NamedGroup, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::common::m03::{self, RawClient};

pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub fn python() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
}

pub fn generate_pki(dir: &Path) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/m06_pki.py");
    let output = Command::new(python())
        .arg(script)
        .arg("--dir")
        .arg(dir)
        .output()
        .expect("run M06 PKI fixture");
    assert!(
        output.status.success(),
        "PKI fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn proxy_ca(dir: &Path) -> PathBuf {
    dir.join("proxy_ca.pem")
}

pub fn site_ca(dir: &Path) -> PathBuf {
    dir.join("site_ca.pem")
}

pub fn load_certificates(path: &Path) -> Vec<CertificateDer<'static>> {
    let bytes = fs::read(path).expect("read certificate PEM");
    CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse certificates")
}

pub fn client_config(ca_path: &Path) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(ca_path) {
        roots.add(certificate).expect("add root certificate");
    }
    assert!(!roots.is_empty(), "empty CA file");
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

pub fn client_config_version(
    ca_path: &Path,
    version: &'static rustls::SupportedProtocolVersion,
    alpn: &[&[u8]],
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(ca_path) {
        roots.add(certificate).expect("add root certificate");
    }
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .expect("client protocol version")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    Arc::new(config)
}

/// Records whether a rustls client successfully stored any resumable session.
///
/// The Angara TLS policy disables TLS 1.2 session ids/tickets and TLS 1.3
/// tickets, so a real handshake must leave this store empty.
#[derive(Debug, Default)]
pub struct RecordingSessions {
    tls12: AtomicUsize,
    tls13: AtomicUsize,
    hint: Mutex<Option<NamedGroup>>,
}

impl RecordingSessions {
    pub fn tls12_stored(&self) -> usize {
        self.tls12.load(Ordering::SeqCst)
    }

    pub fn tls13_stored(&self) -> usize {
        self.tls13.load(Ordering::SeqCst)
    }
}

impl ClientSessionStore for RecordingSessions {
    fn set_kx_hint(&self, _server_name: ServerName<'static>, group: NamedGroup) {
        *self.hint.lock().expect("kx hint") = Some(group);
    }

    fn kx_hint(&self, _server_name: &ServerName<'_>) -> Option<NamedGroup> {
        *self.hint.lock().expect("kx hint")
    }

    fn set_tls12_session(
        &self,
        _server_name: ServerName<'static>,
        _value: Tls12ClientSessionValue,
    ) {
        self.tls12.fetch_add(1, Ordering::SeqCst);
    }

    fn tls12_session(&self, _server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _server_name: &ServerName<'static>) {}

    fn insert_tls13_ticket(
        &self,
        _server_name: ServerName<'static>,
        _value: Tls13ClientSessionValue,
    ) {
        self.tls13.fetch_add(1, Ordering::SeqCst);
    }

    fn take_tls13_ticket(
        &self,
        _server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        None
    }
}

pub fn client_config_recording(
    ca_path: &Path,
    store: Arc<RecordingSessions>,
    version: Option<&'static rustls::SupportedProtocolVersion>,
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(ca_path) {
        roots.add(certificate).expect("add root certificate");
    }
    let provider = rustls::crypto::ring::default_provider();
    let builder = ClientConfig::builder_with_provider(Arc::new(provider));
    let builder = match version {
        Some(version) => builder
            .with_protocol_versions(&[version])
            .expect("client protocol version"),
        None => builder
            .with_safe_default_protocol_versions()
            .expect("client protocol versions"),
    };
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::store(store);
    Arc::new(config)
}

pub fn server_config(cert_chain: &Path, key: &Path) -> Arc<ServerConfig> {
    let chain = load_certificates(cert_chain);
    let key_bytes = fs::read(key).expect("read key PEM");
    let key = PrivateKeyDer::from_pem_slice(&key_bytes).expect("parse key PEM");
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server certificate/key");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

pub async fn connect_tls(
    address: SocketAddr,
    name: &str,
    config: Arc<ClientConfig>,
) -> io::Result<RawClient<tokio_rustls::client::TlsStream<TcpStream>>> {
    let stream = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
    let connector = TlsConnector::from(config);
    let name = ServerName::try_from(name.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad server name"))?;
    let stream = tokio::time::timeout(IO_TIMEOUT, connector.connect(name, stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timeout"))??;
    Ok(RawClient::from_stream(stream))
}

/// One request recorded by the local TLS site.
#[derive(Clone, Debug)]
pub struct SiteRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: SocketAddr,
}

impl SiteRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A TLS origin that sends a greeting, closes its write direction, then keeps
/// reading client bytes.
pub struct HalfCloseSite {
    pub address: SocketAddr,
    pub ties: Arc<AtomicUsize>,
    pub received: Arc<Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl Drop for HalfCloseSite {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_half_close_site(
    config: Arc<ServerConfig>,
    greeting: Vec<u8>,
) -> io::Result<HalfCloseSite> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let ties = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(Mutex::new(Vec::new()));
    let task_ties = Arc::clone(&ties);
    let task_received = Arc::clone(&received);
    let acceptor = TlsAcceptor::from(config);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let ties = Arc::clone(&task_ties);
            let received = Arc::clone(&task_received);
            let greeting = greeting.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                ties.fetch_add(1, Ordering::SeqCst);
                if tls.write_all(&greeting).await.is_err() || tls.shutdown().await.is_err() {
                    return;
                }
                let mut buffer = [0_u8; 8192];
                loop {
                    match tls.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => received.lock().unwrap().extend_from_slice(&buffer[..read]),
                    }
                }
            });
        }
    });
    Ok(HalfCloseSite {
        address,
        ties,
        received,
        task,
    })
}

/// A local real TLS HTTP site.
pub struct TlsSite {
    pub address: SocketAddr,
    pub tcp_accepts: Arc<AtomicUsize>,
    pub ties: Arc<AtomicUsize>,
    pub requests: Arc<Mutex<Vec<SiteRequest>>>,
    task: JoinHandle<()>,
}

impl Drop for TlsSite {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn spawn_site<F>(config: Arc<ServerConfig>, handler: F) -> io::Result<TlsSite>
where
    F: Fn(&SiteRequest) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let tcp_accepts = Arc::new(AtomicUsize::new(0));
    let ties = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let task_tcp_accepts = Arc::clone(&tcp_accepts);
    let task_ties = Arc::clone(&ties);
    let task_requests = Arc::clone(&requests);
    let acceptor = TlsAcceptor::from(config);
    let handler = Arc::new(handler);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            task_tcp_accepts.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let ties = Arc::clone(&task_ties);
            let requests = Arc::clone(&task_requests);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                ties.fetch_add(1, Ordering::SeqCst);
                let Some(request) = read_site_request(&mut tls, peer).await else {
                    return;
                };
                let response = handler(&request);
                requests.lock().unwrap().push(request);
                if !response.is_empty() {
                    let _ = tls.write_all(&response).await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    Ok(TlsSite {
        address,
        tcp_accepts,
        ties,
        requests,
        task,
    })
}

async fn read_site_request<S>(stream: &mut S, peer: SocketAddr) -> Option<SiteRequest>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    let head_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let mut chunk = [0_u8; 8192];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8(buffer[..head_end].to_vec()).ok()?;
    let mut request = SiteRequest {
        method: head.split(' ').next()?.to_owned(),
        target: head.split(' ').nth(1)?.to_owned(),
        headers: head
            .split("\r\n")
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
            .collect(),
        body: Vec::new(),
        peer,
    };
    let length = request
        .header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < head_end + length {
        let mut chunk = [0_u8; 8192];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    request.body = buffer[head_end..head_end + length].to_vec();
    Some(request)
}

pub fn site_response(status: &str, body: &[u8]) -> Vec<u8> {
    m03::response(status, &[], body)
}
