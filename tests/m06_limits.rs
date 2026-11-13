//! M06 TLS resource and load evidence (Linux).

#![allow(clippy::field_reassign_with_default)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use angara::config::Config;
use angara::http::HttpServer;
use common::m03;
use common::m04;
use common::m05;
use common::m06;
use tokio::sync::Semaphore;

static CA_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

fn set_ca(path: PathBuf) {
    *CA_PATH.lock().expect("CA path") = Some(path);
}

fn dir_ca() -> PathBuf {
    CA_PATH
        .lock()
        .expect("CA path")
        .clone()
        .expect("CA path initialized")
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn task_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

fn two_https_config(dir: &Path, users: &Path, connect_port: u16, auth: bool) -> String {
    let cert = dir
        .join("proxy_chain.pem")
        .to_string_lossy()
        .replace('\\', "/");
    let key = dir
        .join("proxy_key.pem")
        .to_string_lossy()
        .replace('\\', "/");
    let users = users.to_string_lossy().replace('\\', "/");
    let auth_table = if auth {
        format!("[auth]\nusers_file = \"{users}\"\nmax_verifying = 2\nverify_timeout_ms = 30000\n")
    } else {
        String::new()
    };
    let listener_auth = if auth {
        "auth = \"basic\""
    } else {
        "auth = \"none\""
    };
    let rules = if auth {
        "[[access.rules]]\nid = \"users\"\naction = \"allow\"\nusers = [\"alice\", \"bob\"]\n"
    } else {
        "[[access.rules]]\nid = \"allow\"\naction = \"allow\"\n"
    };
    format!(
        r#"
schema_version = 1
[runtime]
worker_threads = 2
[limits]
max_connections = 128
max_client_connections = 64
max_header_bytes = 32768
header_read_timeout_ms = 3000
idle_timeout_ms = 30000
shutdown_timeout_ms = 3000
{auth_table}[tls]
max_handshaking = 16
handshake_timeout_ms = 3000
[[listeners]]
id = "a"
bind = "127.0.0.1:3129"
transport = "https"
{listener_auth}
[listeners.tls]
cert_chain_file = "{cert}"
private_key_file = "{key}"
[[listeners]]
id = "b"
bind = "127.0.0.1:3130"
transport = "https"
{listener_auth}
[listeners.tls]
cert_chain_file = "{cert}"
private_key_file = "{key}"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"
{rules}
[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
[transport]
total_timeout_ms = 10000
connect_timeout_ms = 3000
max_connect_attempts = 2
max_connecting = 32
[http]
max_headers = 64
response_header_timeout_ms = 10000
pool_max_idle = 16
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 30000
[connect]
allowed_ports = [{connect_port}]
half_close_timeout_ms = 2000
"#
    )
}

async fn start(dir: &common::TempDir, text: &str) -> (HttpServer, Vec<std::net::SocketAddr>) {
    let path = dir.path().join("load.toml");
    fs::write(&path, text).expect("write load config");
    let config = Arc::new(Config::load(&path).expect("load config"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind load server");
    let addresses = server
        .addresses()
        .iter()
        .map(|(_, address)| *address)
        .collect();
    (server, addresses)
}

async fn request(
    address: std::net::SocketAddr,
    target: std::net::SocketAddr,
    auth: Option<(&str, &str)>,
) -> u16 {
    let mut client = m06::connect_tls(address, "localhost", m06::client_config(&dir_ca()))
        .await
        .expect("TLS client");
    let mut headers = Vec::new();
    if let Some((user, password)) = auth {
        headers.push(("Proxy-Authorization", m05::authorization(user, password)));
    }
    let header_refs = headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect::<Vec<_>>();
    client
        .send(&m03::request("GET", target, "/", &header_refs, b""))
        .await
        .expect("send");
    client.read_response().await.expect("response").head.status
}

#[tokio::test]
async fn m06_res01_tls_handshakes_streams_and_cancellations_return_to_baseline() {
    let _serial = RESOURCE_LOCK.lock().await;
    let dir = common::TempDir::new("m06-res01");
    m06::generate_pki(dir.path());
    set_ca(dir.path().join("proxy_ca.pem"));
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"res"))
        .await
        .expect("origin");
    let (server, addresses) = start(
        &dir,
        &two_https_config(dir.path(), &dir.path().join("unused"), 443, false),
    )
    .await;
    let address = addresses[0];
    let fd_before = fd_count();
    let rss_before = rss_kib();
    let tasks_before = task_count();
    let mut fd_peak = fd_before;

    for _ in 0..30 {
        assert_eq!(request(address, origin.address, None).await, 200);
        fd_peak = fd_peak.max(fd_count());
    }
    for _ in 0..20 {
        let mut raw = tokio::net::TcpStream::connect(address).await.expect("raw");
        let _ = tokio::io::AsyncWriteExt::write_all(&mut raw, &[0x16, 0x03, 0x03, 0x00]).await;
        drop(raw);
        fd_peak = fd_peak.max(fd_count());
    }
    let mut flood = Vec::new();
    for _ in 0..40 {
        let mut raw = tokio::net::TcpStream::connect(address)
            .await
            .expect("handshake flood");
        let _ = tokio::io::AsyncWriteExt::write_all(&mut raw, &[0x16, 0x03, 0x03, 0x00]).await;
        flood.push(raw);
        fd_peak = fd_peak.max(fd_count());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(flood);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(request(address, origin.address, None).await, 200);
    let fd_after = fd_count();
    let rss_after = rss_kib();
    let tasks_after = task_count();
    eprintln!(
        "M06-RES-01 fd {fd_before}->{fd_after} peak={fd_peak}, rss_kib {rss_before}->{rss_after}, tasks {tasks_before}->{tasks_after}, handshakes=50"
    );
    assert!(
        fd_after <= fd_before + 8,
        "fd growth: {fd_before}->{fd_after}"
    );
    assert!(rss_after <= rss_before + 32 * 1024, "rss growth");
    assert!(tasks_after <= tasks_before + 8, "task growth");
    server.shutdown().await;
}

#[tokio::test]
async fn m06_load01_ten_and_twenty_https_clients_mixed_http_connect() {
    let _serial = RESOURCE_LOCK.lock().await;
    let dir = common::TempDir::new("m06-load01");
    m06::generate_pki(dir.path());
    set_ca(dir.path().join("proxy_ca.pem"));
    let users = dir.path().join("users.toml");
    m05::write_secure(
        &users,
        &m05::users_text(&[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ]),
    );
    let echo = m04::spawn_echo_origin(None).await.expect("echo");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"load"))
        .await
        .expect("origin");
    let (server, addresses) = start(
        &dir,
        &two_https_config(dir.path(), &users, echo.address.port(), true),
    )
    .await;
    let capacity = Arc::new(Semaphore::new(2));
    for clients in [10usize, 20] {
        let started = Instant::now();
        let mut tasks = Vec::new();
        for index in 0..clients {
            let capacity = Arc::clone(&capacity);
            let address = addresses[index % addresses.len()];
            let (user, password) = if index % 2 == 0 {
                ("alice", "alice-secret")
            } else {
                ("bob", "bob-secret")
            };
            let origin = origin.address;
            let echo = echo.address;
            tasks.push(tokio::spawn(async move {
                let _permit = capacity.acquire_owned().await.expect("capacity");
                let http = request_with_auth(address, origin, user, password).await;
                let tunnel = connect_tunnel(address, echo, user, password).await;
                (http, tunnel)
            }));
        }
        let mut ok = 0;
        for task in tasks {
            let (http, tunnel) = task.await.expect("join");
            assert_eq!(http, 200, "HTTPS HTTP client failed");
            assert!(tunnel, "HTTPS CONNECT client failed");
            ok += 1;
        }
        eprintln!(
            "M06-LOAD-01 clients={clients} ok={ok} errors=0 elapsed_ms={} fd_live={} rss_kib={}",
            started.elapsed().as_millis(),
            fd_count(),
            rss_kib()
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn m06_load01_handshake_overload_counts_and_recovers() {
    let _serial = RESOURCE_LOCK.lock().await;
    let dir = common::TempDir::new("m06-load-handshake");
    m06::generate_pki(dir.path());
    set_ca(dir.path().join("proxy_ca.pem"));
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"recovered"))
        .await
        .expect("origin");
    let text = two_https_config(dir.path(), &dir.path().join("unused"), 443, false)
        .replace("max_handshaking = 16", "max_handshaking = 1");
    let (server, addresses) = start(&dir, &text).await;
    let address = addresses[0];

    let held = tokio::net::TcpStream::connect(address)
        .await
        .expect("hold handshake slot");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let ca = dir_ca();
        tasks.push(tokio::spawn(async move {
            m06::connect_tls(address, "localhost", m06::client_config(&ca)).await
        }));
    }
    let mut rejected = 0;
    for task in tasks {
        match task.await.expect("join overload client") {
            Ok(_) => panic!("handshake overload admitted a client beyond max_handshaking"),
            Err(_) => rejected += 1,
        }
    }
    assert_eq!(rejected, 10, "all overload handshakes must be rejects");
    drop(held);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(request(address, origin.address, None).await, 200);
    eprintln!("M06-LOAD-01 handshake_overload rejected={rejected} success=1 retries=0");
    server.shutdown().await;
}

#[tokio::test]
async fn m06_load01_auth_overload_is_407_or_503_without_retry() {
    let _serial = RESOURCE_LOCK.lock().await;
    let dir = common::TempDir::new("m06-load-auth");
    m06::generate_pki(dir.path());
    set_ca(dir.path().join("proxy_ca.pem"));
    let users = dir.path().join("users.toml");
    m05::write_secure(
        &users,
        &m05::users_text(&[("alice", &m05::hash("alice-secret"), false)]),
    );
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"never"))
        .await
        .expect("origin");
    let text = two_https_config(dir.path(), &users, 443, true)
        .replace("max_verifying = 2", "max_verifying = 1");
    let (server, addresses) = start(&dir, &text).await;
    let address = addresses[0];

    let mut tasks = Vec::new();
    for index in 0..10 {
        let target = origin.address;
        let address = addresses[index % addresses.len()];
        tasks.push(tokio::spawn(async move {
            request_with_auth(address, target, "alice", "wrong-password").await
        }));
    }
    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.expect("join auth overload"));
    }
    let unauthorized = statuses.iter().filter(|status| **status == 407).count();
    let unavailable = statuses.iter().filter(|status| **status == 503).count();
    assert_eq!(
        unauthorized + unavailable,
        statuses.len(),
        "unexpected statuses under auth overload: {statuses:?}"
    );
    assert!(
        unauthorized > 0,
        "auth overload never returned 407: {statuses:?}"
    );
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        request_with_auth(address, origin.address, "alice", "alice-secret").await,
        200,
        "auth capacity did not recover"
    );
    eprintln!(
        "M06-LOAD-01 auth_overload requests={} 407={unauthorized} 503={unavailable} success_after=1 retries=0",
        statuses.len()
    );
    server.shutdown().await;
}

async fn request_with_auth(
    address: std::net::SocketAddr,
    target: std::net::SocketAddr,
    user: &str,
    password: &str,
) -> u16 {
    let mut client = m06::connect_tls(address, "localhost", m06::client_config(&dir_ca()))
        .await
        .expect("TLS client");
    let auth = m05::authorization(user, password);
    client
        .send(&m03::request(
            "GET",
            target,
            "/",
            &[("Proxy-Authorization", &auth)],
            b"",
        ))
        .await
        .expect("send");
    client.read_response().await.expect("response").head.status
}

async fn connect_tunnel(
    address: std::net::SocketAddr,
    target: std::net::SocketAddr,
    user: &str,
    password: &str,
) -> bool {
    let mut client = m06::connect_tls(address, "localhost", m06::client_config(&dir_ca()))
        .await
        .expect("TLS tunnel client");
    let auth = m05::authorization(user, password);
    client
        .send(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {auth}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send CONNECT");
    if client.read_head().await.expect("200").status != 200 {
        return false;
    }
    client.send(b"ping").await.expect("tunnel write");
    client.read_exact_bytes(4).await.expect("echo") == b"ping"
}

static RESOURCE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
