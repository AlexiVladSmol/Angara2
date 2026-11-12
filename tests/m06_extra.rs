//! M06 TLS ordering, lifecycle, limits, restart and CPU tests.

mod common;

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use angara::config::Config;
use angara::http::HttpServer;
use common::m03;
use common::m04;
use common::m06;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[derive(Clone, Copy)]
struct Tuning {
    idle_ms: u64,
    shutdown_ms: u64,
    max_client: u32,
    max_handshaking: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            idle_ms: 5_000,
            shutdown_ms: 2_000,
            max_client: 32,
            max_handshaking: 8,
        }
    }
}

fn https_config(
    chain: &Path,
    key: &Path,
    tuning: Tuning,
    extra_listener: &str,
    connect_ports: &str,
) -> String {
    let cert = path_text(chain);
    let key = path_text(key);
    format!(
        r#"
schema_version = 1
[runtime]
worker_threads = 2
[limits]
max_connections = 128
max_client_connections = {max_client}
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = {idle_ms}
shutdown_timeout_ms = {shutdown_ms}
[tls]
max_handshaking = {max_handshaking}
handshake_timeout_ms = 3000
[[listeners]]
id = "proxy"
bind = "127.0.0.1:3129"
transport = "https"
auth = "none"
[listeners.tls]
cert_chain_file = "{cert}"
private_key_file = "{key}"
{extra_listener}
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
total_timeout_ms = 10000
connect_timeout_ms = 3000
max_connect_attempts = 2
max_connecting = 16
[http]
max_headers = 64
response_header_timeout_ms = 10000
pool_max_idle = 16
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 30000
[connect]
allowed_ports = [{connect_ports}]
half_close_timeout_ms = 800
"#,
        max_client = tuning.max_client,
        idle_ms = tuning.idle_ms,
        shutdown_ms = tuning.shutdown_ms,
        max_handshaking = tuning.max_handshaking,
    )
}

fn second_listener(chain: &Path, key: &Path) -> String {
    format!(
        r#"
[[listeners]]
id = "second"
bind = "127.0.0.1:3130"
transport = "https"
auth = "none"
[listeners.tls]
cert_chain_file = "{}"
private_key_file = "{}"
"#,
        path_text(chain),
        path_text(key)
    )
}

async fn start(
    dir: &common::TempDir,
    text: &str,
) -> (HttpServer, Vec<(String, std::net::SocketAddr)>) {
    let path = dir.path().join("proxy.toml");
    fs::write(&path, text).expect("write proxy config");
    let config = Arc::new(Config::load(&path).expect("valid HTTPS proxy config"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind HTTPS proxy");
    let addresses = server.addresses().to_vec();
    (server, addresses)
}

fn address(addresses: &[(String, std::net::SocketAddr)], id: &str) -> std::net::SocketAddr {
    addresses
        .iter()
        .find(|(name, _)| name == id)
        .map(|(_, address)| *address)
        .expect("listener address")
}

fn proxy_ca(dir: &common::TempDir) -> Arc<rustls::ClientConfig> {
    m06::client_config(&dir.path().join("proxy_ca.pem"))
}

fn certificate_error(error: &io::Error, expected: &str) {
    let rustls_error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .unwrap_or_else(|| panic!("not a certificate error: {error:?}"));
    let text = format!("{rustls_error:?}");
    assert!(
        text.contains(expected),
        "expected {expected} certificate failure, got {text}"
    );
}

#[tokio::test]
async fn m06_io01_interim_and_pipeline_order_survives_tls_flush() {
    let dir = common::TempDir::new("m06-io01");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|request, _| match request.target.as_str() {
        "/plain" => m03::response("200 OK", &[], b"second"),
        _ => {
            let mut bytes = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n".to_vec();
            bytes.extend_from_slice(b"HTTP/1.1 102 Processing\r\n\r\n");
            bytes.extend_from_slice(&m03::response(
                "200 OK",
                &[("Content-Length", "5"), ("X-Part", "first")],
                b"first",
            ));
            bytes
        }
    })
    .await
    .expect("origin");
    let (server, addresses) = start(
        &dir,
        &https_config(
            &dir.path().join("proxy_chain.pem"),
            &dir.path().join("proxy_key.pem"),
            Tuning::default(),
            "",
            "443",
        ),
    )
    .await;
    let address = address(&addresses, "proxy");
    let mut client = m06::connect_tls(address, "localhost", proxy_ca(&dir))
        .await
        .expect("TLS client");

    let mut first = m03::request("GET", origin.address, "/mixed", &[], b"");
    let mut second = m03::request("GET", origin.address, "/plain", &[], b"");
    first.append(&mut second);
    client.send(&first).await.expect("pipeline");
    let one = client.read_response().await.expect("first response");
    let two = client.read_response().await.expect("second response");
    assert_eq!(
        one.interim
            .iter()
            .map(|head| head.status)
            .collect::<Vec<_>>(),
        vec![103, 102]
    );
    assert_eq!(one.head.header("x-part"), Some("first"));
    assert_eq!(one.text(), "first");
    assert_eq!(two.text(), "second");
    assert_eq!(origin.requests.lock().unwrap().len(), 2);

    server.shutdown().await;
}

#[tokio::test]
async fn m06_http01_head_expect_continue_and_range_over_tls() {
    let dir = common::TempDir::new("m06-http01-extra");
    m06::generate_pki(dir.path());
    let origin =
        m03::spawn_origin(
            |request, _| match (request.method.as_str(), request.target.as_str()) {
                ("HEAD", _) => m03::response("200 OK", &[("Content-Length", "5")], b"hello"),
                ("GET", "/range") => m03::response(
                    "206 Partial Content",
                    &[("Content-Range", "bytes 0-3/10")],
                    b"part",
                ),
                _ => m03::response("200 OK", &[], &request.body),
            },
        )
        .await
        .expect("origin");
    let (server, addresses) = start(
        &dir,
        &https_config(
            &dir.path().join("proxy_chain.pem"),
            &dir.path().join("proxy_key.pem"),
            Tuning::default(),
            "",
            "443",
        ),
    )
    .await;
    let address = address(&addresses, "proxy");
    let mut client = m06::connect_tls(address, "localhost", proxy_ca(&dir))
        .await
        .expect("TLS client");

    client
        .send(&m03::request("HEAD", origin.address, "/", &[], b""))
        .await
        .expect("HEAD");
    let head = client.read_head().await.expect("HEAD response");
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-length"), Some("5"));

    let headers = format!(
        "POST http://{}/echo HTTP/1.1\r\nHost: {}\r\nContent-Length: 7\r\nExpect: 100-continue\r\n\r\n",
        origin.address, origin.address
    )
    .into_bytes();
    client.send(&headers).await.expect("expect headers");
    let interim = client.read_head().await.expect("100 Continue");
    assert_eq!(interim.status, 100);
    client.send(b"payload").await.expect("expect body");
    let response = client.read_response().await.expect("echo response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "payload");

    client
        .send(&m03::request("GET", origin.address, "/range", &[], b""))
        .await
        .expect("range");
    let range = client.read_response().await.expect("range response");
    assert_eq!(range.head.status, 206);
    assert_eq!(range.head.header("content-range"), Some("bytes 0-3/10"));
    assert_eq!(range.body, b"part");

    server.shutdown().await;
}

#[tokio::test]
async fn m06_eof01_abrupt_client_eof_is_not_a_complete_request() {
    let dir = common::TempDir::new("m06-eof01-abrupt");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"never"))
        .await
        .expect("origin");
    let (server, addresses) = start(
        &dir,
        &https_config(
            &dir.path().join("proxy_chain.pem"),
            &dir.path().join("proxy_key.pem"),
            Tuning::default(),
            "",
            "443",
        ),
    )
    .await;
    let address = address(&addresses, "proxy");

    let mut client = m06::connect_tls(address, "localhost", proxy_ca(&dir))
        .await
        .expect("TLS client");
    let mut request = format!(
        "POST http://{}/partial HTTP/1.1\r\nHost: {}\r\nContent-Length: 100\r\n\r\n",
        origin.address, origin.address
    )
    .into_bytes();
    request.extend_from_slice(b"0123456789");
    client.send(&request).await.expect("partial request");
    let (tcp, _connection) = client.into_inner().into_inner();
    drop(tcp);

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        origin.requests.lock().unwrap().is_empty(),
        "truncated body reached the origin as a complete request"
    );

    let mut healthy = m06::connect_tls(address, "localhost", proxy_ca(&dir))
        .await
        .expect("server remains healthy");
    healthy
        .send(&m03::request("GET", origin.address, "/", &[], b""))
        .await
        .expect("send healthy");
    assert_eq!(
        healthy.read_response().await.expect("healthy").head.status,
        200
    );

    server.shutdown().await;
}

#[tokio::test]
async fn m06_time01_tunnel_application_progress_resets_idle_without_control_keepalive() {
    let dir = common::TempDir::new("m06-time01-tunnel");
    m06::generate_pki(dir.path());
    let echo = m04::spawn_echo_origin(None).await.expect("echo origin");
    let tuning = Tuning {
        idle_ms: 3_000,
        ..Tuning::default()
    };
    let (server, addresses) = start(
        &dir,
        &https_config(
            &dir.path().join("proxy_chain.pem"),
            &dir.path().join("proxy_key.pem"),
            tuning,
            "",
            &echo.address.port().to_string(),
        ),
    )
    .await;
    let address = address(&addresses, "proxy");
    let mut client = m06::connect_tls(address, "localhost", proxy_ca(&dir))
        .await
        .expect("TLS client");
    client
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                echo.address, echo.address
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT");
    assert_eq!(client.read_head().await.expect("200").status, 200);

    for index in 0..5 {
        let payload = format!("ping-{index}");
        client.send(payload.as_bytes()).await.expect("tunnel write");
        assert_eq!(
            client
                .read_exact_bytes(payload.len())
                .await
                .expect("tunnel echo"),
            payload.as_bytes()
        );
        tokio::time::sleep(Duration::from_millis(700)).await;
    }

    let started = Instant::now();
    let closed = tokio::time::timeout(Duration::from_secs(6), client.read_until_eof()).await;
    assert!(
        closed.is_ok(),
        "idle tunnel did not close after application progress stopped"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(2_000),
        "idle tunnel closed while application traffic was still flowing"
    );
    assert!(
        started.elapsed() < Duration::from_millis(5_000),
        "idle tunnel exceeded its bound: {:?}",
        started.elapsed()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m06_limit01_client_permit_and_handshake_slot_lifecycle() {
    let dir = common::TempDir::new("m06-limit01-lifecycle");
    m06::generate_pki(dir.path());
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let tuning = Tuning {
        max_client: 1,
        max_handshaking: 1,
        ..Tuning::default()
    };
    let text = https_config(&chain, &key, tuning, &second_listener(&chain, &key), "443");
    let (server, addresses) = start(&dir, &text).await;
    let first = address(&addresses, "proxy");
    let second = address(&addresses, "second");

    // The client permit is acquired at TCP accept, before any TLS bytes.
    let held = TcpStream::connect(first).await.expect("hold client permit");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        m06::connect_tls(second, "localhost", proxy_ca(&dir))
            .await
            .is_err(),
        "a second connection bypassed max_client_connections during TLS"
    );
    drop(held);

    // A successful handshake keeps the client permit for the whole TLS
    // connection but releases the shared handshake slot.
    let first_client = m06::connect_tls(first, "localhost", proxy_ca(&dir))
        .await
        .expect("first TLS connection");
    assert!(
        m06::connect_tls(second, "localhost", proxy_ca(&dir))
            .await
            .is_err(),
        "idle TLS connection released the client permit too early"
    );
    drop(first_client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let recovered = m06::connect_tls(second, "localhost", proxy_ca(&dir))
        .await
        .expect("client permit returned");
    drop(recovered);
    server.shutdown().await;

    let tuning = Tuning {
        max_client: 4,
        max_handshaking: 1,
        ..Tuning::default()
    };
    let text = https_config(&chain, &key, tuning, &second_listener(&chain, &key), "443");
    let (server, addresses) = start(&dir, &text).await;
    let first = address(&addresses, "proxy");
    let second = address(&addresses, "second");
    let first_client = m06::connect_tls(first, "localhost", proxy_ca(&dir))
        .await
        .expect("first handshake");
    let second_client = m06::connect_tls(second, "localhost", proxy_ca(&dir))
        .await
        .expect("handshake slot released after a completed handshake");
    drop(first_client);
    drop(second_client);
    server.shutdown().await;
}

#[tokio::test]
async fn m06_cancel01_shutdown_bounds_tls_flush_and_new_admission() {
    let dir = common::TempDir::new("m06-cancel01-flush");
    m06::generate_pki(dir.path());
    let origin =
        m03::spawn_origin(|_, _| m03::response("200 OK", &[], &vec![0x7e; 8 * 1024 * 1024]))
            .await
            .expect("origin");
    let tuning = Tuning {
        idle_ms: 30_000,
        shutdown_ms: 400,
        ..Tuning::default()
    };
    let (server, addresses) = start(
        &dir,
        &https_config(
            &dir.path().join("proxy_chain.pem"),
            &dir.path().join("proxy_key.pem"),
            tuning,
            "",
            "443",
        ),
    )
    .await;
    let address = address(&addresses, "proxy");
    let mut client = m06::connect_tls(address, "localhost", proxy_ca(&dir))
        .await
        .expect("TLS client");
    client
        .send(&m03::request("GET", origin.address, "/large", &[], b""))
        .await
        .expect("send large");
    assert_eq!(client.read_head().await.expect("head").status, 200);
    tokio::time::sleep(Duration::from_millis(150)).await;

    let started = Instant::now();
    server.shutdown().await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(1800),
        "shutdown waited for TLS flush/close longer than its absolute bound: {elapsed:?}"
    );
    let closed = tokio::time::timeout(Duration::from_secs(1), client.read_until_eof()).await;
    assert!(
        matches!(closed, Ok(Ok(_)) | Ok(Err(_)) | Err(_)),
        "client connection stayed live after forced shutdown"
    );
    assert!(
        m06::connect_tls(address, "localhost", proxy_ca(&dir))
            .await
            .is_err(),
        "new TLS admission started during/after shutdown"
    );
}

#[tokio::test]
async fn m06_time01_slow_tls_reader_does_not_trip_idle_or_lose_body() {
    let dir = common::TempDir::new("m06-time01-slow-reader");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|request, _| {
        if request.target == "/slow" {
            m03::response("200 OK", &[], &vec![0x5a; 512 * 1024])
        } else {
            m03::response("200 OK", &[], b"after-slow")
        }
    })
    .await
    .expect("origin");
    let tuning = Tuning {
        idle_ms: 5_000,
        ..Tuning::default()
    };
    let (server, addresses) = start(
        &dir,
        &https_config(
            &dir.path().join("proxy_chain.pem"),
            &dir.path().join("proxy_key.pem"),
            tuning,
            "",
            "443",
        )
        .replace(
            "header_read_timeout_ms = 2000",
            "header_read_timeout_ms = 10000",
        ),
    )
    .await;
    let proxy = address(&addresses, "proxy");
    let mut client = m06::connect_tls(proxy, "localhost", proxy_ca(&dir))
        .await
        .expect("TLS client");
    client
        .send(&m03::request("GET", origin.address, "/slow", &[], b""))
        .await
        .expect("send slow");
    let head = client.read_head().await.expect("slow head");
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-length"), Some("524288"));
    let mut received = 0;
    for _ in 0..32 {
        let chunk = client
            .read_exact_bytes(16 * 1024)
            .await
            .expect("slow chunk");
        assert!(chunk.iter().all(|byte| *byte == 0x5a));
        received += chunk.len();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(received, 512 * 1024);

    client
        .send(&m03::request("GET", origin.address, "/after", &[], b""))
        .await
        .expect("send after slow");
    let response = client.read_response().await.expect("after slow");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "after-slow");
    server.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn m06_net01_bind_failure_releases_earlier_listeners() {
    let dir = common::TempDir::new("m06-net01-bind");
    m06::generate_pki(dir.path());
    let free = m03::free_port();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("occupy port");
    let occupied_port = occupied.local_addr().expect("occupied address").port();
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let text = https_config(
        &chain,
        &key,
        Tuning::default(),
        &format!(
            r#"
[[listeners]]
id = "second"
bind = "127.0.0.1:{free}"
transport = "https"
auth = "none"
[listeners.tls]
cert_chain_file = "{}"
private_key_file = "{}"
"#,
            path_text(&chain),
            path_text(&key)
        ),
        "443",
    );
    let text = text.replace(
        "bind = \"127.0.0.1:3129\"",
        &format!("bind = \"127.0.0.1:{occupied_port}\""),
    );
    let path = dir.path().join("bind.toml");
    fs::write(&path, text).expect("write bind config");
    let config = Arc::new(Config::load(&path).expect("valid bind config"));
    assert!(
        HttpServer::bind(config).await.is_err(),
        "bind must fail when any listener address is occupied"
    );
    std::net::TcpListener::bind(("127.0.0.1", free))
        .expect("previously prepared listener socket was not released");
    drop(occupied);
}

#[tokio::test]
async fn m06_tls01_no_tls12_or_tls13_resumption_and_no_tickets() {
    let dir = common::TempDir::new("m06-tls01-resumption");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"no-session"))
        .await
        .expect("origin");
    let (server, addresses) = start(
        &dir,
        &https_config(
            &dir.path().join("proxy_chain.pem"),
            &dir.path().join("proxy_key.pem"),
            Tuning::default(),
            "",
            "443",
        ),
    )
    .await;
    let address = address(&addresses, "proxy");
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let store = Arc::new(m06::RecordingSessions::default());
        let config = m06::client_config_recording(
            &dir.path().join("proxy_ca.pem"),
            Arc::clone(&store),
            Some(version),
        );
        let mut client = m06::connect_tls(address, "localhost", Arc::clone(&config))
            .await
            .expect("TLS client");
        client
            .send(&m03::request("GET", origin.address, "/", &[], b""))
            .await
            .expect("send");
        assert_eq!(
            client.read_response().await.expect("response").head.status,
            200
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(client);
        assert_eq!(store.tls12_stored(), 0, "TLS1.2 session id/ticket stored");
        assert_eq!(store.tls13_stored(), 0, "TLS1.3 ticket stored");

        let mut again = m06::connect_tls(address, "localhost", config)
            .await
            .expect("second full handshake");
        again
            .send(&m03::request("GET", origin.address, "/", &[], b""))
            .await
            .expect("send second");
        assert_eq!(
            again.read_response().await.expect("second").head.status,
            200
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn m06_tls03_malformed_and_oversized_client_hello_are_closed() {
    let dir = common::TempDir::new("m06-tls03-malformed");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"healthy"))
        .await
        .expect("origin");
    let (server, addresses) = start(
        &dir,
        &https_config(
            &dir.path().join("proxy_chain.pem"),
            &dir.path().join("proxy_key.pem"),
            Tuning::default(),
            "",
            "443",
        )
        .replace("handshake_timeout_ms = 3000", "handshake_timeout_ms = 500"),
    )
    .await;
    let address = address(&addresses, "proxy");

    for attempt in 0..10 {
        let mut stream = TcpStream::connect(address).await.expect("junk TCP");
        let payload: Vec<u8> = if attempt % 2 == 0 {
            let mut record = vec![0x16, 0x03, 0x03, 0xff, 0xff];
            record.extend(std::iter::repeat_n(0x41, 64));
            record
        } else {
            (0..64 * 1024).map(|index| (index % 251) as u8).collect()
        };
        let _ = stream.write_all(&payload).await;
        let mut buffer = [0_u8; 64];
        let closed = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer)).await;
        match closed {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(read)) => {
                assert_eq!(
                    buffer[0],
                    0x15,
                    "malformed ClientHello received non-alert TLS/plaintext bytes: {:?}",
                    &buffer[..read]
                );
            }
            Err(_) => panic!("malformed ClientHello stayed open"),
        }
    }

    let mut client = m06::connect_tls(address, "localhost", proxy_ca(&dir))
        .await
        .expect("valid TLS after junk");
    client
        .send(&m03::request("GET", origin.address, "/", &[], b""))
        .await
        .expect("send");
    assert_eq!(client.read_response().await.expect("200").head.status, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn m06_ops01_restart_reads_the_new_pair_and_running_snapshot_ignores_files() {
    let dir = common::TempDir::new("m06-ops01-restart");
    m06::generate_pki(dir.path());
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let alt_chain = dir.path().join("proxy_alt_chain.pem");
    let alt_key = dir.path().join("proxy_alt_key.pem");
    let text = https_config(&chain, &key, Tuning::default(), "", "443");
    let (server, addresses) = start(&dir, &text).await;
    let proxy = address(&addresses, "proxy");

    let client = m06::connect_tls(proxy, "localhost", proxy_ca(&dir))
        .await
        .expect("original localhost certificate");
    drop(client);
    let wrong_name = match m06::connect_tls(proxy, "alt.localhost", proxy_ca(&dir)).await {
        Ok(_) => panic!("alt name unexpectedly accepted before restart"),
        Err(error) => error,
    };
    certificate_error(&wrong_name, "NotValidForName");

    fs::copy(&alt_chain, &chain).expect("replace chain file");
    fs::copy(&alt_key, &key).expect("replace key file");
    let running = m06::connect_tls(proxy, "localhost", proxy_ca(&dir))
        .await
        .expect("running snapshot keeps the old pair");
    drop(running);
    server.shutdown().await;

    let (server, addresses) = start(&dir, &text).await;
    let proxy = address(&addresses, "proxy");
    let mut restarted = m06::connect_tls(proxy, "alt.localhost", proxy_ca(&dir))
        .await
        .expect("restart reads the new pair from disk");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"new-pair"))
        .await
        .expect("origin");
    restarted
        .send(&m03::request("GET", origin.address, "/", &[], b""))
        .await
        .expect("send");
    assert_eq!(
        restarted.read_response().await.expect("new pair").text(),
        "new-pair"
    );
    let old_name = match m06::connect_tls(proxy, "localhost", proxy_ca(&dir)).await {
        Ok(_) => panic!("old localhost certificate still active after restart"),
        Err(error) => error,
    };
    certificate_error(&old_name, "NotValidForName");
    server.shutdown().await;
}

#[test]
fn m06_cpu01_https_handshakes_work_with_one_and_two_workers() {
    for workers in [1, 2] {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .expect("build test runtime");
        runtime.block_on(async {
            let dir = common::TempDir::new("m06-cpu01-workers");
            m06::generate_pki(dir.path());
            let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"cpu"))
                .await
                .expect("origin");
            let (server, addresses) = start(
                &dir,
                &https_config(
                    &dir.path().join("proxy_chain.pem"),
                    &dir.path().join("proxy_key.pem"),
                    Tuning {
                        max_handshaking: 4,
                        ..Tuning::default()
                    },
                    "",
                    "443",
                ),
            )
            .await;
            let address = address(&addresses, "proxy");
            let started = Instant::now();
            let mut tasks = Vec::new();
            for _ in 0..4 {
                let ca = proxy_ca(&dir);
                let origin = origin.address;
                tasks.push(tokio::spawn(async move {
                    let handshake = Instant::now();
                    let mut client = m06::connect_tls(address, "localhost", ca)
                        .await
                        .expect("TLS client");
                    let handshake = handshake.elapsed();
                    client
                        .send(&m03::request("GET", origin, "/", &[], b""))
                        .await
                        .expect("send");
                    let status = client.read_response().await.expect("response").head.status;
                    (status, handshake)
                }));
            }
            let mut handshakes = Vec::new();
            for task in tasks {
                let (status, handshake) = task.await.expect("join TLS client");
                assert_eq!(status, 200, "workers={workers}");
                handshakes.push(handshake);
            }
            handshakes.sort();
            eprintln!(
                "M06-CPU-01 workers={workers} handshakes=4 elapsed_ms={} first_ms={} last_ms={}",
                started.elapsed().as_millis(),
                handshakes.first().expect("first").as_millis(),
                handshakes.last().expect("last").as_millis()
            );
            server.shutdown().await;
        });
    }
}
