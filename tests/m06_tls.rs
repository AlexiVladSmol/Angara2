//! M06 TLS listener, certificate, HTTP, and layered CONNECT tests.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use angara::config::Config;
use angara::http::HttpServer;
use common::m03::{self, RawClient};
use common::m05;
use common::m06;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

fn config_text(chain: &Path, key: &Path, connect_port: u16) -> String {
    format!(
        r#"
schema_version = 1
[runtime]
worker_threads = 2
[limits]
max_connections = 64
max_client_connections = 32
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 2000
[tls]
max_handshaking = 8
handshake_timeout_ms = 2000
[[listeners]]
id = "proxy"
bind = "127.0.0.1:3129"
transport = "https"
auth = "none"
[listeners.tls]
cert_chain_file = "{}"
private_key_file = "{}"
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
pool_max_idle = 8
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 30000
[connect]
allowed_ports = [{connect_port}]
half_close_timeout_ms = 1200
"#,
        chain.to_string_lossy().replace('\\', "/"),
        key.to_string_lossy().replace('\\', "/"),
    )
}

async fn start_proxy(
    dir: &common::TempDir,
    chain: &Path,
    key: &Path,
    connect_port: u16,
) -> (HttpServer, std::net::SocketAddr) {
    start_proxy_with_config(dir, &config_text(chain, key, connect_port)).await
}

async fn start_proxy_with_config(
    dir: &common::TempDir,
    text: &str,
) -> (HttpServer, std::net::SocketAddr) {
    let (server, addresses) = start_proxy_multi(dir, text).await;
    (server, addresses[0].1)
}

async fn start_proxy_multi(
    dir: &common::TempDir,
    text: &str,
) -> (HttpServer, Vec<(String, std::net::SocketAddr)>) {
    let config_path = dir.path().join("proxy.toml");
    fs::write(&config_path, text).expect("write proxy config");
    let config = Arc::new(Config::load(&config_path).expect("valid HTTPS proxy config"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind HTTPS proxy");
    let addresses = server.addresses().to_vec();
    (server, addresses)
}

fn auth_config_text(
    chain: &Path,
    key: &Path,
    users_file: &Path,
    access_rules: &str,
    connect_port: u16,
) -> String {
    let users = users_file.to_string_lossy().replace('\\', "/");
    let auth = format!(
        "[auth]\nusers_file = \"{users}\"\nmax_verifying = 2\nverify_timeout_ms = 30000\n\n"
    );
    config_text(chain, key, connect_port)
        .replace("auth = \"none\"", "auth = \"basic\"")
        .replace("[listeners.tls]", &format!("{auth}[listeners.tls]"))
        .replace(
            "[[access.rules]]\nid = \"allow\"\naction = \"allow\"",
            access_rules,
        )
}

fn client_config(ca: &Path) -> Arc<rustls::ClientConfig> {
    m06::client_config(ca)
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

use std::io;

#[tokio::test]
async fn m06_auth01_basic_policy_and_source_gate_over_tls() {
    let dir = common::TempDir::new("m06-auth01");
    m06::generate_pki(dir.path());
    let users = dir.path().join("users.toml");
    m05::write_secure(
        &users,
        &m05::users_text(&[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ]),
    );
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"secure"))
        .await
        .expect("origin");
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let text = auth_config_text(
        &chain,
        &key,
        &users,
        "[[access.rules]]\nid = \"alice\"\naction = \"allow\"\nusers = [\"alice\"]\n",
        443,
    );
    let (server, address) = start_proxy_with_config(&dir, &text).await;

    let request = |auth: Option<(&str, &str)>| {
        let mut value = format!(
            "GET http://{}/ HTTP/1.1\r\nHost: {}\r\n",
            origin.address, origin.address
        );
        if let Some((user, password)) = auth {
            value.push_str(&format!(
                "Proxy-Authorization: {}\r\n",
                m05::authorization(user, password)
            ));
        }
        value.push_str("\r\n");
        value.into_bytes()
    };

    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("alice TLS client");
    client
        .send(&request(Some(("alice", "alice-secret"))))
        .await
        .expect("alice request");
    assert_eq!(
        client.read_response().await.expect("alice 200").head.status,
        200
    );
    client.send(&request(None)).await.expect("missing request");
    let missing = client.read_response().await.expect("missing 407");
    assert_eq!(missing.head.status, 407);
    assert_eq!(
        missing.head.header("proxy-authenticate"),
        Some("Basic realm=\"Angara\", charset=\"UTF-8\"")
    );
    assert_eq!(missing.head.header("connection"), Some("close"));
    assert!(client.read_response().await.is_err());

    let mut bob_client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("bob TLS client");
    bob_client
        .send(&request(Some(("bob", "bob-secret"))))
        .await
        .expect("bob request");
    assert_eq!(
        bob_client
            .read_response()
            .await
            .expect("bob 403")
            .head
            .status,
        403
    );

    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("wrong request client");
    client
        .send(&request(Some(("alice", "wrong"))))
        .await
        .expect("wrong request");
    assert_eq!(
        client.read_response().await.expect("wrong 407").head.status,
        407
    );

    // IP deny after successful auth is still a 403, not a certificate or auth
    // failure.
    let denied = auth_config_text(
        &chain,
        &key,
        &users,
        "[[access.rules]]\nid = \"allow\"\naction = \"allow\"\n",
        443,
    )
    .replace(
        "[[access.ip_rules]]\nid = \"loopback\"\naction = \"allow\"\nnetworks = [\"127.0.0.0/8\"]\nallow_special = true",
        "",
    );
    let (denied_server, denied_address) = start_proxy_with_config(&dir, &denied).await;
    let mut client = m06::connect_tls(
        denied_address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("denied client");
    client
        .send(&request(Some(("alice", "alice-secret"))))
        .await
        .expect("denied request");
    assert_eq!(
        client.read_response().await.expect("ip 403").head.status,
        403
    );
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Early source gate happens before the TLS handshake and before auth.
    let source_denied = text.replace(
        "source_allow = [\"127.0.0.0/8\"]",
        "source_allow = [\"192.0.2.0/24\"]",
    );
    let (source_server, source_address) = start_proxy_with_config(&dir, &source_denied).await;
    assert!(
        m06::connect_tls(
            source_address,
            "localhost",
            client_config(&dir.path().join("proxy_ca.pem")),
        )
        .await
        .is_err(),
        "source-denied TLS connection must close before handshake"
    );

    // HTTPS Basic on a wildcard bind is protected by TLS and does not need
    // the plaintext allow_insecure_basic opt-in.
    let wildcard = text.replace("127.0.0.1:3129", "0.0.0.0:3129");
    let (wildcard_server, wildcard_address) = start_proxy_with_config(&dir, &wildcard).await;
    let wildcard_address = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        wildcard_address.port(),
    );
    let mut client = m06::connect_tls(
        wildcard_address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("wildcard TLS client");
    client
        .send(&request(Some(("alice", "alice-secret"))))
        .await
        .expect("wildcard request");
    assert_eq!(
        client
            .read_response()
            .await
            .expect("wildcard 200")
            .head
            .status,
        200
    );

    server.shutdown().await;
    denied_server.shutdown().await;
    source_server.shutdown().await;
    wildcard_server.shutdown().await;
}

fn two_tls_config(chain: &Path, key: &Path, max_handshaking: u16, timeout_ms: u16) -> String {
    let cert = chain.to_string_lossy().replace('\\', "/");
    let key = key.to_string_lossy().replace('\\', "/");
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
shutdown_timeout_ms = 1500
[tls]
max_handshaking = {max_handshaking}
handshake_timeout_ms = {timeout_ms}
[[listeners]]
id = "proxy"
bind = "127.0.0.1:3129"
transport = "https"
auth = "none"
[listeners.tls]
cert_chain_file = "{cert}"
private_key_file = "{key}"
[[listeners]]
id = "second"
bind = "127.0.0.1:3130"
transport = "https"
auth = "none"
[listeners.tls]
cert_chain_file = "{cert}"
private_key_file = "{key}"
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
[connect]
allowed_ports = [443]
half_close_timeout_ms = 1000
"#
    )
}

#[tokio::test]
async fn m06_con01_connect_early_bytes_and_tunnel_over_outer_tls() {
    let dir = common::TempDir::new("m06-con01-early");
    m06::generate_pki(dir.path());
    let echo = common::m04::spawn_echo_origin(None)
        .await
        .expect("echo origin");
    let (server, address) = start_proxy(
        &dir,
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("proxy_key.pem"),
        echo.address.port(),
    )
    .await;
    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("outer TLS");
    let early = b"early-connect-payload";
    let mut request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        echo.address, echo.address
    )
    .into_bytes();
    request.extend_from_slice(early);
    client
        .send(&request)
        .await
        .expect("CONNECT with early bytes");
    assert_eq!(client.read_head().await.expect("200").status, 200);
    assert_eq!(
        client.read_exact_bytes(early.len()).await.expect("echo"),
        early
    );
    client.send(b"tunnel-after-connect").await.expect("tunnel");
    assert_eq!(
        client
            .read_exact_bytes(b"tunnel-after-connect".len())
            .await
            .expect("echo after connect"),
        b"tunnel-after-connect"
    );
    assert_eq!(echo.accepts.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(client);
    server.shutdown().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn m06_pol01_user_routing_egress_and_connect_port_gate_over_tls() {
    let dir = common::TempDir::new("m06-pol01");
    m06::generate_pki(dir.path());
    let users = dir.path().join("users.toml");
    m05::write_secure(
        &users,
        &m05::users_text(&[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ]),
    );
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"routed"))
        .await
        .expect("origin");
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let text = auth_config_text(
        &chain,
        &key,
        &users,
        "[[access.rules]]\nid = \"users\"\naction = \"allow\"\nusers = [\"alice\", \"bob\"]\n",
        origin.address.port(),
    ) + r#"
[[egress]]
id = "via-a"
mode = "bind_ip"
bind_ip = "127.0.0.1"

[[egress]]
id = "via-b"
mode = "bind_ip"
bind_ip = "127.0.0.2"

[routing]
default_egress = "via-a"

[[routing.rules]]
id = "alice"
egress_id = "via-a"
users = ["alice"]

[[routing.rules]]
id = "bob"
egress_id = "via-b"
users = ["bob"]
"#;
    let (server, address) = start_proxy_with_config(&dir, &text).await;
    for (user, password, expected) in [
        ("alice", "alice-secret", "127.0.0.1"),
        ("bob", "bob-secret", "127.0.0.2"),
    ] {
        let mut client = m06::connect_tls(
            address,
            "localhost",
            client_config(&dir.path().join("proxy_ca.pem")),
        )
        .await
        .expect("TLS client");
        client
            .send(&m03::request(
                "GET",
                origin.address,
                "/",
                &[("Proxy-Authorization", &m05::authorization(user, password))],
                b"",
            ))
            .await
            .expect("send");
        assert_eq!(client.read_response().await.expect("200").head.status, 200);
        let recorded = origin.requests.lock().unwrap();
        assert_eq!(
            recorded.last().expect("recorded").peer.ip().to_string(),
            expected,
            "{user}"
        );
    }

    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("CONNECT client");
    client
        .send(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: {}\r\n\r\n",
                9,
                9,
                m05::authorization("alice", "alice-secret")
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT blocked port");
    assert_eq!(client.read_response().await.expect("403").head.status, 403);

    server.shutdown().await;
}

#[tokio::test]
async fn m06_eof01_tls13_site_fin_preserves_reverse_drain() {
    let dir = common::TempDir::new("m06-eof01");
    m06::generate_pki(dir.path());
    let site = m06::spawn_half_close_site(
        m06::server_config(
            &dir.path().join("site_chain.pem"),
            &dir.path().join("site_key.pem"),
        ),
        b"origin-finished".to_vec(),
    )
    .await
    .expect("half-close site");
    let (server, address) = start_proxy(
        &dir,
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("proxy_key.pem"),
        site.address.port(),
    )
    .await;

    let mut outer = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("outer TLS");
    outer
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                site.address, site.address
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT");
    assert_eq!(outer.read_head().await.expect("200").status, 200);
    let inner = TlsConnector::from(client_config(&dir.path().join("site_ca.pem")))
        .connect(
            ServerName::try_from("localhost").expect("name"),
            outer.into_inner(),
        )
        .await
        .expect("site TLS");
    let mut site_client = RawClient::from_stream(inner);
    assert_eq!(
        site_client
            .read_until_eof()
            .await
            .expect("origin close_notify"),
        b"origin-finished"
    );
    site_client
        .send(b"after-origin-close-notify")
        .await
        .expect("reverse write after peer close_notify");
    site_client
        .shutdown_write()
        .await
        .expect("client close_notify");
    assert!(
        common::m04::wait_until(|| {
            site.received.lock().unwrap().as_slice() == b"after-origin-close-notify"
        })
        .await,
        "origin did not receive reverse bytes: {:?}",
        site.received.lock().unwrap()
    );
    assert_eq!(site.ties.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(site_client);
    server.shutdown().await;
}

#[tokio::test]
async fn m06_eof01_tls12_closure_and_tls13_response_close() {
    let dir = common::TempDir::new("m06-eof01-close");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"closed"))
        .await
        .expect("origin");
    let (server, address) = start_proxy(
        &dir,
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("proxy_key.pem"),
        443,
    )
    .await;
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let config =
            m06::client_config_version(&dir.path().join("proxy_ca.pem"), version, &[b"http/1.1"]);
        let mut client = m06::connect_tls(address, "localhost", config)
            .await
            .expect("TLS client");
        client
            .send(&m03::request(
                "GET",
                origin.address,
                "/",
                &[("Connection", "close")],
                b"",
            ))
            .await
            .expect("send");
        let response = client.read_response().await.expect("response");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.text(), "closed");
        let trailing = client
            .read_until_eof()
            .await
            .expect("normal close must end with TLS close_notify");
        assert!(
            trailing.is_empty(),
            "unexpected bytes after a complete close response"
        );
    }
    server.shutdown().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn m06_net01_two_tls_listeners_with_different_certificates_and_ipv6() {
    let dir = common::TempDir::new("m06-net01");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"net"))
        .await
        .expect("origin");
    let v4 = dir
        .path()
        .join("proxy_chain.pem")
        .to_string_lossy()
        .replace('\\', "/");
    let v4_key = dir
        .path()
        .join("proxy_key.pem")
        .to_string_lossy()
        .replace('\\', "/");
    let v6 = dir
        .path()
        .join("proxy_p256_chain.pem")
        .to_string_lossy()
        .replace('\\', "/");
    let v6_key = dir
        .path()
        .join("proxy_p256_key.pem")
        .to_string_lossy()
        .replace('\\', "/");
    let text = format!(
        r#"
schema_version = 1
[runtime]
worker_threads = 2
[limits]
max_connections = 32
max_client_connections = 16
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 1500
[tls]
max_handshaking = 4
handshake_timeout_ms = 2000
[[listeners]]
id = "v4"
bind = "127.0.0.1:3129"
transport = "https"
auth = "none"
[listeners.tls]
cert_chain_file = "{v4}"
private_key_file = "{v4_key}"
[[listeners]]
id = "v6"
bind = "[::1]:3130"
transport = "https"
auth = "none"
[listeners.tls]
cert_chain_file = "{v6}"
private_key_file = "{v6_key}"
[access]
source_allow = ["127.0.0.0/8", "::1/128"]
ip_default = "deny"
[[access.rules]]
id = "allow"
action = "allow"
[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8", "::1/128"]
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
[connect]
allowed_ports = [443]
half_close_timeout_ms = 1000
"#
    );
    let (server, addresses) = start_proxy_multi(&dir, &text).await;
    for (_, address) in addresses {
        let mut client = m06::connect_tls(
            address,
            "localhost",
            client_config(&dir.path().join("proxy_ca.pem")),
        )
        .await
        .expect("TLS listener");
        client
            .send(&m03::request("GET", origin.address, "/", &[], b""))
            .await
            .expect("send");
        assert_eq!(client.read_response().await.expect("200").head.status, 200);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn m06_cpu01_tls_handshake_does_not_block_independent_http_listener() {
    let dir = common::TempDir::new("m06-cpu01");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"independent"))
        .await
        .expect("origin");
    let chain = dir
        .path()
        .join("proxy_chain.pem")
        .to_string_lossy()
        .replace('\\', "/");
    let key = dir
        .path()
        .join("proxy_key.pem")
        .to_string_lossy()
        .replace('\\', "/");
    let text = format!(
        r#"
schema_version = 1
[runtime]
worker_threads = 2
[limits]
max_connections = 32
max_client_connections = 16
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 1500
[tls]
max_handshaking = 1
handshake_timeout_ms = 5000
[[listeners]]
id = "plain"
bind = "127.0.0.1:3128"
transport = "http"
auth = "none"
[[listeners]]
id = "secure"
bind = "127.0.0.1:3129"
transport = "https"
auth = "none"
[listeners.tls]
cert_chain_file = "{chain}"
private_key_file = "{key}"
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
[connect]
allowed_ports = [443]
half_close_timeout_ms = 1000
"#
    );
    let (server, addresses) = start_proxy_multi(&dir, &text).await;
    let plain = addresses
        .iter()
        .find(|(id, _)| id == "plain")
        .expect("plain address")
        .1;
    let secure = addresses
        .iter()
        .find(|(id, _)| id == "secure")
        .expect("secure address")
        .1;

    let held = tokio::net::TcpStream::connect(secure)
        .await
        .expect("hold TLS handshake");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = std::time::Instant::now();
    let mut client = RawClient::connect(plain).await.expect("plain");
    client
        .send(&m03::request("GET", origin.address, "/", &[], b""))
        .await
        .expect("plain send");
    assert_eq!(
        client.read_response().await.expect("plain").head.status,
        200
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "TLS handshake blocked the independent HTTP listener: {elapsed:?}"
    );
    drop(held);
    eprintln!("M06-CPU-01 independent_http_ms={}", elapsed.as_millis());
    server.shutdown().await;
}

#[tokio::test]
async fn m06_time01_header_clock_starts_after_tls_handshake() {
    let dir = common::TempDir::new("m06-time01");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"unexpected"))
        .await
        .expect("origin");
    let text = config_text(
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("proxy_key.pem"),
        443,
    )
    .replace(
        "header_read_timeout_ms = 2000",
        "header_read_timeout_ms = 300",
    );
    let (server, address) = start_proxy_with_config(&dir, &text).await;
    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("TLS handshake");
    let started = std::time::Instant::now();
    let closed = tokio::time::timeout(Duration::from_secs(2), client.read_head()).await;
    match closed {
        Ok(Ok(head)) => panic!("HTTP header clock returned a response: {head:?}"),
        Ok(Err(_)) => {}
        Err(_) => panic!("HTTP header clock did not close the idle TLS connection"),
    }
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "header clock closed before its configured bound: {:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "header clock exceeded its upper bound: {:?}",
        started.elapsed()
    );
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m06_ops01_tls_files_are_snapshot_bound_until_restart() {
    let dir = common::TempDir::new("m06-ops01");
    m06::generate_pki(dir.path());
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let (server, address) = start_proxy(&dir, &chain, &key, 443).await;
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"snapshot"))
        .await
        .expect("origin");

    fs::copy(dir.path().join("site_chain.pem"), &chain).expect("replace chain");
    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("running snapshot must keep the old certificate");
    client
        .send(&m03::request("GET", origin.address, "/", &[], b""))
        .await
        .expect("send");
    assert_eq!(client.read_response().await.expect("200").head.status, 200);
    assert!(
        Config::load(&dir.path().join("proxy.toml")).is_err(),
        "new startup must reject the replaced mismatching pair"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn m06_cancel01_pending_handshake_is_bounded_by_shutdown() {
    let dir = common::TempDir::new("m06-cancel01");
    m06::generate_pki(dir.path());
    let text = config_text(
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("proxy_key.pem"),
        443,
    )
    .replace(
        "handshake_timeout_ms = 2000",
        "handshake_timeout_ms = 10000",
    )
    .replace("shutdown_timeout_ms = 2000", "shutdown_timeout_ms = 400");
    let (server, address) = start_proxy_with_config(&dir, &text).await;
    let mut pending = tokio::net::TcpStream::connect(address)
        .await
        .expect("pending TCP");
    let started = std::time::Instant::now();
    server.shutdown().await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "shutdown waited for the handshake timeout: {:?}",
        started.elapsed()
    );
    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(Duration::from_millis(500), pending.read(&mut byte)).await;
    match closed {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("pending handshake socket produced unexpected bytes"),
        Err(_) => panic!("pending handshake socket remained live after shutdown"),
    }
}

#[tokio::test]
async fn m06_limit01_handshake_budget_is_shared_and_does_not_queue() {
    let dir = common::TempDir::new("m06-limit01");
    m06::generate_pki(dir.path());
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let text = two_tls_config(&chain, &key, 1, 2000);
    let config_path = dir.path().join("proxy.toml");
    fs::write(&config_path, text).expect("write config");
    let config = Arc::new(Config::load(&config_path).expect("config"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind two HTTPS listeners");
    let first = server.addresses()[0].1;
    let second = server.addresses()[1].1;

    let held = tokio::net::TcpStream::connect(first)
        .await
        .expect("hold handshake socket");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let overloaded = m06::connect_tls(
        second,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await;
    assert!(
        overloaded.is_err(),
        "second handshake must be rejected while the shared budget is full"
    );

    // Overload is a transport close, never plaintext HTTP 503.
    let mut raw = RawClient::connect(second).await.expect("raw overload");
    raw.send(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("raw send");
    match tokio::time::timeout(Duration::from_secs(3), raw.read_head()).await {
        Ok(Ok(head)) => panic!("handshake overload produced HTTP: {head:?}"),
        Ok(Err(_)) => {}
        Err(_) => panic!("handshake overload connection stayed open"),
    }

    drop(held);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"recovered"))
        .await
        .expect("origin");
    let mut client = m06::connect_tls(
        second,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("handshake slot recovered");
    client
        .send(&m03::request("GET", origin.address, "/", &[], b""))
        .await
        .expect("send recovered");
    assert_eq!(
        client.read_response().await.expect("recovered").head.status,
        200
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m06_tls03_partial_client_hello_uses_absolute_handshake_deadline() {
    let dir = common::TempDir::new("m06-tls03");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"unexpected"))
        .await
        .expect("origin");
    let text = config_text(
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("proxy_key.pem"),
        443,
    )
    .replace("handshake_timeout_ms = 2000", "handshake_timeout_ms = 250");
    let (server, address) = start_proxy_with_config(&dir, &text).await;

    // Plain HTTP is not silently interpreted as TLS, and the server must
    // actively close the rejected connection.
    let mut raw = RawClient::connect(address).await.expect("raw");
    raw.send(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("raw send");
    let started = std::time::Instant::now();
    match tokio::time::timeout(Duration::from_secs(2), raw.read_head()).await {
        Ok(Ok(head)) => panic!("plain HTTP received on TLS port: {head:?}"),
        Ok(Err(_)) => {}
        Err(_) => panic!("plain HTTP on TLS port was not closed"),
    }
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "plain HTTP rejection exceeded the handshake deadline: {:?}",
        started.elapsed()
    );

    // A fragmented/incomplete ClientHello does not extend the absolute
    // deadline with each received record.
    let mut slow = tokio::net::TcpStream::connect(address)
        .await
        .expect("slow TCP");
    let started = std::time::Instant::now();
    for _ in 0..5 {
        if slow.write_all(&[0x16, 0x03, 0x03, 0x00]).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(2), slow.read(&mut byte)).await;
    match closed {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("partial ClientHello produced unexpected bytes"),
        Err(_) => panic!("partial ClientHello did not close"),
    }
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "handshake closed before its deadline: {:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "handshake exceeded its absolute deadline: {:?}",
        started.elapsed()
    );
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m06_tls01_tls12_tls13_alpn_and_two_servers() {
    let dir = common::TempDir::new("m06-tls01");
    m06::generate_pki(dir.path());
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let (server, address) = start_proxy(&dir, &chain, &key, 443).await;
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"tls-ok"))
        .await
        .expect("origin");

    let cases: [(&str, Arc<rustls::ClientConfig>); 4] = [
        (
            "tls12",
            m06::client_config_version(
                &dir.path().join("proxy_ca.pem"),
                &rustls::version::TLS12,
                &[b"http/1.1"],
            ),
        ),
        (
            "tls13",
            m06::client_config_version(
                &dir.path().join("proxy_ca.pem"),
                &rustls::version::TLS13,
                &[b"http/1.1"],
            ),
        ),
        (
            "absent-alpn",
            m06::client_config_version(
                &dir.path().join("proxy_ca.pem"),
                &rustls::version::TLS13,
                &[],
            ),
        ),
        (
            "h2-plus-h1",
            m06::client_config_version(
                &dir.path().join("proxy_ca.pem"),
                &rustls::version::TLS13,
                &[b"h2", b"http/1.1"],
            ),
        ),
    ];
    for (label, config) in cases {
        let mut client = m06::connect_tls(address, "localhost", config)
            .await
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        client
            .send(&m03::request("GET", origin.address, "/", &[], b""))
            .await
            .expect("send");
        let response = client.read_response().await.expect("response");
        assert_eq!(response.head.status, 200, "{label}");
        assert_eq!(response.text(), "tls-ok", "{label}");
    }

    let h2_only = m06::client_config_version(
        &dir.path().join("proxy_ca.pem"),
        &rustls::version::TLS13,
        &[b"h2"],
    );
    assert!(
        m06::connect_tls(address, "localhost", h2_only)
            .await
            .is_err(),
        "h2-only client must not negotiate HTTP/2 ingress"
    );

    // A second server instance must not conflict on a process-global provider.
    let (second_server, second_address) = start_proxy(&dir, &chain, &key, 443).await;
    let mut client = m06::connect_tls(
        second_address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("second server handshake");
    client
        .send(&m03::request("GET", origin.address, "/", &[], b""))
        .await
        .expect("second send");
    assert_eq!(
        client.read_response().await.expect("second").head.status,
        200
    );

    server.shutdown().await;
    second_server.shutdown().await;
}

#[tokio::test]
async fn m06_tls02_certificate_trust_name_expiry_and_intermediate() {
    let dir = common::TempDir::new("m06-tls02");
    m06::generate_pki(dir.path());
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let (server, address) = start_proxy(&dir, &chain, &key, 443).await;
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");

    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("trusted intermediate chain");
    client
        .send(&m03::request("GET", origin.address, "/", &[], b""))
        .await
        .expect("send");
    assert_eq!(
        client.read_response().await.expect("response").head.status,
        200
    );

    let wrong_ca = match m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("site_ca.pem")),
    )
    .await
    {
        Ok(_) => panic!("wrong proxy CA unexpectedly accepted"),
        Err(error) => error,
    };
    certificate_error(&wrong_ca, "UnknownIssuer");

    let wrong_name = match m06::connect_tls(
        address,
        "127.0.0.1",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    {
        Ok(_) => panic!("wrong proxy name unexpectedly accepted"),
        Err(error) => error,
    };
    certificate_error(&wrong_name, "NotValidForName");

    let expired_dir = common::TempDir::new("m06-tls02-expired");
    m06::generate_pki(expired_dir.path());
    let (expired_server, expired_address) = start_proxy(
        &expired_dir,
        &expired_dir.path().join("proxy_expired_chain.pem"),
        &expired_dir.path().join("proxy_expired_key.pem"),
        443,
    )
    .await;
    let expired = match m06::connect_tls(
        expired_address,
        "localhost",
        client_config(&expired_dir.path().join("proxy_ca.pem")),
    )
    .await
    {
        Ok(_) => panic!("expired proxy certificate unexpectedly accepted"),
        Err(error) => error,
    };
    certificate_error(&expired, "Expired");

    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 1);
    server.shutdown().await;
    expired_server.shutdown().await;
}

#[tokio::test]
async fn m06_http01_http_semantics_over_tls() {
    let dir = common::TempDir::new("m06-http01");
    m06::generate_pki(dir.path());
    let origin = m03::spawn_origin(|request, _| {
        if request.target == "/large" {
            m03::response("200 OK", &[], &vec![0x5a; 1024 * 1024])
        } else if request.target == "/chunked" {
            m03::chunked_response(
                "200 OK",
                &[("Trailer", "X-Origin-Trailer")],
                &[b"one", b"two"],
                &[("X-Origin-Trailer", "value")],
            )
        } else if request.target == "/interim" {
            let mut bytes =
                b"HTTP/1.1 103 Early Hints\r\nLink: </style>; rel=preload\r\n\r\n".to_vec();
            bytes.extend_from_slice(&m03::response("200 OK", &[], b"final"));
            bytes
        } else if request.target == "/sse" {
            m03::chunked_response("200 OK", &[], &[b"data: one\n\n", b"data: two\n\n"], &[])
        } else if request.method == "POST" {
            m03::response("200 OK", &[], &request.body)
        } else {
            m03::response("200 OK", &[], b"ok")
        }
    })
    .await
    .expect("origin");
    let (server, address) = start_proxy(
        &dir,
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("proxy_key.pem"),
        443,
    )
    .await;

    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("client");

    let mut first = m03::request("GET", origin.address, "/", &[], b"");
    let mut second = m03::request("GET", origin.address, "/second", &[], b"");
    first.append(&mut second);
    client.send(&first).await.expect("pipeline");
    let one = client.read_response().await.expect("first");
    let two = client.read_response().await.expect("second");
    assert_eq!(one.head.status, 200);
    assert_eq!(two.head.status, 200);
    assert_eq!(one.text(), "ok");
    assert_eq!(two.text(), "ok");

    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("large client");
    client
        .send(&m03::request("GET", origin.address, "/large", &[], b""))
        .await
        .expect("large send");
    let response = client.read_response().await.expect("large response");
    assert_eq!(response.body.len(), 1024 * 1024);
    assert!(response.body.iter().all(|byte| *byte == 0x5a));

    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("chunked client");
    client
        .send(&m03::request(
            "GET",
            origin.address,
            "/chunked",
            &[("TE", "trailers")],
            b"",
        ))
        .await
        .expect("chunked send");
    let response = client.read_response().await.expect("chunked response");
    assert_eq!(response.body, b"onetwo");
    assert!(
        response
            .trailers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-origin-trailer") && value == "value")
    );

    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("interim client");
    client
        .send(&m03::request("GET", origin.address, "/interim", &[], b""))
        .await
        .expect("interim send");
    let response = client.read_response().await.expect("interim response");
    assert_eq!(response.interim.len(), 1);
    assert_eq!(response.interim[0].status, 103);
    assert_eq!(response.text(), "final");

    let payload = vec![0x33; 1024 * 1024];
    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("upload client");
    client
        .send(&m03::request(
            "POST",
            origin.address,
            "/upload",
            &[],
            &payload,
        ))
        .await
        .expect("upload send");
    let response = client.read_response().await.expect("upload response");
    assert_eq!(response.body, payload);

    let mut client = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("sse client");
    client
        .send(&m03::request("GET", origin.address, "/sse", &[], b""))
        .await
        .expect("sse send");
    assert!(
        client
            .read_response()
            .await
            .expect("sse response")
            .text()
            .contains("data: two")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn m06_con01_layered_site_tls_and_certificate_failures() {
    let dir = common::TempDir::new("m06-con01");
    m06::generate_pki(dir.path());
    let site = m06::spawn_site(
        m06::server_config(
            &dir.path().join("site_chain.pem"),
            &dir.path().join("site_key.pem"),
        ),
        |request| {
            if request.target == "/download" {
                m06::site_response("200 OK", &vec![0xa5; 1024 * 1024])
            } else if request.target == "/upload" {
                m06::site_response(
                    "200 OK",
                    format!("upload:{}", request.body.len()).as_bytes(),
                )
            } else {
                m06::site_response("200 OK", b"site-ok")
            }
        },
    )
    .await
    .expect("site");
    let expired_site = m06::spawn_site(
        m06::server_config(
            &dir.path().join("site_expired_chain.pem"),
            &dir.path().join("site_expired_key.pem"),
        ),
        |_| m06::site_response("200 OK", b"must-not-be-served"),
    )
    .await
    .expect("expired site");
    let text = config_text(
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("proxy_key.pem"),
        site.address.port(),
    )
    .replace(
        &format!("allowed_ports = [{}]", site.address.port()),
        &format!(
            "allowed_ports = [{}, {}]",
            site.address.port(),
            expired_site.address.port()
        ),
    );
    let (server, address) = start_proxy_with_config(&dir, &text).await;

    let mut outer = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("outer TLS");
    outer
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                site.address, site.address
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT");
    assert_eq!(outer.read_head().await.expect("200").status, 200);
    let inner = outer.into_inner();
    let inner = TlsConnector::from(client_config(&dir.path().join("site_ca.pem")))
        .connect(ServerName::try_from("localhost").expect("name"), inner)
        .await
        .expect("site TLS");
    let mut site_client = RawClient::from_stream(inner);
    site_client
        .send(b"GET /download HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("site download");
    let response = site_client.read_response().await.expect("site response");
    assert_eq!(response.body.len(), 1024 * 1024);
    assert!(response.body.iter().all(|byte| *byte == 0xa5));

    let mut outer = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("outer TLS upload");
    outer
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                site.address, site.address
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT upload");
    assert_eq!(outer.read_head().await.expect("200").status, 200);
    let inner = TlsConnector::from(client_config(&dir.path().join("site_ca.pem")))
        .connect(
            ServerName::try_from("localhost").expect("name"),
            outer.into_inner(),
        )
        .await
        .expect("site TLS upload");
    let mut site_client = RawClient::from_stream(inner);
    let payload = vec![0x42; 1024 * 1024];
    let mut request = format!(
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    request.extend_from_slice(&payload);
    site_client.send(&request).await.expect("site upload");
    let response = site_client.read_response().await.expect("upload response");
    assert_eq!(response.text(), "upload:1048576");

    let before = site.requests.lock().unwrap().len();
    let mut outer = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("outer TLS wrong site CA");
    outer
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                site.address, site.address
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT wrong CA");
    assert_eq!(outer.read_head().await.expect("200").status, 200);
    let inner = TlsConnector::from(client_config(&dir.path().join("proxy_ca.pem")))
        .connect(
            ServerName::try_from("localhost").expect("name"),
            outer.into_inner(),
        )
        .await
        .expect_err("site certificate must fail with proxy CA");
    certificate_error(&inner, "UnknownIssuer");
    assert_eq!(site.requests.lock().unwrap().len(), before);

    let mut outer = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("outer TLS wrong site name");
    outer
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                site.address, site.address
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT wrong name");
    assert_eq!(outer.read_head().await.expect("200").status, 200);
    let wrong_name = TlsConnector::from(client_config(&dir.path().join("site_ca.pem")))
        .connect(
            ServerName::try_from("127.0.0.1").expect("ip name"),
            outer.into_inner(),
        )
        .await
        .expect_err("site name must fail");
    certificate_error(&wrong_name, "NotValidForName");
    assert_eq!(site.requests.lock().unwrap().len(), before);
    assert_eq!(site.ties.load(std::sync::atomic::Ordering::SeqCst), 2);

    let accepted_before = expired_site
        .tcp_accepts
        .load(std::sync::atomic::Ordering::SeqCst);
    let mut outer = m06::connect_tls(
        address,
        "localhost",
        client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("outer TLS expired site");
    outer
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                expired_site.address, expired_site.address
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT expired site");
    assert_eq!(outer.read_head().await.expect("200").status, 200);
    let expired = TlsConnector::from(client_config(&dir.path().join("site_ca.pem")))
        .connect(
            ServerName::try_from("localhost").expect("name"),
            outer.into_inner(),
        )
        .await
        .expect_err("expired site certificate must fail");
    certificate_error(&expired, "Expired");
    assert!(
        expired_site
            .tcp_accepts
            .load(std::sync::atomic::Ordering::SeqCst)
            > accepted_before,
        "CONNECT did not reach the expired origin TCP listener"
    );
    assert!(
        expired_site.requests.lock().unwrap().is_empty(),
        "expired TLS site served an HTTP request"
    );
    assert_eq!(
        expired_site.ties.load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    server.shutdown().await;
}
