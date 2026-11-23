//! M09 parent proxy routing, forwarding, credentials and TLS tests.

mod common;
mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use angara::config::{Config, LogLevel};
use angara::control::ReloadOutcome;
use angara::http::HttpServer;
use angara::logging::Logger;
use angara::transport::TcpDialer;
use tokio_rustls::TlsAcceptor;

use common::m03::{self, RawClient};
use common::m09::{self, FixedResponse, ParentMode};
use common::{TempDir, m04, m06};
use support::ScriptedResolver;

fn config_with_parent(
    parent: Option<SocketAddr>,
    default_parent: Option<&str>,
    rules: &str,
    connect_ports: &[u16],
) -> String {
    let mut text = m03::config("127.0.0.1:3128");
    if let Some(parent) = parent {
        text.push_str(&format!(
            r#"
[[parents]]
id = "parent"
endpoint = "{}"
transport = "http"
"#,
            parent
        ));
    }
    text.push_str(
        r#"
[routing]
default_egress = "system"
"#,
    );
    if let Some(parent) = default_parent {
        text.push_str(&format!("default_parent = \"{parent}\"\n"));
    }
    text.push_str(rules);
    if !connect_ports.is_empty() {
        let ports = connect_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!("[connect]\nallowed_ports = [{ports}]\n"));
    }
    text
}

fn with_instance(text: String, instance_id: &str) -> String {
    text.replace(
        "[runtime]\nworker_threads = 2",
        &format!("[runtime]\nworker_threads = 2\ninstance_id = \"{instance_id}\""),
    )
}

async fn start_with_resolver(
    text: &str,
    answers: Vec<IpAddr>,
) -> (HttpServer, SocketAddr, Arc<ScriptedResolver>) {
    let config = Arc::new(Config::parse(text).expect("proxy config"));
    let resolver = Arc::new(ScriptedResolver::new(
        answers
            .into_iter()
            .map(|address| Ok(vec![address]))
            .collect(),
    ));
    let server = HttpServer::bind_ephemeral_with_components(
        config,
        Arc::clone(&resolver) as Arc<dyn angara::resolver::Resolver>,
        Arc::new(TcpDialer),
    )
    .await
    .expect("bind proxy");
    let address = server.addresses()[0].1;
    (server, address, resolver)
}

async fn start_with_scripted(
    text: &str,
    resolver: Arc<ScriptedResolver>,
) -> (HttpServer, SocketAddr) {
    let config = Arc::new(Config::parse(text).expect("proxy config"));
    let server = HttpServer::bind_ephemeral_with_components(
        config,
        resolver as Arc<dyn angara::resolver::Resolver>,
        Arc::new(TcpDialer),
    )
    .await
    .expect("bind proxy");
    let address = server.addresses()[0].1;
    (server, address)
}

async fn get(proxy: SocketAddr, uri: &str, host: &str) -> m03::RawResponse {
    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let request = format!("GET {uri} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    client.send(request.as_bytes()).await.expect("send request");
    client.read_response().await.expect("read response")
}

#[tokio::test]
async fn m09_parent01_http_ip_uses_absolute_form() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"parent-ok"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let uri = format!("http://{}/path?q=1", origin.address);
    let response = get(proxy, &uri, &origin.address.to_string()).await;
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "parent-ok");

    let parent_requests = parent.requests();
    assert_eq!(parent_requests.len(), 1);
    assert_eq!(parent_requests[0].method, "GET");
    assert_eq!(parent_requests[0].uri, uri);
    assert_eq!(
        parent_requests[0].host.as_deref(),
        Some(origin.address.to_string().as_str())
    );
    assert!(
        parent_requests[0]
            .via
            .iter()
            .any(|value| value.contains("angara"))
    );
    let origin_requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(origin_requests.len(), 1);
    assert_eq!(origin_requests[0].target, "/path?q=1");
    assert_eq!(
        origin_requests[0].header("host"),
        Some(origin.address.to_string().as_str())
    );
    assert_eq!(origin_requests[0].header("proxy-authorization"), None);
    drop(origin_requests);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent02_http_domain_uses_verified_ip_connect() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"tunnel-ok"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    let (server, proxy, resolver) =
        start_with_resolver(&text, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;

    let host = format!("origin.test:{}", origin.address.port());
    let response = get(proxy, &format!("http://{host}/files/x?q=2"), &host).await;
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "tunnel-ok");
    assert_eq!(resolver.hosts(), vec!["origin.test"]);

    let parent_requests = parent.requests();
    assert_eq!(parent_requests.len(), 1);
    assert_eq!(parent_requests[0].method, "CONNECT");
    assert_eq!(parent_requests[0].uri, origin.address.to_string());
    let origin_requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(origin_requests.len(), 1);
    assert_eq!(origin_requests[0].target, "/files/x?q=2");
    assert_eq!(origin_requests[0].header("host"), Some(host.as_str()));
    assert_eq!(origin_requests[0].header("proxy-authorization"), None);
    drop(origin_requests);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent03_client_connect_uses_parent_tunnel() {
    let origin = m04::spawn_echo_origin(None).await.expect("echo origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(
        Some(parent.address),
        Some("parent"),
        "",
        &[origin.address.port()],
    );
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let authority = origin.address.to_string();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.send(request.as_bytes()).await.expect("send CONNECT");
    let head = client.read_head().await.expect("read CONNECT head");
    assert_eq!(head.status, 200);
    client.send(b"ping").await.expect("send tunnel bytes");
    assert_eq!(
        client.read_exact_bytes(4).await.expect("read tunnel bytes"),
        b"ping"
    );

    let parent_requests = parent.requests();
    assert_eq!(parent_requests.len(), 1);
    assert_eq!(parent_requests[0].method, "CONNECT");
    assert_eq!(parent_requests[0].uri, origin.address.to_string());
    assert_eq!(parent.connect_count(), 1);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 1);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent04_credentials_are_isolated_to_parent() {
    let dir = TempDir::new("m09-credentials");
    let credentials = dir.write(
        "parent-creds.toml",
        "version = 1\nusername = \"parent-user\"\npassword = \"parent-secret\"\n",
    );
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600))
        .expect("private credentials");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"secret-ok"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = {
        let mut text = m03::config("127.0.0.1:3128");
        text.push_str(&format!(
            r#"
[[parents]]
id = "parent"
endpoint = "{}"
transport = "http"
credentials_file = "{}"

[routing]
default_egress = "system"
default_parent = "parent"
"#,
            parent.address,
            credentials.display()
        ));
        text
    };
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let request = format!(
        "GET http://{}/ HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic Y2xpZW50OnNlY3JldA==\r\n\r\n",
        origin.address, origin.address
    );
    client.send(request.as_bytes()).await.expect("send request");
    let response = client.read_response().await.expect("read response");
    assert_eq!(response.head.status, 200);

    let parent_requests = parent.requests();
    assert_eq!(parent_requests.len(), 1);
    assert_eq!(
        parent_requests[0].proxy_authorization.as_deref(),
        Some("Basic cGFyZW50LXVzZXI6cGFyZW50LXNlY3JldA==")
    );
    let origin_requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(origin_requests.len(), 1);
    assert_eq!(origin_requests[0].header("proxy-authorization"), None);
    drop(origin_requests);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent05_connect_rejection_is_502_without_challenge_or_fallback() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"must-not-reach"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::RejectConnect(
        FixedResponse::new(407, b"parent body").header("Proxy-Authenticate", "Basic realm=parent"),
    ))
    .await
    .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    let (server, proxy, _resolver) =
        start_with_resolver(&text, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;

    let host = format!("origin.test:{}", origin.address.port());
    let response = get(proxy, &format!("http://{host}/"), &host).await;
    assert_eq!(response.head.status, 502);
    assert_eq!(response.text(), "");
    assert_eq!(response.header("proxy-authenticate"), None);
    assert_eq!(parent.request_count(), 1);
    assert_eq!(parent.connect_count(), 0);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent06_absolute_407_is_502() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"must-not-reach"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Fixed(
        FixedResponse::new(407, b"parent body").header("Proxy-Authenticate", "Basic realm=parent"),
    ))
    .await
    .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let response = get(
        proxy,
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 502);
    assert_eq!(response.text(), "");
    assert_eq!(response.header("proxy-authenticate"), None);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent07_explicit_direct_bypasses_default_parent() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"direct-ok"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let rules = format!(
        r#"
[[routing.rules]]
id = "direct-origin"
egress_id = "system"
next_hop = "direct"
ports = [{}]
"#,
        origin.address.port()
    );
    let text = config_with_parent(Some(parent.address), Some("parent"), &rules, &[]);
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let response = get(
        proxy,
        &format!("http://{}/direct", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "direct-ok");
    assert_eq!(parent.request_count(), 0);
    let origin_requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(origin_requests.len(), 1);
    assert_eq!(origin_requests[0].target, "/direct");
    drop(origin_requests);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent09_large_post_streams_through_parent_tunnel() {
    let body = vec![b'x'; 256 * 1024];
    let expected = body.len();
    let origin = m03::spawn_origin(move |request, _| {
        assert_eq!(request.body.len(), expected);
        m03::response("200 OK", &[], b"posted")
    })
    .await
    .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    let (server, proxy, _resolver) =
        start_with_resolver(&text, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;

    let host = format!("origin.test:{}", origin.address.port());
    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let head = format!(
        "POST http://{host}/upload HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    client.send(head.as_bytes()).await.expect("send head");
    client.send(&body).await.expect("send body");
    let response = client.read_response().await.expect("read response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "posted");
    let origin_requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(origin_requests.len(), 1);
    assert_eq!(origin_requests[0].body.len(), body.len());
    drop(origin_requests);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent10_parent_timeout_is_504() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"late"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Delay(std::time::Duration::from_millis(300)))
        .await
        .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]).replace(
        "response_header_timeout_ms = 5000",
        "response_header_timeout_ms = 100",
    );
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let response = get(
        proxy,
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 504);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent19_connect_timeout_is_504() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"late"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Delay(std::time::Duration::from_millis(300)))
        .await
        .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]).replace(
        "response_header_timeout_ms = 5000",
        "response_header_timeout_ms = 100",
    );
    let (server, proxy, _resolver) =
        start_with_resolver(&text, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;

    let host = format!("origin.test:{}", origin.address.port());
    let response = get(proxy, &format!("http://{host}/"), &host).await;
    assert_eq!(response.head.status, 504);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent11_parent_connect_502_has_no_fallback() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"must-not-reach"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::RejectConnect(FixedResponse::new(
        502,
        b"parent unavailable",
    )))
    .await
    .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    let (server, proxy, _resolver) =
        start_with_resolver(&text, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]).await;

    let host = format!("origin.test:{}", origin.address.port());
    let response = get(proxy, &format!("http://{host}/"), &host).await;
    assert_eq!(response.head.status, 502);
    assert_eq!(parent.connect_count(), 0);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent12_ipv6_connect_authority_is_bracketed() {
    let origin = m04::spawn_echo_origin_at("[::1]:0".parse().expect("IPv6 loopback"), None)
        .await
        .expect("IPv6 echo origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let mut text = config_with_parent(
        Some(parent.address),
        Some("parent"),
        "",
        &[origin.address.port()],
    );
    text = text.replace(
        "networks = [\"127.0.0.0/8\"]",
        "networks = [\"127.0.0.0/8\", \"::1/128\"]",
    );
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let authority = format!("[::1]:{}", origin.address.port());
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.send(request.as_bytes()).await.expect("send CONNECT");
    let head = client.read_head().await.expect("read CONNECT head");
    assert_eq!(head.status, 200);
    client.send(b"v6").await.expect("send tunnel bytes");
    assert_eq!(
        client.read_exact_bytes(2).await.expect("read tunnel bytes"),
        b"v6"
    );
    let parent_requests = parent.requests();
    assert_eq!(parent_requests.len(), 1);
    assert_eq!(parent_requests[0].uri, authority);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent15_ipv6_absolute_form_is_bracketed() {
    let origin = m03::spawn_origin_at("[::1]:0".parse().expect("IPv6 loopback"), |_, _| {
        m03::response("200 OK", &[], b"v6-http")
    })
    .await
    .expect("IPv6 origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let mut text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    text = text.replace(
        "networks = [\"127.0.0.0/8\"]",
        "networks = [\"127.0.0.0/8\", \"::1/128\"]",
    );
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let authority = format!("[::1]:{}", origin.address.port());
    let uri = format!("http://{authority}/v6?q=1");
    let response = get(proxy, &uri, &authority).await;
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "v6-http");
    let parent_requests = parent.requests();
    assert_eq!(parent_requests.len(), 1);
    assert_eq!(parent_requests[0].uri, uri);
    let origin_requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(origin_requests.len(), 1);
    assert_eq!(origin_requests[0].target, "/v6?q=1");
    assert_eq!(origin_requests[0].header("host"), Some(authority.as_str()));
    drop(origin_requests);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent18_tunnel_log_has_parent_route() {
    let echo = m04::spawn_echo_origin(None).await.expect("echo");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(
        Some(parent.address),
        Some("parent"),
        "",
        &[echo.address.port()],
    );
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;
    let telemetry = server.telemetry();
    let (logger, receiver) = Logger::channel(128, LogLevel::Info, telemetry);
    server.set_logger(logger);

    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let authority = echo.address.to_string();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.send(request.as_bytes()).await.expect("send CONNECT");
    assert_eq!(client.read_head().await.expect("head").status, 200);
    client.send(b"x").await.expect("send byte");
    assert_eq!(client.read_exact_bytes(1).await.expect("read byte"), b"x");
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), server.shutdown())
        .await
        .expect("bounded shutdown");
    let record = receive_event(&receiver, "tunnel_finished");
    assert_eq!(record["parent_id"], "parent");
    assert_eq!(record["route"], "parent");
}

#[tokio::test]
async fn m09_parent16a_two_angara_without_loop_forward_successfully() {
    let dir = TempDir::new("m09-chain-ok");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"chain-ok"))
        .await
        .expect("origin");
    let port_a = m03::free_port();
    let mut port_b = m03::free_port();
    while port_b == port_a {
        port_b = m03::free_port();
    }

    let config_b = with_instance(m03::config(&format!("127.0.0.1:{port_b}")), "b");
    let path_b = dir.write("proxy-b.toml", &config_b);
    let server_b =
        HttpServer::bind_with_path(Arc::new(Config::load(&path_b).expect("B config")), path_b)
            .await
            .expect("bind B");

    let config_a = with_instance(
        {
            let mut text = m03::config(&format!("127.0.0.1:{port_a}"));
            text.push_str(&format!(
                r#"
[[parents]]
id = "b"
endpoint = "127.0.0.1:{port_b}"
transport = "http"

[routing]
default_egress = "system"
default_parent = "b"
"#
            ));
            text
        },
        "a",
    );
    let path_a = dir.write("proxy-a.toml", &config_a);
    let server_a =
        HttpServer::bind_with_path(Arc::new(Config::load(&path_a).expect("A config")), path_a)
            .await
            .expect("bind A");

    let response = get(
        SocketAddr::from(([127, 0, 0, 1], port_a)),
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 200);
    let requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(requests.len(), 1);
    let via = requests[0]
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("via"))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    assert!(via.contains("angara-a"), "via: {via}");
    assert!(via.contains("angara-b"), "via: {via}");
    drop(requests);

    server_a.shutdown().await;
    server_b.shutdown().await;
}

#[tokio::test]
async fn m09_parent16b_two_angara_loop_is_rejected_on_returning_instance() {
    let dir = TempDir::new("m09-loop");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"loop-must-not-reach"))
        .await
        .expect("origin");
    let port_a = m03::free_port();
    let mut port_b = m03::free_port();
    while port_b == port_a {
        port_b = m03::free_port();
    }

    let config_b = with_instance(
        {
            let mut text = m03::config(&format!("127.0.0.1:{port_b}"));
            text.push_str(&format!(
                r#"
[[parents]]
id = "a"
endpoint = "127.0.0.1:{port_a}"
transport = "http"

[routing]
default_egress = "system"
default_parent = "a"
"#
            ));
            text
        },
        "b",
    );
    let path_b = dir.write("proxy-b.toml", &config_b);
    let server_b =
        HttpServer::bind_with_path(Arc::new(Config::load(&path_b).expect("B config")), path_b)
            .await
            .expect("bind B");

    let config_a = with_instance(
        {
            let mut text = m03::config(&format!("127.0.0.1:{port_a}"));
            text.push_str(&format!(
                r#"
[[parents]]
id = "b"
endpoint = "127.0.0.1:{port_b}"
transport = "http"

[routing]
default_egress = "system"
default_parent = "b"
"#
            ));
            text
        },
        "a",
    );
    let path_a = dir.write("proxy-a.toml", &config_a);
    let server_a =
        HttpServer::bind_with_path(Arc::new(Config::load(&path_a).expect("A config")), path_a)
            .await
            .expect("bind A");

    let response = get(
        SocketAddr::from(([127, 0, 0, 1], port_a)),
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 508);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        server_a
            .telemetry()
            .via_loop_rejected
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        server_b
            .telemetry()
            .via_loop_rejected
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    server_a.shutdown().await;
    server_b.shutdown().await;
}

struct LoopPair {
    server_a: HttpServer,
    proxy_a: SocketAddr,
    server_b: HttpServer,
}

/// Starts A and B pointing at each other. A is ephemeral and resolves
/// `origin.test` to loopback; B binds the pre-selected port referenced by A.
async fn start_loop_pair(dir: &TempDir, allowed_port: u16) -> LoopPair {
    let port_b = m03::free_port();
    let config_a = with_instance(
        {
            let mut text = m03::config("127.0.0.1:3128");
            text.push_str(&format!(
                r#"
[[parents]]
id = "b"
endpoint = "127.0.0.1:{port_b}"
transport = "http"

[routing]
default_egress = "system"
default_parent = "b"

[connect]
allowed_ports = [{allowed_port}]
"#
            ));
            text
        },
        "edge-a",
    );
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    )])]));
    let (server_a, proxy_a) = start_with_scripted(&config_a, resolver).await;

    let config_b = with_instance(
        {
            let mut text = m03::config(&format!("127.0.0.1:{port_b}"));
            text.push_str(&format!(
                r#"
[[parents]]
id = "a"
endpoint = "{proxy_a}"
transport = "http"

[routing]
default_egress = "system"
default_parent = "a"

[connect]
allowed_ports = [{allowed_port}]
"#
            ));
            text
        },
        "edge-b",
    );
    let path_b = dir.write("proxy-b.toml", &config_b);
    let server_b =
        HttpServer::bind_with_path(Arc::new(Config::load(&path_b).expect("B config")), path_b)
            .await
            .expect("bind B");
    LoopPair {
        server_a,
        proxy_a,
        server_b,
    }
}

struct ChainPair {
    server_a: HttpServer,
    proxy_a: SocketAddr,
    server_b: HttpServer,
}

/// Starts B forwarding to a control parent, then A forwarding to B.
async fn start_chain(dir: &TempDir, control: &m09::ParentStand, allowed_port: u16) -> ChainPair {
    let port_b = m03::free_port();
    let config_b = with_instance(
        {
            let mut text = m03::config(&format!("127.0.0.1:{port_b}"));
            text.push_str(&format!(
                r#"
[[parents]]
id = "control"
endpoint = "{}"
transport = "http"

[routing]
default_egress = "system"
default_parent = "control"

[connect]
allowed_ports = [443, {allowed_port}]
"#,
                control.address
            ));
            text
        },
        "edge-b",
    );
    let path_b = dir.write("chain-b.toml", &config_b);
    let server_b =
        HttpServer::bind_with_path(Arc::new(Config::load(&path_b).expect("B config")), path_b)
            .await
            .expect("bind B");

    let config_a = with_instance(
        {
            let mut text = m03::config("127.0.0.1:3128");
            text.push_str(&format!(
                r#"
[[parents]]
id = "b"
endpoint = "127.0.0.1:{port_b}"
transport = "http"

[routing]
default_egress = "system"
default_parent = "b"

[connect]
allowed_ports = [{allowed_port}]
"#
            ));
            text
        },
        "edge-a",
    );
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    )])]));
    let (server_a, proxy_a) = start_with_scripted(&config_a, resolver).await;
    ChainPair {
        server_a,
        proxy_a,
        server_b,
    }
}

async fn connect_from(source: Ipv4Addr, address: SocketAddr) -> RawClient {
    let socket = tokio::net::TcpSocket::new_v4().expect("source socket");
    socket
        .bind(SocketAddr::new(IpAddr::V4(source), 0))
        .expect("bind source address");
    let stream = socket.connect(address).await.expect("connect source");
    RawClient::from_stream(stream)
}

#[tokio::test]
async fn m09_parent16c_two_angara_connect_loop_is_rejected() {
    let dir = TempDir::new("m09-connect-loop");
    let echo = m04::spawn_echo_origin(None).await.expect("echo");
    let pair = start_loop_pair(&dir, echo.address.port()).await;

    let mut client = RawClient::connect(pair.proxy_a).await.expect("connect A");
    let authority = echo.address.to_string();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.send(request.as_bytes()).await.expect("send CONNECT");
    let head = client.read_head().await.expect("head");
    assert_eq!(head.status, 502);
    assert_eq!(echo.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        pair.server_a
            .telemetry()
            .via_loop_rejected
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        pair.server_b
            .telemetry()
            .via_loop_rejected
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        pair.server_a
            .telemetry()
            .http_started
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(
        pair.server_b
            .telemetry()
            .http_started
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    drop(client);
    pair.server_a.shutdown().await;
    pair.server_b.shutdown().await;
}

#[tokio::test]
async fn m09_parent16d_two_angara_domain_loop_is_rejected() {
    let dir = TempDir::new("m09-domain-loop");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"loop-must-not-reach"))
        .await
        .expect("origin");
    let pair = start_loop_pair(&dir, origin.address.port()).await;
    let host = format!("origin.test:{}", origin.address.port());

    let response = get(pair.proxy_a, &format!("http://{host}/loop"), &host).await;
    assert_eq!(response.head.status, 502);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        pair.server_a
            .telemetry()
            .via_loop_rejected
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        pair.server_b
            .telemetry()
            .via_loop_rejected
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        pair.server_a
            .telemetry()
            .http_started
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(
        pair.server_b
            .telemetry()
            .http_started
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    pair.server_a.shutdown().await;
    pair.server_b.shutdown().await;
}

#[tokio::test]
async fn m09_parent16e_two_angara_chain_preserves_connect_via() {
    let dir = TempDir::new("m09-chain-connect");
    let echo = m04::spawn_echo_origin(None).await.expect("echo");
    let control = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("control parent");
    let chain = start_chain(&dir, &control, echo.address.port()).await;

    let mut client = RawClient::connect(chain.proxy_a).await.expect("connect A");
    let authority = echo.address.to_string();
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nVia: 1.1 client-proxy\r\n\r\n"
    );
    client.send(request.as_bytes()).await.expect("send CONNECT");
    assert_eq!(client.read_head().await.expect("head").status, 200);
    client.send(b"x").await.expect("send byte");
    assert_eq!(client.read_exact_bytes(1).await.expect("read byte"), b"x");
    drop(client);

    let recorded = control.requests();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].method, "CONNECT");
    assert_eq!(
        recorded[0].via,
        vec!["1.1 client-proxy", "1.1 angara-edge-a", "1.1 angara-edge-b"]
    );

    chain.server_a.shutdown().await;
    chain.server_b.shutdown().await;
}

#[tokio::test]
async fn m09_parent16f_two_angara_chain_preserves_domain_http_via() {
    let dir = TempDir::new("m09-chain-domain");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"chain-domain-ok"))
        .await
        .expect("origin");
    let control = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("control parent");
    let chain = start_chain(&dir, &control, origin.address.port()).await;
    let host = format!("origin.test:{}", origin.address.port());

    let response = get(chain.proxy_a, &format!("http://{host}/chain"), &host).await;
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "chain-domain-ok");

    let recorded = control.requests();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].method, "CONNECT");
    assert_eq!(
        recorded[0].via,
        vec!["1.1 angara-edge-a", "1.1 angara-edge-b"]
    );
    let origin_requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(origin_requests.len(), 1);
    assert_eq!(origin_requests[0].target, "/chain");
    drop(origin_requests);

    chain.server_a.shutdown().await;
    chain.server_b.shutdown().await;
}

#[tokio::test]
async fn m09_parent27_angara_parent_http_port_acl_recipe() {
    let dir = TempDir::new("m09-parent-http-acl");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"acl-recipe-ok"))
        .await
        .expect("origin");
    let port_b = m03::free_port();
    let origin_port = origin.address.port();

    let config_b = m03::config(&format!("127.0.0.1:{port_b}")).replace(
        "[[access.rules]]\nid = \"allow\"\naction = \"allow\"\n",
        &format!(
            r#"[[access.rules]]
id = "connect-http-only-from-angara-a"
action = "allow"
sources = ["127.0.0.1/32"]
methods = ["CONNECT"]
ports = [{origin_port}]

[[access.rules]]
id = "connect-http-deny-others"
action = "deny"
methods = ["CONNECT"]
ports = [{origin_port}]

[[access.rules]]
id = "allow"
action = "allow"
"#
        ),
    ) + &format!("\n[connect]\nallowed_ports = [443, {origin_port}]\n");
    let path_b = dir.write("parent-b.toml", &config_b);
    let server_b =
        HttpServer::bind_with_path(Arc::new(Config::load(&path_b).expect("B config")), path_b)
            .await
            .expect("bind B");

    let config_a = with_instance(
        {
            let mut text = m03::config("127.0.0.1:3128");
            text.push_str(&format!(
                r#"
[[parents]]
id = "b"
endpoint = "127.0.0.1:{port_b}"
transport = "http"

[routing]
default_egress = "system"
default_parent = "b"
"#
            ));
            text
        },
        "edge-a",
    );
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    )])]));
    let (server_a, proxy_a) = start_with_scripted(&config_a, resolver).await;
    let host = format!("origin.test:{origin_port}");

    let response = get(proxy_a, &format!("http://{host}/via-a"), &host).await;
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "acl-recipe-ok");

    let other_source = Ipv4Addr::new(127, 0, 0, 2);
    let mut denied = connect_from(other_source, SocketAddr::from(([127, 0, 0, 1], port_b))).await;
    let authority = origin.address.to_string();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    denied.send(request.as_bytes()).await.expect("send CONNECT");
    assert_eq!(denied.read_head().await.expect("head").status, 403);
    drop(denied);

    let mut direct = connect_from(other_source, SocketAddr::from(([127, 0, 0, 1], port_b))).await;
    let request = format!(
        "GET http://{}/direct HTTP/1.1\r\nHost: {}\r\n\r\n",
        origin.address, origin.address
    );
    direct.send(request.as_bytes()).await.expect("send GET");
    let response = direct.read_response().await.expect("read response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "acl-recipe-ok");
    drop(direct);

    let origin_requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(origin_requests.len(), 2);
    assert_eq!(origin_requests[0].target, "/via-a");
    assert_eq!(origin_requests[1].target, "/direct");
    drop(origin_requests);

    server_a.shutdown().await;
    server_b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m09_parent17_concurrent_http_and_connect_then_shutdown() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"concurrent-ok"))
        .await
        .expect("origin");
    let echo = m04::spawn_echo_origin(None).await.expect("echo");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(
        Some(parent.address),
        Some("parent"),
        "",
        &[echo.address.port()],
    )
    .replace("max_client_connections = 16", "max_client_connections = 32")
    .replace("max_connecting = 8", "max_connecting = 32");
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..10 {
        let target = format!("http://{}/", origin.address);
        let host = origin.address.to_string();
        tasks.spawn(async move {
            let response = get(proxy, &target, &host).await;
            assert_eq!(response.head.status, 200);
        });
    }
    for _ in 0..10 {
        let authority = echo.address.to_string();
        tasks.spawn(async move {
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            client.send(request.as_bytes()).await.expect("send CONNECT");
            let head = client.read_head().await.expect("read CONNECT head");
            assert_eq!(head.status, 200);
            client.send(b"c").await.expect("send tunnel byte");
            assert_eq!(
                client.read_exact_bytes(1).await.expect("read tunnel byte"),
                b"c"
            );
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.expect("client task");
    }
    assert!(
        origin.accepts.load(std::sync::atomic::Ordering::SeqCst) >= 10,
        "HTTP origin accepts"
    );
    assert!(
        echo.accepts.load(std::sync::atomic::Ordering::SeqCst) >= 10,
        "CONNECT origin accepts"
    );
    assert!(parent.request_count() >= 20);
    tokio::time::timeout(Duration::from_secs(5), server.shutdown())
        .await
        .expect("bounded shutdown");
}

#[tokio::test]
async fn m09_parent13_routing_reload_switches_to_direct() {
    let dir = TempDir::new("m09-reload");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"reload-ok"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    let path = dir.write("proxy.toml", &text);
    let config = Arc::new(Config::load(&path).expect("initial config"));
    let server = HttpServer::bind_ephemeral_with_path(config, path.clone())
        .await
        .expect("bind proxy");
    let proxy = server.addresses()[0].1;

    let target = format!("http://{}/", origin.address);
    let host = origin.address.to_string();
    let response = get(proxy, &target, &host).await;
    assert_eq!(response.head.status, 200);
    assert_eq!(parent.request_count(), 1);

    let direct = config_with_parent(Some(parent.address), None, "", &[]);
    std::fs::write(&path, direct).expect("rewrite config");
    assert_eq!(
        server.control().reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    let response = get(proxy, &target, &host).await;
    assert_eq!(response.head.status, 200);
    assert_eq!(parent.request_count(), 1);
    let origin_requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(origin_requests.len(), 2);
    drop(origin_requests);

    server.shutdown().await;
}

fn receive_event(receiver: &std::sync::mpsc::Receiver<String>, event: &str) -> serde_json::Value {
    for _ in 0..40 {
        let text = receiver
            .recv_timeout(Duration::from_millis(100))
            .expect("terminal log");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        if value["event"] == event {
            return value;
        }
    }
    panic!("event {event} not logged");
}

#[tokio::test]
async fn m09_parent14_request_log_has_route_but_no_secrets() {
    let dir = TempDir::new("m09-log");
    let credentials = dir.write(
        "parent-creds.toml",
        "version = 1\nusername = \"parent-user\"\npassword = \"parent-secret\"\n",
    );
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600))
        .expect("private credentials");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"log-ok"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = {
        let mut text = m03::config("127.0.0.1:3128");
        text.push_str(&format!(
            r#"
[[parents]]
id = "parent"
endpoint = "{}"
transport = "http"
credentials_file = "{}"

[routing]
default_egress = "system"
default_parent = "parent"
"#,
            parent.address,
            credentials.display()
        ));
        text
    };
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;
    let telemetry = server.telemetry();
    let (logger, receiver) = Logger::channel(128, LogLevel::Info, telemetry);
    server.set_logger(logger);

    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let request = format!(
        "GET http://{}/ HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic Y2xpZW50LXNlY3JldA==\r\n\r\n",
        origin.address, origin.address
    );
    client.send(request.as_bytes()).await.expect("send request");
    let response = client.read_response().await.expect("read response");
    assert_eq!(response.head.status, 200);
    let record = receive_event(&receiver, "request_finished");
    assert_eq!(record["parent_id"], "parent");
    assert_eq!(record["route"], "parent");
    let serialized = record.to_string();
    assert!(!serialized.contains("parent-secret"));
    assert!(!serialized.contains("client-secret"));
    assert!(!serialized.contains("Basic "));

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent20_ip_denied_before_parent_dial() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"must-not-reach"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let response = get(proxy, "http://192.0.2.1/", "192.0.2.1").await;
    assert_eq!(response.head.status, 403);
    assert_eq!(parent.request_count(), 0);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent21_client_acl_deny_has_zero_parent_and_origin_counters() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"must-not-reach"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]).replace(
        "[[access.rules]]\nid = \"allow\"\naction = \"allow\"",
        "[[access.rules]]\nid = \"deny\"\naction = \"deny\"",
    );
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let response = get(
        proxy,
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 403);
    assert_eq!(parent.request_count(), 0);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent22_two_listeners_select_different_next_hops_at_runtime() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"listeners-ok"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = m03::config("127.0.0.1:3128")
        .replace(
            "[[listeners]]\nid = \"proxy\"\nbind = \"127.0.0.1:3128\"\ntransport = \"http\"",
            "[[listeners]]\nid = \"via-parent\"\nbind = \"127.0.0.1:3128\"\ntransport = \"http\"\n\n[[listeners]]\nid = \"direct\"\nbind = \"127.0.0.1:3129\"\ntransport = \"http\"",
        )
        .replace(
            "[routing]\ndefault_egress = \"system\"",
            &format!(
                "[[parents]]\nid = \"parent\"\nendpoint = \"{}\"\ntransport = \"http\"\n\n[routing]\ndefault_egress = \"system\"\ndefault_parent = \"parent\"\n\n[[routing.rules]]\nid = \"direct-listener\"\negress_id = \"system\"\nnext_hop = \"direct\"\nlisteners = [\"direct\"]",
                parent.address
            ),
        );
    // The base helper has no routing table; append it for this test.
    let text = if text.contains("[routing]") {
        text
    } else {
        format!(
            "{text}\n[[parents]]\nid = \"parent\"\nendpoint = \"{}\"\ntransport = \"http\"\n\n[routing]\ndefault_egress = \"system\"\ndefault_parent = \"parent\"\n\n[[routing.rules]]\nid = \"direct-listener\"\negress_id = \"system\"\nnext_hop = \"direct\"\nlisteners = [\"direct\"]\n",
            parent.address
        )
    };
    let config = Arc::new(Config::parse(&text).expect("two-listener config"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind proxy");
    let addresses = server
        .addresses()
        .iter()
        .cloned()
        .collect::<std::collections::HashMap<_, _>>();
    let via_parent = addresses["via-parent"];
    let direct = addresses["direct"];

    let response = get(
        via_parent,
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 200);
    assert_eq!(parent.request_count(), 1);
    let response = get(
        direct,
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 200);
    assert_eq!(parent.request_count(), 1);
    let requests = origin.requests.lock().expect("origin requests").clone();
    assert_eq!(requests.len(), 2);
    drop(requests);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent23_two_parents_keep_credentials_separate() {
    let dir = TempDir::new("m09-two-parents");
    let creds_a = dir.write(
        "parent-a.toml",
        "version = 1\nusername = \"a-user\"\npassword = \"a-secret\"\n",
    );
    let creds_b = dir.write(
        "parent-b.toml",
        "version = 1\nusername = \"b-user\"\npassword = \"b-secret\"\n",
    );
    for path in [&creds_a, &creds_b] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
            .expect("credentials mode");
    }
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"two-parents"))
        .await
        .expect("origin");
    let parent_a = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent A");
    let parent_b = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent B");
    let text = m03::config("127.0.0.1:3128")
        .replace(
            "[[listeners]]\nid = \"proxy\"\nbind = \"127.0.0.1:3128\"\ntransport = \"http\"",
            "[[listeners]]\nid = \"listener-a\"\nbind = \"127.0.0.1:3128\"\ntransport = \"http\"\n\n[[listeners]]\nid = \"listener-b\"\nbind = \"127.0.0.1:3129\"\ntransport = \"http\"",
        );
    let text = format!(
        "{text}\n[[parents]]\nid = \"a\"\nendpoint = \"{}\"\ntransport = \"http\"\ncredentials_file = \"{}\"\n\n[[parents]]\nid = \"b\"\nendpoint = \"{}\"\ntransport = \"http\"\ncredentials_file = \"{}\"\n\n[routing]\ndefault_egress = \"system\"\ndefault_parent = \"a\"\n\n[[routing.rules]]\nid = \"via-b\"\negress_id = \"system\"\nnext_hop = \"b\"\nlisteners = [\"listener-b\"]\n",
        parent_a.address,
        creds_a.display(),
        parent_b.address,
        creds_b.display()
    );
    let config = Arc::new(Config::parse(&text).expect("two-parent config"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind proxy");
    let addresses = server
        .addresses()
        .iter()
        .cloned()
        .collect::<std::collections::HashMap<_, _>>();

    let response = get(
        addresses["listener-a"],
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 200);
    let response = get(
        addresses["listener-b"],
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 200);
    assert_eq!(
        parent_a.requests()[0].proxy_authorization.as_deref(),
        Some("Basic YS11c2VyOmEtc2VjcmV0")
    );
    assert_eq!(
        parent_b.requests()[0].proxy_authorization.as_deref(),
        Some("Basic Yi11c2VyOmItc2VjcmV0")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent24_egress_source_ip_reaches_parent_and_ipv6_target() {
    let origin = m04::spawn_echo_origin_at("[::1]:0".parse().expect("IPv6 loopback"), None)
        .await
        .expect("IPv6 echo origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = config_with_parent(
        Some(parent.address),
        Some("parent"),
        "",
        &[origin.address.port()],
    )
    .replace(
        "[routing]\ndefault_egress = \"system\"",
        "[[egress]]\nid = \"v4-source\"\nmode = \"bind_ip\"\nbind_ip = \"127.0.0.2\"\n\n[routing]\ndefault_egress = \"v4-source\"",
    )
    .replace(
        "networks = [\"127.0.0.0/8\"]",
        "networks = [\"127.0.0.0/8\", \"::1/128\"]",
    );
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let authority = format!("[::1]:{}", origin.address.port());
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.send(request.as_bytes()).await.expect("send CONNECT");
    assert_eq!(client.read_head().await.expect("CONNECT head").status, 200);
    client.send(b"s").await.expect("send tunnel byte");
    assert_eq!(client.read_exact_bytes(1).await.expect("read byte"), b"s");
    let requests = parent.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].peer.ip(),
        std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
    );

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent25_parent_abort_does_not_replay_post() {
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"must-not-reach"))
        .await
        .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Abort).await.expect("parent");
    let text = config_with_parent(Some(parent.address), Some("parent"), "", &[]);
    let (server, proxy, _resolver) = start_with_resolver(&text, Vec::new()).await;

    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let body = b"partially-sent-body";
    let request = format!(
        "POST http://{}/upload HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
        origin.address,
        origin.address,
        body.len()
    );
    client.send(request.as_bytes()).await.expect("send head");
    client.send(body).await.expect("send body");
    let response = client.read_response().await.expect("read response");
    assert_eq!(response.head.status, 502);
    assert_eq!(parent.request_count(), 1);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn m09_parent08_tls_parent_accepts_custom_ca_and_rejects_wrong_name() {
    let dir = TempDir::new("m09-tls-parent");
    m06::generate_pki(dir.path());
    let acceptor = TlsAcceptor::from(m06::server_config(
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("proxy_key.pem"),
    ));
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"tls-parent-ok"))
        .await
        .expect("origin");
    let parent = m09::spawn_tls_parent(acceptor, ParentMode::Forward)
        .await
        .expect("TLS parent");
    let ca = dir.path().join("proxy_ca.pem");

    let trusted = {
        let mut text = m03::config("127.0.0.1:3128");
        text.push_str(&format!(
            r#"
[[parents]]
id = "parent"
endpoint = "localhost:{}"
transport = "https"
ca_file = "{}"

[routing]
default_egress = "system"
default_parent = "parent"
"#,
            parent.address.port(),
            ca.display()
        ));
        text
    };
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    )])]));
    let (server, proxy) = start_with_scripted(&trusted, resolver).await;
    let response = get(
        proxy,
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "tls-parent-ok");
    server.shutdown().await;

    let ip_acceptor = TlsAcceptor::from(m06::server_config(
        &dir.path().join("proxy_ip_chain.pem"),
        &dir.path().join("proxy_ip_key.pem"),
    ));
    let ip_parent = m09::spawn_tls_parent(ip_acceptor, ParentMode::Forward)
        .await
        .expect("TLS IP parent");
    let ip_config = {
        let mut text = m03::config("127.0.0.1:3128");
        text.push_str(&format!(
            r#"
[[parents]]
id = "parent"
endpoint = "127.0.0.1:{}"
transport = "https"
ca_file = "{}"

[routing]
default_egress = "system"
default_parent = "parent"
"#,
            ip_parent.address.port(),
            ca.display()
        ));
        text
    };
    let (server, proxy, _resolver) = start_with_resolver(&ip_config, Vec::new()).await;
    let response = get(
        proxy,
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 200);
    server.shutdown().await;

    let wrong_name = {
        let mut text = m03::config("127.0.0.1:3128");
        text.push_str(&format!(
            r#"
[[parents]]
id = "parent"
endpoint = "127.0.0.1:{}"
transport = "https"
ca_file = "{}"

[routing]
default_egress = "system"
default_parent = "parent"
"#,
            parent.address.port(),
            ca.display()
        ));
        text
    };
    let (server, proxy, _resolver) = start_with_resolver(&wrong_name, Vec::new()).await;
    let response = get(
        proxy,
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 502);
    server.shutdown().await;

    let untrusted = {
        let mut text = m03::config("127.0.0.1:3128");
        text.push_str(&format!(
            r#"
[[parents]]
id = "parent"
endpoint = "localhost:{}"
transport = "https"
ca_file = "{}"

[routing]
default_egress = "system"
default_parent = "parent"
"#,
            parent.address.port(),
            dir.path().join("site_ca.pem").display()
        ));
        text
    };
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    )])]));
    let (server, proxy) = start_with_scripted(&untrusted, resolver).await;
    let response = get(
        proxy,
        &format!("http://{}/", origin.address),
        &origin.address.to_string(),
    )
    .await;
    assert_eq!(response.head.status, 502);
    server.shutdown().await;
}
