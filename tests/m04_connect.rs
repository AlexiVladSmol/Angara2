//! M04 CONNECT and tunnel acceptance tests.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::m03::*;
use common::m04::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::{Builder, Runtime};

fn runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build test runtime")
}

fn connect_config(port: u16) -> String {
    connect_config_ports(&[port])
}

fn connect_config_ports(ports: &[u16]) -> String {
    connect_config_tuned(ports, 5_000, 500)
}

fn connect_config_tuned(ports: &[u16], idle_ms: u64, half_close_ms: u64) -> String {
    let ports = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{}\n[connect]\nallowed_ports = [{ports}]\nhalf_close_timeout_ms = {half_close_ms}\n",
        config("127.0.0.1:3128").replace(
            "idle_timeout_ms = 5000",
            &format!("idle_timeout_ms = {idle_ms}")
        )
    )
}

#[test]
fn m04_con01_connect_echoes_early_bytes_and_origin_greeting() {
    runtime().block_on(async {
        let origin = spawn_echo_origin(Some(b"origin-first".to_vec()))
            .await
            .expect("start echo origin");
        let (server, proxy) = start_proxy(&connect_config(origin.address.port())).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\nEARLY",
                    origin.address, origin.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect and early bytes");

        let head = client.read_head().await.expect("read CONNECT 200");
        assert_eq!(head.status, 200);
        for name in [
            "content-length",
            "transfer-encoding",
            "trailer",
            "upgrade",
            "connection",
            "proxy-connection",
        ] {
            assert!(
                head.header(name).is_none(),
                "CONNECT 200 leaked {name}: {:?}",
                head.headers
            );
        }
        assert_eq!(
            client.read_exact_bytes(12).await.expect("origin greeting"),
            b"origin-first"
        );
        assert_eq!(
            client.read_exact_bytes(5).await.expect("early echo"),
            b"EARLY"
        );
        assert_eq!(
            origin.received.lock().unwrap().as_slice(),
            b"EARLY",
            "early bytes were not delivered exactly once"
        );
        assert_eq!(origin.accepts.load(Ordering::Acquire), 1);

        let binary = b"GET / HTTP/1.1\r\nHost: tunnel\r\n\r\n\0\xff";
        client.send(binary).await.expect("send binary");
        assert_eq!(
            client
                .read_exact_bytes(binary.len())
                .await
                .expect("binary echo"),
            binary
        );
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_con02_invalid_connect_is_rejected_without_dial() {
    runtime().block_on(async {
        let origin = spawn_echo_origin(None).await.expect("start echo origin");
        let port = origin.address.port();
        let host = origin.address.to_string();
        let (server, proxy) = start_proxy(&connect_config(port)).await;
        let cases: Vec<(Vec<u8>, Vec<u16>)> = vec![
            (
                b"CONNECT 127.0.0.1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(),
                vec![400],
            ),
            (
                b"CONNECT 127.0.0.1:0 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(),
                vec![400],
            ),
            (
                b"CONNECT 127.0.0.1:65536 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(),
                vec![400],
            ),
            (
                format!("CONNECT user@127.0.0.1:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT 127.0.0.1:{port}/path HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT 127.0.0.1:{port}?q=1 HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT 127.0.0.1:{port}#fragment HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT {host} HTTP/1.1\r\nHost: example.test\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT {host} HTTP/1.1\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 1\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nTrailer: X-Sum\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nExpect: 100-continue\r\n\r\n").into_bytes(),
                vec![417],
            ),
            (
                format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").into_bytes(),
                vec![400],
            ),
            (
                format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nVia: 1.1 angara\r\n\r\n").into_bytes(),
                vec![508],
            ),
            (
                format!("CONNECT {host} HTTP/1.0\r\nHost: {host}\r\n\r\n").into_bytes(),
                vec![505],
            ),
        ];

        for (bytes, allowed) in cases {
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client.send(&bytes).await.expect("send invalid connect");
            let outcome = tokio::time::timeout(Duration::from_secs(2), client.read_response()).await;
            match outcome {
                Ok(Ok(response)) => {
                    assert!(
                        allowed.contains(&response.head.status),
                        "unexpected status {} for {}",
                        response.head.status,
                        String::from_utf8_lossy(&bytes)
                    );
                    assert!(
                        response.interim.is_empty(),
                        "invalid CONNECT emitted interim response"
                    );
                }
                Ok(Err(_)) => {}
                Err(_) => panic!("invalid CONNECT hung: {}", String::from_utf8_lossy(&bytes)),
            }
            assert_eq!(
                origin.accepts.load(Ordering::Acquire),
                0,
                "invalid CONNECT dialed origin: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        server.shutdown().await;
    });
}

#[test]
fn m04_con01_ipv4_ipv6_mapped_and_host_without_port() {
    runtime().block_on(async {
        let v4 = spawn_echo_origin(None).await.expect("v4 echo");
        let v6 = spawn_echo_origin_at("[::1]:0".parse().expect("v6 loopback"), None)
            .await
            .expect("v6 echo");
        let mut text = connect_config_ports(&[v4.address.port(), v6.address.port()]);
        text = text.replace(
            "networks = [\"127.0.0.0/8\"]",
            "networks = [\"127.0.0.0/8\", \"::1/128\"]",
        );
        let (server, proxy) = start_proxy(&text).await;

        let cases = [
            (
                format!("CONNECT {} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", v4.address),
                "v4-host-no-port",
            ),
            (
                format!(
                    "CONNECT [::1]:{} HTTP/1.1\r\nHost: [::1]:{}\r\n\r\n",
                    v6.address.port(),
                    v6.address.port()
                ),
                "ipv6",
            ),
            (
                format!(
                    "CONNECT [::ffff:127.0.0.1]:{} HTTP/1.1\r\nHost: [::ffff:127.0.0.1]:{}\r\n\r\n",
                    v4.address.port(),
                    v4.address.port()
                ),
                "mapped-ipv6",
            ),
        ];
        for (request, label) in cases {
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client.send(request.as_bytes()).await.expect("send connect");
            let head = client.read_head().await.expect("read connect 200");
            assert_eq!(head.status, 200, "{label}");
            client.send(b"ping").await.expect("send ping");
            assert_eq!(
                client.read_exact_bytes(4).await.expect("echo ping"),
                b"ping",
                "{label}"
            );
            drop(client);
        }
        server.shutdown().await;
    });
}

struct FixedConnectResolver {
    calls: std::sync::atomic::AtomicUsize,
    answer: std::net::IpAddr,
}

impl angara::resolver::Resolver for FixedConnectResolver {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
        _deadline: std::time::Instant,
    ) -> angara::resolver::ResolveFuture<'a> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let answer = self.answer;
        Box::pin(async move { Ok(vec![answer]) })
    }
}

#[test]
fn m04_con01_domain_uses_fresh_resolver_result() {
    runtime().block_on(async {
        let origin = spawn_echo_origin(None).await.expect("echo origin");
        let resolver = Arc::new(FixedConnectResolver {
            calls: std::sync::atomic::AtomicUsize::new(0),
            answer: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        });
        let text = connect_config(origin.address.port());
        let config = Arc::new(angara::config::Config::parse(&text).expect("valid config"));
        let server = angara::http::HttpServer::bind_ephemeral_with_components(
            config,
            resolver.clone(),
            Arc::new(angara::transport::TcpDialer),
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;

        for index in 0..2 {
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            let target = format!("connect.test:{}", origin.address.port());
            client
                .send(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
                .await
                .expect("send connect");
            let head = client.read_head().await.expect("read connect");
            assert_eq!(head.status, 200, "attempt {index}");
            client.send(b"dns").await.expect("send dns payload");
            assert_eq!(
                client.read_exact_bytes(3).await.expect("dns echo"),
                b"dns",
                "attempt {index}"
            );
            drop(client);
        }
        assert_eq!(resolver.calls.load(Ordering::Acquire), 2);
        assert_eq!(origin.accepts.load(Ordering::Acquire), 2);
        server.shutdown().await;
    });
}

struct CountingDialer {
    dials: Arc<std::sync::atomic::AtomicUsize>,
}

impl angara::transport::Dialer for CountingDialer {
    fn connect<'a>(
        &'a self,
        _endpoint: std::net::SocketAddr,
        _egress: &'a angara::config::EgressProfile,
        _deadline: std::time::Instant,
    ) -> angara::transport::DialFuture<'a> {
        self.dials.fetch_add(1, Ordering::AcqRel);
        Box::pin(async { Err(angara::transport::DialError::ConnectFailed) })
    }
}

async fn start_spy_proxy(
    text: &str,
    answer: std::net::IpAddr,
) -> (
    angara::http::HttpServer,
    std::net::SocketAddr,
    Arc<FixedConnectResolver>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let resolver = Arc::new(FixedConnectResolver {
        calls: std::sync::atomic::AtomicUsize::new(0),
        answer,
    });
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = Arc::new(angara::config::Config::parse(text).expect("valid config"));
    let server = angara::http::HttpServer::bind_ephemeral_with_components(
        config,
        resolver.clone(),
        Arc::new(CountingDialer {
            dials: Arc::clone(&dials),
        }),
    )
    .await
    .expect("bind spy proxy");
    let proxy = server.addresses()[0].1;
    (server, proxy, resolver, dials)
}

#[test]
fn m04_pol01_pre_dns_denies_do_not_resolve_or_dial() {
    runtime().block_on(async {
        let origin = spawn_echo_origin(None).await.expect("echo origin");
        let host = format!("deny.test:{}", origin.address.port());
        let port = origin.address.port();
        let allow_rule = "[[access.rules]]\nid = \"allow\"\naction = \"allow\"";
        let deny_rule = "[[access.rules]]\nid = \"deny\"\naction = \"deny\"";

        let cases = [
            (
                "source deny",
                connect_config(port).replace(
                    "source_allow = [\"127.0.0.0/8\"]",
                    "source_allow = [\"10.0.0.0/8\"]",
                ),
            ),
            (
                "request ACL deny",
                connect_config(port).replace(allow_rule, deny_rule),
            ),
            (
                "port deny",
                connect_config(if port == 444 { 445 } else { 444 }),
            ),
        ];

        for (label, text) in cases {
            let (server, proxy, resolver, dials) =
                start_spy_proxy(&text, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client
                .send(format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
                .await
                .expect("send denied connect");
            let response = client.read_response().await.expect("read denial");
            assert_eq!(response.head.status, 403, "{label}");
            assert_eq!(resolver.calls.load(Ordering::Acquire), 0, "{label} DNS");
            assert_eq!(dials.load(Ordering::Acquire), 0, "{label} dial");
            drop(client);
            server.shutdown().await;
        }
        assert_eq!(origin.accepts.load(Ordering::Acquire), 0);
    });
}

#[test]
fn m04_pol01_spoofed_headers_do_not_bypass_acl() {
    runtime().block_on(async {
        let origin = spawn_echo_origin(None).await.expect("echo origin");
        let host = format!("deny.test:{}", origin.address.port());
        let text = connect_config(origin.address.port()).replace(
            "[[access.rules]]\nid = \"allow\"\naction = \"allow\"",
            "[[access.rules]]\nid = \"deny\"\naction = \"deny\"",
        );
        let (server, proxy, resolver, dials) =
            start_spy_proxy(&text, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {host} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: 127.0.0.1\r\nProxy-Authorization: Basic ZmFrZQ==\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("send spoofed connect");
        assert_eq!(
            client.read_response().await.expect("read deny").head.status,
            403
        );
        assert_eq!(resolver.calls.load(Ordering::Acquire), 0);
        assert_eq!(dials.load(Ordering::Acquire), 0);
        assert_eq!(origin.accepts.load(Ordering::Acquire), 0);
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_pol02_ip_deny_stops_before_dial() {
    runtime().block_on(async {
        let origin = spawn_echo_origin(None).await.expect("echo origin");
        let host = format!("deny.test:{}", origin.address.port());
        let text = connect_config(origin.address.port()).replace(
            "[[access.ip_rules]]\nid = \"loopback\"\naction = \"allow\"\nnetworks = [\"127.0.0.0/8\"]\nallow_special = true",
            "[[access.ip_rules]]\nid = \"loopback\"\naction = \"deny\"\nnetworks = [\"127.0.0.0/8\"]",
        );
        let (server, proxy, resolver, dials) =
            start_spy_proxy(&text, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(format!("CONNECT {host} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .expect("send connect");
        assert_eq!(
            client.read_response().await.expect("read deny").head.status,
            403
        );
        assert_eq!(resolver.calls.load(Ordering::Acquire), 1);
        assert_eq!(dials.load(Ordering::Acquire), 0);
        assert_eq!(origin.accepts.load(Ordering::Acquire), 0);
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_con03_failed_dial_is_not_200() {
    runtime().block_on(async {
        let closed_port = 1;
        let (server, proxy, _resolver, dials) = start_spy_proxy(
            &connect_config(closed_port),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        )
        .await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT 127.0.0.1:{closed_port} HTTP/1.1\r\nHost: 127.0.0.1:{closed_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("send failed connect");
        let response = client.read_response().await.expect("read refusal");
        assert_eq!(response.head.status, 502);
        assert!(response.body.is_empty());
        assert_eq!(dials.load(Ordering::Acquire), 1);
        drop(client);
        server.shutdown().await;
    });
}

struct TimeoutResolver;

impl angara::resolver::Resolver for TimeoutResolver {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
        _deadline: std::time::Instant,
    ) -> angara::resolver::ResolveFuture<'a> {
        Box::pin(async { Err(angara::resolver::ResolveError::Timeout) })
    }
}

#[test]
fn m04_con03_dns_timeout_maps_to_504_without_dial() {
    runtime().block_on(async {
        let port = 443;
        let text = connect_config(port);
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let config = Arc::new(angara::config::Config::parse(&text).expect("valid config"));
        let server = angara::http::HttpServer::bind_ephemeral_with_components(
            config,
            Arc::new(TimeoutResolver),
            Arc::new(CountingDialer {
                dials: Arc::clone(&dials),
            }),
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(b"CONNECT timeout.test:443 HTTP/1.1\r\nHost: timeout.test:443\r\n\r\n")
            .await
            .expect("send connect");
        let response = client.read_response().await.expect("read timeout");
        assert_eq!(response.head.status, 504);
        assert_eq!(dials.load(Ordering::Acquire), 0);
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_con06_http_then_connect_keeps_order_and_tunnel_is_opaque() {
    runtime().block_on(async {
        let http_origin = spawn_origin(|_, _| {
            let mut bytes = b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n".to_vec();
            bytes.extend_from_slice(&response("200 OK", &[], &vec![b'H'; 128 * 1024]));
            bytes
        })
        .await
        .expect("HTTP origin");
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let (server, proxy) = start_proxy(&connect_config(echo.address.port())).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        let mut bytes = request("GET", http_origin.address, "/before", &[], b"");
        bytes.extend_from_slice(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\nopaque",
                echo.address, echo.address
            )
            .as_bytes(),
        );
        client.send(&bytes).await.expect("send pipelined requests");

        let first = client.read_response().await.expect("read HTTP response");
        assert_eq!(first.head.status, 200);
        assert_eq!(first.interim.len(), 1);
        assert_eq!(first.body.len(), 128 * 1024);
        assert!(first.body.iter().all(|byte| *byte == b'H'));
        assert_eq!(
            client.read_head().await.expect("read CONNECT 200").status,
            200
        );
        assert_eq!(
            client.read_exact_bytes(6).await.expect("tunnel echo"),
            b"opaque"
        );
        assert_eq!(echo.accepts.load(Ordering::Acquire), 1);
        assert_eq!(
            http_origin.accepts.load(Ordering::Acquire),
            1,
            "CONNECT must not reuse the HTTP origin socket"
        );

        let http_looking = b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n";
        client.send(http_looking).await.expect("send HTTP-looking");
        assert_eq!(
            client
                .read_exact_bytes(http_looking.len())
                .await
                .expect("opaque echo"),
            http_looking
        );
        assert_eq!(echo.accepts.load(Ordering::Acquire), 1);
        assert_eq!(http_origin.accepts.load(Ordering::Acquire), 1);
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_con06_each_connect_opens_a_separate_origin() {
    runtime().block_on(async {
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let (server, proxy) = start_proxy(&connect_config(echo.address.port())).await;
        for attempt in 0..2 {
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client
                .send(
                    format!(
                        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\nx{}",
                        echo.address, echo.address, attempt
                    )
                    .as_bytes(),
                )
                .await
                .expect("send connect");
            assert_eq!(
                client.read_head().await.expect("read 200").status,
                200,
                "attempt {attempt}"
            );
            assert_eq!(
                client.read_exact_bytes(2).await.expect("echo"),
                format!("x{attempt}").as_bytes()
            );
            drop(client);
        }
        assert_eq!(echo.accepts.load(Ordering::Acquire), 2);
        server.shutdown().await;
    });
}

#[test]
fn m04_con04_split_writes_and_payload_larger_than_buffer() {
    runtime().block_on(async {
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let (server, proxy) = start_proxy(&connect_config(echo.address.port())).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);

        for index in 0..4 {
            let chunk = vec![b'a' + index; 32 * 1024];
            client.send(&chunk).await.expect("send tunnel chunk");
            let echoed = client
                .read_exact_bytes(chunk.len())
                .await
                .expect("read tunnel chunk");
            assert_eq!(echoed, chunk, "chunk {index}");
        }
        assert!(echo.received.lock().unwrap().len() >= 4 * 32 * 1024);
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_io02_idle_without_progress_closes_tunnel() {
    runtime().block_on(async {
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let (server, proxy) =
            start_proxy(&connect_config_tuned(&[echo.address.port()], 1_000, 500)).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);
        let started = std::time::Instant::now();
        let rest = client.read_until_eof().await.expect("read idle EOF");
        assert!(rest.is_empty());
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(800) && elapsed < Duration::from_secs(3),
            "idle close happened at {elapsed:?}"
        );
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_io02_upload_only_progress_keeps_tunnel_alive() {
    runtime().block_on(async {
        let sink = spawn_sink_origin().await.expect("sink origin");
        let (server, proxy) =
            start_proxy(&connect_config_tuned(&[sink.address.port()], 1_000, 500)).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    sink.address, sink.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);

        for _ in 0..12 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            client.send(b"upload").await.expect("send progress");
        }
        assert_eq!(sink.accepts.load(Ordering::Acquire), 1);
        assert!(
            wait_until(|| sink.received.load(Ordering::Acquire) >= 12 * 6).await,
            "sink received {} bytes",
            sink.received.load(Ordering::Acquire)
        );
        client.shutdown_write().await.expect("client EOF");
        let rest = client.read_until_eof().await.expect("read tunnel close");
        assert!(rest.is_empty());
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_io02_download_only_progress_keeps_tunnel_alive() {
    runtime().block_on(async {
        let origin = spawn_periodic_origin(Duration::from_millis(200), b"download".to_vec(), 12)
            .await
            .expect("periodic origin");
        let (server, proxy) =
            start_proxy(&connect_config_tuned(&[origin.address.port()], 1_000, 500)).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    origin.address, origin.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);
        for index in 0..12 {
            let chunk = client
                .read_exact_bytes(8)
                .await
                .unwrap_or_else(|error| panic!("download {index}: {error}"));
            assert_eq!(chunk, b"download");
        }
        let rest = client.read_until_eof().await.expect("read tunnel close");
        assert!(rest.is_empty());
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_io01_client_half_close_drains_origin_response() {
    runtime().block_on(async {
        let origin = spawn_eof_reply_origin(b"after-eof".to_vec())
            .await
            .expect("EOF reply origin");
        let (server, proxy) = start_proxy(&connect_config_tuned(
            &[origin.address.port()],
            2_000,
            1_000,
        ))
        .await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    origin.address, origin.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);
        client.send(b"request").await.expect("send request");
        client.shutdown_write().await.expect("client half-close");
        let reply = client.read_until_eof().await.expect("read reply");
        assert_eq!(reply, b"after-eof");
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_io01_half_close_deadline_is_absolute_across_reverse_progress() {
    runtime().block_on(async {
        let origin = spawn_periodic_origin(Duration::from_millis(50), b"tick".to_vec(), 1_000)
            .await
            .expect("periodic origin");
        let (server, proxy) =
            start_proxy(&connect_config_tuned(&[origin.address.port()], 2_000, 300)).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    origin.address, origin.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);
        let started = std::time::Instant::now();
        client.shutdown_write().await.expect("client half-close");
        let received = client.read_until_eof().await.expect("read drain EOF");
        let elapsed = started.elapsed();
        assert!(
            !received.is_empty(),
            "no reverse bytes were delivered before the drain deadline"
        );
        assert!(
            elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(2),
            "half-close drain took {elapsed:?}"
        );
        drop(client);
        server.shutdown().await;
    });
}

struct CancelDialer {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl angara::transport::Dialer for CancelDialer {
    fn connect<'a>(
        &'a self,
        endpoint: std::net::SocketAddr,
        egress: &'a angara::config::EgressProfile,
        deadline: std::time::Instant,
    ) -> angara::transport::DialFuture<'a> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        if call == 0 {
            Box::pin(async {
                std::future::pending::<Result<tokio::net::TcpStream, angara::transport::DialError>>(
                )
                .await
            })
        } else {
            angara::transport::TcpDialer.connect(endpoint, egress, deadline)
        }
    }
}

#[test]
fn m04_io03_cancelled_setup_releases_outbound_permit() {
    runtime().block_on(async {
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let text = connect_config(echo.address.port())
            .replace("max_connections = 64", "max_connections = 1")
            .replace("max_connecting = 8", "max_connecting = 1")
            .replace("pool_max_idle = 4", "pool_max_idle = 1")
            .replace("pool_max_idle_per_key = 2", "pool_max_idle_per_key = 1");
        let config = Arc::new(angara::config::Config::parse(&text).expect("valid config"));
        let server = angara::http::HttpServer::bind_ephemeral_with_components(
            config,
            Arc::new(FixedConnectResolver {
                calls: std::sync::atomic::AtomicUsize::new(0),
                answer: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            }),
            Arc::new(CancelDialer {
                calls: Arc::clone(&dials),
            }),
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;

        let mut first = RawClient::connect(proxy).await.expect("first client");
        first
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send first connect");
        assert!(wait_until(|| dials.load(Ordering::Acquire) == 1).await);
        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut second = RawClient::connect(proxy).await.expect("second client");
        second
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send second connect");
        let response = tokio::time::timeout(Duration::from_secs(3), second.read_head())
            .await
            .expect("second CONNECT timed out");
        assert_eq!(response.expect("second 200").status, 200);
        assert_eq!(dials.load(Ordering::Acquire), 2);
        drop(second);
        server.shutdown().await;
    });
}

#[test]
fn m04_res01_http_and_connect_share_outbound_budget() {
    runtime().block_on(async {
        let http = spawn_slow_http_origin(Duration::from_millis(500))
            .await
            .expect("slow HTTP origin");
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let text = connect_config(echo.address.port())
            .replace("max_connections = 64", "max_connections = 1")
            .replace("max_connecting = 8", "max_connecting = 1")
            .replace("pool_max_idle = 4", "pool_max_idle = 1")
            .replace("pool_max_idle_per_key = 2", "pool_max_idle_per_key = 1");
        let (server, proxy) = start_proxy(&text).await;

        let mut http_client = RawClient::connect(proxy).await.expect("HTTP client");
        http_client
            .send(&request("GET", http.address, "/slow", &[], b""))
            .await
            .expect("send HTTP request");
        let http_head = http_client.read_head().await.expect("read HTTP head");
        assert_eq!(http_head.status, 200);
        assert!(wait_until(|| http.accepts.load(Ordering::Acquire) == 1).await);

        let mut blocked = RawClient::connect(proxy).await.expect("blocked client");
        blocked
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send blocked connect");
        let blocked_head = blocked.read_response().await.expect("read 503");
        assert_eq!(blocked_head.head.status, 503);
        assert_eq!(echo.accepts.load(Ordering::Acquire), 0);

        drop(http_client);
        drop(blocked);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut tunnel = RawClient::connect(proxy).await.expect("tunnel client");
        tunnel
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send allowed connect");
        assert_eq!(tunnel.read_head().await.expect("read 200").status, 200);
        tunnel.send(b"budget").await.expect("send tunnel bytes");
        assert_eq!(
            tunnel.read_exact_bytes(6).await.expect("tunnel echo"),
            b"budget"
        );
        drop(tunnel);
        server.shutdown().await;
    });
}

#[test]
fn m04_res01_client_budget_counts_live_tunnel() {
    runtime().block_on(async {
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let text = connect_config(echo.address.port())
            .replace("max_client_connections = 16", "max_client_connections = 1");
        let (server, proxy) = start_proxy(&text).await;
        let mut first = RawClient::connect(proxy).await.expect("first client");
        first
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send first connect");
        assert_eq!(first.read_head().await.expect("read first 200").status, 200);

        let mut second = RawClient::connect(proxy).await.expect("second TCP");
        second
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send second connect");
        let rejected = tokio::time::timeout(Duration::from_secs(2), second.read_head()).await;
        assert!(
            !matches!(rejected, Ok(Ok(ref head)) if head.status == 200),
            "active tunnel must hold the only client permit: {rejected:?}"
        );
        drop(second);
        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut third = RawClient::connect(proxy).await.expect("third client");
        third
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send third connect");
        assert_eq!(third.read_head().await.expect("read third 200").status, 200);
        drop(third);
        server.shutdown().await;
    });
}

struct WorkerRecordingConnectDialer {
    threads: Arc<std::sync::Mutex<std::collections::HashSet<std::thread::ThreadId>>>,
}

impl angara::transport::Dialer for WorkerRecordingConnectDialer {
    fn connect<'a>(
        &'a self,
        endpoint: std::net::SocketAddr,
        egress: &'a angara::config::EgressProfile,
        deadline: std::time::Instant,
    ) -> angara::transport::DialFuture<'a> {
        Box::pin(async move {
            self.threads
                .lock()
                .expect("worker set")
                .insert(std::thread::current().id());
            let until = std::time::Instant::now() + Duration::from_millis(20);
            let mut spin = 0_u64;
            while std::time::Instant::now() < until {
                spin = spin.wrapping_add(1);
            }
            std::hint::black_box(spin);
            angara::transport::TcpDialer
                .connect(endpoint, egress, deadline)
                .await
        })
    }
}

fn run_connect_clients(
    workers: usize,
    clients: usize,
    recorded: Option<Arc<std::sync::Mutex<std::collections::HashSet<std::thread::ThreadId>>>>,
) -> usize {
    let runtime = Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("worker runtime");
    runtime.block_on(async move {
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let text = connect_config(echo.address.port())
            .replace("max_client_connections = 16", "max_client_connections = 64")
            .replace("max_connecting = 8", "max_connecting = 32");
        let config = Arc::new(angara::config::Config::parse(&text).expect("config"));
        let dialer: Arc<dyn angara::transport::Dialer> = match recorded {
            Some(threads) => Arc::new(WorkerRecordingConnectDialer { threads }),
            None => Arc::new(angara::transport::TcpDialer),
        };
        let server = angara::http::HttpServer::bind_ephemeral_with_components(
            config,
            Arc::new(FixedConnectResolver {
                calls: std::sync::atomic::AtomicUsize::new(0),
                answer: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            }),
            dialer,
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;
        let mut tasks = Vec::new();
        for index in 0..clients {
            let target = echo.address;
            tasks.push(tokio::spawn(async move {
                let mut client = RawClient::connect(proxy).await.expect("tunnel client");
                client
                    .send(
                        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n{index}")
                            .as_bytes(),
                    )
                    .await
                    .expect("send connect");
                assert_eq!(client.read_head().await.expect("read 200").status, 200);
                let expected = format!("{index}");
                assert_eq!(
                    client
                        .read_exact_bytes(expected.len())
                        .await
                        .expect("tunnel echo"),
                    expected.as_bytes()
                );
            }));
        }
        for task in tasks {
            task.await.expect("join client");
        }
        assert_eq!(echo.accepts.load(Ordering::Acquire), clients);
        server.shutdown().await;
        echo.accepts.load(Ordering::Acquire)
    })
}

#[test]
fn m04_cpu01_connect_path_uses_multiple_workers() {
    for workers in [1, 2, 4] {
        let clients = if workers == 4 { 20 } else { 10 };
        assert_eq!(
            run_connect_clients(workers, clients, None),
            clients,
            "workers={workers}"
        );
    }
    let threads = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let clients = 20;
    assert_eq!(
        run_connect_clients(4, clients, Some(Arc::clone(&threads))),
        clients
    );
    let workers = threads.lock().expect("worker set").len();
    eprintln!("M04-CPU-01 workers={workers} clients={clients}");
    assert!(
        workers >= 2,
        "Angara CONNECT outbound path ran on only one worker: {workers}"
    );
}

#[test]
fn m04_net01_two_listeners_egress_ips_and_ipv6_are_preserved() {
    runtime().block_on(async {
        let v4 = spawn_echo_origin(None).await.expect("v4 echo");
        let v6 = spawn_echo_origin_at("[::1]:0".parse().expect("v6 loopback"), None)
            .await
            .expect("v6 echo");
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
shutdown_timeout_ms = 2000
[[listeners]]
id = "via-a"
bind = "127.0.0.1:3128"
transport = "http"
[[listeners]]
id = "via-b"
bind = "127.0.0.1:3129"
transport = "http"
[[listeners]]
id = "via-v6"
bind = "[::1]:3130"
transport = "http"
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
allowed_ports = [{v4port}, {v6port}]
half_close_timeout_ms = 500
[[egress]]
id = "via-a"
mode = "bind_ip"
bind_ip = "127.0.0.1"
[[egress]]
id = "via-b"
mode = "bind_ip"
bind_ip = "127.0.0.2"
[[egress]]
id = "via-v6"
mode = "bind_ip"
bind_ip = "::1"
[routing]
default_egress = "via-a"
[[routing.rules]]
id = "route-a"
listeners = ["via-a"]
egress_id = "via-a"
[[routing.rules]]
id = "route-b"
listeners = ["via-b"]
egress_id = "via-b"
[[routing.rules]]
id = "route-v6"
listeners = ["via-v6"]
egress_id = "via-v6"
"#,
            v4port = v4.address.port(),
            v6port = v6.address.port()
        );
        let config = Arc::new(angara::config::Config::parse(&text).expect("valid net config"));
        let server = angara::http::HttpServer::bind_ephemeral(config)
            .await
            .expect("bind proxy");
        let addresses = server.addresses().to_vec();
        assert_eq!(addresses.len(), 3);

        let cases = [
            (0usize, v4.address.to_string(), "127.0.0.1"),
            (1usize, v4.address.to_string(), "127.0.0.2"),
            (2usize, format!("[::1]:{}", v6.address.port()), "::1"),
        ];
        for (index, target, expected_peer) in cases {
            let mut client = RawClient::connect(addresses[index].1)
                .await
                .expect("connect listener");
            client
                .send(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
                .await
                .expect("send connect");
            assert_eq!(
                client.read_head().await.expect("read 200").status,
                200,
                "listener {index}"
            );
            client.send(b"n").await.expect("send tunnel byte");
            assert_eq!(
                client.read_exact_bytes(1).await.expect("echo"),
                b"n",
                "listener {index}"
            );
            let peers = v4.peers.lock().unwrap().clone();
            let v6_peers = v6.peers.lock().unwrap().clone();
            let peer = if index == 2 {
                v6_peers.last().copied()
            } else {
                peers.get(index).copied()
            };
            assert_eq!(
                peer.map(|ip| ip.to_string()).as_deref(),
                Some(expected_peer),
                "listener {index} used the wrong egress source"
            );
        }
        assert_eq!(v4.accepts.load(Ordering::Acquire), 2);
        assert_eq!(v6.accepts.load(Ordering::Acquire), 1);
        server.shutdown().await;
    });
}

#[test]
fn m04_io03_origin_reset_closes_tunnel_without_http_response() {
    runtime().block_on(async {
        let rst_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("rst listener");
        let rst_address = rst_listener.local_addr().expect("rst address");
        tokio::spawn(async move {
            let (mut stream, _) = rst_listener.accept().await.expect("rst accept");
            let mut buffer = [0_u8; 16];
            let _ = stream.read(&mut buffer).await;
            let _ = stream.set_zero_linger();
            drop(stream);
        });
        let healthy = spawn_echo_origin(None).await.expect("healthy echo");
        let (server, proxy) = start_proxy(&connect_config_ports(&[
            rst_address.port(),
            healthy.address.port(),
        ]))
        .await;

        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!("CONNECT {rst_address} HTTP/1.1\r\nHost: {rst_address}\r\n\r\n").as_bytes(),
            )
            .await
            .expect("send rst tunnel");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);
        client.send(b"trigger").await.expect("trigger reset");
        let bytes = client.read_until_eof().await.unwrap_or_default();
        assert!(
            bytes.is_empty(),
            "tunnel reset produced HTTP/payload bytes: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        drop(client);

        let mut healthy_client = RawClient::connect(proxy).await.expect("healthy client");
        healthy_client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\nok",
                    healthy.address, healthy.address
                )
                .as_bytes(),
            )
            .await
            .expect("send healthy tunnel");
        assert_eq!(
            healthy_client
                .read_head()
                .await
                .expect("healthy 200")
                .status,
            200
        );
        assert_eq!(
            healthy_client
                .read_exact_bytes(2)
                .await
                .expect("healthy echo"),
            b"ok"
        );
        drop(healthy_client);
        server.shutdown().await;
    });
}

struct GateDialer {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    gate: Arc<tokio::sync::Notify>,
}

impl angara::transport::Dialer for GateDialer {
    fn connect<'a>(
        &'a self,
        endpoint: std::net::SocketAddr,
        egress: &'a angara::config::EgressProfile,
        deadline: std::time::Instant,
    ) -> angara::transport::DialFuture<'a> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        if call == 0 {
            Box::pin(async move {
                self.gate.notified().await;
                angara::transport::TcpDialer
                    .connect(endpoint, egress, deadline)
                    .await
            })
        } else {
            angara::transport::TcpDialer.connect(endpoint, egress, deadline)
        }
    }
}

#[test]
fn m04_res01_max_connecting_is_shared_and_returns() {
    runtime().block_on(async {
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());
        let text = connect_config(echo.address.port())
            .replace("max_connections = 64", "max_connections = 4")
            .replace("max_connecting = 8", "max_connecting = 1");
        let config = Arc::new(angara::config::Config::parse(&text).expect("config"));
        let server = angara::http::HttpServer::bind_ephemeral_with_components(
            config,
            Arc::new(FixedConnectResolver {
                calls: std::sync::atomic::AtomicUsize::new(0),
                answer: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            }),
            Arc::new(GateDialer {
                calls: Arc::clone(&calls),
                gate: Arc::clone(&gate),
            }),
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;

        let mut first = RawClient::connect(proxy).await.expect("first client");
        first
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send first connect");
        assert!(wait_until(|| calls.load(Ordering::Acquire) == 1).await);

        let mut blocked = RawClient::connect(proxy).await.expect("blocked client");
        blocked
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send blocked connect");
        assert_eq!(
            blocked.read_response().await.expect("read 503").head.status,
            503
        );
        drop(blocked);

        gate.notify_one();
        assert_eq!(first.read_head().await.expect("read first 200").status, 200);
        first.send(b"g").await.expect("send gate byte");
        assert_eq!(first.read_exact_bytes(1).await.expect("gate echo"), b"g");
        drop(first);
        server.shutdown().await;
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m04_res02_upload_backpressure_does_not_buffer_the_whole_stream() {
    runtime().block_on(async {
        let holding = spawn_holding_origin().await.expect("holding origin");
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let (server, proxy) = start_proxy(&connect_config_ports(&[
            holding.address.port(),
            echo.address.port(),
        ]))
        .await;
        let mut client = connect_small_buffers(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    holding.address, holding.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);
        assert_eq!(holding.accepts.load(Ordering::Acquire), 1);

        let payload = vec![b'U'; 64 * 1024 * 1024];
        let result = tokio::time::timeout(Duration::from_millis(500), client.send(&payload)).await;
        assert!(
            result.is_err(),
            "upload of 64 MiB completed without backpressure"
        );
        drop(client);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut healthy = RawClient::connect(proxy).await.expect("healthy client");
        healthy
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\nok",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send healthy connect");
        assert_eq!(healthy.read_head().await.expect("read 200").status, 200);
        assert_eq!(
            healthy.read_exact_bytes(2).await.expect("healthy echo"),
            b"ok"
        );
        drop(healthy);
        server.shutdown().await;
    });
}

struct SequenceResolver {
    answers: std::sync::Mutex<std::collections::VecDeque<std::net::IpAddr>>,
}

impl angara::resolver::Resolver for SequenceResolver {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
        _deadline: std::time::Instant,
    ) -> angara::resolver::ResolveFuture<'a> {
        Box::pin(async move {
            self.answers
                .lock()
                .expect("answers")
                .pop_front()
                .ok_or(angara::resolver::ResolveError::Failed)
                .map(|answer| vec![answer])
        })
    }
}

#[test]
fn m04_pol02_dns_change_uses_new_endpoint_for_second_connect() {
    runtime().block_on(async {
        let first = spawn_echo_origin(None).await.expect("first echo");
        let second_address = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)),
            first.address.port(),
        );
        let second = spawn_echo_origin_at(second_address, None)
            .await
            .expect("second echo");
        let resolver = Arc::new(SequenceResolver {
            answers: std::sync::Mutex::new(std::collections::VecDeque::from(vec![
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)),
            ])),
        });
        let config = Arc::new(
            angara::config::Config::parse(&connect_config(first.address.port())).expect("config"),
        );
        let server = angara::http::HttpServer::bind_ephemeral_with_components(
            config,
            resolver,
            Arc::new(angara::transport::TcpDialer),
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;
        let target = format!("switch.test:{}", first.address.port());
        for attempt in 0..2 {
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client
                .send(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
                .await
                .expect("send connect");
            assert_eq!(
                client.read_head().await.expect("read 200").status,
                200,
                "attempt {attempt}"
            );
            client.send(b"d").await.expect("send byte");
            assert_eq!(
                client.read_exact_bytes(1).await.expect("echo"),
                b"d",
                "attempt {attempt}"
            );
            drop(client);
        }
        assert_eq!(first.accepts.load(Ordering::Acquire), 1);
        assert_eq!(second.accepts.load(Ordering::Acquire), 1);
        server.shutdown().await;
    });
}

struct ConnectTimeoutDialer;

impl angara::transport::Dialer for ConnectTimeoutDialer {
    fn connect<'a>(
        &'a self,
        _endpoint: std::net::SocketAddr,
        _egress: &'a angara::config::EgressProfile,
        _deadline: std::time::Instant,
    ) -> angara::transport::DialFuture<'a> {
        Box::pin(async { Err(angara::transport::DialError::ConnectTimeout) })
    }
}

#[test]
fn m04_con03_connect_timeout_maps_to_504() {
    runtime().block_on(async {
        let text = connect_config(443);
        let config = Arc::new(angara::config::Config::parse(&text).expect("config"));
        let server = angara::http::HttpServer::bind_ephemeral_with_components(
            config,
            Arc::new(FixedConnectResolver {
                calls: std::sync::atomic::AtomicUsize::new(0),
                answer: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            }),
            Arc::new(ConnectTimeoutDialer),
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
            .await
            .expect("send connect");
        assert_eq!(
            client
                .read_response()
                .await
                .expect("read timeout")
                .head
                .status,
            504
        );
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_con04_effective_zero_content_length_keeps_early_bytes() {
    runtime().block_on(async {
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let (server, proxy) = start_proxy(&connect_config(echo.address.port())).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\nzero",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);
        assert_eq!(
            client.read_exact_bytes(4).await.expect("early zero echo"),
            b"zero"
        );
        drop(client);
        server.shutdown().await;
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m04_con03_real_refused_loopback_maps_to_502() {
    runtime().block_on(async {
        let closed_port = free_port();
        let (server, proxy) = start_proxy(&connect_config(closed_port)).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT 127.0.0.1:{closed_port} HTTP/1.1\r\nHost: 127.0.0.1:{closed_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("send refused connect");
        let response = client.read_response().await.expect("read refused");
        assert_eq!(response.head.status, 502);
        assert!(response.body.is_empty());
        drop(client);
        server.shutdown().await;
    });
}

#[test]
fn m04_io01_origin_fin_keeps_client_to_origin_direction_open() {
    runtime().block_on(async {
        let origin = spawn_half_close_write_origin(b"origin-finished-writing".to_vec())
            .await
            .expect("half-close origin");
        let (server, proxy) = start_proxy(&connect_config_tuned(
            &[origin.address.port()],
            5_000,
            1_000,
        ))
        .await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    origin.address, origin.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);
        let greeting = client.read_until_eof().await.expect("read origin FIN");
        assert_eq!(greeting, b"origin-finished-writing");

        tokio::time::sleep(Duration::from_millis(50)).await;
        client
            .send(b"client-after-origin-fin")
            .await
            .expect("send after origin FIN");
        client.shutdown_write().await.expect("client EOF");
        assert!(
            wait_until(|| {
                origin.received.lock().unwrap().as_slice() == b"client-after-origin-fin"
            })
            .await,
            "origin did not receive bytes after its FIN: {:?}",
            origin.received.lock().unwrap()
        );
        assert_eq!(origin.accepts.load(Ordering::Acquire), 1);
        drop(client);
        server.shutdown().await;
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m04_io02_partial_origin_writes_refresh_shared_idle() {
    runtime().block_on(async {
        let origin = spawn_slow_reader_origin(1024, Duration::from_millis(100))
            .await
            .expect("slow reader origin");
        let (server, proxy) = start_proxy(&connect_config_tuned(
            &[origin.address.port()],
            1_000,
            1_000,
        ))
        .await;
        let mut client = connect_small_buffers(proxy).await.expect("connect proxy");
        client
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    origin.address, origin.address
                )
                .as_bytes(),
            )
            .await
            .expect("send connect");
        assert_eq!(client.read_head().await.expect("read 200").status, 200);

        let payload = vec![b'P'; 16 * 1024 * 1024];
        let send = client.send(&payload);
        let mut send = Box::pin(send);
        tokio::select! {
            result = &mut send => panic!("16 MiB upload completed without backpressure: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(1500)) => {}
        }
        drop(send);
        let closed =
            tokio::time::timeout(Duration::from_millis(200), client.read_until_eof()).await;
        assert!(
            closed.is_err(),
            "tunnel was closed despite ongoing slow origin progress: {closed:?}"
        );
        assert!(origin.received.load(Ordering::Acquire) > 0);
        drop(client);
        server.shutdown().await;
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m04_srv01_final_bridge_drain_uses_half_close_deadline() {
    runtime().block_on(async {
        let origin = spawn_eof_then_write_origin(4 * 1024 * 1024)
            .await
            .expect("EOF then write origin");
        let text = connect_config_tuned(&[origin.address.port()], 5_000, 200)
            .replace("max_client_connections = 16", "max_client_connections = 1");
        let (server, proxy) = start_proxy(&text).await;

        let mut first = connect_small_buffers(proxy).await.expect("first client");
        first
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    origin.address, origin.address
                )
                .as_bytes(),
            )
            .await
            .expect("send first connect");
        assert_eq!(first.read_head().await.expect("read first 200").status, 200);
        first.shutdown_write().await.expect("first half-close");
        let started = std::time::Instant::now();

        let mut second = None;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut candidate = RawClient::connect(proxy).await.expect("second client");
            candidate
                .send(
                    format!(
                        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                        origin.address, origin.address
                    )
                    .as_bytes(),
                )
                .await
                .expect("send second connect");
            match tokio::time::timeout(Duration::from_millis(500), candidate.read_head()).await {
                Ok(Ok(head)) if head.status == 200 => {
                    second = Some(candidate);
                    break;
                }
                _ => drop(candidate),
            }
        }
        let elapsed = started.elapsed();
        assert!(
            second.is_some(),
            "client permit was not released within 2 s: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "final drain used a fresh idle window: {elapsed:?}"
        );
        drop(second);
        drop(first);
        server.shutdown().await;
    });
}

#[test]
fn m04_con04_split_head_and_large_early_payload() {
    runtime().block_on(async {
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        let (server, proxy) = start_proxy(&connect_config(echo.address.port())).await;
        let stream = tokio::net::TcpStream::connect(proxy)
            .await
            .expect("connect proxy");
        let (mut read, mut write) = stream.into_split();
        let target = echo.address.to_string();
        let first = format!("CONNECT {target} HTTP/1.1\r\nHo");
        let second = format!("st: {target}\r\n\r\n");
        let mut payload = b"GET http://looks-like-http/ HTTP/1.1\r\n\r\n\0\xff".to_vec();
        payload.extend((0..128 * 1024).map(|value| (value % 251) as u8));
        let payload_len = payload.len();
        let mut full = second.into_bytes();
        full.extend_from_slice(&payload);
        let writer = tokio::spawn(async move {
            write
                .write_all(first.as_bytes())
                .await
                .expect("write head part 1");
            tokio::time::sleep(Duration::from_millis(10)).await;
            write
                .write_all(&full)
                .await
                .expect("write head part 2 and payload");
        });

        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            read.read_exact(&mut byte).await.expect("read head byte");
            head.push(byte[0]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "unexpected CONNECT head: {:?}",
            String::from_utf8_lossy(&head)
        );
        let mut echoed = vec![0_u8; payload_len];
        read.read_exact(&mut echoed).await.expect("read early echo");
        assert_eq!(echoed, payload, "large early payload changed");
        writer.await.expect("join writer");
        assert_eq!(echo.accepts.load(Ordering::Acquire), 1);
        drop(read);
        server.shutdown().await;
    });
}
