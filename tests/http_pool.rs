//! M03 pool, fresh-DNS and egress tests.

mod common;

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use angara::config::Config;
use angara::http::HttpServer;
use angara::resolver::{ResolveError, ResolveFuture, Resolver};
use angara::transport::TcpDialer;
use common::m03::*;
use tokio::runtime::{Builder, Runtime};

fn runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build test runtime")
}

struct SpyResolver {
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
    calls: Arc<AtomicUsize>,
}

impl SpyResolver {
    fn new(answers: Vec<Vec<IpAddr>>, calls: Arc<AtomicUsize>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
            calls,
        })
    }
}

impl Resolver for SpyResolver {
    fn resolve<'a>(&'a self, _host: &'a str, _deadline: std::time::Instant) -> ResolveFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(ResolveError::Failed)
        })
    }
}

fn proxy_config() -> String {
    config("127.0.0.1:3128")
}

fn domain_request(port: u16, host: &str, path: &str) -> Vec<u8> {
    format!("GET http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").into_bytes()
}

#[test]
fn m03_pool01_reuses_origin_socket_until_exchange_end() {
    runtime().block_on(async {
        let origin =
            spawn_origin(|_, index| response("200 OK", &[], format!("origin-{index}").as_bytes()))
                .await
                .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        for expected in ["origin-0", "origin-1", "origin-2"] {
            client
                .send(&request("GET", origin.address, "/pool", &[], b""))
                .await
                .expect("send request");
            let response = client.read_response().await.expect("read response");
            assert_eq!(response.text(), expected);
        }
        assert_eq!(
            origin.accepts.load(Ordering::Acquire),
            1,
            "pool must reuse the origin socket"
        );
        server.shutdown().await;
    });
}

#[test]
fn m03_pool01_lease_returns_only_after_response_trailers() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| {
            chunked_response(
                "200 OK",
                &[("Trailer", "X-Checksum")],
                &[b"chunk"],
                &[("X-Checksum", "done")],
            )
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        for _ in 0..2 {
            client
                .send(&request(
                    "GET",
                    origin.address,
                    "/trailers",
                    &[("TE", "trailers")],
                    b"",
                ))
                .await
                .expect("send request");
            let response = client.read_response().await.expect("read response");
            assert_eq!(response.head.status, 200);
            assert_eq!(response.text(), "chunk");
            assert_eq!(response.trailers[0].0, "x-checksum");
        }
        assert_eq!(
            origin.accepts.load(Ordering::Acquire),
            1,
            "trailer completion must return the lease to the pool"
        );
        server.shutdown().await;
    });
}

#[test]
fn m03_pool01_zero_capacity_disables_retention() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let text = proxy_config()
            .replace("pool_max_idle = 4", "pool_max_idle = 0")
            .replace("pool_max_idle_per_key = 2", "pool_max_idle_per_key = 0");
        let (server, proxy) = start_proxy(&text).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        for _ in 0..2 {
            client
                .send(&request("GET", origin.address, "/no-pool", &[], b""))
                .await
                .expect("send request");
            assert_eq!(
                client
                    .read_response()
                    .await
                    .expect("read response")
                    .head
                    .status,
                200
            );
        }
        assert_eq!(origin.accepts.load(Ordering::Acquire), 2);
        server.shutdown().await;
    });
}

#[test]
fn m03_pool01_idle_timeout_evicts_socket() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let text =
            proxy_config().replace("pool_idle_timeout_ms = 2000", "pool_idle_timeout_ms = 100");
        let (server, proxy) = start_proxy(&text).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin.address, "/first", &[], b""))
            .await
            .expect("send first");
        assert_eq!(
            client
                .read_response()
                .await
                .expect("read first")
                .head
                .status,
            200
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        client
            .send(&request("GET", origin.address, "/second", &[], b""))
            .await
            .expect("send second");
        assert_eq!(
            client
                .read_response()
                .await
                .expect("read second")
                .head
                .status,
            200
        );
        assert_eq!(
            origin.accepts.load(Ordering::Acquire),
            2,
            "expired idle socket must not be reused"
        );
        server.shutdown().await;
    });
}

#[test]
fn m03_pool01_pool_key_isolates_hosts() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = SpyResolver::new(
            vec![
                vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
                vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            ],
            Arc::clone(&calls),
        );
        let config = Arc::new(Config::parse(&proxy_config()).expect("valid config"));
        let server =
            HttpServer::bind_ephemeral_with_components(config, resolver, Arc::new(TcpDialer))
                .await
                .expect("bind proxy");
        let proxy = server.addresses()[0].1;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        for host in ["a.test", "b.test"] {
            client
                .send(&domain_request(origin.address.port(), host, "/host"))
                .await
                .expect("send request");
            assert_eq!(
                client
                    .read_response()
                    .await
                    .expect("read response")
                    .head
                    .status,
                200,
                "{host}"
            );
        }
        assert_eq!(calls.load(Ordering::Acquire), 2);
        assert_eq!(
            origin.accepts.load(Ordering::Acquire),
            2,
            "different canonical hosts must not share one origin key"
        );
        server.shutdown().await;
    });
}

#[test]
fn m03_pol02_fresh_dns_is_required_even_when_pool_has_a_socket() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = SpyResolver::new(
            vec![
                vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
                vec![IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))],
            ],
            Arc::clone(&calls),
        );
        let config = Arc::new(Config::parse(&proxy_config()).expect("valid config"));
        let server =
            HttpServer::bind_ephemeral_with_components(config, resolver, Arc::new(TcpDialer))
                .await
                .expect("bind proxy");
        let proxy = server.addresses()[0].1;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        client
            .send(&domain_request(origin.address.port(), "fresh.test", "/one"))
            .await
            .expect("send first");
        let first = client.read_response().await.expect("read first");
        assert_eq!(first.head.status, 200);

        client
            .send(&domain_request(origin.address.port(), "fresh.test", "/two"))
            .await
            .expect("send second");
        let second = client.read_response().await.expect("read second");
        assert_eq!(
            second.head.status, 403,
            "new DNS answer must be rechecked before pool reuse"
        );
        assert_eq!(
            calls.load(Ordering::Acquire),
            2,
            "one fresh lookup per request"
        );
        assert_eq!(
            origin.accepts.load(Ordering::Acquire),
            1,
            "pool hit must not bypass the fresh DNS/IP policy"
        );
        server.shutdown().await;
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m03_net01_two_listeners_and_egress_bind_ips_are_preserved() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let text = r#"
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
bind = "127.0.0.2:3128"
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
id = "route-a"
listeners = ["via-a"]
egress_id = "via-a"

[[routing.rules]]
id = "route-b"
listeners = ["via-b"]
egress_id = "via-b"
"#;
        let config = Arc::new(Config::parse(text).expect("valid egress config"));
        let server = HttpServer::bind_ephemeral(config)
            .await
            .expect("bind proxy");
        let addresses = server.addresses().to_vec();
        for (index, (_, bind)) in addresses.iter().enumerate() {
            let mut client = RawClient::connect(*bind).await.expect("connect listener");
            client
                .send(&request("GET", origin.address, "/egress", &[], b""))
                .await
                .expect("send request");
            assert_eq!(
                client
                    .read_response()
                    .await
                    .expect("read response")
                    .head
                    .status,
                200
            );
            let requests = origin.requests.lock().unwrap().clone();
            let expected = if index == 0 { "127.0.0.1" } else { "127.0.0.2" };
            assert_eq!(
                requests[index].peer.ip().to_string(),
                expected,
                "listener {index} used the wrong egress source"
            );
        }
        server.shutdown().await;
    });
}
