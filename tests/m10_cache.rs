//! M10 bounded HTTP cache tests (CACHE-01).

mod common;
mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use angara::config::Config;
use angara::http::HttpServer;

use common::m03::{self, RawClient};

const DEFAULT_CACHE: &str = "enabled = true\nmax_bytes = 1048576\nmax_object_bytes = 262144\nmax_entries = 64\nmax_fills = 4";

fn cache_config(cache: &str, extra: &str) -> String {
    format!(
        "{}\n[cache]\n{cache}\n{extra}\n",
        m03::config("127.0.0.1:3128")
    )
}

async fn start(text: &str) -> (HttpServer, SocketAddr) {
    let config = Config::parse(text).expect("cache test config");
    let server = HttpServer::bind_ephemeral(Arc::new(config))
        .await
        .expect("bind proxy");
    let address = server.addresses()[0].1;
    (server, address)
}

async fn send_raw(proxy: SocketAddr, request: &[u8]) -> m03::RawResponse {
    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    client.send(request).await.expect("send request");
    client.read_response().await.expect("read response")
}

async fn get(
    proxy: SocketAddr,
    uri: &str,
    host: &str,
    headers: &[(&str, &str)],
) -> m03::RawResponse {
    let mut request = format!("GET {uri} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    send_raw(proxy, request.as_bytes()).await
}

async fn get_from(
    source: std::net::IpAddr,
    proxy: SocketAddr,
    uri: &str,
    host: &str,
    headers: &[(&str, &str)],
) -> m03::RawResponse {
    let socket = tokio::net::TcpSocket::new_v4().expect("client socket");
    socket
        .bind(SocketAddr::new(source, 0))
        .expect("bind client source");
    let stream = socket.connect(proxy).await.expect("connect proxy");
    let mut client = RawClient::from_stream(stream);
    let mut request = format!("GET {uri} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    client.send(request.as_bytes()).await.expect("send request");
    client.read_response().await.expect("read response")
}

fn not_modified(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut response = b"HTTP/1.1 304 Not Modified\r\n".to_vec();
    for (name, value) in headers {
        response.extend_from_slice(name.as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(value.as_bytes());
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"\r\n");
    response
}

async fn spawn_slow_get_origin(
    length: usize,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let address = listener.local_addr().expect("origin address");
    let requests = Arc::new(AtomicUsize::new(0));
    let task_requests = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let requests = Arc::clone(&task_requests);
            tokio::spawn(async move {
                let mut head = Vec::new();
                loop {
                    let mut byte = [0_u8; 1];
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                requests.fetch_add(1, Ordering::SeqCst);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: {length}\r\n\r\n"
                );
                if stream.write_all(header.as_bytes()).await.is_err() {
                    return;
                }
                let first = length.min(512);
                if stream.write_all(&vec![b'x'; first]).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = stream.write_all(&vec![b'x'; length - first]).await;
            });
        }
    });
    (address, requests, task)
}

#[tokio::test]
async fn m10_cache01_cold_then_warm_uses_one_origin_request() {
    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"cached-body")
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/file", origin.address);
    let host = origin.address.to_string();

    let first = get(proxy, &uri, &host, &[]).await;
    assert_eq!(first.head.status, 200);
    assert_eq!(first.body, b"cached-body");
    let second = get(proxy, &uri, &host, &[]).await;
    assert_eq!(second.head.status, 200);
    assert_eq!(second.body, b"cached-body");
    assert_eq!(origin.requests.lock().expect("requests").len(), 1);
    assert!(second.head.header("age").is_some());
    assert_eq!(server.control().metrics().cache_hit, 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache02_disabled_and_missing_section_fetch_twice() {
    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"body")
    })
    .await
    .expect("origin");
    let host = origin.address.to_string();
    let uri = format!("http://{}/file", origin.address);

    let (server, proxy) = start(&m03::config("127.0.0.1:3128")).await;
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"body");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"body");
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    server.shutdown().await;

    let disabled = cache_config("enabled = false", "");
    let (server, proxy) = start(&disabled).await;
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"body");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"body");
    assert_eq!(origin.requests.lock().expect("requests").len(), 4);
    assert_eq!(server.control().metrics().cache_hit, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache03_path_query_and_port_are_distinct() {
    let first = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"first")
    })
    .await
    .expect("first origin");
    let second = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"second")
    })
    .await
    .expect("second origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;

    for path in ["/file", "/file?a=1", "/file?a=2"] {
        let uri = format!("http://{}{path}", first.address);
        assert_eq!(
            get(proxy, &uri, &first.address.to_string(), &[]).await.body,
            b"first"
        );
    }
    for path in ["/file", "/file?a=1", "/file?a=2"] {
        let uri = format!("http://{}{path}", first.address);
        assert_eq!(
            get(proxy, &uri, &first.address.to_string(), &[]).await.body,
            b"first"
        );
    }
    assert_eq!(first.requests.lock().expect("requests").len(), 3);

    let uri = format!("http://{}/file", second.address);
    assert_eq!(
        get(proxy, &uri, &second.address.to_string(), &[])
            .await
            .body,
        b"second"
    );
    assert_eq!(first.requests.lock().expect("requests").len(), 3);
    assert_eq!(second.requests.lock().expect("requests").len(), 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache04_age_makes_entry_stale() {
    let origin = m03::spawn_origin(|_, _| {
        m03::response(
            "200 OK",
            &[("Cache-Control", "max-age=2"), ("Age", "2")],
            b"aged",
        )
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/aged", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"aged");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"aged");
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    let metrics = server.control().metrics();
    assert!(metrics.cache_miss >= 1);
    assert_eq!(metrics.cache_hit, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache05_s_maxage_is_used_before_max_age() {
    let origin = m03::spawn_origin(|_, _| {
        m03::response(
            "200 OK",
            &[("Cache-Control", "s-maxage=2, max-age=60"), ("Age", "2")],
            b"shared",
        )
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/shared", origin.address);
    let host = origin.address.to_string();

    get(proxy, &uri, &host, &[]).await;
    get(proxy, &uri, &host, &[]).await;
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache06_expires_relative_to_date_and_max_age_priority() {
    let future = m03::spawn_origin(|_, _| {
        let now = SystemTime::now();
        let date = httpdate::fmt_http_date(now);
        let expires = httpdate::fmt_http_date(now + Duration::from_secs(60));
        m03::response(
            "200 OK",
            &[("Date", &date), ("Expires", &expires)],
            b"expires",
        )
    })
    .await
    .expect("future origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/expires", future.address);
    let host = future.address.to_string();
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"expires");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"expires");
    assert_eq!(future.requests.lock().expect("requests").len(), 1);
    server.shutdown().await;

    let overridden = m03::spawn_origin(|_, _| {
        let now = SystemTime::now();
        let date = httpdate::fmt_http_date(now);
        let expires = httpdate::fmt_http_date(now + Duration::from_secs(60));
        m03::response(
            "200 OK",
            &[
                ("Date", &date),
                ("Expires", &expires),
                ("Cache-Control", "max-age=0"),
            ],
            b"not-cached",
        )
    })
    .await
    .expect("overridden origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/expires", overridden.address);
    let host = overridden.address.to_string();
    get(proxy, &uri, &host, &[]).await;
    get(proxy, &uri, &host, &[]).await;
    assert_eq!(overridden.requests.lock().expect("requests").len(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache07_vary_accept_encoding_keeps_variants_apart() {
    let origin = m03::spawn_origin(|request, _| {
        let body = match request.header("accept-encoding") {
            Some("gzip") => b"gzip-body".as_slice(),
            Some("identity") => b"identity-body".as_slice(),
            _ => b"absent-body".as_slice(),
        };
        m03::response(
            "200 OK",
            &[("Cache-Control", "max-age=60"), ("Vary", "Accept-Encoding")],
            body,
        )
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/vary", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"absent-body");
    assert_eq!(
        get(proxy, &uri, &host, &[("Accept-Encoding", "gzip")])
            .await
            .body,
        b"gzip-body"
    );
    assert_eq!(
        get(proxy, &uri, &host, &[("Accept-Encoding", "identity")])
            .await
            .body,
        b"identity-body"
    );
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"absent-body");
    assert_eq!(
        get(proxy, &uri, &host, &[("Accept-Encoding", "gzip")])
            .await
            .body,
        b"gzip-body"
    );
    assert_eq!(
        get(proxy, &uri, &host, &[("Accept-Encoding", "identity")])
            .await
            .body,
        b"identity-body"
    );
    assert_eq!(origin.requests.lock().expect("requests").len(), 3);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache08_vary_star_and_unsupported_fields_are_not_reused() {
    let origin = m03::spawn_origin(|request, _| {
        let vary = if request.target.contains("star") {
            "*"
        } else {
            "Cookie"
        };
        m03::response(
            "200 OK",
            &[("Cache-Control", "max-age=60"), ("Vary", vary)],
            b"vary",
        )
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let host = origin.address.to_string();

    for path in ["/star", "/cookie"] {
        let uri = format!("http://{}{path}", origin.address);
        get(proxy, &uri, &host, &[]).await;
        get(proxy, &uri, &host, &[]).await;
    }
    assert_eq!(origin.requests.lock().expect("requests").len(), 4);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache09_etag_revalidation_returns_full_body_after_304() {
    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let counter = Arc::clone(&counter);
        move |_, _| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => m03::response(
                "200 OK",
                &[("ETag", "\"v1\""), ("Cache-Control", "max-age=0")],
                b"etag-body",
            ),
            1 => not_modified(&[("ETag", "\"v1\""), ("Cache-Control", "max-age=60")]),
            _ => m03::response("500 Internal Server Error", &[], b"unexpected"),
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/etag", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"etag-body");
    let second = get(proxy, &uri, &host, &[]).await;
    assert_eq!(second.head.status, 200);
    assert_eq!(second.body, b"etag-body");
    let third = get(proxy, &uri, &host, &[]).await;
    assert_eq!(third.body, b"etag-body");
    {
        let requests = origin.requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].header("if-none-match"), Some("\"v1\""));
    }
    let metrics = server.control().metrics();
    assert!(metrics.cache_revalidation >= 1);
    assert!(metrics.cache_hit >= 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache10_last_modified_revalidation_uses_if_modified_since() {
    const MODIFIED: &str = "Wed, 25 Nov 2026 10:00:00 GMT";
    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let counter = Arc::clone(&counter);
        move |_, _| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => m03::response(
                "200 OK",
                &[("Last-Modified", MODIFIED), ("Cache-Control", "max-age=0")],
                b"lm-body",
            ),
            1 => not_modified(&[("Last-Modified", MODIFIED), ("Cache-Control", "max-age=60")]),
            _ => m03::response("500 Internal Server Error", &[], b"unexpected"),
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/last-modified", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"lm-body");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"lm-body");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"lm-body");
    {
        let requests = origin.requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].header("if-modified-since"), Some(MODIFIED));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache11_200_after_revalidation_replaces_entry() {
    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let counter = Arc::clone(&counter);
        move |_, _| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => m03::response(
                "200 OK",
                &[("ETag", "\"v1\""), ("Cache-Control", "max-age=0")],
                b"old-body",
            ),
            1 => m03::response(
                "200 OK",
                &[("ETag", "\"v2\""), ("Cache-Control", "max-age=60")],
                b"new-body",
            ),
            _ => m03::response("500 Internal Server Error", &[], b"unexpected"),
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/replace", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"old-body");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"new-body");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"new-body");
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache12_revalidation_error_is_not_answered_with_stale_body() {
    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let counter = Arc::clone(&counter);
        move |_, _| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => m03::response(
                "200 OK",
                &[("ETag", "\"v1\""), ("Cache-Control", "max-age=0")],
                b"old-body",
            ),
            _ => m03::response("503 Service Unavailable", &[], b"upstream-down"),
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/error", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"old-body");
    let second = get(proxy, &uri, &host, &[]).await;
    assert_eq!(second.head.status, 503);
    assert_eq!(second.body, b"upstream-down");
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache13_bad_304_retries_one_unconditional_get() {
    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let counter = Arc::clone(&counter);
        move |_, _| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => m03::response(
                "200 OK",
                &[("ETag", "\"v1\""), ("Cache-Control", "max-age=0")],
                b"old-body",
            ),
            1 => not_modified(&[("ETag", "\"v1\""), ("Cache-Control", "no-store")]),
            _ => m03::response(
                "200 OK",
                &[("ETag", "\"v2\""), ("Cache-Control", "max-age=60")],
                b"new-body",
            ),
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/bad-304", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"old-body");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"new-body");
    {
        let requests = origin.requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].header("if-none-match"), Some("\"v1\""));
        assert_eq!(requests[2].header("if-none-match"), None);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache14_client_conditions_and_range_bypass_the_cache() {
    let origin = m03::spawn_origin(|request, _| {
        if request.header("range").is_some() {
            return m03::response("206 Partial Content", &[], b"part");
        }
        if request.header("if-none-match").is_some() {
            return m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"conditional");
        }
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"warm")
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/conditions", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"warm");
    assert_eq!(
        get(proxy, &uri, &host, &[("If-None-Match", "\"client\"")])
            .await
            .body,
        b"conditional"
    );
    let ranged = get(proxy, &uri, &host, &[("Range", "bytes=0-3")]).await;
    assert_eq!(ranged.head.status, 206);
    assert_eq!(ranged.body, b"part");
    {
        let requests = origin.requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].header("if-none-match"), Some("\"client\""));
        assert_eq!(requests[2].header("range"), Some("bytes=0-3"));
    }
    let metrics = server.control().metrics();
    assert!(metrics.cache_bypass >= 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache15_authorization_cookie_and_set_cookie_are_not_stored() {
    let origin = m03::spawn_origin(|request, _| {
        let headers: &[(&str, &str)] = if request.target.contains("set-cookie") {
            &[("Cache-Control", "max-age=60"), ("Set-Cookie", "sid=1")]
        } else {
            &[("Cache-Control", "max-age=60")]
        };
        m03::response("200 OK", headers, b"private")
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let host = origin.address.to_string();

    for path in ["/cookie", "/authorization"] {
        let uri = format!("http://{}{path}", origin.address);
        let header = if path == "/cookie" {
            ("Cookie", "a=1")
        } else {
            ("Authorization", "Bearer secret")
        };
        for _ in 0..2 {
            assert_eq!(get(proxy, &uri, &host, &[header]).await.body, b"private");
        }
    }
    let uri = format!("http://{}/set-cookie", origin.address);
    for _ in 0..2 {
        assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"private");
    }
    assert_eq!(origin.requests.lock().expect("requests").len(), 6);
    assert_eq!(server.control().metrics().cache_hit, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache16_users_are_isolated() {
    use common::TempDir;
    use common::m05;

    let dir = TempDir::new("m10-cache-users");
    let alice = m05::hash("alice-pass");
    let bob = m05::hash("bob-pass");
    m05::write_users(&dir, &[("alice", &alice, false), ("bob", &bob, false)]);
    let auth = m05::AuthConfig {
        extra: format!("[cache]\n{DEFAULT_CACHE}"),
        ..m05::AuthConfig::default()
    };
    let path = auth.write(&dir);
    let (server, addresses) = m05::start(&path).await;
    let proxy = m05::address(&addresses, "proxy");

    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let counter = Arc::clone(&counter);
        move |_, _| {
            let index = counter.fetch_add(1, Ordering::SeqCst);
            let body = format!("body-{index}");
            m03::response(
                "200 OK",
                &[("Cache-Control", "max-age=60")],
                body.as_bytes(),
            )
        }
    })
    .await
    .expect("origin");
    let uri = format!("http://{}/private", origin.address);
    let host = origin.address.to_string();

    let auth_get = |user: &str, password: &str| {
        let value = m05::authorization(user, password);
        let request =
            format!("GET {uri} HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: {value}\r\n\r\n");
        request
    };
    assert_eq!(
        send_raw(proxy, auth_get("alice", "alice-pass").as_bytes())
            .await
            .body,
        b"body-0"
    );
    assert_eq!(
        send_raw(proxy, auth_get("bob", "bob-pass").as_bytes())
            .await
            .body,
        b"body-1"
    );
    assert_eq!(
        send_raw(proxy, auth_get("alice", "alice-pass").as_bytes())
            .await
            .body,
        b"body-0"
    );
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache17_listeners_are_isolated() {
    let listeners = r#"
[[listeners]]
id = "a"
bind = "127.0.0.1:3128"
transport = "http"

[[listeners]]
id = "b"
bind = "127.0.0.1:3129"
transport = "http"
"#;
    let text = format!(
        "{}\n[cache]\n{DEFAULT_CACHE}\n",
        m03::config_with_listeners(listeners)
    );
    let config = Config::parse(&text).expect("two-listener cache config");
    let server = HttpServer::bind_ephemeral(Arc::new(config))
        .await
        .expect("bind proxy");
    let addresses = server.addresses().to_vec();
    let first = addresses
        .iter()
        .find(|(id, _)| id == "a")
        .expect("listener a")
        .1;
    let second = addresses
        .iter()
        .find(|(id, _)| id == "b")
        .expect("listener b")
        .1;

    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"listener")
    })
    .await
    .expect("origin");
    let uri = format!("http://{}/listener", origin.address);
    let host = origin.address.to_string();

    get(first, &uri, &host, &[]).await;
    get(second, &uri, &host, &[]).await;
    get(first, &uri, &host, &[]).await;
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    assert_eq!(server.control().metrics().cache_hit, 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache18_new_generation_does_not_read_old_entries() {
    use angara::control::ReloadOutcome;
    use common::TempDir;

    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"generation")
    })
    .await
    .expect("origin");
    let dir = TempDir::new("m10-cache-generation");
    let text = cache_config(DEFAULT_CACHE, "");
    let path = dir.write("proxy.toml", &text);
    let config = Arc::new(Config::load(&path).expect("initial config"));
    let server = HttpServer::bind_ephemeral_with_path(config, path.clone())
        .await
        .expect("bind proxy");
    let proxy = server.addresses()[0].1;
    let uri = format!("http://{}/generation", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"generation");
    assert_eq!(origin.requests.lock().expect("requests").len(), 1);

    std::fs::write(&path, &text).expect("rewrite config");
    let outcome = server.control().reload(1).await;
    assert!(
        matches!(outcome, ReloadOutcome::Applied { generation: 2 }),
        "unexpected reload outcome: {outcome:?}"
    );

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"generation");
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    assert_eq!(server.control().metrics().cache_hit, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache19_acl_deny_after_warm_cache_returns_forbidden() {
    use angara::control::ReloadOutcome;
    use common::TempDir;

    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"restricted")
    })
    .await
    .expect("origin");
    let dir = TempDir::new("m10-cache-acl");
    let initial = cache_config(DEFAULT_CACHE, "");
    let path = dir.write("proxy.toml", &initial);
    let config = Arc::new(Config::load(&path).expect("initial config"));
    let server = HttpServer::bind_ephemeral_with_path(config, path.clone())
        .await
        .expect("bind proxy");
    let proxy = server.addresses()[0].1;
    let uri = format!("http://{}/restricted", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"restricted");
    assert_eq!(origin.requests.lock().expect("requests").len(), 1);

    let deny = r#"[[access.rules]]
id = "deny-get"
action = "deny"
methods = ["GET"]

[[access.rules]]
id = "allow"
action = "allow""#;
    let changed = initial.replace("[[access.rules]]\nid = \"allow\"\naction = \"allow\"", deny);
    std::fs::write(&path, &changed).expect("rewrite config");
    assert!(matches!(
        server.control().reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    ));

    let forbidden = get(proxy, &uri, &host, &[]).await;
    assert_eq!(forbidden.head.status, 403);
    assert_eq!(origin.requests.lock().expect("requests").len(), 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache20_parent_requests_always_reach_the_parent() {
    use common::m09::{self, ParentMode};

    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"via-parent")
    })
    .await
    .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = format!(
        "{}\n[[parents]]\nid = \"parent\"\nendpoint = \"{}\"\ntransport = \"http\"\n\n[routing]\ndefault_egress = \"system\"\ndefault_parent = \"parent\"\n\n[cache]\n{DEFAULT_CACHE}\n",
        m03::config("127.0.0.1:3128"),
        parent.address
    );
    let (server, proxy) = start(&text).await;
    let uri = format!("http://{}/parent", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"via-parent");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"via-parent");
    assert_eq!(parent.request_count(), 2);
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    let metrics = server.control().metrics();
    assert_eq!(metrics.cache_hit, 0);
    assert!(metrics.cache_bypass >= 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache21_connect_is_never_cached() {
    use common::m04;

    let echo = m04::spawn_echo_origin(None).await.expect("echo");
    let text = cache_config(
        DEFAULT_CACHE,
        &format!("[connect]\nallowed_ports = [{}]", echo.address.port()),
    );
    let (server, proxy) = start(&text).await;

    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        echo.address, echo.address
    );
    client.send(request.as_bytes()).await.expect("send CONNECT");
    assert_eq!(client.read_head().await.expect("head").status, 200);
    client.send(b"tunnel-payload").await.expect("send payload");
    assert_eq!(
        client
            .read_exact_bytes(b"tunnel-payload".len())
            .await
            .expect("echo"),
        b"tunnel-payload"
    );
    let _ = client.shutdown_write().await;

    let metrics = server.control().metrics();
    assert_eq!(metrics.cache_entries, 0);
    assert_eq!(metrics.cache_bytes, 0);
    assert_eq!(metrics.cache_hit, 0);
    assert_eq!(metrics.cache_miss, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache22_small_limits_evict_and_stay_bounded() {
    let cache = "enabled = true\nmax_bytes = 65536\nmax_object_bytes = 16384\nmax_entries = 2\nmax_fills = 2";
    let body = vec![b'x'; 12 * 1024];
    let origin_body = body.clone();
    let origin = m03::spawn_origin(move |_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], &origin_body)
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(cache, "")).await;
    let host = origin.address.to_string();

    for path in ["/a", "/b", "/c", "/a"] {
        let uri = format!("http://{}{path}", origin.address);
        let response = get(proxy, &uri, &host, &[]).await;
        assert_eq!(response.head.status, 200);
        assert_eq!(response.body.len(), body.len());
    }
    assert_eq!(origin.requests.lock().expect("requests").len(), 4);
    let metrics = server.control().metrics();
    assert!(metrics.cache_entries <= 2, "{metrics:?}");
    assert!(metrics.cache_bytes <= 65536, "{metrics:?}");
    assert!(metrics.cache_eviction > 0, "{metrics:?}");
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache23_too_large_object_streams_but_is_not_published() {
    let cache = "enabled = true\nmax_bytes = 1048576\nmax_object_bytes = 1024\nmax_entries = 8\nmax_fills = 2";
    let body = vec![b'y'; 4096];
    let origin_body = body.clone();
    let origin = m03::spawn_origin(move |_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], &origin_body)
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(cache, "")).await;
    let uri = format!("http://{}/large", origin.address);
    let host = origin.address.to_string();

    for _ in 0..2 {
        let response = get(proxy, &uri, &host, &[]).await;
        assert_eq!(response.body.len(), body.len());
    }
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    assert!(server.control().metrics().cache_fill_refusals > 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache24_trailers_prevent_storage() {
    let origin = m03::spawn_origin(|_, _| {
        m03::chunked_response(
            "200 OK",
            &[("Cache-Control", "max-age=60")],
            &[b"part1", b"part2"],
            &[("X-Trailer", "present")],
        )
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/trailers", origin.address);
    let host = origin.address.to_string();

    let first = get(proxy, &uri, &host, &[]).await;
    assert_eq!(first.body, b"part1part2");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"part1part2");
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache25_only_if_cached_returns_504_cold_and_body_warm() {
    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"warm")
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/only", origin.address);
    let host = origin.address.to_string();

    let cold = get(proxy, &uri, &host, &[("Cache-Control", "only-if-cached")]).await;
    assert_eq!(cold.head.status, 504);
    assert_eq!(origin.requests.lock().expect("requests").len(), 0);

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"warm");
    let warm = get(proxy, &uri, &host, &[("Cache-Control", "only-if-cached")]).await;
    assert_eq!(warm.head.status, 200);
    assert_eq!(warm.body, b"warm");
    assert_eq!(origin.requests.lock().expect("requests").len(), 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache26_request_no_cache_and_min_fresh_force_upstream() {
    let origin = m03::spawn_origin(|request, _| {
        if request.target.contains("min-fresh") {
            m03::response(
                "200 OK",
                &[("Cache-Control", "max-age=5"), ("Age", "4")],
                b"min-fresh",
            )
        } else {
            m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"no-cache")
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let host = origin.address.to_string();

    let no_cache_uri = format!("http://{}/no-cache", origin.address);
    assert_eq!(
        get(proxy, &no_cache_uri, &host, &[]).await.body,
        b"no-cache"
    );
    assert_eq!(
        get(
            proxy,
            &no_cache_uri,
            &host,
            &[("Cache-Control", "no-cache")]
        )
        .await
        .body,
        b"no-cache"
    );

    let min_fresh_uri = format!("http://{}/min-fresh", origin.address);
    assert_eq!(
        get(proxy, &min_fresh_uri, &host, &[]).await.body,
        b"min-fresh"
    );
    assert_eq!(
        get(
            proxy,
            &min_fresh_uri,
            &host,
            &[("Cache-Control", "min-fresh=4")]
        )
        .await
        .body,
        b"min-fresh"
    );
    assert_eq!(origin.requests.lock().expect("requests").len(), 4);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache27_unsafe_response_invalidates_stored_uri() {
    let changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let changed = Arc::clone(&changed);
        let counter = Arc::clone(&counter);
        move |request, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            if request.method == "POST" {
                changed.store(true, Ordering::SeqCst);
                return m03::response("200 OK", &[], b"posted");
            }
            let body = if changed.load(Ordering::SeqCst) {
                b"new".as_slice()
            } else {
                b"old".as_slice()
            };
            m03::response("200 OK", &[("Cache-Control", "max-age=60")], body)
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/resource", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"old");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"old");
    assert_eq!(
        send_raw(
            proxy,
            &m03::request("POST", origin.address, "/resource", &[], b"x")
        )
        .await
        .body,
        b"posted"
    );
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"new");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"new");
    assert_eq!(counter.load(Ordering::SeqCst), 3);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache28_verified_endpoint_is_part_of_the_key() {
    use std::net::IpAddr;

    use angara::transport::TcpDialer;
    use support::ScriptedResolver;

    let first = m03::spawn_origin_at("127.0.0.1:0".parse().expect("first bind"), |_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"one")
    })
    .await
    .expect("first origin");
    let port = first.address.port();
    let second = m03::spawn_origin_at(
        format!("127.0.0.2:{port}").parse().expect("second bind"),
        |_, _| m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"two"),
    )
    .await
    .expect("second origin");

    let resolver = Arc::new(ScriptedResolver::new(vec![
        Ok(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]),
        Ok(vec![IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2))]),
    ]));
    let config = Arc::new(Config::parse(&cache_config(DEFAULT_CACHE, "")).expect("config"));
    let server = HttpServer::bind_ephemeral_with_components(
        config,
        Arc::clone(&resolver) as Arc<dyn angara::resolver::Resolver>,
        Arc::new(TcpDialer),
    )
    .await
    .expect("bind proxy");
    let proxy = server.addresses()[0].1;
    let uri = format!("http://cache.test:{port}/endpoint");
    let host = format!("cache.test:{port}");

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"one");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"two");
    assert_eq!(first.requests.lock().expect("requests").len(), 1);
    assert_eq!(second.requests.lock().expect("requests").len(), 1);
    assert_eq!(server.control().metrics().cache_hit, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache29_https_listener_uses_the_same_cache() {
    use common::TempDir;
    use common::m06;

    let dir = TempDir::new("m10-cache-tls");
    m06::generate_pki(dir.path());
    let listener = format!(
        "transport = \"https\"\n[listeners.tls]\ncert_chain_file = \"{}\"\nprivate_key_file = \"{}\"",
        dir.path().join("proxy_ip_chain.pem").display(),
        dir.path().join("proxy_ip_key.pem").display()
    );
    let text = format!(
        "{}\n[cache]\n{DEFAULT_CACHE}\n",
        m03::config("127.0.0.1:3128").replace("transport = \"http\"", &listener)
    );
    let config =
        Arc::new(Config::parse_with_base_dir(&text, dir.path()).expect("TLS cache config"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind TLS proxy");
    let proxy = server.addresses()[0].1;
    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"tls-cache")
    })
    .await
    .expect("origin");
    let host = origin.address.to_string();
    let uri = format!("http://{}/tls", origin.address);

    let mut client = m06::connect_tls(
        proxy,
        "127.0.0.1",
        m06::client_config(&dir.path().join("proxy_ca.pem")),
    )
    .await
    .expect("TLS client");
    let request = format!("GET {uri} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    client
        .send(request.as_bytes())
        .await
        .expect("first request");
    assert_eq!(
        client.read_response().await.expect("first response").body,
        b"tls-cache"
    );
    client
        .send(request.as_bytes())
        .await
        .expect("second request");
    assert_eq!(
        client.read_response().await.expect("second response").body,
        b"tls-cache"
    );
    assert_eq!(origin.requests.lock().expect("requests").len(), 1);
    assert_eq!(server.control().metrics().cache_hit, 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache30_logs_and_metrics_do_not_contain_request_data() {
    use angara::config::LogLevel;
    use angara::logging::Logger;

    let origin = m03::spawn_origin(|_, _| {
        m03::response(
            "200 OK",
            &[("Cache-Control", "max-age=60")],
            b"private-body",
        )
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let telemetry = server.telemetry();
    let (logger, receiver) = Logger::channel(64, LogLevel::Info, telemetry);
    server.set_logger(logger);
    let uri = format!("http://{}/secret?token=top-secret", origin.address);
    let host = origin.address.to_string();

    get(proxy, &uri, &host, &[]).await;
    get(proxy, &uri, &host, &[]).await;
    for _ in 0..2 {
        let record = next_event(&receiver, "request_finished");
        let text = serde_json::to_string(&record).expect("JSON");
        for secret in ["secret", "token", "top-secret", "private-body", "127.0.0.1"] {
            assert!(
                !text.contains(secret),
                "log record contains {secret}: {text}"
            );
        }
    }
    let metrics = serde_json::to_string(&server.control().metrics()).expect("metrics JSON");
    for secret in ["secret", "token", "top-secret", "private-body"] {
        assert!(!metrics.contains(secret), "metrics contain {secret}");
    }
    server.shutdown().await;
}

fn next_event(receiver: &std::sync::mpsc::Receiver<String>, event: &str) -> serde_json::Value {
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
async fn m10_cache31_truncated_upstream_body_is_not_published() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let origin_address = listener.local_addr().expect("origin address");
    let connections = Arc::new(AtomicUsize::new(0));
    let task_connections = Arc::clone(&connections);
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("first accept");
        task_connections.fetch_add(1, Ordering::SeqCst);
        read_head(&mut stream).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: 4096\r\n\r\npartial",
            )
            .await;
        drop(stream);

        let (mut stream, _) = listener.accept().await.expect("second accept");
        task_connections.fetch_add(1, Ordering::SeqCst);
        read_head(&mut stream).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: 4\r\n\r\nfull",
            )
            .await;
    });
    async fn read_head(stream: &mut tokio::net::TcpStream) {
        let mut buffer = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                return;
            }
            buffer.push(byte[0]);
            if buffer.ends_with(b"\r\n\r\n") {
                return;
            }
        }
    }

    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{origin_address}/truncated");
    let host = origin_address.to_string();
    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let request = format!("GET {uri} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    client.send(request.as_bytes()).await.expect("send request");
    assert!(
        client.read_response().await.is_err(),
        "truncated body unexpectedly parsed as complete"
    );
    drop(client);

    let second = get(proxy, &uri, &host, &[]).await;
    assert_eq!(second.head.status, 200);
    assert_eq!(second.body, b"full");
    assert_eq!(connections.load(Ordering::SeqCst), 2);
    task.await.expect("origin task");
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m10_cache32_twenty_clients_share_a_warm_entry() {
    let origin = m03::spawn_origin(|_, _| {
        m03::response(
            "200 OK",
            &[("Cache-Control", "max-age=60")],
            &vec![b'z'; 64 * 1024],
        )
    })
    .await
    .expect("origin");
    let text = cache_config(DEFAULT_CACHE, "")
        .replace("max_client_connections = 16", "max_client_connections = 32");
    let (server, proxy) = start(&text).await;
    let uri = format!("http://{}/shared", origin.address);
    let host = origin.address.to_string();
    assert_eq!(get(proxy, &uri, &host, &[]).await.body.len(), 64 * 1024);

    let mut tasks = Vec::new();
    for _ in 0..20 {
        let uri = uri.clone();
        let host = host.clone();
        tasks.push(tokio::spawn(async move {
            let response = get(proxy, &uri, &host, &[]).await;
            (response.head.status, response.body.len())
        }));
    }
    for task in tasks {
        let (status, length) = task.await.expect("client task");
        assert_eq!(status, 200);
        assert_eq!(length, 64 * 1024);
    }
    assert_eq!(origin.requests.lock().expect("requests").len(), 1);
    let metrics = server.control().metrics();
    assert!(metrics.cache_hit >= 20, "{metrics:?}");
    assert_eq!(metrics.cache_entries, 1);
    assert!(metrics.cache_bytes <= 1048576, "{metrics:?}");
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache33_unsafe_location_invalidates_same_origin_target() {
    let changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let origin = m03::spawn_origin({
        let changed = Arc::clone(&changed);
        move |request, _| {
            if request.method == "POST" {
                changed.store(true, Ordering::SeqCst);
                return m03::response("200 OK", &[("Location", "/target")], b"posted");
            }
            let body = if changed.load(Ordering::SeqCst) {
                b"new-target".as_slice()
            } else {
                b"old-target".as_slice()
            };
            m03::response("200 OK", &[("Cache-Control", "max-age=60")], body)
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let target = format!("http://{}/target", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &target, &host, &[]).await.body, b"old-target");
    assert_eq!(get(proxy, &target, &host, &[]).await.body, b"old-target");
    assert_eq!(
        send_raw(
            proxy,
            &m03::request("POST", origin.address, "/source", &[], b"x")
        )
        .await
        .body,
        b"posted"
    );
    assert_eq!(get(proxy, &target, &host, &[]).await.body, b"new-target");
    assert_eq!(get(proxy, &target, &host, &[]).await.body, b"new-target");
    assert_eq!(origin.requests.lock().expect("requests").len(), 3);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache34_weak_etag_revalidation_is_a_match() {
    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let counter = Arc::clone(&counter);
        move |_, _| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => m03::response(
                "200 OK",
                &[("ETag", "\"v1\""), ("Cache-Control", "max-age=0")],
                b"weak-body",
            ),
            1 => not_modified(&[("ETag", "W/\"v1\""), ("Cache-Control", "max-age=60")]),
            _ => m03::response("500 Internal Server Error", &[], b"unexpected"),
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/weak-etag", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"weak-body");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"weak-body");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"weak-body");
    {
        let requests = origin.requests.lock().expect("requests");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].header("if-none-match"), Some("\"v1\""));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache35_other_etag_revalidation_does_one_unconditional_get() {
    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let counter = Arc::clone(&counter);
        move |_, _| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => m03::response(
                "200 OK",
                &[("ETag", "\"v1\""), ("Cache-Control", "max-age=0")],
                b"old-etag",
            ),
            1 => not_modified(&[("ETag", "\"v2\""), ("Cache-Control", "max-age=60")]),
            _ => m03::response(
                "200 OK",
                &[("ETag", "\"v2\""), ("Cache-Control", "max-age=60")],
                b"new-etag",
            ),
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/other-etag", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"old-etag");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"new-etag");
    {
        let requests = origin.requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].header("if-none-match"), Some("\"v1\""));
        assert_eq!(requests[2].header("if-none-match"), None);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache36_multiline_cache_control_in_304_is_merged() {
    let counter = Arc::new(AtomicUsize::new(0));
    let origin = m03::spawn_origin({
        let counter = Arc::clone(&counter);
        move |_, _| match counter.fetch_add(1, Ordering::SeqCst) {
            0 => m03::response(
                "200 OK",
                &[("ETag", "\"v1\""), ("Cache-Control", "max-age=0")],
                b"old-multiline",
            ),
            1 => not_modified(&[
                ("ETag", "\"v1\""),
                ("Cache-Control", "max-age=60"),
                ("Cache-Control", "no-store"),
            ]),
            _ => m03::response(
                "200 OK",
                &[("ETag", "\"v2\""), ("Cache-Control", "max-age=60")],
                b"new-multiline",
            ),
        }
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/multiline", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"old-multiline");
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"new-multiline");
    assert_eq!(origin.requests.lock().expect("requests").len(), 3);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache37_only_if_cached_stale_returns_504() {
    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=0")], b"stale")
    })
    .await
    .expect("origin");
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{}/stale-only", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"stale");
    let response = get(proxy, &uri, &host, &[("Cache-Control", "only-if-cached")]).await;
    assert_eq!(response.head.status, 504);
    assert_eq!(origin.requests.lock().expect("requests").len(), 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache38_egress_isolation() {
    use std::net::{IpAddr, Ipv4Addr};

    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"egress")
    })
    .await
    .expect("origin");
    let text = format!(
        "{}\n[[egress]]\nid = \"a\"\nmode = \"system\"\n\n[[egress]]\nid = \"b\"\nmode = \"system\"\n\n[routing]\ndefault_egress = \"a\"\n\n[[routing.rules]]\nid = \"by-source\"\negress_id = \"b\"\nsources = [\"127.0.0.2/32\"]\n\n[cache]\n{DEFAULT_CACHE}\n",
        m03::config("127.0.0.1:3128")
    );
    let (server, proxy) = start(&text).await;
    let uri = format!("http://{}/egress", origin.address);
    let host = origin.address.to_string();
    let first = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let second = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

    assert_eq!(
        get_from(first, proxy, &uri, &host, &[]).await.body,
        b"egress"
    );
    assert_eq!(
        get_from(second, proxy, &uri, &host, &[]).await.body,
        b"egress"
    );
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    assert_eq!(
        get_from(second, proxy, &uri, &host, &[]).await.body,
        b"egress"
    );
    assert_eq!(origin.requests.lock().expect("requests").len(), 2);
    assert_eq!(server.control().metrics().cache_hit, 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache39_revalidation_connection_failure_is_proxy_error() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let origin_address = listener.local_addr().expect("origin address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("origin accept");
        let mut head = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                return;
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nCache-Control: max-age=0\r\nContent-Length: 8\r\nConnection: close\r\n\r\nold-body",
            )
            .await;
    });

    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{origin_address}/revalidation-fail");
    let host = origin_address.to_string();
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"old-body");
    task.await.expect("origin task");

    let second = get(proxy, &uri, &host, &[]).await;
    assert!(
        second.head.status == 502 || second.head.status == 504,
        "unexpected status {}",
        second.head.status
    );
    assert_ne!(second.body, b"old-body");
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache47_revalidation_timeout_is_proxy_error() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let origin_address = listener.local_addr().expect("origin address");
    let task = tokio::spawn(async move {
        for request in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("origin accept");
            let mut head = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                    return;
                }
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            if request == 0 {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nCache-Control: max-age=0\r\nContent-Length: 8\r\nConnection: close\r\n\r\nold-body",
                    )
                    .await;
            } else {
                // Keep the connection open beyond the test deadline. A
                // regression that removes the revalidation timeout would
                // wait here and then see an EOF only when the test aborts.
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });

    let text = cache_config(DEFAULT_CACHE, "").replace(
        "response_header_timeout_ms = 5000",
        "response_header_timeout_ms = 500",
    );
    let (server, proxy) = start(&text).await;
    let uri = format!("http://{origin_address}/revalidation-timeout");
    let host = origin_address.to_string();
    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"old-body");

    let started = tokio::time::Instant::now();
    let second = get(proxy, &uri, &host, &[]).await;
    let elapsed = started.elapsed();
    assert_eq!(
        second.head.status, 504,
        "revalidation timeout must map to 504, got {} after {elapsed:?}",
        second.head.status
    );
    assert!(
        elapsed < std::time::Duration::from_millis(1_500),
        "revalidation waited for the origin instead of the 500 ms timeout: {elapsed:?}"
    );
    assert_ne!(second.body, b"old-body");
    task.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache40_parent_failure_after_success_is_not_cached() {
    use common::m09::{self, ParentMode};

    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"parent-ok")
    })
    .await
    .expect("origin");
    let parent = m09::spawn_parent(ParentMode::Forward)
        .await
        .expect("parent");
    let text = format!(
        "{}\n[[parents]]\nid = \"parent\"\nendpoint = \"{}\"\ntransport = \"http\"\n\n[routing]\ndefault_egress = \"system\"\ndefault_parent = \"parent\"\n\n[cache]\n{DEFAULT_CACHE}\n",
        m03::config("127.0.0.1:3128"),
        parent.address
    );
    let (server, proxy) = start(&text).await;
    let uri = format!("http://{}/parent-fail", origin.address);
    let host = origin.address.to_string();

    assert_eq!(get(proxy, &uri, &host, &[]).await.body, b"parent-ok");
    parent.set_mode(ParentMode::Abort);
    let second = get(proxy, &uri, &host, &[]).await;
    assert_eq!(second.head.status, 502);
    assert_eq!(origin.requests.lock().expect("requests").len(), 1);
    assert_eq!(parent.request_count(), 2);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m10_cache43_twenty_clients_small_budget_stay_bounded() {
    const BODY_LEN: usize = 12 * 1024;
    let body = vec![b'b'; BODY_LEN];
    let origin_body = body.clone();
    let origin = m03::spawn_origin(move |_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], &origin_body)
    })
    .await
    .expect("origin");
    let cache = "enabled = true\nmax_bytes = 65536\nmax_object_bytes = 16384\nmax_entries = 4\nmax_fills = 8";
    let text = cache_config(cache, "")
        .replace("max_client_connections = 16", "max_client_connections = 32")
        .replace("max_connecting = 8", "max_connecting = 32");
    let (server, proxy) = start(&text).await;
    let host = origin.address.to_string();

    for round in 0..2 {
        let mut tasks = Vec::new();
        for index in 0..20 {
            let uri = format!("http://{}/item?{index}", origin.address);
            let host = host.clone();
            tasks.push(tokio::spawn(async move {
                let response = get(proxy, &uri, &host, &[]).await;
                if response.head.status != 200 {
                    eprintln!(
                        "unexpected {} body {:?}",
                        response.head.status, response.body
                    );
                }
                (response.head.status, response.body.len())
            }));
        }
        for task in tasks {
            let (status, length) = task.await.expect("client task");
            assert_eq!(status, 200);
            assert_eq!(length, BODY_LEN, "round {round}");
        }
    }
    let metrics = server.control().metrics();
    assert!(metrics.cache_entries <= 4, "{metrics:?}");
    assert!(metrics.cache_bytes <= 65536, "{metrics:?}");
    assert!(metrics.cache_eviction > 0, "{metrics:?}");
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m10_cache44_invalidation_of_other_uri_keeps_slow_fill() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn read_head(stream: &mut tokio::net::TcpStream) -> Option<(String, String)> {
        let mut head = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            if stream.read(&mut byte).await.ok()? == 0 {
                return None;
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8(head).ok()?;
        let mut parts = text.split_whitespace();
        Some((parts.next()?.to_owned(), parts.next()?.to_owned()))
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let origin_address = listener.local_addr().expect("origin address");
    let slow_gets = Arc::new(AtomicUsize::new(0));
    let task_gets = Arc::clone(&slow_gets);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let gets = Arc::clone(&task_gets);
            tokio::spawn(async move {
                let Some((method, target)) = read_head(&mut stream).await else {
                    return;
                };
                if method == "POST" {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nposted")
                        .await;
                    return;
                }
                if !target.contains("/slow") {
                    let _ = stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
                gets.fetch_add(1, Ordering::SeqCst);
                if stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: 4096\r\n\r\n",
                    )
                    .await
                    .is_err()
                {
                    return;
                }
                if stream.write_all(&vec![b'x'; 512]).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = stream.write_all(&vec![b'x'; 4096 - 512]).await;
            });
        }
    });

    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{origin_address}/slow");
    let host = origin_address.to_string();
    let slow_uri = uri.clone();
    let slow_host = host.clone();
    let slow = tokio::spawn(async move { get(proxy, &slow_uri, &slow_host, &[]).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    let posted = send_raw(
        proxy,
        &m03::request("POST", origin_address, "/other", &[], b"x"),
    )
    .await;
    assert_eq!(posted.body, b"posted");
    let slow_response = slow.await.expect("slow request");
    assert_eq!(slow_response.body.len(), 4096);

    let again = get(proxy, &uri, &host, &[]).await;
    assert_eq!(again.body.len(), 4096);
    assert_eq!(slow_gets.load(Ordering::SeqCst), 1);
    assert!(server.control().metrics().cache_hit >= 1);
    task.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache45_reload_during_fill_discards_the_old_generation() {
    use angara::control::ReloadOutcome;
    use common::TempDir;

    let (origin, requests, origin_task) = spawn_slow_get_origin(4096).await;
    let dir = TempDir::new("m10-cache-fill-reload");
    let text = cache_config(DEFAULT_CACHE, "");
    let path = dir.write("proxy.toml", &text);
    let config = Arc::new(Config::load(&path).expect("initial config"));
    let server = HttpServer::bind_ephemeral_with_path(config, path.clone())
        .await
        .expect("bind proxy");
    let proxy = server.addresses()[0].1;
    let uri = format!("http://{origin}/slow-reload");
    let host = origin.to_string();

    let slow_uri = uri.clone();
    let slow_host = host.clone();
    let slow = tokio::spawn(async move { get(proxy, &slow_uri, &slow_host, &[]).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(matches!(
        server.control().reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    ));
    let slow_response = slow.await.expect("slow request");
    assert_eq!(slow_response.body.len(), 4096);

    let again = get(proxy, &uri, &host, &[]).await;
    assert_eq!(again.body.len(), 4096);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    origin_task.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn m10_cache46_shutdown_during_fill_releases_cache_budget() {
    let (origin, _requests, origin_task) = spawn_slow_get_origin(4096).await;
    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let telemetry = server.telemetry();
    let uri = format!("http://{origin}/slow-shutdown");
    let host = origin.to_string();

    let slow_uri = uri.clone();
    let slow = tokio::spawn(async move { get(proxy, &slow_uri, &host, &[]).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    let shutdown = tokio::time::timeout(Duration::from_secs(5), server.shutdown()).await;
    assert!(shutdown.is_ok(), "shutdown did not finish during a fill");
    let _ = slow.await;

    let metrics = telemetry.snapshot();
    assert_eq!(metrics.cache_entries, 0);
    assert_eq!(metrics.cache_bytes, 0);
    origin_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m10_cache48_many_idle_invalidations_do_not_cancel_slow_fill() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn read_head(stream: &mut tokio::net::TcpStream) -> Option<String> {
        let mut head = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            if stream.read(&mut byte).await.ok()? == 0 {
                return None;
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(head).ok()
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
    let origin_address = listener.local_addr().expect("origin address");
    let slow_gets = Arc::new(AtomicUsize::new(0));
    let task_gets = Arc::clone(&slow_gets);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let gets = Arc::clone(&task_gets);
            tokio::spawn(async move {
                while let Some(head) = read_head(&mut stream).await {
                    if head.starts_with("GET ") && head.contains("/slow") {
                        gets.fetch_add(1, Ordering::SeqCst);
                        if stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: 4096\r\n\r\n",
                            )
                            .await
                            .is_err()
                        {
                            return;
                        }
                        if stream.write_all(&vec![b'x'; 512]).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(3_000)).await;
                        if stream.write_all(&vec![b'x'; 4096 - 512]).await.is_err() {
                            return;
                        }
                    } else if stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nposted")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });

    let (server, proxy) = start(&cache_config(DEFAULT_CACHE, "")).await;
    let uri = format!("http://{origin_address}/slow");
    let host = origin_address.to_string();
    let slow_uri = uri.clone();
    let slow_host = host.clone();
    let slow = tokio::spawn(async move { get(proxy, &slow_uri, &slow_host, &[]).await });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut posts = RawClient::connect(proxy).await.expect("post client");
    for index in 0..8_300 {
        let request = m03::request("POST", origin_address, &format!("/other/{index}"), &[], b"");
        posts.send(&request).await.expect("send POST");
        assert_eq!(
            posts
                .read_response()
                .await
                .expect("POST response")
                .head
                .status,
            200
        );
    }

    let slow_response = slow.await.expect("slow request");
    assert_eq!(slow_response.body.len(), 4096);
    let again = get(proxy, &uri, &host, &[]).await;
    assert_eq!(again.body.len(), 4096);
    assert_eq!(
        slow_gets.load(Ordering::SeqCst),
        1,
        "idle URI invalidations canceled the slow fill"
    );
    assert!(server.control().metrics().cache_hit >= 1);
    task.abort();
    server.shutdown().await;
}
