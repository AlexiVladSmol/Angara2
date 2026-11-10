//! M03 response limits, timeouts and resource-baseline tests.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::m03::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};

fn runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build test runtime")
}

fn proxy_config() -> String {
    config("127.0.0.1:3128")
}

async fn spawn_stream_origin(
    chunks: Vec<(Duration, Vec<u8>)>,
    hold_open: Option<Duration>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stream origin");
    let address = listener.local_addr().expect("stream origin address");
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buffer = [0_u8; 4096];
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        if stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        for (delay, chunk) in chunks {
            tokio::time::sleep(delay).await;
            let mut frame = format!("{:x}\r\n", chunk.len()).into_bytes();
            frame.extend_from_slice(&chunk);
            frame.extend_from_slice(b"\r\n");
            if stream.write_all(&frame).await.is_err() {
                return;
            }
        }
        if let Some(hold) = hold_open {
            tokio::time::sleep(hold).await;
            return;
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
    });
    address
}

#[test]
fn m03_res01_request_header_count_is_bounded_before_origin() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"no"))
            .await
            .expect("start origin");
        let text = proxy_config().replace("max_headers = 64", "max_headers = 3");
        let (server, proxy) = start_proxy(&text).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        let mut bytes = format!(
            "GET http://{}/headers HTTP/1.1\r\nHost: {}\r\nX-One: 1\r\nX-Two: 2\r\nX-Three: 3\r\nX-Four: 4\r\n\r\n",
            origin.address, origin.address
        )
        .into_bytes();
        bytes.extend_from_slice(b"");
        client.send(&bytes).await.expect("send oversized headers");
        let outcome = tokio::time::timeout(Duration::from_secs(2), client.read_response()).await;
        match outcome {
            Ok(Ok(response)) => assert!(
                matches!(response.head.status, 400 | 431),
                "unexpected status {}",
                response.head.status
            ),
            Ok(Err(_)) => {}
            Err(_) => panic!("header-count limit hung"),
        }
        assert_eq!(origin.accepts.load(Ordering::Acquire), 0);
        server.shutdown().await;
    });
}

#[test]
fn m03_res01_upstream_header_count_is_bounded() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-One: 1\r\nX-Two: 2\r\nX-Three: 3\r\nX-Four: 4\r\n\r\nok"
                .to_vec()
        })
        .await
        .expect("start origin");
        let text = proxy_config().replace("max_headers = 64", "max_headers = 3");
        let (server, proxy) = start_proxy(&text).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin.address, "/upstream-headers", &[], b""))
            .await
            .expect("send request");
        let response = client.read_response().await.expect("read response");
        assert_eq!(response.head.status, 502);
        server.shutdown().await;
    });
}

#[test]
fn m03_res01_response_header_timeout_is_504() {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent origin");
        let origin = listener.local_addr().expect("origin address");
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let text = proxy_config().replace(
            "response_header_timeout_ms = 5000",
            "response_header_timeout_ms = 200",
        );
        let (server, proxy) = start_proxy(&text).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin, "/silent", &[], b""))
            .await
            .expect("send request");
        let started = Instant::now();
        let response = client.read_response().await.expect("read timeout response");
        assert_eq!(response.head.status, 504);
        assert!(started.elapsed() < Duration::from_secs(2));
        server.shutdown().await;
    });
}

#[test]
fn m03_res01_regular_sse_progress_beats_idle_timeout() {
    runtime().block_on(async {
        let mut chunks = Vec::new();
        for index in 0..8 {
            chunks.push((
                Duration::from_millis(100),
                format!("data: {index}\n\n").into_bytes(),
            ));
        }
        let origin = spawn_stream_origin(chunks, None).await;
        let text = proxy_config().replace("idle_timeout_ms = 5000", "idle_timeout_ms = 1000");
        let (server, proxy) = start_proxy(&text).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin, "/sse", &[], b""))
            .await
            .expect("send request");
        let response = client.read_response().await.expect("read SSE");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.text(), "data: 0\n\ndata: 1\n\ndata: 2\n\ndata: 3\n\ndata: 4\n\ndata: 5\n\ndata: 6\n\ndata: 7\n\n");
        server.shutdown().await;
    });
}

#[test]
fn m03_res01_stopped_stream_is_closed_by_idle_timeout() {
    runtime().block_on(async {
        let origin = spawn_stream_origin(
            vec![(Duration::from_millis(10), b"data: first\n\n".to_vec())],
            Some(Duration::from_secs(10)),
        )
        .await;
        let text = proxy_config().replace("idle_timeout_ms = 5000", "idle_timeout_ms = 1000");
        let (server, proxy) = start_proxy(&text).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin, "/stopped", &[], b""))
            .await
            .expect("send request");
        // The origin never sends the terminal chunk/EOF. Either the body is
        // truncated with an error or the socket is closed by the idle timer;
        // both must happen well before the response-header timeout.
        let outcome = tokio::time::timeout(Duration::from_secs(3), client.read_response()).await;
        match outcome {
            Ok(Ok(response)) => {
                assert_eq!(response.head.status, 200);
                assert_eq!(response.text(), "data: first\n\n");
            }
            Ok(Err(_)) => {}
            Err(_) => panic!("stopped stream was not bounded by the idle timeout"),
        }
        server.shutdown().await;
    });
}

#[test]
fn m03_res01_keepalive_idle_is_bounded() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let text = proxy_config().replace("idle_timeout_ms = 5000", "idle_timeout_ms = 1000");
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
        tokio::time::sleep(Duration::from_millis(1300)).await;
        let second = tokio::time::timeout(Duration::from_secs(2), async {
            let _ = client
                .send(&request("GET", origin.address, "/second", &[], b""))
                .await;
            client.read_response().await
        })
        .await
        .expect("idle keep-alive did not close promptly");
        assert!(
            second.is_err(),
            "idle keep-alive connection unexpectedly served a second request"
        );
        assert_eq!(
            origin.requests.lock().unwrap().len(),
            1,
            "idle connection reused for a new request"
        );
        server.shutdown().await;
    });
}

#[test]
fn m03_res01_idle_outbound_socket_pressure_is_503() {
    runtime().block_on(async {
        let first_origin = spawn_origin(|_, _| response("200 OK", &[], b"idle"))
            .await
            .expect("start first origin");
        let second_origin = spawn_origin(|_, _| response("200 OK", &[], b"busy"))
            .await
            .expect("start second origin");
        let text = proxy_config()
            .replace("max_connections = 64", "max_connections = 1")
            .replace("max_connecting = 8", "max_connecting = 1")
            .replace("pool_max_idle = 4", "pool_max_idle = 1")
            .replace("pool_max_idle_per_key = 2", "pool_max_idle_per_key = 1");
        let (server, proxy) = start_proxy(&text).await;

        let mut first = RawClient::connect(proxy).await.expect("connect first");
        first
            .send(&request("GET", first_origin.address, "/idle", &[], b""))
            .await
            .expect("send first");
        assert_eq!(
            first.read_response().await.expect("read first").text(),
            "idle"
        );

        let mut second = RawClient::connect(proxy).await.expect("connect second");
        second
            .send(&request("GET", second_origin.address, "/busy", &[], b""))
            .await
            .expect("send second");
        let second_response = second.read_response().await.expect("read busy");
        assert_eq!(second_response.head.status, 503);
        assert_eq!(second_response.header("retry-after"), Some("1"));
        assert_eq!(
            second_origin.accepts.load(Ordering::Acquire),
            0,
            "outbound permit was not held by the idle socket"
        );
        server.shutdown().await;
    });
}

#[test]
fn m03_http06_partial_upload_does_not_become_a_complete_origin_request() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;

        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        let head = format!(
            "POST http://{}/partial HTTP/1.1\r\nHost: {}\r\nContent-Length: 10\r\n\r\n",
            origin.address, origin.address
        );
        client.send(head.as_bytes()).await.expect("send head");
        client.send(b"abcd").await.expect("send partial body");
        client.shutdown_write().await.expect("close upload side");
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(client);

        let mut healthy = RawClient::connect(proxy).await.expect("connect healthy");
        healthy
            .send(&request("GET", origin.address, "/healthy", &[], b""))
            .await
            .expect("send healthy");
        let response = healthy.read_response().await.expect("read healthy");
        assert_eq!(response.head.status, 200);
        let requests = origin.requests.lock().unwrap().clone();
        assert!(
            requests.iter().all(|request| request.target != "/partial"),
            "partial upload was retried or accepted: {requests:?}"
        );
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].target, "/healthy");
        server.shutdown().await;
    });
}

#[test]
fn m03_http06_origin_eof_truncates_body_and_evicts_stream() {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let origin = listener.local_addr().expect("origin address");
        let accepts = Arc::new(AtomicUsize::new(0));
        let task_accepts = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let index = task_accepts.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4096];
                    let mut request = Vec::new();
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let read = stream.read(&mut buffer).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..read]);
                    }
                    if index == 0 {
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
                            .await;
                        let _ = stream.shutdown().await;
                    } else {
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await;
                    }
                });
            }
        });

        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut first = RawClient::connect(proxy).await.expect("connect first");
        first
            .send(&request("GET", origin, "/truncated", &[], b""))
            .await
            .expect("send truncated request");
        let outcome = tokio::time::timeout(Duration::from_secs(2), first.read_response()).await;
        assert!(
            matches!(outcome, Ok(Err(_))),
            "truncated origin body must surface as a stream error, got {outcome:?}"
        );
        drop(first);
        assert_eq!(
            accepts.load(Ordering::Acquire),
            1,
            "the failed exchange must not be retried automatically"
        );

        let mut second = RawClient::connect(proxy).await.expect("connect second");
        second
            .send(&request("GET", origin, "/healthy", &[], b""))
            .await
            .expect("send second");
        let response = second.read_response().await.expect("read second");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.text(), "ok");
        assert_eq!(accepts.load(Ordering::Acquire), 2);
        server.shutdown().await;
    });
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "resource evidence: run on Linux with --ignored --test-threads=1"]
fn m03_res02_fd_baseline_after_two_hundred_exchanges() {
    runtime().block_on(async {
        fn fd_count() -> usize {
            std::fs::read_dir("/proc/self/fd")
                .expect("read /proc/self/fd")
                .count()
        }
        fn rss_kib() -> u64 {
            let status = std::fs::read_to_string("/proc/self/status").expect("read status");
            status
                .lines()
                .find_map(|line| {
                    line.strip_prefix("VmRSS:")
                        .and_then(|value| value.split_whitespace().next())
                        .and_then(|value| value.parse().ok())
                })
                .expect("VmRSS")
        }

        let origin = spawn_origin(|_, _| response("200 OK", &[], b"cycle"))
            .await
            .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        // Warm up the pool and runtime threads before the baseline.
        client
            .send(&request("GET", origin.address, "/warmup", &[], b""))
            .await
            .expect("send warmup");
        client.read_response().await.expect("read warmup");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let baseline_fd = fd_count();
        let baseline_rss = rss_kib();

        for _ in 0..200 {
            client
                .send(&request("GET", origin.address, "/cycle", &[], b""))
                .await
                .expect("send cycle");
            let response = client.read_response().await.expect("read cycle");
            assert_eq!(response.head.status, 200);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after_fd = fd_count();
        let after_rss = rss_kib();
        eprintln!(
            "M03-RES-02 fd {baseline_fd}->{after_fd}, rss_kib {baseline_rss}->{after_rss}, origin_accepts={}",
            origin.accepts.load(Ordering::Acquire)
        );
        assert!(
            after_fd <= baseline_fd + 8,
            "FD baseline grew from {baseline_fd} to {after_fd}"
        );
        assert!(
            after_rss <= baseline_rss + 128 * 1024,
            "RSS grew from {baseline_rss} KiB to {after_rss} KiB"
        );
        assert_eq!(origin.accepts.load(Ordering::Acquire), 1);
        server.shutdown().await;
    });
}

#[test]
fn m03_res02_many_exchanges_return_to_a_bounded_baseline() {
    runtime().block_on(async {
        let counter = Arc::new(AtomicUsize::new(0));
        let handler_counter = Arc::clone(&counter);
        let origin = spawn_origin(move |_, _| {
            handler_counter.fetch_add(1, Ordering::AcqRel);
            response("200 OK", &[], b"cycle")
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        for _ in 0..200 {
            client
                .send(&request("GET", origin.address, "/cycle", &[], b""))
                .await
                .expect("send cycle request");
            let response = client.read_response().await.expect("read cycle response");
            assert_eq!(response.head.status, 200);
            assert_eq!(response.text(), "cycle");
        }
        assert_eq!(counter.load(Ordering::Acquire), 200);
        assert_eq!(
            origin.accepts.load(Ordering::Acquire),
            1,
            "short healthy exchanges must not leak origin sockets"
        );
        server.shutdown().await;
    });
}
