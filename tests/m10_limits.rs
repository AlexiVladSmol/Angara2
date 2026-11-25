//! M10 cache resource evidence on Linux.

mod common;

#[cfg(target_os = "linux")]
mod linux {
    use angara::config::Config;
    use angara::http::HttpServer;
    use std::sync::Arc;

    use crate::common::m03::{self, RawClient};

    fn rss_kib() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").expect("read status");
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                return rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse().ok())
                    .expect("VmRSS value");
            }
        }
        panic!("VmRSS missing");
    }

    async fn exchange(client: &mut RawClient, request: &[u8]) -> m03::RawResponse {
        client.send(request).await.expect("send request");
        client.read_response().await.expect("read response")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn m10_limits01_small_entries_after_large_no_store_stay_bounded() {
        const LARGE_LEN: usize = 1024 * 1024;
        const SMALL_LEN: usize = 200;
        let large = vec![b'L'; LARGE_LEN];
        let small = vec![b's'; SMALL_LEN];
        let origin = m03::spawn_origin(move |request, _| {
            if request.target.contains("large") {
                m03::response("200 OK", &[("Cache-Control", "no-store")], &large)
            } else {
                m03::response("200 OK", &[("Cache-Control", "max-age=3600")], &small)
            }
        })
        .await
        .expect("origin");
        let text = format!(
            "{}\n[cache]\nenabled = true\nmax_bytes = 33554432\nmax_object_bytes = 1048576\nmax_entries = 512\nmax_fills = 8\n",
            m03::config("127.0.0.1:3128")
        );
        let config = Arc::new(Config::parse(&text).expect("cache config"));
        let server = HttpServer::bind_ephemeral(config)
            .await
            .expect("bind proxy");
        let proxy = server.addresses()[0].1;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        // One warm pair keeps allocator high-water marks out of the delta.
        exchange(
            &mut client,
            &m03::request("GET", origin.address, "/large?warm", &[], b""),
        )
        .await;
        exchange(
            &mut client,
            &m03::request("GET", origin.address, "/small?warm", &[], b""),
        )
        .await;
        let baseline = rss_kib();

        for index in 0..512 {
            let large_request =
                m03::request("GET", origin.address, &format!("/large?{index}"), &[], b"");
            let response = exchange(&mut client, &large_request).await;
            assert_eq!(response.head.status, 200);
            assert_eq!(response.body.len(), LARGE_LEN);

            let small_request =
                m03::request("GET", origin.address, &format!("/small?{index}"), &[], b"");
            let response = exchange(&mut client, &small_request).await;
            assert_eq!(response.head.status, 200);
            assert_eq!(response.body.len(), SMALL_LEN);
        }

        let after = rss_kib();
        let growth = after.saturating_sub(baseline);
        let metrics = server.control().metrics();
        println!(
            "M10-RES-01 entries={} bytes={} rss_kib {baseline}->{after} growth={growth}",
            metrics.cache_entries, metrics.cache_bytes
        );
        assert_eq!(metrics.cache_entries, 512);
        assert!(metrics.cache_bytes <= 33_554_432);
        assert!(
            growth <= 16 * 1024,
            "cache retained {growth} KiB RSS for {} accounted bytes",
            metrics.cache_bytes
        );

        drop(client);
        server.shutdown().await;
    }
}

#[cfg(target_os = "linux")]
mod slow_reader {
    use std::sync::Arc;
    use std::time::Duration;

    use angara::config::Config;
    use angara::http::HttpServer;

    use crate::common::m03::{self, RawClient};

    async fn get(
        proxy: std::net::SocketAddr,
        origin: std::net::SocketAddr,
        path: &str,
    ) -> m03::RawResponse {
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        let request = m03::request("GET", origin, path, &[], b"");
        client.send(&request).await.expect("send request");
        client.read_response().await.expect("read response")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn m10_limits02_slow_reader_stays_within_budget() {
        const BODY_LEN: usize = 200 * 1024;
        let body = vec![b'r'; BODY_LEN];
        let origin_body = body.clone();
        let origin = m03::spawn_origin(move |_, _| {
            m03::response("200 OK", &[("Cache-Control", "max-age=60")], &origin_body)
        })
        .await
        .expect("origin");
        let text = format!(
            "{}\n[cache]\nenabled = true\nmax_bytes = 327680\nmax_object_bytes = 262144\nmax_entries = 8\nmax_fills = 2\n",
            m03::config("127.0.0.1:3128")
        );
        let config = Arc::new(Config::parse(&text).expect("cache config"));
        let server = HttpServer::bind_ephemeral(config)
            .await
            .expect("bind proxy");
        let proxy = server.addresses()[0].1;

        let mut slow = RawClient::connect_with_buffers(proxy, 4096)
            .await
            .expect("slow client");
        slow.send(&m03::request("GET", origin.address, "/slow", &[], b""))
            .await
            .expect("slow request");
        let head = slow.read_head().await.expect("slow head");
        assert_eq!(head.status, 200);
        let length = head
            .header("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .expect("content length");
        assert_eq!(length, BODY_LEN);

        // The slow reader has not consumed the body yet. A second object
        // forces eviction of the first entry, but its bytes stay accounted
        // until the slow response is dropped.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let second = get(proxy, origin.address, "/second").await;
        assert_eq!(second.body.len(), BODY_LEN);
        let peak = server.control().metrics();
        assert!(
            peak.cache_bytes <= 327_680,
            "slow reader exceeded cache budget: {peak:?}"
        );

        let _ = slow.read_exact_bytes(length).await.expect("slow body");
        drop(slow);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let after = server.control().metrics();
        assert!(
            after.cache_bytes <= 327_680,
            "cache budget grew after slow reader: {after:?}"
        );
        assert!(after.cache_eviction >= 1);
        assert_eq!(origin.requests.lock().expect("requests").len(), 2);
        server.shutdown().await;
    }
}
