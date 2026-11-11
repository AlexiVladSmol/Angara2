//! M04 CONNECT resource and backpressure evidence (Linux).

#![cfg(target_os = "linux")]

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::m03::*;
use common::m04::*;
use tokio::runtime::{Builder, Runtime};

fn runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build test runtime")
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "resource/backpressure evidence: run on Linux with --ignored --test-threads=1"]
fn m04_res02_tunnel_backpressure_and_resource_baseline() {
    let runtime = runtime();
    runtime.block_on(async {
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

        const TOTAL: usize = 64 * 1024 * 1024;
        let large = spawn_large_tunnel_origin(TOTAL)
            .await
            .expect("large origin");
        let echo = spawn_echo_origin(None).await.expect("echo origin");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let origin_tasks = runtime.metrics().num_alive_tasks();

        let text = format!(
            "{}\n[connect]\nallowed_ports = [{}, {}]\nhalf_close_timeout_ms = 500\n",
            config("127.0.0.1:3128")
                .replace("pool_idle_timeout_ms = 2000", "pool_idle_timeout_ms = 300"),
            large.address.port(),
            echo.address.port()
        );
        let (server, proxy) = start_proxy(&text).await;

        let mut warm = RawClient::connect(proxy).await.expect("connect proxy");
        warm.send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\nwarm",
                echo.address, echo.address
            )
            .as_bytes(),
        )
        .await
        .expect("send warm tunnel");
        assert_eq!(warm.read_head().await.expect("read warm 200").status, 200);
        assert_eq!(warm.read_exact_bytes(4).await.expect("warm echo"), b"warm");
        drop(warm);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let baseline_fd = fd_count();
        let baseline_rss = rss_kib();

        for round in 0..3 {
            let mut clients = Vec::new();
            for index in 0..6 {
                let mut client = connect_small_buffers(proxy)
                    .await
                    .expect("connect slow consumer");
                client
                    .send(
                        format!(
                            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                            large.address, large.address
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("send large tunnel");
                assert_eq!(
                    client.read_head().await.expect("read large 200").status,
                    200,
                    "round {round} client {index}"
                );
                clients.push(client);
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
            let max_written = large.max_written.load(Ordering::Acquire);
            let total_written = large.written.load(Ordering::Acquire);
            assert!(
                max_written < 16 * 1024 * 1024,
                "round {round}: one tunnel accumulated {max_written} bytes"
            );
            assert!(
                total_written < 128 * 1024 * 1024,
                "round {round}: six tunnels accumulated {total_written} bytes"
            );

            drop(clients);
            for _ in 0..200 {
                if large.active.load(Ordering::Acquire) == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                large.active.load(Ordering::Acquire),
                0,
                "round {round}: tunnel origins were not reclaimed"
            );
        }

        for index in 0..200 {
            let mut client = RawClient::connect(proxy)
                .await
                .expect("short tunnel client");
            client
                .send(
                    format!(
                        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                        echo.address, echo.address
                    )
                    .as_bytes(),
                )
                .await
                .expect("send short tunnel");
            assert_eq!(
                client.read_head().await.expect("read short 200").status,
                200,
                "short tunnel {index}"
            );
            client.send(b"x").await.expect("short tunnel byte");
            assert_eq!(client.read_exact_bytes(1).await.expect("short echo"), b"x");
        }
        assert_eq!(echo.accepts.load(Ordering::Acquire), 201);

        server.shutdown().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after_fd = fd_count();
        let after_rss = rss_kib();
        let after_tasks = runtime.metrics().num_alive_tasks();
        eprintln!(
            "M04-RES-02 fd {baseline_fd}->{after_fd}, rss_kib {baseline_rss}->{after_rss}, \
             tasks {origin_tasks}->{after_tasks}, max_origin_write={}, large_accepts={}",
            large.max_written.load(Ordering::Acquire),
            large.accepts.load(Ordering::Acquire)
        );
        assert!(
            after_fd <= baseline_fd + 8,
            "FD baseline grew from {baseline_fd} to {after_fd}"
        );
        assert!(
            after_rss <= baseline_rss + 128 * 1024,
            "RSS grew from {baseline_rss} KiB to {after_rss} KiB"
        );
        assert!(
            after_tasks <= origin_tasks,
            "tasks leaked: baseline {origin_tasks}, after shutdown {after_tasks}"
        );
    });
}
