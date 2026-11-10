//! M03 listener, client-budget and shutdown tests.

mod common;

#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use angara::config::Config;
use angara::http::HttpServer;
use common::m03::*;
use tokio::runtime::{Builder, Runtime};

fn runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build test runtime")
}

fn two_listeners(first: &str, second: &str) -> String {
    config_with_listeners(&format!(
        "[[listeners]]\nid = \"first\"\nbind = \"{first}\"\ntransport = \"http\"\n\n\
         [[listeners]]\nid = \"second\"\nbind = \"{second}\"\ntransport = \"http\"\n"
    ))
}

#[test]
fn m03_srv01_serves_all_configured_listeners() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"listener"))
            .await
            .expect("start origin");
        let text = two_listeners("127.0.0.1:3128", "127.0.0.1:3129");
        let config = Arc::new(Config::parse(&text).expect("valid config"));
        let server = HttpServer::bind_ephemeral(config).await.expect("bind");
        let addresses = server.addresses().to_vec();
        assert_eq!(addresses.len(), 2);

        for (id, address) in addresses {
            let mut client = RawClient::connect(address).await.expect("connect listener");
            client
                .send(&request("GET", origin.address, "/listener", &[], b""))
                .await
                .expect("send request");
            let response = client.read_response().await.expect("read response");
            assert_eq!(response.head.status, 200, "{id}");
        }
        assert_eq!(origin.requests.lock().unwrap().len(), 2);
        server.shutdown().await;
    });
}

#[test]
fn m03_srv02_client_budget_is_shared_between_listeners() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let text = two_listeners("127.0.0.1:3128", "127.0.0.1:3129")
            .replace("max_client_connections = 16", "max_client_connections = 1");
        let config = Arc::new(Config::parse(&text).expect("valid config"));
        let server = HttpServer::bind_ephemeral(config).await.expect("bind");
        let addresses = server.addresses().to_vec();

        let idle = RawClient::connect(addresses[0].1)
            .await
            .expect("open idle connection");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut rejected = RawClient::connect(addresses[1].1)
            .await
            .expect("TCP connect is accepted before the budget check");
        rejected
            .send(&request("GET", origin.address, "/rejected", &[], b""))
            .await
            .expect("write rejected request");
        let rejected_result =
            tokio::time::timeout(Duration::from_secs(2), rejected.read_response())
                .await
                .expect("rejected socket must close, not hang");
        assert!(
            rejected_result.is_err(),
            "second listener must not receive the shared permit: {rejected_result:?}"
        );

        drop(idle);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut accepted = RawClient::connect(addresses[1].1)
            .await
            .expect("connect after permit release");
        accepted
            .send(&request("GET", origin.address, "/accepted", &[], b""))
            .await
            .expect("send accepted request");
        let response = accepted.read_response().await.expect("read accepted");
        assert_eq!(response.head.status, 200);
        server.shutdown().await;
    });
}

#[test]
fn m03_srv01_shutdown_is_bounded_and_releases_ports() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let port = free_port();
        let bind = format!("127.0.0.1:{port}");
        let text = config(&bind);
        let config = Arc::new(Config::parse(&text).expect("valid config"));
        let server = HttpServer::bind(config).await.expect("bind fixed port");
        let mut client = RawClient::connect(server.addresses()[0].1)
            .await
            .expect("connect proxy");
        client
            .send(&request("GET", origin.address, "/shutdown", &[], b""))
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

        let started = Instant::now();
        server.shutdown().await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "shutdown exceeded the configured bound: {elapsed:?}"
        );
        drop(client);
        let rebound = HttpServer::bind(Arc::new(Config::parse(&text).expect("valid config")))
            .await
            .expect("listener port must be released after shutdown");
        rebound.shutdown().await;
    });
}

#[test]
fn m03_srv02_shutdown_closes_active_origin_before_return() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    let origin = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let origin_address = origin.local_addr().expect("origin address");
    let (stream_tx, stream_rx) = mpsc::channel();
    let (hold_tx, hold_rx) = mpsc::channel::<()>();
    let origin_thread = thread::spawn(move || {
        let (mut stream, _) = origin.accept().expect("accept proxy");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("origin read timeout");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).expect("read proxy request");
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n")
            .expect("write first chunk");
        stream.flush().expect("flush first chunk");
        stream_tx
            .send(stream.try_clone().expect("clone origin stream"))
            .expect("send origin stream");
        let _ = hold_rx.recv_timeout(Duration::from_secs(5));
    });

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime");
    runtime.block_on(async {
        let text = config("127.0.0.1:3128")
            .replace("shutdown_timeout_ms = 2000", "shutdown_timeout_ms = 1");
        let (server, proxy) = start_proxy(&text).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin_address, "/active", &[], b""))
            .await
            .expect("send request");
        let head = client.read_head().await.expect("read response head");
        assert_eq!(head.status, 200);
        let origin_stream = stream_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("origin accepted request");

        server.shutdown().await;

        origin_stream
            .set_nonblocking(true)
            .expect("nonblocking origin stream");
        let mut byte = [0_u8; 1];
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            match origin_stream.try_clone().expect("clone").read(&mut byte) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "shutdown returned before the origin socket closed"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("origin read failed: {error}"),
            }
        }
    });
    drop(hold_tx);
    origin_thread.join().expect("origin thread");
}

#[test]
fn m03_srv02_repeated_forced_shutdown_reclaims_tasks_and_deadline() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime");
    runtime.block_on(async {
        let baseline = runtime.metrics().num_alive_tasks();
        for cycle in 0..4 {
            let drop_only = cycle == 3;
            let origin = TcpListener::bind("127.0.0.1:0").expect("bind origin");
            let origin_address = origin.local_addr().expect("origin address");
            let (stream_tx, stream_rx) = mpsc::channel();
            let (hold_tx, hold_rx) = mpsc::channel::<()>();
            let origin_thread = thread::spawn(move || {
                let (mut stream, _) = origin.accept().expect("accept proxy");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("origin read timeout");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).expect("read proxy request");
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n")
                    .expect("write first chunk");
                stream.flush().expect("flush first chunk");
                stream_tx
                    .send(stream.try_clone().expect("clone origin stream"))
                    .expect("send origin stream");
                let _ = hold_rx.recv_timeout(Duration::from_secs(5));
            });

            let text = config("127.0.0.1:3128")
                .replace("shutdown_timeout_ms = 2000", "shutdown_timeout_ms = 1");
            let (server, proxy) = start_proxy(&text).await;
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client
                .send(&request("GET", origin_address, "/active", &[], b""))
                .await
                .expect("send request");
            assert_eq!(
                client.read_head().await.expect("read response head").status,
                200
            );
            let origin_stream = stream_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("origin accepted request");

            let started = Instant::now();
            if drop_only {
                drop(server);
            } else {
                server.shutdown().await;
            }
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_millis(500),
                "cycle {cycle}: forced shutdown used a fresh timeout: {elapsed:?}"
            );

            drop(client);
            drop(origin_stream);
            drop(hold_tx);
            origin_thread.join().expect("origin thread");
            let mut alive = runtime.metrics().num_alive_tasks();
            for _ in 0..200 {
                if alive == baseline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                alive = runtime.metrics().num_alive_tasks();
            }
            assert_eq!(
                alive, baseline,
                "cycle {cycle}: forced shutdown left {alive} live tasks (baseline {baseline})"
            );
        }
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m03_srv01_ipv4_and_ipv6_wildcards_share_a_port_with_v6only() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"v6"))
            .await
            .expect("start origin");
        let port = free_port();
        let listeners = format!(
            "[[listeners]]\nid = \"v4\"\nbind = \"0.0.0.0:{port}\"\ntransport = \"http\"\n\n\
             [[listeners]]\nid = \"v6\"\nbind = \"[::]:{port}\"\ntransport = \"http\"\n"
        );
        let text = config_with_listeners(&listeners).replace(
            "source_allow = [\"127.0.0.0/8\"]",
            "source_allow = [\"127.0.0.0/8\", \"::1/128\"]",
        );
        let config = Arc::new(Config::parse(&text).expect("valid wildcard config"));
        let server = HttpServer::bind(config).await.expect("bind wildcards");
        assert_eq!(server.addresses().len(), 2);

        let mut v4 = RawClient::connect((Ipv4Addr::LOCALHOST, port).into())
            .await
            .expect("connect IPv4 wildcard");
        v4.send(&request("GET", origin.address, "/v4", &[], b""))
            .await
            .expect("send v4");
        assert_eq!(v4.read_response().await.expect("read v4").head.status, 200);

        let mut v6 = RawClient::connect((IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port).into())
            .await
            .expect("connect IPv6 wildcard");
        v6.send(&request("GET", origin.address, "/v6", &[], b""))
            .await
            .expect("send v6");
        assert_eq!(v6.read_response().await.expect("read v6").head.status, 200);
        server.shutdown().await;
    });
}
