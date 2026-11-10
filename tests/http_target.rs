//! M03 target-form, Host, policy-source and edge-framing tests.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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

fn raw_request(target: &str, host: Option<&str>, method: &str) -> Vec<u8> {
    let mut bytes = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    if let Some(host) = host {
        bytes.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");
    bytes
}

#[test]
fn m03_http01_host_is_required_unique_and_consistent() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"no"))
            .await
            .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let target = format!("http://{}/host", origin.address);
        let host = origin.address.to_string();
        let duplicate_host =
            format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\n\r\n").into_bytes();
        let cases = [
            raw_request(&target, None, "GET"),
            duplicate_host,
            raw_request(&target, Some("other.test"), "GET"),
        ];
        for bytes in cases {
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client.send(&bytes).await.expect("send request");
            let response = client.read_response().await.expect("read response");
            assert_eq!(
                response.head.status,
                400,
                "bytes: {}\nstatus: {}",
                String::from_utf8_lossy(&bytes),
                response.head.status
            );
        }
        assert_eq!(origin.accepts.load(Ordering::Acquire), 0);
        server.shutdown().await;
    });
}

#[test]
fn m03_http01_invalid_absolute_forms_are_rejected_before_origin() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"no"))
            .await
            .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let port = origin.address.port();
        let cases: Vec<Vec<u8>> = vec![
            raw_request("/origin-form", Some(&origin.address.to_string()), "GET"),
            raw_request(
                &format!("http://user:pass@127.0.0.1:{port}/userinfo"),
                Some(&format!("127.0.0.1:{port}")),
                "GET",
            ),
            raw_request(
                &format!("https://127.0.0.1:{port}/tls"),
                Some(&format!("127.0.0.1:{port}")),
                "GET",
            ),
            raw_request("http://127.0.0.1:0/zero", Some("127.0.0.1:0"), "GET"),
            raw_request(
                &format!("http://2130706433:{port}/numeric"),
                Some(&format!("2130706433:{port}")),
                "GET",
            ),
        ];
        for bytes in cases {
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client.send(&bytes).await.expect("send request");
            let outcome =
                tokio::time::timeout(Duration::from_secs(2), client.read_response()).await;
            match outcome {
                Ok(Ok(response)) => assert!(
                    matches!(response.head.status, 400 | 414),
                    "unexpected status {} for {}",
                    response.head.status,
                    String::from_utf8_lossy(&bytes)
                ),
                Ok(Err(_)) => {}
                Err(_) => panic!("invalid target hung: {}", String::from_utf8_lossy(&bytes)),
            }
        }
        assert_eq!(origin.accepts.load(Ordering::Acquire), 0);
        server.shutdown().await;
    });
}

#[test]
fn m03_pol01_mapped_ipv6_and_hex_like_hosts() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| {
            let host = request.header("host").expect("canonical Host");
            assert!(
                host.starts_with("127.0.0.1:"),
                "mapped authority was not normalized: {host}"
            );
            response("200 OK", &[], b"mapped")
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let port = origin.address.port();

        let mapped = format!(
            "GET http://[::ffff:127.0.0.1]:{port}/mapped HTTP/1.1\r\nHost: [::ffff:127.0.0.1]:{port}\r\n\r\n"
        );
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client.send(mapped.as_bytes()).await.expect("send mapped");
        let response = client.read_response().await.expect("read mapped");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.text(), "mapped");

        let hex = format!(
            "GET http://0x7f000001:{port}/hex HTTP/1.1\r\nHost: 0x7f000001:{port}\r\n\r\n"
        );
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client.send(hex.as_bytes()).await.expect("send hex");
        let response = client.read_response().await.expect("read hex");
        assert_eq!(response.head.status, 400);
        assert_eq!(origin.requests.lock().unwrap().len(), 1);
        server.shutdown().await;
    });
}

#[test]
fn m03_pol01_forwarded_headers_do_not_replace_real_peer() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"no"))
            .await
            .expect("start origin");
        let text = proxy_config().replace(
            "source_allow = [\"127.0.0.0/8\"]",
            "source_allow = [\"192.0.2.0/24\"]",
        );
        let config = Arc::new(angara::config::Config::parse(&text).expect("valid config"));
        let server = angara::http::HttpServer::bind_ephemeral(config)
            .await
            .expect("bind listener");
        let proxy = server.addresses()[0].1;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request(
                "GET",
                origin.address,
                "/spoofed",
                &[
                    ("X-Forwarded-For", "127.0.0.1"),
                    ("Forwarded", "for=127.0.0.1"),
                ],
                b"",
            ))
            .await
            .expect("send spoofed request");
        let response = client.read_response().await.expect("read deny");
        assert_eq!(response.head.status, 403);
        assert_eq!(origin.accepts.load(Ordering::Acquire), 0);
        server.shutdown().await;
    });
}

#[test]
fn m03_http02_head_204_304_and_eof_responses() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| match request.target.as_str() {
            "/204" => b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
            "/304" => {
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\nETag: \"x\"\r\n\r\n".to_vec()
            }
            "/head" => {
                let body = b"representation";
                let mut bytes =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                        .into_bytes();
                if request.method != "HEAD" {
                    bytes.extend_from_slice(body);
                }
                bytes
            }
            _ => response("200 OK", &[], b"other"),
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;

        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        for (method, path, status) in [("GET", "/204", 204), ("GET", "/304", 304)] {
            client
                .send(&request(method, origin.address, path, &[], b""))
                .await
                .expect("send request");
            let response = client.read_response().await.expect("read no-body");
            assert_eq!(response.head.status, status);
            assert!(response.body.is_empty());
        }
        client
            .send(&request("GET", origin.address, "/304", &[], b""))
            .await
            .expect("send 304");
        let response = client.read_response().await.expect("read 304");
        assert_eq!(response.head.status, 304);
        assert!(
            response
                .header("content-length")
                .is_none_or(|value| value == "5"),
            "304 Content-Length was corrupted: {:?}",
            response.header("content-length")
        );
        assert_eq!(response.header("etag"), Some("\"x\""));
        assert!(response.body.is_empty());

        client
            .send(&request("HEAD", origin.address, "/head", &[], b""))
            .await
            .expect("send HEAD");
        let response = client.read_head_response().await.expect("read HEAD");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.header("content-length"), Some("14"));
        assert!(response.body.is_empty());

        let eof_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind eof origin");
        let eof_address = eof_listener.local_addr().expect("eof address");
        let accepts = Arc::new(AtomicUsize::new(0));
        let task_accepts = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = eof_listener.accept().await else {
                    return;
                };
                task_accepts.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 2048];
                    let mut request = Vec::new();
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let read = stream.read(&mut buffer).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..read]);
                    }
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\neof-body")
                        .await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let mut eof = RawClient::connect(proxy).await.expect("connect proxy");
        eof.send(&request("GET", eof_address, "/eof", &[], b""))
            .await
            .expect("send eof request");
        let response = eof.read_response().await.expect("read eof response");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.text(), "eof-body");
        assert_eq!(accepts.load(Ordering::Acquire), 1);
        server.shutdown().await;
    });
}

#[test]
fn m03_http07_options_empty_path_is_sent_as_asterisk() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| {
            assert_eq!(request.target, "*");
            response("204 No Content", &[], b"")
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        let target = format!("http://{}", origin.address);
        client
            .send(raw_request(&target, Some(&origin.address.to_string()), "OPTIONS").as_slice())
            .await
            .expect("send options");
        let response = client.read_response().await.expect("read options");
        assert_eq!(response.head.status, 204);
        assert_eq!(origin.requests.lock().unwrap()[0].target, "*");
        server.shutdown().await;
    });
}

#[test]
fn m03_res01_header_and_target_limits_are_bounded() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"no"))
            .await
            .expect("start origin");
        let text = proxy_config().replace("max_header_bytes = 32768", "max_header_bytes = 1024");
        let (server, proxy) = start_proxy(&text).await;

        let mut big_header = RawClient::connect(proxy).await.expect("connect proxy");
        let mut bytes = format!(
            "GET http://{}/big HTTP/1.1\r\nHost: {}\r\nX-Big: ",
            origin.address, origin.address
        )
        .into_bytes();
        bytes.extend(std::iter::repeat_n(b'a', 2000));
        bytes.extend_from_slice(b"\r\n\r\n");
        big_header.send(&bytes).await.expect("send big header");
        let outcome =
            tokio::time::timeout(Duration::from_secs(2), big_header.read_response()).await;
        match outcome {
            Ok(Ok(response)) => assert!(
                matches!(response.head.status, 400 | 431),
                "unexpected big-header status {}",
                response.head.status
            ),
            Ok(Err(_)) => {}
            Err(_) => panic!("big header hung"),
        }

        let mut big_target = RawClient::connect(proxy).await.expect("connect proxy");
        let path = format!("/{}", "a".repeat(9000));
        let target = format!("http://{}{}", origin.address, path);
        big_target
            .send(raw_request(&target, Some(&origin.address.to_string()), "GET").as_slice())
            .await
            .expect("send big target");
        let outcome =
            tokio::time::timeout(Duration::from_secs(2), big_target.read_response()).await;
        match outcome {
            Ok(Ok(response)) => assert!(
                matches!(response.head.status, 400 | 414 | 431),
                "unexpected big-target status {}",
                response.head.status
            ),
            Ok(Err(_)) => {}
            Err(_) => panic!("big target hung"),
        }
        assert_eq!(origin.accepts.load(Ordering::Acquire), 0);
        server.shutdown().await;
    });
}
