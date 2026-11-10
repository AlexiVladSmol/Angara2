//! M03 HTTP forwarding and protocol tests.

mod common;

use std::time::Duration;

use common::m03::*;
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

fn deny_all_config() -> String {
    proxy_config().replace(
        "[[access.rules]]\nid = \"allow\"\naction = \"allow\"",
        "[[access.rules]]\nid = \"deny\"\naction = \"deny\"",
    )
}

fn deny_method_config(method: &str) -> String {
    proxy_config().replace(
        "[[access.rules]]\nid = \"allow\"\naction = \"allow\"",
        &format!(
            "[[access.rules]]\nid = \"deny-method\"\naction = \"deny\"\nmethods = [\"{method}\"]\n\n[[access.rules]]\nid = \"allow-rest\"\naction = \"allow\""
        ),
    )
}

fn deny_loopback_config() -> String {
    proxy_config().replace(
        "[[access.ip_rules]]\nid = \"loopback\"\naction = \"allow\"\nnetworks = [\"127.0.0.0/8\"]\nallow_special = true",
        "[[access.ip_rules]]\nid = \"loopback\"\naction = \"deny\"\nnetworks = [\"127.0.0.0/8\"]",
    )
}

#[test]
fn m03_http01_methods_bodies_and_end_to_end_headers() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| {
            let mut body = request.method.clone().into_bytes();
            body.push(b':');
            body.extend_from_slice(&request.body);
            let mut bytes = format!(
                "HTTP/1.1 200 OK\r\nX-Origin: yes\r\nContent-Type: application/octet-stream\r\nX-End-To-End: {}\r\nContent-Length: {}\r\n\r\n",
                request.header("x-end-to-end").unwrap_or("missing"),
                body.len()
            )
            .into_bytes();
            if request.method != "HEAD" {
                bytes.extend_from_slice(&body);
            }
            bytes
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        let methods = [
            ("GET", b"".as_slice()),
            ("HEAD", b"".as_slice()),
            ("POST", b"post-body".as_slice()),
            ("PUT", b"put-body".as_slice()),
            ("DELETE", b"delete-body".as_slice()),
            ("OPTIONS", b"".as_slice()),
            ("PATCH", b"patch-body".as_slice()),
        ];
        for (method, body) in methods {
            client
                .send(&request(
                    method,
                    origin.address,
                    "/a%2Fb?q=1&x=%00",
                    &[("X-End-To-End", "kept")],
                    body,
                ))
                .await
                .expect("send request");
            let response = if method == "HEAD" {
                client.read_head_response().await.expect("read HEAD response")
            } else {
                client.read_response().await.expect("read response")
            };
            assert_eq!(response.head.status, 200, "{method}");
            assert_eq!(response.header("x-origin"), Some("yes"), "{method}");
            assert_eq!(response.header("x-end-to-end"), Some("kept"), "{method}");
            if method == "HEAD" {
                assert!(response.body.is_empty(), "HEAD body must be empty");
            } else {
                let expected = format!("{method}:{}", String::from_utf8_lossy(body));
                assert_eq!(response.text(), expected, "{method}");
            }
        }

        let requests = origin.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), methods.len());
        let host = origin.address.to_string();
        for (request, (method, _)) in requests.iter().zip(methods) {
            assert_eq!(request.method, method);
            assert_eq!(request.target, "/a%2Fb?q=1&x=%00");
            assert_eq!(request.version, "HTTP/1.1");
            assert_eq!(request.header("host"), Some(host.as_str()));
            assert_eq!(request.header("x-end-to-end"), Some("kept"));
        }

        server.shutdown().await;
    });
}

#[test]
fn m03_http02_keepalive_sequential_and_pipelined_are_ordered() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, index| {
            response(
                "200 OK",
                &[("Content-Type", "text/plain")],
                format!("request-{index}").as_bytes(),
            )
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;

        let mut sequential = RawClient::connect(proxy).await.expect("connect proxy");
        for expected in ["request-0", "request-1"] {
            sequential
                .send(&request("GET", origin.address, "/", &[], b""))
                .await
                .expect("send sequential request");
            let response = sequential.read_response().await.expect("read response");
            assert_eq!(response.text(), expected);
        }
        assert_eq!(
            origin.accepts.load(std::sync::atomic::Ordering::Acquire),
            1,
            "sequential keep-alive must reuse one origin socket"
        );

        let mut pipelined = RawClient::connect(proxy).await.expect("connect proxy");
        let mut bytes = request("GET", origin.address, "/first", &[], b"");
        bytes.extend_from_slice(&request("GET", origin.address, "/second", &[], b""));
        pipelined
            .send(&bytes)
            .await
            .expect("send pipelined requests");
        let first = pipelined.read_response().await.expect("read first");
        let second = pipelined.read_response().await.expect("read second");
        assert_eq!(first.head.status, 200);
        assert_eq!(second.head.status, 200);
        assert!(
            first.text().contains("request-"),
            "unexpected first body: {}",
            first.text()
        );
        assert!(
            second.text().contains("request-"),
            "unexpected second body: {}",
            second.text()
        );

        server.shutdown().await;
    });
}

#[test]
fn m03_http02_trailers_are_forwarded_and_filtered() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| {
            assert_eq!(request.trailers.len(), 1, "origin trailers: {:?}", request.trailers);
            assert_eq!(request.trailers[0].0, "x-checksum");
            assert_eq!(request.trailers[0].1, "upload-ok");
            assert!(
                request
                    .headers
                    .iter()
                    .all(|(name, _)| !name.eq_ignore_ascii_case("proxy-authorization")),
                "proxy credentials leaked upstream"
            );
            chunked_response(
                "200 OK",
                &[
                    ("Content-Type", "text/plain"),
                    ("Trailer", "X-Checksum, Authorization"),
                ],
                &[b"hello", b" world"],
                &[("X-Checksum", "download-ok"), ("Authorization", "must-not-pass")],
            )
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        let mut bytes = format!(
            "POST http://{}/upload HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum, Proxy-Authorization\r\nTE: trailers\r\nProxy-Authorization: secret\r\n\r\n",
            origin.address, origin.address
        )
        .into_bytes();
        bytes.extend_from_slice(b"5\r\nhello\r\n0\r\nX-Checksum: upload-ok\r\nProxy-Authorization: secret\r\n\r\n");
        client.send(&bytes).await.expect("send chunked request");
        let response = client.read_response().await.expect("read chunked response");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.text(), "hello world");
        assert!(
            response
                .trailers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("x-checksum") && value == "download-ok")
        );
        assert!(
            response
                .trailers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("authorization")),
            "authorization trailer leaked to client: {:?}",
            response.trailers
        );

        server.shutdown().await;
    });
}

#[test]
fn m03_http03_hop_by_hop_and_proxy_credentials_are_removed() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| {
            response(
                "200 OK",
                &[
                    ("Connection", "X-Resp-Hop"),
                    ("X-Resp-Hop", "remove"),
                    ("Proxy-Authenticate", "Basic realm=secret"),
                    ("Set-Cookie", "a=1"),
                    ("Set-Cookie", "b=2"),
                    ("WWW-Authenticate", "Basic realm=origin"),
                    ("X-End-Resp", "keep"),
                ],
                b"ok",
            )
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request(
                "GET",
                origin.address,
                "/headers",
                &[
                    ("Connection", "X-Hop, Trailer, TE"),
                    ("X-Hop", "remove"),
                    ("Proxy-Connection", "keep-alive"),
                    ("Keep-Alive", "timeout=5"),
                    ("Trailer", "X-Checksum"),
                    ("TE", "trailers"),
                    ("Proxy-Authorization", "secret-proxy"),
                    ("Authorization", "origin-auth"),
                    ("X-End-To-End", "keep"),
                ],
                b"",
            ))
            .await
            .expect("send request");
        let response = client.read_response().await.expect("read response");
        assert_eq!(response.head.status, 200);
        for name in ["connection", "x-resp-hop", "proxy-authenticate"] {
            assert!(
                response.header(name).is_none(),
                "hop-by-hop response field {name} leaked"
            );
        }
        assert_eq!(response.header("x-end-resp"), Some("keep"));
        assert_eq!(
            response.header("www-authenticate"),
            Some("Basic realm=origin")
        );
        let cookies = response
            .head
            .header_values("set-cookie")
            .collect::<Vec<_>>();
        assert_eq!(cookies, vec!["a=1", "b=2"]);

        let requests = origin.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        for name in [
            "connection",
            "x-hop",
            "proxy-connection",
            "keep-alive",
            "trailer",
            "te",
            "proxy-authorization",
        ] {
            assert!(
                request.header(name).is_none(),
                "hop-by-hop request field {name} reached origin"
            );
        }
        assert_eq!(request.header("authorization"), Some("origin-auth"));
        assert_eq!(request.header("x-end-to-end"), Some("keep"));

        server.shutdown().await;
    });
}

#[test]
fn m03_http04_expect_continue_is_local_and_ordered() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| {
            assert_eq!(request.header("expect"), None);
            assert_eq!(request.body, b"hello");
            response("200 OK", &[], b"received")
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        let head = format!(
            "POST http://{}/expect HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
            origin.address, origin.address
        );
        client.send(head.as_bytes()).await.expect("send headers");
        let interim = client.read_head().await.expect("read 100");
        assert_eq!(interim.status, 100);
        client.send(b"hello").await.expect("send body");
        let response = client.read_response().await.expect("read final");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.text(), "received");
        assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::Acquire), 1);

        server.shutdown().await;
    });
}

#[test]
fn m03_http04_unknown_expect_and_early_deny_do_not_touch_origin() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"no"))
            .await
            .expect("start origin");

        let (server, proxy) = start_proxy(&deny_method_config("POST")).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        let head = format!(
            "POST http://{}/denied HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
            origin.address, origin.address
        );
        client.send(head.as_bytes()).await.expect("send headers");
        let response = client.read_response().await.expect("read deny");
        assert_eq!(response.head.status, 403);
        assert!(response.interim.is_empty(), "deny must not send 100");
        server.shutdown().await;

        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        let head = format!(
            "POST http://{}/unknown HTTP/1.1\r\nHost: {}\r\nExpect: something-else\r\nContent-Length: 0\r\n\r\n",
            origin.address, origin.address
        );
        client.send(head.as_bytes()).await.expect("send headers");
        let response = client.read_response().await.expect("read 417");
        assert_eq!(response.head.status, 417);
        assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::Acquire), 0);
        server.shutdown().await;
    });
}

#[test]
fn m03_http04_interim_heads_are_forwarded_in_order() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| {
            let mut bytes = b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n".to_vec();
            bytes.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\nLink: </b>\r\n\r\n");
            bytes.extend_from_slice(&response("200 OK", &[], b"final"));
            bytes
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin.address, "/interim", &[], b""))
            .await
            .expect("send request");
        let response = client.read_response().await.expect("read response");
        assert_eq!(response.interim.len(), 2);
        assert!(response.interim.iter().all(|head| head.status == 103));
        assert_eq!(response.interim[0].header("link"), Some("</a>"));
        assert_eq!(response.interim[1].header("link"), Some("</b>"));
        assert!(
            response
                .interim
                .iter()
                .all(|head| head.header("via").is_some())
        );
        assert_eq!(response.head.status, 200);
        assert_eq!(response.text(), "final");
        server.shutdown().await;
    });
}

#[test]
fn m03_http04_unexpected_upstream_100_and_101_are_502() {
    runtime().block_on(async {
        for upstream in [
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".to_vec(),
        ] {
            let origin = spawn_origin(move |_, _| upstream.clone())
                .await
                .expect("start origin");
            let (server, proxy) = start_proxy(&proxy_config()).await;
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client
                .send(&request("GET", origin.address, "/unsupported", &[], b""))
                .await
                .expect("send request");
            let response = client.read_response().await.expect("read response");
            assert_eq!(response.head.status, 502, "upstream interim must be rejected");
            assert!(
                response.interim.iter().all(|head| head.status != 100 && head.status != 101),
                "unsupported interim leaked: {:?}",
                response.interim
            );
            server.shutdown().await;
        }
    });
}

#[test]
fn m03_http04_interim_limit_is_bounded() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| {
            let mut bytes = Vec::new();
            for index in 0..17 {
                let value = "x".repeat(4096);
                bytes.extend_from_slice(
                    format!("HTTP/1.1 103 Early Hints\r\nX-Large-{index}: {value}\r\n\r\n")
                        .as_bytes(),
                );
            }
            bytes.extend_from_slice(&response("200 OK", &[], b"final"));
            bytes
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin.address, "/limit", &[], b""))
            .await
            .expect("send request");
        let response = client.read_response().await.expect("read response");
        assert_eq!(
            response.head.status, 502,
            "overflowed interim queue must fail the exchange"
        );
        assert!(response.interim.len() <= 16);
        server.shutdown().await;
    });
}

#[test]
fn m03_http07_rejections_happen_without_origin_dial() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"no"))
            .await
            .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;

        let cases: Vec<(Vec<u8>, u16)> = vec![
            (
                b"TRACE http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
                501,
            ),
            (
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    origin.address, origin.address
                )
                .into_bytes(),
                501,
            ),
            (
                b"CONNECT bad/host HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
                400,
            ),
            (
                b"GET http://example.test/ HTTP/1.0\r\nHost: example.test\r\n\r\n".to_vec(),
                505,
            ),
            (
                b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nVia: 1.1 angara\r\n\r\n"
                    .to_vec(),
                508,
            ),
            (
                b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    .to_vec(),
                501,
            ),
        ];

        for (bytes, expected) in cases {
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client.send(&bytes).await.expect("send rejection case");
            let response = match tokio::time::timeout(Duration::from_secs(3), client.read_response()).await {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => panic!("expected {expected}, got read error {error}"),
                Err(_) => panic!("expected {expected}, timed out"),
            };
            assert_eq!(
                response.head.status, expected,
                "request: {}",
                String::from_utf8_lossy(&bytes)
            );
            assert!(
                response.body.is_empty(),
                "rejection reflected a body for {}",
                String::from_utf8_lossy(&bytes)
            );
        }

        assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::Acquire), 0);
        server.shutdown().await;
    });
}

#[test]
fn m03_http07_h2c_preface_is_rejected_without_origin() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"no"))
            .await
            .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("send h2 preface");
        let outcome = tokio::time::timeout(Duration::from_secs(2), client.read_response()).await;
        match outcome {
            Ok(Ok(response)) => assert!(
                matches!(response.head.status, 400 | 505),
                "unexpected h2 preface status {}",
                response.head.status
            ),
            Ok(Err(_)) => {}
            Err(_) => panic!("h2 preface hung"),
        }
        assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::Acquire), 0);
        server.shutdown().await;
    });
}

#[test]
fn m03_http07_options_max_forwards_and_range_headers() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| {
            if request.method == "OPTIONS" {
                assert_eq!(request.header("max-forwards"), Some("0"));
                return response("204 No Content", &[], b"");
            }
            assert_eq!(request.header("range"), Some("bytes=0-1"));
            assert_eq!(request.header("if-range"), Some("\"etag\""));
            assert_eq!(request.header("if-none-match"), Some("\"etag\""));
            response(
                "206 Partial Content",
                &[("Content-Range", "bytes 0-1/4")],
                b"ab",
            )
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;

        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request(
                "GET",
                origin.address,
                "/range",
                &[
                    ("Range", "bytes=0-1"),
                    ("If-Range", "\"etag\""),
                    ("If-None-Match", "\"etag\""),
                ],
                b"",
            ))
            .await
            .expect("send range request");
        let response = client.read_response().await.expect("read range response");
        assert_eq!(response.head.status, 206);
        assert_eq!(response.header("content-range"), Some("bytes 0-1/4"));
        assert_eq!(response.text(), "ab");

        let mut forwarded = RawClient::connect(proxy).await.expect("connect proxy");
        forwarded
            .send(&request(
                "OPTIONS",
                origin.address,
                "/opt",
                &[("Max-Forwards", "1")],
                b"",
            ))
            .await
            .expect("send forwarded options");
        let response = forwarded.read_response().await.expect("read options");
        assert_eq!(response.head.status, 204);

        let mut local = RawClient::connect(proxy).await.expect("connect proxy");
        local
            .send(&request(
                "OPTIONS",
                origin.address,
                "/",
                &[("Max-Forwards", "0")],
                b"",
            ))
            .await
            .expect("send local options");
        let response = local.read_response().await.expect("read local 204");
        assert_eq!(response.head.status, 204);
        assert!(response.body.is_empty());
        assert_eq!(
            origin.requests.lock().unwrap().len(),
            2,
            "Max-Forwards: 0 must not reach origin"
        );
        server.shutdown().await;
    });
}

#[test]
fn m03_pol01_source_and_ip_deny_happen_before_dial() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"no"))
            .await
            .expect("start origin");

        let (server, proxy) = start_proxy(&deny_all_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin.address, "/denied", &[], b""))
            .await
            .expect("send request");
        let response = client.read_response().await.expect("read deny");
        assert_eq!(response.head.status, 403);
        server.shutdown().await;

        let (server, proxy) = start_proxy(&deny_loopback_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(&request("GET", origin.address, "/denied-ip", &[], b""))
            .await
            .expect("send request");
        let response = client.read_response().await.expect("read deny");
        assert_eq!(response.head.status, 403);
        assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::Acquire), 0);
        server.shutdown().await;
    });
}

#[test]
fn m03_pol02_second_keepalive_request_is_rechecked() {
    runtime().block_on(async {
        let origin = spawn_origin(|_, _| response("200 OK", &[], b"ok"))
            .await
            .expect("start origin");
        let (server, proxy) = start_proxy(&deny_method_config("POST")).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        client
            .send(&request("GET", origin.address, "/first", &[], b""))
            .await
            .expect("send allowed request");
        let first = client.read_response().await.expect("read allowed");
        assert_eq!(first.head.status, 200);

        client
            .send(&request("POST", origin.address, "/second", &[], b"x"))
            .await
            .expect("send denied request");
        let second = client.read_response().await.expect("read denied");
        assert_eq!(second.head.status, 403);
        assert_eq!(origin.requests.lock().unwrap().len(), 1);
        server.shutdown().await;
    });
}

#[test]
fn m03_http01_large_binary_upload_and_download_stream() {
    runtime().block_on(async {
        const SIZE: usize = 64 * 1024 * 1024;
        let origin = spawn_origin(|request, _| {
            assert_eq!(request.body.len(), SIZE);
            let mut body = request.body.clone();
            body.reverse();
            response(
                "200 OK",
                &[("Content-Type", "application/octet-stream")],
                &body,
            )
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");

        let mut upload = Vec::with_capacity(SIZE);
        for index in 0..SIZE {
            upload.push((index % 251) as u8);
        }
        client
            .send(&request("POST", origin.address, "/binary", &[], &upload))
            .await
            .expect("send large request");
        let response = client.read_response().await.expect("read large response");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.body.len(), SIZE);
        let mut expected = upload;
        expected.reverse();
        assert_eq!(response.body, expected);
        server.shutdown().await;
    });
}

#[test]
fn m03_cpu01_http_path_works_with_one_two_and_four_workers() {
    for workers in [1, 2, 4] {
        let runtime = Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .expect("build test runtime");
        runtime.block_on(async {
            let origin =
                spawn_origin(|request, _| response("200 OK", &[], request.body.as_slice()))
                    .await
                    .expect("start origin");
            let text = proxy_config()
                .replace("worker_threads = 2", &format!("worker_threads = {workers}"));
            let (server, proxy) = start_proxy(&text).await;
            let mut first = RawClient::connect(proxy).await.expect("connect first");
            let mut second = RawClient::connect(proxy).await.expect("connect second");
            first
                .send(&request("POST", origin.address, "/one", &[], b"one"))
                .await
                .expect("send first");
            second
                .send(&request("POST", origin.address, "/two", &[], b"two"))
                .await
                .expect("send second");
            let (first, second) = tokio::join!(first.read_response(), second.read_response());
            assert_eq!(first.expect("first response").text(), "one");
            assert_eq!(second.expect("second response").text(), "two");
            server.shutdown().await;
        });
    }
}
