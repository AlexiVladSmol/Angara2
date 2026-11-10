//! M03 raw framing and negative-corpus tests.

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

fn target(origin: std::net::SocketAddr, path: &str) -> String {
    format!("http://{origin}{path}")
}

#[test]
fn m03_http05_raw_negative_corpus_does_not_desync() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| {
            let mut body = format!("{}/{}:", request.method, request.target).into_bytes();
            body.extend_from_slice(&request.body);
            response("200 OK", &[("X-Origin", "framing")], &body)
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;

        let cases: Vec<(&str, Vec<u8>, &[u16], usize)> = vec![
            (
                "cl-te",
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
                    target(origin.address, "/cl-te"),
                    origin.address
                )
                .into_bytes(),
                &[200],
                1,
            ),
            (
                "te-cl",
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
                    target(origin.address, "/te-cl"),
                    origin.address
                )
                .into_bytes(),
                &[200],
                1,
            ),
            (
                "conflicting-cl",
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
                    target(origin.address, "/conflicting-cl"),
                    origin.address
                )
                .into_bytes(),
                &[400],
                0,
            ),
            (
                "comma-cl",
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 3, 3\r\n\r\nabc",
                    target(origin.address, "/comma-cl"),
                    origin.address
                )
                .into_bytes(),
                &[400],
                0,
            ),
            (
                "repeated-chunked",
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked, chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
                    target(origin.address, "/repeated-chunked"),
                    origin.address
                )
                .into_bytes(),
                &[400],
                0,
            ),
            (
                "unsupported-te",
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
                    target(origin.address, "/unsupported-te"),
                    origin.address
                )
                .into_bytes(),
                &[400],
                0,
            ),
            (
                "bad-chunk",
                format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n",
                    target(origin.address, "/bad-chunk"),
                    origin.address
                )
                .into_bytes(),
                &[400, 502],
                0,
            ),
            (
                "obs-fold",
                format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nX-Test: one\r\n two\r\n\r\n",
                    target(origin.address, "/obs-fold"),
                    origin.address
                )
                .into_bytes(),
                &[400],
                0,
            ),
            (
                "space-before-colon",
                format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nX-Test : value\r\n\r\n",
                    target(origin.address, "/space-before-colon"),
                    origin.address
                )
                .into_bytes(),
                &[400],
                0,
            ),
            (
                "trap-after-bad-chunk",
                {
                    let mut bytes = format!(
                        "POST {} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n",
                        target(origin.address, "/bad"),
                        origin.address
                    )
                    .into_bytes();
                    bytes.extend_from_slice(
                        format!(
                            "GET {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
                            target(origin.address, "/trap"),
                            origin.address
                        )
                        .as_bytes(),
                    );
                    bytes
                },
                &[400, 502],
                0,
            ),
        ];

        for (name, bytes, expected, origin_delta) in cases {
            let before = origin.requests.lock().unwrap().len();
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client.send(&bytes).await.expect("send negative request");
            let outcome = tokio::time::timeout(Duration::from_secs(2), client.read_response()).await;
            let response = match outcome {
                Ok(Ok(response)) => response,
                Ok(Err(_)) => panic!("{name}: expected an HTTP status, got a closed stream"),
                Err(_) => panic!("{name}: proxy hung on malformed input"),
            };
            assert!(
                expected.contains(&response.head.status),
                "{name}: unexpected status {}, expected {expected:?}",
                response.head.status
            );
            if origin_delta == 0 {
                assert!(
                    response.body.is_empty(),
                    "{name}: negative corpus returned a body"
                );
            }
            if origin_delta == 1 {
                assert_eq!(
                    response.header("connection"),
                    Some("close"),
                    "{name}: CL+TE must close the input connection"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            let after = origin.requests.lock().unwrap().clone();
            assert_eq!(
                after.len(),
                before + origin_delta,
                "{name}: unexpected origin request count"
            );
            if let Some(request) = after.get(before) {
                assert_ne!(request.target, "/trap", "{name}: trap reached origin");
                assert_eq!(request.body, b"abc", "{name}: ambiguous body crossed the proxy");
            }
        }
        server.shutdown().await;
    });
}

#[test]
fn m03_http05_cl_te_closes_input_and_blocks_trap() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| {
            response("200 OK", &[], &request.body)
        })
        .await
        .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        let mut bytes = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            target(origin.address, "/cl-te-close"),
            origin.address
        )
        .into_bytes();
        bytes.extend_from_slice(
            format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                target(origin.address, "/trap"),
                origin.address
            )
            .as_bytes(),
        );
        client.send(&bytes).await.expect("send request plus trap");
        let response = client.read_response().await.expect("read first response");
        assert_eq!(response.head.status, 200);
        assert_eq!(response.header("connection"), Some("close"));
        let second = tokio::time::timeout(
            Duration::from_secs(2),
            client.read_response(),
        )
        .await
        .expect("closed connection must not hang");
        assert!(second.is_err(), "trap response unexpectedly arrived: {second:?}");
        let requests = origin.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1, "trap reached origin: {requests:?}");
        assert_eq!(requests[0].target, "/cl-te-close");
        assert_eq!(requests[0].body, b"abc");
        server.shutdown().await;
    });
}

#[test]
fn m03_http05_equal_duplicate_content_length_is_bounded() {
    runtime().block_on(async {
        let origin = spawn_origin(|request, _| response("200 OK", &[], &request.body))
            .await
            .expect("start origin");
        let (server, proxy) = start_proxy(&proxy_config()).await;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        let bytes = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
            target(origin.address, "/equal-cl"),
            origin.address
        );
        client.send(bytes.as_bytes()).await.expect("send request");
        let response = client.read_response().await.expect("read response");
        if response.head.status == 200 {
            assert_eq!(response.text(), "abc");
        } else {
            assert_eq!(response.head.status, 400);
        }
        let requests = origin.requests.lock().unwrap().clone();
        assert!(requests.len() <= 1);
        if let Some(request) = requests.first() {
            assert_eq!(request.body, b"abc");
        }
        server.shutdown().await;
    });
}
