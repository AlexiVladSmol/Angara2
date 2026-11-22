//! Temporary M04 spike: hyper 1.12 CONNECT handoff through SplitIo/writer_loop.

mod common;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use angara::http::ConnectionOutput;
use angara::http::interim::{InterimHub, SplitIo, writer_loop};
use common::m03::*;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn m04_spike_connect_upgrade_preserves_early_and_origin_first_bytes() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
        let origin_address = origin.local_addr().expect("origin addr");
        tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.expect("origin accept");
            stream.write_all(b"origin-first").await.expect("greeting");
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await.expect("origin read");
                if read == 0 {
                    break;
                }
                stream.write_all(&buffer[..read]).await.expect("echo");
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy bind");
        let proxy = listener.local_addr().expect("proxy addr");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("proxy accept");
            let output = ConnectionOutput::new();
            let tunnel = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let progress = angara::http::connect::TunnelProgress::new();
            let (io, write_half, bridge_reader) = SplitIo::with_tunnel_flag(
                stream,
                Duration::from_secs(5),
                output.clone(),
                Arc::clone(&tunnel),
            );
            let idle_state = io.idle_state();
            let (_hub, interim_rx) = InterimHub::new("test".to_owned());
            let writer = writer_loop(
                write_half,
                bridge_reader,
                interim_rx,
                Duration::from_secs(5),
                idle_state,
                None,
                output.clone(),
                tunnel,
                progress,
            );
            let service = service_fn(move |mut request| async move {
                let on_upgrade = hyper::upgrade::on(&mut request);
                let origin = TcpStream::connect(origin_address)
                    .await
                    .expect("origin connect");
                tokio::spawn(async move {
                    let upgraded = on_upgrade.await.expect("upgrade");
                    let mut client = TokioIo::new(upgraded);
                    let mut origin = origin;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut origin).await;
                });
                Ok::<_, Infallible>(
                    hyper::Response::builder()
                        .status(200)
                        .body(String::new())
                        .expect("response"),
                )
            });
            let connection = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(io), service)
                .with_upgrades();
            let _ = connection.await;
            let _ = writer.await;
        });

        let mut client = RawClient::connect(proxy).await.expect("client");
        client
            .send(
                format!("CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n\r\nEARLY")
                    .as_bytes(),
            )
            .await
            .expect("send connect");
        let head = client.read_head().await.expect("read 200");
        assert_eq!(head.status, 200);
        assert!(head.header("content-length").is_none());
        assert!(head.header("transfer-encoding").is_none());
        let raw = client.read_exact_bytes(12).await.expect("origin greeting");
        assert_eq!(&raw, b"origin-first");
        let echo = client.read_exact_bytes(5).await.expect("echo early");
        assert_eq!(&echo, b"EARLY");
    });
}
