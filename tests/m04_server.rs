//! M04 shutdown/lifecycle tests (M04-SRV-01).

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use angara::config::Config;
use angara::http::HttpServer;
use common::m03::*;
use tokio::runtime::Builder;

fn connect_config(port: u16) -> String {
    format!(
        "{}\n[connect]\nallowed_ports = [{port}]\nhalf_close_timeout_ms = 500\n",
        config("127.0.0.1:3128").replace("shutdown_timeout_ms = 2000", "shutdown_timeout_ms = 1")
    )
}

fn spawn_holding_tunnel_origin() -> (
    std::net::SocketAddr,
    mpsc::Receiver<std::net::TcpStream>,
    mpsc::Sender<()>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let address = listener.local_addr().expect("origin address");
    let (stream_tx, stream_rx) = mpsc::channel();
    let (hold_tx, hold_rx) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept proxy");
        stream
            .write_all(b"origin-greeting")
            .expect("write greeting");
        stream.flush().expect("flush greeting");
        stream_tx
            .send(stream.try_clone().expect("clone origin stream"))
            .expect("send origin stream");
        let _ = hold_rx.recv_timeout(Duration::from_secs(5));
        let mut buffer = [0_u8; 1];
        let _ = stream.read(&mut buffer);
    });
    (address, stream_rx, hold_tx, handle)
}

#[test]
fn m04_srv01_forced_shutdown_reclaims_active_tunnel_tasks() {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async {
        let baseline = runtime.metrics().num_alive_tasks();
        for cycle in 0..3 {
            let (origin, stream_rx, hold_tx, thread) = spawn_holding_tunnel_origin();
            let config = Arc::new(Config::parse(&connect_config(origin.port())).expect("config"));
            let server = HttpServer::bind_ephemeral(config)
                .await
                .expect("bind proxy");
            let proxy = server.addresses()[0].1;
            let mut client = RawClient::connect(proxy).await.expect("connect proxy");
            client
                .send(format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes())
                .await
                .expect("send connect");
            assert_eq!(client.read_head().await.expect("read 200").status, 200);
            let origin_stream = stream_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("origin accepted");

            let started = Instant::now();
            if cycle == 2 {
                drop(server);
            } else {
                server.shutdown().await;
            }
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_millis(500),
                "cycle {cycle}: shutdown took {elapsed:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            origin_stream
                .set_nonblocking(true)
                .expect("nonblocking origin");
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut byte = [0_u8; 1];
            loop {
                match origin_stream.try_clone().expect("clone").read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "cycle {cycle}: origin did not see EOF"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        // Forced shutdown may close the TCP socket with RST
                        // instead of FIN on some kernels. The read error is a
                        // valid observed close only because the server has
                        // already returned from its absolute shutdown path.
                        break;
                    }
                    Err(error) => panic!("origin read failed: {error}"),
                }
            }
            drop(client);
            drop(origin_stream);
            drop(hold_tx);
            thread.join().expect("origin thread");
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
                "cycle {cycle}: tasks remained after shutdown"
            );
        }
    });
}

struct PendingDialer {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl angara::transport::Dialer for PendingDialer {
    fn connect<'a>(
        &'a self,
        _endpoint: std::net::SocketAddr,
        _egress: &'a angara::config::EgressProfile,
        _deadline: std::time::Instant,
    ) -> angara::transport::DialFuture<'a> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Box::pin(async {
            std::future::pending::<Result<tokio::net::TcpStream, angara::transport::DialError>>()
                .await
        })
    }
}

#[test]
fn m04_srv01_shutdown_cancels_pending_dial() {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async {
        let baseline = runtime.metrics().num_alive_tasks();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let config = Arc::new(Config::parse(&connect_config(443)).expect("config"));
        let server = HttpServer::bind_ephemeral_with_components(
            config,
            Arc::new(PendingResolver),
            Arc::new(PendingDialer {
                calls: Arc::clone(&calls),
            }),
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;
        let mut client = RawClient::connect(proxy).await.expect("connect proxy");
        client
            .send(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
            .await
            .expect("send connect");
        for _ in 0..200 {
            if calls.load(std::sync::atomic::Ordering::Acquire) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Acquire), 1);
        let started = Instant::now();
        server.shutdown().await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "shutdown with pending dial took {elapsed:?}"
        );
        drop(client);
        let mut alive = runtime.metrics().num_alive_tasks();
        for _ in 0..200 {
            if alive == baseline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            alive = runtime.metrics().num_alive_tasks();
        }
        assert_eq!(alive, baseline);
    });
}

struct PendingResolver;

impl angara::resolver::Resolver for PendingResolver {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
        _deadline: std::time::Instant,
    ) -> angara::resolver::ResolveFuture<'a> {
        Box::pin(async { Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]) })
    }
}
