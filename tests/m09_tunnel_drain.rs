//! Issue #52: a CONNECT relay that fails after reading bytes from the parent
//! must still deliver those bytes to the client (D64).

mod common;
mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use angara::config::{Config, LogLevel};
use angara::http::HttpServer;
use angara::logging::Logger;
use angara::transport::TcpDialer;
use tokio_rustls::TlsAcceptor;

use common::m03::{self, RawClient};
use common::m09::{self, TlsParentClose};
use common::{TempDir, m04, m06};
use support::ScriptedResolver;

fn tls_parent_config(dir: &TempDir, parent: SocketAddr, connect_port: u16) -> String {
    let ca = dir.path().join("proxy_ca.pem");
    let mut text = m03::config("127.0.0.1:3128");
    text.push_str(&format!(
        r#"
[[parents]]
id = "parent"
endpoint = "127.0.0.1:{}"
transport = "https"
ca_file = "{}"

[routing]
default_egress = "system"
default_parent = "parent"

[connect]
allowed_ports = [{}]
"#,
        parent.port(),
        ca.display(),
        connect_port
    ));
    text
}

async fn start(text: &str) -> (HttpServer, SocketAddr) {
    let config = Arc::new(Config::parse(text).expect("proxy config"));
    let resolver = Arc::new(ScriptedResolver::new(Vec::new()));
    let server = HttpServer::bind_ephemeral_with_components(
        config,
        resolver as Arc<dyn angara::resolver::Resolver>,
        Arc::new(TcpDialer),
    )
    .await
    .expect("bind proxy");
    let address = server.addresses()[0].1;
    (server, address)
}

fn receive_event(receiver: &std::sync::mpsc::Receiver<String>, event: &str) -> serde_json::Value {
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

/// The parent sends `payload` bytes and drops TLS without close_notify before
/// the client ends its side, so the relay ends as `Io`. The client starts
/// reading only after a pause, so the relay reaches the error while the client
/// bridge still holds bytes. The client must still receive every relayed byte;
/// the outcome stays failed/error.
async fn assert_error_drain_delivers(payload: usize) {
    let dir = TempDir::new("m09-tls-error-drain");
    m06::generate_pki(dir.path());
    let acceptor = TlsAcceptor::from(m06::server_config(
        &dir.path().join("proxy_ip_chain.pem"),
        &dir.path().join("proxy_ip_key.pem"),
    ));
    let parent = m09::spawn_one_shot_tls_parent(
        acceptor,
        TlsParentClose::SendThenDropWithoutCloseNotify(payload),
    )
    .await
    .expect("TLS parent");
    let target = m04::spawn_echo_origin(None).await.expect("echo");
    let text = tls_parent_config(&dir, parent.address, target.address.port());
    let (server, proxy) = start(&text).await;
    let telemetry = server.telemetry();
    let (logger, receiver) = Logger::channel(128, LogLevel::Info, telemetry);
    server.set_logger(logger);

    let mut client = RawClient::connect(proxy).await.expect("connect proxy");
    let authority = target.address.to_string();
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.send(request.as_bytes()).await.expect("send CONNECT");
    assert_eq!(client.read_head().await.expect("head").status, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let received = client.read_until_eof().await.expect("tunnel bytes");

    let record = receive_event(&receiver, "tunnel_finished");
    assert_eq!(record["outcome"], "failed");
    assert_eq!(record["reason"], "error");
    assert_eq!(record["tunnel_bytes"], payload as u64);
    assert_eq!(received.len(), payload, "client lost relayed bytes");
    assert!(
        received == m09::tls_parent_payload(payload),
        "relayed bytes differ from the parent payload"
    );

    server.shutdown().await;
}

/// 128 KiB fits in the loopback buffers, so the parent queues the payload and
/// its FIN before the client reads; this case detects the original defect on
/// every run.
#[tokio::test]
async fn m09_tunnel_drain01_tls_parent_error_delivers_relayed_bytes() {
    assert_error_drain_delivers(128 * 1024).await;
}

/// The 256 KiB size from Issue #52. The parent may still be blocked on socket
/// buffers when the client starts reading, so on the unfixed code this case
/// fails only in most runs; it guards the larger transfer, while drain01 is
/// the deterministic detector.
#[tokio::test]
async fn m09_tunnel_drain02_tls_parent_error_delivers_256k() {
    assert_error_drain_delivers(256 * 1024).await;
}
