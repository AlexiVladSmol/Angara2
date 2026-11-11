//! M04 TLS-through-CONNECT integration (M04-CON-05).

mod common;

use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use angara::config::Config;
use angara::http::HttpServer;
use angara::resolver::{ResolveFuture, Resolver};
use angara::transport::TcpDialer;
use common::m03::*;
use tokio::runtime::{Builder, Runtime};

fn runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build test runtime")
}

struct LoopbackResolver;

impl Resolver for LoopbackResolver {
    fn resolve<'a>(&'a self, _host: &'a str, _deadline: std::time::Instant) -> ResolveFuture<'a> {
        Box::pin(async { Ok(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]) })
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn python() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
}

#[test]
fn m04_con05_tls_handshake_and_certificate_validation_through_tunnel() {
    let dir = common::TempDir::new("m04-tls");
    let site_script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/m04_tls_site.py"
    );
    let mut site = Command::new(python())
        .arg(site_script)
        .arg("--dir")
        .arg(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start TLS fixture");
    let stdout = site.stdout.take().expect("fixture stdout");
    let mut reader = BufReader::new(stdout);
    let mut port_line = String::new();
    reader
        .read_line(&mut port_line)
        .expect("read TLS fixture port");
    let port = port_line
        .trim()
        .strip_prefix("PORT=")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("bad TLS fixture port line: {port_line:?}"));
    let _site = ChildGuard(site);

    runtime().block_on(async {
        let text = format!(
            "{}\n[connect]\nallowed_ports = [{port}]\nhalf_close_timeout_ms = 1000\n",
            config("127.0.0.1:3128")
        );
        let config = Arc::new(Config::parse(&text).expect("valid TLS config"));
        let server = HttpServer::bind_ephemeral_with_components(
            config,
            Arc::new(LoopbackResolver),
            Arc::new(TcpDialer),
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;

        let client_script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/m04_tls_client.py"
        );
        let ca = dir.path().join("ca.pem");
        for mode in ["good", "wrong-name", "wrong-ca"] {
            let output = Command::new(python())
                .arg(client_script)
                .arg("--proxy-host")
                .arg("127.0.0.1")
                .arg("--proxy-port")
                .arg(proxy.port().to_string())
                .arg("--target-host")
                .arg("localhost")
                .arg("--target-port")
                .arg(port.to_string())
                .arg("--ca")
                .arg(&ca)
                .arg("--mode")
                .arg(mode)
                .output()
                .expect("run TLS client");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "mode {mode} failed: status={:?} stdout={stdout} stderr={stderr}",
                output.status
            );
            match mode {
                "good" => assert_eq!(stdout.trim(), "TLS_OK", "{stderr}"),
                _ => assert_eq!(stdout.trim(), "TLS_REJECTED", "{stderr}"),
            }
        }
        server.shutdown().await;
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m04_con05_real_curl_https_smoke_without_k() {
    let dir = common::TempDir::new("m04-curl-tls");
    let site_script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/m04_tls_site.py"
    );
    let mut site = Command::new(python())
        .arg(site_script)
        .arg("--dir")
        .arg(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start TLS fixture");
    let stdout = site.stdout.take().expect("fixture stdout");
    let mut reader = BufReader::new(stdout);
    let mut port_line = String::new();
    reader.read_line(&mut port_line).expect("read fixture port");
    let port = port_line
        .trim()
        .strip_prefix("PORT=")
        .and_then(|value| value.parse::<u16>().ok())
        .expect("fixture port");
    let _site = ChildGuard(site);

    runtime().block_on(async {
        let text = format!(
            "{}\n[connect]\nallowed_ports = [{port}]\nhalf_close_timeout_ms = 1000\n",
            config("127.0.0.1:3128")
        );
        let config = Arc::new(Config::parse(&text).expect("valid TLS config"));
        let server = HttpServer::bind_ephemeral_with_components(
            config,
            Arc::new(LoopbackResolver),
            Arc::new(TcpDialer),
        )
        .await
        .expect("bind proxy");
        let proxy = server.addresses()[0].1;
        let output = Command::new("curl")
            .arg("--silent")
            .arg("--show-error")
            .arg("--noproxy")
            .arg("")
            .arg("--proxy")
            .arg(format!("http://127.0.0.1:{}", proxy.port()))
            .arg("--cacert")
            .arg(dir.path().join("ca.pem"))
            .arg(format!("https://localhost:{port}/"))
            .output()
            .expect("run curl");
        assert!(
            output.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), "tls-ok");
        server.shutdown().await;
    });
}
