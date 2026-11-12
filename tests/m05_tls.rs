//! M05 CONNECT authentication with a real local TLS/HTTPS site.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use common::m05::{self, AuthConfig};

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
fn m05_con01_basic_connect_tls_upload_and_download() {
    let dir = common::TempDir::new("m05-tls");
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

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        m05::write_users(&dir, &[("alice", &m05::hash("alice-secret"), false)]);
        let config = AuthConfig {
            connect_allowed_ports: port.to_string(),
            ..AuthConfig::default()
        };
        let config_path = config.write(&dir);
        let (server, addresses) = m05::start(&config_path).await;
        let proxy = m05::address(&addresses, "proxy");

        let client_script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/m04_tls_client.py"
        );
        let ca = dir.path().join("ca.pem");
        for (mode, expected) in [
            ("good", "TLS_OK"),
            ("good-upload", "TLS_UPLOAD_OK"),
            ("good-download", "TLS_DOWNLOAD_OK"),
        ] {
            let output = Command::new(python())
                .arg(client_script)
                .arg("--proxy-host")
                .arg("127.0.0.1")
                .arg("--proxy-port")
                .arg(proxy.port().to_string())
                .arg("--target-port")
                .arg(port.to_string())
                .arg("--ca")
                .arg(&ca)
                .arg("--proxy-password")
                .arg("alice-secret")
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
            assert_eq!(stdout.trim(), expected, "mode {mode}: {stderr}");
        }

        let missing = Command::new(python())
            .arg(client_script)
            .arg("--proxy-host")
            .arg("127.0.0.1")
            .arg("--proxy-port")
            .arg(proxy.port().to_string())
            .arg("--target-port")
            .arg(port.to_string())
            .arg("--ca")
            .arg(&ca)
            .arg("--mode")
            .arg("good")
            .output()
            .expect("run missing-auth TLS client");
        assert!(
            !missing.status.success(),
            "CONNECT without proxy auth unexpectedly succeeded"
        );
        assert!(
            String::from_utf8_lossy(&missing.stderr)
                .to_ascii_lowercase()
                .contains("407")
                || String::from_utf8_lossy(&missing.stderr)
                    .to_ascii_lowercase()
                    .contains("tunnel"),
            "unexpected missing-auth failure: {}",
            String::from_utf8_lossy(&missing.stderr)
        );
        server.shutdown().await;
    });
}
