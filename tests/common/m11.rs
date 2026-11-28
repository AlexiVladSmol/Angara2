//! M11 control API test helpers.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use angara::config::Config;
use angara::http::HttpServer;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::common::TempDir;
use crate::common::m05;

/// Deterministic test users file with one active account.
pub fn write_users(dir: &TempDir) -> PathBuf {
    m05::write_users(dir, &[("alice", &m05::hash("secret"), false)])
}

/// Writes an auth-enabled configuration that points at `users.toml`.
pub fn write_config(dir: &TempDir) -> PathBuf {
    let config = m05::AuthConfig::default();
    config.write(dir)
}

/// Starts the proxy with the private control reader.
pub async fn start_proxy(config_path: &Path, read_socket: &Path) -> HttpServer {
    let config = Arc::new(Config::load(config_path).expect("valid config"));
    HttpServer::bind_ephemeral_with_path_and_control(
        config,
        config_path.to_path_buf(),
        read_socket.to_path_buf(),
    )
    .await
    .expect("bind proxy and control reader")
}

/// Current effective UID for test-only admin allowances.
pub fn effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let rest = line.strip_prefix("Uid:")?;
                rest.split_whitespace().nth(1)?.parse().ok()
            })
        })
        .unwrap_or(0)
}

/// One JSON request/response over a Unix socket.
pub async fn request(socket: &Path, op: &str, args: Value) -> Value {
    let mut stream = UnixStream::connect(socket).await.expect("control connect");
    let mut request = serde_json::json!({"v": 1, "id": 1, "op": op});
    if let (Some(object), Value::Object(args)) = (request.as_object_mut(), args) {
        for (key, value) in args {
            object.insert(key, value);
        }
    }
    let line = serde_json::to_string(&request).unwrap();
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.write_all(b"\n").await.unwrap();
    stream.flush().await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(70), reader.read_line(&mut response))
        .await
        .expect("response timeout")
        .expect("response read");
    serde_json::from_str(&response).expect("JSON response")
}

/// Successful response result.
pub async fn ok(socket: &Path, op: &str, args: Value) -> Value {
    let response = request(socket, op, args).await;
    assert_eq!(response["ok"], true, "response: {response}");
    response["result"].clone()
}

/// Waits until `condition` is true.
pub async fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    condition()
}
