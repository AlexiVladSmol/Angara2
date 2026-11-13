//! M07 real SIGHUP/SIGTERM lifecycle test (Linux/Unix).

#![cfg(unix)]

mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("free port")
        .local_addr()
        .expect("address")
        .port()
}

fn origin() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin bind");
    let port = listener.local_addr().expect("origin addr").port();
    let handle = thread::spawn(move || {
        for stream in listener.incoming().take(2048) {
            let Ok(mut stream) = stream else {
                return;
            };
            let mut buffer = vec![0_u8; 4096];
            let _ = stream.read(&mut buffer);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (port, handle)
}

fn config(proxy_port: u16, origin_port: u16, rule_port: u16) -> String {
    format!(
        r#"
schema_version = 1
[runtime]
worker_threads = 2
[limits]
max_connections = 16
max_client_connections = 8
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 1500
[operations]
reload_timeout_ms = 3000
[observability]
log_level = "off"
metrics_enabled = false
[[listeners]]
id = "proxy"
bind = "127.0.0.1:{proxy_port}"
transport = "http"
auth = "none"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"
[[access.rules]]
id = "allow"
action = "allow"
ports = [{rule_port}]
[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
[connect]
allowed_ports = [{origin_port}]
"#
    )
}

fn config_logged(proxy_port: u16, origin_port: u16) -> String {
    config(proxy_port, origin_port, origin_port)
        .replace(
            "log_level = \"off\"",
            "log_level = \"info\"\nlog_queue_capacity = 64",
        )
        .replace("metrics_enabled = false", "metrics_enabled = true")
}

fn wait_with_deadline(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("serve did not exit within {timeout:?}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn request(proxy_port: u16, origin_port: u16) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("proxy connect");
    write!(
        stream,
        "GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
    )
    .expect("request write");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    text.split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn kill(child: &Child, signal: &str) {
    let status = Command::new("kill")
        .arg(signal)
        .arg(child.id().to_string())
        .status()
        .expect("kill command");
    assert!(status.success(), "kill {signal}");
}

#[test]
fn cli_m07_sighup_applies_and_sigterm_stops_within_deadline() {
    let dir = common::TempDir::new("m07-signal");
    let proxy_port = free_port();
    let (origin_port, origin_thread) = origin();
    let path = dir.path().join("proxy.toml");
    fs::write(&path, config(proxy_port, origin_port, origin_port)).expect("config");
    let child = Command::new(env!("CARGO_BIN_EXE_angara"))
        .arg("serve")
        .arg("--config")
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    let mut child = ChildGuard(child);

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if request(proxy_port, origin_port) == 200 {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(request(proxy_port, origin_port), 200);

    fs::write(&path, config(proxy_port, origin_port, 1)).expect("reload config");
    kill(&child.0, "-HUP");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut applied = false;
    while Instant::now() < deadline {
        if request(proxy_port, origin_port) == 403 {
            applied = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(applied, "SIGHUP did not apply the ACL change");

    let started = Instant::now();
    kill(&child.0, "-TERM");
    let status = child.0.wait().expect("wait serve");
    assert!(status.success(), "serve exit: {status}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "SIGTERM exceeded the absolute deadline: {:?}",
        started.elapsed()
    );
    drop(origin_thread);
}

#[test]
fn cli_m07_stalled_stderr_pipe_does_not_extend_sigterm_deadline() {
    let dir = common::TempDir::new("m07-stalled-log");
    let proxy_port = free_port();
    let (origin_port, origin_thread) = origin();
    let path = dir.path().join("proxy.toml");
    fs::write(&path, config_logged(proxy_port, origin_port)).expect("config");
    let child = Command::new(env!("CARGO_BIN_EXE_angara"))
        .arg("serve")
        .arg("--config")
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if request(proxy_port, origin_port) == 200 {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(request(proxy_port, origin_port), 200);

    // Fill the bounded logger queue and the OS stderr pipe. The parent never
    // reads the pipe; the data plane must continue and SIGTERM must not join
    // the blocked writer.
    for _ in 0..400 {
        assert_eq!(request(proxy_port, origin_port), 200);
    }

    let started = Instant::now();
    kill(&child.0, "-TERM");
    let status = wait_with_deadline(&mut child.0, Duration::from_secs(4));
    assert!(status.success(), "serve exit: {status}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "stalled stderr extended shutdown: {:?}",
        started.elapsed()
    );
    drop(origin_thread);
}

#[cfg(target_os = "linux")]
#[test]
fn cli_m07_sighup_storm_is_coalesced_and_bounded() {
    let dir = common::TempDir::new("m07-hup-storm");
    let proxy_port = free_port();
    let (origin_port, origin_thread) = origin();
    let path = dir.path().join("proxy.toml");
    fs::write(&path, config(proxy_port, origin_port, origin_port)).expect("config");
    let child = Command::new(env!("CARGO_BIN_EXE_angara"))
        .arg("serve")
        .arg("--config")
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if request(proxy_port, origin_port) == 200 {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(request(proxy_port, origin_port), 200);
    let threads_before = linux_threads(child.0.id());
    for _ in 0..100 {
        kill(&child.0, "-HUP");
    }
    thread::sleep(Duration::from_millis(500));
    assert!(
        child.0.try_wait().expect("try_wait").is_none(),
        "serve died during HUP storm"
    );
    assert_eq!(request(proxy_port, origin_port), 200);
    let threads_after = linux_threads(child.0.id());
    assert!(
        threads_after <= threads_before + 4,
        "HUP storm grew threads {threads_before} -> {threads_after}"
    );
    kill(&child.0, "-TERM");
    let status = wait_with_deadline(&mut child.0, Duration::from_secs(4));
    assert!(status.success(), "serve exit: {status}");
    drop(origin_thread);
}

#[cfg(target_os = "linux")]
fn linux_threads(pid: u32) -> usize {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Threads:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}
