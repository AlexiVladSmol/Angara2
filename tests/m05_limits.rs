//! M05 resource, load and bounded-memory evidence (Linux).

#![allow(clippy::field_reassign_with_default)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::m03::{self, RawClient};
use common::m04;
use common::m05::{self, AuthConfig, RecordingVerifier, VerifierState};

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn task_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

async fn send_get(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
    user: &str,
    password: &str,
) -> u16 {
    let request = m03::request(
        "GET",
        target,
        "/",
        &[("Proxy-Authorization", &m05::authorization(user, password))],
        b"",
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&request).await.expect("send");
    client.read_response().await.expect("response").head.status
}

async fn send_connect(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
    user: &str,
    password: &str,
) -> bool {
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\n\r\n",
                m05::authorization(user, password)
            )
            .as_bytes(),
        )
        .await
        .expect("connect");
    if client.read_head().await.expect("200").status != 200 {
        return false;
    }
    client.send(b"ping").await.expect("tunnel write");
    client.read_exact_bytes(4).await.expect("echo") == b"ping"
}

static RESOURCE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn m05_res01_repeated_auth_returns_to_baseline() {
    let _serial = RESOURCE_LOCK.lock().await;
    let dir = common::TempDir::new("m05-res");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
    let config_path = AuthConfig::default().write(&dir);
    let state = Arc::new(VerifierState::default());
    let (server, addresses) = m05::start_with_verifier(
        &config_path,
        Arc::new(RecordingVerifier::accepting(
            Arc::clone(&state),
            Duration::from_millis(2),
            "secret",
        )),
    )
    .await;
    let proxy = m05::address(&addresses, "proxy");

    let fd_before = fd_count();
    let rss_before = rss_kib();
    let tasks_before = task_count();
    let mut fd_peak = fd_before;
    let mut rss_peak = rss_before;

    for _ in 0..40 {
        assert_eq!(
            send_get(proxy, origin.address, "alice", "secret").await,
            200
        );
        fd_peak = fd_peak.max(fd_count());
        rss_peak = rss_peak.max(rss_kib());
    }
    for _ in 0..40 {
        assert_eq!(send_get(proxy, origin.address, "alice", "wrong").await, 407);
    }
    for _ in 0..40 {
        assert_eq!(
            send_get(proxy, origin.address, "nobody", "wrong").await,
            407
        );
    }
    for _ in 0..40 {
        let mut client = RawClient::connect(proxy).await.expect("client");
        client
            .send(&m05::get_request(origin.address, None, &[]))
            .await
            .expect("send malformed");
        assert_eq!(client.read_response().await.expect("407").head.status, 407);
        fd_peak = fd_peak.max(fd_count());
    }

    assert!(
        m05::wait_until(Duration::from_secs(10), || {
            state.finished.load(Ordering::SeqCst) == 120
        })
        .await,
        "not all hash jobs finished: {}",
        state.finished.load(Ordering::SeqCst)
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 120);
    assert_eq!(state.running.load(Ordering::SeqCst), 0);
    assert_eq!(server.auth_available_permits(), Some(2));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let fd_after = fd_count();
    let rss_after = rss_kib();
    let tasks_after = task_count();
    eprintln!(
        "M05-RES-01 fd {fd_before}->{fd_after} peak={fd_peak}, rss_kib {rss_before}->{rss_after} peak={rss_peak}, tasks {tasks_before}->{tasks_after}, auth_calls=120"
    );
    assert!(
        fd_after <= fd_before + 8,
        "file descriptors leaked: {fd_before} -> {fd_after}"
    );
    assert!(
        rss_after <= rss_before + 16 * 1024,
        "RSS grew by more than 16 MiB: {rss_before} -> {rss_after}"
    );
    assert!(
        tasks_after <= tasks_before + 4,
        "tasks leaked: {tasks_before} -> {tasks_after}"
    );

    server.shutdown().await;
    drop(origin);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let fd_final = fd_count();
    assert!(
        fd_final <= fd_before + 2,
        "descriptors did not return to baseline: {fd_before} -> {fd_final}"
    );
}

#[tokio::test]
async fn m05_limit01_two_running_argon2_checks_do_not_scale_memory_with_attempts() {
    let _serial = RESOURCE_LOCK.lock().await;
    let dir = common::TempDir::new("m05-limit-memory");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
    let config_path = AuthConfig {
        max_verifying: 2,
        ..AuthConfig::default()
    }
    .write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");

    let rss_before = rss_kib();
    let mut rss_peak = rss_before;
    let mut requests = Vec::new();
    for _ in 0..8 {
        requests.push(tokio::spawn(async move {
            send_get(proxy, origin.address, "alice", "wrong").await
        }));
    }
    loop {
        rss_peak = rss_peak.max(rss_kib());
        if requests.iter().all(|request| request.is_finished()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut statuses = Vec::new();
    for request in requests {
        statuses.push(request.await.expect("join"));
    }
    assert!(
        statuses
            .iter()
            .all(|status| *status == 407 || *status == 503)
    );
    assert!(
        statuses.contains(&503),
        "eight simultaneous checks with max_verifying=2 must saturate: {statuses:?}"
    );
    assert_eq!(server.auth_available_permits(), Some(2));

    let rss_after = rss_kib();
    eprintln!(
        "M05-LIMIT-01 max_verifying=2 attempts=8 rss_kib {rss_before}->{rss_after} peak={rss_peak} delta_peak={}",
        rss_peak.saturating_sub(rss_before)
    );
    assert!(
        rss_peak <= rss_before + 60 * 1024,
        "two concurrent Argon2 checks used more than 60 MiB: {rss_before} -> {rss_peak}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m05_load01_ten_and_twenty_clients_mixed_http_connect() {
    let _serial = RESOURCE_LOCK.lock().await;
    let dir = common::TempDir::new("m05-load");
    let echo = m04::spawn_echo_origin(None).await.expect("echo");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(
        &dir,
        &[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ],
    );
    let mut config = AuthConfig {
        max_verifying: 2,
        ..AuthConfig::default()
    };
    config.listeners = r#"
[[listeners]]
id = "proxy"
bind = "127.0.0.1:3128"
transport = "http"
auth = "basic"

[[listeners]]
id = "second"
bind = "127.0.0.1:3129"
transport = "http"
auth = "basic"
"#
    .to_owned();
    config.connect_allowed_ports = echo.address.port().to_string();
    let config_path = config.write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");
    let second = m05::address(&addresses, "second");

    for clients in [10, 20] {
        let fd_before = fd_count();
        let rss_before = rss_kib();
        let mut rss_peak = rss_before;
        let capacity = Arc::new(tokio::sync::Semaphore::new(2));
        let started = Instant::now();
        let mut tasks = Vec::new();
        for index in 0..clients {
            let capacity = Arc::clone(&capacity);
            let listener = if index % 2 == 0 { proxy } else { second };
            let (user, password) = if index % 2 == 0 {
                ("alice", "alice-secret")
            } else {
                ("bob", "bob-secret")
            };
            tasks.push(tokio::spawn(async move {
                let _permit = capacity.acquire_owned().await.expect("capacity");
                let http = send_get(listener, origin.address, user, password).await;
                let tunnel = send_connect(listener, echo.address, user, password).await;
                (http, tunnel)
            }));
        }
        let mut http_ok = 0;
        let mut tunnel_ok = 0;
        for task in tasks {
            let (http, tunnel) = task.await.expect("join load client");
            assert_eq!(http, 200, "HTTP client failed");
            assert!(tunnel, "CONNECT client failed");
            http_ok += 1;
            tunnel_ok += 1;
            rss_peak = rss_peak.max(rss_kib());
        }
        let elapsed = started.elapsed();
        let fd_after = fd_count();
        let rss_after = rss_kib();
        eprintln!(
            "M05-LOAD-01 clients={clients} http_ok={http_ok} connect_ok={tunnel_ok} errors=0 elapsed_ms={} fd_live={fd_after} rss_kib {rss_before}->{rss_after} peak={rss_peak}",
            elapsed.as_millis()
        );
        assert_eq!(http_ok, clients);
        assert_eq!(tunnel_ok, clients);
        assert!(
            fd_after <= fd_before + 8 * clients,
            "unexpected descriptor growth during load"
        );
    }
    assert_eq!(echo.accepts.load(Ordering::SeqCst), 30);
    assert!(
        origin.accepts.load(Ordering::SeqCst) >= 2,
        "each authenticated user/listener must use its own origin pool key"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m05_load01_overload_is_503_and_recovers_without_retries() {
    let _serial = RESOURCE_LOCK.lock().await;
    let dir = common::TempDir::new("m05-load-overload");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
    let config_path = AuthConfig {
        max_verifying: 1,
        ..AuthConfig::default()
    }
    .write(&dir);
    let state = Arc::new(VerifierState::default());
    let (server, addresses) = m05::start_with_verifier(
        &config_path,
        Arc::new(RecordingVerifier::accepting(
            Arc::clone(&state),
            Duration::from_millis(150),
            "secret",
        )),
    )
    .await;
    let proxy = m05::address(&addresses, "proxy");

    let mut tasks = Vec::new();
    for _ in 0..8 {
        tasks.push(tokio::spawn(async move {
            send_get(proxy, origin.address, "alice", "secret").await
        }));
    }
    let mut ok = 0;
    let mut busy = 0;
    for task in tasks {
        match task.await.expect("join") {
            200 => ok += 1,
            503 => busy += 1,
            other => panic!("unexpected overload status {other}"),
        }
    }
    assert!(busy >= 6, "overload must not queue behind the budget");
    assert_eq!(ok, 1);
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    assert!(
        m05::wait_until(Duration::from_secs(5), || {
            state.finished.load(Ordering::SeqCst) == 1
        })
        .await
    );
    assert_eq!(
        send_get(proxy, origin.address, "alice", "secret").await,
        200,
        "a fresh request must succeed after the budget is released"
    );
    assert_eq!(
        send_get(proxy, origin.address, "alice", "wrong").await,
        407,
        "a well-formed wrong password must be reported as 407"
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 3);
    eprintln!(
        "M05-LOAD-01 overload max_verifying=1 attempts=8 ok=1 busy=6+ wrong=1 errors=0 retries=0"
    );
    server.shutdown().await;
}
