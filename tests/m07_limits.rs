//! M07 resource and load evidence (Linux).

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use angara::config::{Config, LogLevel};
use angara::control::ReloadOutcome;
use angara::http::HttpServer;
use angara::logging::{Event, LogRecord, Logger};
use angara::runtime::AngaraRuntime;
use common::TempDir;
use common::m03::{self, RawClient};
use common::m04;
use common::m05;
use common::m06;
use tokio::sync::Semaphore;

// Resource evidence tests intentionally serialize when the binary is run with
// the default parallel harness; CI also runs this target with --test-threads=1.
static HEAVY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn task_count() -> usize {
    fs::read_dir("/proc/self/task")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn rss_kib() -> u64 {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

fn threads() -> usize {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Threads:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn config(_dir: &std::path::Path, port: u16, origin_port: u16, users: &std::path::Path) -> String {
    format!(
        r#"
schema_version = 1
[runtime]
worker_threads = 2
[limits]
max_connections = 64
max_client_connections = 32
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 2000
[operations]
reload_timeout_ms = 1000
[observability]
log_level = "off"
log_queue_capacity = 64
metrics_enabled = true
metrics_interval_ms = 1000
[auth]
users_file = "{}"
max_verifying = 2
verify_timeout_ms = 2000
[[listeners]]
id = "proxy"
bind = "127.0.0.1:{port}"
transport = "http"
auth = "basic"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"
[[access.rules]]
id = "allow"
action = "allow"
users = ["alice", "bob"]
ports = [{origin_port}]
[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
[transport]
total_timeout_ms = 5000
connect_timeout_ms = 2000
max_connect_attempts = 2
max_connecting = 8
[http]
max_headers = 64
response_header_timeout_ms = 5000
pool_max_idle = 8
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 2000
[connect]
allowed_ports = [{origin_port}]
half_close_timeout_ms = 1000
"#,
        users.to_string_lossy().replace('\\', "/")
    )
}

async fn start(
    dir: &std::path::Path,
    port: u16,
    origin: u16,
    users: &std::path::Path,
) -> (HttpServer, std::net::SocketAddr, std::path::PathBuf) {
    let path = dir.join("proxy.toml");
    fs::write(&path, config(dir, port, origin, users)).expect("config");
    let config = Arc::new(Config::load(&path).expect("load"));
    let server = HttpServer::bind_ephemeral_with_path(config, path.clone())
        .await
        .expect("bind");
    let address = server.addresses()[0].1;
    (server, address, path)
}

fn dual_config(
    dir: &std::path::Path,
    http_port: u16,
    connect_port: u16,
    users: &std::path::Path,
) -> String {
    format!(
        r#"
schema_version = 1
[runtime]
worker_threads = 2
[limits]
max_connections = 64
max_client_connections = 64
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 2000
[operations]
reload_timeout_ms = 1000
[observability]
log_level = "off"
log_queue_capacity = 64
metrics_enabled = true
metrics_interval_ms = 1000
[auth]
users_file = "{}"
max_verifying = 2
verify_timeout_ms = 2000
[[listeners]]
id = "proxy-http"
bind = "127.0.0.1:3128"
transport = "http"
auth = "basic"
[[listeners]]
id = "proxy-https"
bind = "127.0.0.1:3129"
transport = "https"
auth = "basic"
[listeners.tls]
cert_chain_file = "{}"
private_key_file = "{}"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"
[[access.rules]]
id = "allow"
action = "allow"
users = ["alice", "bob"]
ports = [{http_port}, {connect_port}]
[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
[transport]
total_timeout_ms = 5000
connect_timeout_ms = 2000
max_connect_attempts = 2
max_connecting = 8
[http]
max_headers = 64
response_header_timeout_ms = 5000
pool_max_idle = 8
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 2000
[connect]
allowed_ports = [{connect_port}]
half_close_timeout_ms = 1000
"#,
        users.to_string_lossy().replace('\\', "/"),
        dir.join("proxy_chain.pem")
            .to_string_lossy()
            .replace('\\', "/"),
        dir.join("proxy_key.pem")
            .to_string_lossy()
            .replace('\\', "/"),
    )
}

async fn start_dual(
    dir: &std::path::Path,
    http_port: u16,
    connect_port: u16,
    users: &std::path::Path,
) -> (
    HttpServer,
    std::net::SocketAddr,
    std::net::SocketAddr,
    std::path::PathBuf,
) {
    let path = dir.join("proxy.toml");
    fs::write(&path, dual_config(dir, http_port, connect_port, users)).expect("dual config");
    let config = Arc::new(Config::load(&path).expect("load dual"));
    let server = HttpServer::bind_ephemeral_with_path(config, path.clone())
        .await
        .expect("bind dual");
    let addresses = server.addresses();
    assert_eq!(addresses.len(), 2);
    let http_address = addresses[0].1;
    let https_address = addresses[1].1;
    (server, http_address, https_address, path)
}

async fn one(
    address: std::net::SocketAddr,
    origin: std::net::SocketAddr,
    user: &str,
    password: &str,
) -> u16 {
    let auth = m05::authorization(user, password);
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&m03::request(
            "GET",
            origin,
            "/",
            &[("Proxy-Authorization", &auth)],
            b"",
        ))
        .await
        .expect("send");
    client.read_response().await.expect("response").head.status
}

#[tokio::test]
async fn m07_res01_hundred_reload_attempts_and_queues_are_bounded() {
    let _heavy = HEAVY.lock().await;
    let dir = TempDir::new("m07-res01");
    m05::write_secure(
        &dir.path().join("users.toml"),
        &m05::users_text(&[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ]),
    );
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"res"))
        .await
        .expect("origin");
    let port = m03::free_port();
    let (server, _, path) = start(
        dir.path(),
        port,
        origin.address.port(),
        &dir.path().join("users.toml"),
    )
    .await;
    let control = server.control();
    let fd0 = fd_count();
    let rss0 = rss_kib();
    let tasks0 = task_count();
    let threads0 = threads();
    let mut fd_peak = fd0;
    let mut rss_peak = rss0;
    let valid = fs::read_to_string(&path).expect("read config");

    for index in 0..100u64 {
        if index % 2 == 0 {
            let result = control.reload(control.status().generation).await;
            assert!(matches!(result, ReloadOutcome::Applied { .. }));
        } else {
            fs::write(&path, "not = [valid").expect("invalid");
            let result = control.reload(control.status().generation).await;
            assert!(matches!(result, ReloadOutcome::Invalid { .. }));
            fs::write(&path, &valid).expect("restore");
        }
        fd_peak = fd_peak.max(fd_count());
        rss_peak = rss_peak.max(rss_kib());
    }
    assert_eq!(control.status().generation, 51);
    assert!(control.metrics().reload_attempts >= 100);
    assert_eq!(control.metrics().reload_applied, 50);
    assert_eq!(control.metrics().reload_invalid, 50);

    let telemetry = server.telemetry();
    let (logger, receiver) = Logger::channel(64, LogLevel::Info, telemetry);
    for _ in 0..1_000 {
        logger.log(LogRecord::new(Event::RequestFinished));
    }
    assert!(receiver.try_recv().is_ok());
    assert!(server.telemetry().snapshot().log_dropped > 0);

    let fd1 = fd_count();
    let rss1 = rss_kib();
    let tasks1 = task_count();
    let threads1 = threads();
    eprintln!(
        "M07-RES-01 reloads=100 fd={fd0}->{fd1} peak={fd_peak} rss={rss0}->{rss1} peak={rss_peak} tasks={tasks0}->{tasks1} threads={threads0}->{threads1}"
    );
    assert!(fd1 <= fd0 + 16);
    assert!(rss1 <= rss0 + 32 * 1024);
    assert!(tasks1 <= tasks0 + 8);
    assert!(threads1 <= threads0 + 4);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_load01_10_20_clients_with_reloads() {
    let _heavy = HEAVY.lock().await;
    let dir = TempDir::new("m07-load01");
    m05::write_secure(
        &dir.path().join("users.toml"),
        &m05::users_text(&[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ]),
    );
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"load"))
        .await
        .expect("origin");
    let port = m03::free_port();
    let (server, address, _) = start(
        dir.path(),
        port,
        origin.address.port(),
        &dir.path().join("users.toml"),
    )
    .await;
    let control = server.control();
    for clients in [10usize, 20] {
        let started = Instant::now();
        let capacity = Arc::new(Semaphore::new(2));
        let mut tasks = Vec::new();
        for index in 0..clients {
            let permit = capacity.clone();
            let (user, password) = if index % 2 == 0 {
                ("alice", "alice-secret")
            } else {
                ("bob", "bob-secret")
            };
            tasks.push(tokio::spawn(async move {
                let _permit = permit.acquire_owned().await.expect("permit");
                one(address, origin.address, user, password).await
            }));
        }
        let mut reloads = 0;
        for task in tasks {
            assert_eq!(task.await.expect("join"), 200);
            if reloads < 20 {
                assert!(matches!(
                    control.reload(control.status().generation).await,
                    ReloadOutcome::Applied { .. }
                ));
                reloads += 1;
            }
        }
        eprintln!(
            "M07-LOAD-01 clients={clients} ok={clients} reloads={reloads} elapsed_ms={} fd={} rss_kib={} tasks={}",
            started.elapsed().as_millis(),
            fd_count(),
            rss_kib(),
            task_count()
        );
    }
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m07_load02_dual_listener_http_https_connect_with_reloads() {
    let _heavy = HEAVY.lock().await;
    let dir = TempDir::new("m07-load02");
    m06::generate_pki(dir.path());
    let users = dir.path().join("users.toml");
    m05::write_secure(
        &users,
        &m05::users_text(&[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ]),
    );
    let http_origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"load"))
        .await
        .expect("http origin");
    let echo = m04::spawn_echo_origin(None).await.expect("echo origin");
    let (server, http_address, https_address, _) = start_dual(
        dir.path(),
        http_origin.address.port(),
        echo.address.port(),
        &users,
    )
    .await;
    let control = server.control();
    let tls_config = m06::client_config(&m06::proxy_ca(dir.path()));
    let auth_gate = Arc::new(Semaphore::new(2));

    for clients in [10usize, 20] {
        let started = Instant::now();
        let mut tasks = Vec::new();
        for index in 0..clients {
            let (user, password) = if index % 2 == 0 {
                ("alice", "alice-secret")
            } else {
                ("bob", "bob-secret")
            };
            if index % 5 == 4 {
                let config = Arc::clone(&tls_config);
                let gate = Arc::clone(&auth_gate);
                let origin = echo.address;
                tasks.push(tokio::spawn(async move {
                    let _permit = gate.acquire_owned().await.expect("auth gate");
                    let auth = m05::authorization(user, password);
                    let mut client = m06::connect_tls(https_address, "localhost", config)
                        .await
                        .expect("tls connect");
                    client
                        .send(
                            format!(
                                "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\nProxy-Authorization: {auth}\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .await
                        .expect("CONNECT");
                    assert_eq!(client.read_head().await.expect("200").status, 200);
                    client.send(b"ping").await.expect("tunnel write");
                    assert_eq!(
                        client.read_exact_bytes(4).await.expect("tunnel echo"),
                        b"ping"
                    );
                    200u16
                }));
            } else if index % 2 == 0 {
                let gate = Arc::clone(&auth_gate);
                tasks.push(tokio::spawn(async move {
                    let _permit = gate.acquire_owned().await.expect("auth gate");
                    one(http_address, http_origin.address, user, password).await
                }));
            } else {
                let config = Arc::clone(&tls_config);
                let gate = Arc::clone(&auth_gate);
                let origin = http_origin.address;
                tasks.push(tokio::spawn(async move {
                    let _permit = gate.acquire_owned().await.expect("auth gate");
                    let auth = m05::authorization(user, password);
                    let mut client = m06::connect_tls(https_address, "localhost", config)
                        .await
                        .expect("tls connect");
                    client
                        .send(&m03::request(
                            "GET",
                            origin,
                            "/",
                            &[("Proxy-Authorization", &auth), ("Connection", "close")],
                            b"",
                        ))
                        .await
                        .expect("https GET");
                    client
                        .read_response()
                        .await
                        .expect("https response")
                        .head
                        .status
                }));
            }
        }

        // Let the cohort enter TLS/auth/HTTP before applying the reload burst.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut reloads = 0;
        for _ in 0..20 {
            let generation = control.status().generation;
            assert!(matches!(
                control.reload(generation).await,
                ReloadOutcome::Applied { .. }
            ));
            reloads += 1;
        }
        for task in tasks {
            assert_eq!(task.await.expect("join"), 200);
        }
        eprintln!(
            "M07-LOAD-02 clients={clients} ok={clients} reloads={reloads} elapsed_ms={} fd={} rss_kib={} tasks={} threads={}",
            started.elapsed().as_millis(),
            fd_count(),
            rss_kib(),
            task_count(),
            threads()
        );
    }
    assert!(control.metrics().reload_applied >= 40);
    server.shutdown().await;
}

#[test]
fn m07_cpu01_workers_are_actual_and_reload_does_not_block_independent_http() {
    let _heavy = HEAVY.blocking_lock();
    let dir = TempDir::new("m07-cpu01");
    m05::write_secure(
        &dir.path().join("users.toml"),
        &m05::users_text(&[("alice", &m05::hash("alice-secret"), false)]),
    );
    let path = dir.path().join("proxy.toml");
    for workers in [1u32, 2] {
        let text = config(dir.path(), 3128, 443, &dir.path().join("users.toml"))
            .replace("worker_threads = 2", &format!("worker_threads = {workers}"));
        fs::write(&path, text).expect("cpu config");
        let config = Config::load(&path).expect("cpu load");
        let runtime = AngaraRuntime::build(&config).expect("runtime");
        assert_eq!(runtime.worker_threads(), workers as usize);
        assert_eq!(runtime.metrics_worker_threads(), workers as usize);
        runtime.shutdown();
    }

    let runtime = AngaraRuntime::build(&{
        let text = config(dir.path(), 3128, 443, &dir.path().join("users.toml"))
            .replace("worker_threads = 2", "worker_threads = 1");
        fs::write(&path, text).expect("cpu single config");
        Config::load(&path).expect("cpu single load")
    })
    .expect("runtime");
    let users = dir.path().join("users.toml");
    runtime.block_on(async {
        let slow = m04::spawn_slow_http_origin(Duration::from_millis(3000))
            .await
            .expect("slow origin");
        let fast = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"fast"))
            .await
            .expect("fast origin");
        let mut text = config(dir.path(), 3128, slow.address.port(), &users)
            .replace("worker_threads = 2", "worker_threads = 1");
        text = text.replace(
            &format!("ports = [{}]", slow.address.port()),
            &format!("ports = [{}, {}]", slow.address.port(), fast.address.port()),
        );
        fs::write(&path, text).expect("cpu ports config");
        let config = Arc::new(Config::load(&path).expect("cpu ports load"));
        let server = HttpServer::bind_ephemeral_with_path(Arc::clone(&config), path.clone())
            .await
            .expect("bind");
        let address = server.addresses()[0].1;
        let control = server.control();
        let slow_task =
            tokio::spawn(async move { one(address, slow.address, "alice", "alice-secret").await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let fast_started = Instant::now();
        let fast_task =
            tokio::spawn(async move { one(address, fast.address, "alice", "alice-secret").await });
        let reload = control.reload(1);
        let (fast_status, reload_outcome) = tokio::join!(fast_task, reload);
        let fast_elapsed = fast_started.elapsed();
        assert_eq!(fast_status.expect("fast join"), 200);
        assert!(matches!(
            reload_outcome,
            ReloadOutcome::Applied { generation: 2 }
        ));
        assert!(
            !slow_task.is_finished(),
            "fast request waited for the slow request under one worker"
        );
        assert_eq!(slow_task.await.expect("slow join"), 200);
        eprintln!("M07-CPU-01 workers=1 fast_ms={}", fast_elapsed.as_millis());
        server.shutdown().await;
    });
    runtime.shutdown();
}
