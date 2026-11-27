//! M05 admission, cancellation, CPU isolation and operational behavior.

#![allow(clippy::field_reassign_with_default)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[cfg(unix)]
use angara::auth::Argon2Verifier;
use angara::config::Config;
use angara::runtime::AngaraRuntime;
use common::m03::{self, RawClient};
use common::m05::{self, AuthConfig, RecordingVerifier, VerifierState};

fn two_listeners() -> String {
    r#"
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
    .to_owned()
}

async fn wait_started(state: &VerifierState, count: usize) {
    assert!(
        m05::wait_until(Duration::from_secs(5), || {
            state.started.load(Ordering::SeqCst) >= count
        })
        .await,
        "verifier did not start"
    );
}

async fn wait_finished(state: &VerifierState, count: usize) {
    assert!(
        m05::wait_until(Duration::from_secs(5), || {
            state.finished.load(Ordering::SeqCst) >= count
        })
        .await,
        "verifier did not finish"
    );
}

#[tokio::test]
async fn m05_limit01_shared_budget_is_fast_and_zero_queue() {
    let dir = common::TempDir::new("m05-limit");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
    let mut config = AuthConfig {
        max_verifying: 1,
        ..AuthConfig::default()
    };
    config.listeners = two_listeners();
    let config_path = config.write(&dir);

    let state = Arc::new(VerifierState::default());
    let verifier = Arc::new(RecordingVerifier::new(
        Arc::clone(&state),
        Duration::from_millis(400),
        Ok(true),
    ));
    let (server, addresses) = m05::start_with_verifier(&config_path, verifier).await;
    let first = m05::address(&addresses, "proxy");
    let second = m05::address(&addresses, "second");

    let mut slow = RawClient::connect(first).await.expect("slow client");
    slow.send(&m05::get_request(
        origin.address,
        Some(("alice", "secret")),
        &[],
    ))
    .await
    .expect("slow request");
    wait_started(&state, 1).await;
    assert_eq!(server.auth_available_permits(), Some(0));

    let started = Instant::now();
    let mut fast = RawClient::connect(second).await.expect("fast client");
    fast.send(&m05::get_request(
        origin.address,
        Some(("alice", "secret")),
        &[],
    ))
    .await
    .expect("fast request");
    let response = fast.read_response().await.expect("503");
    let elapsed = started.elapsed();
    assert_eq!(response.head.status, 503);
    assert_eq!(response.head.header("connection"), Some("close"));
    assert_eq!(response.head.header("proxy-authenticate"), None);
    assert!(response.body.is_empty());
    assert!(
        elapsed < Duration::from_millis(250),
        "saturation must not queue: {elapsed:?}"
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);

    let mut malformed = RawClient::connect(first).await.expect("malformed");
    malformed
        .send(&m05::get_request(origin.address, None, &[]))
        .await
        .expect("malformed");
    assert_eq!(
        malformed.read_response().await.expect("407").head.status,
        407,
        "local 407 must not consume the verification budget"
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);

    let response = slow.read_response().await.expect("slow 200");
    assert_eq!(response.head.status, 200);
    wait_finished(&state, 1).await;
    assert_eq!(server.auth_available_permits(), Some(1));
    assert_eq!(state.max_running.load(Ordering::SeqCst), 1);
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m05_limit01_source_deny_and_malformed_tokens_do_not_take_slots() {
    let dir = common::TempDir::new("m05-limit-deny");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
    let mut config = AuthConfig {
        max_verifying: 1,
        ..AuthConfig::default()
    };
    config.access = r#"
[access]
source_allow = ["192.0.2.0/24"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"
"#
    .to_owned();
    let config_path = config.write(&dir);
    let state = Arc::new(VerifierState::default());
    let (server, addresses) = m05::start_with_verifier(
        &config_path,
        Arc::new(RecordingVerifier::new(
            Arc::clone(&state),
            Duration::ZERO,
            Ok(true),
        )),
    )
    .await;
    let proxy = m05::address(&addresses, "proxy");

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .expect("send");
    assert_eq!(client.read_response().await.expect("403").head.status, 403);
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m05_cancel01_timeout_keeps_slot_until_actual_finish() {
    let dir = common::TempDir::new("m05-cancel-timeout");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
    let config = AuthConfig {
        max_verifying: 1,
        verify_timeout_ms: 100,
        ..AuthConfig::default()
    }
    .write(&dir);
    let state = Arc::new(VerifierState::default());
    let (server, addresses) = m05::start_with_verifier(
        &config,
        Arc::new(
            RecordingVerifier::new(Arc::clone(&state), Duration::from_millis(5), Ok(true))
                .with_first_delay(Duration::from_millis(350)),
        ),
    )
    .await;
    let proxy = m05::address(&addresses, "proxy");

    let started = Instant::now();
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .expect("send");
    let response = client.read_response().await.expect("503 timeout");
    assert_eq!(response.head.status, 503);
    assert_eq!(response.head.header("connection"), Some("close"));
    assert!(started.elapsed() >= Duration::from_millis(80));
    assert_eq!(server.auth_available_permits(), Some(0));
    assert_eq!(state.finished.load(Ordering::SeqCst), 0);

    let mut second = RawClient::connect(proxy).await.expect("second");
    second
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .expect("second send");
    assert_eq!(
        second.read_response().await.expect("503 busy").head.status,
        503
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);

    wait_finished(&state, 1).await;
    assert_eq!(server.auth_available_permits(), Some(1));
    assert!(
        client.read_response().await.is_err(),
        "a late verifier result must not publish another response"
    );

    let mut recovered = RawClient::connect(proxy).await.expect("recovered");
    recovered
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .expect("recovered send");
    assert_eq!(
        recovered.read_response().await.expect("200").head.status,
        200
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m05_cancel01_disconnect_and_shutdown_are_bounded() {
    let dir = common::TempDir::new("m05-cancel-drop");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);

    let config = AuthConfig {
        max_verifying: 1,
        shutdown_timeout_ms: 150,
        ..AuthConfig::default()
    }
    .write(&dir);
    let state = Arc::new(VerifierState::default());
    let (server, addresses) = m05::start_with_verifier(
        &config,
        Arc::new(RecordingVerifier::new(
            Arc::clone(&state),
            Duration::from_millis(250),
            Ok(true),
        )),
    )
    .await;
    let proxy = m05::address(&addresses, "proxy");

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .expect("send");
    wait_started(&state, 1).await;
    drop(client);
    wait_finished(&state, 1).await;
    assert_eq!(server.auth_available_permits(), Some(1));

    let mut client = RawClient::connect(proxy).await.expect("shutdown client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .expect("shutdown send");
    wait_started(&state, 2).await;
    let started = Instant::now();
    server.shutdown().await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "shutdown waited for the Argon2 job instead of the global deadline: {elapsed:?}"
    );
    let reconnect = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect(proxy),
    )
    .await;
    assert!(
        !matches!(reconnect, Ok(Ok(_))),
        "a listener still accepted a connection after shutdown"
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 2);
    wait_finished(&state, 2).await;
}

#[cfg(unix)]
fn cpu_case(workers: usize) {
    use angara::auth::PasswordVerifier as _;
    use common::m04;

    let cpu_phc = m05::hash("cpu-profile");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let dir = common::TempDir::new(&format!("m05-cpu-{workers}"));
        let echo = m04::spawn_echo_origin(None).await.expect("echo origin");
        let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
            .await
            .expect("http origin");
        m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
        let mut config = AuthConfig {
            worker_threads: workers as u32,
            max_verifying: 1,
            ..AuthConfig::default()
        };
        config.listeners = r#"
[[listeners]]
id = "proxy"
bind = "127.0.0.1:3128"
transport = "http"
auth = "basic"

[[listeners]]
id = "plain"
bind = "127.0.0.1:3129"
transport = "http"
"#
        .to_owned();
        config.connect_allowed_ports = echo.address.port().to_string();
        let config_path = config.write(&dir);
        let state = Arc::new(VerifierState::default());
        let (server, addresses) = m05::start_with_verifier(
            &config_path,
            Arc::new(RecordingVerifier::new(
                Arc::clone(&state),
                Duration::from_millis(400),
                Ok(true),
            )),
        )
        .await;
        let proxy = m05::address(&addresses, "proxy");
        let plain = m05::address(&addresses, "plain");

        let mut slow = RawClient::connect(proxy).await.expect("slow");
        slow.send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .expect("slow auth");
        wait_started(&state, 1).await;

        let started = Instant::now();
        let mut fast = RawClient::connect(plain).await.expect("plain");
        fast.send(&m03::request("GET", origin.address, "/", &[], b""))
            .await
            .expect("plain request");
        assert_eq!(
            fast.read_response().await.expect("plain 200").head.status,
            200
        );
        let http_elapsed = started.elapsed();

        let started = Instant::now();
        let mut tunnel = RawClient::connect(plain).await.expect("tunnel");
        tunnel
            .send(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo.address, echo.address
                )
                .as_bytes(),
            )
            .await
            .expect("tunnel connect");
        assert_eq!(tunnel.read_head().await.expect("tunnel 200").status, 200);
        tunnel.send(b"ping").await.expect("tunnel write");
        assert_eq!(tunnel.read_exact_bytes(4).await.expect("echo"), b"ping");
        let tunnel_elapsed = started.elapsed();

        assert_eq!(
            slow.read_response().await.expect("slow 200").head.status,
            200
        );
        assert!(
            http_elapsed < Duration::from_millis(250),
            "HTTP path stalled behind Argon2: {http_elapsed:?}"
        );
        assert!(
            tunnel_elapsed < Duration::from_millis(250),
            "tunnel path stalled behind Argon2: {tunnel_elapsed:?}"
        );

        let started = Instant::now();
        let hash_task =
            tokio::task::spawn_blocking(move || Argon2Verifier.verify(&cpu_phc, "cpu-profile"));
        let mut heartbeat_ticks = 0_usize;
        while !hash_task.is_finished() {
            tokio::time::sleep(Duration::from_millis(1)).await;
            heartbeat_ticks += 1;
        }
        let hash_verified = hash_task.await.expect("join").expect("argon2");
        assert!(hash_verified);
        let argon2_elapsed = started.elapsed();
        assert!(
            heartbeat_ticks > 0,
            "async heartbeat did not run during real Argon2 verification"
        );
        eprintln!(
            "M05-CPU-01 workers={workers} http_ms={} tunnel_ms={} argon2_ms={} heartbeat_ticks={heartbeat_ticks}",
            http_elapsed.as_millis(),
            tunnel_elapsed.as_millis(),
            argon2_elapsed.as_millis()
        );
        server.shutdown().await;
    });
}

#[cfg(unix)]
#[test]
fn m05_cpu01_async_paths_continue_during_verification() {
    for workers in [1, 2] {
        cpu_case(workers);
    }
}

#[tokio::test]
async fn m05_ops01_snapshot_is_immutable_until_restart() {
    let dir = common::TempDir::new("m05-ops");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let users = dir.path().join("users.toml");
    m05::write_secure(
        &users,
        &m05::users_text(&[("alice", &m05::hash("old"), false)]),
    );
    let config_path = AuthConfig::default().write(&dir);

    let (first, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "old")),
            &[],
        ))
        .await
        .expect("old");
    assert_eq!(
        client.read_response().await.expect("old 200").head.status,
        200
    );

    m05::write_secure(
        &users,
        &m05::users_text(&[("alice", &m05::hash("new"), false)]),
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "old")),
            &[],
        ))
        .await
        .expect("old after edit");
    assert_eq!(
        client
            .read_response()
            .await
            .expect("old still valid")
            .head
            .status,
        200,
        "the running server must keep its loaded snapshot"
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "new")),
            &[],
        ))
        .await
        .expect("new before restart");
    assert_eq!(
        client.read_response().await.expect("new 407").head.status,
        407
    );
    first.shutdown().await;

    let (second, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "new")),
            &[],
        ))
        .await
        .expect("new after restart");
    assert_eq!(
        client.read_response().await.expect("new 200").head.status,
        200
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "old")),
            &[],
        ))
        .await
        .expect("old after restart");
    assert_eq!(
        client.read_response().await.expect("old 407").head.status,
        407
    );
    second.shutdown().await;

    m05::write_secure(
        &users,
        &m05::users_text(&[("alice", &m05::hash("new"), true)]),
    );
    let (disabled, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "new")),
            &[],
        ))
        .await
        .expect("disabled");
    assert_eq!(
        client
            .read_response()
            .await
            .expect("disabled 407")
            .head
            .status,
        407
    );
    disabled.shutdown().await;

    m05::write_secure(&users, "version = 3\nusers = []\n");
    assert!(
        Config::load(&config_path).is_err(),
        "an invalid users file must reject the next startup"
    );
}

#[tokio::test]
async fn m05_transport01_spoofed_forwarding_headers_do_not_authorize() {
    let dir = common::TempDir::new("m05-transport-headers");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
    let config_path = AuthConfig::default().write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            None,
            &[
                ("X-Forwarded-Proto", "https"),
                ("Forwarded", "for=127.0.0.1;proto=https"),
            ],
        ))
        .await
        .expect("send");
    assert_eq!(client.read_response().await.expect("407").head.status, 407);
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);

    let mut client = RawClient::connect(proxy).await.expect("connect client");
    client
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nX-Forwarded-Proto: https\r\n\r\n",
                origin.address, origin.address
            )
            .as_bytes(),
        )
        .await
        .expect("connect without auth");
    assert_eq!(
        client
            .read_response()
            .await
            .expect("connect 407")
            .head
            .status,
        407
    );
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m05_transport01_opt_in_does_not_bypass_source_gate() {
    let dir = common::TempDir::new("m05-transport-opt-in");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
    let mut config = AuthConfig::default();
    config.listeners = r#"
[[listeners]]
id = "proxy"
bind = "0.0.0.0:3128"
transport = "http"
auth = "basic"
allow_insecure_basic = true
"#
    .to_owned();
    config.access = r#"
[access]
source_allow = ["192.0.2.0/24"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"
"#
    .to_owned();
    let config_path = config.write(&dir);
    let state = Arc::new(VerifierState::default());
    let (server, addresses) = m05::start_with_verifier(
        &config_path,
        Arc::new(RecordingVerifier::accepting(
            Arc::clone(&state),
            Duration::ZERO,
            "secret",
        )),
    )
    .await;
    let bound = m05::address(&addresses, "proxy");
    let proxy = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        bound.port(),
    );

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .expect("send");
    assert_eq!(client.read_response().await.expect("403").head.status, 403);
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);
    server.shutdown().await;
}

#[test]
fn m05_ops01_runtime_shutdown_uses_the_remaining_server_deadline() {
    let dir = common::TempDir::new("m05-runtime-deadline");
    m05::write_users(&dir, &[("alice", &m05::hash("secret"), false)]);
    let config_path = AuthConfig {
        shutdown_timeout_ms: 400,
        ..AuthConfig::default()
    }
    .write(&dir);
    let config = Arc::new(Config::load(&config_path).expect("config"));
    let runtime = AngaraRuntime::build(&config).expect("runtime");
    let state = Arc::new(VerifierState::default());
    let state_for_server = Arc::clone(&state);
    let started = std::time::Instant::now();
    let deadline = runtime.block_on(async move {
        let server = angara::http::HttpServer::bind_ephemeral_with_verifier(
            Arc::clone(&config),
            Arc::new(RecordingVerifier::new(
                Arc::clone(&state_for_server),
                Duration::from_millis(1_200),
                Ok(true),
            )),
        )
        .await
        .expect("bind server");
        let proxy = server.addresses()[0].1;
        let mut client = RawClient::connect(proxy).await.expect("client");
        client
            .send(&m05::get_request(
                "127.0.0.1:9".parse().expect("target"),
                Some(("alice", "secret")),
                &[],
            ))
            .await
            .expect("send");
        assert!(
            m05::wait_until(Duration::from_secs(2), || {
                state_for_server.started.load(Ordering::SeqCst) == 1
            })
            .await,
            "verifier did not start"
        );
        let deadline = std::time::Instant::now() + Duration::from_millis(400);
        server.shutdown_until(deadline).await;
        deadline
    });
    let server_elapsed = started.elapsed();
    let runtime_started = std::time::Instant::now();
    runtime.shutdown_until(deadline);
    let runtime_elapsed = runtime_started.elapsed();
    assert!(
        runtime_elapsed < Duration::from_millis(200),
        "runtime was given a fresh shutdown window: {runtime_elapsed:?}"
    );
    let finish_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while state.finished.load(Ordering::SeqCst) != 1 {
        assert!(
            std::time::Instant::now() < finish_deadline,
            "blocking verification did not finish"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    eprintln!(
        "M05-OPS-01 server_shutdown_ms={} runtime_shutdown_ms={}",
        server_elapsed.as_millis(),
        runtime_elapsed.as_millis()
    );
}
