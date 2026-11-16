//! M07 reload, snapshot, control, cap and observability tests.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use angara::config::Config;
use angara::control::{Lifecycle, ReloadOutcome};
use angara::http::HttpServer;
use angara::logging::{Event, LogRecord, Logger};
use common::TempDir;
use common::m03::{self, RawClient};
use common::m04;
use common::m05;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn users_file(dir: &Path, entries: &[(&str, &str, bool)]) -> PathBuf {
    let path = dir.join("users.toml");
    m05::write_secure(&path, &m05::users_text(entries));
    path
}

fn config_text(
    dir: &Path,
    origin_port: u16,
    rule_users: &str,
    max_client: u32,
    workers: u32,
    reload_timeout_ms: u64,
    https: bool,
) -> String {
    let tls = if https {
        format!(
            r#"
[listeners.tls]
cert_chain_file = "{}"
private_key_file = "{}"
"#,
            dir.join("proxy_chain.pem")
                .to_string_lossy()
                .replace('\\', "/"),
            dir.join("proxy_key.pem")
                .to_string_lossy()
                .replace('\\', "/"),
        )
    } else {
        String::new()
    };
    format!(
        r#"
schema_version = 1
[runtime]
worker_threads = {workers}
[limits]
max_connections = 16
max_client_connections = {max_client}
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 1500
[operations]
reload_timeout_ms = {reload_timeout_ms}
[observability]
log_level = "off"
log_queue_capacity = 128
metrics_enabled = true
metrics_interval_ms = 1000
[auth]
users_file = "users.toml"
max_verifying = 2
verify_timeout_ms = 2000
[[listeners]]
id = "proxy"
bind = "127.0.0.1:3128"
transport = "{transport}"
auth = "basic"
{tls}
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"
[[access.rules]]
id = "allowed"
action = "allow"
users = [{rule_users}]
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
        transport = if https { "https" } else { "http" },
    )
}

fn write_config(
    dir: &Path,
    origin_port: u16,
    rule_users: &str,
    max_client: u32,
    workers: u32,
    reload_timeout_ms: u64,
    https: bool,
) -> PathBuf {
    let path = dir.join("proxy.toml");
    fs::write(
        &path,
        config_text(
            dir,
            origin_port,
            rule_users,
            max_client,
            workers,
            reload_timeout_ms,
            https,
        ),
    )
    .expect("write config");
    path
}

async fn start(
    dir: &Path,
    origin_port: u16,
    rule_users: &str,
    max_client: u32,
    workers: u32,
    reload_timeout_ms: u64,
    https: bool,
) -> (HttpServer, std::net::SocketAddr) {
    let path = write_config(
        dir,
        origin_port,
        rule_users,
        max_client,
        workers,
        reload_timeout_ms,
        https,
    );
    let config = Arc::new(Config::load(&path).expect("valid config"));
    let server = HttpServer::bind_ephemeral_with_path(config, path)
        .await
        .expect("bind server");
    let address = server.addresses()[0].1;
    (server, address)
}

async fn start_text(dir: &Path, text: String) -> (HttpServer, std::net::SocketAddr) {
    let path = dir.join("proxy.toml");
    fs::write(&path, text).expect("write config");
    let config = Arc::new(Config::load(&path).expect("valid config"));
    let server = HttpServer::bind_ephemeral_with_path(config, path)
        .await
        .expect("bind server");
    let address = server.addresses()[0].1;
    (server, address)
}

fn authenticated_request(
    origin: std::net::SocketAddr,
    user: &str,
    password: &str,
    connection_close: bool,
) -> Vec<u8> {
    let auth = m05::authorization(user, password);
    let mut headers = vec![("Proxy-Authorization", auth.as_str())];
    if connection_close {
        headers.push(("Connection", "close"));
    }
    m03::request("GET", origin, "/", &headers, b"")
}

async fn status(client: &mut RawClient) -> u16 {
    client.read_response().await.expect("response").head.status
}

#[tokio::test]
async fn m07_req01_keepalive_reload_uses_new_snapshot_after_gate() {
    let dir = TempDir::new("m07-req01");
    m05::write_secure(
        &dir.path().join("users.toml"),
        &m05::users_text(&[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ]),
    );
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            false,
        ))
        .await
        .expect("send alice");
    assert_eq!(status(&mut client).await, 200);

    write_config(
        dir.path(),
        origin.address.port(),
        "\"bob\"",
        8,
        2,
        5000,
        false,
    );
    let control = server.control();
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    assert_eq!(control.status().generation, 2);

    client
        .send(&authenticated_request(
            origin.address,
            "bob",
            "bob-secret",
            false,
        ))
        .await
        .expect("send bob");
    assert_eq!(status(&mut client).await, 200);
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            false,
        ))
        .await
        .expect("send alice old");
    assert_eq!(status(&mut client).await, 403);

    // An equivalent candidate still increments exactly once.
    assert_eq!(
        control.reload(2).await,
        ReloadOutcome::Applied { generation: 3 }
    );
    assert_eq!(control.status().generation, 3);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_static01_mixed_restart_change_is_rejected_whole() {
    let dir = TempDir::new("m07-static01");
    users_file(
        dir.path(),
        &[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ],
    );
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    write_config(
        dir.path(),
        origin.address.port(),
        "\"bob\"",
        8,
        4,
        5000,
        false,
    );
    assert!(matches!(
        control.reload(1).await,
        ReloadOutcome::RestartRequired { fields, .. }
            if fields.iter().any(|field| field.contains("runtime"))
    ));
    assert_eq!(control.status().generation, 1);

    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("send alice");
    assert_eq!(status(&mut client).await, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_static02_restart_only_fields_are_rejected_without_publication() {
    let dir = TempDir::new("m07-static02");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let base = config_text(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    );
    let (server, _) = start_text(dir.path(), base.clone()).await;
    let control = server.control();
    for (needle, replacement, field) in [
        (
            "max_verifying = 2",
            "max_verifying = 3",
            "auth.max_verifying",
        ),
        (
            "verify_timeout_ms = 2000",
            "verify_timeout_ms = 3000",
            "auth.verify_timeout_ms",
        ),
        ("max_headers = 64", "max_headers = 65", "http.max_headers"),
        (
            "pool_max_idle = 8",
            "pool_max_idle = 7",
            "http.pool_max_idle",
        ),
        (
            "max_connecting = 8",
            "max_connecting = 7",
            "transport.max_connecting",
        ),
        (
            "max_header_bytes = 32768",
            "max_header_bytes = 65536",
            "limits.max_header_bytes",
        ),
    ] {
        fs::write(
            dir.path().join("proxy.toml"),
            base.replace(needle, replacement),
        )
        .expect("static config");
        let outcome = control.reload(1).await;
        assert!(
            matches!(&outcome, ReloadOutcome::RestartRequired { fields, .. }
                if fields.iter().any(|value| value == field)),
            "{field}: {outcome:?}"
        );
        assert_eq!(control.status().generation, 1);
    }
    fs::write(dir.path().join("proxy.toml"), base).expect("restore base");
    server.shutdown().await;
}

#[tokio::test]
async fn m07_cas01_conflict_invalid_and_validate_do_not_publish() {
    let dir = TempDir::new("m07-cas01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, _) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    assert_eq!(
        control.reload(9).await,
        ReloadOutcome::Conflict { current: 1 }
    );
    assert!(matches!(
        control.validate_on_disk(1).await,
        ReloadOutcome::Valid { generation: 1 }
    ));
    assert_eq!(control.status().generation, 1);

    fs::write(dir.path().join("proxy.toml"), "not = [valid").expect("write invalid");
    assert!(matches!(
        control.reload(1).await,
        ReloadOutcome::Invalid { .. }
    ));
    assert_eq!(control.status().generation, 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_cas02_validate_does_not_cache_bytes_for_reload() {
    let dir = TempDir::new("m07-cas02");
    users_file(
        dir.path(),
        &[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ],
    );
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    assert!(matches!(
        control.validate_on_disk(1).await,
        ReloadOutcome::Valid { generation: 1 }
    ));
    write_config(
        dir.path(),
        origin.address.port(),
        "\"bob\"",
        8,
        2,
        5000,
        false,
    );
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    let mut bob = RawClient::connect(address).await.expect("bob");
    bob.send(&authenticated_request(
        origin.address,
        "bob",
        "bob-secret",
        true,
    ))
    .await
    .expect("bob send");
    assert_eq!(status(&mut bob).await, 200);
    let mut alice = RawClient::connect(address).await.expect("alice");
    alice
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("alice send");
    assert_eq!(status(&mut alice).await, 403);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_limit03_client_cap_lower_keeps_old_holders_and_recovers() {
    let dir = TempDir::new("m07-limit03");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        2,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    let first = tokio::net::TcpStream::connect(address)
        .await
        .expect("first holder");
    let second = tokio::net::TcpStream::connect(address)
        .await
        .expect("second holder");
    tokio::time::sleep(Duration::from_millis(100)).await;

    write_config(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        1,
        2,
        5000,
        false,
    );
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    let mut denied = RawClient::connect(address).await.expect("denied TCP");
    denied
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("denied send");
    let denied_result = tokio::time::timeout(Duration::from_secs(1), denied.read_response()).await;
    assert!(
        denied_result.map(|result| result.is_err()).unwrap_or(true),
        "new connection bypassed lowered cap 1"
    );
    drop(denied);
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut still_denied = RawClient::connect(address).await.expect("still TCP");
    still_denied
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("still send");
    let still_result =
        tokio::time::timeout(Duration::from_secs(1), still_denied.read_response()).await;
    assert!(
        still_result.map(|result| result.is_err()).unwrap_or(true),
        "one old holder did not keep cap 1 active"
    );
    drop(still_denied);
    drop(second);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut allowed = RawClient::connect(address).await.expect("allowed");
    allowed
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("allowed send");
    assert_eq!(status(&mut allowed).await, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_auth01_password_change_applies_on_new_exchange() {
    let dir = TempDir::new("m07-auth01");
    users_file(dir.path(), &[("alice", &m05::hash("old-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "old-secret",
            false,
        ))
        .await
        .expect("send old");
    assert_eq!(status(&mut client).await, 200);

    users_file(dir.path(), &[("alice", &m05::hash("new-secret"), false)]);
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    let mut old = RawClient::connect(address).await.expect("old client");
    old.send(&authenticated_request(
        origin.address,
        "alice",
        "old-secret",
        true,
    ))
    .await
    .expect("send old password");
    assert_eq!(status(&mut old).await, 407);
    let mut new = RawClient::connect(address).await.expect("new client");
    new.send(&authenticated_request(
        origin.address,
        "alice",
        "new-secret",
        true,
    ))
    .await
    .expect("send new password");
    assert_eq!(status(&mut new).await, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_auth02_disabled_unknown_and_users_file_path_reload() {
    let dir = TempDir::new("m07-auth02");
    users_file(
        dir.path(),
        &[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ],
    );
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\", \"bob\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    let request =
        |user: &str, password: &str| authenticated_request(origin.address, user, password, true);

    let mut unknown = RawClient::connect(address).await.expect("unknown");
    unknown
        .send(&request("nobody", "alice-secret"))
        .await
        .expect("unknown send");
    assert_eq!(status(&mut unknown).await, 407);
    let mut alice = RawClient::connect(address).await.expect("alice");
    alice
        .send(&request("alice", "alice-secret"))
        .await
        .expect("alice send");
    assert_eq!(status(&mut alice).await, 200);

    users_file(
        dir.path(),
        &[
            ("alice", &m05::hash("alice-secret"), true),
            ("bob", &m05::hash("bob-secret"), false),
        ],
    );
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    let mut disabled = RawClient::connect(address).await.expect("disabled");
    disabled
        .send(&request("alice", "alice-secret"))
        .await
        .expect("disabled send");
    assert_eq!(status(&mut disabled).await, 407);
    let mut bob = RawClient::connect(address).await.expect("bob");
    bob.send(&request("bob", "bob-secret"))
        .await
        .expect("bob send");
    assert_eq!(status(&mut bob).await, 200);

    let second_users = dir.path().join("users2.toml");
    m05::write_secure(
        &second_users,
        &m05::users_text(&[("carol", &m05::hash("carol-secret"), false)]),
    );
    let text = config_text(
        dir.path(),
        origin.address.port(),
        "\"carol\"",
        8,
        2,
        5000,
        false,
    )
    .replace(
        "users_file = \"users.toml\"",
        "users_file = \"users2.toml\"",
    );
    fs::write(dir.path().join("proxy.toml"), text).expect("users path config");
    assert_eq!(
        control.reload(2).await,
        ReloadOutcome::Applied { generation: 3 }
    );
    let mut carol = RawClient::connect(address).await.expect("carol");
    carol
        .send(&request("carol", "carol-secret"))
        .await
        .expect("carol send");
    assert_eq!(status(&mut carol).await, 200);

    for _ in 0..50 {
        if control.metrics().auth_active == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let metrics = control.metrics();
    assert!(metrics.auth_ok >= 3);
    assert!(metrics.auth_invalid >= 1);
    assert_eq!(metrics.auth_active, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_met01_counters_follow_real_lifecycle_and_remain_after_reload() {
    let dir = TempDir::new("m07-met01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"metrics"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    let http_before = control.metrics();
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("send");
    assert_eq!(status(&mut client).await, 200);
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let metrics = control.metrics();
    assert_eq!(metrics.tcp_accepted, http_before.tcp_accepted + 1);
    assert_eq!(metrics.http_started, http_before.http_started + 1);
    assert_eq!(metrics.http_completed, http_before.http_completed + 1);
    assert_eq!(metrics.http_2xx, http_before.http_2xx + 1);
    assert_eq!(metrics.http_cancelled, 0);
    assert_eq!(metrics.auth_active, 0);
    assert_eq!(metrics.dns_active, 0);
    assert_eq!(
        metrics.outbound_active,
        metrics.pool_idle + metrics.pool_leased,
        "outbound sockets must match idle+leased pool accounting"
    );
    assert!(
        metrics.pool_idle + metrics.pool_leased >= 1,
        "origin socket was not accounted"
    );

    let before_reload = metrics.http_completed;
    write_config(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    );
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    assert!(control.metrics().http_completed >= before_reload);

    let text = serde_json::to_string(&control.metrics()).expect("metrics JSON");
    assert!(text.len() < 8_192, "metrics snapshot grew: {}", text.len());
    assert!(!text.contains("alice"));
    assert!(!text.contains("127.0.0.1"));
    for _ in 0..100 {
        if control.status().client_active == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let status = control.status();
    assert!(status.listeners.len() <= 64);
    assert!(status.egress.len() <= 64);
    assert_eq!(status.client_active, 0);
    assert_eq!(status.connect_active, 0);
    assert_eq!(status.auth_active, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_cancel01_timeout_keeps_slot_busy_and_never_publishes() {
    let dir = TempDir::new("m07-cancel01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, _) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        100,
        false,
    )
    .await;
    let control = server.control();
    control.set_test_preparation_delay(Some(Duration::from_millis(300)));
    assert_eq!(control.reload(1).await, ReloadOutcome::TimedOut);
    assert_eq!(control.reload(1).await, ReloadOutcome::Busy);
    assert_eq!(control.status().generation, 1);
    tokio::time::sleep(Duration::from_millis(350)).await;
    control.set_test_preparation_delay(None);
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m07_gen01_sixteen_live_roots_are_bounded_and_released() {
    let dir = TempDir::new("m07-gen01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, _) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    let mut held = vec![control.snapshot_for_test()];
    for generation in 2..=16 {
        assert_eq!(
            control.reload(generation - 1).await,
            ReloadOutcome::Applied { generation }
        );
        held.push(control.snapshot_for_test());
    }
    assert_eq!(control.status().live_generations, 16);
    assert_eq!(control.reload(16).await, ReloadOutcome::GenerationBusy);
    held.clear();
    assert_eq!(
        control.reload(16).await,
        ReloadOutcome::Applied { generation: 17 }
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m07_limit01_hot_client_cap_lower_and_raise_keep_old_holders() {
    let dir = TempDir::new("m07-limit01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        1,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    let held = tokio::net::TcpStream::connect(address)
        .await
        .expect("hold client permit");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut blocked = RawClient::connect(address)
        .await
        .expect("second TCP connect");
    blocked
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("send blocked");
    let blocked_result =
        tokio::time::timeout(Duration::from_secs(1), blocked.read_response()).await;
    assert!(
        blocked_result.map(|result| result.is_err()).unwrap_or(true),
        "second connection bypassed cap 1"
    );

    write_config(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        2,
        2,
        5000,
        false,
    );
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    let second = tokio::net::TcpStream::connect(address)
        .await
        .expect("raised cap allows second");
    drop(held);
    drop(second);
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.shutdown().await;
}

#[tokio::test]
async fn m07_limit02_outbound_cap_lower_and_raise_keeps_existing_tunnels() {
    let dir = TempDir::new("m07-limit02");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let echo = m04::spawn_echo_origin(None).await.expect("echo");
    let base = config_text(
        dir.path(),
        echo.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .replace("max_connections = 16", "max_connections = 2")
    .replace("max_connecting = 8", "max_connecting = 1")
    .replace("pool_max_idle = 8", "pool_max_idle = 1")
    .replace("pool_max_idle_per_key = 2", "pool_max_idle_per_key = 1");
    let (server, address) = start_text(dir.path(), base.clone()).await;
    let control = server.control();

    let mut first = open_tunnel(address, echo.address, "alice", "alice-secret").await;
    let mut second = open_tunnel(address, echo.address, "alice", "alice-secret").await;
    first.send(b"one").await.expect("first tunnel");
    assert_eq!(first.read_exact_bytes(3).await.expect("echo one"), b"one");
    second.send(b"two").await.expect("second tunnel");
    assert_eq!(second.read_exact_bytes(3).await.expect("echo two"), b"two");

    let lowered = base.replace("max_connections = 2", "max_connections = 1");
    fs::write(dir.path().join("proxy.toml"), lowered).expect("lowered config");
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    let mut denied = RawClient::connect(address).await.expect("denied client");
    send_connect(&mut denied, echo.address, "alice", "alice-secret").await;
    assert_eq!(denied.read_head().await.expect("503").status, 503);
    drop(denied);

    // Existing holders keep their permits and remain usable.
    first.send(b"still").await.expect("old first");
    assert_eq!(
        first.read_exact_bytes(5).await.expect("echo still"),
        b"still"
    );
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut still_denied = RawClient::connect(address).await.expect("still denied");
    send_connect(&mut still_denied, echo.address, "alice", "alice-secret").await;
    assert_eq!(still_denied.read_head().await.expect("503").status, 503);
    drop(still_denied);
    drop(second);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut third = open_tunnel(address, echo.address, "alice", "alice-secret").await;
    third.send(b"new").await.expect("new tunnel");
    assert_eq!(third.read_exact_bytes(3).await.expect("echo new"), b"new");
    drop(third);
    tokio::time::sleep(Duration::from_millis(100)).await;

    fs::write(dir.path().join("proxy.toml"), &base).expect("raised config");
    assert_eq!(
        control.reload(2).await,
        ReloadOutcome::Applied { generation: 3 }
    );
    let mut fourth = open_tunnel(address, echo.address, "alice", "alice-secret").await;
    fourth.send(b"up").await.expect("raised tunnel");
    assert_eq!(fourth.read_exact_bytes(2).await.expect("echo up"), b"up");
    drop(fourth);
    for _ in 0..50 {
        if control.metrics().connect_active == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let metrics = control.metrics();
    assert_eq!(metrics.connect_active, 0);
    assert!(metrics.connect_started >= 4);
    assert_eq!(
        metrics.connect_complete
            + metrics.connect_idle
            + metrics.connect_timeout
            + metrics.connect_error
            + metrics.connect_cancelled,
        metrics.connect_finished
    );
    server.shutdown().await;
}

async fn send_connect(
    client: &mut RawClient,
    origin: std::net::SocketAddr,
    user: &str,
    password: &str,
) {
    let auth = m05::authorization(user, password);
    client
        .send(
            format!(
                "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\nProxy-Authorization: {auth}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("send CONNECT");
}

async fn open_tunnel(
    address: std::net::SocketAddr,
    origin: std::net::SocketAddr,
    user: &str,
    password: &str,
) -> RawClient {
    let mut client = RawClient::connect(address).await.expect("tunnel client");
    send_connect(&mut client, origin, user, password).await;
    assert_eq!(client.read_head().await.expect("200").status, 200);
    client
}

#[tokio::test]
async fn m07_cancel02_caller_drop_and_shutdown_never_publish_late_candidate() {
    let dir = TempDir::new("m07-cancel02");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, _) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    control.set_test_preparation_delay(Some(Duration::from_millis(300)));

    let dropped = tokio::spawn({
        let control = Arc::clone(&control);
        async move { control.reload(1).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    dropped.abort();
    assert!(dropped.await.is_err(), "reload task was not aborted");
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(control.status().generation, 1);
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );

    control.set_test_preparation_delay(Some(Duration::from_millis(300)));
    let shutdown_race = tokio::spawn({
        let control = Arc::clone(&control);
        async move { control.reload(2).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    control.begin_shutdown(angara::control::ShutdownReason::Control);
    assert!(matches!(
        shutdown_race.await.expect("join"),
        ReloadOutcome::ShuttingDown
    ));
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(control.status().generation, 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_shut01_past_absolute_deadline_forces_without_a_new_window() {
    let dir = TempDir::new("m07-shut01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, _) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let started = std::time::Instant::now();
    server.shutdown_until(started).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "past deadline was extended: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn m07_log01_json_terminal_record_and_metrics() {
    let dir = TempDir::new("m07-log01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"logged"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let telemetry = server.telemetry();
    let (logger, receiver) = Logger::channel(64, angara::config::LogLevel::Info, telemetry);
    server.set_logger(logger);
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("send");
    assert_eq!(status(&mut client).await, 200);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut value = None;
    for _ in 0..10 {
        let text = receiver.recv_timeout(Duration::from_secs(1)).expect("log");
        let candidate: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        if candidate["event"] == "request_finished" {
            value = Some(candidate);
            break;
        }
    }
    let value = value.expect("request_finished record");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["status"], 200);
    assert_eq!(value["outcome"], "success");
    assert_eq!(value["request_body_bytes"], 0);
    assert_eq!(value["response_body_bytes"], 6);
    assert!(value["connection_id"].as_u64().unwrap_or(0) > 0);
    assert!(value["request_id"].as_u64().unwrap_or(0) > 0);
    assert_eq!(value["generation"], 1);
    assert!(value.get("client").is_none());
    assert!(value.get("authority").is_none());
    let metrics = server.control().metrics();
    assert!(metrics.http_started >= 1);
    assert!(metrics.http_completed >= 1);
    assert!(metrics.http_2xx >= 1);
    assert_eq!(metrics.http_cancelled, 0);
    assert_eq!(metrics.auth_active, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_log04_request_response_and_head_byte_counts() {
    let dir = TempDir::new("m07-log04");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let telemetry = server.telemetry();
    let (logger, receiver) = Logger::channel(64, angara::config::LogLevel::Info, telemetry);
    server.set_logger(logger);
    let auth = m05::authorization("alice", "alice-secret");
    let mut post = RawClient::connect(address).await.expect("post client");
    post.send(&m03::request(
        "POST",
        origin.address,
        "/",
        &[("Proxy-Authorization", &auth), ("Connection", "close")],
        b"hello",
    ))
    .await
    .expect("post send");
    assert_eq!(status(&mut post).await, 200);

    let mut head = RawClient::connect(address).await.expect("head client");
    head.send(&m03::request(
        "HEAD",
        origin.address,
        "/",
        &[("Proxy-Authorization", &auth), ("Connection", "close")],
        b"",
    ))
    .await
    .expect("head send");
    assert_eq!(
        head.read_head_response().await.expect("head").head.status,
        200
    );

    let mut post_record = None;
    let mut head_record = None;
    for _ in 0..20 {
        let text = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("terminal log");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        if value["event"] != "request_finished" {
            continue;
        }
        match value["request_id"].as_u64() {
            Some(_) if post_record.is_none() => post_record = Some(value),
            _ => head_record = Some(value),
        }
        if post_record.is_some() && head_record.is_some() {
            break;
        }
    }
    let post_record = post_record.expect("post record");
    assert_eq!(post_record["outcome"], "success");
    assert_eq!(post_record["request_body_bytes"], 5);
    assert_eq!(post_record["response_body_bytes"], 2);
    let head_record = head_record.expect("head record");
    assert_eq!(head_record["outcome"], "success");
    assert_eq!(head_record["request_body_bytes"], 0);
    assert_eq!(head_record["response_body_bytes"], 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_log03_truncated_body_is_not_logged_as_success() {
    let dir = TempDir::new("m07-log03");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("origin bind");
    let origin_address = listener.local_addr().expect("origin address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&buffer[..read]);
                    if head.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    let (server, address) = start(
        dir.path(),
        origin_address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let telemetry = server.telemetry();
    let (logger, receiver) = Logger::channel(64, angara::config::LogLevel::Info, telemetry);
    server.set_logger(logger);
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&authenticated_request(
            origin_address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("send");
    let _ = tokio::time::timeout(Duration::from_secs(2), client.read_response()).await;
    let mut value = None;
    for _ in 0..10 {
        let text = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("terminal log");
        let candidate: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        if candidate["event"] == "request_finished" {
            value = Some(candidate);
            break;
        }
    }
    let value = value.expect("request_finished record");
    assert_eq!(value["status"], 200);
    assert_eq!(value["outcome"], "failed");
    assert_eq!(value["response_body_bytes"], 5);
    while let Ok(text) = receiver.recv_timeout(Duration::from_millis(100)) {
        let candidate: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_ne!(
            candidate["event"], "request_finished",
            "duplicate terminal record: {text}"
        );
    }
    let metrics = server.control().metrics();
    assert_eq!(metrics.http_completed, 1);
    assert_eq!(metrics.http_cancelled, 0);
    assert_eq!(metrics.http_2xx, 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_req02_pipelined_bytes_wait_for_gate_and_use_new_snapshot() {
    let dir = TempDir::new("m07-req02");
    users_file(
        dir.path(),
        &[
            ("alice", &m05::hash("alice-secret"), false),
            ("bob", &m05::hash("bob-secret"), false),
        ],
    );
    let origin = m04::spawn_slow_http_origin(Duration::from_millis(300))
        .await
        .expect("slow origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\", \"bob\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            false,
        ))
        .await
        .expect("first");
    assert_eq!(
        client
            .read_head_response()
            .await
            .expect("first head")
            .head
            .status,
        200
    );

    // The second request is already buffered while the first response body is
    // still streaming and the exchange gate is held.
    client
        .send(&authenticated_request(
            origin.address,
            "bob",
            "bob-secret",
            false,
        ))
        .await
        .expect("pipelined");
    write_config(
        dir.path(),
        origin.address.port(),
        "\"bob\"",
        8,
        2,
        5000,
        false,
    );
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    assert_eq!(
        client.read_exact_bytes(4).await.expect("first body"),
        b"body"
    );
    assert_eq!(status(&mut client).await, 200);
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("old user");
    assert_eq!(status(&mut client).await, 403);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_pol01_routing_reload_changes_observed_loopback_source_ip() {
    let dir = TempDir::new("m07-pol01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin =
        m03::spawn_origin(|_, _| m03::response("200 OK", &[("Connection", "close")], b"ok"))
            .await
            .expect("origin");
    let mut text = config_text(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    );
    text.push_str(&format!(
        r#"
[[egress]]
id = "system"
mode = "system"
[[egress]]
id = "alt"
mode = "bind_ip"
bind_ip = "127.0.0.2"
[routing]
default_egress = "system"
[[routing.rules]]
id = "alt-route"
egress_id = "alt"
ports = [{}]
"#,
        origin.address.port()
    ));
    let (server, address) = start_text(dir.path(), text).await;
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("first");
    assert_eq!(status(&mut client).await, 200);
    assert_eq!(
        origin.requests.lock().expect("origin requests")[0]
            .peer
            .ip(),
        "127.0.0.2".parse::<std::net::IpAddr>().expect("ip")
    );

    // Removing the hot routing rule keeps the same static egress profiles and
    // switches the next exchange to system.
    let mut system_text = config_text(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    );
    system_text.push_str(
        r#"
[[egress]]
id = "system"
mode = "system"
[[egress]]
id = "alt"
mode = "bind_ip"
bind_ip = "127.0.0.2"
[routing]
default_egress = "system"
"#,
    );
    fs::write(dir.path().join("proxy.toml"), system_text).expect("system config");
    assert_eq!(
        server.control().reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    let mut second = RawClient::connect(address).await.expect("second client");
    second
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("second");
    assert_eq!(status(&mut second).await, 200);
    assert_eq!(
        origin.requests.lock().expect("origin requests")[1]
            .peer
            .ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().expect("ip")
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m07_tls_static01_policy_reload_does_not_read_bad_tls_files() {
    let dir = TempDir::new("m07-tls-static");
    common::m06::generate_pki(dir.path());
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"tls"))
        .await
        .expect("origin");
    let (server, _) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        true,
    )
    .await;
    fs::write(dir.path().join("proxy_key.pem"), b"not a private key").expect("corrupt key");
    write_config(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        true,
    );
    assert!(matches!(
        server.control().reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    ));

    // A changed TLS path is restart-required and must not be opened.
    let mut changed = config_text(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        true,
    )
    .replace("proxy_key.pem", "missing-key.pem");
    changed.push('\n');
    fs::write(dir.path().join("proxy.toml"), changed).expect("changed TLS path");
    assert!(matches!(
        server.control().reload(2).await,
        ReloadOutcome::RestartRequired { fields, .. }
            if fields.iter().any(|field| field.contains("listeners"))
    ));
    assert_eq!(server.control().status().generation, 2);

    let path = dir.path().join("proxy.toml");
    assert!(Config::load(&path).is_err(), "new startup rejects bad TLS");
    server.shutdown().await;
}

#[tokio::test]
async fn m07_ctrl01_status_is_safe_and_lifecycle_is_typed() {
    let dir = TempDir::new("m07-ctrl01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, _) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    let status = control.status();
    assert_eq!(status.generation, 1);
    assert_eq!(status.lifecycle, Lifecycle::Running);
    assert_eq!(status.listeners.len(), 1);
    assert!(status.egress.len() <= 64);
    assert_eq!(status.max_client_connections, 8);
    assert_eq!(status.client_active, 0);
    assert_eq!(status.tls_active, 0);
    assert_eq!(status.connect_active, 0);
    assert_eq!(status.auth_active, 0);
    assert_eq!(status.dns_active, 0);
    let debug = format!("{status:?}");
    assert!(!debug.contains("alice-secret"));
    assert!(!debug.contains("$argon2"));
    control.begin_shutdown(angara::control::ShutdownReason::Control);
    assert_eq!(control.status().lifecycle, Lifecycle::Draining);
    assert_eq!(control.reload(1).await, ReloadOutcome::ShuttingDown);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_pol02_source_and_port_policy_apply_to_next_exchange() {
    let dir = TempDir::new("m07-pol02");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let control = server.control();
    let mut first = RawClient::connect(address).await.expect("first");
    first
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("first");
    assert_eq!(status(&mut first).await, 200);

    let source_denied = config_text(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .replace(
        "source_allow = [\"127.0.0.0/8\"]",
        "source_allow = [\"10.0.0.0/8\"]",
    );
    fs::write(dir.path().join("proxy.toml"), source_denied).expect("source config");
    assert_eq!(
        control.reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    let mut denied_source = RawClient::connect(address).await.expect("source client");
    denied_source
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("source send");
    assert_eq!(status(&mut denied_source).await, 403);

    let port_denied = config_text(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .replace(
        &format!("ports = [{}]", origin.address.port()),
        "ports = [1]",
    );
    fs::write(dir.path().join("proxy.toml"), port_denied).expect("port config");
    assert_eq!(
        control.reload(2).await,
        ReloadOutcome::Applied { generation: 3 }
    );
    let mut denied_port = RawClient::connect(address).await.expect("port client");
    denied_port
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            true,
        ))
        .await
        .expect("port send");
    assert_eq!(status(&mut denied_port).await, 403);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_pool01_reload_retires_idle_generation() {
    let dir = TempDir::new("m07-pool01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"pool"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            false,
        ))
        .await
        .expect("first");
    assert_eq!(status(&mut client).await, 200);
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 1);

    write_config(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    );
    assert_eq!(
        server.control().reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    client
        .send(&authenticated_request(
            origin.address,
            "alice",
            "alice-secret",
            false,
        ))
        .await
        .expect("second");
    assert_eq!(status(&mut client).await, 200);
    assert!(
        origin.accepts.load(std::sync::atomic::Ordering::SeqCst) >= 2,
        "new generation reused an idle origin socket"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m07_con01_old_connect_keeps_generation_but_new_connect_uses_policy() {
    let dir = TempDir::new("m07-con01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let echo = common::m04::spawn_echo_origin(None).await.expect("echo");
    let (server, address) = start(
        dir.path(),
        echo.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let auth = m05::authorization("alice", "alice-secret");
    let mut tunnel = RawClient::connect(address).await.expect("tunnel client");
    tunnel
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {auth}\r\n\r\n",
                echo.address, echo.address
            )
            .as_bytes(),
        )
        .await
        .expect("CONNECT");
    assert_eq!(tunnel.read_head().await.expect("200").status, 200);
    tunnel.send(b"one").await.expect("tunnel write");
    assert_eq!(tunnel.read_exact_bytes(3).await.expect("echo"), b"one");

    write_config(dir.path(), 1, "\"alice\"", 8, 2, 5000, false);
    assert_eq!(
        server.control().reload(1).await,
        ReloadOutcome::Applied { generation: 2 }
    );
    // Existing tunnel keeps its G1 policy and clocks.
    tunnel.send(b"two").await.expect("old tunnel write");
    assert_eq!(tunnel.read_exact_bytes(3).await.expect("old echo"), b"two");

    let mut denied = RawClient::connect(address).await.expect("new client");
    denied
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {auth}\r\n\r\n",
                echo.address, echo.address
            )
            .as_bytes(),
        )
        .await
        .expect("new CONNECT");
    assert_eq!(denied.read_head().await.expect("403").status, 403);
    server.shutdown().await;
}

#[tokio::test]
async fn m07_secret01_markers_do_not_enter_json_logs_or_status() {
    let dir = TempDir::new("m07-secret01");
    users_file(dir.path(), &[("alice", &m05::hash("alice-secret"), false)]);
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, address) = start(
        dir.path(),
        origin.address.port(),
        "\"alice\"",
        8,
        2,
        5000,
        false,
    )
    .await;
    let telemetry = server.telemetry();
    let (logger, receiver) = Logger::channel(64, angara::config::LogLevel::Info, telemetry);
    server.set_logger(logger);
    let marker = "M07_SECRET_MARKER";
    let auth = m05::authorization("alice", "alice-secret");
    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&m03::request(
            "GET",
            origin.address,
            &format!("/{marker}?token={marker}"),
            &[
                ("Proxy-Authorization", &auth),
                ("X-Secret-Header", marker),
                ("Cookie", marker),
            ],
            b"",
        ))
        .await
        .expect("send");
    assert_eq!(status(&mut client).await, 200);
    {
        let origin_requests = origin.requests.lock().expect("origin requests");
        assert_eq!(origin_requests.len(), 1);
        assert!(origin_requests[0].target.contains(marker));
        assert_eq!(origin_requests[0].header("X-Secret-Header"), Some(marker));
        assert_eq!(origin_requests[0].header("Cookie"), Some(marker));
        assert!(origin_requests[0].header("Proxy-Authorization").is_none());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    while let Ok(text) = receiver.recv_timeout(Duration::from_millis(100)) {
        assert!(!text.contains(marker), "secret marker in log: {text}");
    }
    let status = server.control().status();
    assert!(!format!("{status:?}").contains(marker));
    assert!(!format!("{status:?}").contains("alice-secret"));
    server.shutdown().await;
}

#[tokio::test]
async fn m07_log02_full_queue_drops_without_blocking() {
    let telemetry = angara::telemetry::Telemetry::new();
    let (logger, receiver) =
        Logger::channel(64, angara::config::LogLevel::Info, Arc::clone(&telemetry));
    // The receiver is deliberately not consumed.
    for _ in 0..1_000 {
        let mut record = LogRecord::new(Event::RequestFinished);
        record.outcome = Some(angara::logging::Outcome::Success);
        record.status = Some(200);
        logger.log(record);
    }
    assert!(receiver.try_recv().is_ok());
    let metrics = telemetry.snapshot();
    assert_eq!(metrics.log_queued, 64);
    assert_eq!(metrics.log_dropped, 936);
}
