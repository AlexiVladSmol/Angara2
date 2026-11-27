//! M11 read API, users, blocks, ACL edits, conflicts and authorization.

#![allow(clippy::field_reassign_with_default)]

mod common;

use angara::control_write::{ControlWriter, WriterOptions};
use common::m03::{self, RawClient};
use common::m05;
use common::m11;
use serde_json::json;

async fn start(
    dir: &common::TempDir,
) -> (
    angara::http::HttpServer,
    angara::control_write::WriterHandle,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let config_path = m11::write_config(dir);
    let text = std::fs::read_to_string(&config_path).unwrap();
    m05::write_secure(&config_path, &format!("# retained comment\n{text}"));
    let users_path = m11::write_users(dir);
    let read_socket = dir.path().join("read.sock");
    let socket = dir.path().join("control.sock");
    let server = m11::start_proxy(&config_path, &read_socket).await;
    let mut options = WriterOptions::new(config_path);
    options.read_socket = read_socket;
    options.socket_path = socket.clone();
    options.admin_group = "definitely-missing-angara-admin".to_owned();
    options.test_allow_uid = Some(m11::effective_uid());
    let writer = ControlWriter::start(options).await.expect("control writer");
    (server, writer, socket, users_path)
}

async fn http_status(
    proxy: std::net::SocketAddr,
    origin: std::net::SocketAddr,
    user: &str,
    password: &str,
) -> u16 {
    let mut client = RawClient::connect(proxy).await.expect("proxy client");
    client
        .send(&m05::get_request(origin, Some((user, password)), &[]))
        .await
        .expect("send request");
    client
        .read_response()
        .await
        .expect("proxy response")
        .head
        .status
}

#[tokio::test]
async fn m11_api01_two_clients_share_a_generation_and_follow_events() {
    let dir = common::TempDir::new("m11-api");
    let (server, writer, socket, _users) = start(&dir).await;
    let first = m11::ok(&socket, "snapshot", json!({})).await;
    let second = m11::ok(&socket, "snapshot", json!({})).await;
    assert_eq!(first["generation"], second["generation"]);
    assert_eq!(first["api_version"], 1);
    assert_eq!(first["writable"], true);
    assert!(
        first["config_version"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(
        first["users_version"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let users = m11::ok(&socket, "users", json!({"limit": 10})).await;
    assert_eq!(users["total"], 1);
    assert_eq!(users["users"][0]["username"], "alice");
    assert!(users["users"][0].get("password_hash").is_none());

    let version = first["users_version"].as_str().unwrap().to_owned();
    let added = m11::ok(
        &socket,
        "user.add",
        json!({
            "username": "bob",
            "password": "new secret",
            "password_confirm": "new secret",
            "operation_id": "test-add-bob",
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(added["state"], "applied");
    assert_eq!(added["saved"], true);
    assert!(
        !serde_json::to_string(&added)
            .unwrap()
            .contains("new secret")
    );

    let after = m11::ok(&socket, "snapshot", json!({})).await;
    assert_ne!(after["generation"], first["generation"]);
    assert_ne!(after["users_version"], first["users_version"]);
    let users = m11::ok(&socket, "users", json!({"limit": 10})).await;
    assert_eq!(users["total"], 2);

    let events = m11::ok(&socket, "events", json!({"cursor": 0, "limit": 100})).await;
    let kinds = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["kind"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(kinds.contains(&"users_saved"), "events: {events}");
    assert!(kinds.contains(&"config_applied"), "events: {events}");

    let text = std::fs::read_to_string(dir.path().join("users.toml")).unwrap();
    assert!(text.contains("username = \"bob\""));
    assert!(!text.contains("new secret"));

    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_write01_password_block_and_expiry_reach_the_proxy() {
    let dir = common::TempDir::new("m11-write");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, writer, socket, users_path) = start(&dir).await;
    let proxy = server.addresses()[0].1;
    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        200
    );

    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    let version = snapshot["users_version"].as_str().unwrap().to_owned();
    let outcome = m11::ok(
        &socket,
        "user.password",
        json!({
            "username": "alice",
            "password": "second secret",
            "password_confirm": "second secret",
            "operation_id": "test-password-alice",
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(outcome["state"], "applied");
    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        407
    );
    assert_eq!(
        http_status(proxy, origin.address, "alice", "second secret").await,
        200
    );

    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    let version = snapshot["users_version"].as_str().unwrap().to_owned();
    let outcome = m11::ok(
        &socket,
        "block.set",
        json!({
            "username": "alice",
            "permanent": true,
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(outcome["state"], "applied");
    assert_eq!(
        http_status(proxy, origin.address, "alice", "second secret").await,
        407
    );

    let text = std::fs::read_to_string(&users_path).unwrap();
    assert!(text.contains("disabled = true"));
    assert!(text.contains("version = 1"));

    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    let version = snapshot["users_version"].as_str().unwrap().to_owned();
    let outcome = m11::ok(
        &socket,
        "block.set",
        json!({
            "username": "alice",
            "until": "2000-01-01T00:00:00Z",
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(outcome["state"], "applied");
    assert_eq!(
        http_status(proxy, origin.address, "alice", "second secret").await,
        200,
        "an expired temporary block must allow normal authentication"
    );
    let text = std::fs::read_to_string(&users_path).unwrap();
    assert!(text.contains("version = 2"));
    assert!(!text.contains("disabled = true"));
    assert!(text.contains("blocked_until = \"2000-01-01T00:00:00Z\""));

    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    let version = snapshot["users_version"].as_str().unwrap().to_owned();
    let outcome = m11::ok(
        &socket,
        "block.set",
        json!({
            "username": "alice",
            "until": "2099-01-01T00:00:00Z",
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(outcome["state"], "applied");
    assert_eq!(
        http_status(proxy, origin.address, "alice", "second secret").await,
        407
    );
    let blocks = m11::ok(&socket, "blocks", json!({"limit": 10})).await;
    assert_eq!(blocks["total"], 1);
    assert_eq!(blocks["blocks"][0]["kind"], "temporary");

    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    let version = snapshot["users_version"].as_str().unwrap().to_owned();
    let outcome = m11::ok(
        &socket,
        "block.clear",
        json!({"username": "alice", "expected_version": version}),
    )
    .await;
    assert_eq!(outcome["state"], "applied");
    assert_eq!(
        http_status(proxy, origin.address, "alice", "second secret").await,
        200
    );
    let text = std::fs::read_to_string(&users_path).unwrap();
    assert!(text.contains("version = 1"));
    assert!(!text.contains("blocked_until"));

    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_conflict01_stale_writes_are_rejected_and_comments_survive() {
    let dir = common::TempDir::new("m11-conflict");
    let (server, writer, socket, users_path) = start(&dir).await;
    let users_path_text = std::fs::read_to_string(&users_path).unwrap();
    assert!(users_path_text.contains("version = 1"));
    std::fs::write(
        &users_path,
        format!("# retained comment\n{users_path_text}"),
    )
    .unwrap();
    m05::write_secure(&users_path, &std::fs::read_to_string(&users_path).unwrap());

    let config = m11::ok(&socket, "config", json!({})).await;
    let stale = config["disk_users_version"].as_str().unwrap().to_owned();
    let first = m11::ok(
        &socket,
        "user.add",
        json!({
            "username": "carol",
            "password": "carol secret",
            "password_confirm": "carol secret",
            "operation_id": "add-carol",
            "expected_version": stale,
        }),
    )
    .await;
    assert_eq!(first["state"], "applied");

    let second = m11::request(
        &socket,
        "user.add",
        json!({
            "username": "dave",
            "password": "dave secret",
            "password_confirm": "dave secret",
            "operation_id": "add-dave",
            "expected_version": stale,
        }),
    )
    .await;
    assert_eq!(second["ok"], false);
    assert_eq!(second["error"]["code"], "conflict");
    let text = std::fs::read_to_string(&users_path).unwrap();
    assert!(text.contains("# retained comment"));
    assert!(text.contains("username = \"carol\""));
    assert!(!text.contains("username = \"dave\""));
    assert!(text.contains("# retained comment"));

    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_acl01_rule_create_move_and_delete_preserve_unrelated_sections() {
    let dir = common::TempDir::new("m11-acl");
    let (server, writer, socket, _users) = start(&dir).await;
    let config_path = dir.path().join("proxy.toml");
    let before = std::fs::read_to_string(&config_path).unwrap();
    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    let version = snapshot["config_version"].as_str().unwrap().to_owned();

    let source_page = m11::ok(&socket, "access", json!({"section": "source", "limit": 10})).await;
    assert_eq!(source_page["total"], 1);
    assert_eq!(source_page["source_allow"][0], "127.0.0.0/8");
    let ip_page = m11::ok(
        &socket,
        "access",
        json!({"section": "ip_rules", "limit": 10}),
    )
    .await;
    assert_eq!(ip_page["total"], 1);
    assert_eq!(ip_page["ip_rules"][0]["id"], "loopback");

    let preview = m11::ok(
        &socket,
        "access.preview",
        json!({
            "expected_version": version,
            "change": {
                "kind": "rule_create",
                "rule": {
                    "id": "deny-example",
                    "action": "deny",
                    "host_exact": ["example.test"]
                }
            }
        }),
    )
    .await;
    assert_eq!(preview["valid"], true);
    assert!(preview["after"].as_str().unwrap().contains("deny-example"));

    let applied = m11::ok(
        &socket,
        "access.apply",
        json!({
            "expected_version": version,
            "change": {
                "kind": "rule_create",
                "rule": {
                    "id": "deny-example",
                    "action": "deny",
                    "host_exact": ["example.test"]
                }
            }
        }),
    )
    .await;
    assert_eq!(applied["state"], "applied");
    let text = std::fs::read_to_string(&config_path).unwrap();
    assert!(text.contains("id = \"deny-example\""));
    assert!(text.contains("[transport]"));
    assert!(text.contains("[http]"));
    assert!(text.contains("# retained comment"));
    assert!(text.contains(&before[..40]));

    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    let version = snapshot["config_version"].as_str().unwrap().to_owned();
    let rules = m11::ok(&socket, "access", json!({"section": "rules", "limit": 100})).await;
    let list = rules["rules"].as_array().unwrap();
    let index = list
        .iter()
        .position(|rule| rule["id"] == "deny-example")
        .unwrap();
    let moved = m11::ok(
        &socket,
        "access.apply",
        json!({
            "expected_version": version,
            "change": {"kind": "rule_move", "from": index, "to": 0}
        }),
    )
    .await;
    assert_eq!(moved["state"], "applied");
    let rules = m11::ok(&socket, "access", json!({"section": "rules", "limit": 100})).await;
    assert_eq!(rules["rules"][0]["id"], "deny-example");

    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    let version = snapshot["config_version"].as_str().unwrap().to_owned();
    let deleted = m11::ok(
        &socket,
        "access.apply",
        json!({
            "expected_version": version,
            "change": {"kind": "rule_delete", "index": 0}
        }),
    )
    .await;
    assert_eq!(deleted["state"], "applied");
    let text = std::fs::read_to_string(&config_path).unwrap();
    assert!(!text.contains("deny-example"));

    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_auth01_read_only_writer_connection_cannot_change_users() {
    let dir = common::TempDir::new("m11-auth");
    let config_path = m11::write_config(&dir);
    m11::write_users(&dir);
    let read_socket = dir.path().join("read.sock");
    let socket = dir.path().join("control.sock");
    let server = m11::start_proxy(&config_path, &read_socket).await;
    let mut options = WriterOptions::new(config_path);
    options.read_socket = read_socket;
    options.socket_path = socket.clone();
    options.admin_group = "definitely-missing-angara-admin".to_owned();
    options.test_allow_uid = None;
    let writer = ControlWriter::start(options).await.expect("control writer");
    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    assert_eq!(snapshot["writable"], false);
    let response = m11::request(
        &socket,
        "user.add",
        json!({
            "username": "eve",
            "password": "eve secret",
            "password_confirm": "eve secret",
            "operation_id": "denied",
            "expected_version": snapshot["users_version"],
        }),
    )
    .await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "unauthorized");
    let users = std::fs::read_to_string(dir.path().join("users.toml")).unwrap();
    assert!(!users.contains("eve"));
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_limits01_bad_versions_and_oversized_lines_are_rejected() {
    let dir = common::TempDir::new("m11-limits");
    let (server, writer, socket, _users) = start(&dir).await;
    let response = m11::request(
        &socket,
        "user.add",
        json!({"username": "x", "expected_version": "not-a-version"}),
    )
    .await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "invalid_request");

    let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
    use tokio::io::AsyncWriteExt;
    stream
        .write_all(&vec![b'x'; angara::control_protocol::MAX_LINE_BYTES + 100])
        .await
        .unwrap();
    stream.write_all(b"\n").await.unwrap();
    drop(stream);
    // The server stays alive for the next client.
    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    assert_eq!(snapshot["api_version"], 1);

    let users = m11::ok(&socket, "users", json!({"limit": 100000})).await;
    assert!(users["users"].as_array().unwrap().len() <= angara::control_protocol::MAX_PAGE);
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_acl02_first_match_is_visible_to_real_requests() {
    let dir = common::TempDir::new("m11-acl-http");
    let origin = m03::spawn_origin(|request, _| {
        if request.method == "GET" {
            m03::response("200 OK", &[], b"get")
        } else {
            m03::response("200 OK", &[], b"post")
        }
    })
    .await
    .expect("origin");
    let (server, writer, socket, _users) = start(&dir).await;
    let proxy = server.addresses()[0].1;
    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_config_version"].as_str().unwrap().to_owned();
    let applied = m11::ok(
        &socket,
        "access.apply",
        json!({
            "expected_version": version,
            "change": {
                "kind": "rule_create",
                "index": 0,
                "rule": {"id": "deny-get", "action": "deny", "methods": ["GET"]}
            }
        }),
    )
    .await;
    assert_eq!(applied["state"], "applied");

    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        403
    );
    let mut client = RawClient::connect(proxy).await.unwrap();
    let auth = m05::authorization("alice", "secret");
    client
        .send(&m03::request(
            "POST",
            origin.address,
            "/",
            &[("Proxy-Authorization", auth.as_str())],
            b"",
        ))
        .await
        .unwrap();
    assert_eq!(client.read_response().await.unwrap().head.status, 200);

    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_config_version"].as_str().unwrap().to_owned();
    let deleted = m11::ok(
        &socket,
        "access.apply",
        json!({
            "expected_version": version,
            "change": {"kind": "rule_delete", "index": 0}
        }),
    )
    .await;
    assert_eq!(deleted["state"], "applied");
    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        200
    );
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_expiry01_temporary_block_expires_without_a_write_or_restart() {
    let dir = common::TempDir::new("m11-expiry");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, writer, socket, users_path) = start(&dir).await;
    let proxy = server.addresses()[0].1;
    let until = chrono::Utc::now() + chrono::Duration::seconds(1);
    let until = until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_users_version"].as_str().unwrap().to_owned();
    let applied = m11::ok(
        &socket,
        "block.set",
        json!({
            "username": "alice",
            "until": until,
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(applied["state"], "applied");
    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        407
    );
    let saved = std::fs::read(&users_path).unwrap();
    let saved_version = angara::version::content_version(&saved);

    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        200,
        "the server clock must expire the block without an operator action"
    );
    let after = std::fs::read(&users_path).unwrap();
    assert_eq!(
        saved_version,
        angara::version::content_version(&after),
        "expiry must not rewrite users.toml"
    );
    let blocks = m11::ok(&socket, "blocks", json!({"limit": 10})).await;
    assert_eq!(blocks["total"], 0);

    writer.shutdown().await;
    server.shutdown().await;
    let read_socket = dir.path().join("read-2.sock");
    let config_path = dir.path().join("proxy.toml");
    let restarted = m11::start_proxy(&config_path, &read_socket).await;
    let restarted_proxy = restarted.addresses()[0].1;
    assert_eq!(
        http_status(restarted_proxy, origin.address, "alice", "secret").await,
        200,
        "a process restart after expiry must allow the account"
    );
    restarted.shutdown().await;
}

#[tokio::test]
async fn m11_duplicate01_duplicate_user_is_rejected_without_partial_write() {
    let dir = common::TempDir::new("m11-duplicate");
    let (server, writer, socket, users_path) = start(&dir).await;
    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_users_version"].as_str().unwrap().to_owned();
    let response = m11::request(
        &socket,
        "user.add",
        json!({
            "username": "alice",
            "password": "other secret",
            "password_confirm": "other secret",
            "operation_id": "duplicate-alice",
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "invalid_candidate");
    let text = std::fs::read_to_string(&users_path).unwrap();
    assert_eq!(text.matches("username = \"alice\"").count(), 1);
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_external01_completed_external_edit_is_detected_by_version() {
    let dir = common::TempDir::new("m11-external");
    let (server, writer, socket, users_path) = start(&dir).await;
    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_users_version"].as_str().unwrap().to_owned();
    let mut text = std::fs::read_to_string(&users_path).unwrap();
    text.insert_str(0, "# external edit\n");
    m05::write_secure(&users_path, &text);
    let response = m11::request(
        &socket,
        "user.add",
        json!({
            "username": "mallory",
            "password": "mallory secret",
            "password_confirm": "mallory secret",
            "operation_id": "external-mallory",
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "conflict");
    let text = std::fs::read_to_string(&users_path).unwrap();
    assert!(text.contains("# external edit"));
    assert!(!text.contains("mallory"));
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_restart01_restart_required_change_is_saved_but_not_applied() {
    let dir = common::TempDir::new("m11-restart");
    let (server, writer, socket, _users) = start(&dir).await;
    let config_path = dir.path().join("proxy.toml");
    let original = std::fs::read_to_string(&config_path).unwrap();
    let generation = server.control().status().generation;
    let changed = format!(
        "{original}\n[[listeners]]\nid = \"second\"\nbind = \"127.0.0.1:9\"\ntransport = \"http\"\n"
    );
    m05::write_secure(&config_path, &changed);
    let validation = m11::ok(&socket, "config.validate", json!({})).await;
    assert_eq!(validation["RestartRequired"]["fields"][0], "listeners");
    let outcome = m11::ok(
        &socket,
        "config.apply",
        json!({"expected_version": content_version_of(&changed)}),
    )
    .await;
    assert_eq!(outcome["state"], "restart_required");
    assert_eq!(outcome["saved"], false);
    assert_eq!(outcome["applied"], false);
    assert_eq!(outcome["generation"], generation);
    assert_eq!(server.control().status().generation, generation);
    assert!(
        std::fs::read_to_string(&config_path)
            .unwrap()
            .contains("id = \"second\"")
    );

    m05::write_secure(&config_path, &original);
    let validation = m11::ok(&socket, "config.validate", json!({})).await;
    assert!(validation.get("Valid").is_some(), "{validation}");
    writer.shutdown().await;
    server.shutdown().await;
}

fn content_version_of(text: &str) -> String {
    angara::version::content_version(text.as_bytes())
}

#[tokio::test]
async fn m11_subscribe01_streams_saved_and_applied_events() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let dir = common::TempDir::new("m11-subscribe");
    let (server, writer, socket, _users) = start(&dir).await;
    let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
    stream
        .write_all(
            serde_json::to_string(&json!({"v": 1, "id": 1, "op": "subscribe", "cursor": 0}))
                .unwrap()
                .as_bytes(),
        )
        .await
        .unwrap();
    stream.write_all(b"\n").await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["api_version"], 1);

    let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
    let version = snapshot["users_version"].as_str().unwrap().to_owned();
    let applied = m11::ok(
        &socket,
        "user.add",
        json!({
            "username": "subscriber",
            "password": "subscriber secret",
            "password_confirm": "subscriber secret",
            "operation_id": "subscribe-add",
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(applied["state"], "applied");

    let mut kinds = Vec::new();
    for _ in 0..4 {
        line.clear();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut line),
        )
        .await
        .expect("event timeout")
        .unwrap();
        if read == 0 {
            break;
        }
        let envelope: serde_json::Value = serde_json::from_str(&line).unwrap();
        if let Some(kind) = envelope["event"]["kind"].as_str() {
            kinds.push(kind.to_owned());
        }
        if kinds.contains(&"users_saved".to_owned()) && kinds.contains(&"config_applied".to_owned())
        {
            break;
        }
    }
    assert!(kinds.iter().any(|kind| kind == "users_saved"), "{kinds:?}");
    assert!(
        kinds.iter().any(|kind| kind == "config_applied"),
        "{kinds:?}"
    );
    drop(reader);
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_keepalive01_block_is_checked_on_every_request() {
    let dir = common::TempDir::new("m11-keepalive");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, writer, socket, _users) = start(&dir).await;
    let proxy = server.addresses()[0].1;
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(client.read_response().await.unwrap().head.status, 200);

    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_users_version"].as_str().unwrap().to_owned();
    let applied = m11::ok(
        &socket,
        "block.set",
        json!({"username": "alice", "permanent": true, "expected_version": version}),
    )
    .await;
    assert_eq!(applied["state"], "applied");

    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", "secret")),
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(
        client.read_response().await.unwrap().head.status,
        407,
        "the same keep-alive connection must re-check the block"
    );
    // Closing the write side keeps the raw client from waiting for another response.
    let _ = client.shutdown_write().await;
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_cache01_block_wins_over_a_warm_cache_entry() {
    let dir = common::TempDir::new("m11-cache-block");
    let origin = m03::spawn_origin(|_, _| {
        m03::response("200 OK", &[("Cache-Control", "max-age=60")], b"cached")
    })
    .await
    .expect("origin");
    let mut auth = m05::AuthConfig::default();
    auth.extra = "[cache]\nenabled = true\n".to_owned();
    let config_path = auth.write(&dir);
    let users_path = m11::write_users(&dir);
    let read_socket = dir.path().join("read.sock");
    let socket = dir.path().join("control.sock");
    let server = m11::start_proxy(&config_path, &read_socket).await;
    let mut options = WriterOptions::new(config_path);
    options.read_socket = read_socket;
    options.socket_path = socket.clone();
    options.admin_group = "definitely-missing-angara-admin".to_owned();
    options.test_allow_uid = Some(m11::effective_uid());
    let writer = ControlWriter::start(options).await.expect("writer");
    let proxy = server.addresses()[0].1;

    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        200
    );
    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        200
    );
    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_users_version"].as_str().unwrap().to_owned();
    let applied = m11::ok(
        &socket,
        "block.set",
        json!({"username": "alice", "permanent": true, "expected_version": version}),
    )
    .await;
    assert_eq!(applied["state"], "applied");
    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        407,
        "authentication and block checks precede a cache hit"
    );
    let _ = users_path;
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_retry01_operation_id_returns_the_cached_result_before_version_check() {
    let dir = common::TempDir::new("m11-retry");
    let (server, writer, socket, _users) = start(&dir).await;
    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_users_version"].as_str().unwrap().to_owned();
    let request = json!({
        "username": "retry",
        "password": "retry secret",
        "password_confirm": "retry secret",
        "operation_id": "retry-operation",
        "expected_version": version,
    });
    let first = m11::ok(&socket, "user.add", request.clone()).await;
    assert_eq!(first["state"], "applied");
    let repeat = m11::ok(&socket, "user.add", request).await;
    assert_eq!(repeat, first, "a repeated operation must not write twice");
    let users = std::fs::read_to_string(dir.path().join("users.toml")).unwrap();
    assert_eq!(users.matches("username = \"retry\"").count(), 1);
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_invalid01_invalid_candidate_and_subscriber_limit_are_bounded() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let dir = common::TempDir::new("m11-invalid");
    let (server, writer, socket, _users) = start(&dir).await;
    let config_path = dir.path().join("proxy.toml");
    let original = std::fs::read_to_string(&config_path).unwrap();
    let invalid = original.replace(
        "schema_version = 1",
        "schema_version = 1\nunknown_key = true",
    );
    m05::write_secure(&config_path, &invalid);
    let state = m11::ok(&socket, "config", json!({})).await;
    assert_eq!(state["valid"], false);
    let response = m11::request(&socket, "config.validate", json!({})).await;
    assert_eq!(response["ok"], true, "{response}");
    assert!(response["result"].get("Invalid").is_some(), "{response}");
    let response = m11::request(&socket, "config.apply", json!({})).await;
    assert_eq!(response["ok"], false, "{response}");
    assert_eq!(response["error"]["code"], "invalid_candidate");
    m05::write_secure(&config_path, &original);

    let mut subscriptions = Vec::new();
    for index in 0..angara::control_protocol::MAX_SUBSCRIBERS {
        let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        stream
            .write_all(
                serde_json::to_string(&json!({"v":1,"id":index,"op":"subscribe","cursor":0}))
                    .unwrap()
                    .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(b"\n").await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.contains("\"ok\":true"), "{line}");
        subscriptions.push(reader);
    }
    let mut extra = tokio::net::UnixStream::connect(&socket).await.unwrap();
    extra
        .write_all(b"{\"v\":1,\"id\":99,\"op\":\"subscribe\",\"cursor\":0}\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(extra);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("busy"), "{line}");
    drop(subscriptions);
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_connect01_block_rejects_new_tunnels_and_keeps_existing_ones() {
    use common::m04;

    let dir = common::TempDir::new("m11-connect");
    let echo = m04::spawn_echo_origin(None).await.expect("echo origin");
    let mut auth = m05::AuthConfig::default();
    auth.connect_allowed_ports = echo.address.port().to_string();
    let config_path = auth.write(&dir);
    m11::write_users(&dir);
    let read_socket = dir.path().join("read.sock");
    let socket = dir.path().join("control.sock");
    let server = m11::start_proxy(&config_path, &read_socket).await;
    let mut options = WriterOptions::new(config_path);
    options.read_socket = read_socket;
    options.socket_path = socket.clone();
    options.admin_group = "definitely-missing-angara-admin".to_owned();
    options.test_allow_uid = Some(m11::effective_uid());
    let writer = ControlWriter::start(options).await.expect("writer");
    let proxy = server.addresses()[0].1;

    let authority = echo.address.to_string();
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {}\r\n\r\n",
        m05::authorization("alice", "secret")
    );
    let mut tunnel = RawClient::connect(proxy).await.unwrap();
    tunnel.send(request.as_bytes()).await.unwrap();
    assert_eq!(tunnel.read_head().await.unwrap().status, 200);
    tunnel.send(b"before").await.unwrap();
    assert_eq!(tunnel.read_exact_bytes(6).await.unwrap(), b"before");

    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_users_version"].as_str().unwrap().to_owned();
    let applied = m11::ok(
        &socket,
        "block.set",
        json!({"username": "alice", "permanent": true, "expected_version": version}),
    )
    .await;
    assert_eq!(applied["state"], "applied");

    tunnel.send(b"after").await.unwrap();
    assert_eq!(
        tunnel.read_exact_bytes(5).await.unwrap(),
        b"after",
        "an already established tunnel keeps working under the M11 policy"
    );
    let mut refused = RawClient::connect(proxy).await.unwrap();
    refused.send(request.as_bytes()).await.unwrap();
    assert_eq!(
        refused.read_head().await.unwrap().status,
        407,
        "a new CONNECT is rejected before dial"
    );
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_load01_many_independent_clients_do_not_block_the_proxy() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let dir = common::TempDir::new("m11-load");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let (server, writer, socket, _users) = start(&dir).await;
    let proxy = server.addresses()[0].1;

    // Open the maximum number of subscriptions and leave them idle.
    let mut subscribers = Vec::new();
    for index in 0..angara::control_protocol::MAX_SUBSCRIBERS {
        let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
        stream
            .write_all(
                serde_json::to_string(&json!({"v":1,"id":index,"op":"subscribe","cursor":0}))
                    .unwrap()
                    .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(b"\n").await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        subscribers.push(reader);
    }

    let done = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let socket = socket.clone();
        let done = Arc::clone(&done);
        tasks.push(tokio::spawn(async move {
            for _ in 0..5 {
                let snapshot = m11::ok(&socket, "snapshot", json!({})).await;
                assert_eq!(snapshot["api_version"], 1);
                let users = m11::ok(&socket, "users", json!({"limit": 100})).await;
                assert!(users["total"].as_u64().unwrap() >= 1);
            }
            done.fetch_add(1, Ordering::SeqCst);
        }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .expect("control clients timed out");
    assert_eq!(done.load(Ordering::SeqCst), 4);
    assert_eq!(
        http_status(proxy, origin.address, "alice", "secret").await,
        200,
        "proxy traffic must continue while control clients are active"
    );
    drop(subscribers);
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn m11_empty01_first_user_can_be_added_to_an_empty_users_file() {
    let dir = common::TempDir::new("m11-empty-users");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let auth = m05::AuthConfig::default();
    let config_path = auth.write(&dir);
    let users_path = dir.path().join("users.toml");
    m05::write_secure(&users_path, "version = 1\nusers = []\n");
    let read_socket = dir.path().join("read.sock");
    let socket = dir.path().join("control.sock");
    let server = m11::start_proxy(&config_path, &read_socket).await;
    let mut options = WriterOptions::new(config_path);
    options.read_socket = read_socket;
    options.socket_path = socket.clone();
    options.admin_group = "definitely-missing-angara-admin".to_owned();
    options.test_allow_uid = Some(m11::effective_uid());
    let writer = ControlWriter::start(options).await.expect("writer");
    let proxy = server.addresses()[0].1;

    let config = m11::ok(&socket, "config", json!({})).await;
    let version = config["disk_users_version"].as_str().unwrap().to_owned();
    let added = m11::ok(
        &socket,
        "user.add",
        json!({
            "username": "first",
            "password": "first secret",
            "password_confirm": "first secret",
            "operation_id": "empty-first",
            "expected_version": version,
        }),
    )
    .await;
    assert_eq!(added["state"], "applied");
    let text = std::fs::read_to_string(&users_path).unwrap();
    assert!(text.contains("version = 1"));
    assert!(text.contains("[[users]]"));
    assert!(text.contains("username = \"first\""));
    assert_eq!(
        http_status(proxy, origin.address, "first", "first secret").await,
        200,
        "the first account must authenticate after being added"
    );
    writer.shutdown().await;
    server.shutdown().await;
}
