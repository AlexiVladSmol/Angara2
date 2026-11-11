//! Focused M05 tests: users snapshot, Basic guard, identity selectors, pool
//! isolation and the `users hash` CLI input contract.

mod common;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use angara::auth::{Argon2Verifier, PasswordVerifier as _, hash_password, prepare_password};
use angara::config::Config;
use angara::http::HttpServer;
use angara::outbound::{OutboundError, OutboundService, RequestContext};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::m03::{self, RawClient};

fn hash(password: &str) -> String {
    let password = prepare_password(password).expect("valid test password");
    hash_password(&password, &[0x42; 16]).expect("test hash")
}

fn users_text(entries: &[(&str, &str, bool)]) -> String {
    let mut text = String::from("version = 1\n");
    if entries.is_empty() {
        text.push_str("users = []\n");
    }
    for (username, password_hash, disabled) in entries {
        text.push_str(&format!(
            "\n[[users]]\nusername = \"{username}\"\npassword_hash = \"{password_hash}\"\ndisabled = {disabled}\n"
        ));
    }
    text
}

fn write_secure(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
}

fn proxy_config(
    users_file: &str,
    bind: &str,
    extra_listener: &str,
    access_rules: &str,
    connect_port: u16,
) -> String {
    format!(
        r#"
schema_version = 1

[runtime]
worker_threads = 2

[limits]
max_connections = 64
max_client_connections = 16
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 2000

[auth]
users_file = "{users_file}"
max_verifying = 2
verify_timeout_ms = 2000

[[listeners]]
id = "proxy"
bind = "{bind}"
transport = "http"
auth = "basic"
{extra_listener}

[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

{access_rules}

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
pool_max_idle = 4
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 4000

[connect]
allowed_ports = [{connect_port}]
half_close_timeout_ms = 1000
"#
    )
}

async fn start_config(path: &Path) -> (HttpServer, SocketAddr) {
    let config = Arc::new(Config::load(path).expect("valid auth config"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind ephemeral proxy");
    let address = server.addresses()[0].1;
    (server, address)
}

fn authorization(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

fn request_with_auth(
    target: SocketAddr,
    auth: Option<(&str, &str)>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut all_headers = headers.to_vec();
    let auth_value;
    if let Some((user, password)) = auth {
        auth_value = authorization(user, password);
        all_headers.push(("Proxy-Authorization", auth_value.as_str()));
    }
    m03::request("GET", target, "/", &all_headers, body)
}

#[test]
fn config_requires_explicit_file_context_for_relative_users_file() {
    let dir = common::TempDir::new("m05-config-context");
    let users_path = dir.path().join("users.toml");
    write_secure(
        &users_path,
        &users_text(&[("alice", &hash("secret"), false)]),
    );
    let config_path = dir.path().join("proxy.toml");
    let text = proxy_config(
        "users.toml",
        "127.0.0.1:3128",
        "",
        r#"
[[access.rules]]
id = "alice"
action = "allow"
users = ["alice"]
"#,
        443,
    );
    write_secure(&config_path, &text);

    let error = Config::parse(&text).expect_err("context-free parse must fail");
    let message = error.to_string();
    assert!(message.contains("configuration file context"), "{message}");
    assert!(!message.contains("users.toml"), "{message}");

    let parsed = Config::parse_with_base_dir(&text, dir.path()).expect("base-dir parse");
    assert!(parsed.auth().is_some());
    let loaded = Config::load(&config_path).expect("load relative users file");
    assert_eq!(
        loaded.listener("proxy").expect("listener").auth(),
        angara::auth::AuthMode::Basic
    );
}

#[test]
fn absolute_users_file_path_is_supported() {
    let dir = common::TempDir::new("m05-config-absolute");
    let users_path = dir.path().join("users.toml");
    write_secure(
        &users_path,
        &users_text(&[("alice", &hash("secret"), false)]),
    );
    let users = users_path.to_string_lossy().replace('\\', "/");
    let text = proxy_config(
        &users,
        "127.0.0.1:3128",
        "",
        r#"
[[access.rules]]
id = "alice"
action = "allow"
users = ["alice"]
"#,
        443,
    );
    Config::parse_with_base_dir(&text, Path::new(".")).expect("absolute users file");
}

#[test]
fn users_file_and_record_errors_reject_the_whole_snapshot() {
    let dir = common::TempDir::new("m05-users-errors");
    let config_path = dir.path().join("proxy.toml");
    let text = proxy_config(
        "users.toml",
        "127.0.0.1:3128",
        "",
        r#"
[[access.rules]]
id = "alice"
action = "allow"
users = ["alice"]
"#,
        443,
    );
    write_secure(&config_path, &text);

    let cases = [
        ("version = 2\nusers = []\n".to_owned(), "version"),
        (
            users_text(&[
                ("alice", &hash("one"), false),
                ("alice", &hash("two"), false),
            ]),
            "duplicated",
        ),
        (
            "version = 1\n\n[[users]]\nusername = \"_bad\"\npassword_hash = \"x\"\n".to_owned(),
            "username",
        ),
        (
            "version = 1\n\n[[users]]\nusername = \"alice\"\npassword_hash = \"$argon2id$v=19$m=1,t=2,p=1$AA$AA\"\n"
                .to_owned(),
            "password_hash",
        ),
        (
            "version = 1\nusers = []\nunknown = \"MARKER-SECRET\"\n".to_owned(),
            "unknown field",
        ),
    ];
    for (index, (contents, expected)) in cases.iter().enumerate() {
        let users_path = dir.path().join("users.toml");
        write_secure(&users_path, contents);
        let error = Config::load(&config_path)
            .expect_err("invalid users snapshot")
            .to_string();
        assert!(
            error.contains(expected),
            "case {index}: expected {expected}: {error}"
        );
        assert!(!error.contains("MARKER-SECRET"), "case {index}: {error}");
        assert!(!error.contains("$argon2"), "case {index}: {error}");
    }

    fs::remove_file(dir.path().join("users.toml")).expect("remove users file");
    let error = Config::load(&config_path)
        .expect_err("missing users file")
        .to_string();
    assert!(error.contains("cannot open users file"), "{error}");

    fs::create_dir(dir.path().join("users.toml")).expect("directory users file");
    let error = Config::load(&config_path)
        .expect_err("directory users file")
        .to_string();
    assert!(
        error.contains("cannot open users file") || error.contains("regular file"),
        "{error}"
    );

    fs::remove_dir(dir.path().join("users.toml")).expect("remove directory");
    let oversized = "a".repeat(1_048_577);
    write_secure(&dir.path().join("users.toml"), &oversized);
    let error = Config::load(&config_path)
        .expect_err("oversized users file")
        .to_string();
    assert!(error.contains("1 MiB"), "{error}");

    let users_path = dir.path().join("users.toml");
    fs::write(&users_path, [0xff, 0xfe, 0x00]).expect("invalid UTF-8");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&users_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
    let error = Config::load(&config_path)
        .expect_err("invalid UTF-8 users file")
        .to_string();
    assert!(error.contains("UTF-8"), "{error}");
}

#[cfg(unix)]
#[test]
fn linux_users_file_permissions_are_checked_on_the_open_handle() {
    use std::os::unix::fs::PermissionsExt;

    let dir = common::TempDir::new("m05-users-permissions");
    let config_path = dir.path().join("proxy.toml");
    let users_path = dir.path().join("users.toml");
    let text = proxy_config(
        "users.toml",
        "127.0.0.1:3128",
        "",
        r#"
[[access.rules]]
id = "alice"
action = "allow"
users = ["alice"]
"#,
        443,
    );
    write_secure(&config_path, &text);
    write_secure(
        &users_path,
        &users_text(&[("alice", &hash("secret"), false)]),
    );

    fs::set_permissions(&users_path, fs::Permissions::from_mode(0o644)).expect("chmod unsafe");
    let error = Config::load(&config_path)
        .expect_err("world-readable users file must be rejected")
        .to_string();
    assert!(error.contains("unsafe permissions"), "{error}");

    fs::set_permissions(&users_path, fs::Permissions::from_mode(0o640))
        .expect("chmod safe group-read");
    Config::load(&config_path).expect("0640 is allowed");
}

#[test]
fn auth_defaults_ranges_and_required_fields_are_strict() {
    let dir = common::TempDir::new("m05-auth-ranges");
    write_secure(&dir.path().join("users.toml"), &users_text(&[]));
    let base = proxy_config(
        "users.toml",
        "127.0.0.1:3128",
        "",
        "[[access.rules]]\nid = \"allow\"\naction = \"allow\"\n",
        443,
    );
    let defaults = Config::parse_with_base_dir(&base, dir.path()).expect("defaults");
    let auth = defaults.auth().expect("auth config");
    assert_eq!(auth.max_verifying(), 2);
    assert_eq!(auth.verify_timeout(), Duration::from_millis(2_000));

    for (old, new, expected) in [
        (
            "max_verifying = 2",
            "max_verifying = 0",
            "auth.max_verifying",
        ),
        (
            "max_verifying = 2",
            "max_verifying = 17",
            "auth.max_verifying",
        ),
        (
            "verify_timeout_ms = 2000",
            "verify_timeout_ms = 99",
            "auth.verify_timeout_ms",
        ),
        (
            "verify_timeout_ms = 2000",
            "verify_timeout_ms = 30001",
            "auth.verify_timeout_ms",
        ),
    ] {
        let error = Config::parse_with_base_dir(&base.replace(old, new), dir.path())
            .expect_err("auth range")
            .to_string();
        assert!(error.contains(expected), "{new}: {error}");
    }

    let empty = base.replace("users_file = \"users.toml\"", "users_file = \"\"");
    let error = Config::parse_with_base_dir(&empty, dir.path())
        .expect_err("empty users_file")
        .to_string();
    assert!(error.contains("auth.users_file"), "{error}");

    let missing = base.replace("users_file = \"users.toml\"\n", "");
    let error = Config::parse_with_base_dir(&missing, dir.path())
        .expect_err("missing users_file")
        .to_string();
    assert!(error.contains("users_file"), "{error}");
}

#[test]
fn listener_auth_and_insecure_basic_rules_are_strict() {
    let dir = common::TempDir::new("m05-listener-auth");
    let users_path = dir.path().join("users.toml");
    write_secure(&users_path, &users_text(&[]));
    let base = |bind: &str, extra: &str| {
        proxy_config(
            "users.toml",
            bind,
            extra,
            r#"
[[access.rules]]
id = "allow"
action = "allow"
"#,
            443,
        )
    };

    Config::parse_with_base_dir(&base("127.0.0.1:3128", ""), dir.path()).expect("IPv4 loopback");
    Config::parse_with_base_dir(&base("[::1]:3128", ""), dir.path()).expect("IPv6 loopback");
    let wildcard = Config::parse_with_base_dir(&base("0.0.0.0:3128", ""), dir.path())
        .expect_err("wildcard Basic must fail");
    assert!(wildcard.to_string().contains("allow_insecure_basic"));
    Config::parse_with_base_dir(
        &base("0.0.0.0:3128", "allow_insecure_basic = true"),
        dir.path(),
    )
    .expect("explicit insecure opt-in");

    let none_with_opt_in = base("127.0.0.1:3128", "").replace(
        "auth = \"basic\"",
        "auth = \"none\"\nallow_insecure_basic = true",
    );
    let error = Config::parse_with_base_dir(&none_with_opt_in, dir.path())
        .expect_err("insecure flag needs basic");
    assert!(error.to_string().contains("allow_insecure_basic"));

    let missing_auth = proxy_config(
        "users.toml",
        "127.0.0.1:3128",
        "",
        r#"
[[access.rules]]
id = "allow"
action = "allow"
"#,
        443,
    )
    .replace(
        "[auth]\nusers_file = \"users.toml\"\nmax_verifying = 2\nverify_timeout_ms = 2000\n",
        "",
    );
    let error = Config::parse_with_base_dir(&missing_auth, dir.path())
        .expect_err("basic listener requires [auth]");
    assert!(error.to_string().contains("listeners[0].auth"));
}

#[test]
fn user_selector_lists_are_nonempty_unique_and_strict() {
    let dir = common::TempDir::new("m05-selectors");
    write_secure(&dir.path().join("users.toml"), &users_text(&[]));
    for users in [
        "users = []",
        "users = [\"alice\", \"alice\"]",
        "users = [\"_bad\"]",
    ] {
        let text = proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            &format!("[[access.rules]]\nid = \"rule\"\naction = \"allow\"\n{users}\n"),
            443,
        );
        let error = Config::parse_with_base_dir(&text, dir.path())
            .expect_err("invalid users selector")
            .to_string();
        assert!(error.contains("users"), "{users}: {error}");
    }

    let text = proxy_config(
        "users.toml",
        "127.0.0.1:3128",
        "",
        "[[access.rules]]\nid = \"rule\"\naction = \"allow\"\nusers = [\"alice\"]\n",
        443,
    ) + "\n[[routing.rules]]\nid = \"route\"\negress_id = \"system\"\nusers = [\"alice\"]\n";
    let config = Config::parse_with_base_dir(&text, dir.path()).expect("routing users");
    assert_eq!(
        config.routing().rules()[0].selectors().users(),
        Some(&["alice".to_owned()][..])
    );

    let ghost = proxy_config(
        "users.toml",
        "127.0.0.1:3128",
        "",
        "[[access.rules]]\nid = \"ghost\"\naction = \"allow\"\nusers = [\"ghost\"]\n",
        443,
    );
    Config::parse_with_base_dir(&ghost, dir.path())
        .expect("selectors may name users absent from the current snapshot");

    let mut many = String::from("[[access.rules]]\nid = \"many\"\naction = \"allow\"\nusers = [");
    for index in 0..257 {
        if index > 0 {
            many.push_str(", ");
        }
        many.push_str(&format!("\"user{index}\""));
    }
    many.push_str("]\n");
    let too_many = proxy_config("users.toml", "127.0.0.1:3128", "", &many, 443);
    let error = Config::parse_with_base_dir(&too_many, dir.path())
        .expect_err("users selector is bounded")
        .to_string();
    assert!(error.contains("at most 256"), "{error}");
}

#[cfg(unix)]
#[test]
fn users_file_symlink_must_resolve_to_a_regular_file() {
    use std::os::unix::fs::symlink;

    let dir = common::TempDir::new("m05-users-symlink");
    let real = dir.path().join("real-users.toml");
    write_secure(&real, &users_text(&[("alice", &hash("secret"), false)]));
    let link = dir.path().join("users.toml");
    symlink(&real, &link).expect("symlink regular file");
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        &proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            "[[access.rules]]\nid = \"allow\"\naction = \"allow\"\n",
            443,
        ),
    );
    Config::load(&config_path).expect("symlink to a regular file is accepted");

    fs::remove_file(&link).expect("remove symlink");
    symlink(dir.path(), &link).expect("symlink directory");
    let error = Config::load(&config_path)
        .expect_err("symlink to a directory must be rejected")
        .to_string();
    assert!(error.contains("regular file"), "{error}");
}

#[tokio::test]
async fn basic_http_guard_and_header_filtering() {
    let origin = m03::spawn_origin(|_request, _index| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let dir = common::TempDir::new("m05-http");
    let users_path = dir.path().join("users.toml");
    write_secure(
        &users_path,
        &users_text(&[
            ("alice", &hash("alice-secret"), false),
            ("disabled", &hash("disabled-secret"), true),
        ]),
    );
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        &proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            r#"
[[access.rules]]
id = "alice"
action = "allow"
users = ["alice"]
"#,
            443,
        )
        .replace("verify_timeout_ms = 2000", "verify_timeout_ms = 10000"),
    );
    let (server, address) = start_config(&config_path).await;

    let expect_without_auth = format!(
        "GET http://{}/ HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\n\r\n",
        origin.address, origin.address
    );
    let options_without_auth = format!(
        "OPTIONS http://{}/ HTTP/1.1\r\nHost: {}\r\nMax-Forwards: 0\r\n\r\n",
        origin.address, origin.address
    );
    for request in [
        request_with_auth(origin.address, None, &[], b""),
        request_with_auth(origin.address, Some(("alice", "wrong")), &[], b""),
        request_with_auth(
            origin.address,
            Some(("disabled", "disabled-secret")),
            &[],
            b"",
        ),
        request_with_auth(origin.address, Some(("nobody", "anything")), &[], b""),
        request_with_auth(origin.address, Some(("Alice", "alice-secret")), &[], b""),
        m03::request(
            "GET",
            origin.address,
            "/",
            &[("Proxy-Authorization", "Basic !!!")],
            b"",
        ),
        expect_without_auth.into_bytes(),
        options_without_auth.into_bytes(),
    ] {
        let mut client = RawClient::connect(address).await.expect("client");
        client.send(&request).await.expect("send");
        let response = client.read_response().await.expect("407 response");
        assert_eq!(response.head.status, 407, "{:?}", response.head);
        assert_eq!(
            response.header("proxy-authenticate"),
            Some("Basic realm=\"Angara\", charset=\"UTF-8\"")
        );
        assert_eq!(response.header("connection"), Some("close"));
        assert!(response.interim.is_empty());
    }
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);

    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&request_with_auth(
            origin.address,
            Some(("alice", "alice-secret")),
            &[("Authorization", "Bearer site-token")],
            b"",
        ))
        .await
        .expect("send");
    let response = client.read_response().await.expect("200 response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "ok");
    {
        let recorded = origin.requests.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].header("authorization"),
            Some("Bearer site-token")
        );
        assert_eq!(recorded[0].header("proxy-authorization"), None);
    }

    let auth_value = authorization("alice", "alice-secret");
    let options = m03::request(
        "OPTIONS",
        origin.address,
        "/",
        &[
            ("Proxy-Authorization", auth_value.as_str()),
            ("Max-Forwards", "0"),
        ],
        b"",
    );
    let mut client = RawClient::connect(address).await.expect("options client");
    client.send(&options).await.expect("send options");
    assert_eq!(
        client
            .read_response()
            .await
            .expect("options response")
            .head
            .status,
        204
    );
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 1);

    server.shutdown().await;
}

#[tokio::test]
async fn keepalive_reauthenticates_and_pool_isolates_users() {
    let origin = m03::spawn_origin(|_request, _index| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let dir = common::TempDir::new("m05-keepalive");
    write_secure(
        &dir.path().join("users.toml"),
        &users_text(&[
            ("alice", &hash("alice-secret"), false),
            ("bob", &hash("bob-secret"), false),
        ]),
    );
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        &proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            r#"
[[access.rules]]
id = "alice"
action = "allow"
users = ["alice"]

[[access.rules]]
id = "bob"
action = "allow"
users = ["bob"]
"#,
            443,
        ),
    );
    let (server, address) = start_config(&config_path).await;

    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&request_with_auth(
            origin.address,
            Some(("alice", "alice-secret")),
            &[],
            b"",
        ))
        .await
        .expect("alice request");
    assert_eq!(
        client.read_response().await.expect("alice").head.status,
        200
    );
    client
        .send(&request_with_auth(
            origin.address,
            Some(("bob", "bob-secret")),
            &[],
            b"",
        ))
        .await
        .expect("bob request");
    assert_eq!(client.read_response().await.expect("bob").head.status, 200);
    client
        .send(&request_with_auth(origin.address, None, &[], b""))
        .await
        .expect("anonymous request");
    assert_eq!(
        client
            .read_response()
            .await
            .expect("anonymous 407")
            .head
            .status,
        407
    );

    let accepts = origin.accepts.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        accepts, 2,
        "different users must not share an origin socket"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&request_with_auth(
            origin.address,
            Some(("alice", "alice-secret")),
            &[],
            b"",
        ))
        .await
        .expect("alice reuse request");
    assert_eq!(
        client
            .read_response()
            .await
            .expect("alice reuse")
            .head
            .status,
        200
    );
    assert_eq!(
        origin.accepts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "one user must be able to reuse the origin pool"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn authenticated_user_can_still_be_denied_by_request_acl() {
    let origin = m03::spawn_origin(|_request, _index| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    let dir = common::TempDir::new("m05-acl");
    write_secure(
        &dir.path().join("users.toml"),
        &users_text(&[
            ("alice", &hash("alice-secret"), false),
            ("bob", &hash("bob-secret"), false),
        ]),
    );
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        &proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            r#"
[[access.rules]]
id = "alice"
action = "allow"
users = ["alice"]
"#,
            443,
        ),
    );
    let (server, address) = start_config(&config_path).await;

    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(&request_with_auth(
            origin.address,
            Some(("bob", "bob-secret")),
            &[],
            b"",
        ))
        .await
        .expect("bob request");
    let response = client.read_response().await.expect("bob 403");
    assert_eq!(response.head.status, 403);
    assert!(response.interim.is_empty());
    assert_eq!(origin.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn connect_authenticates_before_dial() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo listener");
    let echo_port = listener.local_addr().expect("echo address").port();
    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    let echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            task_accepts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buffer = [0_u8; 64];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    if stream.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let dir = common::TempDir::new("m05-connect");
    write_secure(
        &dir.path().join("users.toml"),
        &users_text(&[("alice", &hash("alice-secret"), false)]),
    );
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        &proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            &format!(
                "[[access.rules]]\nid = \"alice-connect\"\naction = \"allow\"\nusers = [\"alice\"]\nmethods = [\"CONNECT\"]\nports = [{echo_port}]\n"
            ),
            echo_port,
        ),
    );
    let (server, address) = start_config(&config_path).await;

    let connect = |auth: Option<(&str, &str)>| {
        let mut request =
            format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n");
        if let Some((user, password)) = auth {
            request.push_str(&format!(
                "Proxy-Authorization: {}\r\n",
                authorization(user, password)
            ));
        }
        request.push_str("\r\n");
        request
    };

    for request in [
        connect(None),
        connect(Some(("alice", "wrong"))),
        connect(Some(("nobody", "anything"))),
    ] {
        let mut client = RawClient::connect(address).await.expect("client");
        client.send(request.as_bytes()).await.expect("send");
        let response = client.read_response().await.expect("407");
        assert_eq!(response.head.status, 407);
        assert_eq!(
            response.header("proxy-authenticate"),
            Some("Basic realm=\"Angara\", charset=\"UTF-8\"")
        );
    }
    assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 0);

    let mut client = RawClient::connect(address).await.expect("client");
    client
        .send(connect(Some(("alice", "alice-secret"))).as_bytes())
        .await
        .expect("send connect");
    let response = client.read_head().await.expect("200");
    assert_eq!(response.status, 200);
    client.send(b"ping").await.expect("tunnel bytes");
    assert_eq!(client.read_exact_bytes(4).await.expect("echo"), b"ping");
    drop(client);

    server.shutdown().await;
    echo_task.abort();
}

#[tokio::test]
async fn anonymous_outbound_context_cannot_bypass_basic_listener() {
    let dir = common::TempDir::new("m05-outbound");
    write_secure(
        &dir.path().join("users.toml"),
        &users_text(&[("alice", &hash("alice-secret"), false)]),
    );
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        &proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            r#"
[[access.rules]]
id = "allow"
action = "allow"
"#,
            443,
        ),
    );
    let config = Arc::new(Config::load(&config_path).expect("config"));
    let service = OutboundService::new(config);
    let context = RequestContext::new("127.0.0.1".parse().expect("source"), "proxy");
    let error = service
        .open_outbound(
            &context,
            &http::Method::GET,
            "http://127.0.0.1:9/",
            Some("127.0.0.1:9"),
        )
        .await
        .err()
        .expect("anonymous context must be rejected");
    assert_eq!(error, OutboundError::AuthenticationRequired);
}

fn run_hash(args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_angara"));
    command.args(args);
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn angara users hash");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("write stdin");
    }
    child.wait_with_output().expect("wait for users hash")
}

#[test]
fn cli_users_hash_stdin_prints_only_one_phc() {
    let output = run_hash(&["users", "hash", "--password-stdin"], Some(b"secret\n"));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let stdout = String::from_utf8(output.stdout).expect("PHC stdout");
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
    assert!(stdout.ends_with('\n'));
    let phc = stdout.trim_end_matches('\n');
    assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
    assert_eq!(phc.len(), 97, "{phc}");
    assert!(Argon2Verifier.verify(phc, "secret").expect("verify"));

    let crlf = run_hash(
        &["users", "hash", "--password-stdin"],
        Some(b"line with : spaces\r\n"),
    );
    assert_eq!(crlf.status.code(), Some(0));
    let crlf_phc = String::from_utf8(crlf.stdout)
        .expect("CRLF PHC")
        .trim_end_matches('\n')
        .to_owned();
    assert!(
        Argon2Verifier
            .verify(&crlf_phc, "line with : spaces")
            .expect("CRLF verify")
    );

    let eof = run_hash(&["users", "hash", "--password-stdin"], Some(b"no-newline"));
    assert_eq!(eof.status.code(), Some(0));
    let eof_phc = String::from_utf8(eof.stdout)
        .expect("EOF PHC")
        .trim_end_matches('\n')
        .to_owned();
    assert!(
        Argon2Verifier
            .verify(&eof_phc, "no-newline")
            .expect("EOF verify")
    );

    let nfc = run_hash(
        &["users", "hash", "--password-stdin"],
        Some("cafe\u{301}\n".as_bytes()),
    );
    assert_eq!(nfc.status.code(), Some(0));
    let nfc_phc = String::from_utf8(nfc.stdout)
        .expect("NFC PHC")
        .trim_end_matches('\n')
        .to_owned();
    assert!(
        Argon2Verifier
            .verify(&nfc_phc, "café")
            .expect("composed verify"),
        "stdin hashing must normalize to NFC"
    );

    let second = run_hash(&["users", "hash", "--password-stdin"], Some(b"secret\n"));
    assert_ne!(
        phc,
        String::from_utf8(second.stdout)
            .expect("second PHC")
            .trim_end()
    );
}

#[test]
fn cli_users_hash_rejects_bad_stdin_and_surprising_inputs() {
    for (input, expected) in [
        (b"".as_slice(), "empty"),
        (b"\n".as_slice(), "empty"),
        (b"one\ntwo\n".as_slice(), "exactly one line"),
        (&[b'a'; 1_028][..], "1027-byte limit"),
        (&[0xff, b'\n'][..], "UTF-8"),
        (b"bad\rcontrol\n".as_slice(), "control"),
    ] {
        let output = run_hash(&["users", "hash", "--password-stdin"], Some(input));
        assert_eq!(output.status.code(), Some(1), "{input:?}");
        assert!(output.stdout.is_empty(), "{input:?}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{input:?}: {error}");
    }

    let no_tty = run_hash(&["users", "hash"], None);
    assert_eq!(no_tty.status.code(), Some(2));
    assert!(no_tty.stdout.is_empty());
    assert!(String::from_utf8_lossy(&no_tty.stderr).contains("--password-stdin"));

    let argv_password = run_hash(&["users", "hash", "secret"], None);
    assert_eq!(argv_password.status.code(), Some(2));
    assert!(argv_password.stdout.is_empty());

    let duplicate = run_hash(
        &["users", "hash", "--password-stdin", "--password-stdin"],
        Some(b"secret\n"),
    );
    assert_eq!(duplicate.status.code(), Some(2));
    assert!(duplicate.stdout.is_empty());
}

#[test]
fn transport_gate_accepts_mapped_loopback_and_requires_opt_in_for_nonloopback() {
    let dir = common::TempDir::new("m05-transport");
    write_secure(&dir.path().join("users.toml"), &users_text(&[]));
    let base = |bind: &str, extra: &str| {
        proxy_config(
            "users.toml",
            bind,
            extra,
            r#"
[[access.rules]]
id = "allow"
action = "allow"
"#,
            443,
        )
    };

    for bind in ["127.0.0.1:3128", "[::1]:3128"] {
        Config::parse_with_base_dir(&base(bind, ""), dir.path())
            .unwrap_or_else(|error| panic!("{bind}: {error}"));
    }
    for bind in ["0.0.0.0:3128", "[::]:3128", "192.0.2.10:3128"] {
        let error = Config::parse_with_base_dir(&base(bind, ""), dir.path())
            .expect_err("non-loopback Basic needs opt-in")
            .to_string();
        assert!(error.contains("allow_insecure_basic"), "{bind}: {error}");
        Config::parse_with_base_dir(&base(bind, "allow_insecure_basic = true"), dir.path())
            .unwrap_or_else(|error| panic!("{bind} opt-in: {error}"));
    }

    let forwarded =
        base("127.0.0.1:3128", "").replace("[access]", "x-forwarded-proto = \"https\"\n\n[access]");
    assert!(
        Config::parse_with_base_dir(&forwarded, dir.path()).is_err(),
        "unknown transport spoofing field must be rejected"
    );
}

#[test]
fn users_snapshot_rejects_too_many_entries_and_bad_toml() {
    let dir = common::TempDir::new("m05-users-many");
    let phc = hash("synthetic");
    let mut text = String::from("version = 1\n");
    for index in 0..1_025 {
        text.push_str(&format!(
            "\n[[users]]\nusername = \"user{index}\"\npassword_hash = \"{phc}\"\n"
        ));
    }
    write_secure(&dir.path().join("users.toml"), &text);
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        &proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            "[[access.rules]]\nid = \"allow\"\naction = \"allow\"\n",
            443,
        ),
    );
    let error = Config::load(&config_path)
        .expect_err("1025 users must fail")
        .to_string();
    assert!(error.contains("1024 users"), "{error}");

    write_secure(&dir.path().join("users.toml"), "version = \n");
    let error = Config::load(&config_path)
        .expect_err("invalid TOML")
        .to_string();
    assert!(error.contains("TOML"), "{error}");

    let none_config = proxy_config(
        "users.toml",
        "127.0.0.1:3128",
        "",
        "[[access.rules]]\nid = \"allow\"\naction = \"allow\"\n",
        443,
    )
    .replace("auth = \"basic\"", "auth = \"none\"");
    write_secure(&config_path, &none_config);
    write_secure(&dir.path().join("users.toml"), "version = 2\nusers = []\n");
    let error = Config::load(&config_path)
        .expect_err("declared auth must reject even with no Basic listener")
        .to_string();
    assert!(error.contains("users file version"), "{error}");
}

#[test]
fn cli_check_does_not_hash_a_full_snapshot() {
    let dir = common::TempDir::new("m05-check-no-hash");
    let phc = hash("synthetic");
    let mut text = String::from("version = 1\n");
    for index in 0..1_024 {
        text.push_str(&format!(
            "\n[[users]]\nusername = \"user{index}\"\npassword_hash = \"{phc}\"\n"
        ));
    }
    write_secure(&dir.path().join("users.toml"), &text);
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        &proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            "[[access.rules]]\nid = \"allow\"\naction = \"allow\"\n",
            443,
        ),
    );
    let started = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_angara"))
        .arg("check")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("run check");
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "check took {:?}; it must validate PHC without hashing 1024 passwords",
        started.elapsed()
    );
}

#[cfg(unix)]
#[test]
fn cli_users_hash_pty_no_echo_and_confirmation() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/m05_pty.py");
    let binary = env!("CARGO_BIN_EXE_angara");
    let success = Command::new("python3")
        .arg(script)
        .arg("--binary")
        .arg(binary)
        .arg("--password")
        .arg("pty synthetic : password")
        .arg("--confirm")
        .arg("pty synthetic : password")
        .arg("--expect-success")
        .output()
        .expect("run PTY harness");
    assert!(
        success.status.success(),
        "PTY success case failed: stdout={} stderr={}",
        String::from_utf8_lossy(&success.stdout),
        String::from_utf8_lossy(&success.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&success.stdout).trim(), "PTY_OK");

    let mismatch = Command::new("python3")
        .arg(script)
        .arg("--binary")
        .arg(binary)
        .arg("--password")
        .arg("first-value")
        .arg("--confirm")
        .arg("second-value")
        .output()
        .expect("run PTY mismatch harness");
    assert!(
        mismatch.status.success(),
        "PTY mismatch case failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mismatch.stdout),
        String::from_utf8_lossy(&mismatch.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&mismatch.stdout).trim(),
        "PTY_MISMATCH_OK"
    );
}

#[test]
fn m05_example_is_valid_with_a_generated_users_file() {
    let dir = common::TempDir::new("m05-example");
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        include_str!("../examples/m05-auth-local.toml"),
    );
    write_secure(
        &dir.path().join("m05-users.local.toml"),
        &users_text(&[("alice", &hash("synthetic"), false)]),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_angara"))
        .arg("check")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("run check");
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(String::from_utf8_lossy(&output.stdout).contains("config ok"));
}

#[test]
fn cli_check_reads_auth_users_without_hashing() {
    let dir = common::TempDir::new("m05-cli-check");
    write_secure(
        &dir.path().join("users.toml"),
        &users_text(&[("alice", &hash("secret"), false)]),
    );
    let config_path = dir.path().join("proxy.toml");
    write_secure(
        &config_path,
        &proxy_config(
            "users.toml",
            "127.0.0.1:3128",
            "",
            r#"
[[access.rules]]
id = "alice"
action = "allow"
users = ["alice"]
"#,
            443,
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_angara"))
        .arg("check")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("run check");
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(String::from_utf8_lossy(&output.stdout).contains("config ok"));
    assert!(output.stderr.is_empty());
}
