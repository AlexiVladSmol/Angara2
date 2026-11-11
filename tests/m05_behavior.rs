//! M05 HTTP, identity, ACL, pool and header behavior.

#![allow(clippy::field_reassign_with_default)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use angara::auth::AuthService;
use angara::config::Config;
use angara::http::HttpServer;
use angara::outbound::{OutboundError, OutboundService, RequestContext};
use angara::resolver::{ResolveFuture, Resolver};
use angara::transport::TcpDialer;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::m03::{self, RawClient, TestOrigin};
use common::m05::{self, AuthConfig, RecordingVerifier, VerifierState};

const ALICE: &str = "alice-secret";
const BOB: &str = "bob-secret";

fn origin() -> impl Fn(&m03::RecordedRequest, usize) -> Vec<u8> + Send + Sync + 'static {
    |request, _index| {
        let body = if request.target.ends_with("/download") {
            vec![0x5a; 1024 * 1024]
        } else if request.target.ends_with("/upload") {
            format!("upload:{}", request.body.len()).into_bytes()
        } else {
            b"ok".to_vec()
        };
        if request.target.ends_with("/trailers") {
            m03::chunked_response(
                "200 OK",
                &[("Trailer", "X-Origin-Trailer")],
                &[b"chunk-one", b"chunk-two"],
                &[("X-Origin-Trailer", "origin-value")],
            )
        } else if request.target.ends_with("/origin-407") {
            m03::response(
                "407 Proxy Authentication Required",
                &[("Proxy-Authenticate", "Basic realm=\"origin\"")],
                b"origin-challenge",
            )
        } else {
            m03::response("200 OK", &[], &body)
        }
    }
}

async fn basic_server(
    dir: &common::TempDir,
    users: &[(&str, &str, bool)],
) -> (HttpServer, std::net::SocketAddr, TestOrigin) {
    let origin = m03::spawn_origin(origin()).await.expect("origin");
    m05::write_users(dir, users);
    let config = AuthConfig::default().write(dir);
    let (server, addresses) = m05::start(&config).await;
    (server, m05::address(&addresses, "proxy"), origin)
}

#[tokio::test]
async fn m05_http01_basic_get_post_streaming_trailers_and_expect_order() {
    let dir = common::TempDir::new("m05-http01");
    let (server, proxy, origin) = basic_server(&dir, &[("alice", &m05::hash(ALICE), false)]).await;
    let target = origin.address;

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            target,
            Some(("alice", ALICE)),
            &[("Accept", "text/plain")],
        ))
        .await
        .expect("GET");
    let response = client.read_response().await.expect("GET response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "ok");

    let payload = vec![0xa5; 1024 * 1024];
    let request = m03::request(
        "POST",
        target,
        "/upload",
        &[("Proxy-Authorization", &m05::authorization("alice", ALICE))],
        &payload,
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&request).await.expect("upload");
    let response = client.read_response().await.expect("upload response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "upload:1048576");

    let request = m03::request(
        "GET",
        target,
        "/download",
        &[("Proxy-Authorization", &m05::authorization("alice", ALICE))],
        b"",
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&request).await.expect("download");
    let response = client.read_response().await.expect("download response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.body.len(), 1024 * 1024);
    assert!(response.body.iter().all(|byte| *byte == 0x5a));

    let request = m03::request(
        "GET",
        target,
        "/trailers",
        &[
            ("Proxy-Authorization", &m05::authorization("alice", ALICE)),
            ("TE", "trailers"),
        ],
        b"",
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&request).await.expect("trailer request");
    let response = client.read_response().await.expect("trailer response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.body, b"chunk-onechunk-two");
    assert!(
        response.trailers.iter().any(
            |(name, value)| name.eq_ignore_ascii_case("x-origin-trailer")
                && value == "origin-value"
        ),
        "{:?}",
        response.trailers
    );

    let head = format!(
        "POST http://{target}/upload HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n",
        m05::authorization("alice", ALICE)
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(head.as_bytes()).await.expect("expect head");
    let interim = client.read_head().await.expect("interim");
    assert_eq!(interim.status, 100);
    client.send(b"hello").await.expect("expect body");
    let response = client.read_response().await.expect("expect response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "upload:5");

    let chunked = format!(
        "POST http://{target}/upload HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        m05::authorization("alice", ALICE)
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(chunked.as_bytes()).await.expect("chunked upload");
    let response = client.read_response().await.expect("chunked response");
    assert_eq!(response.head.status, 200);
    assert_eq!(response.text(), "upload:5");

    {
        let recorded = origin.requests.lock().unwrap();
        let upload = recorded
            .iter()
            .find(|request| request.target == "/upload")
            .expect("upload recorded");
        assert_eq!(upload.body, payload);
        assert_eq!(upload.header("proxy-authorization"), None);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn m05_http02_failure_classes_share_one_response_and_count_checks() {
    let dir = common::TempDir::new("m05-http02");
    let origin = m03::spawn_origin(origin()).await.expect("origin");
    m05::write_users(
        &dir,
        &[
            ("alice", &m05::hash(ALICE), false),
            ("disabled", &m05::hash("disabled-secret"), true),
        ],
    );
    let config = AuthConfig::default().write(&dir);
    let state = Arc::new(VerifierState::default());
    let verifier = Arc::new(RecordingVerifier::new(
        Arc::clone(&state),
        Duration::ZERO,
        Ok(false),
    ));
    let (server, addresses) = m05::start_with_verifier(&config, verifier).await;
    let proxy = m05::address(&addresses, "proxy");
    let target = origin.address;

    let mut malformed = Vec::new();
    malformed.push(m05::get_request(
        target,
        None,
        &[("X-Secret-Marker", "MARKER-AUTH-71")],
    ));
    malformed.push(m05::get_request(target, Some(("", "x")), &[]));
    malformed.push(m05::get_request(target, Some(("alice", "")), &[]));
    malformed.push(
        format!(
            "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer abc\r\n\r\n"
        )
        .into_bytes(),
    );
    malformed.push(
        format!(
            "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic !!!\r\n\r\n"
        )
        .into_bytes(),
    );
    malformed.push(
        format!(
            "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            STANDARD.encode("alice:x"),
            STANDARD.encode("alice:x")
        )
        .into_bytes(),
    );
    let overlong = format!(
        "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        "A".repeat(1_600)
    );
    malformed.push(overlong.into_bytes());
    let non_utf8 = {
        let mut request = format!(
            "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic "
        )
        .into_bytes();
        request.extend_from_slice(&[0xff, 0xfe]);
        request.extend_from_slice(b"\r\n\r\n");
        request
    };
    malformed.push(non_utf8);

    let mut bodies = Vec::new();
    for request in malformed {
        let mut client = RawClient::connect(proxy).await.expect("client");
        client.send(&request).await.expect("send malformed");
        let response = client.read_response().await.expect("407");
        assert_eq!(response.head.status, 407);
        assert!(response.interim.is_empty());
        assert_eq!(
            response.head.header("proxy-authenticate"),
            Some("Basic realm=\"Angara\", charset=\"UTF-8\"")
        );
        assert_eq!(response.head.header("connection"), Some("close"));
        assert!(
            !response.head.headers.iter().any(
                |(_, value)| value.contains("MARKER-AUTH-71") || value.contains("alice-secret")
            ),
            "local failure leaked a credential marker: {:?}",
            response.head.headers
        );
        assert!(
            !response
                .body
                .windows(b"MARKER-AUTH-71".len())
                .any(|window| window == b"MARKER-AUTH-71"),
            "local failure body leaked the marker"
        );
        bodies.push((
            response.body,
            response.head.header("content-length").map(str::to_owned),
        ));
    }
    assert!(
        bodies.windows(2).all(|pair| pair[0] == pair[1]),
        "local failures must be indistinguishable"
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        0,
        "malformed credentials must not dial"
    );

    let denied = m05::get_request(target, None, &[]);
    let allowed = m05::get_request(target, Some(("alice", "wrong")), &[]);
    let mut pipelined = denied;
    pipelined.extend_from_slice(&allowed);
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&pipelined).await.expect("send denied pipeline");
    assert_eq!(client.read_response().await.expect("407").head.status, 407);
    assert!(
        client.read_response().await.is_err(),
        "bytes pipelined after a local 407 must not become another request"
    );
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);
    assert_eq!(state.calls.load(Ordering::SeqCst), 0);

    for (user, password) in [
        ("nobody", "anything"),
        ("disabled", "disabled-secret"),
        ("alice", "wrong"),
        ("Alice", ALICE),
    ] {
        let mut client = RawClient::connect(proxy).await.expect("client");
        client
            .send(&m05::get_request(
                target,
                Some((user, password)),
                &[("Expect", "100-continue")],
            ))
            .await
            .expect("send credentials");
        let response = client.read_response().await.expect("407 credentials");
        assert_eq!(response.head.status, 407, "{user}");
        assert!(response.interim.is_empty(), "{user}");
    }
    assert_eq!(
        state.calls.load(Ordering::SeqCst),
        4,
        "unknown, disabled and wrong users must each run one verification"
    );
    assert_eq!(state.max_running.load(Ordering::SeqCst), 1);
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(target, Some(("alice", ALICE)), &[]))
        .await
        .expect("send bad password");
    assert_eq!(client.read_response().await.expect("bad").head.status, 407);
    assert_eq!(state.calls.load(Ordering::SeqCst), 5);
    assert_eq!(server.auth_available_permits(), Some(2));
    server.shutdown().await;
}

#[tokio::test]
async fn m05_http02_success_and_header_filtering_with_injected_verifier() {
    let dir = common::TempDir::new("m05-http02-success");
    let origin = m03::spawn_origin(origin()).await.expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash(ALICE), false)]);
    let config = AuthConfig::default().write(&dir);
    let state = Arc::new(VerifierState::default());
    let (server, addresses) = m05::start_with_verifier(
        &config,
        Arc::new(RecordingVerifier::new(
            Arc::clone(&state),
            Duration::ZERO,
            Ok(true),
        )),
    )
    .await;
    let proxy = m05::address(&addresses, "proxy");
    let target = origin.address;

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            target,
            Some(("alice", "any-password")),
            &[
                ("Authorization", "Bearer origin-token"),
                ("Connection", "Proxy-Authorization"),
            ],
        ))
        .await
        .expect("send");
    let response = client.read_response().await.expect("200");
    assert_eq!(response.head.status, 200);
    drop(client);

    {
        let recorded = origin.requests.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].header("authorization"),
            Some("Bearer origin-token")
        );
        assert_eq!(recorded[0].header("proxy-authorization"), None);
    }
    assert_eq!(state.calls.load(Ordering::SeqCst), 1);
    server.shutdown().await;
}

#[tokio::test]
async fn m05_id01_pipelined_users_keep_order_and_missing_auth_closes() {
    let dir = common::TempDir::new("m05-id01");
    let origin = m03::spawn_origin(|request, _| {
        let body = format!("user-path:{}", request.target).into_bytes();
        m03::response("200 OK", &[], &body)
    })
    .await
    .expect("origin");
    m05::write_users(
        &dir,
        &[
            ("alice", &m05::hash(ALICE), false),
            ("bob", &m05::hash(BOB), false),
        ],
    );
    let mut config = AuthConfig::default();
    config.access = r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "alice-bob"
action = "allow"
users = ["alice", "bob"]

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#
    .to_owned();
    let config_path = config.write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");

    let first = format!(
        "GET http://{}/one HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
        origin.address,
        origin.address,
        m05::authorization("alice", ALICE)
    );
    let second = format!(
        "GET http://{}/two HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
        origin.address,
        origin.address,
        m05::authorization("bob", BOB)
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(format!("{first}{second}").as_bytes())
        .await
        .expect("pipeline");
    let one = client.read_response().await.expect("first response");
    let two = client.read_response().await.expect("second response");
    assert_eq!(one.text(), "user-path:/one");
    assert_eq!(two.text(), "user-path:/two");
    drop(client);

    for auth in [None, Some(("alice", "wrong")), Some(("Alice", ALICE))] {
        let mut client = RawClient::connect(proxy).await.expect("client");
        client
            .send(&m05::get_request(origin.address, auth, &[]))
            .await
            .expect("send");
        let response = client.read_response().await.expect("407");
        assert_eq!(response.head.status, 407);
        assert_eq!(response.head.header("connection"), Some("close"));
        assert!(
            client.read_response().await.is_err(),
            "a local 407 must close the connection"
        );
    }

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(
            format!(
                "GET http://{0}/bob HTTP/1.1\r\nHost: {0}\r\nProxy-Authorization: {1}\r\n\r\n",
                origin.address,
                m05::authorization("bob", BOB)
            )
            .as_bytes(),
        )
        .await
        .expect("bob");
    assert_eq!(client.read_response().await.expect("bob").head.status, 200);
    server.shutdown().await;
}

#[tokio::test]
async fn m05_headers01_auth_none_never_uses_proxy_credentials() {
    let dir = common::TempDir::new("m05-headers-none");
    let origin = m03::spawn_origin(origin()).await.expect("origin");
    m05::write_users(&dir, &[]);
    let mut config = AuthConfig::default();
    config.listeners = config
        .listeners
        .replace("auth = \"basic\"", "auth = \"none\"");
    config.access = r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "alice-only"
action = "allow"
users = ["alice"]

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#
    .to_owned();
    let config_path = config.write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");

    let request = format!(
        "GET http://{0}/ HTTP/1.1\r\nHost: {0}\r\nProxy-Authorization: {1}\r\nX-Secret-Marker: MARKER-71\r\n\r\n",
        origin.address,
        m05::authorization("alice", ALICE)
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(request.as_bytes()).await.expect("send");
    let response = client.read_response().await.expect("403");
    assert_eq!(response.head.status, 403);
    assert!(response.interim.is_empty());
    assert!(!response.text().contains("MARKER-71"));
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m05_headers01_trailers_and_origin_challenge_do_not_authenticate_or_replay() {
    let dir = common::TempDir::new("m05-headers-trailers");
    let origin = m03::spawn_origin(origin()).await.expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash(ALICE), false)]);
    let config_path = AuthConfig::default().write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");

    let request = format!(
        "POST http://{0}/trailer-auth HTTP/1.1\r\nHost: {0}\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization\r\n\r\n5\r\nhello\r\n0\r\nProxy-Authorization: {1}\r\n\r\n",
        origin.address,
        m05::authorization("alice", ALICE)
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(request.as_bytes()).await.expect("send trailer");
    let response = client.read_response().await.expect("407 trailer");
    assert_eq!(response.head.status, 407);
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);

    let request = m03::request(
        "GET",
        origin.address,
        "/origin-407",
        &[("Proxy-Authorization", &m05::authorization("alice", ALICE))],
        b"",
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&request).await.expect("send origin 407");
    let response = client.read_response().await.expect("origin 407");
    assert_eq!(response.head.status, 407);
    assert_eq!(origin.requests.lock().unwrap().len(), 1);
    assert_eq!(
        response.head.header("proxy-authenticate"),
        None,
        "origin proxy challenge must not be forwarded as a local challenge"
    );
    drop(client);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        origin.requests.lock().unwrap().len(),
        1,
        "an origin challenge must not trigger replay"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn m05_pool01_identity_listener_and_snapshot_isolation() {
    let dir = common::TempDir::new("m05-pool");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(
        &dir,
        &[
            ("alice", &m05::hash(ALICE), false),
            ("bob", &m05::hash(BOB), false),
        ],
    );
    let mut config = AuthConfig::default();
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
    config.access = r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#
    .to_owned();
    let config_path = config.write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");
    let second = m05::address(&addresses, "second");

    let make_request = |user: &str, password: &str| {
        m03::request(
            "GET",
            origin.address,
            "/",
            &[("Proxy-Authorization", &m05::authorization(user, password))],
            b"",
        )
        .into_boxed_slice()
    };

    for (address, user, password) in [
        (proxy, "alice", ALICE),
        (proxy, "alice", ALICE),
        (proxy, "bob", BOB),
        (second, "alice", ALICE),
    ] {
        let request = make_request(user, password);
        let mut client = RawClient::connect(address).await.expect("client");
        client.send(&request).await.expect("send");
        assert_eq!(
            client.read_response().await.expect("response").head.status,
            200,
            "{user} on {address}"
        );
    }
    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        3,
        "one user reuses; other user and listener do not"
    );

    let request = make_request("alice", "wrong");
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&request).await.expect("send wrong");
    assert_eq!(client.read_response().await.expect("407").head.status, 407);
    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        3,
        "failed auth must not dial or consume a pooled socket"
    );

    let request = make_request("alice", ALICE);
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&request).await.expect("send alice again");
    assert_eq!(client.read_response().await.expect("200").head.status, 200);
    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        3,
        "a successful request must reuse the alice socket"
    );

    let (other_server, other_addresses) = m05::start(&config_path).await;
    let other_proxy = m05::address(&other_addresses, "proxy");
    let request = make_request("alice", ALICE);
    let mut client = RawClient::connect(other_proxy).await.expect("client");
    client.send(&request).await.expect("send other server");
    assert_eq!(client.read_response().await.expect("200").head.status, 200);
    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        4,
        "different server snapshots must not share a pool"
    );

    server.shutdown().await;
    other_server.shutdown().await;
}

#[tokio::test]
async fn m05_acl01_source_deny_skips_verifier_and_foreign_snapshot_is_rejected() {
    let dir = common::TempDir::new("m05-acl-source");
    let origin = m03::spawn_origin(origin()).await.expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash(ALICE), false)]);
    let mut config = AuthConfig::default();
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
    let verifier = Arc::new(RecordingVerifier::new(
        Arc::clone(&state),
        Duration::ZERO,
        Ok(true),
    ));
    let (server, addresses) = m05::start_with_verifier(&config_path, verifier).await;
    let proxy = m05::address(&addresses, "proxy");

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", ALICE)),
            &[],
        ))
        .await
        .expect("send");
    assert_eq!(client.read_response().await.expect("403").head.status, 403);
    assert_eq!(
        state.calls.load(Ordering::SeqCst),
        0,
        "source deny must happen before password verification"
    );
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);
    server.shutdown().await;

    let first_dir = common::TempDir::new("m05-acl-snapshot-a");
    m05::write_users(&first_dir, &[("alice", &m05::hash(ALICE), false)]);
    let first_config = AuthConfig {
        users_file: "users.toml".to_owned(),
        ..AuthConfig::default()
    }
    .write(&first_dir);
    let first = Arc::new(Config::load(&first_config).expect("first config"));
    let first_auth = AuthService::from_config(&first).expect("first auth");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::PROXY_AUTHORIZATION,
        http::HeaderValue::from_str(&m05::authorization("alice", ALICE)).unwrap(),
    );
    let identity = first_auth
        .authenticate_headers(&headers)
        .await
        .expect("verified identity");

    let second_dir = common::TempDir::new("m05-acl-snapshot-b");
    m05::write_users(&second_dir, &[("alice", &m05::hash(ALICE), false)]);
    let second_config = AuthConfig {
        users_file: "users.toml".to_owned(),
        ..AuthConfig::default()
    }
    .write(&second_dir);
    let second = Arc::new(Config::load(&second_config).expect("second config"));
    let service = OutboundService::new(second);
    let context =
        RequestContext::with_identity("127.0.0.1".parse().expect("source"), "proxy", identity);
    let error = service
        .open_outbound(
            &context,
            &http::Method::GET,
            "http://127.0.0.1:9/",
            Some("127.0.0.1:9"),
        )
        .await
        .err()
        .expect("foreign snapshot must be rejected");
    assert_eq!(error, OutboundError::AuthenticationRequired);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn m05_route01_users_select_egress_and_bind_failure_has_no_fallback() {
    let dir = common::TempDir::new("m05-route");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(
        &dir,
        &[
            ("alice", &m05::hash(ALICE), false),
            ("bob", &m05::hash(BOB), false),
        ],
    );
    let mut config = AuthConfig::default();
    config.access = r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#
    .to_owned();
    config.extra = r#"
[[egress]]
id = "alice-egress"
mode = "bind_ip"
bind_ip = "127.0.0.1"

[[egress]]
id = "bob-egress"
mode = "bind_ip"
bind_ip = "127.0.0.2"

[[egress]]
id = "broken-egress"
mode = "bind_ip"
bind_ip = "192.0.2.50"

[routing]
default_egress = "alice-egress"

[[routing.rules]]
id = "alice"
egress_id = "alice-egress"
users = ["alice"]

[[routing.rules]]
id = "bob"
egress_id = "bob-egress"
users = ["bob"]
"#
    .to_owned();
    let config_path = config.write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");

    for (user, password, expected) in [("alice", ALICE, "127.0.0.1"), ("bob", BOB, "127.0.0.2")] {
        let request = m03::request(
            "GET",
            origin.address,
            "/",
            &[("Proxy-Authorization", &m05::authorization(user, password))],
            b"",
        );
        let mut client = RawClient::connect(proxy).await.expect("client");
        client.send(&request).await.expect("send");
        assert_eq!(client.read_response().await.expect("200").head.status, 200);
        let recorded = origin.requests.lock().unwrap();
        let last = recorded.last().expect("recorded");
        assert_eq!(last.peer.ip().to_string(), expected, "{user}");
        drop(recorded);
    }
    server.shutdown().await;

    let broken = AuthConfig {
        extra: r#"
[[egress]]
id = "broken-egress"
mode = "bind_ip"
bind_ip = "192.0.2.50"

[routing]
default_egress = "broken-egress"
"#
        .to_owned(),
        ..AuthConfig::default()
    }
    .write(&dir);
    let (server, addresses) = m05::start(&broken).await;
    let proxy = m05::address(&addresses, "proxy");
    let request = m03::request(
        "GET",
        origin.address,
        "/",
        &[("Proxy-Authorization", &m05::authorization("alice", ALICE))],
        b"",
    );
    let before = origin.accepts.load(Ordering::SeqCst);
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&request).await.expect("send");
    let response = client.read_response().await.expect("bind failure");
    assert_eq!(response.head.status, 502);
    assert_eq!(origin.accepts.load(Ordering::SeqCst), before);
    server.shutdown().await;
}

#[tokio::test]
async fn m05_con01_connect_auth_before_dial_blocked_port_and_early_payload() {
    use common::m04;

    let dir = common::TempDir::new("m05-connect-auth");
    let echo = m04::spawn_echo_origin(None).await.expect("echo origin");
    m05::write_users(&dir, &[("alice", &m05::hash(ALICE), false)]);
    let mut config = AuthConfig::default();
    config.connect_allowed_ports = echo.address.port().to_string();
    config.access = r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"
methods = ["CONNECT"]

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#
    .to_owned();
    let config_path = config.write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");

    let payload = b"EARLY-TUNNEL-BYTES-MUST-NOT-REACH-ORIGIN";
    for auth in [None, Some(("alice", "wrong")), Some(("nobody", "x"))] {
        let mut request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
            echo.address, echo.address
        );
        if let Some((user, password)) = auth {
            request.push_str(&format!(
                "Proxy-Authorization: {}\r\n",
                m05::authorization(user, password)
            ));
        }
        request.push_str("\r\n");
        let mut client = RawClient::connect(proxy).await.expect("client");
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(payload);
        client.send(&bytes).await.expect("send denied CONNECT");
        let response = client.read_response().await.expect("407");
        assert_eq!(response.head.status, 407);
        assert!(response.interim.is_empty());
    }
    assert_eq!(
        echo.accepts.load(Ordering::SeqCst),
        0,
        "denied CONNECT must not dial or forward early bytes"
    );

    let blocked = AuthConfig {
        users_file: "users.toml".to_owned(),
        connect_allowed_ports: "443".to_owned(),
        ..AuthConfig::default()
    }
    .write(&dir);
    let (blocked_server, addresses) = m05::start(&blocked).await;
    let blocked_proxy = m05::address(&addresses, "proxy");
    let mut client = RawClient::connect(blocked_proxy).await.expect("client");
    client
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                echo.address,
                echo.address,
                m05::authorization("alice", ALICE)
            )
            .as_bytes(),
        )
        .await
        .expect("send blocked port");
    assert_eq!(
        client.read_response().await.expect("403").head.status,
        403,
        "good credentials must not bypass the CONNECT port gate"
    );
    assert_eq!(echo.accepts.load(Ordering::SeqCst), 0);
    blocked_server.shutdown().await;

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                echo.address,
                echo.address,
                m05::authorization("alice", ALICE)
            )
            .as_bytes(),
        )
        .await
        .expect("send good CONNECT");
    assert_eq!(client.read_head().await.expect("200").status, 200);
    client.send(b"ping").await.expect("tunnel write");
    assert_eq!(client.read_exact_bytes(4).await.expect("echo"), b"ping");
    drop(client);
    server.shutdown().await;
    drop(echo);
}

#[derive(Default)]
struct CountingResolver {
    calls: AtomicUsize,
}

impl Resolver for CountingResolver {
    fn resolve<'a>(&'a self, _host: &'a str, _deadline: std::time::Instant) -> ResolveFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]) })
    }
}

#[tokio::test]
async fn m05_pool01_fresh_dns_on_authenticated_pool_hit() {
    let dir = common::TempDir::new("m05-pool-dns");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash(ALICE), false)]);
    let config_path = AuthConfig::default().write(&dir);
    let config = Arc::new(Config::load(&config_path).expect("config"));
    let resolver = Arc::new(CountingResolver::default());
    let state = Arc::new(VerifierState::default());
    let server = HttpServer::bind_ephemeral_with_components_and_verifier(
        config,
        Arc::clone(&resolver) as Arc<dyn Resolver>,
        Arc::new(TcpDialer),
        Arc::new(RecordingVerifier::accepting(
            Arc::clone(&state),
            Duration::ZERO,
            ALICE,
        )),
    )
    .await
    .expect("bind proxy");
    let proxy = server.addresses()[0].1;
    let port = origin.address.port();

    for _ in 0..2 {
        let request = format!(
            "GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost:{port}\r\nProxy-Authorization: {}\r\n\r\n",
            m05::authorization("alice", ALICE)
        );
        let mut client = RawClient::connect(proxy).await.expect("client");
        client.send(request.as_bytes()).await.expect("send");
        assert_eq!(client.read_response().await.expect("200").head.status, 200);
    }
    assert_eq!(
        resolver.calls.load(Ordering::SeqCst),
        2,
        "pool hits must perform fresh DNS"
    );
    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        1,
        "the authenticated user should reuse one origin connection"
    );
    assert_eq!(state.calls.load(Ordering::SeqCst), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn m05_headers01_auth_none_removes_proxy_authorization_but_keeps_origin_auth() {
    let dir = common::TempDir::new("m05-headers-none-allow");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[]);
    let mut config = AuthConfig::default();
    config.listeners = config
        .listeners
        .replace("auth = \"basic\"", "auth = \"none\"");
    let config_path = config.write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");

    let request = m03::request(
        "GET",
        origin.address,
        "/",
        &[
            (
                "Proxy-Authorization",
                &m05::authorization("alice", "not-a-real-password"),
            ),
            ("Authorization", "Bearer origin-token"),
        ],
        b"",
    );
    let mut client = RawClient::connect(proxy).await.expect("client");
    client.send(&request).await.expect("send");
    assert_eq!(client.read_response().await.expect("200").head.status, 200);
    {
        let recorded = origin.requests.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].header("proxy-authorization"), None);
        assert_eq!(
            recorded[0].header("authorization"),
            Some("Bearer origin-token")
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn m05_acl01_good_auth_does_not_bypass_destination_ip_policy() {
    let dir = common::TempDir::new("m05-acl-ip");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash(ALICE), false)]);
    let mut config = AuthConfig::default();
    config.access = r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"
"#
    .to_owned();
    let config_path = config.write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");

    let mut client = RawClient::connect(proxy).await.expect("client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", ALICE)),
            &[],
        ))
        .await
        .expect("send");
    assert_eq!(client.read_response().await.expect("403").head.status, 403);
    assert_eq!(origin.accepts.load(Ordering::SeqCst), 0);
    server.shutdown().await;
}

#[tokio::test]
async fn m05_pool01_anonymous_listener_does_not_share_authenticated_pool() {
    let dir = common::TempDir::new("m05-pool-anon");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"ok"))
        .await
        .expect("origin");
    m05::write_users(&dir, &[("alice", &m05::hash(ALICE), false)]);
    let mut config = AuthConfig::default();
    config.listeners = r#"
[[listeners]]
id = "proxy"
bind = "127.0.0.1:3128"
transport = "http"
auth = "basic"

[[listeners]]
id = "anonymous"
bind = "127.0.0.1:3129"
transport = "http"
auth = "none"
"#
    .to_owned();
    let config_path = config.write(&dir);
    let (server, addresses) = m05::start(&config_path).await;
    let proxy = m05::address(&addresses, "proxy");
    let anonymous = m05::address(&addresses, "anonymous");

    let mut client = RawClient::connect(proxy).await.expect("alice client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", ALICE)),
            &[],
        ))
        .await
        .expect("alice");
    assert_eq!(client.read_response().await.expect("200").head.status, 200);

    let mut client = RawClient::connect(anonymous).await.expect("anon client");
    client
        .send(&m05::get_request(
            origin.address,
            Some(("alice", ALICE)),
            &[],
        ))
        .await
        .expect("anonymous");
    assert_eq!(client.read_response().await.expect("200").head.status, 200);
    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        2,
        "authenticated and anonymous contexts must not share an origin socket"
    );
    server.shutdown().await;
}
