//! M06 CLI and manual-server contract tests.

mod common;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use angara::config::Config;
use common::m03;
use common::m05;
use common::m06;

fn angara() -> Command {
    Command::new(env!("CARGO_BIN_EXE_angara"))
}

fn status(output: &Output) -> i32 {
    output.status.code().expect("process exited with a code")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn config_text(bind: &str, chain: &Path, key: &Path, users: Option<&Path>) -> String {
    let auth = match users {
        Some(users) => format!(
            "[auth]\nusers_file = \"{}\"\nmax_verifying = 2\nverify_timeout_ms = 2000\n",
            path_text(users)
        ),
        None => String::new(),
    };
    let auth_mode = if users.is_some() { "basic" } else { "none" };
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
{auth}[tls]
max_handshaking = 4
handshake_timeout_ms = 2000
[[listeners]]
id = "secure"
bind = "{bind}"
transport = "https"
auth = "{auth_mode}"
[listeners.tls]
cert_chain_file = "{}"
private_key_file = "{}"
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
pool_idle_timeout_ms = 2000
[connect]
allowed_ports = [443]
half_close_timeout_ms = 1000
"#,
        path_text(chain),
        path_text(key),
    )
}

fn write(path: &Path, text: &str) {
    fs::write(path, text).expect("write test file");
}

fn secure(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[test]
fn cli_m06_check_and_serve_reject_bad_pair_before_bind() {
    let dir = common::TempDir::new("cli-m06-bad-pair");
    m06::generate_pki(dir.path());
    let port = m03::free_port();
    let config = config_text(
        &format!("127.0.0.1:{port}"),
        &dir.path().join("proxy_chain.pem"),
        &dir.path().join("site_key.pem"),
        None,
    );
    let config_path = dir.path().join("bad.toml");
    write(&config_path, &config);

    for command in ["check", "serve"] {
        let output = angara()
            .arg(command)
            .arg("--config")
            .arg(&config_path)
            .output()
            .expect("run angara");
        assert_eq!(status(&output), 1, "{command}");
        let error = stderr(&output);
        assert!(
            error.contains("listeners[0].tls.private_key_file"),
            "{error}"
        );
        assert!(error.contains("does not match"), "{error}");
        assert!(!error.contains("BEGIN PRIVATE KEY"), "{error}");
        assert!(!error.contains("MII"), "{error}");
    }

    let mixed_key = dir.path().join("mixed-key.pem");
    let mut mixed = fs::read(dir.path().join("proxy_key.pem")).expect("proxy key");
    mixed.extend_from_slice(
        &fs::read(dir.path().join("proxy_encrypted_key.pem")).expect("encrypted key"),
    );
    fs::write(&mixed_key, mixed).expect("mixed key");
    secure(&mixed_key);
    let mixed_config = dir.path().join("mixed.toml");
    write(
        &mixed_config,
        &config_text(
            &format!("127.0.0.1:{port}"),
            &dir.path().join("proxy_chain.pem"),
            &mixed_key,
            None,
        ),
    );
    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(&mixed_config)
        .output()
        .expect("run angara check");
    assert_eq!(status(&output), 1);
    let error = stderr(&output);
    assert!(
        error.contains("listeners[0].tls.private_key_file"),
        "{error}"
    );
    assert!(error.contains("private key"), "{error}");
    assert!(!error.contains("ENCRYPTED PRIVATE KEY"), "{error}");

    std::net::TcpListener::bind(("127.0.0.1", port))
        .expect("serve rejected the config before binding a socket");
}

#[test]
fn cli_m06_full_https_example_with_generated_material_checks() {
    let dir = common::TempDir::new("cli-m06-example");
    m06::generate_pki(dir.path());
    let tls_dir = dir.path().join("tls");
    fs::create_dir(&tls_dir).expect("tls dir");
    fs::copy(
        dir.path().join("proxy_chain.pem"),
        tls_dir.join("proxy-chain.pem"),
    )
    .expect("copy chain");
    fs::copy(
        dir.path().join("proxy_key.pem"),
        tls_dir.join("proxy-key.pem"),
    )
    .expect("copy key");
    let users = dir.path().join("m06-users.local.toml");
    m05::write_secure(
        &users,
        &m05::users_text(&[("alice", &m05::hash("synthetic-ci-password"), false)]),
    );
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/m06-https-local.toml");
    let config_path = dir.path().join("m06.toml");
    fs::copy(&example, &config_path).expect("copy example");

    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(&config_path)
        .env("SSLKEYLOGFILE", dir.path().join("check-keylog.txt"))
        .output()
        .expect("run check");
    assert_eq!(status(&output), 0, "{}", stderr(&output));
    assert!(
        !dir.path().join("check-keylog.txt").exists(),
        "check created a TLS key log"
    );
}

#[tokio::test]
async fn cli_m06_sslkeylogfile_is_not_honoured_by_serve() {
    let dir = common::TempDir::new("cli-m06-keylog");
    m06::generate_pki(dir.path());
    let port = m03::free_port();
    let config_path = dir.path().join("serve.toml");
    write(
        &config_path,
        &config_text(
            &format!("127.0.0.1:{port}"),
            &dir.path().join("proxy_chain.pem"),
            &dir.path().join("proxy_key.pem"),
            None,
        ),
    );
    Config::load(&config_path).expect("valid serve config");
    let keylog = dir.path().join("serve-keylog.txt");
    let origin = m03::spawn_origin(|_, _| m03::response("200 OK", &[], b"keylog"))
        .await
        .expect("origin");
    let mut child = angara()
        .arg("serve")
        .arg("--config")
        .arg(&config_path)
        .env("SSLKEYLOGFILE", &keylog)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn angara serve");

    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut connected = None;
    for _ in 0..100 {
        if let Ok(Ok(client)) = tokio::time::timeout(
            Duration::from_millis(400),
            m06::connect_tls(
                address,
                "localhost",
                m06::client_config(&dir.path().join("proxy_ca.pem")),
            ),
        )
        .await
        {
            connected = Some(client);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut client = connected.expect("serve did not accept TLS");
    client
        .send(&m03::request("GET", origin.address, "/", &[], b""))
        .await
        .expect("send");
    assert_eq!(
        client.read_response().await.expect("response").head.status,
        200
    );
    drop(client);

    let _ = child.kill();
    let output = child.wait_with_output().expect("wait for serve");
    assert!(
        !keylog.exists(),
        "SSLKEYLOGFILE created a key log: {}",
        keylog.display()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("CLIENT_RANDOM"), "{stderr}");
    assert!(!stderr.contains("BEGIN PRIVATE KEY"), "{stderr}");
}

#[test]
fn cli_m06_help_mentions_https_ingress() {
    let output = angara().arg("--help").output().expect("run help");
    assert_eq!(status(&output), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("HTTPS"), "{stdout}");
    assert!(stdout.contains("HTTP/1.1"), "{stdout}");
}

#[test]
fn cli_m06_users_hash_reuses_safe_secret_input() {
    // CLI-01 reuses the M05 PTY/stdin secret-input contract; this smoke keeps
    // the full example's credentials reproducible without argv passwords.
    let mut child = angara()
        .args(["users", "hash", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn users hash");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"quote\"back\\slash:colon space \xc3\xa9\n")
        .expect("write password");
    let output = child.wait_with_output().expect("hash output");
    assert_eq!(status(&output), 0, "{}", stderr(&output));
    let phc = String::from_utf8_lossy(&output.stdout);
    assert!(phc.starts_with("$argon2id$"), "{phc}");
    assert!(!stderr(&output).contains("quote"), "{}", stderr(&output));
}
