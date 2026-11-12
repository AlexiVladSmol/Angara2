//! M06 strict TLS configuration and preparation tests.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use angara::config::{Config, Transport};
use common::m06;

fn python_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn config_text(bind: &str, transport: &str, chain: &Path, key: &Path, tls: Option<&str>) -> String {
    let listener_tls = if transport == "https" {
        format!(
            "[listeners.tls]\ncert_chain_file = \"{}\"\nprivate_key_file = \"{}\"\n",
            python_path(chain),
            python_path(key)
        )
    } else {
        String::new()
    };
    let tls_table = tls.unwrap_or("[tls]\nmax_handshaking = 4\nhandshake_timeout_ms = 2000\n");
    format!(
        r#"
schema_version = 1
[runtime]
worker_threads = 2
[limits]
max_connections = 32
max_client_connections = 16
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 2000
{tls_table}
[[listeners]]
id = "secure"
bind = "{bind}"
transport = "{transport}"
auth = "none"
{listener_tls}
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
"#
    )
}

fn write(dir: &common::TempDir, name: &str, text: &str) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, text).expect("write test config");
    path
}

#[test]
fn m06_cfg01_https_is_strict_and_old_http_configs_remain_valid() {
    let dir = common::TempDir::new("m06-cfg01");
    m06::generate_pki(dir.path());
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let valid = write(
        &dir,
        "valid.toml",
        &config_text("127.0.0.1:3129", "https", &chain, &key, None),
    );
    let config = Config::load(&valid).expect("valid HTTPS config");
    assert_eq!(config.listeners()[0].transport(), Transport::Https);
    assert_eq!(config.tls().max_handshaking(), 4);
    assert_eq!(
        config.tls().handshake_timeout(),
        std::time::Duration::from_millis(2_000)
    );
    assert!(config.listeners()[0].tls().is_some());

    let http = write(
        &dir,
        "http.toml",
        &config_text("127.0.0.1:3129", "https", &chain, &key, None)
            .replace("transport = \"https\"", "transport = \"http\""),
    );
    assert!(
        Config::load(&http).is_err(),
        "http with tls table must fail"
    );

    let without_tls = write(
        &dir,
        "without.toml",
        &config_text("127.0.0.1:3129", "https", &chain, &key, None)
            .replace("[listeners.tls]", "# missing listener tls"),
    );
    assert!(
        Config::load(&without_tls).is_err(),
        "https without tls must fail"
    );

    let unknown = write(
        &dir,
        "unknown.toml",
        &config_text("127.0.0.1:3129", "https", &chain, &key, None).replace(
            "[listeners.tls]\n",
            "[listeners.tls]\nunknown_tls_marker = 0\n",
        ),
    );
    let error = Config::load(&unknown).expect_err("unknown listener tls field");
    assert!(error.to_string().contains("unknown field"), "{error}");
    assert!(!error.to_string().contains("MARKER-SECRET"), "{error}");

    for value in ["max_handshaking = 0", "max_handshaking = 257"] {
        let text = config_text(
            "127.0.0.1:3129",
            "https",
            &chain,
            &key,
            Some(&format!("[tls]\n{value}\nhandshake_timeout_ms = 2000\n")),
        );
        let path = write(&dir, "range.toml", &text);
        assert!(Config::load(&path).is_err(), "{value}");
    }
    for value in ["handshake_timeout_ms = 99", "handshake_timeout_ms = 60001"] {
        let text = config_text(
            "127.0.0.1:3129",
            "https",
            &chain,
            &key,
            Some(&format!("[tls]\nmax_handshaking = 4\n{value}\n")),
        );
        let path = write(&dir, "timeout.toml", &text);
        assert!(Config::load(&path).is_err(), "{value}");
    }

    let no_context = config_text("127.0.0.1:3129", "https", &chain, &key, None);
    let error = Config::parse(&no_context).expect_err("context-free HTTPS must fail");
    assert!(
        error.to_string().contains("configuration file context"),
        "{error}"
    );

    let _ = m06::server_config(&chain, &key);
}

#[test]
fn m06_cfg01_relative_paths_and_p256_are_supported() {
    let dir = common::TempDir::new("m06-cfg01-relative");
    m06::generate_pki(dir.path());
    let tls_dir = dir.path().join("tls");
    fs::create_dir(&tls_dir).expect("tls dir");
    for name in [
        "proxy_chain.pem",
        "proxy_key.pem",
        "proxy_p256_chain.pem",
        "proxy_p256_key.pem",
    ] {
        fs::copy(dir.path().join(name), tls_dir.join(name)).expect("copy TLS fixture");
    }
    let text = config_text(
        "127.0.0.1:3129",
        "https",
        Path::new("tls/proxy_chain.pem"),
        Path::new("tls/proxy_key.pem"),
        None,
    );
    let path = write(&dir, "relative.toml", &text);
    Config::load(&path).expect("relative TLS paths resolve from config directory");

    let p256 = config_text(
        "127.0.0.1:3129",
        "https",
        &tls_dir.join("proxy_p256_chain.pem"),
        &tls_dir.join("proxy_p256_key.pem"),
        None,
    );
    let path = write(&dir, "p256.toml", &p256);
    Config::load(&path).expect("P-256 certificate/key pair");
}

#[test]
fn m06_cfg02_chain_and_key_errors_reject_the_whole_startup() {
    let dir = common::TempDir::new("m06-cfg02");
    m06::generate_pki(dir.path());
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let valid = config_text("127.0.0.1:3129", "https", &chain, &key, None);

    let malformed = dir.path().join("malformed.pem");
    fs::write(&malformed, b"not a PEM\n").expect("malformed file");
    let invalid_der = dir.path().join("invalid-der.pem");
    fs::write(
        &invalid_der,
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    .expect("invalid DER");
    let encrypted = dir.path().join("encrypted.pem");
    fs::copy(dir.path().join("proxy_encrypted_key.pem"), &encrypted).expect("encrypted key");
    let multiple = dir.path().join("multiple.pem");
    let mut both = fs::read(&key).expect("proxy key");
    both.extend_from_slice(&fs::read(dir.path().join("site_key.pem")).expect("site key"));
    fs::write(&multiple, both).expect("multiple keys");
    let mismatch = config_text(
        "127.0.0.1:3129",
        "https",
        &chain,
        &dir.path().join("site_key.pem"),
        None,
    );
    let mismatch_path = write(&dir, "mismatch.toml", &mismatch);

    let cases = [
        (
            config_text("127.0.0.1:3129", "https", &malformed, &key, None),
            "PEM",
        ),
        (
            config_text("127.0.0.1:3129", "https", &invalid_der, &key, None),
            "certificate chain",
        ),
        (
            config_text("127.0.0.1:3129", "https", &chain, &encrypted, None),
            "private key",
        ),
        (
            config_text("127.0.0.1:3129", "https", &chain, &multiple, None),
            "private key",
        ),
    ];
    for (text, expected) in cases {
        let path = write(&dir, "invalid.toml", &text);
        let error = Config::load(&path)
            .expect_err("invalid TLS material must fail")
            .to_string();
        assert!(error.contains(expected), "{expected}: {error}");
        assert!(!error.contains("PRIVATE KEY"), "{error}");
    }
    let error = Config::load(&mismatch_path)
        .expect_err("mismatched key")
        .to_string();
    assert!(error.contains("does not match"), "{error}");

    let missing = write(
        &dir,
        "missing.toml",
        &valid.replace(&python_path(&chain), "missing.pem"),
    );
    assert!(Config::load(&missing).is_err());

    let oversized = dir.path().join("oversized.pem");
    fs::write(&oversized, vec![b'x'; 1_048_577]).expect("oversized");
    let path = write(
        &dir,
        "oversized.toml",
        &config_text("127.0.0.1:3129", "https", &oversized, &key, None),
    );
    assert!(Config::load(&path).is_err());

    let directory = write(
        &dir,
        "directory.toml",
        &config_text("127.0.0.1:3129", "https", &chain, dir.path(), None),
    );
    assert!(Config::load(&directory).is_err());
}

#[test]
fn m06_cfg02_empty_material_and_secret_markers_are_rejected_safely() {
    let dir = common::TempDir::new("m06-cfg02-secrets");
    m06::generate_pki(dir.path());
    let key = dir.path().join("proxy_key.pem");
    let chain = dir.path().join("proxy_chain.pem");
    let marker = "MARKER-PRIVATE-KEY-CONTENT";
    let empty = dir.path().join("empty.pem");
    fs::write(&empty, b"").expect("empty file");
    let marker_chain = dir.path().join("marker-chain.pem");
    fs::write(
        &marker_chain,
        format!("-----BEGIN CERTIFICATE-----\n{marker}\n-----END CERTIFICATE-----\n"),
    )
    .expect("marker chain");
    let marker_key = dir.path().join("marker-key.pem");
    fs::write(
        &marker_key,
        format!("-----BEGIN PRIVATE KEY-----\n{marker}\n-----END PRIVATE KEY-----\n"),
    )
    .expect("marker key");

    for text in [
        config_text("127.0.0.1:3129", "https", &empty, &key, None),
        config_text("127.0.0.1:3129", "https", &marker_chain, &key, None),
        config_text("127.0.0.1:3129", "https", &chain, &marker_key, None),
        config_text("127.0.0.1:3129", "https", &chain, &empty, None),
    ] {
        let path = write(&dir, "secret.toml", &text);
        let error = Config::load(&path).expect_err("invalid TLS material");
        let message = error.to_string();
        assert!(!message.contains(marker), "{message}");
        assert!(!message.contains("BEGIN"), "{message}");
        assert!(!message.contains("MII"), "{message}");
        assert!(
            message.contains("listeners[0].tls."),
            "typed path missing: {message}"
        );
        let debug = format!("{error:?}");
        assert!(!debug.contains(marker), "{debug}");
    }

    let valid = write(
        &dir,
        "valid.toml",
        &config_text("127.0.0.1:3129", "https", &chain, &key, None),
    );
    let config = Config::load(&valid).expect("valid config");
    let debug = format!("{config:?}");
    assert!(!debug.contains("BEGIN PRIVATE KEY"), "{debug}");
    assert!(!debug.contains(marker), "{debug}");
    assert!(debug.contains("PreparedTls(<redacted>)"), "{debug}");
}

#[cfg(unix)]
#[test]
fn m06_cfg02_linux_permissions_and_owner_checks_apply() {
    use std::os::unix::fs::PermissionsExt;

    let dir = common::TempDir::new("m06-cfg02-perms");
    m06::generate_pki(dir.path());
    let chain = dir.path().join("proxy_chain.pem");
    let key = dir.path().join("proxy_key.pem");
    let config = write(
        &dir,
        "proxy.toml",
        &config_text("127.0.0.1:3129", "https", &chain, &key, None),
    );
    Config::load(&config).expect("fixture permissions");

    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("chmod key");
    assert!(Config::load(&config).is_err(), "world-readable key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("chmod key back");
    fs::set_permissions(&chain, fs::Permissions::from_mode(0o644)).expect("chmod chain");
    Config::load(&config).expect("0644 certificate chain is allowed");
}
