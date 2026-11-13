//! M07 strict operations/observability and main-file tests.

mod common;

use std::fs;
use std::path::Path;

use angara::config::{Config, LogLevel};

fn base(listener: &str, extra: &str) -> String {
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
shutdown_timeout_ms = 2000
{extra}
[[listeners]]
id = "proxy"
bind = "127.0.0.1:3128"
transport = "http"
{listener}
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
    )
}

#[test]
fn m07_cfg01_defaults_and_strict_observability_schema() {
    let config = Config::parse(&base("", "")).expect("old config remains valid");
    assert_eq!(config.operations().reload_timeout().as_millis(), 5000);
    assert_eq!(config.observability().log_level(), LogLevel::Info);
    assert_eq!(config.observability().log_queue_capacity(), 1024);
    assert!(config.observability().metrics_enabled());

    let extra = r#"
[operations]
reload_timeout_ms = 100
[observability]
log_level = "warn"
log_queue_capacity = 64
metrics_enabled = false
metrics_interval_ms = 1000
"#;
    let config = Config::parse(&base("", extra)).expect("minimum values");
    assert_eq!(config.operations().reload_timeout().as_millis(), 100);
    assert_eq!(config.observability().log_level(), LogLevel::Warn);
    assert_eq!(config.observability().log_queue_capacity(), 64);
    assert!(!config.observability().metrics_enabled());
    assert_eq!(config.observability().metrics_interval().as_millis(), 1000);

    for (extra, field) in [
        (
            "[operations]\nreload_timeout_ms = 99",
            "operations.reload_timeout_ms",
        ),
        (
            "[operations]\nreload_timeout_ms = 60001",
            "operations.reload_timeout_ms",
        ),
        (
            "[observability]\nlog_level = \"debug\"",
            "observability.log_level",
        ),
        (
            "[observability]\nlog_queue_capacity = 63",
            "observability.log_queue_capacity",
        ),
        (
            "[observability]\nlog_queue_capacity = 8193",
            "observability.log_queue_capacity",
        ),
        (
            "[observability]\nmetrics_interval_ms = 999",
            "observability.metrics_interval_ms",
        ),
        (
            "[observability]\nmetrics_interval_ms = 600001",
            "observability.metrics_interval_ms",
        ),
        ("[operations]\nunknown = true", "unknown field"),
        ("[observability]\nunknown = true", "unknown field"),
    ] {
        let error = Config::parse(&base("", extra))
            .expect_err("invalid operations schema")
            .to_string();
        assert!(
            error.contains(field) || error.contains("unknown field"),
            "{field}: {error}"
        );
    }
}

#[test]
fn m07_cfg01_main_file_is_bounded_regular_and_symlink_safe() {
    let dir = common::TempDir::new("m07-cfg-file");
    let path = dir.write("proxy.toml", &base("", ""));
    let config = Config::load(&path).expect("regular config");
    assert_eq!(config.listeners().len(), 1);

    let oversized = dir.path().join("oversized.toml");
    fs::write(&oversized, vec![b' '; 1_048_577]).expect("oversized");
    assert!(Config::load(&oversized).is_err());
    assert!(Config::parse(&" ".repeat(1_048_577)).is_err());

    assert!(Config::load(dir.path()).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = dir.path().join("link.toml");
        symlink(&path, &link).expect("symlink");
        Config::load(&link).expect("symlink to safe regular file is allowed");
    }
}

#[cfg(unix)]
#[test]
fn m07_cfg01_main_file_permissions_are_checked() {
    use std::os::unix::fs::PermissionsExt;

    let dir = common::TempDir::new("m07-cfg-mode");
    let path = dir.write("proxy.toml", &base("", ""));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("chmod");
    assert!(Config::load(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod secure");
    Config::load(&path).expect("0600 accepted");
}

#[test]
fn m07_cfg01_check_does_not_require_network_or_tls_files() {
    let dir = common::TempDir::new("m07-cfg-check");
    let path = dir.write("proxy.toml", &base("", ""));
    Config::load(&path).expect("check-compatible config");
    let _ = Path::new("missing");
}
