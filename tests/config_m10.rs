//! M10 cache configuration tests.

mod common;

use angara::config::{Config, ConfigError};
use common::TempDir;
use common::m03;
use common::m05;

fn base(extra: &str) -> String {
    format!("{}\n{extra}\n", m03::config("127.0.0.1:3128"))
}

fn failure(text: &str) -> String {
    match Config::parse(text) {
        Ok(_) => panic!("configuration was accepted"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn m10_cfg01_absent_or_disabled_cache_is_off() {
    let config = Config::parse(&m03::config("127.0.0.1:3128")).expect("base config");
    assert!(!config.cache().enabled());

    let config = Config::parse(&base("[cache]\nenabled = false")).expect("disabled config");
    assert!(!config.cache().enabled());
}

#[test]
fn m10_cfg02_enabled_defaults_and_values() {
    let config = Config::parse(&base("[cache]\nenabled = true")).expect("cache defaults");
    let cache = config.cache();
    assert!(cache.enabled());
    assert_eq!(cache.max_bytes(), 32 * 1024 * 1024);
    assert_eq!(cache.max_object_bytes(), 1024 * 1024);
    assert_eq!(cache.max_entries(), 512);
    assert_eq!(cache.max_fills(), 8);

    let text = "[cache]\nenabled = true\nmax_bytes = 131072\nmax_object_bytes = 65536\nmax_entries = 7\nmax_fills = 3";
    let config = Config::parse(&base(text)).expect("explicit cache values");
    let cache = config.cache();
    assert_eq!(cache.max_bytes(), 131_072);
    assert_eq!(cache.max_object_bytes(), 65_536);
    assert_eq!(cache.max_entries(), 7);
    assert_eq!(cache.max_fills(), 3);
}

#[test]
fn m10_cfg03_invalid_cache_values_are_rejected() {
    for (fragment, path) in [
        ("max_bytes = 1024", "cache.max_bytes"),
        ("max_bytes = 4294967296", "cache.max_bytes"),
        ("max_object_bytes = 512", "cache.max_object_bytes"),
        ("max_entries = 0", "cache.max_entries"),
        ("max_fills = 65", "cache.max_fills"),
    ] {
        let text = base(&format!("[cache]\nenabled = true\n{fragment}"));
        let message = failure(&text);
        assert!(message.contains(path), "{fragment}: {message}");
    }

    let text = base("[cache]\nenabled = true\nmax_bytes = 131072\nmax_object_bytes = 262144");
    let message = failure(&text);
    assert!(message.contains("cache.max_object_bytes"), "{message}");

    let text = base("[cache]\nenabled = true\nunknown = 1");
    let message = failure(&text);
    assert!(message.contains("unknown field `unknown`"), "{message}");
}

#[test]
fn m10_cfg04_cache_changes_are_restart_required() {
    let dir = TempDir::new("m10-cache-reload");
    let path = dir.write(
        "proxy.toml",
        &base("[cache]\nenabled = true\nmax_bytes = 65536\nmax_object_bytes = 8192"),
    );
    let initial = Config::load(&path).expect("initial config");
    let changed = dir.write(
        "proxy.toml",
        &base("[cache]\nenabled = true\nmax_bytes = 131072\nmax_object_bytes = 8192"),
    );
    let error = Config::load_for_reload(&changed, &initial).expect_err("restart required");
    match error {
        ConfigError::RestartRequired { path, .. } => assert_eq!(path, "cache"),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn m10_cfg05_check_accepts_cache_section() {
    let dir = TempDir::new("m10-cache-check");
    let path = dir.write(
        "proxy.toml",
        &base("[cache]\nenabled = true\nmax_bytes = 131072\nmax_object_bytes = 65536\nmax_entries = 16\nmax_fills = 2"),
    );
    let output = m05::run_cli(
        &["check", "--config", path.to_str().expect("utf8 path")],
        None,
    );
    assert!(
        output.status.success(),
        "check rejected cache: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let invalid = dir.write(
        "invalid.toml",
        &base("[cache]\nenabled = true\nmax_bytes = 1024"),
    );
    let output = m05::run_cli(
        &["check", "--config", invalid.to_str().expect("utf8 path")],
        None,
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cache.max_bytes"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn m10_cfg06_example_is_valid() {
    let config = Config::parse(include_str!("../examples/m10-cache-local.toml"))
        .expect("m10 example config");
    assert!(config.cache().enabled());
    assert_eq!(config.cache().max_bytes(), 32 * 1024 * 1024);
}
