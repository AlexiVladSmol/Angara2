//! M03 configuration and default tests (M03-CFG-01).

mod common;

use std::time::Duration;

use angara::config::Config;

fn base() -> String {
    common::config("\"auto\"")
}

fn with_http(extra: &str) -> String {
    format!("{}{extra}", base())
}

fn error(text: &str) -> String {
    Config::parse(text)
        .expect_err("configuration must be rejected")
        .to_string()
}

fn with_client_limit(value: &str) -> String {
    base().replace(
        "max_connections = 256",
        &format!("max_connections = 256\nmax_client_connections = {value}"),
    )
}

#[test]
fn m03_cfg01_defaults_for_missing_http_section() {
    let config = Config::parse(&base()).expect("base config is valid");
    assert_eq!(config.limits().max_client_connections(), 256);
    assert_eq!(config.http().max_headers(), 100);
    assert_eq!(
        config.http().response_header_timeout(),
        Duration::from_secs(30)
    );
    assert_eq!(config.http().pool_max_idle(), 16);
    assert_eq!(config.http().pool_max_idle_per_key(), 2);
    assert_eq!(config.http().pool_idle_timeout(), Duration::from_secs(15));
}

#[test]
fn m03_cfg01_pool_defaults_follow_connection_budget() {
    let text = base().replace("max_connections = 256", "max_connections = 8");
    let config = Config::parse(&text).expect("small budget config");
    assert_eq!(config.http().pool_max_idle(), 8);
    assert_eq!(config.http().pool_max_idle_per_key(), 2);

    let text = base().replace("max_connections = 256", "max_connections = 1");
    let config = Config::parse(&text).expect("one connection config");
    assert_eq!(config.http().pool_max_idle(), 1);
    assert_eq!(config.http().pool_max_idle_per_key(), 1);
}

#[test]
fn m03_cfg01_example_is_valid_and_uses_explicit_http_values() {
    let config = Config::parse(include_str!("../examples/m03-http-local.toml"))
        .expect("M03 example is valid");
    assert_eq!(config.listeners().len(), 1);
    assert_eq!(config.limits().max_client_connections(), 128);
    assert_eq!(config.http().max_headers(), 100);
    assert_eq!(config.http().pool_max_idle(), 16);
    assert_eq!(config.http().pool_max_idle_per_key(), 2);
}

#[test]
fn m03_cfg01_rejects_http_and_client_limit_boundaries() {
    let cases: Vec<String> = vec![
        with_client_limit("0"),
        with_client_limit("65536"),
        with_http("[http]\nmax_headers = 0\n"),
        with_http("[http]\nmax_headers = 257\n"),
        with_http("[http]\nresponse_header_timeout_ms = 99\n"),
        with_http("[http]\nresponse_header_timeout_ms = 300001\n"),
        with_http("[http]\npool_max_idle = 257\n"),
        with_http("[http]\npool_max_idle = 0\npool_max_idle_per_key = 1\n"),
        with_http("[http]\npool_max_idle = 1\npool_max_idle_per_key = 2\n"),
        with_http("[http]\npool_idle_timeout_ms = 99\n"),
        with_http("[http]\npool_idle_timeout_ms = 300001\n"),
    ];
    for text in cases {
        let message = error(&text);
        assert!(
            message.contains("must be in") || message.contains("must be 0"),
            "unexpected diagnostic: {message}"
        );
    }
}

#[test]
fn m03_cfg01_accepts_boundary_values() {
    let text = with_client_limit("1")
        + "[http]\nmax_headers = 256\nresponse_header_timeout_ms = 100\npool_max_idle = 256\npool_max_idle_per_key = 2\npool_idle_timeout_ms = 100\n";
    let config = Config::parse(&text).expect("boundary config");
    assert_eq!(config.limits().max_client_connections(), 1);
    assert_eq!(config.http().max_headers(), 256);
    assert_eq!(
        config.http().response_header_timeout(),
        Duration::from_millis(100)
    );
    assert_eq!(config.http().pool_max_idle(), 256);
    assert_eq!(
        config.http().pool_idle_timeout(),
        Duration::from_millis(100)
    );

    let text = with_client_limit("65535")
        + "[http]\nmax_headers = 1\nresponse_header_timeout_ms = 300000\npool_max_idle = 0\npool_max_idle_per_key = 0\npool_idle_timeout_ms = 300000\n";
    let config = Config::parse(&text).expect("upper boundary config");
    assert_eq!(config.limits().max_client_connections(), 65535);
    assert_eq!(config.http().max_headers(), 1);
    assert_eq!(
        config.http().response_header_timeout(),
        Duration::from_secs(300)
    );
    assert_eq!(config.http().pool_max_idle(), 0);
    assert_eq!(config.http().pool_max_idle_per_key(), 0);
    assert_eq!(config.http().pool_idle_timeout(), Duration::from_secs(300));
}

#[test]
fn m03_cfg01_rejects_unknown_http_fields_without_echoing_values() {
    const MARKER: &str = "MARKER-SECRET-HTTP-123";
    let text = with_http(&format!("[http]\nunknown = \"{MARKER}\"\n"));
    let message = error(&text);
    assert!(message.contains("unknown field"), "{message}");
    assert!(
        !message.contains(MARKER),
        "diagnostic echoed a secret: {message}"
    );
}

#[test]
fn m03_cfg01_old_examples_remain_valid() {
    for text in [
        include_str!("../examples/minimal.toml"),
        include_str!("../examples/multi-listener.toml"),
        include_str!("../examples/m02-policy.toml"),
        include_str!("../examples/m02-egress-local.toml"),
    ] {
        Config::parse(text).expect("old example remains valid");
    }
}
