//! M04 CONNECT configuration tests (M04-CFG-01).

mod common;

use std::time::Duration;

use angara::config::Config;

fn base() -> String {
    common::config("\"auto\"")
}

fn with_connect(extra: &str) -> String {
    format!("{}{extra}", base())
}

#[test]
fn m04_cfg01_connect_defaults_and_empty_section() {
    for text in [base(), with_connect("[connect]\n")] {
        let config = Config::parse(&text).expect("CONNECT defaults");
        assert_eq!(config.connect().allowed_ports(), &[443]);
        assert!(config.connect().allows_port(443));
        assert!(!config.connect().allows_port(80));
        assert_eq!(
            config.connect().half_close_timeout(),
            Duration::from_millis(5_000)
        );
    }
}

#[test]
fn m04_cfg01_empty_allowed_ports_denies_connect() {
    let config = Config::parse(&with_connect("[connect]\nallowed_ports = []\n"))
        .expect("empty explicit port list is valid");
    assert!(config.connect().allowed_ports().is_empty());
    assert!(!config.connect().allows_port(443));
}

#[test]
fn m04_cfg01_allowed_ports_are_unique_and_sorted() {
    let config = Config::parse(&with_connect(
        "[connect]\nallowed_ports = [8443, 443, 10443]\nhalf_close_timeout_ms = 250\n",
    ))
    .expect("valid port list");
    assert_eq!(config.connect().allowed_ports(), &[443, 8443, 10443]);
    assert_eq!(
        config.connect().half_close_timeout(),
        Duration::from_millis(250)
    );
}

#[test]
fn m04_cfg01_rejects_invalid_connect_values() {
    let ports_65 = (1..=65)
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let cases = [
        with_connect("[connect]\nallowed_ports = [0]\n"),
        with_connect("[connect]\nallowed_ports = [65536]\n"),
        with_connect("[connect]\nallowed_ports = [-1]\n"),
        with_connect("[connect]\nallowed_ports = [443, 443]\n"),
        with_connect(&format!("[connect]\nallowed_ports = [{ports_65}]\n")),
        with_connect("[connect]\nhalf_close_timeout_ms = 99\n"),
        with_connect("[connect]\nhalf_close_timeout_ms = 300001\n"),
        with_connect("[connect]\nunknown = true\n"),
        with_connect("[connect]\nallowed_ports = \"443\"\n"),
    ];
    for text in cases {
        let error = Config::parse(&text)
            .expect_err("invalid CONNECT config must be rejected")
            .to_string();
        assert!(
            error.contains("connect."),
            "error did not identify the CONNECT field: {error}"
        );
    }
}

#[test]
fn m04_cfg01_previous_examples_remain_valid() {
    for text in [
        include_str!("../examples/minimal.toml"),
        include_str!("../examples/multi-listener.toml"),
        include_str!("../examples/m02-policy.toml"),
        include_str!("../examples/m02-egress-local.toml"),
        include_str!("../examples/m03-http-local.toml"),
    ] {
        let config = Config::parse(text).expect("previous example remains valid");
        assert_eq!(config.connect().allowed_ports(), &[443]);
    }
}

#[test]
fn m04_cfg01_connect_example_is_valid() {
    let config = Config::parse(include_str!("../examples/m04-connect-local.toml"))
        .expect("M04 example is valid");
    assert_eq!(config.connect().allowed_ports(), &[443, 8443]);
    assert_eq!(
        config.connect().half_close_timeout(),
        Duration::from_millis(5_000)
    );
}
