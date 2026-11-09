//! Configuration contract tests (CFG-01/CFG-03).

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use angara::config::{
    Config, ConfigError, HEADER_READ_TIMEOUT_MS_LIMIT, IDLE_TIMEOUT_MS_LIMIT,
    MAX_CONNECTIONS_LIMIT, MAX_HEADER_BYTES_LIMIT, MAX_LISTENERS, MAX_WORKERS,
    SHUTDOWN_TIMEOUT_MS_LIMIT, Transport, WorkerThreads,
};
use common::{ONE_LISTENER, TWO_LISTENERS, config, config_with};

fn error(text: &str) -> ConfigError {
    Config::parse(text).expect_err("configuration must be rejected")
}

fn message(text: &str) -> String {
    error(text).to_string()
}

fn assert_rejected(text: &str, fragments: &[&str]) {
    let message = message(text);
    for fragment in fragments {
        assert!(
            message.contains(fragment),
            "expected `{fragment}` in error, got: {message}"
        );
    }
}

fn listener(id: &str, bind: &str) -> String {
    format!(
        r#"
[[listeners]]
id = "{id}"
bind = "{bind}"
transport = "http"
"#
    )
}

fn two_listeners(first: (&str, &str), second: (&str, &str)) -> String {
    format!(
        "{}{}",
        listener(first.0, first.1),
        listener(second.0, second.1)
    )
}

fn with_limit(field: &str, value: &str) -> String {
    let default = match field {
        "max_connections" => "256",
        "max_header_bytes" => "32768",
        "header_read_timeout_ms" => "10000",
        "idle_timeout_ms" => "60000",
        "shutdown_timeout_ms" => "10000",
        other => panic!("unknown limit {other}"),
    };
    let base = config("\"auto\"");
    let replaced = base.replace(
        &format!("{field} = {default}"),
        &format!("{field} = {value}"),
    );
    assert_ne!(replaced, base, "limit {field} was not present");
    replaced
}

#[test]
fn cfg01_accepts_minimal_config() {
    let config = Config::parse(&config("\"auto\"")).expect("valid configuration");

    assert_eq!(config.schema_version(), 1);
    assert_eq!(config.runtime().worker_threads(), WorkerThreads::Auto);
    assert_eq!(config.listeners().len(), 1);

    let listener = &config.listeners()[0];
    assert_eq!(listener.id(), "loopback");
    assert_eq!(
        listener.bind(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3128)
    );
    assert_eq!(listener.transport(), Transport::Http);

    let limits = config.limits();
    assert_eq!(limits.max_connections(), 256);
    assert_eq!(limits.max_header_bytes(), 32_768);
    assert_eq!(limits.header_read_timeout(), Duration::from_secs(10));
    assert_eq!(limits.idle_timeout(), Duration::from_secs(60));
    assert_eq!(limits.shutdown_timeout(), Duration::from_secs(10));
}

#[test]
fn cfg01_accepts_multiple_listeners() {
    let config = Config::parse(&config_with(TWO_LISTENERS, "4")).expect("valid configuration");
    assert_eq!(config.listeners().len(), 2);
    assert_eq!(config.listeners()[0].id(), "loopback-v4");
    assert_eq!(config.listeners()[1].id(), "loopback-v6");
    assert_eq!(config.runtime().worker_threads(), WorkerThreads::Fixed(4));
}

#[test]
fn cfg01_accepts_example_files() {
    let minimal = Config::parse(include_str!("../examples/minimal.toml")).expect("minimal example");
    assert_eq!(minimal.schema_version(), 1);
    assert_eq!(minimal.listeners().len(), 1);

    let multi = Config::parse(include_str!("../examples/multi-listener.toml"))
        .expect("multi-listener example");
    assert_eq!(multi.listeners().len(), 3);
    assert_eq!(multi.listeners()[1].bind().port(), 3128);
    assert!(multi.listeners()[1].bind().is_ipv6());
}

#[test]
fn cfg01_rejects_corrupted_toml_with_position() {
    let message = message("schema_version = 1\n[runtime");
    assert!(
        message.contains("invalid configuration at line 2"),
        "{message}"
    );
}

#[test]
fn cfg01_rejects_unknown_and_future_root_fields() {
    for field in [
        "tls", "auth", "acl", "egress", "cache", "admin", "routing", "users",
    ] {
        let text = config("\"auto\"").replace(
            "[runtime]",
            &format!("[{field}]\nenabled = true\n\n[runtime]"),
        );
        let message = message(&text);
        assert!(
            message.contains(&format!("field `{field}` is not supported in M01")),
            "{field}: {message}"
        );
    }

    let text = config("\"auto\"").replace("[runtime]", "unexpected = true\n\n[runtime]");
    assert_rejected(&text, &["unknown field `unexpected`"]);
}

#[test]
fn cfg01_rejects_unknown_nested_fields() {
    let text = config("\"auto\"").replace("[runtime]", "[runtime]\nextra = 1");
    assert_rejected(&text, &["unknown field `extra`", "runtime"]);

    let text = config("\"auto\"").replace("[limits]", "[limits]\nunexpected = 1");
    assert_rejected(&text, &["unknown field `unexpected`", "limits"]);

    let text = listener("loopback", "127.0.0.1:3128")
        .replace("transport = \"http\"", "transport = \"http\"\ntls = true");
    let text = config_with(&text, "\"auto\"");
    let message = message(&text);
    assert!(
        message.contains("field `tls` is not supported in M01"),
        "{message}"
    );
}

#[test]
fn cfg01_rejects_missing_required_fields() {
    assert_rejected("", &["missing field"]);
    assert_rejected(
        &config("\"auto\"").replace("schema_version = 1\n", ""),
        &["missing field `schema_version`"],
    );
    assert_rejected(
        &config("\"auto\"").replace("worker_threads = \"auto\"\n", ""),
        &["missing field `worker_threads`"],
    );
    let missing_limits = format!(
        r#"
schema_version = 1
[runtime]
worker_threads = "auto"
{ONE_LISTENER}
"#
    );
    assert_rejected(&missing_limits, &["missing field `limits`"]);
}

#[test]
fn cfg01_rejects_unsupported_schema_version() {
    assert_rejected(
        &config("\"auto\"").replace("schema_version = 1", "schema_version = 2"),
        &[
            "schema_version",
            "unsupported schema_version 2",
            "supports 1",
        ],
    );
}

#[test]
fn cfg03_rejects_unsupported_transport() {
    let text = config_with(
        &listener("loopback", "127.0.0.1:3128").replace("http", "https"),
        "\"auto\"",
    );
    assert_rejected(
        &text,
        &[
            "listeners[0].transport",
            "unsupported transport",
            "only `http`",
        ],
    );
}

#[test]
fn cfg03_rejects_non_numeric_bind_addresses() {
    for bind in [
        "localhost:3128",
        "127.0.0.1",
        "127.0.0.1:65536",
        "[::1]",
        "example.com:3128",
    ] {
        let text = config_with(&listener("loopback", bind), "\"auto\"");
        assert_rejected(&text, &["listeners[0].bind", "numeric IP:port"]);
    }
}

#[test]
fn cfg03_rejects_port_zero_and_ipv4_mapped_ipv6() {
    let text = config_with(&listener("loopback", "127.0.0.1:0"), "\"auto\"");
    assert_rejected(&text, &["listeners[0].bind", "port 0"]);

    let text = config_with(&listener("loopback", "[::ffff:127.0.0.1]:3128"), "\"auto\"");
    assert_rejected(&text, &["listeners[0].bind", "IPv4-mapped"]);
}

#[test]
fn cfg03_rejects_scoped_or_unparsable_ipv6_listener() {
    let text = config_with(&listener("loopback", "[fe80::1%25eth0]:3128"), "\"auto\"");
    let message = message(&text);
    assert!(message.contains("listeners[0].bind"), "{message}");
}

#[test]
fn cfg03_rejects_duplicate_listener_ids() {
    let text = config_with(
        &two_listeners(("same", "127.0.0.1:3128"), ("same", "127.0.0.2:3128")),
        "\"auto\"",
    );
    assert_rejected(
        &text,
        &[
            "listeners[1].id",
            "duplicate listener id `same`",
            "listeners[0]",
        ],
    );
}

#[test]
fn cfg03_rejects_duplicate_listener_addresses() {
    let text = config_with(
        &two_listeners(("first", "127.0.0.1:3128"), ("second", "127.0.0.1:3128")),
        "\"auto\"",
    );
    assert_rejected(
        &text,
        &[
            "listeners[1].bind",
            "duplicate listener address `127.0.0.1:3128`",
        ],
    );
}

#[test]
fn cfg03_rejects_wildcard_overlap_in_same_family() {
    let text = config_with(
        &two_listeners(("wildcard", "0.0.0.0:3128"), ("specific", "127.0.0.1:3128")),
        "\"auto\"",
    );
    assert_rejected(
        &text,
        &["listeners[1].bind", "wildcard conflict", "0.0.0.0:3128"],
    );

    let text = config_with(
        &two_listeners(("wildcard", "[::]:3128"), ("specific", "[::1]:3128")),
        "\"auto\"",
    );
    assert_rejected(
        &text,
        &["listeners[1].bind", "wildcard conflict", "[::]:3128"],
    );
}

#[test]
fn cfg03_allows_ipv6_only_wildcard_next_to_ipv4_wildcard() {
    let text = config_with(
        &two_listeners(("v4", "0.0.0.0:3128"), ("v6", "[::]:3128")),
        "\"auto\"",
    );
    let config = Config::parse(&text).expect("IPv6-only policy permits both wildcards");
    assert_eq!(config.listeners().len(), 2);
}

#[test]
fn cfg03_allows_distinct_concrete_addresses_and_families() {
    let text = config_with(
        &two_listeners(("first", "127.0.0.1:3128"), ("second", "127.0.0.2:3128")),
        "\"auto\"",
    );
    Config::parse(&text).expect("distinct concrete addresses are allowed");

    let text = config_with(
        &two_listeners(("v4", "0.0.0.0:3128"), ("v6", "[::1]:3128")),
        "\"auto\"",
    );
    Config::parse(&text).expect("different address families do not conflict");

    let text = config_with(
        &two_listeners(("first", "0.0.0.0:3128"), ("second", "127.0.0.1:3129")),
        "\"auto\"",
    );
    Config::parse(&text).expect("different ports do not conflict");
}

#[test]
fn cfg03_rejects_empty_and_excessive_listener_lists() {
    let base = config("\"auto\"");
    let without_listeners = &base[..base.find("[[listeners]]").expect("listener section")];
    let text = without_listeners.replace("[runtime]", "listeners = []\n\n[runtime]");
    assert_rejected(&text, &["listeners", "at least one listener"]);

    let mut listeners = String::new();
    for index in 0..=MAX_LISTENERS {
        listeners.push_str(&listener(
            &format!("listener-{index}"),
            &format!("127.0.0.1:{}", 3000 + index),
        ));
    }
    let text = config_with(&listeners, "\"auto\"");
    let expected = format!("at most {MAX_LISTENERS} listeners");
    assert_rejected(&text, &["listeners", &expected]);
}

#[test]
fn cfg03_accepts_worker_policies_and_bounds() {
    let maximum = MAX_WORKERS.to_string();
    for workers in ["\"auto\"", "1", maximum.as_str()] {
        Config::parse(&config(workers))
            .unwrap_or_else(|error| panic!("worker policy {workers} must be accepted: {error}"));
    }

    assert_eq!(
        Config::parse(&config("\"auto\""))
            .expect("auto")
            .runtime()
            .worker_threads(),
        WorkerThreads::Auto
    );
    assert_eq!(
        Config::parse(&config("1"))
            .expect("one worker")
            .runtime()
            .worker_threads(),
        WorkerThreads::Fixed(1)
    );
    assert_eq!(
        Config::parse(&config(&MAX_WORKERS.to_string()))
            .expect("max workers")
            .runtime()
            .worker_threads(),
        WorkerThreads::Fixed(MAX_WORKERS)
    );
}

#[test]
fn cfg03_rejects_invalid_worker_policies() {
    for workers in [
        "0",
        "-1",
        "65",
        "4294967296",
        "1.5",
        "true",
        "\"4\"",
        "\"AUTO\"",
        "\"MARKER-WORKER-SECRET\"",
    ] {
        let text = config(workers);
        let message = message(&text);
        assert!(
            message.contains("runtime.worker_threads"),
            "workers {workers}: {message}"
        );
        assert!(
            message.contains("must be `auto` or an integer from 1 to 64"),
            "workers {workers}: {message}"
        );
        assert!(
            !message.contains("MARKER-WORKER-SECRET"),
            "sensitive marker leaked: {message}"
        );
    }

    let text = config("999999999999999999999");
    let message = message(&text);
    assert!(message.contains("line 5"), "{message}");
    assert!(!message.contains("999999999999999999999"), "{message}");
}

#[test]
fn cfg03_rejects_limit_boundaries() {
    let cases: Vec<(&str, String)> = vec![
        ("max_connections", "0".to_owned()),
        ("max_connections", (MAX_CONNECTIONS_LIMIT + 1).to_string()),
        ("max_header_bytes", "1023".to_owned()),
        ("max_header_bytes", (MAX_HEADER_BYTES_LIMIT + 1).to_string()),
        ("header_read_timeout_ms", "99".to_owned()),
        (
            "header_read_timeout_ms",
            (HEADER_READ_TIMEOUT_MS_LIMIT + 1).to_string(),
        ),
        ("idle_timeout_ms", "999".to_owned()),
        ("idle_timeout_ms", (IDLE_TIMEOUT_MS_LIMIT + 1).to_string()),
        ("shutdown_timeout_ms", "0".to_owned()),
        (
            "shutdown_timeout_ms",
            (SHUTDOWN_TIMEOUT_MS_LIMIT + 1).to_string(),
        ),
        ("max_connections", "4294967296".to_owned()),
    ];

    for (field, value) in cases {
        let text = with_limit(field, &value);
        let message = message(&text);
        assert!(
            message.contains(&format!("limits.{field}")),
            "{field}={value}: {message}"
        );
        assert!(message.contains("must be in"), "{field}={value}: {message}");
    }
}

#[test]
fn cfg03_accepts_limit_minimums_and_maximums() {
    let minimum = config("\"auto\"")
        .replace("max_connections = 256", "max_connections = 1")
        .replace("max_header_bytes = 32768", "max_header_bytes = 1024")
        .replace(
            "header_read_timeout_ms = 10000",
            "header_read_timeout_ms = 100",
        )
        .replace("idle_timeout_ms = 60000", "idle_timeout_ms = 1000")
        .replace("shutdown_timeout_ms = 10000", "shutdown_timeout_ms = 1");
    let minimum_config = Config::parse(&minimum).expect("minimum limits");
    assert_eq!(minimum_config.limits().max_connections(), 1);
    assert_eq!(minimum_config.limits().max_header_bytes(), 1024);
    assert_eq!(
        minimum_config.limits().header_read_timeout(),
        Duration::from_millis(100)
    );
    assert_eq!(
        minimum_config.limits().idle_timeout(),
        Duration::from_millis(1000)
    );
    assert_eq!(
        minimum_config.limits().shutdown_timeout(),
        Duration::from_millis(1)
    );

    let maximum = config("\"auto\"")
        .replace(
            "max_connections = 256",
            &format!("max_connections = {MAX_CONNECTIONS_LIMIT}"),
        )
        .replace(
            "max_header_bytes = 32768",
            &format!("max_header_bytes = {MAX_HEADER_BYTES_LIMIT}"),
        )
        .replace(
            "header_read_timeout_ms = 10000",
            &format!("header_read_timeout_ms = {HEADER_READ_TIMEOUT_MS_LIMIT}"),
        )
        .replace(
            "idle_timeout_ms = 60000",
            &format!("idle_timeout_ms = {IDLE_TIMEOUT_MS_LIMIT}"),
        )
        .replace(
            "shutdown_timeout_ms = 10000",
            &format!("shutdown_timeout_ms = {SHUTDOWN_TIMEOUT_MS_LIMIT}"),
        );
    let maximum_config = Config::parse(&maximum).expect("maximum limits");
    assert_eq!(
        maximum_config.limits().max_connections(),
        MAX_CONNECTIONS_LIMIT
    );
    assert_eq!(
        maximum_config.limits().max_header_bytes(),
        MAX_HEADER_BYTES_LIMIT
    );
    assert_eq!(
        maximum_config.limits().header_read_timeout(),
        Duration::from_millis(HEADER_READ_TIMEOUT_MS_LIMIT)
    );
    assert_eq!(
        maximum_config.limits().idle_timeout(),
        Duration::from_millis(IDLE_TIMEOUT_MS_LIMIT)
    );
    assert_eq!(
        maximum_config.limits().shutdown_timeout(),
        Duration::from_millis(SHUTDOWN_TIMEOUT_MS_LIMIT)
    );
}

#[test]
fn cfg03_resolves_worker_policies_without_machine_dependence() {
    assert_eq!(WorkerThreads::Auto.resolve_with(0), 1);
    assert_eq!(WorkerThreads::Auto.resolve_with(1), 1);
    assert_eq!(WorkerThreads::Auto.resolve_with(8), 8);
    assert_eq!(WorkerThreads::Auto.resolve_with(1000), MAX_WORKERS);
    assert_eq!(WorkerThreads::Fixed(3).resolve_with(1000), 3);

    assert_eq!(WorkerThreads::Auto.to_string(), "auto");
    assert_eq!(WorkerThreads::Fixed(4).to_string(), "4");
}

#[test]
fn cfg01_rejects_invalid_listener_ids_without_echoing_them() {
    for id in ["", "MARKER ID WITH SPACES", "bad/id"] {
        let text = config_with(&listener(id, "127.0.0.1:3128"), "\"auto\"");
        let message = message(&text);
        assert!(message.contains("listeners[0].id"), "id {id:?}: {message}");
        assert!(!message.contains("MARKER"), "listener id leaked: {message}");
    }
}

#[test]
fn cfg01_never_echoes_sensitive_values() {
    const MARKER: &str = "MARKER-SECRET-123";

    let cases = [
        format!("schema_version = \"{MARKER}\""),
        format!("{}[auth]\npassword = \"{MARKER}\"", config("\"auto\"")),
        config_with(&listener("loopback", MARKER), "\"auto\""),
        config_with(
            &listener("loopback", "127.0.0.1:3128").replace("\"http\"", &format!("\"{MARKER}\"")),
            "\"auto\"",
        ),
        with_limit("max_connections", &format!("\"{MARKER}\"")),
        config(&format!("\"{MARKER}\"")),
        format!("schema_version = \"{MARKER}"),
    ];

    for text in cases {
        let message = message(&text);
        assert!(
            !message.contains(MARKER),
            "sensitive marker leaked in: {message}"
        );
        assert!(
            message.contains("line") || message.contains("field"),
            "error lost useful context: {message}"
        );
    }
}
