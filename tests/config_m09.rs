//! M09 parent configuration and reload tests.

mod common;
mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use angara::config::{Config, ConfigError};

use common::TempDir;

fn base(bind: &str) -> String {
    common::m03::config(bind)
}

fn with_parent(bind: &str, parent: &str, routing: &str) -> String {
    format!("{}{}{}", base(bind), parent, routing)
}

#[test]
fn m09_cfg01_old_config_keeps_direct_defaults() {
    let config = Config::parse(&base("127.0.0.1:3128")).expect("old config");
    assert!(config.parents().is_empty());
    assert_eq!(config.routing().default_parent(), None);
    assert!(
        config
            .routing()
            .rules()
            .iter()
            .all(|rule| rule.next_hop().is_none())
    );
}

#[test]
fn m09_cfg02_parent_and_next_hop_parse() {
    let text = with_parent(
        "127.0.0.1:3128",
        r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "http"

[[parents]]
id = "other"
endpoint = "[::1]:13138"
transport = "http"
"#,
        r#"
[routing]
default_egress = "system"
default_parent = "squid"

[[routing.rules]]
id = "direct"
egress_id = "system"
next_hop = "direct"
listeners = ["proxy"]

[[routing.rules]]
id = "other"
egress_id = "system"
next_hop = "other"
listeners = ["proxy"]
"#,
    );
    let config = Config::parse(&text).expect("parent config");
    assert_eq!(config.parents().len(), 2);
    assert!(config.parent("squid").is_some());
    assert!(config.parent("other").is_some());
    assert_eq!(config.routing().default_parent(), Some("squid"));
    assert_eq!(config.routing().rules()[0].next_hop(), Some("direct"));
    assert_eq!(config.routing().rules()[1].next_hop(), Some("other"));
}

#[test]
fn m09_cfg03_unknown_profiles_are_rejected() {
    let missing_parent = with_parent(
        "127.0.0.1:3128",
        r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "http"
"#,
        r#"
[routing]
default_egress = "system"
default_parent = "missing"
"#,
    );
    let error = Config::parse(&missing_parent).expect_err("unknown parent");
    assert!(
        matches!(error, ConfigError::Validation { ref path, .. } if path == "routing.default_parent")
    );

    let missing_hop = with_parent(
        "127.0.0.1:3128",
        r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "http"
"#,
        r#"
[routing]
default_egress = "system"

[[routing.rules]]
id = "bad"
egress_id = "system"
next_hop = "missing"
"#,
    );
    let error = Config::parse(&missing_hop).expect_err("unknown next hop");
    assert!(
        matches!(error, ConfigError::Validation { ref path, .. } if path == "routing.rules[0].next_hop")
    );
}

#[test]
fn m09_cfg04_direct_parent_id_is_reserved_and_duplicates_fail() {
    let reserved = with_parent(
        "127.0.0.1:3128",
        r#"
[[parents]]
id = "direct"
endpoint = "127.0.0.1:13128"
transport = "http"
"#,
        "",
    );
    let error = Config::parse(&reserved).expect_err("reserved id");
    assert!(matches!(error, ConfigError::Validation { ref path, .. } if path == "parents[0].id"));

    let duplicates = with_parent(
        "127.0.0.1:3128",
        r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "http"

[[parents]]
id = "squid"
endpoint = "127.0.0.1:13129"
transport = "http"
"#,
        "",
    );
    let error = Config::parse(&duplicates).expect_err("duplicate id");
    assert!(matches!(error, ConfigError::Validation { ref path, .. } if path == "parents[1].id"));
}

#[test]
fn m09_cfg05_obvious_self_route_is_rejected() {
    let self_route = with_parent(
        "127.0.0.1:3128",
        r#"
[[parents]]
id = "self"
endpoint = "127.0.0.1:3128"
transport = "http"
"#,
        "",
    );
    let error = Config::parse(&self_route).expect_err("self route");
    assert!(
        matches!(error, ConfigError::Validation { ref path, .. } if path == "parents[0].endpoint")
    );
}

#[test]
fn m09_cfg06_http_parent_rejects_ca_file() {
    let text = with_parent(
        "127.0.0.1:3128",
        r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "http"
ca_file = "/tmp/unused-ca.pem"
"#,
        "",
    );
    let error = Config::parse(&text).expect_err("ca on http");
    assert!(
        matches!(error, ConfigError::Validation { ref path, .. } if path == "parents[0].ca_file")
    );
}

#[test]
fn m09_cfg07_credentials_permissions_and_schema_are_checked() {
    let dir = TempDir::new("m09-cfg-creds");
    let credentials = dir.write(
        "parent-creds.toml",
        "version = 1\nusername = \"parent\"\npassword = \"secret\"\n",
    );
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o644))
        .expect("set permissive mode");
    let text = with_parent(
        "127.0.0.1:3128",
        &format!(
            r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "http"
credentials_file = "{}"
"#,
            credentials.display()
        ),
        "",
    );
    let error = Config::parse(&text).expect_err("permissive credentials");
    assert!(
        matches!(error, ConfigError::Validation { ref path, .. } if path == "parents[0].credentials_file")
    );

    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o600)).expect("set private mode");
    Config::parse(&text).expect("private credentials");

    dir.write("bad-creds.toml", "version = 1\nusername = \"parent\"\n");
    let bad = with_parent(
        "127.0.0.1:3128",
        &format!(
            r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "http"
credentials_file = "{}"
"#,
            dir.path().join("bad-creds.toml").display()
        ),
        "",
    );
    let error = Config::parse(&bad).expect_err("bad credentials");
    assert!(
        matches!(error, ConfigError::Validation { ref path, .. } if path == "parents[0].credentials_file")
    );
}

#[test]
fn m09_cfg08_parent_change_requires_restart_but_content_is_not_reread() {
    let dir = TempDir::new("m09-cfg-reload");
    let credentials = dir.write(
        "parent-creds.toml",
        "version = 1\nusername = \"parent\"\npassword = \"secret\"\n",
    );
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o600)).expect("set private mode");
    let config_path = dir.write(
        "proxy.toml",
        &with_parent(
            "127.0.0.1:3128",
            &format!(
                r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "http"
credentials_file = "{}"
"#,
                credentials.display()
            ),
            r#"
[routing]
default_egress = "system"
default_parent = "squid"
"#,
        ),
    );
    let initial = Config::load(&config_path).expect("initial config");
    fs::remove_file(&credentials).expect("remove credentials after preparation");
    let reloaded = Config::load_for_reload(&config_path, &initial).expect("reload reuses prepared");
    assert_eq!(reloaded.parents().len(), 1);
    assert!(reloaded.parent("squid").expect("parent").has_credentials());

    dir.write(
        "proxy.toml",
        &with_parent(
            "127.0.0.1:3128",
            r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13129"
transport = "http"
"#,
            r#"
[routing]
default_egress = "system"
default_parent = "squid"
"#,
        ),
    );
    let error = Config::load_for_reload(&config_path, &initial).expect_err("changed parent");
    assert!(matches!(error, ConfigError::RestartRequired { ref path, .. } if path == "parents"));
}

#[test]
fn m09_cfg09_invalid_endpoint_and_transport_are_rejected() {
    let bad_endpoint = with_parent(
        "127.0.0.1:3128",
        r#"
[[parents]]
id = "squid"
endpoint = "http://127.0.0.1:13128/"
transport = "http"
"#,
        "",
    );
    let error = Config::parse(&bad_endpoint).expect_err("bad endpoint");
    assert!(
        matches!(error, ConfigError::Validation { ref path, .. } if path == "parents[0].endpoint")
    );

    let bad_transport = with_parent(
        "127.0.0.1:3128",
        r#"
[[parents]]
id = "squid"
endpoint = "127.0.0.1:13128"
transport = "socks5"
"#,
        "",
    );
    let error = Config::parse(&bad_transport).expect_err("bad transport");
    assert!(
        matches!(error, ConfigError::Validation { ref path, .. } if path == "parents[0].transport")
    );
}
