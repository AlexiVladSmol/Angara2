//! M02 configuration contract tests (M02-CFG-01, M02-ERR-01, M02-REG-01).

mod common;

use std::time::Duration;

use angara::config::{
    Config, ConfigError, EgressMode, HostSelectors, IpDefault, MAX_POLICY_LIST_ITEMS, RuleAction,
};

fn base() -> String {
    common::config("\"auto\"")
}

fn with_extra(extra: &str) -> String {
    format!("{}{extra}", base())
}

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

#[test]
fn m02_accepts_examples_and_documents_defaults() {
    let policy =
        Config::parse(include_str!("../examples/m02-policy.toml")).expect("policy example");
    assert_eq!(policy.access().source_allow().len(), 2);
    assert_eq!(policy.access().rules().len(), 3);
    assert_eq!(policy.access().ip_default(), IpDefault::PublicOnly);
    assert_eq!(policy.access().rules()[0].action(), RuleAction::Deny);
    assert_eq!(policy.dns().timeout(), Duration::from_secs(3));
    assert_eq!(policy.dns().max_in_flight(), 4);
    assert_eq!(policy.dns().max_answers(), 16);
    assert_eq!(policy.transport().total_timeout(), Duration::from_secs(10));
    assert_eq!(policy.transport().connect_timeout(), Duration::from_secs(3));
    assert_eq!(policy.transport().max_connect_attempts(), 3);
    assert_eq!(policy.transport().max_connecting(), 32);
    assert_eq!(policy.egress().len(), 1);
    assert_eq!(policy.egress()[0].id(), "system");
    assert_eq!(policy.egress()[0].mode(), &EgressMode::System);
    assert_eq!(policy.routing().default_egress(), "system");

    let lab = Config::parse(include_str!("../examples/m02-egress-local.toml"))
        .expect("local egress example");
    assert_eq!(lab.egress().len(), 2);
    assert_eq!(lab.routing().rules().len(), 2);
    assert_eq!(lab.access().ip_default(), IpDefault::Deny);
    assert_eq!(lab.access().ip_rules().len(), 1);
    assert!(lab.access().ip_rules()[0].allow_special());
    assert_eq!(lab.transport().max_connecting(), 32);
}

#[test]
fn m02_m01_examples_and_defaults_remain_valid() {
    for text in [
        include_str!("../examples/minimal.toml"),
        include_str!("../examples/multi-listener.toml"),
    ] {
        let config = Config::parse(text).expect("M01 example remains valid");
        assert!(config.access().source_allow().is_empty());
        assert!(config.access().rules().is_empty());
        assert!(config.access().ip_rules().is_empty());
        assert_eq!(config.access().ip_default(), IpDefault::PublicOnly);
        assert_eq!(config.dns().timeout(), Duration::from_secs(3));
        assert_eq!(config.dns().max_in_flight(), 4);
        assert_eq!(config.dns().max_answers(), 16);
        assert_eq!(config.transport().total_timeout(), Duration::from_secs(10));
        assert_eq!(config.transport().connect_timeout(), Duration::from_secs(3));
        assert_eq!(config.transport().max_connect_attempts(), 3);
        assert_eq!(
            config.transport().max_connecting(),
            core::cmp::min(32, config.limits().max_connections() as usize)
        );
        assert_eq!(config.egress().len(), 1);
        assert_eq!(config.egress()[0].id(), "system");
        assert_eq!(config.routing().default_egress(), "system");
        assert!(config.routing().rules().is_empty());
    }
}

#[test]
fn m02_accepts_unicode_and_ascii_domain_selectors_equivalently() {
    let text = with_extra(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "unicode"
action = "allow"
host_exact = ["Bücher.Example."]

[[egress]]
id = "system"
mode = "system"

[routing]
default_egress = "system"
"#,
    );
    let config = Config::parse(&text).expect("unicode selector");
    let selectors = config.access().rules()[0].selectors();
    let HostSelectors::Exact(domains) = selectors.hosts() else {
        panic!("expected exact host selector");
    };
    assert_eq!(domains[0].as_str(), "xn--bcher-kva.example");
}

#[test]
fn m02_rejects_cidr_with_host_bits() {
    for (section, field) in [
        ("access.source_allow", "source_allow"),
        ("access.rules[0].sources", "sources"),
        ("access.ip_rules[0].networks", "networks"),
    ] {
        let text = match field {
            "source_allow" => with_extra(
                r#"
[access]
source_allow = ["127.0.0.1/8"]
"#,
            ),
            "sources" => with_extra(
                r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "rule"
action = "allow"
sources = ["127.0.0.1/8"]
"#,
            ),
            _ => with_extra(
                r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.ip_rules]]
id = "ip"
action = "allow"
networks = ["127.0.0.1/8"]
allow_special = true
"#,
            ),
        };
        assert_rejected(&text, &[section, "zero host bits"]);
    }
}

#[test]
fn m02_rejects_empty_selector_lists() {
    let cases = [
        ("listeners", "listeners = []"),
        ("sources", "sources = []"),
        ("methods", "methods = []"),
        ("ports", "ports = []"),
        ("host_exact", "host_exact = []"),
    ];
    for (field, selector) in cases {
        let text = with_extra(&format!(
            r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "rule"
action = "allow"
{selector}
"#
        ));
        assert_rejected(
            &text,
            &[&format!("access.rules[0].{field}"), "must not be empty"],
        );
    }
}

#[test]
fn m02_rejects_mutually_exclusive_host_selectors() {
    let text = with_extra(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "rule"
action = "allow"
host_exact = ["example.com"]
host_suffix = ["example.org"]
"#,
    );
    assert_rejected(
        &text,
        &["access.rules[0].host_suffix", "mutually exclusive"],
    );
}

#[test]
fn m02_rejects_unknown_listener_and_egress_references() {
    let text = with_extra(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "rule"
action = "allow"
listeners = ["missing"]
"#,
    );
    assert_rejected(
        &text,
        &["access.rules[0].listeners[0]", "unknown listener id"],
    );

    let text = with_extra(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "rule"
action = "allow"

[[egress]]
id = "via-a"
mode = "system"

[routing]
default_egress = "via-a"

[[routing.rules]]
id = "route"
egress_id = "missing"
"#,
    );
    assert_rejected(&text, &["routing.rules[0].egress_id", "unknown egress id"]);
}

#[test]
fn m02_rejects_duplicate_ids_in_each_category() {
    let access_rules = with_extra(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "same"
action = "allow"

[[access.rules]]
id = "same"
action = "deny"
"#,
    );
    assert_rejected(
        &access_rules,
        &[
            "access.rules[1].id",
            "access.rules[1].id duplicates access.rules[0].id",
        ],
    );

    let ip_rules = with_extra(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.ip_rules]]
id = "same"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true

[[access.ip_rules]]
id = "same"
action = "deny"
networks = ["10.0.0.0/8"]
"#,
    );
    assert_rejected(
        &ip_rules,
        &[
            "access.ip_rules[1].id",
            "access.ip_rules[1].id duplicates access.ip_rules[0].id",
        ],
    );

    let egress = with_extra(
        r#"
[[egress]]
id = "same"
mode = "system"

[[egress]]
id = "same"
mode = "system"
"#,
    );
    assert_rejected(&egress, &["egress[1].id", "duplicates egress[0].id"]);

    let routing = with_extra(
        r#"
[[egress]]
id = "system"
mode = "system"

[routing]
default_egress = "system"

[[routing.rules]]
id = "same"
egress_id = "system"

[[routing.rules]]
id = "same"
egress_id = "system"
"#,
    );
    assert_rejected(
        &routing,
        &["routing.rules[1].id", "duplicates routing.rules[0].id"],
    );
}

#[test]
fn m02_rejects_invalid_ids_without_echoing_them() {
    const MARKER: &str = "MARKER-SECRET-M02-ID";
    for id in ["", "bad/id", "bad/MARKER-SECRET-M02-ID"] {
        let text = with_extra(&format!(
            r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "{id}"
action = "allow"
"#
        ));
        let diagnostic = message(&text);
        assert!(diagnostic.contains("access.rules[0].id"), "{diagnostic}");
        if id.contains(MARKER) {
            assert!(!diagnostic.contains(MARKER), "{diagnostic}");
        }
    }
}

#[test]
fn m02_rejects_list_length_limits() {
    let too_many = MAX_POLICY_LIST_ITEMS + 1;

    let cidrs = (0..too_many)
        .map(|index| format!("\"10.0.{}.0/24\"", index / 256))
        .collect::<Vec<_>>()
        .join(", ");
    let text = with_extra(&format!(
        r#"
[access]
source_allow = [{cidrs}]
"#
    ));
    assert_rejected(&text, &["access.source_allow", "at most 256 entries"]);

    let mut rules = String::new();
    for index in 0..too_many {
        rules.push_str(&format!(
            "\n[[access.rules]]\nid = \"rule-{index}\"\naction = \"allow\"\n"
        ));
    }
    assert_rejected(
        &with_extra(&format!(
            "[access]\nsource_allow = [\"127.0.0.0/8\"]\n{rules}"
        )),
        &["access.rules", "at most 256 entries"],
    );

    let mut profiles = String::new();
    for index in 0..too_many {
        profiles.push_str(&format!(
            "\n[[egress]]\nid = \"egress-{index}\"\nmode = \"system\"\n"
        ));
    }
    assert_rejected(&with_extra(&profiles), &["egress", "at most 256 entries"]);

    let mut routing = String::new();
    for index in 0..too_many {
        routing.push_str(&format!(
            "\n[[routing.rules]]\nid = \"route-{index}\"\negress_id = \"system\"\n"
        ));
    }
    assert_rejected(
        &with_extra(&format!(
            "[[egress]]\nid = \"system\"\nmode = \"system\"\n{routing}"
        )),
        &["routing.rules", "at most 256 entries"],
    );
}

#[test]
fn m02_rejects_ip_rule_errors() {
    let empty_networks = with_extra(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.ip_rules]]
id = "ip"
action = "allow"
networks = []
allow_special = true
"#,
    );
    assert_rejected(
        &empty_networks,
        &["access.ip_rules[0].networks", "must not be empty"],
    );

    let deny_special = with_extra(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.ip_rules]]
id = "ip"
action = "deny"
networks = ["10.0.0.0/8"]
allow_special = true
"#,
    );
    assert_rejected(
        &deny_special,
        &[
            "access.ip_rules[0].allow_special",
            "only allow rules may set allow_special",
        ],
    );
}

#[test]
fn m02_rejects_egress_profile_errors() {
    let cases = [
        (
            r#"
[[egress]]
id = "bad"
mode = "system"
bind_ip = "127.0.0.1"
"#,
            "egress[0].bind_ip",
            "not allowed for system mode",
        ),
        (
            r#"
[[egress]]
id = "bad"
mode = "bind_ip"
"#,
            "egress[0].bind_ip",
            "required for bind_ip mode",
        ),
        (
            r#"
[[egress]]
id = "bad"
mode = "bind_ip"
bind_ip = "0.0.0.0"
"#,
            "egress[0].bind_ip",
            "specific unicast",
        ),
        (
            r#"
[[egress]]
id = "bad"
mode = "bind_ip"
bind_ip = "::ffff:127.0.0.1"
"#,
            "egress[0].bind_ip",
            "specific unicast",
        ),
        (
            r#"
[[egress]]
id = "bad"
mode = "bogus"
"#,
            "egress[0].mode",
            "must be `system` or `bind_ip`",
        ),
    ];
    for (extra, path, reason) in cases {
        assert_rejected(&with_extra(extra), &[path, reason]);
    }

    assert_rejected(
        &base().replace("[runtime]", "egress = []\n\n[runtime]"),
        &["egress", "must not be empty"],
    );
}

#[test]
fn m02_rejects_routing_errors() {
    assert_rejected(
        &with_extra(
            r#"
[[egress]]
id = "via-a"
mode = "system"
"#,
        ),
        &["routing.default_egress", "unknown egress id"],
    );

    assert_rejected(
        &with_extra(
            r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "rule"
action = "allow"

[[egress]]
id = "system"
mode = "system"

[[routing.rules]]
id = "route"
egress_id = "system"
sources = ["127.0.0.0/8"]
"#,
        ),
        &["routing.rules[0]", "unknown field `sources`"],
    );
}

#[test]
fn m02_rejects_dns_and_transport_ranges() {
    let dns_cases = [
        ("timeout_ms = 99", "dns.timeout_ms"),
        ("timeout_ms = 30001", "dns.timeout_ms"),
        ("max_in_flight = 0", "dns.max_in_flight"),
        ("max_in_flight = 65", "dns.max_in_flight"),
        ("max_answers = 0", "dns.max_answers"),
        ("max_answers = 65", "dns.max_answers"),
    ];
    for (field, path) in dns_cases {
        assert_rejected(
            &with_extra(&format!("[dns]\n{field}\n")),
            &[path, "must be in"],
        );
    }

    let transport_cases = [
        ("total_timeout_ms = 99", "transport.total_timeout_ms"),
        ("total_timeout_ms = 120001", "transport.total_timeout_ms"),
        ("connect_timeout_ms = 99", "transport.connect_timeout_ms"),
        ("connect_timeout_ms = 30001", "transport.connect_timeout_ms"),
        ("max_connect_attempts = 0", "transport.max_connect_attempts"),
        ("max_connect_attempts = 9", "transport.max_connect_attempts"),
        ("max_connecting = 0", "transport.max_connecting"),
        ("max_connecting = 257", "transport.max_connecting"),
    ];
    for (field, path) in transport_cases {
        assert_rejected(
            &with_extra(&format!("[transport]\n{field}\n")),
            &[path, "must be in"],
        );
    }

    assert_rejected(
        &with_extra("[transport]\ntotal_timeout_ms = 1000\nconnect_timeout_ms = 1001\n"),
        &["transport.connect_timeout_ms", "must not exceed"],
    );

    let low_connections = base().replace("max_connections = 256", "max_connections = 1")
        + "[transport]\nmax_connecting = 2\n";
    assert_rejected(
        &low_connections,
        &["transport.max_connecting", "must be in 1..=1"],
    );
}

#[test]
fn m02_rejects_unknown_nested_fields() {
    let cases = [
        (
            with_extra("[access]\nsource_allow = [\"127.0.0.0/8\"]\nunexpected = true\n"),
            "access",
            "unexpected",
        ),
        (
            with_extra(
                r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "rule"
action = "allow"
unexpected = true
"#,
            ),
            "access.rules[0]",
            "unexpected",
        ),
        (
            with_extra("[dns]\nunexpected = true\n"),
            "dns",
            "unexpected",
        ),
        (
            with_extra("[transport]\nunexpected = true\n"),
            "transport",
            "unexpected",
        ),
        (
            with_extra("[[egress]]\nid = \"system\"\nmode = \"system\"\nbind_device = \"eth0\"\n"),
            "egress[0]",
            "bind_device",
        ),
        (
            with_extra(
                r#"
[[egress]]
id = "system"
mode = "system"

[routing]
default_egress = "system"
unexpected = true
"#,
            ),
            "routing",
            "unexpected",
        ),
    ];
    for (text, path, field) in cases {
        let diagnostic = message(&text);
        assert!(diagnostic.contains(path), "{path}: {diagnostic}");
        assert!(
            diagnostic.contains(&format!("unknown field `{field}`")),
            "{path}: {diagnostic}"
        );
    }
}

#[test]
fn m02_errors_do_not_echo_policy_values_or_inject_lines() {
    const MARKER: &str = "MARKER-SECRET-M02";
    let cases = [
        with_extra(&format!("[access]\nsource_allow = [\"{MARKER}\"]\n")),
        with_extra(&format!(
            r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "rule"
action = "allow"
host_exact = ["bad/{MARKER}"]
"#
        )),
        with_extra(&format!("[[egress]]\nid = \"bad\"\nmode = \"{MARKER}\"\n")),
        with_extra(&format!(
            "[[egress]]\nid = \"bad\"\nmode = \"bind_ip\"\nbind_ip = \"{MARKER}\"\n"
        )),
        with_extra(&format!("[dns]\ntimeout_ms = \"{MARKER}\"\n")),
        with_extra(
            "[access]\nsource_allow = [\"127.0.0.0/8\"]\n\"first\\nFORGED-LOG-LINE\" = true\n",
        ),
    ];
    for text in cases {
        let diagnostic = message(&text);
        assert!(
            !diagnostic.contains(MARKER),
            "sensitive value leaked: {diagnostic}"
        );
        assert!(
            !diagnostic.contains('\n'),
            "raw newline in diagnostic: {diagnostic:?}"
        );
        assert!(
            diagnostic.contains("field")
                || diagnostic.contains("access")
                || diagnostic.contains("dns"),
            "lost context: {diagnostic}"
        );
    }
}
