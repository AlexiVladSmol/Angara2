//! M02 ACL and IP policy tests (M02-ACL-01/02, M02-IP-01/02).

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use angara::config::{Config, IpDefault, RuleAction};
use angara::policy::{
    PolicyError, RequestMeta, check_ip, check_request, check_source, special_ipv4_prefixes,
    special_ipv6_prefixes,
};
use angara::target::CanonicalTarget;
use http::Method;

fn config(extra: &str) -> Config {
    Config::parse(&format!("{}{extra}", common::config("\"auto\""))).expect("valid config")
}

fn meta<'a>(
    target: &'a CanonicalTarget,
    method: &'a Method,
    source: IpAddr,
    listener: &'a str,
) -> RequestMeta<'a> {
    RequestMeta {
        listener_id: listener,
        source,
        method,
        target,
    }
}

#[test]
fn m02_acl01_source_gate_normalizes_and_defaults_to_deny() {
    let empty = config("");
    assert_eq!(
        check_source(empty.access(), IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Err(PolicyError::SourceDenied)
    );

    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8", "::ffff:10.0.0.0/104"]
"#,
    );
    assert!(check_source(access.access(), IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
    assert!(
        check_source(
            access.access(),
            IpAddr::V6("::ffff:127.0.0.1".parse().expect("mapped"))
        )
        .is_ok()
    );
    assert_eq!(
        check_source(access.access(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        Err(PolicyError::SourceDenied)
    );
}

#[test]
fn m02_acl01_mapped_source_cidr_matches_plain_and_mapped_source() {
    let access = config(
        r#"
[access]
source_allow = ["::ffff:127.0.0.0/104"]
"#,
    );
    assert!(check_source(access.access(), IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
    assert!(
        check_source(
            access.access(),
            IpAddr::V6("::ffff:127.0.0.1".parse().expect("mapped"))
        )
        .is_ok()
    );
    assert_eq!(
        check_source(access.access(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        Ok(())
    );
}

#[test]
fn m02_acl01_first_match_and_selectors_and_or_semantics() {
    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "deny-admin-get"
action = "deny"
listeners = ["loopback"]
methods = ["GET"]
host_exact = ["admin.example.com"]

[[access.rules]]
id = "allow-example"
action = "allow"
listeners = ["loopback"]
methods = ["GET", "HEAD"]
ports = [80, 8080]
host_suffix = ["example.com"]

[[access.rules]]
id = "catch-all-deny"
action = "deny"
"#,
    );
    let get = Method::GET;
    let post = Method::POST;

    let allowed = CanonicalTarget::parse(&get, "http://a.example.com:8080/").expect("target");
    let selected = check_request(
        access.access(),
        &meta(&allowed, &get, IpAddr::V4(Ipv4Addr::LOCALHOST), "loopback"),
    )
    .expect("allowed");
    assert_eq!(selected.id(), "allow-example");

    let head = Method::HEAD;
    let allowed = CanonicalTarget::parse(&head, "http://example.com/").expect("target");
    assert_eq!(
        check_request(
            access.access(),
            &meta(&allowed, &head, IpAddr::V4(Ipv4Addr::LOCALHOST), "loopback")
        )
        .expect("allowed")
        .id(),
        "allow-example"
    );

    let admin = CanonicalTarget::parse(&get, "http://admin.example.com/").expect("target");
    assert_eq!(
        check_request(
            access.access(),
            &meta(&admin, &get, IpAddr::V4(Ipv4Addr::LOCALHOST), "loopback")
        ),
        Err(PolicyError::AccessDenied)
    );

    let post_target = CanonicalTarget::parse(&post, "http://example.com/").expect("target");
    assert_eq!(
        check_request(
            access.access(),
            &meta(
                &post_target,
                &post,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "loopback"
            )
        ),
        Err(PolicyError::AccessDenied)
    );

    let wrong_listener = CanonicalTarget::parse(&get, "http://example.com/").expect("target");
    assert_eq!(
        check_request(
            access.access(),
            &meta(
                &wrong_listener,
                &get,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "other"
            )
        ),
        Err(PolicyError::AccessDenied)
    );

    let catch_all = CanonicalTarget::parse(&get, "http://unrelated.test/").expect("target");
    assert_eq!(
        check_request(
            access.access(),
            &meta(
                &catch_all,
                &get,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "loopback"
            )
        ),
        Err(PolicyError::AccessDenied)
    );
}

#[test]
fn m02_acl01_catch_all_allow_and_default_deny() {
    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "allow-all"
action = "allow"
"#,
    );
    let get = Method::GET;
    let target = CanonicalTarget::parse(&get, "http://anything.test/").expect("target");
    assert_eq!(
        check_request(
            access.access(),
            &meta(&target, &get, IpAddr::V4(Ipv4Addr::LOCALHOST), "loopback")
        )
        .expect("catch-all")
        .id(),
        "allow-all"
    );

    let no_rules = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]
"#,
    );
    assert_eq!(
        check_request(
            no_rules.access(),
            &meta(&target, &get, IpAddr::V4(Ipv4Addr::LOCALHOST), "loopback")
        ),
        Err(PolicyError::AccessDenied)
    );
}

#[test]
fn m02_acl02_exact_and_suffix_do_not_match_ip_literals() {
    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "allow-example"
action = "allow"
host_suffix = ["example.com"]
"#,
    );
    let get = Method::GET;
    for target in [
        "http://example.com/",
        "http://a.example.com/",
        "http://example.com./",
    ] {
        let target = CanonicalTarget::parse(&get, target).expect("target");
        assert!(
            check_request(
                access.access(),
                &meta(&target, &get, IpAddr::V4(Ipv4Addr::LOCALHOST), "loopback")
            )
            .is_ok(),
            "{target:?}"
        );
    }
    for target in [
        "http://notexample.com/",
        "http://example.com.attacker.test/",
        "http://127.0.0.1/",
        "http://[::1]/",
    ] {
        let target = CanonicalTarget::parse(&get, target).expect("target");
        assert_eq!(
            check_request(
                access.access(),
                &meta(&target, &get, IpAddr::V4(Ipv4Addr::LOCALHOST), "loopback")
            ),
            Err(PolicyError::AccessDenied),
            "{target:?}"
        );
    }
}

#[test]
fn m02_ip01_public_only_blocks_special_ranges_and_allows_global_unicast() {
    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "public_only"
"#,
    );
    let blocked = [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "64:ff9b::1",
        "100::1",
        "2001:db8::1",
        "2001:0::1",
        "2002::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "4000::1",
    ];
    for address in blocked {
        assert_eq!(
            check_ip(access.access(), IpAddr::from_str(address).expect("IP")),
            Err(PolicyError::DestinationDenied),
            "{address}"
        );
    }
    for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2a00:1450::1"] {
        assert!(
            check_ip(access.access(), IpAddr::from_str(address).expect("IP")).is_ok(),
            "{address}"
        );
    }

    assert!(!special_ipv4_prefixes().is_empty());
    assert!(!special_ipv6_prefixes().is_empty());
}

#[test]
fn m02_ip01_narrow_allow_special_opens_only_listed_network() {
    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.ip_rules]]
id = "loopback-v4"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#,
    );
    assert!(check_ip(access.access(), IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
    assert!(check_ip(access.access(), IpAddr::from_str("127.0.0.2").unwrap()).is_ok());
    for address in ["10.0.0.1", "169.254.169.254", "::1", "8.8.8.8"] {
        assert_eq!(
            check_ip(access.access(), IpAddr::from_str(address).expect("IP")),
            Err(PolicyError::DestinationDenied),
            "{address}"
        );
    }
}

#[test]
fn m02_ip01_first_match_rules_and_unsafe_categories() {
    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.ip_rules]]
id = "allow-all-special"
action = "allow"
networks = ["0.0.0.0/0", "::/0"]
allow_special = true

[[access.ip_rules]]
id = "deny-private"
action = "deny"
networks = ["10.0.0.0/8"]
"#,
    );
    // First match wins: the broad allow precedes the private deny.
    assert!(check_ip(access.access(), IpAddr::from_str("10.0.0.1").unwrap()).is_ok());
    // Unsafe targets stay denied even with allow_special.
    for address in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "ff02::1"] {
        assert_eq!(
            check_ip(access.access(), IpAddr::from_str(address).expect("IP")),
            Err(PolicyError::DestinationDenied),
            "{address}"
        );
    }
}

#[test]
fn m02_ip01_deny_before_allow_and_default_deny() {
    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "public_only"

[[access.ip_rules]]
id = "deny-loopback"
action = "deny"
networks = ["127.0.0.0/8"]

[[access.ip_rules]]
id = "allow-loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#,
    );
    assert_eq!(
        check_ip(access.access(), IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Err(PolicyError::DestinationDenied)
    );
    assert_eq!(access.access().ip_default(), IpDefault::PublicOnly);
    assert_eq!(access.access().ip_rules()[0].action(), RuleAction::Deny);
}

#[test]
fn m02_ip02_ipv4_mapped_is_normalized_before_policy() {
    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.ip_rules]]
id = "allow-loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#,
    );
    let mapped = IpAddr::V6("::ffff:127.0.0.1".parse::<Ipv6Addr>().expect("mapped"));
    assert_eq!(
        check_ip(access.access(), mapped),
        Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
}

#[test]
fn m02_acl02_unicode_config_selector_matches_ascii_target() {
    let access = config(
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "unicode"
action = "allow"
host_exact = ["Bücher.Example."]
"#,
    );
    let get = Method::GET;
    let target = CanonicalTarget::parse(&get, "http://xn--bcher-kva.example/").expect("target");
    assert!(
        check_request(
            access.access(),
            &meta(&target, &get, IpAddr::V4(Ipv4Addr::LOCALHOST), "loopback")
        )
        .is_ok()
    );
}
