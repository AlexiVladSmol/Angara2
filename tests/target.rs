//! M02 target normalization tests (M02-TGT-01, M02-TGT-02).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use angara::target::{
    CanonicalTarget, DomainName, Host, MAX_HOST_HEADER_BYTES, MAX_REQUEST_TARGET_BYTES,
    TargetError, check_host_header, parse_method,
};
use http::Method;

fn target(method: &Method, value: &str) -> Result<CanonicalTarget, TargetError> {
    CanonicalTarget::parse(method, value)
}

fn domain(value: &str) -> String {
    DomainName::parse(value)
        .expect("valid domain")
        .as_str()
        .to_owned()
}

#[test]
fn m02_tgt01_parses_http_defaults_path_and_query_without_decoding() {
    let parsed = target(&Method::GET, "http://Example.COM").expect("HTTP target");
    assert_eq!(
        parsed.host().as_domain().map(DomainName::as_str),
        Some("example.com")
    );
    assert_eq!(parsed.port(), 80);
    assert_eq!(parsed.path_and_query().map(|path| path.as_str()), Some("/"));
    assert!(!parsed.is_connect());

    let parsed = target(&Method::GET, "HTTP://example.com:8080/a%2Fb?q=1").expect("HTTP target");
    assert_eq!(parsed.port(), 8080);
    assert_eq!(
        parsed.path_and_query().map(|path| path.as_str()),
        Some("/a%2Fb?q=1")
    );

    let parsed = target(&Method::GET, "http://example.com?q=1").expect("query-only target");
    assert_eq!(
        parsed.path_and_query().map(|path| path.as_str()),
        Some("/?q=1")
    );

    let parsed = target(&Method::GET, "http://[::1]:8080/").expect("IPv6 target");
    assert_eq!(parsed.host().as_ip(), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert_eq!(parsed.port(), 8080);
}

#[test]
fn m02_tgt01_parses_connect_authority() {
    let parsed = target(&Method::CONNECT, "example.com:443").expect("CONNECT target");
    assert!(parsed.is_connect());
    assert_eq!(
        parsed.host().as_domain().map(DomainName::as_str),
        Some("example.com")
    );
    assert_eq!(parsed.port(), 443);
    assert!(parsed.path_and_query().is_none());

    let parsed = target(&Method::CONNECT, "[2001:db8::1]:8443").expect("IPv6 CONNECT");
    assert_eq!(parsed.port(), 8443);
    assert_eq!(
        parsed.host().as_ip(),
        Some(IpAddr::V6("2001:db8::1".parse().expect("IP")))
    );
}

#[test]
fn m02_tgt01_rejects_bad_http_forms() {
    let cases = [
        ("https://example.com/", TargetError::InvalidScheme),
        ("/origin-form", TargetError::InvalidForm),
        ("*", TargetError::InvalidForm),
        ("http://example.com/#fragment", TargetError::Fragment),
        ("http://user:pass@example.com/", TargetError::UserInfo),
        ("http://", TargetError::InvalidForm),
        ("http://example.com:0/", TargetError::InvalidPort),
        ("http://example.com:65536/", TargetError::InvalidPort),
        ("http://example.com:bad/", TargetError::InvalidPort),
        ("http://exa mple.com/", TargetError::ForbiddenCharacter),
        ("http://example.com\\path", TargetError::ForbiddenCharacter),
        ("http://example.com/\u{1}", TargetError::ForbiddenCharacter),
    ];
    for (value, expected) in cases {
        assert_eq!(
            target(&Method::GET, value).expect_err(value),
            expected,
            "target {value:?}"
        );
    }

    let too_long = format!(
        "http://example.com/{}",
        "a".repeat(MAX_REQUEST_TARGET_BYTES)
    );
    assert_eq!(
        target(&Method::GET, &too_long).expect_err("too long"),
        TargetError::TooLong
    );
}

#[test]
fn m02_tgt01_rejects_bad_connect_forms() {
    let cases = [
        ("example.com", TargetError::InvalidPort),
        ("example.com:0", TargetError::InvalidPort),
        ("example.com:65536", TargetError::InvalidPort),
        ("example.com/path", TargetError::InvalidForm),
        ("example.com?query", TargetError::InvalidForm),
        ("example.com#fragment", TargetError::Fragment),
        ("user@example.com:443", TargetError::UserInfo),
        ("::1:443", TargetError::InvalidForm),
        ("[::1]", TargetError::InvalidPort),
        ("[fe80::1%25eth0]:443", TargetError::InvalidHost),
    ];
    for (value, expected) in cases {
        assert_eq!(
            target(&Method::CONNECT, value).expect_err(value),
            expected,
            "target {value:?}"
        );
    }
}

#[test]
fn m02_tgt02_normalizes_case_trailing_dot_and_idna() {
    assert_eq!(domain("Example.COM."), "example.com");
    assert_eq!(domain("Bücher.Example."), "xn--bcher-kva.example");
    assert_eq!(domain("XN--BCHER-KVA.example"), "xn--bcher-kva.example");
    assert_eq!(domain("foo_bar.example"), "foo_bar.example");

    let suffix = DomainName::parse("example.com").expect("suffix");
    assert!(
        DomainName::parse("a.example.com")
            .expect("subdomain")
            .matches_suffix(&suffix)
    );
    assert!(
        !DomainName::parse("notexample.com")
            .expect("other")
            .matches_suffix(&suffix)
    );
    assert!(
        !DomainName::parse("example.com.attacker.test")
            .expect("other")
            .matches_suffix(&suffix)
    );
}

#[test]
fn m02_tgt02_rejects_invalid_domains_and_numeric_ipv4_forms() {
    for value in [
        "127.1",
        "0177.0.0.1",
        "2130706433",
        "0x7f000001",
        "127.0.0.1",
        "::1",
        "bad host",
        "bad/host",
        "bad%2fhost",
        "bad@host",
        "*",
    ] {
        assert!(
            DomainName::parse(value).is_err(),
            "domain {value:?} must be rejected"
        );
    }

    for value in [
        "http://127.1/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
    ] {
        assert_eq!(
            target(&Method::GET, value).expect_err(value),
            TargetError::NumericIp,
            "{value}"
        );
    }
}

#[test]
fn m02_tgt02_normalizes_ipv4_mapped_and_rejects_scoped_ipv6() {
    let parsed = target(&Method::GET, "http://[::ffff:127.0.0.1]:80/").expect("mapped IPv6");
    assert_eq!(parsed.host().as_ip(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    assert_eq!(
        target(&Method::GET, "http://[fe80::1%25eth0]:80/").expect_err("scope"),
        TargetError::InvalidHost
    );
}

#[test]
fn m02_tgt02_method_case_is_significant_and_token_checked() {
    assert_eq!(parse_method("GET").expect("GET"), Method::GET);
    let lowercase = parse_method("get").expect("custom token");
    assert_ne!(lowercase, Method::GET);
    assert!(parse_method("bad method").is_err());

    let parsed = target(&lowercase, "http://example.com/").expect("HTTP target");
    assert_eq!(parsed.method(), &lowercase);
    // A lowercase token is not CONNECT and must not select CONNECT parsing.
    assert_eq!(
        target(&lowercase, "example.com:443").expect_err("authority form"),
        TargetError::InvalidForm
    );
}

#[test]
fn m02_tgt02_host_header_rules_match_http_and_connect() {
    let http = target(&Method::GET, "http://example.com:8080/").expect("HTTP");
    assert!(check_host_header(&http, Some("example.com:8080")).is_ok());
    assert!(check_host_header(&http, Some("EXAMPLE.COM.:8080")).is_ok());
    assert_eq!(
        check_host_header(&http, Some("example.com")).expect_err("port"),
        TargetError::HostMismatch
    );
    assert_eq!(
        check_host_header(&http, Some("other.example:8080")).expect_err("host"),
        TargetError::HostMismatch
    );
    assert_eq!(
        check_host_header(&http, None).expect_err("missing"),
        TargetError::MissingHost
    );

    let http_default = target(&Method::GET, "http://example.com/").expect("HTTP");
    assert!(check_host_header(&http_default, Some("example.com")).is_ok());

    let connect = target(&Method::CONNECT, "example.com:443").expect("CONNECT");
    assert!(check_host_header(&connect, Some("example.com")).is_ok());
    assert!(check_host_header(&connect, Some("example.com:443")).is_ok());
    assert_eq!(
        check_host_header(&connect, Some("example.com:80")).expect_err("port"),
        TargetError::HostMismatch
    );

    let ipv4 = target(&Method::GET, "http://127.0.0.1:8080/").expect("IPv4");
    assert!(check_host_header(&ipv4, Some("127.0.0.1:8080")).is_ok());
    assert!(check_host_header(&ipv4, Some("localhost:8080")).is_err());

    let ipv6 = target(&Method::GET, "http://[::1]:8080/").expect("IPv6");
    assert!(check_host_header(&ipv6, Some("[::1]:8080")).is_ok());
    assert!(check_host_header(&ipv6, Some("[0:0:0:0:0:0:0:1]:8080")).is_ok());
}

#[test]
fn m02_tgt02_host_header_limits_and_invalid_values() {
    let target = target(&Method::GET, "http://example.com/").expect("HTTP");
    let too_long = format!("Host{}", "a".repeat(MAX_HOST_HEADER_BYTES));
    assert_eq!(
        check_host_header(&target, Some(&too_long)).expect_err("too long"),
        TargetError::HostHeaderTooLong
    );
    for value in [
        "",
        "example.com/path",
        "example.com?query",
        "user@example.com",
        "bad host",
        "example.com:0",
        "example.com:bad",
    ] {
        assert!(
            check_host_header(&target, Some(value)).is_err(),
            "Host {value:?} must be rejected"
        );
    }
}

#[test]
fn m02_tgt02_errors_do_not_echo_sensitive_target_parts() {
    const MARKER: &str = "MARKER-SECRET-TARGET";
    let errors = [
        target(&Method::GET, &format!("http://user:{MARKER}@example.com/")).expect_err("userinfo"),
        target(&Method::GET, &format!("http://example.com:{MARKER}/")).expect_err("port"),
        target(&Method::CONNECT, &format!("{MARKER}..example:443")).expect_err("domain"),
    ];
    for error in errors {
        let text = error.to_string();
        assert!(!text.contains(MARKER), "{text}");
    }

    let http = target(&Method::GET, "http://example.com/").expect("HTTP");
    let error =
        check_host_header(&http, Some(&format!("{MARKER}@example.com"))).expect_err("bad host");
    assert!(!error.to_string().contains(MARKER));
    assert_eq!(
        http.host(),
        &Host::Domain(DomainName::parse("example.com").unwrap())
    );
}
