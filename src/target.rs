//! Canonical HTTP / CONNECT destinations and host normalization.
//!
//! This module works with an already extracted request-target and `Host`
//! header value. It does not parse raw HTTP messages and does not perform DNS.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use http::uri::{Authority, PathAndQuery};
use http::{Method, Uri};

/// Maximum request-target length before parsing.
pub const MAX_REQUEST_TARGET_BYTES: usize = 8_192;
/// Maximum `Host` header value length before parsing.
pub const MAX_HOST_HEADER_BYTES: usize = 1_024;
/// Maximum normalized domain length without the trailing dot.
pub const MAX_DOMAIN_BYTES: usize = 253;
/// Maximum DNS label length.
pub const MAX_LABEL_BYTES: usize = 63;

/// A normalized ASCII domain name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainName(String);

impl DomainName {
    /// Normalizes a domain using the UTS #46 web profile.
    pub fn parse(input: &str) -> Result<Self, TargetError> {
        normalize_domain(input)
    }

    /// Normalized ASCII representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns true when `self` equals `suffix` or is a subdomain of it.
    ///
    /// The comparison is by DNS label boundary, so `example.com` matches
    /// `example.com` and `a.example.com`, but not `notexample.com`.
    pub fn matches_suffix(&self, suffix: &Self) -> bool {
        self.0 == suffix.0
            || self
                .0
                .strip_suffix(&suffix.0)
                .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A canonical destination host.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    /// Normalized domain name.
    Domain(DomainName),
    /// Numeric IPv4 or IPv6 address (IPv4-mapped IPv6 is normalized to IPv4).
    Ip(IpAddr),
}

impl Host {
    /// The domain when this is a domain host.
    pub fn as_domain(&self) -> Option<&DomainName> {
        match self {
            Self::Domain(domain) => Some(domain),
            Self::Ip(_) => None,
        }
    }

    /// The IP address when this is an IP host.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Domain(_) => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain) => formatter.write_str(domain.as_str()),
            Self::Ip(ip) => write!(formatter, "{ip}"),
        }
    }
}

/// A canonical request destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalTarget {
    method: Method,
    kind: TargetKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TargetKind {
    Http {
        host: Host,
        port: u16,
        path_and_query: PathAndQuery,
    },
    Connect {
        host: Host,
        port: u16,
    },
}

impl CanonicalTarget {
    /// Parses an absolute-form HTTP target or a CONNECT authority.
    ///
    /// The method is expected to come from a token parser; its case is
    /// significant and is not normalized here.
    pub fn parse(method: &Method, request_target: &str) -> Result<Self, TargetError> {
        if request_target.len() > MAX_REQUEST_TARGET_BYTES {
            return Err(TargetError::TooLong);
        }
        if request_target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\')
        {
            return Err(TargetError::ForbiddenCharacter);
        }

        if method == Method::CONNECT {
            parse_connect(method, request_target)
        } else {
            parse_http(method, request_target)
        }
    }

    /// HTTP method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Canonical destination host.
    pub fn host(&self) -> &Host {
        match &self.kind {
            TargetKind::Http { host, .. } | TargetKind::Connect { host, .. } => host,
        }
    }

    /// Effective destination port.
    pub fn port(&self) -> u16 {
        match &self.kind {
            TargetKind::Http { port, .. } | TargetKind::Connect { port, .. } => *port,
        }
    }

    /// HTTP path and query, preserved without percent-decoding.
    pub fn path_and_query(&self) -> Option<&PathAndQuery> {
        match &self.kind {
            TargetKind::Http { path_and_query, .. } => Some(path_and_query),
            TargetKind::Connect { .. } => None,
        }
    }

    /// Whether this is a CONNECT authority target.
    pub fn is_connect(&self) -> bool {
        matches!(self.kind, TargetKind::Connect { .. })
    }
}

/// Parses an HTTP method token without changing its case.
pub fn parse_method(raw: &str) -> Result<Method, TargetError> {
    Method::from_bytes(raw.as_bytes()).map_err(|_| TargetError::InvalidMethod)
}

/// Checks a `Host` header against the canonical target.
///
/// Missing and duplicate values are normally rejected by the HTTP protocol
/// layer in M03/M04; this helper covers the absent, malformed and contradictory
/// cases available to M02.
pub fn check_host_header(
    target: &CanonicalTarget,
    host_header: Option<&str>,
) -> Result<(), TargetError> {
    let Some(host_header) = host_header else {
        return Err(TargetError::MissingHost);
    };
    if host_header.len() > MAX_HOST_HEADER_BYTES {
        return Err(TargetError::HostHeaderTooLong);
    }
    if host_header
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == b'\\')
        || host_header.contains('/')
        || host_header.contains('?')
        || host_header.contains('#')
        || host_header.contains('@')
    {
        return Err(TargetError::InvalidHostHeader);
    }

    let authority = Authority::from_str(host_header).map_err(|_| TargetError::InvalidHostHeader)?;
    let host = parse_authority_host(&authority)?;
    let header_port = parse_authority_port(&authority, None)?;

    if host != *target.host() {
        return Err(TargetError::HostMismatch);
    }

    match &target.kind {
        TargetKind::Http { port, .. } => {
            let effective = header_port.unwrap_or(80);
            if effective != *port {
                return Err(TargetError::HostMismatch);
            }
        }
        TargetKind::Connect { port, .. } => {
            if let Some(header_port) = header_port
                && header_port != *port
            {
                return Err(TargetError::HostMismatch);
            }
        }
    }

    Ok(())
}

/// Normalizes an IPv4-mapped IPv6 address to IPv4.
pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ipv6)),
    }
}

fn parse_http(method: &Method, request_target: &str) -> Result<CanonicalTarget, TargetError> {
    if request_target.contains('#') {
        return Err(TargetError::Fragment);
    }

    let uri = Uri::from_str(request_target).map_err(|_| TargetError::InvalidForm)?;
    let Some(scheme) = uri.scheme_str() else {
        return Err(TargetError::InvalidForm);
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(TargetError::InvalidScheme);
    }
    let Some(authority) = uri.authority() else {
        return Err(TargetError::InvalidForm);
    };
    if authority.as_str().contains('@') {
        return Err(TargetError::UserInfo);
    }

    let host = parse_authority_host(authority)?;
    let port = parse_authority_port(authority, Some(80))?.ok_or(TargetError::InvalidPort)?;
    let raw_path = uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    let normalized_path = if raw_path.is_empty() {
        "/".to_owned()
    } else if raw_path.starts_with('/') {
        raw_path.to_owned()
    } else if raw_path.starts_with('?') {
        format!("/{raw_path}")
    } else {
        return Err(TargetError::InvalidForm);
    };
    let path_and_query =
        PathAndQuery::from_str(&normalized_path).map_err(|_| TargetError::InvalidForm)?;

    Ok(CanonicalTarget {
        method: method.clone(),
        kind: TargetKind::Http {
            host,
            port,
            path_and_query,
        },
    })
}

fn parse_connect(method: &Method, request_target: &str) -> Result<CanonicalTarget, TargetError> {
    if request_target.contains('#') {
        return Err(TargetError::Fragment);
    }
    if request_target.contains('/') || request_target.contains('?') {
        return Err(TargetError::InvalidForm);
    }
    if request_target.contains('@') {
        return Err(TargetError::UserInfo);
    }
    if !request_target.starts_with('[') && request_target.matches(':').count() > 1 {
        return Err(TargetError::InvalidForm);
    }

    let authority = Authority::from_str(request_target).map_err(|_| TargetError::InvalidForm)?;
    let host = parse_authority_host(&authority)?;
    let port = parse_authority_port(&authority, None)?.ok_or(TargetError::InvalidPort)?;

    Ok(CanonicalTarget {
        method: method.clone(),
        kind: TargetKind::Connect { host, port },
    })
}

fn parse_authority_host(authority: &Authority) -> Result<Host, TargetError> {
    let host = authority.host();
    if host.is_empty() {
        return Err(TargetError::InvalidHost);
    }

    if let Some(ipv6) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        if ipv6.contains('%') {
            return Err(TargetError::InvalidHost);
        }
        let ipv6 = Ipv6Addr::from_str(ipv6).map_err(|_| TargetError::InvalidHost)?;
        return Ok(Host::Ip(normalize_ip(IpAddr::V6(ipv6))));
    }

    if host.contains('[') || host.contains(']') || host.contains(':') {
        return Err(TargetError::InvalidHost);
    }
    if let Ok(ipv4) = Ipv4Addr::from_str(host) {
        return Ok(Host::Ip(IpAddr::V4(ipv4)));
    }
    if looks_like_numeric_ipv4(host) {
        return Err(TargetError::NumericIp);
    }

    DomainName::parse(host).map(Host::Domain)
}

fn parse_authority_port(
    authority: &Authority,
    default: Option<u16>,
) -> Result<Option<u16>, TargetError> {
    let authority = authority.as_str();
    let port = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(TargetError::InvalidHost)?;
        let rest = &authority[end + 1..];
        if rest.is_empty() {
            None
        } else if let Some(port) = rest.strip_prefix(':') {
            Some(port)
        } else {
            return Err(TargetError::InvalidHostHeader);
        }
    } else {
        authority.rsplit_once(':').map(|(_, port)| port)
    };

    match port {
        None => Ok(default),
        Some(port) => {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(TargetError::InvalidPort);
            }
            let port = u16::from_str(port).map_err(|_| TargetError::InvalidPort)?;
            if port == 0 {
                return Err(TargetError::InvalidPort);
            }
            Ok(Some(port))
        }
    }
}

fn normalize_domain(input: &str) -> Result<DomainName, TargetError> {
    if input.is_empty() || input.len() > 4_096 {
        return Err(TargetError::InvalidDomain);
    }
    if input.chars().any(|character| {
        character.is_control()
            || character.is_whitespace()
            || matches!(
                character,
                '/' | '\\' | '@' | ':' | '#' | '?' | '*' | '%' | '[' | ']'
            )
    }) {
        return Err(TargetError::InvalidDomain);
    }

    let ascii = idna::domain_to_ascii_cow(input.as_bytes(), idna::AsciiDenyList::URL)
        .map_err(|_| TargetError::InvalidDomain)?;
    let mut normalized = ascii.into_owned();
    if normalized.ends_with('.') {
        normalized.pop();
    }
    normalized.make_ascii_lowercase();

    if normalized.is_empty() || normalized.len() > MAX_DOMAIN_BYTES {
        return Err(TargetError::InvalidDomain);
    }
    if normalized.starts_with('.') || normalized.ends_with('.') || normalized.contains("..") {
        return Err(TargetError::InvalidDomain);
    }
    if !normalized.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
    }) {
        return Err(TargetError::InvalidDomain);
    }
    if normalized
        .split('.')
        .any(|label| label.is_empty() || label.len() > MAX_LABEL_BYTES)
    {
        return Err(TargetError::InvalidDomain);
    }
    if Ipv4Addr::from_str(&normalized).is_ok()
        || Ipv6Addr::from_str(&normalized).is_ok()
        || looks_like_numeric_ipv4(&normalized)
    {
        return Err(TargetError::NumericIp);
    }

    Ok(DomainName(normalized))
}

fn looks_like_numeric_ipv4(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let host = host.to_ascii_lowercase();
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return true;
    }
    host.split('.').any(|label| {
        label
            .strip_prefix("0x")
            .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    })
}

/// Errors produced while parsing or normalizing a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetError {
    /// Request-target or Host exceeds its input limit.
    TooLong,
    /// Request-target contains a space, backslash or control character.
    ForbiddenCharacter,
    /// Method token is invalid.
    InvalidMethod,
    /// Target form is not absolute-form or CONNECT authority.
    InvalidForm,
    /// Scheme is not `http`.
    InvalidScheme,
    /// Port is missing, zero or out of range.
    InvalidPort,
    /// Host is empty or malformed.
    InvalidHost,
    /// Host contains userinfo.
    UserInfo,
    /// Target contains a fragment.
    Fragment,
    /// Host is a non-standard numeric IPv4 form.
    NumericIp,
    /// Domain is not a valid normalized DNS name.
    InvalidDomain,
    /// `Host` header is absent.
    MissingHost,
    /// `Host` header is too long.
    HostHeaderTooLong,
    /// `Host` header is malformed.
    InvalidHostHeader,
    /// `Host` header contradicts the request target.
    HostMismatch,
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLong => "request target or Host is too long",
            Self::ForbiddenCharacter => "request target contains a forbidden character",
            Self::InvalidMethod => "invalid HTTP method token",
            Self::InvalidForm => "invalid request-target form",
            Self::InvalidScheme => "only absolute-form http targets are supported",
            Self::InvalidPort => "invalid or missing port",
            Self::InvalidHost => "invalid host",
            Self::UserInfo => "userinfo is not allowed",
            Self::Fragment => "fragments are not allowed",
            Self::NumericIp => "non-standard numeric IPv4 host is not allowed",
            Self::InvalidDomain => "invalid domain name",
            Self::MissingHost => "Host header is required",
            Self::HostHeaderTooLong => "Host header is too long",
            Self::InvalidHostHeader => "invalid Host header",
            Self::HostMismatch => "Host header does not match the request target",
        })
    }
}

impl std::error::Error for TargetError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_domains_and_matches_suffixes_by_label() {
        let domain = DomainName::parse("Bücher.Example.").expect("IDNA domain");
        assert_eq!(domain.as_str(), "xn--bcher-kva.example");

        let suffix = DomainName::parse("example.com").expect("suffix");
        assert!(
            DomainName::parse("a.example.com")
                .expect("subdomain")
                .matches_suffix(&suffix)
        );
        assert!(
            !DomainName::parse("notexample.com")
                .expect("other domain")
                .matches_suffix(&suffix)
        );
        assert!(
            !DomainName::parse("example.com.attacker.test")
                .expect("other domain")
                .matches_suffix(&suffix)
        );
    }

    #[test]
    fn rejects_non_standard_numeric_hosts() {
        for host in ["127.1", "0177.0.0.1", "2130706433", "0x7f000001"] {
            assert!(DomainName::parse(host).is_err(), "{host}");
        }
    }

    #[test]
    fn parses_http_and_connect_targets() {
        let http = CanonicalTarget::parse(&Method::GET, "http://Example.COM:8080/a%2Fb?q=1")
            .expect("HTTP target");
        assert_eq!(
            http.host().as_domain().map(DomainName::as_str),
            Some("example.com")
        );
        assert_eq!(http.port(), 8080);
        assert_eq!(
            http.path_and_query().map(PathAndQuery::as_str),
            Some("/a%2Fb?q=1")
        );
        assert!(!http.is_connect());

        let connect =
            CanonicalTarget::parse(&Method::CONNECT, "[::1]:443").expect("CONNECT target");
        assert_eq!(
            connect.host().as_ip(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(connect.port(), 443);
        assert!(connect.is_connect());
    }

    #[test]
    fn check_host_header_handles_http_and_connect_rules() {
        let http =
            CanonicalTarget::parse(&Method::GET, "http://example.com:8080/").expect("HTTP target");
        assert!(check_host_header(&http, Some("example.com:8080")).is_ok());
        assert!(check_host_header(&http, Some("example.com")).is_err());
        assert!(check_host_header(&http, None).is_err());

        let connect =
            CanonicalTarget::parse(&Method::CONNECT, "example.com:443").expect("CONNECT target");
        assert!(check_host_header(&connect, Some("example.com")).is_ok());
        assert!(check_host_header(&connect, Some("example.com:443")).is_ok());
        assert!(check_host_header(&connect, Some("example.com:80")).is_err());
    }
}
