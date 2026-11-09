//! Source gate, pre-DNS request ACL and destination IP policy.

use std::fmt;
use std::net::IpAddr;
use std::sync::LazyLock;

use http::Method;
use ipnet::IpNet;

use crate::config::{AccessConfig, AccessRule, HostSelectors, IpDefault, RuleAction, Selectors};
use crate::target::{CanonicalTarget, normalize_ip};

/// Request attributes visible to ACL matching.
pub struct RequestMeta<'a> {
    /// Listener that accepted the client.
    pub listener_id: &'a str,
    /// Trusted client peer address.
    pub source: IpAddr,
    /// HTTP method, preserving token case.
    pub method: &'a Method,
    /// Canonical destination.
    pub target: &'a CanonicalTarget,
}

/// Policy rejection classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// Client source is not in `access.source_allow`.
    SourceDenied,
    /// No request rule allowed the request.
    AccessDenied,
    /// A destination IP was rejected by the IP policy.
    DestinationDenied,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceDenied => "client source is not allowed",
            Self::AccessDenied => "request is denied by access rules",
            Self::DestinationDenied => "destination address is denied",
        })
    }
}

impl std::error::Error for PolicyError {}

/// Applies the source CIDR allow-list.
pub fn check_source(access: &AccessConfig, source: IpAddr) -> Result<(), PolicyError> {
    let source = normalize_ip(source);
    if access
        .source_allow()
        .iter()
        .any(|network| network.contains(&source))
    {
        Ok(())
    } else {
        Err(PolicyError::SourceDenied)
    }
}

/// Applies the first matching pre-DNS request rule.
pub fn check_request<'a>(
    access: &'a AccessConfig,
    meta: &RequestMeta<'_>,
) -> Result<&'a AccessRule, PolicyError> {
    for rule in access.rules() {
        if selectors_match(rule.selectors(), meta) {
            return match rule.action() {
                RuleAction::Allow => Ok(rule),
                RuleAction::Deny => Err(PolicyError::AccessDenied),
            };
        }
    }
    Err(PolicyError::AccessDenied)
}

/// Applies the first matching destination IP rule and the default.
pub fn check_ip(access: &AccessConfig, ip: IpAddr) -> Result<IpAddr, PolicyError> {
    let ip = normalize_ip(ip);
    if is_unsafe_target(ip) {
        return Err(PolicyError::DestinationDenied);
    }

    for rule in access.ip_rules() {
        if rule.networks().iter().any(|network| network.contains(&ip)) {
            return match rule.action() {
                RuleAction::Deny => Err(PolicyError::DestinationDenied),
                RuleAction::Allow if is_special(ip) && !rule.allow_special() => {
                    Err(PolicyError::DestinationDenied)
                }
                RuleAction::Allow => Ok(ip),
            };
        }
    }

    match access.ip_default() {
        IpDefault::Deny => Err(PolicyError::DestinationDenied),
        IpDefault::PublicOnly if is_special(ip) => Err(PolicyError::DestinationDenied),
        IpDefault::PublicOnly => Ok(ip),
    }
}

/// Matches all present selectors; selectors inside a list are OR.
pub(crate) fn selectors_match(selectors: &Selectors, meta: &RequestMeta<'_>) -> bool {
    if let Some(listeners) = selectors.listeners()
        && !listeners
            .iter()
            .any(|listener| listener == meta.listener_id)
    {
        return false;
    }
    if let Some(sources) = selectors.sources() {
        let source = normalize_ip(meta.source);
        if !sources.iter().any(|network| network.contains(&source)) {
            return false;
        }
    }
    if let Some(methods) = selectors.methods()
        && !methods.iter().any(|method| method == meta.method)
    {
        return false;
    }
    if let Some(ports) = selectors.ports()
        && !ports.contains(&meta.target.port())
    {
        return false;
    }

    match selectors.hosts() {
        HostSelectors::Any => true,
        HostSelectors::Exact(domains) => meta
            .target
            .host()
            .as_domain()
            .is_some_and(|host| domains.iter().any(|domain| domain == host)),
        HostSelectors::Suffix(domains) => meta
            .target
            .host()
            .as_domain()
            .is_some_and(|host| domains.iter().any(|domain| host.matches_suffix(domain))),
    }
}

/// Whether an address is in a special-purpose or otherwise non-global range.
pub(crate) fn is_special(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(ip) => {
            let address = IpAddr::V4(ip);
            ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || SPECIAL_V4.iter().any(|network| network.contains(&address))
        }
        IpAddr::V6(ip) => {
            let address = IpAddr::V6(ip);
            ip.is_unspecified()
                || ip.is_multicast()
                || !V6_GLOBAL.contains(&address)
                || SPECIAL_V6.iter().any(|network| network.contains(&address))
        }
    }
}

fn is_unsafe_target(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    }
}

// Snapshot of the IANA IPv4/Iv6 Special-Purpose Address Registries, 2026-11-09.
// Angara deliberately treats every listed special prefix as non-public, even
// entries marked Globally Reachable, and additionally blocks IPv4 240.0.0.0/4
// and IPv6 outside 2000::/3.
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
static SPECIAL_V4: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ]
    .into_iter()
    .map(|network| network.parse().expect("valid static IPv4 CIDR"))
    .collect()
});

static SPECIAL_V6: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "2620:4f:8000::/48",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .into_iter()
    .map(|network| network.parse().expect("valid static IPv6 CIDR"))
    .collect()
});

static V6_GLOBAL: LazyLock<IpNet> =
    LazyLock::new(|| "2000::/3".parse().expect("valid IPv6 global CIDR"));

/// IANA special-purpose IPv4 snapshot.
pub fn special_ipv4_prefixes() -> &'static [IpNet] {
    &SPECIAL_V4
}

/// IANA special-purpose IPv6 snapshot.
pub fn special_ipv6_prefixes() -> &'static [IpNet] {
    &SPECIAL_V6
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use http::Method;

    use crate::config::Config;
    use crate::target::CanonicalTarget;

    fn access_config(text: &str) -> Config {
        Config::parse(text).expect("valid config")
    }

    fn config_with_access(access: &str) -> Config {
        access_config(&format!(
            r#"
schema_version = 1
[runtime]
worker_threads = "auto"
[limits]
max_connections = 256
max_header_bytes = 32768
header_read_timeout_ms = 10000
idle_timeout_ms = 60000
shutdown_timeout_ms = 10000
[[listeners]]
id = "lab"
bind = "127.0.0.1:3128"
transport = "http"
{access}
"#
        ))
    }

    #[test]
    fn public_only_blocks_special_ranges_and_allows_plain_global() {
        let config = config_with_access(
            r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "public_only"
"#,
        );
        let access = config.access();
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "8.8.8.8",
            "2606:4700:4700::1111",
        ] {
            let ip = IpAddr::from_str(address).expect("IP");
            let expected = address == "8.8.8.8" || address == "2606:4700:4700::1111";
            assert_eq!(check_ip(access, ip).is_ok(), expected, "address {address}");
        }
    }

    #[test]
    fn narrow_allow_special_opens_only_the_listed_network() {
        let config = config_with_access(
            r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#,
        );
        let access = config.access();
        assert!(check_ip(access, IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
        assert!(check_ip(access, IpAddr::from_str("127.0.0.2").expect("IP")).is_ok());
        assert!(check_ip(access, IpAddr::from_str("10.0.0.1").expect("IP")).is_err());
        assert!(check_ip(access, IpAddr::V6(Ipv6Addr::LOCALHOST)).is_err());
    }

    #[test]
    fn request_rules_apply_and_or_and_label_boundaries() {
        let config = config_with_access(
            r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "deny-exact"
action = "deny"
host_exact = ["admin.example.com"]

[[access.rules]]
id = "allow-get"
action = "allow"
methods = ["GET"]
ports = [80]
host_suffix = ["example.com"]
"#,
        );
        let access = config.access();
        let target =
            CanonicalTarget::parse(&Method::GET, "http://a.example.com/path").expect("target");
        let meta = RequestMeta {
            listener_id: "lab",
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            method: &Method::GET,
            target: &target,
        };
        assert_eq!(
            check_request(access, &meta).expect("allowed").id(),
            "allow-get"
        );

        let admin =
            CanonicalTarget::parse(&Method::GET, "http://admin.example.com/").expect("target");
        let meta = RequestMeta {
            listener_id: "lab",
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            method: &Method::GET,
            target: &admin,
        };
        assert_eq!(
            check_request(access, &meta).unwrap_err(),
            PolicyError::AccessDenied
        );

        let other = CanonicalTarget::parse(&Method::GET, "http://notexample.com/").expect("target");
        let meta = RequestMeta {
            listener_id: "lab",
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            method: &Method::GET,
            target: &other,
        };
        assert_eq!(
            check_request(access, &meta).unwrap_err(),
            PolicyError::AccessDenied
        );

        let wrong_port =
            CanonicalTarget::parse(&Method::GET, "http://example.com:81/").expect("target");
        let meta = RequestMeta {
            listener_id: "lab",
            source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            method: &Method::GET,
            target: &wrong_port,
        };
        assert_eq!(
            check_request(access, &meta).unwrap_err(),
            PolicyError::AccessDenied
        );
    }
}
