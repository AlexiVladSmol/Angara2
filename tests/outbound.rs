//! M02 outbound integration tests (M02-NET-01/02/03/04, M02-ACL-04, M02-IP-02).

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use angara::config::Config;
use angara::outbound::{OutboundError, OutboundService, RequestContext};
use angara::resolver::ResolveError;
use angara::runtime::AngaraRuntime;
use angara::transport::TcpDialer;
use http::Method;

#[cfg(target_os = "linux")]
use support::spawn_echo_with_peers;
use support::{
    DelayedDialer, GatedDialer, RecordingDialer, ScriptedResolver, allow_loopback_access,
    echo_roundtrip, spawn_echo, system_egress,
};

fn runtime(config: &Config) -> AngaraRuntime {
    AngaraRuntime::build(config).expect("runtime")
}

fn config(extra: &str) -> Config {
    support::config(extra)
}

fn context(listener: &str) -> RequestContext {
    RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener)
}

fn http_target(address: std::net::SocketAddr) -> (String, String) {
    (
        format!("http://127.0.0.1:{}/", address.port()),
        format!("127.0.0.1:{}", address.port()),
    )
}

fn domain_target(host: &str, port: u16) -> (String, String) {
    (format!("http://{host}:{port}/"), format!("{host}:{port}"))
}

#[test]
fn m02_net01_full_pipeline_resolves_and_connects_real_tcp() {
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    )])]));
    let dialer = Arc::new(TcpDialer);
    let config = config(&format!("{}{}", allow_loopback_access(), system_egress()));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (address, _server) = spawn_echo().await;
        let (target, host) = domain_target("example.test", address.port());
        let mut connected = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .expect("domain request");
        assert_eq!(resolver.calls(), 1);
        assert_eq!(resolver.hosts(), vec!["example.test".to_owned()]);
        assert_eq!(connected.endpoint().egress_id(), "system");
        assert_eq!(connected.endpoint().generation(), 1);
        assert_eq!(
            connected
                .endpoint()
                .target()
                .host()
                .as_domain()
                .map(|domain| domain.as_str()),
            Some("example.test")
        );
        echo_roundtrip(&mut connected).await;
        drop(connected);

        let (target, host) = http_target(address);
        let mut connected = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .expect("direct IP request");
        assert_eq!(resolver.calls(), 1, "direct IP must not perform DNS");
        echo_roundtrip(&mut connected).await;
    });
}

#[test]
fn m02_net01_connect_target_uses_the_same_pipeline() {
    let resolver = Arc::new(ScriptedResolver::new(vec![]));
    let dialer = Arc::new(TcpDialer);
    let config = config(&format!("{}{}", allow_loopback_access(), system_egress()));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (address, _server) = spawn_echo().await;
        let target = format!("127.0.0.1:{}", address.port());
        let host = "127.0.0.1".to_owned();
        let mut connected = service
            .open_outbound(&context("lab"), &Method::CONNECT, &target, Some(&host))
            .await
            .expect("CONNECT target");
        assert!(connected.endpoint().target().is_connect());
        assert_eq!(resolver.calls(), 0);
        echo_roundtrip(&mut connected).await;
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m02_net02_two_loopback_egress_profiles_select_source_ip() {
    let resolver = Arc::new(ScriptedResolver::new(vec![]));
    let dialer = Arc::new(TcpDialer);
    let config = config(
        r#"
[[listeners]]
id = "lab-b"
bind = "127.0.0.2:3128"
transport = "http"

[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow-lab"
action = "allow"
listeners = ["lab", "lab-b"]

[[access.ip_rules]]
id = "allow-loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true

[[egress]]
id = "via-a"
mode = "bind_ip"
bind_ip = "127.0.0.1"

[[egress]]
id = "via-b"
mode = "bind_ip"
bind_ip = "127.0.0.2"

[routing]
default_egress = "via-a"

[[routing.rules]]
id = "route-a"
listeners = ["lab"]
egress_id = "via-a"

[[routing.rules]]
id = "route-b"
listeners = ["lab-b"]
egress_id = "via-b"
"#,
    );
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (address, mut peers, _server) = spawn_echo_with_peers().await;
        let (target, host) = http_target(address);

        let mut connected = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .expect("via-a");
        echo_roundtrip(&mut connected).await;
        drop(connected);
        assert_eq!(
            peers.recv().await.expect("peer"),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );

        let mut connected = service
            .open_outbound(&context("lab-b"), &Method::GET, &target, Some(&host))
            .await
            .expect("via-b");
        echo_roundtrip(&mut connected).await;
        drop(connected);
        assert_eq!(
            peers.recv().await.expect("peer"),
            IpAddr::from([127, 0, 0, 2])
        );
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m02_net02_routing_by_domain_and_port_selects_egress() {
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    )])]));
    let dialer = Arc::new(TcpDialer);
    let config = config(&format!(
        "{}{}",
        allow_loopback_access(),
        r#"
[[egress]]
id = "via-a"
mode = "bind_ip"
bind_ip = "127.0.0.1"

[[egress]]
id = "via-b"
mode = "bind_ip"
bind_ip = "127.0.0.2"

[routing]
default_egress = "via-a"

[[routing.rules]]
id = "domain-route"
host_exact = ["route.test"]
egress_id = "via-b"
"#
    ));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (address, mut peers, _server) = spawn_echo_with_peers().await;
        let (target, host) = domain_target("route.test", address.port());
        let mut connected = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .expect("domain route");
        echo_roundtrip(&mut connected).await;
        drop(connected);
        assert_eq!(
            peers.recv().await.expect("peer"),
            IpAddr::from([127, 0, 0, 2])
        );
        assert_eq!(resolver.calls(), 1);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn m02_net03_bind_failure_has_no_silent_fallback() {
    let resolver = Arc::new(ScriptedResolver::new(vec![]));
    let dialer = Arc::new(TcpDialer);
    let config = config(&format!(
        "{}{}",
        allow_loopback_access(),
        r#"
[[egress]]
id = "bad"
mode = "bind_ip"
bind_ip = "192.0.2.1"

[[egress]]
id = "system"
mode = "system"

[routing]
default_egress = "bad"
"#
    ));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (address, mut peers, _server) = spawn_echo_with_peers().await;
        let (target, host) = http_target(address);
        let error = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .err()
            .expect("bind failure");
        assert_eq!(error, OutboundError::BindFailed);
        assert!(peers.try_recv().is_err(), "fallback connected to origin");
    });
}

#[test]
fn m02_net03_incompatible_family_does_not_dial() {
    let resolver = Arc::new(ScriptedResolver::new(vec![]));
    let dialer = Arc::new(RecordingDialer::new(
        angara::transport::DialError::ConnectFailed,
    ));
    let config = config(&format!(
        "{}{}",
        allow_loopback_access(),
        r#"
[[egress]]
id = "via-v4"
mode = "bind_ip"
bind_ip = "127.0.0.1"

[routing]
default_egress = "via-v4"
"#
    ));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let target = "http://[::1]:9/".to_owned();
        let host = "[::1]:9".to_owned();
        let error = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .err()
            .expect("family mismatch");
        assert_eq!(error, OutboundError::NoCompatibleAddress);
        assert!(dialer.attempts().is_empty());
        assert_eq!(resolver.calls(), 0);
    });
}

#[test]
fn m02_net04_outbound_permit_is_held_until_connected_drop() {
    let resolver = Arc::new(ScriptedResolver::new(vec![]));
    let dialer = Arc::new(TcpDialer);
    let config = Config::parse(&format!(
        "{}{}{}",
        support::base_config().replace("max_connections = 256", "max_connections = 1"),
        allow_loopback_access(),
        system_egress()
    ))
    .expect("config");
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (address, _server) = spawn_echo().await;
        let (target, host) = http_target(address);
        let mut first = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .expect("first");
        echo_roundtrip(&mut first).await;

        assert_eq!(
            service
                .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
                .await
                .err(),
            Some(OutboundError::OutboundBusy)
        );
        drop(first);

        let mut third = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .expect("after drop");
        echo_roundtrip(&mut third).await;
    });
}

#[test]
fn m02_net04_connecting_budget_released_after_future_drop() {
    let resolver = Arc::new(ScriptedResolver::new(vec![
        Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
    ]));
    let dialer = Arc::new(GatedDialer::new());
    let started = dialer.started();
    let release = dialer.release();
    let config = config(&format!(
        "{}{}{}",
        allow_loopback_access(),
        system_egress(),
        "[transport]\nmax_connecting = 1\ntotal_timeout_ms = 2000\nconnect_timeout_ms = 2000\n"
    ));
    let runtime = runtime(&config);
    let service = Arc::new(OutboundService::with_components(
        Arc::new(config),
        resolver,
        dialer.clone(),
    ));

    runtime.block_on(async {
        let (target, host) = domain_target("example.test", 80);
        let first = tokio::spawn({
            let service = Arc::clone(&service);
            let context = context("lab");
            let target = target.clone();
            let host = host.clone();
            async move {
                service
                    .open_outbound(&context, &Method::GET, &target, Some(&host))
                    .await
            }
        });
        started.notified().await;
        assert_eq!(
            service
                .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
                .await
                .err(),
            Some(OutboundError::OutboundBusy)
        );
        first.abort();
        let _ = first.await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        release.notify_one();
        let result = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await;
        assert_eq!(result.err(), Some(OutboundError::ConnectFailed));
        assert_eq!(dialer.attempts(), 2);
    });
}

#[test]
fn m02_net04_total_timeout_has_priority_over_attempt_timeout() {
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
    ])]));
    let dialer = Arc::new(DelayedDialer::new());
    let config = config(&format!(
        "{}{}{}",
        allow_loopback_access(),
        system_egress(),
        "[transport]\ntotal_timeout_ms = 100\nconnect_timeout_ms = 100\nmax_connect_attempts = 2\n"
    ));
    let runtime = runtime(&config);
    let service = OutboundService::with_components(Arc::new(config), resolver, dialer.clone());

    runtime.block_on(async {
        let (target, host) = domain_target("example.test", 80);
        let error = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .err()
            .expect("timeout");
        assert_eq!(error, OutboundError::TotalTimeout);
        assert!(dialer.attempts() <= 2);
    });
}

#[test]
fn m02_net04_max_connect_attempts_is_enforced() {
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
    ])]));
    let dialer = Arc::new(RecordingDialer::new(
        angara::transport::DialError::ConnectFailed,
    ));
    let config = config(&format!(
        "{}{}{}",
        allow_loopback_access(),
        system_egress(),
        "[transport]\ntotal_timeout_ms = 1000\nconnect_timeout_ms = 100\nmax_connect_attempts = 2\n"
    ));
    let runtime = runtime(&config);
    let service = OutboundService::with_components(Arc::new(config), resolver, dialer.clone());

    runtime.block_on(async {
        let (target, host) = domain_target("example.test", 80);
        let error = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .err()
            .expect("connect failure");
        assert_eq!(error, OutboundError::ConnectFailed);
        assert_eq!(dialer.attempts().len(), 2);
    });
}

#[test]
fn m02_acl01_source_denied_prevents_dns_and_dial() {
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    )])]));
    let dialer = Arc::new(RecordingDialer::new(
        angara::transport::DialError::ConnectFailed,
    ));
    let config = config(&format!("{}{}", allow_loopback_access(), system_egress()));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (target, host) = domain_target("example.test", 80);
        let context = RequestContext::new(IpAddr::from([192, 0, 2, 1]), "lab");
        let error = service
            .open_outbound(&context, &Method::GET, &target, Some(&host))
            .await
            .err()
            .expect("source denied");
        assert_eq!(error, OutboundError::SourceDenied);
        assert_eq!(resolver.calls(), 0);
        assert!(dialer.attempts().is_empty());
    });
}

#[test]
fn m02_dns01_empty_and_oversized_resolver_answers_are_rejected() {
    let resolver = Arc::new(ScriptedResolver::new(vec![
        Ok(vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
        ]),
        Ok(vec![]),
    ]));
    let dialer = Arc::new(RecordingDialer::new(
        angara::transport::DialError::ConnectFailed,
    ));
    let config = config(&format!(
        "{}{}{}",
        allow_loopback_access(),
        system_egress(),
        "[dns]\nmax_answers = 2\n"
    ));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (target, host) = domain_target("example.test", 80);
        assert_eq!(
            service
                .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
                .await
                .err(),
            Some(OutboundError::DnsTooManyAddresses)
        );
        assert_eq!(
            service
                .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
                .await
                .err(),
            Some(OutboundError::DnsNoAddresses)
        );
        assert!(dialer.attempts().is_empty());
    });
}

#[test]
fn m02_acl04_deny_prevents_dns_and_dial() {
    let resolver = Arc::new(ScriptedResolver::new(vec![Ok(vec![IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    )])]));
    let dialer = Arc::new(RecordingDialer::new(
        angara::transport::DialError::ConnectFailed,
    ));
    let config = config(&format!(
        "{}{}",
        r#"
[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
id = "deny-all"
action = "deny"

[[access.ip_rules]]
id = "allow-loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#,
        system_egress()
    ));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (target, host) = domain_target("example.test", 80);
        let error = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .err()
            .expect("denied");
        assert_eq!(error, OutboundError::AccessDenied);
        assert_eq!(resolver.calls(), 0);
        assert!(dialer.attempts().is_empty());
    });
}

#[test]
fn m02_ip02_mixed_dns_filters_candidates_and_all_denied_skips_dial() {
    let resolver = Arc::new(ScriptedResolver::new(vec![
        Ok(vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ]),
        Ok(vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
        ]),
    ]));
    let dialer = Arc::new(RecordingDialer::new(
        angara::transport::DialError::ConnectFailed,
    ));
    let config = config(&format!(
        "{}{}",
        r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow-all"
action = "allow"

[[access.ip_rules]]
id = "allow-one"
action = "allow"
networks = ["127.0.0.1/32"]
allow_special = true
"#,
        system_egress()
    ));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (target, host) = domain_target("example.test", 80);
        let error = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .err()
            .expect("connect failure");
        assert_eq!(error, OutboundError::ConnectFailed);
        let attempts = dialer.attempts();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].0.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let error = service
            .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
            .await
            .err()
            .expect("all denied");
        assert_eq!(error, OutboundError::DestinationDenied);
        assert_eq!(dialer.attempts().len(), 1);
    });
}

#[test]
fn m02_dns03_each_request_resolves_once_and_gets_checked_ips() {
    let resolver = Arc::new(ScriptedResolver::new(vec![
        Ok(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
        Ok(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]),
    ]));
    let dialer = Arc::new(RecordingDialer::new(
        angara::transport::DialError::ConnectFailed,
    ));
    let config = config(&format!("{}{}", allow_loopback_access(), system_egress()));
    let runtime = runtime(&config);
    let service =
        OutboundService::with_components(Arc::new(config), resolver.clone(), dialer.clone());

    runtime.block_on(async {
        let (target, host) = domain_target("example.test", 80);
        for _ in 0..2 {
            let error = service
                .open_outbound(&context("lab"), &Method::GET, &target, Some(&host))
                .await
                .err()
                .expect("recorded failure");
            assert_eq!(error, OutboundError::ConnectFailed);
        }
        assert_eq!(resolver.calls(), 2);
        let attempts = dialer.attempts();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].0.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(attempts[1].0.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    });
}

#[test]
fn m02_err01_outbound_errors_do_not_echo_target_values() {
    let resolver = Arc::new(ScriptedResolver::new(vec![Err(ResolveError::Failed)]));
    let dialer = Arc::new(RecordingDialer::new(
        angara::transport::DialError::ConnectFailed,
    ));
    let config = config(&format!("{}{}", allow_loopback_access(), system_egress()));
    let runtime = runtime(&config);
    let service = OutboundService::with_components(Arc::new(config), resolver, dialer);

    runtime.block_on(async {
        const MARKER: &str = "MARKER-SECRET-OUTBOUND";
        let target = format!("http://{MARKER}.example/");
        let error = service
            .open_outbound(
                &context("lab"),
                &Method::GET,
                &target,
                Some(&format!("{MARKER}.example")),
            )
            .await
            .err()
            .expect("error");
        assert!(!error.to_string().contains(MARKER));
    });
}
