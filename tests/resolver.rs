//! M02 DNS resolver tests (M02-DNS-01/02/03).

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use angara::config::Config;
use angara::resolver::{ResolveError, Resolver, SystemResolver};
use angara::runtime::AngaraRuntime;
use tokio::sync::Notify;

fn config(dns: &str) -> Config {
    Config::parse(&format!("{}{dns}", common::config("\"auto\""))).expect("valid config")
}

fn runtime(config: &Config) -> AngaraRuntime {
    AngaraRuntime::build(config).expect("runtime")
}

fn deadline(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds)
}

#[test]
fn m02_dns01_deduplicates_preserves_order_and_limits_answers() {
    let config = config("[dns]\ntimeout_ms = 1000\nmax_in_flight = 2\nmax_answers = 3\n");
    let dns = *config.dns();

    let duplicate = SystemResolver::with_lookup(
        dns,
        Arc::new(|_host| {
            Ok(vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            ])
        }),
    );
    let runtime = runtime(&config);
    let addresses = runtime
        .block_on(duplicate.resolve("duplicate.test", deadline(2)))
        .expect("lookup");
    assert_eq!(
        addresses,
        vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        ]
    );

    let empty = SystemResolver::with_lookup(dns, Arc::new(|_host| Ok(vec![])));
    assert_eq!(
        runtime.block_on(empty.resolve("empty.test", deadline(2))),
        Err(ResolveError::NoAddresses)
    );

    let too_many = SystemResolver::with_lookup(
        dns,
        Arc::new(|_host| {
            Ok(vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
            ])
        }),
    );
    assert_eq!(
        runtime.block_on(too_many.resolve("many.test", deadline(2))),
        Err(ResolveError::TooMany)
    );

    let failed = SystemResolver::with_lookup(
        dns,
        Arc::new(|_host| Err(std::io::Error::other("synthetic failure"))),
    );
    assert_eq!(
        runtime.block_on(failed.resolve("failed.test", deadline(2))),
        Err(ResolveError::Failed)
    );

    let mapped = SystemResolver::with_lookup(
        dns,
        Arc::new(|_host| {
            Ok(vec![
                IpAddr::V6("::ffff:127.0.0.1".parse().expect("mapped")),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ])
        }),
    );
    assert_eq!(
        runtime
            .block_on(mapped.resolve("mapped.test", deadline(2)))
            .expect("lookup"),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
    );
}

#[test]
fn m02_dns02_timeout_keeps_blocking_permit_until_real_completion() {
    let config = config("[dns]\ntimeout_ms = 100\nmax_in_flight = 1\nmax_answers = 4\n");
    let dns = *config.dns();

    let started = Arc::new(Notify::new());
    let done = Arc::new(Notify::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (release_sender, release_receiver) = mpsc::channel::<()>();
    let release_receiver = Arc::new(Mutex::new(release_receiver));
    let lookup = {
        let started = Arc::clone(&started);
        let done = Arc::clone(&done);
        let calls = Arc::clone(&calls);
        Arc::new(move |_host: &str| {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                started.notify_one();
                let _ = release_receiver.lock().expect("release mutex").recv();
                done.notify_one();
            }
            Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
        })
    };
    let resolver = SystemResolver::with_lookup(dns, lookup);
    let runtime = runtime(&config);

    runtime.block_on(async {
        let first = resolver
            .resolve("blocked.test", Instant::now() + Duration::from_millis(100))
            .await;
        assert!(
            matches!(
                first,
                Err(ResolveError::Timeout | ResolveError::TotalTimeout)
            ),
            "{first:?}"
        );
        started.notified().await;

        assert_eq!(
            resolver
                .resolve("second.test", Instant::now() + Duration::from_millis(100),)
                .await,
            Err(ResolveError::Busy)
        );

        release_sender.send(()).expect("release lookup");
        done.notified().await;
        let retry_deadline = Instant::now() + Duration::from_secs(1);
        let third = loop {
            match resolver
                .resolve("third.test", Instant::now() + Duration::from_secs(1))
                .await
            {
                Ok(addresses) => break addresses,
                Err(ResolveError::Busy) if Instant::now() < retry_deadline => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => panic!("permit did not return: {error:?}"),
            }
        };
        assert_eq!(third, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    });
}

#[test]
fn m02_dns02_total_deadline_has_priority() {
    let config = config("[dns]\ntimeout_ms = 1000\nmax_in_flight = 1\nmax_answers = 4\n");
    let dns = *config.dns();
    let resolver = SystemResolver::with_lookup(
        dns,
        Arc::new(|_host| {
            std::thread::sleep(Duration::from_millis(100));
            Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
        }),
    );
    let runtime = runtime(&config);

    let error = runtime
        .block_on(resolver.resolve("deadline.test", Instant::now() + Duration::from_millis(40)))
        .expect_err("total deadline");
    assert_eq!(error, ResolveError::TotalTimeout);

    assert_eq!(
        runtime.block_on(resolver.resolve("expired.test", Instant::now())),
        Err(ResolveError::TotalTimeout)
    );
}

#[test]
fn m02_dns02_shutdown_is_bounded_and_closes_new_work() {
    let config = config("[dns]\ntimeout_ms = 1000\nmax_in_flight = 1\nmax_answers = 4\n");
    let dns = *config.dns();
    let started = Arc::new(Notify::new());
    let (release_sender, release_receiver) = mpsc::channel::<()>();
    let release_receiver = Arc::new(Mutex::new(release_receiver));
    let lookup = {
        let started = Arc::clone(&started);
        Arc::new(move |_host: &str| {
            started.notify_one();
            let _ = release_receiver.lock().expect("release mutex").recv();
            Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
        })
    };
    let resolver = Arc::new(SystemResolver::with_lookup(dns, lookup));
    let runtime = runtime(&config);

    runtime.block_on(async {
        let first = tokio::spawn({
            let resolver = Arc::clone(&resolver);
            async move {
                resolver
                    .resolve("blocked.test", Instant::now() + Duration::from_secs(2))
                    .await
            }
        });
        started.notified().await;

        assert!(!resolver.shutdown(Duration::from_millis(50)).await);
        assert_eq!(
            resolver
                .resolve("closed.test", Instant::now() + Duration::from_secs(1),)
                .await,
            Err(ResolveError::Closed)
        );

        release_sender.send(()).expect("release lookup");
        assert!(resolver.shutdown(Duration::from_secs(2)).await);
        let _ = first.await.expect("lookup task");
    });
}

#[test]
fn m02_dns03_real_system_resolver_smoke() {
    let config = config("[dns]\ntimeout_ms = 3000\nmax_in_flight = 1\nmax_answers = 16\n");
    let resolver = SystemResolver::new(*config.dns());
    let runtime = runtime(&config);

    let addresses = runtime
        .block_on(resolver.resolve("localhost", deadline(5)))
        .expect("system localhost lookup");
    assert!(!addresses.is_empty());
}
