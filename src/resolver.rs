//! Bounded system DNS resolution.
//!
//! The blocking system lookup runs in Tokio's blocking pool. Its permit is
//! moved into the blocking closure, so dropping the waiting future does not
//! release the budget until the real lookup finishes.

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::config::DnsConfig;
use crate::target::normalize_ip;

/// Future returned by [`Resolver::resolve`].
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send + 'a>>;

/// Resolver failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// In-flight budget is exhausted; no queue is created.
    Busy,
    /// DNS-specific timeout elapsed.
    Timeout,
    /// Overall `open_outbound` deadline elapsed.
    TotalTimeout,
    /// System resolver failed.
    Failed,
    /// Lookup returned no addresses.
    NoAddresses,
    /// Lookup returned more unique addresses than `max_answers`.
    TooMany,
    /// Resolver is shutting down.
    Closed,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "DNS budget is exhausted",
            Self::Timeout => "DNS lookup timed out",
            Self::TotalTimeout => "total outbound deadline elapsed",
            Self::Failed => "system resolver failed",
            Self::NoAddresses => "DNS lookup returned no addresses",
            Self::TooMany => "DNS lookup returned too many addresses",
            Self::Closed => "resolver is shutting down",
        })
    }
}

impl std::error::Error for ResolveError {}

/// Resolver abstraction used by the outbound pipeline.
pub trait Resolver: Send + Sync {
    /// Resolves a normalized host before the overall deadline.
    fn resolve<'a>(&'a self, host: &'a str, deadline: Instant) -> ResolveFuture<'a>;
}

/// Testable system lookup function.
pub type BlockingLookup = Arc<dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync>;

/// Resolver backed by the operating system's name service.
pub struct SystemResolver {
    dns: DnsConfig,
    lookup: BlockingLookup,
    permits: Arc<Semaphore>,
    closed: Arc<AtomicBool>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl SystemResolver {
    /// Creates a resolver using the operating system's `getaddrinfo` policy.
    pub fn new(dns: DnsConfig) -> Self {
        Self::with_lookup(dns, Arc::new(system_lookup))
    }

    /// Creates a resolver with an injected blocking lookup for tests.
    pub fn with_lookup(dns: DnsConfig, lookup: BlockingLookup) -> Self {
        Self {
            dns,
            lookup,
            permits: Arc::new(Semaphore::new(dns.max_in_flight())),
            closed: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
        }
    }

    /// Stops new work, aborts lookups that have not started, and waits for
    /// actual blocking lookups up to `timeout`.
    ///
    /// A lookup already inside `getaddrinfo` cannot be forcibly interrupted;
    /// the boolean reports whether all permits returned in time.
    pub async fn shutdown(&self, timeout: Duration) -> bool {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut handles) = self.handles.lock() {
            for handle in handles.drain(..) {
                handle.abort();
            }
        }
        let all = self.dns.max_in_flight() as u32;
        match tokio::time::timeout(timeout, self.permits.clone().acquire_many_owned(all)).await {
            Ok(Ok(permits)) => {
                drop(permits);
                true
            }
            Ok(Err(_)) | Err(_) => false,
        }
    }
}

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, deadline: Instant) -> ResolveFuture<'a> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(ResolveError::Closed);
            }
            if Instant::now() >= deadline {
                return Err(ResolveError::TotalTimeout);
            }

            let permit = self
                .permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| ResolveError::Busy)?;
            if self.closed.load(Ordering::Acquire) {
                return Err(ResolveError::Closed);
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ResolveError::TotalTimeout);
            }
            let lookup_timeout = self.dns.timeout().min(remaining);

            let (sender, receiver) = tokio::sync::oneshot::channel();
            let lookup = Arc::clone(&self.lookup);
            let closed = Arc::clone(&self.closed);
            let host = host.to_owned();
            // The permit lives inside the blocking closure. Dropping this
            // future only drops the receiver; the lookup and its permit stay
            // accounted for until the blocking call actually returns.
            let handle = tokio::task::spawn_blocking(move || {
                if closed.load(Ordering::Acquire) {
                    let _ = sender.send(Err(ResolveError::Closed));
                    return;
                }
                let _permit = permit;
                let result = lookup(&host).map_err(|_| ResolveError::Failed);
                // The real lookup is complete; return the budget before
                // publishing the result so a waiting caller observes the
                // permit as available once it sees the value.
                drop(_permit);
                let _ = sender.send(result);
            });
            if let Ok(mut handles) = self.handles.lock() {
                handles.retain(|handle| !handle.is_finished());
                handles.push(handle);
            }

            match tokio::time::timeout(lookup_timeout, receiver).await {
                Ok(Ok(Ok(addresses))) => normalize_addresses(addresses, self.dns.max_answers()),
                Ok(Ok(Err(error))) => Err(error),
                Ok(Err(_)) => Err(ResolveError::Failed),
                Err(_) if Instant::now() >= deadline => Err(ResolveError::TotalTimeout),
                Err(_) => Err(ResolveError::Timeout),
            }
        })
    }
}

impl Drop for SystemResolver {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut handles) = self.handles.lock() {
            for handle in handles.drain(..) {
                handle.abort();
            }
        }
    }
}

fn normalize_addresses(
    addresses: Vec<IpAddr>,
    max_answers: usize,
) -> Result<Vec<IpAddr>, ResolveError> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for address in addresses {
        let address = normalize_ip(address);
        if seen.insert(address) {
            unique.push(address);
        }
    }

    if unique.is_empty() {
        Err(ResolveError::NoAddresses)
    } else if unique.len() > max_answers {
        Err(ResolveError::TooMany)
    } else {
        Ok(unique)
    }
}

fn system_lookup(host: &str) -> io::Result<Vec<IpAddr>> {
    (host, 0)
        .to_socket_addrs()
        .map(|addresses| addresses.map(|address| address.ip()).collect())
}
