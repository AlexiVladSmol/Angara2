//! Outbound pipeline composition.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use http::Method;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{Config, EgressMode};
use crate::policy::{self, PolicyError, RequestMeta};
use crate::resolver::{ResolveError, Resolver, SystemResolver};
use crate::routing::{self, RoutingError};
use crate::target::{self, CanonicalTarget, Host};
use crate::transport::{DialError, Dialer, TcpDialer};

/// Trusted client context supplied by the accepting layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    source: IpAddr,
    listener_id: String,
}

impl RequestContext {
    /// Creates a trusted context from a real peer address and listener.
    pub fn new(source: IpAddr, listener_id: impl Into<String>) -> Self {
        Self {
            source,
            listener_id: listener_id.into(),
        }
    }

    /// Client source address.
    pub fn source(&self) -> IpAddr {
        self.source
    }

    /// Listener identifier.
    pub fn listener_id(&self) -> &str {
        &self.listener_id
    }
}

/// Metadata for one allowed and connected outbound endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedEndpoint {
    endpoint: SocketAddr,
    target: CanonicalTarget,
    egress_id: String,
    matched_rule_id: String,
    generation: u64,
}

impl AuthorizedEndpoint {
    /// Successful destination socket address.
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Original canonical target.
    pub fn target(&self) -> &CanonicalTarget {
        &self.target
    }

    /// Selected egress profile ID.
    pub fn egress_id(&self) -> &str {
        &self.egress_id
    }

    /// Matched pre-DNS rule ID.
    pub fn matched_rule_id(&self) -> &str {
        &self.matched_rule_id
    }

    /// Configuration generation used for the whole request.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// An open outbound connection that owns its outbound permit.
///
/// The raw socket is intentionally not exposed separately from the permit.
/// Callers use the `AsyncRead`/`AsyncWrite` implementations; dropping this
/// value closes the stream and returns the connection budget.
pub struct Connected {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    endpoint: AuthorizedEndpoint,
}

impl Connected {
    /// Metadata for the connected endpoint.
    pub fn endpoint(&self) -> &AuthorizedEndpoint {
        &self.endpoint
    }

    /// Local socket address selected by the egress profile.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// Remote socket address that was actually connected.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}

impl AsyncRead for Connected {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for Connected {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

/// Outbound failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundError {
    /// Request target or Host header is invalid.
    InvalidTarget,
    /// Source gate denied the client.
    SourceDenied,
    /// Pre-DNS request ACL denied the request.
    AccessDenied,
    /// Destination IP policy denied every candidate.
    DestinationDenied,
    /// Configured routing is inconsistent.
    RouteInvalid,
    /// DNS budget is exhausted.
    DnsBusy,
    /// DNS-specific timeout elapsed.
    DnsTimeout,
    /// System resolver failed or is shutting down.
    DnsFailed,
    /// DNS returned no addresses.
    DnsNoAddresses,
    /// DNS returned too many unique addresses.
    DnsTooManyAddresses,
    /// No address compatible with the selected egress family.
    NoCompatibleAddress,
    /// Outbound or connecting budget is exhausted.
    OutboundBusy,
    /// Per-attempt connect timeout elapsed.
    ConnectTimeout,
    /// Connect failed.
    ConnectFailed,
    /// Binding the selected source IP failed.
    BindFailed,
    /// Overall outbound deadline elapsed.
    TotalTimeout,
    /// Explicit cancellation.
    Cancelled,
}

impl fmt::Display for OutboundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTarget => "invalid request target",
            Self::SourceDenied => "client source is not allowed",
            Self::AccessDenied => "request is denied by access rules",
            Self::DestinationDenied => "destination address is denied",
            Self::RouteInvalid => "egress route is invalid",
            Self::DnsBusy => "DNS budget is exhausted",
            Self::DnsTimeout => "DNS lookup timed out",
            Self::DnsFailed => "system resolver failed",
            Self::DnsNoAddresses => "DNS lookup returned no addresses",
            Self::DnsTooManyAddresses => "DNS lookup returned too many addresses",
            Self::NoCompatibleAddress => "no compatible address family for egress",
            Self::OutboundBusy => "outbound connection budget is exhausted",
            Self::ConnectTimeout => "connect attempt timed out",
            Self::ConnectFailed => "connect failed",
            Self::BindFailed => "binding the outbound source address failed",
            Self::TotalTimeout => "total outbound deadline elapsed",
            Self::Cancelled => "outbound operation was cancelled",
        })
    }
}

impl std::error::Error for OutboundError {}

/// Composed target → source → ACL → routing → DNS → IP policy → dial pipeline.
///
/// Clones share the same resolver, dialer and resource budgets.
#[derive(Clone)]
pub struct OutboundService {
    config: Arc<Config>,
    resolver: Arc<dyn Resolver>,
    dialer: Arc<dyn Dialer>,
    outbound_permits: Arc<Semaphore>,
    connecting_permits: Arc<Semaphore>,
    generation: u64,
}

impl OutboundService {
    /// Builds the production service with `SystemResolver` and `TcpDialer`.
    pub fn new(config: Arc<Config>) -> Self {
        let resolver = Arc::new(SystemResolver::new(*config.dns()));
        let dialer = Arc::new(TcpDialer);
        Self::with_components(config, resolver, dialer)
    }

    /// Builds a service with injected resolver and dialer.
    pub fn with_components(
        config: Arc<Config>,
        resolver: Arc<dyn Resolver>,
        dialer: Arc<dyn Dialer>,
    ) -> Self {
        let outbound_permits = Arc::new(Semaphore::new(config.limits().max_connections() as usize));
        let connecting_permits = Arc::new(Semaphore::new(config.transport().max_connecting()));
        Self {
            config,
            resolver,
            dialer,
            outbound_permits,
            connecting_permits,
            generation: 1,
        }
    }

    /// Immutable configuration generation used by this service.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Runs the complete outbound policy and connection path.
    pub async fn open_outbound(
        &self,
        context: &RequestContext,
        method: &Method,
        request_target: &str,
        host_header: Option<&str>,
    ) -> Result<Connected, OutboundError> {
        let deadline = Instant::now() + self.config.transport().total_timeout();

        let target = CanonicalTarget::parse(method, request_target)
            .map_err(|_| OutboundError::InvalidTarget)?;
        target::check_host_header(&target, host_header)
            .map_err(|_| OutboundError::InvalidTarget)?;

        let meta = RequestMeta {
            listener_id: context.listener_id(),
            source: context.source(),
            method: target.method(),
            target: &target,
        };

        policy::check_source(self.config.access(), context.source()).map_err(map_policy)?;
        let matched_rule =
            policy::check_request(self.config.access(), &meta).map_err(map_policy)?;
        let matched_rule_id = matched_rule.id().to_owned();

        let egress = routing::select_egress(self.config.routing(), self.config.egress(), &meta)
            .map_err(map_routing)?;

        check_deadline(deadline)?;
        let outbound_permit = self
            .outbound_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| OutboundError::OutboundBusy)?;

        let addresses = match target.host() {
            Host::Ip(ip) => vec![*ip],
            Host::Domain(domain) => {
                let addresses = self
                    .resolver
                    .resolve(domain.as_str(), deadline)
                    .await
                    .map_err(map_resolve)?;
                check_deadline(deadline)?;
                prepare_addresses(addresses, self.config.dns().max_answers())?
            }
        };

        let mut allowed = Vec::with_capacity(addresses.len());
        for address in addresses {
            if let Ok(address) = policy::check_ip(self.config.access(), address) {
                allowed.push(address);
            }
        }
        check_deadline(deadline)?;
        if allowed.is_empty() {
            return Err(OutboundError::DestinationDenied);
        }

        let compatible = allowed
            .into_iter()
            .filter_map(|ip| {
                let compatible = match egress.mode() {
                    EgressMode::System => true,
                    EgressMode::BindIp(bind_ip) => bind_ip.is_ipv4() == ip.is_ipv4(),
                };
                compatible.then(|| SocketAddr::new(ip, target.port()))
            })
            .collect::<Vec<_>>();
        check_deadline(deadline)?;
        if compatible.is_empty() {
            return Err(OutboundError::NoCompatibleAddress);
        }

        let attempts = compatible
            .len()
            .min(self.config.transport().max_connect_attempts());
        let mut last_error = None;
        for endpoint in compatible.into_iter().take(attempts) {
            check_deadline(deadline)?;
            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                return Err(OutboundError::TotalTimeout);
            }
            let attempt_deadline = now + self.config.transport().connect_timeout().min(remaining);
            let connecting_permit = self
                .connecting_permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| OutboundError::OutboundBusy)?;

            match self
                .dialer
                .connect(endpoint, egress, attempt_deadline)
                .await
            {
                Ok(stream) => {
                    drop(connecting_permit);
                    if Instant::now() >= deadline {
                        return Err(OutboundError::TotalTimeout);
                    }
                    return Ok(Connected {
                        stream,
                        _permit: outbound_permit,
                        endpoint: AuthorizedEndpoint {
                            endpoint,
                            target,
                            egress_id: egress.id().to_owned(),
                            matched_rule_id,
                            generation: self.generation,
                        },
                    });
                }
                Err(DialError::BindFailed) => {
                    if Instant::now() >= deadline {
                        return Err(OutboundError::TotalTimeout);
                    }
                    return Err(OutboundError::BindFailed);
                }
                Err(DialError::ConnectTimeout) => {
                    last_error = Some(OutboundError::ConnectTimeout);
                    if Instant::now() >= deadline {
                        return Err(OutboundError::TotalTimeout);
                    }
                }
                Err(DialError::ConnectFailed) => {
                    if Instant::now() >= deadline {
                        return Err(OutboundError::TotalTimeout);
                    }
                    last_error = Some(OutboundError::ConnectFailed);
                }
                Err(DialError::NoCompatibleAddress) => {
                    last_error = Some(OutboundError::NoCompatibleAddress);
                }
                Err(DialError::Cancelled) => return Err(OutboundError::Cancelled),
            }
        }

        check_deadline(deadline)?;
        Err(last_error.unwrap_or(OutboundError::ConnectFailed))
    }
}

fn check_deadline(deadline: Instant) -> Result<(), OutboundError> {
    if Instant::now() >= deadline {
        Err(OutboundError::TotalTimeout)
    } else {
        Ok(())
    }
}

fn prepare_addresses(
    addresses: Vec<IpAddr>,
    max_answers: usize,
) -> Result<Vec<IpAddr>, OutboundError> {
    let mut unique = Vec::new();
    for address in addresses {
        let address = target::normalize_ip(address);
        if !unique.contains(&address) {
            unique.push(address);
            if unique.len() > max_answers {
                return Err(OutboundError::DnsTooManyAddresses);
            }
        }
    }
    if unique.is_empty() {
        Err(OutboundError::DnsNoAddresses)
    } else {
        Ok(unique)
    }
}

fn map_policy(error: PolicyError) -> OutboundError {
    match error {
        PolicyError::SourceDenied => OutboundError::SourceDenied,
        PolicyError::AccessDenied => OutboundError::AccessDenied,
        PolicyError::DestinationDenied => OutboundError::DestinationDenied,
    }
}

fn map_routing(_error: RoutingError) -> OutboundError {
    OutboundError::RouteInvalid
}

fn map_resolve(error: ResolveError) -> OutboundError {
    match error {
        ResolveError::Busy => OutboundError::DnsBusy,
        ResolveError::Timeout => OutboundError::DnsTimeout,
        ResolveError::TotalTimeout => OutboundError::TotalTimeout,
        ResolveError::Failed | ResolveError::Closed => OutboundError::DnsFailed,
        ResolveError::NoAddresses => OutboundError::DnsNoAddresses,
        ResolveError::TooMany => OutboundError::DnsTooManyAddresses,
    }
}
