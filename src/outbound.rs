//! Outbound pipeline composition.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Instant;

use http::Method;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::auth::{AuthMode, VerifiedIdentity};
use crate::config::{Config, EgressMode};
use crate::limits::{CapController, CapPermit};
use crate::parent::{PreparedParent, is_self_route_addr_runtime};
use crate::policy::{self, PolicyError, RequestMeta};
use crate::resolver::{ResolveError, Resolver, SystemResolver};
use crate::routing::{self, RoutingError};
use crate::target::{self, CanonicalTarget, Host};
use crate::telemetry::Telemetry;
use crate::transport::{DialError, Dialer, TcpDialer};

/// Trusted client context supplied by the accepting layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    source: IpAddr,
    listener_id: String,
    identity: Option<VerifiedIdentity>,
}

impl RequestContext {
    /// Creates an anonymous trusted context from a real peer address and
    /// listener.
    pub fn new(source: IpAddr, listener_id: impl Into<String>) -> Self {
        Self {
            source,
            listener_id: listener_id.into(),
            identity: None,
        }
    }

    /// Creates a context carrying one verified identity.
    ///
    /// The identity type has no public constructor; it can only come from a
    /// successful [`crate::auth::AuthService`] verification. The outbound
    /// pipeline rechecks that it belongs to the current configuration snapshot.
    #[doc(hidden)]
    pub fn with_identity(
        source: IpAddr,
        listener_id: impl Into<String>,
        identity: VerifiedIdentity,
    ) -> Self {
        Self {
            source,
            listener_id: listener_id.into(),
            identity: Some(identity),
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

    /// Verified identity, if the caller supplied one.
    pub fn identity(&self) -> Option<&VerifiedIdentity> {
        self.identity.as_ref()
    }
}

/// Metadata for one allowed and connected outbound endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedEndpoint {
    endpoint: SocketAddr,
    target_endpoint: SocketAddr,
    parent_id: Option<String>,
    target: CanonicalTarget,
    egress_id: String,
    matched_rule_id: String,
    generation: u64,
}

impl AuthorizedEndpoint {
    /// Actual parent or direct socket address that was dialed.
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Verified destination socket address selected for this request.
    pub fn target_endpoint(&self) -> SocketAddr {
        self.target_endpoint
    }

    /// Selected parent ID, or `None` for direct.
    pub fn parent_id(&self) -> Option<&str> {
        self.parent_id.as_deref()
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
    _permit: CapPermit,
    endpoint: AuthorizedEndpoint,
    telemetry: Arc<Telemetry>,
}

impl Drop for Connected {
    fn drop(&mut self) {
        self.telemetry
            .outbound_active
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
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
    /// The listener requires a verified identity that is missing or stale.
    AuthenticationRequired,
    /// Pre-DNS request ACL denied the request.
    AccessDenied,
    /// Destination IP policy denied every candidate.
    DestinationDenied,
    /// Configured routing is inconsistent.
    RouteInvalid,
    /// Configured parent reference is inconsistent.
    ParentInvalid,
    /// A parent endpoint resolves to an own listener.
    ParentLoop,
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
            Self::AuthenticationRequired => "proxy authentication is required",
            Self::AccessDenied => "request is denied by access rules",
            Self::DestinationDenied => "destination address is denied",
            Self::RouteInvalid => "egress route is invalid",
            Self::ParentInvalid => "parent route is invalid",
            Self::ParentLoop => "parent route points to an own listener",
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

/// A fully authorized outbound plan created by the policy path.
///
/// The plan may be handed to the pool only after fresh ACL/DNS/IP checks. It
/// contains no unchecked constructor for callers outside the crate path.
#[derive(Clone)]
pub struct OutboundPlan {
    target: CanonicalTarget,
    egress: crate::config::EgressProfile,
    parent: Option<Arc<PreparedParent>>,
    matched_rule_id: String,
    routing_rule_id: Option<String>,
    target_endpoints: Vec<SocketAddr>,
    endpoints: Vec<SocketAddr>,
    generation: u64,
    deadline: Instant,
    listener_id: String,
    identity: Option<String>,
    auth_snapshot_id: Option<u64>,
}

impl fmt::Debug for OutboundPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundPlan")
            .field("target", &self.target)
            .field("egress_id", &self.egress.id())
            .field("parent_id", &self.parent.as_ref().map(|parent| parent.id()))
            .field("matched_rule_id", &self.matched_rule_id)
            .field("routing_rule_id", &self.routing_rule_id)
            .field("target_endpoints", &self.target_endpoints)
            .field("endpoints", &self.endpoints)
            .field("generation", &self.generation)
            .field("listener_id", &self.listener_id)
            .finish_non_exhaustive()
    }
}

impl OutboundPlan {
    /// Canonical target for this request.
    pub fn target(&self) -> &CanonicalTarget {
        &self.target
    }

    /// Selected egress profile ID.
    pub fn egress_id(&self) -> &str {
        self.egress.id()
    }

    /// Selected parent, or `None` for direct.
    pub fn parent(&self) -> Option<&Arc<PreparedParent>> {
        self.parent.as_ref()
    }

    /// Selected parent ID, or `None` for direct.
    pub fn parent_id(&self) -> Option<&str> {
        self.parent.as_ref().map(|parent| parent.id())
    }

    /// Matched pre-DNS access rule ID.
    pub fn matched_rule_id(&self) -> &str {
        &self.matched_rule_id
    }

    /// Matched routing rule, when the defaults were not used.
    pub fn routing_rule_id(&self) -> Option<&str> {
        self.routing_rule_id.as_deref()
    }

    /// First verified destination endpoint selected for a parent request.
    pub fn target_endpoint(&self) -> Option<SocketAddr> {
        self.target_endpoints.first().copied()
    }

    /// All verified destination endpoints after IP and family checks.
    pub fn target_endpoints(&self) -> &[SocketAddr] {
        &self.target_endpoints
    }

    /// Dial endpoints: verified targets for direct, resolved parents for a
    /// parent route.
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }

    /// Configuration generation used for the whole request.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Absolute authorization/DNS/connect deadline.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Whether the authorization/DNS/connect deadline has elapsed.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Listener that accepted the request.
    pub fn listener_id(&self) -> &str {
        &self.listener_id
    }

    /// Verified username, or `None` for an anonymous context.
    pub fn identity(&self) -> Option<&str> {
        self.identity.as_deref()
    }

    /// Snapshot that produced the identity, if any.
    pub fn auth_snapshot_id(&self) -> Option<u64> {
        self.auth_snapshot_id
    }
}

/// Composed target → source → ACL → routing → DNS → IP policy → dial pipeline.
///
/// Clones share the same resolver, dialer and resource budgets.
struct ConnectingGauge(Arc<Telemetry>);

impl ConnectingGauge {
    fn new(telemetry: Arc<Telemetry>) -> Self {
        telemetry.outbound_connecting.fetch_add(1, Ordering::AcqRel);
        Self(telemetry)
    }
}

impl Drop for ConnectingGauge {
    fn drop(&mut self) {
        self.0.outbound_connecting.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone)]
pub struct OutboundService {
    config: Arc<Config>,
    resolver: Arc<dyn Resolver>,
    dialer: Arc<dyn Dialer>,
    outbound_permits: Arc<CapController>,
    connecting_permits: Arc<Semaphore>,
    generation: u64,
    telemetry: Arc<Telemetry>,
}

impl OutboundService {
    /// Builds the production service with `SystemResolver` and `TcpDialer`.
    pub fn new(config: Arc<Config>) -> Self {
        let telemetry = Telemetry::new();
        let resolver = Arc::new(SystemResolver::new_with_telemetry(
            *config.dns(),
            Arc::clone(&telemetry),
        ));
        let dialer = Arc::new(TcpDialer);
        Self::with_components_and_telemetry(config, resolver, dialer, telemetry)
    }

    /// Builds a production service sharing caller-owned telemetry.
    pub fn new_with_telemetry(config: Arc<Config>, telemetry: Arc<Telemetry>) -> Self {
        let resolver = Arc::new(SystemResolver::new_with_telemetry(
            *config.dns(),
            Arc::clone(&telemetry),
        ));
        let dialer = Arc::new(TcpDialer);
        Self::with_components_and_telemetry(config, resolver, dialer, telemetry)
    }

    /// Builds a service with injected resolver and dialer.
    pub fn with_components(
        config: Arc<Config>,
        resolver: Arc<dyn Resolver>,
        dialer: Arc<dyn Dialer>,
    ) -> Self {
        let telemetry = Telemetry::new();
        Self::with_components_and_telemetry(config, resolver, dialer, telemetry)
    }

    /// Builds a service with injected components and shared telemetry.
    pub fn with_components_and_telemetry(
        config: Arc<Config>,
        resolver: Arc<dyn Resolver>,
        dialer: Arc<dyn Dialer>,
        telemetry: Arc<Telemetry>,
    ) -> Self {
        let outbound_permits = CapController::new(config.limits().max_connections() as usize);
        let connecting_permits = Arc::new(Semaphore::new(config.transport().max_connecting()));
        Self {
            config,
            resolver,
            dialer,
            outbound_permits,
            connecting_permits,
            generation: 1,
            telemetry,
        }
    }

    /// Updates the shared global outbound cap after a successful reload.
    pub fn set_outbound_limit(&self, limit: usize) {
        self.outbound_permits.set_limit(limit);
    }

    /// Current outbound cap and holders for status/metrics.
    pub fn outbound_cap(&self) -> (usize, usize) {
        (
            self.outbound_permits.limit(),
            self.outbound_permits.active(),
        )
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
        let plan = self
            .prepare_outbound(context, method, request_target, host_header)
            .await?;
        self.open_plan(&plan).await
    }

    /// Performs target, source, request ACL, routing, DNS and IP policy checks.
    ///
    /// The returned plan contains only endpoints allowed for this request. It
    /// does not consume an outbound connection permit; a pool hit may reuse an
    /// existing permitted socket.
    pub async fn prepare_outbound(
        &self,
        context: &RequestContext,
        method: &Method,
        request_target: &str,
        host_header: Option<&str>,
    ) -> Result<OutboundPlan, OutboundError> {
        self.prepare_outbound_with(
            &self.config,
            self.generation,
            context,
            method,
            request_target,
            host_header,
        )
        .await
    }

    /// Snapshot-aware preparation used by the reloadable proxy path.
    pub async fn prepare_outbound_with(
        &self,
        config: &Config,
        generation: u64,
        context: &RequestContext,
        method: &Method,
        request_target: &str,
        host_header: Option<&str>,
    ) -> Result<OutboundPlan, OutboundError> {
        let deadline = Instant::now() + config.transport().total_timeout();

        let target = CanonicalTarget::parse(method, request_target)
            .map_err(|_| OutboundError::InvalidTarget)?;
        target::check_host_header(&target, host_header)
            .map_err(|_| OutboundError::InvalidTarget)?;

        let listener = config
            .listener(context.listener_id())
            .ok_or(OutboundError::AccessDenied)?;
        let identity = match listener.auth() {
            AuthMode::None => None,
            AuthMode::Basic => {
                let identity = context
                    .identity()
                    .ok_or(OutboundError::AuthenticationRequired)?;
                let auth = config.auth().ok_or(OutboundError::AuthenticationRequired)?;
                if !identity.belongs_to(auth.snapshot()) {
                    return Err(OutboundError::AuthenticationRequired);
                }
                Some(identity)
            }
        };

        let meta = RequestMeta {
            listener_id: context.listener_id(),
            source: context.source(),
            method: target.method(),
            target: &target,
            identity,
        };

        policy::check_source(config.access(), context.source()).map_err(map_policy)?;
        let matched_rule = policy::check_request(config.access(), &meta).map_err(map_policy)?;
        let matched_rule_id = matched_rule.id().to_owned();

        let route = routing::select_route(config, &meta).map_err(map_routing)?;
        let egress = route.egress().clone();
        let parent = route.parent().cloned();
        let routing_rule_id = route.routing_rule_id().map(str::to_owned);

        check_deadline(deadline)?;
        let addresses = self.resolve_host(target.host(), deadline, config).await?;

        let mut allowed = Vec::with_capacity(addresses.len());
        for address in addresses {
            if let Ok(address) = policy::check_ip(config.access(), address) {
                allowed.push(address);
            }
        }
        check_deadline(deadline)?;
        if allowed.is_empty() {
            return Err(OutboundError::DestinationDenied);
        }

        let target_port = target.port();
        let mut target_endpoints = allowed
            .into_iter()
            .map(|ip| SocketAddr::new(ip, target_port))
            .collect::<Vec<_>>();
        if parent.is_none() {
            target_endpoints.retain(|endpoint| egress_accepts(&egress, endpoint.ip()));
        }
        check_deadline(deadline)?;
        if target_endpoints.is_empty() {
            return Err(OutboundError::NoCompatibleAddress);
        }

        let endpoints = if let Some(parent) = parent.as_ref() {
            let parent_address = parent.endpoint();
            let addresses = self
                .resolve_host(parent_address.host(), deadline, config)
                .await?;
            let parent_port = parent_address.port();
            let endpoints = addresses
                .into_iter()
                .filter(|ip| egress_accepts(&egress, *ip))
                .map(|ip| SocketAddr::new(ip, parent_port))
                .collect::<Vec<_>>();
            check_deadline(deadline)?;
            if endpoints.is_empty() {
                return Err(OutboundError::NoCompatibleAddress);
            }
            if endpoints
                .iter()
                .any(|endpoint| is_self_route_addr_runtime(*endpoint, config.listeners()))
            {
                return Err(OutboundError::ParentLoop);
            }
            endpoints
        } else {
            target_endpoints.clone()
        };

        Ok(OutboundPlan {
            target,
            egress,
            parent,
            matched_rule_id,
            routing_rule_id,
            target_endpoints,
            endpoints,
            generation,
            deadline,
            listener_id: context.listener_id().to_owned(),
            identity: identity.map(|identity| identity.username().to_owned()),
            auth_snapshot_id: identity.map(VerifiedIdentity::snapshot_id),
        })
    }

    async fn resolve_host(
        &self,
        host: &Host,
        deadline: Instant,
        config: &Config,
    ) -> Result<Vec<IpAddr>, OutboundError> {
        match host {
            Host::Ip(ip) => Ok(vec![*ip]),
            Host::Domain(domain) => {
                let result = self.resolver.resolve(domain.as_str(), deadline).await;
                let addresses = match result {
                    Ok(addresses) => addresses,
                    Err(error) => {
                        if matches!(error, ResolveError::Timeout | ResolveError::TotalTimeout) {
                            self.telemetry.dns_timeout.fetch_add(1, Ordering::Relaxed);
                        } else if !matches!(error, ResolveError::Busy) {
                            self.telemetry.dns_error.fetch_add(1, Ordering::Relaxed);
                        }
                        return Err(map_resolve(error));
                    }
                };
                check_deadline(deadline)?;
                prepare_addresses(addresses, config.dns().max_answers())
            }
        }
    }

    /// Opens a new checked connection for an authorized plan.
    pub async fn open_plan(&self, plan: &OutboundPlan) -> Result<Connected, OutboundError> {
        self.open_plan_with(&self.config, plan).await
    }

    /// Snapshot-aware dial used by the reloadable proxy path.
    pub async fn open_plan_with(
        &self,
        config: &Config,
        plan: &OutboundPlan,
    ) -> Result<Connected, OutboundError> {
        check_deadline(plan.deadline)?;
        let outbound_permit = self
            .outbound_permits
            .try_acquire()
            .ok_or(OutboundError::OutboundBusy)?;

        let attempts = plan
            .endpoints
            .len()
            .min(config.transport().max_connect_attempts());
        let mut last_error = None;
        for endpoint in plan.endpoints.iter().copied().take(attempts) {
            check_deadline(plan.deadline)?;
            let now = Instant::now();
            let remaining = plan.deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                return Err(OutboundError::TotalTimeout);
            }
            let attempt_deadline = now + config.transport().connect_timeout().min(remaining);
            let connecting_permit = self
                .connecting_permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| OutboundError::OutboundBusy)?;
            let connecting_gauge = ConnectingGauge::new(Arc::clone(&self.telemetry));

            match self
                .dialer
                .connect(endpoint, &plan.egress, attempt_deadline)
                .await
            {
                Ok(stream) => {
                    drop(connecting_gauge);
                    drop(connecting_permit);
                    if Instant::now() >= plan.deadline {
                        return Err(OutboundError::TotalTimeout);
                    }
                    self.telemetry
                        .outbound_active
                        .fetch_add(1, Ordering::AcqRel);
                    let target_endpoint = if plan.parent.is_some() {
                        plan.target_endpoint().unwrap_or(endpoint)
                    } else {
                        endpoint
                    };
                    return Ok(Connected {
                        stream,
                        _permit: outbound_permit,
                        endpoint: AuthorizedEndpoint {
                            endpoint,
                            target_endpoint,
                            parent_id: plan.parent_id().map(str::to_owned),
                            target: plan.target.clone(),
                            egress_id: plan.egress_id().to_owned(),
                            matched_rule_id: plan.matched_rule_id.clone(),
                            generation: plan.generation,
                        },
                        telemetry: Arc::clone(&self.telemetry),
                    });
                }
                Err(DialError::BindFailed) => {
                    if Instant::now() >= plan.deadline {
                        return Err(OutboundError::TotalTimeout);
                    }
                    return Err(OutboundError::BindFailed);
                }
                Err(DialError::ConnectTimeout) => {
                    last_error = Some(OutboundError::ConnectTimeout);
                    if Instant::now() >= plan.deadline {
                        return Err(OutboundError::TotalTimeout);
                    }
                }
                Err(DialError::ConnectFailed) => {
                    if Instant::now() >= plan.deadline {
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

        check_deadline(plan.deadline)?;
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

fn egress_accepts(egress: &crate::config::EgressProfile, ip: IpAddr) -> bool {
    match egress.mode() {
        EgressMode::System => true,
        EgressMode::BindIp(bind_ip) => bind_ip.is_ipv4() == ip.is_ipv4(),
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

fn map_routing(error: RoutingError) -> OutboundError {
    match error {
        RoutingError::RouteInvalid => OutboundError::RouteInvalid,
        RoutingError::ParentInvalid => OutboundError::ParentInvalid,
    }
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
