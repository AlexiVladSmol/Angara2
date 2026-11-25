//! One HTTP/1.1 forwarding transaction.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, EXPECT, HOST, TRAILER, TRANSFER_ENCODING};
use http::{Method, Request, Response, StatusCode, Version};
use http_body::Body as _;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::ext::OriginalRequestTarget;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;

use crate::auth::{AuthError, AuthMode, AuthService, PasswordVerifier, VerifiedIdentity};
use crate::cache::{self, CacheEntry, CacheFillBody, CacheKey, CacheStore, CacheVariant, Lookup};
use crate::config::Config;
use crate::http::ResponseBody;
use crate::http::connect::TunnelSetup;
use crate::http::headers;
use crate::http::interim::InterimSender;
use crate::http::parent_client::{self, BoxedIo, ParentError};
use crate::http::pool::{
    Lease, LeaseRequestBody, LeaseResponseBody, OriginPool, PoolBody, PooledSender,
};
use crate::limits::CapController;
use crate::logging::{Event, LogRecord, Logger, Outcome, Reason, RouteKind};
use crate::outbound::{OutboundError, OutboundPlan, OutboundService, RequestContext};
use crate::policy::{self, RequestMeta};
use crate::snapshot::SnapshotStore;
use crate::target::{self, CanonicalTarget, Host, TargetError};
use crate::telemetry::Telemetry;

const MIN_CONNECTION_BUFFER: usize = 64 * 1024;
const HEADER_BUFFER_MARGIN: usize = 16 * 1024;

pub(crate) fn connection_buffer_size(config: &Config) -> usize {
    (config.limits().max_header_bytes() as usize)
        .saturating_add(HEADER_BUFFER_MARGIN)
        .max(MIN_CONNECTION_BUFFER)
}

/// Trusted acceptance information for one client connection.
#[derive(Clone, Debug)]
pub struct ClientInfo {
    /// Real peer IP from the accepted TCP socket.
    pub peer: IpAddr,
    /// Stable configured listener ID.
    pub listener_id: String,
    /// Server-created connection ID.
    pub connection_id: u64,
    /// Server-created request ID for this exchange.
    pub request_id: u64,
}

/// Route metadata filled after the outbound plan is selected.
#[derive(Clone, Debug, Default)]
struct RouteInfo {
    parent_id: Option<String>,
    kind: Option<RouteKind>,
}

struct ForwardParts {
    method: Method,
    target: CanonicalTarget,
    target_text: String,
    body: Incoming,
    headers: http::HeaderMap,
    via: Vec<http::HeaderValue>,
    nominations: Vec<http::header::HeaderName>,
    request_chunked: bool,
    request_had_content_length: bool,
    interim: InterimSender,
    request_body_bytes: Arc<AtomicU64>,
}

enum ParentOpenError {
    Outbound(OutboundError),
    Parent(ParentError),
    MissingParent,
}

impl ParentOpenError {
    fn response(self) -> Response<ResponseBody> {
        match self {
            Self::Outbound(error) => {
                let (status, close) = outbound_status(error);
                headers::error_response(status, close)
            }
            Self::Parent(error) => headers::error_response(error.status(), true),
            Self::MissingParent => headers::error_response(StatusCode::INTERNAL_SERVER_ERROR, true),
        }
    }
}

fn finalize_upstream_response(
    response: Response<Incoming>,
    lease: Lease,
    method: &Method,
    request_chunked: bool,
    instance_id: &str,
) -> Result<Response<ResponseBody>, ()> {
    if response.status() == StatusCode::SWITCHING_PROTOCOLS || response.status().is_informational()
    {
        lease.abort();
        return Err(());
    }
    if headers::validate_framing(response.headers()).is_err() {
        lease.abort();
        return Err(());
    }
    let original_headers = response.headers().clone();
    let mut response_headers = original_headers.clone();
    let response_nominations = match headers::filter_hop_by_hop(&mut response_headers, false) {
        Ok(names) => names,
        Err(()) => {
            lease.abort();
            return Err(());
        }
    };
    let response_trailer_names =
        match headers::trailer_names(&original_headers, &response_nominations) {
            Ok(names) => names,
            Err(()) => {
                lease.abort();
                return Err(());
            }
        };
    let response_trailer_nominated = response_nominations.contains(&http::header::TRAILER);
    headers::append_via(&mut response_headers, instance_id);
    if request_chunked {
        // Hyper normalizes CL+TE to TE before the service runs. M03 keeps the
        // conservative safe outcome: a chunked request closes the client
        // connection after the response.
        response_headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
    }
    let status = response.status();
    let response_body = response.into_body();
    let body_length = response_body.size_hint().exact();
    if headers::response_has_body(method, status) {
        if let Some(length) = body_length {
            headers::set_content_length(&mut response_headers, length);
        } else if !response_trailer_nominated {
            headers::set_trailer_names(&mut response_headers, &response_trailer_names);
        }
    } else if status != StatusCode::NO_CONTENT {
        headers::keep_representation_length(&mut response_headers, &original_headers);
    }
    let body = LeaseResponseBody::new(response_body, lease, response_nominations).boxed();
    let mut local = Response::new(body);
    *local.status_mut() = status;
    *local.version_mut() = Version::HTTP_11;
    *local.headers_mut() = response_headers;
    Ok(local)
}

/// Immutable terminal metadata for one HTTP exchange.
#[derive(Clone, Debug)]
pub struct ExchangeMeta {
    generation: u64,
    started: tokio::time::Instant,
    connection_id: u64,
    request_id: u64,
    listener_id: String,
    status: Option<StatusCode>,
    request_body_bytes: Arc<AtomicU64>,
    route: Arc<Mutex<RouteInfo>>,
}

impl ExchangeMeta {
    /// Generation captured before source/auth/policy checks.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Terminal HTTP status when a response was produced.
    pub fn status(&self) -> Option<StatusCode> {
        self.status
    }

    /// Observed request DATA bytes at terminal time.
    pub fn request_body_bytes(&self) -> u64 {
        self.request_body_bytes.load(Ordering::Relaxed)
    }
}

fn set_route(route: &Arc<Mutex<RouteInfo>>, plan: &OutboundPlan) {
    if let Ok(mut route) = route.lock() {
        route.parent_id = plan.parent_id().map(str::to_owned);
        route.kind = Some(if plan.parent().is_some() {
            RouteKind::Parent
        } else {
            RouteKind::Direct
        });
    }
}

/// Exactly-once terminal guard for an admitted exchange. Until the response
/// body is armed, dropping the future records a cancellation instead of
/// leaving `http_started` without an outcome.
struct ExchangeTerminal {
    telemetry: Arc<Telemetry>,
    logger: Logger,
    meta: ExchangeMeta,
    disarmed: bool,
}

impl ExchangeTerminal {
    fn new(telemetry: Arc<Telemetry>, logger: Logger, meta: ExchangeMeta) -> Self {
        Self {
            telemetry,
            logger,
            meta,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for ExchangeTerminal {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        log_terminal(
            &self.telemetry,
            &self.logger,
            &self.meta,
            crate::http::BodyOutcome::Cancelled,
            0,
        );
    }
}

/// Terminal ownership for a CONNECT request before a tunnel exists. It is
/// created immediately after the exchange gate and disarmed only on successful
/// 200 handoff; rejection/cancellation becomes one request terminal.
pub(crate) struct ConnectTerminal {
    telemetry: Arc<Telemetry>,
    logger: Logger,
    meta: ExchangeMeta,
    parent_failure: bool,
    disarmed: bool,
}

impl ConnectTerminal {
    pub(crate) fn disarm(&mut self) {
        self.disarmed = true;
    }

    /// Records the selected parent route before a parent dial/handshake.
    pub(crate) fn set_parent_route(&mut self, plan: &OutboundPlan) {
        if plan.parent().is_none() {
            return;
        }
        set_route(&self.meta.route, plan);
    }

    /// Parent failures use the same terminal reason as HTTP-to-name exchanges.
    pub(crate) fn mark_parent_failure(&mut self) {
        self.parent_failure = true;
    }

    pub(crate) fn reject(&mut self, status: StatusCode) {
        if self.disarmed {
            return;
        }
        self.disarmed = true;
        self.meta.status = Some(status);
        self.telemetry.http_started.fetch_add(1, Ordering::Relaxed);
        self.telemetry
            .connect_rejected
            .fetch_add(1, Ordering::Relaxed);
        let reason = if self.parent_failure {
            Reason::Error
        } else {
            Reason::Rejected
        };
        log_terminal_with_reason(
            &self.telemetry,
            &self.logger,
            &self.meta,
            crate::http::BodyOutcome::Failed,
            0,
            Some(reason),
        );
    }
}

impl Drop for ConnectTerminal {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        self.telemetry.http_started.fetch_add(1, Ordering::Relaxed);
        log_terminal_with_reason(
            &self.telemetry,
            &self.logger,
            &self.meta,
            crate::http::BodyOutcome::Cancelled,
            0,
            Some(Reason::ClientClosed),
        );
    }
}

/// HTTP proxy state shared by all listeners.
pub struct Proxy {
    snapshots: Arc<SnapshotStore>,
    outbound: OutboundService,
    pool: Arc<OriginPool>,
    origin_tasks: Arc<crate::http::OriginTasks>,
    cache: Option<Arc<CacheStore>>,
    draining: Arc<AtomicBool>,
    auth: Option<AuthService>,
    telemetry: Arc<Telemetry>,
    client_caps: Arc<CapController>,
    logger: Mutex<Logger>,
    next_id: AtomicU64,
}

impl Proxy {
    /// Builds proxy state.
    pub fn new(config: Arc<Config>) -> Arc<Self> {
        let telemetry = Telemetry::with_detailed(config.observability().metrics_enabled());
        let outbound =
            OutboundService::new_with_telemetry(Arc::clone(&config), Arc::clone(&telemetry));
        Self::assemble_with_verifier(config, outbound, telemetry, None)
    }

    /// Builds proxy state with injected resolver and dialer for library tests.
    #[doc(hidden)]
    pub fn with_components(
        config: Arc<Config>,
        resolver: Arc<dyn crate::resolver::Resolver>,
        dialer: Arc<dyn crate::transport::Dialer>,
    ) -> Arc<Self> {
        let telemetry = Telemetry::with_detailed(config.observability().metrics_enabled());
        let outbound = OutboundService::with_components_and_telemetry(
            Arc::clone(&config),
            resolver,
            dialer,
            Arc::clone(&telemetry),
        );
        Self::assemble_with_verifier(config, outbound, telemetry, None)
    }

    fn assemble_with_verifier(
        config: Arc<Config>,
        outbound: OutboundService,
        telemetry: Arc<Telemetry>,
        verifier: Option<Arc<dyn PasswordVerifier>>,
    ) -> Arc<Self> {
        let pool = OriginPool::with_telemetry(&config, Arc::clone(&telemetry));
        let auth = match verifier {
            Some(verifier) => AuthService::from_config_with_verifier_and_telemetry(
                &config,
                verifier,
                Some(Arc::clone(&telemetry)),
            ),
            None => AuthService::from_config_with_telemetry(&config, Arc::clone(&telemetry)),
        };
        let snapshots = SnapshotStore::new(Arc::clone(&config));
        let client_caps = CapController::new(config.limits().max_client_connections() as usize);
        let logger = Mutex::new(Logger::disabled(Arc::clone(&telemetry)));
        let cache = config
            .cache()
            .enabled()
            .then(|| CacheStore::new(config.cache(), Arc::clone(&telemetry)));
        Arc::new(Self {
            snapshots,
            outbound,
            pool,
            origin_tasks: crate::http::OriginTasks::new(),
            cache,
            draining: Arc::new(AtomicBool::new(false)),
            auth,
            telemetry,
            client_caps,
            logger,
            next_id: AtomicU64::new(1),
        })
    }

    /// Replaces the library/no-op logger with a caller-owned sink.
    pub fn set_logger(&self, logger: Logger) {
        if let Ok(mut current) = self.logger.lock() {
            *current = logger;
        }
    }

    /// Clone of the current logger handle.
    pub fn logger(&self) -> Logger {
        self.logger
            .lock()
            .map(|logger| logger.clone())
            .unwrap_or_else(|_| Logger::disabled(Arc::clone(&self.telemetry)))
    }

    /// Server-created connection ID.
    pub fn next_connection_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Server-created request ID.
    pub fn next_request_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Shared global client admission cap.
    pub fn client_caps(&self) -> Arc<CapController> {
        Arc::clone(&self.client_caps)
    }

    /// Publishes the candidate global caps before the root becomes visible.
    /// This prevents a post-publish admission under a stale higher cap.
    pub fn set_published_caps(&self, config: &Config) {
        self.client_caps
            .set_limit(config.limits().max_client_connections() as usize);
        self.outbound
            .set_outbound_limit(config.limits().max_connections() as usize);
    }

    /// Retires idle origins after a successful root publication.
    pub fn retire_published_pool(&self, generation: u64) {
        self.pool.retire_before(generation);
    }

    /// Shared telemetry counters.
    pub fn telemetry(&self) -> Arc<Telemetry> {
        Arc::clone(&self.telemetry)
    }

    /// Shared snapshot store used by the control service and accept loops.
    pub fn snapshots(&self) -> Arc<SnapshotStore> {
        Arc::clone(&self.snapshots)
    }

    /// Current configuration generation.
    pub fn generation(&self) -> u64 {
        self.snapshots.generation()
    }

    /// Test/library API with an injected password verifier.
    #[doc(hidden)]
    pub fn with_verifier(config: Arc<Config>, verifier: Arc<dyn PasswordVerifier>) -> Arc<Self> {
        let telemetry = Telemetry::with_detailed(config.observability().metrics_enabled());
        let outbound =
            OutboundService::new_with_telemetry(Arc::clone(&config), Arc::clone(&telemetry));
        Self::assemble_with_verifier(config, outbound, telemetry, Some(verifier))
    }

    /// Test/library API with injected components and a password verifier.
    #[doc(hidden)]
    pub fn with_components_and_verifier(
        config: Arc<Config>,
        resolver: Arc<dyn crate::resolver::Resolver>,
        dialer: Arc<dyn crate::transport::Dialer>,
        verifier: Arc<dyn PasswordVerifier>,
    ) -> Arc<Self> {
        let telemetry = Telemetry::with_detailed(config.observability().metrics_enabled());
        let outbound = OutboundService::with_components_and_telemetry(
            Arc::clone(&config),
            resolver,
            dialer,
            Arc::clone(&telemetry),
        );
        Self::assemble_with_verifier(config, outbound, telemetry, Some(verifier))
    }

    /// Number of free password-verification slots across all listeners.
    #[doc(hidden)]
    pub fn auth_available_permits(&self) -> Option<usize> {
        self.auth.as_ref().map(AuthService::available_permits)
    }

    /// Applies the listener's authentication mode before policy and routing.
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
        client: &ClientInfo,
        config: &Config,
    ) -> Result<Option<VerifiedIdentity>, Response<ResponseBody>> {
        let Some(listener) = config.listener(&client.listener_id) else {
            return Err(headers::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                true,
            ));
        };
        match listener.auth() {
            AuthMode::None => Ok(None),
            AuthMode::Basic => {
                let Some(auth) = self.auth.as_ref() else {
                    return Err(headers::error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        true,
                    ));
                };
                let Some(auth_config) = config.auth() else {
                    return Err(headers::error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        true,
                    ));
                };
                match auth
                    .authenticate_headers_with_snapshot(headers, auth_config.snapshot())
                    .await
                {
                    Ok(identity) => Ok(Some(identity)),
                    Err(AuthError::InvalidCredentials) => {
                        Err(headers::proxy_auth_required_response())
                    }
                    Err(AuthError::Busy | AuthError::Timeout | AuthError::Internal) => Err(
                        headers::error_response(StatusCode::SERVICE_UNAVAILABLE, true),
                    ),
                }
            }
        }
    }

    /// Starts shutdown: new exchanges are refused and idle origin sockets are
    /// closed. In-flight exchanges keep their leases until they complete or the
    /// server force-closes their tasks.
    pub fn begin_shutdown(&self) {
        self.draining.store(true, Ordering::Release);
        self.pool.clear();
        if let Some(cache) = &self.cache {
            cache.clear();
        }
    }

    /// Removes expired idle origin sockets.
    pub fn purge_pool(&self) {
        self.pool.purge_expired();
    }

    /// Retires idle origins from older generations after a successful publish.
    pub fn retire_before(&self, generation: u64) {
        self.pool.retire_before(generation);
        if let Some(cache) = &self.cache {
            cache.retire_before(generation);
        }
    }

    /// Closes every idle origin socket at the start of draining.
    pub fn clear_idle_origins(&self) {
        self.pool.clear();
    }

    /// Reaps finished origin driver tasks.
    pub async fn reap_origin_tasks(&self) {
        self.origin_tasks.reap().await;
    }

    /// Aborts and awaits all origin drivers.
    pub async fn shutdown_origins(&self) -> bool {
        self.origin_tasks.shutdown().await
    }

    /// Whether new exchanges must be refused.
    fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Handles a CONNECT request and performs all pre-dial validation.
    ///
    /// On success the returned setup owns the authorized origin socket and the
    /// hyper upgrade; the caller must send the 200 response before awaiting it.
    pub(crate) async fn handle_connect(
        &self,
        request: Request<Incoming>,
        client: ClientInfo,
        on_upgrade: OnUpgrade,
        snapshot: &Arc<crate::snapshot::RuntimeSnapshot>,
        terminal: &mut ConnectTerminal,
    ) -> Result<(Response<ResponseBody>, TunnelSetup), Response<ResponseBody>> {
        let error = |status: StatusCode| headers::error_response(status, true);
        if self.is_draining() {
            return Err(error(StatusCode::SERVICE_UNAVAILABLE));
        }
        let config = snapshot.config();
        if request.version() != Version::HTTP_11 {
            return Err(error(StatusCode::HTTP_VERSION_NOT_SUPPORTED));
        }
        if request.method() != Method::CONNECT {
            return Err(error(StatusCode::BAD_REQUEST));
        }
        if request.headers().contains_key(EXPECT) {
            return Err(error(StatusCode::EXPECTATION_FAILED));
        }
        if headers::has_upgrade(request.headers()) {
            return Err(error(StatusCode::BAD_REQUEST));
        }
        if headers::via_has_angara(request.headers(), config.instance_id()) {
            self.telemetry
                .via_loop_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(error(StatusCode::LOOP_DETECTED));
        }
        if headers::validate_framing(request.headers()).is_err() {
            return Err(error(StatusCode::BAD_REQUEST));
        }
        if request.headers().contains_key(TRANSFER_ENCODING)
            || request.headers().contains_key(TRAILER)
        {
            return Err(error(StatusCode::BAD_REQUEST));
        }
        for value in request.headers().get_all(CONTENT_LENGTH) {
            let Ok(value) = value.to_str() else {
                return Err(error(StatusCode::BAD_REQUEST));
            };
            if value
                .split(',')
                .map(str::trim)
                .any(|part| part.parse::<u64>() != Ok(0))
            {
                return Err(error(StatusCode::BAD_REQUEST));
            }
        }

        let target_text = request
            .extensions()
            .get::<OriginalRequestTarget>()
            .map(|target| target.as_str().to_owned())
            .unwrap_or_else(|| request.uri().to_string());
        let target = match CanonicalTarget::parse(&Method::CONNECT, &target_text) {
            Ok(target) if target.is_connect() => target,
            Ok(_) => return Err(error(StatusCode::BAD_REQUEST)),
            Err(target_error) => return Err(error(target_status(target_error))),
        };

        let host_count = request.headers().get_all(HOST).iter().count();
        if host_count != 1 {
            return Err(error(StatusCode::BAD_REQUEST));
        }
        let host_header = request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok());
        if target::check_host_header(&target, host_header).is_err() {
            return Err(error(StatusCode::BAD_REQUEST));
        }
        if policy::check_source(config.access(), client.peer).is_err() {
            return Err(error(StatusCode::FORBIDDEN));
        }
        let identity = self
            .authenticate(request.headers(), &client, config)
            .await?;
        if !config.connect().allows_port(target.port()) {
            return Err(error(StatusCode::FORBIDDEN));
        }

        let context = match identity {
            Some(identity) => {
                RequestContext::with_identity(client.peer, client.listener_id.clone(), identity)
            }
            None => RequestContext::new(client.peer, client.listener_id.clone()),
        };
        let plan = match self
            .outbound
            .prepare_outbound_with(
                config,
                snapshot.generation(),
                &context,
                &Method::CONNECT,
                &target_text,
                host_header,
            )
            .await
        {
            Ok(plan) => plan,
            Err(OutboundError::AuthenticationRequired) => {
                return Err(headers::proxy_auth_required_response());
            }
            Err(outbound_error) => {
                let (status, close) = outbound_status(outbound_error);
                return Err(headers::error_response(status, close));
            }
        };
        if plan.parent().is_some() {
            terminal.set_parent_route(&plan);
            terminal.mark_parent_failure();
        }
        let connected = match self.outbound.open_plan_with(config, &plan).await {
            Ok(origin) => origin,
            Err(outbound_error) => {
                let (status, close) = outbound_status(outbound_error);
                return Err(headers::error_response(status, close));
            }
        };
        let tunnel_generation = connected.endpoint().generation();
        let parent_id = plan.parent_id().map(str::to_owned);
        let route = if plan.parent().is_some() {
            RouteKind::Parent
        } else {
            RouteKind::Direct
        };
        let origin_tls = plan
            .parent()
            .is_some_and(|parent| parent.transport() == crate::parent::ParentTransport::Https);
        let origin: BoxedIo = if let Some(parent) = plan.parent() {
            let Some(target_endpoint) = plan.target_endpoint() else {
                return Err(headers::error_response(StatusCode::BAD_GATEWAY, true));
            };
            let deadline = tokio::time::Instant::from_std(plan.deadline());
            let io = match parent_client::connect_io(
                connected,
                parent,
                config.limits().idle_timeout(),
                deadline,
            )
            .await
            {
                Ok(io) => io,
                Err(error) => {
                    return Err(headers::error_response(error.status(), true));
                }
            };
            let incoming_via = headers::via_chain(request.headers());
            match parent_client::open_tunnel(
                io,
                parent,
                target_endpoint,
                config.instance_id(),
                &incoming_via,
                config.http().response_header_timeout(),
                deadline,
            )
            .await
            {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    return Err(headers::error_response(error.status(), true));
                }
            }
        } else {
            Box::new(connected)
        };

        let body = http_body_util::Full::new(bytes::Bytes::new())
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed();
        let response = Response::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_11)
            .body(body)
            .unwrap_or_else(|_| {
                Response::new(
                    http_body_util::Full::new(bytes::Bytes::new())
                        .map_err(|never: std::convert::Infallible| match never {})
                        .boxed(),
                )
            });
        let setup = TunnelSetup {
            on_upgrade,
            origin,
            origin_tls,
            deadline: tokio::time::Instant::now() + config.limits().idle_timeout(),
            idle_timeout: config.limits().idle_timeout(),
            half_close_timeout: config.connect().half_close_timeout(),
            gauge: crate::http::connect::TunnelGauge::new(
                Arc::clone(&self.telemetry),
                self.logger(),
                tunnel_generation,
                client.connection_id,
                parent_id,
                route,
            ),
        };
        self.telemetry
            .connect_started
            .fetch_add(1, Ordering::Relaxed);
        Ok((response, setup))
    }

    /// Handles one non-CONNECT client request. All failures before final headers
    /// become bounded local responses; the server wraps the returned body and
    /// calls [`Proxy::log_exchange`] exactly once when that body reaches a
    /// terminal state.
    pub(crate) async fn handle(
        &self,
        request: Request<Incoming>,
        client: ClientInfo,
        interim: InterimSender,
    ) -> Response<ResponseBody> {
        let started = tokio::time::Instant::now();
        self.telemetry.http_started.fetch_add(1, Ordering::Relaxed);
        let snapshot = self.snapshots.load();
        let request_body_bytes = Arc::new(AtomicU64::new(0));
        let route = Arc::new(Mutex::new(RouteInfo::default()));
        let mut meta = ExchangeMeta {
            generation: snapshot.generation(),
            started,
            connection_id: client.connection_id,
            request_id: client.request_id,
            listener_id: client.listener_id.clone(),
            status: None,
            request_body_bytes,
            route: Arc::clone(&route),
        };
        let mut terminal =
            ExchangeTerminal::new(Arc::clone(&self.telemetry), self.logger(), meta.clone());
        let mut response = if self.is_draining() {
            headers::error_response(StatusCode::SERVICE_UNAVAILABLE, true)
        } else {
            self.handle_inner(
                request,
                client.clone(),
                interim,
                &snapshot,
                Arc::clone(&meta.request_body_bytes),
                Arc::clone(&route),
            )
            .await
        };
        meta.status = Some(response.status());
        terminal.disarm();
        response.extensions_mut().insert(meta);
        response
    }

    /// Creates the exactly-once terminal guard for a CONNECT request before
    /// auth/DNS/dial. The generation belongs to the one exchange snapshot.
    pub(crate) fn connect_terminal(
        &self,
        client: &ClientInfo,
        generation: u64,
        started: tokio::time::Instant,
    ) -> ConnectTerminal {
        ConnectTerminal {
            telemetry: Arc::clone(&self.telemetry),
            logger: self.logger(),
            meta: ExchangeMeta {
                generation,
                started,
                connection_id: client.connection_id,
                request_id: client.request_id,
                listener_id: client.listener_id.clone(),
                status: None,
                request_body_bytes: Arc::new(AtomicU64::new(0)),
                route: Arc::new(Mutex::new(RouteInfo::default())),
            },
            parent_failure: false,
            disarmed: false,
        }
    }

    /// Emits exactly one terminal record and metrics update for an exchange.
    pub fn log_exchange(
        &self,
        meta: ExchangeMeta,
        outcome: crate::http::BodyOutcome,
        response_body_bytes: u64,
    ) {
        log_terminal(
            &self.telemetry,
            &self.logger(),
            &meta,
            outcome,
            response_body_bytes,
        );
    }

    async fn handle_inner(
        &self,
        request: Request<Incoming>,
        client: ClientInfo,
        interim: InterimSender,
        snapshot: &Arc<crate::snapshot::RuntimeSnapshot>,
        request_body_bytes: Arc<AtomicU64>,
        route: Arc<Mutex<RouteInfo>>,
    ) -> Response<ResponseBody> {
        if self.is_draining() {
            return headers::error_response(StatusCode::SERVICE_UNAVAILABLE, true);
        }
        let config = snapshot.config();
        if request.version() != Version::HTTP_11 {
            return headers::error_response(StatusCode::HTTP_VERSION_NOT_SUPPORTED, true);
        }
        if headers::validate_framing(request.headers()).is_err() {
            return headers::error_response(StatusCode::BAD_REQUEST, true);
        }
        let request_chunked = request
            .headers()
            .get_all(http::header::TRANSFER_ENCODING)
            .iter()
            .any(|value| {
                value.to_str().is_ok_and(|value| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
                })
            });

        let method = request.method().clone();
        let uri = request.uri().clone();
        let target_text = request
            .extensions()
            .get::<OriginalRequestTarget>()
            .map(|target| target.as_str().to_owned())
            .unwrap_or_else(|| uri.to_string());
        if target_text.contains('#') {
            return headers::error_response(StatusCode::BAD_REQUEST, true);
        }

        if method == Method::CONNECT {
            // CONNECT is served by `handle_connect`, which owns the upgrade
            // handoff. A direct call without that context cannot succeed.
            return headers::error_response(StatusCode::BAD_REQUEST, true);
        }
        if method == Method::TRACE {
            return headers::error_response(StatusCode::NOT_IMPLEMENTED, true);
        }
        if headers::has_upgrade(request.headers()) {
            return headers::error_response(StatusCode::NOT_IMPLEMENTED, true);
        }
        if headers::via_has_angara(request.headers(), config.instance_id()) {
            self.telemetry
                .via_loop_rejected
                .fetch_add(1, Ordering::Relaxed);
            return headers::error_response(StatusCode::LOOP_DETECTED, true);
        }

        let host_count = request.headers().get_all(HOST).iter().count();
        if host_count != 1 {
            return headers::error_response(StatusCode::BAD_REQUEST, true);
        }
        let host_header = request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok());
        let target = match CanonicalTarget::parse(&method, &target_text) {
            Ok(target) => target,
            Err(error) => return headers::error_response(target_status(error), true),
        };
        if target::check_host_header(&target, host_header).is_err() {
            return headers::error_response(StatusCode::BAD_REQUEST, true);
        }

        let _expect_continue = match headers::expect_continue(request.headers()) {
            Ok(value) => value,
            Err(()) => return headers::error_response(StatusCode::EXPECTATION_FAILED, true),
        };
        let request_had_content_length = request.headers().contains_key(CONTENT_LENGTH);
        let request_accepts_trailers = headers::accepts_trailers(request.headers());
        let max_forwards = if method == Method::OPTIONS {
            match headers::max_forwards(request.headers()) {
                Ok(value) => value,
                Err(()) => return headers::error_response(StatusCode::BAD_REQUEST, true),
            }
        } else {
            None
        };

        if policy::check_source(config.access(), client.peer).is_err() {
            return headers::error_response(StatusCode::FORBIDDEN, true);
        }
        let identity = match self.authenticate(request.headers(), &client, config).await {
            Ok(identity) => identity,
            Err(response) => return response,
        };
        let meta = RequestMeta {
            listener_id: &client.listener_id,
            source: client.peer,
            method: &method,
            target: &target,
            identity: identity.as_ref(),
        };
        if policy::check_request(config.access(), &meta).is_err() {
            return headers::error_response(StatusCode::FORBIDDEN, true);
        }
        let context = match identity {
            Some(identity) => {
                RequestContext::with_identity(client.peer, client.listener_id.clone(), identity)
            }
            None => RequestContext::new(client.peer, client.listener_id.clone()),
        };
        let original_request_headers = request.headers().clone();
        let incoming_via = headers::via_chain(&original_request_headers);
        if max_forwards == Some(0) {
            let has_body = request_chunked
                || request
                    .headers()
                    .get_all(CONTENT_LENGTH)
                    .iter()
                    .any(|value| {
                        value
                            .to_str()
                            .is_ok_and(|value| value.parse::<u64>().is_ok_and(|length| length > 0))
                    });
            return headers::error_response(StatusCode::NO_CONTENT, has_body);
        }

        let mut request_headers = request.headers().clone();
        let request_nominations = match headers::filter_hop_by_hop(&mut request_headers, true) {
            Ok(names) => names,
            Err(()) => return headers::error_response(StatusCode::BAD_REQUEST, true),
        };
        let request_trailer_names =
            match headers::trailer_names(&original_request_headers, &request_nominations) {
                Ok(names) => names,
                Err(()) => return headers::error_response(StatusCode::BAD_REQUEST, true),
            };
        let request_trailer_nominated = request_nominations.contains(&http::header::TRAILER);
        let request_te_nominated = request_nominations.contains(&http::header::TE);
        headers::set_canonical_host(&mut request_headers, &target);
        headers::remove_expect(&mut request_headers);
        if !request_trailer_nominated {
            headers::set_trailer_names(&mut request_headers, &request_trailer_names);
        }
        if request_accepts_trailers && !request_te_nominated {
            headers::set_te_trailers(&mut request_headers);
        }
        if let Some(value) = max_forwards {
            headers::set_max_forwards(&mut request_headers, value - 1);
        }
        headers::append_via(&mut request_headers, config.instance_id());

        let plan = match self
            .outbound
            .prepare_outbound_with(
                config,
                snapshot.generation(),
                &context,
                &method,
                &target_text,
                host_header,
            )
            .await
        {
            Ok(plan) => plan,
            Err(OutboundError::AuthenticationRequired) => {
                return headers::proxy_auth_required_response();
            }
            Err(error) => {
                let (status, close) = outbound_status(error);
                return headers::error_response(status, close);
            }
        };
        set_route(&route, &plan);

        let has_request_body = request_chunked
            || request
                .headers()
                .get_all(CONTENT_LENGTH)
                .iter()
                .any(|value| {
                    value
                        .to_str()
                        .is_ok_and(|value| value.parse::<u64>().is_ok_and(|length| length > 0))
                });
        let mut cache_write = self.cache.is_some() && method == Method::GET && !has_request_body;
        let mut cache_request_time = SystemTime::now();
        let mut revalidation = None;

        if plan.parent().is_some() {
            if self.cache.is_some() {
                self.telemetry.cache_bypass.fetch_add(1, Ordering::Relaxed);
            }
            let response = self
                .forward_parent(
                    config,
                    &plan,
                    ForwardParts {
                        method: method.clone(),
                        target: target.clone(),
                        target_text: target_text.clone(),
                        body: request.into_body(),
                        headers: request_headers,
                        via: incoming_via,
                        nominations: request_nominations,
                        request_chunked,
                        request_had_content_length,
                        interim,
                        request_body_bytes,
                    },
                    &route,
                )
                .await;
            self.invalidate_unsafe(&method, &target, &response);
            return response;
        }

        if cache_write {
            let Some(store) = self.cache.as_ref() else {
                return headers::error_response(StatusCode::INTERNAL_SERVER_ERROR, true);
            };
            let Some(policy) = cache::analyze_request(&original_request_headers) else {
                cache_write = false;
                self.telemetry.cache_bypass.fetch_add(1, Ordering::Relaxed);
                return self
                    .forward_direct(
                        config,
                        &plan,
                        request,
                        &method,
                        &target,
                        &target_text,
                        request_headers,
                        request_nominations,
                        request_chunked,
                        request_had_content_length,
                        interim,
                        request_body_bytes,
                        cache_write,
                        cache_request_time,
                    )
                    .await;
            };
            let Some(accept_encoding) = cache::request_accept_encoding(&original_request_headers)
            else {
                cache_write = false;
                self.telemetry.cache_bypass.fetch_add(1, Ordering::Relaxed);
                return self
                    .forward_direct(
                        config,
                        &plan,
                        request,
                        &method,
                        &target,
                        &target_text,
                        request_headers,
                        request_nominations,
                        request_chunked,
                        request_had_content_length,
                        interim,
                        request_body_bytes,
                        cache_write,
                        cache_request_time,
                    )
                    .await;
            };
            cache_write = policy.write;
            if policy.only_if_cached && (!policy.read || !policy.write) {
                return headers::error_response(StatusCode::GATEWAY_TIMEOUT, true);
            }
            if !policy.read {
                self.telemetry.cache_bypass.fetch_add(1, Ordering::Relaxed);
            } else {
                let now = SystemTime::now();
                let mut found: Option<(CacheKey, Arc<CacheEntry>, bool)> = None;
                {
                    let key = make_cache_key(
                        &plan,
                        &target,
                        CacheVariant::AcceptEncoding(accept_encoding.clone()),
                    );
                    match store.lookup(&key, now) {
                        Lookup::Fresh(entry) => {
                            let acceptable = policy.accepts_age(entry.current_age(now))
                                && policy.min_fresh.is_none_or(|min_fresh| {
                                    entry.freshness_remaining(now) >= min_fresh
                                });
                            if acceptable {
                                self.telemetry.cache_hit.fetch_add(1, Ordering::Relaxed);
                                return entry.response(config.instance_id());
                            }
                            found = Some((key, entry, false));
                        }
                        Lookup::Stale(entry) => found = Some((key, entry, false)),
                        Lookup::Miss => {}
                    }
                }
                if found.is_none() {
                    let key = make_cache_key(&plan, &target, CacheVariant::None);
                    match store.lookup(&key, now) {
                        Lookup::Fresh(entry) => {
                            let acceptable = policy.accepts_age(entry.current_age(now))
                                && policy.min_fresh.is_none_or(|min_fresh| {
                                    entry.freshness_remaining(now) >= min_fresh
                                });
                            if acceptable {
                                self.telemetry.cache_hit.fetch_add(1, Ordering::Relaxed);
                                return entry.response(config.instance_id());
                            }
                            found = Some((key, entry, false));
                        }
                        Lookup::Stale(entry) => found = Some((key, entry, false)),
                        Lookup::Miss => {}
                    }
                }
                match found {
                    Some((key, entry, _fresh)) => {
                        self.telemetry.cache_miss.fetch_add(1, Ordering::Relaxed);
                        if policy.only_if_cached {
                            return headers::error_response(StatusCode::GATEWAY_TIMEOUT, true);
                        }
                        if let Some((name, value)) = cache_validators(&entry) {
                            revalidation = Some((key, entry, name, value));
                        }
                    }
                    None => {
                        self.telemetry.cache_miss.fetch_add(1, Ordering::Relaxed);
                        if policy.only_if_cached {
                            return headers::error_response(StatusCode::GATEWAY_TIMEOUT, true);
                        }
                    }
                }
            }
        }

        if let Some((key, entry, name, value)) = revalidation {
            self.telemetry
                .cache_revalidation
                .fetch_add(1, Ordering::Relaxed);
            cache_request_time = SystemTime::now();
            let mut conditional_headers = request_headers.clone();
            conditional_headers.insert(name, value);
            match self
                .send_revalidation(
                    config,
                    &plan,
                    &method,
                    &target,
                    conditional_headers,
                    &interim,
                )
                .await
            {
                Revalidation::NotModified(headers) => {
                    if let Some(store) = self.cache.as_ref()
                        && store.revalidate(&key, &entry, &headers, SystemTime::now())
                    {
                        self.telemetry.cache_hit.fetch_add(1, Ordering::Relaxed);
                        return entry.response(config.instance_id());
                    }
                }
                Revalidation::Response(response, lease) => {
                    let response = self.finalize_direct(
                        config,
                        &method,
                        request_chunked,
                        &target,
                        &plan,
                        &original_request_headers,
                        cache_write,
                        cache_request_time,
                        response,
                        *lease,
                    );
                    self.invalidate_unsafe(&method, &target, &response);
                    return response;
                }
                Revalidation::Failed(response) => return response,
            }
        }

        cache_request_time = SystemTime::now();
        let response = self
            .forward_direct(
                config,
                &plan,
                request,
                &method,
                &target,
                &target_text,
                request_headers,
                request_nominations,
                request_chunked,
                request_had_content_length,
                interim,
                request_body_bytes,
                cache_write,
                cache_request_time,
            )
            .await;
        self.invalidate_unsafe(&method, &target, &response);
        response
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_direct(
        &self,
        config: &Config,
        plan: &OutboundPlan,
        request: Request<Incoming>,
        method: &Method,
        target: &CanonicalTarget,
        target_text: &str,
        request_headers: http::HeaderMap,
        request_nominations: Vec<http::header::HeaderName>,
        request_chunked: bool,
        request_had_content_length: bool,
        interim: InterimSender,
        request_body_bytes: Arc<AtomicU64>,
        cache_write: bool,
        cache_request_time: SystemTime,
    ) -> Response<ResponseBody> {
        let lease = match self.direct_lease(plan, config).await {
            Ok(lease) => lease,
            Err(response) => return response,
        };

        let mut request_headers = request_headers;
        let body = request.into_body();
        let body_length = body.size_hint().exact();
        if request_had_content_length && let Some(length) = body_length {
            headers::set_content_length(&mut request_headers, length);
        }
        let request_body =
            LeaseRequestBody::new(body, lease.clone(), request_nominations, request_body_bytes)
                .boxed();
        let origin_form = if method == Method::OPTIONS && options_without_path(target_text) {
            "*"
        } else {
            headers::origin_form(target)
        };
        let mut upstream_request = Request::new(request_body);
        *upstream_request.method_mut() = method.clone();
        *upstream_request.uri_mut() = origin_form
            .parse()
            .unwrap_or_else(|_| "/".parse().expect("static origin-form"));
        *upstream_request.version_mut() = Version::HTTP_11;
        *upstream_request.headers_mut() = request_headers.clone();

        let interim_callback = interim.clone();
        hyper::ext::on_informational(&mut upstream_request, move |response| {
            let _ = interim_callback.send_interim(response.status(), response.headers());
        });

        let mut sender = match lease.take_sender() {
            Some(sender) => sender,
            None => {
                lease.abort();
                return headers::error_response(StatusCode::BAD_GATEWAY, true);
            }
        };
        let response_timeout = config.http().response_header_timeout();
        let result =
            tokio::time::timeout(response_timeout, sender.send_request(upstream_request)).await;
        match result {
            Ok(Ok(response)) => {
                lease.put_sender(sender);
                if interim.failed() {
                    lease.abort();
                    return headers::error_response(StatusCode::BAD_GATEWAY, true);
                }
                self.finalize_direct(
                    config,
                    method,
                    request_chunked,
                    target,
                    plan,
                    &request_headers,
                    cache_write,
                    cache_request_time,
                    response,
                    lease,
                )
            }
            Ok(Err(_)) => {
                lease.abort();
                headers::error_response(StatusCode::BAD_GATEWAY, true)
            }
            Err(_) => {
                lease.abort();
                headers::error_response(StatusCode::GATEWAY_TIMEOUT, true)
            }
        }
    }

    async fn direct_lease(
        &self,
        plan: &OutboundPlan,
        config: &Config,
    ) -> Result<Lease, Response<ResponseBody>> {
        let lease = match self.pool.checkout(plan) {
            Some(lease) => lease,
            None => match self.open_new_connection(plan, config).await {
                Ok(lease) => lease,
                Err(error) => {
                    let (status, close) = outbound_status(error);
                    return Err(headers::error_response(status, close));
                }
            },
        };
        if plan.is_expired() {
            lease.abort();
            return Err(headers::error_response(StatusCode::GATEWAY_TIMEOUT, true));
        }
        Ok(lease)
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_direct(
        &self,
        config: &Config,
        method: &Method,
        request_chunked: bool,
        target: &CanonicalTarget,
        plan: &OutboundPlan,
        request_headers: &http::HeaderMap,
        cache_write: bool,
        cache_request_time: SystemTime,
        response: Response<Incoming>,
        lease: Lease,
    ) -> Response<ResponseBody> {
        let response_time = SystemTime::now();
        let expected_len = response.body().size_hint().exact();
        let mut fill = None;
        if cache_write && let Some(store) = self.cache.as_ref() {
            let mut cache_headers = response.headers().clone();
            let filtered =
                crate::http::headers::filter_hop_by_hop(&mut cache_headers, false).is_ok();
            if filtered
                && let Some(policy) = cache::analyze_response(
                    request_headers,
                    &cache_headers,
                    method,
                    response.status(),
                    cache_request_time,
                    response_time,
                    false,
                )
                && let Some(variant) = cache::request_variant_for(request_headers, &cache_headers)
            {
                let key = make_cache_key(plan, target, variant);
                fill = store.begin_fill(
                    key,
                    cache_headers,
                    policy,
                    expected_len,
                    cache_request_time,
                    response_time,
                );
            }
        }
        if fill.is_none() && cache_write {
            self.telemetry.cache_bypass.fetch_add(1, Ordering::Relaxed);
        }
        match finalize_upstream_response(
            response,
            lease,
            method,
            request_chunked,
            config.instance_id(),
        ) {
            Ok(local) => {
                if let Some(fill) = fill {
                    let (parts, body) = local.into_parts();
                    let body: ResponseBody = CacheFillBody::new(body, fill).boxed();
                    Response::from_parts(parts, body)
                } else {
                    local
                }
            }
            Err(()) => headers::error_response(StatusCode::BAD_GATEWAY, true),
        }
    }

    async fn send_revalidation(
        &self,
        config: &Config,
        plan: &OutboundPlan,
        method: &Method,
        target: &CanonicalTarget,
        headers: http::HeaderMap,
        interim: &InterimSender,
    ) -> Revalidation {
        let lease = match self.direct_lease(plan, config).await {
            Ok(lease) => lease,
            Err(response) => return Revalidation::Failed(response),
        };
        let body = http_body_util::Full::new(Bytes::new())
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed();
        lease.request_complete();
        let expected_etag = headers.get(http::header::IF_NONE_MATCH).cloned();
        let mut upstream_request = Request::new(body);
        *upstream_request.method_mut() = method.clone();
        *upstream_request.uri_mut() = headers::origin_form(target)
            .parse()
            .unwrap_or_else(|_| "/".parse().expect("static origin-form"));
        *upstream_request.version_mut() = Version::HTTP_11;
        *upstream_request.headers_mut() = headers;
        let interim_callback = interim.clone();
        hyper::ext::on_informational(&mut upstream_request, move |response| {
            let _ = interim_callback.send_interim(response.status(), response.headers());
        });
        let mut sender = match lease.take_sender() {
            Some(sender) => sender,
            None => {
                lease.abort();
                return Revalidation::Failed(headers::error_response(
                    StatusCode::BAD_GATEWAY,
                    true,
                ));
            }
        };
        let result = tokio::time::timeout(
            config.http().response_header_timeout(),
            sender.send_request(upstream_request),
        )
        .await;
        match result {
            Ok(Ok(response)) => {
                lease.put_sender(sender);
                if interim.failed() {
                    lease.abort();
                    return Revalidation::Failed(headers::error_response(
                        StatusCode::BAD_GATEWAY,
                        true,
                    ));
                }
                if response.status() == StatusCode::NOT_MODIFIED {
                    if headers::validate_framing(response.headers()).is_err() {
                        lease.abort();
                        return Revalidation::Failed(headers::error_response(
                            StatusCode::BAD_GATEWAY,
                            true,
                        ));
                    }
                    if let (Some(expected), Some(actual)) = (
                        expected_etag.as_ref(),
                        response.headers().get(http::header::ETAG),
                    ) && expected != actual
                    {
                        lease.abort();
                        return Revalidation::Failed(headers::error_response(
                            StatusCode::BAD_GATEWAY,
                            true,
                        ));
                    }
                    let mut updated = response.headers().clone();
                    if crate::http::headers::filter_hop_by_hop(&mut updated, false).is_err() {
                        lease.abort();
                        return Revalidation::Failed(headers::error_response(
                            StatusCode::BAD_GATEWAY,
                            true,
                        ));
                    }
                    drop(response);
                    lease.response_complete();
                    Revalidation::NotModified(updated)
                } else {
                    Revalidation::Response(response, Box::new(lease))
                }
            }
            Ok(Err(_)) => {
                lease.abort();
                Revalidation::Failed(headers::error_response(StatusCode::BAD_GATEWAY, true))
            }
            Err(_) => {
                lease.abort();
                Revalidation::Failed(headers::error_response(StatusCode::GATEWAY_TIMEOUT, true))
            }
        }
    }

    fn invalidate_unsafe(
        &self,
        method: &Method,
        target: &CanonicalTarget,
        response: &Response<ResponseBody>,
    ) {
        if is_safe_method(method) || response.status().as_u16() >= 400 {
            return;
        }
        let Some(cache) = self.cache.as_ref() else {
            return;
        };
        cache.invalidate(&cache_uri(target));
        for uri in invalidation_uris(target, response.headers()) {
            cache.invalidate(&uri);
        }
    }

    async fn forward_parent(
        &self,
        config: &Config,
        plan: &OutboundPlan,
        parts: ForwardParts,
        route: &Arc<Mutex<RouteInfo>>,
    ) -> Response<ResponseBody> {
        set_route(route, plan);
        let Some(parent) = plan.parent().cloned() else {
            return headers::error_response(StatusCode::INTERNAL_SERVER_ERROR, true);
        };
        let Some(target_endpoint) = plan.target_endpoint() else {
            return headers::error_response(StatusCode::BAD_GATEWAY, true);
        };
        let use_tunnel = plan.target().host().as_domain().is_some()
            || (parts.method == Method::OPTIONS && options_without_path(&parts.target_text));
        let response_timeout = config.http().response_header_timeout();
        let deadline = tokio::time::Instant::from_std(plan.deadline());

        let (lease, uri) = if use_tunnel {
            let (io, _parent_endpoint) = match self.open_parent_io(config, plan).await {
                Ok(value) => value,
                Err(error) => {
                    return error.response();
                }
            };
            let tunnel = match parent_client::open_tunnel(
                io,
                &parent,
                target_endpoint,
                config.instance_id(),
                &parts.via,
                response_timeout,
                deadline,
            )
            .await
            {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    return headers::error_response(error.status(), true);
                }
            };
            let sender = match self.handshake_parent_io(tunnel, config).await {
                Ok(sender) => sender,
                Err(error) => {
                    return headers::error_response(error.status(), true);
                }
            };
            let lease = self.pool.new_parent_lease(plan, target_endpoint, sender);
            let uri = if parts.method == Method::OPTIONS && options_without_path(&parts.target_text)
            {
                "*".to_owned()
            } else {
                headers::origin_form(&parts.target).to_owned()
            };
            (lease, uri)
        } else {
            let (io, parent_endpoint) = match self.open_parent_io(config, plan).await {
                Ok(value) => value,
                Err(error) => return error.response(),
            };
            let sender = match self.handshake_parent_io(io, config).await {
                Ok(sender) => sender,
                Err(error) => return headers::error_response(error.status(), true),
            };
            let lease = self.pool.new_parent_lease(plan, parent_endpoint, sender);
            let path = parts
                .target
                .path_and_query()
                .map(|path| path.as_str())
                .unwrap_or("/");
            let authority = parent_client::connect_authority(target_endpoint);
            (lease, format!("http://{authority}{path}"))
        };

        let body_length = parts.body.size_hint().exact();
        let mut request_headers = parts.headers;
        if parts.request_had_content_length
            && let Some(length) = body_length
        {
            headers::set_content_length(&mut request_headers, length);
        }
        if !use_tunnel && let Some(authorization) = parent.authorization() {
            request_headers.insert(http::header::PROXY_AUTHORIZATION, authorization);
        }

        let request_body = LeaseRequestBody::new(
            parts.body,
            lease.clone(),
            parts.nominations,
            parts.request_body_bytes,
        )
        .boxed();
        let mut upstream_request = Request::new(request_body);
        *upstream_request.method_mut() = parts.method.clone();
        *upstream_request.uri_mut() = uri
            .parse()
            .unwrap_or_else(|_| "/".parse().expect("static origin-form"));
        *upstream_request.version_mut() = Version::HTTP_11;
        *upstream_request.headers_mut() = request_headers;

        let interim_callback = parts.interim.clone();
        hyper::ext::on_informational(&mut upstream_request, move |response| {
            let _ = interim_callback.send_interim(response.status(), response.headers());
        });

        let mut sender = match lease.take_sender() {
            Some(sender) => sender,
            None => {
                lease.abort();
                return headers::error_response(StatusCode::BAD_GATEWAY, true);
            }
        };
        let result =
            tokio::time::timeout(response_timeout, sender.send_request(upstream_request)).await;
        match result {
            Ok(Ok(response)) => {
                lease.put_sender(sender);
                if response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    lease.abort();
                    return headers::error_response(StatusCode::BAD_GATEWAY, true);
                }
                if parts.interim.failed() {
                    lease.abort();
                    return headers::error_response(StatusCode::BAD_GATEWAY, true);
                }
                match finalize_upstream_response(
                    response,
                    lease,
                    &parts.method,
                    parts.request_chunked,
                    config.instance_id(),
                ) {
                    Ok(response) => response,
                    Err(()) => headers::error_response(StatusCode::BAD_GATEWAY, true),
                }
            }
            Ok(Err(_)) => {
                lease.abort();
                headers::error_response(StatusCode::BAD_GATEWAY, true)
            }
            Err(_) => {
                lease.abort();
                headers::error_response(StatusCode::GATEWAY_TIMEOUT, true)
            }
        }
    }

    async fn open_parent_io(
        &self,
        config: &Config,
        plan: &OutboundPlan,
    ) -> Result<(BoxedIo, std::net::SocketAddr), ParentOpenError> {
        let connected = self
            .outbound
            .open_plan_with(config, plan)
            .await
            .map_err(ParentOpenError::Outbound)?;
        let endpoint = connected.endpoint().endpoint();
        let parent = plan.parent().ok_or(ParentOpenError::MissingParent)?;
        let deadline = tokio::time::Instant::from_std(plan.deadline());
        let io =
            parent_client::connect_io(connected, parent, config.limits().idle_timeout(), deadline)
                .await
                .map_err(ParentOpenError::Parent)?;
        Ok((io, endpoint))
    }

    async fn handshake_parent_io(
        &self,
        io: BoxedIo,
        config: &Config,
    ) -> Result<PooledSender, ParentError> {
        let handshake = client_http1::Builder::new()
            .max_headers(config.http().max_headers())
            .max_header_size(config.limits().max_header_bytes() as usize)
            .max_buf_size(connection_buffer_size(config))
            .handshake::<_, PoolBody>(TokioIo::new(io))
            .await
            .map_err(|_| ParentError::Protocol)?;
        let (sender, connection) = handshake;
        let task = self
            .origin_tasks
            .spawn(async move {
                let _ = connection.await;
            })
            .await;
        Ok(PooledSender::new(sender, task))
    }

    async fn open_new_connection(
        &self,
        plan: &crate::outbound::OutboundPlan,
        config: &Config,
    ) -> Result<Lease, OutboundError> {
        let connected = self.outbound.open_plan_with(config, plan).await?;
        let endpoint = connected.endpoint().endpoint();
        let stream = crate::http::idle::IdleIo::new(connected, config.limits().idle_timeout());
        let handshake = client_http1::Builder::new()
            .max_headers(config.http().max_headers())
            .max_header_size(config.limits().max_header_bytes() as usize)
            .max_buf_size(connection_buffer_size(config))
            .handshake::<_, PoolBody>(TokioIo::new(stream))
            .await;
        let (sender, connection) = match handshake {
            Ok(pair) => pair,
            Err(_) => return Err(OutboundError::ConnectFailed),
        };
        let task = self
            .origin_tasks
            .spawn(async move {
                let _ = connection.await;
            })
            .await;
        Ok(self
            .pool
            .new_lease(plan, endpoint, PooledSender::new(sender, task)))
    }
}

fn log_terminal(
    telemetry: &Telemetry,
    logger: &Logger,
    meta: &ExchangeMeta,
    outcome: crate::http::BodyOutcome,
    response_body_bytes: u64,
) {
    log_terminal_with_reason(telemetry, logger, meta, outcome, response_body_bytes, None);
}

fn log_terminal_with_reason(
    telemetry: &Telemetry,
    logger: &Logger,
    meta: &ExchangeMeta,
    outcome: crate::http::BodyOutcome,
    response_body_bytes: u64,
    reason: Option<Reason>,
) {
    match outcome {
        crate::http::BodyOutcome::Cancelled => {
            telemetry.http_cancelled.fetch_add(1, Ordering::Relaxed);
        }
        crate::http::BodyOutcome::Success | crate::http::BodyOutcome::Failed => {
            telemetry.http_completed.fetch_add(1, Ordering::Relaxed);
        }
    }
    if let Some(status) = meta.status {
        if status.is_success() {
            telemetry.http_2xx.fetch_add(1, Ordering::Relaxed);
        } else if status.is_redirection() {
            telemetry.http_3xx.fetch_add(1, Ordering::Relaxed);
        } else if status.is_client_error() {
            telemetry.http_4xx.fetch_add(1, Ordering::Relaxed);
        } else {
            telemetry.http_5xx.fetch_add(1, Ordering::Relaxed);
        }
    }
    telemetry.observe_http(meta.started.elapsed());
    let outcome = match outcome {
        crate::http::BodyOutcome::Success
            if meta.status.is_some_and(|status| status.is_server_error()) =>
        {
            Outcome::Failed
        }
        crate::http::BodyOutcome::Success => Outcome::Success,
        crate::http::BodyOutcome::Failed => Outcome::Failed,
        crate::http::BodyOutcome::Cancelled => Outcome::Cancelled,
    };
    let request_body_bytes = meta.request_body_bytes();
    let mut record = LogRecord::new(Event::RequestFinished);
    record.outcome = Some(outcome);
    record.reason = Some(reason.unwrap_or(match outcome {
        Outcome::Success => Reason::Completed,
        Outcome::Cancelled => Reason::ClientClosed,
        _ => Reason::Error,
    }));
    record.generation = Some(meta.generation);
    record.connection_id = Some(meta.connection_id);
    record.request_id = Some(meta.request_id);
    record.listener_id = Some(meta.listener_id.clone());
    record.status = meta.status.map(|status| status.as_u16());
    record.elapsed_ms = Some(u64::try_from(meta.started.elapsed().as_millis()).unwrap_or(u64::MAX));
    record.request_body_bytes = Some(request_body_bytes);
    record.response_body_bytes = Some(response_body_bytes);
    if let Ok(route) = meta.route.lock() {
        record.parent_id = route.parent_id.clone();
        record.route = route.kind;
    }
    logger.log(record);
}

enum Revalidation {
    NotModified(http::HeaderMap),
    Response(Response<Incoming>, Box<Lease>),
    Failed(Response<ResponseBody>),
}

fn is_safe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

fn cache_authority(target: &CanonicalTarget) -> String {
    let host = match target.host() {
        Host::Domain(domain) => domain.to_string(),
        Host::Ip(std::net::IpAddr::V4(ip)) => ip.to_string(),
        Host::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
    };
    format!("{host}:{}", target.port())
}

fn cache_uri(target: &CanonicalTarget) -> String {
    let path = target
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    format!("http://{}{path}", cache_authority(target))
}

/// Same-origin Location/Content-Location targets whose cached bodies could be
/// affected by an unsafe method.
fn invalidation_uris(target: &CanonicalTarget, headers: &http::HeaderMap) -> Vec<String> {
    let mut uris = Vec::new();
    for name in [http::header::LOCATION, http::header::CONTENT_LOCATION] {
        for value in headers.get_all(name) {
            let Ok(value) = value.to_str() else {
                continue;
            };
            if let Ok(parsed) = CanonicalTarget::parse(&Method::GET, value) {
                if parsed.host() == target.host() && parsed.port() == target.port() {
                    uris.push(cache_uri(&parsed));
                }
            } else if value.starts_with('/') {
                uris.push(format!("http://{}{value}", cache_authority(target)));
            }
        }
    }
    uris
}

fn make_cache_key(
    plan: &OutboundPlan,
    target: &CanonicalTarget,
    variant: CacheVariant,
) -> CacheKey {
    let mut endpoints = plan.target_endpoints().to_vec();
    endpoints.sort_unstable();
    endpoints.dedup();
    CacheKey::new(
        cache_uri(target),
        variant,
        plan.listener_id().to_owned(),
        plan.identity().map(str::to_owned),
        plan.egress_id().to_owned(),
        endpoints,
        plan.generation(),
    )
}

fn cache_validators(entry: &CacheEntry) -> Option<(http::header::HeaderName, http::HeaderValue)> {
    if let Some(etag) = entry.etag() {
        return Some((http::header::IF_NONE_MATCH, etag));
    }
    entry
        .last_modified()
        .map(|value| (http::header::IF_MODIFIED_SINCE, value))
}

fn options_without_path(target: &str) -> bool {
    let Some(rest) = target.get(7..) else {
        return false;
    };
    target
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        && !rest.contains('/')
        && !rest.contains('?')
}

fn target_status(error: TargetError) -> StatusCode {
    match error {
        TargetError::TooLong => StatusCode::URI_TOO_LONG,
        TargetError::HostHeaderTooLong => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn outbound_status(error: OutboundError) -> (StatusCode, bool) {
    match error {
        OutboundError::InvalidTarget => (StatusCode::BAD_REQUEST, true),
        OutboundError::AuthenticationRequired => (StatusCode::PROXY_AUTHENTICATION_REQUIRED, true),
        OutboundError::SourceDenied
        | OutboundError::AccessDenied
        | OutboundError::DestinationDenied => (StatusCode::FORBIDDEN, true),
        OutboundError::DnsBusy | OutboundError::OutboundBusy => {
            (StatusCode::SERVICE_UNAVAILABLE, true)
        }
        OutboundError::DnsTimeout | OutboundError::ConnectTimeout | OutboundError::TotalTimeout => {
            (StatusCode::GATEWAY_TIMEOUT, true)
        }
        OutboundError::RouteInvalid | OutboundError::ParentInvalid => {
            (StatusCode::INTERNAL_SERVER_ERROR, true)
        }
        OutboundError::ParentLoop => (StatusCode::BAD_GATEWAY, true),
        OutboundError::DnsFailed
        | OutboundError::DnsNoAddresses
        | OutboundError::DnsTooManyAddresses
        | OutboundError::ConnectFailed
        | OutboundError::BindFailed
        | OutboundError::NoCompatibleAddress
        | OutboundError::Cancelled => (StatusCode::BAD_GATEWAY, true),
    }
}
