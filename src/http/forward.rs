//! One HTTP/1.1 forwarding transaction.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
use crate::config::Config;
use crate::http::ResponseBody;
use crate::http::connect::TunnelSetup;
use crate::http::headers;
use crate::http::interim::InterimSender;
use crate::http::pool::{
    Lease, LeaseRequestBody, LeaseResponseBody, OriginPool, PoolBody, PooledSender,
};
use crate::limits::CapController;
use crate::logging::{Event, LogRecord, Logger, Outcome, Reason};
use crate::outbound::{OutboundError, OutboundService, RequestContext};
use crate::policy::{self, RequestMeta};
use crate::snapshot::SnapshotStore;
use crate::target::{self, CanonicalTarget, TargetError};
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

/// Immutable terminal metadata for one HTTP exchange.
#[derive(Clone, Debug)]
pub struct ExchangeMeta {
    generation: u64,
    started: tokio::time::Instant,
    connection_id: u64,
    request_id: u64,
    listener_id: String,
    status: StatusCode,
    request_body_bytes: Arc<AtomicU64>,
}

impl ExchangeMeta {
    /// Generation captured before source/auth/policy checks.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Terminal HTTP status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Observed request DATA bytes at terminal time.
    pub fn request_body_bytes(&self) -> u64 {
        self.request_body_bytes.load(Ordering::Relaxed)
    }
}

/// HTTP proxy state shared by all listeners.
pub struct Proxy {
    snapshots: Arc<SnapshotStore>,
    outbound: OutboundService,
    pool: Arc<OriginPool>,
    origin_tasks: Arc<crate::http::OriginTasks>,
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
        Arc::new(Self {
            snapshots,
            outbound,
            pool,
            origin_tasks: crate::http::OriginTasks::new(),
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
    }

    /// Removes expired idle origin sockets.
    pub fn purge_pool(&self) {
        self.pool.purge_expired();
    }

    /// Retires idle origins from older generations after a successful publish.
    pub fn retire_before(&self, generation: u64) {
        self.pool.retire_before(generation);
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
    ) -> Result<(Response<ResponseBody>, TunnelSetup), Response<ResponseBody>> {
        let error = |status: StatusCode| headers::error_response(status, true);
        if self.is_draining() {
            return Err(error(StatusCode::SERVICE_UNAVAILABLE));
        }
        let snapshot = self.snapshots.load();
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
        if headers::via_has_angara(request.headers()) {
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
        let origin = match self.outbound.open_plan_with(config, &plan).await {
            Ok(origin) => origin,
            Err(outbound_error) => {
                let (status, close) = outbound_status(outbound_error);
                return Err(headers::error_response(status, close));
            }
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
            deadline: tokio::time::Instant::now() + config.limits().idle_timeout(),
            idle_timeout: config.limits().idle_timeout(),
            half_close_timeout: config.connect().half_close_timeout(),
            gauge: crate::http::connect::TunnelGauge::new(Arc::clone(&self.telemetry)),
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
        let mut response = if self.is_draining() {
            headers::error_response(StatusCode::SERVICE_UNAVAILABLE, true)
        } else {
            self.handle_inner(
                request,
                client.clone(),
                interim,
                &snapshot,
                Arc::clone(&request_body_bytes),
            )
            .await
        };
        let meta = ExchangeMeta {
            generation: snapshot.generation(),
            started,
            connection_id: client.connection_id,
            request_id: client.request_id,
            listener_id: client.listener_id.clone(),
            status: response.status(),
            request_body_bytes,
        };
        response.extensions_mut().insert(meta);
        response
    }

    /// Emits exactly one terminal record and metrics update for an exchange.
    pub fn log_exchange(
        &self,
        meta: ExchangeMeta,
        outcome: crate::http::BodyOutcome,
        response_body_bytes: u64,
    ) {
        let status = meta.status;
        match outcome {
            crate::http::BodyOutcome::Cancelled => {
                self.telemetry
                    .http_cancelled
                    .fetch_add(1, Ordering::Relaxed);
            }
            crate::http::BodyOutcome::Success | crate::http::BodyOutcome::Failed => {
                self.telemetry
                    .http_completed
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        if status.is_success() {
            self.telemetry.http_2xx.fetch_add(1, Ordering::Relaxed);
        } else if status.is_redirection() {
            self.telemetry.http_3xx.fetch_add(1, Ordering::Relaxed);
        } else if status.is_client_error() {
            self.telemetry.http_4xx.fetch_add(1, Ordering::Relaxed);
        } else {
            self.telemetry.http_5xx.fetch_add(1, Ordering::Relaxed);
        }
        self.telemetry.observe_http(meta.started.elapsed());
        let outcome = match outcome {
            crate::http::BodyOutcome::Success if status.is_server_error() => Outcome::Failed,
            crate::http::BodyOutcome::Success => Outcome::Success,
            crate::http::BodyOutcome::Failed => Outcome::Failed,
            crate::http::BodyOutcome::Cancelled => Outcome::Cancelled,
        };
        let request_body_bytes = meta.request_body_bytes();
        let mut record = LogRecord::new(Event::RequestFinished);
        record.outcome = Some(outcome);
        record.reason = Some(match outcome {
            Outcome::Success => Reason::Completed,
            Outcome::Cancelled => Reason::ClientClosed,
            _ => Reason::Error,
        });
        record.generation = Some(meta.generation);
        record.connection_id = Some(meta.connection_id);
        record.request_id = Some(meta.request_id);
        record.listener_id = Some(meta.listener_id);
        record.status = Some(status.as_u16());
        record.elapsed_ms =
            Some(u64::try_from(meta.started.elapsed().as_millis()).unwrap_or(u64::MAX));
        record.request_body_bytes = Some(request_body_bytes);
        record.response_body_bytes = Some(response_body_bytes);
        self.logger().log(record);
    }

    async fn handle_inner(
        &self,
        request: Request<Incoming>,
        client: ClientInfo,
        interim: InterimSender,
        snapshot: &Arc<crate::snapshot::RuntimeSnapshot>,
        request_body_bytes: Arc<AtomicU64>,
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
        if headers::via_has_angara(request.headers()) {
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
        headers::append_via(&mut request_headers);

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

        let lease = match self.pool.checkout(&plan) {
            Some(lease) => lease,
            None => match self.open_new_connection(&plan, config).await {
                Ok(lease) => lease,
                Err(error) => {
                    let (status, close) = outbound_status(error);
                    return headers::error_response(status, close);
                }
            },
        };
        if plan.is_expired() {
            lease.abort();
            return headers::error_response(StatusCode::GATEWAY_TIMEOUT, true);
        }

        let body = request.into_body();
        let body_length = body.size_hint().exact();
        if request_had_content_length && let Some(length) = body_length {
            headers::set_content_length(&mut request_headers, length);
        }
        let request_body =
            LeaseRequestBody::new(body, lease.clone(), request_nominations, request_body_bytes)
                .boxed();
        let origin_form = if method == Method::OPTIONS && options_without_path(&target_text) {
            "*"
        } else {
            headers::origin_form(&target)
        };
        let mut upstream_request = Request::new(request_body);
        *upstream_request.method_mut() = method.clone();
        *upstream_request.uri_mut() = origin_form
            .parse()
            .unwrap_or_else(|_| "/".parse().expect("static origin-form"));
        *upstream_request.version_mut() = Version::HTTP_11;
        *upstream_request.headers_mut() = request_headers;

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
                if response.status() == StatusCode::SWITCHING_PROTOCOLS
                    || response.status().is_informational()
                {
                    lease.abort();
                    return headers::error_response(StatusCode::BAD_GATEWAY, true);
                }
                if headers::validate_framing(response.headers()).is_err() {
                    lease.abort();
                    return headers::error_response(StatusCode::BAD_GATEWAY, true);
                }
                let original_headers = response.headers().clone();
                let mut response_headers = original_headers.clone();
                let response_nominations =
                    match headers::filter_hop_by_hop(&mut response_headers, false) {
                        Ok(names) => names,
                        Err(()) => {
                            lease.abort();
                            return headers::error_response(StatusCode::BAD_GATEWAY, true);
                        }
                    };
                let response_trailer_names =
                    match headers::trailer_names(&original_headers, &response_nominations) {
                        Ok(names) => names,
                        Err(()) => {
                            lease.abort();
                            return headers::error_response(StatusCode::BAD_GATEWAY, true);
                        }
                    };
                let response_trailer_nominated =
                    response_nominations.contains(&http::header::TRAILER);
                headers::append_via(&mut response_headers);
                if request_chunked {
                    // Hyper normalizes CL+TE to TE before the service runs.
                    // M03 keeps the conservative safe outcome: a chunked
                    // request closes the client connection after the response.
                    response_headers.insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                }
                let status = response.status();
                let response_body = response.into_body();
                let body_length = response_body.size_hint().exact();
                if headers::response_has_body(&method, status) {
                    if let Some(length) = body_length {
                        headers::set_content_length(&mut response_headers, length);
                    } else if !response_trailer_nominated {
                        headers::set_trailer_names(&mut response_headers, &response_trailer_names);
                    }
                } else if status != StatusCode::NO_CONTENT {
                    headers::keep_representation_length(&mut response_headers, &original_headers);
                }
                let body =
                    LeaseResponseBody::new(response_body, lease, response_nominations).boxed();
                let mut local = Response::new(body);
                *local.status_mut() = status;
                *local.version_mut() = Version::HTTP_11;
                *local.headers_mut() = response_headers;
                local
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
        OutboundError::RouteInvalid => (StatusCode::INTERNAL_SERVER_ERROR, true),
        OutboundError::DnsFailed
        | OutboundError::DnsNoAddresses
        | OutboundError::DnsTooManyAddresses
        | OutboundError::ConnectFailed
        | OutboundError::BindFailed
        | OutboundError::NoCompatibleAddress
        | OutboundError::Cancelled => (StatusCode::BAD_GATEWAY, true),
    }
}
