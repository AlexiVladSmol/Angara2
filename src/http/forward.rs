//! One HTTP/1.1 forwarding transaction.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use http::header::{CONTENT_LENGTH, HOST};
use http::{Method, Request, Response, StatusCode, Version};
use http_body::Body as _;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper_util::rt::TokioIo;

use crate::config::Config;
use crate::http::ResponseBody;
use crate::http::headers;
use crate::http::interim::InterimSender;
use crate::http::pool::{
    Lease, LeaseRequestBody, LeaseResponseBody, OriginPool, PoolBody, PooledSender,
};
use crate::outbound::{OutboundError, OutboundService, RequestContext};
use crate::policy::{self, RequestMeta};
use crate::target::{self, CanonicalTarget, TargetError};

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
}

/// HTTP proxy state shared by all listeners.
pub struct Proxy {
    config: Arc<Config>,
    outbound: OutboundService,
    pool: Arc<OriginPool>,
    draining: Arc<AtomicBool>,
}

impl Proxy {
    /// Builds proxy state.
    pub fn new(config: Arc<Config>) -> Arc<Self> {
        let outbound = OutboundService::new(Arc::clone(&config));
        let pool = OriginPool::new(&config);
        Arc::new(Self {
            config,
            outbound,
            pool,
            draining: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Builds proxy state with injected resolver and dialer for library tests.
    #[doc(hidden)]
    pub fn with_components(
        config: Arc<Config>,
        resolver: Arc<dyn crate::resolver::Resolver>,
        dialer: Arc<dyn crate::transport::Dialer>,
    ) -> Arc<Self> {
        let outbound = OutboundService::with_components(Arc::clone(&config), resolver, dialer);
        let pool = OriginPool::new(&config);
        Arc::new(Self {
            config,
            outbound,
            pool,
            draining: Arc::new(AtomicBool::new(false)),
        })
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

    /// Whether new exchanges must be refused.
    fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Handles one client request. All failures before final headers become
    /// bounded local responses; failures after headers are surfaced as body
    /// errors so the server closes/evicts the exchange.
    pub async fn handle(
        &self,
        request: Request<Incoming>,
        client: ClientInfo,
        interim: InterimSender,
    ) -> Response<ResponseBody> {
        if self.is_draining() {
            return headers::error_response(StatusCode::SERVICE_UNAVAILABLE, true);
        }
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

        if method == Method::CONNECT {
            return match CanonicalTarget::parse(&method, &uri.to_string()) {
                Ok(_) => headers::error_response(StatusCode::NOT_IMPLEMENTED, true),
                Err(_) => headers::error_response(StatusCode::BAD_REQUEST, true),
            };
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
        let target_text = uri.to_string();
        let target = match CanonicalTarget::parse(&method, &target_text) {
            Ok(target) => target,
            Err(error) => return headers::error_response(target_status(error), true),
        };
        if target::check_host_header(&target, host_header).is_err() {
            return headers::error_response(StatusCode::BAD_REQUEST, true);
        }

        let expect_continue = match headers::expect_continue(request.headers()) {
            Ok(value) => value,
            Err(()) => return headers::error_response(StatusCode::EXPECTATION_FAILED, true),
        };
        let request_had_content_length = request.headers().contains_key(CONTENT_LENGTH);
        let request_trailer_names = match headers::trailer_names(request.headers()) {
            Ok(names) => names,
            Err(()) => return headers::error_response(StatusCode::BAD_REQUEST, true),
        };
        let request_accepts_trailers = headers::accepts_trailers(request.headers());
        let request_trailer_nominated = headers::is_nominated(request.headers(), "trailer");
        let request_te_nominated = headers::is_nominated(request.headers(), "te");
        let max_forwards = if method == Method::OPTIONS {
            match headers::max_forwards(request.headers()) {
                Ok(value) => value,
                Err(()) => return headers::error_response(StatusCode::BAD_REQUEST, true),
            }
        } else {
            None
        };

        let context = RequestContext::new(client.peer, client.listener_id.clone());
        let meta = RequestMeta {
            listener_id: &client.listener_id,
            source: client.peer,
            method: &method,
            target: &target,
        };
        if policy::check_source(self.config.access(), client.peer).is_err() {
            return headers::error_response(StatusCode::FORBIDDEN, true);
        }
        if policy::check_request(self.config.access(), &meta).is_err() {
            return headers::error_response(StatusCode::FORBIDDEN, true);
        }
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
        if headers::filter_hop_by_hop(&mut request_headers, true).is_err() {
            return headers::error_response(StatusCode::BAD_REQUEST, true);
        }
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
            .prepare_outbound(&context, &method, &target_text, host_header)
            .await
        {
            Ok(plan) => plan,
            Err(error) => {
                let (status, close) = outbound_status(error);
                return headers::error_response(status, close);
            }
        };

        let lease = match self.pool.checkout(&plan) {
            Some(lease) => lease,
            None => match self.open_new_connection(&plan).await {
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

        if expect_continue && !interim.send_continue() {
            lease.abort();
            return headers::error_response(StatusCode::BAD_GATEWAY, true);
        }

        let body = request.into_body();
        let body_length = body.size_hint().exact();
        if request_had_content_length && let Some(length) = body_length {
            headers::set_content_length(&mut request_headers, length);
        }
        let request_body = LeaseRequestBody::new(body, lease.clone()).boxed();
        let origin_form = if method == Method::OPTIONS && uri.path() == "/" && uri.query().is_none()
        {
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
        let response_timeout = self.config.http().response_header_timeout();
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
                let response_trailer_names = match headers::trailer_names(&original_headers) {
                    Ok(names) => names,
                    Err(()) => {
                        lease.abort();
                        return headers::error_response(StatusCode::BAD_GATEWAY, true);
                    }
                };
                let response_trailer_nominated =
                    headers::is_nominated(&original_headers, "trailer");
                let mut response_headers = original_headers.clone();
                if headers::filter_hop_by_hop(&mut response_headers, false).is_err() {
                    lease.abort();
                    return headers::error_response(StatusCode::BAD_GATEWAY, true);
                }
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
                let body = LeaseResponseBody::new(response_body, lease).boxed();
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
    ) -> Result<Lease, OutboundError> {
        let connected = self.outbound.open_plan(plan).await?;
        let endpoint = connected.endpoint().endpoint();
        let stream = crate::http::idle::IdleIo::new(connected, self.config.limits().idle_timeout());
        let handshake = client_http1::Builder::new()
            .max_headers(self.config.http().max_headers())
            .max_header_size(self.config.limits().max_header_bytes() as usize)
            .max_buf_size(connection_buffer_size(&self.config))
            .handshake::<_, PoolBody>(TokioIo::new(stream))
            .await;
        let (sender, connection) = match handshake {
            Ok(pair) => pair,
            Err(_) => return Err(OutboundError::ConnectFailed),
        };
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(self
            .pool
            .new_lease(plan, endpoint, PooledSender::new(sender, task)))
    }
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
