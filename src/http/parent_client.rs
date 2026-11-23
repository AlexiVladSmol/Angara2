//! Parent proxy HTTP/TLS client handshakes.
//!
//! This module owns the Angara -> parent transport only. It never performs a
//! second target DNS lookup and never forwards a client challenge/body from a
//! rejected parent CONNECT.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use http::header::{HOST, PROXY_AUTHORIZATION, VIA};
use http::{Method, Request, StatusCode, Version};
use http_body_util::Empty;
use hyper::client::conn::http1 as client_http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::http::idle::IdleIo;
use crate::outbound::Connected;
use crate::parent::{ParentEndpoint, ParentTransport, PreparedParent};
use crate::target::Host;

/// Object-safe transport used by parent connections and client tunnels.
pub(crate) trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// Boxed parent or tunnel transport. The outbound permit remains inside.
pub(crate) type BoxedIo = Box<dyn AsyncReadWrite + Send + Unpin>;

/// Parent handshake failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParentError {
    /// TLS handshake or certificate/name verification failed.
    Tls,
    /// HTTP/1.1 parent protocol failure.
    Protocol,
    /// Parent rejected CONNECT or returned a non-2xx status.
    Rejected,
    /// Parent response or upgrade deadline elapsed.
    Timeout,
}

impl fmt::Display for ParentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Tls => "parent TLS handshake failed",
            Self::Protocol => "parent HTTP protocol failed",
            Self::Rejected => "parent rejected the request",
            Self::Timeout => "parent response timed out",
        })
    }
}

impl std::error::Error for ParentError {}

impl ParentError {
    /// Client-facing status before any response body was forwarded.
    pub(crate) fn status(self) -> StatusCode {
        match self {
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Tls | Self::Protocol | Self::Rejected => StatusCode::BAD_GATEWAY,
        }
    }
}

/// Wraps a connected parent socket with optional TLS and idle enforcement.
pub(crate) async fn connect_io(
    connected: Connected,
    parent: &PreparedParent,
    idle_timeout: Duration,
    deadline: Instant,
) -> Result<BoxedIo, ParentError> {
    match parent.transport() {
        ParentTransport::Http => Ok(Box::new(IdleIo::new(connected, idle_timeout))),
        ParentTransport::Https => {
            let config = parent.tls_config().ok_or(ParentError::Tls)?;
            let name = server_name(parent.endpoint())?;
            let connector = TlsConnector::from(config);
            let stream = tokio::time::timeout_at(deadline, connector.connect(name, connected))
                .await
                .map_err(|_| ParentError::Timeout)?
                .map_err(|_| ParentError::Tls)?;
            Ok(Box::new(IdleIo::new(stream, idle_timeout)))
        }
    }
}

/// Sends one CONNECT to the parent and returns the upgraded origin stream.
///
/// `incoming_via` is the chain received from the client or the request being
/// forwarded. It is preserved in order and this instance's token is appended
/// last, so a parent running Angara can reject the returning identifier before
/// another dial.
pub(crate) async fn open_tunnel(
    io: BoxedIo,
    parent: &PreparedParent,
    target: SocketAddr,
    instance_id: &str,
    incoming_via: &[http::HeaderValue],
    response_timeout: Duration,
    deadline: Instant,
) -> Result<BoxedIo, ParentError> {
    let (mut sender, connection) = client_http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| ParentError::Protocol)?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });

    let authority = connect_authority(target);
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(authority.clone())
        .version(Version::HTTP_11)
        .body(Empty::<bytes::Bytes>::new())
        .map_err(|_| ParentError::Protocol)?;
    request.headers_mut().insert(
        HOST,
        http::HeaderValue::from_str(&authority).map_err(|_| ParentError::Protocol)?,
    );
    if let Some(authorization) = parent.authorization() {
        request
            .headers_mut()
            .insert(PROXY_AUTHORIZATION, authorization);
    }
    for value in incoming_via {
        request.headers_mut().append(VIA, value.clone());
    }
    let via = format!("1.1 angara-{instance_id}");
    request.headers_mut().append(
        VIA,
        http::HeaderValue::from_str(&via).expect("validated instance id"),
    );

    let now = Instant::now();
    let remaining = deadline
        .saturating_duration_since(now)
        .min(response_timeout);
    if remaining.is_zero() {
        connection_task.abort();
        return Err(ParentError::Timeout);
    }
    match tokio::time::timeout(remaining, sender.ready()).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            connection_task.abort();
            return Err(ParentError::Protocol);
        }
        Err(_) => {
            connection_task.abort();
            return Err(ParentError::Timeout);
        }
    }
    let response = match tokio::time::timeout(remaining, sender.send_request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => {
            connection_task.abort();
            return Err(ParentError::Protocol);
        }
        Err(_) => {
            connection_task.abort();
            return Err(ParentError::Timeout);
        }
    };
    if !response.status().is_success() {
        connection_task.abort();
        return Err(ParentError::Rejected);
    }

    let now = Instant::now();
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        connection_task.abort();
        return Err(ParentError::Timeout);
    }
    let upgraded = match tokio::time::timeout(remaining, hyper::upgrade::on(response)).await {
        Ok(Ok(upgraded)) => upgraded,
        Ok(Err(_)) => {
            connection_task.abort();
            return Err(ParentError::Protocol);
        }
        Err(_) => {
            connection_task.abort();
            return Err(ParentError::Timeout);
        }
    };
    // The connection task hands the socket to the upgrade and finishes. Drop
    // the handle without aborting; the upgraded stream owns the IO now.
    drop(connection_task);
    Ok(Box::new(TokioIo::new(upgraded)))
}

/// Formats a verified target as a CONNECT authority.
pub(crate) fn connect_authority(target: SocketAddr) -> String {
    match target {
        SocketAddr::V4(address) => format!("{}:{}", address.ip(), address.port()),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    }
}

fn server_name(endpoint: &ParentEndpoint) -> Result<ServerName<'static>, ParentError> {
    match endpoint.host() {
        Host::Domain(domain) => {
            ServerName::try_from(domain.as_str().to_owned()).map_err(|_| ParentError::Tls)
        }
        Host::Ip(IpAddr::V4(ip)) => Ok(ServerName::IpAddress((*ip).into())),
        Host::Ip(IpAddr::V6(ip)) => Ok(ServerName::IpAddress((*ip).into())),
    }
}
