//! TCP connect with the selected egress profile.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use tokio::net::{TcpSocket, TcpStream};

use crate::config::{EgressMode, EgressProfile};

/// Future returned by [`Dialer::connect`].
pub type DialFuture<'a> = Pin<Box<dyn Future<Output = Result<TcpStream, DialError>> + Send + 'a>>;

/// Dial failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialError {
    /// Binding the selected source IP failed.
    BindFailed,
    /// Connect attempt deadline elapsed.
    ConnectTimeout,
    /// Connect failed (refused, unreachable, reset, socket setup).
    ConnectFailed,
    /// Egress bind IP and destination address families differ.
    NoCompatibleAddress,
    /// Explicit cancellation.
    Cancelled,
}

impl fmt::Display for DialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BindFailed => "binding the outbound source address failed",
            Self::ConnectTimeout => "connect attempt timed out",
            Self::ConnectFailed => "connect failed",
            Self::NoCompatibleAddress => "no compatible address family for egress",
            Self::Cancelled => "connect was cancelled",
        })
    }
}

impl std::error::Error for DialError {}

/// Transport abstraction used by the outbound pipeline.
///
/// Implementations receive only a checked [`SocketAddr`] and the already
/// selected egress profile; there is no hostname and no second DNS lookup.
pub trait Dialer: Send + Sync {
    /// Connects to one checked address before the attempt deadline.
    fn connect<'a>(
        &'a self,
        endpoint: SocketAddr,
        egress: &'a EgressProfile,
        deadline: Instant,
    ) -> DialFuture<'a>;
}

/// Real Tokio TCP dialer.
#[derive(Debug, Default, Clone, Copy)]
pub struct TcpDialer;

impl Dialer for TcpDialer {
    fn connect<'a>(
        &'a self,
        endpoint: SocketAddr,
        egress: &'a EgressProfile,
        deadline: Instant,
    ) -> DialFuture<'a> {
        Box::pin(async move {
            let socket = match egress.mode() {
                EgressMode::System => new_socket(endpoint)?,
                EgressMode::BindIp(bind_ip) => {
                    if bind_ip.is_ipv4() != endpoint.is_ipv4() {
                        return Err(DialError::NoCompatibleAddress);
                    }
                    let socket = new_socket(endpoint)?;
                    socket
                        .bind(SocketAddr::new(*bind_ip, 0))
                        .map_err(|_| DialError::BindFailed)?;
                    socket
                }
            };

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(DialError::ConnectTimeout);
            }
            match tokio::time::timeout(remaining, socket.connect(endpoint)).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(_)) => Err(DialError::ConnectFailed),
                Err(_) => Err(DialError::ConnectTimeout),
            }
        })
    }
}

fn new_socket(endpoint: SocketAddr) -> Result<TcpSocket, DialError> {
    if endpoint.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|_| DialError::ConnectFailed)
}
