//! Angara proxy core library.
//!
//! M03 adds the HTTP/1.1 forward proxy: listeners, strict HTTP framing and
//! header conversion, streaming bodies, Expect/1xx, trailers, a bounded origin
//! connection pool and controlled shutdown. CONNECT, TLS and auth are later
//! stages.

pub mod auth;
pub mod cli;
pub mod config;
pub mod http;
pub mod outbound;
pub mod policy;
pub mod resolver;
pub mod routing;
pub mod runtime;
pub mod target;
mod tls;
pub mod transport;
