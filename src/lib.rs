//! Angara proxy core library.
//!
//! The crate contains the HTTP/1.1 forward proxy, CONNECT tunneling, HTTPS
//! listeners, Basic authentication, the outbound policy/DNS/egress pipeline,
//! and the M07 operational layer: atomic snapshots, typed reload/control,
//! bounded JSON logging and fixed metrics. Network administration is not part
//! of this milestone.

pub mod auth;
pub mod cli;
pub mod config;
pub mod control;
pub mod http;
pub mod limits;
pub mod logging;
pub mod outbound;
pub mod policy;
pub mod resolver;
pub mod routing;
pub mod runtime;
pub mod snapshot;
pub mod target;
pub mod telemetry;
mod tls;
pub mod transport;
