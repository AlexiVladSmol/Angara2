//! Angara proxy core library.
//!
//! The crate contains the HTTP/1.1 forward proxy, CONNECT tunneling, HTTPS
//! listeners, Basic authentication, the outbound policy/DNS/egress pipeline,
//! the bounded in-memory HTTP cache, and the M07 operational layer: atomic
//! snapshots, typed reload/control, bounded JSON logging and fixed metrics.
//! M11 adds the local JSONL control API, the privileged file writer and the
//! Ratatui terminal panel. No TCP administration listener is exposed.

pub mod auth;
pub mod cache;
pub mod cli;
pub mod config;
pub mod connections;
pub mod control;
pub mod control_edit;
pub mod control_files;
pub mod control_protocol;
pub mod control_server;
pub mod control_write;
pub mod http;
pub mod limits;
pub mod logging;
pub mod outbound;
pub mod parent;
pub mod policy;
pub mod resolver;
pub mod routing;
pub mod runtime;
pub mod snapshot;
pub mod target;
pub mod telemetry;
mod tls;
pub mod transport;
pub mod tui;
pub mod version;
