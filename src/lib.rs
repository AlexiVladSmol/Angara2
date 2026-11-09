//! Angara proxy core library.
//!
//! M02 contains the CLI, strict configuration, canonical targets, source/ACL
//! policy, bounded system DNS, egress routing and checked TCP connect. No HTTP
//! forwarding, CONNECT tunnel, TLS or auth code exists yet.

pub mod cli;
pub mod config;
pub mod outbound;
pub mod policy;
pub mod resolver;
pub mod routing;
pub mod runtime;
pub mod target;
pub mod transport;
