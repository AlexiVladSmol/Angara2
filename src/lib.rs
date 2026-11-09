//! Angara proxy bootstrap library.
//!
//! M01 contains only the CLI, strict configuration validation and a
//! multi-threaded Tokio runtime. No HTTP forwarding, CONNECT, TLS, auth or
//! ACL code exists yet.

pub mod cli;
pub mod config;
pub mod runtime;
