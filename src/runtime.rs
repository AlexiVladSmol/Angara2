//! Multi-threaded Tokio runtime setup and controlled shutdown.
//!
//! M01 intentionally builds the runtime without I/O or timer drivers. Network
//! and time features are added by the milestones that actually use them; the
//! absence here keeps the bootstrap runtime from opening any network resource.

use std::fmt;
use std::future::Future;
use std::io;
use std::time::Duration;

use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;

use crate::config::Config;

/// A runtime that could not be built.
#[derive(Debug)]
pub struct RuntimeError {
    source: io::Error,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cannot build Tokio runtime: {}", self.source)
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// A built Angara runtime with a bounded shutdown.
///
/// Dropping the value also performs the configured bounded shutdown, so an
/// early return cannot leave an unbounded Tokio shutdown behind.
pub struct AngaraRuntime {
    runtime: Option<Runtime>,
    worker_threads: usize,
    shutdown_timeout: Duration,
}

impl AngaraRuntime {
    /// Builds a multi-threaded runtime according to `config`.
    pub fn build(config: &Config) -> Result<Self, RuntimeError> {
        let worker_threads = config.runtime().worker_threads().resolve();
        let runtime = Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .thread_name("angara-worker")
            .build()
            .map_err(|source| RuntimeError { source })?;

        Ok(Self {
            runtime: Some(runtime),
            worker_threads,
            shutdown_timeout: config.limits().shutdown_timeout(),
        })
    }

    /// The number of worker threads requested when the runtime was built.
    pub fn worker_threads(&self) -> usize {
        self.worker_threads
    }

    /// The number of worker threads reported by Tokio's public metrics API.
    pub fn metrics_worker_threads(&self) -> usize {
        self.runtime().metrics().num_workers()
    }

    /// The underlying Tokio runtime.
    pub fn runtime(&self) -> &Runtime {
        self.runtime
            .as_ref()
            .expect("runtime is present until AngaraRuntime::shutdown")
    }

    /// Runs a future to completion on this runtime.
    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.runtime().block_on(future)
    }

    /// Spawns a task on this runtime.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.runtime().spawn(future)
    }

    /// Stops the runtime, waiting at most the configured shutdown timeout.
    pub fn shutdown(mut self) {
        self.shutdown_inner();
    }

    fn shutdown_inner(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(self.shutdown_timeout);
        }
    }
}

impl Drop for AngaraRuntime {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}
