//! Shared test helpers.
//!
//! Every integration test binary compiles this module separately, so unused
//! helpers are expected in some binaries.

#![allow(dead_code)]

pub mod m03;
pub mod m04;
pub mod m05;
pub mod m06;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A temporary directory removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a unique temporary directory.
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "angara-{tag}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create temporary directory");
        Self { path }
    }

    /// Directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes a UTF-8 file and returns its path.
    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path.join(name);
        fs::write(&path, contents).expect("write temporary file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A minimal valid listener definition.
pub const ONE_LISTENER: &str = r#"
[[listeners]]
id = "loopback"
bind = "127.0.0.1:3128"
transport = "http"
"#;

/// Two valid listeners in different address families.
pub const TWO_LISTENERS: &str = r#"
[[listeners]]
id = "loopback-v4"
bind = "127.0.0.1:3128"
transport = "http"

[[listeners]]
id = "loopback-v6"
bind = "[::1]:3128"
transport = "http"
"#;

/// Builds a valid configuration around the supplied listener text and worker
/// policy (the policy must already be a TOML value).
pub fn config_with(listeners: &str, workers: &str) -> String {
    format!(
        r#"
schema_version = 1

[runtime]
worker_threads = {workers}

[limits]
max_connections = 256
max_header_bytes = 32768
header_read_timeout_ms = 10000
idle_timeout_ms = 60000
shutdown_timeout_ms = 10000
{listeners}
"#
    )
}

/// Builds a valid configuration with one listener and the supplied worker
/// policy.
pub fn config(workers: &str) -> String {
    config_with(ONE_LISTENER, workers)
}
