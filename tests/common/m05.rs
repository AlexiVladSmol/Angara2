//! M05 authentication test helpers.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use angara::auth::{
    Argon2Verifier, PasswordVerifier, VerifyError, hash_password, prepare_password,
};
use angara::config::Config;
use angara::http::HttpServer;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::common::TempDir;

/// Deterministic Argon2id PHC for synthetic test passwords.
pub fn hash(password: &str) -> String {
    let password = prepare_password(password).expect("valid test password");
    hash_password(&password, &[0x42; 16]).expect("test hash")
}

/// Builds a users TOML document.
pub fn users_text(entries: &[(&str, &str, bool)]) -> String {
    let mut text = String::from("version = 1\n");
    if entries.is_empty() {
        text.push_str("users = []\n");
    }
    for (username, password_hash, disabled) in entries {
        text.push_str(&format!(
            "\n[[users]]\nusername = \"{username}\"\npassword_hash = \"{password_hash}\"\ndisabled = {disabled}\n"
        ));
    }
    text
}

/// Writes a file and restricts it to 0600 on Unix.
pub fn write_secure(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
}

/// Writes users and returns the path.
pub fn write_users(dir: &TempDir, entries: &[(&str, &str, bool)]) -> PathBuf {
    let path = dir.path().join("users.toml");
    write_secure(&path, &users_text(entries));
    path
}

/// Configuration builder for Basic-auth listeners.
pub struct AuthConfig {
    pub users_file: String,
    pub max_verifying: u32,
    pub verify_timeout_ms: u64,
    pub worker_threads: u32,
    pub shutdown_timeout_ms: u64,
    pub listeners: String,
    pub access: String,
    pub extra: String,
    pub connect_allowed_ports: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            users_file: "users.toml".to_owned(),
            max_verifying: 2,
            verify_timeout_ms: 30_000,
            worker_threads: 2,
            shutdown_timeout_ms: 2_000,
            listeners: r#"
[[listeners]]
id = "proxy"
bind = "127.0.0.1:3128"
transport = "http"
auth = "basic"
"#
            .to_owned(),
            access: r#"
[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8", "::1/128"]
allow_special = true
"#
            .to_owned(),
            extra: String::new(),
            connect_allowed_ports: "443".to_owned(),
        }
    }
}

impl AuthConfig {
    pub fn render(&self) -> String {
        format!(
            r#"
schema_version = 1

[runtime]
worker_threads = {}

[limits]
max_connections = 256
max_client_connections = 64
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = {}

[auth]
users_file = "{}"
max_verifying = {}
verify_timeout_ms = {}

{}

[transport]
total_timeout_ms = 5000
connect_timeout_ms = 2000
max_connect_attempts = 2
max_connecting = 16

[http]
max_headers = 64
response_header_timeout_ms = 5000
pool_max_idle = 8
pool_max_idle_per_key = 2
pool_idle_timeout_ms = 4000

[connect]
allowed_ports = [{}]
half_close_timeout_ms = 1000

{}
{}
"#,
            self.worker_threads,
            self.shutdown_timeout_ms,
            self.users_file,
            self.max_verifying,
            self.verify_timeout_ms,
            self.listeners,
            self.connect_allowed_ports,
            self.access,
            self.extra,
        )
    }

    pub fn write(&self, dir: &TempDir) -> PathBuf {
        let path = dir.path().join("proxy.toml");
        write_secure(&path, &self.render());
        path
    }
}

/// Loads a configuration and binds all listeners on ephemeral ports.
pub async fn start(config_path: &Path) -> (HttpServer, Vec<(String, std::net::SocketAddr)>) {
    let config = Arc::new(Config::load(config_path).expect("valid auth config"));
    let server = HttpServer::bind_ephemeral(config)
        .await
        .expect("bind ephemeral proxy");
    let addresses = server.addresses().to_vec();
    (server, addresses)
}

/// Binds with one injected password verifier.
pub async fn start_with_verifier(
    config_path: &Path,
    verifier: Arc<dyn PasswordVerifier>,
) -> (HttpServer, Vec<(String, std::net::SocketAddr)>) {
    let config = Arc::new(Config::load(config_path).expect("valid auth config"));
    let server = HttpServer::bind_ephemeral_with_verifier(config, verifier)
        .await
        .expect("bind ephemeral proxy");
    let addresses = server.addresses().to_vec();
    (server, addresses)
}

/// One listener address by id.
pub fn address(addresses: &[(String, std::net::SocketAddr)], id: &str) -> std::net::SocketAddr {
    addresses
        .iter()
        .find(|(listener, _)| listener == id)
        .map(|(_, address)| *address)
        .expect("listener address")
}

/// Basic `Proxy-Authorization` value.
pub fn authorization(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

/// Absolute-form GET with optional Basic credentials.
pub fn get_request(
    target: std::net::SocketAddr,
    auth: Option<(&str, &str)>,
    headers: &[(&str, &str)],
) -> Vec<u8> {
    let mut all_headers = headers.to_vec();
    let auth_value;
    if let Some((user, password)) = auth {
        auth_value = authorization(user, password);
        all_headers.push(("Proxy-Authorization", auth_value.as_str()));
    }
    crate::common::m03::request("GET", target, "/", &all_headers, b"")
}

/// A verifier with observable concurrency and deterministic results.
pub struct RecordingVerifier {
    state: Arc<VerifierState>,
    delay: Duration,
    result: Result<bool, VerifyError>,
    panic: bool,
    accepted_password: Option<String>,
    first_delay: Option<Duration>,
}

/// Shared verifier observations.
#[derive(Default)]
pub struct VerifierState {
    pub calls: AtomicUsize,
    pub started: AtomicUsize,
    pub finished: AtomicUsize,
    pub running: AtomicUsize,
    pub max_running: AtomicUsize,
    pub phc_inputs: std::sync::Mutex<Vec<String>>,
}

impl VerifierState {
    fn enter(self: &Arc<Self>) -> usize {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.fetch_add(1, Ordering::SeqCst);
        let running = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        let mut observed = self.max_running.load(Ordering::SeqCst);
        while running > observed {
            match self.max_running.compare_exchange(
                observed,
                running,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(value) => observed = value,
            }
        }
        running
    }

    fn leave(&self) {
        self.running.fetch_sub(1, Ordering::SeqCst);
        self.finished.fetch_add(1, Ordering::SeqCst);
    }
}

impl RecordingVerifier {
    pub fn new(
        state: Arc<VerifierState>,
        delay: Duration,
        result: Result<bool, VerifyError>,
    ) -> Self {
        Self {
            state,
            delay,
            result,
            panic: false,
            accepted_password: None,
            first_delay: None,
        }
    }

    pub fn with_first_delay(mut self, delay: Duration) -> Self {
        self.first_delay = Some(delay);
        self
    }

    pub fn accepting(state: Arc<VerifierState>, delay: Duration, password: &str) -> Self {
        Self {
            state,
            delay,
            result: Ok(false),
            panic: false,
            accepted_password: Some(password.to_owned()),
            first_delay: None,
        }
    }

    pub fn panicking(state: Arc<VerifierState>, delay: Duration) -> Self {
        Self {
            state,
            delay,
            result: Err(VerifyError),
            panic: true,
            accepted_password: None,
            first_delay: None,
        }
    }

    pub fn state(&self) -> Arc<VerifierState> {
        Arc::clone(&self.state)
    }
}

impl PasswordVerifier for RecordingVerifier {
    fn verify(&self, phc: &str, password: &str) -> Result<bool, VerifyError> {
        self.state
            .phc_inputs
            .lock()
            .expect("verifier state")
            .push(phc.to_owned());
        self.state.enter();
        let call = self.state.calls.load(Ordering::SeqCst);
        let delay = if call == 1 {
            self.first_delay.unwrap_or(self.delay)
        } else {
            self.delay
        };
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        if self.panic {
            self.state.leave();
            panic!("synthetic verifier panic");
        }
        self.state.leave();
        if let Some(expected) = &self.accepted_password {
            return Ok(password == expected);
        }
        self.result
    }
}

/// Waits until a condition is true, bounded by `timeout`.
pub async fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while !condition() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// Real Argon2id verification of a fixture PHC.
pub fn verify_real(phc: &str, password: &str) -> bool {
    Argon2Verifier.verify(phc, password).expect("real verify")
}

/// Writes stdin to a spawned CLI process and returns its output.
pub fn run_cli(args: &[&str], stdin: Option<&[u8]>) -> std::process::Output {
    use std::process::{Command, Stdio};

    let mut command = Command::new(env!("CARGO_BIN_EXE_angara"));
    command.args(args);
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn angara");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("write stdin");
    }
    child.wait_with_output().expect("wait for angara")
}
