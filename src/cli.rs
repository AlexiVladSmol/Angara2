//! Command-line interface.
//!
//! The M01 command surface is intentionally small and fixed, so it is parsed
//! directly without a CLI framework. Unknown commands and options are rejected
//! with exit code 2 and are not echoed, which keeps accidental secrets out of
//! diagnostics.

use std::ffi::OsString;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::sync::Arc;

use crate::auth;
use crate::config::Config;
use crate::control::{ControlState, ReloadOutcome};
use crate::http::HttpServer;
use crate::logging::{Event, LogRecord, Logger, Outcome, spawn_stderr_worker};
use crate::runtime::AngaraRuntime;

/// Successful command.
pub const EXIT_OK: u8 = 0;
/// Configuration could not be read, parsed or validated.
pub const EXIT_CONFIG_ERROR: u8 = 1;
/// Command-line usage error.
pub const EXIT_USAGE: u8 = 2;
/// Server startup or unexpected server failure.
pub const EXIT_SERVER_ERROR: u8 = 3;

const USAGE: &str = "\
Usage:
  angara --version
  angara check --config <path>
  angara serve --config <path> [--control-read-socket <path>]
  angara control-write --config <path> [--socket <path>] [--read-socket <path>]
  angara tui [--socket <path>]
  angara users hash [--password-stdin]
  angara --help";

const HELP: &str = "\
Angara proxy

Usage:
  angara --version
  angara check --config <path>
  angara serve --config <path> [--control-read-socket <path>]
  angara control-write --config <path> [--socket <path>] [--read-socket <path>]
  angara tui [--socket <path>]
  angara users hash [--password-stdin]
  angara --help

Commands:
  check --config <path>       Validate the configuration without network access.
  serve --config <path>       Bind all listeners and run the HTTP/1.1 proxy
                              (HTTP and HTTPS ingress).
  control-write               Run the privileged local control writer.
  tui                         Open the terminal control panel.
  users hash                  Read a password from the terminal without echo.
  users hash --password-stdin Read exactly one password line from stdin.
  --version                   Print the version and stop.
  --help                      Print this help and stop.

The password is never accepted through argv or an environment variable.
Success prints one Argon2id PHC string to stdout. Without a terminal,
`users hash` exits with code 2 and asks for the explicit --password-stdin mode.

Exit codes:
  0  success
  1  password input, hashing or local file error
  2  command-line usage error
  3  server startup or unexpected server failure";

/// Runs the CLI and returns the process exit code.
pub fn run<I>(args: I) -> u8
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let _program = args.next();

    let Some(command) = args.next() else {
        return usage_error("команда не указана");
    };

    match command.to_str() {
        Some("--version") | Some("-V") => {
            if args.next().is_some() {
                return usage_error("--version не принимает аргументов");
            }
            println!("angara {}", env!("CARGO_PKG_VERSION"));
            EXIT_OK
        }
        Some("--help") | Some("-h") => {
            if args.next().is_some() {
                return usage_error("--help не принимает аргументов");
            }
            println!("{HELP}");
            EXIT_OK
        }
        Some("check") => run_config_command(Mode::Check, args),
        Some("serve") => run_config_command(Mode::Serve, args),
        Some("control-write") => run_control_write(args),
        Some("tui") => run_tui(args),
        Some("users") => run_users(args),
        _ => usage_error("неизвестная команда или аргумент"),
    }
}

const USERS_USAGE: &str = "\
Usage:
  angara users hash [--password-stdin]";

fn run_users<I>(args: I) -> u8
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return users_usage_error("не указана подкоманда users");
    };
    match command.to_str() {
        Some("hash") => run_users_hash(args),
        Some("--help") | Some("-h") => {
            if args.next().is_some() {
                return users_usage_error("users --help не принимает аргументов");
            }
            println!("{USERS_USAGE}");
            EXIT_OK
        }
        _ => users_usage_error("неизвестная подкоманда users"),
    }
}

fn run_users_hash<I>(args: I) -> u8
where
    I: IntoIterator<Item = OsString>,
{
    let mut password_stdin = false;
    for argument in args {
        match argument.to_str() {
            Some("--password-stdin") if !password_stdin => password_stdin = true,
            Some("--help") | Some("-h") => {
                println!("{USERS_USAGE}");
                return EXIT_OK;
            }
            _ => return users_usage_error("неподдерживаемый аргумент users hash"),
        }
    }

    let password = if password_stdin {
        match read_password_stdin() {
            Ok(password) => password,
            Err(error) => {
                eprintln!("error: {error}");
                return EXIT_CONFIG_ERROR;
            }
        }
    } else {
        if !std::io::stdin().is_terminal() {
            eprintln!("error: stdin is not a terminal; use `angara users hash --password-stdin`");
            return EXIT_USAGE;
        }
        let first = match rpassword::prompt_password("Password: ") {
            Ok(password) => zeroize::Zeroizing::new(password),
            Err(_) => {
                eprintln!("error: cannot read the password from the terminal");
                return EXIT_CONFIG_ERROR;
            }
        };
        let confirmation = match rpassword::prompt_password("Confirm password: ") {
            Ok(password) => zeroize::Zeroizing::new(password),
            Err(_) => {
                eprintln!("error: cannot read the password confirmation from the terminal");
                return EXIT_CONFIG_ERROR;
            }
        };
        let first = match auth::prepare_password(first.as_str()) {
            Ok(password) => password,
            Err(error) => {
                eprintln!("error: {error}");
                return EXIT_CONFIG_ERROR;
            }
        };
        let confirmation = match auth::prepare_password(confirmation.as_str()) {
            Ok(password) => password,
            Err(error) => {
                eprintln!("error: {error}");
                return EXIT_CONFIG_ERROR;
            }
        };
        if first.as_str() != confirmation.as_str() {
            eprintln!("error: password confirmation does not match");
            return EXIT_CONFIG_ERROR;
        }
        first
    };

    let salt = match auth::generate_salt() {
        Ok(salt) => salt,
        Err(error) => {
            eprintln!("error: {error}");
            return EXIT_CONFIG_ERROR;
        }
    };
    match auth::hash_password(password.as_str(), &salt) {
        Ok(phc) => {
            println!("{phc}");
            EXIT_OK
        }
        Err(error) => {
            eprintln!("error: {error}");
            EXIT_CONFIG_ERROR
        }
    }
}

fn read_password_stdin() -> Result<zeroize::Zeroizing<String>, auth::PasswordInputError> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(1_028)
        .read_to_end(&mut bytes)
        .map_err(|_| auth::PasswordInputError::Read)?;
    auth::parse_password_stdin(&bytes)
}

fn users_usage_error(message: &str) -> u8 {
    eprintln!("error: {message}");
    eprintln!("{USERS_USAGE}");
    EXIT_USAGE
}

#[derive(Clone, Copy)]
enum Mode {
    Check,
    Serve,
}

impl Mode {
    fn usage(self) -> &'static str {
        match self {
            Self::Check => "Usage: angara check --config <path>",
            Self::Serve => "Usage: angara serve --config <path> [--control-read-socket <path>]",
        }
    }
}

fn run_config_command<I>(mode: Mode, args: I) -> u8
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let mut config_path = None;
    let mut control_socket = None;

    while let Some(argument) = args.next() {
        if argument == "--help" || argument == "-h" {
            println!("{}", mode.usage());
            return EXIT_OK;
        }

        if argument == "--config" {
            if config_path.is_some() {
                return usage_error("--config указан повторно");
            }
            let Some(value) = args.next() else {
                return usage_error("после --config требуется путь");
            };
            config_path = Some(PathBuf::from(value));
            continue;
        }

        if let Some(value) = argument
            .to_str()
            .and_then(|value| value.strip_prefix("--config="))
        {
            if config_path.is_some() {
                return usage_error("--config указан повторно");
            }
            config_path = Some(PathBuf::from(value));
            continue;
        }

        if argument == "--control-read-socket" && matches!(mode, Mode::Serve) {
            if control_socket.is_some() {
                return usage_error("--control-read-socket указан повторно");
            }
            let Some(value) = args.next() else {
                return usage_error("после --control-read-socket требуется путь");
            };
            control_socket = Some(PathBuf::from(value));
            continue;
        }

        if let Some(value) = argument
            .to_str()
            .and_then(|value| value.strip_prefix("--control-read-socket="))
            && matches!(mode, Mode::Serve)
        {
            if control_socket.is_some() {
                return usage_error("--control-read-socket указан повторно");
            }
            control_socket = Some(PathBuf::from(value));
            continue;
        }

        return usage_error("неподдерживаемый аргумент команды");
    }

    let Some(path) = config_path else {
        return usage_error("не указан --config");
    };
    let path = std::path::absolute(&path).unwrap_or(path);

    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return EXIT_CONFIG_ERROR;
        }
    };

    match mode {
        Mode::Check => {
            println!(
                "config ok: schema_version={} listeners={} worker_threads={}",
                config.schema_version(),
                config.listeners().len(),
                config.runtime().worker_threads()
            );
            EXIT_OK
        }
        Mode::Serve => {
            let runtime = match AngaraRuntime::build(&config) {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("error: {error}");
                    return EXIT_SERVER_ERROR;
                }
            };
            let observability = config.observability().clone();
            let config = Arc::new(config);
            let result = runtime.block_on(async move {
                let signals = match ShutdownSignals::install() {
                    Ok(signals) => signals,
                    Err(_) => {
                        return Err(crate::http::ServerError::new(
                            "cannot install shutdown signal handlers",
                        ));
                    }
                };
                let server = match control_socket {
                    Some(socket) => {
                        HttpServer::bind_with_path_and_control(config, path, socket).await?
                    }
                    None => HttpServer::bind_with_path(config, path).await?,
                };
                let telemetry = server.telemetry();
                let logger = if observability.log_level() == crate::config::LogLevel::Off {
                    Logger::disabled(telemetry)
                } else {
                    let (logger, receiver) = Logger::channel(
                        observability.log_queue_capacity(),
                        observability.log_level(),
                        telemetry.clone(),
                    );
                    spawn_stderr_worker(receiver, telemetry);
                    logger
                };
                server.set_logger(logger.clone());
                let generation = server.control().status().generation;
                let mut started = LogRecord::new(Event::ServiceStarted);
                started.generation = Some(generation);
                started.listeners = Some(
                    server
                        .addresses()
                        .iter()
                        .map(|(id, address)| format!("{id}={address}"))
                        .collect(),
                );
                logger.log(started);
                let control = server.control();
                let mut driver = ReloadDriver::new(signals, Arc::clone(&control));
                loop {
                    match driver.next().await {
                        DriverEvent::Shutdown => break,
                        DriverEvent::Reload(result) => match result {
                            Ok(outcome) => log_reload(&logger, &outcome),
                            Err(_) => log_reload(&logger, &ReloadOutcome::Internal),
                        },
                    }
                }
                let deadline = std::time::Instant::now() + control.shutdown_timeout();
                logger.log(LogRecord::new(Event::ShutdownStarted));
                server.shutdown_until(deadline).await;
                logger.log(LogRecord::new(Event::ServiceStopped));
                Ok::<std::time::Instant, crate::http::ServerError>(deadline)
            });
            match result {
                Ok(deadline) => {
                    runtime.shutdown_until(deadline);
                    EXIT_OK
                }
                Err(error) => {
                    runtime.shutdown();
                    eprintln!("error: {error}");
                    EXIT_SERVER_ERROR
                }
            }
        }
    }
}

#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
}

#[cfg_attr(not(unix), allow(dead_code))]
enum SignalEvent {
    Shutdown,
    Hangup,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn install() -> std::io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            hangup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
        })
    }

    async fn next(&mut self) -> SignalEvent {
        tokio::select! {
            _ = self.interrupt.recv() => SignalEvent::Shutdown,
            _ = self.terminate.recv() => SignalEvent::Shutdown,
            _ = self.hangup.recv() => SignalEvent::Hangup,
        }
    }
}

#[cfg(not(unix))]
struct ShutdownSignals;

#[cfg(not(unix))]
impl ShutdownSignals {
    fn install() -> std::io::Result<Self> {
        Ok(Self)
    }

    async fn next(&mut self) -> SignalEvent {
        let _ = tokio::signal::ctrl_c().await;
        SignalEvent::Shutdown
    }
}

enum DriverEvent {
    Shutdown,
    Reload(Result<ReloadOutcome, tokio::task::JoinError>),
}

/// Coalesces SIGHUP into at most one pending reload and lets SIGTERM abort an
/// in-flight reload before it can publish.
struct ReloadDriver {
    signals: ShutdownSignals,
    control: Arc<ControlState>,
    task: Option<tokio::task::JoinHandle<ReloadOutcome>>,
    pending: bool,
}

impl ReloadDriver {
    fn new(signals: ShutdownSignals, control: Arc<ControlState>) -> Self {
        Self {
            signals,
            control,
            task: None,
            pending: false,
        }
    }

    fn start(&mut self) {
        let control = Arc::clone(&self.control);
        let expected = control.status().generation;
        self.task = Some(tokio::spawn(async move { control.reload(expected).await }));
    }

    async fn next(&mut self) -> DriverEvent {
        loop {
            if let Some(task) = self.task.as_mut() {
                tokio::select! {
                    biased;
                    event = self.signals.next() => match event {
                        SignalEvent::Shutdown => {
                            if let Some(task) = self.task.take() {
                                task.abort();
                            }
                            return DriverEvent::Shutdown;
                        }
                        SignalEvent::Hangup => {
                            self.pending = true;
                        }
                    },
                    result = task => {
                        self.task = None;
                        let event = DriverEvent::Reload(result);
                        if self.pending {
                            self.pending = false;
                            self.start();
                        }
                        return event;
                    }
                }
            } else {
                match self.signals.next().await {
                    SignalEvent::Shutdown => return DriverEvent::Shutdown,
                    SignalEvent::Hangup => self.start(),
                }
            }
        }
    }
}

fn log_reload(logger: &Logger, outcome: &ReloadOutcome) {
    let mut record = LogRecord::new(Event::ReloadApplied);
    match outcome {
        ReloadOutcome::Applied { generation } => {
            record.generation = Some(*generation);
            record.outcome = Some(Outcome::Success);
        }
        ReloadOutcome::Valid { generation } => {
            record.generation = Some(*generation);
            record.outcome = Some(Outcome::Success);
            record.event = Event::ReloadRejected;
        }
        ReloadOutcome::Invalid { .. } => {
            record.event = Event::ReloadRejected;
            record.outcome = Some(Outcome::Invalid);
        }
        ReloadOutcome::RestartRequired { .. } => {
            record.event = Event::ReloadRejected;
            record.outcome = Some(Outcome::RestartRequired);
        }
        ReloadOutcome::Conflict { current } => {
            record.event = Event::ReloadRejected;
            record.outcome = Some(Outcome::Conflict);
            record.generation = Some(*current);
        }
        ReloadOutcome::Busy => {
            record.event = Event::ReloadRejected;
            record.outcome = Some(Outcome::Busy);
        }
        ReloadOutcome::GenerationBusy => {
            record.event = Event::ReloadRejected;
            record.outcome = Some(Outcome::GenerationBusy);
        }
        ReloadOutcome::TimedOut => {
            record.event = Event::ReloadRejected;
            record.outcome = Some(Outcome::TimedOut);
        }
        ReloadOutcome::Cancelled => {
            record.event = Event::ReloadRejected;
            record.outcome = Some(Outcome::Cancelled);
        }
        ReloadOutcome::ShuttingDown => {
            record.event = Event::ReloadRejected;
            record.outcome = Some(Outcome::ShuttingDown);
        }
        ReloadOutcome::Internal => {
            record.event = Event::ReloadRejected;
            record.outcome = Some(Outcome::Failed);
        }
    }
    logger.log(record);
}

fn run_control_write<I>(args: I) -> u8
where
    I: IntoIterator<Item = OsString>,
{
    const USAGE: &str = "Usage: angara control-write --config <path> [--socket <path>] [--read-socket <path>] [--admin-group <name>] [--socket-group <name>]";
    let mut config_path = None;
    let mut options = None::<crate::control_write::WriterOptions>;
    let mut arguments = args.into_iter();
    while let Some(argument) = arguments.next() {
        if argument == "--help" || argument == "-h" {
            println!("{USAGE}");
            return EXIT_OK;
        }
        let Some(flag) = argument.to_str() else {
            eprintln!("error: неподдерживаемый аргумент control-write");
            return EXIT_USAGE;
        };
        let value = match flag {
            "--config" | "--socket" | "--read-socket" | "--admin-group" | "--socket-group" => {
                let Some(value) = arguments.next() else {
                    eprintln!("error: после {flag} требуется значение");
                    return EXIT_USAGE;
                };
                value
            }
            _ => {
                eprintln!("error: неподдерживаемый аргумент control-write");
                return EXIT_USAGE;
            }
        };
        match flag {
            "--config" => config_path = Some(PathBuf::from(value)),
            "--socket" => {
                let mut current = options
                    .take()
                    .unwrap_or_else(|| crate::control_write::WriterOptions::new(PathBuf::new()));
                current.socket_path = PathBuf::from(value);
                options = Some(current);
            }
            "--read-socket" => {
                let mut current = options
                    .take()
                    .unwrap_or_else(|| crate::control_write::WriterOptions::new(PathBuf::new()));
                current.read_socket = PathBuf::from(value);
                options = Some(current);
            }
            "--admin-group" => {
                let mut current = options
                    .take()
                    .unwrap_or_else(|| crate::control_write::WriterOptions::new(PathBuf::new()));
                current.admin_group = value.to_string_lossy().into_owned();
                options = Some(current);
            }
            "--socket-group" => {
                let mut current = options
                    .take()
                    .unwrap_or_else(|| crate::control_write::WriterOptions::new(PathBuf::new()));
                current.socket_group = value.to_string_lossy().into_owned();
                options = Some(current);
            }
            _ => unreachable!(),
        }
    }
    let Some(config_path) = config_path else {
        eprintln!("error: не указан --config");
        eprintln!("{USAGE}");
        return EXIT_USAGE;
    };
    let config_path = std::path::absolute(&config_path).unwrap_or(config_path);
    let config = match Config::load(&config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return EXIT_CONFIG_ERROR;
        }
    };
    let mut options =
        options.unwrap_or_else(|| crate::control_write::WriterOptions::new(config_path.clone()));
    options.config_path = config_path;
    let runtime = match AngaraRuntime::build(&config) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: {error}");
            return EXIT_SERVER_ERROR;
        }
    };
    let result = runtime.block_on(async move {
        let handle = crate::control_write::ControlWriter::start(options).await?;
        wait_for_control_signal().await;
        let socket = handle.socket_path.clone();
        handle.shutdown().await;
        Ok::<PathBuf, std::io::Error>(socket)
    });
    match result {
        Ok(socket) => {
            println!("control writer stopped: {}", socket.display());
            runtime.shutdown();
            EXIT_OK
        }
        Err(error) => {
            eprintln!("error: {error}");
            runtime.shutdown();
            EXIT_SERVER_ERROR
        }
    }
}

async fn wait_for_control_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn run_tui<I>(args: I) -> u8
where
    I: IntoIterator<Item = OsString>,
{
    const USAGE: &str = "Usage: angara tui [--socket <path>]";
    let mut socket = PathBuf::from(crate::control_write::DEFAULT_SOCKET);
    let mut arguments = args.into_iter();
    while let Some(argument) = arguments.next() {
        if argument == "--help" || argument == "-h" {
            println!("{USAGE}");
            return EXIT_OK;
        }
        if argument == "--socket" {
            let Some(value) = arguments.next() else {
                eprintln!("error: после --socket требуется путь");
                return EXIT_USAGE;
            };
            socket = PathBuf::from(value);
            continue;
        }
        eprintln!("error: неподдерживаемый аргумент tui");
        eprintln!("{USAGE}");
        return EXIT_USAGE;
    }
    match crate::tui::run(&socket) {
        Ok(()) => EXIT_OK,
        Err(error) => {
            eprintln!("error: {error}");
            EXIT_CONFIG_ERROR
        }
    }
}

fn usage_error(message: &str) -> u8 {
    eprintln!("error: {message}");
    eprintln!("{USAGE}");
    EXIT_USAGE
}
