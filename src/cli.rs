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
use crate::http::HttpServer;
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
  angara serve --config <path>
  angara users hash [--password-stdin]
  angara --help";

const HELP: &str = "\
Angara proxy

Usage:
  angara --version
  angara check --config <path>
  angara serve --config <path>
  angara users hash [--password-stdin]
  angara --help

Commands:
  check --config <path>       Validate the configuration without network access.
  serve --config <path>       Bind all listeners and run the HTTP/1.1 proxy.
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
            Self::Serve => "Usage: angara serve --config <path>",
        }
    }
}

fn run_config_command<I>(mode: Mode, args: I) -> u8
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let mut config_path = None;

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

        return usage_error("неподдерживаемый аргумент команды");
    }

    let Some(path) = config_path else {
        return usage_error("не указан --config");
    };

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
                let server = HttpServer::bind(config).await?;
                for (id, address) in server.addresses() {
                    eprintln!("listening: {id} {address}");
                }
                signals.wait().await;
                server.shutdown().await;
                Ok::<(), crate::http::ServerError>(())
            });
            match result {
                Ok(()) => EXIT_OK,
                Err(error) => {
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
}

#[cfg(unix)]
impl ShutdownSignals {
    fn install() -> std::io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }

    async fn wait(mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
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

    async fn wait(self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn usage_error(message: &str) -> u8 {
    eprintln!("error: {message}");
    eprintln!("{USAGE}");
    EXIT_USAGE
}
