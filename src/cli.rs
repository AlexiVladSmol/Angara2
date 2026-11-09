//! Command-line interface.
//!
//! The M01 command surface is intentionally small and fixed, so it is parsed
//! directly without a CLI framework. Unknown commands and options are rejected
//! with exit code 2 and are not echoed, which keeps accidental secrets out of
//! diagnostics.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::config::Config;

/// Successful command.
pub const EXIT_OK: u8 = 0;
/// Configuration could not be read, parsed or validated.
pub const EXIT_CONFIG_ERROR: u8 = 1;
/// Command-line usage error.
pub const EXIT_USAGE: u8 = 2;
/// The proxy itself is not implemented yet.
pub const EXIT_PROXY_NOT_IMPLEMENTED: u8 = 3;

/// Message returned by `serve` until the proxy exists.
pub const PROXY_NOT_IMPLEMENTED_MESSAGE: &str =
    "proxy ещё не реализован; сетевые listeners не открыты (M03)";

const USAGE: &str = "\
Usage:
  angara --version
  angara check --config <path>
  angara serve --config <path>
  angara --help";

const HELP: &str = "\
Angara proxy

Usage:
  angara --version
  angara check --config <path>
  angara serve --config <path>
  angara --help

Commands:
  check --config <path>   Validate the configuration without network access.
  serve --config <path>   Validate the configuration and stop with code 3.
  --version               Print the version and stop.
  --help                  Print this help and stop.

Exit codes:
  0  success
  1  configuration error
  2  command-line usage error
  3  proxy is not implemented (M03)";

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
        _ => usage_error("неизвестная команда или аргумент"),
    }
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
            eprintln!("error: {PROXY_NOT_IMPLEMENTED_MESSAGE}");
            EXIT_PROXY_NOT_IMPLEMENTED
        }
    }
}

fn usage_error(message: &str) -> u8 {
    eprintln!("error: {message}");
    eprintln!("{USAGE}");
    EXIT_USAGE
}
