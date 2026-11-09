use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(angara::cli::run(std::env::args_os()))
}
