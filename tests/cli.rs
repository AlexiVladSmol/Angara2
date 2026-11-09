//! CLI contract tests. Every test runs the real `angara` binary.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{ONE_LISTENER, TWO_LISTENERS, TempDir, config, config_with};

fn angara() -> Command {
    Command::new(env!("CARGO_BIN_EXE_angara"))
}

fn output(args: &[&str]) -> Output {
    angara().args(args).output().expect("run angara")
}

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn status(output: &Output) -> i32 {
    output.status.code().expect("process exited with a code")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

#[test]
fn cli_version_prints_version_and_succeeds() {
    let output = output(&["--version"]);
    assert_eq!(status(&output), 0);
    assert_eq!(
        stdout(&output),
        format!("angara {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(stderr(&output).is_empty());
}

#[test]
fn cli_help_prints_usage_and_succeeds() {
    let output = output(&["--help"]);
    assert_eq!(status(&output), 0);
    let stdout = stdout(&output);
    assert!(stdout.contains("Usage:"), "{stdout}");
    assert!(stdout.contains("check --config <path>"), "{stdout}");
}

#[test]
fn cli_check_accepts_examples_without_network() {
    for (name, listeners) in [("minimal.toml", 1), ("multi-listener.toml", 3)] {
        let path = example(name);
        let output = angara()
            .arg("check")
            .arg("--config")
            .arg(&path)
            .output()
            .expect("run angara");
        assert_eq!(status(&output), 0, "{name}: {}", stderr(&output));
        let stdout = stdout(&output);
        assert!(stdout.contains("config ok"), "{name}: {stdout}");
        assert!(
            stdout.contains(&format!("listeners={listeners}")),
            "{name}: {stdout}"
        );
        assert!(stderr(&output).is_empty(), "{name}: {}", stderr(&output));
    }
}

#[test]
fn cli_check_accepts_config_equals_form() {
    let path = example("minimal.toml");
    let argument = format!("--config={}", path.display());
    let output = angara()
        .args(["check", &argument])
        .output()
        .expect("run angara");
    assert_eq!(status(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("config ok"));
}

#[test]
fn cli_check_rejects_invalid_config_with_nonzero_exit() {
    let dir = TempDir::new("cli-invalid");
    let text = config_with(&format!("{ONE_LISTENER}{ONE_LISTENER}"), "\"auto\"");
    let path = dir.write("invalid.toml", &text);

    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 1);
    assert!(stdout(&output).is_empty());
    let error = stderr(&output);
    assert!(error.contains("duplicate listener id"), "{error}");
    assert!(error.contains("listeners[1].id"), "{error}");
}

#[test]
fn cli_check_rejects_missing_file() {
    let dir = TempDir::new("cli-missing");
    let path = dir.path().join("does-not-exist.toml");

    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 1);
    assert!(stdout(&output).is_empty());
    let error = stderr(&output);
    assert!(error.contains("cannot read configuration file"), "{error}");
    assert!(error.contains("does-not-exist.toml"), "{error}");
}

#[test]
fn cli_check_rejects_invalid_utf8_file() {
    let dir = TempDir::new("cli-utf8");
    let path = dir.path().join("invalid.toml");
    fs::write(&path, [0xff, 0xfe, 0x00]).expect("write invalid UTF-8");

    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 1);
    assert!(stderr(&output).contains("cannot read configuration file"));
}

#[test]
fn cli_serve_reports_unavailable_proxy_with_exit_code_3() {
    let path = example("minimal.toml");
    let output = angara()
        .arg("serve")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 3);
    assert!(stdout(&output).is_empty());
    let error = stderr(&output);
    assert!(error.contains("proxy ещё не реализован"), "{error}");
}

#[test]
fn cli_serve_rejects_invalid_config_with_exit_code_1() {
    let dir = TempDir::new("cli-serve-invalid");
    let path = dir.write("invalid.toml", "schema_version = 2");

    let output = angara()
        .arg("serve")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 1);
    assert!(stdout(&output).is_empty());
    assert!(!stderr(&output).contains("proxy ещё не реализован"));
}

#[test]
fn cli_usage_errors_exit_2() {
    let dir = TempDir::new("cli-usage");
    let path = dir.write("valid.toml", &config("\"auto\""));
    let path_text = path.to_string_lossy().into_owned();

    let cases: Vec<Vec<&str>> = vec![
        vec![],
        vec!["unknown"],
        vec!["check"],
        vec!["serve"],
        vec!["check", "--config"],
        vec!["check", "--config", &path_text, "--config", &path_text],
        vec!["check", "--config", &path_text, "extra"],
        vec!["check", "--unknown"],
        vec!["--version", "extra"],
        vec!["--help", "extra"],
    ];

    for args in cases {
        let output = output(&args);
        assert_eq!(status(&output), 2, "args {args:?}");
        assert!(stdout(&output).is_empty(), "args {args:?}");
        assert!(!stderr(&output).is_empty(), "args {args:?}");
    }
}

#[test]
fn cli_check_help_exits_zero() {
    for arguments in [vec!["check", "--help"], vec!["serve", "-h"]] {
        let output = output(&arguments);
        assert_eq!(status(&output), 0, "args {arguments:?}");
        assert!(stdout(&output).contains("Usage:"), "args {arguments:?}");
        assert!(stderr(&output).is_empty(), "args {arguments:?}");
    }
}

#[test]
fn cli_check_does_not_leak_sensitive_marker() {
    const MARKER: &str = "MARKER-SECRET-CLI-123";
    let dir = TempDir::new("cli-secret");
    let text = format!("{}[auth]\npassword = \"{MARKER}\"\n", config("\"auto\""));
    let path = dir.write("invalid.toml", &text);

    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 1);
    let combined = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !combined.contains(MARKER),
        "sensitive marker leaked: {combined}"
    );
    assert!(stderr(&output).contains("auth"), "{}", stderr(&output));
}

#[test]
fn cli_error_keeps_field_and_position() {
    let dir = TempDir::new("cli-position");
    let text = config("\"MARKER-WORKER\"");
    let path = dir.write("invalid.toml", &text);

    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 1);
    let error = stderr(&output);
    assert!(error.contains("runtime.worker_threads"), "{error}");
    assert!(error.contains("line 5"), "{error}");
    assert!(!error.contains("MARKER-WORKER"), "{error}");
}

#[test]
fn cli_check_rejects_unknown_transport() {
    let dir = TempDir::new("cli-transport");
    let text = config_with(&ONE_LISTENER.replace("http", "https"), "\"auto\"");
    let path = dir.write("invalid.toml", &text);

    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 1);
    let error = stderr(&output);
    assert!(error.contains("listeners[0].transport"), "{error}");
    assert!(error.contains("unsupported transport"), "{error}");
}

#[test]
fn cli_check_accepts_multiple_listeners() {
    let dir = TempDir::new("cli-multi");
    let path = dir.write("multi.toml", &config_with(TWO_LISTENERS, "4"));

    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("listeners=2"));
}
