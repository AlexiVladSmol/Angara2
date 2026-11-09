#![cfg(target_os = "linux")]

//! CFG-02: prove that `check` and `serve` never call socket/bind/connect or a
//! resolver. An LD_PRELOAD guard records network entry points, and a positive
//! control proves that the guard is actually loaded and detects a real socket
//! call. This is stronger than probing one free port.

mod common;

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::TempDir;

const NETGUARD_C: &str = include_str!("fixtures/netguard.c");

const CONTROL_C: &str = r#"
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 1;
    }
    close(fd);
    return 0;
}
"#;

fn compile(dir: &Path, name: &str, source: &str, shared: bool) -> PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    fs::write(&source_path, source).expect("write C fixture");

    let output_path = dir.join(name);
    let mut command = Command::new("cc");
    if shared {
        command.args(["-shared", "-fPIC"]);
    }
    command
        .arg("-O2")
        .arg("-o")
        .arg(&output_path)
        .arg(&source_path);
    if shared {
        command.arg("-ldl");
    }

    let status = command.status().expect("run system C compiler");
    assert!(status.success(), "C fixture {name} must compile");
    output_path
}

fn run_with_guard(binary: &Path, arguments: &[&OsStr], guard: &Path, marker: &Path) -> Output {
    Command::new(binary)
        .args(arguments)
        .env("LD_PRELOAD", guard)
        .env("ANGARA_NETGUARD_MARKER", marker)
        .output()
        .expect("run guarded process")
}

fn marker_contents(marker: &Path) -> String {
    match fs::read_to_string(marker) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => panic!("read netguard marker: {error}"),
    }
}

fn network_calls(marker: &Path) -> Vec<String> {
    marker_contents(marker)
        .lines()
        .filter(|line| *line != "loaded")
        .map(str::to_owned)
        .collect()
}

#[test]
fn cfg02_check_and_serve_make_no_network_calls() {
    let dir = TempDir::new("netguard");
    let guard = compile(dir.path(), "netguard.so", NETGUARD_C, true);

    let config = dir.write("minimal.toml", &common::config("\"auto\""));
    let check_marker = dir.path().join("check.marker");
    let serve_marker = dir.path().join("serve.marker");

    let check = run_with_guard(
        Path::new(env!("CARGO_BIN_EXE_angara")),
        &[
            OsStr::new("check"),
            OsStr::new("--config"),
            config.as_os_str(),
        ],
        &guard,
        &check_marker,
    );
    assert_eq!(
        check.status.code(),
        Some(0),
        "check failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );

    let check_marker_text = marker_contents(&check_marker);
    assert!(
        check_marker_text.contains("loaded"),
        "netguard was not loaded into angara check; LD_PRELOAD proof is invalid"
    );
    assert!(
        network_calls(&check_marker).is_empty(),
        "check called network functions: {check_marker_text}"
    );

    let serve = run_with_guard(
        Path::new(env!("CARGO_BIN_EXE_angara")),
        &[
            OsStr::new("serve"),
            OsStr::new("--config"),
            config.as_os_str(),
        ],
        &guard,
        &serve_marker,
    );
    assert_eq!(
        serve.status.code(),
        Some(3),
        "serve failed: {}",
        String::from_utf8_lossy(&serve.stderr)
    );

    let serve_marker_text = marker_contents(&serve_marker);
    assert!(
        serve_marker_text.contains("loaded"),
        "netguard was not loaded into angara serve; LD_PRELOAD proof is invalid"
    );
    assert!(
        network_calls(&serve_marker).is_empty(),
        "serve called network functions: {serve_marker_text}"
    );

    for name in [
        "minimal.toml",
        "multi-listener.toml",
        "m02-policy.toml",
        "m02-egress-local.toml",
    ] {
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join(name);
        let marker = dir.path().join(format!("{name}.marker"));
        let output = run_with_guard(
            Path::new(env!("CARGO_BIN_EXE_angara")),
            &[
                OsStr::new("check"),
                OsStr::new("--config"),
                example.as_os_str(),
            ],
            &guard,
            &marker,
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{name} check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let marker_text = marker_contents(&marker);
        assert!(
            marker_text.contains("loaded"),
            "{name}: netguard was not loaded; LD_PRELOAD proof is invalid"
        );
        assert!(
            network_calls(&marker).is_empty(),
            "{name} called network functions: {marker_text}"
        );
    }
}

#[test]
fn cfg02_netguard_positive_control_detects_socket() {
    let dir = TempDir::new("netguard-control");
    let guard = compile(dir.path(), "netguard.so", NETGUARD_C, true);
    let control = compile(dir.path(), "netguard-control", CONTROL_C, false);
    let marker = dir.path().join("control.marker");

    let output = run_with_guard(&control, &[], &guard, &marker);
    if !output.status.success() {
        // The guard forwards to the real socket(); a failure means the control
        // program or the guard is broken and the proof above is not valid.
        // The control binary is linked against a kernel that may deny sockets
        // in a restricted sandbox; report that explicitly instead of passing.
        panic!(
            "positive control failed to open a socket: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let contents = marker_contents(&marker);
    assert!(
        contents.contains("loaded"),
        "netguard was not loaded into the control process"
    );
    assert!(
        contents.lines().any(|line| line == "socket"),
        "netguard did not observe the control socket call: {contents}"
    );
}
