//! M11 terminal panel PTY checks and view-model-level terminal behavior.

mod common;

use std::process::Command;

use angara::control_write::{ControlWriter, WriterOptions};
use common::m11;

fn run_pty(binary: &str, socket: &std::path::Path, mode: &str) -> std::process::Output {
    Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/m11_tui.py"
        ))
        .arg("--binary")
        .arg(binary)
        .arg("--socket")
        .arg(socket)
        .arg("--mode")
        .arg(mode)
        .output()
        .expect("run PTY fixture")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m11_tui01_pty_renders_users_search_resize_and_restores_terminal() {
    let dir = common::TempDir::new("m11-tui");
    let config_path = m11::write_config(&dir);
    m11::write_users(&dir);
    let read_socket = dir.path().join("read.sock");
    let socket = dir.path().join("control.sock");
    let server = m11::start_proxy(&config_path, &read_socket).await;
    let mut options = WriterOptions::new(config_path);
    options.read_socket = read_socket;
    options.socket_path = socket.clone();
    options.admin_group = "definitely-missing-angara-admin".to_owned();
    options.test_allow_uid = Some(m11::effective_uid());
    let writer = ControlWriter::start(options).await.expect("control writer");
    let binary = env!("CARGO_BIN_EXE_angara").to_owned();
    let socket_for_task = socket.clone();
    let output =
        tokio::task::spawn_blocking(move || run_pty(&binary, &socket_for_task, "connected"))
            .await
            .expect("PTY task");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("TUI_PTY_OK"));
    writer.shutdown().await;
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m11_tui02_pty_disconnected_state_exits_cleanly() {
    let dir = common::TempDir::new("m11-tui-offline");
    let socket = dir.path().join("missing.sock");
    let binary = env!("CARGO_BIN_EXE_angara").to_owned();
    let output = tokio::task::spawn_blocking(move || run_pty(&binary, &socket, "disconnected"))
        .await
        .expect("PTY task");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
