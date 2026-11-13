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

fn listener(id: &str, bind: &str) -> String {
    format!("\n[[listeners]]\nid = \"{id}\"\nbind = \"{bind}\"\ntransport = \"http\"\n")
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
    assert!(
        stdout.contains("Bind all listeners and run the HTTP/1.1 proxy"),
        "{stdout}"
    );
    assert!(stdout.contains("HTTP and HTTPS ingress"), "{stdout}");
    assert!(!stdout.contains("not implemented"), "{stdout}");
}

#[test]
fn cli_check_accepts_examples_without_network() {
    for (name, listeners) in [
        ("minimal.toml", 1),
        ("multi-listener.toml", 3),
        ("m02-policy.toml", 1),
        ("m02-egress-local.toml", 2),
        ("m03-http-local.toml", 1),
    ] {
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
    assert!(error.contains("duplicates listeners[0].id"), "{error}");
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
fn cli_serve_proxies_a_request_and_shuts_down() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    #[cfg(unix)]
    use std::time::Instant;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral port")
            .local_addr()
            .expect("local address")
            .port()
    }

    let proxy_port = free_port();
    let origin = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let origin_port = origin.local_addr().expect("origin address").port();
    let origin = Arc::new(origin);
    let origin_thread = {
        let origin = Arc::clone(&origin);
        thread::spawn(move || {
            let (mut stream, _) = origin.accept().expect("accept origin request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("read origin request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write origin response");
        })
    };

    let dir = TempDir::new("cli-serve");
    let text = format!(
        r#"
schema_version = 1

[runtime]
worker_threads = 1

[limits]
max_connections = 16
max_client_connections = 8
max_header_bytes = 32768
header_read_timeout_ms = 2000
idle_timeout_ms = 5000
shutdown_timeout_ms = 2000

[[listeners]]
id = "proxy"
bind = "127.0.0.1:{proxy_port}"
transport = "http"

[access]
source_allow = ["127.0.0.0/8"]
ip_default = "deny"

[[access.rules]]
id = "allow"
action = "allow"

[[access.ip_rules]]
id = "loopback"
action = "allow"
networks = ["127.0.0.0/8"]
allow_special = true
"#
    );
    let path = dir.write("serve.toml", &text);

    let mut child = angara()
        .arg("serve")
        .arg("--config")
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn angara serve");

    let stderr = child.stderr.take().expect("serve stderr");
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::spawn(move || {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            if line.contains("listening:") {
                let _ = ready_tx.send(line);
            }
        }
    });
    assert!(
        ready_rx.recv_timeout(Duration::from_secs(10)).is_ok(),
        "serve did not report readiness"
    );

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect proxy");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    write!(
        client,
        "GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
    )
    .expect("write proxy request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("read proxy response");
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    #[cfg(unix)]
    {
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("send SIGTERM");
        assert!(status.success(), "kill -TERM failed");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().expect("wait for serve") {
                assert_eq!(status.code(), Some(0), "serve did not exit cleanly");
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("serve did not stop after SIGTERM");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
        let _ = child.wait();
    }

    origin_thread.join().expect("origin thread");
}

#[test]
fn cli_serve_startup_failure_releases_all_listeners() {
    use std::net::TcpListener;

    // Hold the conflicting port for the whole scenario: a closed probe port
    // can be taken by another process before Angara starts.
    let occupied = TcpListener::bind(("127.0.0.1", 0)).expect("occupy second port");
    let second = occupied.local_addr().expect("occupied address").port();

    // The first listener must remain bindable by Angara. Reserve an ephemeral
    // port distinct from the occupied one, then release it immediately before
    // spawning the child.
    let first_probe = TcpListener::bind(("127.0.0.1", 0)).expect("probe first port");
    let first = first_probe.local_addr().expect("probe address").port();
    assert_ne!(first, second);
    drop(first_probe);

    let dir = TempDir::new("cli-serve-bind");
    let listeners = format!(
        "\n[[listeners]]\nid = \"first\"\nbind = \"127.0.0.1:{first}\"\ntransport = \"http\"\n\
         \n[[listeners]]\nid = \"second\"\nbind = \"127.0.0.1:{second}\"\ntransport = \"http\"\n"
    );
    let path = dir.write("conflict.toml", &config_with(&listeners, "1"));
    let output = angara()
        .arg("serve")
        .arg("--config")
        .arg(path)
        .output()
        .expect("run angara");

    assert_eq!(status(&output), 3);
    let error = stderr(&output);
    assert!(!error.contains("listening:"), "{error}");
    assert!(!error.contains(&first.to_string()), "{error}");
    assert!(!error.contains(&second.to_string()), "{error}");
    drop(occupied);
    TcpListener::bind(("127.0.0.1", first))
        .expect("first listener must be released after a failed bind");
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
fn cli_semantic_errors_do_not_leak_listener_values() {
    const MARKER: &str = "MARKER-SECRET-REVIEW-123";
    let dir = TempDir::new("cli-semantic-secret");

    let duplicate = config_with(
        &format!(
            "{}{}",
            listener(MARKER, "127.0.0.1:3128"),
            listener(MARKER, "127.0.0.2:3128")
        ),
        "\"auto\"",
    );
    let wildcard = config_with(
        &format!(
            "{}{}",
            listener(MARKER, "0.0.0.0:3128"),
            listener("other", "127.0.0.1:3128")
        ),
        "\"auto\"",
    );

    for (name, text) in [("duplicate.toml", duplicate), ("wildcard.toml", wildcard)] {
        let path = dir.write(name, &text);
        for mode in ["check", "serve"] {
            let output = angara()
                .arg(mode)
                .arg("--config")
                .arg(&path)
                .output()
                .expect("run angara");

            assert_eq!(status(&output), 1, "{mode} {name}");
            assert!(stdout(&output).is_empty(), "{mode} {name}");
            let error = stderr(&output);
            assert!(
                !error.contains(MARKER),
                "{mode} {name} leaked listener id: {error}"
            );
            assert!(error.contains("listeners[1]"), "{mode} {name}: {error}");
        }
    }
}

#[test]
fn cli_escapes_control_characters_in_unknown_field_diagnostic() {
    let dir = TempDir::new("cli-newline");
    let text =
        config("\"auto\"").replace("[runtime]", "[runtime]\n\"first\\nFORGED-LOG-LINE\" = true");
    let path = dir.write("injected.toml", &text);

    for mode in ["check", "serve"] {
        let output = angara()
            .arg(mode)
            .arg("--config")
            .arg(&path)
            .output()
            .expect("run angara");

        assert_eq!(status(&output), 1, "{mode}");
        assert!(stdout(&output).is_empty(), "{mode}");
        let error = stderr(&output);
        assert_eq!(
            error.lines().count(),
            1,
            "{mode}: diagnostic must stay one record: {error:?}"
        );
        assert!(
            error.contains("\\n"),
            "{mode}: newline is not shown as escape: {error:?}"
        );
        assert!(error.contains("FORGED-LOG-LINE"), "{mode}: {error:?}");
        assert!(!error.contains("\nFORGED"), "{mode}: {error:?}");
    }
}

#[test]
fn cli_check_rejects_unknown_transport_and_missing_tls() {
    let dir = TempDir::new("cli-transport");
    let unknown = dir.write(
        "unknown.toml",
        &config_with(&ONE_LISTENER.replace("http", "quic"), "\"auto\""),
    );
    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(&unknown)
        .output()
        .expect("run angara");
    assert_eq!(status(&output), 1);
    let error = stderr(&output);
    assert!(error.contains("listeners[0].transport"), "{error}");
    assert!(error.contains("http") && error.contains("https"), "{error}");

    let https = dir.write(
        "https.toml",
        &config_with(&ONE_LISTENER.replace("http", "https"), "\"auto\""),
    );
    let output = angara()
        .arg("check")
        .arg("--config")
        .arg(&https)
        .output()
        .expect("run angara");
    assert_eq!(status(&output), 1);
    let error = stderr(&output);
    assert!(error.contains("listeners[0].tls"), "{error}");
    assert!(error.contains("required"), "{error}");
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
