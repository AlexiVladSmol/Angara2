//! Read-only Unix-socket control server owned by the proxy process.
//!
//! The public writer socket is provided by the privileged `angara control-write`
//! component. This server accepts only the writer (root or the same effective
//! UID), serves bounded snapshots and accepts a reload request. It never writes
//! configuration or users files.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use zeroize::Zeroize;

use crate::connections::ConnectionRegistry;
use crate::control::ControlState;
use crate::control_protocol::{
    self, API_VERSION, AccessSection, ApiError, ApiLimits, BlocksPage, ConfigState,
    ConnectionsPage, ErrorCode, EventsPage, Op, ProxySnapshot, Request, Response, Snapshot,
    UsersPage,
};

/// Default private read socket used by the privileged writer.
pub const DEFAULT_READ_SOCKET: &str = "/run/angara/control-read.sock";

/// One bound read server. Dropping it removes the socket file.
pub struct ReadServer {
    path: PathBuf,
    task: JoinHandle<()>,
}

impl ReadServer {
    /// Binds the private read socket and starts accepting clients.
    pub async fn bind(
        path: PathBuf,
        control: Arc<ControlState>,
        connections: Arc<ConnectionRegistry>,
    ) -> io::Result<Self> {
        prepare_socket_path(&path)?;
        let listener = UnixListener::bind(&path)?;
        set_socket_mode(&path)?;
        let task = tokio::spawn(accept_loop(listener, control, connections));
        Ok(Self { path, task })
    }

    /// Socket path owned by this server.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stops accepting and removes the socket path.
    pub async fn shutdown(mut self) {
        self.task.abort();
        let _ = tokio::time::timeout(Duration::from_secs(1), &mut self.task).await;
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for ReadServer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn accept_loop(
    listener: UnixListener,
    control: Arc<ControlState>,
    connections: Arc<ConnectionRegistry>,
) {
    let permits = Arc::new(Semaphore::new(control_protocol::MAX_CLIENTS));
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(25)).await;
            continue;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let control = Arc::clone(&control);
        let connections = Arc::clone(&connections);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_client(stream, control, connections).await;
        });
    }
}

async fn handle_client(
    stream: UnixStream,
    control: Arc<ControlState>,
    connections: Arc<ConnectionRegistry>,
) -> io::Result<()> {
    let peer = stream.peer_cred()?;
    let trusted = peer.uid() == 0 || effective_uid().is_some_and(|uid| uid == peer.uid());
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut buffer = Vec::new();
    loop {
        let Some(mut line) = tokio::time::timeout(
            Duration::from_secs(control_protocol::CLIENT_IDLE_TIMEOUT_SECS),
            read_limited_line(&mut reader, &mut buffer),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client idle timeout"))??
        else {
            return Ok(());
        };
        let mut request = match control_protocol::parse_request(&line) {
            Ok(request) => request,
            Err(error) => {
                line.zeroize();
                let response = Response::error(0, 0, error);
                write_response(&mut write, &response).await?;
                return Ok(());
            }
        };
        if request.v != API_VERSION {
            line.zeroize();
            let response = Response::error(
                request.id,
                0,
                ApiError::new(
                    ErrorCode::UnsupportedVersion,
                    format!("protocol version {API_VERSION} is required"),
                ),
            );
            write_response(&mut write, &response).await?;
            return Ok(());
        }
        let id = request.id;
        let result = dispatch(&mut request, &control, &connections, trusted).await;
        request.zeroize_secrets();
        line.zeroize();
        let response = match result {
            Ok(value) => Response::ok(id, 0, value),
            Err(error) => Response::error(id, 0, error),
        };
        write_response(&mut write, &response).await?;
    }
}

async fn dispatch(
    request: &mut Request,
    control: &Arc<ControlState>,
    connections: &Arc<ConnectionRegistry>,
    trusted: bool,
) -> Result<serde_json::Value, ApiError> {
    if !request.op.is_public() && !matches!(request.op, Op::Reload | Op::ConfigValidate) {
        return Err(ApiError::new(
            ErrorCode::Unauthorized,
            "internal operation is not available on this socket",
        ));
    }
    match request.op {
        Op::Hello => Ok(serde_json::json!({
            "api_version": API_VERSION,
            "role": "read",
            "generation": control.status().generation,
        })),
        Op::Snapshot => Ok(to_value(proxy_snapshot(control, connections))),
        Op::Status => Ok(to_value(control.status())),
        Op::Connections => {
            let limit = control_protocol::page_limit(request.limit);
            let offset = control_protocol::page_offset(request.offset);
            let (rows, total) = connections.page(offset, limit);
            Ok(to_value(ConnectionsPage {
                connections: rows,
                offset,
                total,
            }))
        }
        Op::Users => {
            let now = Utc::now();
            let limit = control_protocol::page_limit(request.limit);
            let offset = control_protocol::page_offset(request.offset);
            let query = request.query.as_deref().unwrap_or("");
            let (users, total) = control.users(query, offset, limit, now);
            Ok(to_value(UsersPage {
                users,
                offset,
                total,
            }))
        }
        Op::Blocks => {
            let now = Utc::now();
            let limit = control_protocol::page_limit(request.limit);
            let offset = control_protocol::page_offset(request.offset);
            let query = request.query.as_deref().unwrap_or("");
            let (blocks, total) = control.blocks(query, offset, limit, now);
            Ok(to_value(BlocksPage {
                blocks,
                offset,
                total,
            }))
        }
        Op::Access => {
            let section = match request.section.as_deref() {
                None | Some("summary") => AccessSection::Summary,
                Some("source") => AccessSection::Source,
                Some("rules") => AccessSection::Rules,
                Some("ip_rules") => AccessSection::IpRules,
                Some(_) => {
                    return Err(ApiError::new(
                        ErrorCode::InvalidRequest,
                        "unknown access section",
                    ));
                }
            };
            let limit = control_protocol::page_limit(request.limit);
            let offset = control_protocol::page_offset(request.offset);
            Ok(to_value(control.access_page(section, offset, limit)))
        }
        Op::Config => {
            let status = control.status();
            Ok(to_value(ConfigState {
                config_path: control
                    .config_path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                users_path: control.users_path().map(|path| path.display().to_string()),
                active_config_version: status.config_version.clone(),
                disk_config_version: Some(status.config_version.clone()),
                active_users_version: status.users_version.clone(),
                disk_users_version: status.users_version.clone(),
                generation: status.generation,
                last_reload: status.last_reload,
                writable: false,
                valid: true,
                detail: None,
            }))
        }
        Op::Events | Op::Subscribe => Err(ApiError::new(
            ErrorCode::ResyncRequired,
            "event history is served by the control writer",
        )),
        Op::Reload => {
            if !trusted {
                return Err(ApiError::new(
                    ErrorCode::Unauthorized,
                    "reload is restricted to the privileged writer",
                ));
            }
            let expected = request.expected_generation.ok_or_else(|| {
                ApiError::new(ErrorCode::InvalidRequest, "expected_generation is required")
            })?;
            let outcome = control.reload(expected).await;
            Ok(to_value(outcome))
        }
        Op::ConfigValidate => {
            if !trusted {
                return Err(ApiError::new(
                    ErrorCode::Unauthorized,
                    "validation is restricted to the privileged writer",
                ));
            }
            let expected = request.expected_generation.ok_or_else(|| {
                ApiError::new(ErrorCode::InvalidRequest, "expected_generation is required")
            })?;
            let outcome = control.validate_on_disk(expected).await;
            Ok(to_value(outcome))
        }
        Op::UserAdd
        | Op::UserPassword
        | Op::BlockSet
        | Op::BlockClear
        | Op::AccessPreview
        | Op::AccessApply
        | Op::ConfigApply => Err(ApiError::new(
            ErrorCode::Unauthorized,
            "write operations require the privileged control writer",
        )),
    }
}

/// Builds one proxy snapshot shared by the writer and independent clients.
pub fn proxy_snapshot(
    control: &Arc<ControlState>,
    connections: &Arc<ConnectionRegistry>,
) -> ProxySnapshot {
    let root = control.snapshot_for_test();
    let config = root.config();
    let status = control.status();
    let now = Utc::now();
    ProxySnapshot {
        api_version: API_VERSION,
        instance_id: control.control_instance_id().to_owned(),
        generation: status.generation,
        config_version: status.config_version.clone(),
        users_version: status.users_version.clone(),
        config_path: control
            .config_path()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        users_path: control.users_path().map(|path| path.display().to_string()),
        status,
        access: control.access_summary(),
        routing: {
            let routing = config.routing();
            crate::control_protocol::RoutingSummary {
                default_egress: routing.default_egress().to_owned(),
                default_parent: routing.default_parent().map(str::to_owned),
                rule_count: routing.rules().len(),
            }
        },
        counters: {
            let metrics = control.metrics();
            crate::control_protocol::CounterSummary {
                tcp_accepted: metrics.tcp_accepted,
                tcp_rejected: metrics.tcp_rejected,
                http_completed: metrics.http_completed,
                http_cancelled: metrics.http_cancelled,
                http_4xx: metrics.http_4xx,
                http_5xx: metrics.http_5xx,
                connect_completed: metrics.connect_complete,
                connect_error: metrics.connect_error,
                auth_ok: metrics.auth_ok,
                auth_invalid: metrics.auth_invalid,
                dns_error: metrics.dns_error,
                reload_applied: metrics.reload_applied,
                reload_rejected: metrics.reload_invalid
                    + metrics.reload_restart
                    + metrics.reload_conflict,
                cache_hit: metrics.cache_hit,
                cache_miss: metrics.cache_miss,
                log_dropped: metrics.log_dropped,
            }
        },
        user_count: control.user_count(),
        block_count: control.block_count(now),
        connection_count: connections.len(),
        limits: ApiLimits::default(),
    }
}

fn to_value<T: serde::Serialize>(value: T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

async fn write_response(write: &mut OwnedWriteHalf, response: &Response) -> io::Result<()> {
    let line = match control_protocol::encode_line(response) {
        Ok(line) => line,
        Err(error) => {
            let fallback = Response::error(response.id, response.event_cursor, error);
            control_protocol::encode_line(&fallback).map_err(io::Error::other)?
        }
    };
    if tokio::time::timeout(
        Duration::from_secs(control_protocol::READ_TIMEOUT_SECS),
        write.write_all(line.as_bytes()),
    )
    .await
    .is_err()
    {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "write timeout"));
    }
    write.flush().await
}

/// Reads one bounded UTF-8 line, leaving the newline removed.
pub(crate) async fn read_limited_line<R>(
    reader: &mut BufReader<R>,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<String>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    buffer.clear();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(None);
        }
        if let Some(position) = available.iter().position(|byte| *byte == b'\n') {
            if buffer.len() + position + 1 > control_protocol::MAX_LINE_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            buffer.extend_from_slice(&available[..position]);
            reader.consume(position + 1);
            break;
        }
        if buffer.len() + available.len() > control_protocol::MAX_LINE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        let length = available.len();
        buffer.extend_from_slice(available);
        reader.consume(length);
    }
    String::from_utf8(std::mem::take(buffer))
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line is not UTF-8"))
}

pub(crate) fn prepare_socket_path(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            let is_socket = {
                use std::os::unix::fs::FileTypeExt;
                metadata.file_type().is_socket()
            };
            #[cfg(not(unix))]
            let is_socket = false;
            if !is_socket {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "control socket path exists and is not a socket",
                ));
            }
            // A live server must not be replaced. A stale socket is removed
            // only after a failed connection attempt.
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "control socket is already in use",
                    ));
                }
                Err(_) => std::fs::remove_file(path)?,
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

pub(crate) fn set_socket_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(target_os = "linux")]
pub(crate) fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let _real = fields.next()?;
        return fields.next()?.parse().ok();
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn effective_uid() -> Option<u32> {
    None
}

/// Converts a `ProxySnapshot` into the writer-level snapshot envelope.
pub fn snapshot_envelope(proxy: ProxySnapshot, event_cursor: u64, writable: bool) -> Snapshot {
    Snapshot {
        proxy,
        event_cursor,
        writable,
    }
}

/// Converts a proxy response value back into a typed snapshot.
pub fn decode_proxy_snapshot(value: serde_json::Value) -> Option<ProxySnapshot> {
    serde_json::from_value(value).ok()
}

/// Reads one response line from a writer relay connection.
pub async fn relay_request(
    socket: &Path,
    request: &serde_json::Value,
    timeout: Duration,
) -> Result<Response, ApiError> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|_| ApiError::new(ErrorCode::Unavailable, "control reader is unavailable"))?;
    let line = control_protocol::encode_line(request)?;
    tokio::time::timeout(timeout, async {
        stream
            .write_all(line.as_bytes())
            .await
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "cannot write to control reader"))?;
        stream
            .flush()
            .await
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "cannot flush control reader"))?;
        read_response(&mut stream).await
    })
    .await
    .map_err(|_| ApiError::new(ErrorCode::Timeout, "control reader timed out"))?
}

async fn read_response(stream: &mut UnixStream) -> Result<Response, ApiError> {
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();
    let Some(line) = read_limited_line(&mut reader, &mut buffer)
        .await
        .ok()
        .flatten()
    else {
        return Err(ApiError::new(
            ErrorCode::Unavailable,
            "control reader closed the connection",
        ));
    };
    serde_json::from_str(&line)
        .map_err(|_| ApiError::new(ErrorCode::Unavailable, "control reader response is invalid"))
}

/// Decodes an `EventsPage` response with a bounded resync flag.
pub fn events_page_or_resync(value: serde_json::Value) -> Result<EventsPage, ApiError> {
    serde_json::from_value(value)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "invalid event page"))
}
