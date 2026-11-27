//! Background Unix-socket client for the TUI.
//!
//! Requests run on a worker thread and the event subscription on its own
//! thread, so a slow writer never freezes terminal input. Both channels are
//! bounded.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::control::ReloadOutcome;
use crate::control_protocol::{
    API_VERSION, AccessChange, AccessPage, AccessPreview, ApiError, BlocksPage, ConfigState,
    ConnectionsPage, Event, EventEnvelope, EventsPage, Response, Snapshot, StatusSnapshot,
    UsersPage, WriteOutcome,
};

const COMMAND_QUEUE: usize = 8;
const UPDATE_QUEUE: usize = 64;

/// One operator command.
pub enum Command {
    RefreshAll {
        connections_offset: usize,
        users_offset: usize,
        blocks_offset: usize,
        access_section: String,
    },
    RefreshStatus,
    RefreshConnections {
        offset: usize,
    },
    RefreshUsers {
        query: String,
        offset: usize,
    },
    RefreshBlocks {
        query: String,
        offset: usize,
    },
    RefreshAccess {
        section: String,
    },
    RefreshConfig,
    RefreshEvents,
    UserAdd {
        username: String,
        password: Zeroizing<String>,
        password_confirm: Zeroizing<String>,
        operation_id: String,
        expected_version: String,
    },
    UserPassword {
        username: String,
        password: Zeroizing<String>,
        password_confirm: Zeroizing<String>,
        operation_id: String,
        expected_version: String,
    },
    BlockSet {
        username: String,
        permanent: bool,
        until: Option<String>,
        expected_version: String,
    },
    BlockClear {
        username: String,
        expected_version: String,
    },
    AccessPreview {
        change: AccessChange,
        expected_version: String,
    },
    AccessApply {
        change: AccessChange,
        expected_version: String,
    },
    ConfigValidate,
    ConfigApply {
        expected_version: String,
    },
}

/// One asynchronous update for the view model.
#[allow(clippy::large_enum_variant)]
pub enum Update {
    Connected,
    Disconnected(String),
    Snapshot(Snapshot),
    Status(StatusSnapshot),
    Connections(ConnectionsPage),
    Users(UsersPage),
    Blocks(BlocksPage),
    Access(AccessPage),
    Config(ConfigState),
    Events(EventsPage),
    Event(Event),
    Resync,
    Write(WriteOutcome),
    Reload(ReloadOutcome),
    Preview(AccessPreview),
    Error(ApiError),
}

/// Handle used by the terminal loop.
pub struct Client {
    commands: SyncSender<Command>,
    updates: Receiver<Update>,
    stopped: Arc<AtomicBool>,
}

impl Client {
    /// Starts request and subscription workers.
    pub fn start(socket: PathBuf) -> Self {
        let (command_tx, command_rx) = sync_channel(COMMAND_QUEUE);
        let (update_tx, update_rx) = sync_channel(UPDATE_QUEUE);
        let stopped = Arc::new(AtomicBool::new(false));
        let request_socket = socket.clone();
        let request_updates = update_tx.clone();
        let request_stopped = Arc::clone(&stopped);
        std::thread::Builder::new()
            .name("angara-tui-request".to_owned())
            .spawn(move || {
                request_loop(request_socket, command_rx, request_updates, request_stopped)
            })
            .expect("request worker");
        let cursor = Arc::new(std::sync::Mutex::new(0_u64));
        let subscribe_updates = update_tx;
        let subscribe_stopped = Arc::clone(&stopped);
        std::thread::Builder::new()
            .name("angara-tui-events".to_owned())
            .spawn(move || {
                subscribe_loop(socket, cursor, subscribe_updates, subscribe_stopped);
            })
            .expect("subscription worker");
        Self {
            commands: command_tx,
            updates: update_rx,
            stopped,
        }
    }

    /// Queues one command without blocking the terminal.
    pub fn send(&self, command: Command) {
        let _ = self.commands.try_send(command);
    }

    /// Returns one pending update.
    pub fn try_update(&self) -> Option<Update> {
        self.updates.try_recv().ok()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
    }
}

fn request_loop(
    socket: PathBuf,
    commands: Receiver<Command>,
    updates: SyncSender<Update>,
    stopped: Arc<AtomicBool>,
) {
    while let Ok(command) = commands.recv() {
        if stopped.load(Ordering::Acquire) {
            return;
        }
        let update = execute(&socket, command);
        if updates.send(update).is_err() {
            return;
        }
        if stopped.load(Ordering::Acquire) {
            return;
        }
    }
}

fn execute(socket: &std::path::Path, command: Command) -> Update {
    match command {
        Command::RefreshAll {
            connections_offset,
            users_offset,
            blocks_offset,
            access_section,
        } => {
            let mut last = Update::Connected;
            for (op, args) in [
                ("snapshot", Map::new()),
                (
                    "connections",
                    json!({"limit": 100, "offset": connections_offset})
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                ),
                (
                    "users",
                    json!({"limit": 100, "offset": users_offset})
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                ),
                (
                    "blocks",
                    json!({"limit": 100, "offset": blocks_offset})
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                ),
                (
                    "access",
                    json!({"section": access_section, "limit": 100})
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                ),
                ("config", Map::new()),
                (
                    "events",
                    json!({"limit": 100})
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                ),
            ] {
                match request(socket, op, Value::Object(args), Duration::from_secs(6)) {
                    Ok(value) => {
                        last = decode(op, value).unwrap_or(last);
                    }
                    Err(error) => return Update::Error(error),
                }
            }
            last
        }
        Command::RefreshStatus => {
            match request(socket, "status", Value::Null, Duration::from_secs(6)) {
                Ok(value) => decode_value::<StatusSnapshot>(value)
                    .map(Update::Status)
                    .unwrap_or_else(protocol_error),
                Err(error) => Update::Error(error),
            }
        }
        Command::RefreshConnections { offset } => {
            match request(
                socket,
                "connections",
                json!({"limit": 100, "offset": offset}),
                Duration::from_secs(6),
            ) {
                Ok(value) => decode_value::<ConnectionsPage>(value)
                    .map(Update::Connections)
                    .unwrap_or_else(protocol_error),
                Err(error) => Update::Error(error),
            }
        }
        Command::RefreshUsers { query, offset } => match request(
            socket,
            "users",
            json!({"limit": 100, "query": query, "offset": offset}),
            Duration::from_secs(6),
        ) {
            Ok(value) => decode_value::<UsersPage>(value)
                .map(Update::Users)
                .unwrap_or_else(protocol_error),
            Err(error) => Update::Error(error),
        },
        Command::RefreshBlocks { query, offset } => match request(
            socket,
            "blocks",
            json!({"limit": 100, "query": query, "offset": offset}),
            Duration::from_secs(6),
        ) {
            Ok(value) => decode_value::<BlocksPage>(value)
                .map(Update::Blocks)
                .unwrap_or_else(protocol_error),
            Err(error) => Update::Error(error),
        },
        Command::RefreshAccess { section } => match request(
            socket,
            "access",
            json!({"section": section, "limit": 100}),
            Duration::from_secs(6),
        ) {
            Ok(value) => decode_value::<AccessPage>(value)
                .map(Update::Access)
                .unwrap_or_else(protocol_error),
            Err(error) => Update::Error(error),
        },
        Command::RefreshConfig => {
            match request(socket, "config", Value::Null, Duration::from_secs(6)) {
                Ok(value) => decode_value::<ConfigState>(value)
                    .map(Update::Config)
                    .unwrap_or_else(protocol_error),
                Err(error) => Update::Error(error),
            }
        }
        Command::RefreshEvents => match request(
            socket,
            "events",
            json!({"limit": 100}),
            Duration::from_secs(6),
        ) {
            Ok(value) => decode_value::<EventsPage>(value)
                .map(Update::Events)
                .unwrap_or_else(protocol_error),
            Err(error) => Update::Error(error),
        },
        Command::UserAdd {
            username,
            password,
            password_confirm,
            operation_id,
            expected_version,
        } => write_request(
            socket,
            "user.add",
            json!({
                "username": username,
                "password": password.as_str(),
                "password_confirm": password_confirm.as_str(),
                "operation_id": operation_id,
                "expected_version": expected_version,
            }),
            Duration::from_secs(70),
        ),
        Command::UserPassword {
            username,
            password,
            password_confirm,
            operation_id,
            expected_version,
        } => write_request(
            socket,
            "user.password",
            json!({
                "username": username,
                "password": password.as_str(),
                "password_confirm": password_confirm.as_str(),
                "operation_id": operation_id,
                "expected_version": expected_version,
            }),
            Duration::from_secs(70),
        ),
        Command::BlockSet {
            username,
            permanent,
            until,
            expected_version,
        } => {
            let mut args = json!({
                "username": username,
                "permanent": permanent,
                "expected_version": expected_version,
            });
            if let (Some(object), Some(until)) = (args.as_object_mut(), until) {
                object.insert("until".to_owned(), Value::String(until));
            }
            write_request(socket, "block.set", args, Duration::from_secs(20))
        }
        Command::BlockClear {
            username,
            expected_version,
        } => write_request(
            socket,
            "block.clear",
            json!({"username": username, "expected_version": expected_version}),
            Duration::from_secs(20),
        ),
        Command::AccessPreview {
            change,
            expected_version,
        } => match request(
            socket,
            "access.preview",
            json!({"change": change, "expected_version": expected_version}),
            Duration::from_secs(20),
        ) {
            Ok(value) => decode_value::<AccessPreview>(value)
                .map(Update::Preview)
                .unwrap_or_else(protocol_error),
            Err(error) => Update::Error(error),
        },
        Command::AccessApply {
            change,
            expected_version,
        } => write_request(
            socket,
            "access.apply",
            json!({"change": change, "expected_version": expected_version}),
            Duration::from_secs(70),
        ),
        Command::ConfigValidate => match request(
            socket,
            "config.validate",
            Value::Null,
            Duration::from_secs(20),
        ) {
            Ok(value) => decode_value::<ReloadOutcome>(value)
                .map(Update::Reload)
                .unwrap_or_else(protocol_error),
            Err(error) => Update::Error(error),
        },
        Command::ConfigApply { expected_version } => write_request(
            socket,
            "config.apply",
            json!({"expected_version": expected_version}),
            Duration::from_secs(70),
        ),
    }
}

fn write_request(socket: &std::path::Path, op: &str, args: Value, timeout: Duration) -> Update {
    match request(socket, op, args, timeout) {
        Ok(value) => decode_value::<WriteOutcome>(value)
            .map(Update::Write)
            .unwrap_or_else(protocol_error),
        Err(error) => Update::Error(error),
    }
}

fn decode(op: &str, value: Value) -> Option<Update> {
    Some(match op {
        "snapshot" => Update::Snapshot(decode_value(value)?),
        "status" => Update::Status(decode_value(value)?),
        "connections" => Update::Connections(decode_value(value)?),
        "users" => Update::Users(decode_value(value)?),
        "blocks" => Update::Blocks(decode_value(value)?),
        "access" => Update::Access(decode_value(value)?),
        "config" => Update::Config(decode_value(value)?),
        "events" => Update::Events(decode_value(value)?),
        _ => return None,
    })
}

fn decode_value<T: serde::de::DeserializeOwned>(value: Value) -> Option<T> {
    serde_json::from_value(value).ok()
}

fn protocol_error() -> Update {
    Update::Error(ApiError {
        code: crate::control_protocol::ErrorCode::Internal,
        message: "сервер вернул неожиданный ответ".to_owned(),
        fields: Vec::new(),
        current_version: None,
        current_generation: None,
        saved: None,
    })
}

fn request(
    socket: &std::path::Path,
    op: &str,
    args: Value,
    timeout: Duration,
) -> Result<Value, ApiError> {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut request = json!({"v": API_VERSION, "id": id, "op": op});
    if let (Some(object), Value::Object(args)) = (request.as_object_mut(), args) {
        for (key, value) in args {
            object.insert(key, value);
        }
    }
    let mut stream = UnixStream::connect(socket).map_err(|_| ApiError {
        code: crate::control_protocol::ErrorCode::Unavailable,
        message: "нет связи с angara control.sock".to_owned(),
        fields: Vec::new(),
        current_version: None,
        current_generation: None,
        saved: None,
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| unavailable())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| unavailable())?;
    let line = serde_json::to_string(&request).map_err(|_| unavailable())?;
    stream
        .write_all(line.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|_| unavailable())?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).map_err(|_| ApiError {
        code: crate::control_protocol::ErrorCode::Timeout,
        message: "истекло время ожидания ответа".to_owned(),
        fields: Vec::new(),
        current_version: None,
        current_generation: None,
        saved: None,
    })?;
    if response.len() > crate::control_protocol::MAX_LINE_BYTES {
        return Err(unavailable());
    }
    let response: Response = serde_json::from_str(&response).map_err(|_| unavailable())?;
    if response.ok {
        Ok(response.result.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(unavailable))
    }
}

fn unavailable() -> ApiError {
    ApiError {
        code: crate::control_protocol::ErrorCode::Unavailable,
        message: "локальный API недоступен".to_owned(),
        fields: Vec::new(),
        current_version: None,
        current_generation: None,
        saved: None,
    }
}

fn subscribe_loop(
    socket: PathBuf,
    cursor: Arc<std::sync::Mutex<u64>>,
    updates: SyncSender<Update>,
    stopped: Arc<AtomicBool>,
) {
    while !stopped.load(Ordering::Acquire) {
        let Some(mut stream) = connect_with_retry(&socket, &stopped) else {
            return;
        };
        let start = cursor.lock().map(|value| *value).unwrap_or(0);
        let request = json!({
            "v": API_VERSION,
            "id": 1,
            "op": "subscribe",
            "cursor": start,
        });
        let line = match serde_json::to_string(&request) {
            Ok(line) => line,
            Err(_) => return,
        };
        if stream
            .write_all(line.as_bytes())
            .and_then(|()| stream.write_all(b"\n"))
            .is_err()
        {
            let _ = updates.send(Update::Disconnected(
                "не удалось отправить подписку".to_owned(),
            ));
            continue;
        }
        let mut reader = BufReader::new(stream);
        let mut first = String::new();
        if reader.read_line(&mut first).is_err() {
            let _ = updates.send(Update::Disconnected("подписка закрыта сервером".to_owned()));
            continue;
        }
        let response: Response = match serde_json::from_str(&first) {
            Ok(response) => response,
            Err(_) => {
                let _ = updates.send(Update::Error(unavailable()));
                continue;
            }
        };
        if !response.ok {
            if let Some(error) = response.error {
                let _ = updates.send(Update::Error(error));
            }
            continue;
        }
        let Some(snapshot): Option<Snapshot> = response
            .result
            .and_then(|value| serde_json::from_value(value).ok())
        else {
            continue;
        };
        let snapshot_cursor = snapshot.event_cursor;
        if let Ok(mut current) = cursor.lock() {
            *current = snapshot_cursor;
        }
        let _ = updates.send(Update::Connected);
        let _ = updates.send(Update::Snapshot(snapshot));
        let mut last = snapshot_cursor;
        loop {
            if stopped.load(Ordering::Acquire) {
                return;
            }
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
            if line.len() > crate::control_protocol::MAX_LINE_BYTES {
                break;
            }
            let envelope: EventEnvelope = match serde_json::from_str(&line) {
                Ok(envelope) => envelope,
                Err(_) => break,
            };
            if let Some(event) = envelope.event {
                if event.cursor > last {
                    last = event.cursor;
                    if let Ok(mut current) = cursor.lock() {
                        *current = last;
                    }
                }
                let _ = updates.send(Update::Event(event));
            } else if let Some(resync_cursor) = envelope.resync_cursor {
                last = resync_cursor;
                if let Ok(mut current) = cursor.lock() {
                    *current = resync_cursor;
                }
                let _ = updates.send(Update::Resync);
            }
        }
        let _ = updates.send(Update::Disconnected(
            "подписка прервана, переподключаюсь".to_owned(),
        ));
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn connect_with_retry(socket: &std::path::Path, stopped: &AtomicBool) -> Option<UnixStream> {
    loop {
        if stopped.load(Ordering::Acquire) {
            return None;
        }
        match UnixStream::connect(socket) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                return Some(stream);
            }
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    }
}
