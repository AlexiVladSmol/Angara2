//! Privileged local control writer.
//!
//! This component is the only process allowed to replace the main TOML or the
//! configured users file. It owns `/run/angara/control.sock`, checks peer
//! credentials, validates candidates with the production loaders, replaces
//! files atomically and asks the proxy to reload the exact saved version.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, broadcast, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::auth::{self, MAX_USERS_FILE_BYTES, UsersSnapshot, is_valid_username};
use crate::config::{Config, ConfigError, MAX_CONFIG_BYTES};
use crate::control::ReloadOutcome;
use crate::control_edit::{
    UsersEdit, access_change_summary, access_fragment, apply_access_edit, apply_users_edit,
};
use crate::control_files::{CandidateError, FileErrorKind, edit_locked, read_checked};
use crate::control_protocol::{
    self, API_VERSION, AccessChange, AccessPreview, ApiError, ConfigState, ErrorCode, Event,
    EventEnvelope, EventKind, EventsPage, Op, Request, Response, WriteOutcome,
};
use crate::control_server::{
    self, effective_uid, prepare_socket_path, read_limited_line, relay_request, snapshot_envelope,
};
use crate::version::content_version;

/// Default public writer socket.
pub const DEFAULT_SOCKET: &str = "/run/angara/control.sock";
/// Default privileged group for writes.
pub const DEFAULT_ADMIN_GROUP: &str = "angara-admin";
/// Default socket group.
pub const DEFAULT_SOCKET_GROUP: &str = "angara";
/// Maximum recognized operation identifiers retained for idempotent retries.
const MAX_CACHED_OPERATIONS: usize = 128;
/// Recognition window for repeated add/password operations.
const OPERATION_TTL: Duration = Duration::from_secs(600);

/// Writer startup options.
#[derive(Clone, Debug)]
pub struct WriterOptions {
    /// Main configuration path.
    pub config_path: PathBuf,
    /// Private proxy read socket.
    pub read_socket: PathBuf,
    /// Public control socket.
    pub socket_path: PathBuf,
    /// Group whose members may mutate users/ACL.
    pub admin_group: String,
    /// Group that receives read access to the public socket.
    pub socket_group: String,
    /// Test-only allowance for the current UID.
    pub test_allow_uid: Option<u32>,
}

impl WriterOptions {
    /// Production defaults for one configuration path.
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            read_socket: PathBuf::from(control_server::DEFAULT_READ_SOCKET),
            socket_path: PathBuf::from(DEFAULT_SOCKET),
            admin_group: DEFAULT_ADMIN_GROUP.to_owned(),
            socket_group: DEFAULT_SOCKET_GROUP.to_owned(),
            test_allow_uid: None,
        }
    }
}

/// One running writer.
pub struct WriterHandle {
    /// Public socket path.
    pub socket_path: PathBuf,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl WriterHandle {
    /// Stops the accept loop, poller and removes the socket.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.task).await;
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for WriterHandle {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

struct CachedOperation {
    op: Op,
    username: Option<String>,
    result: WriteOutcome,
    at: Instant,
}

struct EventLog {
    cursor: AtomicU64,
    ring: Mutex<VecDeque<Event>>,
    subscriber_sender: broadcast::Sender<Event>,
}

impl EventLog {
    fn new() -> Arc<Self> {
        let (subscriber_sender, _) = broadcast::channel(control_protocol::SUBSCRIBER_QUEUE);
        Arc::new(Self {
            cursor: AtomicU64::new(1),
            ring: Mutex::new(VecDeque::new()),
            subscriber_sender,
        })
    }

    fn latest(&self) -> u64 {
        self.cursor.load(Ordering::Acquire).saturating_sub(1)
    }

    fn push(
        &self,
        kind: EventKind,
        generation: u64,
        config_version: Option<String>,
        users_version: Option<String>,
        username: Option<String>,
        detail: Option<String>,
    ) -> u64 {
        let cursor = self.cursor.fetch_add(1, Ordering::AcqRel);
        let event = Event {
            cursor,
            kind,
            at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            generation,
            config_version,
            users_version,
            username,
            detail,
        };
        if let Ok(mut ring) = self.ring.lock() {
            ring.push_back(event.clone());
            while ring.len() > control_protocol::EVENT_RING {
                ring.pop_front();
            }
        }
        let _ = self.subscriber_sender.send(event);
        cursor
    }

    fn page(&self, cursor: u64, limit: usize) -> EventsPage {
        let latest = self.latest();
        let Ok(ring) = self.ring.lock() else {
            return EventsPage {
                events: Vec::new(),
                next_cursor: cursor,
                resync_required: true,
            };
        };
        let oldest = ring.front().map(|event| event.cursor);
        let resync_required =
            cursor > latest || oldest.is_some_and(|oldest| cursor.saturating_add(1) < oldest);
        if resync_required {
            return EventsPage {
                events: Vec::new(),
                next_cursor: latest,
                resync_required: true,
            };
        }
        let events = ring
            .iter()
            .filter(|event| event.cursor > cursor)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = events.last().map(|event| event.cursor).unwrap_or(cursor);
        EventsPage {
            events,
            next_cursor,
            resync_required: false,
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.subscriber_sender.subscribe()
    }
}

#[derive(Default)]
struct Baseline {
    initialized: bool,
    disk_config: Option<String>,
    disk_users: Option<String>,
    generation: Option<u64>,
    active_config: Option<String>,
    active_users: Option<String>,
    blocks: BTreeMap<String, DateTime<Utc>>,
}

/// One control writer.
pub struct ControlWriter {
    options: WriterOptions,
    owners: Vec<u32>,
    events: Arc<EventLog>,
    read_id: AtomicU64,
    write_lock: tokio::sync::Mutex<()>,
    hash_permits: Arc<Semaphore>,
    subscribers: Arc<Semaphore>,
    operations: Mutex<HashMap<String, CachedOperation>>,
    baseline: Mutex<Baseline>,
}

impl ControlWriter {
    /// Binds the public socket and starts the accept/poll loops.
    pub async fn start(options: WriterOptions) -> io::Result<WriterHandle> {
        let config_path = options.config_path.clone();
        let metadata = std::fs::symlink_metadata(&config_path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "configuration must be a regular file",
            ));
        }
        #[cfg(unix)]
        let owner = {
            use std::os::unix::fs::MetadataExt;
            metadata.uid()
        };
        #[cfg(not(unix))]
        let owner = 0;
        let mut owners = vec![0, owner];
        owners.sort_unstable();
        owners.dedup();
        let writer = Arc::new(Self {
            options,
            owners,
            events: EventLog::new(),
            read_id: AtomicU64::new(1),
            write_lock: tokio::sync::Mutex::new(()),
            hash_permits: Arc::new(Semaphore::new(1)),
            subscribers: Arc::new(Semaphore::new(control_protocol::MAX_SUBSCRIBERS)),
            operations: Mutex::new(HashMap::new()),
            baseline: Mutex::new(Baseline::default()),
        });
        prepare_socket_path(&writer.options.socket_path)?;
        let listener = UnixListener::bind(&writer.options.socket_path)?;
        writer.set_socket_permissions()?;
        let (shutdown, shutdown_rx) = watch::channel(false);
        let task_writer = Arc::clone(&writer);
        let accept_shutdown = shutdown_rx.clone();
        let task = tokio::spawn(async move {
            task_writer.accept_loop(listener, accept_shutdown).await;
        });
        let poller = Arc::downgrade(&writer);
        tokio::spawn(async move {
            poll_loop(poller, shutdown_rx).await;
        });
        Ok(WriterHandle {
            socket_path: writer.options.socket_path.clone(),
            shutdown,
            task,
        })
    }

    fn set_socket_permissions(&self) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let uid = effective_uid();
        if uid == Some(0)
            && let Some(gid) = group_gid(&self.options.socket_group)
        {
            std::os::unix::fs::chown(&self.options.socket_path, Some(0), Some(gid))?;
            std::fs::set_permissions(
                &self.options.socket_path,
                std::fs::Permissions::from_mode(0o660),
            )?;
            return Ok(());
        }
        std::fs::set_permissions(
            &self.options.socket_path,
            std::fs::Permissions::from_mode(0o600),
        )
    }

    async fn accept_loop(
        self: Arc<Self>,
        listener: UnixListener,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let permits = Arc::new(Semaphore::new(control_protocol::MAX_CLIENTS));
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        continue;
                    };
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let writer = Arc::clone(&self);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = writer.handle_client(stream).await;
                    });
                }
            }
        }
    }

    async fn handle_client(self: Arc<Self>, stream: UnixStream) -> io::Result<()> {
        let peer = stream.peer_cred()?;
        let admin = is_admin(
            peer.uid(),
            &self.options.admin_group,
            self.options.test_allow_uid,
        );
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
                    let response = Response::error(0, self.events.latest(), error);
                    write_response(&mut write, &response).await?;
                    return Ok(());
                }
            };
            if request.v != API_VERSION {
                line.zeroize();
                let response = Response::error(
                    request.id,
                    self.events.latest(),
                    ApiError::new(
                        ErrorCode::UnsupportedVersion,
                        format!("protocol version {API_VERSION} is required"),
                    ),
                );
                write_response(&mut write, &response).await?;
                return Ok(());
            }
            if request.op == Op::Subscribe {
                line.zeroize();
                let Ok(permit) = Arc::clone(&self.subscribers).try_acquire_owned() else {
                    let response = Response::error(
                        request.id,
                        self.events.latest(),
                        ApiError::new(ErrorCode::Busy, "subscriber limit reached"),
                    );
                    write_response(&mut write, &response).await?;
                    return Ok(());
                };
                let result = self
                    .subscription(request, &mut reader, &mut write, admin)
                    .await;
                drop(permit);
                return result;
            }
            let id = request.id;
            let result = self.dispatch(&mut request, admin).await;
            request.zeroize_secrets();
            line.zeroize();
            let response = match result {
                Ok(value) => Response::ok(id, self.events.latest(), value),
                Err(error) => Response::error(id, self.events.latest(), error),
            };
            write_response(&mut write, &response).await?;
        }
    }

    async fn dispatch(&self, request: &mut Request, admin: bool) -> Result<Value, ApiError> {
        match request.op {
            Op::Hello => Ok(json!({
                "api_version": API_VERSION,
                "role": "writer",
                "writable": admin,
            })),
            Op::Snapshot => {
                let proxy = self.proxy_snapshot().await?;
                Ok(
                    serde_json::to_value(snapshot_envelope(proxy, self.events.latest(), admin))
                        .unwrap_or(Value::Null),
                )
            }
            Op::Status | Op::Connections | Op::Users | Op::Blocks | Op::Access => {
                let mut args = Map::new();
                if let Some(offset) = request.offset {
                    args.insert("offset".to_owned(), json!(offset));
                }
                if let Some(limit) = request.limit {
                    args.insert("limit".to_owned(), json!(limit));
                }
                if let Some(query) = &request.query {
                    args.insert("query".to_owned(), json!(query));
                }
                if let Some(section) = &request.section {
                    args.insert("section".to_owned(), json!(section));
                }
                self.relay(request.op, Value::Object(args)).await
            }
            Op::Config => self.config_state(admin).await,
            Op::Events => {
                let cursor = request.cursor.unwrap_or(0);
                let page = self
                    .events
                    .page(cursor, control_protocol::page_limit(request.limit));
                Ok(serde_json::to_value(page).unwrap_or(Value::Null))
            }
            Op::Subscribe => Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "subscribe is handled as a streaming operation",
            )),
            Op::Reload => Err(ApiError::new(
                ErrorCode::Unauthorized,
                "reload is requested internally by the writer",
            )),
            Op::UserAdd => {
                require_admin(admin)?;
                self.user_add(request).await
            }
            Op::UserPassword => {
                require_admin(admin)?;
                self.user_password(request).await
            }
            Op::BlockSet => {
                require_admin(admin)?;
                self.block_set(request).await
            }
            Op::BlockClear => {
                require_admin(admin)?;
                self.block_clear(request).await
            }
            Op::AccessPreview => {
                require_admin(admin)?;
                self.access_preview(request).await
            }
            Op::AccessApply => {
                require_admin(admin)?;
                self.access_apply(request).await
            }
            Op::ConfigValidate => {
                require_admin(admin)?;
                self.config_validate().await
            }
            Op::ConfigApply => {
                require_admin(admin)?;
                self.config_apply(request).await
            }
        }
    }

    async fn subscription(
        self: &Arc<Self>,
        request: Request,
        reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
        write: &mut OwnedWriteHalf,
        admin: bool,
    ) -> io::Result<()> {
        let id = request.id;
        let initial_cursor = request.cursor.unwrap_or_else(|| self.events.latest());
        let mut receiver = self.events.subscribe();
        let proxy = match self.proxy_snapshot().await {
            Ok(proxy) => proxy,
            Err(error) => {
                let response = Response::error(id, self.events.latest(), error);
                write_response(write, &response).await?;
                return Ok(());
            }
        };
        let cursor = self.events.latest();
        let snapshot = snapshot_envelope(proxy, cursor, admin);
        let response = Response::ok(id, cursor, snapshot);
        write_response(write, &response).await?;
        let mut last = cursor.max(initial_cursor.saturating_sub(1));
        // Catch up from the retained ring before following the live channel.
        let page = self.events.page(last, control_protocol::MAX_PAGE);
        if page.resync_required {
            last = self.events.latest();
            send_envelope(write, None, Some(last)).await?;
        } else {
            for event in page.events {
                last = event.cursor;
                send_envelope(write, Some(event), None).await?;
            }
        }
        loop {
            tokio::select! {
                biased;
                _ = reader.fill_buf() => return Ok(()),
                event = receiver.recv() => match event {
                    Ok(event) => {
                        if event.cursor > last {
                            last = event.cursor;
                            send_envelope(write, Some(event), None).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        last = self.events.latest();
                        send_envelope(write, None, Some(last)).await?;
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                },
            }
        }
    }

    async fn proxy_snapshot(&self) -> Result<control_protocol::ProxySnapshot, ApiError> {
        let value = self.relay(Op::Snapshot, Value::Null).await?;
        serde_json::from_value(value)
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "proxy snapshot is invalid"))
    }

    async fn relay(&self, op: Op, extra: Value) -> Result<Value, ApiError> {
        let id = self.read_id.fetch_add(1, Ordering::Relaxed);
        let mut request = json!({"v": API_VERSION, "id": id, "op": op});
        if let (Some(object), Value::Object(extra)) = (request.as_object_mut(), extra) {
            for (key, value) in extra {
                object.insert(key, value);
            }
        }
        let timeout = if op == Op::Reload {
            Duration::from_secs(control_protocol::WRITE_TIMEOUT_SECS)
        } else {
            Duration::from_secs(control_protocol::READ_TIMEOUT_SECS)
        };
        let response = relay_request(&self.options.read_socket, &request, timeout).await?;
        if response.ok {
            Ok(response.result.unwrap_or(Value::Null))
        } else {
            Err(response.error.unwrap_or_else(|| {
                ApiError::new(ErrorCode::Internal, "proxy returned an unspecified error")
            }))
        }
    }

    async fn config_state(&self, admin: bool) -> Result<Value, ApiError> {
        let mut state: ConfigState =
            serde_json::from_value(self.relay(Op::Config, Value::Null).await?).map_err(|_| {
                ApiError::new(ErrorCode::Unavailable, "configuration state is invalid")
            })?;
        state.writable = admin;
        state.disk_config_version = None;
        state.disk_users_version = None;
        state.valid = true;
        state.detail = None;
        let config_path = self.options.config_path.clone();
        let owners = self.owners.clone();
        let disk = tokio::task::spawn_blocking(move || {
            let (config_bytes, _) = read_checked(&config_path, MAX_CONFIG_BYTES, &owners, false)?;
            let config_version = content_version(&config_bytes);
            let parsed = Config::load(&config_path);
            let (users_version, detail) = match parsed {
                Ok(config) => match config.auth() {
                    Some(auth) => {
                        let (users_bytes, _) =
                            read_checked(auth.users_file(), MAX_USERS_FILE_BYTES, &owners, true)?;
                        (Some(content_version(&users_bytes)), None)
                    }
                    None => (None, None),
                },
                Err(error) => (None, Some(error.to_string())),
            };
            Ok::<_, crate::control_files::FileError>((config_version, users_version, detail))
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "disk version task failed"))?
        .map_err(file_error)?;
        state.disk_config_version = Some(disk.0);
        state.disk_users_version = disk.1;
        if let Some(detail) = disk.2 {
            state.valid = false;
            state.detail = Some(detail.chars().take(200).collect());
        }
        Ok(serde_json::to_value(state).unwrap_or(Value::Null))
    }

    async fn user_add(&self, request: &mut Request) -> Result<Value, ApiError> {
        let _guard = self.write_lock.lock().await;
        let username = required_username(request)?;
        let operation_id = required_operation_id(request)?;
        if let Some(cached) = self.cached_result(&operation_id, Op::UserAdd, &username) {
            return Ok(serde_json::to_value(cached).unwrap_or(Value::Null));
        }
        let password = take_checked_password(request)?;
        let expected = required_version(request)?;
        let phc = self.hash_password(password).await?;
        let path = self.users_path().await?;
        let owners = self.owners.clone();
        let edit = UsersEdit::Add {
            username: username.clone(),
            password_hash: phc,
        };
        let expected_for_task = expected.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            edit_locked(
                &path,
                &expected_for_task,
                MAX_USERS_FILE_BYTES,
                &owners,
                true,
                |document| apply_users_edit(document, &edit),
                validate_users,
            )
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "users edit task failed"))?
        .map_err(file_error)?;
        let result = self
            .finish_saved(
                true,
                &outcome.version,
                Some(&username),
                "пользователь добавлен",
            )
            .await;
        self.remember(&operation_id, Op::UserAdd, Some(username), &result);
        Ok(serde_json::to_value(result).unwrap_or(Value::Null))
    }

    async fn user_password(&self, request: &mut Request) -> Result<Value, ApiError> {
        let _guard = self.write_lock.lock().await;
        let username = required_username(request)?;
        let operation_id = required_operation_id(request)?;
        if let Some(cached) = self.cached_result(&operation_id, Op::UserPassword, &username) {
            return Ok(serde_json::to_value(cached).unwrap_or(Value::Null));
        }
        let password = take_checked_password(request)?;
        let expected = required_version(request)?;
        let phc = self.hash_password(password).await?;
        let path = self.users_path().await?;
        let owners = self.owners.clone();
        let edit = UsersEdit::Password {
            username: username.clone(),
            password_hash: phc,
        };
        let expected_for_task = expected.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            edit_locked(
                &path,
                &expected_for_task,
                MAX_USERS_FILE_BYTES,
                &owners,
                true,
                |document| apply_users_edit(document, &edit),
                validate_users,
            )
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "users edit task failed"))?
        .map_err(file_error)?;
        let result = self
            .finish_saved(true, &outcome.version, Some(&username), "пароль изменён")
            .await;
        self.remember(&operation_id, Op::UserPassword, Some(username), &result);
        Ok(serde_json::to_value(result).unwrap_or(Value::Null))
    }

    async fn block_set(&self, request: &mut Request) -> Result<Value, ApiError> {
        let _guard = self.write_lock.lock().await;
        let username = required_username(request)?;
        let expected = required_version(request)?;
        let permanent = request.permanent.unwrap_or(false);
        let until = if permanent {
            if request.until.is_some() {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    "permanent block must not carry an end time",
                ));
            }
            None
        } else {
            let value = request.until.as_deref().ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidRequest,
                    "temporary block requires an RFC 3339 end time",
                )
            })?;
            Some(auth::parse_blocked_until(value).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidRequest,
                    "block end must be an RFC 3339 instant with an explicit offset",
                )
            })?)
        };
        let path = self.users_path().await?;
        let owners = self.owners.clone();
        let edit = UsersEdit::Block {
            username: username.clone(),
            until,
        };
        let outcome = tokio::task::spawn_blocking(move || {
            edit_locked(
                &path,
                &expected,
                MAX_USERS_FILE_BYTES,
                &owners,
                true,
                |document| apply_users_edit(document, &edit),
                validate_users,
            )
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "users edit task failed"))?
        .map_err(file_error)?;
        let result = self
            .finish_saved(
                true,
                &outcome.version,
                Some(&username),
                "блокировка сохранена",
            )
            .await;
        Ok(serde_json::to_value(result).unwrap_or(Value::Null))
    }

    async fn block_clear(&self, request: &mut Request) -> Result<Value, ApiError> {
        let _guard = self.write_lock.lock().await;
        let username = required_username(request)?;
        let expected = required_version(request)?;
        let path = self.users_path().await?;
        let owners = self.owners.clone();
        let edit = UsersEdit::ClearBlock {
            username: username.clone(),
        };
        let outcome = tokio::task::spawn_blocking(move || {
            edit_locked(
                &path,
                &expected,
                MAX_USERS_FILE_BYTES,
                &owners,
                true,
                |document| apply_users_edit(document, &edit),
                validate_users,
            )
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "users edit task failed"))?
        .map_err(file_error)?;
        let result = self
            .finish_saved(true, &outcome.version, Some(&username), "блокировка снята")
            .await;
        Ok(serde_json::to_value(result).unwrap_or(Value::Null))
    }

    async fn access_preview(&self, request: &Request) -> Result<Value, ApiError> {
        let change: AccessChange = serde_json::from_value(
            request
                .change
                .clone()
                .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "change is required"))?,
        )
        .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "access change is invalid"))?;
        let expected = request.expected_version.clone();
        let path = self.options.config_path.clone();
        let owners = self.owners.clone();
        let summary = access_change_summary(&change);
        let preview = tokio::task::spawn_blocking(move || {
            let (bytes, _) =
                read_checked(&path, MAX_CONFIG_BYTES, &owners, false).map_err(file_error)?;
            let text = String::from_utf8(bytes)
                .map_err(|_| ApiError::new(ErrorCode::InvalidCandidate, "config is not UTF-8"))?;
            let version = content_version(text.as_bytes());
            if let Some(expected) = expected
                && expected != version
            {
                return Err(ApiError {
                    code: ErrorCode::Conflict,
                    message: "configuration changed since the form was opened".to_owned(),
                    fields: Vec::new(),
                    current_version: Some(version),
                    current_generation: None,
                    saved: None,
                });
            }
            let mut document = text.parse::<toml_edit::DocumentMut>().map_err(|_| {
                ApiError::new(ErrorCode::InvalidCandidate, "config is not valid TOML")
            })?;
            let before = access_fragment(&document, &change);
            apply_access_edit(&mut document, &change).map_err(candidate_api)?;
            let candidate = document.to_string();
            validate_config_text(&candidate, &path).map_err(candidate_api)?;
            let after = access_fragment(&document, &change);
            Ok::<_, ApiError>(AccessPreview {
                summary,
                before: Some(before),
                after: Some(after),
                neighbor_before: None,
                neighbor_after: None,
                valid: true,
            })
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "preview task failed"))??;
        Ok(serde_json::to_value(preview).unwrap_or(Value::Null))
    }

    async fn access_apply(&self, request: &Request) -> Result<Value, ApiError> {
        let _guard = self.write_lock.lock().await;
        let change: AccessChange = serde_json::from_value(
            request
                .change
                .clone()
                .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "change is required"))?,
        )
        .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "access change is invalid"))?;
        let expected = required_version(request)?;
        let path = self.options.config_path.clone();
        let owners = self.owners.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let expected_for_edit = expected.clone();
            edit_locked(
                &path,
                &expected_for_edit,
                MAX_CONFIG_BYTES,
                &owners,
                false,
                |document| apply_access_edit(document, &change),
                |candidate| validate_config_text(candidate, &path),
            )
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "config edit task failed"))?
        .map_err(file_error)?;
        let result = self
            .finish_saved(false, &outcome.version, None, "правило сохранено")
            .await;
        Ok(serde_json::to_value(result).unwrap_or(Value::Null))
    }

    async fn config_validate(&self) -> Result<Value, ApiError> {
        let snapshot = self.proxy_snapshot().await?;
        let outcome = self
            .relay(
                Op::ConfigValidate,
                json!({"expected_generation": snapshot.generation}),
            )
            .await?;
        let outcome: ReloadOutcome = serde_json::from_value(outcome)
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "validation outcome is invalid"))?;
        Ok(serde_json::to_value(outcome).unwrap_or(Value::Null))
    }

    async fn config_apply(&self, request: &Request) -> Result<Value, ApiError> {
        let _guard = self.write_lock.lock().await;
        let expected_version = request.expected_version.clone();
        let path = self.options.config_path.clone();
        let owners = self.owners.clone();
        let (saved_version, users_version) = tokio::task::spawn_blocking(move || {
            let (bytes, _) = read_checked(&path, MAX_CONFIG_BYTES, &owners, false)?;
            let version = content_version(&bytes);
            if let Some(expected) = expected_version
                && expected != version
            {
                return Err(crate::control_files::FileError {
                    kind: FileErrorKind::Conflict,
                    message: "configuration changed since the form was opened".to_owned(),
                    fields: Vec::new(),
                    current_version: Some(version),
                    saved: false,
                });
            }
            let config = Config::load(&path).map_err(|error| crate::control_files::FileError {
                kind: FileErrorKind::InvalidCandidate,
                message: error.to_string(),
                fields: config_fields(&error),
                current_version: Some(version.clone()),
                saved: false,
            })?;
            let users_version = config.auth().and_then(|auth| {
                read_checked(auth.users_file(), MAX_USERS_FILE_BYTES, &owners, true)
                    .ok()
                    .map(|(bytes, _)| content_version(&bytes))
            });
            Ok::<_, crate::control_files::FileError>((version, users_version))
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "config read task failed"))?
        .map_err(file_error)?;
        let snapshot = match self.proxy_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Ok(serde_json::to_value(WriteOutcome {
                    state: "unknown".to_owned(),
                    saved: false,
                    version: Some(saved_version),
                    generation: 0,
                    applied: false,
                    detail: Some(error.message),
                })
                .unwrap_or(Value::Null));
            }
        };
        let expected_generation = request.expected_generation.unwrap_or(snapshot.generation);
        let reload = self
            .relay(
                Op::Reload,
                json!({"expected_generation": expected_generation}),
            )
            .await;
        let result = self
            .evaluate_reload(
                reload,
                false,
                &saved_version,
                users_version.as_deref(),
                snapshot.generation,
                "конфигурация проверена",
                false,
            )
            .await;
        Ok(serde_json::to_value(result).unwrap_or(Value::Null))
    }

    async fn finish_saved(
        &self,
        users_file: bool,
        saved_version: &str,
        username: Option<&str>,
        detail: &str,
    ) -> WriteOutcome {
        let cursor_detail = username.map(|username| format!("{detail}: {username}"));
        let snapshot = match self.proxy_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.events.push(
                    if users_file {
                        EventKind::UsersSaved
                    } else {
                        EventKind::ConfigSaved
                    },
                    0,
                    (!users_file).then(|| saved_version.to_owned()),
                    users_file.then(|| saved_version.to_owned()),
                    username.map(str::to_owned),
                    Some(detail.to_owned()),
                );
                return WriteOutcome {
                    state: "unknown".to_owned(),
                    saved: true,
                    version: Some(saved_version.to_owned()),
                    generation: 0,
                    applied: false,
                    detail: Some(error.message),
                };
            }
        };
        self.events.push(
            if users_file {
                EventKind::UsersSaved
            } else {
                EventKind::ConfigSaved
            },
            snapshot.generation,
            (!users_file).then(|| saved_version.to_owned()),
            users_file.then(|| saved_version.to_owned()),
            username.map(str::to_owned),
            cursor_detail,
        );
        if let Ok(mut baseline) = self.baseline.lock() {
            if users_file {
                baseline.disk_users = Some(saved_version.to_owned());
            } else {
                baseline.disk_config = Some(saved_version.to_owned());
            }
        }
        let reload = self
            .relay(
                Op::Reload,
                json!({"expected_generation": snapshot.generation}),
            )
            .await;
        self.evaluate_reload(
            reload,
            users_file,
            saved_version,
            None,
            snapshot.generation,
            detail,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn evaluate_reload(
        &self,
        reload: Result<Value, ApiError>,
        users_file: bool,
        saved_version: &str,
        expected_users_version: Option<&str>,
        previous_generation: u64,
        detail: &str,
        saved: bool,
    ) -> WriteOutcome {
        let outcome = match reload {
            Ok(value) => match serde_json::from_value::<ReloadOutcome>(value) {
                Ok(outcome) => outcome,
                Err(_) => {
                    return WriteOutcome {
                        state: "unknown".to_owned(),
                        saved,
                        version: Some(saved_version.to_owned()),
                        generation: previous_generation,
                        applied: false,
                        detail: Some("не удалось разобрать результат применения".to_owned()),
                    };
                }
            },
            Err(error) => {
                return WriteOutcome {
                    state: "unknown".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation: previous_generation,
                    applied: false,
                    detail: Some(error.message),
                };
            }
        };
        let applied_generation = match outcome {
            ReloadOutcome::Applied { generation } => generation,
            ReloadOutcome::Valid { generation } => {
                return WriteOutcome {
                    state: "saved".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation,
                    applied: false,
                    detail: Some("кандидат проверен, но не применён".to_owned()),
                };
            }
            ReloadOutcome::Invalid { fields, .. } => {
                self.events.push(
                    EventKind::ConfigRejected,
                    previous_generation,
                    None,
                    None,
                    None,
                    Some(format!("invalid: {}", fields.join(", "))),
                );
                return WriteOutcome {
                    state: "rejected".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation: previous_generation,
                    applied: false,
                    detail: Some("кандидат отклонён validator-ом".to_owned()),
                };
            }
            ReloadOutcome::RestartRequired { fields, .. } => {
                self.events.push(
                    EventKind::ConfigRejected,
                    previous_generation,
                    None,
                    None,
                    None,
                    Some(format!("restart_required: {}", fields.join(", "))),
                );
                return WriteOutcome {
                    state: "restart_required".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation: previous_generation,
                    applied: false,
                    detail: Some("изменение требует перезапуска".to_owned()),
                };
            }
            ReloadOutcome::Conflict { current } => {
                return WriteOutcome {
                    state: "conflict".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation: current,
                    applied: false,
                    detail: Some("поколение изменилось до применения".to_owned()),
                };
            }
            ReloadOutcome::Busy | ReloadOutcome::GenerationBusy => {
                return WriteOutcome {
                    state: "saved".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation: previous_generation,
                    applied: false,
                    detail: Some("применение занято; повторите проверку".to_owned()),
                };
            }
            ReloadOutcome::TimedOut | ReloadOutcome::Cancelled => {
                return WriteOutcome {
                    state: "unknown".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation: previous_generation,
                    applied: false,
                    detail: Some("истёк срок применения".to_owned()),
                };
            }
            ReloadOutcome::ShuttingDown => {
                return WriteOutcome {
                    state: "saved".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation: previous_generation,
                    applied: false,
                    detail: Some("сервис завершает работу".to_owned()),
                };
            }
            ReloadOutcome::Internal => {
                return WriteOutcome {
                    state: "unknown".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation: previous_generation,
                    applied: false,
                    detail: Some("внутренняя ошибка применения".to_owned()),
                };
            }
        };
        let after = match self.proxy_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return WriteOutcome {
                    state: "unknown".to_owned(),
                    saved,
                    version: Some(saved_version.to_owned()),
                    generation: applied_generation,
                    applied: false,
                    detail: Some(error.message),
                };
            }
        };
        let matches = after.generation == applied_generation
            && if users_file {
                after.users_version.as_deref() == Some(saved_version)
                    && expected_users_version
                        .is_none_or(|value| after.users_version.as_deref() == Some(value))
            } else {
                after.config_version == saved_version
            };
        if !matches {
            self.events.push(
                EventKind::ConfigRejected,
                after.generation,
                None,
                None,
                None,
                Some("активная версия не совпала с сохранённой".to_owned()),
            );
            return WriteOutcome {
                state: "unknown".to_owned(),
                saved,
                version: Some(saved_version.to_owned()),
                generation: after.generation,
                applied: false,
                detail: Some("активная версия не совпала с сохранённой".to_owned()),
            };
        }
        if let Ok(mut baseline) = self.baseline.lock() {
            baseline.generation = Some(after.generation);
            baseline.active_config = Some(after.config_version.clone());
            baseline.active_users = after.users_version.clone();
            if users_file {
                baseline.disk_users = Some(saved_version.to_owned());
            } else {
                baseline.disk_config = Some(saved_version.to_owned());
            }
        }
        self.events.push(
            EventKind::ConfigApplied,
            after.generation,
            Some(after.config_version.clone()),
            after.users_version.clone(),
            None,
            Some(detail.to_owned()),
        );
        WriteOutcome {
            state: "applied".to_owned(),
            saved,
            version: Some(saved_version.to_owned()),
            generation: after.generation,
            applied: true,
            detail: Some(detail.to_owned()),
        }
    }

    async fn users_path(&self) -> Result<PathBuf, ApiError> {
        let path = self.options.config_path.clone();
        tokio::task::spawn_blocking(move || {
            let config = Config::load(&path)
                .map_err(|error| ApiError::new(ErrorCode::Unavailable, error.to_string()))?;
            config
                .auth()
                .map(|auth| auth.users_file().to_path_buf())
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::Unavailable,
                        "local authentication is not configured",
                    )
                })
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "users path task failed"))?
    }

    async fn hash_password(&self, password: Zeroizing<String>) -> Result<String, ApiError> {
        let permit = Arc::clone(&self.hash_permits)
            .try_acquire_owned()
            .map_err(|_| ApiError::new(ErrorCode::Busy, "password hashing is busy"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let salt = auth::generate_salt()
                .map_err(|_| ApiError::new(ErrorCode::Internal, "cannot generate a salt"))?;
            auth::hash_password(password.as_str(), &salt)
                .map_err(|_| ApiError::new(ErrorCode::Internal, "cannot hash the password"))
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal, "password task failed"))?
    }

    fn cached_result(&self, operation_id: &str, op: Op, username: &str) -> Option<WriteOutcome> {
        let Ok(mut operations) = self.operations.lock() else {
            return None;
        };
        let now = Instant::now();
        operations.retain(|_, cached| now.duration_since(cached.at) < OPERATION_TTL);
        operations
            .get(operation_id)
            .filter(|cached| cached.op == op && cached.username.as_deref() == Some(username))
            .map(|cached| cached.result.clone())
    }

    fn remember(
        &self,
        operation_id: &str,
        op: Op,
        username: Option<String>,
        result: &WriteOutcome,
    ) {
        let Ok(mut operations) = self.operations.lock() else {
            return;
        };
        if operations.len() >= MAX_CACHED_OPERATIONS
            && let Some(oldest) = operations
                .iter()
                .min_by_key(|(_, cached)| cached.at)
                .map(|(key, _)| key.clone())
        {
            operations.remove(&oldest);
        }
        operations.insert(
            operation_id.to_owned(),
            CachedOperation {
                op,
                username,
                result: result.clone(),
                at: Instant::now(),
            },
        );
    }

    async fn tick(self: &Arc<Self>) {
        let first = self
            .baseline
            .lock()
            .map(|baseline| !baseline.initialized)
            .unwrap_or(false);
        let config_path = self.options.config_path.clone();
        let owners = self.owners.clone();
        let disk = tokio::task::spawn_blocking(move || {
            let (config_bytes, _) =
                read_checked(&config_path, MAX_CONFIG_BYTES, &owners, false).ok()?;
            let config_version = content_version(&config_bytes);
            let parsed = Config::load(&config_path).ok()?;
            let users_version = parsed.auth().and_then(|auth| {
                let (bytes, _) =
                    read_checked(auth.users_file(), MAX_USERS_FILE_BYTES, &owners, true).ok()?;
                Some(content_version(&bytes))
            });
            Some((config_version, users_version))
        })
        .await
        .ok()
        .flatten();
        if let Some((config_version, users_version)) = disk {
            let (config_changed, users_changed) = {
                let mut baseline = match self.baseline.lock() {
                    Ok(baseline) => baseline,
                    Err(_) => return,
                };
                let config_changed = baseline.disk_config.as_deref() != Some(&config_version);
                let users_changed = baseline.disk_users != users_version;
                if config_changed {
                    baseline.disk_config = Some(config_version.clone());
                }
                if users_changed {
                    baseline.disk_users = users_version.clone();
                }
                (config_changed, users_changed)
            };
            if config_changed && !first {
                self.events.push(
                    EventKind::ConfigSaved,
                    self.baseline_generation(),
                    Some(config_version),
                    None,
                    None,
                    Some("файл конфигурации изменён на диске".to_owned()),
                );
            }
            if users_changed && !first {
                self.events.push(
                    EventKind::UsersSaved,
                    self.baseline_generation(),
                    None,
                    users_version,
                    None,
                    Some("файл пользователей изменён на диске".to_owned()),
                );
            }
        }
        let snapshot = match self.proxy_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(_) => return,
        };
        let (generation_changed, active_changed) = {
            let mut baseline = match self.baseline.lock() {
                Ok(baseline) => baseline,
                Err(_) => return,
            };
            let generation_changed = baseline.generation != Some(snapshot.generation);
            let active_changed = baseline.active_config.as_deref()
                != Some(&snapshot.config_version)
                || baseline.active_users != snapshot.users_version;
            if generation_changed || active_changed {
                baseline.generation = Some(snapshot.generation);
                baseline.active_config = Some(snapshot.config_version.clone());
                baseline.active_users = snapshot.users_version.clone();
            }
            (generation_changed, active_changed)
        };
        if (generation_changed || active_changed) && !first {
            self.events.push(
                EventKind::ConfigApplied,
                snapshot.generation,
                Some(snapshot.config_version),
                snapshot.users_version,
                None,
                Some("активное поколение обновлено".to_owned()),
            );
        }
        if let Ok(value) = self.relay(Op::Blocks, json!({"limit": 100})).await
            && let Ok(page) = serde_json::from_value::<control_protocol::BlocksPage>(value)
        {
            let now = Utc::now();
            let mut current = BTreeMap::new();
            for block in page.blocks {
                if let Some(until) = block
                    .blocked_until
                    .as_deref()
                    .and_then(auth::parse_blocked_until)
                {
                    current.insert(block.username, until);
                }
            }
            let mut baseline = match self.baseline.lock() {
                Ok(baseline) => baseline,
                Err(_) => return,
            };
            let previous = std::mem::replace(&mut baseline.blocks, current.clone());
            drop(baseline);
            for (username, until) in previous {
                if !first && !current.contains_key(&username) && now >= until {
                    self.events.push(
                        EventKind::BlockExpired,
                        self.baseline_generation(),
                        None,
                        None,
                        Some(username),
                        Some("срок блокировки истёк".to_owned()),
                    );
                }
            }
        }
        if let Ok(mut baseline) = self.baseline.lock() {
            baseline.initialized = true;
        }
    }

    fn baseline_generation(&self) -> u64 {
        self.baseline
            .lock()
            .ok()
            .and_then(|baseline| baseline.generation)
            .unwrap_or(0)
    }
}

async fn poll_loop(writer: Weak<ControlWriter>, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = ticker.tick() => {
                let Some(writer) = writer.upgrade() else {
                    break;
                };
                writer.tick().await;
            }
        }
    }
}

fn require_admin(admin: bool) -> Result<(), ApiError> {
    if admin {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::Unauthorized,
            "this connection may read but not change users or ACL",
        ))
    }
}

fn required_username(request: &Request) -> Result<String, ApiError> {
    let username = request
        .username
        .as_deref()
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "username is required"))?;
    if !is_valid_username(username) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "username must use 1..=64 ASCII letters, digits, dot, underscore or hyphen",
        ));
    }
    Ok(username.to_owned())
}

fn required_version(request: &Request) -> Result<String, ApiError> {
    let version = request
        .expected_version
        .as_deref()
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "expected_version is required"))?;
    if !auth::is_content_version(version) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "expected_version is not a content version",
        ));
    }
    Ok(version.to_owned())
}

fn required_operation_id(request: &Request) -> Result<String, ApiError> {
    let operation_id = request
        .operation_id
        .as_deref()
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "operation_id is required"))?;
    if operation_id.is_empty()
        || operation_id.len() > 128
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "operation_id must use 1..=128 ASCII letters, digits, dot, underscore or hyphen",
        ));
    }
    Ok(operation_id.to_owned())
}

fn take_checked_password(request: &mut Request) -> Result<Zeroizing<String>, ApiError> {
    let password = request
        .take_password()
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "password is required"))?;
    let confirmation = request
        .take_password_confirm()
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "password_confirm is required"))?;
    if !constant_time_equal(password.as_bytes(), confirmation.as_bytes()) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "password confirmation does not match",
        ));
    }
    let prepared = auth::prepare_password(password.as_str())
        .map_err(|error| ApiError::new(ErrorCode::InvalidRequest, error.to_string()))?;
    Ok(prepared)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn validate_users(candidate: &str) -> Result<(), CandidateError> {
    UsersSnapshot::parse(candidate)
        .map(|_| ())
        .map_err(|error| CandidateError::invalid(error.to_string(), vec!["users".to_owned()]))
}

fn validate_config_text(candidate: &str, path: &Path) -> Result<(), CandidateError> {
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    Config::parse_with_base_dir(candidate, base)
        .map(|_| ())
        .map_err(|error| CandidateError {
            restart_required: false,
            message: error.to_string(),
            fields: config_fields(&error),
        })
}

fn config_fields(error: &ConfigError) -> Vec<String> {
    match error {
        ConfigError::RestartRequired { path, .. } | ConfigError::Validation { path, .. } => {
            vec![path.clone()]
        }
        ConfigError::Toml { path, .. } => path.clone().into_iter().collect(),
        ConfigError::Read { .. } => vec!["config".to_owned()],
    }
}

fn candidate_api(error: CandidateError) -> ApiError {
    ApiError::new(
        if error.restart_required {
            ErrorCode::RestartRequired
        } else {
            ErrorCode::InvalidCandidate
        },
        error.message,
    )
    .with_fields(error.fields)
}

fn file_error(error: crate::control_files::FileError) -> ApiError {
    let code = if error.saved {
        ErrorCode::UnknownResult
    } else {
        match error.kind {
            FileErrorKind::NotFound => ErrorCode::NotFound,
            FileErrorKind::Conflict => ErrorCode::Conflict,
            FileErrorKind::InvalidCandidate => ErrorCode::InvalidCandidate,
            FileErrorKind::RestartRequired => ErrorCode::RestartRequired,
            FileErrorKind::Unsafe => ErrorCode::Unauthorized,
            FileErrorKind::TooLarge | FileErrorKind::Lock | FileErrorKind::Io => {
                ErrorCode::Internal
            }
        }
    };
    let mut api = ApiError::new(code, error.message).with_fields(error.fields);
    api.current_version = error.current_version;
    api.saved = error.saved.then_some(true);
    api
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

async fn send_envelope(
    write: &mut OwnedWriteHalf,
    event: Option<Event>,
    resync_cursor: Option<u64>,
) -> io::Result<()> {
    let envelope = EventEnvelope {
        v: API_VERSION,
        event,
        resync_cursor,
    };
    let line = control_protocol::encode_line(&envelope).map_err(io::Error::other)?;
    if tokio::time::timeout(
        Duration::from_secs(control_protocol::READ_TIMEOUT_SECS),
        write.write_all(line.as_bytes()),
    )
    .await
    .is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "subscriber write timeout",
        ));
    }
    write.flush().await
}

/// Whether a peer UID may mutate users/ACL.
pub fn is_admin(uid: u32, admin_group: &str, test_allow_uid: Option<u32>) -> bool {
    if uid == 0 || test_allow_uid == Some(uid) {
        return true;
    }
    let Some((gid, members)) = group_entry(admin_group) else {
        return false;
    };
    let Some((username, primary_gid)) = passwd_entry(uid) else {
        return false;
    };
    primary_gid == gid || members.iter().any(|member| member == &username)
}

fn group_entry(name: &str) -> Option<(u32, Vec<String>)> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    for line in text.lines() {
        let mut fields = line.split(':');
        let Some(group) = fields.next() else { continue };
        let _password = fields.next();
        let Some(gid) = fields.next().and_then(|value| value.parse().ok()) else {
            continue;
        };
        let members = fields
            .next()
            .map(|value| {
                value
                    .split(',')
                    .filter(|member| !member.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        if group == name {
            return Some((gid, members));
        }
    }
    None
}

fn group_gid(name: &str) -> Option<u32> {
    group_entry(name).map(|(gid, _)| gid)
}

fn passwd_entry(uid: u32) -> Option<(String, u32)> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next() else { continue };
        let _password = fields.next();
        let Some(entry_uid) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Some(gid) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        if entry_uid == uid {
            return Some((name.to_owned(), gid));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_membership_is_evaluated_for_the_peer_uid() {
        let current = effective_uid().unwrap_or(0);
        assert!(is_admin(0, "definitely-missing-group", None));
        assert!(is_admin(current, "definitely-missing-group", Some(current)));
        assert!(!is_admin(current, "definitely-missing-group", None));
    }

    #[test]
    fn saved_after_replace_maps_to_unknown_result() {
        let error = crate::control_files::FileError {
            kind: FileErrorKind::Io,
            message: "directory sync failed".to_owned(),
            fields: Vec::new(),
            current_version: None,
            saved: true,
        };
        let api = file_error(error);
        assert_eq!(api.code, ErrorCode::UnknownResult);
        assert_eq!(api.saved, Some(true));
    }

    #[test]
    fn operation_ids_are_strict_ascii() {
        for value in ["a", "abc.def_1-2", &"x".repeat(128)] {
            assert!(!value.is_empty());
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            );
        }
        assert!(
            "a b"
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
        );
    }
}
