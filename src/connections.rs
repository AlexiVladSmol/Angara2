//! Bounded live-connection projection for the local control API.
//!
//! The registry never owns sockets or protocol state. It stores only service
//! identifiers, listener/transport labels, a coarse state and a start instant.
//! Entries beyond [`MAX_TRACKED_CONNECTIONS`] are not tracked; traffic is never
//! refused because the diagnostic projection is full.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Maximum simultaneously tracked connections.
pub const MAX_TRACKED_CONNECTIONS: usize = 256;

/// Coarse connection state exposed to operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// An ordinary HTTP/1.1 client connection.
    Http,
    /// A TLS handshake that has not completed yet.
    TlsHandshake,
    /// A CONNECT tunnel.
    Connect,
}

impl ConnectionState {
    fn code(self) -> u8 {
        match self {
            Self::Http => 0,
            Self::TlsHandshake => 1,
            Self::Connect => 2,
        }
    }

    fn from_code(value: u8) -> Self {
        match value {
            1 => Self::TlsHandshake,
            2 => Self::Connect,
            _ => Self::Http,
        }
    }
}

/// Safe connection row. No peer address, URL, host or credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRow {
    /// Server-created connection identifier.
    pub id: u64,
    /// Configured listener identifier.
    pub listener: String,
    /// `http` or `https`.
    pub transport: String,
    /// Current coarse state.
    pub state: ConnectionState,
    /// Whole milliseconds since admission.
    pub duration_ms: u64,
    /// Requests admitted on this connection.
    pub requests: u64,
}

struct Entry {
    listener: String,
    transport: &'static str,
    state: AtomicU8,
    started: Instant,
    requests: AtomicU64,
}

/// Process-wide bounded registry.
pub struct ConnectionRegistry {
    entries: Mutex<BTreeMap<u64, Arc<Entry>>>,
    next_id: AtomicU64,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Registers one admitted connection. Returns `None` when the diagnostic
    /// cap is already reached.
    pub fn open(
        self: &Arc<Self>,
        listener: &str,
        transport: &'static str,
    ) -> Option<ConnectionGuard> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(Entry {
            listener: listener.to_owned(),
            transport,
            state: AtomicU8::new(ConnectionState::Http.code()),
            started: Instant::now(),
            requests: AtomicU64::new(0),
        });
        let inserted = {
            let Ok(mut entries) = self.entries.lock() else {
                return None;
            };
            if entries.len() >= MAX_TRACKED_CONNECTIONS {
                false
            } else {
                entries.insert(id, Arc::clone(&entry));
                true
            }
        };
        inserted.then(|| ConnectionGuard {
            registry: Arc::downgrade(self),
            id,
            entry,
        })
    }

    /// Updates the coarse state for one tracked connection.
    pub fn set_state(&self, id: u64, state: ConnectionState) {
        let Ok(entries) = self.entries.lock() else {
            return;
        };
        if let Some(entry) = entries.get(&id) {
            entry.state.store(state.code(), Ordering::Release);
        }
    }

    /// Counts one admitted request on a tracked connection.
    pub fn count_request(&self, id: u64) {
        let Ok(entries) = self.entries.lock() else {
            return;
        };
        if let Some(entry) = entries.get(&id) {
            entry.requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Stable page ordered by connection id. `total` is the tracked count.
    pub fn page(&self, offset: usize, limit: usize) -> (Vec<ConnectionRow>, usize) {
        let Ok(entries) = self.entries.lock() else {
            return (Vec::new(), 0);
        };
        let total = entries.len();
        let rows = entries
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(id, entry)| ConnectionRow {
                id: *id,
                listener: entry.listener.clone(),
                transport: entry.transport.to_owned(),
                state: ConnectionState::from_code(entry.state.load(Ordering::Acquire)),
                duration_ms: u64::try_from(entry.started.elapsed().as_millis()).unwrap_or(u64::MAX),
                requests: entry.requests.load(Ordering::Relaxed),
            })
            .collect();
        (rows, total)
    }

    /// Number of tracked connections.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Removes its entry when the connection task ends, including cancellation.
pub struct ConnectionGuard {
    registry: Weak<ConnectionRegistry>,
    id: u64,
    entry: Arc<Entry>,
}

impl ConnectionGuard {
    /// Connection identifier stored in the registry.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Updates the coarse state through the guard's own entry.
    pub fn set_state(&self, state: ConnectionState) {
        self.entry.state.store(state.code(), Ordering::Release);
    }

    /// Counts one request without taking the registry lock.
    pub fn count_request(&self) {
        self.entry.requests.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade()
            && let Ok(mut entries) = registry.entries.lock()
        {
            entries.remove(&self.id);
        }
    }
}

impl std::fmt::Debug for ConnectionRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionRegistry")
            .field("tracked", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_is_bounded_and_guard_removes_the_entry() {
        let registry = Arc::new(ConnectionRegistry::new());
        let mut guards = Vec::new();
        for _ in 0..MAX_TRACKED_CONNECTIONS {
            guards.push(registry.open("loopback", "http").expect("tracked"));
        }
        assert!(registry.open("loopback", "http").is_none());
        assert_eq!(registry.len(), MAX_TRACKED_CONNECTIONS);

        let (page, total) = registry.page(0, 100);
        assert_eq!(total, MAX_TRACKED_CONNECTIONS);
        assert_eq!(page.len(), 100);
        assert!(page.iter().all(|row| row.state == ConnectionState::Http));

        guards[42].set_state(ConnectionState::Connect);
        guards[42].count_request();
        let (page, _) = registry.page(40, 5);
        let moved = page.iter().find(|row| row.id == guards[42].id()).unwrap();
        assert_eq!(moved.state, ConnectionState::Connect);
        assert_eq!(moved.requests, 1);

        let removed = guards.remove(42).id();
        assert!(
            !registry
                .page(0, MAX_TRACKED_CONNECTIONS)
                .0
                .iter()
                .any(|row| row.id == removed)
        );
        drop(guards);
        assert!(registry.is_empty());
    }
}
