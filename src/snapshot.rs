//! Atomic runtime configuration generation and bounded root registry.

use std::sync::{Arc, Mutex, Weak};

use arc_swap::ArcSwap;

use crate::config::Config;

/// Maximum number of simultaneously live published roots.
pub const MAX_LIVE_GENERATIONS: usize = 16;

/// One immutable configuration/user generation.
pub struct RuntimeSnapshot {
    generation: u64,
    config: Arc<Config>,
}

impl RuntimeSnapshot {
    fn new(generation: u64, config: Arc<Config>) -> Self {
        Self { generation, config }
    }

    /// Published generation, starting at 1.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Immutable validated configuration and users snapshot.
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }
}

/// A publication conflict or generation budget failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishError {
    /// The caller expected a different current generation.
    Conflict,
    /// Publishing would retain more than [`MAX_LIVE_GENERATIONS`] roots.
    GenerationBusy,
    /// Generation counter exhausted.
    Exhausted,
}

/// One root Arc and a bounded registry of live generations.
pub struct SnapshotStore {
    current: ArcSwap<RuntimeSnapshot>,
    live: Mutex<Vec<Weak<RuntimeSnapshot>>>,
    publish: Mutex<()>,
}

impl SnapshotStore {
    /// Creates generation 1 from the startup config.
    pub fn new(config: Arc<Config>) -> Arc<Self> {
        let root = Arc::new(RuntimeSnapshot::new(1, config));
        let store = Arc::new(Self {
            current: ArcSwap::from(Arc::clone(&root)),
            live: Mutex::new(vec![Arc::downgrade(&root)]),
            publish: Mutex::new(()),
        });
        drop(root);
        store
    }

    /// Strong current root for one exchange or status snapshot.
    pub fn load(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    /// Current generation without retaining the root.
    pub fn generation(&self) -> u64 {
        self.current.load().generation()
    }

    /// Number of roots still actually held, including the current root.
    pub fn live_generations(&self) -> usize {
        let Ok(mut live) = self.live.lock() else {
            return 0;
        };
        Self::prune(&mut live);
        live.len()
    }

    fn prune(live: &mut Vec<Weak<RuntimeSnapshot>>) {
        live.retain(|weak| weak.strong_count() > 0);
    }

    /// Publishes `config` if `expected` still matches and the root budget is
    /// not exhausted. The generation increments only after the new root is
    /// fully constructed.
    pub fn publish(&self, expected: u64, config: Arc<Config>) -> Result<u64, PublishError> {
        let Ok(_guard) = self.publish.lock() else {
            return Err(PublishError::Conflict);
        };
        let current = self.current.load_full();
        if current.generation() != expected {
            return Err(PublishError::Conflict);
        }
        let next = expected.checked_add(1).ok_or(PublishError::Exhausted)?;
        {
            let Ok(mut live) = self.live.lock() else {
                return Err(PublishError::GenerationBusy);
            };
            Self::prune(&mut live);
            if live.len() >= MAX_LIVE_GENERATIONS {
                return Err(PublishError::GenerationBusy);
            }
            let root = Arc::new(RuntimeSnapshot::new(next, config));
            self.current.store(Arc::clone(&root));
            live.push(Arc::downgrade(&root));
        }
        Ok(next)
    }
}

impl std::fmt::Debug for SnapshotStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotStore")
            .field("generation", &self.generation())
            .field("live", &self.live_generations())
            .finish()
    }
}
