//! Dynamic global admission caps shared by all configuration generations.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// One dynamic cap with RAII accounting.
#[derive(Debug)]
pub struct CapController {
    limit: AtomicUsize,
    active: AtomicUsize,
}

impl CapController {
    /// Creates a controller at `limit`.
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit: AtomicUsize::new(limit),
            active: AtomicUsize::new(0),
        })
    }

    /// Updates the global cap without touching active holders.
    pub fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Release);
    }

    /// Current configured cap.
    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Acquire)
    }

    /// Number of active holders.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Non-waiting acquisition. Refuses when the current cap is reached.
    pub fn try_acquire(self: &Arc<Self>) -> Option<CapPermit> {
        let limit = self.limit.load(Ordering::Acquire);
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(CapPermit {
                        controller: Arc::clone(self),
                    });
                }
                Err(actual) => active = actual,
            }
        }
    }
}

/// RAII holder of one dynamic cap slot.
pub struct CapPermit {
    controller: Arc<CapController>,
}

impl Drop for CapPermit {
    fn drop(&mut self) {
        self.controller.active.fetch_sub(1, Ordering::AcqRel);
    }
}
