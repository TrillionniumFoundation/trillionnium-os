use std::sync::Mutex;

use crate::{JobRegistryError, Result};

/// Shared logical owned-state/staging reservation for the linked job module.
/// This does not cover arbitrary caller-retained snapshots or child RSS.
pub const MAX_JOB_OWNED_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESIDENT_BYTES: usize = 48 * 1024 * 1024;
const MAX_WORKING_BYTES: usize = MAX_JOB_OWNED_BYTES - MAX_RESIDENT_BYTES;
struct Pool {
    resident: usize,
    working: usize,
}
static OWNED_BYTES: Mutex<Pool> = Mutex::new(Pool {
    resident: 0,
    working: 0,
});

/// Noncloneable reservation. An owning Arc may share one lease across workers;
/// increasing a charge succeeds before the associated allocation/publication.
#[derive(Debug)]
pub struct JobMemoryLease {
    bytes: usize,
    working: bool,
}

impl JobMemoryLease {
    pub fn acquire(bytes: usize) -> Result<Self> {
        let mut lease = Self {
            bytes: 0,
            working: false,
        };
        lease.resize(bytes)?;
        Ok(lease)
    }

    /// Working headroom cannot be consumed by retained identities. Callers
    /// serialize the output DOM pipeline and release after all owned copies.
    pub fn acquire_working(bytes: usize) -> Result<Self> {
        let mut lease = Self {
            bytes: 0,
            working: true,
        };
        lease.resize(bytes)?;
        Ok(lease)
    }

    pub fn resize(&mut self, bytes: usize) -> Result<()> {
        let mut pool = OWNED_BYTES
            .lock()
            .map_err(|_| JobRegistryError::StatePoisoned)?;
        let (charged, maximum) = if self.working {
            (&mut pool.working, MAX_WORKING_BYTES)
        } else {
            (&mut pool.resident, MAX_RESIDENT_BYTES)
        };
        let without_self = charged
            .checked_sub(self.bytes)
            .ok_or(JobRegistryError::StatePoisoned)?;
        let next = without_self
            .checked_add(bytes)
            .ok_or(JobRegistryError::CapacityExhausted)?;
        if next > maximum {
            return Err(JobRegistryError::CapacityExhausted);
        }
        *charged = next;
        self.bytes = bytes;
        Ok(())
    }
}

impl Drop for JobMemoryLease {
    fn drop(&mut self) {
        if let Ok(mut pool) = OWNED_BYTES.lock() {
            let charged = if self.working {
                &mut pool.working
            } else {
                &mut pool.resident
            };
            debug_assert!(*charged >= self.bytes);
            *charged = charged.saturating_sub(self.bytes);
        }
        // Poisoned accounting remains unavailable instead of guessing which
        // identities/allocations survived an interrupted transition.
    }
}
