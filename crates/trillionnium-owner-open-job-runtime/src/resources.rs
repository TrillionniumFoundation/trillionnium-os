//! Logical owned-buffer admission, separate from allocator and child RSS.
use std::ffi::OsString;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{JobInvocation, JobRuntimeConfig, JobRuntimeError, JobStartRequest, Result};
use trillionnium_owner_open_job_registry::JobMemoryLease;

pub(crate) const MAX_START_SPEC_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_START_ARGV: usize = 4096;
pub(crate) const MAX_START_ENV: usize = 1024;
pub(crate) const MAX_INHERITED_ENV_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_INHERITED_ENV_VALUE_BYTES: usize = 64 * 1024;
pub(crate) const SHARED_PROCESS_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const SHARED_PROCESS_OWNERS: usize = 16;
const FIXED_PROCESS_STAGING: usize = 64 * 1024;

#[derive(Debug, Default)]
struct Pool {
    bytes: usize,
    owners: usize,
}

static PROCESS_POOL: Mutex<Pool> = Mutex::new(Pool {
    bytes: 0,
    owners: 0,
});
static WORKING_LANE: Mutex<()> = Mutex::new(());

pub(crate) fn working_lane() -> Result<MutexGuard<'static, ()>> {
    WORKING_LANE
        .lock()
        .map_err(|_| JobRuntimeError::StatePoisoned)
}

/// Arc clones share one charge. Workers keep their own Arc so detaching a
/// worker after a cleanup error cannot prematurely release its reservation.
#[derive(Debug)]
pub(crate) struct ProcessLease {
    bytes: usize,
    _owned_lease: JobMemoryLease,
}

impl ProcessLease {
    pub(crate) fn acquire(bytes: usize) -> Result<Arc<Self>> {
        let mut pool = PROCESS_POOL
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        let next = add(pool.bytes, bytes)?;
        if next > SHARED_PROCESS_BYTES || pool.owners >= SHARED_PROCESS_OWNERS {
            return Err(exhausted());
        }
        let owned_lease = JobMemoryLease::acquire(bytes).map_err(|_| exhausted())?;
        pool.bytes = next;
        pool.owners += 1;
        Ok(Arc::new(Self {
            bytes,
            _owned_lease: owned_lease,
        }))
    }
}

impl Drop for ProcessLease {
    fn drop(&mut self) {
        if let Ok(mut pool) = PROCESS_POOL.lock() {
            debug_assert!(pool.bytes >= self.bytes && pool.owners > 0);
            pool.bytes = pool.bytes.saturating_sub(self.bytes);
            pool.owners = pool.owners.saturating_sub(1);
        }
        // A poisoned pool never admits another owner; do not recover capacity
        // by guessing which charges survived a panic.
    }
}

fn exhausted() -> JobRuntimeError {
    JobRuntimeError::InvalidRequest(
        "job owned memory capacity is exhausted before acceptance".to_string(),
    )
}

fn add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize> {
    left.checked_mul(right).ok_or_else(exhausted)
}

/// Inspect caller-owned spare capacity before a digest DOM or Command clone.
/// The caller already allocated these buffers; rejection prevents this module
/// from retaining/cloning them or crossing durable acceptance/effect.
pub(crate) fn start_spec_bytes(
    request: &JobStartRequest,
    config: &JobRuntimeConfig,
) -> Result<usize> {
    if request.initial_stdin.capacity() > config.max_input_bytes
        || request.env.len() > MAX_START_ENV
    {
        return Err(exhausted());
    }
    let mut bytes = std::mem::size_of::<JobStartRequest>();
    for value in [
        &request.key.scope.session_id,
        &request.key.scope.profile_id,
        &request.key.scope.task_id,
        &request.key.scope.turn_id,
        &request.key.scope.turn_stream_id,
        &request.key.job_id,
        &request.request.request_sha256,
        &request.request.binding_fingerprint,
        &request.request.tool,
        &request.request.mode,
        &request.operation_id,
    ] {
        bytes = add(bytes, value.capacity())?;
    }
    if let Some(target) = &request.request.target_id {
        bytes = add(bytes, target.capacity())?;
    }
    bytes = add(bytes, request.shell_executable.capacity())?;
    if let Some(cwd) = &request.cwd {
        bytes = add(bytes, cwd.capacity())?;
    }
    match &request.invocation {
        JobInvocation::Command { command } => bytes = add(bytes, command.capacity())?,
        JobInvocation::Argv { argv } => {
            if argv.len() > MAX_START_ARGV || argv.capacity() > MAX_START_ARGV {
                return Err(exhausted());
            }
            bytes = add(bytes, mul(argv.capacity(), std::mem::size_of::<String>())?)?;
            for argument in argv {
                bytes = add(bytes, argument.capacity())?;
            }
        }
    }
    bytes = add(bytes, mul(request.env.len(), 256)?)?;
    for (key, value) in &request.env {
        bytes = add(bytes, key.capacity())?;
        if let Some(value) = value {
            bytes = add(bytes, value.capacity())?;
        }
    }
    if bytes > MAX_START_SPEC_BYTES {
        return Err(exhausted());
    }
    Ok(bytes)
}

pub(crate) fn process_reservation(
    request: &JobStartRequest,
    config: &JobRuntimeConfig,
    inherited: &[(OsString, OsString)],
) -> Result<usize> {
    let spec = start_spec_bytes(request, config)?;
    let mut inherited_bytes = mul(inherited.len(), 128)?;
    for (key, value) in inherited {
        if value.capacity() > MAX_INHERITED_ENV_VALUE_BYTES {
            return Err(exhausted());
        }
        inherited_bytes = add(add(inherited_bytes, key.capacity())?, value.capacity())?;
    }
    if inherited_bytes > MAX_INHERITED_ENV_BYTES {
        return Err(exhausted());
    }
    // Full channel, both readers, blocked sends and dispatcher copies. The
    // original stdin allocation and worker clone coexist. Twelve spec copies
    // cover source, two digest DOMs, worst-case JSON escaping, envelope and
    // Command/exec staging; three inherited copies cover snapshot/Command/exec.
    let buffers = mul(
        config.max_output_chunk_bytes,
        crate::process::PROCESS_EVENT_QUEUE + 6,
    )?;
    let stdin = add(
        request.initial_stdin.capacity(),
        request.initial_stdin.len(),
    )?;
    add(
        add(
            add(add(buffers, stdin)?, mul(spec, 12)?)?,
            mul(inherited_bytes, 3)?,
        )?,
        FIXED_PROCESS_STAGING,
    )
}
