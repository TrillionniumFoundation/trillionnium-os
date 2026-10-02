//! Capacity-based process admission. A lease lives through acceptance and cleanup.
use std::sync::Mutex;

use crate::types::{
    AdbExecRequest, MechanicalLimits, Result, RuntimeError, ShellExecRequest, ShellInvocation,
};

pub const MAX_RUNTIME_OWNED_BUFFER_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RUNTIME_ACTIVE_BUFFER_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RUNTIME_ACTIVE_PROCESSES: usize = 16;
pub const MAX_RUNTIME_INHERITED_ENV_BYTES: usize = 1024 * 1024;
const FIXED_OPERATION_BYTES: usize = 3 * 1024 * 1024;

fn over_budget() -> RuntimeError {
    RuntimeError::InvalidRequest("runtime aggregate owned buffer budget exhausted".into())
}
fn add(sum: usize, value: usize) -> Result<usize> {
    sum.checked_add(value).ok_or_else(over_budget)
}
fn multiply(value: usize, factor: usize) -> Result<usize> {
    value.checked_mul(factor).ok_or_else(over_budget)
}
fn check(bytes: usize) -> Result<usize> {
    if bytes > MAX_RUNTIME_OWNED_BUFFER_BYTES {
        return Err(over_budget());
    }
    Ok(bytes)
}
fn reader_reservation(limits: &MechanicalLimits) -> Result<usize> {
    // One shared queue, two reader buffers, two blocked senders, current chunk
    // and copied sink event. Factor two covers transient growth/copies; the
    // fixed reserve covers small metadata, channel nodes and worker controls.
    let slots = add(limits.reader_queue_depth, 6)?;
    let bytes = multiply(multiply(slots, limits.stream_chunk_bytes)?, 2)?;
    add(add(bytes, multiply(slots, 128)?)?, FIXED_OPERATION_BYTES)
}

pub(crate) fn profile_reservation(limits: &MechanicalLimits) -> Result<usize> {
    let mut metadata = 0;
    for bytes in [
        limits.max_call_id_bytes,
        limits.max_target_id_bytes,
        multiply(limits.max_cwd_bytes, 2)?,
        limits.max_total_argument_bytes,
        limits.max_environment_bytes,
        multiply(limits.max_argv_items, std::mem::size_of::<String>())?,
        multiply(limits.max_environment_items, 256)?,
    ] {
        metadata = add(metadata, bytes)?;
    }
    check(add(
        add(reader_reservation(limits)?, limits.max_stdin_bytes)?,
        multiply(metadata, 3)?,
    )?)
}

fn common_owned(
    call_id: &String,
    target_id: Option<&String>,
    cwd: Option<&std::path::PathBuf>,
    env: &crate::types::EnvironmentDelta,
) -> Result<usize> {
    let mut bytes = call_id.capacity();
    if let Some(value) = target_id {
        bytes = add(bytes, value.capacity())?;
    }
    if let Some(value) = cwd {
        bytes = add(bytes, value.capacity())?;
    }
    for (key, value) in env {
        bytes = add(add(bytes, 256)?, key.capacity())?;
        if let Some(value) = value {
            bytes = add(bytes, value.capacity())?;
        }
    }
    Ok(bytes)
}
fn argv_owned(argv: &Vec<String>) -> Result<usize> {
    argv.iter().try_fold(
        multiply(argv.capacity(), std::mem::size_of::<String>())?,
        |sum, argument| add(sum, argument.capacity()),
    )
}
fn complete_owned(
    metadata: usize,
    stdin_capacity: usize,
    limits: &MechanicalLimits,
) -> Result<usize> {
    // Request -> spec -> Command/acceptance copies. Stdin moves to its writer;
    // output retained by the caller's sink belongs to that caller's budget.
    check(add(
        add(reader_reservation(limits)?, stdin_capacity)?,
        multiply(metadata, 3)?,
    )?)
}
pub(crate) fn shell_owned(request: &ShellExecRequest, limits: &MechanicalLimits) -> Result<usize> {
    let mut metadata = common_owned(
        &request.call_id,
        request.target_id.as_ref(),
        request.cwd.as_ref(),
        &request.env,
    )?;
    metadata = add(metadata, request.shell_executable.capacity())?;
    metadata = add(
        metadata,
        match &request.invocation {
            ShellInvocation::Command(command) => add(command.capacity(), 128)?,
            ShellInvocation::Argv(argv) => argv_owned(argv)?,
        },
    )?;
    complete_owned(metadata, request.stdin.capacity(), limits)
}
pub(crate) fn adb_owned(request: &AdbExecRequest, limits: &MechanicalLimits) -> Result<usize> {
    let metadata = add(
        add(
            common_owned(
                &request.call_id,
                request.target_id.as_ref(),
                request.cwd.as_ref(),
                &request.env,
            )?,
            request.adb_executable.capacity(),
        )?,
        argv_owned(&request.argv)?,
    )?;
    complete_owned(metadata, request.stdin.capacity(), limits)
}

#[derive(Default)]
struct Usage {
    bytes: usize,
    processes: usize,
}
static ACTIVE: Mutex<Usage> = Mutex::new(Usage {
    bytes: 0,
    processes: 0,
});

pub struct ExecutionCapacity {
    bytes: usize,
    inherited: Vec<(std::ffi::OsString, std::ffi::OsString)>,
}
impl ExecutionCapacity {
    pub(crate) fn inherited(&self) -> &[(std::ffi::OsString, std::ffi::OsString)] {
        &self.inherited
    }
    pub(crate) fn ensure(&self, bytes: usize) -> Result<()> {
        if bytes > self.bytes {
            return Err(over_budget());
        }
        Ok(())
    }
    pub(crate) fn acquire(bytes: usize) -> Result<Self> {
        check(bytes)?;
        // Freeze the environment that Command would otherwise read after
        // admission. Preserve all inherited values and then apply the request
        // delta; a changed host environment cannot evade this snapshot bound.
        let mut inherited = Vec::new();
        let mut inherited_bytes = 0usize;
        for (key, value) in std::env::vars_os() {
            inherited_bytes = add(
                add(add(inherited_bytes, key.capacity())?, value.capacity())?,
                256,
            )?;
            if inherited_bytes > MAX_RUNTIME_INHERITED_ENV_BYTES {
                return Err(RuntimeError::InvalidRequest(
                    "runtime inherited environment exceeds its capacity budget".into(),
                ));
            }
            inherited.push((key, value));
        }
        let mut active = ACTIVE.lock().map_err(|_| over_budget())?;
        let next_bytes = add(active.bytes, bytes)?;
        let next_count = add(active.processes, 1)?;
        if next_bytes > MAX_RUNTIME_ACTIVE_BUFFER_BYTES || next_count > MAX_RUNTIME_ACTIVE_PROCESSES
        {
            return Err(RuntimeError::InvalidRequest(
                "runtime shared process/buffer capacity exhausted".into(),
            ));
        }
        active.bytes = next_bytes;
        active.processes = next_count;
        Ok(Self { bytes, inherited })
    }
}
impl Drop for ExecutionCapacity {
    fn drop(&mut self) {
        // No user code runs under this lock. Poison prevents new admission;
        // existing owners still return exactly their reservation on cleanup.
        let mut active = ACTIVE.lock().unwrap_or_else(|error| error.into_inner());
        active.bytes -= self.bytes;
        active.processes -= 1;
    }
}
