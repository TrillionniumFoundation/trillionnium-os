//! Mechanism-only owner-open process substrate.
//!
//! This crate deliberately has no semantic command allowlist, risk classifier,
//! approval gate, target substitution, serial injection, or ADB subcommand
//! parser. It validates only framing/resource bounds, starts the exact process
//! selected by the caller, streams raw stdout/stderr bytes, and reports one
//! terminal observation.

mod process;
mod raw_adb;
mod types;
mod validate;

pub use process::{execute_shell, execute_shell_pty};
pub use raw_adb::{
    DEFAULT_ADB_EXECUTABLE, executable_configured, unconfigured_request as unconfigured_adb_request,
};
pub use types::{
    AdbExecRequest, CancellationToken, EnvironmentDelta, ExecutionEvent, ExecutionEventKind,
    ExecutionTerminal, MechanicalLimits, PtySize, Result, RuntimeError, ShellExecRequest,
    ShellInvocation, StreamKind, TerminalKind, ToolKind,
};

/// Execute raw ADB argv with pipe-based stdout/stderr streaming.
///
/// Keep this wrapper at the public crate boundary instead of only re-exporting
/// the implementation module: source/ABI auditors can identify the one
/// owner-open entry point, while the transport implementation remains
/// isolated in `raw_adb`.
pub fn execute_adb<F>(
    request: AdbExecRequest,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    raw_adb::execute(request, limits, cancellation, sink)
}

/// Execute raw ADB argv through a real PTY with one merged `pty` stream.
pub fn execute_adb_pty<F>(
    request: AdbExecRequest,
    size: PtySize,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    raw_adb::execute_pty(request, size, limits, cancellation, sink)
}
