//! Raw owner-open ADB transport entry points.
//!
//! The transport deliberately treats the executable and every argument as
//! opaque owner-selected values.  It does not know an ADB subcommand table,
//! inject `-s`, rewrite paths, clear the environment, or add an approval/risk
//! decision.  If no executable is configured, execution returns a truthful
//! `transport_unavailable` terminal observation.

use crate::process::execute_process;
use crate::types::{
    AdbExecRequest, CancellationToken, ExecutionEvent, ExecutionTerminal, MechanicalLimits,
    PtySize, Result,
};
use crate::validate::adb_spec;

/// The conventional PATH-resolved ADB client name.  Product code should set
/// `AdbExecRequest::adb_executable` to an installed ARM64 client or transparent
/// relay when the default name is not appropriate.
pub const DEFAULT_ADB_EXECUTABLE: &str = "adb";

/// Build an explicitly unconfigured request.
///
/// Keeping this state representable lets a Host report transport absence as a
/// terminal observation while preserving the requested argv for diagnostics.
#[must_use]
pub fn unconfigured_request(call_id: impl Into<String>, argv: Vec<String>) -> AdbExecRequest {
    AdbExecRequest::unconfigured(call_id, argv)
}

/// Whether an explicit executable value was supplied.  This is a mechanical
/// configuration helper only; a non-empty PATH name may still fail to resolve
/// at spawn time and will then be reported as `transport_unavailable`.
#[must_use]
pub fn executable_configured(request: &AdbExecRequest) -> bool {
    !request.adb_executable.as_os_str().is_empty()
}

/// Execute raw ADB argv with pipe-based stdout/stderr streaming.
pub fn execute<F>(
    request: AdbExecRequest,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    execute_process(adb_spec(request, limits)?, limits, cancellation, sink)
}

/// Execute raw ADB argv through a real PTY. PTY output is a merged terminal
/// stream and is emitted as the distinct `StreamKind::Pty` stream.
pub fn execute_pty<F>(
    request: AdbExecRequest,
    size: PtySize,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    size.validate()?;
    let mut spec = adb_spec(request, limits)?;
    spec.io_mode = crate::types::ProcessIoMode::Pty(size);
    execute_process(spec, limits, cancellation, sink)
}
