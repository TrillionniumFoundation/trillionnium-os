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

use std::time::Instant;

pub use raw_adb::{
    DEFAULT_ADB_EXECUTABLE, executable_configured, unconfigured_request as unconfigured_adb_request,
};
pub use types::{
    AdbExecRequest, CancellationToken, EnvironmentDelta, ExecutionEvent, ExecutionEventKind,
    ExecutionTerminal, MAX_RUNTIME_ARGUMENT_BYTES, MAX_RUNTIME_ARGV_ITEMS,
    MAX_RUNTIME_CALL_ID_BYTES, MAX_RUNTIME_CWD_BYTES, MAX_RUNTIME_DEFAULT_TIMEOUT,
    MAX_RUNTIME_ENVIRONMENT_BYTES, MAX_RUNTIME_ENVIRONMENT_ITEMS, MAX_RUNTIME_OUTPUT_BYTES,
    MAX_RUNTIME_POLL_INTERVAL, MAX_RUNTIME_READER_BUFFER_BYTES, MAX_RUNTIME_READER_QUEUE_DEPTH,
    MAX_RUNTIME_REQUEST_TIMEOUT, MAX_RUNTIME_STDIN_BYTES, MAX_RUNTIME_STREAM_CHUNK_BYTES,
    MAX_RUNTIME_TARGET_ID_BYTES, MAX_RUNTIME_TERMINATE_GRACE, MAX_RUNTIME_TOTAL_ARGUMENT_BYTES,
    MechanicalLimits, PtySize, Result, RuntimeError, ShellExecRequest, ShellInvocation, StreamKind,
    TerminalKind, ToolKind,
};

/// Publish the accepted observation synchronously before entering any process
/// preparation or spawn path.
///
/// The caller's sink is the ownership boundary used by the Host to obtain a
/// durable acceptance receipt. A failed receipt cancels the linked token while
/// the sink is running. Re-checking it here means no PTY allocation, executable
/// resolution or process creation can occur after that failure. The lower-level
/// process implementation still emits its historical `Accepted` event; that
/// duplicate is suppressed so the public observation sequence remains exactly
/// `Accepted(0), Started/Terminal(1..)`.
fn execute_after_acceptance<F, R>(
    call_id: String,
    target_id: Option<String>,
    tool: ToolKind,
    cancellation: &CancellationToken,
    mut sink: F,
    run: R,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
    R: FnOnce(&mut dyn FnMut(ExecutionEvent)) -> Result<ExecutionTerminal>,
{
    let started_at = Instant::now();
    sink(ExecutionEvent {
        call_id: call_id.clone(),
        target_id: target_id.clone(),
        tool,
        seq: 0,
        elapsed_ms: 0,
        kind: ExecutionEventKind::Accepted,
    });

    if cancellation.is_cancelled() {
        let elapsed_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let terminal = ExecutionTerminal {
            kind: TerminalKind::Cancelled,
            exit_code: None,
            signal: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
            output_truncated: false,
            elapsed_ms,
            error: Some("effect admission cancelled before process spawn".to_string()),
        };
        sink(ExecutionEvent {
            call_id,
            target_id,
            tool,
            seq: 1,
            elapsed_ms,
            kind: ExecutionEventKind::Terminal(terminal.clone()),
        });
        return Ok(terminal);
    }

    let mut forward = |event: ExecutionEvent| {
        if matches!(event.kind, ExecutionEventKind::Accepted) {
            debug_assert_eq!(event.seq, 0);
            return;
        }
        sink(event);
    };
    run(&mut forward)
}

/// Execute a first-class shell request only after its accepted observation has
/// crossed the caller-owned synchronous admission boundary.
pub fn execute_shell<F>(
    request: ShellExecRequest,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    let call_id = request.call_id.clone();
    let target_id = request.target_id.clone();
    execute_after_acceptance(
        call_id,
        target_id,
        ToolKind::ShellExec,
        cancellation,
        sink,
        |forward| process::execute_shell(request, limits, cancellation, forward),
    )
}

/// Execute a shell request through a PTY under the same pre-effect acceptance
/// barrier as pipe mode.
pub fn execute_shell_pty<F>(
    request: ShellExecRequest,
    size: PtySize,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    let call_id = request.call_id.clone();
    let target_id = request.target_id.clone();
    execute_after_acceptance(
        call_id,
        target_id,
        ToolKind::ShellExec,
        cancellation,
        sink,
        |forward| process::execute_shell_pty(request, size, limits, cancellation, forward),
    )
}

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
    let call_id = request.call_id.clone();
    let target_id = request.target_id.clone();
    execute_after_acceptance(
        call_id,
        target_id,
        ToolKind::AdbExec,
        cancellation,
        sink,
        |forward| raw_adb::execute(request, limits, cancellation, forward),
    )
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
    let call_id = request.call_id.clone();
    let target_id = request.target_id.clone();
    execute_after_acceptance(
        call_id,
        target_id,
        ToolKind::AdbExec,
        cancellation,
        sink,
        |forward| raw_adb::execute_pty(request, size, limits, cancellation, forward),
    )
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn accepted_sink_cancellation_prevents_process_spawn() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut request =
            ShellExecRequest::command("receipt-failure", "printf x > effect-must-not-exist");
        request.cwd = Some(directory.path().to_path_buf());

        let cancellation = CancellationToken::new();
        let sink_cancellation = cancellation.clone();
        let mut events = Vec::new();
        let terminal = execute_shell(
            request,
            &MechanicalLimits::default(),
            &cancellation,
            |event| {
                let kind = event.kind.clone();
                if matches!(kind, ExecutionEventKind::Accepted) {
                    sink_cancellation.cancel();
                }
                events.push(kind);
            },
        )
        .expect("pre-effect cancellation is a terminal observation");

        assert_eq!(terminal.kind, TerminalKind::Cancelled);
        assert!(!directory.path().join("effect-must-not-exist").exists());
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], ExecutionEventKind::Accepted));
        assert!(matches!(events[1], ExecutionEventKind::Terminal(_)));
        assert!(
            events
                .iter()
                .all(|kind| !matches!(kind, ExecutionEventKind::Started { .. }))
        );
    }

    #[test]
    fn successful_admission_preserves_one_accepted_event() {
        let request = ShellExecRequest::command("single-accepted", "exit 0");
        let cancellation = CancellationToken::new();
        let mut events = Vec::new();
        let terminal = execute_shell(
            request,
            &MechanicalLimits::default(),
            &cancellation,
            |event| events.push(event.kind),
        )
        .expect("admitted command executes");

        assert!(terminal.success());
        assert_eq!(
            events
                .iter()
                .filter(|kind| matches!(kind, ExecutionEventKind::Accepted))
                .count(),
            1
        );
        assert!(
            events
                .iter()
                .any(|kind| matches!(kind, ExecutionEventKind::Started { .. }))
        );
        assert!(
            events
                .iter()
                .any(|kind| matches!(kind, ExecutionEventKind::Terminal(_)))
        );
    }
}
