//! Mechanism-only owner-open process substrate.
//!
//! This crate deliberately has no semantic command allowlist, risk classifier,
//! approval gate, target substitution, serial injection, or ADB subcommand
//! parser. It validates only framing/resource bounds, starts the exact process
//! selected by the caller, streams raw stdout/stderr bytes, and reports one
//! terminal observation.

mod process;
mod types;
mod validate;

pub use process::{execute_adb, execute_shell};
pub use types::{
    AdbExecRequest, CancellationToken, EnvironmentDelta, ExecutionEvent, ExecutionEventKind,
    ExecutionTerminal, MechanicalLimits, Result, RuntimeError, ShellExecRequest, ShellInvocation,
    StreamKind, TerminalKind, ToolKind,
};
