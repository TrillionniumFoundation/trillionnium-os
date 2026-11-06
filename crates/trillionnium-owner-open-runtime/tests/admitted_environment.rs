//! Environment mutation requires a genuinely single-threaded fixture. A
//! harness-free parent starts one fresh, cleared-environment child per entry
//! point; only that child mutates its own harmless sentinel values, before the
//! runtime creates any workers. No caller environment values are inspected.

use std::path::PathBuf;
use std::process::Command;

use trillionnium_owner_open_runtime::{
    AdbExecRequest, CancellationToken, ExecutionEvent, ExecutionEventKind, MechanicalLimits,
    PtySize, ShellExecRequest, StreamKind, execute_adb_pty_with_capacity,
    execute_adb_with_capacity, execute_shell_pty_with_capacity, execute_shell_with_capacity,
    reserve_adb_capacity, reserve_shell_capacity,
};

const MODES: [&str; 4] = ["shell-pipe", "shell-pty", "adb-pipe", "adb-pty"];
const COMMAND: &str = "printf '%s|%s|%s|%s|%s|%s' \
    \"${TERM-unset}\" \"${HOME-unset}\" \"${NO_COLOR-unset}\" \
    \"${RUNTIME_SNAPSHOT_FORBIDDEN-unset}\" \"${LANG-unset}\" \"${LC_ALL-unset}\"";
const EXPECTED: &[u8] = b"admitted-term|admitted-home|unset|unset|C|unset";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--fixture") {
        let mode = args.get(2).expect("fixture mode is required");
        assert!(MODES.contains(&mode.as_str()));
        fixture(mode);
        return;
    }

    let executable = std::env::current_exe().expect("fixture executable is available");
    let mut failures = Vec::new();
    for mode in MODES {
        let output = Command::new(&executable)
            .args(["--fixture", mode])
            .env_clear()
            .env("TERM", "admitted-term")
            .env("HOME", "admitted-home")
            .env("LANG", "POSIX")
            .env("LC_ALL", "C")
            .env("RUNTIME_SNAPSHOT_FORBIDDEN", "admitted-forbidden")
            .output()
            .expect("isolated fixture starts");
        if !output.status.success() {
            failures.push(mode);
            eprintln!(
                "{mode} snapshot fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    assert!(
        failures.is_empty(),
        "snapshot entrypoints failed: {failures:?}"
    );
}

fn fixture(mode: &str) {
    let limits = MechanicalLimits::default();
    let cancellation = CancellationToken::new();
    let mut shell = ShellExecRequest::command("snapshot-shell", COMMAND);
    let mut adb = AdbExecRequest::new("snapshot-adb", vec!["-c".to_string(), COMMAND.to_string()]);
    // This is an ordinary local shell fixture, never an ADB/device operation.
    adb.adb_executable = PathBuf::from("/bin/sh");
    for environment in [&mut shell.env, &mut adb.env] {
        environment.insert("LANG".to_string(), Some("C".to_string()));
        environment.insert("LC_ALL".to_string(), None);
    }
    let capacity = if mode.starts_with("shell") {
        reserve_shell_capacity(&shell, &limits)
    } else {
        reserve_adb_capacity(&adb, &limits)
    }
    .expect("the fixed sentinel snapshot is admitted");

    // SAFETY: this harness-free fixture is a fresh, single-threaded process.
    // No runtime execution or worker has started. The enclosing parent uses
    // env_clear and supplies only the fixed, non-sensitive values above. No
    // other code reads the environment concurrently, and no mutation occurs
    // after execute_* creates runtime workers.
    unsafe {
        std::env::set_var("TERM", "later-term");
        std::env::remove_var("HOME");
        std::env::set_var("NO_COLOR", "later-only");
        std::env::set_var("RUNTIME_SNAPSHOT_FORBIDDEN", "later-forbidden");
        std::env::set_var("LANG", "C.UTF-8");
    }

    let mut output = Vec::new();
    let mut observe = |event: ExecutionEvent| {
        if let ExecutionEventKind::Output { stream, bytes } = event.kind
            && matches!(stream, StreamKind::Stdout | StreamKind::Pty)
        {
            output.extend_from_slice(&bytes);
        }
    };
    let terminal = match mode {
        "shell-pipe" => {
            execute_shell_with_capacity(shell, &limits, &cancellation, capacity, &mut observe)
        }
        "shell-pty" => execute_shell_pty_with_capacity(
            shell,
            PtySize::default(),
            &limits,
            &cancellation,
            capacity,
            &mut observe,
        ),
        "adb-pipe" => {
            execute_adb_with_capacity(adb, &limits, &cancellation, capacity, &mut observe)
        }
        "adb-pty" => execute_adb_pty_with_capacity(
            adb,
            PtySize::default(),
            &limits,
            &cancellation,
            capacity,
            &mut observe,
        ),
        _ => unreachable!("parent selects a known entrypoint"),
    }
    .expect("admitted runtime execution returns a terminal");
    assert!(terminal.success(), "{mode}: {terminal:?}");
    assert_eq!(
        output, EXPECTED,
        "{mode}: admitted allowlisted values drifted"
    );
}
