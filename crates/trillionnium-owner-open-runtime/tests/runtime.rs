use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use trillionnium_owner_open_runtime::{
    AdbExecRequest, CancellationToken, ExecutionEvent, ExecutionEventKind, MechanicalLimits,
    ShellExecRequest, StreamKind, TerminalKind, execute_adb, execute_shell,
};

fn output(events: &[ExecutionEvent], stream: StreamKind) -> Vec<u8> {
    events
        .iter()
        .filter_map(|event| match &event.kind {
            ExecutionEventKind::Output {
                stream: candidate,
                bytes,
            } if *candidate == stream => Some(bytes.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

fn terminal_count(events: &[ExecutionEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event.kind, ExecutionEventKind::Terminal(_)))
        .count()
}

#[test]
fn command_string_streams_raw_stdout_stderr_and_preserves_failure() {
    let mut events = Vec::new();
    let terminal = execute_shell(
        ShellExecRequest::command(
            "call-command",
            "printf 'out\\000tail'; printf 'err' >&2; exit 7",
        ),
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| events.push(event),
    )
    .unwrap();

    assert_eq!(terminal.kind, TerminalKind::Exited);
    assert_eq!(terminal.exit_code, Some(7));
    assert_eq!(output(&events, StreamKind::Stdout), b"out\0tail");
    assert_eq!(output(&events, StreamKind::Stderr), b"err");
    assert_eq!(terminal_count(&events), 1);
    assert!(matches!(events[0].kind, ExecutionEventKind::Accepted));
    assert!(matches!(events[1].kind, ExecutionEventKind::Started { .. }));
}

#[test]
fn argv_is_element_preserving_and_does_not_expand_shell_text() {
    let mut events = Vec::new();
    let terminal = execute_shell(
        ShellExecRequest::argv(
            "call-argv",
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf '%s|%s' \"$1\" \"$2\"".to_string(),
                "unused-argv-zero".to_string(),
                "value with spaces".to_string(),
                "$HOME;not-expanded".to_string(),
            ],
        ),
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| events.push(event),
    )
    .unwrap();

    assert!(terminal.success());
    assert_eq!(
        output(&events, StreamKind::Stdout),
        b"value with spaces|$HOME;not-expanded"
    );
}

#[test]
fn cwd_environment_delta_and_stdin_are_mechanical_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let mut request = ShellExecRequest::command(
        "call-context",
        "printf '%s\\n' \"$TRILLIONNIUM_SET\"; printf '%s\\n' \"${TRILLIONNIUM_REMOVED-unset}\"; pwd; cat",
    );
    request.cwd = Some(directory.path().to_path_buf());
    request.env.insert(
        "TRILLIONNIUM_SET".to_string(),
        Some("exact value".to_string()),
    );
    request.env.insert("TRILLIONNIUM_REMOVED".to_string(), None);
    request.stdin = b"stdin bytes\0remain binary".to_vec();

    let mut events = Vec::new();
    let terminal = execute_shell(
        request,
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| events.push(event),
    )
    .unwrap();

    assert!(terminal.success());
    let stdout = output(&events, StreamKind::Stdout);
    assert!(stdout.starts_with(b"exact value\nunset\n"));
    assert!(
        stdout
            .windows(directory.path().as_os_str().as_encoded_bytes().len())
            .any(|window| window == directory.path().as_os_str().as_encoded_bytes())
    );
    assert!(stdout.ends_with(b"stdin bytes\0remain binary"));
}

#[test]
fn timeout_terminates_the_process_group_and_emits_one_terminal_event() {
    let limits = MechanicalLimits {
        terminate_grace: Duration::from_millis(20),
        ..MechanicalLimits::default()
    };
    let mut request = ShellExecRequest::command("call-timeout", "sleep 30");
    request.timeout = Some(Duration::from_millis(50));
    let mut events = Vec::new();

    let terminal = execute_shell(request, &limits, &CancellationToken::new(), |event| {
        events.push(event)
    })
    .unwrap();

    assert_eq!(terminal.kind, TerminalKind::TimedOut);
    assert_eq!(terminal_count(&events), 1);
    assert!(terminal.elapsed_ms < 5_000);
}

#[test]
fn cancellation_terminates_the_process_group_without_redispatch() {
    let limits = MechanicalLimits {
        terminate_grace: Duration::from_millis(20),
        ..MechanicalLimits::default()
    };
    let cancellation = CancellationToken::new();
    let canceller = cancellation.clone();
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        canceller.cancel();
    });
    let mut events = Vec::new();

    let terminal = execute_shell(
        ShellExecRequest::command("call-cancel", "sleep 30"),
        &limits,
        &cancellation,
        |event| events.push(event),
    )
    .unwrap();
    worker.join().unwrap();

    assert_eq!(terminal.kind, TerminalKind::Cancelled);
    assert_eq!(terminal_count(&events), 1);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, ExecutionEventKind::Started { .. }))
            .count(),
        1
    );
}

#[test]
fn output_exhaustion_is_mechanical_and_returns_truncated_observation() {
    let limits = MechanicalLimits {
        max_output_bytes: 32,
        stream_chunk_bytes: 8,
        terminate_grace: Duration::from_millis(20),
        ..MechanicalLimits::default()
    };
    let mut events = Vec::new();

    let terminal = execute_shell(
        ShellExecRequest::command(
            "call-output-cap",
            "i=0; while [ \"$i\" -lt 1000 ]; do printf x; i=$((i + 1)); done",
        ),
        &limits,
        &CancellationToken::new(),
        |event| events.push(event),
    )
    .unwrap();

    assert_eq!(terminal.kind, TerminalKind::OutputLimitExceeded);
    assert!(terminal.output_truncated);
    assert_eq!(terminal.stdout_bytes + terminal.stderr_bytes, 32);
    assert_eq!(output(&events, StreamKind::Stdout).len(), 32);
    assert_eq!(terminal_count(&events), 1);
}

#[test]
fn adb_exec_passes_unknown_future_argv_without_target_or_serial_injection() {
    // Use a stable system executable rather than a freshly-created script in a
    // temporary directory. Some CI sandboxes can mount temporary directories
    // with execution restrictions; that would test the runner filesystem, not
    // the ordinary-ADB exact-argv boundary.
    let mut request = AdbExecRequest::new(
        "call-adb-transparent",
        vec![
            "-c".to_string(),
            "printf '%s\\n' \"$1\" \"$2\" \"$3\"".to_string(),
            "unused-argv-zero".to_string(),
            "future-subcommand".to_string(),
            "--future-option".to_string(),
            "value with spaces".to_string(),
        ],
    );
    request.target_id = Some("android:diagnostic-only".to_string());
    request.adb_executable = PathBuf::from("/bin/sh");
    let mut events = Vec::new();

    let terminal = execute_adb(
        request,
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| events.push(event),
    )
    .unwrap();

    assert!(terminal.success(), "terminal={terminal:?}; events={events:#?}");
    assert_eq!(
        output(&events, StreamKind::Stdout),
        b"future-subcommand\n--future-option\nvalue with spaces\n"
    );
    let stdout = String::from_utf8(output(&events, StreamKind::Stdout)).unwrap();
    assert!(!stdout.contains("android:diagnostic-only"));
    assert!(!stdout.lines().any(|line| line == "-s"));
}

#[test]
fn spawn_failure_is_an_honest_terminal_observation() {
    let mut request = ShellExecRequest::argv(
        "call-spawn-failure",
        vec!["/definitely/not/a/real/executable".to_string()],
    );
    request.target_id = Some("rootlinux".to_string());
    let mut events = Vec::new();

    let terminal = execute_shell(
        request,
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| events.push(event),
    )
    .unwrap();

    assert_eq!(terminal.kind, TerminalKind::SpawnFailed);
    assert!(terminal.error.is_some());
    assert_eq!(terminal_count(&events), 1);
    assert!(matches!(events[0].kind, ExecutionEventKind::Accepted));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, ExecutionEventKind::Started { .. }))
    );
}

#[test]
fn malformed_adb_request_is_rejected_before_any_process_event() {
    let mut events = Vec::new();
    let error = execute_adb(
        AdbExecRequest::new("call-empty-adb", Vec::new()),
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| events.push(event),
    )
    .unwrap_err();

    assert!(error.to_string().contains("must not be empty"));
    assert!(events.is_empty());
}
