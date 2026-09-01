use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use trillionnium_owner_open_call_registry::{
    CallEventKind, CallKey, CallRegistry, EffectiveState, RegistryError, TurnScope,
};
use trillionnium_owner_open_runtime::{
    AdbExecRequest, ExecutionEvent, ExecutionEventKind, PtySize, ShellExecRequest, StreamKind,
    TerminalKind,
};
use trillionnium_owner_open_tool_bridge::{
    BoundToolCall, BridgeError, BridgeLimits, DirectToolBridge, DirectToolRequest, DispatchResult,
};

fn scope() -> TurnScope {
    TurnScope::new(
        "session-bridge",
        "owner-open",
        "task-bridge",
        "turn-bridge",
        "stream-bridge",
    )
}

fn key(call_id: &str) -> CallKey {
    CallKey::new(scope(), call_id)
}

fn shell_call(call_id: &str, canonical: &[u8], command: &str) -> BoundToolCall {
    BoundToolCall::new(
        key(call_id),
        "ab".repeat(32),
        Some("rootlinux".to_string()),
        canonical.to_vec(),
        DirectToolRequest::Shell(ShellExecRequest::command(call_id, command)),
    )
    .unwrap()
}

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

fn assert_sha256(value: &str) {
    assert_eq!(value.len(), 64);
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    );
}

#[test]
fn shell_call_records_pid_raw_events_terminal_and_observation_digest() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = Arc::clone(&events);
    let call = shell_call(
        "call-shell-success",
        br#"{"tool":"shell.exec","command":"printf 'out'; printf 'err' >&2"}"#,
        "printf 'out'; printf 'err' >&2",
    );

    let result = bridge
        .execute(call.clone(), &BridgeLimits::default(), move |event| {
            sink_events.lock().unwrap().push(event);
        })
        .unwrap();

    let (generation, terminal, observation_sha256, snapshot) = match result {
        DispatchResult::Executed {
            generation,
            terminal,
            observation_sha256,
            snapshot,
        } => (generation, terminal, observation_sha256, snapshot),
        other => panic!("unexpected dispatch result: {other:?}"),
    };
    assert!(generation > 0);
    assert!(terminal.success());
    assert_sha256(&observation_sha256);
    assert!(matches!(snapshot.state, EffectiveState::Terminal { .. }));
    let events = events.lock().unwrap();
    assert!(matches!(events[0].kind, ExecutionEventKind::Accepted));
    assert!(
        events
            .iter()
            .any(|event| matches!(event.kind, ExecutionEventKind::Started { .. }))
    );
    assert_eq!(output(&events, StreamKind::Stdout), b"out");
    assert_eq!(output(&events, StreamKind::Stderr), b"err");
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, ExecutionEventKind::Terminal(_)))
            .count(),
        1
    );

    match registry.snapshot(&call.key).unwrap().state {
        EffectiveState::Terminal {
            generation: recorded,
            terminal: recorded_terminal,
        } => {
            assert_eq!(recorded, generation);
            assert_eq!(recorded_terminal.observation_sha256, observation_sha256);
            assert_eq!(recorded_terminal.exit_code, Some(0));
        }
        other => panic!("registry did not retain the terminal: {other:?}"),
    }
}

#[test]
fn pty_call_records_merged_pty_stream_without_pipe_streams() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));
    let events = Arc::new(Mutex::new(Vec::new()));
    let command =
        "if [ -t 1 ] && [ -t 2 ]; then printf pty-out; printf pty-err >&2; else exit 8; fi";
    let mut request = ShellExecRequest::command("call-pty-bridge", command);
    request
        .env
        .insert("TERM".to_string(), Some("xterm-256color".to_string()));
    let call = BoundToolCall::new_with_pty(
        key("call-pty-bridge"),
        "ac".repeat(32),
        Some("rootlinux".to_string()),
        br#"{"tool":"shell.exec","command":"if [ -t 1 ] && [ -t 2 ]; then printf pty-out; printf pty-err >&2; else exit 8; fi","env":{"TERM":"xterm-256color"},"pty":{"enabled":true,"rows":24,"cols":80}}"#.to_vec(),
        DirectToolRequest::Shell(request),
        Some(PtySize::new(24, 80)),
    )
    .unwrap()
    ;
    let sink_events = Arc::clone(&events);

    let result = bridge
        .execute(call, &BridgeLimits::default(), move |event| {
            sink_events.lock().unwrap().push(event);
        })
        .unwrap();
    let terminal = match result {
        DispatchResult::Executed { terminal, .. } => terminal,
        other => panic!("unexpected PTY dispatch result: {other:?}"),
    };
    assert!(terminal.success());
    let events = events.lock().unwrap();
    let merged = output(&events, StreamKind::Pty);
    assert!(
        merged
            .windows(b"pty-out".len())
            .any(|window| window == b"pty-out")
    );
    assert!(
        merged
            .windows(b"pty-err".len())
            .any(|window| window == b"pty-err")
    );
    assert!(output(&events, StreamKind::Stdout).is_empty());
    assert!(output(&events, StreamKind::Stderr).is_empty());
}

#[test]
fn canonical_pty_binding_is_bidirectional() {
    let request = DirectToolRequest::Shell(ShellExecRequest::command("call-pty-binding", "true"));
    let enabled =
        br#"{"tool":"shell.exec","command":"true","pty":{"enabled":true,"rows":24,"cols":80}}"#;
    let disabled = br#"{"tool":"shell.exec","command":"true","pty":false}"#;

    let error = BoundToolCall::new(
        key("call-pty-enabled-without-transport"),
        "bd".repeat(32),
        Some("rootlinux".to_string()),
        enabled.to_vec(),
        request.clone(),
    )
    .unwrap_err();
    assert!(
        matches!(error, BridgeError::InvalidRequest(message) if message.contains("no PTY transport"))
    );

    let error = BoundToolCall::new_with_pty(
        key("call-pty-disabled-with-transport"),
        "be".repeat(32),
        Some("rootlinux".to_string()),
        disabled.to_vec(),
        request.clone(),
        Some(PtySize::new(24, 80)),
    )
    .unwrap_err();
    assert!(
        matches!(error, BridgeError::InvalidRequest(message) if message.contains("does not match"))
    );

    let call = BoundToolCall::new_with_pty(
        key("call-pty-clear"),
        "bf".repeat(32),
        Some("rootlinux".to_string()),
        enabled.to_vec(),
        request,
        Some(PtySize::new(24, 80)),
    )
    .unwrap();
    let error = call.with_pty(None).unwrap_err();
    assert!(
        matches!(error, BridgeError::InvalidRequest(message) if message.contains("no PTY transport"))
    );
}

#[test]
fn concurrent_duplicate_call_executes_one_real_process() {
    let directory = tempfile::tempdir().unwrap();
    let counter = directory.path().join("counter");
    let command = format!(
        "printf x >> '{}'; sleep 0.25; printf done",
        counter.display()
    );
    let call = shell_call(
        "call-concurrent-process",
        br#"{"tool":"shell.exec","command":"one-real-spawn"}"#,
        &command,
    );
    let registry = Arc::new(CallRegistry::default());
    let bridge = Arc::new(DirectToolBridge::new(Arc::clone(&registry)));
    let barrier = Arc::new(Barrier::new(2));

    let workers = (0..2)
        .map(|_| {
            let bridge = Arc::clone(&bridge);
            let barrier = Arc::clone(&barrier);
            let call = call.clone();
            thread::spawn(move || {
                barrier.wait();
                bridge
                    .execute(call, &BridgeLimits::default(), |_| {})
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, DispatchResult::Executed { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, DispatchResult::Existing(_)))
            .count(),
        1
    );
    assert_eq!(fs::read(&counter).unwrap(), b"x");
    assert!(matches!(
        registry.snapshot(&call.key).unwrap().state,
        EffectiveState::Terminal { .. }
    ));
}

#[test]
fn conflicting_canonical_bytes_are_rejected_without_second_spawn() {
    let directory = tempfile::tempdir().unwrap();
    let counter = directory.path().join("counter");
    let first = shell_call(
        "call-conflict",
        br#"{"tool":"shell.exec","command":"first"}"#,
        &format!("printf a >> '{}'", counter.display()),
    );
    let second = shell_call(
        "call-conflict",
        br#"{"tool":"shell.exec","command":"second"}"#,
        &format!("printf b >> '{}'", counter.display()),
    );
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));

    assert!(matches!(
        bridge
            .execute(first, &BridgeLimits::default(), |_| {})
            .unwrap(),
        DispatchResult::Executed { .. }
    ));
    let error = bridge
        .execute(second, &BridgeLimits::default(), |_| {})
        .unwrap_err();
    assert!(matches!(
        error,
        BridgeError::Registry(RegistryError::CallIdConflict)
    ));
    assert_eq!(fs::read(counter).unwrap(), b"a");
}

#[test]
fn claimed_request_digest_is_recomputed_before_registry_admission() {
    let registry = Arc::new(CallRegistry::default());
    let request = DirectToolRequest::Shell(ShellExecRequest::command(
        "call-digest-mismatch",
        "printf must-not-run",
    ));
    let error = BoundToolCall::with_claimed_digest(
        key("call-digest-mismatch"),
        "ab".repeat(32),
        Some("rootlinux".to_string()),
        br#"{"tool":"shell.exec","command":"must-not-run"}"#.to_vec(),
        "00".repeat(32),
        request,
    )
    .unwrap_err();
    assert!(matches!(error, BridgeError::ClaimedDigestMismatch { .. }));
    assert!(registry.is_empty().unwrap());
}

#[test]
fn registry_cancel_after_spawn_reaches_the_runtime_process_group() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = Arc::new(DirectToolBridge::new(Arc::clone(&registry)));
    let call = shell_call(
        "call-shared-cancel",
        br#"{"tool":"shell.exec","command":"sleep 30"}"#,
        "sleep 30",
    );
    let call_key = call.key.clone();
    let worker_bridge = Arc::clone(&bridge);
    let worker = thread::spawn(move || {
        worker_bridge
            .execute(
                call,
                &BridgeLimits {
                    cancellation_poll: Duration::from_millis(2),
                    ..BridgeLimits::default()
                },
                |_| {},
            )
            .unwrap()
    });

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if registry
            .snapshot(&call_key)
            .is_ok_and(|snapshot| matches!(snapshot.state, EffectiveState::Started { .. }))
        {
            break;
        }
        assert!(Instant::now() < deadline, "call never reached Started");
        thread::sleep(Duration::from_millis(2));
    }
    registry.request_cancel(&call_key).unwrap();

    match worker.join().unwrap() {
        DispatchResult::Executed { terminal, .. } => {
            assert_eq!(terminal.kind, TerminalKind::Cancelled)
        }
        other => panic!("unexpected cancelled dispatch result: {other:?}"),
    }
    assert!(matches!(
        registry.snapshot(&call_key).unwrap().state,
        EffectiveState::Terminal { .. }
    ));
}

#[test]
fn external_cancellation_is_published_to_registry_causality() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = Arc::new(DirectToolBridge::new(Arc::clone(&registry)));
    let external = Arc::new(AtomicBool::new(false));
    let call = shell_call(
        "call-external-cancel",
        br#"{"tool":"shell.exec","command":"sleep 30"}"#,
        "sleep 30",
    );
    let call_key = call.key.clone();
    let worker_bridge = Arc::clone(&bridge);
    let worker_external = Arc::clone(&external);
    let worker = thread::spawn(move || {
        worker_bridge
            .execute_fallible_with_external_flags(
                call,
                &BridgeLimits {
                    cancellation_poll: Duration::from_millis(2),
                    ..BridgeLimits::default()
                },
                [worker_external],
                |_| Ok::<(), String>(()),
            )
            .unwrap()
    });

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if registry
            .snapshot(&call_key)
            .is_ok_and(|snapshot| matches!(snapshot.state, EffectiveState::Started { .. }))
        {
            break;
        }
        assert!(Instant::now() < deadline, "call never reached Started");
        thread::sleep(Duration::from_millis(2));
    }
    external.store(true, Ordering::SeqCst);

    match worker.join().unwrap() {
        DispatchResult::Executed { terminal, .. } => {
            assert_eq!(terminal.kind, TerminalKind::Cancelled)
        }
        other => panic!("unexpected externally cancelled dispatch result: {other:?}"),
    }
    let snapshot = registry.snapshot(&call_key).unwrap();
    assert!(snapshot.cancellation_requested);
    assert!(
        registry
            .history_from(&call_key, 0)
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, CallEventKind::CancelRequested))
    );
}

#[test]
fn already_cancelled_external_scope_inhibits_spawn_and_records_history() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));
    let external = Arc::new(AtomicBool::new(true));
    let call = shell_call(
        "call-pre-cancelled",
        br#"{"tool":"shell.exec","command":"printf must-not-run"}"#,
        "printf must-not-run",
    );
    let key = call.key.clone();
    let result = bridge
        .execute_fallible_with_external_flags(call, &BridgeLimits::default(), [external], |_| {
            Ok::<(), String>(())
        })
        .unwrap();
    let snapshot = match result {
        DispatchResult::Inhibited(snapshot) => snapshot,
        other => panic!("unexpected pre-cancelled dispatch result: {other:?}"),
    };
    assert!(snapshot.cancellation_requested);
    assert!(matches!(
        snapshot.state,
        EffectiveState::CancelledBeforeSpawn
    ));
    assert!(
        registry
            .history_from(&key, 0)
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, CallEventKind::CancelRequested))
    );
}

#[test]
fn raw_adb_bridge_preserves_unknown_argv_and_does_not_inject_target() {
    let directory = tempfile::tempdir().unwrap();
    let fake_adb = directory.path().join("adb");
    fs::write(&fake_adb, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
    fs::set_permissions(&fake_adb, fs::Permissions::from_mode(0o700)).unwrap();
    let mut request = AdbExecRequest::new(
        "call-adb-bridge",
        vec![
            "future-subcommand".to_string(),
            "--future-option".to_string(),
            "value with spaces".to_string(),
        ],
    );
    request.adb_executable = fake_adb;
    request.target_id = Some("android:correlation-only".to_string());
    let call = BoundToolCall::new(
        key("call-adb-bridge"),
        "cd".repeat(32),
        Some("android:correlation-only".to_string()),
        br#"{"tool":"adb.exec","argv":["future-subcommand","--future-option","value with spaces"]}"#
            .to_vec(),
        DirectToolRequest::Adb(request),
    )
    .unwrap();
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(registry);
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = Arc::clone(&events);

    let result = bridge
        .execute(call, &BridgeLimits::default(), move |event| {
            sink_events.lock().unwrap().push(event);
        })
        .unwrap();
    assert!(matches!(result, DispatchResult::Executed { .. }));
    let stdout = output(&events.lock().unwrap(), StreamKind::Stdout);
    assert_eq!(
        stdout,
        b"future-subcommand\n--future-option\nvalue with spaces\n"
    );
    let text = String::from_utf8(stdout).unwrap();
    assert!(!text.contains("android:correlation-only"));
    assert!(!text.lines().any(|line| line == "-s"));
}

#[test]
fn spawn_failure_still_closes_the_registry_with_one_terminal() {
    let call = BoundToolCall::new(
        key("call-spawn-failure"),
        "ef".repeat(32),
        Some("rootlinux".to_string()),
        br#"{"tool":"shell.exec","argv":["/not/a/real/program"]}"#.to_vec(),
        DirectToolRequest::Shell(ShellExecRequest::argv(
            "call-spawn-failure",
            vec!["/not/a/real/program".to_string()],
        )),
    )
    .unwrap();
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));
    let result = bridge
        .execute(call.clone(), &BridgeLimits::default(), |_| {})
        .unwrap();
    match result {
        DispatchResult::Executed { terminal, .. } => {
            assert_eq!(terminal.kind, TerminalKind::SpawnFailed)
        }
        other => panic!("unexpected spawn-failure result: {other:?}"),
    }
    assert!(matches!(
        registry.snapshot(&call.key).unwrap().state,
        EffectiveState::Terminal { .. }
    ));
}
