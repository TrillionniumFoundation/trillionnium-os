use std::path::PathBuf;

use trillionnium_owner_open_runtime::{
    AdbExecRequest, CancellationToken, ExecutionEvent, ExecutionEventKind, MechanicalLimits,
    PtySize, StreamKind, TerminalKind, execute_adb, execute_adb_pty, unconfigured_adb_request,
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

#[test]
fn raw_adb_preserves_argv_environment_and_nonzero_observation() {
    let mut request = AdbExecRequest::new(
        "raw-adb-nonzero",
        vec![
            "-c".to_string(),
            "printf '%s|%s|%s' \"$RAW_ADB_ENV\" \"$1\" \"$2\"; printf raw-adb-err >&2; exit 17"
                .to_string(),
            "argv-zero-placeholder".to_string(),
            "future-subcommand".to_string(),
            "--future-option=value with spaces".to_string(),
        ],
    );
    request.adb_executable = PathBuf::from("/bin/sh");
    request.target_id = Some("android:serial-without-injection".to_string());
    request.env.insert(
        "RAW_ADB_ENV".to_string(),
        Some("configured-value".to_string()),
    );

    let mut events = Vec::new();
    let terminal = execute_adb(
        request,
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| events.push(event),
    )
    .unwrap();

    assert_eq!(terminal.kind, TerminalKind::Exited);
    assert_eq!(terminal.exit_code, Some(17));
    assert_eq!(
        output(&events, StreamKind::Stdout),
        b"configured-value|future-subcommand|--future-option=value with spaces"
    );
    assert_eq!(output(&events, StreamKind::Stderr), b"raw-adb-err");
}

#[test]
fn raw_adb_pty_keeps_future_arguments_opaque_and_exposes_tty() {
    let mut request = AdbExecRequest::new(
        "raw-adb-pty",
        vec![
            "-c".to_string(),
            "if [ -t 1 ] && [ -t 2 ]; then printf 'pty-adb-ok:%s:%s' \"$1\" \"$2\"; exit 0; fi; exit 19"
                .to_string(),
            "argv-zero-placeholder".to_string(),
            "future-subcommand".to_string(),
            "--future-pty-option".to_string(),
        ],
    );
    request.adb_executable = PathBuf::from("/bin/sh");
    let mut events = Vec::new();

    let terminal = execute_adb_pty(
        request,
        PtySize::new(24, 80),
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| events.push(event),
    )
    .unwrap();

    assert!(terminal.success(), "terminal={terminal:?}");
    assert_eq!(
        output(&events, StreamKind::Pty),
        b"pty-adb-ok:future-subcommand:--future-pty-option"
    );
    assert_eq!(output(&events, StreamKind::Stdout), Vec::<u8>::new());
    assert_eq!(output(&events, StreamKind::Stderr), Vec::<u8>::new());
}

#[test]
fn raw_adb_unconfigured_request_retains_requested_argv() {
    let request = unconfigured_adb_request(
        "raw-adb-no-client",
        vec!["future-subcommand".to_string(), "--raw".to_string()],
    );
    assert!(request.adb_executable.as_os_str().is_empty());
    assert_eq!(request.argv, ["future-subcommand", "--raw"]);

    let terminal = execute_adb(
        request,
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |_| {},
    )
    .unwrap();
    assert_eq!(terminal.kind, TerminalKind::TransportUnavailable);
    assert!(terminal.error.is_some());
}
