use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use trillionnium_owner_open_call_registry::{CallKey, CallRegistry};
use trillionnium_owner_open_runtime::{
    AdbExecRequest, ExecutionEventKind, ShellExecRequest, StreamKind, TerminalKind,
};
use trillionnium_owner_open_tool_bridge::{BoundToolCall, DirectToolRequest};
use trillionnium_owner_open_turn_loop::{
    ProviderEvent, ProviderHost, ProviderTerminal, ProviderTerminalStatus, SameTurnProvider,
    ToolOutcome, TurnEventKind, TurnRequest, TurnRunner,
};

fn request() -> TurnRequest {
    TurnRequest {
        session_id: "session-r5".to_string(),
        profile_id: "owner-open".to_string(),
        task_id: "task-r5".to_string(),
        turn_id: "turn-r5".to_string(),
        turn_stream_id: "stream-r5".to_string(),
        user_input: "exercise the same-turn tool loop".to_string(),
    }
}

fn shell_call(
    request: &TurnRequest,
    call_id: &str,
    canonical: &[u8],
    command: &str,
) -> BoundToolCall {
    BoundToolCall::new(
        CallKey::new(request.scope(), call_id),
        "ab".repeat(32),
        Some("rootlinux".to_string()),
        canonical.to_vec(),
        DirectToolRequest::Shell(ShellExecRequest::command(call_id, command)),
    )
    .unwrap()
}

fn output(
    events: &[trillionnium_owner_open_runtime::ExecutionEvent],
    stream: StreamKind,
) -> Vec<u8> {
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

struct ContinueAfterFailure;

impl SameTurnProvider for ContinueAfterFailure {
    fn run_turn(
        &mut self,
        request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> Result<ProviderTerminal, String> {
        host.emit(ProviderEvent::ModelDelta("before-tool".to_string()))
            .map_err(|error| error.to_string())?;
        let outcome = host
            .invoke_tool(shell_call(
                request,
                "call-failure-observation",
                br#"{"tool":"shell.exec","command":"printf out; printf err >&2; exit 7"}"#,
                "printf out; printf err >&2; exit 7",
            ))
            .map_err(|error| error.to_string())?;
        match outcome {
            ToolOutcome::Executed {
                terminal, events, ..
            } => {
                if terminal.kind != TerminalKind::Exited
                    || terminal.exit_code != Some(7)
                    || output(&events, StreamKind::Stdout) != b"out"
                    || output(&events, StreamKind::Stderr) != b"err"
                {
                    return Err("tool observation did not preserve the failure".to_string());
                }
            }
            _ => return Err("first tool call was not executed".to_string()),
        }
        host.emit(ProviderEvent::ModelMessage("after-tool".to_string()))
            .map_err(|error| error.to_string())?;
        Ok(ProviderTerminal::completed(
            "provider continued after failure",
        ))
    }
}

#[test]
fn provider_observes_a_failed_shell_call_and_continues_in_the_same_turn() {
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let mut provider = ContinueAfterFailure;
    let run = runner.run(request(), &mut provider).unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Completed);
    assert!(matches!(&run.events[0].kind, TurnEventKind::TurnAccepted));
    assert!(matches!(
        &run.events.last().unwrap().kind,
        TurnEventKind::TurnTerminal(_)
    ));
    let model_positions = run
        .events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| match &event.kind {
            TurnEventKind::Provider(ProviderEvent::ModelDelta(text)) if text == "before-tool" => {
                Some(index)
            }
            TurnEventKind::Provider(ProviderEvent::ModelMessage(text)) if text == "after-tool" => {
                Some(index)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(model_positions.len(), 2);
    let terminal_tool = run
        .events
        .iter()
        .position(|event| {
            matches!(
                &event.kind,
                TurnEventKind::ToolRuntime(runtime)
                    if matches!(&runtime.kind, ExecutionEventKind::Terminal(_))
            )
        })
        .unwrap();
    assert!(model_positions[0] < terminal_tool);
    assert!(terminal_tool < model_positions[1]);
    assert_eq!(
        run.events.iter().map(|event| event.seq).collect::<Vec<_>>(),
        (0..run.events.len() as u64).collect::<Vec<_>>()
    );
}

struct DuplicateProvider {
    counter: std::path::PathBuf,
}

impl SameTurnProvider for DuplicateProvider {
    fn run_turn(
        &mut self,
        request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> Result<ProviderTerminal, String> {
        let command = format!("printf x >> '{}'", self.counter.display());
        let call = shell_call(
            request,
            "call-duplicate",
            br#"{"tool":"shell.exec","command":"one-spawn"}"#,
            &command,
        );
        if !matches!(
            host.invoke_tool(call.clone())
                .map_err(|error| error.to_string())?,
            ToolOutcome::Executed { .. }
        ) {
            return Err("first duplicate call did not execute".to_string());
        }
        if !matches!(
            host.invoke_tool(call).map_err(|error| error.to_string())?,
            ToolOutcome::Existing(_)
        ) {
            return Err("second duplicate call did not attach".to_string());
        }
        Ok(ProviderTerminal::completed("duplicate attached"))
    }
}

#[test]
fn an_exact_duplicate_call_produces_one_real_process_effect() {
    let directory = tempfile::tempdir().unwrap();
    let counter = directory.path().join("counter");
    let registry = Arc::new(CallRegistry::default());
    let runner = TurnRunner::new(Arc::clone(&registry));
    let mut provider = DuplicateProvider {
        counter: counter.clone(),
    };
    let run = runner.run(request(), &mut provider).unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Completed);
    assert_eq!(fs::read(counter).unwrap(), b"x");
    assert_eq!(
        run.events
            .iter()
            .filter(|event| matches!(&event.kind, TurnEventKind::ToolExisting(_)))
            .count(),
        1
    );
}

struct TransparentAdb {
    executable: std::path::PathBuf,
}

impl SameTurnProvider for TransparentAdb {
    fn run_turn(
        &mut self,
        request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> Result<ProviderTerminal, String> {
        let mut adb = AdbExecRequest::new(
            "call-adb",
            vec![
                "future-subcommand".to_string(),
                "--future-option".to_string(),
                "value with spaces".to_string(),
            ],
        );
        adb.adb_executable = self.executable.clone();
        adb.target_id = Some("android:correlation-only".to_string());
        let call = BoundToolCall::new(
            CallKey::new(request.scope(), "call-adb"),
            "cd".repeat(32),
            Some("android:correlation-only".to_string()),
            br#"{"tool":"adb.exec","argv":["future-subcommand","--future-option","value with spaces"]}"#
                .to_vec(),
            DirectToolRequest::Adb(adb),
        )
        .unwrap();
        match host.invoke_tool(call).map_err(|error| error.to_string())? {
            ToolOutcome::Executed {
                terminal, events, ..
            } => {
                if !terminal.success() {
                    return Err("fake ordinary adb failed".to_string());
                }
                let stdout = String::from_utf8(output(&events, StreamKind::Stdout))
                    .map_err(|error| error.to_string())?;
                if stdout != "future-subcommand\n--future-option\nvalue with spaces\n"
                    || stdout.contains("android:correlation-only")
                    || stdout.lines().any(|line| line == "-s")
                {
                    return Err("ADB argv was rewritten or target-injected".to_string());
                }
            }
            _ => return Err("ADB call did not execute".to_string()),
        }
        Ok(ProviderTerminal::completed(
            "ordinary adb remained transparent",
        ))
    }
}

#[test]
fn ordinary_adb_argv_is_transparent_inside_the_same_turn() {
    let directory = tempfile::tempdir().unwrap();
    let fake_adb = directory.path().join("adb");
    fs::write(&fake_adb, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
    fs::set_permissions(&fake_adb, fs::Permissions::from_mode(0o700)).unwrap();
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let mut provider = TransparentAdb {
        executable: fake_adb,
    };
    let run = runner.run(request(), &mut provider).unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Completed);
}

struct PanickingProvider;

impl SameTurnProvider for PanickingProvider {
    fn run_turn(
        &mut self,
        _request: &TurnRequest,
        _host: &mut ProviderHost<'_>,
    ) -> Result<ProviderTerminal, String> {
        panic!("fixture provider panic")
    }
}

#[test]
fn provider_panic_becomes_one_truthful_turn_terminal() {
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let mut provider = PanickingProvider;
    let run = runner.run(request(), &mut provider).unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Panicked);
    assert_eq!(
        run.events
            .iter()
            .filter(|event| matches!(&event.kind, TurnEventKind::TurnTerminal(_)))
            .count(),
        1
    );
}
