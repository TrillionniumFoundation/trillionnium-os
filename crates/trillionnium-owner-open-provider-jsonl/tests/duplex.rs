use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use trillionnium_owner_open_call_registry::CallRegistry;
use trillionnium_owner_open_provider_jsonl::{JsonlProvider, JsonlProviderConfig};
use trillionnium_owner_open_runtime::{ExecutionEventKind, StreamKind, TerminalKind};
use trillionnium_owner_open_turn_loop::{
    ProviderEvent, ProviderTerminalStatus, TurnEventKind, TurnRequest, TurnRunner,
};

fn request() -> TurnRequest {
    TurnRequest {
        session_id: "session-jsonl".to_string(),
        profile_id: "owner-open".to_string(),
        task_id: "task-jsonl".to_string(),
        turn_id: "turn-jsonl".to_string(),
        turn_stream_id: "stream-jsonl".to_string(),
        user_input: "run the duplex provider fixture".to_string(),
    }
}

fn executable_script(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("provider.sh");
    fs::write(&script, contents).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    (directory, script)
}

fn provider_for(script: &std::path::Path) -> JsonlProvider {
    JsonlProvider::new(JsonlProviderConfig {
        executable: script.to_path_buf(),
        ..JsonlProviderConfig::default()
    })
    .unwrap()
}

fn output(run: &trillionnium_owner_open_turn_loop::TurnRun, stream: StreamKind) -> Vec<u8> {
    run.events
        .iter()
        .filter_map(|event| match &event.kind {
            TurnEventKind::ToolRuntime(runtime) => match &runtime.kind {
                ExecutionEventKind::Output {
                    stream: candidate,
                    bytes,
                } if *candidate == stream => Some(bytes.as_slice()),
                _ => None,
            },
            _ => None,
        })
        .flatten()
        .copied()
        .collect()
}

#[test]
fn external_provider_receives_a_failed_shell_observation_and_continues() {
    let (_directory, script) = executable_script(
        r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":0,"event":"model.delta","text":"before"}'
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":1,"call":{"call_id":"call-jsonl-shell","tool":"shell.exec","command":"printf out; printf err >&2; exit 9"}}'
IFS= read -r result || exit 11
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":2,"event":"model.message","text":"after"}'
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":3,"summary":"continued"}'
"#,
    );
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let mut provider = provider_for(&script);
    let run = runner.run(request(), &mut provider).unwrap();

    assert_eq!(run.terminal.status, ProviderTerminalStatus::Completed);
    assert_eq!(output(&run, StreamKind::Stdout), b"out");
    assert_eq!(output(&run, StreamKind::Stderr), b"err");
    assert!(run.events.iter().any(|event| {
        matches!(
            &event.kind,
            TurnEventKind::ToolRuntime(runtime)
                if matches!(
                    &runtime.kind,
                    ExecutionEventKind::Terminal(terminal)
                        if terminal.kind == TerminalKind::Exited
                            && terminal.exit_code == Some(9)
                )
        )
    }));
    let provider_text = run
        .events
        .iter()
        .filter_map(|event| match &event.kind {
            TurnEventKind::Provider(ProviderEvent::ModelDelta(text))
            | TurnEventKind::Provider(ProviderEvent::ModelMessage(text)) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(provider_text, vec!["before", "after"]);
}

#[test]
fn duplicate_provider_members_fail_before_a_tool_can_spawn() {
    let (_directory, script) = executable_script(
        r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","kind":"tool.call","seq":0,"call":{"call_id":"must-not-run","tool":"shell.exec","command":"touch /tmp/must-not-run"}}'
"#,
    );
    let registry = Arc::new(CallRegistry::default());
    let runner = TurnRunner::new(Arc::clone(&registry));
    let mut provider = provider_for(&script);
    let run = runner.run(request(), &mut provider).unwrap();

    assert_eq!(run.terminal.status, ProviderTerminalStatus::Failed);
    assert!(
        run.terminal
            .error
            .as_deref()
            .is_some_and(|value| value.contains("duplicate key kind"))
    );
    assert!(registry.is_empty().unwrap());
}

#[test]
fn provider_eof_before_terminal_is_truthful_failure() {
    let (_directory, script) = executable_script(
        r#"#!/bin/sh
IFS= read -r start || exit 10
exit 0
"#,
    );
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let mut provider = provider_for(&script);
    let run = runner.run(request(), &mut provider).unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Failed);
    assert!(
        run.terminal
            .error
            .as_deref()
            .is_some_and(|value| value.contains("before a terminal"))
    );
}

#[test]
fn unknown_tool_is_returned_to_provider_without_killing_the_turn() {
    let (_directory, script) = executable_script(
        r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"unknown-call","tool":"future.owner.tool"}}'
IFS= read -r result || exit 11
case "$result" in
  *'"status":"invalid_request"'*) ;;
  *) exit 12 ;;
esac
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"observed unavailable tool"}'
"#,
    );
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let mut provider = provider_for(&script);
    let run = runner.run(request(), &mut provider).unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Completed);
}
