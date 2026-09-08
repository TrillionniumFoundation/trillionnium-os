use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use trillionnium_owner_open_call_registry::CallRegistry;
use trillionnium_owner_open_provider_jsonl::{JsonlProvider, JsonlProviderConfig};
use trillionnium_owner_open_runtime::{ExecutionEventKind, TerminalKind};
use trillionnium_owner_open_turn_loop::{
    ProviderTerminalStatus, TurnCancellation, TurnEvent, TurnEventKind, TurnRequest, TurnRun,
    TurnRunner,
};

fn request() -> TurnRequest {
    TurnRequest {
        session_id: "session-provider-cancel".to_string(),
        profile_id: "owner-open".to_string(),
        task_id: "task-provider-cancel".to_string(),
        turn_id: "turn-provider-cancel".to_string(),
        turn_stream_id: "stream-provider-cancel".to_string(),
        user_input: "cancel this provider turn".to_string(),
    }
}

fn cancel_active_callback(terminal: serde_json::Value) -> TurnRun {
    let directory = tempfile::tempdir().unwrap();
    let provider_path = directory.path().join("provider.sh");
    fs::write(
        &provider_path,
        format!(
            r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{{"call_id":"cancel-active-call","tool":"shell.exec","command":"sleep 30"}}}}'
IFS= read -r result || exit 11
case "$result" in
  *'"kind":"client_cancelled"'*) ;;
  *) exit 12 ;;
esac
IFS= read -r cancel || exit 13
case "$cancel" in
  *'"kind":"turn.cancel"'*) ;;
  *) exit 14 ;;
esac
printf '%s\n' '{terminal}'
"#
        ),
    )
    .unwrap();
    fs::set_permissions(&provider_path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut provider = JsonlProvider::new(JsonlProviderConfig {
        executable: provider_path,
        timeout: Duration::from_secs(5),
        ..JsonlProviderConfig::default()
    })
    .unwrap();
    let cancellation = TurnCancellation::new();
    let mut sink = |event: &TurnEvent| {
        // Cancel at the actual runtime Started observation: the callback is
        // definitely active, without depending on sleeps or thread timing.
        if matches!(&event.kind, TurnEventKind::ToolRuntime(runtime)
            if matches!(runtime.kind, ExecutionEventKind::Started { .. }))
        {
            cancellation.cancel();
        }
        Ok::<(), String>(())
    };
    let run = TurnRunner::new(Arc::new(CallRegistry::default()))
        .run_with_sink_and_cancellation(request(), &mut provider, &cancellation, &mut sink)
        .unwrap();
    assert!(cancellation.is_cancelled());
    assert!(run.events.iter().any(|event| {
        matches!(&event.kind, TurnEventKind::ToolRuntime(runtime)
            if matches!(&runtime.kind, ExecutionEventKind::Terminal(terminal)
                if terminal.kind == TerminalKind::Cancelled))
    }));
    run
}

#[test]
fn active_callback_cancel_delivers_its_result_before_explicit_provider_ack() {
    let run = cancel_active_callback(serde_json::json!({
        "protocol": "trillionnium.owner-open.provider-jsonl.v1",
        "kind": "turn.cancelled",
        "seq": 1,
        "summary": "callback result and turn.cancel both received",
    }));
    assert_eq!(
        run.terminal.status,
        ProviderTerminalStatus::Cancelled,
        "{:?}",
        run.terminal
    );
    // A generic cancelled-on-EOF result cannot satisfy this assertion.
    assert_eq!(
        run.terminal.summary.as_deref(),
        Some("callback result and turn.cancel both received")
    );
    assert!(run.terminal.error.is_none());
}

#[test]
fn explicit_provider_failure_after_callback_cancellation_remains_failure() {
    let run = cancel_active_callback(serde_json::json!({
        "protocol": "trillionnium.owner-open.provider-jsonl.v1",
        "kind": "turn.fail",
        "seq": 1,
        "error": "intentional provider failure after cancellation",
    }));
    assert_eq!(
        run.terminal.status,
        ProviderTerminalStatus::Failed,
        "{:?}",
        run.terminal
    );
    assert!(
        run.terminal
            .error
            .as_deref()
            .is_some_and(|error| error.contains("intentional provider failure after cancellation"))
    );
}

#[test]
fn cancellation_is_sent_to_the_provider_and_acknowledged() {
    let directory = tempfile::tempdir().unwrap();
    let provider_path = directory.path().join("provider.sh");
    let ready = directory.path().join("provider-ready");
    fs::write(
        &provider_path,
        r#"#!/bin/sh
IFS= read -r start || exit 10
: > "$1"
IFS= read -r cancel || exit 11
case "$cancel" in
  *'"kind":"turn.cancel"'*) ;;
  *) exit 12 ;;
esac
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.cancelled","seq":0,"summary":"provider acknowledged cancellation"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider_path, fs::Permissions::from_mode(0o700)).unwrap();

    let mut provider = JsonlProvider::new(JsonlProviderConfig {
        executable: provider_path,
        args: vec![ready.display().to_string()],
        ..JsonlProviderConfig::default()
    })
    .unwrap();
    let cancellation = TurnCancellation::new();
    let worker_cancellation = cancellation.clone();
    let worker = thread::spawn(move || {
        let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
        let mut sink = |_event: &TurnEvent| Ok::<(), String>(());
        runner.run_with_sink_and_cancellation(
            request(),
            &mut provider,
            &worker_cancellation,
            &mut sink,
        )
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() {
        assert!(
            Instant::now() < deadline,
            "provider never received turn.start"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(cancellation.cancel());

    let run = worker.join().unwrap().unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Cancelled);
    assert_eq!(
        run.terminal.summary.as_deref(),
        Some("provider acknowledged cancellation")
    );
}
