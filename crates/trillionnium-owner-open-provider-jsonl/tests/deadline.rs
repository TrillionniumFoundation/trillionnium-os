use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use trillionnium_owner_open_call_registry::CallRegistry;
use trillionnium_owner_open_provider_jsonl::{JsonlProvider, JsonlProviderConfig};
use trillionnium_owner_open_runtime::{ExecutionEventKind, TerminalKind};
use trillionnium_owner_open_turn_loop::{
    ProviderTerminalStatus, TurnEventKind, TurnRequest, TurnRunner,
};

fn request() -> TurnRequest {
    TurnRequest {
        session_id: "deadline-session".into(),
        profile_id: "owner-open".into(),
        task_id: "deadline-task".into(),
        turn_id: "deadline-turn".into(),
        turn_stream_id: "deadline-stream".into(),
        user_input: "local deadline fixture".into(),
    }
}

fn provider(script: &std::path::Path, timeout: Duration) -> JsonlProvider {
    JsonlProvider::new(JsonlProviderConfig {
        executable: PathBuf::from("/bin/sh"),
        args: vec![script.to_string_lossy().into_owned()],
        timeout,
        terminate_grace: Duration::from_millis(10),
        ..JsonlProviderConfig::default()
    })
    .unwrap()
}

fn script(path: &std::path::Path, command: &str, delay_before_call: bool) {
    let call = json!({"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,
        "call":{"call_id":"deadline-call","tool":"shell.exec","command":command,"timeout_ms":10000}});
    // JSON contains no shell apostrophe in these fixed local test commands.
    let delay = if delay_before_call { "sleep 1\n" } else { "" };
    fs::write(path, format!("IFS= read -r start || exit 10\n{delay}printf '%s\\n' '{call}'\nIFS= read -r result || exit 11\nprintf '%s\\n' '{{\"protocol\":\"trillionnium.owner-open.provider-jsonl.v1\",\"kind\":\"turn.complete\",\"seq\":1}}'\n")).unwrap();
}

#[test]
fn turn_deadline_interrupts_synchronous_tool_without_executing_its_late_effect() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sh");
    script(&path, "sleep 2; printf must-not-occur", false);
    let mut provider = provider(&path, Duration::from_millis(150));
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let run = runner.run(request(), &mut provider).unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Failed);
    assert!(
        run.terminal
            .error
            .as_deref()
            .unwrap()
            .contains("turn deadline")
    );
    assert!(run.events.iter().any(|event| matches!(&event.kind, TurnEventKind::ToolRuntime(runtime)
        if matches!(&runtime.kind, ExecutionEventKind::Terminal(terminal) if terminal.kind == TerminalKind::TimedOut))));
    assert!(!run.events.iter().any(
        |event| matches!(&event.kind, TurnEventKind::ToolRuntime(runtime)
        if matches!(runtime.kind, ExecutionEventKind::Output { .. }))
    ));
}

#[test]
fn deadline_before_callback_admission_never_starts_a_tool() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sh");
    script(&path, "printf must-not-occur", true);
    let mut provider = provider(&path, Duration::from_millis(100));
    let registry = Arc::new(CallRegistry::default());
    let run = TurnRunner::new(Arc::clone(&registry))
        .run(request(), &mut provider)
        .unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Failed);
    assert!(registry.is_empty().unwrap());
    assert!(
        !run.events
            .iter()
            .any(|event| matches!(event.kind, TurnEventKind::ToolRuntime(_)))
    );
}

#[test]
fn callback_completing_within_turn_budget_keeps_exact_output_and_success() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sh");
    script(&path, "printf exact-output", false);
    let mut provider = provider(&path, Duration::from_secs(5));
    let run = TurnRunner::new(Arc::new(CallRegistry::default()))
        .run(request(), &mut provider)
        .unwrap();
    assert_eq!(
        run.terminal.status,
        ProviderTerminalStatus::Completed,
        "{:?}",
        run.terminal
    );
    let mut output = Vec::new();
    for event in run.events {
        if let TurnEventKind::ToolRuntime(runtime) = event.kind
            && let ExecutionEventKind::Output { bytes, .. } = runtime.kind
        {
            output.extend(bytes);
        }
    }
    assert_eq!(output, b"exact-output");
}

#[test]
fn stalled_initial_provider_input_respects_the_same_turn_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("not-reading.sh");
    fs::write(&path, "exec sleep 5\n").unwrap();
    let mut provider = provider(&path, Duration::from_millis(100));
    let mut request = request();
    request.user_input = "x".repeat(512 * 1024);
    let started = Instant::now();
    let run = TurnRunner::new(Arc::new(CallRegistry::default()))
        .run(request, &mut provider)
        .unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Failed);
    assert!(
        run.terminal
            .error
            .as_deref()
            .unwrap()
            .contains("turn deadline"),
        "{:?}",
        run.terminal
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}
