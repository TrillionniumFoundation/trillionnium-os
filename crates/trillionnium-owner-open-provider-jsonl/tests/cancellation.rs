use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use trillionnium_owner_open_call_registry::CallRegistry;
use trillionnium_owner_open_provider_jsonl::{JsonlProvider, JsonlProviderConfig};
use trillionnium_owner_open_turn_loop::{
    ProviderTerminalStatus, TurnCancellation, TurnEvent, TurnRequest, TurnRunner,
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
