use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use trillionnium_owner_open_call_registry::CallRegistry;
use trillionnium_owner_open_provider_jsonl::{JsonlProvider, JsonlProviderConfig};
use trillionnium_owner_open_turn_loop::{ProviderTerminalStatus, TurnRequest, TurnRunner};

fn request(attempt: usize) -> TurnRequest {
    TurnRequest {
        session_id: "session-provider-order".to_string(),
        profile_id: "owner-open".to_string(),
        task_id: "task-provider-order".to_string(),
        turn_id: format!("turn-provider-order-{attempt}"),
        turn_stream_id: format!("stream-provider-order-{attempt}"),
        user_input: "prove provider terminal ordering".to_string(),
    }
}

#[test]
fn immediate_provider_exit_cannot_overtake_its_terminal_line() {
    let registry = Arc::new(CallRegistry::default());
    let runner = TurnRunner::new(registry);
    let script = r#"
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":0,"summary":"ordered terminal"}'
exit 0
"#;

    for attempt in 0..64 {
        let mut provider = JsonlProvider::new(JsonlProviderConfig {
            executable: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), script.to_string()],
            poll_interval: Duration::from_nanos(1),
            terminate_grace: Duration::from_millis(20),
            ..JsonlProviderConfig::default()
        })
        .unwrap();
        let run = runner.run(request(attempt), &mut provider).unwrap();
        assert_eq!(
            run.terminal.status,
            ProviderTerminalStatus::Completed,
            "attempt {attempt} returned terminal {:?}",
            run.terminal
        );
        assert_eq!(run.terminal.summary.as_deref(), Some("ordered terminal"));
    }
}
