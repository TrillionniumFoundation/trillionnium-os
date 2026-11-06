use std::{fs, path::PathBuf, sync::Arc, time::Duration};
use trillionnium_owner_open_call_registry::CallRegistry;
use trillionnium_owner_open_provider_jsonl::{JsonlProvider, JsonlProviderConfig};
use trillionnium_owner_open_turn_loop::{ProviderTerminalStatus, TurnRequest, TurnRunner};

fn request() -> TurnRequest {
    TurnRequest {
        session_id: "s".into(),
        profile_id: "owner-open".into(),
        task_id: "t".into(),
        turn_id: "turn".into(),
        turn_stream_id: "stream".into(),
        user_input: "source fixture".into(),
    }
}
fn provider(path: &std::path::Path) -> JsonlProvider {
    JsonlProvider::new(JsonlProviderConfig {
        executable: PathBuf::from("/usr/bin/python3"),
        args: vec![path.to_string_lossy().into()],
        timeout: Duration::from_secs(20),
        ..JsonlProviderConfig::default()
    })
    .unwrap()
}

#[test]
fn dense_json_below_line_limit_is_rejected_before_tool_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.py");
    let marker = directory.path().join("must-not-run");
    let command = format!("touch {}", marker.display());
    fs::write(&path, format!(r#"import json,sys
sys.stdin.readline()
print(json.dumps({{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{{"call_id":"dense","tool":"shell.exec","command":{command:?},"dense_extension":[0]*100000}}}}),flush=True)
sys.stdin.readline()
"#)).unwrap();
    let registry = Arc::new(CallRegistry::default());
    let run = TurnRunner::new(Arc::clone(&registry))
        .run(request(), &mut provider(&path))
        .unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Failed);
    assert!(
        run.terminal
            .error
            .as_deref()
            .unwrap()
            .contains("decode allocation")
    );
    assert!(registry.is_empty().unwrap());
    assert!(!marker.exists());
}

#[test]
fn smaller_inbound_limit_still_delivers_a_complete_default_16_mib_tool_result() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.py");
    fs::write(&path, r#"import json,sys,base64
sys.stdin.readline()
print(json.dumps({"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"full-output","tool":"shell.exec","command":"head -c 16777216 /dev/zero"}}),flush=True)
result=json.loads(sys.stdin.readline())
assert result['status']=='terminal'
assert result['terminal']['stdout_bytes']==16777216
assert not result.get('events_truncated',False)
assert not result['terminal']['output_truncated']
count=sum(len(base64.b64decode(event['event']['data'])) for event in result['events'] if event['event']['kind']=='output')
assert count==16777216
print(json.dumps({"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"all default output received"}),flush=True)
"#).unwrap();
    let run = TurnRunner::new(Arc::new(CallRegistry::default()))
        .run(request(), &mut provider(&path))
        .unwrap();
    assert_eq!(
        run.terminal.status,
        ProviderTerminalStatus::Completed,
        "{:?}",
        run.terminal
    );
    assert_eq!(
        run.terminal.summary.as_deref(),
        Some("all default output received")
    );
}
