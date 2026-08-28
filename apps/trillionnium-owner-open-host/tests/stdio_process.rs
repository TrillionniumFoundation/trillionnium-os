use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

fn run_host(input: &str) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-host"))
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn owner-open Host process");
    child
        .stdin
        .take()
        .expect("Host stdin")
        .write_all(input.as_bytes())
        .expect("write Host frames");
    let output = child.wait_with_output().expect("wait for owner-open Host");
    assert!(
        output.status.success(),
        "Host failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Host stdout is UTF-8 JSONL")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("valid Host JSONL frame"))
        .collect()
}

#[test]
fn stdio_process_preserves_one_turn_lineage_and_reports_provider_hold() {
    let frames = run_host(concat!(
        "{\"kind\":\"hello\",\"seq\":0,\"payload\":{}}\n",
        "{\"kind\":\"turn.start\",\"seq\":1,\"payload\":{",
        "\"protocol\":\"trillionnium.agent.turn.v1\",",
        "\"protocol_version\":1,",
        "\"session_id\":\"session-process\",",
        "\"task_id\":\"task-process\",",
        "\"turn_id\":\"turn-process\",",
        "\"user_input\":\"run pwd\"}}\n"
    ));
    assert_eq!(frames[0]["kind"], "hello.ack");
    assert_eq!(frames[1]["kind"], "turn.accepted");
    assert_eq!(frames.last().unwrap()["kind"], "turn.end");
    assert_eq!(
        frames.last().unwrap()["payload"]["status"],
        "provider_unavailable"
    );
    let turn_stream_id = frames[1]["turn_stream_id"]
        .as_str()
        .expect("accepted turn stream id");
    for frame in &frames[1..] {
        assert_eq!(frame["turn_stream_id"], turn_stream_id);
        assert_eq!(frame["session_id"], "session-process");
        assert_eq!(frame["task_id"], "task-process");
        assert_eq!(frame["turn_id"], "turn-process");
    }
}

#[test]
fn stdio_process_rejects_duplicate_members_without_starting_a_turn() {
    let frames =
        run_host("{\"kind\":\"turn.start\",\"kind\":\"hello\",\"seq\":0,\"payload\":{}}\n");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["kind"], "host.error");
    assert_eq!(frames[0]["payload"]["code"], "invalid_frame");
    assert!(
        frames[0]["payload"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("duplicate key kind"))
    );
}
