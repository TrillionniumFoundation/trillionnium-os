use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

mod support;

use support::secure_tempdir;

fn run_host(provider: &Path, counter: &Path, event_store: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args(["--provider"])
        .arg(provider)
        .args(["--provider-arg"])
        .arg(counter)
        .args(["--event-store"])
        .arg(event_store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(
            stdin,
            "{{\"kind\":\"hello\",\"seq\":0,\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1}}}}"
        )
        .unwrap();
        writeln!(
            stdin,
            "{{\"kind\":\"turn.start\",\"seq\":1,\"direction\":\"client_to_host\",\"client_request_id\":\"delivery-only\",\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1,\"session_id\":\"session-replay\",\"task_id\":\"task-replay\",\"turn_id\":\"turn-replay\",\"user_input\":\"complete once and replay\"}}}}"
        )
        .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn frames(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "host failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

fn turn_event_ids(frames: &[Value]) -> Vec<String> {
    frames
        .iter()
        .filter(|frame| frame["turn_stream_id"].is_string())
        .map(|frame| frame["event_id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn completed_turn_replays_without_a_second_provider_process() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let counter = directory.path().join("provider-starts");
    let event_store = directory.path().join("events.jsonl");
    fs::write(
        &provider,
        r#"#!/bin/sh
printf x >> "$1"
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":0,"event":"model.message","text":"completed once"}'
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"durable completion"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let first_output = run_host(&provider, &counter, &event_store);
    let first = frames(&first_output);
    assert_eq!(fs::read(&counter).unwrap(), b"x");
    assert_eq!(first[0]["kind"], "hello.ack");
    assert_eq!(first[0]["payload"]["durable_event_store"], true);
    assert_eq!(first.last().unwrap()["kind"], "turn.end");
    assert_eq!(first.last().unwrap()["payload"]["status"], "completed");
    assert_eq!(
        first.last().unwrap()["payload"]["event_log_status"],
        "durable"
    );

    let second_output = run_host(&provider, &counter, &event_store);
    let second = frames(&second_output);
    assert_eq!(
        fs::read(&counter).unwrap(),
        b"x",
        "completed replay must not spawn the provider a second time"
    );
    assert_eq!(second[0]["kind"], "hello.ack");
    assert_eq!(second.last().unwrap()["kind"], "turn.end");
    assert_eq!(second.last().unwrap()["payload"]["status"], "completed");
    assert_eq!(turn_event_ids(&first), turn_event_ids(&second));
}
