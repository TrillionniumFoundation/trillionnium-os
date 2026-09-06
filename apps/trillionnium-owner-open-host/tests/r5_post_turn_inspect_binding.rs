use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use serde_json::Value;

mod support;

use support::secure_tempdir;

#[test]
fn post_turn_call_inspection_cannot_bypass_the_durable_request_digest() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let event_store = directory.path().join("events.jsonl");
    fs::write(
        &provider,
        r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"call-post-turn-binding","tool":"shell.exec","command":"printf bound"}}'
IFS= read -r tool_result || exit 11
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"completed before inspection"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args(["--provider"])
        .arg(&provider)
        .args(["--event-store"])
        .arg(&event_store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(
        stdin,
        "{{\"kind\":\"turn.start\",\"seq\":0,\"direction\":\"client_to_host\",\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1,\"session_id\":\"session-post-turn-binding\",\"task_id\":\"task-post-turn-binding\",\"turn_id\":\"turn-post-turn-binding\",\"user_input\":\"complete and inspect\"}}}}"
    )
    .unwrap();
    stdin.flush().unwrap();

    loop {
        let mut line = String::new();
        assert!(stdout.read_line(&mut line).unwrap() > 0);
        let frame = serde_json::from_str::<Value>(line.trim_end()).unwrap();
        if frame["kind"] == "turn.end" {
            assert_eq!(frame["payload"]["status"], "completed");
            break;
        }
    }

    writeln!(
        stdin,
        "{{\"kind\":\"call.inspect\",\"seq\":1,\"direction\":\"client_to_host\",\"call_id\":\"call-post-turn-binding\",\"payload\":{{\"session_id\":\"session-post-turn-binding\",\"task_id\":\"task-post-turn-binding\",\"turn_id\":\"turn-post-turn-binding\",\"call_id\":\"call-post-turn-binding\",\"request_sha256\":\"{}\",\"inclusive_cursor\":0,\"limit\":64}}}}",
        "f".repeat(64)
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    assert!(stdout.read_line(&mut line).unwrap() > 0);
    let response = serde_json::from_str::<Value>(line.trim_end()).unwrap();
    assert_eq!(response["kind"], "host.error");
    assert_eq!(response["payload"]["code"], "inspect_conflict");
    assert!(
        response["payload"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("request digest"))
    );

    drop(stdin);
    let mut remainder = String::new();
    stdout.read_to_string(&mut remainder).unwrap();
    let status = child.wait().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "Host failed: {stderr}");
}
