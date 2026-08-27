use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use serde_json::Value;

#[test]
fn spawned_r5_host_completes_one_provider_shell_callback_turn() {
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("provider.sh");
    fs::write(
        &provider,
        r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":0,"event":"model.delta","text":"before"}'
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":1,"call":{"call_id":"call-r5-host","tool":"shell.exec","command":"printf out; printf err >&2; exit 9"}}'
IFS= read -r result || exit 11
case "$result" in
  *'"kind":"tool.result"'*) ;;
  *) exit 12 ;;
esac
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":2,"event":"model.message","text":"after"}'
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":3,"summary":"continued after tool failure"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args(["--provider"])
        .arg(&provider)
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
            "{{\"kind\":\"turn.start\",\"seq\":1,\"direction\":\"client_to_host\",\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1,\"session_id\":\"session-host\",\"task_id\":\"task-host\",\"turn_id\":\"turn-host\",\"user_input\":\"exercise provider callback\"}}}}"
        )
        .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "host failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let frames = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let kinds = frames
        .iter()
        .map(|frame| frame["kind"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(kinds.first().copied(), Some("hello.ack"));
    assert!(kinds.contains(&"turn.accepted"));
    assert!(kinds.contains(&"model.delta"));
    assert!(kinds.contains(&"tool.accepted"));
    assert!(kinds.contains(&"tool.started"));
    assert!(kinds.contains(&"tool.stdout"));
    assert!(kinds.contains(&"tool.stderr"));
    assert!(kinds.contains(&"tool.result"));
    assert!(kinds.contains(&"model.message"));
    assert_eq!(kinds.last().copied(), Some("turn.end"));

    let tool_result = frames
        .iter()
        .find(|frame| frame["kind"] == "tool.result")
        .unwrap();
    assert_eq!(tool_result["payload"]["terminal_kind"], "exited");
    assert_eq!(tool_result["payload"]["exit_code"], 9);
    assert_eq!(frames.last().unwrap()["payload"]["status"], "completed");
    assert_eq!(frames.last().unwrap()["payload"]["runtime_ready"], true);

    let before = kinds.iter().position(|kind| *kind == "model.delta").unwrap();
    let result = kinds.iter().position(|kind| *kind == "tool.result").unwrap();
    let after = kinds.iter().position(|kind| *kind == "model.message").unwrap();
    assert!(before < result && result < after);
}
