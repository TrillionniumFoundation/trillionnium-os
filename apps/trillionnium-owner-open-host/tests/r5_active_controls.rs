use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::Value;

struct RunningHost {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

fn start_host(provider: &std::path::Path, event_store: &std::path::Path) -> RunningHost {
    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args(["--provider"])
        .arg(provider)
        .args(["--event-store"])
        .arg(event_store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    RunningHost {
        child,
        stdin,
        stdout,
    }
}

fn send_start(stdin: &mut ChildStdin, turn_id: &str) {
    writeln!(
        stdin,
        "{{\"kind\":\"turn.start\",\"seq\":0,\"direction\":\"client_to_host\",\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1,\"session_id\":\"session-controls\",\"task_id\":\"task-controls\",\"turn_id\":\"{turn_id}\",\"user_input\":\"exercise active controls\"}}}}"
    )
    .unwrap();
    stdin.flush().unwrap();
}

fn read_until_kind(reader: &mut BufReader<ChildStdout>, target: &str) -> Vec<Value> {
    let mut frames = Vec::new();
    loop {
        let mut line = String::new();
        let count = reader.read_line(&mut line).unwrap();
        assert!(count > 0, "Host stdout closed before {target}");
        let frame = serde_json::from_str::<Value>(line.trim_end()).unwrap();
        let found = frame["kind"] == target;
        frames.push(frame);
        if found {
            return frames;
        }
    }
}

fn finish(mut running: RunningHost, mut frames: Vec<Value>) -> Vec<Value> {
    drop(running.stdin);
    let mut remainder = String::new();
    running.stdout.read_to_string(&mut remainder).unwrap();
    frames.extend(
        remainder
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()),
    );
    let status = running.child.wait().unwrap();
    let mut stderr = String::new();
    running
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "Host failed: {stderr}");
    frames
}

#[test]
fn turn_cancel_is_serviceable_while_a_tool_is_running() {
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("provider.sh");
    let event_store = directory.path().join("events.jsonl");
    fs::write(
        &provider,
        r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"call-turn-cancel","tool":"shell.exec","command":"sleep 30"}}'
IFS= read -r tool_result || exit 11
case "$tool_result" in
  *'"kind":"client_cancelled"'*) ;;
  *) exit 12 ;;
esac
IFS= read -r cancel || exit 13
case "$cancel" in
  *'"kind":"turn.cancel"'*) ;;
  *) exit 14 ;;
esac
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.cancelled","seq":1,"summary":"turn cancel acknowledged"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut running = start_host(&provider, &event_store);
    send_start(&mut running.stdin, "turn-active-cancel");
    let frames = read_until_kind(&mut running.stdout, "tool.started");
    writeln!(
        running.stdin,
        "{{\"kind\":\"turn.cancel\",\"seq\":1,\"direction\":\"client_to_host\",\"payload\":{{\"session_id\":\"session-controls\",\"turn_id\":\"turn-active-cancel\"}}}}"
    )
    .unwrap();
    running.stdin.flush().unwrap();
    let frames = finish(running, frames);

    assert!(frames.iter().any(|frame| frame["kind"] == "turn.cancel.accepted"));
    let tool_result = frames
        .iter()
        .find(|frame| frame["kind"] == "tool.result")
        .unwrap();
    assert_eq!(tool_result["payload"]["terminal_kind"], "client_cancelled");
    let terminal = frames.last().unwrap();
    assert_eq!(terminal["kind"], "turn.end");
    assert_eq!(terminal["payload"]["status"], "cancelled");
    assert_eq!(
        terminal["payload"]["summary"],
        "turn cancel acknowledged"
    );
    let stored = fs::read_to_string(event_store).unwrap();
    assert!(stored.contains("turn.cancel.accepted"));
    assert!(stored.contains("client_cancelled"));
}

#[test]
fn tool_cancel_terminates_only_the_target_call_and_the_turn_continues() {
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("provider.sh");
    let event_store = directory.path().join("events.jsonl");
    fs::write(
        &provider,
        r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"call-tool-cancel","tool":"shell.exec","command":"sleep 30"}}'
IFS= read -r tool_result || exit 11
case "$tool_result" in
  *'"kind":"client_cancelled"'*) ;;
  *) exit 12 ;;
esac
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":1,"event":"model.message","text":"continued after targeted cancel"}'
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":2,"summary":"targeted call cancelled"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut running = start_host(&provider, &event_store);
    send_start(&mut running.stdin, "turn-tool-cancel");
    let frames = read_until_kind(&mut running.stdout, "tool.started");
    writeln!(
        running.stdin,
        "{{\"kind\":\"tool.cancel\",\"seq\":1,\"direction\":\"client_to_host\",\"call_id\":\"call-tool-cancel\",\"payload\":{{\"session_id\":\"session-controls\",\"turn_id\":\"turn-tool-cancel\",\"call_id\":\"call-tool-cancel\"}}}}"
    )
    .unwrap();
    running.stdin.flush().unwrap();
    let frames = finish(running, frames);

    assert!(frames.iter().any(|frame| frame["kind"] == "tool.cancel.accepted"));
    let tool_result = frames
        .iter()
        .find(|frame| frame["kind"] == "tool.result")
        .unwrap();
    assert_eq!(tool_result["payload"]["terminal_kind"], "client_cancelled");
    assert!(frames.iter().any(|frame| {
        frame["kind"] == "model.message"
            && frame["payload"]["text"] == "continued after targeted cancel"
    }));
    let terminal = frames.last().unwrap();
    assert_eq!(terminal["kind"], "turn.end");
    assert_eq!(terminal["payload"]["status"], "completed");
    assert_eq!(terminal["payload"]["summary"], "targeted call cancelled");
    let stored = fs::read_to_string(event_store).unwrap();
    assert!(stored.contains("tool.cancel.accepted"));
    assert!(stored.contains("continued after targeted cancel"));
}
