use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

mod support;

use support::secure_tempdir;

struct RunningHost {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

fn start_host(
    provider: &std::path::Path,
    provider_args: &[&std::path::Path],
    event_store: Option<&std::path::Path>,
) -> RunningHost {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"));
    command
        .args([
            "--transport-core",
            env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-core"),
        ])
        .args(["--provider"])
        .arg(provider);
    for argument in provider_args {
        command.args(["--provider-arg"]).arg(argument);
    }
    if let Some(path) = event_store {
        command.args(["--event-store"]).arg(path);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    RunningHost {
        stdin: child.stdin.take().unwrap(),
        stdout: BufReader::new(child.stdout.take().unwrap()),
        child,
    }
}

fn send(writer: &mut ChildStdin, value: Value) {
    serde_json::to_writer(&mut *writer, &value).unwrap();
    writer.write_all(b"\n").unwrap();
    writer.flush().unwrap();
}

fn read_frame(reader: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    assert!(
        reader.read_line(&mut line).unwrap() > 0,
        "Host stdout closed"
    );
    serde_json::from_str(line.trim_end()).unwrap()
}

fn read_until(reader: &mut BufReader<ChildStdout>, kind: &str) -> Vec<Value> {
    let mut frames = Vec::new();
    loop {
        let frame = read_frame(reader);
        let found = frame["kind"] == kind;
        frames.push(frame);
        if found {
            return frames;
        }
    }
}

fn start_frame(turn_id: &str) -> Value {
    json!({
        "kind": "turn.start",
        "seq": 1,
        "direction": "client_to_host",
        "payload": {
            "protocol": "trillionnium.agent.turn.v1",
            "protocol_version": 1,
            "session_id": "session-flow",
            "task_id": "task-flow",
            "turn_id": turn_id,
            "user_input": "exercise bounded transport flow"
        }
    })
}

fn flow_frame(
    kind: &str,
    transport_seq: u64,
    control_seq: u64,
    accepted: &Value,
    extra: Value,
) -> Value {
    let mut payload = json!({
        "control_seq": control_seq,
        "session_id": accepted["session_id"],
        "profile_id": accepted["profile_id"],
        "task_id": accepted["task_id"],
        "turn_id": accepted["turn_id"],
        "turn_stream_id": accepted["turn_stream_id"]
    });
    payload
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    json!({
        "kind": kind,
        "seq": transport_seq,
        "direction": "client_to_host",
        "session_id": accepted["session_id"],
        "profile_id": accepted["profile_id"],
        "task_id": accepted["task_id"],
        "turn_id": accepted["turn_id"],
        "turn_stream_id": accepted["turn_stream_id"],
        "payload": payload
    })
}

fn finish(mut running: RunningHost) -> Vec<Value> {
    drop(running.stdin);
    let mut remainder = String::new();
    running.stdout.read_to_string(&mut remainder).unwrap();
    let frames = remainder
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
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
fn durable_pause_window_update_and_resume_gate_model_delivery() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let emit = directory.path().join("emit");
    let finish_marker = directory.path().join("finish");
    let event_store = directory.path().join("events.jsonl");
    fs::write(
        &provider,
        r#"#!/bin/sh
IFS= read -r start || exit 10
while [ ! -f "$1" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":0,"event":"model.delta","text":"held-by-flow-window"}'
while [ ! -f "$2" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"flow completed"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut running = start_host(&provider, &[&emit, &finish_marker], Some(&event_store));
    send(
        &mut running.stdin,
        json!({"kind":"hello","seq":0,"payload":{}}),
    );
    assert_eq!(read_frame(&mut running.stdout)["kind"], "hello.ack");
    send(&mut running.stdin, start_frame("turn-flow-window"));
    let accepted = read_until(&mut running.stdout, "turn.accepted")
        .pop()
        .unwrap();
    assert_eq!(accepted["payload"]["flow_control_available"], true);

    send(
        &mut running.stdin,
        flow_frame("stream.pause", 2, 0, &accepted, json!({})),
    );
    assert_eq!(read_frame(&mut running.stdout)["kind"], "stream.pause.ack");
    fs::write(&emit, b"emit").unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if event_store.exists()
            && fs::read_to_string(&event_store)
                .unwrap_or_default()
                .contains("held-by-flow-window")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "model delta was not persisted while paused"
        );
        thread::sleep(Duration::from_millis(10));
    }

    send(
        &mut running.stdin,
        flow_frame(
            "stream.window_update",
            3,
            1,
            &accepted,
            json!({"credit_bytes": 65536}),
        ),
    );
    send(
        &mut running.stdin,
        flow_frame("stream.resume", 4, 2, &accepted, json!({})),
    );
    assert_eq!(
        read_frame(&mut running.stdout)["kind"],
        "stream.window_update.ack"
    );
    assert_eq!(read_frame(&mut running.stdout)["kind"], "stream.resume.ack");
    let model = read_frame(&mut running.stdout);
    assert_eq!(model["kind"], "model.delta");
    assert_eq!(model["payload"]["text"], "held-by-flow-window");

    fs::write(&finish_marker, b"finish").unwrap();
    let terminal = read_until(&mut running.stdout, "turn.end").pop().unwrap();
    assert_eq!(terminal["payload"]["status"], "completed");
    finish(running);
}

#[test]
fn flow_control_without_durable_store_is_rejected_without_stopping_the_turn() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let finish_marker = directory.path().join("finish");
    fs::write(
        &provider,
        r#"#!/bin/sh
IFS= read -r start || exit 10
while [ ! -f "$1" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":0,"summary":"completed without flow"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut running = start_host(&provider, &[&finish_marker], None);
    send(&mut running.stdin, start_frame("turn-no-durable-flow"));
    let accepted = read_until(&mut running.stdout, "turn.accepted")
        .pop()
        .unwrap();
    send(
        &mut running.stdin,
        flow_frame("stream.pause", 2, 0, &accepted, json!({})),
    );
    let error = read_frame(&mut running.stdout);
    assert_eq!(error["kind"], "host.error");
    assert_eq!(
        error["payload"]["code"],
        "flow_control_requires_durable_store"
    );
    fs::write(&finish_marker, b"finish").unwrap();
    let terminal = read_until(&mut running.stdout, "turn.end").pop().unwrap();
    assert_eq!(terminal["payload"]["status"], "completed");
    finish(running);
}

#[test]
fn turn_cancel_remains_serviceable_while_high_volume_delivery_is_paused() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let release = directory.path().join("release");
    let event_store = directory.path().join("events.jsonl");
    fs::write(
        &provider,
        r#"#!/bin/sh
IFS= read -r start || exit 10
while [ ! -f "$1" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"call-paused-cancel","tool":"shell.exec","command":"sleep 30"}}'
IFS= read -r result || exit 11
case "$result" in
  *'"terminal_kind":"client_cancelled"'*) ;;
  *) exit 12 ;;
esac
IFS= read -r cancel || exit 13
case "$cancel" in
  *'"kind":"turn.cancel"'*) ;;
  *) exit 14 ;;
esac
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.cancelled","seq":1,"summary":"cancel remained serviceable"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut running = start_host(&provider, &[&release], Some(&event_store));
    send(&mut running.stdin, start_frame("turn-paused-cancel"));
    let accepted = read_until(&mut running.stdout, "turn.accepted")
        .pop()
        .unwrap();
    send(
        &mut running.stdin,
        flow_frame("stream.pause", 2, 0, &accepted, json!({})),
    );
    assert_eq!(read_frame(&mut running.stdout)["kind"], "stream.pause.ack");
    fs::write(&release, b"release").unwrap();
    read_until(&mut running.stdout, "tool.started");

    send(
        &mut running.stdin,
        json!({
            "kind": "turn.cancel",
            "seq": 3,
            "direction": "client_to_host",
            "session_id": accepted["session_id"],
            "profile_id": accepted["profile_id"],
            "task_id": accepted["task_id"],
            "turn_id": accepted["turn_id"],
            "turn_stream_id": accepted["turn_stream_id"],
            "payload": {
                "session_id": accepted["session_id"],
                "profile_id": accepted["profile_id"],
                "task_id": accepted["task_id"],
                "turn_id": accepted["turn_id"],
                "turn_stream_id": accepted["turn_stream_id"]
            }
        }),
    );
    let frames = read_until(&mut running.stdout, "turn.end");
    assert!(
        frames
            .iter()
            .any(|frame| frame["kind"] == "turn.cancel.accepted")
    );
    assert!(frames.iter().any(|frame| {
        frame["kind"] == "tool.result" && frame["payload"]["terminal_kind"] == "client_cancelled"
    }));
    assert_eq!(frames.last().unwrap()["payload"]["status"], "cancelled");
    finish(running);
}
