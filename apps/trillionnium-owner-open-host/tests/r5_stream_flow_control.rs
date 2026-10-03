use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

mod support;

use support::{read_event_store, secure_tempdir};

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
    start_host_with_transport_args(provider, provider_args, event_store, &[])
}

fn start_host_with_transport_args(
    provider: &std::path::Path,
    provider_args: &[&std::path::Path],
    event_store: Option<&std::path::Path>,
    transport_args: &[&str],
) -> RunningHost {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"));
    command
        .args(transport_args)
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
    } else {
        // This fixture deliberately tests flow-control rejection in the
        // explicitly selected development-only memory mode.
        command.arg("--allow-unjournaled-effects-for-development");
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
        if read_event_store(&event_store).contains("held-by-flow-window") {
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
    let provider_trace = directory.path().join("provider-trace");
    let event_store = directory.path().join("events.jsonl");
    fs::write(
        &provider,
        r#"#!/bin/sh
trap 'status=$?; printf "exit=%s\n" "$status" >> "$2"' 0
IFS= read -r start || exit 10
while [ ! -f "$1" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"call-paused-cancel","tool":"shell.exec","command":"sleep 30"}}'
IFS= read -r result || exit 11
printf 'result=%s\n' "$result" >> "$2"
case "$result" in
  *'"kind":"client_cancelled"'*) ;;
  *) exit 12 ;;
esac
IFS= read -r cancel || exit 13
printf 'cancel=%s\n' "$cancel" >> "$2"
case "$cancel" in
  *'"kind":"turn.cancel"'*) ;;
  *) exit 14 ;;
esac
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.cancelled","seq":1,"summary":"cancel remained serviceable"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut running = start_host(&provider, &[&release, &provider_trace], Some(&event_store));
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
    assert_eq!(
        frames.last().unwrap()["payload"]["status"],
        "cancelled",
        "complete cancellation frame trace: {}; provider input/exit trace: {}",
        serde_json::to_string_pretty(&frames).unwrap(),
        fs::read_to_string(&provider_trace).unwrap_or_else(|error| error.to_string())
    );
    // EOF after a cancellation request is also classified as cancelled. The
    // explicit summary proves that this fixture actually accepted the tool
    // result and cancel frame, instead of exiting early on a wrong field.
    assert_eq!(
        frames.last().unwrap()["payload"]["summary"],
        "cancel remained serviceable",
        "provider input/exit trace: {}",
        fs::read_to_string(&provider_trace).unwrap_or_else(|error| error.to_string())
    );
    finish(running);
}

#[test]
fn actual_core_inspection_covers_overflow_before_scoped_resume_releases_new_data() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let emit = directory.path().join("emit");
    let second = directory.path().join("second");
    let terminal = directory.path().join("terminal");
    let event_store = directory.path().join("events.jsonl");
    fs::write(&provider, r#"#!/bin/sh
IFS= read -r start || exit 10
while [ ! -f "$1" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":0,"event":"model.delta","text":"recover this durable observation"}'
while [ ! -f "$2" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":1,"event":"model.delta","text":"delivered after scoped recovery"}'
while [ ! -f "$3" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":2,"summary":"recovered"}'
"#).unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();
    let mut running = start_host_with_transport_args(
        &provider,
        &[&emit, &second, &terminal],
        Some(&event_store),
        &["--transport-buffer-bytes", "128"],
    );
    send(
        &mut running.stdin,
        json!({"kind":"hello","seq":0,"payload":{}}),
    );
    let hello = read_until(&mut running.stdout, "hello.ack").pop().unwrap();
    assert_eq!(
        hello["payload"]["resync_protocols"],
        json!(["scoped_cursor_v1"])
    );
    assert_eq!(hello["payload"]["legacy_numeric_resume_after_gap"], false);
    send(&mut running.stdin, start_frame("turn-scoped-resume"));
    let accepted = read_until(&mut running.stdout, "turn.accepted")
        .pop()
        .unwrap();
    send(
        &mut running.stdin,
        flow_frame("stream.pause", 2, 0, &accepted, json!({})),
    );
    read_until(&mut running.stdout, "stream.pause.ack");
    fs::write(&emit, b"emit").unwrap();
    let gap = read_until(&mut running.stdout, "stream.resync_required")
        .pop()
        .unwrap();
    let required = &gap["payload"]["required_resumes"][0];
    assert_eq!(required["cursor_domain"], "transport_event");
    assert_eq!(required["cursor_scope"]["turn_id"], "turn-scoped-resume");
    let next = required["required_resume_cursor"].as_u64().unwrap();
    send(
        &mut running.stdin,
        flow_frame(
            "stream.resume",
            3,
            1,
            &accepted,
            json!({"resumed_through_cursor":next}),
        ),
    );
    let rejected = read_until(&mut running.stdout, "host.error").pop().unwrap();
    assert_eq!(rejected["payload"]["code"], "flow_control_conflict");
    let acknowledged = json!([{"cursor_domain":required["cursor_domain"],"cursor_scope":required["cursor_scope"],"resumed_through_cursor":next}]);
    send(
        &mut running.stdin,
        flow_frame(
            "stream.resume",
            4,
            1,
            &accepted,
            json!({"resync_protocol":"scoped_cursor_v1","resumed_cursors":acknowledged}),
        ),
    );
    let rejected = read_until(&mut running.stdout, "host.error").pop().unwrap();
    assert_eq!(rejected["payload"]["code"], "flow_control_conflict");
    let mut inspect_payload = required["cursor_scope"].clone();
    inspect_payload["inclusive_cursor"] = required["first_missing_cursor"].clone();
    inspect_payload["limit"] = json!(1);
    inspect_payload["request_sha256"] = accepted["payload"]["turn_request_sha256"].clone();
    send(
        &mut running.stdin,
        json!({"kind":"turn.inspect","seq":5,"direction":"client_to_host","payload":inspect_payload}),
    );
    let inspected = read_until(&mut running.stdout, "turn.inspect.result")
        .pop()
        .unwrap();
    assert_eq!(inspected["payload"]["next_cursor"], next);
    assert_eq!(
        inspected["payload"]["frames"][0]["payload"]["text"],
        "recover this durable observation"
    );
    assert_eq!(inspected["payload"]["side_effects"], false);
    send(
        &mut running.stdin,
        flow_frame(
            "stream.window_update",
            6,
            1,
            &accepted,
            json!({"credit_bytes":4096}),
        ),
    );
    read_until(&mut running.stdout, "stream.window_update.ack");
    send(
        &mut running.stdin,
        flow_frame(
            "stream.resume",
            7,
            2,
            &accepted,
            json!({"resync_protocol":"scoped_cursor_v1","resumed_cursors":acknowledged}),
        ),
    );
    let resumed = read_until(&mut running.stdout, "stream.resume.ack")
        .pop()
        .unwrap();
    assert_eq!(resumed["payload"]["resync_required"], false);
    fs::write(&second, b"emit").unwrap();
    let delivered = read_until(&mut running.stdout, "model.delta")
        .pop()
        .unwrap();
    assert_eq!(
        delivered["payload"]["text"],
        "delivered after scoped recovery"
    );
    fs::write(&terminal, b"finish").unwrap();
    read_until(&mut running.stdout, "turn.end");
    finish(running);
}

#[test]
fn actual_job_inspection_uses_job_scope_and_runtime_domain_to_recover_output() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let terminal = directory.path().join("terminal");
    let emit = directory.path().join("job-emit");
    let event_store = directory.path().join("events.jsonl");
    let job_store = directory.path().join("jobs.jsonl");
    fs::write(&provider, r#"#!/bin/sh
IFS= read -r start || exit 10
while [ ! -f "$1" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":0,"summary":"job output recovered"}'
"#).unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();
    let mut running = start_host_with_transport_args(
        &provider,
        &[&terminal],
        Some(&event_store),
        &[
            "--transport-buffer-bytes",
            "128",
            "--job-store",
            job_store.to_str().unwrap(),
        ],
    );
    send(
        &mut running.stdin,
        json!({"kind":"hello","seq":0,"payload":{}}),
    );
    read_until(&mut running.stdout, "hello.ack");
    send(&mut running.stdin, start_frame("turn-job-scoped-resume"));
    let accepted = read_until(&mut running.stdout, "turn.accepted")
        .pop()
        .unwrap();
    send(
        &mut running.stdin,
        flow_frame("stream.pause", 2, 0, &accepted, json!({})),
    );
    read_until(&mut running.stdout, "stream.pause.ack");
    let mut job = flow_frame("stream.pause", 3, 0, &accepted, json!({}));
    job["kind"] = json!("job.start");
    job["payload"]
        .as_object_mut()
        .unwrap()
        .remove("control_seq");
    job["payload"]["job_id"] = json!("job-recovery");
    job["payload"]["operation_id"] = json!("start-job-recovery");
    job["payload"]["tool"] = json!("shell.job");
    job["payload"]["target_id"] = json!("rootlinux");
    job["payload"]["mode"] = json!("pipe");
    job["payload"]["command"] = json!(format!(
        "while [ ! -f '{}' ]; do sleep 0.01; done; printf durable-job-observation; while [ ! -f '{}' ]; do sleep 0.01; done",
        emit.display(),
        terminal.display()
    ));
    send(&mut running.stdin, job);
    let started = read_until(&mut running.stdout, "job.start.result")
        .pop()
        .unwrap();
    assert_eq!(started["payload"]["status"], "started");
    fs::write(&emit, b"emit").unwrap();
    let gap = read_until(&mut running.stdout, "stream.resync_required")
        .pop()
        .unwrap();
    let required = &gap["payload"]["required_resumes"][0];
    assert_eq!(required["cursor_domain"], "job_runtime_event");
    assert_eq!(required["cursor_scope"]["job_id"], "job-recovery");
    let mut inspect_payload = required["cursor_scope"].clone();
    inspect_payload["inclusive_cursor"] = required["first_missing_cursor"].clone();
    inspect_payload["durable_inclusive_cursor"] = json!(0);
    inspect_payload["limit"] = json!(1);
    send(
        &mut running.stdin,
        json!({"kind":"job.inspect","seq":4,"direction":"client_to_host","payload":inspect_payload}),
    );
    let inspected = read_until(&mut running.stdout, "job.inspect.result")
        .pop()
        .unwrap();
    assert_eq!(inspected["job_id"], "job-recovery");
    assert_eq!(inspected["payload"]["inspection"]["resync_required"], false);
    assert_eq!(
        inspected["payload"]["inspection"]["next_cursor"],
        required["required_resume_cursor"]
    );
    let acknowledgement = json!([{"cursor_domain":required["cursor_domain"],"cursor_scope":required["cursor_scope"],"resumed_through_cursor":required["required_resume_cursor"]}]);
    send(
        &mut running.stdin,
        flow_frame(
            "stream.resume",
            5,
            1,
            &accepted,
            json!({"resync_protocol":"scoped_cursor_v1","resumed_cursors":acknowledgement}),
        ),
    );
    let resumed = read_until(&mut running.stdout, "stream.resume.ack")
        .pop()
        .unwrap();
    assert_eq!(resumed["payload"]["resync_required"], false);
    fs::write(&terminal, b"finish").unwrap();
    read_until(&mut running.stdout, "turn.end");
    finish(running);
}
