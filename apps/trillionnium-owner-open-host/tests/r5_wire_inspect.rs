#[allow(dead_code)]
#[path = "../src/r5_persistence.rs"]
mod r5_persistence;

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

use r5_persistence::{Persistence, event_scope, request_sha256, stable_turn_stream_id};
use serde_json::{Value, json};
use trillionnium_owner_open_types::{PROTOCOL, PROTOCOL_VERSION, RunTurnFrame, RunTurnRequest};

mod support;

use support::secure_tempdir;

fn request(session: &str, task: &str, turn: &str, input: &str) -> RunTurnRequest {
    RunTurnRequest {
        protocol: PROTOCOL.to_string(),
        protocol_version: json!(PROTOCOL_VERSION),
        session_id: session.to_string(),
        task_id: task.to_string(),
        turn_id: turn.to_string(),
        user_input: input.to_string(),
        profile_id: None,
        context_ref: None,
        config_generation: None,
        client_request_id: None,
        server_request_id: None,
        turn_request_sha256: None,
        resume_cursor: None,
        resume_token: None,
        prior_connection_id: None,
        parent_turn_id: None,
        continuation_of: None,
        extensions: BTreeMap::new(),
    }
}

fn durable_frame(
    request: &RunTurnRequest,
    stream: &str,
    kind: &str,
    seq: u64,
    call_id: Option<&str>,
) -> RunTurnFrame {
    RunTurnFrame {
        kind: kind.to_string(),
        seq,
        payload: json!({"fixture": kind, "ordinal": seq}),
        direction: Some("host_to_client".to_string()),
        client_seq: None,
        host_seq: Some(seq),
        frame_sha256: None,
        event_id: Some(format!("{stream}-event-{seq}")),
        connection_id: Some("connection-inspect-fixture".to_string()),
        stream_id: Some(stream.to_string()),
        turn_stream_id: Some(stream.to_string()),
        session_id: Some(request.session_id.clone()),
        profile_id: Some(request.effective_profile_id().to_string()),
        task_id: Some(request.task_id.clone()),
        turn_id: Some(request.turn_id.clone()),
        call_id: call_id.map(str::to_string),
        job_id: None,
        tool: call_id.map(|_| "shell.exec".to_string()),
        target: None,
        target_id: call_id.map(|_| "rootlinux".to_string()),
        extensions: BTreeMap::new(),
    }
}

fn executable_script(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn parse_output(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "Host failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect()
}

#[test]
fn completed_turn_and_call_inspection_are_read_only_and_do_not_spawn_provider() {
    let directory = secure_tempdir();
    let event_store = directory.path().join("events.jsonl");
    let provider = directory.path().join("provider.sh");
    let provider_counter = directory.path().join("provider-starts");
    executable_script(&provider, "#!/bin/sh\nprintf x >> \"$1\"\nexit 99\n");

    let request = request(
        "session-wire-inspect",
        "task-wire-inspect",
        "turn-wire-inspect",
        "inspect durable state",
    );
    let stream = stable_turn_stream_id(&request).unwrap();
    let digest = request_sha256(&request).unwrap();
    let scope = event_scope(&request, &stream);
    let durable = vec![
        durable_frame(&request, &stream, "turn.accepted", 0, None),
        durable_frame(
            &request,
            &stream,
            "tool.accepted",
            1,
            Some("call-wire-inspect"),
        ),
        durable_frame(
            &request,
            &stream,
            "tool.result",
            2,
            Some("call-wire-inspect"),
        ),
        durable_frame(&request, &stream, "turn.end", 3, None),
    ];
    {
        let mut persistence = Persistence::open_best_effort(Some(&event_store));
        for frame in &durable {
            assert!(persistence.append_frame(&scope, &digest, frame));
        }
    }
    let before = fs::read(&event_store).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args(["--provider"])
        .arg(&provider)
        .args(["--provider-arg"])
        .arg(&provider_counter)
        .args(["--event-store"])
        .arg(&event_store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{{\"kind\":\"hello\",\"seq\":0,\"payload\":{{}}}}").unwrap();
        writeln!(
            stdin,
            "{{\"kind\":\"turn.inspect\",\"seq\":1,\"direction\":\"client_to_host\",\"payload\":{{\"session_id\":\"session-wire-inspect\",\"task_id\":\"task-wire-inspect\",\"turn_id\":\"turn-wire-inspect\",\"request_sha256\":\"{digest}\",\"inclusive_cursor\":1,\"limit\":2}}}}"
        )
        .unwrap();
        writeln!(
            stdin,
            "{{\"kind\":\"call.inspect\",\"seq\":2,\"direction\":\"client_to_host\",\"call_id\":\"call-wire-inspect\",\"payload\":{{\"session_id\":\"session-wire-inspect\",\"task_id\":\"task-wire-inspect\",\"turn_id\":\"turn-wire-inspect\",\"call_id\":\"call-wire-inspect\",\"request_sha256\":\"{digest}\",\"inclusive_cursor\":0,\"limit\":8}}}}"
        )
        .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let frames = parse_output(&output);

    assert_eq!(frames[0]["kind"], "hello.ack");
    assert_eq!(
        frames[0]["payload"]["turn_inspect"],
        "read_only_inclusive_cursor"
    );
    assert_eq!(
        frames[0]["payload"]["call_inspect"],
        "live_registry_or_durable_frames"
    );

    let turn = frames
        .iter()
        .find(|frame| frame["kind"] == "turn.inspect.result")
        .unwrap();
    assert_eq!(turn["payload"]["status"], "found");
    assert_eq!(turn["payload"]["source"], "durable_event_store");
    assert_eq!(turn["payload"]["inclusive_cursor"], 1);
    assert_eq!(turn["payload"]["next_cursor"], 3);
    assert_eq!(turn["payload"]["total_events"], 4);
    assert_eq!(turn["payload"]["complete"], true);
    assert_eq!(turn["payload"]["has_more"], true);
    assert_eq!(turn["payload"]["frames"].as_array().unwrap().len(), 2);

    let call = frames
        .iter()
        .find(|frame| frame["kind"] == "call.inspect.result")
        .unwrap();
    assert_eq!(call["payload"]["status"], "found");
    assert_eq!(call["payload"]["source"], "durable_event_store");
    assert_eq!(call["payload"]["total_call_events"], 2);
    assert_eq!(call["payload"]["turn_complete"], true);
    let call_frames = call["payload"]["frames"].as_array().unwrap();
    assert_eq!(call_frames[0]["kind"], "tool.accepted");
    assert_eq!(call_frames[1]["kind"], "tool.result");

    assert!(
        !provider_counter.exists(),
        "read-only inspection must never start the provider"
    );
    assert_eq!(
        fs::read(&event_store).unwrap(),
        before,
        "wire inspection mutated the durable event store"
    );
}

struct RunningHost {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

fn start_host(provider: &Path, event_store: &Path) -> RunningHost {
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
fn active_turn_and_call_inspection_observe_current_state_without_cancelling() {
    let directory = secure_tempdir();
    let event_store = directory.path().join("events.jsonl");
    let provider = directory.path().join("provider.sh");
    executable_script(
        &provider,
        r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"call-live-inspect","tool":"shell.exec","command":"sleep 30"}}'
IFS= read -r tool_result || exit 11
case "$tool_result" in
  *'"kind":"client_cancelled"'*) ;;
  *) exit 12 ;;
esac
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"continued after inspection and targeted cancel"}'
"#,
    );

    let mut running = start_host(&provider, &event_store);
    writeln!(
        running.stdin,
        "{{\"kind\":\"turn.start\",\"seq\":0,\"direction\":\"client_to_host\",\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1,\"session_id\":\"session-live-inspect\",\"task_id\":\"task-live-inspect\",\"turn_id\":\"turn-live-inspect\",\"user_input\":\"inspect while active\"}}}}"
    )
    .unwrap();
    running.stdin.flush().unwrap();

    let mut frames = read_until_kind(&mut running.stdout, "tool.started");
    writeln!(
        running.stdin,
        "{{\"kind\":\"turn.inspect\",\"seq\":1,\"direction\":\"client_to_host\",\"payload\":{{\"session_id\":\"session-live-inspect\",\"task_id\":\"task-live-inspect\",\"turn_id\":\"turn-live-inspect\",\"inclusive_cursor\":0,\"limit\":64}}}}"
    )
    .unwrap();
    running.stdin.flush().unwrap();
    frames.extend(read_until_kind(&mut running.stdout, "turn.inspect.result"));
    let turn = frames
        .iter()
        .rev()
        .find(|frame| frame["kind"] == "turn.inspect.result")
        .unwrap();
    assert_eq!(turn["payload"]["status"], "found");
    assert_eq!(turn["payload"]["complete"], false);
    assert!(
        turn["payload"]["frames"]
            .as_array()
            .unwrap()
            .iter()
            .any(|frame| frame["kind"] == "tool.started")
    );

    writeln!(
        running.stdin,
        "{{\"kind\":\"call.inspect\",\"seq\":2,\"direction\":\"client_to_host\",\"call_id\":\"call-live-inspect\",\"payload\":{{\"session_id\":\"session-live-inspect\",\"task_id\":\"task-live-inspect\",\"turn_id\":\"turn-live-inspect\",\"call_id\":\"call-live-inspect\",\"inclusive_cursor\":0,\"limit\":64}}}}"
    )
    .unwrap();
    running.stdin.flush().unwrap();
    frames.extend(read_until_kind(&mut running.stdout, "call.inspect.result"));
    let call = frames
        .iter()
        .rev()
        .find(|frame| frame["kind"] == "call.inspect.result")
        .unwrap();
    assert_eq!(call["payload"]["status"], "found");
    assert_eq!(call["payload"]["source"], "live_registry");
    assert_eq!(call["payload"]["snapshot"]["state"]["kind"], "started");
    assert_eq!(call["payload"]["side_effects"], false);

    writeln!(
        running.stdin,
        "{{\"kind\":\"tool.cancel\",\"seq\":3,\"direction\":\"client_to_host\",\"call_id\":\"call-live-inspect\",\"payload\":{{\"session_id\":\"session-live-inspect\",\"turn_id\":\"turn-live-inspect\",\"call_id\":\"call-live-inspect\"}}}}"
    )
    .unwrap();
    running.stdin.flush().unwrap();

    let frames = finish(running, frames);
    assert!(
        frames
            .iter()
            .any(|frame| frame["kind"] == "tool.cancel.accepted")
    );
    let terminal = frames.last().unwrap();
    assert_eq!(terminal["kind"], "turn.end");
    assert_eq!(terminal["payload"]["status"], "completed");
    assert_eq!(
        terminal["payload"]["summary"],
        "continued after inspection and targeted cancel"
    );
}
