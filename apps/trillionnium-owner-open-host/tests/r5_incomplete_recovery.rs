#[allow(dead_code)]
#[path = "../src/r5_persistence.rs"]
mod r5_persistence;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use r5_persistence::{Persistence, StoredTurn, event_scope, request_sha256, stable_turn_stream_id};
use serde_json::{Value, json};
use trillionnium_owner_open_types::{PROTOCOL, PROTOCOL_VERSION, RunTurnFrame, RunTurnRequest};

fn request() -> RunTurnRequest {
    RunTurnRequest {
        protocol: PROTOCOL.to_string(),
        protocol_version: json!(PROTOCOL_VERSION),
        session_id: "session-incomplete".to_string(),
        task_id: "task-incomplete".to_string(),
        turn_id: "turn-incomplete".to_string(),
        user_input: "do not redispatch me".to_string(),
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

#[test]
fn incomplete_durable_turn_becomes_unknown_without_starting_provider() {
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("provider.sh");
    let counter = directory.path().join("provider-starts");
    let event_store = directory.path().join("events.jsonl");
    fs::write(
        &provider,
        r#"#!/bin/sh
printf x >> "$1"
exit 99
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let request = request();
    let stream = stable_turn_stream_id(&request).unwrap();
    let digest = request_sha256(&request).unwrap();
    let scope = event_scope(&request, &stream);
    let accepted = RunTurnFrame {
        kind: "turn.accepted".to_string(),
        seq: 1,
        payload: json!({
            "status": "accepted",
            "provider_status": "starting",
            "event_log_status": "durable",
            "event_log_error": Value::Null
        }),
        direction: Some("host_to_client".to_string()),
        client_seq: None,
        host_seq: Some(1),
        frame_sha256: None,
        event_id: Some(format!("{stream}-event-0")),
        connection_id: Some("connection-before-crash".to_string()),
        stream_id: Some(stream.clone()),
        turn_stream_id: Some(stream.clone()),
        session_id: Some(request.session_id.clone()),
        profile_id: Some(request.effective_profile_id().to_string()),
        task_id: Some(request.task_id.clone()),
        turn_id: Some(request.turn_id.clone()),
        call_id: None,
        job_id: None,
        tool: None,
        target: None,
        target_id: None,
        extensions: BTreeMap::new(),
    };
    {
        let mut persistence = Persistence::open_best_effort(Some(&event_store));
        assert!(persistence.append_frame(&scope, &digest, &accepted));
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args(["--provider"])
        .arg(&provider)
        .args(["--provider-arg"])
        .arg(&counter)
        .args(["--event-store"])
        .arg(&event_store)
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
            "{{\"kind\":\"turn.start\",\"seq\":1,\"direction\":\"client_to_host\",\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1,\"session_id\":\"session-incomplete\",\"task_id\":\"task-incomplete\",\"turn_id\":\"turn-incomplete\",\"user_input\":\"do not redispatch me\"}}}}"
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
    assert!(
        !counter.exists(),
        "an incomplete durable turn must not start the provider"
    );
    let frames = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(frames[0]["kind"], "hello.ack");
    assert_eq!(frames[1]["kind"], "turn.accepted");
    let terminal = frames.last().unwrap();
    assert_eq!(terminal["kind"], "turn.end");
    assert_eq!(terminal["payload"]["status"], "unknown_after_disconnect");
    assert_eq!(terminal["payload"]["automatic_redispatch"], false);
    assert_eq!(terminal["payload"]["reconciliation"], true);

    let persistence = Persistence::open_best_effort(Some(&event_store));
    match persistence.load(&scope, &digest) {
        StoredTurn::Complete(stored) => {
            assert_eq!(stored.len(), 2);
            assert_eq!(stored.last().unwrap().kind, "turn.end");
            assert_eq!(
                stored.last().unwrap().payload["status"],
                "unknown_after_disconnect"
            );
        }
        other => panic!("unexpected recovered turn: {other:?}"),
    }
}
