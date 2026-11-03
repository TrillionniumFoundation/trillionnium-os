//! Real local Host/Core protocol fixture, with a fixed synthetic provider.
//! No phone, HTTP provider, model generation, or accepted-state repair.
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
mod support;
use support::{read_event_store_bytes, secure_tempdir};

fn send(writer: &mut impl Write, value: &Value) {
    writeln!(writer, "{value}").unwrap();
    writer.flush().unwrap();
}
fn read_until(reader: &mut impl BufRead, kind: &str) -> Value {
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        let frame: Value = serde_json::from_str(line.trim_end()).unwrap();
        if frame["kind"] == kind {
            return frame;
        }
    }
}

#[test]
fn completed_turn_late_control_gets_exact_reply_and_original_readback_stays_complete() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let events = directory.path().join("events.jsonl");
    let invocations = directory.path().join("provider-invocations.txt");
    let script=r#"#!/bin/sh
printf 'once\n' >> '__INVOCATIONS__'
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"call-late-fixture","tool":"shell.exec","command":"printf 37"}}'
IFS= read -r result || exit 11
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"known local fixture complete"}'
"#.replace("__INVOCATIONS__",invocations.to_str().unwrap());
    fs::write(&provider, script).unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .arg("--provider")
        .arg(&provider)
        .arg("--event-store")
        .arg(&events)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"kind":"turn.start","seq":0,"direction":"client_to_host",
        "broker_request_id":"start:1","broker_request_sha256":"b".repeat(64),"broker_request_upstream_seq":11,
        "payload":{"protocol":"trillionnium.agent.turn.v1","protocol_version":1,"profile_id":"owner-open",
          "session_id":"session-late-fixture","task_id":"task-late-fixture","turn_id":"turn-late-fixture",
          "user_input":"local mechanism fixture"}}),
    );
    let accepted = read_until(&mut stdout, "turn.accepted");
    let digest = accepted["payload"]["turn_request_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let stream = accepted["turn_stream_id"].as_str().unwrap().to_string();
    let terminal = read_until(&mut stdout, "turn.end");
    assert_eq!(terminal["payload"]["status"], "completed");
    let original_events = read_event_store_bytes(&events);
    assert!(!original_events.is_empty());
    let scope = json!({"profile_id":"owner-open","session_id":"session-late-fixture",
      "task_id":"task-late-fixture","turn_id":"turn-late-fixture","turn_stream_id":stream});
    for (index, kind, id) in [
        (1, "turn.cancel", "late-cancel:2"),
        (2, "tool.cancel", "late-tool-cancel:3"),
    ] {
        let mut payload = scope.clone();
        if kind == "tool.cancel" {
            payload["call_id"] = json!("call-late-fixture");
        }
        send(
            &mut stdin,
            &json!({"kind":kind,"seq":index,"direction":"client_to_host",
            "broker_request_id":id,"broker_request_sha256":"c".repeat(64),"broker_request_upstream_seq":11+index,
            "payload":payload}),
        );
        let reply = read_until(&mut stdout, "host.error");
        assert_eq!(reply["payload"]["code"], "no_active_turn");
        assert_eq!(reply["payload"]["request_kind"], kind);
        assert_eq!(reply["broker_request_id"], id);
        assert_eq!(reply["broker_request_sha256"], "c".repeat(64));
        assert_eq!(reply["broker_request_upstream_seq"], 11 + index);
        assert_eq!(reply["payload"]["cancel_requested"], false);
        assert_eq!(read_event_store_bytes(&events), original_events);
    }
    let mut inspect = scope;
    inspect["request_sha256"] = json!(digest);
    inspect["inclusive_cursor"] = json!(0);
    inspect["limit"] = json!(256);
    send(
        &mut stdin,
        &json!({"kind":"turn.inspect","seq":3,"direction":"client_to_host",
        "broker_request_id":"inspect:4","broker_request_sha256":"d".repeat(64),"broker_request_upstream_seq":14,
        "payload":inspect}),
    );
    let readback = read_until(&mut stdout, "turn.inspect.result");
    assert_eq!(readback["broker_request_id"], "inspect:4");
    let payload = &readback["payload"];
    assert_eq!(payload["complete"], true);
    assert_eq!(payload["has_more"], false);
    assert_eq!(payload["inclusive_cursor"], 0);
    let frames = payload["frames"].as_array().unwrap();
    assert_eq!(
        frames
            .iter()
            .filter(|v| v["kind"] == "tool.started")
            .count(),
        1
    );
    assert_eq!(frames.last().unwrap()["payload"]["status"], "completed");
    assert_eq!(read_event_store_bytes(&events), original_events);
    assert_eq!(fs::read_to_string(&invocations).unwrap(), "once\n");
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
    assert!(status.success(), "Host fixture failed: {stderr}");
}
