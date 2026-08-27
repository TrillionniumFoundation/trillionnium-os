use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

#[test]
fn provider_event_is_persisted_while_the_turn_is_still_running() {
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("provider.sh");
    let ready = directory.path().join("provider-ready");
    let release = directory.path().join("provider-release");
    let event_store = directory.path().join("events.jsonl");
    fs::write(
        &provider,
        r#"#!/bin/sh
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":0,"event":"model.delta","text":"persisted-before-terminal"}'
: > "$1"
while [ ! -f "$2" ]; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"released"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args(["--provider"])
        .arg(&provider)
        .args(["--provider-arg"])
        .arg(&ready)
        .args(["--provider-arg"])
        .arg(&release)
        .args(["--event-store"])
        .arg(&event_store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        "{{\"kind\":\"turn.start\",\"seq\":0,\"direction\":\"client_to_host\",\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1,\"session_id\":\"session-stream-store\",\"task_id\":\"task-stream-store\",\"turn_id\":\"turn-stream-store\",\"user_input\":\"persist before completion\"}}}}"
    )
    .unwrap();
    stdin.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "provider never reached its hold point");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(child.try_wait().unwrap().is_none(), "turn completed too early");

    let persisted_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let contents = fs::read_to_string(&event_store).unwrap_or_default();
        if contents.contains("persisted-before-terminal")
            && contents.contains("\"kind\":\"model.delta\"")
        {
            break;
        }
        assert!(
            Instant::now() < persisted_deadline,
            "model.delta was not durably visible before provider completion"
        );
        thread::sleep(Duration::from_millis(5));
    }

    fs::write(&release, b"release").unwrap();
    drop(stdin);
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
    let model = frames
        .iter()
        .position(|frame| frame["kind"] == "model.delta")
        .unwrap();
    let terminal = frames
        .iter()
        .position(|frame| frame["kind"] == "turn.end")
        .unwrap();
    assert!(model < terminal);
    assert_eq!(frames[terminal]["payload"]["status"], "completed");
}
