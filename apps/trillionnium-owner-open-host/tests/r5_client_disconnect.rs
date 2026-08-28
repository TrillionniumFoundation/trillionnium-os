use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

#[test]
fn client_output_disconnect_does_not_cancel_an_accepted_turn() {
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("provider.sh");
    let counter = directory.path().join("provider-starts");
    let event_store = directory.path().join("events.jsonl");
    let transport_store = std::path::PathBuf::from(format!("{}.transport", event_store.display()));
    fs::write(
        &provider,
        r#"#!/bin/sh
printf x >> "$1"
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"provider.event","seq":0,"event":"model.message","text":"completed-with-detached-client"}'
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"client delivery detached"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args([
            "--transport-core",
            env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-core"),
        ])
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

    drop(child.stdout.take());
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(
            stdin,
            "{{\"kind\":\"turn.start\",\"seq\":0,\"direction\":\"client_to_host\",\"payload\":{{\"protocol\":\"trillionnium.agent.turn.v1\",\"protocol_version\":1,\"session_id\":\"session-detached\",\"task_id\":\"task-detached\",\"turn_id\":\"turn-detached\",\"user_input\":\"finish despite delivery loss\"}}}}"
        )
        .unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "host should finish the accepted turn after EPIPE\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&counter).unwrap(), b"x");

    let stored = fs::read_to_string(&event_store).unwrap();
    assert!(stored.contains("completed-with-detached-client"));
    assert!(stored.contains("\"kind\":\"turn.end\""));
    assert!(stored.contains("\"status\":\"completed\""));

    let transport = fs::read_to_string(&transport_store).unwrap();
    assert!(transport.contains("transport.delivery.terminal"));
    assert!(transport.contains("\"client_delivery_status\":\"detached\""));
    assert!(transport.contains("\"automatic_redispatch\":false"));
}
