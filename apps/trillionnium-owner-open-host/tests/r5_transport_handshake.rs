use std::io::{BufReader, Read, Write};
use std::process::{Command, Stdio};

use serde_json::Value;

#[test]
fn pre_accept_negative_core_quarantines_late_frames() {
    // The resolver is flushed first, then the fake core waits before writing
    // already-buffered provider/terminal bytes. Those bytes arrive after the
    // transport has closed the unaccepted turn generation; they must not be
    // routed into the client stream.
    let script = r#"
import json
import sys
import time

if not sys.stdin.readline():
    sys.exit(2)

scope = {
    "session_id": "session-quarantine",
    "task_id": "task-quarantine",
    "turn_id": "turn-quarantine",
}

def emit(kind, seq, payload):
    frame = {"kind": kind, "seq": seq, "payload": payload}
    frame.update(scope)
    sys.stdout.write(json.dumps(frame, separators=(",", ":")) + "\n")
    sys.stdout.flush()

emit("host.error", 0, {"code": "provider_unavailable", "message": "rejected"})
time.sleep(0.25)
emit("model.delta", 1, {"text": "late-provider-byte"})
emit("turn.end", 2, {"status": "failed", "summary": "late-terminal-byte"})
"#;

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .args(["--transport-core", "python3", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("transport Host must start");
    {
        let mut stdin = child.stdin.take().expect("transport stdin");
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "kind": "turn.start",
                "seq": 0,
                "direction": "client_to_host",
                "payload": {
                    "protocol": "trillionnium.agent.turn.v1",
                    "protocol_version": 1,
                    "session_id": "session-quarantine",
                    "task_id": "task-quarantine",
                    "turn_id": "turn-quarantine",
                    "user_input": "exercise pre-accept quarantine"
                }
            })
        )
        .expect("turn.start writes");
        stdin.flush().expect("turn.start flushes");
    }

    let mut stdout = BufReader::new(child.stdout.take().expect("transport stdout"));
    let mut encoded = String::new();
    stdout
        .read_to_string(&mut encoded)
        .expect("transport stdout is readable");
    let status = child.wait().expect("transport Host exits");
    assert!(
        status.success(),
        "transport Host failed: stdout={encoded}; status={status:?}"
    );

    let frames = encoded
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("Host emits JSON frames"))
        .collect::<Vec<_>>();
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame["kind"] == "host.error")
            .count(),
        1,
        "the pre-accept resolver remains observable"
    );
    assert!(
        frames
            .iter()
            .all(|frame| frame["kind"] != "model.delta" && frame["kind"] != "turn.end"),
        "late core frames must be quarantined: {frames:?}"
    );
}
