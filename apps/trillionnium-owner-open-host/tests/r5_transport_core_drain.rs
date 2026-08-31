use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

mod support;

use support::secure_tempdir;

#[test]
fn transport_drains_the_final_core_frame_and_reaps_the_descendant_group() {
    let directory = secure_tempdir();
    let pid_file = directory.path().join("core-descendant.pid");
    let script = r#"
import json
import os
import sys
import time

pid = os.fork()
if pid == 0:
    time.sleep(30)
    os._exit(0)

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(str(pid))
    handle.flush()
    os.fsync(handle.fileno())

frame = {"kind": "hello.ack", "seq": 41, "payload": {"status": "ready"}}
sys.stdout.write(json.dumps(frame, separators=(",", ":")) + "\n")
sys.stdout.flush()
os._exit(0)
"#;

    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .arg("--transport-core")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .arg(&pid_file)
        .stdin(Stdio::null())
        .output()
        .expect("transport Host must start");

    assert!(
        output.status.success(),
        "status={:?}; stdout={}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.lines().any(|line| {
        let frame: serde_json::Value = serde_json::from_str(line).unwrap();
        frame.get("kind").and_then(serde_json::Value::as_str) == Some("hello.ack")
            && frame
                .get("payload")
                .and_then(|payload| payload.get("status"))
                .and_then(serde_json::Value::as_str)
                == Some("ready")
    }));

    let descendant = fs::read_to_string(&pid_file)
        .expect("core must publish the descendant pid")
        .trim()
        .parse::<i32>()
        .expect("descendant pid must be decimal");
    assert!(descendant > 1);

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let result = unsafe { libc::kill(descendant, 0) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            panic!("unexpected descendant liveness probe error: {error}");
        }
        assert!(
            Instant::now() < deadline,
            "core descendant {descendant} survived transport process-group cleanup"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
