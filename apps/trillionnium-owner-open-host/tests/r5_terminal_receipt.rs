//! A real successful effect followed by a failed turn-terminal append must stay
//! uncertain, and recovering the retained store must never execute it again.
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

mod support;
use support::secure_tempdir;

struct Running {
    child: Child,
    input: Option<ChildStdin>,
    frames: Receiver<Value>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    fn start(root: &Path, transport: bool) -> Self {
        let mut command = Command::new(if transport {
            env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host")
        } else {
            env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-core")
        });
        if transport {
            command.args([
                "--transport-core",
                env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-core"),
            ]);
        }
        let mut child = command
            .arg("--provider")
            .arg(root.join("provider.sh"))
            .arg("--provider-arg")
            .arg(root)
            .arg("--provider-cwd")
            .arg(root)
            .arg("--event-store")
            .arg(root.join("events.jsonl"))
            .arg("--job-store")
            .arg(root.join("jobs.jsonl"))
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let output = child.stdout.take().unwrap();
        let (sender, frames) = channel();
        thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let value = serde_json::from_str(&line.unwrap()).unwrap();
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        let mut running = Self {
            child,
            input,
            frames,
        };
        for frame in [
            json!({"kind":"hello","seq":0,"payload":{"protocol":"trillionnium.agent.turn.v1","protocol_version":1}}),
            json!({"kind":"turn.start","seq":1,"payload":{"protocol":"trillionnium.agent.turn.v1","protocol_version":1,"session_id":"session-terminal-receipt","task_id":"task-terminal-receipt","turn_id":"turn-terminal-receipt","user_input":"complete exactly once"}}),
        ] {
            let writer = running.input.as_mut().unwrap();
            serde_json::to_writer(&mut *writer, &frame).unwrap();
            writer.write_all(b"\n").unwrap();
            writer.flush().unwrap();
        }
        running
    }

    fn finish(mut self) -> Vec<Value> {
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut frames = Vec::new();
        loop {
            match self.frames.recv_timeout(Duration::from_millis(20)) {
                Ok(frame) => frames.push(frame),
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => assert!(
                    Instant::now() < deadline,
                    "terminal receipt fixture did not finish: {frames:?}"
                ),
            }
        }
        assert!(self.child.wait().unwrap().success());
        frames
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "provider did not receive tool.result"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn failed_terminal_append_preserves_observed_success_but_never_reexecutes_after_recovery() {
    for transport in [false, true] {
        let root = secure_tempdir();
        let provider = root.path().join("provider.sh");
        fs::write(&provider, r#"#!/bin/sh
set -eu
root=$1
IFS= read -r start
printf x >> "$root/provider-starts"
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{"call_id":"call-terminal-receipt","tool":"shell.exec","command":"printf x >> effects"}}'
IFS= read -r result
case "$result" in *'"kind":"tool.result"'*) ;; *) exit 12 ;; esac
printf received > "$root/tool-result-received"
while test ! -e "$root/finish"; do sleep 0.01; done
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"observed successful effect"}'
"#).unwrap();
        fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();
        let host = Running::start(root.path(), transport);
        // This handshake comes from the provider after the durable tool.result
        // receipt, so the fault is at turn completion, not tool admission.
        wait_for_file(&root.path().join("tool-result-received"));
        assert_eq!(fs::read(root.path().join("effects")).unwrap(), b"x");
        let store = root.path().join("events.jsonl.segments");
        let retained = root.path().join("retained-segments");
        fs::rename(&store, &retained).unwrap();
        fs::write(root.path().join("finish"), b"finish").unwrap();
        let frames = host.finish();
        let terminal = frames.iter().find(|f| f["kind"] == "turn.end").unwrap();
        assert_eq!(
            terminal["payload"]["status"],
            "unknown_after_journal_failure"
        );
        assert_eq!(terminal["payload"]["observed_status"], "completed");
        assert_eq!(terminal["payload"]["runtime_ready"], false);
        assert_eq!(terminal["payload"]["automatic_redispatch"], false);
        assert!(
            frames
                .iter()
                .any(|f| f["kind"] == "tool.result" && f["payload"]["exit_code"] == 0)
        );

        // Restore the same retained bytes, rather than creating an empty store.
        fs::rename(&retained, &store).unwrap();
        let recovered = Running::start(root.path(), transport).finish();
        let terminal = recovered.iter().find(|f| f["kind"] == "turn.end").unwrap();
        assert_eq!(terminal["payload"]["status"], "unknown_after_disconnect");
        assert_eq!(terminal["payload"]["automatic_redispatch"], false);
        assert_eq!(fs::read(root.path().join("effects")).unwrap(), b"x");
        assert_eq!(fs::read(root.path().join("provider-starts")).unwrap(), b"x");
    }
}
