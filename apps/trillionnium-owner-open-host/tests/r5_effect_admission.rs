use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
#[allow(dead_code)]
#[path = "../src/r5_persistence.rs"]
mod r5_persistence;
use r5_persistence::Persistence;

mod support;
use support::secure_tempdir;

fn provider(root: &Path, wait: bool) -> std::path::PathBuf {
    let path = root.join("provider.sh");
    let wait = if wait {
        "while test ! -e \"$root/continue\"; do sleep 0.01; done\n"
    } else {
        ""
    };
    fs::write(&path, format!(r#"#!/bin/sh
root=$1
IFS= read -r start || exit 10
printf x >> "$root/provider-starts"
{wait}printf '%s\n' '{{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"tool.call","seq":0,"call":{{"call_id":"same-call","tool":"shell.exec","command":"printf x >> effects"}}}}'
IFS= read -r result || exit 11
printf '%s\n' '{{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":1,"summary":"fixture complete"}}'
"#)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

struct Running {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    fn send(&mut self, value: &Value) {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, value).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }

    fn frame(&mut self) -> Value {
        let mut line = String::new();
        assert!(self.output.read_line(&mut line).unwrap() > 0);
        serde_json::from_str(&line).unwrap()
    }

    fn finish(mut self) -> Vec<Value> {
        self.input.take();
        // Fixtures emit only a bounded handful of frames. Wait with a deadline
        // so an admission/receipt deadlock fails the test instead of hanging CI.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Host did not finish bounded fixture"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let mut remaining = String::new();
        self.output.read_to_string(&mut remaining).unwrap();
        remaining
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn start(root: &Path, transport: bool, configured: bool, allow: bool, wait: bool) -> Running {
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
    command
        .arg("--provider")
        .arg(provider(root, wait))
        .arg("--provider-arg")
        .arg(root)
        .arg("--provider-cwd")
        .arg(root)
        .arg("--job-store")
        .arg(root.join("jobs.jsonl"));
    if configured {
        command.arg("--event-store").arg(root.join("events.jsonl"));
    }
    if allow {
        command.arg("--allow-unjournaled-effects-for-development");
    }
    let mut child = command
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    Running {
        input: child.stdin.take(),
        output: BufReader::new(child.stdout.take().unwrap()),
        child,
    }
}

fn hello() -> Value {
    json!({"kind":"hello","seq":0,"payload":{"protocol":"trillionnium.agent.turn.v1","protocol_version":1}})
}
fn turn() -> Value {
    json!({"kind":"turn.start","seq":1,"payload":{"protocol":"trillionnium.agent.turn.v1","protocol_version":1,"session_id":"same-session","task_id":"same-task","turn_id":"same-turn","user_input":"bounded local fixture"}})
}

fn assert_rejected(frames: &[Value], root: &Path) {
    assert!(
        frames.iter().any(|frame| frame["kind"] == "host.error"),
        "{frames:?}"
    );
    assert!(
        !frames
            .iter()
            .any(|frame| frame["kind"] == "turn.accepted" || frame["kind"] == "tool.started")
    );
    assert!(!root.join("provider-starts").exists());
    assert!(!root.join("effects").exists());
}

#[test]
fn configured_corrupt_history_never_runs_or_retries_even_with_development_override() {
    for transport in [false, true] {
        for allow in [false, true] {
            let root = secure_tempdir();
            fs::write(root.path().join("events.jsonl"), b"not valid JSON\n").unwrap();
            fs::set_permissions(
                root.path().join("events.jsonl"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            for _ in 0..2 {
                let mut host = start(root.path(), transport, true, allow, false);
                host.send(&hello());
                let greeting = host.frame();
                assert_eq!(greeting["payload"]["runtime_ready"], false);
                assert_eq!(greeting["payload"]["event_log_status"], "unavailable");
                host.send(&turn());
                assert_rejected(&host.finish(), root.path());
            }
        }
    }
}

#[test]
fn unconfigured_direct_effects_require_the_explicit_development_option() {
    for allow in [false, true] {
        let root = secure_tempdir();
        let mut host = start(root.path(), false, false, allow, false);
        host.send(&hello());
        assert_eq!(host.frame()["payload"]["runtime_ready"], allow);
        host.send(&turn());
        let frames = host.finish();
        if allow {
            assert_eq!(fs::read(root.path().join("effects")).unwrap(), b"x");
            assert!(
                frames
                    .iter()
                    .any(|f| f["kind"] == "turn.end" && f["payload"]["status"] == "completed")
            );
        } else {
            assert_rejected(&frames, root.path());
        }
    }
}

#[test]
fn acceptance_append_failure_fences_provider_before_start() {
    let root = secure_tempdir();
    let mut host = start(root.path(), false, true, false, false);
    host.send(&hello());
    assert_eq!(host.frame()["payload"]["runtime_ready"], true);
    fs::rename(
        root.path().join("events.jsonl.segments"),
        root.path().join("retained-store"),
    )
    .unwrap();
    host.send(&turn());
    assert_rejected(&host.finish(), root.path());
}

#[test]
fn tool_acceptance_receipt_fences_effect_after_mid_turn_store_failure() {
    for transport in [false, true] {
        let root = secure_tempdir();
        let mut host = start(root.path(), transport, true, false, true);
        host.send(&hello());
        assert_eq!(host.frame()["payload"]["runtime_ready"], true);
        host.send(&turn());
        assert_eq!(host.frame()["kind"], "turn.accepted");
        fs::rename(
            root.path().join("events.jsonl.segments"),
            root.path().join("retained-store"),
        )
        .unwrap();
        fs::write(root.path().join("continue"), b"continue").unwrap();
        let frames = host.finish();
        assert!(!root.path().join("effects").exists());
        assert!(!frames.iter().any(|f| f["kind"] == "tool.started"));
        let terminal = frames
            .iter()
            .find(|f| f["kind"] == "turn.end")
            .expect("truthful terminal");
        assert_eq!(
            terminal["payload"]["status"],
            "unknown_after_journal_failure"
        );
        assert_eq!(terminal["payload"]["runtime_ready"], false);
    }
}

#[test]
fn competing_writer_is_not_an_empty_history_or_permission_to_execute() {
    let root = secure_tempdir();
    let persistence =
        Persistence::open_best_effort_segmented_path(Some(&root.path().join("events.jsonl")));
    assert!(persistence.is_durable());
    let mut host = start(root.path(), false, true, false, false);
    host.send(&hello());
    assert_eq!(host.frame()["payload"]["runtime_ready"], false);
    host.send(&turn());
    assert_rejected(&host.finish(), root.path());
}
