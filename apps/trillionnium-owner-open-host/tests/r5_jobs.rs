use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn provider_fixture(path: &Path, marker: &Path) {
    fs::write(
        path,
        format!(
            "#!/bin/sh\nprintf provider-started > '{}'\nexit 99\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn job_start(command: &str) -> String {
    serde_json::json!({
        "kind": "job.start",
        "seq": 1,
        "direction": "client_to_host",
        "payload": {
            "session_id": "session-jobs",
            "profile_id": "owner-open",
            "task_id": "task-jobs",
            "turn_id": "turn-jobs",
            "turn_stream_id": "turn-stream-jobs",
            "job_id": "job-pipe",
            "operation_id": "start-job-pipe",
            "tool": "shell.job",
            "target_id": "rootlinux",
            "mode": "pipe",
            "command": command
        }
    })
    .to_string()
}

fn run_core(provider: &Path, job_store: &Path, frames: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-core"))
        .args(["--provider"])
        .arg(provider)
        .args(["--job-store"])
        .arg(job_store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(
            stdin,
            "{}",
            serde_json::json!({
                "kind": "hello",
                "seq": 0,
                "payload": {
                    "protocol": "trillionnium.agent.turn.v1",
                    "protocol_version": 1
                }
            })
        )
        .unwrap();
        for frame in frames {
            writeln!(stdin, "{frame}").unwrap();
        }
    }
    child.wait_with_output().unwrap()
}

fn decoded(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "job core failed\nstdout:\n{}\nstderr:\n{}",
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
fn pipe_job_runs_on_the_same_carrier_without_starting_the_provider() {
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("provider.sh");
    let provider_marker = directory.path().join("provider-started");
    let job_store = directory.path().join("jobs.jsonl");
    provider_fixture(&provider, &provider_marker);

    let frames = vec![
        job_start("IFS= read -r line; printf 'job:%s' \"$line\""),
        serde_json::json!({
            "kind": "job.write",
            "seq": 2,
            "direction": "client_to_host",
            "payload": {
                "session_id": "session-jobs",
                "profile_id": "owner-open",
                "task_id": "task-jobs",
                "turn_id": "turn-jobs",
                "turn_stream_id": "turn-stream-jobs",
                "job_id": "job-pipe",
                "operation_id": "write-job-pipe",
                "data": {"encoding": "utf8", "data": "hello\n"}
            }
        })
        .to_string(),
        serde_json::json!({
            "kind": "job.close_stdin",
            "seq": 3,
            "direction": "client_to_host",
            "payload": {
                "session_id": "session-jobs",
                "profile_id": "owner-open",
                "task_id": "task-jobs",
                "turn_id": "turn-jobs",
                "turn_stream_id": "turn-stream-jobs",
                "job_id": "job-pipe",
                "operation_id": "close-job-pipe"
            }
        })
        .to_string(),
    ];
    let output = run_core(&provider, &job_store, &frames);
    let frames = decoded(&output);
    assert!(!provider_marker.exists());
    assert!(frames.iter().any(|frame| {
        frame["kind"] == "hello.ack" && frame["payload"]["long_running_jobs"] == true
    }));
    assert!(
        frames
            .iter()
            .any(|frame| frame["kind"] == "job.start.result")
    );
    assert!(frames.iter().any(|frame| frame["kind"] == "job.started"));
    let output = frames
        .iter()
        .find(|frame| {
            frame["kind"] == "job.output"
                && frame["payload"]["stream"] == "stdout"
                && frame["payload"]["encoding"] == "base64"
        })
        .expect("job.output");
    assert!(output["payload"]["cursor"].is_u64());
    assert!(output["durable_cursor"].is_u64());
    assert!(frames.iter().any(|frame| {
        frame["kind"] == "job.result" && frame["payload"]["terminal_kind"] == "exited"
    }));
    assert!(
        fs::read_to_string(job_store)
            .unwrap()
            .contains("job.terminal")
    );
}

#[test]
fn completed_job_is_not_redispatched_after_a_new_core_process() {
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("provider.sh");
    let provider_marker = directory.path().join("provider-started");
    let job_store = directory.path().join("jobs.jsonl");
    let counter = directory.path().join("counter");
    provider_fixture(&provider, &provider_marker);
    let command = format!("printf x >> '{}'; printf completed", counter.display());

    let first = decoded(&run_core(&provider, &job_store, &[job_start(&command)]));
    assert!(first.iter().any(|frame| frame["kind"] == "job.result"));
    assert_eq!(fs::read(&counter).unwrap(), b"x");

    let second = decoded(&run_core(&provider, &job_store, &[job_start(&command)]));
    assert_eq!(fs::read(&counter).unwrap(), b"x");
    assert!(!provider_marker.exists());
    let start = second
        .iter()
        .find(|frame| frame["kind"] == "job.start.result")
        .unwrap();
    assert_eq!(start["payload"]["status"], "existing_terminal");
    assert_eq!(start["payload"]["automatic_redispatch"], false);
}

#[test]
fn exact_job_responses_bind_scope_digest_and_operation_identity() {
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("provider.sh");
    let provider_marker = directory.path().join("provider-started");
    let job_store = directory.path().join("jobs.jsonl");
    provider_fixture(&provider, &provider_marker);

    let frames = vec![
        job_start("sleep 5"),
        serde_json::json!({
            "kind": "job.attach",
            "seq": 2,
            "direction": "client_to_host",
            "payload": {
                "session_id": "session-jobs",
                "profile_id": "owner-open",
                "task_id": "task-jobs",
                "turn_id": "turn-jobs",
                "turn_stream_id": "turn-stream-jobs",
                "job_id": "job-pipe",
                "operation_id": "attach-job-pipe",
                "attachment_id": "attachment-job-pipe",
                "inclusive_cursor": 0,
                "limit": 16
            }
        })
        .to_string(),
        serde_json::json!({
            "kind": "job.resize",
            "seq": 3,
            "direction": "client_to_host",
            "payload": {
                "session_id": "session-jobs",
                "profile_id": "owner-open",
                "task_id": "task-jobs",
                "turn_id": "turn-jobs",
                "turn_stream_id": "turn-stream-jobs",
                "job_id": "job-pipe",
                "operation_id": "resize-pipe-job",
                "rows": 40,
                "cols": 120
            }
        })
        .to_string(),
        serde_json::json!({
            "kind": "job.kill",
            "seq": 4,
            "direction": "client_to_host",
            "payload": {
                "session_id": "session-jobs",
                "profile_id": "owner-open",
                "task_id": "task-jobs",
                "turn_id": "turn-jobs",
                "turn_stream_id": "turn-stream-jobs",
                "job_id": "job-pipe",
                "operation_id": "kill-job-pipe",
                "signal": 15
            }
        })
        .to_string(),
    ];
    let output = run_core(&provider, &job_store, &frames);
    let frames = decoded(&output);
    assert!(!provider_marker.exists());

    let start = frames
        .iter()
        .find(|frame| frame["kind"] == "job.start.result")
        .expect("job.start.result");
    assert_eq!(start["payload"]["operation_id"], "start-job-pipe");
    let request_sha256 = start["payload"]["request_sha256"]
        .as_str()
        .expect("canonical job request digest");
    assert_eq!(request_sha256.len(), 64);
    assert!(request_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let attach = frames
        .iter()
        .find(|frame| frame["kind"] == "job.attach.result")
        .expect("job.attach.result");
    assert_eq!(attach["payload"]["operation_id"], "attach-job-pipe");
    assert_eq!(attach["payload"]["attachment_id"], "attachment-job-pipe");

    let error = frames
        .iter()
        .find(|frame| {
            frame["kind"] == "job.error" && frame["payload"]["operation_id"] == "resize-pipe-job"
        })
        .expect("correlated job.error");
    assert_eq!(error["payload"]["request_sha256"], request_sha256);

    let control = frames
        .iter()
        .find(|frame| {
            frame["kind"] == "job.control.result"
                && frame["payload"]["operation_id"] == "kill-job-pipe"
        })
        .expect("correlated job.control.result");
    assert_eq!(control["payload"]["request_sha256"], request_sha256);

    for frame in frames.iter().filter(|frame| {
        frame["kind"]
            .as_str()
            .is_some_and(|kind| kind.starts_with("job."))
    }) {
        assert_eq!(frame["turn_stream_id"], "turn-stream-jobs");
        assert_eq!(frame["session_id"], "session-jobs");
        assert_eq!(frame["profile_id"], "owner-open");
        assert_eq!(frame["task_id"], "task-jobs");
        assert_eq!(frame["turn_id"], "turn-jobs");
        assert_eq!(frame["job_id"], "job-pipe");
        assert_eq!(frame["payload"]["request_sha256"], request_sha256);
    }
}
