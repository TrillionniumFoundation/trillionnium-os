use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

mod support;

use support::secure_tempdir;

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
    job_start_for("job-pipe", "start-job-pipe", command)
}

fn job_start_for(job_id: &str, operation_id: &str, command: &str) -> String {
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
            "job_id": job_id,
            "operation_id": operation_id,
            "tool": "shell.job",
            "target_id": "rootlinux",
            "mode": "pipe",
            "command": command
        }
    })
    .to_string()
}

fn turn_start() -> String {
    turn_start_for("turn-jobs", 0)
}

fn turn_start_for(turn_id: &str, seq: u64) -> String {
    serde_json::json!({
        "kind": "turn.start",
        "seq": seq,
        "direction": "client_to_host",
        "payload": {
            "protocol": "trillionnium.agent.turn.v1",
            "protocol_version": 1,
            "session_id": "session-jobs",
            "task_id": "task-jobs",
            "turn_id": turn_id,
            "user_input": "start a direct turn before the local job"
        }
    })
    .to_string()
}

fn job_wait(inclusive_cursor: u64, operation_id: &str, timeout_ms: u64) -> String {
    serde_json::json!({
        "kind": "job.wait",
        "seq": 2,
        "direction": "client_to_host",
        "payload": {
            "session_id": "session-jobs",
            "profile_id": "owner-open",
            "task_id": "task-jobs",
            "turn_id": "turn-jobs",
            "turn_stream_id": "turn-stream-jobs",
            "job_id": "job-pipe",
            "operation_id": operation_id,
            "inclusive_cursor": inclusive_cursor,
            "durable_inclusive_cursor": 0,
            "limit": 32,
            "timeout_ms": timeout_ms,
            "poll_interval_ms": 5
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

fn run_core_without_hello(provider: &Path, job_store: &Path, frames: &[String]) -> Output {
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
    let directory = secure_tempdir();
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
    // `hello` and the job requests are intentionally pipelined. The core's
    // hello acknowledgement is the first host response; local job handling
    // is released only after that barrier, so no job frame can leapfrog the
    // connection handshake.
    assert_eq!(
        frames.first().and_then(|frame| frame["kind"].as_str()),
        Some("hello.ack")
    );
    let ack_index = frames
        .iter()
        .position(|frame| frame["kind"] == "hello.ack")
        .expect("hello.ack");
    let job_result_index = frames
        .iter()
        .position(|frame| frame["kind"] == "job.start.result")
        .expect("job.start.result");
    assert!(ack_index < job_result_index);
    assert!(frames.iter().any(|frame| {
        frame["kind"] == "hello.ack" && frame["payload"]["long_running_jobs"] == true
    }));
    assert!(
        frames
            .iter()
            .any(|frame| frame["kind"] == "job.start.result")
    );
    let identity_index = frames
        .iter()
        .position(|frame| frame["kind"] == "job.process_identity_bound")
        .expect("job.process_identity_bound");
    let started_index = frames
        .iter()
        .position(|frame| frame["kind"] == "job.started")
        .expect("job.started");
    assert!(identity_index < started_index);
    let identity = &frames[identity_index]["payload"]["identity"];
    assert!(identity["pid"].is_u64());
    assert!(identity["process_group_id"].is_i64());
    assert!(identity["session_id"].is_i64());
    assert_eq!(identity["boot_id"].as_str().map(str::len), Some(64));
    assert!(identity["start_time_ticks"].is_u64());
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
fn direct_turn_start_and_pipelined_job_wait_for_turn_accepted() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let provider_marker = directory.path().join("provider-started");
    let job_store = directory.path().join("jobs.jsonl");
    provider_fixture(&provider, &provider_marker);

    // No hello preface is used here intentionally: this exercises the
    // independent turn.start -> turn.accepted gate in the job-aware carrier.
    let frames = decoded(&run_core_without_hello(
        &provider,
        &job_store,
        &[turn_start(), job_start("printf direct-job")],
    ));
    let accepted_index = frames
        .iter()
        .position(|frame| frame["kind"] == "turn.accepted")
        .expect("turn.accepted");
    let job_result_index = frames
        .iter()
        .position(|frame| frame["kind"] == "job.start.result")
        .expect("job.start.result");
    assert!(accepted_index < job_result_index);
}

#[test]
fn hello_turn_start_and_job_pipeline_waits_for_both_acknowledgements() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let provider_marker = directory.path().join("provider-started");
    let job_store = directory.path().join("jobs.jsonl");
    provider_fixture(&provider, &provider_marker);

    let frames = decoded(&run_core(
        &provider,
        &job_store,
        &[turn_start(), job_start("printf hello-turn-job")],
    ));
    let ack_index = frames
        .iter()
        .position(|frame| frame["kind"] == "hello.ack")
        .expect("hello.ack");
    let accepted_index = frames
        .iter()
        .position(|frame| frame["kind"] == "turn.accepted")
        .expect("turn.accepted");
    let job_result_index = frames
        .iter()
        .position(|frame| frame["kind"] == "job.start.result")
        .expect("job.start.result");
    assert!(ack_index < accepted_index);
    assert!(accepted_index < job_result_index);
}

#[test]
fn deferred_protocol_errors_preserve_fifo_position_among_jobs() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let provider_marker = directory.path().join("provider-started");
    let job_store = directory.path().join("jobs.jsonl");
    provider_fixture(&provider, &provider_marker);

    let duplicate_hello = serde_json::json!({
        "kind": "hello",
        "seq": 2,
        "direction": "client_to_host",
        "payload": {
            "protocol": "trillionnium.agent.turn.v1",
            "protocol_version": 1
        }
    })
    .to_string();
    let frames = decoded(&run_core(
        &provider,
        &job_store,
        &[
            turn_start(),
            job_start_for("job-one", "start-job-one", "printf one"),
            duplicate_hello,
            job_start_for("job-two", "start-job-two", "printf two"),
        ],
    ));
    let first_job_index = frames
        .iter()
        .position(|frame| {
            frame["kind"] == "job.start.result"
                && frame["payload"]["operation_id"] == "start-job-one"
        })
        .expect("first job response");
    let duplicate_index = frames
        .iter()
        .position(|frame| {
            frame["kind"] == "host.error" && frame["payload"]["code"] == "duplicate_hello"
        })
        .expect("duplicate hello response");
    let second_job_index = frames
        .iter()
        .position(|frame| {
            frame["kind"] == "job.start.result"
                && frame["payload"]["operation_id"] == "start-job-two"
        })
        .expect("second job response");
    assert!(first_job_index < duplicate_index);
    assert!(duplicate_index < second_job_index);
}

#[test]
fn pipelined_second_turn_start_is_rejected_before_following_job() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let job_store = directory.path().join("jobs.jsonl");
    fs::write(&provider, "#!/bin/sh\nsleep 0.2\nexit 99\n").unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let frames = decoded(&run_core_without_hello(
        &provider,
        &job_store,
        &[
            turn_start_for("turn-jobs", 0),
            job_start_for("job-one", "start-job-one", "printf one"),
            turn_start_for("turn-two", 2),
            job_start_for("job-two", "start-job-two", "printf two"),
        ],
    ));
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame["kind"] == "turn.accepted")
            .count(),
        1,
        "the second turn.start must not reach the one-turn core"
    );
    let duplicate_index = frames
        .iter()
        .position(|frame| {
            frame["kind"] == "host.error" && frame["payload"]["code"] == "duplicate_turn_start"
        })
        .expect("duplicate turn.start rejection");
    let second_job_index = frames
        .iter()
        .position(|frame| {
            frame["kind"] == "job.start.result"
                && frame["payload"]["operation_id"] == "start-job-two"
        })
        .expect("second job response");
    assert!(duplicate_index < second_job_index);
}

#[test]
fn duplicate_hello_uses_the_shared_connection_control_sequence() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let provider_marker = directory.path().join("provider-started");
    let job_store = directory.path().join("jobs.jsonl");
    provider_fixture(&provider, &provider_marker);

    let duplicate = serde_json::json!({
        "kind": "hello",
        "seq": 1,
        "direction": "client_to_host",
        "payload": {
            "protocol": "trillionnium.agent.turn.v1",
            "protocol_version": 1
        }
    })
    .to_string();
    let frames = decoded(&run_core(&provider, &job_store, &[duplicate]));
    let ack = frames
        .iter()
        .find(|frame| frame["kind"] == "hello.ack")
        .expect("hello.ack");
    let error = frames
        .iter()
        .find(|frame| {
            frame["kind"] == "host.error" && frame["payload"]["code"] == "duplicate_hello"
        })
        .expect("duplicate hello host.error");
    assert_eq!(ack["seq"], 0);
    assert_eq!(error["seq"], 1);
    assert_eq!(ack["host_seq"], Value::Null);
    assert_eq!(error["host_seq"], Value::Null);
    assert_eq!(ack["connection_id"], error["connection_id"]);
    let expected_event_id = format!("{}-event-1", ack["connection_id"].as_str().unwrap());
    assert_eq!(error["event_id"].as_str(), Some(expected_event_id.as_str()));
}

#[test]
fn completed_job_is_not_redispatched_after_a_new_core_process() {
    let directory = secure_tempdir();
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
    let directory = secure_tempdir();
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

#[test]
fn wait_returns_terminal_observation_for_an_already_finished_job() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let provider_marker = directory.path().join("provider-started");
    let job_store = directory.path().join("jobs.jsonl");
    provider_fixture(&provider, &provider_marker);

    let frames = decoded(&run_core(
        &provider,
        &job_store,
        &[job_start("printf done"), job_wait(0, "wait-terminal", 1000)],
    ));
    let wait = frames
        .iter()
        .find(|frame| {
            frame["kind"] == "job.inspect.result"
                && frame["payload"]["operation_id"] == "wait-terminal"
        })
        .expect("job.wait result");
    assert_eq!(wait["payload"]["wait_status"], "terminal_observed");
    assert_eq!(wait["payload"]["read_only"], true);
    assert_eq!(wait["payload"]["side_effects"], false);
    assert_eq!(wait["payload"]["automatic_redispatch"], false);
}

#[test]
fn wait_rejects_a_future_runtime_cursor_as_job_error() {
    let directory = secure_tempdir();
    let provider = directory.path().join("provider.sh");
    let provider_marker = directory.path().join("provider-started");
    let job_store = directory.path().join("jobs.jsonl");
    provider_fixture(&provider, &provider_marker);

    let frames = decoded(&run_core(
        &provider,
        &job_store,
        &[job_start("true"), job_wait(u64::MAX, "wait-future", 1000)],
    ));
    let error = frames
        .iter()
        .find(|frame| {
            frame["kind"] == "job.error" && frame["payload"]["operation_id"] == "wait-future"
        })
        .expect("future cursor job.error");
    assert_eq!(error["payload"]["code"], "job_wait_invalid_request");
    assert!(
        error["payload"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("inclusive cursor"))
    );
}
