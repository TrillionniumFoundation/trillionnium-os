use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use trillionnium_owner_open_job_registry::{JobKey, JobRequest, JobScope};
use trillionnium_owner_open_job_runtime::{
    ControlDisposition, JobInvocation, JobJournal, JobManager, JobRuntimeConfig, JobStartRequest,
    JournalStatus, PtySize, RuntimeJobEventKind, StartDisposition,
};

fn key(id: &str) -> JobKey {
    JobKey::new(
        JobScope::new("session", "owner-open", "task", "turn", "stream"),
        id,
    )
}

fn request(seed: char, mode: &str) -> JobRequest {
    JobRequest::new(
        seed.to_string().repeat(64),
        "b".repeat(64),
        "shell.job",
        mode,
        Some("rootlinux".to_string()),
    )
}

fn start_request(
    key: JobKey,
    request: JobRequest,
    operation_id: &str,
    command: String,
    pty: Option<PtySize>,
) -> JobStartRequest {
    JobStartRequest {
        key,
        request,
        operation_id: operation_id.to_string(),
        invocation: JobInvocation::Command { command },
        shell_executable: PathBuf::from("/bin/sh"),
        cwd: None,
        env: BTreeMap::new(),
        initial_stdin: Vec::new(),
        pty,
    }
}

fn wait_terminal(manager: &JobManager, key: &JobKey) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let inspection = manager.inspect(key, 0, 4096).unwrap();
        let mut output = Vec::new();
        let terminal = inspection
            .runtime_events
            .iter()
            .any(|event| match &event.event {
                RuntimeJobEventKind::Output { bytes, .. } => {
                    output.extend_from_slice(bytes);
                    false
                }
                RuntimeJobEventKind::Terminal { .. } => true,
                _ => false,
            });
        if terminal {
            return output;
        }
        assert!(Instant::now() < deadline, "job did not become terminal");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn pipe_job_supports_write_close_inspect_and_durable_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("jobs.jsonl");
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal)).unwrap();
    let job = key("job-pipe");
    let result = manager
        .start(start_request(
            job.clone(),
            request('a', "pipe"),
            "start-pipe",
            "IFS= read -r line; cat >/dev/null; printf 'got:%s' \"$line\"".to_string(),
            None,
        ))
        .unwrap();
    assert_eq!(result.disposition, StartDisposition::Started);
    assert_eq!(
        manager.write(&job, "write-line", b"hello\n").unwrap(),
        ControlDisposition::Applied
    );
    assert_eq!(
        manager.close_stdin(&job, "close-pipe").unwrap(),
        ControlDisposition::Applied
    );
    let output = wait_terminal(&manager, &job);
    assert_eq!(output, b"got:hello");
    assert!(!manager.durable_records(&job).unwrap().is_empty());
}

#[test]
fn pty_job_supports_resize_and_process_group_kill() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("jobs.jsonl");
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal)).unwrap();
    let job = key("job-pty");
    manager
        .start(start_request(
            job.clone(),
            request('c', "pty"),
            "start-pty",
            "trap 'exit 0' TERM; printf ready; while :; do sleep 1; done".to_string(),
            Some(PtySize { rows: 24, cols: 80 }),
        ))
        .unwrap();
    assert_eq!(
        manager
            .resize(
                &job,
                "resize-pty",
                PtySize {
                    rows: 40,
                    cols: 120
                }
            )
            .unwrap(),
        ControlDisposition::Applied
    );
    assert_eq!(
        manager.kill(&job, "kill-pty", libc::SIGTERM).unwrap(),
        ControlDisposition::Applied
    );
    let output = wait_terminal(&manager, &job);
    assert!(String::from_utf8_lossy(&output).contains("ready"));
}

#[test]
fn completed_durable_job_never_spawns_again_after_manager_restart() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("jobs.jsonl");
    let counter = directory.path().join("counter");
    let job = key("job-restart-complete");
    let request = request('d', "pipe");
    let command = format!("printf x >> '{}'; printf done", counter.display());
    {
        let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal)).unwrap();
        manager
            .start(start_request(
                job.clone(),
                request.clone(),
                "start-once",
                command.clone(),
                None,
            ))
            .unwrap();
        wait_terminal(&manager, &job);
    }
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal)).unwrap();
    let replay = manager
        .start(start_request(job, request, "start-once", command, None))
        .unwrap();
    assert_eq!(replay.disposition, StartDisposition::ExistingTerminal);
    assert_eq!(fs::read(counter).unwrap(), b"x");
}

#[test]
fn accepted_without_terminal_is_unknown_and_not_redispatched() {
    let directory = tempfile::tempdir().unwrap();
    let journal_path = directory.path().join("jobs.jsonl");
    let job = key("job-uncertain");
    let request = request('e', "pipe");
    {
        let journal = JobJournal::open_best_effort(Some(&journal_path));
        journal
            .begin_operation(
                &job,
                &request,
                "start-uncertain",
                "start",
                &"f".repeat(64),
                json!({"fixture": true}),
            )
            .unwrap();
    }
    let marker = directory.path().join("must-not-run");
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal_path)).unwrap();
    let result = manager
        .start(start_request(
            job,
            request,
            "different-delivery-operation",
            format!("touch '{}'", marker.display()),
            None,
        ))
        .unwrap();
    assert_eq!(result.disposition, StartDisposition::UnknownAfterRestart);
    assert!(!marker.exists());
}

#[test]
fn configured_unavailable_journal_is_unknown_and_never_dispatched() {
    let directory = tempfile::tempdir().unwrap();
    let journal_path = directory.path().join("jobs.jsonl");
    let held = JobJournal::open_best_effort(Some(&journal_path));
    assert_eq!(held.status().unwrap(), JournalStatus::Durable);
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal_path)).unwrap();
    assert!(matches!(
        manager.journal().status().unwrap(),
        JournalStatus::Unavailable { .. }
    ));
    let marker = directory.path().join("must-not-run-unavailable");
    let result = manager
        .start(start_request(
            key("job-unavailable"),
            request('f', "pipe"),
            "start-unavailable",
            format!("touch '{}'", marker.display()),
            None,
        ))
        .unwrap();
    assert_eq!(result.disposition, StartDisposition::UnknownAfterRestart);
    assert!(!marker.exists());
}
