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
fn repeated_start_of_a_live_job_returns_existing_live_before_recovery_state() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("jobs.jsonl");
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal)).unwrap();
    let job = key("job-live-idempotent");
    let request = request('a', "pipe");
    let command = "trap 'exit 0' TERM; while :; do sleep 1; done".to_string();
    manager
        .start(start_request(
            job.clone(),
            request.clone(),
            "start-live-idempotent",
            command.clone(),
            None,
        ))
        .unwrap();

    // The durable journal already contains the accepted/start record while
    // this manager still owns a live child.  The live map must win over that
    // recovery record for an idempotent repeat.
    let repeat = manager
        .start(start_request(
            job.clone(),
            request,
            "start-live-idempotent",
            command,
            None,
        ))
        .unwrap();
    assert_eq!(repeat.disposition, StartDisposition::ExistingLive);

    manager
        .kill(&job, "kill-live-idempotent", libc::SIGTERM)
        .unwrap();
    wait_terminal(&manager, &job);
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

#[test]
fn capacity_rejection_happens_before_spawn_or_visible_side_effect() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("jobs.jsonl");
    let config = JobRuntimeConfig {
        max_jobs: 1,
        ..JobRuntimeConfig::default()
    };
    let manager = JobManager::open(config, Some(&journal)).unwrap();
    let live = key("job-capacity-live");
    manager
        .start(start_request(
            live.clone(),
            request('a', "pipe"),
            "start-capacity-live",
            "trap 'exit 0' TERM; while :; do sleep 1; done".to_string(),
            None,
        ))
        .unwrap();

    let marker = directory.path().join("capacity-must-not-run");
    let rejected_key = key("job-capacity-rejected");
    let rejected_request = request('b', "pipe");
    let error = manager
        .start(start_request(
            rejected_key.clone(),
            rejected_request.clone(),
            "start-capacity-rejected",
            format!("touch '{}'", marker.display()),
            None,
        ))
        .unwrap_err();
    assert!(error.to_string().contains("before acceptance"));
    assert!(!marker.exists());
    assert!(manager.registry().snapshot(&rejected_key).is_err());

    manager
        .kill(&live, "kill-capacity-live", libc::SIGTERM)
        .unwrap();
    wait_terminal(&manager, &live);
    assert!(!marker.exists());

    let retry_marker = directory.path().join("capacity-retry-ran");
    let retry = manager
        .start(start_request(
            rejected_key.clone(),
            rejected_request,
            "start-capacity-retry",
            format!("touch '{}'", retry_marker.display()),
            None,
        ))
        .unwrap();
    assert_eq!(retry.disposition, StartDisposition::Started);
    wait_terminal(&manager, &rejected_key);
    assert!(retry_marker.exists());
}

#[test]
fn output_drains_are_live_before_large_initial_stdin_is_written() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("jobs.jsonl");
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal)).unwrap();
    let job = key("job-reader-before-writer");
    let mut start = start_request(
        job.clone(),
        request('c', "pipe"),
        "start-reader-before-writer",
        concat!(
            "dd if=/dev/zero bs=65536 count=16 2>/dev/null; ",
            "IFS= read -r line; printf 'got:%s' \"$line\""
        )
        .to_string(),
        None,
    );
    start.initial_stdin = b"hello\n".to_vec();
    manager.start(start).unwrap();
    let output = wait_terminal(&manager, &job);
    assert!(output.len() >= 1024 * 1024);
    assert!(output.ends_with(b"got:hello"));
}

#[test]
fn retained_observation_prefix_loss_is_reported_as_an_exact_gap() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("jobs.jsonl");
    let config = JobRuntimeConfig {
        max_output_chunk_bytes: 8,
        max_observations_per_job: 4,
        max_observation_bytes_per_job: 32,
        ..JobRuntimeConfig::default()
    };
    let manager = JobManager::open(config, Some(&journal)).unwrap();
    let job = key("job-retention-gap");
    manager
        .start(start_request(
            job.clone(),
            request('d', "pipe"),
            "start-retention-gap",
            "printf 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'".to_string(),
            None,
        ))
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let inspection = loop {
        let inspection = manager.inspect(&job, 0, 4).unwrap();
        if inspection
            .runtime_events
            .iter()
            .any(|event| matches!(event.event, RuntimeJobEventKind::Terminal { .. }))
        {
            break inspection;
        }
        assert!(
            Instant::now() < deadline,
            "retention-gap job did not terminate"
        );
        thread::sleep(Duration::from_millis(10));
    };

    assert!(inspection.resync_required);
    assert!(inspection.oldest_available_cursor > 0);
    assert!(inspection.total_events > inspection.runtime_events.len() as u64);
    let gap = inspection
        .gap
        .expect("retention loss must include an exact gap");
    assert_eq!(gap.first_missing_cursor, 0);
    assert_eq!(
        gap.last_missing_cursor,
        inspection.oldest_available_cursor - 1
    );
    assert!(inspection.durable_fallback_available);
}

#[test]
fn leader_exit_does_not_leave_a_background_process_group_member() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("jobs.jsonl");
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal)).unwrap();
    let job = key("job-descendant-cleanup");
    manager
        .start(start_request(
            job.clone(),
            request('e', "pipe"),
            "start-descendant-cleanup",
            "sleep 30 & printf '%s' \"$!\"; exit 0".to_string(),
            None,
        ))
        .unwrap();
    let output = wait_terminal(&manager, &job);
    let child_pid = String::from_utf8(output)
        .unwrap()
        .parse::<i32>()
        .expect("job must report its background child pid");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let exists = unsafe { libc::kill(child_pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        if !exists {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "background process remains after terminal observation"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
