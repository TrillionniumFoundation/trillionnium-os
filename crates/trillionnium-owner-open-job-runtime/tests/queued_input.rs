use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use serde_json::json;
use trillionnium_owner_open_event_store::{EventInput, SegmentedEventStore, TurnScope};
use trillionnium_owner_open_job_registry::{
    JobKey, JobMemoryLease, JobRequest, JobScope, MAX_JOB_OWNED_BYTES,
};
use trillionnium_owner_open_job_runtime::{
    JobInvocation, JobManager, JobRuntimeConfig, JobRuntimeError, JobStartRequest, JournalStatus,
    StartDisposition,
};

fn owned_start(key: JobKey, request: JobRequest) -> JobStartRequest {
    let mut command = String::with_capacity(512 * 1024);
    command.push(':');
    JobStartRequest {
        key,
        request,
        operation_id: "start".to_string(),
        invocation: JobInvocation::Command { command },
        shell_executable: PathBuf::from("/bin/sh"),
        cwd: None,
        env: BTreeMap::new(),
        initial_stdin: Vec::new(),
        pty: None,
    }
}

// Discover the remaining real resident capacity without hardcoding the private
// resident/working split or racing another test's transient reservations.
fn fill_remaining_resident() -> (JobMemoryLease, usize) {
    let mut lease = JobMemoryLease::acquire(0).unwrap();
    let (mut low, mut high) = (0, MAX_JOB_OWNED_BYTES + 1);
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if lease.resize(middle).is_ok() {
            low = middle;
        } else {
            high = middle;
        }
    }
    lease.resize(low).unwrap();
    (lease, low)
}

#[test]
fn free_start_shard_admits_owned_input_before_waiting_for_terminal_recovery() {
    const CHILD: &str = "TRILLIONNIUM_JOB_FREE_START_INPUT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "free_start_shard_admits_owned_input_before_waiting_for_terminal_recovery",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated real-pool fixture failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal_path = directory.path().join("jobs.jsonl");
    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal_path)).unwrap();
    let key = JobKey::new(
        JobScope::new("session", "owner-open", "task", "turn", "stream"),
        "existing-terminal",
    );
    let request = JobRequest::new(
        "a".repeat(64),
        "b".repeat(64),
        "shell.job",
        "pipe",
        Some("rootlinux".to_string()),
    );
    manager
        .journal()
        .record_job_terminal(&key, &request, 0, json!({"terminal": true}))
        .unwrap();
    let original_identity = manager.journal().recovered_job(&key).unwrap().unwrap();
    let original_wal = fs::read(&journal_path).unwrap();

    // A different store owns the process-shared codec lane. No start has run
    // on this manager, so its start shard is free; only terminal recovery
    // would cause this owned request to wait without all-path input admission.
    let blocker =
        Arc::new(SegmentedEventStore::open_default(directory.path().join("blocker")).unwrap());
    blocker
        .append(EventInput {
            scope: TurnScope::new("s", "p", "t", "u", "v"),
            event_id: "record".to_string(),
            kind: "test".to_string(),
            payload: json!({}),
        })
        .unwrap();
    let (entered_sender, entered_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let lane_owner = Arc::clone(&blocker);
    let held_lane = std::thread::spawn(move || {
        lane_owner
            .visit_records(|_| {
                entered_sender.send(()).unwrap();
                release_receiver
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
                Ok::<(), ()>(())
            })
            .unwrap()
            .unwrap();
    });
    entered_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let (mut pressure, available) = fill_remaining_resident();
    assert!(JobMemoryLease::acquire(1).is_err());

    let (ready_sender, ready_receiver) = mpsc::channel();
    let (result_sender, result_receiver) = mpsc::channel();
    let clone = manager.clone();
    let input = owned_start(key.clone(), request.clone());
    let worker = std::thread::spawn(move || {
        ready_sender.send(()).unwrap();
        result_sender.send(clone.start(input)).unwrap();
    });
    ready_receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    let before_release = result_receiver.recv_timeout(Duration::from_secs(2));
    // Always release and join before asserting. Regressing to an uncharged
    // EventStore wait must fail this fixture without stranding either thread.
    release_sender.send(()).unwrap();
    held_lane.join().unwrap();
    worker.join().unwrap();
    assert!(
        matches!(&before_release, Ok(Err(JobRuntimeError::Registry(error))) if error.contains("capacity")),
        "owned start reached a blocked terminal read without memory admission: {before_release:?}"
    );
    assert_eq!(fs::read(&journal_path).unwrap(), original_wal);
    assert_eq!(
        manager.journal().recovered_job(&key).unwrap().unwrap(),
        original_identity
    );
    assert!(manager.registry().is_empty().unwrap());
    assert!(!manager.has_live_or_pending_jobs());

    // Admit the same legal owned heap, then exercise an error after admission.
    // Restoring the exact former pressure proves the input lease was returned
    // rather than leaking after recovery reports a canonical request conflict.
    assert!(available > 1024 * 1024);
    pressure.resize(available - 1024 * 1024).unwrap();
    let mut conflicting = request.clone();
    conflicting.request_sha256 = "c".repeat(64);
    assert!(matches!(
        manager.start(owned_start(key.clone(), conflicting)),
        Err(JobRuntimeError::JobConflict)
    ));
    pressure
        .resize(available)
        .expect("owned input capacity must return after an admitted error");

    // A capacity refusal does not poison or replace the durable identity.
    // With headroom restored, the canonical request remains idempotent.
    pressure.resize(available - 1024 * 1024).unwrap();
    let duplicate = manager.start(owned_start(key.clone(), request)).unwrap();
    assert_eq!(duplicate.disposition, StartDisposition::ExistingTerminal);
    pressure
        .resize(available)
        .expect("owned input capacity must return after an idempotent result");
    assert_eq!(fs::read(&journal_path).unwrap(), original_wal);
    assert_eq!(
        manager.journal().recovered_job(&key).unwrap().unwrap(),
        original_identity
    );
    assert!(matches!(
        manager.journal().status().unwrap(),
        JournalStatus::Durable
    ));
    assert!(manager.registry().is_empty().unwrap());
    assert!(!manager.has_live_or_pending_jobs());
}
