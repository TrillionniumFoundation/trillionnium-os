#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one {label}, found {count}")
    return text.replace(old, new)


def main() -> None:
    manager_path = Path("crates/trillionnium-owner-open-job-runtime/src/manager.rs")
    manager = manager_path.read_text(encoding="utf-8")
    old_terminal = """                            match manager.push_runtime_event(&key, &request, event.clone()) {
                                Ok(seq) => {
                                    if let Err(error) = manager.inner.journal.record_job_terminal(
                                        &key,
                                        &request,
                                        seq,
                                        serde_json::to_value(event).unwrap_or(Value::Null),
                                    ) {
                                        let _ = manager.note_journal_failure(error.to_string());
                                    }
                                }
                                Err(error) => {
                                    let _ = manager.note_journal_failure(error.to_string());
                                }
                            }
"""
    new_terminal = """                            // `push_runtime_event` appends the terminal observation and
                            // the canonical `job.terminal` record under one journal lock before
                            // exposing the in-memory terminal event. Do not write the same terminal
                            // again after publication: that redundant call keeps the exclusive
                            // writer lease alive after a consumer can observe completion and makes
                            // an immediate in-process manager handoff spuriously fail closed.
                            if let Err(error) =
                                manager.push_runtime_event(&key, &request, event)
                            {
                                let _ = manager.note_journal_failure(error.to_string());
                            }
"""
    manager_path.write_text(
        replace_once(manager, old_terminal, new_terminal, "terminal double-write block"),
        encoding="utf-8",
    )

    test_path = Path("crates/trillionnium-owner-open-job-runtime/tests/runtime.rs")
    test = test_path.read_text(encoding="utf-8")
    wait_terminal = """fn wait_terminal(manager: &JobManager, key: &JobKey) -> Vec<u8> {
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
"""
    lease_helper = wait_terminal + """
fn reopen_after_dispatcher_shutdown(journal: &std::path::Path) -> JobManager {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let manager = JobManager::open(JobRuntimeConfig::default(), Some(journal)).unwrap();
        if matches!(manager.journal().status().unwrap(), JournalStatus::Durable) {
            return manager;
        }
        // A terminal observation is durable before it becomes visible, but the old
        // dispatcher may still be releasing the same-process exclusive writer lease.
        // Retry only the lease handoff; once reopened, the assertion below still proves
        // that the terminal record exists and no second process is dispatched.
        drop(manager);
        assert!(
            Instant::now() < deadline,
            "old job dispatcher did not release the durable journal writer lease"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
"""
    test = replace_once(test, wait_terminal, lease_helper, "wait_terminal helper")
    old_reopen = """    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal)).unwrap();
    let replay = manager
        .start(start_request(job, request, "start-once", command, None))
        .unwrap();
"""
    new_reopen = """    let manager = reopen_after_dispatcher_shutdown(&journal);
    let replay = manager
        .start(start_request(job, request, "start-once", command, None))
        .unwrap();
"""
    test_path.write_text(
        replace_once(test, old_reopen, new_reopen, "immediate durable-manager reopen block"),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
