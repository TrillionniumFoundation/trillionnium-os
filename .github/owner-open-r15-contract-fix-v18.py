from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"R15 {label} anchor is not exact")
    return text.replace(old, new, 1)


process_path = Path("crates/trillionnium-owner-open-job-runtime/src/process.rs")
process = process_path.read_text()
if process.count("spawn_reaper(guard, workers, sender)?;") != 2:
    raise SystemExit("R15 job reaper call anchors are not exact")
process = process.replace(
    "spawn_reaper(guard, workers, sender)?;",
    "spawn_reaper(guard, workers, sender, identity.clone())?;",
)
process = replace_once(
    process,
    "fn spawn_reaper(\n"
    "    guard: SpawnGuard,\n"
    "    workers: Vec<JoinHandle<()>>,\n"
    "    sender: SyncSender<InternalProcessEvent>,\n"
    ") -> Result<()> {\n"
    "    let pid = guard.pid;\n",
    "fn spawn_reaper(\n"
    "    guard: SpawnGuard,\n"
    "    workers: Vec<JoinHandle<()>>,\n"
    "    sender: SyncSender<InternalProcessEvent>,\n"
    "    identity: ProcessIdentity,\n"
    ") -> Result<()> {\n"
    "    let pid = identity.pid;\n",
    "job reaper identity ownership",
)
process = replace_once(
    process,
    "            if let Err(error) = cleanup_process_group(pid) {\n",
    "            if let Err(error) = cleanup_process_group(&identity) {\n",
    "identity-bound descendant cleanup",
)
helper = r'''
fn verify_cleanup_signal_identity(
    identity: &ProcessIdentity,
) -> std::result::Result<(), String> {
    let Some(observed) = observe_process_identity(identity.pid)? else {
        // The original leader has been reaped. A surviving original process
        // group may still contain descendants, and the numeric group remains
        // reserved while that group exists.
        return Ok(());
    };
    if observed != *identity {
        return Err(format!(
            "refusing descendant cleanup after leader identity changed: expected={identity:?}, observed={observed:?}"
        ));
    }
    Ok(())
}

'''
process = replace_once(
    process,
    "fn observe_process_identity(\n",
    helper + "fn observe_process_identity(\n",
    "cleanup identity verifier",
)
cleanup_start = process.index("fn cleanup_process_group(")
cleanup_end = process.index("\nfn process_group_exists", cleanup_start)
cleanup = process[cleanup_start:cleanup_end]
cleanup = replace_once(
    cleanup,
    "fn cleanup_process_group(pid: u32) -> std::result::Result<(), String> {\n"
    "    if !process_group_exists(pid)? {\n",
    "fn cleanup_process_group(\n"
    "    identity: &ProcessIdentity,\n"
    ") -> std::result::Result<(), String> {\n"
    "    let pid = identity.pid;\n"
    "    if !process_group_exists(pid)? {\n",
    "cleanup signature identity",
)
cleanup = replace_once(
    cleanup,
    "    send_process_group_signal(pid, libc::SIGTERM)?;\n",
    "    verify_cleanup_signal_identity(identity)?;\n"
    "    send_process_group_signal(pid, libc::SIGTERM)?;\n",
    "SIGTERM identity check",
)
cleanup = replace_once(
    cleanup,
    "    send_process_group_signal(pid, libc::SIGKILL)?;\n",
    "    verify_cleanup_signal_identity(identity)?;\n"
    "    send_process_group_signal(pid, libc::SIGKILL)?;\n",
    "SIGKILL identity check",
)
process = process[:cleanup_start] + cleanup + process[cleanup_end:]
process = replace_once(
    process,
    "        assert!(\n"
    "            verify_process_identity(&stale)\n"
    "                .unwrap_err()\n"
    "                .contains(\"identity changed\")\n"
    "        );\n",
    "        assert!(\n"
    "            verify_process_identity(&stale)\n"
    "                .unwrap_err()\n"
    "                .contains(\"identity changed\")\n"
    "        );\n"
    "        assert!(\n"
    "            verify_cleanup_signal_identity(&stale)\n"
    "                .unwrap_err()\n"
    "                .contains(\"leader identity changed\")\n"
    "        );\n",
    "cleanup identity negative test",
)
process_path.write_text(process)

manager_path = Path("crates/trillionnium-owner-open-job-runtime/src/manager.rs")
manager = manager_path.read_text()
manager = replace_once(
    manager,
    "        running_jobs.insert(request.key.clone(), Arc::clone(&running));\n"
    "        drop(running_jobs);\n\n",
    "",
    "premature live-control publication",
)
manager = replace_once(
    manager,
    "        if let Err(error) =\n"
    "            self.push_runtime_event(&request.key, &request.request, identity_bound)\n"
    "        {\n"
    "            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());\n",
    "        if let Err(error) =\n"
    "            self.push_runtime_event(&request.key, &request.request, identity_bound)\n"
    "        {\n"
    "            drop(running_jobs);\n"
    "            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());\n",
    "identity-event rollback lock release",
)
manager = replace_once(
    manager,
    "        if let Err(error) = self.push_runtime_event(&request.key, &request.request, started) {\n"
    "            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());\n",
    "        if let Err(error) = self.push_runtime_event(&request.key, &request.request, started) {\n"
    "            drop(running_jobs);\n"
    "            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());\n",
    "started-event rollback lock release",
)
manager = replace_once(
    manager,
    "        ) {\n"
    "            let _ = self.note_journal_failure(error.to_string());\n"
    "            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());\n"
    "            return Err(error);\n"
    "        }\n"
    "        if let Err(error) = self.spawn_dispatcher(\n",
    "        ) {\n"
    "            let _ = self.note_journal_failure(error.to_string());\n"
    "            drop(running_jobs);\n"
    "            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());\n"
    "            return Err(error);\n"
    "        }\n"
    "        running_jobs.insert(request.key.clone(), Arc::clone(&running));\n"
    "        if let Err(error) = self.spawn_dispatcher(\n",
    "durable-start before live-control publication",
)
manager = replace_once(
    manager,
    "        ) {\n"
    "            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());\n"
    "            return Err(error);\n"
    "        }\n"
    "        Ok(JobStartResult {\n",
    "        ) {\n"
    "            running_jobs.remove(&request.key);\n"
    "            drop(running_jobs);\n"
    "            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());\n"
    "            return Err(error);\n"
    "        }\n"
    "        drop(running_jobs);\n"
    "        Ok(JobStartResult {\n",
    "dispatcher publication rollback",
)
manager_path.write_text(manager)

source_test_path = Path("tools/tests/test_owner_open_r15_runtime_hardening.py")
source_test = source_test_path.read_text()
source_test = replace_once(
    source_test,
    '        self.assertIn("process_session_id", manager)\n',
    '        self.assertIn("process_session_id", manager)\n'
    '        publication = manager[manager.index("let running = Arc::new(RunningJob"):manager.index("Ok(JobStartResult {", manager.index("let running = Arc::new(RunningJob"))]\n'
    '        self.assertLess(publication.index("ProcessIdentityBound"), publication.index("running_jobs.insert"))\n'
    '        self.assertLess(publication.index("process_start_time_ticks"), publication.index("running_jobs.insert"))\n'
    '        self.assertLess(publication.index("complete_operation"), publication.index("running_jobs.insert"))\n'
    '        self.assertIn("verify_cleanup_signal_identity(identity)", process)\n',
    "live-control ordering source assertions",
)
source_test_path.write_text(source_test)

doc_path = Path("docs/protocols/owner-open-jobs-v1.md")
doc = doc_path.read_text()
doc = replace_once(
    doc,
    "runtime emits a `process_identity_bound` observation and records the same\n"
    "PID/PGID/SID/boot/start-time tuple in the durable start result before the\n"
    "dispatcher accepts live controls. Before sending a signal to a numeric\n",
    "runtime emits a `process_identity_bound` observation and records the same\n"
    "PID/PGID/SID/boot/start-time tuple in the durable start result before the\n"
    "job enters the live-control map or its dispatcher can observe traffic.\n"
    "Before sending a signal to a numeric\n",
    "live-control publication protocol truth",
)
doc = replace_once(
    doc,
    "gone, while any reused or changed identity fails closed.\n\n",
    "gone, while any reused or changed identity fails closed. Descendant cleanup\n"
    "repeats the identity check before TERM and KILL so a reallocated leader PID\n"
    "cannot redirect cleanup into an unrelated process group.\n\n",
    "descendant reuse protocol truth",
)
doc_path.write_text(doc)
