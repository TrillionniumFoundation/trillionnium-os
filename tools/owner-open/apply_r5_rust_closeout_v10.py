#!/usr/bin/env python3
"""Apply the exact v10 Rust test-closure repairs.

The v9 applicator owns every previously reviewed production and fixture repair.
This wrapper makes the pipe close test actually wait for EOF before completing,
narrows dead-code allowance to the four integration-test-local copies of the
persistence implementation, fails closed when an explicitly configured journal
is temporarily unavailable, and keeps the complete default Rust graph
Clippy-clean. Deliberate memory-only operation remains unchanged. This is
exact-preimage and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v9.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v9", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v9 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

REPAIR = BASE.BASE.REPAIR


def repair_pipe_close_fixture() -> None:
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-job-runtime/tests/runtime.rs",
        "            \"IFS= read -r line; printf 'got:%s' \\\"$line\\\"\".to_string(),\n",
        "            \"IFS= read -r line; cat >/dev/null; printf 'got:%s' \\\"$line\\\"\".to_string(),\n",
    )


def fail_closed_configured_unavailable_journal() -> None:
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-job-runtime/src/manager.rs",
        "        if begin.disposition == BeginDisposition::Existing {\n"
        "            return Ok(JobStartResult {\n"
        "                disposition: match &begin.snapshot.state {\n"
        "                    JobEffectiveState::Terminal { .. } => StartDisposition::ExistingTerminal,\n"
        "                    JobEffectiveState::UnknownAfterRestart { .. }\n"
        "                    | JobEffectiveState::ProvenNotStartedAfterRestart => {\n"
        "                        StartDisposition::UnknownAfterRestart\n"
        "                    }\n"
        "                    _ => StartDisposition::ExistingLive,\n"
        "                },\n"
        "                snapshot: Some(begin.snapshot),\n"
        "                replay_status: self.replay_status(false)?,\n"
        "            });\n"
        "        }\n\n"
        "        let operation_sha256 = start_operation_sha256(&request)?;\n",
        "        if begin.disposition == BeginDisposition::Existing {\n"
        "            return Ok(JobStartResult {\n"
        "                disposition: match &begin.snapshot.state {\n"
        "                    JobEffectiveState::Terminal { .. } => StartDisposition::ExistingTerminal,\n"
        "                    JobEffectiveState::UnknownAfterRestart { .. }\n"
        "                    | JobEffectiveState::ProvenNotStartedAfterRestart => {\n"
        "                        StartDisposition::UnknownAfterRestart\n"
        "                    }\n"
        "                    _ => StartDisposition::ExistingLive,\n"
        "                },\n"
        "                snapshot: Some(begin.snapshot),\n"
        "                replay_status: self.replay_status(false)?,\n"
        "            });\n"
        "        }\n"
        "        if matches!(\n"
        "            self.inner.journal.status()?,\n"
        "            JournalStatus::Unavailable { .. }\n"
        "        ) {\n"
        "            let snapshot = self\n"
        "                .inner\n"
        "                .registry\n"
        "                .mark_restart_uncertain(&request.key)\n"
        "                .map_err(registry_error)?;\n"
        "            return Ok(JobStartResult {\n"
        "                disposition: StartDisposition::UnknownAfterRestart,\n"
        "                snapshot: Some(snapshot),\n"
        "                replay_status: ReplayStatus::UnknownAfterRestart,\n"
        "            });\n"
        "        }\n\n"
        "        let operation_sha256 = start_operation_sha256(&request)?;\n",
    )
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-job-runtime/tests/runtime.rs",
        "use trillionnium_owner_open_job_runtime::{\n"
        "    ControlDisposition, JobInvocation, JobJournal, JobManager, JobRuntimeConfig, JobStartRequest,\n"
        "    PtySize, RuntimeJobEventKind, StartDisposition,\n"
        "};\n",
        "use trillionnium_owner_open_job_runtime::{\n"
        "    ControlDisposition, JobInvocation, JobJournal, JobManager, JobRuntimeConfig, JobStartRequest,\n"
        "    JournalStatus, PtySize, RuntimeJobEventKind, StartDisposition,\n"
        "};\n",
    )
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-job-runtime/tests/runtime.rs",
        "    assert_eq!(result.disposition, StartDisposition::UnknownAfterRestart);\n"
        "    assert!(!marker.exists());\n"
        "}\n",
        "    assert_eq!(result.disposition, StartDisposition::UnknownAfterRestart);\n"
        "    assert!(!marker.exists());\n"
        "}\n\n"
        "#[test]\n"
        "fn configured_unavailable_journal_is_unknown_and_never_dispatched() {\n"
        "    let directory = tempfile::tempdir().unwrap();\n"
        "    let journal_path = directory.path().join(\"jobs.jsonl\");\n"
        "    let held = JobJournal::open_best_effort(Some(&journal_path));\n"
        "    assert_eq!(held.status().unwrap(), JournalStatus::Durable);\n"
        "    let manager = JobManager::open(JobRuntimeConfig::default(), Some(&journal_path)).unwrap();\n"
        "    assert!(matches!(\n"
        "        manager.journal().status().unwrap(),\n"
        "        JournalStatus::Unavailable { .. }\n"
        "    ));\n"
        "    let marker = directory.path().join(\"must-not-run-unavailable\");\n"
        "    let result = manager\n"
        "        .start(start_request(\n"
        "            key(\"job-unavailable\"),\n"
        "            request('f', \"pipe\"),\n"
        "            \"start-unavailable\",\n"
        "            format!(\"touch '{}'\", marker.display()),\n"
        "            None,\n"
        "        ))\n"
        "        .unwrap();\n"
        "    assert_eq!(result.disposition, StartDisposition::UnknownAfterRestart);\n"
        "    assert!(!marker.exists());\n"
        "}\n",
    )


def repair_stream_window_clippy() -> None:
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-stream-window/src/lib.rs",
        "        if let Self::WindowUpdate { credit_bytes } = self {\n"
        "            if *credit_bytes == 0 || *credit_bytes > config.max_credit_bytes {\n"
        "                return Err(StreamWindowError::InvalidRequest(\n"
        "                    \"window update must be non-zero and no larger than max credit\".to_string(),\n"
        "                ));\n"
        "            }\n"
        "        }\n",
        "        if let Self::WindowUpdate { credit_bytes } = self\n"
        "            && (*credit_bytes == 0 || *credit_bytes > config.max_credit_bytes)\n"
        "        {\n"
        "            return Err(StreamWindowError::InvalidRequest(\n"
        "                \"window update must be non-zero and no larger than max credit\".to_string(),\n"
        "            ));\n"
        "        }\n",
    )


def repair_runtime_and_job_registry_clippy() -> None:
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-runtime/tests/process_group.rs",
        "    let mut limits = MechanicalLimits::default();\n"
        "    limits.terminate_grace = Duration::from_millis(30);\n",
        "    let limits = MechanicalLimits {\n"
        "        terminate_grace: Duration::from_millis(30),\n"
        "        ..MechanicalLimits::default()\n"
        "    };\n",
    )
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-runtime/tests/runtime.rs",
        "fn timeout_terminates_the_process_group_and_emits_one_terminal_event() {\n"
        "    let mut limits = MechanicalLimits::default();\n"
        "    limits.terminate_grace = Duration::from_millis(20);\n"
        "    let mut request = ShellExecRequest::command(\"call-timeout\", \"sleep 30\");\n",
        "fn timeout_terminates_the_process_group_and_emits_one_terminal_event() {\n"
        "    let limits = MechanicalLimits {\n"
        "        terminate_grace: Duration::from_millis(20),\n"
        "        ..MechanicalLimits::default()\n"
        "    };\n"
        "    let mut request = ShellExecRequest::command(\"call-timeout\", \"sleep 30\");\n",
    )
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-runtime/tests/runtime.rs",
        "fn cancellation_terminates_the_process_group_without_redispatch() {\n"
        "    let mut limits = MechanicalLimits::default();\n"
        "    limits.terminate_grace = Duration::from_millis(20);\n"
        "    let cancellation = CancellationToken::new();\n",
        "fn cancellation_terminates_the_process_group_without_redispatch() {\n"
        "    let limits = MechanicalLimits {\n"
        "        terminate_grace: Duration::from_millis(20),\n"
        "        ..MechanicalLimits::default()\n"
        "    };\n"
        "    let cancellation = CancellationToken::new();\n",
    )
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-runtime/tests/runtime.rs",
        "fn output_exhaustion_is_mechanical_and_returns_truncated_observation() {\n"
        "    let mut limits = MechanicalLimits::default();\n"
        "    limits.max_output_bytes = 32;\n"
        "    limits.stream_chunk_bytes = 8;\n"
        "    limits.terminate_grace = Duration::from_millis(20);\n"
        "    let mut events = Vec::new();\n",
        "fn output_exhaustion_is_mechanical_and_returns_truncated_observation() {\n"
        "    let limits = MechanicalLimits {\n"
        "        max_output_bytes: 32,\n"
        "        stream_chunk_bytes: 8,\n"
        "        terminate_grace: Duration::from_millis(20),\n"
        "        ..MechanicalLimits::default()\n"
        "    };\n"
        "    let mut events = Vec::new();\n",
    )
    REPAIR.replace_exact(
        "crates/trillionnium-owner-open-job-registry/src/registry.rs",
        "    #[must_use]\n"
        "    pub fn len(&self) -> Result<usize> {\n"
        "        Ok(self.lock()?.entries.len())\n"
        "    }\n\n"
        "    #[must_use]\n"
        "    pub fn is_empty(&self) -> Result<bool> {\n"
        "        Ok(self.len()? == 0)\n"
        "    }\n",
        "    pub fn len(&self) -> Result<usize> {\n"
        "        Ok(self.lock()?.entries.len())\n"
        "    }\n\n"
        "    pub fn is_empty(&self) -> Result<bool> {\n"
        "        Ok(self.len()? == 0)\n"
        "    }\n",
    )


def narrow_test_local_persistence_allowance() -> None:
    for path in (
        "apps/trillionnium-owner-open-host/tests/r5_incomplete_recovery.rs",
        "apps/trillionnium-owner-open-host/tests/r5_inspect.rs",
        "apps/trillionnium-owner-open-host/tests/r5_persistence.rs",
        "apps/trillionnium-owner-open-host/tests/r5_wire_inspect.rs",
    ):
        REPAIR.replace_exact(
            path,
            '#[path = "../src/r5_persistence.rs"]\nmod r5_persistence;\n',
            '#[allow(dead_code)]\n#[path = "../src/r5_persistence.rs"]\nmod r5_persistence;\n',
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v10 Rust closeout replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    if BASE.main() != 0:
        raise RuntimeError("v9 R5 Rust closeout applicator failed")
    repair_pipe_close_fixture()
    fail_closed_configured_unavailable_journal()
    repair_stream_window_clippy()
    repair_runtime_and_job_registry_clippy()
    narrow_test_local_persistence_allowance()
    print("PASS_R5_RUST_CLOSEOUT_V10_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
