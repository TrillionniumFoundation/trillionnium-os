#!/usr/bin/env python3
"""Apply the exact v13 job-runtime complete-graph Clippy repairs.

The v12 applicator owns all previously reviewed runtime, persistence, broker,
EOF, types, event-store and provider closure. This wrapper closes the five
remaining job-runtime structural warnings using let-chains, a named replay
state type and direct single-pattern control flow. Journal error precedence,
replay semantics, dispatch behavior and protocol bytes remain unchanged. This
is exact-preimage and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v12.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v12", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v12 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

REPAIR = BASE.REPAIR


def repair_job_journal_clippy() -> None:
    path = "crates/trillionnium-owner-open-job-runtime/src/journal.rs"
    REPAIR.replace_exact(
        path,
        "#[derive(Debug, Clone)]\n"
        "struct JobState {\n"
        "    request: JobRequest,\n"
        "    start_result: Option<Value>,\n"
        "    terminal: Option<Value>,\n"
        "}\n\n"
        "#[derive(Debug)]\n",
        "#[derive(Debug, Clone)]\n"
        "struct JobState {\n"
        "    request: JobRequest,\n"
        "    start_result: Option<Value>,\n"
        "    terminal: Option<Value>,\n"
        "}\n\n"
        "type OperationStates = HashMap<OperationKey, OperationState>;\n"
        "type JobStates = HashMap<JobKey, JobState>;\n"
        "type RecoveredState = (OperationStates, JobStates);\n\n"
        "#[derive(Debug)]\n",
    )
    REPAIR.replace_exact(
        path,
        "        if operation_kind == \"start\" {\n"
        "            if let Some(existing) = state.jobs.get(key) {\n"
        "                if existing.request != *request {\n"
        "                    return Err(JobRuntimeError::JobConflict);\n"
        "                }\n"
        "                return Ok(OperationBegin::ExistingAccepted {\n"
        "                    restart_uncertain: existing.start_result.is_some(),\n"
        "                });\n"
        "            }\n"
        "        }\n",
        "        if operation_kind == \"start\"\n"
        "            && let Some(existing) = state.jobs.get(key)\n"
        "        {\n"
        "            if existing.request != *request {\n"
        "                return Err(JobRuntimeError::JobConflict);\n"
        "            }\n"
        "            return Ok(OperationBegin::ExistingAccepted {\n"
        "                restart_uncertain: existing.start_result.is_some(),\n"
        "            });\n"
        "        }\n",
    )
    REPAIR.replace_exact(
        path,
        "        if operation_kind == \"start\" {\n"
        "            if let Some(job) = state.jobs.get_mut(key) {\n"
        "                job.start_result = Some(result);\n"
        "            }\n"
        "        }\n",
        "        if operation_kind == \"start\"\n"
        "            && let Some(job) = state.jobs.get_mut(key)\n"
        "        {\n"
        "            job.start_result = Some(result);\n"
        "        }\n",
    )
    REPAIR.replace_exact(
        path,
        "fn recover(\n"
        "    store: &DurableEventStore,\n"
        ") -> std::result::Result<\n"
        "    (\n"
        "        HashMap<OperationKey, OperationState>,\n"
        "        HashMap<JobKey, JobState>,\n"
        "    ),\n"
        "    String,\n"
        "> {\n",
        "fn recover(store: &DurableEventStore) -> std::result::Result<RecoveredState, String> {\n",
    )


def repair_job_manager_clippy() -> None:
    path = "crates/trillionnium-owner-open-job-runtime/src/manager.rs"
    REPAIR.replace_exact(
        path,
        "        match self.begin_control(\n"
        "            key,\n"
        "            &running.request,\n"
        "            operation_id,\n"
        "            \"write\",\n"
        "            &digest,\n"
        "            json!({\n"
        "                \"byte_count\": bytes.len(),\n"
        "                \"sha256\": sha256_hex(bytes)\n"
        "            }),\n"
        "        )? {\n"
        "            Some(disposition) => return Ok(disposition),\n"
        "            None => {}\n"
        "        }\n",
        "        if let Some(disposition) = self.begin_control(\n"
        "            key,\n"
        "            &running.request,\n"
        "            operation_id,\n"
        "            \"write\",\n"
        "            &digest,\n"
        "            json!({\n"
        "                \"byte_count\": bytes.len(),\n"
        "                \"sha256\": sha256_hex(bytes)\n"
        "            }),\n"
        "        )? {\n"
        "            return Ok(disposition);\n"
        "        }\n",
    )
    REPAIR.replace_exact(
        path,
        "        if let Err(error) = journal_result {\n"
        "            if !self.inner.config.allow_unjournaled_effects {\n"
        "                return Err(error);\n"
        "            }\n"
        "        }\n",
        "        if let Err(error) = journal_result\n"
        "            && !self.inner.config.allow_unjournaled_effects\n"
        "        {\n"
        "            return Err(error);\n"
        "        }\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v13 job-runtime Clippy replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    if BASE.main() != 0:
        raise RuntimeError("v12 R5 Rust closeout applicator failed")
    repair_job_journal_clippy()
    repair_job_manager_clippy()
    print("PASS_R5_RUST_CLOSEOUT_V13_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
