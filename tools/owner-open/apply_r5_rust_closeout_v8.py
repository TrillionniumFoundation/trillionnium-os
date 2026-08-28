#!/usr/bin/env python3
"""Apply the exact v8 Rust fixes exposed by the fail-closed R5 closeout.

The v7 applicator owns all previously reviewed source repairs. This wrapper
closes the remaining explicit import surfaces for the v4 inspection carrier
and the v7 durable-job carrier. It changes no protocol value or runtime state
transition. It is development-only, exact-preimage, and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v7.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v7", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v7 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

REPAIR = BASE.BASE.BASE.BASE


def repair_v4_inspection_imports() -> None:
    path = "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v4/entry.rs"
    REPAIR.replace_exact(
        path,
        "use trillionnium_owner_open_turn_loop::{\n"
        "    ProviderTerminal, TurnCancellation, TurnEvent, TurnRequest as LoopTurnRequest,\n"
        "    TurnRunner,\n"
        "};\n",
        "use trillionnium_owner_open_turn_loop::{\n"
        "    TurnCancellation, TurnEvent, TurnRequest as LoopTurnRequest, TurnRunner,\n"
        "};\n",
    )
    REPAIR.replace_exact(
        path,
        "    FRAME_CALL_INSPECT, FRAME_CALL_INSPECT_RESULT, FRAME_HELLO, FRAME_TOOL_CANCEL,\n"
        "    FRAME_TURN_ACCEPTED, FRAME_TURN_CANCEL, FRAME_TURN_END, FRAME_TURN_INSPECT,\n",
        "    FRAME_CALL_INSPECT, FRAME_CALL_INSPECT_RESULT, FRAME_HELLO, FRAME_HELLO_ACK,\n"
        "    FRAME_TOOL_CANCEL, FRAME_TURN_ACCEPTED, FRAME_TURN_CANCEL, FRAME_TURN_END,\n"
        "    FRAME_TURN_INSPECT,\n",
    )


def repair_v7_job_imports() -> None:
    path = "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v7/imports.rs"
    REPAIR.replace_exact(
        path,
        "use std::io::Write as IoWrite;\n",
        "use std::io::{BufReader, Write as IoWrite};\n",
    )
    REPAIR.replace_exact(
        path,
        "use std::thread;\n\n",
        "use std::thread;\nuse std::time::Duration;\n\nuse crate::base::read_bounded_frame;\n\n",
    )
    REPAIR.replace_exact(
        path,
        "use trillionnium_owner_open_job_runtime::{\n"
        "    ControlDisposition, JobInspection, JobInvocation, JobManager, JobRuntimeConfig,\n"
        "    JobStartRequest, JobStartResult, PtySize, RuntimeJobEvent, RuntimeJobEventKind,\n"
        "};\n",
        "use trillionnium_owner_open_job_runtime::{\n"
        "    ControlDisposition, JobInspection, JobInvocation, JobManager, JobRuntimeConfig,\n"
        "    JobStartRequest, JobStartResult, PtySize, RuntimeJobEvent, RuntimeJobEventKind,\n"
        "};\n"
        "use trillionnium_owner_open_types::{DEFAULT_PROFILE_ID, FRAME_HELLO_ACK};\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v8 Rust closeout replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    REPAIR.apply_repairs()
    BASE.BASE.BASE.repair_call_registry_cancel_before_spawn()
    BASE.BASE.BASE.repair_concurrency_tests()
    BASE.BASE.repair_transport_nested_include_paths()
    BASE.repair_control_host_inspection_includes()
    BASE.repair_transport_unused_mut()
    repair_v4_inspection_imports()
    repair_v7_job_imports()
    print("PASS_R5_RUST_CLOSEOUT_V8_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
