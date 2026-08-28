#!/usr/bin/env python3
"""Apply the exact v15 Host complete-graph Clippy repairs.

The v14 applicator owns all previously reviewed R5 source closure. This wrapper
boxes only the legacy v2 Host TurnEvent message payload and collapses one v4
active-inspection scope guard. Event contents, channel ordering, persistence,
inspection scope, cancellation and redispatch semantics remain unchanged. This
is exact-preimage and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v14.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v14", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v14 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

REPAIR = BASE.REPAIR


def repair_v2_host_message_layout() -> None:
    path = "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v2.rs"
    REPAIR.replace_exact(
        path,
        "enum HostMessage {\n"
        "    Inbound(Vec<u8>),\n"
        "    InputEof,\n"
        "    InputError(String),\n"
        "    TurnEvent(TurnEvent),\n"
        "    TurnComplete(Result<ProviderTerminal, String>),\n"
        "}\n",
        "enum HostMessage {\n"
        "    Inbound(Vec<u8>),\n"
        "    InputEof,\n"
        "    InputError(String),\n"
        "    TurnEvent(Box<TurnEvent>),\n"
        "    TurnComplete(Result<ProviderTerminal, String>),\n"
        "}\n",
    )
    REPAIR.replace_exact(
        path,
        "                                        .send(HostMessage::TurnEvent(event.clone()))\n",
        "                                        .send(HostMessage::TurnEvent(Box::new(event.clone())))\n",
    )


def repair_v4_inspect_scope_guard() -> None:
    path = "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v4/inspect_parse.rs"
    REPAIR.replace_exact(
        path,
        "    if let Some(active) = active {\n"
        "        if active.context.session_id != context.session_id\n"
        "            || active.context.profile_id != context.profile_id\n"
        "            || active.context.task_id != context.task_id\n"
        "            || active.context.turn_id != context.turn_id\n"
        "            || active.context.turn_stream_id != context.turn_stream_id\n"
        "        {\n"
        "            return Err(\n"
        "                \"inspect scope does not match the active turn\".to_string(),\n"
        "            );\n"
        "        }\n"
        "    }\n",
        "    if let Some(active) = active\n"
        "        && (active.context.session_id != context.session_id\n"
        "            || active.context.profile_id != context.profile_id\n"
        "            || active.context.task_id != context.task_id\n"
        "            || active.context.turn_id != context.turn_id\n"
        "            || active.context.turn_stream_id != context.turn_stream_id)\n"
        "    {\n"
        "        return Err(\n"
        "            \"inspect scope does not match the active turn\".to_string(),\n"
        "        );\n"
        "    }\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v15 Host Clippy replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    if BASE.main() != 0:
        raise RuntimeError("v14 R5 Rust closeout applicator failed")
    repair_v2_host_message_layout()
    repair_v4_inspect_scope_guard()
    print("PASS_R5_RUST_CLOSEOUT_V15_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
