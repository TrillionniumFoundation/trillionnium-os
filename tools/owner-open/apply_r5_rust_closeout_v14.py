#!/usr/bin/env python3
"""Apply the exact v14 Host complete-graph Clippy repairs.

The v13 applicator owns all previously reviewed runtime, persistence, broker,
EOF, types, event-store, provider and job-runtime closure. This wrapper closes
the final two Host structural warnings by collapsing the terminal-frame guard
and boxing only the large delivery enum payload. Delivery order, frame bytes,
flow-control gaps, ownership, persistence and redispatch semantics remain
unchanged. This is exact-preimage and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v13.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v13", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v13 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

REPAIR = BASE.REPAIR


def repair_persistence_terminal_guard() -> None:
    path = "apps/trillionnium-owner-open-host/src/r5_persistence.rs"
    REPAIR.replace_exact(
        path,
        "            if frame.kind == \"turn.end\" {\n"
        "                if terminal_index.replace(index).is_some() {\n"
        "                    return StoredTurn::Conflict(\n"
        "                        \"stored turn has more than one terminal frame\".to_string(),\n"
        "                    );\n"
        "                }\n"
        "            }\n",
        "            if frame.kind == \"turn.end\"\n"
        "                && terminal_index.replace(index).is_some()\n"
        "            {\n"
        "                return StoredTurn::Conflict(\n"
        "                    \"stored turn has more than one terminal frame\".to_string(),\n"
        "                );\n"
        "            }\n",
    )


def repair_transport_delivery_layout() -> None:
    REPAIR.replace_exact(
        "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/flow/types.rs",
        "enum SubmitResult {\n"
        "    Deliver(RunTurnFrame),\n"
        "    Queued,\n"
        "    GapStarted(ResyncGap),\n"
        "    Suppressed,\n"
        "}\n",
        "enum SubmitResult {\n"
        "    Deliver(Box<RunTurnFrame>),\n"
        "    Queued,\n"
        "    GapStarted(ResyncGap),\n"
        "    Suppressed,\n"
        "}\n",
    )
    path = "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/flow/queue.rs"
    REPAIR.replace_exact(
        path,
        "            return Ok(SubmitResult::Deliver(frame));\n",
        "            return Ok(SubmitResult::Deliver(Box::new(frame)));\n",
    )
    REPAIR.replace_exact(
        path,
        "            ReserveDisposition::Granted { .. } => Ok(SubmitResult::Deliver(buffered.frame)),\n",
        "            ReserveDisposition::Granted { .. } => {\n"
        "                Ok(SubmitResult::Deliver(Box::new(buffered.frame)))\n"
        "            }\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v14 Host Clippy replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    if BASE.main() != 0:
        raise RuntimeError("v13 R5 Rust closeout applicator failed")
    repair_persistence_terminal_guard()
    repair_transport_delivery_layout()
    print("PASS_R5_RUST_CLOSEOUT_V14_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
