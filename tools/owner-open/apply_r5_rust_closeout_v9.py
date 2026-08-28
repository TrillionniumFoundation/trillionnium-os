#!/usr/bin/env python3
"""Apply the exact v9 Rust fixture repair exposed by source closeout.

The v8 applicator owns all previously reviewed production and test-source
repairs. This wrapper corrects the live wire-inspect provider fixture so it
matches the actual provider JSONL ``tool.result.terminal.kind`` contract. The
terminal completion assertion remains unchanged. This is development-only,
exact-preimage, and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v8.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v8", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v8 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)


def repair_wire_inspect_provider_fixture() -> None:
    BASE.REPAIR.replace_exact(
        "apps/trillionnium-owner-open-host/tests/r5_wire_inspect.rs",
        "  *'\"terminal_kind\":\"client_cancelled\"'*) ;;\n",
        "  *'\"kind\":\"client_cancelled\"'*) ;;\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v9 Rust closeout replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    if BASE.main() != 0:
        raise RuntimeError("v8 R5 Rust closeout applicator failed")
    repair_wire_inspect_provider_fixture()
    print("PASS_R5_RUST_CLOSEOUT_V9_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
