#!/usr/bin/env python3
"""Apply the exact v10 Rust test-closure repairs.

The v9 applicator owns every previously reviewed production and fixture repair.
This wrapper makes the pipe close test actually wait for EOF before completing
and narrows dead-code allowance to the four integration-test-local copies of
the persistence implementation. Production warning policy and runtime control
semantics remain unchanged. This is exact-preimage and requires ``--apply``.
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
    narrow_test_local_persistence_allowance()
    print("PASS_R5_RUST_CLOSEOUT_V10_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
