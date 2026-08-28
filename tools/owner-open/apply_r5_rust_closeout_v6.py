#!/usr/bin/env python3
"""Apply the exact v6 Rust fixes exposed by the fail-closed R5 closeout.

The v5 applicator owns the previously reviewed Rust and cancel-before-spawn
repairs. This wrapper adds only the transport Host's nested include-path fix.
It is development-only, exact-preimage, and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v5.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v5", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v5 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)


def repair_transport_nested_include_paths() -> None:
    BASE.BASE.replace_exact(
        "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/flow/state.rs",
        "include!(\"flow/window.rs\");\ninclude!(\"flow/queue.rs\");\n",
        "include!(\"window.rs\");\ninclude!(\"queue.rs\");\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v6 Rust closeout replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    BASE.BASE.apply_repairs()
    BASE.repair_call_registry_cancel_before_spawn()
    BASE.repair_concurrency_tests()
    repair_transport_nested_include_paths()
    print("PASS_R5_RUST_CLOSEOUT_V6_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
