#!/usr/bin/env python3
"""Apply the exact v7 Rust fixes exposed by the fail-closed R5 closeout.

The v6 applicator owns the previously reviewed Rust, cancellation and transport
repairs. This wrapper restores the real v4 inspection modules used by the
active and retained control-host carriers and removes the already observed
transport ``unused_mut`` warning. It is development-only, exact-preimage, and
requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v6.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v6", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v6 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)


def repair_control_host_inspection_includes() -> None:
    old = '        include!("r5_control_host_v4/protocol.rs");\n'
    new = (
        '        include!("r5_control_host_v4/inspect_handlers.rs");\n'
        '        include!("r5_control_host_v4/inspect_parse.rs");\n'
    )
    for path in (
        "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v6.rs",
        "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v7.rs",
    ):
        BASE.BASE.BASE.replace_exact(path, old, new)


def repair_transport_unused_mut() -> None:
    BASE.BASE.BASE.replace_exact(
        "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/process/io.rs",
        "fn spawn_stderr_drain(mut stderr: std::process::ChildStderr) {\n",
        "fn spawn_stderr_drain(stderr: std::process::ChildStderr) {\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v7 Rust closeout replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    BASE.BASE.BASE.apply_repairs()
    BASE.BASE.repair_call_registry_cancel_before_spawn()
    BASE.BASE.repair_concurrency_tests()
    BASE.repair_transport_nested_include_paths()
    repair_control_host_inspection_includes()
    repair_transport_unused_mut()
    print("PASS_R5_RUST_CLOSEOUT_V7_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
