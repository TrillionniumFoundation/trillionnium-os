#!/usr/bin/env python3
"""Strict v2 wrapper for the exact R5 runner repair candidate.

The first applicator contains the reviewed Python/environment repairs. This
wrapper replaces only its Rust repair function with preimages copied from the
current source cut, including the event-store error mapping chain. Importing
this module has no side effects; `--apply` is required.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_runner_repair_candidate.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_repair_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the base R5 repair applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)


def repair_rust_sources_v2() -> None:
    event_store = "crates/trillionnium-owner-open-event-store/src/lib.rs"
    BASE.replace_exact(
        event_store,
        "    let read = reader\n"
        "        .take(maximum as u64 + 2)\n"
        "        .read_until(b'\\n', &mut line)\n"
        "        .map_err(|error| EventStoreError::Io(error.to_string()))?;\n",
        "    let mut limited = (&mut *reader).take(maximum as u64 + 2);\n"
        "    let read = limited\n"
        "        .read_until(b'\\n', &mut line)\n"
        "        .map_err(|error| EventStoreError::Io(error.to_string()))?;\n",
    )
    BASE.replace_exact(
        event_store,
        "    if matches!(\n"
        "        error.raw_os_error(),\n"
        "        Some(libc::EWOULDBLOCK) | Some(libc::EAGAIN)\n"
        "    ) {\n",
        "    if error\n"
        "        .raw_os_error()\n"
        "        .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)\n"
        "    {\n",
    )
    BASE.replace_exact(
        "crates/trillionnium-owner-open-runtime/src/lib.rs",
        "use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};\n",
        "use std::sync::mpsc::{SyncSender, sync_channel};\n",
    )
    BASE.replace_exact(
        "crates/trillionnium-owner-open-runtime/tests/runtime.rs",
        "use std::path::PathBuf;\n",
        "",
    )
    BASE.replace_exact(
        "crates/trillionnium-owner-open-call-registry/src/lib.rs",
        "    #[must_use]\n    pub fn len(&self) -> Result<usize> {\n",
        "    pub fn len(&self) -> Result<usize> {\n",
    )
    BASE.replace_exact(
        "crates/trillionnium-owner-open-call-registry/src/lib.rs",
        "    #[must_use]\n    pub fn is_empty(&self) -> Result<bool> {\n",
        "    pub fn is_empty(&self) -> Result<bool> {\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    BASE.repair_rust_sources = repair_rust_sources_v2
    BASE.apply_repairs()
    print("PASS_R5_EXACT_REPAIRS_V2_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
