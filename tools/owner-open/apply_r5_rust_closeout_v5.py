#!/usr/bin/env python3
"""Apply the exact v5 Rust fixes exposed by the fail-closed R5 closeout.

The v4 applicator retains the already reviewed compiler/clippy repairs. This
wrapper adds only the call-registry cancel-before-spawn closure, its Host
inspection projection, and mechanical concurrency-test corrections. It is a
development-only exact-preimage applicator and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v3.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v4", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v4 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)


def replace_in_function(
    path: str,
    function: str,
    old: str,
    new: str,
    *,
    expected: int = 1,
) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    marker = f"fn {function}"
    start = text.find(marker)
    if start < 0:
        raise BASE.RepairError(f"{path}: function {function!r} is absent")
    next_function = text.find("\nfn ", start + len(marker))
    next_test = text.find("\n#[test]\n", start + len(marker))
    candidates = [value for value in (next_function, next_test) if value >= 0]
    end = min(candidates) if candidates else len(text)
    segment = text[start:end]
    count = segment.count(old)
    if count != expected:
        raise BASE.RepairError(
            f"{path}:{function}: expected {expected}, observed {count}: {old!r}"
        )
    target.write_text(
        text[:start] + segment.replace(old, new) + text[end:],
        encoding="utf-8",
    )


def repair_call_registry_cancel_before_spawn() -> None:
    registry = "crates/trillionnium-owner-open-call-registry/src/lib.rs"
    BASE.replace_exact(
        registry,
        "pub enum EffectiveState {\n"
        "    Accepted,\n"
        "    Started {\n",
        "pub enum EffectiveState {\n"
        "    Accepted,\n"
        "    CancelledBeforeSpawn,\n"
        "    Started {\n",
    )
    BASE.replace_exact(
        registry,
        "            DispatchState::Accepted { spawn_inhibited } => {\n"
        "                if *spawn_inhibited || self.connection_lost {\n"
        "                    EffectiveState::ProvenNotStartedAfterDisconnect\n"
        "                } else {\n"
        "                    EffectiveState::Accepted\n"
        "                }\n"
        "            }\n",
        "            DispatchState::Accepted { spawn_inhibited } => {\n"
        "                if self.cancellation.is_cancelled() {\n"
        "                    EffectiveState::CancelledBeforeSpawn\n"
        "                } else if *spawn_inhibited || self.connection_lost {\n"
        "                    EffectiveState::ProvenNotStartedAfterDisconnect\n"
        "                } else {\n"
        "                    EffectiveState::Accepted\n"
        "                }\n"
        "            }\n",
    )
    BASE.replace_exact(
        registry,
        "        match &entry.dispatch {\n"
        "            DispatchState::Accepted {\n"
        "                spawn_inhibited: true,\n"
        "            } => return Ok(SpawnClaim::Inhibited(entry.snapshot())),\n"
        "            DispatchState::Started { .. } | DispatchState::Terminal { .. } => {\n"
        "                return Ok(SpawnClaim::Existing(entry.snapshot()));\n"
        "            }\n"
        "            DispatchState::Accepted {\n"
        "                spawn_inhibited: false,\n"
        "            } => {}\n"
        "        }\n",
        "        match &entry.dispatch {\n"
        "            DispatchState::Accepted { spawn_inhibited }\n"
        "                if *spawn_inhibited || entry.cancellation.is_cancelled() =>\n"
        "            {\n"
        "                return Ok(SpawnClaim::Inhibited(entry.snapshot()));\n"
        "            }\n"
        "            DispatchState::Started { .. } | DispatchState::Terminal { .. } => {\n"
        "                return Ok(SpawnClaim::Existing(entry.snapshot()));\n"
        "            }\n"
        "            DispatchState::Accepted { .. } => {}\n"
        "        }\n",
    )

    inspect = "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v4/inspect_encode.rs"
    BASE.replace_exact(
        inspect,
        "        EffectiveState::Accepted => json!({\"kind\": \"accepted\"}),\n"
        "        EffectiveState::Started { generation, pid } => json!({\n",
        "        EffectiveState::Accepted => json!({\"kind\": \"accepted\"}),\n"
        "        EffectiveState::CancelledBeforeSpawn => {\n"
        "            json!({\"kind\": \"cancelled_before_spawn\"})\n"
        "        }\n"
        "        EffectiveState::Started { generation, pid } => json!({\n",
    )


def repair_concurrency_tests() -> None:
    path = "crates/trillionnium-owner-open-call-registry/tests/concurrency.rs"
    BASE.replace_exact(
        path,
        ".is_err_and(|error| **error == RegistryError::CallIdConflict))",
        ".is_err_and(|error| *error == RegistryError::CallIdConflict))",
    )
    replace_in_function(
        path,
        "pid_and_terminal_updates_are_generation_bound_and_idempotent()",
        "    let terminal = terminal(8);\n",
        "    let terminal_record = terminal(8);\n",
    )
    replace_in_function(
        path,
        "pid_and_terminal_updates_are_generation_bound_and_idempotent()",
        "terminal.clone()",
        "terminal_record.clone()",
        expected=3,
    )
    replace_in_function(
        path,
        "capacity_is_global_and_terminal_cleanup_is_explicit()",
        "    let request = request(14);\n",
        "    let first_request = request(14);\n",
    )
    replace_in_function(
        path,
        "capacity_is_global_and_terminal_cleanup_is_explicit()",
        "request.clone()",
        "first_request.clone()",
    )
    replace_in_function(
        path,
        "capacity_is_global_and_terminal_cleanup_is_explicit()",
        "&request.request_sha256",
        "&first_request.request_sha256",
    )
    replace_in_function(
        path,
        "cancellation_wins_before_spawn_but_started_calls_become_shared_cancel_requests()",
        "    let after = key(1, \"call-cancel-after\");\n",
        "    let direct = key(1, \"call-cancel-direct-signal\");\n"
        "    let direct_request = request(17);\n"
        "    let direct_begin = registry\n"
        "        .begin(direct.clone(), direct_request.clone())\n"
        "        .unwrap();\n"
        "    assert!(direct_begin.cancellation.cancel());\n"
        "    match registry\n"
        "        .claim_spawn(&direct, &direct_request.request_sha256)\n"
        "        .unwrap()\n"
        "    {\n"
        "        SpawnClaim::Inhibited(snapshot) => {\n"
        "            assert_eq!(snapshot.state, EffectiveState::CancelledBeforeSpawn)\n"
        "        }\n"
        "        other => panic!(\"directly cancelled call unexpectedly spawned: {other:?}\"),\n"
        "    }\n\n"
        "    let after = key(1, \"call-cancel-after\");\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v5 Rust closeout replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    BASE.apply_repairs()
    repair_call_registry_cancel_before_spawn()
    repair_concurrency_tests()
    print("PASS_R5_RUST_CLOSEOUT_V5_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
