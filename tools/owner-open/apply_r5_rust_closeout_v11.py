#!/usr/bin/env python3
"""Apply the exact v11 complete-graph Clippy repairs.

The v10 applicator owns the reviewed runtime, persistence, broker, EOF and
focused-Clippy closure. This wrapper keeps those exact replacements and closes
the six complete-default-graph warnings exposed in owner-open-types without
changing protocol semantics. This is exact-preimage and requires ``--apply``.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "apply_r5_rust_closeout_v10.py"
SPEC = importlib.util.spec_from_file_location("owner_open_r5_rust_closeout_v10", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the v10 R5 Rust closeout applicator")
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

REPAIR = BASE.REPAIR


def repair_owner_open_types_clippy() -> None:
    path = "crates/trillionnium-owner-open-types/src/lib.rs"
    REPAIR.replace_exact(
        path,
        "        if let Some(direction) = self.direction.as_deref() {\n"
        "            if !matches!(direction, \"client_to_host\" | \"host_to_client\") {\n"
        "                return Err(invalid(\"direction is not a supported transport role\"));\n"
        "            }\n"
        "        }\n",
        "        if let Some(direction) = self.direction.as_deref()\n"
        "            && !matches!(direction, \"client_to_host\" | \"host_to_client\")\n"
        "        {\n"
        "            return Err(invalid(\"direction is not a supported transport role\"));\n"
        "        }\n",
    )
    REPAIR.replace_exact(
        path,
        "        if let Some(profile_id) = self.profile_id.as_deref() {\n"
        "            if profile_id != request.effective_profile_id() {\n"
        "                return Err(invalid(\n"
        "                    \"envelope profile_id conflicts with payload profile_id\",\n"
        "                ));\n"
        "            }\n"
        "        }\n",
        "        if let Some(profile_id) = self.profile_id.as_deref()\n"
        "            && profile_id != request.effective_profile_id()\n"
        "        {\n"
        "            return Err(invalid(\n"
        "                \"envelope profile_id conflicts with payload profile_id\",\n"
        "            ));\n"
        "        }\n",
    )
    REPAIR.replace_exact(
        path,
        "        if let Some(cwd) = self.cwd.as_deref() {\n"
        "            if cwd.contains('\\0') {\n"
        "                return Err(invalid(\"cwd contains NUL\"));\n"
        "            }\n"
        "        }\n",
        "        if let Some(cwd) = self.cwd.as_deref()\n"
        "            && cwd.contains('\\0')\n"
        "        {\n"
        "            return Err(invalid(\"cwd contains NUL\"));\n"
        "        }\n",
    )
    REPAIR.replace_exact(
        path,
        "fn validate_optional_alias(name: &str, first: Option<&str>, second: Option<&str>) -> Result<()> {\n"
        "    if let (Some(first), Some(second)) = (first, second) {\n"
        "        if first != second {\n"
        "            return Err(invalid(format!(\n"
        "                \"envelope {name} conflicts with payload {name}\"\n"
        "            )));\n"
        "        }\n"
        "    }\n"
        "    Ok(())\n"
        "}\n",
        "fn validate_optional_alias(name: &str, first: Option<&str>, second: Option<&str>) -> Result<()> {\n"
        "    if let (Some(first), Some(second)) = (first, second)\n"
        "        && first != second\n"
        "    {\n"
        "        return Err(invalid(format!(\n"
        "            \"envelope {name} conflicts with payload {name}\"\n"
        "        )));\n"
        "    }\n"
        "    Ok(())\n"
        "}\n",
    )
    REPAIR.replace_exact(
        path,
        "fn validate_alias_pair(\n"
        "    first_name: &str,\n"
        "    first: Option<&str>,\n"
        "    second_name: &str,\n"
        "    second: Option<&str>,\n"
        ") -> Result<()> {\n"
        "    if let (Some(first), Some(second)) = (first, second) {\n"
        "        if first != second {\n"
        "            return Err(invalid(format!(\n"
        "                \"{first_name} conflicts with alias {second_name}\"\n"
        "            )));\n"
        "        }\n"
        "    }\n"
        "    Ok(())\n"
        "}\n",
        "fn validate_alias_pair(\n"
        "    first_name: &str,\n"
        "    first: Option<&str>,\n"
        "    second_name: &str,\n"
        "    second: Option<&str>,\n"
        ") -> Result<()> {\n"
        "    if let (Some(first), Some(second)) = (first, second)\n"
        "        && first != second\n"
        "    {\n"
        "        return Err(invalid(format!(\n"
        "            \"{first_name} conflicts with alias {second_name}\"\n"
        "        )));\n"
        "    }\n"
        "    Ok(())\n"
        "}\n",
    )
    REPAIR.replace_exact(
        path,
        "    fn resource_limits_are_mechanical_not_semantic() {\n"
        "        let mut limits = MechanicalLimits::default();\n"
        "        limits.max_total_argv_bytes = 3;\n"
        "        let mut call = base_tool_call();\n",
        "    fn resource_limits_are_mechanical_not_semantic() {\n"
        "        let limits = MechanicalLimits {\n"
        "            max_total_argv_bytes: 3,\n"
        "            ..MechanicalLimits::default()\n"
        "        };\n"
        "        let mut call = base_tool_call();\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the exact audited v11 complete-graph Clippy replacements",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if not arguments.apply:
        raise SystemExit("HOLD: --apply is required")
    if BASE.main() != 0:
        raise RuntimeError("v10 R5 Rust closeout applicator failed")
    repair_owner_open_types_clippy()
    print("PASS_R5_RUST_CLOSEOUT_V11_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
