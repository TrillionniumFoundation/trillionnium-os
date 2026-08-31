#!/usr/bin/env python3
"""Generate the canonical G1 status views from docs/machine."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MACHINE = ROOT / "docs" / "machine"
GENERATED = ROOT / "docs" / "generated"

def load(name: str) -> dict[str, Any]:
    return json.loads((MACHINE / name).read_text(encoding="utf-8"))

def cell(value: Any) -> str:
    return str(value).replace("|", r"\|").replace("\n", " ")

def current_state() -> str:
    base = load("current-baseline.v1.json")
    program = load("program-state.v1.json")
    lines = [
        "# Current State",
        "",
        "<!-- GENERATED. DO NOT EDIT. -->",
        "",
        f"- Program: `{program['program_revision']}`",
        f"- Status: `{program['status']}`",
        f"- Semantic revision: `{program['semantic_revision']}`",
        f"- Architecture revision: `{program['architecture_revision']}`",
        f"- Zero gap: `{str(program['zero_gap']).lower()}`",
        f"- Public release: `{str(program['public_release']).lower()}`",
        f"- Automatic redispatch: `{str(program['automatic_redispatch']).lower()}`",
        "",
        "## Baselines",
        "",
        "| Role | Branch | Commit | Tree | CI | Review | Claim ceiling |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for label, key in [
        ("Protected trunk", "trunk"),
        ("Latest source CI", "latest_source_ci"),
        ("Latest source parent", "latest_candidate_parent"),
        ("G1 documentation candidate", "documentation_candidate"),
    ]:
        item = base[key]
        lines.append(
            f"| {label} | `{cell(item.get('branch'))}` | `{cell(item.get('commit') or 'CI_GENERATED')}` | "
            f"`{cell(item.get('tree') or 'CI_GENERATED')}` | `{cell(item.get('ci_status', item.get('state', 'n/a')))}` | "
            f"`{cell(item.get('review_status', 'n/a'))}` | `{cell(item.get('claim_ceiling', 'n/a'))}` |"
        )
    lines += [
        "",
        "## Capability milestones",
        "",
        "| ID | Capability | Required level | Status | Exit |",
        "| --- | --- | --- | --- | --- |",
    ]
    for cap in program["capability_milestones"]:
        lines.append(
            f"| `{cap['id']}` | {cell(cap['name'])} | `{cap['required_level']}` | "
            f"`{cap['status']}` | {cell(cap['exit'])} |"
        )
    lines += ["", "## Critical path", ""]
    for index, item in enumerate(program["critical_path"], 1):
        lines.append(f"{index}. {item}")
    lines += ["", "## Explicit non-claims", ""]
    for item in base["non_claims"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"

def module_status() -> str:
    data = load("module-catalog.v1.json")
    lines = [
        "# Module Status",
        "",
        "<!-- GENERATED. DO NOT EDIT. -->",
        "",
        "| Module | Name | Plane | Primary | Backup | Maturity | Dependencies | State owned |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for module in data["modules"]:
        lines.append(
            f"| `{module['id']}` | {cell(module['name'])} | `{module['plane']}` | "
            f"`{module['owner_team']}` | `{module['backup_team']}` | `{module['maturity']}` | "
            f"{cell(', '.join(module['dependencies']) or 'none')} | "
            f"{cell(', '.join(module['state_owned']) or 'none')} |"
        )
    return "\n".join(lines) + "\n"

def gap_status() -> str:
    data = load("gap-register.v2.json")
    counts: dict[str, int] = {status: 0 for status in data["status_vocabulary"]}
    for gap in data["gaps"]:
        counts[gap["status"]] += 1
    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    gaps = sorted(data["gaps"], key=lambda g: (priority_order.get(g["priority"], 9), g["id"]))
    lines = [
        "# Gap Status",
        "",
        "<!-- GENERATED. DO NOT EDIT. -->",
        "",
        f"- Total: `{len(gaps)}`",
    ]
    for status in data["status_vocabulary"]:
        lines.append(f"- {status}: `{counts[status]}`")
    lines += [
        "",
        "| Gap | Priority | Class | Status | Exit | Modules | Summary |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for gap in gaps:
        lines.append(
            f"| `{gap['id']}` | `{gap['priority']}` | `{gap['class']}` | `{gap['status']}` | "
            f"`{gap['exit_level']}` | {cell(', '.join(gap['modules']))} | {cell(gap['summary'])} |"
        )
    return "\n".join(lines) + "\n"

def traceability() -> str:
    data = load("requirement-graph.v1.json")
    header = ["requirement_id", "capability", "modules", "gaps", "source", "tests", "evidence", "status"]
    rows = ["\t".join(header)]
    for req in data["requirements"]:
        rows.append("\t".join([
            req["id"],
            req["capability"],
            ";".join(req["modules"]),
            ";".join(req["gaps"]),
            ";".join(req["source"]),
            ";".join(req["tests"]),
            ";".join(req["evidence"]),
            req["status"],
        ]))
    return "\n".join(rows) + "\n"

def performance_status() -> str:
    objective = load("global-objective.v1.json")
    gaps = load("gap-register.v2.json")["gaps"]
    perf_gap = next(g for g in gaps if g["id"] == "GAP-PERF-SYSTEM-BASELINE-001")
    lines = [
        "# Performance Status",
        "",
        "<!-- GENERATED. DO NOT EDIT. -->",
        "",
        f"- Objective mode: `{objective['mode']}`",
        f"- Baseline gap: `{perf_gap['status']}`",
        f"- Optimization claim: {objective['optimization_claim']}",
        "",
        "## Hard constraints",
        "",
    ]
    lines.extend(f"- {value}" for value in objective["hard_constraints"])
    lines += [
        "",
        "## Workload profiles",
        "",
        "| ID | Workload |",
        "| --- | --- |",
    ]
    for workload in objective["workload_profiles"]:
        lines.append(f"| `{workload['id']}` | {cell(workload['name'])} |")
    lines += [
        "",
        "## Required measurements",
        "",
        ", ".join(f"`{value}`" for value in objective["required_measurements"]),
        "",
        "No global performance or optimality claim is promotable until the workload "
        "profiles produce retained exact-source artifacts.",
    ]
    return "\n".join(lines) + "\n"

def outputs() -> dict[Path, str]:
    return {
        GENERATED / "CURRENT_STATE.md": current_state(),
        GENERATED / "MODULE_STATUS.md": module_status(),
        GENERATED / "GAP_STATUS.md": gap_status(),
        GENERATED / "TRACEABILITY.tsv": traceability(),
        GENERATED / "PERFORMANCE_STATUS.md": performance_status(),
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    mismatches: list[str] = []
    for path, content in outputs().items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                mismatches.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    if mismatches:
        print("generated documentation is stale:")
        for value in mismatches:
            print(f"  {value}")
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
