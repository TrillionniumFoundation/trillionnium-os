#!/usr/bin/env python3
"""Generate the canonical G1 status views from docs/machine."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MACHINE = ROOT / "docs" / "machine"
GENERATED = ROOT / "docs" / "generated"

def load(name: str) -> dict[str, Any]:
    return json.loads((MACHINE / name).read_text(encoding="utf-8"))

def cell(value: Any) -> str:
    return str(value).replace("|", r"\|").replace("\n", " ")


def test_reference_cell(references: list[dict[str, Any]]) -> str:
    """Render typed machine test references without losing their identity."""
    rendered: list[str] = []
    for reference in references:
        kind = reference.get("kind", "unknown")
        path = reference.get("path", "")
        target = reference.get("target", "")
        if kind == "external":
            rendered.append(f"external:{path}:{target}")
        else:
            command = " ".join(reference.get("command", []))
            workflow = reference.get("workflow", "")
            job = reference.get("workflow_job", "")
            rendered.append(f"{kind}:{path}:{command}:{workflow}#{job}")
    return ";".join(rendered)

def summarize_gaps(data: dict[str, Any]) -> dict[str, Any]:
    """Count every non-CLOSED gap without promoting evidence or changing state."""
    vocabulary = data.get("status_vocabulary")
    expected = {"OPEN", "SOURCE_CLOSED_PENDING_EVIDENCE", "EXTERNAL_HOLD", "CLOSED"}
    if (not isinstance(vocabulary, list) or not all(isinstance(v, str) for v in vocabulary)
            or len(vocabulary) != len(expected) or set(vocabulary) != expected):
        raise ValueError("gap status vocabulary differs")
    gaps = data.get("gaps")
    if not isinstance(gaps, list):
        raise ValueError("gap register must contain a list")
    counts = {status: 0 for status in vocabulary}
    levels = {f"L{level}": 0 for level in range(1, 7)}
    seen: set[str] = set()
    for gap in gaps:
        if not isinstance(gap, dict):
            raise ValueError("gap entry is not an object")
        identity, status, level = gap.get("id"), gap.get("status"), gap.get("exit_level")
        if not isinstance(identity, str) or not identity or identity in seen:
            raise ValueError("gap identity is missing or duplicated")
        if not isinstance(status, str) or status not in counts:
            raise ValueError("gap status is unknown")
        if not isinstance(level, str) or level not in levels:
            raise ValueError("gap exit level is unknown")
        seen.add(identity)
        counts[status] += 1
        if status != "CLOSED":
            levels[level] += 1
    return {"total": len(gaps), "closed": counts["CLOSED"],
            "unresolved": len(gaps) - counts["CLOSED"],
            "statuses": counts, "unresolved_by_exit_level": levels}


def current_state() -> str:
    base = load("current-baseline.v1.json")
    program = load("program-state.v1.json")
    gap_summary = summarize_gaps(load("gap-register.v2.json"))
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
        f"- Unresolved gaps: `{gap_summary['unresolved']}` of `{gap_summary['total']}` (only CLOSED is resolved)",
        f"- Public release: `{str(program['public_release']).lower()}`",
        f"- Automatic redispatch: `{str(program['automatic_redispatch']).lower()}`",
        "",
        "## Recorded baseline snapshot (not live PR status)",
        "",
        f"Snapshot observed at: `{base['observed_at']}`. The compatibility keys named "
        "`latest_*` describe this recorded snapshot, not the current remote head.",
        "Current candidate, CI, review and integration claims require a newly retained "
        "exact-head report; none is inferred from the rows below.",
        "",
        "| Role | Branch | Commit | Tree | CI | Review | Claim ceiling |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for label, key in [
        ("Recorded protected trunk", "trunk"),
        ("Recorded source CI", "latest_source_ci"),
        ("Recorded source parent", "latest_candidate_parent"),
        ("Recorded documentation candidate", "documentation_candidate"),
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
        "| Module | Version | Name | Plane | Primary | Backup | Maturity | API | State schema | Concurrency | Resource budget | SLO | Dependencies | State owned | Open gaps |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for module in data["modules"]:
        resource = module["resource_contract"]
        slo = module["slo"]
        resource_summary = (
            f"mem={resource['memory_bytes']};fd={resource['fd_count']};"
            f"threads={resource['thread_count']};queue={resource['queue_items']}"
        )
        slo_summary = (
            f"p99={slo['latency_p99_ms']}ms;throughput={slo['throughput_per_sec']}/s;"
            f"availability={slo['availability_percent']}%"
        )
        concurrency = module["concurrency_contract"]
        concurrency_summary = (
            f"key={concurrency['ordering_key']};max={concurrency['max_concurrency']};"
            f"lock={concurrency['lock_scope']}"
        )
        lines.append(
            f"| `{module['id']}` | `{module['module_version']}` | {cell(module['name'])} | `{module['plane']}` | "
            f"`{module['owner_team']}` | `{module['backup_team']}` | `{module['maturity']}` | "
            f"`{module['api_contract']['version']}` | `{module['state_contract']['schema']}` | "
            f"`{cell(concurrency_summary)}` | "
            f"`{cell(resource_summary)}` | `{cell(slo_summary)}` | "
            f"{cell(', '.join(module['dependencies']) or 'none')} | "
            f"{cell(', '.join(module['state_owned']) or 'none')} | "
            f"{cell(', '.join(module['open_gaps']) or 'none')} |"
        )
    return "\n".join(lines) + "\n"

def component_status() -> str:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    workspace = cargo["workspace"]
    members = workspace["members"]
    defaults = set(workspace["default-members"])
    lifecycle = json.loads(
        (ROOT / "governance/component-lifecycle.v1.json").read_text(encoding="utf-8")
    )
    excluded = {entry["path"]: entry for entry in lifecycle["non_product_members"]}
    lines = [
        "# Component Status",
        "",
        "<!-- GENERATED. DO NOT EDIT. -->",
        "",
        f"- Workspace members: `{len(members)}`",
        f"- Default source closure: `{len(defaults)}`",
        f"- Sealed non-product members: `{len(members) - len(defaults)}`",
        "",
        "| Path | Package | Selection | Classification | Replacement | Documentation | Local source test | Rationale |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for member in members:
        manifest = tomllib.loads(
            (ROOT / member / "Cargo.toml").read_text(encoding="utf-8")
        )
        package = manifest["package"]["name"]
        if member in defaults:
            selection = "default-source-closure"
            classification = "active_default_component"
            replacement = "none"
            rationale = (
                "Selected by Cargo default-members and module-catalog "
                "default_source_closure."
            )
        else:
            entry = excluded[member]
            selection = "sealed-explicit-only"
            classification = entry["classification"]
            replacement = ", ".join(entry["replacement"]) or "none"
            rationale = entry["reason"]
        lines.append(
            f"| `{member}` | `{package}` | `{selection}` | `{classification}` | "
            f"{cell(replacement)} | `{member}/README.md` | "
            f"`cargo test --locked -p {package} --all-targets` | "
            f"{cell(rationale)} |"
        )
    lines += [
        "",
        "A successful source test does not activate a sealed component or establish",
        "installed-target, Android-image, physical-device, destructive-fault or",
        "public-release evidence.",
        "",
    ]
    return "\n".join(lines)

def product_profile_status() -> str:
    data = load("product-profile-catalog.v1.json")
    lines = [
        "# Product Profile Status",
        "",
        "<!-- GENERATED. DO NOT EDIT. -->",
        "",
        f"- Default profile: `{data['default_profile']}`",
        "",
        "| Profile | Status | Default | Activation | Modules | Cargo components | Offered capabilities | Blocked capabilities | Claim ceiling |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for profile in data["profiles"]:
        offered = ", ".join(item["id"] for item in profile["offered_capabilities"]) or "none"
        blocked = ", ".join(item["id"] for item in profile["blocked_capabilities"]) or "none"
        lines.append(
            f"| `{profile['id']}` | `{profile['status']}` | "
            f"`{str(profile['default']).lower()}` | "
            f"`{str(profile['activation_allowed']).lower()}` | "
            f"{cell(', '.join(profile['selected_modules']) or 'none')} | "
            f"{cell(', '.join(profile['selected_cargo_components']) or 'none')} | "
            f"{cell(offered)} | {cell(blocked)} | {cell(profile['claim_ceiling'])} |"
        )
    lines += [
        "",
        "A sealed profile contributes no current product capability. Source presence or",
        "a successful build cannot activate it without a reviewed catalog transition and",
        "the evidence named by its blockers.",
        "",
    ]
    return "\n".join(lines)

def effect_lifecycle_status() -> str:
    data = load("effect-lifecycle.v1.json")
    lines = [
        "# Effect Lifecycle",
        "",
        "<!-- GENERATED. DO NOT EDIT. -->",
        "",
        f"- Schema: `{data['schema']}`",
        f"- Status: `{data['status']}`",
        f"- Claim ceiling: `{data['claim_ceiling']}`",
        f"- Automatic redispatch: `{str(data['automatic_redispatch']).lower()}`",
        f"- States: `{len(data['states'])}`",
        f"- Transitions: `{len(data['transitions'])}`",
        f"- Crash cuts: `{len(data['crash_cuts'])}`",
        "",
        "## States",
        "",
        "| State | Phase | Durable | Effect may have started | Outcome | New effect permitted | Meaning |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for state in data["states"]:
        lines.append(
            f"| `{state['id']}` | `{state['phase']}` | "
            f"`{str(state['durable']).lower()}` | "
            f"`{str(state['effect_may_have_started']).lower()}` | "
            f"`{state['outcome']}` | "
            f"`{str(state['permits_new_effect']).lower()}` | "
            f"{cell(state['meaning'])} |"
        )
    lines += [
        "",
        "## Transitions",
        "",
        "| ID | From | To | Trigger | Effect boundary | Durable acceptance required |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for transition in data["transitions"]:
        lines.append(
            f"| `{transition['id']}` | `{transition['from']}` | `{transition['to']}` | "
            f"`{transition['trigger']}` | "
            f"`{str(transition['effect_boundary']).lower()}` | "
            f"`{str(transition['requires_durable_acceptance']).lower()}` |"
        )
    lines += ["", "## Invariants", ""]
    for invariant in data["invariants"]:
        lines.append(
            f"- `{invariant['id']}` / `{invariant['checker']}` — "
            f"{invariant['statement']}"
        )
    lines += [
        "",
        "## Crash cuts",
        "",
        "| Cut | After | Legal recovery | Forbidden inference | Automatic redispatch |",
        "| --- | --- | --- | --- | --- |",
    ]
    for cut in data["crash_cuts"]:
        lines.append(
            f"| `{cut['id']}` | `{cut['after']}` | "
            f"{cell(', '.join(cut['legal_recovery']))} | "
            f"{cell(', '.join(cut['forbidden_inference']))} | "
            f"`{str(cut['automatic_redispatch']).lower()}` |"
        )
    lines += [
        "",
        "## Implementation bindings",
        "",
        "| Binding | Modules | Source symbol | Transitions | Tests |",
        "| --- | --- | --- | --- | --- |",
    ]
    for binding in data["implementation_bindings"]:
        lines.append(
            f"| `{binding['id']}` | {cell(', '.join(binding['modules']))} | "
            f"`{binding['source_path']}::{binding['symbol']}` | "
            f"{cell(', '.join(binding['transitions']))} | "
            f"{cell(', '.join(binding['tests']))} |"
        )
    lines += [
        "",
        "The generated view is descriptive. The executable verifier and finite model",
        "checker remain the authority for legal transitions. Passing them is L1 source",
        "evidence only and cannot substitute for installed-target or destructive-fault proof.",
        "",
    ]
    return "\n".join(lines)

def gap_status() -> str:
    data = load("gap-register.v2.json")
    summary = summarize_gaps(data)
    counts = summary["statuses"]
    priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    gaps = sorted(data["gaps"], key=lambda g: (priority_order.get(g["priority"], 9), g["id"]))
    lines = [
        "# Gap Status",
        "",
        "<!-- GENERATED. DO NOT EDIT. -->",
        "",
        f"- Total: `{len(gaps)}`",
        f"- Unresolved: `{summary['unresolved']}` (includes pending evidence and external holds)",
    ]
    for status in data["status_vocabulary"]:
        lines.append(f"- {status}: `{counts[status]}`")
    lines += ["", "OPEN=0 does not mean zero unresolved gaps. Source-closed pending evidence",
              "and external holds remain unresolved until the required receipt is accepted.",
              "These counts are a projection of the recorded register, not a live CI or target observation.",
              "", "## Unresolved by required exit level", "",
              "| Exit level | Unresolved gaps |", "| --- | ---: |"]
    for level, count in summary["unresolved_by_exit_level"].items():
        lines.append(f"| `{level}` | `{count}` |")
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
            test_reference_cell(req["tests"]),
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
        GENERATED / "COMPONENT_STATUS.md": component_status(),
        GENERATED / "PRODUCT_PROFILE_STATUS.md": product_profile_status(),
        GENERATED / "EFFECT_LIFECYCLE.md": effect_lifecycle_status(),
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
