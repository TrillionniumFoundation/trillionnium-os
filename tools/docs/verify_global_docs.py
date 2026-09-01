#!/usr/bin/env python3
"""Fail-closed verifier for the Trillionnium OS G1 documentation graph."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
MACHINE = DOCS / "machine"

class VerificationError(Exception):
    pass


class DuplicateJsonMember(ValueError):
    """Raised when an authority document repeats an object member."""


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise DuplicateJsonMember(f"duplicate JSON member {key!r}")
        value[key] = member
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")

def fail(message: str) -> None:
    raise VerificationError(message)

def load(name: str) -> dict[str, Any]:
    path = MACHINE / name
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_nonfinite,
        )
        if not isinstance(value, dict):
            raise ValueError("authority document root must be an object")
        return value
    except (OSError, ValueError) as error:
        fail(f"{path.relative_to(ROOT)} is not valid JSON: {error}")

def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)

def unique(values: list[str], label: str) -> None:
    duplicates = [value for value, count in Counter(values).items() if count > 1]
    require(not duplicates, f"duplicate {label}: {duplicates}")

def verify_doc_set(docset: dict[str, Any]) -> None:
    required = set(docset["required_files"])
    actual = {
        str(path.relative_to(ROOT))
        for path in DOCS.rglob("*")
        if path.is_file()
    }
    require(actual == required, f"document set drift; missing={sorted(required-actual)}, extra={sorted(actual-required)}")
    for forbidden in docset["forbidden_paths"]:
        require(not (ROOT / forbidden).exists(), f"forbidden historical path exists: {forbidden}")
    marker_policy_path = ROOT / "docs" / "machine" / "doc-set.v1.json"
    for path in sorted(DOCS.rglob("*")):
        if not path.is_file() or path == marker_policy_path:
            continue
        text = path.read_text(encoding="utf-8")
        for marker in docset["forbidden_content_markers"]:
            require(marker not in text, f"legacy marker {marker!r} appears in {path.relative_to(ROOT)}")
    authority = docset["authority_order"]
    unique(authority, "authority path")
    for path in authority:
        require(path in required, f"authority path is not registered: {path}")

def verify_modules(catalog: dict[str, Any]) -> set[str]:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    actual_default = cargo.get("workspace", {}).get("default-members", [])
    require(actual_default == catalog["default_source_closure"], "Cargo default-members drift from module catalog")
    modules = catalog["modules"]
    ids = [module["id"] for module in modules]
    unique(ids, "module id")
    known = set(ids)
    required_fields = {
        "id", "name", "plane", "owner_team", "backup_team", "paths",
        "responsibilities", "non_goals", "dependencies", "state_owned",
        "ordering_keys", "resource_contract", "slo", "compatibility", "maturity",
    }
    state_owners: dict[str, str] = {}
    graph: dict[str, list[str]] = {}
    for module in modules:
        missing = required_fields - set(module)
        require(not missing, f"{module.get('id')} missing module fields: {sorted(missing)}")
        require(module["owner_team"] != module["backup_team"], f"{module['id']} primary and backup teams must differ")
        require(module["responsibilities"], f"{module['id']} has no responsibilities")
        require(module["non_goals"], f"{module['id']} has no non-goals")
        require(module["ordering_keys"], f"{module['id']} has no ordering keys")
        require(module["resource_contract"], f"{module['id']} has no resource contract")
        require(module["slo"], f"{module['id']} has no SLO")
        require(module["compatibility"], f"{module['id']} has no compatibility contract")
        graph[module["id"]] = module["dependencies"]
        for dependency in module["dependencies"]:
            require(dependency in known, f"{module['id']} references unknown dependency {dependency}")
            require(dependency != module["id"], f"{module['id']} depends on itself")
        for state in module["state_owned"]:
            require(state not in state_owners, f"state {state!r} has multiple owners: {state_owners.get(state)} and {module['id']}")
            state_owners[state] = module["id"]

    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(node: str) -> None:
        if node in visiting:
            fail(f"module dependency cycle reaches {node}")
        if node in visited:
            return
        visiting.add(node)
        for dependency in graph[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)
    for node in graph:
        visit(node)
    return known

def verify_gaps(register: dict[str, Any], module_ids: set[str]) -> set[str]:
    gaps = register["gaps"]
    ids = [gap["id"] for gap in gaps]
    unique(ids, "gap id")
    known_status = set(register["status_vocabulary"])
    required_fields = {"id","priority","class","status","exit_level","modules","summary","acceptance"}
    for gap in gaps:
        missing = required_fields - set(gap)
        require(not missing, f"{gap.get('id')} missing gap fields: {sorted(missing)}")
        require(gap["status"] in known_status, f"{gap['id']} has invalid status")
        require(re.fullmatch(r"L[1-6]", gap["exit_level"]) is not None, f"{gap['id']} has invalid exit level")
        require(gap["modules"], f"{gap['id']} has no affected modules")
        for module in gap["modules"]:
            require(module in module_ids, f"{gap['id']} references unknown module {module}")
        require(gap["acceptance"], f"{gap['id']} has no acceptance criteria")
    return set(ids)

def verify_requirements(graph: dict[str, Any], module_ids: set[str], gap_ids: set[str], evidence_ids: set[str], capability_ids: set[str]) -> None:
    requirements = graph["requirements"]
    unique([req["id"] for req in requirements], "requirement id")
    for req in requirements:
        require(req["capability"] in capability_ids, f"{req['id']} references unknown capability")
        for module in req["modules"]:
            require(module in module_ids, f"{req['id']} references unknown module {module}")
        for gap in req["gaps"]:
            require(gap in gap_ids, f"{req['id']} references unknown gap {gap}")
        for evidence in req["evidence"]:
            require(evidence in evidence_ids, f"{req['id']} references unknown evidence {evidence}")
        require(req["source"] and req["tests"], f"{req['id']} lacks source or tests")
        verify_test_references(req["id"], req["tests"])


TEST_REF_KINDS = {"source", "planned", "external"}
TEST_REF_REQUIRED = {"kind", "path", "target"}


def _repository_path(value: Any, label: str) -> Path:
    require(isinstance(value, str) and value, f"{label} must be a non-empty relative path")
    candidate = Path(value)
    require(not candidate.is_absolute(), f"{label} must be repository-relative")
    require(".." not in candidate.parts, f"{label} must not escape the repository")
    resolved = (ROOT / candidate).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        fail(f"{label} resolves outside the repository")
    require(resolved.exists(), f"{label} does not exist: {value}")
    return resolved


def _command_tokens(value: Any, label: str) -> list[str]:
    require(isinstance(value, list) and value, f"{label} must be a non-empty command array")
    tokens: list[str] = []
    for index, token in enumerate(value):
        require(isinstance(token, str) and token and "\x00" not in token,
                f"{label}[{index}] must be a non-empty string")
        tokens.append(token)
    return tokens


def verify_test_references(requirement_id: str, references: Any) -> None:
    """Validate typed, reachable test declarations in the machine graph.

    A prose label is not executable evidence.  Source/planned references bind
    a repository path, command, target and workflow job.  External references
    remain explicit holds and cannot masquerade as a local test command.
    """

    require(isinstance(references, list), f"{requirement_id} tests must be an array")
    for index, reference in enumerate(references):
        label = f"{requirement_id} tests[{index}]"
        require(isinstance(reference, dict), f"{label} must be a typed object")
        missing = TEST_REF_REQUIRED - set(reference)
        require(not missing, f"{label} missing fields: {sorted(missing)}")
        kind = reference["kind"]
        require(isinstance(kind, str) and kind in TEST_REF_KINDS,
                f"{label} has unknown kind {kind!r}")
        _repository_path(reference["path"], f"{label}.path")
        target = reference["target"]
        require(isinstance(target, str) and target.strip() and "\x00" not in target,
                f"{label}.target must be a non-empty string")
        if kind == "external":
            require("command" not in reference and "workflow" not in reference,
                    f"{label} external references must not claim an executable workflow")
            continue

        command = _command_tokens(reference.get("command"), f"{label}.command")
        workflow = reference.get("workflow")
        workflow_path = _repository_path(workflow, f"{label}.workflow")
        require(str(workflow).startswith(".github/workflows/"),
                f"{label}.workflow must be under .github/workflows")
        workflow_job = reference.get("workflow_job")
        require(isinstance(workflow_job, str) and re.fullmatch(r"[A-Za-z0-9_-]+", workflow_job),
                f"{label}.workflow_job is malformed")
        workflow_text = workflow_path.read_text(encoding="utf-8")
        require(re.search(rf"(?m)^\s{{2}}{re.escape(workflow_job)}:", workflow_text) is not None,
                f"{label} workflow job is not declared: {workflow_job}")
        # Bind the declared target to the actual shell stanza.  This prevents
        # a machine graph from pointing at a test that no workflow executes.
        require(target in workflow_text or str(reference["path"]) in workflow_text,
                f"{label} path/target is not reachable from {workflow_job}")
        # Keep command identity machine-readable and bounded.  A command may
        # use a tool name or a repository script, but never shell fragments.
        require(all("\n" not in token and "\r" not in token for token in command),
                f"{label}.command contains a line break")

def verify_baseline(base: dict[str, Any], evidence_ids: set[str]) -> None:
    require(base["exact_head_evidence_must_be_ci_generated"] is True, "exact-head evidence policy must be true")
    candidate = base["documentation_candidate"]
    require(candidate["commit"] is None and candidate["tree"] is None, "checked-in candidate must not self-claim its own commit/tree")
    require(candidate["ci_status"] != "PASSED", "checked-in candidate cannot self-claim CI pass")
    require(base["latest_source_ci"]["commit"] != base["latest_candidate_parent"]["commit"], "source-CI and latest parent roles must remain distinct")
    require("EVID-G1-HEAD-PENDING" in evidence_ids, "pending G1 evidence record is missing")

def verify_program(program: dict[str, Any], gap_register: dict[str, Any]) -> set[str]:
    capabilities = program["capability_milestones"]
    ids = [cap["id"] for cap in capabilities]
    unique(ids, "capability id")
    require(program["automatic_redispatch"] is False, "automatic redispatch must remain false")
    require(program["public_release"] is False, "public release cannot be true in the G1 candidate")
    all_closed = all(gap["status"] == "CLOSED" for gap in gap_register["gaps"])
    require(program["zero_gap"] == all_closed, "zero_gap disagrees with gap states")
    phase_ids = {phase["id"] for phase in program["phases"]}
    for phase in program["phases"]:
        for dependency in phase["depends_on"]:
            require(dependency in phase_ids, f"{phase['id']} has unknown phase dependency {dependency}")
    return set(ids)

def verify_objective(objective: dict[str, Any]) -> None:
    claim = objective["optimization_claim"].lower()
    require("no claim" in claim and "global" in claim, "objective must explicitly disclaim unconditional global optimality")
    require(len(objective["hard_constraints"]) >= 8, "hard-constraint set is incomplete")
    workload_ids = [item["id"] for item in objective["workload_profiles"]]
    unique(workload_ids, "workload id")
    require(workload_ids == [f"WL-{index:02d}" for index in range(1, 13)], "WL-01 through WL-12 must be complete")
    required = {"latency_p99","lock_wait","rss","recovery_time","unknown_rate","redispatch_count","fairness"}
    require(required <= set(objective["required_measurements"]), "required system measurements are incomplete")
    require(objective["control_phases"] == ["OBSERVE","SHADOW","ADVISORY","ACTIVE_CANARY","ACTIVE"], "control maturity sequence drift")

def main() -> int:
    try:
        docset = load("doc-set.v1.json")
        base = load("current-baseline.v1.json")
        program = load("program-state.v1.json")
        catalog = load("module-catalog.v1.json")
        requirements = load("requirement-graph.v1.json")
        gaps = load("gap-register.v2.json")
        objective = load("global-objective.v1.json")
        evidence = load("evidence-index.v1.json")

        revisions = {
            docset["program_revision"],
            program["program_revision"],
            catalog["program_revision"],
            requirements["program_revision"],
            gaps["program_revision"],
            objective["program_revision"],
            evidence["program_revision"],
        }
        require(len(revisions) == 1, f"program revision drift: {sorted(revisions)}")

        evidence_ids = {item["id"] for item in evidence["records"]}
        unique([item["id"] for item in evidence["records"]], "evidence id")
        module_ids = verify_modules(catalog)
        gap_ids = verify_gaps(gaps, module_ids)
        capability_ids = verify_program(program, gaps)
        verify_requirements(requirements, module_ids, gap_ids, evidence_ids, capability_ids)
        verify_baseline(base, evidence_ids)
        verify_objective(objective)
        verify_doc_set(docset)

        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "docs" / "generate_global_docs.py"), "--check"],
            cwd=ROOT,
            check=False,
        )
        require(result.returncode == 0, "generated documentation does not match machine truth")
    except VerificationError as error:
        print(f"G1 documentation verification failed: {error}", file=sys.stderr)
        return 1
    print("G1 documentation verification passed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
