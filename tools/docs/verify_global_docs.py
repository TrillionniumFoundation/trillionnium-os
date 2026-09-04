#!/usr/bin/env python3
"""Fail-closed verifier for the Trillionnium OS G1 documentation graph."""
from __future__ import annotations

import json
import math
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


SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
STATE_VERSION_RE = re.compile(r"^[0-9]+$")
LEVEL_RE = re.compile(r"^L[1-6]$")
# API members identify concrete versioned wire types.  Generic labels such as
# ``typed_request`` make a catalog look complete while leaving the boundary
# unowned, so they are deliberately outside this grammar.
API_TYPE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*_v[0-9]+$")

MODULE_CATALOG_KEYS = {
    "schema", "program_revision", "module_definition", "contract_schema",
    "modules", "default_source_closure",
}
CONTRACT_SCHEMA_KEYS = {
    "schema", "version", "required_module_fields", "resource_fields", "slo_fields",
}
MODULE_REQUIRED_FIELDS = {
    "id", "module_version", "name", "plane", "owner_team", "backup_team", "paths",
    "responsibilities", "non_goals", "dependencies", "state_owned", "ordering_keys",
    "concurrency_contract",
    "api_contract", "state_contract", "resource_contract", "slo", "fault_contract",
    "evidence_contract", "compatibility", "migration", "rollback", "maturity", "open_gaps",
}
CONCURRENCY_KEYS = {
    "admission_resource", "ordering_key", "max_concurrency", "lease_source", "lock_scope",
    "slow_paths", "timeout_ms", "cancellation", "backpressure", "lease_expiry",
    "duplicate_conflict",
}
API_CONTRACT_KEYS = {"version", "schema", "inputs", "outputs", "errors"}
STATE_CONTRACT_KEYS = {
    "version", "schema", "authoritative", "partition", "durability", "retention",
    "terminal_states",
}
STATE_RETENTION_KEYS = {"max_items", "max_bytes"}
RESOURCE_KEYS = {
    "cpu_weight", "memory_bytes", "fd_count", "process_count", "thread_count",
    "io_bytes_per_sec", "queue_items", "queue_bytes", "store_bytes", "timeout_ms",
    "recovery_ms",
}
SLO_KEYS = {
    "latency_p99_ms", "throughput_per_sec", "availability_percent", "recovery_ms",
    "measurement_window_sec",
}
FAULT_KEYS = {"failure_modes", "degraded_state", "recovery", "uncertain_effect"}
EVIDENCE_KEYS = {
    "minimum_level", "required_artifacts", "raw_observations", "claim_ceiling", "negative_claims",
}
COMPATIBILITY_KEYS = {
    "api_semver", "state_schema", "rolling", "read_write_matrix", "unknown_fields",
}
READ_WRITE_KEYS = {"read", "write"}
MIGRATION_KEYS = {"from_versions", "to_version", "strategy", "dual_read", "dual_write"}
ROLLBACK_KEYS = {"supported", "procedure", "fail_closed"}
# The only catalog migrations currently implemented by source are the v1
# JSONL-to-v2 segmented stores.  Every other module is intentionally v1-only;
# declaring a vague migration there would overstate compatibility evidence.
IMPLEMENTED_V2_MIGRATIONS = {
    "MOD-TRANSPORT": "fenced_prefix_reconcile",
    "MOD-JOB-RUNTIME": "fenced_prefix_reconcile",
    "MOD-EVENT-STORE": "fenced_prefix_reconcile",
}

# These are schema ceilings, not performance claims.  Individual module
# budgets are declared in the machine catalog and must remain finite and
# addressable before a source candidate can pass the graph gate.
RESOURCE_MAX = {
    "cpu_weight": 10_000,
    "memory_bytes": 1 << 40,
    "fd_count": 1 << 20,
    "process_count": 1 << 16,
    "thread_count": 1 << 20,
    "io_bytes_per_sec": 1 << 40,
    "queue_items": 1 << 24,
    "queue_bytes": 1 << 40,
    "store_bytes": 1 << 40,
    "timeout_ms": 86_400_000,
    "recovery_ms": 86_400_000,
}


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


def require_object(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def require_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} must be a non-empty string")
    require("\x00" not in value, f"{label} contains a NUL")
    return value


def require_string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    if not allow_empty:
        require(bool(value), f"{label} must not be empty")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(require_string(item, f"{label}[{index}]"))
    unique(result, label)
    return result


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    missing = expected - actual
    extra = actual - expected
    require(not missing and not extra,
            f"{label} keys drift; missing={sorted(missing)}, extra={sorted(extra)}")


def require_semver(value: Any, label: str) -> str:
    text = require_string(value, label)
    require(SEMVER_RE.fullmatch(text) is not None, f"{label} must be semantic version X.Y.Z")
    return text


def require_state_version(value: Any, label: str) -> str:
    text = require_string(value, label)
    require(STATE_VERSION_RE.fullmatch(text) is not None, f"{label} must be a numeric state version")
    return text


def require_positive_int(value: Any, label: str, maximum: int | None = None) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    require(value > 0, f"{label} must be positive")
    if maximum is not None:
        require(value <= maximum, f"{label} exceeds schema ceiling {maximum}")
    return value


def require_finite_positive(value: Any, label: str, maximum: float | None = None) -> float:
    require(isinstance(value, (int, float)) and not isinstance(value, bool),
            f"{label} must be numeric")
    number = float(value)
    require(math.isfinite(number) and number > 0, f"{label} must be finite and positive")
    if maximum is not None:
        require(number <= maximum, f"{label} exceeds schema ceiling {maximum}")
    return number

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
    require_exact_keys(catalog, MODULE_CATALOG_KEYS, "module catalog")
    require(catalog["schema"] == "org.trillionnium.module-catalog.v1",
            "module catalog schema is unsupported")
    require_string(catalog["program_revision"], "module catalog program_revision")
    require_string(catalog["module_definition"], "module catalog module_definition")
    contract_schema = require_object(catalog["contract_schema"], "module catalog contract_schema")
    require_exact_keys(contract_schema, CONTRACT_SCHEMA_KEYS, "module contract schema")
    require(contract_schema["schema"] == "org.trillionnium.module-contract.v1",
            "module contract schema is unsupported")
    require_state_version(contract_schema["version"], "module contract schema.version")
    required_contract_fields = require_string_list(
        contract_schema["required_module_fields"],
        "module contract schema.required_module_fields",
    )
    require(set(required_contract_fields) == MODULE_REQUIRED_FIELDS,
            "module contract required field set is incomplete or drifted")
    resource_fields = require_string_list(
        contract_schema["resource_fields"], "module contract schema.resource_fields"
    )
    require(set(resource_fields) == RESOURCE_KEYS,
            "module contract resource field set is incomplete or drifted")
    slo_fields = require_string_list(
        contract_schema["slo_fields"], "module contract schema.slo_fields"
    )
    require(set(slo_fields) == SLO_KEYS,
            "module contract SLO field set is incomplete or drifted")

    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    actual_default = cargo.get("workspace", {}).get("default-members", [])
    require(actual_default == catalog["default_source_closure"], "Cargo default-members drift from module catalog")
    require_string_list(catalog["default_source_closure"], "module catalog.default_source_closure")
    modules = catalog["modules"]
    require(isinstance(modules, list) and bool(modules), "module catalog.modules must be a non-empty array")
    ids = [require_string(module.get("id"), "module id")
           for module in modules if isinstance(module, dict)]
    require(len(ids) == len(modules), "every module entry must be an object")
    unique(ids, "module id")
    known = set(ids)
    state_owners: dict[str, str] = {}
    graph: dict[str, list[str]] = {}
    path_owners: dict[Path, str] = {}
    for module in modules:
        module_id = module["id"]
        require_exact_keys(module, MODULE_REQUIRED_FIELDS, f"{module_id} module entry")
        require_semver(module["module_version"], f"{module_id}.module_version")
        require_string(module["name"], f"{module_id}.name")
        require_string(module["plane"], f"{module_id}.plane")
        owner = require_string(module["owner_team"], f"{module_id}.owner_team")
        backup = require_string(module["backup_team"], f"{module_id}.backup_team")
        require(owner != backup, f"{module_id} primary and backup teams must differ")
        paths = require_string_list(module["paths"], f"{module_id}.paths")
        for path_text in paths:
            resolved = _repository_path(path_text, f"{module_id}.paths")
            for owned_path, owned_by in path_owners.items():
                require(
                    resolved != owned_path
                    and not resolved.is_relative_to(owned_path)
                    and not owned_path.is_relative_to(resolved),
                    f"module path ownership overlaps: {module_id} and {owned_by}",
                )
            path_owners[resolved] = module_id
        require_string_list(module["responsibilities"], f"{module_id}.responsibilities")
        require_string_list(module["non_goals"], f"{module_id}.non_goals")
        dependencies = require_string_list(module["dependencies"], f"{module_id}.dependencies", allow_empty=True)
        graph[module_id] = dependencies
        for dependency in dependencies:
            require(dependency in known, f"{module['id']} references unknown dependency {dependency}")
            require(dependency != module["id"], f"{module['id']} depends on itself")
        state_owned = require_string_list(module["state_owned"], f"{module_id}.state_owned", allow_empty=True)
        ordering_keys = require_string_list(module["ordering_keys"], f"{module_id}.ordering_keys")
        for state in state_owned:
            require(state not in state_owners, f"state {state!r} has multiple owners: {state_owners.get(state)} and {module['id']}")
            state_owners[state] = module_id

        verify_module_contract(module, ordering_keys, state_owned)
        require_string(module["maturity"], f"{module_id}.maturity")
        require_string_list(module["open_gaps"], f"{module_id}.open_gaps", allow_empty=True)

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


def verify_module_contract(module: dict[str, Any], ordering_keys: list[str], state_owned: list[str]) -> None:
    """Validate the concrete, non-placeholder contract carried by one module."""

    module_id = module["id"]
    concurrency = require_object(module["concurrency_contract"], f"{module_id}.concurrency_contract")
    require_exact_keys(concurrency, CONCURRENCY_KEYS, f"{module_id}.concurrency_contract")
    admission_resource = require_string(
        concurrency["admission_resource"], f"{module_id}.concurrency_contract.admission_resource"
    )
    require(admission_resource.startswith("resource_contract."),
            f"{module_id}.concurrency_contract.admission_resource must reference resource_contract")
    require_string(concurrency["ordering_key"], f"{module_id}.concurrency_contract.ordering_key")
    require(concurrency["ordering_key"] in ordering_keys,
            f"{module_id}.concurrency_contract.ordering_key is not declared")
    max_concurrency = require_positive_int(
        concurrency["max_concurrency"], f"{module_id}.concurrency_contract.max_concurrency", 1 << 20
    )
    queue_items = require_positive_int(
        module["resource_contract"]["queue_items"],
        f"{module_id}.resource_contract.queue_items", RESOURCE_MAX["queue_items"],
    )
    require(max_concurrency <= queue_items,
            f"{module_id} concurrency exceeds queue item budget")
    require_string(concurrency["lease_source"], f"{module_id}.concurrency_contract.lease_source")
    require_string(concurrency["lock_scope"], f"{module_id}.concurrency_contract.lock_scope")
    require_string_list(concurrency["slow_paths"], f"{module_id}.concurrency_contract.slow_paths")
    timeout_ms = require_positive_int(
        concurrency["timeout_ms"], f"{module_id}.concurrency_contract.timeout_ms", RESOURCE_MAX["timeout_ms"]
    )
    require(timeout_ms <= module["resource_contract"]["timeout_ms"],
            f"{module_id} concurrency timeout exceeds resource timeout budget")
    for field in ("cancellation", "backpressure", "lease_expiry", "duplicate_conflict"):
        require_string(concurrency[field], f"{module_id}.concurrency_contract.{field}")
    require(concurrency["backpressure"] != "unbounded", f"{module_id} cannot declare unbounded backpressure")
    require("fence" in concurrency["lease_expiry"] or "stop" in concurrency["lease_expiry"],
            f"{module_id} lease expiry must stop or fence authoritative work")

    api = require_object(module["api_contract"], f"{module_id}.api_contract")
    require_exact_keys(api, API_CONTRACT_KEYS, f"{module_id}.api_contract")
    api_version = require_semver(api["version"], f"{module_id}.api_contract.version")
    require(api_version == module["module_version"], f"{module_id} API/module version mismatch")
    api_schema = require_string(api["schema"], f"{module_id}.api_contract.schema")
    require(re.fullmatch(r"org\.[A-Za-z0-9_.-]+\.api\.v[0-9]+", api_schema) is not None,
            f"{module_id}.api_contract.schema is malformed")
    for field in ("inputs", "outputs", "errors"):
        members = require_string_list(api[field], f"{module_id}.api_contract.{field}")
        require(
            all(API_TYPE_RE.fullmatch(member) is not None for member in members),
            f"{module_id}.api_contract.{field} must name concrete versioned schema types",
        )

    state = require_object(module["state_contract"], f"{module_id}.state_contract")
    require_exact_keys(state, STATE_CONTRACT_KEYS, f"{module_id}.state_contract")
    state_version = require_state_version(state["version"], f"{module_id}.state_contract.version")
    state_schema = require_string(state["schema"], f"{module_id}.state_contract.schema")
    require(re.fullmatch(r"org\.[A-Za-z0-9_.-]+\.state\.v[0-9]+", state_schema) is not None,
            f"{module_id}.state_contract.schema is malformed")
    require(state_schema.endswith(f".v{state_version}"), f"{module_id} state schema/version mismatch")
    require(isinstance(state["authoritative"], bool), f"{module_id}.state_contract.authoritative must be boolean")
    require(state["authoritative"] == bool(state_owned),
            f"{module_id} authoritative state flag disagrees with state_owned")
    require_string(state["partition"], f"{module_id}.state_contract.partition")
    require(state["partition"] in ordering_keys,
            f"{module_id}.state_contract.partition must be a declared ordering key")
    require(state["durability"] in {"none", "memory", "journaled", "derived", "external"},
            f"{module_id}.state_contract.durability is invalid")
    retention = require_object(state["retention"], f"{module_id}.state_contract.retention")
    require_exact_keys(retention, STATE_RETENTION_KEYS, f"{module_id}.state_contract.retention")
    require_positive_int(retention["max_items"], f"{module_id}.state_contract.retention.max_items", 1 << 24)
    require_positive_int(retention["max_bytes"], f"{module_id}.state_contract.retention.max_bytes", 1 << 40)
    require_string_list(state["terminal_states"], f"{module_id}.state_contract.terminal_states")

    resources = require_object(module["resource_contract"], f"{module_id}.resource_contract")
    require_exact_keys(resources, RESOURCE_KEYS, f"{module_id}.resource_contract")
    for field, maximum in RESOURCE_MAX.items():
        require_positive_int(resources[field], f"{module_id}.resource_contract.{field}", maximum)
    require(resources["queue_bytes"] <= resources["memory_bytes"],
            f"{module_id} queue byte budget exceeds memory budget")

    slo = require_object(module["slo"], f"{module_id}.slo")
    require_exact_keys(slo, SLO_KEYS, f"{module_id}.slo")
    for field in ("latency_p99_ms", "throughput_per_sec", "recovery_ms", "measurement_window_sec"):
        require_finite_positive(slo[field], f"{module_id}.slo.{field}")
    availability = require_finite_positive(slo["availability_percent"], f"{module_id}.slo.availability_percent", 100.0)
    require(availability <= 100.0, f"{module_id}.slo.availability_percent exceeds 100")

    fault = require_object(module["fault_contract"], f"{module_id}.fault_contract")
    require_exact_keys(fault, FAULT_KEYS, f"{module_id}.fault_contract")
    require_string_list(fault["failure_modes"], f"{module_id}.fault_contract.failure_modes")
    require_string(fault["degraded_state"], f"{module_id}.fault_contract.degraded_state")
    require_string(fault["recovery"], f"{module_id}.fault_contract.recovery")
    require(fault["uncertain_effect"] == "no_automatic_redispatch",
            f"{module_id} fault contract must prohibit automatic redispatch")

    evidence = require_object(module["evidence_contract"], f"{module_id}.evidence_contract")
    require_exact_keys(evidence, EVIDENCE_KEYS, f"{module_id}.evidence_contract")
    require(LEVEL_RE.fullmatch(require_string(evidence["minimum_level"], f"{module_id}.evidence_contract.minimum_level")) is not None,
            f"{module_id}.evidence_contract.minimum_level is invalid")
    require_string_list(evidence["required_artifacts"], f"{module_id}.evidence_contract.required_artifacts")
    require(evidence["raw_observations"] is True, f"{module_id} evidence must retain raw observations")
    require_string(evidence["claim_ceiling"], f"{module_id}.evidence_contract.claim_ceiling")
    negative_claims = require_string_list(evidence["negative_claims"], f"{module_id}.evidence_contract.negative_claims")
    require("no_automatic_redispatch" in negative_claims,
            f"{module_id} evidence contract must carry the no-redispatch negative claim")

    compatibility = require_object(module["compatibility"], f"{module_id}.compatibility")
    require_exact_keys(compatibility, COMPATIBILITY_KEYS, f"{module_id}.compatibility")
    require_semver(compatibility["api_semver"], f"{module_id}.compatibility.api_semver")
    require(compatibility["api_semver"] == api_version,
            f"{module_id} compatibility/API version mismatch")
    require(compatibility["state_schema"] == state_schema,
            f"{module_id} compatibility/state schema mismatch")
    require(isinstance(compatibility["rolling"], bool), f"{module_id}.compatibility.rolling must be boolean")
    matrix = require_object(compatibility["read_write_matrix"], f"{module_id}.compatibility.read_write_matrix")
    require_exact_keys(matrix, READ_WRITE_KEYS, f"{module_id}.compatibility.read_write_matrix")
    require_string_list(matrix["read"], f"{module_id}.compatibility.read_write_matrix.read")
    require_string_list(matrix["write"], f"{module_id}.compatibility.read_write_matrix.write")
    require(compatibility["unknown_fields"] in {"reject", "preserve"},
            f"{module_id}.compatibility.unknown_fields is invalid")

    migration = require_object(module["migration"], f"{module_id}.migration")
    require_exact_keys(migration, MIGRATION_KEYS, f"{module_id}.migration")
    require_string_list(migration["from_versions"], f"{module_id}.migration.from_versions", allow_empty=True)
    target_version = require_string(migration["to_version"], f"{module_id}.migration.to_version")
    require(re.fullmatch(r"v[0-9]+", target_version) is not None,
            f"{module_id}.migration.to_version must be vN")
    require_string(migration["strategy"], f"{module_id}.migration.strategy")
    require(isinstance(migration["dual_read"], bool), f"{module_id}.migration.dual_read must be boolean")
    require(isinstance(migration["dual_write"], bool), f"{module_id}.migration.dual_write must be boolean")
    if migration["strategy"] == "none":
        require(not migration["dual_read"] and not migration["dual_write"],
                f"{module_id} no-op migration cannot enable dual read/write")
        require(not migration["from_versions"] and target_version == "v1",
                f"{module_id} no-op migration must remain explicitly v1-only")
    else:
        require(module_id in IMPLEMENTED_V2_MIGRATIONS,
                f"{module_id} declares an unsupported migration strategy")
        require(migration["strategy"] == IMPLEMENTED_V2_MIGRATIONS[module_id],
                f"{module_id} migration strategy is not the implemented v2 path")
        require(migration["from_versions"] == ["v1"] and target_version == "v2",
                f"{module_id} migration must bind the v1-to-v2 transition")

    rollback = require_object(module["rollback"], f"{module_id}.rollback")
    require_exact_keys(rollback, ROLLBACK_KEYS, f"{module_id}.rollback")
    require(isinstance(rollback["supported"], bool), f"{module_id}.rollback.supported must be boolean")
    require_string(rollback["procedure"], f"{module_id}.rollback.procedure")
    require(rollback["fail_closed"] is True, f"{module_id} rollback must fail closed")


def verify_module_gap_refs(catalog: dict[str, Any], register: dict[str, Any]) -> None:
    gaps = register.get("gaps")
    require(isinstance(gaps, list), "gap register.gaps must be an array")
    require(all(isinstance(gap, dict) for gap in gaps), "every gap entry must be an object")
    statuses: dict[str, str] = {}
    affected: dict[str, set[str]] = {}
    for gap in gaps:
        gap_id = require_string(gap.get("id"), "gap id")
        status = require_string(gap.get("status"), f"{gap_id}.status")
        modules = require_string_list(gap.get("modules"), f"{gap_id}.modules")
        statuses[gap_id] = status
        affected[gap_id] = set(modules)
    for module in catalog["modules"]:
        module_id = module["id"]
        for gap_id in module["open_gaps"]:
            require(gap_id in statuses, f"{module_id} references unknown open gap {gap_id}")
            require(module_id in affected[gap_id], f"{module_id} open gap {gap_id} does not affect the module")
            require(statuses[gap_id] != "CLOSED", f"{module_id} lists CLOSED gap {gap_id} as open")

def verify_gaps(register: dict[str, Any], module_ids: set[str]) -> set[str]:
    require(register.get("schema") == "org.trillionnium.gap-register.v2",
            "gap register schema is unsupported")
    require_string(register.get("program_revision"), "gap register program_revision")
    statuses = require_string_list(register.get("status_vocabulary"), "gap register.status_vocabulary")
    require("OPEN" in statuses and "CLOSED" in statuses, "gap register status vocabulary is incomplete")
    require_string(register.get("zero_gap_rule"), "gap register.zero_gap_rule")
    gaps = register["gaps"]
    require(isinstance(gaps, list) and bool(gaps), "gap register.gaps must be a non-empty array")
    require(all(isinstance(gap, dict) for gap in gaps), "every gap entry must be an object")
    ids = [require_string(gap.get("id"), "gap id") for gap in gaps]
    unique(ids, "gap id")
    known_status = set(register["status_vocabulary"])
    required_fields = {"id", "priority", "class", "status", "exit_level", "modules", "summary", "acceptance"}
    for gap in gaps:
        require(isinstance(gap, dict), "every gap entry must be an object")
        missing = required_fields - set(gap)
        require(not missing, f"{gap.get('id')} missing gap fields: {sorted(missing)}")
        require_exact_keys(gap, required_fields, f"{gap['id']} gap entry")
        require_string(gap["id"], "gap id")
        require(re.fullmatch(r"P[0-3]", require_string(gap["priority"], f"{gap['id']}.priority")) is not None,
                f"{gap['id']} has invalid priority")
        require_string(gap["class"], f"{gap['id']}.class")
        require(gap["status"] in known_status, f"{gap['id']} has invalid status")
        require(re.fullmatch(r"L[1-6]", gap["exit_level"]) is not None, f"{gap['id']} has invalid exit level")
        require_string_list(gap["modules"], f"{gap['id']}.modules")
        for module in gap["modules"]:
            require(module in module_ids, f"{gap['id']} references unknown module {module}")
        require_string_list(gap["acceptance"], f"{gap['id']}.acceptance")
        require_string(gap["summary"], f"{gap['id']}.summary")
    return set(ids)

def verify_requirements(graph: dict[str, Any], module_ids: set[str], gap_ids: set[str], evidence_ids: set[str], capability_ids: set[str]) -> None:
    require(graph.get("schema") == "org.trillionnium.requirement-graph.v1",
            "requirement graph schema is unsupported")
    require_string(graph.get("program_revision"), "requirement graph program_revision")
    requirements = graph["requirements"]
    require(isinstance(requirements, list) and bool(requirements), "requirement graph must be a non-empty array")
    require(all(isinstance(req, dict) for req in requirements), "every requirement entry must be an object")
    unique([require_string(req.get("id"), "requirement id") for req in requirements], "requirement id")
    for req in requirements:
        require(isinstance(req, dict), "every requirement entry must be an object")
        required = {"id", "capability", "modules", "gaps", "source", "tests", "evidence", "status"}
        require_exact_keys(req, required, f"{req.get('id')} requirement entry")
        require_string(req["id"], "requirement id")
        require(req["capability"] in capability_ids, f"{req['id']} references unknown capability")
        require_string_list(req["modules"], f"{req['id']}.modules")
        for module in req["modules"]:
            require(module in module_ids, f"{req['id']} references unknown module {module}")
        require_string_list(req["gaps"], f"{req['id']}.gaps", allow_empty=True)
        for gap in req["gaps"]:
            require(gap in gap_ids, f"{req['id']} references unknown gap {gap}")
        require_string_list(req["evidence"], f"{req['id']}.evidence", allow_empty=True)
        for evidence in req["evidence"]:
            require(evidence in evidence_ids, f"{req['id']} references unknown evidence {evidence}")
        sources = require_string_list(req["source"], f"{req['id']}.source")
        for source in sources:
            _repository_path(source, f"{req['id']}.source")
        require(req["tests"], f"{req['id']} lacks tests")
        require_string(req["status"], f"{req['id']}.status")
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


EVIDENCE_INDEX_KEYS = {
    "schema", "program_revision", "public_release", "package_schema", "records", "external_levels",
}
PACKAGE_SCHEMA_KEYS = {
    "schema", "version", "binding_schema", "hold_status", "required_binding_fields",
}
EVIDENCE_RECORD_KEYS = {
    "id", "level", "source_commit", "source_tree", "result", "review", "promotable", "claim_ceiling",
    "package",
}
EVIDENCE_PACKAGE_KEYS = {"schema", "version", "status", "binding"}
EVIDENCE_BINDING_META_KEYS = {"schema", "status", "holds"}
EVIDENCE_HOLD_KEYS = {"field", "status", "reason"}
EVIDENCE_BINDING_FIELDS = {
    "program_version", "architecture_version", "protocol_version", "module_versions",
    "repository", "branch", "source_commit", "source_tree", "lockfile", "toolchain",
    "environment", "hardware", "commands", "environment_allowlist", "test_counts",
    "raw_observations", "artifacts", "claim_ceiling", "negative_claims", "producer",
    "operator", "reviewer", "authorization", "timestamps", "retention",
}
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _verify_evidence_binding(
    record: dict[str, Any],
    package: dict[str, Any],
    package_schema: dict[str, Any],
) -> None:
    """Validate one explicit evidence package/binding, including holds.

    The checked-in file is an index, not a substitute for a CI/target
    evidence bundle.  Every unavailable canonical field is nevertheless
    represented as ``null`` plus a typed ``NOT_OBSERVED`` hold; silently
    omitting a field would make the index look stronger than its evidence.
    """

    package_id = record["id"]
    require_exact_keys(package, EVIDENCE_PACKAGE_KEYS, f"{package_id}.package")
    require(package["schema"] == package_schema["schema"], f"{package_id}.package schema mismatch")
    require_state_version(package["version"], f"{package_id}.package.version")
    require(package["version"] == package_schema["version"], f"{package_id}.package version mismatch")
    require(package["status"] in {"OBSERVED", "NOT_OBSERVED"}, f"{package_id}.package.status is invalid")

    binding = require_object(package["binding"], f"{package_id}.package.binding")
    require_exact_keys(
        binding,
        EVIDENCE_BINDING_META_KEYS | set(package_schema["required_binding_fields"]),
        f"{package_id}.package.binding",
    )
    require(binding["schema"] == package_schema["binding_schema"], f"{package_id} binding schema mismatch")
    require(binding["status"] == package["status"], f"{package_id} package/binding status mismatch")
    require(binding["status"] in {"OBSERVED", "NOT_OBSERVED"}, f"{package_id}.binding.status is invalid")

    holds_raw = binding["holds"]
    require(isinstance(holds_raw, list), f"{package_id}.package.binding.holds must be an array")
    hold_fields: set[str] = set()
    for index, hold in enumerate(holds_raw):
        hold = require_object(hold, f"{package_id}.package.binding.holds[{index}]")
        require_exact_keys(hold, EVIDENCE_HOLD_KEYS, f"{package_id}.package.binding.holds[{index}]")
        field = require_string(hold["field"], f"{package_id}.package.binding.holds[{index}].field")
        require(field in EVIDENCE_BINDING_FIELDS, f"{package_id} hold names an unknown field {field}")
        require(field not in hold_fields, f"{package_id} repeats a hold for {field}")
        hold_fields.add(field)
        require(hold["status"] == package_schema["hold_status"], f"{package_id} hold status is not NOT_OBSERVED")
        require_string(hold["reason"], f"{package_id}.package.binding.holds[{index}].reason")

    required_fields = set(package_schema["required_binding_fields"])
    require(required_fields == EVIDENCE_BINDING_FIELDS, "evidence package required field set is incomplete or drifted")
    for field in required_fields:
        value = binding[field]
        if value is None:
            require(field in hold_fields, f"{package_id}.{field} is null without a NOT_OBSERVED hold")
        else:
            require(field not in hold_fields, f"{package_id}.{field} is observed but still marked NOT_OBSERVED")
    if package["status"] == "NOT_OBSERVED":
        require(bool(hold_fields), f"{package_id} NOT_OBSERVED package has no holds")
    else:
        # An observed package is complete by definition.  Allowing an
        # ``OBSERVED`` status alongside null fields would silently turn a
        # partial index row into promotion-capable evidence.
        require(not hold_fields, f"{package_id} OBSERVED package cannot carry NOT_OBSERVED holds")
        require(
            all(binding[field] is not None for field in required_fields),
            f"{package_id} OBSERVED package has incomplete binding fields",
        )

    # The two identities represented in the index row are always required and
    # must be copied into the binding; this prevents a package from silently
    # describing a different checkout.
    for field in ("source_commit", "source_tree"):
        value = binding[field]
        require(isinstance(value, str) and HEX40_RE.fullmatch(value) is not None,
                f"{package_id}.package.binding.{field} must be a 40-digit lowercase hash")
        require(value == record[field], f"{package_id} package/{field} identity mismatch")
    require(binding["claim_ceiling"] == record["claim_ceiling"], f"{package_id} package claim ceiling mismatch")
    negative_claims = require_string_list(
        binding["negative_claims"], f"{package_id}.package.binding.negative_claims"
    )
    require(bool(negative_claims), f"{package_id} package must carry negative claims")

    # Validate concrete values whenever a future observed package supplies
    # them.  Current checked-in rows intentionally leave these fields null and
    # carry explicit holds instead of inventing runner/device facts.
    for field in ("program_version", "architecture_version", "protocol_version", "repository", "branch"):
        if binding[field] is not None:
            require_string(binding[field], f"{package_id}.package.binding.{field}")
    if binding["module_versions"] is not None:
        versions = require_object(binding["module_versions"], f"{package_id}.package.binding.module_versions")
        require(bool(versions), f"{package_id}.module_versions must not be empty")
        for module_id, version in versions.items():
            require_string(module_id, f"{package_id}.module_versions key")
            require_semver(version, f"{package_id}.module_versions.{module_id}")
    for field in ("lockfile", "toolchain", "environment", "hardware", "test_counts", "raw_observations", "timestamps", "retention"):
        if binding[field] is not None:
            require_object(binding[field], f"{package_id}.package.binding.{field}")
    for field in ("commands", "environment_allowlist"):
        if binding[field] is not None:
            require_string_list(binding[field], f"{package_id}.package.binding.{field}")
    if binding["artifacts"] is not None:
        artifacts = binding["artifacts"]
        require(isinstance(artifacts, list), f"{package_id}.package.binding.artifacts must be an array")
        for index, artifact in enumerate(artifacts):
            artifact = require_object(artifact, f"{package_id}.artifacts[{index}]")
            require_exact_keys(artifact, {"name", "size_bytes", "sha256"}, f"{package_id}.artifacts[{index}]")
            require_string(artifact["name"], f"{package_id}.artifacts[{index}].name")
            require_positive_int(artifact["size_bytes"], f"{package_id}.artifacts[{index}].size_bytes")
            require(isinstance(artifact["sha256"], str) and HEX64_RE.fullmatch(artifact["sha256"]) is not None,
                    f"{package_id}.artifacts[{index}].sha256 must be a 64-digit lowercase hash")
    for field in ("producer", "operator", "reviewer", "authorization"):
        if binding[field] is not None:
            require_string(binding[field], f"{package_id}.package.binding.{field}")


def verify_evidence_index(index: dict[str, Any]) -> set[str]:
    require_exact_keys(index, EVIDENCE_INDEX_KEYS, "evidence index")
    require(index.get("schema") == "org.trillionnium.evidence-index.v1",
            "evidence index schema is unsupported")
    require_string(index.get("program_revision"), "evidence index program_revision")
    require(isinstance(index.get("public_release"), bool), "evidence index public_release must be boolean")
    package_schema = require_object(index.get("package_schema"), "evidence index.package_schema")
    require_exact_keys(package_schema, PACKAGE_SCHEMA_KEYS, "evidence index.package_schema")
    require(package_schema["schema"] == "org.trillionnium.evidence-package.v1",
            "evidence package schema is unsupported")
    require_state_version(package_schema["version"], "evidence index.package_schema.version")
    require(package_schema["version"] == "1", "evidence package schema version is unsupported")
    require(package_schema["binding_schema"] == "org.trillionnium.evidence-binding.v1",
            "evidence binding schema is unsupported")
    require(package_schema["hold_status"] == "NOT_OBSERVED",
            "evidence package hold status must be NOT_OBSERVED")
    binding_fields = require_string_list(
        package_schema["required_binding_fields"],
        "evidence index.package_schema.required_binding_fields",
    )
    require(set(binding_fields) == EVIDENCE_BINDING_FIELDS,
            "evidence package required binding field set is incomplete or drifted")
    external_levels = require_object(index["external_levels"], "evidence index.external_levels")
    require(set(external_levels) == {"L2", "L3", "L4", "L5", "L6"},
            "evidence index external level set is incomplete or drifted")
    for level, description in external_levels.items():
        require_string(description, f"evidence index.external_levels.{level}")
    records = index.get("records")
    require(isinstance(records, list) and bool(records), "evidence index.records must be a non-empty array")
    ids: list[str] = []
    for record in records:
        require(isinstance(record, dict), "every evidence record must be an object")
        require_exact_keys(record, EVIDENCE_RECORD_KEYS, f"{record.get('id')} evidence record")
        evidence_id = require_string(record["id"], "evidence id")
        ids.append(evidence_id)
        level = require_string(record["level"], f"{evidence_id}.level")
        require(re.fullmatch(r"L[0-6]", level) is not None, f"{evidence_id} has invalid level")
        for field in ("source_commit", "source_tree"):
            value = record[field]
            require(isinstance(value, str) and HEX40_RE.fullmatch(value) is not None,
                    f"{evidence_id}.{field} must be a 40-digit lowercase commit/tree hash")
        require_string(record["result"], f"{evidence_id}.result")
        require_string(record["review"], f"{evidence_id}.review")
        require(isinstance(record["promotable"], bool), f"{evidence_id}.promotable must be boolean")
        require_string(record["claim_ceiling"], f"{evidence_id}.claim_ceiling")
        if record["promotable"]:
            require(level != "L0", f"{evidence_id} cannot be promotable at L0")
        _verify_evidence_binding(record, require_object(record["package"], f"{evidence_id}.package"), package_schema)
        if record["promotable"]:
            require(record["package"]["status"] == "OBSERVED",
                    f"{evidence_id} cannot be promotable with an unobserved package")
    unique(ids, "evidence id")
    return set(ids)

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

        evidence_ids = verify_evidence_index(evidence)
        module_ids = verify_modules(catalog)
        gap_ids = verify_gaps(gaps, module_ids)
        verify_module_gap_refs(catalog, gaps)
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
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        # A malformed authority document must fail closed with a stable
        # verifier result rather than leaking a traceback (or accidentally
        # continuing after a missing structural field).
        print(f"G1 documentation verification failed: malformed authority data: {error}", file=sys.stderr)
        return 1
    print("G1 documentation verification passed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
