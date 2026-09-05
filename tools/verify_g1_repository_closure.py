#!/usr/bin/env python3
"""Fail-closed checks for repository topology omitted by prose-only G1 gates.

This verifier deliberately checks the real checkout. It does not promote
installed-target, Android-image, physical-device, destructive-fault or release
evidence. It closes only repository-controlled topology and documentation
routing defects.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any


class VerificationError(Exception):
    pass


REQUIRED_WORKFLOWS = {
    ".github/workflows/owner-open-r5-tool-loop.yml",
    ".github/workflows/owner-open-r5-governance-readiness.yml",
    ".github/workflows/owner-open-r5-target-evidence-capture.yml",
}
TARGET_WORKFLOW = ".github/workflows/owner-open-r5-target-evidence-capture.yml"
OPERATOR_CONTRACT = "governance/TARGET_EVIDENCE_OPERATOR.md"
LIFECYCLE_KEYS = {
    "schema",
    "program_revision",
    "authority",
    "rule",
    "non_product_members",
}
LIFECYCLE_ENTRY_KEYS = {"path", "classification", "replacement", "reason"}
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SCHEMA_RE = re.compile(r"^org\.[A-Za-z0-9_.-]+\.(?:api|state)\.v[0-9]+$")
TYPE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*_v[0-9]+$")
ROUTE_ONLY_MARKERS = (
    '"status": "ROUTE_ONLY_PENDING_EXTERNAL_ADMISSION"',
    '"candidate_checkout_performed": False',
    '"candidate_code_executed": False',
    '"external_runner_allocated": False',
    '"capture_scheduled": False',
    '"promotion_authorized": False',
    '"public_release": False',
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise VerificationError(f"non-finite JSON number {value}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise VerificationError(f"cannot read strict JSON {path}: {error}") from error
    require(isinstance(value, dict), f"{path} root must be an object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(
        actual == expected,
        f"{label} key drift; missing={sorted(expected-actual)}, extra={sorted(actual-expected)}",
    )


def text(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and bool(value.strip()),
        f"{label} must be non-empty text",
    )
    require("\x00" not in value, f"{label} contains NUL")
    return value


def strings(value: Any, label: str, *, empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    require(empty or bool(value), f"{label} must not be empty")
    result = [text(item, f"{label}[{index}]") for index, item in enumerate(value)]
    duplicates = [item for item, count in Counter(result).items() if count > 1]
    require(not duplicates, f"{label} duplicates: {duplicates}")
    return result


def normalized_repo_path(root: Path, value: Any, label: str) -> tuple[str, Path]:
    raw = text(value, label)
    pure = PurePosixPath(raw)
    require(not pure.is_absolute(), f"{label} must be relative")
    require(
        raw == pure.as_posix() and "\\" not in raw,
        f"{label} must be POSIX-normalized",
    )
    require("." not in pure.parts and ".." not in pure.parts, f"{label} contains traversal")
    path = root.joinpath(*pure.parts)
    resolved_root = root.resolve()
    resolved = path.resolve(strict=False)
    require(resolved.is_relative_to(resolved_root), f"{label} escapes repository")
    return raw, path


def parse_workspace(root: Path) -> tuple[list[str], list[str]]:
    try:
        cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"Cargo.toml cannot be parsed: {error}") from error
    workspace = cargo.get("workspace")
    require(isinstance(workspace, dict), "Cargo.toml [workspace] is missing")
    members = strings(workspace.get("members"), "workspace.members")
    defaults = strings(workspace.get("default-members"), "workspace.default-members")
    require(set(defaults) <= set(members), "default-members are not a subset of members")
    for index, member in enumerate(members):
        _, directory = normalized_repo_path(root, member, f"workspace.members[{index}]")
        require(directory.is_dir(), f"workspace member directory missing: {member}")
        manifest = directory / "Cargo.toml"
        require(
            manifest.is_file() and not manifest.is_symlink(),
            f"workspace member Cargo.toml missing: {member}",
        )
    return members, defaults


def verify_lifecycle(
    root: Path,
    members: list[str],
    defaults: list[str],
    catalog: dict[str, Any],
) -> None:
    lifecycle = load_json(root / "governance/component-lifecycle.v1.json")
    exact_keys(lifecycle, LIFECYCLE_KEYS, "component lifecycle")
    require(
        lifecycle["schema"] == "org.trillionnium.component-lifecycle.v1",
        "unsupported lifecycle schema",
    )
    require(
        lifecycle["authority"] == "docs/machine/module-catalog.v1.json",
        "lifecycle authority drifted",
    )
    text(lifecycle["program_revision"], "lifecycle.program_revision")
    text(lifecycle["rule"], "lifecycle.rule")

    catalog_defaults = strings(
        catalog.get("default_source_closure"), "catalog.default_source_closure"
    )
    require(
        defaults == catalog_defaults,
        "Cargo default-members drift from catalog default_source_closure",
    )

    entries = lifecycle["non_product_members"]
    require(isinstance(entries, list), "non_product_members must be an array")
    excluded: list[str] = []
    member_set = set(members)
    default_set = set(defaults)
    for index, entry in enumerate(entries):
        require(
            isinstance(entry, dict),
            f"non_product_members[{index}] must be an object",
        )
        exact_keys(entry, LIFECYCLE_ENTRY_KEYS, f"non_product_members[{index}]")
        path, _ = normalized_repo_path(
            root, entry["path"], f"non_product_members[{index}].path"
        )
        excluded.append(path)
        require(
            path in member_set,
            f"lifecycle entry is not a Cargo workspace member: {path}",
        )
        require(
            path not in default_set,
            f"active default member is classified non-product: {path}",
        )
        classification = text(entry["classification"], f"{path}.classification")
        require(
            classification.startswith("sealed_"),
            f"non-product classification is not sealed: {path}",
        )
        reason = text(entry["reason"], f"{path}.reason")
        require(len(reason) >= 32, f"non-product reason is too short: {path}")
        replacements = strings(
            entry["replacement"], f"{path}.replacement", empty=True
        )
        for replacement in replacements:
            replacement_path, absolute = normalized_repo_path(
                root, replacement, f"{path}.replacement"
            )
            require(
                absolute.exists(),
                f"replacement path does not exist: {replacement_path}",
            )

    expected_excluded = [member for member in members if member not in default_set]
    require(
        excluded == expected_excluded,
        "non-product lifecycle entries must exactly follow workspace member order",
    )

    for member in defaults:
        readme = root / member / "README.md"
        require(
            readme.is_file() and not readme.is_symlink(),
            f"active component README missing: {member}",
        )
        require(
            len(readme.read_bytes()) >= 256,
            f"active component README is truncated: {member}",
        )


def verify_modules(root: Path, catalog: dict[str, Any]) -> None:
    modules = catalog.get("modules")
    require(
        isinstance(modules, list) and bool(modules),
        "catalog.modules must be a non-empty array",
    )
    index = load_json(root / "docs/machine/module-document-index.v1.json")
    indexed = index.get("modules")
    require(
        isinstance(indexed, list),
        "module document index modules must be an array",
    )
    index_map = {
        text(entry.get("id"), "module index id"): text(
            entry.get("doc_path"), "module index path"
        )
        for entry in indexed
        if isinstance(entry, dict)
    }
    require(
        len(index_map) == len(indexed),
        "module document index contains malformed or duplicate entries",
    )

    ids: list[str] = []
    api_schemas: set[str] = set()
    state_schemas: set[str] = set()
    for position, module in enumerate(modules):
        require(
            isinstance(module, dict),
            f"catalog.modules[{position}] must be an object",
        )
        module_id = text(module.get("id"), f"catalog.modules[{position}].id")
        ids.append(module_id)
        expected_doc = f"docs/modules/{module_id}.md"
        require(
            index_map.get(module_id) == expected_doc,
            f"module document mapping drifted: {module_id}",
        )
        document = root / expected_doc
        require(
            document.is_file() and not document.is_symlink(),
            f"module document missing: {module_id}",
        )
        prose = document.read_text(encoding="utf-8")

        paths = strings(module.get("paths"), f"{module_id}.paths")
        for path_index, source in enumerate(paths):
            source_text, source_path = normalized_repo_path(
                root, source, f"{module_id}.paths[{path_index}]"
            )
            require(
                source_path.exists(),
                f"module source path missing: {source_text}",
            )
            require(
                f"`{source_text}`" in prose,
                f"module prose omits source path {source_text}",
            )

        api = module.get("api_contract")
        state = module.get("state_contract")
        require(
            isinstance(api, dict) and isinstance(state, dict),
            f"{module_id} API/state contract missing",
        )
        api_schema = text(api.get("schema"), f"{module_id}.api.schema")
        state_schema = text(state.get("schema"), f"{module_id}.state.schema")
        require(
            SCHEMA_RE.fullmatch(api_schema) is not None,
            f"malformed API schema: {api_schema}",
        )
        require(
            SCHEMA_RE.fullmatch(state_schema) is not None,
            f"malformed state schema: {state_schema}",
        )
        require(api_schema not in api_schemas, f"duplicate API schema: {api_schema}")
        require(
            state_schema not in state_schemas,
            f"duplicate state schema: {state_schema}",
        )
        api_schemas.add(api_schema)
        state_schemas.add(state_schema)
        require(
            f"`{api_schema}`" in prose,
            f"module document omits API schema: {module_id}",
        )
        require(
            f"`{state_schema}`" in prose,
            f"module document omits state schema: {module_id}",
        )
        for field in ("inputs", "outputs", "errors"):
            values = strings(api.get(field), f"{module_id}.api.{field}")
            for value in values:
                require(
                    TYPE_RE.fullmatch(value) is not None,
                    f"placeholder API type in {module_id}: {value}",
                )
                require(
                    f"`{value}`" in prose,
                    f"module document omits API type {value}",
                )

    require(
        len(ids) == len(set(ids)) == 16,
        "G1 catalog must contain exactly 16 unique modules",
    )
    require(
        set(ids) == set(index_map),
        "catalog and module document index sets differ",
    )


def verify_target_evidence_boundary(target: str, operator: str) -> None:
    """Separate repository routing from independently administered execution."""
    require(
        "workflow_dispatch:" in target,
        "target evidence workflow is not manually dispatched",
    )
    require(
        "pull_request:" not in target and "push:" not in target,
        "target evidence workflow must not run automatically",
    )
    require(
        "runs-on: ubuntu-24.04" in target,
        "target evidence route must use a GitHub-hosted runner",
    )
    require(
        re.search(r"(?i)\bself-hosted\b", target) is None,
        "target evidence route must not allocate a self-hosted runner",
    )
    require(
        "actions/checkout" not in target,
        "target evidence route must not check out candidate code",
    )
    require(
        "GITHUB_WORKSPACE" not in target,
        "target evidence route must not reference candidate workspace content",
    )
    for level in range(2, 7):
        require(
            f"owner-open-r5-l{level}" in target,
            f"target route omits external L{level} lane identity",
        )
    for marker in ROUTE_ONLY_MARKERS:
        require(marker in target, f"target route omits fail-closed marker {marker}")
    require(
        "/usr/bin/python3 -I" in target
        and "unset PYTHONPATH PYTHONHOME" in target,
        "target route does not isolate its hosted interpreter",
    )
    require(
        "synthetic" in target and "False" in target,
        "target route omits synthetic-evidence rejection",
    )

    require(
        "/opt/owner-open-r5/harnesses/<kind>" in operator,
        "operator contract omits fixed external harness root",
    )
    require(
        "/etc/owner-open-r5/attestations/<kind>.json" in operator,
        "operator contract omits fixed external attestation root",
    )
    require(
        "independently administered" in operator,
        "operator contract omits independent administration boundary",
    )
    require(
        "Candidate checkout content" in operator
        and "inert content-addressed data only" in operator,
        "operator contract omits inert-candidate execution boundary",
    )


def verify_workflows(root: Path) -> None:
    for relative in sorted(REQUIRED_WORKFLOWS):
        path = root / relative
        require(
            path.is_file() and not path.is_symlink(),
            f"required permanent workflow missing: {relative}",
        )
        body = path.read_text(encoding="utf-8")
        require(
            "permissions:" in body,
            f"workflow lacks explicit permissions: {relative}",
        )
        require(
            "contents: write" not in body,
            f"workflow may write repository contents: {relative}",
        )
        require(
            "pull-requests: write" not in body,
            f"workflow may mutate pull requests: {relative}",
        )
        require(
            "persist-credentials: false" in body or "actions/checkout" not in body,
            f"workflow checkout persists credentials: {relative}",
        )
        for match in re.finditer(r"uses:\s*([^\s]+)", body):
            action = match.group(1)
            require(
                "@" in action
                and not action.endswith(
                    ("@main", "@master", "@v1", "@v2", "@v3", "@v4")
                ),
                f"workflow action is not commit-pinned: {relative}: {action}",
            )

    target = (root / TARGET_WORKFLOW).read_text(encoding="utf-8")
    operator_path = root / OPERATOR_CONTRACT
    require(
        operator_path.is_file() and not operator_path.is_symlink(),
        "target evidence operator contract is absent or unsafe",
    )
    operator = operator_path.read_text(encoding="utf-8")
    verify_target_evidence_boundary(target, operator)

    governance = (
        root / ".github/workflows/owner-open-r5-governance-readiness.yml"
    ).read_text(encoding="utf-8")
    require(
        "OBSERVE_ONLY" in governance,
        "governance workflow must declare observe-only posture",
    )
    require(
        "merge_pull_request" not in governance
        and "enable_auto_merge" not in governance,
        "governance workflow contains a merge mutation",
    )
    require(
        'report["ready_for_protected_integration"] is False' in governance,
        "governance workflow may imply integration authority",
    )

    compatibility = (
        root / ".github/workflows/owner-open-r5-tool-loop.yml"
    ).read_text(encoding="utf-8")
    require(
        "verify_g1_repository_closure.py" in compatibility,
        "compatibility workflow does not verify the real repository closure",
    )
    require(
        "ALIAS_ONLY_NO_EVIDENCE_AUTHORITY" in compatibility,
        "compatibility workflow omits its non-authorizing claim",
    )


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    members, defaults = parse_workspace(root)
    catalog = load_json(root / "docs/machine/module-catalog.v1.json")
    verify_lifecycle(root, members, defaults, catalog)
    verify_modules(root, catalog)
    verify_workflows(root)
    return {
        "schema": "org.trillionnium.repository-closure-report.v1",
        "status": "PASS_REPOSITORY_CONTROLLED_TOPOLOGY_ONLY",
        "workspace_members": len(members),
        "default_members": len(defaults),
        "non_product_members": len(members) - len(defaults),
        "catalog_modules": len(catalog["modules"]),
        "permanent_workflows": sorted(REQUIRED_WORKFLOWS),
        "target_evidence_posture": "ROUTE_ONLY_EXTERNAL_ADMISSION_REQUIRED",
        "claim_ceiling": "SOURCE_REPOSITORY_TOPOLOGY_ONLY",
        "synthetic": False,
        "zero_gap": False,
        "public_release": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = verify(args.root)
    except (VerificationError, UnicodeError) as error:
        print(f"repository closure verification failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print("repository closure verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
