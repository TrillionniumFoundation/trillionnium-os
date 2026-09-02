#!/usr/bin/env python3
"""Fail-closed verifier for detailed Trillionnium OS module documentation."""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

INDEX_KEYS = {
    "schema", "program_revision", "status", "catalog_path",
    "budget_provenance_path", "required_sections",
    "minimum_document_bytes", "modules",
}
INDEX_ENTRY_KEYS = {"id", "doc_path"}
PROVENANCE_KEYS = {
    "schema", "program_revision", "status", "activation_mode", "measured",
    "catalog_fields", "workload_profiles", "qualification_rule", "modules",
}
PROVENANCE_ENTRY_KEYS = {
    "id", "classification", "measured", "sample_count", "evidence_id",
    "measurement_environment", "last_calibrated_at", "activation",
}
EDITORIAL = re.compile(r"\b(?:TODO|TBD|FIXME|PLACEHOLDER)\b|same\s+as\s+above", re.I)


class VerificationError(Exception):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise VerificationError(message)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON member {key!r}")
        value[key] = item
    return value


def _constant(value: str) -> None:
    raise VerificationError(f"non-finite JSON number {value}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (OSError, ValueError) as error:
        raise VerificationError(f"{path} is not strict JSON: {error}") from error
    require(isinstance(value, dict), f"{path} root must be an object")
    return value


def exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    actual = set(value)
    require(
        actual == keys,
        f"{label} keys drift; missing={sorted(keys-actual)}, extra={sorted(actual-keys)}",
    )


def string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} must be a string")
    require("\x00" not in value, f"{label} contains NUL")
    return value


def strings(value: Any, label: str, *, empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    require(empty or bool(value), f"{label} must not be empty")
    result = [string(item, f"{label}[{i}]") for i, item in enumerate(value)]
    duplicates = [item for item, count in Counter(result).items() if count > 1]
    require(not duplicates, f"{label} duplicates: {duplicates}")
    return result


def repo_path(root: Path, value: Any, label: str) -> Path:
    text = string(value, label)
    pure = PurePosixPath(text)
    require(not pure.is_absolute(), f"{label} must be relative")
    require("." not in pure.parts and ".." not in pure.parts, f"{label} is not normalized")
    require("\\" not in text and text == pure.as_posix(), f"{label} is not POSIX-normalized")
    candidate = root.joinpath(*pure.parts)
    resolved = candidate.resolve(strict=False)
    require(resolved.is_relative_to(root.resolve()), f"{label} escapes repository")
    cursor = candidate
    while cursor != root and cursor.exists():
        require(not cursor.is_symlink(), f"{label} traverses symlink {cursor}")
        cursor = cursor.parent
    return candidate


def catalog_modules(catalog: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, Any]]]:
    value = catalog.get("modules")
    require(isinstance(value, list) and bool(value), "catalog.modules must be non-empty")
    order: list[str] = []
    mapped: dict[str, dict[str, Any]] = {}
    for i, module in enumerate(value):
        require(isinstance(module, dict), f"catalog.modules[{i}] must be an object")
        module_id = string(module.get("id"), f"catalog.modules[{i}].id")
        require(module_id not in mapped, f"duplicate catalog module {module_id}")
        order.append(module_id)
        mapped[module_id] = module
    return order, mapped


def verify_headings(text: str, headings: list[str], module_id: str) -> None:
    positions = []
    for heading in headings:
        require(text.count(heading) == 1, f"{module_id} must contain {heading!r} exactly once")
        positions.append(text.index(heading))
    require(positions == sorted(positions), f"{module_id} section order drifted")


def verify_provenance(path: Path, module_order: list[str]) -> None:
    value = load_json(path)
    exact_keys(value, PROVENANCE_KEYS, "resource provenance")
    require(value["schema"] == "org.trillionnium.resource-budget-provenance.v1", "bad provenance schema")
    require(value["status"] == "PROVISIONAL_SOURCE_CEILINGS_UNMEASURED", "provenance must be unmeasured")
    require(value["activation_mode"] == "OBSERVE_ONLY", "budget activation must be observe-only")
    require(value["measured"] is False, "budget provenance claims measurement")
    require(value["catalog_fields"] == ["resource_contract", "slo"], "catalog field scope drifted")
    require(
        strings(value["workload_profiles"], "workload_profiles")
        == [f"WL-{i:02d}" for i in range(1, 13)],
        "workload profile set drifted",
    )
    string(value["program_revision"], "provenance.program_revision")
    string(value["qualification_rule"], "provenance.qualification_rule")
    entries = value["modules"]
    require(isinstance(entries, list), "provenance.modules must be an array")
    ids: list[str] = []
    for i, entry in enumerate(entries):
        require(isinstance(entry, dict), f"provenance.modules[{i}] must be an object")
        exact_keys(entry, PROVENANCE_ENTRY_KEYS, f"provenance.modules[{i}]")
        module_id = string(entry["id"], f"provenance.modules[{i}].id")
        ids.append(module_id)
        require(
            entry == {
                "id": module_id,
                "classification": "ADMISSION_CEILING_AND_PROVISIONAL_OBJECTIVE",
                "measured": False,
                "sample_count": 0,
                "evidence_id": None,
                "measurement_environment": None,
                "last_calibrated_at": None,
                "activation": "OBSERVE_ONLY",
            },
            f"{module_id} has unqualified budget provenance",
        )
    require(ids == module_order, "provenance module order/set drifted")


def verify_component_readmes(root: Path, catalog: dict[str, Any]) -> None:
    try:
        cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"Cargo.toml parse failed: {error}") from error
    members = cargo.get("workspace", {}).get("default-members")
    require(isinstance(members, list) and bool(members), "Cargo default-members missing")
    require(members == catalog.get("default_source_closure"), "Cargo default-members drift from catalog")
    for i, member in enumerate(members):
        directory = repo_path(root, member, f"default-members[{i}]")
        readme = directory / "README.md"
        require(directory.is_dir(), f"default member directory missing: {member}")
        require(readme.is_file() and not readme.is_symlink(), f"default member README missing: {member}")
        require(len(readme.read_bytes()) >= 256, f"default member README truncated: {member}")


def verify_index_and_documents(root: Path) -> None:
    machine = root / "docs/machine"
    catalog = load_json(machine / "module-catalog.v1.json")
    docset = load_json(machine / "doc-set.v1.json")
    index = load_json(machine / "module-document-index.v1.json")
    exact_keys(index, INDEX_KEYS, "module document index")
    require(index["schema"] == "org.trillionnium.module-document-index.v1", "bad index schema")
    require(index["status"] == "ACTIVE_CANDIDATE_SOURCE_DOCUMENTATION", "bad index status")
    require(index["catalog_path"] == "docs/machine/module-catalog.v1.json", "catalog path drifted")
    require(
        index["budget_provenance_path"] == "docs/machine/resource-budget-provenance.v1.json",
        "provenance path drifted",
    )
    headings = strings(index["required_sections"], "required_sections")
    require(len(headings) >= 15, "required section set is too small")
    minimum = index["minimum_document_bytes"]
    require(type(minimum) is int and minimum >= 4096, "minimum_document_bytes is too small")

    order, modules = catalog_modules(catalog)
    entries = index["modules"]
    require(isinstance(entries, list), "index.modules must be an array")
    required_files = set(strings(docset.get("required_files"), "doc-set.required_files"))
    authority = {
        "docs/MODULE_DOCUMENTATION_POLICY.md",
        "docs/machine/module-document-index.v1.json",
        "docs/machine/resource-budget-provenance.v1.json",
    }
    require(authority <= required_files, "module documentation authority is absent from doc-set")
    for relative in authority:
        path = repo_path(root, relative, "authority path")
        require(path.is_file() and not path.is_symlink(), f"authority file missing: {relative}")

    ids: list[str] = []
    paths: list[str] = []
    for i, entry in enumerate(entries):
        require(isinstance(entry, dict), f"index.modules[{i}] must be an object")
        exact_keys(entry, INDEX_ENTRY_KEYS, f"index.modules[{i}]")
        module_id = string(entry["id"], f"index.modules[{i}].id")
        ids.append(module_id)
        require(module_id in modules, f"unknown indexed module {module_id}")
        module = modules[module_id]
        relative = string(entry["doc_path"], f"{module_id}.doc_path")
        require(relative == f"docs/modules/{module_id}.md", f"{module_id} doc path drifted")
        require(relative in required_files, f"{module_id} document is absent from doc-set")
        paths.append(relative)
        path = repo_path(root, relative, f"{module_id}.doc_path")
        require(path.is_file() and not path.is_symlink(), f"{module_id} document missing")
        raw = path.read_bytes()
        require(len(raw) >= minimum, f"{module_id} document truncated")
        text = raw.decode("utf-8")
        verify_headings(text, headings, module_id)
        require(EDITORIAL.search(text) is None, f"{module_id} contains editorial marker")
        required = [
            f"# {module_id} — {module.get('name')}",
            f"Primary owner: `{module.get('owner_team')}`",
            f"Backup owner: `{module.get('backup_team')}`",
            f"Maturity: `{module.get('maturity')}`",
            f"API schema: `{module.get('api_contract', {}).get('schema')}`",
            f"State schema: `{module.get('state_contract', {}).get('schema')}`",
            f"Evidence ceiling: **{module.get('evidence_contract', {}).get('claim_ceiling')}**.",
            "Automatic redispatch: **forbidden**.",
            "Measurement status: **unmeasured until qualified evidence**.",
            "Resource budget authority: `docs/machine/resource-budget-provenance.v1.json`.",
        ]
        for literal in required:
            require(literal in text, f"{module_id} omits {literal!r}")
        for j, source in enumerate(module.get("paths", [])):
            require(repo_path(root, source, f"{module_id}.paths[{j}]").exists(), f"{module_id} source missing")
            require(f"`{source}`" in text, f"{module_id} omits source path {source}")
        for dependency in module.get("dependencies", []):
            require(f"`{dependency}`" in text, f"{module_id} omits dependency {dependency}")
        gaps = module.get("open_gaps", [])
        require(isinstance(gaps, list), f"{module_id}.open_gaps must be an array")
        if gaps:
            for gap in gaps:
                require(gap in text, f"{module_id} omits gap {gap}")
        else:
            require("Open machine gaps: none." in text, f"{module_id} omits no-gap declaration")

    require(ids == order, "index module order/set drifted")
    require(len(paths) == len(set(paths)), "module document paths are not unique")
    actual = {
        str(path.relative_to(root))
        for path in (root / "docs/modules").glob("*.md")
        if path.is_file()
    }
    require(actual == set(paths), "unregistered or missing module documents exist")
    verify_provenance(repo_path(root, index["budget_provenance_path"], "provenance path"), order)
    verify_component_readmes(root, catalog)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    try:
        verify_index_and_documents(args.root)
    except (VerificationError, UnicodeError) as error:
        print(f"module documentation verification failed: {error}", file=sys.stderr)
        return 1
    print("module documentation verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
