#!/usr/bin/env python3
"""Verify the exact owner-open Python release-candidate source selection."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

CONTRACT_PATH = Path("docs/contracts/owner-open-r5-selected-python-paths-v1.json")
EXPECTED_SCHEMA = "org.trillionnium.owner-open.selected-python-paths.v1"
MAX_CONTRACT_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024


class DuplicateMember(ValueError):
    pass


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateMember(f"duplicate key {key}")
        value[key] = item
    return value


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def value(self) -> dict[str, Any]:
        return {"ok": self.ok, "errors": self.errors, "facts": self.facts}


def load_json(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_CONTRACT_BYTES
    ):
        raise ValueError(f"{path} is not a bounded real file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ValueError(f"{path} changed while read")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise ValueError(f"invalid {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def string_list(value: Any, label: str, report: Report) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        report.errors.append(f"{label} must be a nonempty string list")
        return []
    if len(value) != len(set(value)):
        report.errors.append(f"{label} contains duplicates")
    return list(value)


def safe_file(root: Path, relative: str, report: Report) -> Path | None:
    path = root / relative
    try:
        resolved_parent = path.parent.resolve(strict=True)
        root_resolved = root.resolve(strict=True)
        if root_resolved != resolved_parent and root_resolved not in resolved_parent.parents:
            report.errors.append(f"selected path escapes repository: {relative}")
            return None
        metadata = path.lstat()
    except OSError as error:
        report.errors.append(f"selected path is missing: {relative}: {error}")
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        report.errors.append(f"selected path is not a real file: {relative}")
        return None
    if metadata.st_size <= 0 or metadata.st_size > MAX_SOURCE_BYTES:
        report.errors.append(f"selected path is empty or oversized: {relative}")
        return None
    return path


def read_text(path: Path, relative: str, report: Report) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        report.errors.append(f"selected path is not UTF-8 text: {relative}: {error}")
        return None


def verify(root: Path) -> Report:
    report = Report()
    try:
        contract = load_json(root / CONTRACT_PATH)
    except (OSError, ValueError) as error:
        report.errors.append(str(error))
        return report
    if contract.get("schema") != EXPECTED_SCHEMA:
        report.errors.append(f"contract schema must be {EXPECTED_SCHEMA}")

    selected_value = contract.get("selected")
    if not isinstance(selected_value, dict) or not selected_value:
        report.errors.append("selected must be a nonempty object")
        selected: dict[str, str] = {}
    else:
        selected = {}
        for role, path in selected_value.items():
            if not isinstance(role, str) or not role or not isinstance(path, str) or not path:
                report.errors.append("selected roles and paths must be nonempty strings")
                continue
            selected[role] = path
    selected_paths = list(selected.values())
    if len(selected_paths) != len(set(selected_paths)):
        report.errors.append("selected paths are not unique")

    tests = string_list(contract.get("selected_tests"), "selected_tests", report)
    workflows = string_list(contract.get("selected_workflows"), "selected_workflows", report)
    drafts = string_list(contract.get("superseded_drafts"), "superseded_drafts", report)
    roots = string_list(contract.get("release_reference_roots"), "release_reference_roots", report)
    forbidden = string_list(
        contract.get("forbidden_release_reference_tokens"),
        "forbidden_release_reference_tokens",
        report,
    )
    overlap = sorted(set(selected_paths) & set(drafts))
    if overlap:
        report.errors.append(f"selected paths also appear as drafts: {overlap}")

    checked: dict[str, str] = {}
    for relative in [*selected_paths, *tests, *workflows, *roots]:
        path = safe_file(root, relative, report)
        if path is None:
            continue
        checked[relative] = str(path.stat().st_size)

    markers = contract.get("required_markers")
    if not isinstance(markers, dict):
        report.errors.append("required_markers must be an object")
        markers = {}
    for relative, required in markers.items():
        if relative not in selected_paths:
            report.errors.append(f"required markers target is not selected: {relative}")
            continue
        required_values = string_list(required, f"required_markers[{relative}]", report)
        path = safe_file(root, relative, report)
        if path is None:
            continue
        text = read_text(path, relative, report)
        if text is None:
            continue
        missing = [marker for marker in required_values if marker not in text]
        if missing:
            report.errors.append(f"selected path {relative} is missing markers: {missing}")

    for relative in roots:
        path = safe_file(root, relative, report)
        if path is None:
            continue
        text = read_text(path, relative, report)
        if text is None:
            continue
        hits = [token for token in forbidden if token in text]
        if hits:
            report.errors.append(
                f"release reference {relative} selects superseded draft tokens: {hits}"
            )

    report.facts = {
        "revision": contract.get("revision"),
        "selected": selected,
        "selected_count": len(selected),
        "test_count": len(tests),
        "workflow_count": len(workflows),
        "superseded_count": len(drafts),
        "checked_files": checked,
    }
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    arguments = parse_args(argv)
    report = verify(arguments.root)
    if arguments.json:
        print(json.dumps(report.value(), ensure_ascii=False, sort_keys=True, indent=2))
    elif report.ok:
        print(
            "PASS_OWNER_OPEN_SELECTED_PATHS "
            f"selected={report.facts.get('selected_count', 0)}"
        )
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
