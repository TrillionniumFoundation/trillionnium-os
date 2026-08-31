#!/usr/bin/env python3
"""Verify the exact owner-open Python release-candidate source selection."""
from __future__ import annotations

import argparse
import ast
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
    # Contract paths are untrusted JSON strings.  In addition to ordinary
    # missing/racing filesystem errors, pathlib can raise ValueError for an
    # embedded NUL and RuntimeError for a symlink loop.  Treat all of these as
    # a verification error instead of allowing the verifier itself to abort.
    except (OSError, ValueError, RuntimeError) as error:
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


def local_python_imports(
    root: Path,
    relative: str,
    text: str,
    known_paths: set[str],
    report: Report,
) -> list[str]:
    try:
        tree = ast.parse(text, filename=relative)
    except SyntaxError as error:
        report.errors.append(f"selected Python path does not parse: {relative}: {error}")
        return []

    source = Path(relative)
    discovered: set[str] = set()

    def add_module(module: str, level: int = 0) -> None:
        if not module:
            return
        module_path = Path(*module.split("."))
        candidates: list[Path] = []
        if level:
            parent = source.parent
            for _ in range(level - 1):
                parent = parent.parent
            candidates.append((parent / module_path).with_suffix(".py"))
        else:
            candidates.extend(
                (
                    source.parent / f"{module.rsplit('.', 1)[-1]}.py",
                    module_path.with_suffix(".py"),
                )
            )
        for candidate in candidates:
            normalized = candidate.as_posix()
            if normalized in known_paths or os.path.lexists(root / candidate):
                discovered.add(normalized)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add_module(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                add_module(node.module, node.level)
            elif node.level:
                for alias in node.names:
                    add_module(alias.name, node.level)
    discovered.discard(relative)
    return sorted(discovered)


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

    helpers = string_list(
        contract.get("implementation_helpers"), "implementation_helpers", report
    )
    tests = string_list(contract.get("selected_tests"), "selected_tests", report)
    workflows = string_list(contract.get("selected_workflows"), "selected_workflows", report)
    drafts = string_list(contract.get("superseded_drafts"), "superseded_drafts", report)
    roots = string_list(contract.get("release_reference_roots"), "release_reference_roots", report)
    forbidden = string_list(
        contract.get("forbidden_release_reference_tokens"),
        "forbidden_release_reference_tokens",
        report,
    )
    selected_set = set(selected_paths)
    helper_set = set(helpers)
    draft_set = set(drafts)
    selected_drafts = sorted(selected_set & draft_set)
    if selected_drafts:
        report.errors.append(
            f"selected paths also appear as drafts: {selected_drafts}"
        )
    selected_helpers = sorted(selected_set & helper_set)
    if selected_helpers:
        report.errors.append(
            f"selected paths also appear as implementation helpers: {selected_helpers}"
        )
    helper_drafts = sorted(helper_set & draft_set)
    if helper_drafts:
        report.errors.append(
            f"implementation helpers also appear as drafts: {helper_drafts}"
        )

    checked: dict[str, str] = {}
    for relative in [*selected_paths, *helpers, *tests, *workflows, *roots]:
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

    declared_python = selected_set | helper_set
    known_python = declared_python | draft_set
    import_closure: dict[str, list[str]] = {}
    for relative in [*selected_paths, *helpers]:
        if not relative.endswith(".py"):
            continue
        path = safe_file(root, relative, report)
        if path is None:
            continue
        text = read_text(path, relative, report)
        if text is None:
            continue
        imports = local_python_imports(root, relative, text, known_python, report)
        import_closure[relative] = imports
        for imported in imports:
            if imported in draft_set:
                report.errors.append(
                    f"selected Python closure imports superseded draft: "
                    f"{relative} -> {imported}"
                )
            elif imported not in declared_python:
                report.errors.append(
                    f"selected Python closure imports undeclared local module: "
                    f"{relative} -> {imported}"
                )

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
        "implementation_helper_count": len(helpers),
        "import_closure": import_closure,
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
