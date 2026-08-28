#!/usr/bin/env python3
"""Verify the exact release Root Linux payload staging/image source selection."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import stat
import sys
from typing import Any

CONTRACT = Path("docs/contracts/owner-open-r5-rootfs-payload-selection-v1.json")
EXPECTED_SCHEMA = "org.trillionnium.owner-open.rootfs-payload-selection.v1"
MAX_BYTES = 16 * 1024 * 1024


class DuplicateMember(ValueError):
    pass


def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise DuplicateMember(f"duplicate key {key}")
        result[key] = value
    return result


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def value(self) -> dict[str, Any]:
        return {"ok": self.ok, "errors": self.errors, "facts": self.facts}


def load_contract(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > MAX_BYTES
    ):
        raise ValueError("Root Linux payload selection contract is not a bounded real file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ValueError("Root Linux payload selection contract changed while read")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise ValueError(f"invalid Root Linux payload selection contract: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("Root Linux payload selection contract must contain an object")
    return value


def string_list(value: Any, label: str, report: Report) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        report.errors.append(f"{label} must be a string list")
        return []
    if len(value) != len(set(value)):
        report.errors.append(f"{label} contains duplicates")
    return list(value)


def safe_file(root: Path, relative: str, label: str, report: Report) -> Path | None:
    path = root / relative
    try:
        root_resolved = root.resolve(strict=True)
        parent = path.parent.resolve(strict=True)
        if parent != root_resolved and root_resolved not in parent.parents:
            report.errors.append(f"{label} escapes repository: {relative}")
            return None
        metadata = path.lstat()
    except OSError as error:
        report.errors.append(f"{label} is missing: {relative}: {error}")
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        report.errors.append(f"{label} is not a real file: {relative}")
        return None
    if metadata.st_size <= 0 or metadata.st_size > MAX_BYTES:
        report.errors.append(f"{label} is empty or oversized: {relative}")
        return None
    return path


def read_text(path: Path, relative: str, report: Report) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        report.errors.append(f"selected file is not UTF-8: {relative}: {error}")
        return None


def verify(root: Path) -> Report:
    report = Report()
    try:
        contract = load_contract(root / CONTRACT)
    except (OSError, ValueError) as error:
        report.errors.append(str(error))
        return report
    if contract.get("schema") != EXPECTED_SCHEMA:
        report.errors.append(f"contract schema must be {EXPECTED_SCHEMA}")

    raw_selected = contract.get("selected")
    if not isinstance(raw_selected, dict) or not raw_selected:
        report.errors.append("selected must be a nonempty object")
        selected: dict[str, str] = {}
    else:
        selected = {}
        for role, relative in raw_selected.items():
            if not isinstance(role, str) or not role or not isinstance(relative, str) or not relative:
                report.errors.append("selected roles and paths must be nonempty strings")
                continue
            selected[role] = relative
    paths = list(selected.values())
    if len(paths) != len(set(paths)):
        report.errors.append("selected Root Linux payload paths are not unique")

    helpers = string_list(
        contract.get("implementation_helpers"), "implementation_helpers", report
    )
    drafts = string_list(contract.get("superseded_drafts"), "superseded_drafts", report)
    roots = string_list(
        contract.get("release_reference_roots"), "release_reference_roots", report
    )
    forbidden = string_list(
        contract.get("forbidden_release_reference_tokens"),
        "forbidden_release_reference_tokens",
        report,
    )
    overlap = sorted(set(paths) & set(drafts))
    if overlap:
        report.errors.append(f"selected payload paths are also superseded: {overlap}")

    checked: dict[str, int] = {}
    for relative in [*paths, *helpers, *roots]:
        path = safe_file(root, relative, "payload selection path", report)
        if path is not None:
            checked[relative] = path.stat().st_size

    markers = contract.get("required_markers")
    if not isinstance(markers, dict):
        report.errors.append("required_markers must be an object")
        markers = {}
    for relative, raw_markers in markers.items():
        if relative not in paths:
            report.errors.append(f"required marker target is not selected: {relative}")
            continue
        required = string_list(raw_markers, f"required_markers[{relative}]", report)
        path = safe_file(root, relative, "required marker target", report)
        if path is None:
            continue
        text = read_text(path, relative, report)
        if text is None:
            continue
        missing = [marker for marker in required if marker not in text]
        if missing:
            report.errors.append(f"selected path {relative} is missing markers: {missing}")

    builder_relative = selected.get("image_builder")
    helper_relative = helpers[0] if helpers else None
    if builder_relative and helper_relative:
        builder_path = safe_file(root, builder_relative, "selected image builder", report)
        if builder_path is not None:
            text = read_text(builder_path, builder_relative, report)
            helper_module = Path(helper_relative).stem
            if text is not None and f"import {helper_module} as base" not in text:
                report.errors.append("selected image builder does not bind the reviewed helper")

    for relative in roots:
        path = safe_file(root, relative, "release reference root", report)
        if path is None:
            continue
        text = read_text(path, relative, report)
        if text is None:
            continue
        hits = [token for token in forbidden if token in text]
        if hits:
            report.errors.append(
                f"release reference {relative} selects superseded payload tokens: {hits}"
            )

    report.facts = {
        "revision": contract.get("revision"),
        "selected": selected,
        "selected_count": len(selected),
        "helper_count": len(helpers),
        "superseded_count": len(drafts),
        "checked_files": checked,
        "claim_ceiling": contract.get("claim_ceiling"),
    }
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = verify(args.root)
    if args.json:
        print(json.dumps(report.value(), ensure_ascii=False, sort_keys=True, indent=2))
    elif report.ok:
        print(
            "PASS_OWNER_OPEN_ROOTFS_PAYLOAD_SELECTION "
            f"selected={report.facts.get('selected_count', 0)}"
        )
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
