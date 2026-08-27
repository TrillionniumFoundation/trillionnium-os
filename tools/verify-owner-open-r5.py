#!/usr/bin/env python3
"""Verify the owner-open R5 source graph, plan/status binding, and known Android hold.

This verifier is deliberately a source/graph gate. It never promotes source
presence to host, image, device, fault, or release evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tomllib
from typing import Any

CONTRACT = Path("docs/contracts/owner-open-forbidden-default-graph-v2.json")
PLAN = Path("docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md")
STATUS = Path("docs/status/owner-open-r5-status.json")
TRACEABILITY = Path("docs/status/owner-open-r5-traceability.tsv")


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.facts: dict[str, Any] = {}

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def dependency_names(manifest: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = manifest.get(section, {})
        if isinstance(value, dict):
            result.update(str(item) for item in value)
    target = manifest.get("target", {})
    if isinstance(target, dict):
        for config in target.values():
            if not isinstance(config, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = config.get(section, {})
                if isinstance(value, dict):
                    result.update(str(item) for item in value)
    return result


def verify(root: Path, strict_android: bool = False) -> Report:
    report = Report()
    try:
        contract = read_json(root / CONTRACT)
        status = read_json(root / STATUS)
        workspace = read_toml(root / "Cargo.toml")
        plan_text = (root / PLAN).read_text(encoding="utf-8")
        traceability_text = (root / TRACEABILITY).read_text(encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        report.errors.append(f"cannot parse R5 verification input: {error}")
        return report

    revision = contract.get("revision")
    report.check(revision == "2026-08-28-r5", "R5 graph revision must be 2026-08-28-r5")
    report.check(status.get("plan_revision") == revision, "R5 status revision does not match graph contract")
    report.check(str(revision) in plan_text, "R5 plan does not contain the machine revision")
    report.check(
        "ACTIVE — the only implementation sequencing and closeout plan" in plan_text,
        "R5 plan authority statement is missing",
    )
    report.check(
        traceability_text.startswith("requirement_id\twork_package\t"),
        "R5 traceability header is missing or malformed",
    )

    ws = workspace.get("workspace")
    if not isinstance(ws, dict):
        report.errors.append("Cargo.toml has no [workspace] table")
        return report
    members = set(str(value) for value in ws.get("members", []))
    defaults = set(str(value) for value in ws.get("default-members", []))
    cargo = contract.get("cargo")
    if not isinstance(cargo, dict):
        report.errors.append("R5 graph cargo section is not an object")
        return report

    required_members = set(str(value) for value in cargo.get("required_workspace_members", []))
    required_defaults = set(str(value) for value in cargo.get("required_default_members", []))
    allowed_defaults = set(str(value) for value in cargo.get("allowed_default_members", []))
    forbidden_defaults = set(str(value) for value in cargo.get("forbidden_default_members", []))

    report.check(required_members <= members, "required R5 workspace members are absent: " + ", ".join(sorted(required_members - members)))
    report.check(required_defaults <= defaults, "required R5 default members are absent: " + ", ".join(sorted(required_defaults - defaults)))
    report.check(not (defaults & forbidden_defaults), "forbidden legacy default members are present: " + ", ".join(sorted(defaults & forbidden_defaults)))
    report.check(defaults == allowed_defaults, "Cargo default-members drifted from the exact R5 closure: " + ", ".join(sorted(defaults ^ allowed_defaults)))

    forbidden_dependencies = set(str(value) for value in cargo.get("forbidden_internal_dependencies", []))
    package_specs = cargo.get("owner_open_packages", [])
    if not isinstance(package_specs, list):
        report.errors.append("owner_open_packages must be a list")
        return report

    package_facts: dict[str, list[str]] = {}
    marker_hits: list[str] = []
    for spec in package_specs:
        if not isinstance(spec, dict):
            report.errors.append("owner_open_packages entry is not an object")
            continue
        path = Path(str(spec.get("path", "")))
        manifest_path = root / path / "Cargo.toml"
        report.check(manifest_path.is_file(), f"owner-open package manifest is absent: {manifest_path}")
        if not manifest_path.is_file():
            continue
        manifest = read_toml(manifest_path)
        dependencies = dependency_names(manifest)
        package_facts[str(path)] = sorted(dependencies)
        leaked = dependencies & forbidden_dependencies
        report.check(not leaked, f"{path} imports forbidden legacy dependencies: " + ", ".join(sorted(leaked)))
        allowed_internal = set(str(value) for value in spec.get("allowed_internal_dependencies", []))
        actual_internal = {value for value in dependencies if value.startswith("trillionnium-")}
        report.check(
            actual_internal <= allowed_internal,
            f"{path} has an unreviewed owner-open internal edge: " + ", ".join(sorted(actual_internal - allowed_internal)),
        )
        source_root = root / path / "src"
        if source_root.is_dir():
            for source in sorted(source_root.rglob("*.rs")):
                text = source.read_text(encoding="utf-8")
                for marker in cargo.get("forbidden_source_markers", []):
                    if str(marker) in text:
                        marker_hits.append(f"{source.relative_to(root)}:{marker}")

    report.check(not marker_hits, "owner-open source contains forbidden legacy markers: " + ", ".join(marker_hits))

    allowed_status = {
        "NOT_STARTED",
        "SPEC_ONLY",
        "SOURCE_IMPLEMENTED",
        "HOST_TESTED",
        "IMAGE_INCLUDED",
        "DEVICE_OBSERVED",
        "FAULT_TESTED",
        "RELEASE_QUALIFIED",
    }
    packages = status.get("work_packages", [])
    report.check(isinstance(packages, list), "R5 status work_packages must be a list")
    if isinstance(packages, list):
        seen: set[str] = set()
        for item in packages:
            if not isinstance(item, dict):
                report.errors.append("R5 status work-package entry is not an object")
                continue
            identifier = str(item.get("id", ""))
            report.check(identifier and identifier not in seen, f"duplicate or empty R5 work-package id: {identifier}")
            seen.add(identifier)
            report.check(item.get("status") in allowed_status, f"invalid status level for {identifier}")
            evidence = str(item.get("latest_evidence_level", ""))
            report.check(evidence in {"L0", "L1", "L2", "L3", "L4", "L5", "L6"}, f"invalid evidence level for {identifier}")
        report.check(seen == {f"W{index}" for index in range(8)}, "R5 status must contain exactly W0-W7")

    report.check(status.get("public_release") is False, "R5 source branch must not claim a public release")
    negative = status.get("not_claimed", [])
    report.check(isinstance(negative, list) and negative, "R5 status must carry explicit negative claims")

    android = contract.get("android", {})
    android_hits: list[str] = []
    if isinstance(android, dict):
        overlay = root / str(android.get("audit_overlay_path", ""))
        if overlay.is_file():
            text = overlay.read_text(encoding="utf-8")
            android_hits = sorted(
                marker
                for marker in {str(value) for value in android.get("forbidden_owner_open_packages", [])}
                if marker in text
            )
            if android_hits:
                message = "Android overlay still selects forbidden owner-open nodes: " + ", ".join(android_hits)
                if strict_android:
                    report.errors.append(message)
                else:
                    report.warn(message)
        else:
            report.warn(f"Android audit overlay is unavailable: {overlay}")
    else:
        report.errors.append("R5 graph android section is not an object")

    report.facts.update(
        {
            "workspace_members": sorted(members),
            "default_members": sorted(defaults),
            "owner_open_package_dependencies": package_facts,
            "forbidden_source_marker_hits": marker_hits,
            "android_forbidden_package_hits": android_hits,
        }
    )
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--strict-android", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = verify(args.root.resolve(), strict_android=args.strict_android)
    payload = {
        "ok": not report.errors,
        "errors": report.errors,
        "warnings": report.warnings,
        "facts": report.facts,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for message in report.errors:
            print(f"ERROR: {message}", file=sys.stderr)
        for message in report.warnings:
            print(f"WARN: {message}", file=sys.stderr)
        if not report.errors:
            print("owner-open R5 source graph verified")
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
