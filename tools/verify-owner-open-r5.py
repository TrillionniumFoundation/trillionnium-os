#!/usr/bin/env python3
"""Verify the owner-open R5 graph, active plan, status and zero-gap register.

The Cargo/Android graph contract retains revision ``2026-08-28-r5`` for
compatibility. The active implementation and gap-closure plan is revision
``2026-08-29-r6``. This verifier keeps those identities distinct and never
promotes source presence to installed, image, physical, fault or release
evidence.
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
GAP_REGISTER = Path("docs/status/owner-open-r5-gap-closure.json")

GRAPH_REVISION = "2026-08-28-r5"
ACTIVE_PLAN_REVISION = "2026-08-29-r6"
GAP_SCHEMA = "org.trillionnium.owner-open-r5.gap-closure.v1"
STATUS_LEVELS = {
    "NOT_STARTED",
    "SPEC_ONLY",
    "SOURCE_IMPLEMENTED",
    "HOST_TESTED",
    "IMAGE_INCLUDED",
    "DEVICE_OBSERVED",
    "FAULT_TESTED",
    "RELEASE_QUALIFIED",
}
EVIDENCE_LEVELS = {f"L{index}" for index in range(7)}
GAP_STATES = {
    "OPEN",
    "SOURCE_CLOSED_PENDING_EVIDENCE",
    "EXTERNAL_HOLD",
    "CLOSED",
}
EXTERNAL_GAPS = {
    "R5-GAP-INSTALLED-CODEX-001",
    "R5-GAP-ROOTLINUX-PLACEMENT-001",
    "R5-GAP-ANDROID-GRAPH-001",
    "R5-GAP-PHYSICAL-ADB-001",
    "R5-GAP-FAULT-MATRIX-001",
    "R5-GAP-RELEASE-001",
}
REQUIRED_R6_DOCS = (
    Path("docs/OWNER_OPEN_R5_START_HERE.md"),
    Path("docs/architecture/2026-08-29-owner-open-runtime-authority-and-process-topology.md"),
    Path("docs/protocols/owner-open-effect-state-machine-v1.md"),
    Path("docs/operations/owner-open-deployment-lifecycle-and-emergency-stop.md"),
    Path("docs/qualification/owner-open-evidence-promotion-and-fault-matrix.md"),
)


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


def _positive_issue_values(item: dict[str, Any]) -> list[int]:
    result: list[int] = []
    issue = item.get("issue")
    if isinstance(issue, int) and not isinstance(issue, bool):
        result.append(issue)
    issues = item.get("issues")
    if isinstance(issues, list):
        result.extend(
            value
            for value in issues
            if isinstance(value, int) and not isinstance(value, bool)
        )
    return result


def verify_gap_register(
    root: Path,
    gap: dict[str, Any],
    status: dict[str, Any],
    plan_text: str,
    report: Report,
) -> None:
    report.check(gap.get("schema") == GAP_SCHEMA, "R5 gap-register schema is invalid")
    report.check(
        gap.get("revision") == ACTIVE_PLAN_REVISION,
        f"R5 active gap revision must be {ACTIVE_PLAN_REVISION}",
    )
    report.check(
        status.get("active_plan_revision") == gap.get("revision"),
        "R5 status active plan revision does not match the gap register",
    )
    report.check(
        str(gap.get("revision")) in plan_text,
        "R5 execution plan does not contain the active gap revision",
    )
    report.check(
        "zero_gap=true" in plan_text and "automatic" in plan_text.lower(),
        "R5 plan is missing the zero-gap/no-automatic-redispatch closure rule",
    )

    for path in REQUIRED_R6_DOCS:
        report.check((root / path).is_file(), f"required R6 document is absent: {path}")

    raw_gaps = gap.get("gaps")
    report.check(isinstance(raw_gaps, list) and bool(raw_gaps), "R5 gap list is absent or empty")
    if not isinstance(raw_gaps, list):
        return

    seen: set[str] = set()
    closed: set[str] = set()
    external: set[str] = set()
    facts: list[dict[str, Any]] = []
    for item in raw_gaps:
        if not isinstance(item, dict):
            report.errors.append("R5 gap entry is not an object")
            continue
        identifier = str(item.get("id", ""))
        report.check(
            bool(identifier) and identifier not in seen,
            f"duplicate or empty R5 gap id: {identifier}",
        )
        seen.add(identifier)
        state = str(item.get("status", ""))
        report.check(state in GAP_STATES, f"invalid R5 gap state for {identifier}: {state}")
        level = str(item.get("exit_evidence_level", ""))
        report.check(level in EVIDENCE_LEVELS, f"invalid exit evidence level for {identifier}")
        issues = _positive_issue_values(item)
        report.check(bool(issues) and all(value > 0 for value in issues), f"R5 gap has no valid issue: {identifier}")
        summary = item.get("summary")
        report.check(isinstance(summary, str) and bool(summary.strip()), f"R5 gap summary is absent: {identifier}")
        acceptance = item.get("acceptance")
        report.check(
            isinstance(acceptance, list)
            and bool(acceptance)
            and all(isinstance(value, str) and bool(value.strip()) for value in acceptance),
            f"R5 gap acceptance is absent or malformed: {identifier}",
        )
        report.check(identifier in plan_text, f"R5 plan does not reference gap {identifier}")
        if state == "CLOSED":
            closed.add(identifier)
            if level == "L1":
                report.check(
                    isinstance(item.get("source_evidence"), dict),
                    f"closed L1 R5 gap has no source evidence: {identifier}",
                )
            else:
                evidence = item.get("evidence")
                report.check(
                    isinstance(evidence, list) and bool(evidence),
                    f"closed R5 gap has no evidence: {identifier}",
                )
        if state == "EXTERNAL_HOLD":
            external.add(identifier)
        facts.append(
            {
                "id": identifier,
                "status": state,
                "exit_evidence_level": level,
                "issues": issues,
            }
        )

    order = gap.get("priority_order")
    report.check(isinstance(order, list), "R5 priority_order must be a list")
    if isinstance(order, list):
        normalized_order = [str(value) for value in order]
        report.check(
            len(normalized_order) == len(set(normalized_order)),
            "R5 priority_order contains duplicate gap IDs",
        )
        report.check(
            set(normalized_order) == seen,
            "R5 priority_order does not contain exactly the declared gaps",
        )

    report.check(
        EXTERNAL_GAPS <= seen,
        "R5 gap register is missing required external evidence lanes: "
        + ", ".join(sorted(EXTERNAL_GAPS - seen)),
    )
    report.check(
        EXTERNAL_GAPS <= external,
        "R5 external evidence lane is not held explicitly: "
        + ", ".join(sorted(EXTERNAL_GAPS - external)),
    )
    report.check(
        not (EXTERNAL_GAPS & closed),
        "R5 external evidence lane cannot be closed by the source candidate: "
        + ", ".join(sorted(EXTERNAL_GAPS & closed)),
    )

    all_closed = bool(seen) and closed == seen
    report.check(
        status.get("zero_gap") is all_closed,
        "R5 status zero_gap does not equal the complete gap-closure state",
    )
    release_closed = "R5-GAP-RELEASE-001" in closed
    report.check(
        status.get("public_release") is release_closed,
        "R5 public_release does not match the release-gap closure state",
    )
    report.check(
        gap.get("generated_policy", {}).get("automatic_redispatch") is False,
        "R5 gap policy must keep automatic_redispatch false",
    )
    report.facts["gap_register"] = sorted(facts, key=lambda value: value["id"])
    report.facts["zero_gap"] = all_closed


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
    report.check(revision == GRAPH_REVISION, f"R5 graph revision must be {GRAPH_REVISION}")
    report.check(
        status.get("plan_revision") == revision,
        "R5 status graph-compatible plan revision does not match the graph contract",
    )
    active_revision = status.get("active_plan_revision", status.get("plan_revision"))
    report.check(
        str(active_revision) in plan_text,
        "R5 plan does not contain the active machine revision",
    )
    report.check("ACTIVE" in plan_text, "R5 plan authority statement is missing")
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

    report.check(
        required_members <= members,
        "required R5 workspace members are absent: " + ", ".join(sorted(required_members - members)),
    )
    report.check(
        required_defaults <= defaults,
        "required R5 default members are absent: " + ", ".join(sorted(required_defaults - defaults)),
    )
    report.check(
        not (defaults & forbidden_defaults),
        "forbidden legacy default members are present: " + ", ".join(sorted(defaults & forbidden_defaults)),
    )
    report.check(
        defaults == allowed_defaults,
        "Cargo default-members drifted from the exact R5 closure: "
        + ", ".join(sorted(defaults ^ allowed_defaults)),
    )

    host_binary_facts: list[dict[str, str]] = []
    host_contract = cargo.get("host_binary_contract")
    if not isinstance(host_contract, dict):
        report.errors.append("R5 graph host_binary_contract is not an object")
    else:
        host_manifest_path = root / str(host_contract.get("manifest", ""))
        report.check(host_manifest_path.is_file(), f"R5 Host manifest is absent: {host_manifest_path}")
        if host_manifest_path.is_file():
            host_manifest = read_toml(host_manifest_path)
            package = host_manifest.get("package", {})
            report.check(
                isinstance(package, dict)
                and package.get("autobins") is host_contract.get("autobins"),
                "R5 Host autobins setting drifted from the exact binary contract",
            )
            raw_bins = host_manifest.get("bin", [])
            actual_bins: set[tuple[str, str]] = set()
            if isinstance(raw_bins, list):
                for item in raw_bins:
                    if isinstance(item, dict):
                        name = str(item.get("name", ""))
                        path = str(item.get("path", ""))
                        actual_bins.add((name, path))
                        host_binary_facts.append({"name": name, "path": path})
            required_bins = {
                (str(item.get("name", "")), str(item.get("path", "")))
                for item in host_contract.get("required_bins", [])
                if isinstance(item, dict)
            }
            report.check(
                actual_bins == required_bins,
                "R5 Host explicit binaries drifted from the exact contract: "
                + ", ".join(sorted(f"{name}={path}" for name, path in actual_bins ^ required_bins)),
            )
            forbidden_paths = {
                str(value) for value in host_contract.get("forbidden_selected_paths", [])
            }
            selected_paths = {path for _, path in actual_bins}
            report.check(
                not (selected_paths & forbidden_paths),
                "a superseded Host entrypoint is selected: "
                + ", ".join(sorted(selected_paths & forbidden_paths)),
            )

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
        report.check(
            not leaked,
            f"{path} imports forbidden legacy dependencies: " + ", ".join(sorted(leaked)),
        )
        allowed_internal = set(str(value) for value in spec.get("allowed_internal_dependencies", []))
        actual_internal = {value for value in dependencies if value.startswith("trillionnium-")}
        report.check(
            actual_internal <= allowed_internal,
            f"{path} has an unreviewed owner-open internal edge: "
            + ", ".join(sorted(actual_internal - allowed_internal)),
        )
        source_root = root / path / "src"
        if source_root.is_dir():
            for source in sorted(source_root.rglob("*.rs")):
                text = source.read_text(encoding="utf-8")
                for marker in cargo.get("forbidden_source_markers", []):
                    if str(marker) in text:
                        marker_hits.append(f"{source.relative_to(root)}:{marker}")

    report.check(
        not marker_hits,
        "owner-open source contains forbidden legacy markers: " + ", ".join(marker_hits),
    )

    packages = status.get("work_packages", [])
    report.check(isinstance(packages, list), "R5 status work_packages must be a list")
    if isinstance(packages, list):
        seen: set[str] = set()
        for item in packages:
            if not isinstance(item, dict):
                report.errors.append("R5 status work-package entry is not an object")
                continue
            identifier = str(item.get("id", ""))
            report.check(
                bool(identifier) and identifier not in seen,
                f"duplicate or empty R5 work-package id: {identifier}",
            )
            seen.add(identifier)
            report.check(item.get("status") in STATUS_LEVELS, f"invalid status level for {identifier}")
            evidence = str(item.get("latest_evidence_level", ""))
            report.check(evidence in EVIDENCE_LEVELS, f"invalid evidence level for {identifier}")
        report.check(seen == {f"W{index}" for index in range(8)}, "R5 status must contain exactly W0-W7")

    report.check(status.get("public_release") is False or status.get("zero_gap") is True, "R5 source candidate must not claim a public release")
    negative = status.get("not_claimed", [])
    report.check(isinstance(negative, list) and bool(negative), "R5 status must carry explicit negative claims")

    gap_path = root / GAP_REGISTER
    if gap_path.is_file():
        try:
            gap = read_json(gap_path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            report.errors.append(f"cannot parse R5 gap register: {error}")
        else:
            verify_gap_register(root, gap, status, plan_text, report)

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
            "graph_revision": revision,
            "active_plan_revision": active_revision,
            "workspace_members": sorted(members),
            "default_members": sorted(defaults),
            "host_binaries": sorted(host_binary_facts, key=lambda item: item["name"]),
            "owner_open_package_dependencies": package_facts,
            "forbidden_source_marker_hits": marker_hits,
            "android_forbidden_package_hits": android_hits,
            "claim_ceiling": status.get("claim_ceiling"),
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
            print("owner-open R5 graph and gap register verified")
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
