#!/usr/bin/env python3
"""Verify the r4 owner-open foundation and negative default graph.

The default mode is intentionally honest about the checked-in Android audit
overlay: it reports legacy product-graph hits as known W0/W6 holds. After the
owner-open Android profile split, CI must add --strict-android so those hits
become hard failures.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any

CONTRACT_PATH = Path("docs/contracts/owner-open-forbidden-default-graph-v1.json")
STATUS_PATH = Path("docs/status/owner-open-r4-status.json")
PLAN_PATH = Path("docs/TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md")
OWNER_OPEN_CRATE = Path("crates/trillionnium-owner-open-types/Cargo.toml")
OWNER_OPEN_HOST = Path("apps/trillionnium-owner-open-host/Cargo.toml")
GENERATOR = Path("tools/generate-owner-open-types.py")
SCHEMA_PATH = Path("schemas/codex-sovereign-direct-tools.schema.json")
SEMANTIC_CONTRACT = Path("docs/contracts/codex-sovereign-direct-tools-v1.json")


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.facts: dict[str, Any] = {}

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            self.error(message)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def dependency_names(manifest: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = manifest.get(section, {})
        if isinstance(value, dict):
            names.update(str(name) for name in value)
    target = manifest.get("target", {})
    if isinstance(target, dict):
        for target_config in target.values():
            if not isinstance(target_config, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = target_config.get(section, {})
                if isinstance(value, dict):
                    names.update(str(name) for name in value)
    return names


def work_package(status: dict[str, Any], identifier: str) -> dict[str, Any] | None:
    packages = status.get("work_packages", [])
    if not isinstance(packages, list):
        return None
    for package in packages:
        if isinstance(package, dict) and package.get("id") == identifier:
            return package
    return None


def verify(root: Path, strict_android: bool) -> Report:
    report = Report()
    try:
        contract = read_json(root / CONTRACT_PATH)
        status = read_json(root / STATUS_PATH)
        cargo = read_toml(root / "Cargo.toml")
        owner_open_manifest = read_toml(root / OWNER_OPEN_CRATE)
        owner_open_host_manifest = read_toml(root / OWNER_OPEN_HOST)
        schema = read_json(root / SCHEMA_PATH)
        semantic = read_json(root / SEMANTIC_CONTRACT)
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        report.error(f"foundation input cannot be parsed: {error}")
        return report

    revision = contract.get("revision")
    report.check(revision == "2026-08-27-r4", "forbidden graph revision must be r4")
    report.check(
        status.get("plan_revision") == revision,
        "machine status plan_revision does not match graph contract revision",
    )
    report.check(
        semantic.get("revision") == status.get("semantic_contract_revision"),
        "machine status semantic contract revision does not match the contract",
    )

    plan_text = (root / PLAN_PATH).read_text(encoding="utf-8")
    report.check(
        str(revision) in plan_text,
        "active plan does not contain the graph/status revision",
    )
    report.check(
        "ACTIVE — the only implementation sequencing and closeout plan" in plan_text,
        "active plan authority statement is missing",
    )

    workspace = cargo.get("workspace", {})
    if not isinstance(workspace, dict):
        report.error("Cargo.toml has no [workspace] object")
        return report
    members = set(workspace.get("members", []))
    defaults = set(workspace.get("default-members", []))
    cargo_contract = contract.get("cargo", {})
    if not isinstance(cargo_contract, dict):
        report.error("forbidden graph cargo section is invalid")
        return report

    for required in cargo_contract.get("required_workspace_members", []):
        report.check(required in members, f"required workspace member is absent: {required}")
    for required in cargo_contract.get("required_default_members", []):
        report.check(required in defaults, f"required default member is absent: {required}")
    for forbidden in cargo_contract.get("forbidden_default_members", []):
        report.check(
            forbidden not in defaults,
            f"forbidden owner-open Cargo default member is present: {forbidden}",
        )
    allowed_defaults = set(cargo_contract.get("allowed_default_members", []))
    unexpected_defaults = sorted(defaults.difference(allowed_defaults))
    report.check(
        not unexpected_defaults,
        "unexpected Cargo default members are outside the owner-open graph: "
        + ", ".join(unexpected_defaults),
    )

    owner_open_dependencies = dependency_names(owner_open_manifest)
    forbidden_dependencies = set(
        cargo_contract.get("owner_open_types_forbidden_dependencies", [])
    )
    leaked_dependencies = sorted(owner_open_dependencies.intersection(forbidden_dependencies))
    report.check(
        not leaked_dependencies,
        "owner-open types depend on legacy/broad internal crates: "
        + ", ".join(leaked_dependencies),
    )
    host_manifest_path = Path(
        str(cargo_contract.get("owner_open_host_manifest", OWNER_OPEN_HOST))
    )
    report.check(
        host_manifest_path == OWNER_OPEN_HOST,
        "owner-open host manifest path must remain canonical",
    )
    host_dependencies = dependency_names(owner_open_host_manifest)
    forbidden_host_dependencies = set(
        cargo_contract.get("owner_open_host_forbidden_dependencies", [])
    )
    leaked_host_dependencies = sorted(
        host_dependencies.intersection(forbidden_host_dependencies)
    )
    report.check(
        not leaked_host_dependencies,
        "owner-open Host depends on legacy/broad internal crates: "
        + ", ".join(leaked_host_dependencies),
    )

    source_marker_hits: list[str] = []
    for source_root in cargo_contract.get("isolated_source_roots", []):
        path = root / str(source_root)
        if not path.is_dir():
            report.error(f"isolated owner-open source root is absent: {source_root}")
            continue
        for source in sorted(path.rglob("*")):
            if not source.is_file() or source.suffix not in {".rs", ".toml"}:
                continue
            text = source.read_text(encoding="utf-8")
            for marker in cargo_contract.get("forbidden_source_markers", []):
                if str(marker) in text:
                    source_marker_hits.append(f"{source.relative_to(root)}:{marker}")
    report.check(
        not source_marker_hits,
        "isolated owner-open source contains legacy semantic markers: "
        + ", ".join(source_marker_hits),
    )

    report.facts["owner_open_dependencies"] = sorted(owner_open_dependencies)
    report.facts["owner_open_host_dependencies"] = sorted(host_dependencies)
    report.facts["cargo_default_members"] = sorted(defaults)
    report.facts["source_marker_hits"] = source_marker_hits

    for required_document in contract.get("required_documents", []):
        report.check(
            (root / required_document).is_file(),
            f"required r4 document is absent: {required_document}",
        )

    report.check(
        schema.get("additionalProperties") is True,
        "owner-open frame schema must retain unknown extension fields",
    )
    definitions = schema.get("$defs", {})
    report.check(
        isinstance(definitions, dict)
        and "runTurnRequest" in definitions
        and "turnCancelRequest" in definitions
        and "shellExec" in definitions
        and "adbExec" in definitions,
        "owner-open schema must define turn, cancel, shellExec and adbExec codec shapes",
    )
    description = str(schema.get("description", "")).lower()
    report.check(
        "does not grant" in description and "deny" in description,
        "schema must explicitly state that it is not an allow/deny authority",
    )

    generated_checks = contract.get("generated_checks", [])
    if not isinstance(generated_checks, list):
        report.error("generated_checks must be a list")
    else:
        for item in generated_checks:
            if not isinstance(item, dict):
                report.error("generated check entry must be an object")
                continue
            generator = root / str(item.get("generator", ""))
            output = root / str(item.get("output", ""))
            report.check(generator.is_file(), f"generator is absent: {generator}")
            report.check(output.is_file(), f"generated output is absent: {output}")
            if generator.is_file() and output.is_file():
                result = subprocess.run(
                    [
                        sys.executable,
                        str(generator),
                        "--contract",
                        str(root / SEMANTIC_CONTRACT),
                        "--output",
                        str(output),
                        "--check",
                    ],
                    cwd=root,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                report.check(
                    result.returncode == 0,
                    "generated owner-open constants are stale: "
                    + (result.stderr.strip() or result.stdout.strip()),
                )

    android = contract.get("android", {})
    android_hits: list[str] = []
    if isinstance(android, dict):
        overlay = root / str(android.get("audit_overlay_path", ""))
        if overlay.is_file():
            text = overlay.read_text(encoding="utf-8")
            for marker in android.get("forbidden_owner_open_packages", []):
                if marker in text:
                    android_hits.append(str(marker))
            android_hits = sorted(set(android_hits))
            if android_hits:
                message = (
                    "Android audit overlay still contains forbidden owner-open product markers: "
                    + ", ".join(android_hits)
                )
                if strict_android:
                    report.error(message)
                else:
                    report.warning(message)
        else:
            report.warning(f"Android audit overlay was not available at {overlay}")
    else:
        report.error("forbidden graph android section is invalid")

    report.facts["android_forbidden_package_hits"] = android_hits
    w0 = work_package(status, "W0")
    w6 = work_package(status, "W6")
    report.check(w0 is not None and w6 is not None, "machine status must contain W0 and W6")
    if android_hits:
        report.check(
            not bool(w0 and w0.get("complete")),
            "W0 cannot be complete while Android forbidden graph hits remain",
        )
        report.check(
            not bool(w6 and w6.get("complete")),
            "W6 cannot be complete while Android forbidden graph hits remain",
        )

    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root",
    )
    parser.add_argument(
        "--strict-android",
        action="store_true",
        help="treat legacy markers in the Android overlay as failures",
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = verify(args.root.resolve(), args.strict_android)
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
            print(
                "owner-open r4 foundation verified"
                + (f" with {len(report.warnings)} known hold(s)" if report.warnings else "")
            )
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
