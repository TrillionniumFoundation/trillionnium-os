#!/usr/bin/env python3
"""Verify the unselected or strict owner-open Android product profile."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

PROFILE = Path("android-integration/owner-open-profile/profile.json")
EXPECTED_SCHEMA = "org.trillionnium.owner-open.android-profile.v1"
GENERATOR = Path("tools/generate-owner-open-android-profile-v2.py")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 32 * 1024 * 1024


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
    warnings: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def value(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
            "facts": self.facts,
        }


def bounded_real_file(path: Path, maximum: int, label: str) -> bytes:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        raise ValueError(f"{label} is not a bounded real file: {path}")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ValueError(f"{label} changed while read: {path}")
    return raw


def load_profile(path: Path) -> dict[str, Any]:
    raw = bounded_real_file(path, MAX_JSON_BYTES, "owner-open Android profile")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise ValueError(f"invalid owner-open Android profile: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != EXPECTED_SCHEMA:
        raise ValueError(f"profile schema must be {EXPECTED_SCHEMA}")
    return value


def string_list(value: Any, label: str, report: Report) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        report.errors.append(f"{label} must be a nonempty string list")
        return []
    if len(value) != len(set(value)):
        report.errors.append(f"{label} contains duplicates")
    return list(value)


def safe_source(root: Path, relative: str, label: str, report: Report) -> Path | None:
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
    return path


def verify(root: Path, *, strict: bool = False) -> Report:
    report = Report()
    try:
        profile = load_profile(root / PROFILE)
    except (OSError, ValueError) as error:
        report.errors.append(str(error))
        return report

    activation = profile.get("activation")
    claims = profile.get("claims")
    if not isinstance(activation, dict):
        report.errors.append("profile activation must be an object")
        activation = {}
    if not isinstance(claims, dict):
        report.errors.append("profile claims must be an object")
        claims = {}

    selected = activation.get("selected_in_current_product")
    if not isinstance(selected, bool):
        report.errors.append("selected_in_current_product must be boolean")
    for field_name in (
        "source_contract_only",
        "soong_modules_bound",
        "init_services_bound",
        "selinux_domains_bound",
        "target_files_built",
        "image_included",
        "physical_device_observed",
        "public_release",
    ):
        if not isinstance(claims.get(field_name), bool):
            report.errors.append(f"claim {field_name} must be boolean")

    artifacts = profile.get("required_source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        report.errors.append("required_source_artifacts must be nonempty")
        artifacts = []
    artifact_roles: list[str] = []
    artifact_paths: list[str] = []
    for item in artifacts:
        if not isinstance(item, dict):
            report.errors.append("source artifact entry must be an object")
            continue
        role, relative = item.get("role"), item.get("path")
        if not isinstance(role, str) or not role or not isinstance(relative, str) or not relative:
            report.errors.append("source artifact role/path is malformed")
            continue
        artifact_roles.append(role)
        artifact_paths.append(relative)
        safe_source(root, relative, f"source artifact {role}", report)
    if len(artifact_roles) != len(set(artifact_roles)):
        report.errors.append("source artifact roles are duplicated")
    if len(artifact_paths) != len(set(artifact_paths)):
        report.errors.append("source artifact paths are duplicated")

    modules = profile.get("required_product_modules")
    if not isinstance(modules, list) or not modules:
        report.errors.append("required_product_modules must be nonempty")
        modules = []
    module_names: list[str] = []
    unbound: list[str] = []
    for item in modules:
        if not isinstance(item, dict):
            report.errors.append("product module entry must be an object")
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name:
            report.errors.append("product module name is malformed")
            continue
        module_names.append(name)
        if item.get("materialization") != "BOUND_SOONG_MODULE":
            unbound.append(name)
    if len(module_names) != len(set(module_names)):
        report.errors.append("product module names are duplicated")

    forbidden_packages = string_list(
        profile.get("forbidden_product_packages"),
        "forbidden_product_packages",
        report,
    )
    forbidden_markers = string_list(
        profile.get("forbidden_source_markers"),
        "forbidden_source_markers",
        report,
    )

    fragment_relative = activation.get("product_make_fragment")
    overlay_relative = activation.get("current_audit_overlay")
    fragment_text = ""
    overlay_text = ""
    if isinstance(fragment_relative, str) and fragment_relative:
        fragment_path = safe_source(root, fragment_relative, "generated package fragment", report)
        if fragment_path is not None:
            try:
                fragment_raw = bounded_real_file(
                    fragment_path, MAX_TEXT_BYTES, "generated package fragment"
                )
                fragment_text = fragment_raw.decode("utf-8")
            except (OSError, UnicodeDecodeError, ValueError) as error:
                report.errors.append(str(error))
    else:
        report.errors.append("product_make_fragment is missing")
    if isinstance(overlay_relative, str) and overlay_relative:
        overlay_path = safe_source(root, overlay_relative, "current audit overlay", report)
        if overlay_path is not None:
            try:
                overlay_raw = bounded_real_file(
                    overlay_path, MAX_TEXT_BYTES, "current audit overlay"
                )
                overlay_text = overlay_raw.decode("utf-8")
            except (OSError, UnicodeDecodeError, ValueError) as error:
                report.errors.append(str(error))
    else:
        report.errors.append("current_audit_overlay is missing")

    fragment_package_hits = sorted(
        token for token in forbidden_packages if token in fragment_text
    )
    fragment_marker_hits = sorted(
        token for token in forbidden_markers if token in fragment_text
    )
    if fragment_package_hits or fragment_marker_hits:
        report.errors.append(
            "generated owner-open fragment contains forbidden legacy tokens: "
            f"packages={fragment_package_hits} markers={fragment_marker_hits}"
        )

    overlay_hits = sorted(token for token in forbidden_packages if token in overlay_text)
    include_selected = bool(
        isinstance(fragment_relative, str)
        and fragment_relative
        and (
            fragment_relative in overlay_text
            or Path(fragment_relative).name in overlay_text
            or str(profile.get("profile_id")) in overlay_text
        )
    )
    if include_selected and (selected is not True or unbound):
        report.errors.append(
            "current Android product selects the owner-open fragment before activation and Soong binding"
        )

    generator = safe_source(root, str(GENERATOR), "Android profile generator", report)
    generator_check_rc = None
    generator_check_stdout = ""
    generator_check_stderr = ""
    if generator is not None:
        completed = subprocess.run(
            [sys.executable, str(generator), "--root", str(root), "--check"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        generator_check_rc = completed.returncode
        generator_check_stdout = completed.stdout.decode("utf-8", errors="replace")
        generator_check_stderr = completed.stderr.decode("utf-8", errors="replace")
        if completed.returncode != 0:
            report.errors.append(
                "generated owner-open package fragment drifted: "
                + generator_check_stderr[:2048]
            )

    if strict:
        if selected is not True:
            report.errors.append("strict Android verification requires profile activation")
        if unbound:
            report.errors.append(f"strict Android verification has unbound Soong modules: {unbound}")
        for field_name in (
            "soong_modules_bound",
            "init_services_bound",
            "selinux_domains_bound",
            "target_files_built",
            "image_included",
        ):
            if claims.get(field_name) is not True:
                report.errors.append(f"strict Android verification requires claim {field_name}=true")
        if overlay_hits:
            report.errors.append(
                f"strict Android product still selects forbidden packages: {overlay_hits}"
            )
        if not include_selected:
            report.errors.append("strict Android product does not select the owner-open fragment")
    else:
        if overlay_hits:
            report.warnings.append(
                f"W6 HOLD: current audit overlay still selects forbidden packages: {overlay_hits}"
            )
        if unbound:
            report.warnings.append(
                f"W6 HOLD: owner-open product modules are not yet bound: {unbound}"
            )

    report.facts = {
        "revision": profile.get("revision"),
        "profile_id": profile.get("profile_id"),
        "strict": strict,
        "selected_in_current_product": selected,
        "include_observed_in_current_overlay": include_selected,
        "required_source_artifacts": artifact_paths,
        "required_product_modules": module_names,
        "unbound_product_modules": unbound,
        "current_overlay_forbidden_packages": overlay_hits,
        "generator_check_returncode": generator_check_rc,
        "generator_check_stdout": generator_check_stdout,
        "generator_check_stderr": generator_check_stderr,
        "claim_ceiling": profile.get("claim_ceiling"),
    }
    return report


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = verify(args.root, strict=args.strict)
    if args.json:
        print(json.dumps(report.value(), ensure_ascii=False, sort_keys=True, indent=2))
    elif report.ok:
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        print(
            "PASS_OWNER_OPEN_ANDROID_PROFILE "
            f"strict={str(args.strict).lower()} "
            f"selected={str(report.facts.get('selected_in_current_product')).lower()}"
        )
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
