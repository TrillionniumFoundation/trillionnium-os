#!/usr/bin/env python3
"""Deep consistency verifier for the owner-open Android profile."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

BASE_PATH = Path(__file__).with_name("verify-owner-open-android-profile.py")
spec = importlib.util.spec_from_file_location("verify_owner_open_android_profile_base", BASE_PATH)
assert spec is not None and spec.loader is not None
base = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = base
spec.loader.exec_module(base)


def object_list(value: Any, label: str, report: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or any(not isinstance(item, dict) for item in value):
        report.errors.append(f"{label} must be a nonempty object list")
        return []
    return list(value)


def named_states(
    values: list[dict[str, Any]],
    label: str,
    report: Any,
) -> tuple[list[str], dict[str, str]]:
    names: list[str] = []
    states: dict[str, str] = {}
    for item in values:
        name, state = item.get("name"), item.get("state")
        if not isinstance(name, str) or not name:
            report.errors.append(f"{label} name is malformed")
            continue
        if not isinstance(state, str) or not state:
            report.errors.append(f"{label} {name} state is malformed")
            continue
        names.append(name)
        states[name] = state
    if len(names) != len(set(names)):
        report.errors.append(f"{label} names are duplicated")
    return names, states


def verify(root: Path, *, strict: bool = False):
    report = base.verify(root, strict=strict)
    try:
        profile = base.load_profile(root / base.PROFILE)
    except (OSError, ValueError) as error:
        if str(error) not in report.errors:
            report.errors.append(str(error))
        return report
    claims = profile.get("claims")
    activation = profile.get("activation")
    if not isinstance(claims, dict) or not isinstance(activation, dict):
        return report

    services = object_list(profile.get("required_services"), "required_services", report)
    endpoints = object_list(
        profile.get("required_local_endpoints"),
        "required_local_endpoints",
        report,
    )
    service_names, service_states = named_states(services, "service", report)
    endpoint_names, endpoint_states = named_states(endpoints, "endpoint", report)
    selinux = base.string_list(
        profile.get("required_selinux_boundaries"),
        "required_selinux_boundaries",
        report,
    )

    if claims.get("image_included") is True and claims.get("target_files_built") is not True:
        report.errors.append("image_included=true requires target_files_built=true")
    if claims.get("target_files_built") is True:
        for dependency in (
            "soong_modules_bound",
            "init_services_bound",
            "selinux_domains_bound",
        ):
            if claims.get(dependency) is not True:
                report.errors.append(
                    f"target_files_built=true requires {dependency}=true"
                )
    if activation.get("selected_in_current_product") is True and claims.get("soong_modules_bound") is not True:
        report.errors.append(
            "selected_in_current_product=true requires soong_modules_bound=true"
        )
    if claims.get("physical_device_observed") is True and claims.get("image_included") is not True:
        report.errors.append(
            "physical_device_observed=true requires image_included=true"
        )
    if claims.get("public_release") is True and claims.get("physical_device_observed") is not True:
        report.errors.append(
            "public_release=true requires physical_device_observed=true"
        )

    if strict:
        if claims.get("source_contract_only") is not False:
            report.errors.append(
                "strict Android verification requires source_contract_only=false"
            )
        unbound_services = sorted(
            name for name, state in service_states.items() if state != "BOUND_INIT_SERVICE"
        )
        unbound_endpoints = sorted(
            name for name, state in endpoint_states.items() if state != "BOUND_ENDPOINT"
        )
        if unbound_services:
            report.errors.append(
                f"strict Android verification has unbound services: {unbound_services}"
            )
        if unbound_endpoints:
            report.errors.append(
                f"strict Android verification has unbound endpoints: {unbound_endpoints}"
            )
        if not selinux:
            report.errors.append(
                "strict Android verification requires explicit SELinux boundaries"
            )
    else:
        if activation.get("selected_in_current_product") is False and claims.get("source_contract_only") is not True:
            report.errors.append(
                "unselected foundation profile must retain source_contract_only=true"
            )

    report.facts.update(
        required_services=service_names,
        service_states=service_states,
        required_endpoints=endpoint_names,
        endpoint_states=endpoint_states,
        required_selinux_boundaries=selinux,
        consistency_verifier="v2",
    )
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
            "PASS_OWNER_OPEN_ANDROID_PROFILE_V2 "
            f"strict={str(args.strict).lower()}"
        )
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
