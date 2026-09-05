#!/usr/bin/env python3
"""Verify the Root Linux payload based owner-open Android profile v2."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any

V2_PATH = Path(__file__).with_name("verify-owner-open-android-profile-v2.py")
spec = importlib.util.spec_from_file_location("verify_owner_open_android_profile_v2_base", V2_PATH)
assert spec is not None and spec.loader is not None
v2 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = v2
spec.loader.exec_module(v2)

PROFILE = Path("android-integration/owner-open-profile/profile-v2.json")
EXPECTED_SCHEMA = "org.trillionnium.owner-open.android-profile.v2"
GENERATOR = Path("tools/generate-owner-open-android-profile-v3.py")

# Repoint the structural verifier at the Root Linux payload profile.
v2.base.PROFILE = PROFILE
v2.base.EXPECTED_SCHEMA = EXPECTED_SCHEMA
v2.base.GENERATOR = GENERATOR


def absolute_posix(value: Any, label: str, report: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        report.errors.append(f"{label} must be an absolute NUL-free POSIX path")
        return None
    path = PurePosixPath(value)
    if ".." in path.parts or str(path) != value:
        report.errors.append(f"{label} is not canonical: {value}")
        return None
    return value


def verify(root: Path, *, strict: bool = False):
    # Foundation structural checks are reused. v3 owns strict lifecycle states
    # because Android-init and Root-Linux-supervisor services are intentionally
    # different kinds of binding.
    report = v2.verify(root, strict=False)
    try:
        profile = v2.base.load_profile(root / PROFILE)
    except (OSError, ValueError) as error:
        if str(error) not in report.errors:
            report.errors.append(str(error))
        return report

    activation = profile.get("activation")
    claims = profile.get("claims")
    payload = profile.get("rootlinux_payload")
    modules = profile.get("required_product_modules")
    services = profile.get("required_services")
    endpoints = profile.get("required_local_endpoints")
    if not isinstance(activation, dict) or not isinstance(claims, dict):
        return report
    if not isinstance(payload, dict):
        report.errors.append("rootlinux_payload must be an object")
        payload = {}
    if not isinstance(modules, list):
        modules = []
    if not isinstance(services, list):
        services = []
    if not isinstance(endpoints, list):
        endpoints = []

    for field_name in ("rootlinux_payload_bound", "android_bootstrap_bound"):
        if not isinstance(claims.get(field_name), bool):
            report.errors.append(f"claim {field_name} must be boolean")

    if payload.get("format") not in {"squashfs", "erofs"}:
        report.errors.append("Root Linux payload format must be squashfs or erofs")
    if payload.get("read_only") is not True:
        report.errors.append("Root Linux payload lower image must be read_only=true")

    install_path = absolute_posix(
        payload.get("android_install_path"),
        "rootlinux payload android_install_path",
        report,
    )
    manifest_path = absolute_posix(
        payload.get("manifest_install_path"),
        "rootlinux payload manifest_install_path",
        report,
    )
    runtime_mount = absolute_posix(
        payload.get("runtime_mount_path"),
        "rootlinux payload runtime_mount_path",
        report,
    )
    overlay_path = absolute_posix(
        payload.get("writable_overlay_path"),
        "rootlinux payload writable_overlay_path",
        report,
    )
    state_root = absolute_posix(
        payload.get("state_root"),
        "rootlinux payload state_root",
        report,
    )
    if install_path is not None and not install_path.startswith(
        "/system_ext/etc/trillionnium/rootlinux/"
    ):
        report.errors.append("Root Linux payload must install under system_ext etc, not bin")
    if manifest_path is not None and not manifest_path.startswith(
        "/system_ext/etc/trillionnium/rootlinux/"
    ):
        report.errors.append("Root Linux manifest must install under system_ext etc")
    for label, value in (
        ("runtime mount", runtime_mount),
        ("writable overlay", overlay_path),
        ("state root", state_root),
    ):
        if value is not None and not value.startswith("/data/trillionnium/owner-open/"):
            report.errors.append(f"{label} must remain under private owner-open /data")

    entries = payload.get("required_entries")
    if not isinstance(entries, list) or not entries:
        report.errors.append("rootlinux_payload.required_entries must be nonempty")
        entries = []
    entry_roles: list[str] = []
    entry_paths: list[str] = []
    entry_states: dict[str, str] = {}
    for item in entries:
        if not isinstance(item, dict):
            report.errors.append("Root Linux payload entry must be an object")
            continue
        role, entry_path, state = item.get("role"), item.get("path"), item.get("state")
        if not isinstance(role, str) or not role:
            report.errors.append("Root Linux payload entry role is malformed")
            continue
        normalized = absolute_posix(entry_path, f"Root Linux payload entry {role}", report)
        if normalized is not None:
            if normalized.startswith("/system") or normalized.startswith("/vendor"):
                report.errors.append(
                    f"Root Linux payload entry {role} uses an Android partition path"
                )
            entry_paths.append(normalized)
        if not isinstance(state, str) or not state:
            report.errors.append(f"Root Linux payload entry {role} state is malformed")
            continue
        entry_roles.append(role)
        entry_states[role] = state
    if len(entry_roles) != len(set(entry_roles)):
        report.errors.append("Root Linux payload entry roles are duplicated")
    if len(entry_paths) != len(set(entry_paths)):
        report.errors.append("Root Linux payload entry paths are duplicated")

    forbidden_destinations = v2.base.string_list(
        profile.get("forbidden_android_destinations_for_rootlinux_roles"),
        "forbidden_android_destinations_for_rootlinux_roles",
        report,
    )
    module_roles: dict[str, dict[str, Any]] = {}
    module_destinations: list[str] = []
    for item in modules:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        destination = item.get("destination")
        if isinstance(role, str) and role:
            if role in module_roles:
                report.errors.append(f"product module role is duplicated: {role}")
            module_roles[role] = item
        if isinstance(destination, str):
            module_destinations.append(destination)
            if destination in forbidden_destinations:
                report.errors.append(
                    f"Root Linux runtime is incorrectly reserved as Android executable: {destination}"
                )

    expected_payload_destination = (
        install_path.removeprefix("/system_ext/") if install_path is not None else None
    )
    expected_manifest_destination = (
        manifest_path.removeprefix("/system_ext/") if manifest_path is not None else None
    )
    if module_roles.get("rootlinux_payload", {}).get("destination") != expected_payload_destination:
        report.errors.append("rootlinux_payload module destination does not bind payload install path")
    if module_roles.get("rootlinux_manifest", {}).get("destination") != expected_manifest_destination:
        report.errors.append("rootlinux_manifest module destination does not bind manifest install path")
    for required_role in (
        "rootlinux_payload",
        "rootlinux_manifest",
        "android_native_bootstrap",
        "android_native_emergency_stop",
        "android_init_config",
        "profile_config",
    ):
        if required_role not in module_roles:
            report.errors.append(f"required product module role is missing: {required_role}")

    service_states: dict[str, str] = {}
    service_owners: dict[str, str] = {}
    for item in services:
        if not isinstance(item, dict):
            continue
        name, owner, state = item.get("name"), item.get("owner"), item.get("state")
        if isinstance(name, str) and isinstance(owner, str) and isinstance(state, str):
            service_states[name] = state
            service_owners[name] = owner
    endpoint_states = {
        str(item.get("name")): str(item.get("state"))
        for item in endpoints
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and isinstance(item.get("state"), str)
    }

    if claims.get("rootlinux_payload_bound") is True:
        if payload.get("artifact_state") != "BOUND_ROOTFS_IMAGE":
            report.errors.append(
                "rootlinux_payload_bound=true requires artifact_state=BOUND_ROOTFS_IMAGE"
            )
        if payload.get("manifest_state") != "BOUND_ROOTFS_MANIFEST":
            report.errors.append(
                "rootlinux_payload_bound=true requires manifest_state=BOUND_ROOTFS_MANIFEST"
            )
        unbound_entries = sorted(
            role for role, state in entry_states.items() if state != "BOUND_ROOTFS_ENTRY"
        )
        if unbound_entries:
            report.errors.append(
                f"rootlinux_payload_bound=true has unbound entries: {unbound_entries}"
            )
    if claims.get("image_included") is True and claims.get("rootlinux_payload_bound") is not True:
        report.errors.append("image_included=true requires rootlinux_payload_bound=true")
    if claims.get("image_included") is True and claims.get("android_bootstrap_bound") is not True:
        report.errors.append("image_included=true requires android_bootstrap_bound=true")

    if strict:
        if activation.get("selected_in_current_product") is not True:
            report.errors.append("strict Android v3 requires profile activation")
        for field_name in (
            "rootlinux_payload_bound",
            "android_bootstrap_bound",
            "soong_modules_bound",
            "init_services_bound",
            "selinux_domains_bound",
            "target_files_built",
            "image_included",
        ):
            if claims.get(field_name) is not True:
                report.errors.append(f"strict Android v3 requires claim {field_name}=true")
        if claims.get("source_contract_only") is not False:
            report.errors.append("strict Android v3 requires source_contract_only=false")
        unbound_modules = sorted(
            str(item.get("name"))
            for item in modules
            if isinstance(item, dict)
            and item.get("materialization") != "BOUND_SOONG_MODULE"
        )
        if unbound_modules:
            report.errors.append(f"strict Android v3 has unbound Soong modules: {unbound_modules}")
        wrong_services: list[str] = []
        for name, owner in service_owners.items():
            expected = (
                "BOUND_INIT_SERVICE"
                if owner == "android_init"
                else "BOUND_ROOTLINUX_SERVICE"
                if owner == "rootlinux_supervisor"
                else None
            )
            if expected is None or service_states.get(name) != expected:
                wrong_services.append(name)
        if wrong_services:
            report.errors.append(
                f"strict Android v3 has unbound or mis-owned services: {sorted(wrong_services)}"
            )
        wrong_endpoints = sorted(
            name for name, state in endpoint_states.items() if state != "BOUND_ENDPOINT"
        )
        if wrong_endpoints:
            report.errors.append(
                f"strict Android v3 has unbound endpoints: {wrong_endpoints}"
            )
        if report.facts.get("current_overlay_forbidden_packages"):
            report.errors.append(
                "strict Android v3 current product still selects forbidden legacy packages"
            )
        if report.facts.get("include_observed_in_current_overlay") is not True:
            report.errors.append(
                "strict Android v3 current product does not select the v2 package fragment"
            )
    else:
        if activation.get("selected_in_current_product") is False:
            for field_name in (
                "rootlinux_payload_bound",
                "android_bootstrap_bound",
                "soong_modules_bound",
                "init_services_bound",
                "selinux_domains_bound",
                "target_files_built",
                "image_included",
                "physical_device_observed",
                "public_release",
            ):
                if claims.get(field_name) is not False:
                    report.errors.append(
                        f"unselected Android v2 profile requires {field_name}=false"
                    )
            if payload.get("artifact_state") != "UNBOUND_ROOTFS_IMAGE":
                report.errors.append(
                    "unselected Android v2 profile requires UNBOUND_ROOTFS_IMAGE"
                )
            if payload.get("manifest_state") != "UNBOUND_ROOTFS_MANIFEST":
                report.errors.append(
                    "unselected Android v2 profile requires UNBOUND_ROOTFS_MANIFEST"
                )

    report.facts.update(
        verifier="owner-open-android-profile-v3",
        profile_path=str(PROFILE),
        rootlinux_payload_format=payload.get("format"),
        rootlinux_payload_install_path=install_path,
        rootlinux_manifest_install_path=manifest_path,
        rootlinux_entry_roles=entry_roles,
        rootlinux_entry_states=entry_states,
        product_module_roles=sorted(module_roles),
        product_module_destinations=module_destinations,
        service_owners=service_owners,
        service_states_v3=service_states,
        endpoint_states_v3=endpoint_states,
        strict_v3=strict,
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
            "PASS_OWNER_OPEN_ANDROID_PROFILE_V3 "
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
