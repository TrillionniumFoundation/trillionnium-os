#!/usr/bin/env python3
"""Verify the authored owner-open Android/Root-Linux source closure.

This gate proves only that the checked-in source graph is complete and mutually
consistent.  It deliberately does not claim that Soong, init or SELinux has
compiled, that target-files contain the modules, that a device booted, or that a
physical effect occurred.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import sys
from typing import Any

PROFILE = Path("android-integration/owner-open-profile/profile-v2.json")
GENERATED_FRAGMENT = Path(
    "android-integration/owner-open-profile/generated/owner_open_packages_v2.mk"
)
ANDROID_ROOT = Path(
    "android-integration/working-tree/vendor/trillionnium/owner-open"
)
COMMON_OWNER_OPEN = Path(
    "android-integration/working-tree/vendor/trillionnium/config/common_owner_open.mk"
)
SUPERVISOR_CONFIG = Path("packaging/owner-open-rootfs/rootlinux-supervisor.json")
# The unselected v2/v3 documents remain their own sealed foundation contract.
# The authored Android surface now packages exactly this explicit Leap variant.
ACTIVE_RUNTIME_PROFILE = ANDROID_ROOT / "config/profile-codex-host-relay-v1.json"
ACTIVE_SOURCE_FILES = (
    ACTIVE_RUNTIME_PROFILE,
    ANDROID_ROOT / "tools/verify_owner_open_materialized_erofs_payload.py",
    ANDROID_ROOT / "init/trillionnium-sun-btfm-modprobe.rc",
)
ACTIVE_EXTRA_MODULES = {"trillionnium-sun-btfm-modprobe-init-rc"}
ACTIVE_EXTRA_SERVICES = {"trillionnium_owner_open_verify"}
ACTIVE_PAYLOAD_PATHS = {
    "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs",
    "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs.sha256",
    "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.image-manifest.json",
    "/data/trillionnium/owner-open/root",
    "/data/trillionnium/owner-open/state",
    "/usr/bin/python3",
    "/usr/bin/adb",
    "/usr/libexec/trillionnium/trillionnium-owner-open-r5-host",
    "/usr/libexec/trillionnium/trillionnium-owner-open-r5-core",
    "/usr/libexec/trillionnium/owner-open/owner_open_rootlinux_supervisor.py",
    "/usr/libexec/trillionnium/owner-open/owner_open_connection_broker.py",
    "/usr/libexec/trillionnium/owner-open/adb_smart_socket_relay_release.py",
    "/usr/libexec/trillionnium/provider-adapter",
    "/etc/trillionnium/owner-open/rootlinux-supervisor.json",
    "/etc/trillionnium/owner-open/provider-host-relay-v1.json",
}
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 32 * 1024 * 1024
PROFILE_SCHEMA = "org.trillionnium.owner-open.android-profile.v2"
RUNTIME_PROFILE_SCHEMA = "org.trillionnium.owner-open.android-runtime-profile.v3"
SUPERVISOR_SCHEMA = "org.trillionnium.owner-open.rootlinux-supervisor.v1"
SOURCE_CLAIM = "ANDROID_OWNER_OPEN_SOURCE_IMPLEMENTED_NOT_BUILT_L0"
RUNTIME_CLAIM = "ANDROID_OWNER_OPEN_SOURCE_IMPLEMENTED_NOT_BUILT"
MODULE_PATTERN = re.compile(r'^\s*name:\s*"([A-Za-z0-9_.+-]+)"\s*,?\s*$', re.MULTILINE)
SERVICE_PATTERN = re.compile(r"^service\s+([A-Za-z0-9_.-]+)\s+", re.MULTILINE)
SECLABEL_PATTERN = re.compile(r"^\s*seclabel\s+(u:r:[A-Za-z0-9_]+:s0)\s*$", re.MULTILINE)


class DuplicateMember(ValueError):
    pass


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


def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise DuplicateMember(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def bounded_file(path: Path, maximum: int, label: str) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} is not a regular non-symlink file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise ValueError(f"{label} size is outside 1..{maximum}: {metadata.st_size}")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ValueError(f"{label} changed while read: {path}")
    return raw


def load_json(path: Path, label: str) -> dict[str, Any]:
    raw = bounded_file(path, MAX_JSON_BYTES, label)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise ValueError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def load_text(path: Path, label: str) -> str:
    raw = bounded_file(path, MAX_TEXT_BYTES, label)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not UTF-8: {error}") from error


def safe_source(root: Path, relative: str, label: str, report: Report) -> Path | None:
    if not relative or relative.startswith("/") or "\x00" in relative:
        report.errors.append(f"{label} path is malformed: {relative!r}")
        return None
    path = root / relative
    try:
        root_real = root.resolve(strict=True)
        parent_real = path.parent.resolve(strict=True)
        if parent_real != root_real and root_real not in parent_real.parents:
            report.errors.append(f"{label} escapes repository: {relative}")
            return None
        bounded_file(path, MAX_TEXT_BYTES, label)
    except (OSError, ValueError) as error:
        report.errors.append(f"{label}: {error}")
        return None
    return path


def profile_reference(
    root: Path, value: Any, field_name: str, report: Report
) -> str | None:
    """Validate a profile document reference and bind it to a real source file.

    Profile references are part of the source-closure evidence chain.  A
    dangling or traversal-shaped reference would leave the profile apparently
    self-consistent while severing the normative plan/architecture link.
    Keep the check strict and POSIX-canonical so the same bytes resolve on
    Linux and in the exact-head CI checkout.
    """
    if not isinstance(value, str) or not value or value.startswith("/") or "\x00" in value:
        report.errors.append(f"profile {field_name} must be a relative NUL-free path")
        return None
    path = PurePosixPath(value)
    if ".." in path.parts or str(path) != value:
        report.errors.append(f"profile {field_name} is not canonical: {value!r}")
        return None
    if safe_source(root, value, f"profile {field_name}", report) is None:
        return None
    return value


def string_set(value: Any, label: str, report: Report) -> set[str]:
    if not isinstance(value, list) or not value:
        report.errors.append(f"{label} must be a nonempty list")
        return set()
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            report.errors.append(f"{label} contains a malformed value")
            continue
        result.append(item)
    if len(result) != len(set(result)):
        report.errors.append(f"{label} contains duplicates")
    return set(result)


def object_list(value: Any, label: str, report: Report) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or any(not isinstance(item, dict) for item in value):
        report.errors.append(f"{label} must be a nonempty object list")
        return []
    return list(value)


def added_product_packages(product_text: str) -> set[str]:
    """Return only package names in the first PRODUCT_PACKAGES assignment.

    Android make fragments commonly place explanatory comments immediately
    after a continued assignment.  Treating the whole remainder of the file
    as package data would turn words from those comments into bogus module
    names and make the source-closure gate fail on its own generated output.
    Stop at the first blank/comment line after the assignment has started (or
    at the next make variable) while preserving continuation lines.
    """
    marker = "PRODUCT_PACKAGES +="
    start = product_text.find(marker)
    if start < 0:
        return set()
    result: set[str] = set()
    started = False
    for raw_line in product_text[start + len(marker) :].splitlines():
        line = raw_line.strip()
        if "#" in line:
            line = line.split("#", 1)[0].rstrip()
        if not line:
            if started:
                break
            continue
        # A new assignment marks the end even when the author omitted a
        # separating blank line.
        if started and re.match(r"^[A-Za-z0-9_.-]+\s*(?:\+=|:=|=)", line):
            break
        started = True
        for token in line.replace("\\", " ").split():
            if re.fullmatch(r"[A-Za-z0-9_.+-]+", token):
                result.add(token)
    return result


def verify_active_surface(root: Path, bootstrap: str, init: str, report: Report) -> None:
    """Bind the exact EROFS/host-provider/init-handoff source variant.

    These are source assertions, never materialization or device evidence. The
    old SquashFS/phone-Codex profile is checked independently below and cannot
    silently authorize the changed runtime surface.
    """
    for relative in ACTIVE_SOURCE_FILES:
        safe_source(root, str(relative), "Leap host-relay source", report)
    try:
        active = load_json(root / ACTIVE_RUNTIME_PROFILE, "Leap host-relay runtime profile")
        btfm = load_text(root / ACTIVE_SOURCE_FILES[2], "sun BTFM init rc")
    except (OSError, ValueError) as error:
        report.errors.append(str(error))
        return
    expected = {
        "schema": "org.trillionnium.owner-open.android-runtime-profile.v4",
        "revision": "2026-10-08-leap-api37-init-mount-handoff",
        "profile_id": "leap-codex-host-relay-v1",
        "enabled_property": "ro.trillionnium.owner_open.enabled",
        "data_ready_property": "trillionnium.owner_open.data_ready",
        "ready_property": "trillionnium.owner_open.ready",
        "emergency_stop_property": "sys.trillionnium.owner_open.stop",
        "rootlinux_payload": {
            "image": "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs",
            "image_sha256": "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs.sha256",
            "image_manifest": "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.image-manifest.json",
            "mount_root": "/data/trillionnium/owner-open/root",
            "state_root": "/data/trillionnium/owner-open/state",
            "read_only_lower": True,
        },
        "android_services": {
            "bootstrap": "trillionnium-owner-open-bootstrap",
            "ingress": "trillionnium-owner-open-ingress",
            "emergency_stop": "trillionnium-owner-open-emergency-stop",
        },
        "android_ingress": {
            "abstract_socket": "trillionnium_owner_open",
            "allowed_peer_domain": "u:r:trillionnium_owner_open_client:s0",
            "upstream_socket": "/data/trillionnium/owner-open/state/broker/owner-open.sock",
            "broker_token": "/data/trillionnium/owner-open/state/broker/owner-open.token",
            "maximum_connections": 32,
            "automatic_redispatch": False,
        },
        "rootlinux_supervisor": {
            "executable": "/usr/bin/python3",
            "entry": "/usr/libexec/trillionnium/owner-open/owner_open_rootlinux_supervisor.py",
            "config": "/etc/trillionnium/owner-open/rootlinux-supervisor.json",
        },
        "claims": {
            "source_modules_authored": True,
            "soong_compiled": False,
            "selinux_compiled": False,
            "target_files_built": False,
            "image_included": False,
            "physical_device_observed": False,
            "public_release": False,
        },
        "claim_ceiling": "LEAP_API37_SOURCE_CANDIDATE_NOT_DEVICE_QUALIFIED",
        "mount_handoff": {
            "owner": "android_init",
            "verified_property": "trillionnium.owner_open.verified",
            "mount_ready_property": "trillionnium.owner_open.mount_ready",
            "service_mount_namespace": "mnt",
            "bootstrap_mount_operations": False,
        },
        "provider": {
            "role": "host_codex",
            "phone_adapter": "/usr/libexec/trillionnium/provider-adapter",
            "config": "/etc/trillionnium/owner-open/provider-host-relay-v1.json",
            "long_lived_credentials_on_phone": False,
            "automatic_reconnect": False,
            "automatic_redispatch": False,
        },
    }
    if set(active) != set(expected):
        report.errors.append("Leap host-relay runtime profile key inventory differs")
    for name, value in expected.items():
        if active.get(name) != value:
            report.errors.append(f"Leap host-relay runtime profile {name} differs from exact source contract")
    missing = sorted(value for value in ACTIVE_PAYLOAD_PATHS if value not in bootstrap)
    if missing:
        report.errors.append(f"bootstrap does not bind active payload paths: {missing}")
    if re.search(r"\b(?:mount|umount|umount2)\s*\(", bootstrap):
        report.errors.append("init-handoff bootstrap must not perform mount operations")
    commands = [line.strip() for line in init.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    required_commands = {
        "on property:ro.trillionnium.owner_open.enabled=true && property:trillionnium.owner_open.data_ready=1",
        "exec_start trillionnium_owner_open_verify",
        "on property:trillionnium.owner_open.verified=1 && property:trillionnium.owner_open.data_ready=1",
        "mount erofs loop@/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs /data/trillionnium/owner-open/root ro nosuid nodev",
        "mount none none /data/trillionnium/owner-open/root/var/lib/trillionnium/owner-open bind remount nosuid nodev noexec",
        "mount none none /data/trillionnium/owner-open/root/proc bind remount ro nosuid nodev noexec",
        "mount none none /data/trillionnium/owner-open/root/dev bind remount ro nosuid noexec",
        "mount none none /data/trillionnium/owner-open/root private rec",
        "setprop trillionnium.owner_open.mount_ready 1",
        "start trillionnium_owner_open_bootstrap",
        "umount /data/trillionnium/owner-open/root/dev",
        "umount /data/trillionnium/owner-open/root/proc",
        "umount /data/trillionnium/owner-open/root/var/lib/trillionnium/owner-open",
        "umount /data/trillionnium/owner-open/root",
    }
    missing_commands = sorted(required_commands - set(commands))
    if missing_commands:
        report.errors.append(f"init mount handoff misses safety commands: {missing_commands}")
    if commands.count("start trillionnium_owner_open_bootstrap") != 1:
        report.errors.append("init mount handoff requires exactly one bootstrap start")
    blocks: dict[str, list[str]] = {}
    heading = ""
    for command in commands:
        if command.startswith(("on ", "service ")):
            heading = command
            if heading in blocks:
                report.errors.append("duplicate init action or service heading")
            blocks[heading] = []
        elif heading:
            blocks[heading].append(command)
    verify_trigger = "on property:ro.trillionnium.owner_open.enabled=true && property:trillionnium.owner_open.data_ready=1"
    mount_trigger = "on property:trillionnium.owner_open.verified=1 && property:trillionnium.owner_open.data_ready=1"
    if blocks.get(verify_trigger) != ["exec_start trillionnium_owner_open_verify"]:
        report.errors.append("init verifier must be the sole enabled/data-ready action")
    if blocks.get(mount_trigger) != [
        "mount erofs loop@/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs /data/trillionnium/owner-open/root ro nosuid nodev",
        "mount none /data/trillionnium/owner-open/state /data/trillionnium/owner-open/root/var/lib/trillionnium/owner-open bind",
        "mount none none /data/trillionnium/owner-open/root/var/lib/trillionnium/owner-open bind remount nosuid nodev noexec",
        "mount none /proc /data/trillionnium/owner-open/root/proc bind",
        "mount none none /data/trillionnium/owner-open/root/proc bind remount ro nosuid nodev noexec",
        "mount none /dev /data/trillionnium/owner-open/root/dev bind",
        "mount none none /data/trillionnium/owner-open/root/dev bind remount ro nosuid noexec",
        "mount none none /data/trillionnium/owner-open/root private rec",
        "setprop trillionnium.owner_open.mount_ready 1",
        "start trillionnium_owner_open_bootstrap",
    ]:
        report.errors.append("init mount/start ordering differs from verified data-ready handoff")
    observed_mounts = [command for command in commands if command.startswith(("mount ", "umount "))]
    expected_mounts = [command for command in blocks.get(mount_trigger, []) if command.startswith("mount ")]
    expected_mounts += [
        "umount /data/trillionnium/owner-open/root/dev",
        "umount /data/trillionnium/owner-open/root/proc",
        "umount /data/trillionnium/owner-open/root/var/lib/trillionnium/owner-open",
        "umount /data/trillionnium/owner-open/root",
    ]
    if observed_mounts != expected_mounts:
        report.errors.append("init mount operation inventory differs from exact handoff/teardown")
    for service, arguments, settings in (
        ("verify", "/system_ext/bin/trillionnium-owner-open-bootstrap --verify-image", ["oneshot", "seclabel u:r:trillionnium_owner_open_bootstrap:s0", "capabilities"]),
        ("bootstrap", "/system_ext/bin/trillionnium-owner-open-bootstrap --run-mounted", ["oneshot", "namespace mnt", "seclabel u:r:trillionnium_owner_open_bootstrap:s0", "capabilities SYS_CHROOT KILL"]),
        ("ingress", "/system_ext/bin/trillionnium-owner-open-ingress", ["seclabel u:r:trillionnium_owner_open_ingress:s0", "capabilities"]),
        ("emergency_stop", "/system_ext/bin/trillionnium-owner-open-emergency-stop", ["oneshot", "seclabel u:r:trillionnium_owner_open_emergency_stop:s0", "capabilities"]),
    ):
        key = f"service trillionnium_owner_open_{service} {arguments}"
        if blocks.get(key) != ["class core", "user root", "group root system", "disabled", *settings]:
            report.errors.append(f"init {service} service command/capability contract differs")
    btfm_commands = [line.strip() for line in btfm.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if btfm_commands != [
        "on property:ro.boot.product.vendor.sku=sun && property:ro.build.version.sdk=37",
        "exec u:r:vendor_modprobe:s0 -- /vendor/bin/modprobe -b -s -d /vendor_dlkm/lib/modules -a btfmcodec btfm_slim_codec bt_fm_swr",
    ]:
        report.errors.append("sun BTFM init contract differs from exact SKU/SDK/OEM module invocation")


def verify(root: Path) -> Report:
    report = Report()
    try:
        profile = load_json(root / PROFILE, "owner-open Android profile")
    except (OSError, ValueError) as error:
        report.errors.append(str(error))
        return report
    if profile.get("schema") != PROFILE_SCHEMA:
        report.errors.append(f"profile schema must be {PROFILE_SCHEMA}")

    profile_references: dict[str, str] = {}
    for field_name in ("semantic_contract", "architecture_decision"):
        reference = profile_reference(root, profile.get(field_name), field_name, report)
        if reference is not None:
            profile_references[field_name] = reference

    activation = profile.get("activation")
    claims = profile.get("claims")
    payload = profile.get("rootlinux_payload")
    if not isinstance(activation, dict):
        report.errors.append("profile activation must be an object")
        activation = {}
    if not isinstance(claims, dict):
        report.errors.append("profile claims must be an object")
        claims = {}
    if not isinstance(payload, dict):
        report.errors.append("rootlinux_payload must be an object")
        payload = {}

    if activation.get("selected_in_current_product") is not False:
        report.errors.append("source closure must remain unselected before target-files qualification")
    if claims.get("source_contract_only") is not True:
        report.errors.append("source closure must retain source_contract_only=true")
    for claim in (
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
        if claims.get(claim) is not False:
            report.errors.append(f"source closure cannot promote claim {claim}")
    if profile.get("claim_ceiling") != SOURCE_CLAIM:
        report.errors.append(f"profile claim ceiling must be {SOURCE_CLAIM}")

    source_entries = object_list(
        profile.get("required_source_artifacts"), "required_source_artifacts", report
    )
    source_roles: set[str] = set()
    source_paths: set[str] = set()
    for item in source_entries:
        role, relative = item.get("role"), item.get("path")
        if not isinstance(role, str) or not role or role in source_roles:
            report.errors.append("required source role is malformed or duplicated")
            continue
        if not isinstance(relative, str) or not relative or relative in source_paths:
            report.errors.append("required source path is malformed or duplicated")
            continue
        source_roles.add(role)
        source_paths.add(relative)
        safe_source(root, relative, f"required source {role}", report)

    modules = object_list(
        profile.get("required_product_modules"), "required_product_modules", report
    )
    module_names: set[str] = set()
    for item in modules:
        name = item.get("name")
        if not isinstance(name, str) or not name or name in module_names:
            report.errors.append("required product module name is malformed or duplicated")
            continue
        module_names.add(name)
        if item.get("materialization") != "UNBOUND_SOONG_MODULE":
            report.errors.append(
                f"unbuilt source closure requires UNBOUND_SOONG_MODULE: {name}"
            )

    try:
        bp_text = load_text(root / ANDROID_ROOT / "Android.bp", "owner-open Android.bp")
        product_text = load_text(root / ANDROID_ROOT / "product.mk", "owner-open product.mk")
        supplement_text = load_text(root / COMMON_OWNER_OPEN, "owner-open product supplement")
        fragment_text = load_text(root / GENERATED_FRAGMENT, "generated owner-open package fragment")
        init_text = load_text(
            root / ANDROID_ROOT / "init/trillionnium-owner-open.rc", "owner-open init rc"
        )
        bootstrap_text = load_text(
            root / ANDROID_ROOT / "native/owner_open_bootstrap.cpp", "owner-open bootstrap"
        )
        manifest_text = load_text(
            root / ANDROID_ROOT / "client/AndroidManifest.xml", "owner-open client manifest"
        )
        runtime_profile = load_json(
            root / ANDROID_ROOT / "config/profile-v3.json", "owner-open runtime profile"
        )
        supervisor = load_json(root / SUPERVISOR_CONFIG, "Root Linux supervisor config")
    except (OSError, ValueError) as error:
        report.errors.append(str(error))
        return report

    bp_modules = set(MODULE_PATTERN.findall(bp_text))
    missing_bp = sorted(module_names - bp_modules)
    if missing_bp:
        report.errors.append(f"Android.bp misses required modules: {missing_bp}")
    active_module_names = module_names | ACTIVE_EXTRA_MODULES
    expected_bp_modules = active_module_names | {
        "trillionnium-owner-open-materialized-payload-verifier",
        "trillionnium-owner-open-rootfs-image-verified",
        "trillionnium-owner-open-rootfs-manifest-verified",
        "trillionnium-owner-open-rootfs-digest-verified",
    }
    if bp_modules != expected_bp_modules:
        report.errors.append("Android.bp module inventory differs from exact active source contract")
    product_modules = added_product_packages(product_text)
    missing_product = sorted(active_module_names - product_modules)
    extra_product = sorted(product_modules - active_module_names)
    if missing_product or extra_product:
        report.errors.append(
            f"owner-open PRODUCT_PACKAGES differs: missing={missing_product} extra={extra_product}"
        )
    generated_modules = added_product_packages(fragment_text)
    if generated_modules != module_names:
        report.errors.append(
            "generated package fragment differs from required modules: "
            f"missing={sorted(module_names - generated_modules)} "
            f"extra={sorted(generated_modules - module_names)}"
        )

    common_include = "vendor/trillionnium/config/common.mk"
    product_include = "vendor/trillionnium/owner-open/product.mk"
    if supplement_text.count(common_include) != 1 or supplement_text.count(product_include) != 1:
        report.errors.append("common_owner_open.mk must inherit common and owner-open product exactly once")
    elif supplement_text.index(common_include) > supplement_text.index(product_include):
        report.errors.append("common_owner_open.mk must apply owner-open graph cut after common.mk")

    forbidden = string_set(
        profile.get("forbidden_product_packages"), "forbidden_product_packages", report
    )
    missing_filter = sorted(name for name in forbidden if name not in product_text)
    if missing_filter:
        report.errors.append(f"product cut does not name forbidden packages: {missing_filter}")
    if "filter-out $(_TRILLIONNIUM_OWNER_OPEN_FORBIDDEN_PACKAGES)" not in product_text:
        report.errors.append("product cut does not filter forbidden packages from product variables")

    required_bp_references = {
        "tools/verify_owner_open_materialized_erofs_payload.py",
        "native/owner_open_bootstrap.cpp",
        "native/owner_open_emergency_stop.cpp",
        "native/owner_open_ingress_proxy.cpp",
        "init/trillionnium-owner-open.rc",
        "init/trillionnium-sun-btfm-modprobe.rc",
        "config/profile-codex-host-relay-v1.json",
        "client/AndroidManifest.xml",
    }
    missing_references = sorted(reference for reference in required_bp_references if reference not in bp_text)
    if missing_references:
        report.errors.append(f"Android.bp misses source references: {missing_references}")

    expected_services = {
        str(item.get("name"))
        for item in object_list(profile.get("required_services"), "required_services", report)
        if item.get("owner") == "android_init"
    }
    expected_services |= ACTIVE_EXTRA_SERVICES
    observed_services = set(SERVICE_PATTERN.findall(init_text))
    if expected_services != observed_services:
        report.errors.append(
            f"init service set differs: missing={sorted(expected_services - observed_services)} "
            f"extra={sorted(observed_services - expected_services)}"
        )
    expected_seclabels = {
        "u:r:trillionnium_owner_open_bootstrap:s0",
        "u:r:trillionnium_owner_open_ingress:s0",
        "u:r:trillionnium_owner_open_emergency_stop:s0",
    }
    observed_seclabels = set(SECLABEL_PATTERN.findall(init_text))
    if expected_seclabels != observed_seclabels:
        report.errors.append(
            f"init seclabel set differs: missing={sorted(expected_seclabels - observed_seclabels)} "
            f"extra={sorted(observed_seclabels - expected_seclabels)}"
        )

    runtime_payload = runtime_profile.get("rootlinux_payload")
    runtime_claims = runtime_profile.get("claims")
    if runtime_profile.get("schema") != RUNTIME_PROFILE_SCHEMA:
        report.errors.append(f"runtime profile schema must be {RUNTIME_PROFILE_SCHEMA}")
    if runtime_profile.get("claim_ceiling") != RUNTIME_CLAIM:
        report.errors.append(f"runtime profile claim ceiling must be {RUNTIME_CLAIM}")
    if not isinstance(runtime_payload, dict):
        report.errors.append("runtime profile rootlinux_payload must be an object")
        runtime_payload = {}
    if not isinstance(runtime_claims, dict):
        report.errors.append("runtime profile claims must be an object")
        runtime_claims = {}
    if runtime_claims.get("source_modules_authored") is not True:
        report.errors.append("runtime profile must claim only authored source modules")
    for claim in (
        "soong_compiled",
        "selinux_compiled",
        "target_files_built",
        "image_included",
        "physical_device_observed",
        "public_release",
    ):
        if runtime_claims.get(claim) is not False:
            report.errors.append(f"runtime profile cannot promote claim {claim}")

    path_bindings = {
        str(payload.get("android_install_path")): str(runtime_payload.get("image")),
        str(payload.get("manifest_install_path")): str(runtime_payload.get("image_manifest")),
        str(payload.get("runtime_mount_path")): str(runtime_payload.get("mount_root")),
        str(payload.get("state_root")): str(runtime_payload.get("state_root")),
    }
    drift = {left: right for left, right in path_bindings.items() if left != right}
    if drift:
        report.errors.append(f"canonical and runtime profile paths differ: {drift}")

    verify_active_surface(root, bootstrap_text, init_text, report)
    for marker in (
        "unsetenv(\"ANDROID_SERIAL\")",
        "unsetenv(\"ADB_SERVER_PORT\")",
        "unsetenv(\"ANDROID_ADB_SERVER_PORT\")",
        "MS_RDONLY | MS_NOSUID | MS_NODEV",
    ):
        if marker not in bootstrap_text:
            report.errors.append(f"bootstrap source misses safety marker: {marker}")

    if supervisor.get("schema") != SUPERVISOR_SCHEMA:
        report.errors.append(f"supervisor config schema must be {SUPERVISOR_SCHEMA}")
    if supervisor.get("automatic_effect_redispatch") is not False:
        report.errors.append("supervisor automatic_effect_redispatch must be false")
    environment = supervisor.get("environment")
    if not isinstance(environment, dict):
        report.errors.append("supervisor environment must be an object")
        environment = {}
    if "ANDROID_SERIAL" in environment:
        report.errors.append("supervisor environment may not contain ANDROID_SERIAL")
    if environment.get("ADB_SERVER_SOCKET") != "tcp:127.0.0.1:15038":
        report.errors.append("supervisor ADB_SERVER_SOCKET differs from selected topology")
    children = object_list(supervisor.get("children"), "supervisor children", report)
    child_names = {str(item.get("name")) for item in children}
    if child_names != {"owner-open-broker", "owner-open-adb-relay"}:
        report.errors.append(f"supervisor child set differs: {sorted(child_names)}")
    supervisor_raw = json.dumps(supervisor, ensure_ascii=False, sort_keys=True)
    for marker in (
        "/usr/libexec/trillionnium/trillionnium-owner-open-r5-host",
        "/usr/libexec/trillionnium/trillionnium-owner-open-r5-core",
        "/usr/libexec/trillionnium/provider-adapter",
        "/usr/bin/adb",
        "/usr/libexec/trillionnium/owner-open/adb_smart_socket_relay_release.py",
        "--require-job-journal",
    ):
        if marker not in supervisor_raw:
            report.errors.append(f"supervisor config misses selected runtime marker: {marker}")

    package_match = re.search(r'package="([A-Za-z0-9_.]+)"', manifest_text)
    if package_match is None:
        report.errors.append("owner-open client manifest has no package")
        client_package = None
    else:
        client_package = package_match.group(1)
    if 'android:debuggable="false"' not in manifest_text or 'android:usesCleartextTraffic="false"' not in manifest_text:
        report.errors.append("owner-open client manifest security flags drifted")

    sepolicy_files = {
        "types": ANDROID_ROOT / "sepolicy/private/types.te",
        "domains": ANDROID_ROOT / "sepolicy/private/domains.te",
        "file_contexts": ANDROID_ROOT / "sepolicy/private/file_contexts",
        "property_contexts": ANDROID_ROOT / "sepolicy/private/property_contexts",
        "seapp_contexts": ANDROID_ROOT / "sepolicy/private/seapp_contexts",
    }
    sepolicy_text: dict[str, str] = {}
    for name, relative in sepolicy_files.items():
        try:
            sepolicy_text[name] = load_text(root / relative, f"owner-open SELinux {name}")
        except (OSError, ValueError) as error:
            report.errors.append(str(error))
    required_boundaries = string_set(
        profile.get("required_selinux_boundaries"), "required_selinux_boundaries", report
    )
    all_policy = "\n".join(sepolicy_text.values())
    missing_boundaries = sorted(boundary for boundary in required_boundaries if boundary not in all_policy)
    if missing_boundaries:
        report.errors.append(f"SELinux source misses required boundaries: {missing_boundaries}")
    expected_properties = {
        "enabled_property": "ro.trillionnium.owner_open.enabled",
        "data_ready_property": "trillionnium.owner_open.data_ready",
        "ready_property": "trillionnium.owner_open.ready",
        "emergency_stop_property": "sys.trillionnium.owner_open.stop",
    }
    for field, property_name in expected_properties.items():
        if runtime_profile.get(field) != property_name:
            report.errors.append(
                f"Android runtime profile {field} must be {property_name}"
            )
    # The bootstrap must not start merely because the read-only enable bit is
    # present: post-fs-data has to publish the data_ready barrier after
    # creating and relabeling the private state tree. Keep all four property
    # names in this verifier so profile/SELinux drift cannot silently bypass
    # that ordering contract.
    for property_name in (
        "ro.trillionnium.owner_open.enabled",
        "trillionnium.owner_open.data_ready",
        "trillionnium.owner_open.ready",
        "sys.trillionnium.owner_open.stop",
    ):
        if not re.search(
            rf"(?m)^\s*{re.escape(property_name)}(?:\s|$)",
            sepolicy_text.get("property_contexts", ""),
        ):
            report.errors.append(f"property_contexts misses {property_name}")
    if client_package and f"name={client_package}" not in sepolicy_text.get("seapp_contexts", ""):
        report.errors.append("seapp_contexts does not bind the owner-open client package")

    report.facts = {
        "revision": profile.get("revision"),
        "profile_id": profile.get("profile_id"),
        "foundation_profile_selected": False,
        "authored_runtime_profile": str(ACTIVE_RUNTIME_PROFILE),
        "authored_runtime_profile_id": "leap-codex-host-relay-v1",
        "active_required_module_count": len(active_module_names),
        "semantic_contract": profile_references.get("semantic_contract"),
        "architecture_decision": profile_references.get("architecture_decision"),
        "enabled_property": runtime_profile.get("enabled_property"),
        "data_ready_property": runtime_profile.get("data_ready_property"),
        "ready_property": runtime_profile.get("ready_property"),
        "emergency_stop_property": runtime_profile.get("emergency_stop_property"),
        "source_artifact_count": len(source_paths),
        "required_module_count": len(module_names),
        "android_bp_modules": sorted(bp_modules),
        "product_modules": sorted(product_modules),
        "generated_modules": sorted(generated_modules),
        "android_init_services": sorted(observed_services),
        "selinux_boundaries": sorted(required_boundaries),
        "rootlinux_supervisor_children": sorted(child_names),
        "source_modules_authored": True,
        "soong_compiled": False,
        "selinux_compiled": False,
        "target_files_built": False,
        "image_included": False,
        "physical_device_observed": False,
        "public_release": False,
        "automatic_effect_redispatch": False,
        "claim_ceiling": "ANDROID_OWNER_OPEN_SOURCE_CLOSURE_PASSED_NOT_COMPILED",
    }
    if report.ok:
        report.warnings.append(
            "source closure is complete, but Soong/init/SELinux compilation, target-files and device evidence remain external gates"
        )
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
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        print("PASS_OWNER_OPEN_ANDROID_SOURCE_CLOSURE compiled=false")
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
