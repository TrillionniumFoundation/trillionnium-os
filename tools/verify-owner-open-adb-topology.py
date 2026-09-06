#!/usr/bin/env python3
"""Verify the selected owner-open ordinary-ADB physical topology contract."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any

CONTRACT = Path("docs/contracts/owner-open-r5-adb-topology-v1.json")
SCHEMA = "org.trillionnium.owner-open.adb-topology.v1"
MAX_JSON_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def bounded_regular(path: Path, maximum: int, label: str) -> bytes:
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


def load_contract(path: Path) -> dict[str, Any]:
    raw = bounded_regular(path, MAX_JSON_BYTES, "ADB topology contract")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise ValueError(f"invalid ADB topology contract: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError(f"ADB topology schema must be {SCHEMA}")
    return value


def exact_keys(value: Any, expected: set[str], label: str, report: Report) -> dict[str, Any]:
    if not isinstance(value, dict):
        report.errors.append(f"{label} must be an object")
        return {}
    actual = set(value)
    if actual != expected:
        report.errors.append(
            f"{label} keys differ: missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )
    return value


def loopback(value: Any, label: str, report: Report) -> str | None:
    if not isinstance(value, str):
        report.errors.append(f"{label} must be a loopback IP string")
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        report.errors.append(f"{label} is not an IP address")
        return None
    if not address.is_loopback:
        report.errors.append(f"{label} must remain loopback-only")
    return value


def port(value: Any, label: str, report: Report) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        report.errors.append(f"{label} must be an integer in 1..65535")
        return None
    return value


def canonical_rootlinux_path(value: Any, label: str, report: Report) -> str | None:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        report.errors.append(f"{label} must be an absolute NUL-free path")
        return None
    parsed = PurePosixPath(value)
    if ".." in parsed.parts or str(parsed) != value:
        report.errors.append(f"{label} is not canonical")
    return value


def source_file(root: Path, relative: Any, label: str, report: Report) -> Path | None:
    if not isinstance(relative, str) or not relative or relative.startswith("/"):
        report.errors.append(f"{label} path is malformed")
        return None
    path = root / relative
    try:
        root_real = root.resolve(strict=True)
        parent_real = path.parent.resolve(strict=True)
        if parent_real != root_real and root_real not in parent_real.parents:
            report.errors.append(f"{label} escapes the repository: {relative}")
            return None
        bounded_regular(path, MAX_SOURCE_BYTES, label)
    except (OSError, ValueError) as error:
        report.errors.append(str(error))
        return None
    return path


def verify(root: Path) -> Report:
    report = Report()
    try:
        value = load_contract(root / CONTRACT)
    except (OSError, ValueError) as error:
        report.errors.append(str(error))
        return report

    top = exact_keys(
        value,
        {
            "schema",
            "revision",
            "topology_id",
            "selection_status",
            "mode",
            "rootlinux_client",
            "device_relay",
            "owner_host_bootstrap",
            "qualification",
            "required_sources",
            "required_markers",
            "claims",
            "claim_ceiling",
        },
        "ADB topology",
        report,
    )
    if top.get("selection_status") != "SOURCE_SELECTED":
        report.errors.append("ADB topology must be SOURCE_SELECTED")
    if top.get("mode") != "device_loopback_reverse_to_owner_host_adb_server":
        report.errors.append("ADB topology mode is not the reviewed reverse-relay topology")

    client = exact_keys(
        top.get("rootlinux_client"),
        {
            "adb_path",
            "artifact_state",
            "required_architecture",
            "adb_server_socket",
            "android_serial_environment",
            "exact_argv_passthrough",
            "serial_injected",
            "host_injected",
            "port_injected",
            "privilege_injected",
            "automatic_redispatch",
        },
        "rootlinux_client",
        report,
    )
    adb_path = canonical_rootlinux_path(client.get("adb_path"), "rootlinux adb_path", report)
    if client.get("artifact_state") not in {"UNBOUND_ARM64_ADB_ARTIFACT", "BOUND_ARM64_ADB_ARTIFACT"}:
        report.errors.append("rootlinux adb artifact_state is invalid")
    if client.get("required_architecture") != "aarch64":
        report.errors.append("ordinary adb artifact must be aarch64")
    if client.get("android_serial_environment") != "UNSET":
        report.errors.append("ANDROID_SERIAL must be removed from the Root Linux client environment")
    if client.get("exact_argv_passthrough") is not True:
        report.errors.append("ordinary adb must preserve exact argv")
    for field_name in (
        "serial_injected",
        "host_injected",
        "port_injected",
        "privilege_injected",
        "automatic_redispatch",
    ):
        if client.get(field_name) is not False:
            report.errors.append(f"rootlinux_client.{field_name} must be false")

    relay = exact_keys(
        top.get("device_relay"),
        {
            "entry",
            "listen_host",
            "listen_port",
            "upstream_host",
            "upstream_port",
            "byte_transparent",
            "adb_protocol_parsed",
            "payload_logged",
            "automatic_redispatch",
        },
        "device_relay",
        report,
    )
    listen_host = loopback(relay.get("listen_host"), "relay listen_host", report)
    upstream_host = loopback(relay.get("upstream_host"), "relay upstream_host", report)
    listen_port = port(relay.get("listen_port"), "relay listen_port", report)
    upstream_port = port(relay.get("upstream_port"), "relay upstream_port", report)
    if listen_port is not None and upstream_port is not None and listen_port == upstream_port:
        report.errors.append("relay listen and upstream ports must be distinct")
    if relay.get("byte_transparent") is not True:
        report.errors.append("relay must be byte transparent")
    for field_name in ("adb_protocol_parsed", "payload_logged", "automatic_redispatch"):
        if relay.get(field_name) is not False:
            report.errors.append(f"device_relay.{field_name} must be false")

    bootstrap = exact_keys(
        top.get("owner_host_bootstrap"),
        {
            "entry",
            "mapping_direction",
            "mapping_action",
            "device_endpoint",
            "owner_host_endpoint",
            "exact_serial_required",
            "host_server_listener_policy",
            "credential_custody",
            "usb_transport_owner",
            "automatic_mapping_retry",
        },
        "owner_host_bootstrap",
        report,
    )
    if bootstrap.get("mapping_direction") != "device_to_owner_host":
        report.errors.append("ADB mapping direction must be device_to_owner_host")
    if bootstrap.get("mapping_action") != "adb_reverse":
        report.errors.append("owner-host mapping must use explicit adb reverse")
    if bootstrap.get("device_endpoint") != f"tcp:{upstream_port}":
        report.errors.append("reverse device endpoint does not match relay upstream port")
    if bootstrap.get("owner_host_endpoint") != "tcp:5037":
        report.errors.append("reverse owner-host endpoint must bind the ordinary adb server port")
    if bootstrap.get("exact_serial_required") is not True:
        report.errors.append("owner-host bootstrap must require an explicit serial")
    if bootstrap.get("host_server_listener_policy") != "LOOPBACK_OR_EXPLICIT_OWNER_ACKNOWLEDGEMENT":
        report.errors.append("owner-host adb server listener policy drifted")
    if bootstrap.get("credential_custody") != "OWNER_HOST_PRIVATE_ADB_KEY":
        report.errors.append("ADB key custody must remain on the owner host")
    if bootstrap.get("usb_transport_owner") != "OWNER_HOST_ADB_SERVER":
        report.errors.append("USB transport must remain owned by the owner-host adb server")
    if bootstrap.get("automatic_mapping_retry") is not False:
        report.errors.append("uncertain reverse mappings may not be automatically retried")

    expected_socket = f"tcp:{listen_host}:{listen_port}"
    if client.get("adb_server_socket") != expected_socket:
        report.errors.append("ADB_SERVER_SOCKET does not target the selected local relay")

    qualification = exact_keys(
        top.get("qualification"),
        {
            "exact_argv_runner",
            "required_cases",
            "same_installed_codex_turn_required",
            "uncertain_acceptance_requires_unknown_not_retry",
        },
        "qualification",
        report,
    )
    cases = qualification.get("required_cases")
    if not isinstance(cases, list) or len(cases) != len(set(cases)) or any(
        not isinstance(item, str) or not item for item in cases
    ):
        report.errors.append("qualification.required_cases must be a unique string list")
    required_cases = {
        "zero_targets",
        "one_target",
        "multiple_targets",
        "authorized",
        "unauthorized",
        "offline",
        "unknown_subcommand",
        "shell_success",
        "shell_failure",
        "binary_push_pull",
        "install_update",
        "server_restart",
        "usb_disconnect",
        "reboot_recovery",
    }
    if isinstance(cases, list) and set(cases) != required_cases:
        report.errors.append("physical ADB qualification case set drifted")
    if qualification.get("same_installed_codex_turn_required") is not True:
        report.errors.append("physical ADB promotion must require one installed Codex turn")
    if qualification.get("uncertain_acceptance_requires_unknown_not_retry") is not True:
        report.errors.append("uncertain ADB acceptance must become unknown, never blind retry")

    sources = top.get("required_sources")
    source_paths: dict[str, Path] = {}
    if not isinstance(sources, list) or not sources:
        report.errors.append("required_sources must be nonempty")
    else:
        roles: set[str] = set()
        paths: set[str] = set()
        for item in sources:
            if not isinstance(item, dict) or set(item) != {"role", "path"}:
                report.errors.append("required source entries must contain exact role/path fields")
                continue
            role, relative = item.get("role"), item.get("path")
            if not isinstance(role, str) or not role or role in roles:
                report.errors.append("required source role is malformed or duplicated")
                continue
            if not isinstance(relative, str) or not relative or relative in paths:
                report.errors.append("required source path is malformed or duplicated")
                continue
            roles.add(role)
            paths.add(relative)
            path = source_file(root, relative, f"required source {role}", report)
            if path is not None:
                source_paths[relative] = path

    if relay.get("entry") not in source_paths:
        report.errors.append("selected relay entry is not a required source")
    if bootstrap.get("entry") not in source_paths:
        report.errors.append("selected reverse bootstrap is not a required source")
    if qualification.get("exact_argv_runner") not in source_paths:
        report.errors.append("selected exact-argv runner is not a required source")

    markers = top.get("required_markers")
    if not isinstance(markers, dict) or not markers:
        report.errors.append("required_markers must be a nonempty object")
    else:
        if set(markers) - set(source_paths):
            report.errors.append(
                f"required_markers references unselected sources: {sorted(set(markers) - set(source_paths))}"
            )
        for relative, expected in markers.items():
            path = source_paths.get(relative)
            if path is None:
                continue
            if not isinstance(expected, list) or not expected or any(
                not isinstance(item, str) or not item for item in expected
            ):
                report.errors.append(f"required markers for {relative} are malformed")
                continue
            text = path.read_text(encoding="utf-8")
            missing = [item for item in expected if item not in text]
            if missing:
                report.errors.append(f"required source markers missing from {relative}: {missing}")

    claims = exact_keys(
        top.get("claims"),
        {
            "source_topology_selected",
            "relay_source_implemented",
            "reverse_bootstrap_source_implemented",
            "exact_argv_qualification_source_implemented",
            "arm64_adb_artifact_bound",
            "owner_host_mapping_observed",
            "physical_usb_target_observed",
            "same_turn_physical_adb_effect_observed",
            "fault_matrix_qualified",
            "public_release",
        },
        "claims",
        report,
    )
    for field_name in (
        "source_topology_selected",
        "relay_source_implemented",
        "reverse_bootstrap_source_implemented",
        "exact_argv_qualification_source_implemented",
    ):
        if claims.get(field_name) is not True:
            report.errors.append(f"claims.{field_name} must be true for the selected source topology")
    for field_name in (
        "arm64_adb_artifact_bound",
        "owner_host_mapping_observed",
        "physical_usb_target_observed",
        "same_turn_physical_adb_effect_observed",
        "fault_matrix_qualified",
        "public_release",
    ):
        if claims.get(field_name) is not False:
            report.errors.append(f"claims.{field_name} cannot be promoted without external evidence")
    if client.get("artifact_state") == "BOUND_ARM64_ADB_ARTIFACT" and claims.get("arm64_adb_artifact_bound") is not True:
        report.errors.append("bound adb artifact state requires a matching claim")
    if top.get("claim_ceiling") != "ADB_TOPOLOGY_SOURCE_SELECTED_NOT_PHYSICAL":
        report.errors.append("ADB topology claim ceiling drifted")

    report.facts = {
        "revision": top.get("revision"),
        "topology_id": top.get("topology_id"),
        "mode": top.get("mode"),
        "adb_path": adb_path,
        "adb_server_socket": client.get("adb_server_socket"),
        "relay": {
            "listen_host": listen_host,
            "listen_port": listen_port,
            "upstream_host": upstream_host,
            "upstream_port": upstream_port,
        },
        "reverse": {
            "device_endpoint": bootstrap.get("device_endpoint"),
            "owner_host_endpoint": bootstrap.get("owner_host_endpoint"),
        },
        "required_sources": sorted(source_paths),
        "claim_ceiling": top.get("claim_ceiling"),
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
        print("PASS_OWNER_OPEN_ADB_TOPOLOGY_SOURCE_SELECTED_NOT_PHYSICAL")
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
