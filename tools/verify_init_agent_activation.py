#!/usr/bin/env python3
"""Verify the source-side init -> Agent API activation graph.

This is deliberately a host-only contract checker.  It reads the Android
source files and the Rust ABI/daemon source, but never talks to ``adb`` and
never starts a service.  A passing result means only that the *source graph*
contains the reviewed edges.  Live init state, an authenticated peer, a
Codex turn, and effect authority remain explicit HOLDs until independently
observed on a matching target.

The checker exists because a source init rc file can be present while an old
target-files image omits it (or while init never reaches the readiness
properties).  Treating source presence as runtime activation was the source
of several misleading P0 reports.  Keep the distinction in the output and
in the exit status: malformed source is a hard failure; a complete source
graph with no live observation is ``PASS_SOURCE_GRAPH_DEVICE_HOLD``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import zipfile
from dataclasses import dataclass
from typing import Any


SCHEMA = "org.trillionnium.init-agent-activation-host-contract.v1"
SOURCE_PASS = "PASS_SOURCE_GRAPH_DEVICE_HOLD"
SOURCE_HOLD = "HOLD_SOURCE_GRAPH_INCOMPLETE"
FAIL = "FAIL_CLOSED_SOURCE_CONTRACT"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TARGET_ENTRY_BYTES = 8 * 1024 * 1024
SHA256_RE = r"^[0-9a-f]{64}$"


class ContractError(RuntimeError):
    """A malformed, unsafe, or incomplete source contract."""


@dataclass(frozen=True)
class SourceFile:
    key: str
    relative: str


SOURCE_FILES = (
    SourceFile(
        "init_rc",
        "vendor/trillionnium/prebuilt/common/etc/init/init.trillionnium-system_ext.rc",
    ),
    SourceFile(
        "daemon_wrapper",
        "vendor/trillionnium/prebuilt/common/bin/trillionniumd.sh",
    ),
    SourceFile(
        "linux_manifest",
        "vendor/trillionnium/prebuilt/common/linux/manifest.txt",
    ),
    SourceFile(
        "agent_abi",
        "crates/trillionnium-os-types/contracts/direct-agent-host-abi-v1.json",
    ),
    SourceFile("daemon_main", "apps/trillionniumd/src/main.rs"),
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_symlink_parents(path: Path) -> None:
    if not path.is_absolute():
        raise ContractError(f"path must be absolute: {path}")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except OSError as exc:
            raise ContractError(f"path component unavailable: {current}") from exc
        if stat.S_ISLNK(mode):
            raise ContractError(f"symlink path component is forbidden: {current}")


def read_regular(path: Path, *, label: str, maximum: int = MAX_SOURCE_BYTES) -> bytes:
    """Read one stable, singly-linked regular file without following symlinks."""

    path = Path(os.path.abspath(os.fspath(path)))
    _reject_symlink_parents(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ContractError(f"{label} is unavailable: {path}") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise ContractError(f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        after = os.fstat(fd)
        if total != before.st_size or before != after:
            raise ContractError(f"{label} changed while being read")
    finally:
        os.close(fd)
    try:
        current = os.lstat(path)
    except OSError as exc:
        raise ContractError(f"{label} disappeared after read") from exc
    if stat.S_ISLNK(current.st_mode) or current != before:
        raise ContractError(f"{label} pathname changed while being read")
    return b"".join(chunks)


def canonical_json(raw: bytes, *, label: str) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ContractError(f"{label} contains duplicate key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ContractError(f"{label} contains non-finite number: {token}")
            ),
        )
    except ContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be a JSON object")
    return value


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise ContractError(f"{label} is missing required marker: {needle}")


def require_regex(text: str, pattern: str, label: str) -> None:
    import re

    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise ContractError(f"{label} is missing required pattern: {pattern}")


def service_block(init: str, service: str) -> str:
    """Return one init service stanza, bounded before the next top-level stanza."""

    import re

    match = re.search(
        rf"(?ms)^service\s+{re.escape(service)}\b(?P<body>.*?)(?=^(?:service|on)\s|\Z)",
        init,
    )
    if match is None:
        raise ContractError(f"init service stanza is absent: {service}")
    return match.group(0)


def event_block(init: str, prefix: str) -> str:
    """Return one bounded init property-event stanza."""

    import re

    match = re.search(
        rf"(?ms)^on\s+{re.escape(prefix)}\s*$.*?(?=^(?:service|on)\s|\Z)",
        init,
    )
    if match is None:
        raise ContractError(f"init event stanza is absent: {prefix}")
    return match.group(0)


def parse_manifest(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8", "strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise ContractError("linux manifest is not UTF-8") from exc
    result: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        if line.count("=") != 1:
            raise ContractError(f"linux manifest line {number} is not key=value")
        key, value = line.split("=", 1)
        if not key or not value or key in result or any(ord(c) < 0x20 for c in value):
            raise ContractError(f"linux manifest line {number} is malformed")
        result[key] = value
    if not result:
        raise ContractError("linux manifest is empty")
    return result


def inspect_source_graph(android_root: Path, rust_root: Path) -> dict[str, Any]:
    files: dict[str, bytes] = {}
    measurements: dict[str, dict[str, Any]] = {}
    for spec in SOURCE_FILES:
        root = rust_root if spec.key in {"agent_abi", "daemon_main"} else android_root
        path = root / spec.relative
        raw = read_regular(path, label=spec.key)
        files[spec.key] = raw
        measurements[spec.key] = {
            "relative": spec.relative,
            "size": len(raw),
            "sha256": sha256(raw),
        }

    # The Android vendor checkout historically stores shell/init inputs with
    # CRLF.  Normalize only the in-memory parser view; measurements retain the
    # exact source bytes so provenance is not silently rewritten.
    init = files["init_rc"].decode("utf-8", "strict").replace("\r\n", "\n")
    wrapper = files["daemon_wrapper"].decode("utf-8", "strict").replace("\r\n", "\n")
    manifest = parse_manifest(files["linux_manifest"])
    abi = canonical_json(files["agent_abi"], label="agent ABI contract")
    main = files["daemon_main"].decode("utf-8", "strict").replace("\r\n", "\n")

    # Init graph: bootstrap -> prepared tree -> egress/high-water/shell gates
    # -> daemon.  These checks intentionally inspect source text only.
    require(init, "service trillionnium_root_linux_bootstrap /system_ext/bin/trillionnium-root-linux-bootstrap", "init bootstrap service")
    require(init, "service trillionnium_root_linux_daemon /system_ext/bin/trillionniumd --agent-api-uds", "init daemon service")
    require_regex(init, r"on property:sys\.trillionnium\.rootlinux\.prepare=0[\s\S]*?start trillionnium_agent_egress_guard", "init prepare/egress edge")
    require_regex(init, r"on property:sys\.trillionnium\.agent_egress_guard=ready && property:sys\.trillionnium\.agentd\.desired=1[\s\S]*?start trillionnium_root_linux_daemon", "init authenticated readiness edge")
    require_regex(init, r"on property:sys\.trillionnium\.high_water_ready=ready[\s\S]*?start trillionnium_shell_exec_broker", "init high-water/shell edge")
    require(init, "service trillionnium_root_linux_daemon", "init daemon declaration")
    require(init, "user root", "init daemon root ownership")
    require(init, "disabled\n    oneshot", "init oneshot/disabled lifecycle")

    # Wrapper and manifest bind the same socket/service identity.
    require(wrapper, "export TRILLIONNIUM_AGENT_API_SOCKET=/run/trillionnium/agent-api-v2.sock", "daemon socket export")
    require(wrapper, "TRILLIONNIUM_ANDROID_UI_AGENT_API=1", "Android built-in provider gate")
    require(wrapper, "exec /system_ext/bin/trillionnium-root-linux-run /usr/bin/trillionniumd", "measured daemon runner")
    if manifest.get("android_daemon_service") != "trillionnium_root_linux_daemon":
        raise ContractError("manifest daemon service does not match init")
    if manifest.get("agent_api_requires_adb") != "false":
        raise ContractError("manifest must keep Agent API independent of adb")

    # ABI and daemon source prove the intended authenticated channel.  Presence
    # is not runtime proof; the output records that distinction explicitly.
    kernel = abi.get("carriers", {}).get("kernel_agent_api")
    if not isinstance(kernel, dict):
        raise ContractError("agent ABI kernel carrier is missing")
    if kernel.get("socket") != "/run/trillionnium/agent-api-v2.sock":
        raise ContractError("ABI socket does not match wrapper")
    if kernel.get("trust_domain") != "kernel_peercred_peersec_channel_binding":
        raise ContractError("ABI trust domain is not the reviewed peer channel")
    require(main, "fn bind_agent_api_listener", "daemon listener implementation")
    require(main, "libc::SO_PEERCRED", "daemon peer credential check")
    require(main, "libc::SO_PEERSEC", "daemon SELinux peer check")
    require(main, "requires_channel_binding", "daemon channel-binding gate")
    require(main, "AgentApiReplayStore::open_from_env", "daemon replay store")
    require(main, "from_store_after_exclusive_startup", "daemon exclusive startup")

    checks = [
        {"id": "init_bootstrap_service", "status": "PASS"},
        {"id": "init_daemon_service", "status": "PASS"},
        {"id": "init_readiness_edges", "status": "PASS"},
        {"id": "daemon_socket_contract", "status": "PASS"},
        {"id": "manifest_service_contract", "status": "PASS"},
        {"id": "agent_api_peer_auth_source", "status": "PASS"},
        {"id": "agent_api_replay_source", "status": "PASS"},
    ]
    return {
        "source_root": str(android_root),
        "rust_root": str(rust_root),
        "measurements": measurements,
        "checks": checks,
        "source_graph": "PASS",
        "live_activation": "HOLD_NOT_OBSERVED",
        "authenticated_peer": "HOLD_NOT_OBSERVED",
        "codex_turn": "HOLD_NOT_RUN",
        "effect_authority": "DISABLED",
        "device_mutation": False,
    }


def inspect_target_files(path: Path) -> dict[str, Any]:
    """Inspect only the ZIP directory and small init/socket entries."""

    path = Path(os.path.abspath(os.fspath(path)))
    _reject_symlink_parents(path.parent)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ContractError(f"target-files ZIP is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > 64 * 1024 * 1024 * 1024
    ):
        raise ContractError("target-files ZIP is not a bounded regular file")
    required = {
        "SYSTEM_EXT/etc/init/init.trillionnium-system_ext.rc": "init_rc",
        "SYSTEM_EXT/bin/trillionniumd": "daemon_payload",
    }
    observations: dict[str, Any] = {"path": str(path), "required": {}}
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            for name, key in required.items():
                info = archive.getinfo(name) if name in names else None
                if info is None:
                    observations["required"][key] = {"status": "HOLD", "reason": "entry_absent"}
                    continue
                if info.file_size > MAX_TARGET_ENTRY_BYTES:
                    raise ContractError(f"target entry exceeds bound: {name}")
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise ContractError(f"target entry is a symlink: {name}")
                entry = archive.read(info)
                observations["required"][key] = {
                    "status": "PASS",
                    "size": len(entry),
                    "sha256": sha256(entry),
                }
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise ContractError(f"target-files archive cannot be inspected: {exc}") from exc
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise ContractError("target-files ZIP disappeared after inspection") from exc
    if after != before or stat.S_ISLNK(after.st_mode):
        raise ContractError("target-files ZIP changed while being inspected")
    observations["source_graph_is_not_live_proof"] = True
    return observations


def build_evidence(android_root: Path, rust_root: Path, target_files: Path | None) -> dict[str, Any]:
    source = inspect_source_graph(android_root, rust_root)
    target = None if target_files is None else inspect_target_files(target_files)
    checks = source["checks"]
    if target is not None:
        target_values = target["required"]
        if any(item.get("status") != "PASS" for item in target_values.values()):
            source["target_artifacts"] = target
            source["decision"] = SOURCE_HOLD
        else:
            source["target_artifacts"] = target
            source["decision"] = SOURCE_PASS
    else:
        source["target_artifacts"] = {"status": "HOLD", "reason": "target_files_not_supplied"}
        source["decision"] = SOURCE_PASS
    return {
        "schema": SCHEMA,
        "decision": source.pop("decision"),
        "scope": "host_only_source_contract",
        "source": source,
        "safety": {
            "device_write_performed": False,
            "adb_invoked": False,
            "init_service_started": False,
            "codex_turn_started": False,
            "effect_sent": False,
            "reboot_performed": False,
            "flash_performed": False,
            "authority_enabled": False,
        },
        "evidence_sha256": "computed_over_object_without_this_field",
    }


def canonical_evidence(value: dict[str, Any]) -> bytes:
    copy = dict(value)
    copy.pop("evidence_sha256", None)
    digest = sha256(json.dumps(copy, sort_keys=True, separators=(",", ":")).encode())
    value["evidence_sha256"] = digest
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def publish_new(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise ContractError(f"refusing to overwrite evidence: {path}")
    _reject_symlink_parents(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ContractError(f"evidence publication failed: {path}") from exc
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--android-root", required=True, type=Path)
    parser.add_argument("--rust-root", required=True, type=Path)
    parser.add_argument("--target-files", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        evidence = build_evidence(args.android_root, args.rust_root, args.target_files)
        encoded = canonical_evidence(evidence)
        if args.output is not None:
            publish_new(args.output, encoded)
        else:
            sys.stdout.buffer.write(encoded)
        return 0
    except (ContractError, OSError, UnicodeError) as exc:
        print(f"verify_init_agent_activation: {FAIL}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
