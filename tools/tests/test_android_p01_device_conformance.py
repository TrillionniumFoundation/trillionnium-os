#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


TOOL_PATH = Path(__file__).resolve().parents[1] / "android_p01_device_conformance.py"
SPEC = importlib.util.spec_from_file_location("android_p01_device_conformance", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


# Synthetic fixture hashes.  Product hashes must come from a measured contract.
ARTIFACT_HASHES = {
    "p01_launcher": "1" * 64,
    "p01_core": "2" * 64,
    "daemon_payload": "3" * 64,
    "system_api": "4" * 64,
    "p01_replay_helper": "5" * 64,
    "high_water": "6" * 64,
    "codex_launcher": "7" * 64,
    "codex_runtime": "8" * 64,
    "accessibility": "a" * 64,
}


def manifest_bytes(extra_lines: list[str] | None = None) -> bytes:
    facts = manifest_facts()
    lines = [f"{key}={value}" for key, value in facts.items()]
    lines.extend(extra_lines or [])
    return ("\n".join(lines) + "\n").encode()


def manifest_facts() -> dict[str, str]:
    return {
        "p01_product_variant": "userdebug",
        "p01_binding_schema": "trillionnium.direct-operation.binding.v3",
        "p01_system_api_device_conformance_sha256": ARTIFACT_HASHES["system_api"],
        "p01_system_api_device_replay_sync_path": (
            "/system_ext/bin/trillionnium-system-api-device-conformance-replay-sync"
        ),
        "p01_system_api_device_replay_sync_sha256": ARTIFACT_HASHES[
            "p01_replay_helper"
        ],
        "p01_daemon_binding_custody_predispatch_wired": (
            "true_userdebug_conformance_only"
        ),
        "p01_daemon_logical_delivery_admission_wired": (
            "true_userdebug_conformance_only"
        ),
        "p01_daemon_direct_tool_call_prepared_ack_wired": (
            "true_userdebug_conformance_only"
        ),
        "p01_sealed_replay_authority_handoff": (
            "complete_source_host_userdebug_only"
        ),
        "p01_daemon_custody_ack_compact_retire": (
            "complete_source_host_userdebug_only"
        ),
        "p01_android_ack_transport": "source_wired_device_evidence_hold",
        "p01_external_authority_device_evidence": "hold_not_run",
        "p01_hardware_rollback_anchor": "hold_not_implemented",
        "p01_physical_device_evidence": "hold_not_run",
        "p01_release_allowed": "false_userdebug_only",
        "p01_accessibility_authorized": "false_hold",
        "p01_windowscompat": "research_only_not_implemented",
        "agent_outer_ack_integration": (
            "p01_source_host_complete_device_evidence_hold_userdebug_only"
        ),
        "agentd_payload_sha256": ARTIFACT_HASHES["daemon_payload"],
        "agent_system_api_sha256": ARTIFACT_HASHES["system_api"],
        "codex_integrity_launcher_sha256": ARTIFACT_HASHES["codex_launcher"],
        "codex_runtime_sha256": ARTIFACT_HASHES["codex_runtime"],
        "agent_accessibility_sha256": ARTIFACT_HASHES["accessibility"],
    }


def expectation_contract(manifest: bytes | None = None) -> dict[str, object]:
    manifest = manifest if manifest is not None else manifest_bytes()
    return {
        "schema": tool.CONTRACT_SCHEMA,
        "product": "fogos",
        "variant": "userdebug",
        "upstream_evidence": {"kind": "target_files", "sha256": "b" * 64},
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "system_ext_image_sha256": "c" * 64,
        "required_manifest_facts": manifest_facts(),
        "artifact_sha256": dict(ARTIFACT_HASHES),
        "release_boundaries": dict(tool.EXPECTED_RELEASE_BOUNDARIES),
        "authorizes_device_mutation": False,
    }


def contract_measurement(contract: dict[str, object]) -> dict[str, object]:
    data = tool._canonical_json_bytes(contract)
    return {
        "path": "/measured/test/expectation-contract.json",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "device": 1,
        "inode": 2,
        "mode": "0644",
    }


def proc_stat(pid: int, start_time: int) -> bytes:
    # Fields after comm start at field 3; starttime is field 22 / index 19.
    trailing = ["S", *(["0"] * 18), str(start_time)]
    return f"{pid} (trillionnium service) {' '.join(trailing)}\n".encode()


class FakeAdb:
    def __init__(
        self,
        *,
        root: bool = True,
        manifest: bytes | None = None,
        contract: dict[str, object] | None = None,
    ) -> None:
        self.root = root
        self.calls: list[tuple[str, str | None]] = []
        self.command_audit: list[dict[str, object]] = []
        self.manifest = manifest if manifest is not None else manifest_bytes()
        self.contract = contract if contract is not None else expectation_contract(self.manifest)
        self.boot_id = "01234567-89ab-cdef-0123-456789abcdef"
        self.properties = {
            "ro.product.device": "fogos",
            "ro.build.type": "userdebug",
            "ro.build.fingerprint": (
                "Trillionnium/trillionnium_fogos/fogos:16/BP4A/test:userdebug/test-keys"
            ),
            "ro.system_ext.build.fingerprint": (
                "Trillionnium/trillionnium_fogos/fogos:16/BP4A/test:userdebug/test-keys"
            ),
            "ro.boot.slot_suffix": "_a",
            "ro.boot.verifiedbootstate": "green",
            "ro.boot.vbmeta.device_state": "locked",
            "ro.boot.flash.locked": "1",
            "ro.boot.vbmeta.digest": "a" * 64,
            "ro.boot.veritymode": "enforcing",
            "ro.boot.avb_version": "1.3",
            "sys.trillionnium.rootlinux.prepare": "0",
            "sys.trillionnium.agentd.desired": "1",
            "sys.trillionnium.agent_egress_guard": "ready",
            "init.svc.trillionnium_root_linux_bootstrap": "stopped",
            "init.svc.trillionnium_agent_egress_guard": "stopped",
            "init.svc.trillionnium_direct_operation_custody_high_water": "running",
            "init.svc.trillionnium_root_linux_daemon": "running",
            "init.svc_debug_pid.trillionnium_root_linux_daemon": "411",
            "init.svc_debug_pid.trillionnium_direct_operation_custody_high_water": "412",
        }
        self.hashes: dict[str, str] = {}
        self.stats: dict[str, dict[str, object]] = {}
        for index, artifact in enumerate(tool.ARTIFACT_SPECS, 1):
            expected_hash = tool._expected_artifact_hash(artifact, self.contract)
            self.hashes[artifact.source] = expected_hash
            source_stat = {
                "file_type": "regular file",
                "size": 8192 + index,
                "mode": "0755",
                "uid": 0,
                "gid": 0,
                "device": 100,
                "inode": 1000 + index,
                "links": 1,
                "selinux_context": artifact.context or "u:object_r:system_file:s0",
            }
            self.stats[artifact.source] = source_stat
            if artifact.root_target:
                self.hashes[artifact.root_target] = expected_hash
                self.stats[artifact.root_target] = dict(source_stat)
        self.stats[tool.HIGH_WATER_SOCKET] = {
            "file_type": "socket",
            "size": 0,
            "mode": "0600",
            "uid": 0,
            "gid": 0,
            "device": 101,
            "inode": 9001,
            "links": 1,
            "selinux_context": (
                "u:object_r:trillionnium_direct_operation_custody_high_water_socket:s0"
            ),
        }
        proc_stat_value = {
            "file_type": "directory",
            "size": 0,
            "mode": "0555",
            "uid": 0,
            "gid": 0,
            "device": 202,
            "inode": 1,
            "links": 100,
            "selinux_context": "u:object_r:proc:s0",
        }
        self.stats[tool.PROC_SOURCE] = proc_stat_value
        self.stats[tool.PROC_ROOT_TARGET] = dict(proc_stat_value)

    def _record(self, operation: str, detail: str | None = None) -> None:
        self.calls.append((operation, detail))
        self.command_audit.append(
            {
                "sequence": len(self.command_audit) + 1,
                "operation": operation,
                "read_only_argv": [operation, detail] if detail else [operation],
                "exit_code": 0,
                "stdout_bytes": 0,
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "stderr_bytes": 0,
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            }
        )

    def get_state(self) -> str:
        self._record("get_state")
        return "device"

    def getprop(self, key: str) -> str:
        self._record("getprop", key)
        return self.properties[key]

    def getenforce(self) -> str:
        self._record("getenforce")
        return "Enforcing"

    def shell_uid(self) -> int:
        self._record("shell_uid")
        return 0 if self.root else 2000

    def sha256(self, path: str) -> str:
        self._record("sha256", path)
        return self.hashes[path]

    def stat(self, path: str) -> dict[str, object]:
        self._record("stat", path)
        return dict(self.stats[path])

    def cat(self, path: str, *, maximum: int) -> bytes:
        self._record("cat", path)
        if path == tool.MANIFEST_PATH:
            return self.manifest
        if path == tool.BOOT_ID_PATH:
            return (self.boot_id + "\n").encode()
        if path == tool.EGRESS_EVIDENCE_PATH:
            receipt = {
                "schema": "org.trillionnium.agent-egress-boot-evidence.v2",
                "decision": "FIXTURE_CODEX_ONLY_EGRESS_CANDIDATE_NON_AUTHORIZING",
                "boot_id_sha256": hashlib.sha256(self.boot_id.encode()).hexdigest(),
                "artifacts": {
                    "codex": self._egress_artifact(
                        "agent-codex-direct-v1", ARTIFACT_HASHES["codex_launcher"]
                    ),
                },
                "firewall": {
                    "ipv4": {
                        "agent-codex-direct-v1": {},
                    },
                    "ipv6": {
                        "agent-codex-direct-v1": {},
                    },
                },
            }
            return json.dumps(receipt, separators=(",", ":")).encode()
        if path == tool.HIGH_WATER_STATE:
            return json.dumps(
                {
                    "schema": (
                        "trillionnium.direct-operation-custody-high-water-authority.v2"
                    ),
                    "state_sha256": "b" * 64,
                },
                separators=(",", ":"),
            ).encode()
        if path.endswith("/stat"):
            pid = int(path.split("/")[2])
            return proc_stat(pid, 123456 + pid)
        if path.endswith("/status"):
            return b"Name:\ttest\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
        if path.endswith("/attr/current"):
            if "/411/" in path:
                return b"u:r:trillionnium_agentd:s0\n"
            return b"u:r:trillionnium_direct_operation_custody_high_water:s0\n"
        if path.endswith("/cgroup"):
            return b"0::/trillionnium/p01/service\n"
        if path.endswith("/mountinfo"):
            return self._mountinfo()
        raise KeyError(path)

    @staticmethod
    def _egress_artifact(agent_id: str, expected_hash: str) -> dict[str, object]:
        return {
            "agent_id": agent_id,
            "expected_sha256": expected_hash,
            "source_sha256": expected_hash,
            "target_sha256": expected_hash,
            "same_inode": True,
            "mount_read_only": True,
            "mount_nosuid": True,
            "mount_nodev": True,
        }

    @staticmethod
    def _mountinfo() -> bytes:
        lines: list[str] = []
        mount_id = 100
        for artifact in tool.ARTIFACT_SPECS:
            if not artifact.root_target:
                continue
            mount_id += 1
            lines.append(
                f"{mount_id} 1 0:1 {artifact.source} {artifact.root_target} "
                "ro,nosuid,nodev - ext4 /dev/block/by-name/system_ext "
                "ro,nosuid,nodev"
            )
        lines.append(
            "199 1 0:2 / /data/trillionnium/root-linux/rootfs/proc "
            "ro,nosuid,nodev,noexec - proc proc ro,nosuid,nodev,noexec"
        )
        return ("\n".join(lines) + "\n").encode()


class AndroidP01DeviceConformanceTest(unittest.TestCase):
    def collect(self, fake: FakeAdb, **kwargs: object) -> dict[str, object]:
        contract = kwargs.pop("contract", fake.contract)
        measurement = kwargs.pop(
            "contract_measurement", contract_measurement(contract)
        )
        collector = tool.DeviceCollector(
            fake,
            contract=contract,
            contract_measurement=measurement,
            **kwargs,
        )
        return tool.finalize_evidence(collector.collect())

    def test_full_mocked_collection_holds_without_codex_egress_producer(self) -> None:
        fake = FakeAdb()
        evidence = self.collect(fake)
        self.assertEqual(
            evidence["decision"], "HOLD_INCOMPLETE_READ_ONLY_EVIDENCE"
        )
        layers = evidence["layers"]
        self.assertNotIn("FAIL", {layer["decision"] for layer in layers.values()})
        egress_checks = layers["egress_boot_evidence"]["checks"]
        authority = next(
            check
            for check in egress_checks
            if check["id"] == "codex_only_egress_authority_contract"
        )
        self.assertEqual(authority["status"], "HOLD")
        self.assertEqual(
            layers["manifest_unique_truth"]["observations"]["p01_facts"][
                "p01_physical_device_evidence"
            ],
            "hold_not_run",
        )
        self.assertFalse(evidence["safety"]["device_write_performed"])
        self.assertFalse(evidence["safety"]["android_ack_performed"])
        self.assertEqual(
            evidence["release_boundaries"]["hardware_rollback_resistance"],
            "hold_not_implemented",
        )
        self.assertRegex(evidence["evidence_sha256"], r"^[0-9a-f]{64}$")

    def test_all_action_flags_are_plan_only_and_issue_no_extra_adb_calls(self) -> None:
        baseline = FakeAdb()
        self.collect(baseline)
        requested = FakeAdb()
        evidence = self.collect(
            requested,
            action_requests={
                "settings_effect": True,
                "ack_compact_retire": True,
                "service_restart": True,
                "reboot": True,
                "power_loss": True,
            },
        )
        self.assertEqual(requested.calls, baseline.calls)
        for plan in evidence["action_plans"].values():
            self.assertTrue(plan["requested"])
            self.assertEqual(plan["mode"], "dry_run_plan_only")
        settings = evidence["action_plans"]["settings_effect"]
        self.assertEqual(settings["codex_trigger_interface"], "absent_closed_hold")
        self.assertFalse(settings["effect_executed"])
        ack = evidence["action_plans"]["ack_compact_retire"]
        self.assertEqual(
            ack["daemon_custody_source_closure"],
            "complete_source_host_userdebug_only",
        )
        self.assertFalse(ack["android_ack_executed"])

    def test_non_root_adbd_is_held_without_privileged_reads_or_adb_root(self) -> None:
        fake = FakeAdb(root=False)
        evidence = self.collect(fake)
        self.assertEqual(evidence["decision"], "HOLD_INCOMPLETE_READ_ONLY_EVIDENCE")
        privileged_details = [
            detail
            for operation, detail in fake.calls
            if operation in {"cat", "stat", "sha256"}
            and detail is not None
            and (detail.startswith("/data/") or detail.startswith("/proc/4"))
        ]
        self.assertEqual(privileged_details, [])
        flattened = json.dumps(evidence["command_audit"])
        self.assertNotIn('"root"', flattened)

    def test_manifest_duplicate_key_is_rejected(self) -> None:
        data = manifest_bytes(["p01_product_variant=userdebug"])
        with self.assertRaisesRegex(tool.ConformanceError, "duplicate key"):
            tool.parse_manifest(data)

    def test_manifest_malformed_line_is_rejected(self) -> None:
        with self.assertRaisesRegex(tool.ConformanceError, "key=value"):
            tool.parse_manifest(b"not-a-fact\n")

    def test_expectation_contract_is_mandatory(self) -> None:
        with mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                tool.build_parser().parse_args(["--serial", "SERIAL"])
        self.assertEqual(raised.exception.code, 2)

    def test_contract_rejects_manifest_artifact_cross_splice(self) -> None:
        contract = expectation_contract()
        contract["artifact_sha256"]["system_api"] = "c" * 64
        with self.assertRaisesRegex(tool.ConformanceError, "cross-binding mismatch"):
            tool.parse_expectation_contract(tool._canonical_json_bytes(contract))

    def test_contract_rejects_retired_secondary_provider_artifact(self) -> None:
        contract = expectation_contract()
        contract["artifact_sha256"]["retired_secondary_provider"] = "9" * 64
        with self.assertRaisesRegex(
            tool.ConformanceError, "artifact hash set does not match"
        ):
            tool.parse_expectation_contract(tool._canonical_json_bytes(contract))

    def test_contract_rejects_retired_provider_manifest_fact(self) -> None:
        contract = expectation_contract()
        retired_key = "open" + "claw_launcher_sha256"
        contract["required_manifest_facts"][retired_key] = "9" * 64
        with self.assertRaisesRegex(tool.ConformanceError, "retired Provider"):
            tool.parse_expectation_contract(tool._canonical_json_bytes(contract))

    def test_device_manifest_rejects_retired_provider_fact(self) -> None:
        retired_key = "open" + "claw_launcher_sha256"
        manifest = manifest_bytes([f"{retired_key}={'9' * 64}"])
        contract = expectation_contract(manifest)
        fake = FakeAdb(manifest=manifest, contract=contract)
        evidence = self.collect(fake)
        self.assertEqual(evidence["decision"], "FAIL_CLOSED_READ_ONLY_BASELINE")
        checks = evidence["layers"]["manifest_unique_truth"]["checks"]
        retired = next(
            check for check in checks if check["id"] == "retired_provider_absent"
        )
        self.assertEqual(retired["status"], "FAIL")

    def test_egress_evidence_rejects_retired_secondary_provider(self) -> None:
        fake = FakeAdb()
        original_cat = fake.cat

        def cat(path: str, *, maximum: int) -> bytes:
            raw = original_cat(path, maximum=maximum)
            if path != tool.EGRESS_EVIDENCE_PATH:
                return raw
            receipt = json.loads(raw)
            receipt["artifacts"]["retired_secondary_provider"] = fake._egress_artifact(
                "agent-retired-secondary-v1", "9" * 64
            )
            for family in ("ipv4", "ipv6"):
                receipt["firewall"][family]["agent-retired-secondary-v1"] = {}
            return json.dumps(receipt, separators=(",", ":")).encode()

        fake.cat = cat
        evidence = self.collect(fake)
        self.assertEqual(evidence["decision"], "FAIL_CLOSED_READ_ONLY_BASELINE")
        checks = evidence["layers"]["egress_boot_evidence"]["checks"]
        artifact_set = next(
            check for check in checks if check["id"] == "egress_artifact_set"
        )
        self.assertEqual(artifact_set["status"], "FAIL")

    def test_contract_rejects_mutation_authority(self) -> None:
        contract = expectation_contract()
        contract["authorizes_device_mutation"] = True
        with self.assertRaisesRegex(tool.ConformanceError, "deny device mutation"):
            tool.parse_expectation_contract(tool._canonical_json_bytes(contract))

    def test_contract_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = expectation_contract()
            real = root / "contract-real.json"
            encoded = tool._canonical_json_bytes(contract)
            real.write_bytes(encoded)
            link = root / "contract.json"
            link.symlink_to(real.name)
            with self.assertRaisesRegex(tool.ConformanceError, "symlink"):
                tool.load_expectation_contract(
                    str(link), hashlib.sha256(encoded).hexdigest()
                )

    def test_measured_contract_loads_and_binds_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            contract = expectation_contract()
            encoded = json.dumps(contract, indent=2, sort_keys=True).encode() + b"\n"
            path.write_bytes(encoded)
            loaded, measurement = tool.load_expectation_contract(
                str(path), hashlib.sha256(encoded).hexdigest()
            )
            self.assertEqual(loaded, contract)
            self.assertEqual(measurement["sha256"], hashlib.sha256(encoded).hexdigest())

    def test_contract_digest_pin_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_bytes(tool._canonical_json_bytes(expectation_contract()))
            with self.assertRaisesRegex(tool.ConformanceError, "does not match its pin"):
                tool.load_expectation_contract(str(path), "f" * 64)

    def test_manifest_must_match_exact_contract_digest(self) -> None:
        contract = expectation_contract()
        changed_manifest = manifest_bytes(["unrelated_extra_fact=present"])
        fake = FakeAdb(manifest=changed_manifest, contract=contract)
        evidence = self.collect(fake)
        self.assertEqual(evidence["decision"], "FAIL_CLOSED_READ_ONLY_BASELINE")
        checks = evidence["layers"]["manifest_unique_truth"]["checks"]
        digest_check = next(
            check for check in checks if check["id"] == "manifest_contract_digest"
        )
        self.assertEqual(digest_check["status"], "FAIL")

    def test_strict_json_duplicate_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(tool.ConformanceError, "duplicate JSON key"):
            tool._strict_json_loads(b'{"x":1,"x":2}', maximum=100, label="fixture")

    def test_mountinfo_parser_preserves_required_flags(self) -> None:
        parsed = tool.parse_mountinfo(FakeAdb._mountinfo())
        target = next(
            item.root_target for item in tool.ARTIFACT_SPECS if item.root_target
        )
        flags = set(parsed[target]["mount_options"]) | set(
            parsed[target]["super_options"]
        )
        self.assertTrue({"ro", "nosuid", "nodev"}.issubset(flags))

    def test_mountinfo_accepts_exact_daemon_chroot_view(self) -> None:
        host_target = (
            "/data/trillionnium/root-linux/rootfs/usr/local/bin/"
            "trillionnium-agent-system-api"
        )
        chroot_target = "/usr/local/bin/trillionnium-agent-system-api"
        mount = {"mount_options": ["ro"], "super_options": ["nodev", "nosuid"]}
        located = tool.find_mountinfo_entry({chroot_target: mount}, host_target)
        self.assertEqual(located, (chroot_target, mount))

    def test_mountinfo_rejects_ambiguous_host_and_chroot_views(self) -> None:
        host_target = (
            "/data/trillionnium/root-linux/rootfs/usr/local/bin/"
            "trillionnium-agent-system-api"
        )
        chroot_target = "/usr/local/bin/trillionnium-agent-system-api"
        with self.assertRaisesRegex(tool.ConformanceError, "both host and chroot"):
            tool.find_mountinfo_entry(
                {host_target: {}, chroot_target: {}}, host_target
            )

    def test_symlink_adb_executable_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "adb-real"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            link = root / "adb"
            link.symlink_to(executable.name)
            with self.assertRaisesRegex(tool.ConformanceError, "symlink"):
                tool.AdbClient(str(link), "SERIAL")

    def test_bounded_runner_rejects_oversized_output(self) -> None:
        with self.assertRaisesRegex(tool.ConformanceError, "output exceeded bound"):
            tool.run_bounded(
                [sys.executable, "-c", "import sys; sys.stdout.write('x'*10000)"],
                timeout_seconds=5,
                maximum_output=1024,
            )

    def test_bounded_runner_rejects_timeout(self) -> None:
        with self.assertRaisesRegex(tool.ConformanceError, "timed out"):
            tool.run_bounded(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout_seconds=0.05,
                maximum_output=1024,
            )

    def test_output_is_new_mode_0600_and_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence.json"
            tool.write_new_output(str(output), b"{}\n")
            self.assertEqual(output.read_bytes(), b"{}\n")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaisesRegex(tool.ConformanceError, "refusing to create"):
                tool.write_new_output(str(output), b"changed\n")

    def test_output_final_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_bytes(b"sentinel")
            output = root / "evidence.json"
            output.symlink_to(target.name)
            with self.assertRaises(tool.ConformanceError):
                tool.write_new_output(str(output), b"{}\n")
            self.assertEqual(target.read_bytes(), b"sentinel")

    def test_output_parent_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_parent = root / "real"
            real_parent.mkdir()
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent.name, target_is_directory=True)
            with self.assertRaises(tool.ConformanceError):
                tool.write_new_output(str(linked_parent / "evidence.json"), b"{}\n")
            self.assertFalse((real_parent / "evidence.json").exists())

    def test_system_ext_image_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "system_ext.img"
            image.write_bytes(b"image")
            link = root / "linked.img"
            link.symlink_to(image.name)
            with self.assertRaisesRegex(tool.ConformanceError, "symlink"):
                tool.measure_regular_file(str(link), maximum=100)

    def test_host_image_exact_hash_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "system_ext.img"
            image.write_bytes(b"tiny-host-image")
            expected = hashlib.sha256(image.read_bytes()).hexdigest()
            fake = FakeAdb()
            contract = dict(fake.contract)
            contract["system_ext_image_sha256"] = expected
            fake.contract = contract
            evidence = self.collect(
                fake,
                system_ext_image=str(image),
            )
            layer = evidence["layers"]["optional_host_system_ext_image"]
            self.assertEqual(layer["decision"], "PASS")
            self.assertEqual(layer["observations"]["measurement"]["sha256"], expected)

    def test_adb_client_emits_only_fixed_read_only_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_adb = Path(temporary) / "adb"
            fake_adb.write_bytes(b"#!/bin/sh\nexit 0\n")
            fake_adb.chmod(0o755)
            outputs = {
                "get_state": b"device\n",
                "getprop:ro.build.type": b"userdebug\n",
                "getenforce": b"Enforcing\n",
                "shell_uid": b"0\n",
            }
            captured: list[list[str]] = []

            def bounded(argv: list[str], **_: object) -> tuple[int, bytes, bytes]:
                captured.append(list(argv))
                tail = argv[3:]
                if tail == ["get-state"]:
                    return 0, outputs["get_state"], b""
                if tail == ["shell", "getprop", "ro.build.type"]:
                    return 0, outputs["getprop:ro.build.type"], b""
                if tail == ["shell", "getenforce"]:
                    return 0, outputs["getenforce"], b""
                if tail == ["shell", "id", "-u"]:
                    return 0, outputs["shell_uid"], b""
                raise AssertionError(tail)

            with mock.patch.object(tool, "run_bounded", side_effect=bounded):
                client = tool.AdbClient(str(fake_adb), "SERIAL")
                self.assertEqual(client.get_state(), "device")
                self.assertEqual(client.getprop("ro.build.type"), "userdebug")
                self.assertEqual(client.getenforce(), "Enforcing")
                self.assertEqual(client.shell_uid(), 0)
            tails = [argv[3:] for argv in captured]
            self.assertEqual(
                tails,
                [
                    ["get-state"],
                    ["shell", "getprop", "ro.build.type"],
                    ["shell", "getenforce"],
                    ["shell", "id", "-u"],
                ],
            )

    def test_adb_file_reads_use_no_remote_shell_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_adb = Path(temporary) / "adb"
            fake_adb.write_bytes(b"#!/bin/sh\nexit 0\n")
            fake_adb.chmod(0o755)
            captured: list[list[str]] = []
            source = tool.ARTIFACT_SPECS[0].source
            expected_hash = "d" * 64

            def bounded(argv: list[str], **_: object) -> tuple[int, bytes, bytes]:
                captured.append(list(argv))
                tail = argv[3:]
                if tail == ["exec-out", "cat", tool.MANIFEST_PATH]:
                    return 0, b"key=value\n", b""
                if tail == ["shell", "sha256sum", source]:
                    return 0, f"{expected_hash}  {source}\n".encode(), b""
                if tail == [
                    "shell",
                    "stat",
                    "-c",
                    "%F|%s|%a|%u|%g|%d|%i|%h|%C",
                    source,
                ]:
                    return (
                        0,
                        b"regular file|12|755|0|0|1|2|1|u:object_r:system_file:s0\n",
                        b"",
                    )
                raise AssertionError(tail)

            with mock.patch.object(tool, "run_bounded", side_effect=bounded):
                client = tool.AdbClient(str(fake_adb), "SERIAL")
                self.assertEqual(
                    client.cat(tool.MANIFEST_PATH, maximum=100), b"key=value\n"
                )
                self.assertEqual(client.sha256(source), expected_hash)
                self.assertEqual(client.stat(source)["inode"], 2)
            tails = [argv[3:] for argv in captured]
            self.assertNotIn("sh", {item for tail in tails for item in tail})
            self.assertTrue(all(tail[:2] != ["shell", "sh"] for tail in tails))


if __name__ == "__main__":
    unittest.main()
