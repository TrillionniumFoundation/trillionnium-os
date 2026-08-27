#!/usr/bin/env python3
"""Host contract for the fail-closed shell.exec.v1 Android product wiring."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import trillionnium_receipt_stage_verify as VERIFY  # noqa: E402


def locate_layout() -> tuple[Path, Path | None]:
    """Return the contract-data root and, when available, the Android top."""

    source_common = Path(__file__).resolve().parents[1]
    source_vendor = source_common.parents[1]
    source_top = source_vendor.parents[1]
    if (
        (source_common / "contracts/trillionnium-receipt-stage-v1.contract.json")
        .is_file()
        and (source_top / "device/trillionnium/sepolicy").is_dir()
    ):
        return source_common, source_top
    packaged = Path(sys.argv[0]).resolve().parent
    if (
        packaged / "contracts/trillionnium-receipt-stage-v1.contract.json"
    ).is_file():
        return packaged, None
    raise FileNotFoundError(
        "shell-exec Android product inputs are absent from source and packaged layouts"
    )


COMMON, ANDROID_TOP = locate_layout()
if ANDROID_TOP is None:
    PRODUCT_CONFIG = COMMON / "common.mk"
    SEPOLICY = COMMON
    DEVICE_CONFIG = COMMON / "config.fs"
else:
    VENDOR = ANDROID_TOP / "vendor/trillionnium"
    PRODUCT_CONFIG = VENDOR / "config/common.mk"
    SEPOLICY = ANDROID_TOP / "device/trillionnium/sepolicy"
    DEVICE_CONFIG = ANDROID_TOP / "device/motorola/sm6375-common/config.fs"
def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def document(path: Path) -> dict[str, object]:
    return json.loads(read(path))


def json_pointer(value: object, pointer: str) -> object:
    current = value
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current


def metadata(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class ShellExecAndroidProductWiringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.hold = document(
            COMMON / "contracts/shell-exec-v1-android-product-hold.v1.json"
        )
        cls.stage = document(
            COMMON / "contracts/trillionnium-receipt-stage-v1.contract.json"
        )
        cls.specs = {item["role"]: item for item in cls.stage["role_specs"]}

    def test_product_posture_is_explicitly_non_authorizing(self) -> None:
        self.assertEqual(self.hold["decision"], "PASS_SOURCE_WIRING_ONLY")
        self.assertEqual(
            self.hold["status"], "HOLD_UNBOUND_BUILD_AND_DEVICE_EVIDENCE"
        )
        self.assertFalse(self.hold["effect_authority"])
        self.assertFalse(self.hold["public_release_allowed"])
        self.assertFalse(self.hold["scope"]["android_shell_fallback"])
        self.assertFalse(self.hold["scope"]["adb_transport"])
        self.assertEqual(self.hold["source_protocol"]["revision"], 3)
        self.assertTrue(self.hold["source_wiring"]["ready_publisher_implemented"])
        self.assertTrue(self.hold["source_wiring"]["cgroup_isolation_implemented"])
        self.assertTrue(self.hold["source_wiring"]["seccomp_isolation_implemented"])
        self.assertTrue(
            self.hold["source_wiring"]["root_linux_chroot_entry_implemented"]
        )
        self.assertFalse(
            self.hold["source_wiring"]["independent_mount_namespace_implemented"]
        )
        binding = self.hold["artifact_binding"]
        self.assertEqual(
            binding["schema"], "org.trillionnium.shell-exec-artifact-set.v1"
        )
        self.assertTrue(binding["product_feature_closure_locked"])
        self.assertEqual(
            binding["verifier_admission"],
            "exact_android_product_feature_locked_source_only",
        )

    def test_receipt_stage_requires_independent_four_role_shell_closure(self) -> None:
        self.assertEqual(len(self.stage["role_specs"]), 27)
        expected = {
            "p01_shell_tool": (
                "artifacts/p01/trillionnium-agent-shell",
                "/usr/local/bin/trillionnium-agent-shell",
            ),
            "p01_shell_broker": (
                "artifacts/p01/trillionnium-shell-exec-broker-userdebug",
                "/system_ext/bin/trillionnium-shell-exec-broker-userdebug",
            ),
            "p01_shell_worker": (
                "artifacts/p01/trillionnium-shell-exec-worker-userdebug",
                "/system_ext/bin/trillionnium-shell-exec-worker-userdebug",
            ),
            "shell_artifact_set": (
                "evidence/trillionnium-shell-exec-artifact-set-v1.json",
                "/system_ext/etc/trillionnium/p01-userdebug/"
                "trillionnium-shell-exec-artifact-set-v1.json",
            ),
        }
        for role, (stage_path, install_path) in expected.items():
            self.assertEqual(self.specs[role]["stage_path"], stage_path)
            self.assertEqual(self.specs[role]["install_path"], install_path)
        self.assertEqual(
            self.specs["p01_shell_tool"]["install_paths"],
            [
                "/usr/local/bin/trillionnium-agent-shell",
                "/system_ext/bin/trillionnium-agent-shell",
            ],
        )
        shell_claims = [
            item
            for item in self.stage["claims"]
            if item["evidence_role"] == "shell_artifact_set"
        ]
        self.assertEqual(len(shell_claims), 7)
        self.assertEqual(
            {item["artifact_role"] for item in shell_claims},
            {
                "p01_shell_tool",
                "p01_shell_broker",
                "p01_shell_worker",
                "source_bom",
            },
        )
        self.assertTrue(
            self.stage["cross_bindings"][
                "shell_artifacts_match_shell_artifact_set"
            ]
        )
        # The Soong python launcher embeds imported modules in its executable
        # archive, where inspect.getsource() is intentionally unavailable.
        # Assert the loaded verifier's fail-closed API and bytecode constants
        # so this test covers both source checkout and installed runfiles.
        self.assertEqual(
            VERIFY.EXPECTED_SHELL_ARTIFACT_SET_FEATURES, ("android-product",)
        )
        self.assertTrue(callable(VERIFY.validate_shell_artifact_set))
        elf_guards = "\n".join(
            item
            for item in VERIFY.validate_fully_static_elf.__code__.co_consts
            if isinstance(item, str)
        )
        shell_guards = "\n".join(
            item
            for item in VERIFY.validate_shell_artifact_set.__code__.co_consts
            if isinstance(item, str)
        )
        self.assertIn("contains PT_INTERP", elf_guards)
        self.assertIn("contains DT_NEEDED", elf_guards)
        self.assertIn(
            "artifact_set_sha256 does not bind its canonical preimage",
            shell_guards,
        )

    def test_v9_v5_stage_names_are_single_userdebug_authority(self) -> None:
        expected = {
            "rootfs_archive": (
                "artifacts/rootfs/rootfs-current.tar.zst",
                None,
            ),
            "common_artifact_set": (
                "evidence/common-codex-rootfs-artifact-set.v5.json",
                "org.trillionnium.common-codex-rootfs-artifact-set.v5",
            ),
            "p01_final_artifact_set": (
                "evidence/p01-userdebug-final-daemon-artifact-set.v5.json",
                "org.trillionnium.p01-userdebug-final-daemon-artifact-set.v5",
            ),
            "rootfs_contract": (
                "evidence/rootfs-package.contract.v9.json",
                "org.trillionnium.rootfs-package.contract.v9",
            ),
            "rootfs_receipt": (
                "evidence/rootfs-package-receipt.json",
                "org.trillionnium.rootfs-package.receipt.v9",
            ),
        }
        for role, (stage_path, schema) in expected.items():
            self.assertEqual(self.specs[role]["stage_path"], stage_path)
            self.assertEqual(self.specs[role]["document_schema"], schema)
        baseline = self.hold["receipt_stage_baseline"]
        self.assertFalse(baseline["old_common_v4_accepted"])
        self.assertFalse(baseline["old_p01_final_v4_accepted"])
        self.assertFalse(baseline["old_rootfs_v8_accepted"])

    def test_soong_and_product_select_every_required_userdebug_input(self) -> None:
        blueprint = read(COMMON / "Android.bp")
        product = read(PRODUCT_CONFIG)
        userdebug = product.split(
            "ifeq ($(TARGET_BUILD_VARIANT),userdebug)", 1
        )[1].split("endif", 1)[0]
        modules = (
            "trillionnium-agent-shell",
            "trillionnium-shell-exec-broker-userdebug",
            "trillionnium-shell-exec-worker-userdebug",
            "trillionnium-shell-exec-artifact-set-v1",
            "trillionnium-p01-final-artifact-set-v5",
            "trillionnium-rootfs-package-contract-v9",
            "trillionnium-rootfs-package-receipt-v9",
            "trillionnium-rootfs-common-artifact-set-v5",
        )
        for module in modules:
            self.assertIn(module, userdebug)
            self.assertIn(f'name: "{module}"', blueprint)
        for tag in (
            ".p01_shell_tool",
            ".p01_shell_broker",
            ".p01_shell_worker",
            ".shell_artifact_set",
        ):
            self.assertIn(tag, blueprint)
        self.assertNotIn("trillionnium-agent-shell", product.split(
            "ifeq ($(TARGET_BUILD_VARIANT),userdebug)", 1
        )[0])

    def test_legacy_privileged_adb_binder_helper_is_absent(self) -> None:
        product = read(PRODUCT_CONFIG)
        active_product = "\n".join(
            line.split("#", 1)[0] for line in product.splitlines()
        )
        self.assertNotRegex(
            active_product,
            r"(?m)^\s*PRODUCT_PACKAGES(?:_DEBUG)?\s*\+=.*\badb_root\b",
        )
        self.assertNotRegex(active_product, r"(?m)^\s*adb_root\s*(?:\\)?$")

        private = SEPOLICY / "common/private"
        self.assertFalse((private / "adbroot.te").exists())
        for name in (
            "adbd.te",
            "file.te",
            "file_contexts",
            "service.te",
            "service_contexts",
            "system_server.te",
        ):
            path = private / name
            if path.exists():
                self.assertNotRegex(read(path), r"\badbroot(?:_[a-z_]+)?\b")

    def test_init_keeps_agent_host_behind_pending_shell_gate(self) -> None:
        init = read(COMMON / "etc/init/init.trillionnium-system_ext.rc")
        self.assertIn("setprop sys.trillionnium.shell_exec.ready pending", init)
        self.assertIn("start trillionnium_shell_exec_broker", init)
        high_water = init.split(
            "on property:sys.trillionnium.high_water_ready=ready", 1
        )[1].split("\non ", 1)[0]
        self.assertNotIn("setprop sys.trillionnium.agentd.desired 1", high_water)
        ready = init.split(
            "on property:sys.trillionnium.shell_exec.ready=ready", 1
        )[1].split("\non ", 1)[0]
        self.assertIn("setprop sys.trillionnium.agentd.desired 1", ready)
        service = init.split("service trillionnium_shell_exec_broker ", 1)[1].split(
            "\nservice ", 1
        )[0]
        self.assertIn("user root", service)
        self.assertIn("group root system vendor_trillionnium_execworker", service)
        self.assertIn(
            "capabilities CHOWN KILL SETGID SETUID SYS_CHROOT", service
        )
        self.assertNotRegex(service, r"(?m)^\s+capabilities.*\bDAC_READ_SEARCH\b")
        self.assertNotRegex(service, r"(?m)^\s+capabilities.*\bDAC_OVERRIDE\b")
        self.assertNotRegex(service, r"(?m)^\s+capabilities.*\bSYS_ADMIN\b")
        self.assertNotIn("service trillionnium_shell_exec_worker", init)
        self.assertNotRegex(init, r"(?m)^\s+socket\s+trillionnium_shell_exec")
        self.assertIn(
            "shell-exec/workspace 0711 root root",
            init,
        )
        self.assertIn(
            "shell-exec/temporary 0711 root root",
            init,
        )
        self.assertIn(
            "mount none /system_ext/bin/trillionnium-agent-shell "
            "/data/trillionnium/root-linux/rootfs/usr/local/bin/"
            "trillionnium-agent-shell bind",
            init,
        )
        host_stopped = init.split(
            "on property:init.svc.trillionnium_root_linux_daemon=stopped "
            "&& property:sys.trillionnium.agentd.desired=1",
            1,
        )[1].split("\non ", 1)[0]
        self.assertIn("setprop sys.trillionnium.agentd.desired 0", host_stopped)
        self.assertIn("setprop sys.trillionnium.shell_exec.desired 0", host_stopped)
        self.assertIn("setprop sys.trillionnium.shell_exec.ready failed", host_stopped)
        self.assertIn("stop trillionnium_shell_exec_broker", host_stopped)
        self.assertIn("stop trillionnium_agent_egress_guard", host_stopped)
        self.assertNotIn("start trillionnium_agent_egress_guard", host_stopped)

    def test_aid_and_selinux_domains_are_independent(self) -> None:
        config = read(DEVICE_CONFIG)
        aids = dict(
            re.findall(r"\[(AID_VENDOR_TRILLIONNIUM_[A-Z_]+)\]\nvalue:(\d+)", config)
        )
        self.assertEqual(aids["AID_VENDOR_TRILLIONNIUM_CODEX"], "5901")
        self.assertEqual(aids["AID_VENDOR_TRILLIONNIUM_OPENCLAW"], "5902")
        self.assertEqual(aids["AID_VENDOR_TRILLIONNIUM_EXECWORKER"], "5903")
        # Bionic passwd/group names generated from OEM AIDs must be strictly
        # shorter than 32 characters.  Keep this checked here because the
        # former SHELL_WORKER spelling reached exactly 32 and made fs_config
        # generation fail only after the full Soong/product graph was built.
        worker_name = "vendor_trillionnium_execworker"
        self.assertLess(len(worker_name), 32)
        self.assertEqual(
            worker_name,
            "AID_VENDOR_TRILLIONNIUM_EXECWORKER".removeprefix("AID_").lower(),
        )
        self.assertEqual(len(set(aids.values())), len(aids))
        policy = read(SEPOLICY / "common/private/trillionnium_shell_exec.te")
        for domain in (
            "trillionnium_agent_shell_tool",
            "trillionnium_shell_exec_broker",
            "trillionnium_shell_exec_worker",
        ):
            self.assertIn(f"type {domain}, domain, coredomain;", policy)
        self.assertIn("-trillionnium_agent_shell_tool", policy)
        self.assertIn("-trillionnium_shell_exec_broker", policy)
        self.assertIn("-trillionnium_agentd", policy)
        self.assertIn("-init", policy)
        self.assertRegex(
            policy,
            r"allow\s+trillionnium_agentd\s+"
            r"trillionnium_shell_exec_broker:unix_stream_socket\s*\{[^}]*"
            r"\bconnectto\b",
        )
        self.assertRegex(
            policy,
            r"allow\s+trillionnium_agent_shell_tool\s+"
            r"trillionnium_shell_exec_broker:unix_stream_socket\s*\{[^}]*"
            r"\bconnectto\b",
        )
        self.assertIn(
            "set_prop(trillionnium_shell_exec_broker, "
            "trillionnium_shell_exec_ready_prop)",
            policy,
        )
        self.assertIn(
            "allow trillionnium_shell_exec_broker "
            "trillionnium_shell_exec_payload_file:file r_file_perms;",
            policy,
        )
        file_types = read(SEPOLICY / "common/private/file.te")
        self.assertIn(
            "type trillionnium_shell_exec_payload_file, file_type, "
            "data_file_type, core_data_file_type, verified_data_exec_type;",
            file_types,
        )
        users = read(SEPOLICY / "common/private/users")
        self.assertIn(
            "constrain unix_stream_socket { accept bind connect listen }",
            users,
        )
        self.assertIn(
            "restorecon_recursive --force "
            "/data/trillionnium/root-linux/rootfs",
            read(COMMON / "etc/init/init.trillionnium-system_ext.rc"),
        )

    def test_real_v20_projection_proves_new_inputs_and_rootfs_target_absent(self) -> None:
        configured_root = os.environ.get("TRILLIONNIUM_V20_RELEASE_ROOT")
        if not configured_root:
            self.skipTest("release projection root is not configured")
        root = Path(configured_root)
        if not root.is_dir():
            self.skipTest("canonical v20 release root is not available")
        source_boms = list((root / "source-bom").glob(
            "trillionnium-canonical-source-bom-v20-*.json"
        ))
        self.assertEqual(len(source_boms), 1)
        paths = {
            "common_daemon": root / "launchers/common-a/trillionniumd",
            "common_codex_launcher": root / "launchers/common-a/trillionnium-codex-agent-0.144.1",
            "common_system_api": root / "launchers/common-a/trillionnium-agent-system-api",
            "common_accessibility": root / "launchers/common-a/trillionnium-agent-accessibility",
            "common_replay_sync": root / "launchers/common-a/trillionnium-system-api-replay-sync",
            "p01_daemon": root / "final-daemon-v5/set-a/trillionniumd",
            "p01_codex_launcher": root / "final-daemon-v5/set-a/trillionnium-codex-agent-0.144.1-p01-userdebug",
            "p01_system_api": root / "final-daemon-v5/set-a/trillionnium-agent-system-api-device-conformance",
            "p01_replay_sync": root / "final-daemon-v5/set-a/trillionnium-system-api-device-conformance-replay-sync",
            "p01_high_water": root / "final-daemon-v5/set-a/trillionnium-direct-operation-custody-high-water",
            "rootfs_archive": root / "rootfs-v9/package-a/rootfs-current.tar.zst",
            "fresh_base_receipt": root / "rootfs-v9/inputs/minimal-bookworm-arm64.receipt.json",
            "fresh_base_sbom": root / "rootfs-v9/inputs/minimal-bookworm-arm64.spdx.json",
            "source_bom": source_boms[0],
            "resolved_manifest": root / "source-bom/resolved-manifest-head-20260809.xml",
            "common_artifact_set": root / "launchers/common-a/common-codex-rootfs-artifact-set.v5.json",
            "p01_final_artifact_set": root / "final-daemon-v5/set-a/p01-userdebug-final-daemon-artifact-set.v5.json",
            "rootfs_contract": root / "rootfs-v9/contract/rootfs-package.contract.v9.json",
            "rootfs_receipt": root / "rootfs-v9/package-a/rootfs-package-receipt.json",
        }
        for path in paths.values():
            self.assertTrue(path.is_file(), path)
        docs = {
            role: document(paths[role])
            for role in (
                "common_artifact_set",
                "p01_final_artifact_set",
                "rootfs_contract",
                "rootfs_receipt",
            )
        }
        for role, doc in docs.items():
            self.assertEqual(doc["schema"], self.specs[role]["document_schema"])
        entries = {role: metadata(path) for role, path in paths.items()}
        for claim in self.stage["claims"]:
            if claim["artifact_role"] not in entries or claim["evidence_role"] not in docs:
                continue
            self.assertEqual(
                json_pointer(docs[claim["evidence_role"]], claim["json_pointer"]),
                entries[claim["artifact_role"]][claim["artifact_field"]],
                claim,
            )
        members = {item["path"] for item in docs["rootfs_receipt"]["output_rootfs"]["members"]}
        self.assertNotIn("usr/local/bin/trillionnium-agent-shell", members)
        self.assertNotIn("var/lib/trillionnium/shell-exec", members)
        self.assertFalse(any(root.rglob("trillionnium-agent-shell")))
        self.assertFalse(any(root.rglob("trillionnium-shell-exec-*")))
        self.assertFalse(any(root.rglob("trillionnium-shell-exec-artifact-set-v1.json")))
        self.assertFalse(any(root.rglob("codex-runtime-0.144.1")))


if __name__ == "__main__":
    unittest.main()
