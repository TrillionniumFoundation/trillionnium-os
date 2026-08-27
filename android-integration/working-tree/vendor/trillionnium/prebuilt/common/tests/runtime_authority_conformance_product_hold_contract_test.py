#!/usr/bin/env python3
"""Cross-tree guard for the non-authorizing runtime-authority probe.

The Rust ``runtime-authority-conformance`` lane is useful for exercising the
peer/state-machine seam, but it is deliberately not an Android authority.  It
must not acquire an init service, product package, SELinux transition, or
replay/ACK endpoint by accident.  This test is intentionally read-only and
does not require (or create) a device state directory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import unittest


HERE = Path(__file__).resolve()
ANDROID_TOP = HERE.parents[5]
COMMON = ANDROID_TOP / "vendor/trillionnium/prebuilt/common"
VENDOR = ANDROID_TOP / "vendor/trillionnium"
DEVICE_PRIVATE = ANDROID_TOP / "device/trillionnium/sepolicy/common/private"
RECEIPT_STAGE_CONTRACT = COMMON / "contracts/trillionnium-receipt-stage-v1.contract.json"
# Optional source-only inspection.  Never encode a retired worktree in the
# Android tree; callers that want the stronger check must name the one active
# control-plane tree explicitly.
RUST_WORKTREE = Path(
    os.environ.get(
        "TRILLIONNIUM_RUST_WORKTREE",
        "/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/"
        "trillionnium-release-sources/p0-agent-native-integration-20260731/"
        "trillionnium-os",
    )
)
HIGH_WATER_SOURCE = (
    RUST_WORKTREE
    / "apps/trillionnium-agent-privilege-broker/src/bin/direct_operation_custody_high_water.rs"
)

# Keep these markers exact.  Generic words such as "conformance" also occur
# in the existing device replay-sync probe and are not this lane.
PROTOCOL = "trillionnium.direct-operation-runtime-authority-conformance.v1"
MODULE_MARKERS = (
    "runtime-authority-conformance",
    "direct_operation_runtime_authority_conformance",
)


def read(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise AssertionError(f"missing or symlinked contract input: {path}")
    return path.read_text(encoding="utf-8")


def active_android_inputs() -> list[Path]:
    """Return product/policy files where an accidental route could appear."""

    paths = [
        COMMON / "Android.bp",
        VENDOR / "config/common.mk",
        COMMON / "linux/manifest.txt",
        COMMON / "etc/init/init.trillionnium-system_ext.rc",
        COMMON / "etc/init/init.trillionnium-agent-adb-debug.rc",
    ]
    paths.extend(sorted(DEVICE_PRIVATE.glob("*")))
    return [path for path in paths if path.is_file() and not path.is_symlink()]


class RuntimeAuthorityConformanceProductHoldTest(unittest.TestCase):
    def test_probe_is_absent_from_android_product_graph(self) -> None:
        inputs = active_android_inputs()
        self.assertGreaterEqual(len(inputs), 10)
        for path in inputs:
            text = read(path)
            self.assertNotIn(PROTOCOL, text, path.as_posix())
            for marker in MODULE_MARKERS:
                self.assertNotIn(marker, text, path.as_posix())

        # A source-only feature must not be introduced as a service/socket or
        # an alternate SELinux entrypoint under a spelling that omits hyphens.
        joined = "\n".join(read(path) for path in inputs)
        self.assertNotRegex(
            joined,
            r"(?im)^\s*(?:service|socket)\s+[^\n]*runtime[_-]?authority",
        )
        self.assertNotRegex(
            joined,
            r"(?im)trillionnium[_-]runtime[_-]?authority[^\n]*\b(?:domain|exec_type)\b",
        )

    def test_userdebug_chain_stays_fail_closed_before_agentd(self) -> None:
        init = read(COMMON / "etc/init/init.trillionnium-system_ext.rc")

        high_water_blocks = list(re.finditer(
            r"(?ms)^on property:sys\.trillionnium\.rootlinux\.prepare=0\s*"
            r"&& property:ro\.build\.type=userdebug\n(?P<body>.*?)(?=^on |^service |\Z)",
            init,
        ))
        high_water_start = next(
            (
                match
                for match in high_water_blocks
                if "start trillionnium_direct_operation_custody_high_water" in match.group(
                    "body"
                )
            ),
            None,
        )
        self.assertIsNotNone(high_water_start)
        body = high_water_start.group("body")
        self.assertIn("setprop sys.trillionnium.high_water_ready pending", body)
        self.assertIn("start trillionnium_direct_operation_custody_high_water", body)
        self.assertIn(
            "start trillionnium_direct_operation_custody_high_water_ready_gate",
            body,
        )
        self.assertIn("property:ro.build.type=userdebug", high_water_start.group(0))

        ready = re.search(
            r"(?ms)^on property:sys\.trillionnium\.high_water_ready=ready\s*"
            r"&& property:sys\.trillionnium\.rootlinux\.prepare=0\s*"
            r"&& property:ro\.build\.type=userdebug\n(?P<body>.*?)(?=^on |^service |\Z)",
            init,
        )
        self.assertIsNotNone(ready)
        ready_body = ready.group("body")
        self.assertIn("setprop sys.trillionnium.shell_exec.ready pending", ready_body)
        self.assertIn("start trillionnium_shell_exec_broker", ready_body)
        self.assertNotIn("setprop sys.trillionnium.agentd.desired 1", ready_body)

        agentd = re.search(
            r"(?ms)^on property:sys\.trillionnium\.shell_exec\.ready=ready\s*"
            r"&& property:sys\.trillionnium\.shell_exec\.desired=1\s*"
            r"&& property:sys\.trillionnium\.high_water_ready=ready\s*"
            r"&& property:sys\.trillionnium\.rootlinux\.prepare=0\s*"
            r"&& property:ro\.build\.type=userdebug\n(?P<body>.*?)(?=^on |^service |\Z)",
            init,
        )
        self.assertIsNotNone(agentd)
        self.assertIn("setprop sys.trillionnium.agentd.desired 1", agentd.group("body"))

        # Every observed failure path must retire the downstream chain; init
        # must never substitute a stale ready property for missing authority.
        for trigger in (
            "init.svc.trillionnium_direct_operation_custody_high_water=stopped",
            "init.svc.trillionnium_direct_operation_custody_high_water_ready_gate=stopped",
            "init.svc.trillionnium_shell_exec_broker=stopped",
        ):
            self.assertIn(trigger, init)
        self.assertIn("setprop sys.trillionnium.high_water_ready failed", init)
        self.assertIn("setprop sys.trillionnium.shell_exec.ready failed", init)
        self.assertIn("stop trillionnium_root_linux_daemon", init)

    def test_manifest_keeps_journal_and_epoch_replay_holds_explicit(self) -> None:
        manifest = {}
        for line in read(COMMON / "linux/manifest.txt").splitlines():
            if not line or line.startswith("#"):
                continue
            self.assertEqual(line.count("="), 1, line)
            key, value = line.split("=", 1)
            self.assertNotIn(key, manifest)
            manifest[key] = value

        expected = {
            "agent_operation_journal_v3_transition_tools": "absent_product_hold",
            "agent_operation_journal_v3_migration_receipt_verifier": "absent_product_hold",
            "agent_operation_journal_v3_gate": "read_only_verdict_always_hold",
            "agent_operation_journal_v3_hotpath": "disabled",
            "agent_operation_epoch_replay_contract_schema": (
                "org.trillionnium.agent-operation-epoch-replay-product-hold.v1"
            ),
            "agent_system_api_epoch_activation": "absent_product_hold",
            "agent_accessibility_epoch_activation": "absent_product_hold",
            "agent_operation_replay_ack_transport": "absent_product_hold",
            "agent_operation_first_use_authority": "absent_product_hold",
            "agent_operation_replay_control_product_wired": "false",
        }
        for key, value in expected.items():
            self.assertEqual(manifest.get(key), value, key)

    def test_high_water_receipt_role_cannot_become_runtime_authority_alias(self) -> None:
        """Keep the existing authority artifact's identity/protocol closed.

        A second protocol must not be smuggled into the high-water role by
        changing only an init command, output alias, or wrapper.  If a real
        runtime authority is promoted later, it needs its own versioned
        receipt contract (or a separately reviewed daemon-owned design).
        """

        contract = json.loads(read(RECEIPT_STAGE_CONTRACT))
        self.assertEqual(contract.get("schema"), "org.trillionnium.android.receipt-stage.contract.v1")
        roles = contract.get("role_specs")
        self.assertIsInstance(roles, list)
        self.assertEqual(len(roles), 27)
        high_water = next(
            (item for item in roles if item.get("role") == "p01_high_water"),
            None,
        )
        self.assertIsNotNone(high_water)
        self.assertEqual(
            {
                key: high_water[key]
                for key in ("kind", "install_path", "semantic", "stage_path", "tag")
            },
            {
                "kind": "elf",
                "install_path": "/system_ext/bin/trillionnium-direct-operation-custody-high-water",
                "semantic": "p01_userdebug_high_water_direct_tool",
                "stage_path": "artifacts/p01/trillionnium-direct-operation-custody-high-water",
                "tag": ".p01_high_water",
            },
        )

        init = read(COMMON / "etc/init/init.trillionnium-system_ext.rc")
        high_water_service = re.search(
            r"(?ms)^service\s+trillionnium_direct_operation_custody_high_water\s+"
            r"(?P<body>.*?)(?=^service\s|\Z)",
            init,
        )
        self.assertIsNotNone(high_water_service)
        self.assertIn(
            "/system_ext/bin/trillionnium-direct-operation-custody-high-water",
            high_water_service.group("body"),
        )
        self.assertNotIn("runtime_authority", high_water_service.group("body"))

        policy = read(DEVICE_PRIVATE / "trillionnium_direct_operation_custody_high_water.te")
        self.assertIn("trillionnium_direct_operation_custody_high_water_state_file", policy)
        self.assertIn("trillionnium_direct_operation_custody_high_water_socket", policy)
        self.assertIn("neverallow trillionnium_direct_operation_custody_high_water", policy)
        self.assertNotIn("runtime_authority", policy)

        # The source binary is a separate v2 protocol.  If the canonical
        # Rust worktree is unavailable this remains an Android-only contract;
        # the optional source check below gives the stronger assertion when
        # the tree is present.
        if HIGH_WATER_SOURCE.is_file() and not HIGH_WATER_SOURCE.is_symlink():
            source = read(HIGH_WATER_SOURCE)
            self.assertIn("DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL", source)
            self.assertNotIn("runtime_authority_conformance", source)

    def test_rust_lane_is_explicitly_non_authorizing_when_present(self) -> None:
        """Check the canonical source lane without making it product input."""

        if not RUST_WORKTREE.is_dir():
            self.skipTest("configured Rust conformance worktree is unavailable")
        runtime_path = (
            RUST_WORKTREE
            / "crates/trillionnium-os-types/src/direct_operation_runtime_authority.rs"
        )
        probe_path = (
            RUST_WORKTREE
            / "crates/trillionnium-os-types/src/direct_operation_runtime_authority_conformance.rs"
        )
        backend_path = (
            RUST_WORKTREE
            / "apps/trillionnium-agent-privilege-broker/src/runtime_authority_conformance.rs"
        )
        if not (runtime_path.is_file() and probe_path.is_file() and backend_path.is_file()):
            # The old detached probe is intentionally not part of the active
            # tree.  Its absence is the expected Codex-only product posture.
            self.assertTrue(runtime_path.is_file())
            self.skipTest("non-authorizing conformance probe is not in the active tree")
        runtime_abi = read(
            runtime_path
        )
        probe_abi = read(
            probe_path
        )
        backend = read(
            backend_path
        )
        self.assertIn("NON_AUTHORIZING_PROBE: bool = true", probe_abi)
        for marker in (
            "SOURCE_STATUS",
            "userdebug_conformance_only_authenticated_observe_backend_no_product_route_v1",
            "No Android init socket",
        ):
            self.assertIn(marker, backend)
        for marker in (
            "EXTERNAL_RUNTIME_AUTHORITY_PRODUCT_AVAILABLE",
            "DAEMON_LISTENER_PRODUCT_WIRED",
            "ANDROID_ACTIVATION_PRODUCT_WIRED",
            "CONFERS_EFFECT_AUTHORITY",
        ):
            self.assertRegex(
                runtime_abi, rf"{re.escape(marker)}\s*:\s*bool\s*=\s*false"
            )


if __name__ == "__main__":
    unittest.main()
