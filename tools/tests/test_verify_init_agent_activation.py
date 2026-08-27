#!/usr/bin/env python3
"""Hermetic tests for the host-only init/Agent activation graph verifier."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile


TOOL_PATH = Path(__file__).resolve().parents[1] / "verify_init_agent_activation.py"
SPEC = importlib.util.spec_from_file_location("verify_init_agent_activation_tested", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TOOL
SPEC.loader.exec_module(TOOL)


INIT = """\
on property:sys.trillionnium.rootlinux.prepare=0
    start trillionnium_agent_egress_guard
on property:sys.trillionnium.agent_egress_guard=ready && property:sys.trillionnium.agentd.desired=1
    start trillionnium_root_linux_daemon
on property:sys.trillionnium.high_water_ready=ready && property:sys.trillionnium.rootlinux.prepare=0
    start trillionnium_shell_exec_broker
service trillionnium_root_linux_bootstrap /system_ext/bin/trillionnium-root-linux-bootstrap
    class late_start
    user root
    disabled
    oneshot
service trillionnium_root_linux_daemon /system_ext/bin/trillionniumd --agent-api-uds
    class late_start
    user root
    disabled
    oneshot
"""
WRAPPER = """\
export TRILLIONNIUM_ANDROID_UI_AGENT_API=1
export TRILLIONNIUM_AGENT_API_SOCKET=/run/trillionnium/agent-api-v2.sock
exec /system_ext/bin/trillionnium-root-linux-run /usr/bin/trillionniumd "$@"
"""
MANIFEST = """\
agent_api_requires_adb=false
android_daemon_service=trillionnium_root_linux_daemon
"""
ABI = {
    "carriers": {
        "kernel_agent_api": {
            "socket": "/run/trillionnium/agent-api-v2.sock",
            "trust_domain": "kernel_peercred_peersec_channel_binding",
        }
    }
}
MAIN = """
fn bind_agent_api_listener() {}
libc::SO_PEERCRED
libc::SO_PEERSEC
requires_channel_binding
AgentApiReplayStore::open_from_env
from_store_after_exclusive_startup
"""


def make_fixture(root: Path) -> tuple[Path, Path]:
    android = root / "android"
    rust = root / "rust"
    init_path = android / "vendor/trillionnium/prebuilt/common/etc/init/init.trillionnium-system_ext.rc"
    wrapper_path = android / "vendor/trillionnium/prebuilt/common/bin/trillionniumd.sh"
    manifest_path = android / "vendor/trillionnium/prebuilt/common/linux/manifest.txt"
    abi_path = rust / "crates/trillionnium-os-types/contracts/direct-agent-host-abi-v1.json"
    main_path = rust / "apps/trillionniumd/src/main.rs"
    for path in (init_path, wrapper_path, manifest_path, abi_path, main_path):
        path.parent.mkdir(parents=True, exist_ok=True)
    init_path.write_text(INIT, encoding="utf-8")
    wrapper_path.write_text(WRAPPER, encoding="utf-8")
    manifest_path.write_text(MANIFEST, encoding="utf-8")
    abi_path.write_text(json.dumps(ABI), encoding="utf-8")
    main_path.write_text(MAIN, encoding="utf-8")
    return android, rust


class InitAgentActivationVerifierTests(unittest.TestCase):
    def test_source_graph_passes_but_live_activation_remains_hold(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            android, rust = make_fixture(Path(temporary))
            evidence = TOOL.build_evidence(android, rust, None)
        self.assertEqual(evidence["decision"], TOOL.SOURCE_PASS)
        self.assertEqual(evidence["scope"], "host_only_source_contract")
        self.assertEqual(evidence["source"]["source_graph"], "PASS")
        self.assertEqual(evidence["source"]["live_activation"], "HOLD_NOT_OBSERVED")
        self.assertEqual(evidence["source"]["authenticated_peer"], "HOLD_NOT_OBSERVED")
        self.assertFalse(any(evidence["safety"].values()))

    def test_init_service_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            android, rust = make_fixture(Path(temporary))
            path = android / "vendor/trillionnium/prebuilt/common/etc/init/init.trillionnium-system_ext.rc"
            path.write_text(INIT.replace("--agent-api-uds", "--wrong-mode"), encoding="utf-8")
            with self.assertRaisesRegex(TOOL.ContractError, "init daemon service"):
                TOOL.build_evidence(android, rust, None)

    def test_socket_splice_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            android, rust = make_fixture(Path(temporary))
            path = android / "vendor/trillionnium/prebuilt/common/bin/trillionniumd.sh"
            path.write_text(WRAPPER.replace("agent-api-v2.sock", "other.sock"), encoding="utf-8")
            with self.assertRaisesRegex(TOOL.ContractError, "daemon socket export"):
                TOOL.build_evidence(android, rust, None)

    def test_target_without_init_artifacts_is_hold_not_source_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            android, rust = make_fixture(root)
            target = root / "target-files.zip"
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("META/misc_info.txt", "userdata_fs_type=ext4\n")
            evidence = TOOL.build_evidence(android, rust, target)
        self.assertEqual(evidence["decision"], TOOL.SOURCE_HOLD)
        self.assertEqual(
            evidence["source"]["target_artifacts"]["required"]["init_rc"]["status"],
            "HOLD",
        )

    def test_target_symlink_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            android, rust = make_fixture(root)
            target = root / "target-files.zip"
            info = zipfile.ZipInfo("SYSTEM_EXT/etc/init/init.trillionnium-system_ext.rc")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr(info, "redirect")
            with self.assertRaisesRegex(TOOL.ContractError, "symlink"):
                TOOL.build_evidence(android, rust, target)

    def test_evidence_publication_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            TOOL.publish_new(path, b"{}\n")
            with self.assertRaisesRegex(TOOL.ContractError, "overwrite"):
                TOOL.publish_new(path, b"changed\n")


if __name__ == "__main__":
    unittest.main()
