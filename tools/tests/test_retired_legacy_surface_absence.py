#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
OLD_RUNTIME = "hep" + "ta"
OLD_DISTRO = "mob" + "ian"
OLD_SESSION = "pho" + "sh"
OLD_SHELL_PACKAGE = "trillionnium-" + "shell"
OLD_CENTER_PACKAGE = "trillionnium-" + "command-center"


class RetiredLegacySurfaceAbsenceTests(unittest.TestCase):
    def test_retired_source_and_packaging_roots_are_absent(self) -> None:
        retired = (
            ROOT / "apps" / OLD_SHELL_PACKAGE,
            ROOT / "apps" / OLD_CENTER_PACKAGE,
            ROOT / "crates" / "trillionnium-bridge-protocol",
            ROOT / "crates" / f"{OLD_RUNTIME}-core-shim",
            ROOT / "crates" / f"{OLD_RUNTIME}-runtime-shim",
            ROOT / "packaging" / OLD_DISTRO,
            ROOT / "packaging" / "debian",
            ROOT / "platform" / OLD_DISTRO,
            ROOT / "platform" / "debian",
            ROOT / "profile" / f"mobile-{OLD_SESSION}",
            ROOT / "profile" / "desktop-gnome",
            ROOT / "packaging" / "android" / "bridge-apk",
            ROOT / "packaging" / "install-dev.sh",
            ROOT / "packaging" / "uninstall-dev.sh",
            ROOT / "packaging" / f"trillionnium-{OLD_RUNTIME}-sidecar-noop.service",
            ROOT / "packaging" / f"{OLD_SHELL_PACKAGE}-companion.service",
            ROOT / "packaging" / "org.trillionnium.Shell.service",
            ROOT / "systemd" / "user" / "trillionniumd.service",
        )
        self.assertFalse(
            [str(path.relative_to(ROOT)) for path in retired if path.exists()],
            "retired legacy paths must remain absent from the active tree",
        )

    def test_workspace_has_no_retired_members_or_dependencies(self) -> None:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        workspace = cargo["workspace"]
        rendered = json.dumps(
            {
                "members": workspace["members"],
                "default-members": workspace["default-members"],
                "dependencies": sorted(workspace["dependencies"]),
            },
            sort_keys=True,
        ).lower()
        for token in (
            OLD_RUNTIME,
            OLD_SHELL_PACKAGE,
            OLD_CENTER_PACKAGE,
            "trillionnium-bridge-protocol",
        ):
            # Retired package names are identifier tokens.  A plain substring
            # check would reject the current `trillionnium-shell-exec` crate
            # while trying to retire the distinct `trillionnium-shell` package.
            pattern = rf"(?<![a-z0-9_-]){re.escape(token)}(?![a-z0-9_-])"
            self.assertIsNone(
                re.search(pattern, rendered),
                f"retired workspace token is present: {token}",
            )

        runtime = tomllib.loads(
            (ROOT / "crates/trillionnium-tool-runtime/Cargo.toml").read_text(
                encoding="utf-8"
            )
        )
        types = tomllib.loads(
            (ROOT / "crates/trillionnium-os-types/Cargo.toml").read_text(
                encoding="utf-8"
            )
        )
        self.assertNotIn(OLD_RUNTIME, json.dumps(runtime, sort_keys=True).lower())
        self.assertNotIn(OLD_RUNTIME, json.dumps(types, sort_keys=True).lower())

    def test_root_linux_policy_is_neutral_and_self_bound(self) -> None:
        policy_root = ROOT / "packaging/root-linux"
        admission_path = policy_root / "rootfs-codex-erofs-admission.v4.json"
        allowlist_path = (
            policy_root / "rootfs-fresh-minimal-bookworm-arm64.allowlist.v1.json"
        )
        admission = json.loads(admission_path.read_text(encoding="utf-8"))
        self.assertEqual(
            admission["schema"],
            "org.trillionnium.root-linux.codex-erofs-admission.v4",
        )
        self.assertEqual(
            admission["archive_contract"]["contract_schema"],
            "org.trillionnium.rootfs-package.contract.v9",
        )
        self.assertEqual(
            admission["archive_contract"]["receipt_schema"],
            "org.trillionnium.rootfs-package.receipt.v9",
        )
        for version in (1, 2, 3):
            historical_path = (
                policy_root / f"rootfs-codex-erofs-admission.v{version}.json"
            )
            historical = json.loads(historical_path.read_text(encoding="utf-8"))
            self.assertEqual(
                historical["schema"],
                f"org.trillionnium.root-linux.codex-erofs-admission.v{version}",
            )
        binding = admission["archive_contract"]["fresh_base_allowlist"]
        self.assertEqual(
            binding["path"],
            "packaging/root-linux/rootfs-fresh-minimal-bookworm-arm64.allowlist.v1.json",
        )
        self.assertEqual(
            binding["sha256"], hashlib.sha256(allowlist_path.read_bytes()).hexdigest()
        )
        self.assertTrue(
            (ROOT / "tools/root-linux/agentd-capability-runtime-conformance.sh").is_file()
        )

    def test_retirement_and_base_bound_replay_guards_remain(self) -> None:
        retained = (
            ROOT / "packaging/production-retirement-policy-v1.json",
            ROOT / "tools/production_retirement_policy.py",
            ROOT / "tools/tests/test_production_retirement_policy.py",
            ROOT / "tools/evidence-factory/legacy-rootfs-e9e937451c20-migration.json",
        )
        self.assertFalse(
            [str(path.relative_to(ROOT)) for path in retained if not path.is_file()],
            "required retirement or base-bound replay guard is missing",
        )


if __name__ == "__main__":
    unittest.main()
