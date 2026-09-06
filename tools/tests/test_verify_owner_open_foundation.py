from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = REPO_ROOT / "tools/verify-owner-open-foundation.py"
GENERATOR_PATH = REPO_ROOT / "tools/generate-owner-open-types.py"

spec = importlib.util.spec_from_file_location("owner_open_verifier", VERIFIER_PATH)
assert spec is not None and spec.loader is not None
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class OwnerOpenFoundationVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def json_write(self, relative: str, value: object) -> None:
        self.write(relative, json.dumps(value, indent=2) + "\n")

    def _write_fixture(self) -> None:
        self.write(
            "Cargo.toml",
            textwrap.dedent(
                """
                [workspace]
                members = ["apps/trillionnium-owner-open-host", "crates/trillionnium-owner-open-types", "apps/legacy"]
                default-members = ["apps/trillionnium-owner-open-host", "crates/trillionnium-owner-open-types"]
                resolver = "3"
                """
            ).lstrip(),
        )
        self.write(
            "apps/trillionnium-owner-open-host/Cargo.toml",
            textwrap.dedent(
                """
                [package]
                name = "trillionnium-owner-open-host"
                version = "0.1.0"
                edition = "2024"

                [dependencies]
                serde = "1"
                serde_json = "1"
                trillionnium-owner-open-types = { path = "../../crates/trillionnium-owner-open-types" }
                """
            ).lstrip(),
        )
        self.write(
            "apps/trillionnium-owner-open-host/src/lib.rs",
            "pub const FOUNDATION: &str = \"owner-open\";\n",
        )
        self.write(
            "crates/trillionnium-owner-open-types/src/lib.rs",
            "pub const FOUNDATION: &str = \"owner-open\";\n",
        )
        self.write(
            "crates/trillionnium-owner-open-types/Cargo.toml",
            textwrap.dedent(
                """
                [package]
                name = "trillionnium-owner-open-types"
                version = "0.1.0"
                edition = "2024"

                [dependencies]
                serde = "1"
                serde_json = "1"
                """
            ).lstrip(),
        )
        self.write(
            "docs/TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md",
            "Revision 2026-08-27-r4\n\n"
            "Status: ACTIVE — the only implementation sequencing and closeout plan\n",
        )
        self.json_write(
            "docs/contracts/codex-sovereign-direct-tools-v1.json",
            {
                "schema": "org.trillionnium.codex-sovereign-direct-tools.v1",
                "revision": "2026-08-27-r3",
                "profiles": {"owner_open": {}},
                "ingress": {
                    "default_socket": "@trillionnium_direct_agent_host_v1",
                    "rootlinux_alias": "/run/trillionnium/direct-agent-host-v1.sock",
                    "owner_open_request_type": "RunTurnRequest",
                },
                "request_schemas": {},
                "run_turn_frame": {},
            },
        )
        graph = {
            "schema": "org.trillionnium.owner-open-forbidden-default-graph.v1",
            "revision": "2026-08-27-r4",
            "cargo": {
                "required_workspace_members": [
                    "apps/trillionnium-owner-open-host",
                    "crates/trillionnium-owner-open-types",
                ],
                "required_default_members": [
                    "apps/trillionnium-owner-open-host",
                    "crates/trillionnium-owner-open-types",
                ],
                "allowed_default_members": [
                    "apps/trillionnium-owner-open-host",
                    "crates/trillionnium-owner-open-types",
                ],
                "forbidden_default_members": ["apps/legacy"],
                "owner_open_types_forbidden_dependencies": ["legacy-dependency"],
                "owner_open_host_manifest": "apps/trillionnium-owner-open-host/Cargo.toml",
                "owner_open_host_forbidden_dependencies": ["legacy-host-dependency"],
                "isolated_source_roots": [
                    "apps/trillionnium-owner-open-host",
                    "crates/trillionnium-owner-open-types",
                ],
                "forbidden_source_markers": ["AgentPlanSubmission"],
            },
            "android": {
                "audit_overlay_path": "android.mk",
                "forbidden_owner_open_packages": ["ForbiddenAndroid"],
            },
            "required_documents": [],
            "generated_checks": [
                {
                    "generator": "tools/generate-owner-open-types.py",
                    "output": "crates/trillionnium-owner-open-types/src/generated.rs",
                }
            ],
        }
        self.json_write(
            "docs/contracts/owner-open-forbidden-default-graph-v1.json", graph
        )
        self.json_write(
            "docs/status/owner-open-r4-status.json",
            {
                "plan_revision": "2026-08-27-r4",
                "semantic_contract_revision": "2026-08-27-r3",
                "work_packages": [
                    {"id": "W0", "complete": False},
                    {"id": "W6", "complete": False},
                ],
            },
        )
        self.json_write(
            "schemas/codex-sovereign-direct-tools.schema.json",
            {
                "description": "Codec only; it does not grant or deny an operation.",
                "additionalProperties": True,
                "$defs": {
                    "runTurnRequest": {},
                    "turnCancelRequest": {},
                    "shellExec": {},
                    "adbExec": {},
                },
            },
        )
        self.write("android.mk", "PRODUCT_PACKAGES += OwnerOpenHost\n")
        target_generator = self.root / "tools/generate-owner-open-types.py"
        target_generator.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(GENERATOR_PATH, target_generator)
        subprocess.run(
            [
                sys.executable,
                str(target_generator),
                "--contract",
                str(self.root / "docs/contracts/codex-sovereign-direct-tools-v1.json"),
                "--output",
                str(
                    self.root
                    / "crates/trillionnium-owner-open-types/src/generated.rs"
                ),
            ],
            cwd=self.root,
            check=True,
        )

    def test_clean_fixture_passes(self) -> None:
        report = verifier.verify(self.root, strict_android=False)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.warnings, [])

    def test_forbidden_default_member_fails(self) -> None:
        cargo = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        cargo = cargo.replace(
            'default-members = ["apps/trillionnium-owner-open-host", "crates/trillionnium-owner-open-types"]',
            'default-members = ["apps/trillionnium-owner-open-host", "crates/trillionnium-owner-open-types", "apps/legacy"]',
        )
        self.write("Cargo.toml", cargo)
        report = verifier.verify(self.root, strict_android=False)
        self.assertTrue(
            any("forbidden owner-open Cargo default member" in error for error in report.errors)
        )

    def test_forbidden_internal_dependency_fails(self) -> None:
        manifest = (
            self.root / "crates/trillionnium-owner-open-types/Cargo.toml"
        ).read_text(encoding="utf-8")
        manifest += 'legacy-dependency = "1"\n'
        self.write("crates/trillionnium-owner-open-types/Cargo.toml", manifest)
        report = verifier.verify(self.root, strict_android=False)
        self.assertTrue(
            any("legacy/broad internal crates" in error for error in report.errors)
        )

    def test_forbidden_host_dependency_fails(self) -> None:
        manifest = (
            self.root / "apps/trillionnium-owner-open-host/Cargo.toml"
        ).read_text(encoding="utf-8")
        manifest += 'legacy-host-dependency = "1"\n'
        self.write("apps/trillionnium-owner-open-host/Cargo.toml", manifest)
        report = verifier.verify(self.root, strict_android=False)
        self.assertTrue(
            any("owner-open Host depends" in error for error in report.errors)
        )

    def test_legacy_source_marker_fails(self) -> None:
        self.write(
            "apps/trillionnium-owner-open-host/src/lib.rs",
            "struct AgentPlanSubmission;\n",
        )
        report = verifier.verify(self.root, strict_android=False)
        self.assertTrue(
            any("legacy semantic markers" in error for error in report.errors)
        )

    def test_android_hits_are_warning_until_strict_cutover(self) -> None:
        self.write("android.mk", "PRODUCT_PACKAGES += ForbiddenAndroid\n")
        foundation = verifier.verify(self.root, strict_android=False)
        self.assertEqual(foundation.errors, [])
        self.assertTrue(foundation.warnings)
        strict = verifier.verify(self.root, strict_android=True)
        self.assertTrue(
            any("Android audit overlay" in error for error in strict.errors)
        )

    def test_stale_generated_file_fails(self) -> None:
        self.write(
            "crates/trillionnium-owner-open-types/src/generated.rs",
            "// stale\n",
        )
        report = verifier.verify(self.root, strict_android=False)
        self.assertTrue(
            any("generated owner-open constants are stale" in error for error in report.errors)
        )


if __name__ == "__main__":
    unittest.main()
