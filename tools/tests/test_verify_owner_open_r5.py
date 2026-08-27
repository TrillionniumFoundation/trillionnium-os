from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-r5.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_r5", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class VerifyOwnerOpenR5Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, path: str, content: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def json_write(self, path: str, value: object) -> None:
        self.write(path, json.dumps(value, indent=2) + "\n")

    def _write_fixture(self) -> None:
        packages = {
            "apps/host": ["types", "turn-loop"],
            "crates/types": [],
            "crates/runtime": [],
            "crates/registry": [],
            "crates/bridge": ["registry", "runtime"],
            "crates/turn-loop": ["registry", "bridge", "runtime"],
        }
        defaults = list(packages)
        self.write(
            "Cargo.toml",
            "[workspace]\n"
            + "members = " + json.dumps(defaults + ["apps/legacy"]) + "\n"
            + "default-members = " + json.dumps(defaults) + "\n",
        )
        specs = []
        for path, internal in packages.items():
            deps = "\n".join(f'{name} = "1"' for name in internal)
            package_extra = "autobins = false\n" if path == "apps/host" else ""
            bins = (
                "\n[[bin]]\nname = \"foundation-host\"\npath = \"src/main.rs\"\n"
                "\n[[bin]]\nname = \"r5-host\"\npath = \"src/bin/r5_streaming_host.rs\"\n"
                if path == "apps/host"
                else ""
            )
            self.write(
                f"{path}/Cargo.toml",
                f"[package]\nname = \"{path.replace('/', '-')}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n{package_extra}\n[dependencies]\n{deps}\n{bins}",
            )
            self.write(f"{path}/src/lib.rs", "pub const OWNER_OPEN: bool = true;\n")
            specs.append(
                {
                    "path": path,
                    "allowed_internal_dependencies": internal,
                }
            )
        contract = {
            "schema": "org.trillionnium.owner-open-forbidden-default-graph.v2",
            "revision": "2026-08-28-r5",
            "cargo": {
                "required_workspace_members": defaults,
                "required_default_members": defaults,
                "allowed_default_members": defaults,
                "forbidden_default_members": ["apps/legacy"],
                "forbidden_internal_dependencies": ["legacy-crate"],
                "forbidden_source_markers": ["AgentPlanSubmission"],
                "host_binary_contract": {
                    "manifest": "apps/host/Cargo.toml",
                    "autobins": False,
                    "required_bins": [
                        {"name": "foundation-host", "path": "src/main.rs"},
                        {
                            "name": "r5-host",
                            "path": "src/bin/r5_streaming_host.rs",
                        },
                    ],
                    "forbidden_selected_paths": ["src/bin/r5_host.rs"],
                },
                "owner_open_packages": specs,
            },
            "android": {
                "audit_overlay_path": "android.mk",
                "forbidden_owner_open_packages": ["ForbiddenAndroid"],
            },
        }
        self.json_write("docs/contracts/owner-open-forbidden-default-graph-v2.json", contract)
        self.write(
            "docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md",
            "Revision 2026-08-28-r5\nStatus: ACTIVE — the only implementation sequencing and closeout plan\n",
        )
        self.json_write(
            "docs/status/owner-open-r5-status.json",
            {
                "plan_revision": "2026-08-28-r5",
                "public_release": False,
                "not_claimed": ["device"],
                "work_packages": [
                    {"id": f"W{index}", "status": "SOURCE_IMPLEMENTED", "latest_evidence_level": "L0"}
                    for index in range(8)
                ],
            },
        )
        self.write(
            "docs/status/owner-open-r5-traceability.tsv",
            "requirement_id\twork_package\tsource\ttest\tevidence\tstatus\n",
        )
        self.write("android.mk", "PRODUCT_PACKAGES += OwnerOpen\n")

    def test_clean_fixture_passes(self) -> None:
        report = module.verify(self.root)
        self.assertEqual(report.errors, [])
        self.assertEqual(
            report.facts["host_binaries"],
            [
                {"name": "foundation-host", "path": "src/main.rs"},
                {"name": "r5-host", "path": "src/bin/r5_streaming_host.rs"},
            ],
        )

    def test_default_graph_drift_fails(self) -> None:
        cargo = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        cargo = cargo.replace('"crates/turn-loop"]', '"crates/turn-loop", "apps/legacy"]', 1)
        self.write("Cargo.toml", cargo)
        report = module.verify(self.root)
        self.assertTrue(any("forbidden legacy default" in value for value in report.errors))

    def test_unreviewed_internal_edge_fails(self) -> None:
        manifest = (self.root / "apps/host/Cargo.toml").read_text(encoding="utf-8")
        self.write("apps/host/Cargo.toml", manifest + 'trillionnium-surprise = "1"\n')
        report = module.verify(self.root)
        self.assertTrue(any("unreviewed owner-open internal edge" in value for value in report.errors))

    def test_legacy_dependency_fails(self) -> None:
        manifest = (self.root / "crates/turn-loop/Cargo.toml").read_text(encoding="utf-8")
        self.write("crates/turn-loop/Cargo.toml", manifest + 'legacy-crate = "1"\n')
        report = module.verify(self.root)
        self.assertTrue(any("forbidden legacy dependencies" in value for value in report.errors))

    def test_source_marker_fails(self) -> None:
        self.write("crates/runtime/src/lib.rs", "struct AgentPlanSubmission;\n")
        report = module.verify(self.root)
        self.assertTrue(any("forbidden legacy markers" in value for value in report.errors))

    def test_host_autobins_drift_fails(self) -> None:
        manifest = (self.root / "apps/host/Cargo.toml").read_text(encoding="utf-8")
        self.write("apps/host/Cargo.toml", manifest.replace("autobins = false", "autobins = true"))
        report = module.verify(self.root)
        self.assertTrue(any("autobins setting drifted" in value for value in report.errors))

    def test_superseded_host_path_cannot_be_selected(self) -> None:
        manifest = (self.root / "apps/host/Cargo.toml").read_text(encoding="utf-8")
        manifest = manifest.replace(
            "src/bin/r5_streaming_host.rs", "src/bin/r5_host.rs"
        )
        self.write("apps/host/Cargo.toml", manifest)
        report = module.verify(self.root)
        self.assertTrue(
            any(
                "superseded Host entrypoint" in value
                or "explicit binaries drifted" in value
                for value in report.errors
            )
        )

    def test_android_hold_is_warning_then_strict_error(self) -> None:
        self.write("android.mk", "PRODUCT_PACKAGES += ForbiddenAndroid\n")
        report = module.verify(self.root, strict_android=False)
        self.assertEqual(report.errors, [])
        self.assertTrue(report.warnings)
        strict = module.verify(self.root, strict_android=True)
        self.assertTrue(any("Android overlay" in value for value in strict.errors))


if __name__ == "__main__":
    unittest.main()
