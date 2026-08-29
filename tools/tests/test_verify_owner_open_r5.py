from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

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

    @staticmethod
    def _git_result(stdout: str) -> mock.Mock:
        result = mock.Mock()
        result.stdout = stdout
        return result

    def _write_fixture(self) -> None:
        packages = {
            "apps/host": [
                "trillionnium-job-runtime",
                "trillionnium-types",
                "trillionnium-turn-loop",
            ],
            "crates/types": [],
            "crates/runtime": [],
            "crates/registry": [],
            "crates/event-store": [],
            "crates/job-registry": [],
            "crates/job-runtime": [
                "trillionnium-event-store",
                "trillionnium-job-registry",
            ],
            "crates/bridge": ["trillionnium-registry", "trillionnium-runtime"],
            "crates/turn-loop": [
                "trillionnium-registry",
                "trillionnium-bridge",
                "trillionnium-runtime",
            ],
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
                "\n[[bin]]\nname = \"r5-core\"\npath = \"src/bin/r5_control_host_v7.rs\"\n"
                "\n[[bin]]\nname = \"r5-host\"\npath = \"src/bin/r5_transport_host.rs\"\n"
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
                            "name": "r5-core",
                            "path": "src/bin/r5_control_host_v7.rs",
                        },
                        {
                            "name": "r5-host",
                            "path": "src/bin/r5_transport_host.rs",
                        },
                    ],
                    "forbidden_selected_paths": [
                        "src/bin/r5_host.rs",
                        "src/bin/r5_streaming_host.rs",
                        "src/bin/r5_control_host.rs",
                        "src/bin/r5_control_host_v2.rs",
                        "src/bin/r5_control_host_v4.rs",
                        "src/bin/r5_control_host_v6.rs",
                    ],
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
                "schema": module.STATUS_SCHEMA,
                "plan_revision": "2026-08-28-r5",
                "public_release": False,
                "automatic_redispatch": False,
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
                {"name": "r5-core", "path": "src/bin/r5_control_host_v7.rs"},
                {"name": "r5-host", "path": "src/bin/r5_transport_host.rs"},
            ],
        )

    def test_default_graph_drift_fails(self) -> None:
        cargo = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        cargo = cargo.replace('"crates/turn-loop"]', '"crates/turn-loop", "apps/legacy"]', 1)
        self.write("Cargo.toml", cargo)
        report = module.verify(self.root)
        self.assertTrue(any("forbidden legacy default" in value for value in report.errors))

    def test_job_runtime_cannot_fall_out_of_default_closure(self) -> None:
        cargo = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        first = cargo.find('"crates/job-runtime"')
        second = cargo.find('"crates/job-runtime"', first + 1)
        self.assertGreaterEqual(second, 0)
        cargo = cargo[:second] + cargo[second + len('"crates/job-runtime", '):]
        self.write("Cargo.toml", cargo)
        report = module.verify(self.root)
        self.assertTrue(any("required R5 default members are absent" in value for value in report.errors))

    def test_unreviewed_internal_edge_fails(self) -> None:
        manifest = (self.root / "apps/host/Cargo.toml").read_text(encoding="utf-8")
        manifest = manifest.replace(
            "[dependencies]\n",
            '[dependencies]\ntrillionnium-surprise = "1"\n',
            1,
        )
        self.write("apps/host/Cargo.toml", manifest)
        report = module.verify(self.root)
        self.assertTrue(any("unreviewed owner-open internal edge" in value for value in report.errors))

    def test_legacy_dependency_fails(self) -> None:
        manifest = (self.root / "crates/turn-loop/Cargo.toml").read_text(encoding="utf-8")
        manifest = manifest.replace(
            "[dependencies]\n",
            '[dependencies]\nlegacy-crate = "1"\n',
            1,
        )
        self.write("crates/turn-loop/Cargo.toml", manifest)
        report = module.verify(self.root)
        self.assertTrue(any("forbidden legacy dependencies" in value for value in report.errors))

    def test_source_marker_fails(self) -> None:
        self.write("crates/runtime/src/lib.rs", "struct AgentPlanSubmission;\n")
        report = module.verify(self.root)
        self.assertTrue(any("forbidden legacy markers" in value for value in report.errors))

    def test_invalid_utf8_owner_open_source_fails_closed(self) -> None:
        path = self.root / "crates/runtime/src/invalid.rs"
        path.write_bytes(b"fn invalid() { \xff }\n")
        report = module.verify(self.root)
        self.assertTrue(any("cannot read owner-open source" in value for value in report.errors))

    def test_invalid_utf8_android_overlay_fails_closed(self) -> None:
        (self.root / "android.mk").write_bytes(b"PRODUCT_PACKAGES += \xff\n")
        report = module.verify(self.root)
        self.assertTrue(any("cannot read Android audit overlay" in value for value in report.errors))

    def test_host_autobins_drift_fails(self) -> None:
        manifest = (self.root / "apps/host/Cargo.toml").read_text(encoding="utf-8")
        self.write("apps/host/Cargo.toml", manifest.replace("autobins = false", "autobins = true"))
        report = module.verify(self.root)
        self.assertTrue(any("autobins setting drifted" in value for value in report.errors))

    def test_job_aware_core_cannot_be_downgraded(self) -> None:
        manifest = (self.root / "apps/host/Cargo.toml").read_text(encoding="utf-8")
        manifest = manifest.replace(
            "src/bin/r5_control_host_v7.rs", "src/bin/r5_control_host_v4.rs"
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

    def test_active_r6_status_cannot_bypass_missing_gap_register(self) -> None:
        status_path = self.root / "docs/status/owner-open-r5-status.json"
        status = json.loads(status_path.read_text(encoding="utf-8"))
        status.update(
            {
                "schema": module.STATUS_SCHEMA,
                "active_plan_revision": module.ACTIVE_PLAN_REVISION,
                "automatic_redispatch": False,
            }
        )
        self.json_write("docs/status/owner-open-r5-status.json", status)
        report = module.verify(self.root)
        self.assertTrue(
            any("requires the canonical gap register" in value for value in report.errors)
        )

    def test_checkout_status_probe_failure_is_fail_closed(self) -> None:
        report = module.Report()
        with mock.patch.object(
            module.subprocess,
            "run",
            side_effect=[
                self._git_result(str(self.root)),
                self._git_result("a" * 40),
                self._git_result("b" * 40),
                self._git_result(""),
                subprocess.CalledProcessError(128, ["git", "status"]),
            ],
        ):
            module._check_checkout_against_expected(
                self.root, "a" * 40, "b" * 40, report
            )
        self.assertTrue(
            any("cannot verify checkout exact source files" in error for error in report.errors)
        )

    def test_checkout_hash_probe_failure_is_fail_closed(self) -> None:
        report = module.Report()
        with mock.patch.object(
            module.subprocess,
            "run",
            side_effect=[
                self._git_result(str(self.root)),
                self._git_result("a" * 40),
                self._git_result("b" * 40),
                self._git_result(""),
                self._git_result(""),
                self._git_result("H docs/status/owner-open-r5-gap-closure.json\n"),
                self._git_result("f" * 40),
                subprocess.CalledProcessError(128, ["git", "hash-object"]),
            ],
        ):
            module._check_checkout_against_expected(
                self.root, "a" * 40, "b" * 40, report
            )
        self.assertTrue(
            any("cannot verify checkout exact source files" in error for error in report.errors)
        )


if __name__ == "__main__":
    unittest.main()
