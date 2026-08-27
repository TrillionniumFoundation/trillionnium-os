#!/usr/bin/env python3
"""Hermetic tests for the production Agent feature graph gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parent
MODULE_PATH = TOOLS / "production_agent_feature_gate.py"
SPEC = importlib.util.spec_from_file_location("production_feature_gate_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CORE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CORE
SPEC.loader.exec_module(CORE)


class Completed:
    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class ProductionFeatureGateTests(unittest.TestCase):
    def test_real_source_contract_and_clean_graph_pass(self) -> None:
        workspace = TOOLS.parent
        with mock.patch.object(
            CORE.subprocess,
            "run",
            return_value=Completed("trillionniumd feature graph without retired features"),
        ) as cargo_run:
            result = CORE.check(workspace, Path("cargo"))
        self.assertEqual(result["decision"], "PASS_PRODUCTION_AGENT_FEATURE_GRAPH")
        self.assertFalse(result["legacy_execution_compiled"])
        cargo_args = cargo_run.call_args.args[0]
        self.assertEqual(
            [
                cargo_args[index + 1]
                for index, value in enumerate(cargo_args)
                if value == "-p"
            ],
            [
                "trillionnium-agent-direct-tools",
                "trillionniumd",
            ],
        )
        selected_features = cargo_args[cargo_args.index("--features") + 1].split(",")
        self.assertEqual(
            selected_features,
            ["trillionnium-agent-direct-tools/production-durable-hotpath"],
        )
        self.assertEqual(
            result["retired_paths_absent"],
            ["apps/trillionnium-shell", "packaging/mobian"],
        )

    def test_retired_shell_token_boundary_allows_shell_exec_only(self) -> None:
        workspace = TOOLS.parent
        CORE.reject_retired_tokens(workspace, [], "trillionnium-shell-exec")
        with self.assertRaisesRegex(
            CORE.GateError, "retired_product_token:root_builder:trillionnium-shell"
        ):
            CORE.reject_retired_tokens(workspace, [], "trillionnium-shell")

    def test_forbidden_transitive_feature_holds(self) -> None:
        workspace = TOOLS.parent
        with mock.patch.object(
            CORE.subprocess,
            "run",
            return_value=Completed(
                'trillionnium-tool-runtime feature "legacy-authority-effects"'
            ),
        ):
            with self.assertRaisesRegex(
                CORE.GateError, "production_feature_activated:legacy-authority-effects"
            ):
                CORE.check(workspace, Path("cargo"))

    def test_development_compatibility_lane_in_production_graph_holds(self) -> None:
        workspace = TOOLS.parent
        with mock.patch.object(
            CORE.subprocess,
            "run",
            return_value=Completed(
                'trillionnium-agent-direct-tools feature "development-compatibility-lane"'
            ),
        ):
            with self.assertRaisesRegex(
                CORE.GateError,
                "production_feature_activated:development-compatibility-lane",
            ):
                CORE.check(workspace, Path("cargo"))

    def test_dev_overrides_in_production_graph_holds(self) -> None:
        workspace = TOOLS.parent
        with mock.patch.object(
            CORE.subprocess,
            "run",
            return_value=Completed(
                'trillionnium-agent-direct-tools feature "dev-overrides"'
            ),
        ):
            with self.assertRaisesRegex(
                CORE.GateError,
                "production_feature_activated:dev-overrides",
            ):
                CORE.check(workspace, Path("cargo"))

    def test_root_builder_all_features_is_rejected(self) -> None:
        workspace = TOOLS.parent
        original = CORE.regular_file

        def poisoned(path: Path, maximum: int) -> bytes:
            data = original(path, maximum)
            if path.name == "build-root-linux-arm64.sh":
                return data + b"\n# --all-features\n"
            return data

        with mock.patch.object(CORE, "regular_file", side_effect=poisoned):
            with self.assertRaisesRegex(CORE.GateError, "all_features_denied"):
                CORE.check(workspace, Path("cargo"))

    def test_root_builder_cannot_drop_durable_hotpath(self) -> None:
        workspace = TOOLS.parent
        original = CORE.regular_file

        def poisoned(path: Path, maximum: int) -> bytes:
            data = original(path, maximum)
            if path.name == "build-root-linux-arm64.sh":
                return data.replace(
                    (
                        b"--features "
                        b"trillionnium-agent-direct-tools/production-durable-hotpath"
                    ),
                    (
                        b"--features "
                        b"trillionnium-agent-direct-tools/"
                        b"development-compatibility-lane"
                    ),
                )
            return data

        with mock.patch.object(CORE, "regular_file", side_effect=poisoned):
            with self.assertRaisesRegex(
                CORE.GateError, "root_builder_durable_hotpath_feature_drift"
            ):
                CORE.check(workspace, Path("cargo"))

    def test_root_builder_extra_package_is_rejected(self) -> None:
        workspace = TOOLS.parent
        original = CORE.regular_file

        def poisoned(path: Path, maximum: int) -> bytes:
            data = original(path, maximum)
            if path.name == "build-root-linux-arm64.sh":
                return data.replace(
                    b"    -p trillionniumd\n",
                    (
                        b"    -p trillionniumd \\\n"
                        b"    -p trillionnium-agent-privilege-broker\n"
                    ),
                )
            return data

        with mock.patch.object(CORE, "regular_file", side_effect=poisoned):
            with self.assertRaisesRegex(
                CORE.GateError, "root_builder_package_contract_drift"
            ):
                CORE.check(workspace, Path("cargo"))

    def test_workspace_member_contract_drift_is_rejected(self) -> None:
        workspace = TOOLS.parent
        original = CORE.load_toml

        def drifted(path: Path) -> dict[str, object]:
            value = original(path)
            if path == workspace / "Cargo.toml":
                value["workspace"]["members"].append("apps/trillionnium-shell")
            return value

        with mock.patch.object(CORE, "load_toml", side_effect=drifted):
            with self.assertRaisesRegex(
                CORE.GateError, "workspace_member_contract_drift"
            ):
                CORE.check(workspace, Path("cargo"))

    def test_manifest_feature_drift_is_rejected(self) -> None:
        workspace = TOOLS.parent
        original = CORE.load_toml

        def drifted(path: Path) -> dict[str, object]:
            value = original(path)
            if path.as_posix().endswith("apps/trillionniumd/Cargo.toml"):
                value["features"]["default"] = ["legacy-plan-conformance"]
            return value

        with mock.patch.object(CORE, "load_toml", side_effect=drifted):
            with self.assertRaisesRegex(CORE.GateError, "feature_contract_drift"):
                CORE.check(workspace, Path("cargo"))

    def test_development_compatibility_lane_must_remain_explicit_and_non_product(
        self,
    ) -> None:
        workspace = TOOLS.parent
        original = CORE.load_toml

        def drifted(path: Path) -> dict[str, object]:
            value = original(path)
            if path.as_posix().endswith(
                "crates/trillionnium-agent-direct-tools/Cargo.toml"
            ):
                value["features"]["development-compatibility-lane"] = []
            return value

        with mock.patch.object(CORE, "load_toml", side_effect=drifted):
            with self.assertRaisesRegex(CORE.GateError, "feature_contract_drift"):
                CORE.check(workspace, Path("cargo"))

    def test_implicit_default_feature_table_is_rejected(self) -> None:
        workspace = TOOLS.parent
        original = CORE.load_toml

        def drifted(path: Path) -> dict[str, object]:
            value = original(path)
            if path.as_posix().endswith("apps/trillionniumd/Cargo.toml"):
                value["features"].pop("default")
            return value

        with mock.patch.object(CORE, "load_toml", side_effect=drifted):
            with self.assertRaisesRegex(CORE.GateError, "feature_contract_drift"):
                CORE.check(workspace, Path("cargo"))

    def test_retired_shell_token_in_product_builder_is_rejected(self) -> None:
        workspace = TOOLS.parent
        original_lstat = CORE.os.lstat

        def shell_present(path: object) -> object:
            if Path(path) == workspace / "apps/trillionnium-shell":
                return object()
            return original_lstat(path)

        with mock.patch.object(CORE.os, "lstat", side_effect=shell_present):
            with self.assertRaisesRegex(
                CORE.GateError, "retired_path_present:apps/trillionnium-shell"
            ):
                CORE.check(workspace, Path("cargo"))

        original = CORE.regular_file

        def poisoned(path: Path, maximum: int) -> bytes:
            data = original(path, maximum)
            if path.name == "build-root-linux-arm64.sh":
                return data + b"\n# forbidden: trillionnium-shell/ui shell-ui\n"
            return data

        with mock.patch.object(CORE, "regular_file", side_effect=poisoned):
            with self.assertRaisesRegex(CORE.GateError, "retired_product_token"):
                CORE.check(workspace, Path("cargo"))

    def test_mobian_injection_in_product_builder_is_rejected(self) -> None:
        workspace = TOOLS.parent
        original = CORE.regular_file

        def poisoned(path: Path, maximum: int) -> bytes:
            data = original(path, maximum)
            if path.name == "build-root-linux-arm64.sh":
                return data + b"\n# Mobian payload injection\n"
            return data

        with mock.patch.object(CORE, "regular_file", side_effect=poisoned):
            with self.assertRaisesRegex(
                CORE.GateError, "retired_product_token:root_builder:mobian"
            ):
                CORE.check(workspace, Path("cargo"))


if __name__ == "__main__":
    unittest.main()
