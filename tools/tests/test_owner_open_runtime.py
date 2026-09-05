#!/usr/bin/env python3
"""Static negative guards for the r4 owner-open process runtime."""

from __future__ import annotations

import json
from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "crates/trillionnium-owner-open-runtime"


class OwnerOpenRuntimeContractTest(unittest.TestCase):
    def test_runtime_is_an_explicit_isolated_workspace_member(self) -> None:
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        members = workspace["workspace"]["members"]
        defaults = workspace["workspace"]["default-members"]
        path = "crates/trillionnium-owner-open-runtime"
        self.assertIn(path, members)
        self.assertIn(path, defaults)

        package = tomllib.loads((RUNTIME / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(package["package"]["name"], "trillionnium-owner-open-runtime")
        self.assertEqual(set(package.get("dependencies", {})), {"libc", "thiserror"})
        self.assertEqual(set(package.get("dev-dependencies", {})), {"tempfile"})
        self.assertEqual(package.get("features", {}).get("default"), [])

    def test_runtime_has_no_legacy_trillionnium_dependency_edge(self) -> None:
        manifest = (RUNTIME / "Cargo.toml").read_text(encoding="utf-8")
        for forbidden in (
            "trillionnium-shell-exec",
            "trillionnium-os-types",
            "trillionnium-agent-direct-tools",
            "trillionnium-tool-runtime",
            "trillionnium-privilege-broker-protocol",
            "trillionnium-agent-api-uds",
        ):
            self.assertNotIn(forbidden, manifest)

    def test_shell_and_adb_boundaries_are_mechanical(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((RUNTIME / "src").glob("*.rs"))
        )
        for required in (
            "pub fn execute_shell",
            "pub fn execute_adb",
            "command.pre_exec",
            "libc::setpgid",
            "terminate_process_group",
            "send_process_group_signal",
            "TerminalKind::OutputLimitExceeded",
            "request.adb_executable.into_os_string()",
            "args: request.argv.into_iter().map(OsString::from).collect()",
        ):
            self.assertIn(required, source)

        for forbidden in (
            "serial_args(",
            "known_adb_subcommand",
            "risk_class",
            "requires_approval",
            "confirmation_lease",
            "ProductionAdbTransport",
            "standard_shell_exec_only",
            "command_string_mode_not_in_v1",
        ):
            self.assertNotIn(forbidden, source)

    def test_authored_tests_cover_normal_negative_and_fault_paths(self) -> None:
        tests = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((RUNTIME / "tests").glob("*.rs"))
        )
        for required in (
            "command_string_streams_raw_stdout_stderr_and_preserves_failure",
            "argv_is_element_preserving_and_does_not_expand_shell_text",
            "cwd_environment_delta_and_stdin_are_mechanical_inputs",
            "timeout_terminates_the_process_group_and_emits_one_terminal_event",
            "cancellation_terminates_the_process_group_without_redispatch",
            "output_exhaustion_is_mechanical_and_returns_truncated_observation",
            "adb_exec_passes_unknown_future_argv_without_target_or_serial_injection",
            "spawn_failure_is_an_honest_terminal_observation",
            "malformed_adb_request_is_rejected_before_any_process_event",
            "leader_exit_with_inherited_pipes_is_bounded_and_reaps_the_descendant",
        ):
            self.assertIn(required, tests)
        self.assertIn("assert_eq!(terminal_count(&events), 1)", tests)

    def test_machine_status_does_not_promote_unexecuted_source(self) -> None:
        baseline = json.loads(
            (ROOT / "docs/machine/current-baseline.v1.json").read_text(
                encoding="utf-8"
            )
        )
        program = json.loads(
            (ROOT / "docs/machine/program-state.v1.json").read_text(
                encoding="utf-8"
            )
        )
        evidence = json.loads(
            (ROOT / "docs/machine/evidence-index.v1.json").read_text(
                encoding="utf-8"
            )
        )

        candidate = baseline["documentation_candidate"]
        self.assertIsNone(candidate["commit"])
        self.assertIsNone(candidate["tree"])
        self.assertNotEqual(candidate["ci_status"], "PASSED")
        self.assertEqual(
            candidate["claim_ceiling"], "DOCUMENTATION_AND_GOVERNANCE_CANDIDATE_ONLY"
        )
        self.assertFalse(program["zero_gap"])
        self.assertFalse(program["public_release"])
        self.assertFalse(program["automatic_redispatch"])
        self.assertEqual(
            program["status"], "G1_DOCUMENTATION_AND_MODULARIZATION_CANDIDATE"
        )
        for milestone in program["capability_milestones"]:
            if milestone["required_level"] != "L1":
                self.assertEqual(milestone["status"], "EXTERNAL_HOLD")
        self.assertTrue(evidence["records"])
        self.assertTrue(all(not record["promotable"] for record in evidence["records"]))
        for claim in (
            "installed Root Linux Codex qualification",
            "clean Android image or target-files qualification",
            "physical shell, job or ordinary ADB effect",
            "destructive crash, storage, USB, reboot or power-loss qualification",
            "signed public release",
        ):
            self.assertIn(claim, baseline["non_claims"])


if __name__ == "__main__":
    unittest.main()
