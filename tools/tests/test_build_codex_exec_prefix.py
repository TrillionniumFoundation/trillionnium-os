#!/usr/bin/env python3
"""Tests for the owner-open Codex exec-prefix generator."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = ROOT / "tools/owner-open/probe_codex_cli.py"
PREFIX_PATH = ROOT / "tools/owner-open/build_codex_exec_prefix.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROBE = load("probe_codex_for_prefix_test", PROBE_PATH)
PREFIX = load("build_codex_exec_prefix_test", PREFIX_PATH)


class CodexExecPrefixTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fake = self.root / "codex"
        self.log = self.root / "argv.log"
        self.probe_path = self.root / "probe.json"
        self.write_fake(
            r'''#!/bin/sh
set -eu
: "${FAKE_CODEX_PREFIX_LOG:?}"
printf '%s\n' "$*" >>"$FAKE_CODEX_PREFIX_LOG"
case "$*" in
  --version) printf '%s\n' 'codex-prefix-fixture 1.2.3' ;;
  --help) printf '%s\n' 'Commands:' '  exec execute one turn' ;;
  'exec --help') cat <<'EOF'
Usage: codex exec [OPTIONS]
  --json
  -s, --sandbox <MODE>
  values: danger-full-access
  --dangerously-bypass-approvals-and-sandbox
  -m, --model <MODEL>
EOF
  ;;
  *) printf 'execution forbidden: %s\n' "$*" >&2; exit 91 ;;
esac
'''
        )
        self.previous = os.environ.get("FAKE_CODEX_PREFIX_LOG")
        os.environ["FAKE_CODEX_PREFIX_LOG"] = str(self.log)
        report = PROBE.probe(self.fake)
        PROBE.atomic_write(self.probe_path, report)
        self.executable_sha256 = report["executable"]["sha256"]
        self.log.write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        if self.previous is None:
            os.environ.pop("FAKE_CODEX_PREFIX_LOG", None)
        else:
            os.environ["FAKE_CODEX_PREFIX_LOG"] = self.previous
        self.temp.cleanup()

    def write_fake(self, content: str) -> None:
        self.fake.write_text(textwrap.dedent(content), encoding="utf-8")
        self.fake.chmod(0o700)

    def build(self, policy: str = "auto-owner-open", model: str | None = None):
        return PREFIX.build_plan(
            self.probe_path,
            expected_executable_sha256=self.executable_sha256,
            access_policy=policy,
            config_generation="owner-open-config-7",
            model=model,
        )

    def test_auto_policy_deterministically_prefers_observed_bypass(self) -> None:
        plan = self.build()
        self.assertEqual(plan["selected_access_policy"], "bypass-approvals-and-sandbox")
        self.assertEqual(
            plan["argv_prefix"],
            [
                str(self.fake),
                "exec",
                "--json",
                "--dangerously-bypass-approvals-and-sandbox",
            ],
        )
        self.assertEqual(plan["prompt_delivery"], "unselected_requires_W1_2_adapter_test")
        self.assertEqual(plan["claim_ceiling"], "EXEC_PREFIX_GENERATED_NOT_EXECUTED")
        self.assertEqual(self.log.read_text(encoding="utf-8"), "")
        self.assertTrue(plan["claims"]["generated_only"])
        for field in (
            "codex_executed",
            "credentials_opened",
            "provider_contacted",
            "model_invoked",
            "json_transport_executed",
            "owner_open_mode_executed",
            "host_integrated",
            "same_turn_tool_effect",
            "release_evidence",
        ):
            self.assertFalse(plan["claims"][field], field)

    def test_explicit_danger_full_access_uses_observed_long_sandbox_option(self) -> None:
        plan = self.build("danger-full-access")
        self.assertEqual(plan["selected_access_policy"], "danger-full-access")
        self.assertEqual(
            plan["argv_prefix"],
            [str(self.fake), "exec", "--json", "--sandbox", "danger-full-access"],
        )

    def test_model_override_uses_only_an_observed_option(self) -> None:
        plan = self.build(model="gpt-test-model")
        self.assertEqual(plan["argv_prefix"][-2:], ["--model", "gpt-test-model"])
        document = json.loads(self.probe_path.read_text(encoding="utf-8"))
        document["capabilities"]["model_flag_observed"] = False
        self.probe_path.write_text(json.dumps(document), encoding="utf-8")
        self.probe_path.chmod(0o600)
        with self.assertRaisesRegex(PREFIX.PrefixError, "no model option"):
            self.build(model="gpt-test-model")

    def test_digest_and_claim_promotion_mismatches_are_rejected(self) -> None:
        with self.assertRaisesRegex(PREFIX.PrefixError, "does not match"):
            PREFIX.build_plan(
                self.probe_path,
                expected_executable_sha256="0" * 64,
                access_policy="auto-owner-open",
                config_generation="generation-1",
            )

        document = json.loads(self.probe_path.read_text(encoding="utf-8"))
        document["claims"]["exec_turn_started"] = True
        self.probe_path.write_text(json.dumps(document), encoding="utf-8")
        self.probe_path.chmod(0o600)
        with self.assertRaisesRegex(PREFIX.PrefixError, "promoted or missing"):
            self.build()

    def test_missing_json_exec_or_access_capability_is_not_guessed(self) -> None:
        for field, expected in (
            ("exec_subcommand_observed", "exec subcommand"),
            ("json_event_flag_observed", "JSON event option"),
        ):
            document = json.loads(self.probe_path.read_text(encoding="utf-8"))
            document["capabilities"][field] = False
            self.probe_path.write_text(json.dumps(document), encoding="utf-8")
            self.probe_path.chmod(0o600)
            with self.assertRaisesRegex(PREFIX.PrefixError, expected):
                self.build()
            report = PROBE.probe(self.fake)
            PROBE.atomic_write(self.probe_path, report)

        document = json.loads(self.probe_path.read_text(encoding="utf-8"))
        document["capabilities"]["bypass_approvals_and_sandbox_flag_observed"] = False
        document["capabilities"]["danger_full_access_value_observed"] = False
        self.probe_path.write_text(json.dumps(document), encoding="utf-8")
        self.probe_path.chmod(0o600)
        with self.assertRaisesRegex(PREFIX.PrefixError, "no observed owner-open"):
            self.build()

    def test_exec_help_bytes_are_rebound_before_option_selection(self) -> None:
        document = json.loads(self.probe_path.read_text(encoding="utf-8"))
        document["probes"]["exec_help"]["stdout"] += "\n--invented-option"
        self.probe_path.write_text(json.dumps(document), encoding="utf-8")
        self.probe_path.chmod(0o600)
        with self.assertRaisesRegex(PREFIX.PrefixError, "stdout digest"):
            self.build()

    def test_plan_hash_is_deterministic_and_binds_policy_generation_and_model(self) -> None:
        first = self.build(model="gpt-test-model")
        second = self.build(model="gpt-test-model")
        self.assertEqual(first, second)
        changed_policy = self.build("danger-full-access", model="gpt-test-model")
        self.assertNotEqual(first["plan_sha256"], changed_policy["plan_sha256"])
        changed_generation = PREFIX.build_plan(
            self.probe_path,
            expected_executable_sha256=self.executable_sha256,
            access_policy="auto-owner-open",
            config_generation="owner-open-config-8",
            model="gpt-test-model",
        )
        self.assertNotEqual(first["plan_sha256"], changed_generation["plan_sha256"])

    def test_atomic_plan_is_private_and_generator_never_executes_codex(self) -> None:
        output = self.root / "plans" / "exec-prefix.json"
        plan = self.build()
        PREFIX.atomic_write(output, plan)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), plan)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "")
        source = PREFIX_PATH.read_text(encoding="utf-8")
        for forbidden in ("subprocess", "os.system", "Popen", "exec_turn_started\": true"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
