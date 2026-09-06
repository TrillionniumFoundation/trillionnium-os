#!/usr/bin/env python3
"""Tests for the read-only owner-open Codex CLI capability probe."""

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
SPEC = importlib.util.spec_from_file_location("probe_owner_open_codex_cli", PROBE_PATH)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class CodexCliProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / "argv.log"
        self.fake = self.root / "codex"
        self.write_fake(
            r'''#!/bin/sh
set -eu
: "${FAKE_CODEX_LOG:?}"
printf '%s\n' "$*" >>"$FAKE_CODEX_LOG"
case "$*" in
  --version)
    printf '%s\n' 'codex-cli 9.9.9-test'
    ;;
  --help)
    cat <<'EOF'
Codex CLI test fixture
Commands:
  exec    execute one turn
EOF
    ;;
  'exec --help')
    cat <<'EOF'
Usage: codex exec [OPTIONS]
  --json
  -s, --sandbox <MODE>
      danger-full-access
  --dangerously-bypass-approvals-and-sandbox
  -m, --model <MODEL>
  -c, --config <KEY=VALUE>
EOF
    ;;
  *)
    printf 'unexpected execution: %s\n' "$*" >&2
    exit 73
    ;;
esac
'''
        )
        self.previous_log = os.environ.get("FAKE_CODEX_LOG")
        os.environ["FAKE_CODEX_LOG"] = str(self.log)

    def tearDown(self) -> None:
        if self.previous_log is None:
            os.environ.pop("FAKE_CODEX_LOG", None)
        else:
            os.environ["FAKE_CODEX_LOG"] = self.previous_log
        self.temp.cleanup()

    def write_fake(self, content: str) -> None:
        self.fake.write_text(textwrap.dedent(content), encoding="utf-8")
        self.fake.chmod(0o700)

    def test_observes_help_capabilities_without_starting_a_turn(self) -> None:
        report = PROBE.probe(self.fake)
        capabilities = report["capabilities"]
        self.assertTrue(capabilities["exec_subcommand_observed"])
        self.assertTrue(capabilities["json_event_flag_observed"])
        self.assertTrue(capabilities["sandbox_long_flag_observed"])
        self.assertTrue(capabilities["sandbox_short_flag_observed"])
        self.assertTrue(capabilities["danger_full_access_value_observed"])
        self.assertTrue(
            capabilities["bypass_approvals_and_sandbox_flag_observed"]
        )
        self.assertTrue(capabilities["model_flag_observed"])
        self.assertTrue(capabilities["config_override_flag_observed"])
        self.assertEqual(report["claim_ceiling"], "INSTALLED_CLI_HELP_OBSERVATION_ONLY")

        claims = report["claims"]
        self.assertTrue(claims["help_only"])
        for field in (
            "credentials_opened_by_probe",
            "provider_contacted",
            "model_invoked",
            "exec_turn_started",
            "mcp_server_started",
            "owner_open_flags_verified_by_execution",
            "integrated_host",
            "same_turn_tool_effect",
            "release_evidence",
        ):
            self.assertFalse(claims[field], field)

        self.assertEqual(
            self.log.read_text(encoding="utf-8").splitlines(),
            ["--version", "--help", "exec --help"],
        )

    def test_report_binds_executable_and_each_raw_probe_output(self) -> None:
        report = PROBE.probe(self.fake)
        executable = self.fake.read_bytes()
        self.assertEqual(report["executable"]["bytes"], len(executable))
        self.assertEqual(
            report["executable"]["sha256"], PROBE.sha256_bytes(executable)
        )
        self.assertEqual(report["version_text"], "codex-cli 9.9.9-test")
        for name in ("version", "root_help", "exec_help"):
            value = report["probes"][name]
            self.assertEqual(value["exit_code"], 0)
            self.assertEqual(
                value["stdout_sha256"],
                PROBE.sha256_bytes(value["stdout"].encode("utf-8")),
            )
            self.assertEqual(
                value["stderr_sha256"],
                PROBE.sha256_bytes(value["stderr"].encode("utf-8")),
            )

    def test_atomic_report_is_private_and_retains_non_claims(self) -> None:
        output = self.root / "evidence" / "probe.json"
        report = PROBE.probe(self.fake)
        PROBE.atomic_write(output, report)
        decoded = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(decoded["schema"], PROBE.REPORT_SCHEMA)
        self.assertFalse(decoded["claims"]["exec_turn_started"])
        self.assertFalse(decoded["claims"]["integrated_host"])
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertFalse(any(output.parent.glob(f".{output.name}.tmp-*")))

    def test_rejects_symlink_writable_non_executable_and_changed_identity(self) -> None:
        target = self.root / "real-codex"
        target.write_bytes(self.fake.read_bytes())
        target.chmod(0o700)
        self.fake.unlink()
        self.fake.symlink_to(target)
        with self.assertRaisesRegex(PROBE.ProbeError, "real regular file"):
            PROBE.probe(self.fake)

        self.fake.unlink()
        self.write_fake("#!/bin/sh\nexit 0\n")
        self.fake.chmod(0o600)
        with self.assertRaisesRegex(PROBE.ProbeError, "no executable bit"):
            PROBE.probe(self.fake)

        self.fake.chmod(0o720)
        with self.assertRaisesRegex(PROBE.ProbeError, "group/world writable"):
            PROBE.probe(self.fake)

    def test_nonzero_help_and_timeout_fail_closed_without_exec_turn(self) -> None:
        self.write_fake(
            r'''#!/bin/sh
set -eu
: "${FAKE_CODEX_LOG:?}"
printf '%s\n' "$*" >>"$FAKE_CODEX_LOG"
case "$*" in
  --version) printf '%s\n' 'codex broken fixture' ;;
  --help) exit 7 ;;
  *) printf 'must not reach: %s\n' "$*" >&2; exit 88 ;;
esac
'''
        )
        with self.assertRaisesRegex(PROBE.ProbeError, "help probe failed"):
            PROBE.probe(self.fake)
        self.assertEqual(
            self.log.read_text(encoding="utf-8").splitlines(),
            ["--version", "--help"],
        )

        self.log.write_text("", encoding="utf-8")
        self.write_fake(
            r'''#!/bin/sh
set -eu
: "${FAKE_CODEX_LOG:?}"
printf '%s\n' "$*" >>"$FAKE_CODEX_LOG"
sleep 2
'''
        )
        previous = PROBE.PROBE_TIMEOUT_SECONDS
        PROBE.PROBE_TIMEOUT_SECONDS = 0.05
        try:
            with self.assertRaisesRegex(PROBE.ProbeError, "timed out"):
                PROBE.probe(self.fake)
        finally:
            PROBE.PROBE_TIMEOUT_SECONDS = previous
        self.assertEqual(self.log.read_text(encoding="utf-8").splitlines(), ["--version"])

    def test_oversized_help_output_is_rejected(self) -> None:
        self.write_fake(
            r'''#!/bin/sh
set -eu
: "${FAKE_CODEX_LOG:?}"
printf '%s\n' "$*" >>"$FAKE_CODEX_LOG"
case "$*" in
  --version) printf '%s\n' 'codex large fixture' ;;
  *) python3 - <<'PY'
print('x' * 4096)
PY
  ;;
esac
'''
        )
        previous = PROBE.MAX_OUTPUT_BYTES
        PROBE.MAX_OUTPUT_BYTES = 1024
        try:
            with self.assertRaisesRegex(PROBE.ProbeError, "exceeded the byte bound"):
                PROBE.probe(self.fake)
        finally:
            PROBE.MAX_OUTPUT_BYTES = previous
        self.assertEqual(
            self.log.read_text(encoding="utf-8").splitlines(),
            ["--version", "--help"],
        )


if __name__ == "__main__":
    unittest.main()
