#!/usr/bin/env python3
"""Black-box and library tests for validated Codex exec-plan execution."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
OWNER_OPEN = ROOT / "tools/owner-open"
PROBE_PATH = OWNER_OPEN / "probe_codex_cli.py"
PREFIX_PATH = OWNER_OPEN / "build_codex_exec_prefix.py"
EXECUTOR_PATH = OWNER_OPEN / "execute_codex_exec_plan.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PROBE = load("owner_open_probe_for_executor_test", PROBE_PATH)
PREFIX = load("owner_open_prefix_for_executor_test", PREFIX_PATH)
EXECUTOR = load("owner_open_exec_plan_test", EXECUTOR_PATH)


class ExecuteCodexPlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.codex = self.root / "codex"
        self.log = self.root / "argv.log"
        self.probe = self.root / "probe.json"
        self.plan = self.root / "plan.json"
        self.prompt = self.root / "prompt.txt"
        self.write_codex(
            r'''
import json
import os
import sys

log = os.environ["FAKE_CODEX_EXEC_LOG"]
with open(log, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\n")

args = sys.argv[1:]
if args == ["--version"]:
    print("codex executor fixture 1.0")
elif args == ["--help"]:
    print("Commands:\n  exec execute one turn")
elif args == ["exec", "--help"]:
    print("Usage: codex exec [OPTIONS] [PROMPT]")
    print("  --json")
    print("  --sandbox <MODE>")
    print("  danger-full-access")
    print("  --dangerously-bypass-approvals-and-sandbox")
elif args and args[0] == "exec":
    prompt = args[-1]
    print(json.dumps({"type": "provider.start", "prompt": prompt}), flush=True)
    print(json.dumps({"type": "tool.call", "call_id": "call-1", "tool": "shell.exec", "command": "pwd"}), flush=True)
    result = json.loads(sys.stdin.buffer.readline())
    print(json.dumps({"type": "provider.final", "tool_result": result}), flush=True)
else:
    print("unexpected invocation", args, file=sys.stderr)
    raise SystemExit(90)
'''
        )
        self.previous = os.environ.get("FAKE_CODEX_EXEC_LOG")
        os.environ["FAKE_CODEX_EXEC_LOG"] = str(self.log)
        probe = PROBE.probe(self.codex)
        PROBE.atomic_write(self.probe, probe)
        plan = PREFIX.build_plan(
            self.probe,
            expected_executable_sha256=probe["executable"]["sha256"],
            access_policy="auto-owner-open",
            config_generation="config-generation-1",
        )
        PREFIX.atomic_write(self.plan, plan)
        self.prompt.write_text("exact owner prompt with spaces", encoding="utf-8")
        self.prompt.chmod(0o600)
        self.log.write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        if self.previous is None:
            os.environ.pop("FAKE_CODEX_EXEC_LOG", None)
        else:
            os.environ["FAKE_CODEX_EXEC_LOG"] = self.previous
        self.temp.cleanup()

    def write_codex(self, source: str) -> None:
        self.codex.write_text(
            "#!/usr/bin/python3\n" + textwrap.dedent(source), encoding="utf-8"
        )
        self.codex.chmod(0o700)

    def handler(self, event):
        if event.value.get("type") != "tool.call":
            return None
        return (
            json.dumps(
                {
                    "type": "tool.result",
                    "call_id": event.value["call_id"],
                    "terminal": "exited",
                    "exit_code": 0,
                    "stdout": "/workspace\n",
                },
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

    def test_validated_fixture_plan_runs_exact_prefix_prompt_and_duplex_events(self) -> None:
        records, terminal = EXECUTOR.execute_plan(
            self.plan,
            self.prompt,
            prompt_mode="argv-final",
            provider_kind="fixture",
            environment_mode="inherit",
            event_handler=self.handler,
            limits=EXECUTOR.RUNTIME.ProcessLimits(timeout_seconds=3),
        )
        self.assertTrue(terminal["success"], terminal)
        self.assertTrue(terminal["process_cleanup"]["confirmed"])
        self.assertTrue(terminal["process_cleanup"]["leader_reaped"])
        self.assertEqual(terminal["process_cleanup"]["scope"], "original_process_group_only")
        self.assertFalse(terminal["process_cleanup"]["escaped_descendants_absence_proven"])
        self.assertFalse(terminal["process_cleanup"]["pid_is_recovery_authority"])
        self.assertFalse(terminal["process_cleanup"]["automatic_redispatch"])
        self.assertEqual(terminal["claim_ceiling"], "VALIDATED_PROVIDER_PROCESS_EXECUTION_ONLY")
        self.assertTrue(terminal["claims"]["validated_plan_executed"])
        self.assertTrue(terminal["claims"]["fixture_provider"])
        self.assertFalse(terminal["claims"]["installed_codex_requested"])
        for field in (
            "provider_contact_proven",
            "model_invocation_proven",
            "codex_event_compatibility_proven",
            "host_integrated",
            "same_turn_tool_effect",
            "physical_device_effect",
            "release_evidence",
        ):
            self.assertFalse(terminal["claims"][field], field)
        self.assertEqual([item["seq"] for item in records], [0, 1, 2])
        self.assertEqual(records[0]["provider_event"]["prompt"], self.prompt.read_text())
        self.assertEqual(records[1]["provider_event"]["call_id"], "call-1")
        self.assertEqual(
            records[2]["provider_event"]["tool_result"]["stdout"], "/workspace\n"
        )
        self.assertIsNone(records[0]["normalized_host_event"])
        self.assertFalse(records[0]["same_turn_tool_effect_proven"])
        for record in records:
            raw = __import__("base64").b64decode(record["raw_line_base64"])
            self.assertEqual(record["raw_line_sha256"], EXECUTOR.sha256_bytes(raw))

        invocations = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(len(invocations), 1)
        expected_prefix = json.loads(self.plan.read_text())["argv_prefix"][1:]
        self.assertEqual(
            invocations[0], [*expected_prefix, "exact owner prompt with spaces"]
        )

    def test_missing_execute_flag_is_a_no_spawn_hold(self) -> None:
        events = self.root / "events.jsonl"
        terminal = self.root / "terminal.json"
        result = subprocess.run(
            [
                sys.executable,
                str(EXECUTOR_PATH),
                "--plan",
                str(self.plan),
                "--prompt-file",
                str(self.prompt),
                "--prompt-mode",
                "argv-final",
                "--provider-kind",
                "fixture",
                "--environment-mode",
                "inherit",
                "--events-output",
                str(events),
                "--terminal-output",
                str(terminal),
            ],
            cwd=ROOT,
            env=os.environ.copy(),
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 64)
        self.assertIn("--execute is required", result.stderr)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "")
        self.assertFalse(events.exists())
        self.assertFalse(terminal.exists())

    def test_cli_writes_private_event_and_terminal_evidence(self) -> None:
        # Use a no-tool fixture so the CLI requires no embedding Host handler.
        self.write_codex(
            r'''
import json
import os
import sys
with open(os.environ["FAKE_CODEX_EXEC_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if args == ["--version"]:
    print("codex executor fixture 2.0")
elif args == ["--help"]:
    print("Commands:\n  exec execute")
elif args == ["exec", "--help"]:
    print("Usage: codex exec [OPTIONS] [PROMPT]\n--json\n--sandbox <MODE>\ndanger-full-access")
elif args and args[0] == "exec":
    print(json.dumps({"type": "provider.final", "prompt": args[-1]}), flush=True)
else:
    raise SystemExit(91)
'''
        )
        probe = PROBE.probe(self.codex)
        PROBE.atomic_write(self.probe, probe)
        plan = PREFIX.build_plan(
            self.probe,
            expected_executable_sha256=probe["executable"]["sha256"],
            access_policy="danger-full-access",
            config_generation="config-generation-2",
        )
        PREFIX.atomic_write(self.plan, plan)
        self.log.write_text("", encoding="utf-8")
        events = self.root / "evidence" / "events.jsonl"
        terminal = self.root / "evidence" / "terminal.json"
        result = subprocess.run(
            [
                sys.executable,
                str(EXECUTOR_PATH),
                "--execute",
                "--plan",
                str(self.plan),
                "--prompt-file",
                str(self.prompt),
                "--prompt-mode",
                "argv-final",
                "--provider-kind",
                "fixture",
                "--environment-mode",
                "inherit",
                "--events-output",
                str(events),
                "--terminal-output",
                str(terminal),
                "--timeout-seconds",
                "3",
            ],
            cwd=ROOT,
            env=os.environ.copy(),
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(events.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(terminal.stat().st_mode), 0o600)
        records = [json.loads(line) for line in events.read_text().splitlines()]
        terminal_value = json.loads(terminal.read_text())
        self.assertEqual(records[0]["provider_event"]["type"], "provider.final")
        self.assertEqual(terminal_value["provider_kind"], "fixture")
        self.assertFalse(terminal_value["claims"]["model_invocation_proven"])

    def test_tampered_plan_hash_claims_and_private_mode_are_rejected_before_spawn(self) -> None:
        original = json.loads(self.plan.read_text())
        for mutate, expected in (
            (
                lambda value: value.__setitem__("config_generation", "tampered"),
                "canonical preimage",
            ),
            (
                lambda value: value["claims"].__setitem__("codex_executed", True),
                "canonical preimage",
            ),
        ):
            value = json.loads(json.dumps(original))
            mutate(value)
            self.plan.write_text(json.dumps(value), encoding="utf-8")
            self.plan.chmod(0o600)
            with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, expected):
                EXECUTOR.execute_plan(
                    self.plan,
                    self.prompt,
                    prompt_mode="argv-final",
                    provider_kind="fixture",
                    environment_mode="inherit",
                )
            self.assertEqual(self.log.read_text(encoding="utf-8"), "")

        PREFIX.atomic_write(self.plan, original)
        self.plan.chmod(0o640)
        with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, "private regular file"):
            EXECUTOR.validate_plan(self.plan)

    def test_recomputed_plan_with_promoted_claim_is_still_rejected(self) -> None:
        value = json.loads(self.plan.read_text())
        value["claims"]["codex_executed"] = True
        preimage = dict(value)
        preimage.pop("plan_sha256")
        value["plan_sha256"] = EXECUTOR.sha256_bytes(
            json.dumps(
                preimage,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        self.plan.write_text(json.dumps(value), encoding="utf-8")
        self.plan.chmod(0o600)
        with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, "promoted"):
            EXECUTOR.validate_plan(self.plan)

    def test_executable_drift_and_path_substitution_are_rejected(self) -> None:
        self.codex.write_text("#!/usr/bin/python3\nprint('changed')\n", encoding="utf-8")
        self.codex.chmod(0o700)
        with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, "no longer matches"):
            EXECUTOR.validate_plan(self.plan)

        # Restore a fresh plan, then substitute argv[0] and recompute only the plan hash.
        self.setUp_fresh_plan_after_drift()
        value = json.loads(self.plan.read_text())
        value["argv_prefix"][0] = "/different/codex"
        preimage = dict(value)
        preimage.pop("plan_sha256")
        value["plan_sha256"] = EXECUTOR.sha256_bytes(
            json.dumps(
                preimage,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        self.plan.write_text(json.dumps(value), encoding="utf-8")
        self.plan.chmod(0o600)
        with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, "path is not exact"):
            EXECUTOR.validate_plan(self.plan)

    def setUp_fresh_plan_after_drift(self) -> None:
        self.write_codex(
            r'''
import sys
args = sys.argv[1:]
if args == ["--version"]: print("fixture-restored")
elif args == ["--help"]: print("Commands:\n  exec")
elif args == ["exec", "--help"]: print("--json\n--sandbox <MODE>\ndanger-full-access")
else: raise SystemExit(99)
'''
        )
        probe = PROBE.probe(self.codex)
        PROBE.atomic_write(self.probe, probe)
        plan = PREFIX.build_plan(
            self.probe,
            expected_executable_sha256=probe["executable"]["sha256"],
            access_policy="danger-full-access",
            config_generation="config-restored",
        )
        PREFIX.atomic_write(self.plan, plan)
        self.log.write_text("", encoding="utf-8")

    def test_prompt_transport_is_explicit_and_nul_is_only_valid_on_stdin(self) -> None:
        self.prompt.write_bytes(b"prompt\x00bytes")
        self.prompt.chmod(0o600)
        plan = EXECUTOR.validate_plan(self.plan)
        with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, "contains NUL"):
            EXECUTOR.build_invocation(plan, self.prompt.read_bytes(), "argv-final")
        argv, stdin, policy = EXECUTOR.build_invocation(
            plan, self.prompt.read_bytes(), "stdin-close"
        )
        self.assertEqual(argv, plan["argv_prefix"])
        self.assertEqual(stdin, b"prompt\x00bytes")
        self.assertEqual(policy, "close-after-initial")
        with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, "unsupported prompt mode"):
            EXECUTOR.build_invocation(plan, b"prompt", "guessed-mode")

    def test_prompt_and_plan_must_be_private_single_link_files(self) -> None:
        self.prompt.chmod(0o644)
        with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, "private bounded"):
            EXECUTOR.load_prompt(self.prompt)
        self.prompt.chmod(0o600)
        link = self.root / "prompt-link"
        link.symlink_to(self.prompt)
        with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, "private bounded"):
            EXECUTOR.load_prompt(link)


if __name__ == "__main__":
    unittest.main()
