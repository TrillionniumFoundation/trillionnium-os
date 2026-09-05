#!/usr/bin/env python3
"""Black-box and library tests for validated Codex exec-plan execution."""

from __future__ import annotations

import contextlib
import io
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
from unittest import mock


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
        with self.assertRaisesRegex(EXECUTOR.ExecutionPlanError, "private.*regular file"):
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

    def test_numeric_claim_values_cannot_impersonate_booleans(self) -> None:
        original = json.loads(self.plan.read_text())
        for field, value in original["claims"].items():
            with self.subTest(field=field):
                changed = json.loads(json.dumps(original))
                changed["claims"][field] = int(value)
                preimage = dict(changed)
                preimage.pop("plan_sha256")
                changed["plan_sha256"] = EXECUTOR.sha256_bytes(json.dumps(
                    preimage, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ).encode())
                self.plan.write_text(json.dumps(changed))
                with self.assertRaises(EXECUTOR.ExecutionPlanError):
                    EXECUTOR.validate_plan(self.plan)
        self.assertEqual(self.log.read_text(), "")

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



class PrivateReceiptBoundaryTest(unittest.TestCase):
    """Local file and mocked CLI boundaries, not installed-provider evidence."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prompt = self.root / "prompt"
        self.prompt.write_bytes(b"test-only prompt")
        self.prompt.chmod(0o600)
        self.plan = self.root / "plan.json"
        self.plan.write_bytes(b'{"test_only":true}')
        self.plan.chmod(0o600)
        self.output = self.root / "receipt.json"

    def remaining_temporaries(self, parent=None):
        return list((parent or self.root).glob(".provider-receipt-*.tmp"))

    def cli(self, events=None, terminal=None):
        return ["--execute", "--plan", str(self.plan), "--prompt-file", str(self.prompt),
                "--prompt-mode", "argv-final", "--provider-kind", "fixture",
                "--environment-mode", "empty", "--events-output", str(events or self.output),
                "--terminal-output", str(terminal or self.root / "terminal.json")]

    def test_temporary_private_before_first_byte_under_permissive_umask(self):
        original, sync, modes = os.write, os.fsync, []
        def write(fd, data):
            modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
            self.assertFalse(os.get_inheritable(fd))
            return original(fd, data)
        def check_sync(fd):
            current = os.fstat(fd)
            if stat.S_ISREG(current.st_mode):
                modes.append(stat.S_IMODE(current.st_mode))
                self.assertEqual(stat.S_IMODE(current.st_mode), 0o600)
            return sync(fd)
        mask = os.umask(0)
        try:
            with mock.patch.object(EXECUTOR.os, "write", side_effect=write), \
                    mock.patch.object(EXECUTOR.os, "fsync", side_effect=check_sync):
                EXECUTOR.atomic_write_json(self.output, {"test_only": "secret"})
        finally:
            os.umask(mask)
        self.assertTrue(modes)
        self.assertEqual(set(modes), {0o600})
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_legacy_temporary_of_another_attempt_is_not_deleted(self):
        other = self.root / f".{self.output.name}.tmp-{os.getpid()}"
        other.write_bytes(b"another attempt")
        EXECUTOR.atomic_write_json(self.output, {})
        self.assertEqual(other.read_bytes(), b"another attempt")

    def test_exclusive_random_name_collision_preserves_existing_file(self):
        other = self.root / (".provider-receipt-" + "a" * 32 + ".tmp")
        other.write_bytes(b"another attempt")
        with mock.patch.object(EXECUTOR.secrets, "token_hex", return_value="a" * 32):
            with self.assertRaises(FileExistsError):
                EXECUTOR.atomic_write_json(self.output, {})
        self.assertEqual(other.read_bytes(), b"another attempt")
        self.assertFalse(self.output.exists())

    def test_symlink_parent_rejected_without_external_directory_creation(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (self.root / "alias").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            EXECUTOR.atomic_write_json(self.root / "alias" / "new" / "receipt", {})
        self.assertEqual(list(outside.iterdir()), [])

    def test_public_output_parent_rejected_without_chmod(self):
        parent = self.root / "public"
        parent.mkdir(mode=0o755)
        with self.assertRaises(EXECUTOR.ExecutionPlanError):
            EXECUTOR.atomic_write_json(parent / "receipt", {})
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
        self.assertEqual(list(parent.iterdir()), [])

    def test_new_nested_output_directories_are_private(self):
        destination = self.root / "new" / "nested" / "receipt"
        EXECUTOR.atomic_write_json(destination, {})
        for parent in (destination.parent, destination.parent.parent):
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)

    def test_unsafe_existing_output_leaf_is_not_replaced(self):
        for kind in ("symlink", "hardlink", "fifo", "directory", "public"):
            with self.subTest(kind=kind):
                outside = self.root / ("outside-" + kind)
                outside.write_bytes(b"preserve")
                outside.chmod(0o600)
                if kind == "symlink": self.output.symlink_to(outside)
                elif kind == "hardlink": os.link(outside, self.output)
                elif kind == "fifo": os.mkfifo(self.output, 0o600)
                elif kind == "directory": self.output.mkdir(mode=0o700)
                else:
                    self.output.write_bytes(b"preserve")
                    self.output.chmod(0o644)
                try:
                    with self.assertRaises(EXECUTOR.ExecutionPlanError):
                        EXECUTOR.atomic_write_json(self.output, {})
                    self.assertEqual(outside.read_bytes(), b"preserve")
                finally:
                    self.output.rmdir() if kind == "directory" else self.output.unlink()
        self.assertEqual(self.remaining_temporaries(), [])

    def test_positive_short_writes_complete_exact_jsonl(self):
        original = os.write
        with mock.patch.object(EXECUTOR.os, "write", side_effect=lambda fd, data: original(fd, data[:3])):
            EXECUTOR.atomic_write_json(self.output, [{"x": "汉字"}, {"y": 2}], jsonl=True)
        self.assertEqual(self.output.read_bytes(), '{"x":"汉字"}\n{"y":2}\n'.encode())

    def test_zero_or_invalid_write_preserves_previous_output(self):
        self.output.write_bytes(b"previous")
        self.output.chmod(0o600)
        for value in (0, -1, 99999):
            with self.subTest(value=value), mock.patch.object(EXECUTOR.os, "write", return_value=value):
                with self.assertRaises(EXECUTOR.ExecutionPlanError):
                    EXECUTOR.atomic_write_json(self.output, {"new": 1})
            self.assertEqual(self.output.read_bytes(), b"previous")
            self.assertEqual(self.remaining_temporaries(), [])

    def test_write_failure_cleans_only_own_temporary(self):
        with mock.patch.object(EXECUTOR.os, "write", side_effect=OSError("injected ENOSPC")):
            with self.assertRaises(OSError): EXECUTOR.atomic_write_json(self.output, {})
        self.assertEqual(self.remaining_temporaries(), [])
        self.assertFalse(self.output.exists())

    def test_prepublication_fsync_failure_preserves_previous_output(self):
        self.output.write_bytes(b"previous")
        self.output.chmod(0o600)
        with EXECUTOR._ReceiptTarget(self.output) as target:
            with mock.patch.object(EXECUTOR.os, "fsync", side_effect=OSError("injected fsync")):
                with self.assertRaises(OSError): target.publish({})
        self.assertEqual(self.output.read_bytes(), b"previous")
        self.assertEqual(self.remaining_temporaries(), [])

    def test_postreplace_directory_fsync_failure_is_not_rollback(self):
        with EXECUTOR._ReceiptTarget(self.output) as target:
            original = os.fsync
            def sync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError("directory sync unknown")
                original(fd)
            with mock.patch.object(EXECUTOR.os, "fsync", side_effect=sync):
                with self.assertRaises(OSError): target.publish({"visible": True})
            self.assertTrue(target.published)
        self.assertEqual(json.loads(self.output.read_bytes()), {"visible": True})
        self.assertEqual(self.remaining_temporaries(), [])

    def test_replace_failure_keeps_old_output(self):
        self.output.write_bytes(b"previous")
        self.output.chmod(0o600)
        with mock.patch.object(EXECUTOR.os, "replace", side_effect=OSError("injected rename")):
            with self.assertRaises(OSError): EXECUTOR.atomic_write_json(self.output, {})
        self.assertEqual(self.output.read_bytes(), b"previous")
        self.assertEqual(self.remaining_temporaries(), [])

    def test_nonfinite_output_never_publishes_partial_json(self):
        for number in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(number=number), self.assertRaises(ValueError):
                EXECUTOR.atomic_write_json(self.output, {"number": number})
            self.assertFalse(self.output.exists())
            self.assertEqual(self.remaining_temporaries(), [])

    def test_serialized_output_has_finite_budget(self):
        with mock.patch.object(EXECUTOR, "MAX_RECEIPT_BYTES", 16):
            with self.assertRaises(EXECUTOR.ExecutionPlanError):
                EXECUTOR.atomic_write_json(self.output, {"x": "a" * 32})
        self.assertFalse(self.output.exists())
        self.assertEqual(self.remaining_temporaries(), [])

    def test_generator_failure_does_not_publish_earlier_records(self):
        def records():
            yield {"first": 1}
            raise RuntimeError("injected generator failure")
        with self.assertRaises(RuntimeError):
            EXECUTOR.atomic_write_json(self.output, records(), jsonl=True)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.remaining_temporaries(), [])

    def test_parent_replacement_rejected_and_pinned_temporary_cleaned(self):
        parent, moved = self.root / "parent", self.root / "moved"
        parent.mkdir(mode=0o700)
        with EXECUTOR._ReceiptTarget(parent / "receipt") as target:
            parent.rename(moved)
            parent.mkdir(mode=0o700)
            with self.assertRaises(EXECUTOR.ExecutionPlanError): target.publish({})
        self.assertEqual(list(parent.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_target_changed_after_preflight_is_preserved(self):
        with EXECUTOR._ReceiptTarget(self.output) as target:
            self.output.write_bytes(b"new other writer")
            self.output.chmod(0o600)
            with self.assertRaises(EXECUTOR.ExecutionPlanError): target.publish({})
        self.assertEqual(self.output.read_bytes(), b"new other writer")

    def test_replaced_temporary_is_not_published_or_unlinked(self):
        with EXECUTOR._ReceiptTarget(self.output) as target:
            temp = self.root / target.temporary
            temp.rename(self.root / "saved-own-temp")
            temp.write_bytes(b"replacement")
            with self.assertRaises(EXECUTOR.ExecutionPlanError): target.publish({})
        self.assertEqual(temp.read_bytes(), b"replacement")
        self.assertFalse(self.output.exists())

    def test_fd_counts_stable_on_success_and_validation_failures(self):
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(10):
            EXECUTOR.atomic_write_json(self.output, {})
            EXECUTOR.load_prompt(self.prompt)
            with self.assertRaises(EXECUTOR.ExecutionPlanError):
                EXECUTOR.load_private_json(self.prompt, label="invalid", maximum=4096)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_empty_prompt_accepted_but_empty_plan_rejected(self):
        self.prompt.write_bytes(b"")
        self.assertEqual(EXECUTOR.load_prompt(self.prompt), b"")
        with self.assertRaises(EXECUTOR.ExecutionPlanError):
            EXECUTOR.load_private_json(self.prompt, label="plan", maximum=4096)

    def test_nonfinite_duplicate_and_deep_input_json_rejected(self):
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e9999}', b'{"x":1,"x":2}',
                    b'{"x":' + b'[' * 64 + b'0' + b']' * 64 + b'}'):
            with self.subTest(raw=raw[:30]):
                self.plan.write_bytes(raw)
                with self.assertRaises(EXECUTOR.ExecutionPlanError):
                    EXECUTOR.load_private_json(self.plan, label="plan", maximum=4096)

    def test_unsafe_input_leaves_fail_without_blocking_fifo(self):
        for kind in ("symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                leaf = self.root / kind
                if kind == "symlink": leaf.symlink_to(self.prompt)
                elif kind == "hardlink": os.link(self.prompt, leaf)
                elif kind == "fifo": os.mkfifo(leaf, 0o600)
                else: leaf.mkdir()
                with self.assertRaises(EXECUTOR.ExecutionPlanError): EXECUTOR.load_prompt(leaf)
                leaf.rmdir() if kind == "directory" else leaf.unlink()

    def test_input_symlink_ancestor_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(EXECUTOR.ExecutionPlanError):
            EXECUTOR.load_prompt(alias / self.prompt.name)

    def test_input_uses_descriptor_instead_of_unbounded_path_read(self):
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("path reopen")):
            self.assertEqual(EXECUTOR.load_prompt(self.prompt), b"test-only prompt")

    def test_input_replaced_during_descriptor_read_is_rejected(self):
        original, swapped = os.read, [False]
        def read(fd, size):
            if not swapped[0]:
                swapped[0] = True
                self.prompt.rename(self.root / "old-prompt")
                self.prompt.write_bytes(b"same-sized-other")
                self.prompt.chmod(0o600)
            return original(fd, size)
        with mock.patch.object(EXECUTOR.os, "read", side_effect=read):
            with self.assertRaises(EXECUTOR.ExecutionPlanError): EXECUTOR.load_prompt(self.prompt)
        self.assertTrue(swapped[0])

    def test_input_growth_reads_at_most_limit_plus_one(self):
        self.prompt.write_bytes(b"1234")
        original, changed, requested = os.read, [False], []
        def read(fd, size):
            requested.append(size)
            if not changed[0]:
                changed[0] = True
                with self.prompt.open("ab") as f: f.write(b"x" * 100)
            return original(fd, size)
        with mock.patch.object(EXECUTOR, "MAX_PROMPT_BYTES", 4), mock.patch.object(EXECUTOR.os, "read", side_effect=read):
            with self.assertRaises(EXECUTOR.ExecutionPlanError): EXECUTOR.load_prompt(self.prompt)
        self.assertEqual(requested, [5])

    def test_path_budgets_and_parent_traversal_are_rejected(self):
        for path in (self.root / ".." / "escape", Path("/" + "x" * 4096), Path("/a" * 65)):
            with self.subTest(path=str(path)[:40]), self.assertRaises(EXECUTOR.ExecutionPlanError):
                EXECUTOR.atomic_write_json(path, {})

    def test_cli_aliases_fail_before_execution(self):
        cases = [(self.output, self.output), (self.prompt, self.output),
                 (self.plan, self.output), (self.output, self.output / "nested")]
        for events, terminal in cases:
            with self.subTest(events=events, terminal=terminal), mock.patch.object(EXECUTOR, "execute_plan") as execute:
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(EXECUTOR.main(self.cli(events, terminal)), 1)
                execute.assert_not_called()
        self.assertEqual(self.prompt.read_bytes(), b"test-only prompt")

    def test_cli_invalid_second_output_never_calls_provider(self):
        parent = self.root / "public"
        parent.mkdir(mode=0o755)
        with mock.patch.object(EXECUTOR, "execute_plan") as execute, contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(EXECUTOR.main(self.cli(terminal=parent / "terminal")), 1)
        execute.assert_not_called()
        self.assertIn("pre_execution", output.getvalue())
        self.assertEqual(self.remaining_temporaries(), [])

    def test_cli_second_publication_failure_reports_partial_after_execution(self):
        real_publish = EXECUTOR._ReceiptTarget.publish
        def publish(target, value, **kwargs):
            if target.path.name == "terminal.json": raise OSError("injected second receipt error")
            return real_publish(target, value, **kwargs)
        with mock.patch.object(EXECUTOR, "execute_plan", return_value=([{"observed": True}], {"success": True})) as execute, \
                mock.patch.object(EXECUTOR._ReceiptTarget, "publish", publish), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(EXECUTOR.main(self.cli()), 1)
        execute.assert_called_once()
        self.assertTrue(self.output.exists())
        self.assertFalse((self.root / "terminal.json").exists())
        self.assertIn("receipt_publication_after_execution", output.getvalue())
        self.assertIn("automatic_retry=false", output.getvalue())
        self.assertEqual(self.remaining_temporaries(), [])

    def test_cli_unsuccessful_terminal_never_prints_pass(self):
        terminal = {"success": False, "kind": "spawn_failed", "event_count": 0}
        with mock.patch.object(EXECUTOR, "execute_plan", return_value=([], terminal)), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(EXECUTOR.main(self.cli()), 1)
        self.assertTrue(output.getvalue().startswith("FAIL_"))
        self.assertNotIn("PASS_", output.getvalue())

    def test_no_spawn_terminal_does_not_claim_execution(self):
        plan = dict(plan_sha256="test", probe_report_sha256="test", executable_sha256="test",
                    config_generation="test", selected_access_policy="test")
        for kind in ("spawn_failed", "client_cancelled"):
            terminal = EXECUTOR.RUNTIME.ProviderTerminal(kind, None, None, 0, 0, b"", 0, 0, None)
            result = EXECUTOR.terminal_record(terminal, plan, prompt=b"", prompt_mode="stdin-close",
                                               provider_kind="fixture", environment_mode="empty")
            self.assertFalse(result["claims"]["validated_plan_executed"])
            self.assertFalse(result["success"])


    def test_cli_existing_receipt_is_preserved_before_execution(self):
        for path in (self.output, self.root / "terminal.json"):
            path.write_bytes(b"previous evidence")
            path.chmod(0o600)
            with mock.patch.object(EXECUTOR, "execute_plan") as execute, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(EXECUTOR.main(self.cli()), 1)
            execute.assert_not_called()
            self.assertEqual(path.read_bytes(), b"previous evidence")
            path.unlink()
        self.assertEqual(self.remaining_temporaries(), [])

    def test_publication_cannot_retry_after_partial_serialization(self):
        with EXECUTOR._ReceiptTarget(self.output) as target:
            with self.assertRaises(ValueError): target.publish({"x": float("nan")})
            with self.assertRaises(EXECUTOR.ExecutionPlanError): target.publish({"valid": True})
        self.assertFalse(self.output.exists())
        self.assertEqual(self.remaining_temporaries(), [])

    def test_preflight_sync_failure_prevents_provider_execution(self):
        with mock.patch.object(EXECUTOR.os, "fsync", side_effect=OSError("preflight sync")), \
                mock.patch.object(EXECUTOR, "execute_plan") as execute, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(EXECUTOR.main(self.cli()), 1)
        execute.assert_not_called()
        self.assertEqual(self.remaining_temporaries(), [])

    def test_same_size_input_mutation_during_read_is_rejected(self):
        original, changed = os.read, [False]
        def read(fd, size):
            if not changed[0]:
                changed[0] = True
                self.prompt.write_bytes(b"X" * len(b"test-only prompt"))
                current = self.prompt.stat()
                os.utime(self.prompt, ns=(current.st_atime_ns, current.st_mtime_ns + 1000000000))
            return original(fd, size)
        with mock.patch.object(EXECUTOR.os, "read", side_effect=read):
            with self.assertRaises(EXECUTOR.ExecutionPlanError): EXECUTOR.load_prompt(self.prompt)
        self.assertTrue(changed[0])


if __name__ == "__main__":
    unittest.main()
