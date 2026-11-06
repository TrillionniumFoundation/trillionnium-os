from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "r5_target_capture_process", ROOT / "tools/capture-owner-open-r5-target-evidence.py"
)
assert SPEC is not None and SPEC.loader is not None
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "WNOWAIT"), "Linux process ownership")
class TargetHarnessProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def run_harness(self, body: str, *, timeout: float = 5):
        harness = self.directory / "harness"
        harness.write_text("#!" + sys.executable + "\n" + body + "\n")
        harness.chmod(0o700)
        return CAPTURE.run_harness(
            harness, raw_dir=self.directory,
            index=self.directory / "index.json",
            observations=self.directory / "observations.json",
            kind="installed-target", source_commit="a" * 40,
            source_tree="b" * 40, timeout=timeout,
        )

    def test_normal_output_is_retained(self) -> None:
        result = self.run_harness("import os; os.write(1,b'out'); os.write(2,b'err')")
        self.assertEqual(result["returncode"], 0)
        self.assertEqual((self.directory / "harness-stdout.bin").read_bytes(), b"out")
        self.assertEqual((self.directory / "harness-stderr.bin").read_bytes(), b"err")

    def test_nonzero_output_is_retained_before_refusal(self) -> None:
        with self.assertRaisesRegex(CAPTURE.EvidenceError, "failed with 7"):
            self.run_harness("import os; os.write(2,b'failed'); raise SystemExit(7)")
        self.assertEqual((self.directory / "harness-stderr.bin").read_bytes(), b"failed")

    def test_output_is_refused_during_capture(self) -> None:
        with self.assertRaisesRegex(CAPTURE.EvidenceError, "exceeded 64 MiB"):
            self.run_harness("import os\nfor _ in range(70): os.write(1,b'x'*1048576)")
        self.assertFalse((self.directory / "harness-stdout.bin").exists())

    def test_closed_pipes_do_not_disable_timeout(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(CAPTURE.EvidenceError, "timed out"):
            self.run_harness("import os,time; os.close(1); os.close(2); time.sleep(20)", timeout=.1)
        self.assertLess(time.monotonic() - started, 3)

    def test_live_descendant_prevents_a_success_receipt(self) -> None:
        pid_file = self.directory / "child.pid"
        child = "import os,time; os.close(1); os.close(2); time.sleep(20)"
        body = (
            "import subprocess,sys,pathlib\n"
            f"p=subprocess.Popen([sys.executable,'-c',{child!r}])\n"
            f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid))\n"
        )
        try:
            with self.assertRaisesRegex(CAPTURE.EvidenceError, "capture failed"):
                self.run_harness(body)
            pid = int(pid_file.read_text())
            try:
                state = (Path('/proc') / str(pid) / 'stat').read_bytes().rsplit(b') ',1)[1].split()[0]
            except FileNotFoundError:
                state = b'X'
            self.assertIn(state, {b'Z', b'X'})
            self.assertFalse((self.directory / "harness-stdout.bin").exists())
        finally:
            # A failing regression must retire only the known fixture. pidfd
            # identity prevents signalling an unrelated process after reuse.
            if pid_file.exists() and hasattr(os, "pidfd_open"):
                import signal
                try:
                    fd = os.pidfd_open(int(pid_file.read_text()))
                except ProcessLookupError:
                    pass
                else:
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    finally:
                        os.close(fd)

    def test_nonfinite_timeout_fails_before_execution(self) -> None:
        marker = self.directory / "effect"
        with self.assertRaises(CAPTURE.EvidenceError):
            self.run_harness(f"from pathlib import Path; Path({str(marker)!r}).touch()", timeout=float('nan'))
        self.assertFalse(marker.exists())


class TargetCaptureMainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="r5-capture-main.")
        self.addCleanup(self.temporary.cleanup)
        self.bundle = Path(self.temporary.name) / "bundle"

    def arguments(self) -> list[str]:
        return [
            "--kind", "repository_governance_controls",
            "--gap-id", "R5-GAP-GOVERNANCE-001",
            "--bundle-dir", str(self.bundle),
            "--branch", "fixture",
            "--source-commit", "a" * 40,
            "--source-tree", "b" * 40,
            "--claim-ceiling", "L1",
            "--producer-login", "fixture",
            "--workflow", "fixture",
            "--workflow-run-id", "1",
            "--workflow-run-attempt", "1",
            "--job", "fixture",
            "--negative-claim", "source fixtures provide no target qualification",
        ]

    def test_nonfinite_cli_timeouts_report_error_before_target_or_output_creation(self) -> None:
        for value in ("nan", "inf", "-inf"):
            with self.subTest(timeout=value), mock.patch.object(
                CAPTURE, "require_fixed_target_file"
            ) as target, mock.patch.object(
                CAPTURE, "run_harness"
            ) as harness, mock.patch.object(
                CAPTURE.subprocess, "run"
            ) as finalizer, redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(CAPTURE.main(self.arguments() + [f"--timeout={value}"]), 1)
            self.assertIn("ERROR: capture timeout is outside 1..43200 seconds", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertFalse(self.bundle.exists())
            target.assert_not_called()
            harness.assert_not_called()
            finalizer.assert_not_called()

    def test_successful_main_executes_adjacent_finalizer_and_validates_capture_chain(self) -> None:
        index = {"schema": CAPTURE.ARTIFACT_INDEX_SCHEMA, "artifacts": []}
        observations = {
            "schema": CAPTURE.OBSERVATIONS_SCHEMA,
            "kind": "repository_governance_controls",
        }
        completed = subprocess.CompletedProcess([], 0, "fixture-finalized\n", "")
        with mock.patch.object(
            CAPTURE, "require_fixed_target_file", return_value={"sha256": "c" * 64}
        ), mock.patch.object(
            CAPTURE, "validate_target_attestation", return_value={"harness": {}}
        ), mock.patch.object(
            CAPTURE, "assert_harness_identity"
        ), mock.patch.object(
            CAPTURE, "run_harness", return_value={"returncode": 0}
        ) as harness, mock.patch.object(
            CAPTURE, "read_json_object", side_effect=[index, observations]
        ), mock.patch.object(
            CAPTURE.subprocess, "run", return_value=completed
        ) as finalizer, mock.patch.object(
            CAPTURE, "validate_capture_chain"
        ) as validate, redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(CAPTURE.main(self.arguments()), 0)
        harness.assert_called_once()
        finalizer.assert_called_once()
        argv = finalizer.call_args.args[0]
        self.assertEqual(argv[:2], [sys.executable, str(CAPTURE.TOOLS / "finalize-owner-open-r5-evidence-bundle.py")])
        self.assertEqual(argv[argv.index("--bundle-dir") + 1], str(self.bundle))
        self.assertEqual(argv[argv.index("--source-commit") + 1], "a" * 40)
        self.assertEqual(finalizer.call_args.kwargs["timeout"], 120)
        validate.assert_called_once_with(self.bundle / "manifest.json")
        self.assertEqual(stdout.getvalue(), "fixture-finalized\n")

    def test_target_artifact_error_is_classified_before_finalizer(self) -> None:
        with mock.patch.object(
            CAPTURE, "require_fixed_target_file", return_value={"sha256": "c" * 64}
        ), mock.patch.object(
            CAPTURE, "validate_target_attestation", return_value={"harness": {}}
        ), mock.patch.object(
            CAPTURE, "assert_harness_identity"
        ), mock.patch.object(
            CAPTURE, "run_harness", side_effect=OSError("fixture artifact write failure")
        ), mock.patch.object(
            CAPTURE.subprocess, "run"
        ) as finalizer, redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(CAPTURE.main(self.arguments()), 1)
        self.assertIn("ERROR: fixture artifact write failure", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertFalse((self.bundle / "manifest.json").exists())
        finalizer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
