"""Local process fixtures for the actual CLI executable binding; no model or phone."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, os.environ.get("HEPTA_TEST_PROVIDER_SOURCE", str(BASE / "source")))
import daily_provider as provider


class CliBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-cli-pin-")
        self.root = Path(self.temporary.name)
        self.launcher = self.root / "codex-cli/bin/codex"
        self.binary = self.root / "codex-cli/CodexCLI.app/Contents/MacOS/codex"
        self.wrapper_marker = self.root / "wrapper-effects.txt"
        self.binary_marker = self.root / "binary-effects.txt"
        self.launcher.parent.mkdir(parents=True)
        self.binary.parent.mkdir(parents=True)
        self.launcher.write_text("#!" + sys.executable + "\nimport os,sys\nfrom pathlib import Path\n"
                                 + "Path(" + repr(str(self.wrapper_marker)) + ").write_text('ran')\n"
                                 + "os.execv(" + repr(str(self.binary)) + ",["
                                 + repr(str(self.binary)) + ",*sys.argv[1:]])\n")
        self.binary.write_text("#!" + sys.executable + "\nimport json,sys\nfrom pathlib import Path\n"
                               + "Path(" + repr(str(self.binary_marker)) + ").write_text('once')\n"
                               + "print(json.dumps({'argv':sys.argv[1:],'fixture':'approved-binary'}))\n")
        self.launcher.chmod(0o700)
        self.binary.chmod(0o700)
        self.launcher_sha = provider.sha(self.launcher)
        self.binary_sha = provider.sha(self.binary)
        self.run = self.root / "run"
        self.run.mkdir()
        self.args = SimpleNamespace(
            codex=str(self.launcher), cli_stat=provider.file_identity(self.launcher),
            cli_binary=str(self.binary), cli_binary_stat=provider.file_identity(self.binary),
            cli_binding={"schema": "fixture-only", "launcher_sha256": self.launcher_sha,
                         "executable_sha256": self.binary_sha},
            model_health=SimpleNamespace(begin=lambda: {"id": 1, "fixture": True}))
        self.adapter = provider.DailyAdapter.__new__(provider.DailyAdapter)
        self.adapter.args = self.args
        self.adapter.run_dir = self.run
        self.adapter.round = 1
        self.adapter.child_lock = threading.Lock()
        self.adapter.cancelled = threading.Event()
        self.adapter.shutdown = threading.Event()
        self.adapter.child = None
        self.adapter.health_attempt = None

    def tearDown(self):
        self.adapter.join_child()
        self.temporary.cleanup()

    def qualify_fixture(self):
        with mock.patch.object(provider, "CLI_SHA", self.launcher_sha), \
             mock.patch.object(provider, "CLI_EXECUTABLE_SHA", self.binary_sha):
            provider.qualify_cli(self.args)

    def assert_no_spawn(self):
        self.assertIsNone(self.adapter.child)
        self.assertFalse(self.wrapper_marker.exists())
        self.assertFalse(self.binary_marker.exists())
        self.assertFalse((self.run / "codex-01.spawn-intent.json").exists())

    def test_underlying_binary_change_is_rejected_before_spawn(self):
        # A stable wrapper does not imply a stable binary behind that wrapper.
        with self.binary.open("a") as stream:
            stream.write("\n# application update changed the executable\n")
        with self.assertRaises(provider.ProviderError):
            process = self.adapter.spawn_codex([str(self.launcher), "fixture-argument"])
            process.communicate(timeout=5)
        self.assertTrue(self.adapter.shutdown.is_set())
        self.assert_no_spawn()

    def test_launcher_change_is_rejected_before_spawn(self):
        with self.launcher.open("a") as stream:
            stream.write("\n# changed launcher\n")
        with self.assertRaises(provider.ProviderError):
            self.adapter.spawn_codex([str(self.launcher)])
        self.assertTrue(self.adapter.shutdown.is_set())
        self.assert_no_spawn()

    def test_missing_binary_stops_accepting_without_spawn(self):
        self.binary.unlink()
        with self.assertRaises(provider.ProviderError):
            self.adapter.spawn_codex([str(self.launcher)])
        self.assertTrue(self.adapter.shutdown.is_set())
        self.assert_no_spawn()

    def test_selected_binary_is_launched_directly_with_arguments_and_receipt(self):
        self.qualify_fixture()
        requested = [str(self.launcher), "--model", "fixture-model", "--", "value with spaces"]
        process = self.adapter.spawn_codex(requested)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(stderr, b"")
        self.assertEqual(json.loads(stdout)["argv"], requested[1:])
        self.assertEqual(self.binary_marker.read_text(), "once")
        self.assertFalse(self.wrapper_marker.exists())
        self.adapter.join_child()
        receipt = json.loads((self.run / "codex-01.spawn-intent.json").read_text())
        actual = [str(self.binary), *requested[1:]]
        self.assertEqual(receipt["argv_sha256"],
                         hashlib.sha256(json.dumps(actual).encode()).hexdigest())
        self.assertEqual(receipt["requested_argv_sha256"],
                         hashlib.sha256(json.dumps(requested).encode()).hexdigest())
        self.assertEqual(receipt["cli_binding"]["executable"]["sha256"], self.binary_sha)
        self.assertEqual(receipt["cli_binding"]["launcher"]["sha256"], self.launcher_sha)
        joined = json.loads((self.run / "codex-01.joined.json").read_text())
        self.assertTrue(joined["dedicated_process_group_absent"])

    def test_startup_rejects_wrong_binary_bytes_even_with_approved_launcher(self):
        with self.binary.open("a") as stream:
            stream.write("\n# different release\n")
        with self.assertRaisesRegex(RuntimeError, "executable byte pin differs"):
            self.qualify_fixture()
        self.assert_no_spawn()

    def test_startup_rejects_wrong_launcher_bytes(self):
        with self.launcher.open("a") as stream:
            stream.write("\n# different launcher\n")
        with self.assertRaisesRegex(RuntimeError, "launcher byte pin differs"):
            self.qualify_fixture()
        self.assert_no_spawn()

    def test_startup_rejects_executable_changed_during_hash(self):
        original_sha = provider.sha
        def read_then_replace(path):
            result = original_sha(path)
            if Path(path) == self.binary:
                with self.binary.open("a") as stream:
                    stream.write("\n# changed while qualifying\n")
            return result
        with mock.patch.object(provider, "sha", side_effect=read_then_replace):
            with self.assertRaisesRegex(RuntimeError, "changed during qualification"):
                self.qualify_fixture()
        self.assert_no_spawn()

    def test_unqualified_argv_program_is_rejected(self):
        with self.assertRaises(provider.ProviderError):
            self.adapter.spawn_codex(["/unqualified/program", "fixture"])
        self.assert_no_spawn()

    def test_cancelled_request_keeps_zero_launches(self):
        self.adapter.cancelled.set()
        with self.assertRaises(provider.ProviderError):
            self.adapter.spawn_codex([str(self.launcher)])
        self.assert_no_spawn()


if __name__ == "__main__":
    unittest.main(verbosity=2)
