"""Source identity and producer/consumer separation regressions; no Android execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import bind_consumer as gate


class SourceFixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-consumer-source-")
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "component"
        (self.source / "src").mkdir(parents=True)
        (self.source / "src/main.txt").write_bytes(b"original source\n")
        self.manifest()
        self.run("init", "-q")
        self.commit()

    def run(self, *args):
        return subprocess.check_output(
            ["git", "-c", "user.name=Hepta contract fixture",
             "-c", "user.email=fixture@example.invalid", "-C", str(self.root), *args],
            stderr=subprocess.STDOUT, env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        )

    def manifest(self):
        files = []
        for path in sorted(self.source.rglob("*")):
            if path.is_file() and path.name != "SOURCE-MANIFEST.json":
                raw = path.read_bytes()
                files.append({"path": str(path.relative_to(self.source)), "bytes": len(raw),
                              "sha256": hashlib.sha256(raw).hexdigest()})
        (self.source / "SOURCE-MANIFEST.json").write_text(
            json.dumps({"schema": "hepta.local-source.v3", "files": files}) + "\n")

    def commit(self):
        self.run("add", "--all")
        self.run("commit", "-qm", "Synthetic source fixture")
        self.head = self.run("rev-parse", "HEAD").decode().strip()

    def verify(self):
        return gate.verify_source(self.root, self.head, "component")

    def close(self):
        self.temp.cleanup()


class ExactSourceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = SourceFixture()
        self.addCleanup(self.fixture.close)

    def test_complete_manifest_and_git_bytes_agree(self):
        identity, files = self.fixture.verify()
        self.assertEqual(identity["source_files"], 2)
        self.assertEqual(set(files), {"SOURCE-MANIFEST.json", "src/main.txt"})
        self.assertEqual(identity["head"], self.fixture.head)

    def test_valid_new_manifest_does_not_authorize_dirty_git_bytes(self):
        (self.fixture.source / "src/main.txt").write_bytes(b"changed source\n")
        self.fixture.manifest()
        with self.assertRaisesRegex(ValueError, "exact Git head"):
            self.fixture.verify()

    def test_changed_source_without_new_manifest_rejected(self):
        (self.fixture.source / "src/main.txt").write_bytes(b"tampered\n")
        with self.assertRaises(ValueError):
            self.fixture.verify()

    def test_wrong_head_rejected(self):
        with self.assertRaisesRegex(ValueError, "required source head"):
            gate.verify_source(self.fixture.root, "0" * 40, "component")

    def test_unlisted_source_rejected(self):
        (self.fixture.source / "extra.txt").write_text("unlisted")
        with self.assertRaisesRegex(ValueError, "unlisted or missing"):
            self.fixture.verify()

    def test_missing_source_rejected(self):
        (self.fixture.source / "src/main.txt").unlink()
        with self.assertRaisesRegex(ValueError, "unlisted or missing"):
            self.fixture.verify()

    def test_manifest_duplicate_path_rejected_even_if_committed(self):
        path = self.fixture.source / "SOURCE-MANIFEST.json"
        manifest = json.loads(path.read_text())
        manifest["files"].append(manifest["files"][0])
        path.write_text(json.dumps(manifest))
        self.fixture.commit()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.fixture.verify()

    def test_manifest_parent_traversal_rejected(self):
        path = self.fixture.source / "SOURCE-MANIFEST.json"
        manifest = json.loads(path.read_text())
        manifest["files"][0]["path"] = "../escape"
        path.write_text(json.dumps(manifest))
        self.fixture.commit()
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.fixture.verify()

    def test_json_duplicate_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            gate.obj(b'{"files":[],"files":[]}')

    def test_symlink_source_rejected(self):
        path = self.fixture.source / "src/main.txt"
        path.unlink()
        path.symlink_to("/dev/null")
        with self.assertRaises(ValueError):
            self.fixture.verify()

    def test_hardlinked_source_rejected(self):
        path = self.fixture.source / "src/main.txt"
        other = self.fixture.root / "link"
        os.link(path, other)
        with self.assertRaisesRegex(ValueError, "single-link"):
            self.fixture.verify()

    def test_executable_mode_drift_rejected(self):
        path = self.fixture.source / "src/main.txt"
        path.chmod(path.stat().st_mode | 0o111)
        with self.assertRaisesRegex(ValueError, "mode"):
            self.fixture.verify()

    def test_git_tracked_file_missing_from_manifest_rejected(self):
        (self.fixture.source / "tracked.txt").write_text("not in manifest")
        self.fixture.commit()
        with self.assertRaisesRegex(ValueError, "complete Git component"):
            self.fixture.verify()

    def test_independent_checkout_outside_component_is_not_consumer_source(self):
        other = self.fixture.root / "hepta-runtime-producer"
        other.mkdir()
        (other / "separate.txt").write_text("separate checkout")
        self.assertEqual(self.fixture.verify()[0]["source_files"], 2)


class RuntimeClosureTests(unittest.TestCase):
    def source(self):
        files = {name: {"mode": "100644", "git_blob": "a" * 40, "bytes": 3, "sha256": "b" * 64}
                 for name in gate.CONTRACT_FILES}
        for prefix in gate.CONTRACT_PREFIXES:
            files[prefix + "native.c"] = {"mode": "100644", "git_blob": "c" * 40, "bytes": 4, "sha256": "d" * 64}
        return files

    def test_consumer_app_may_change_without_changing_runtime_source(self):
        old, new = self.source(), self.source()
        new["src/ChangedApp.java"] = {"sha256": "different"}
        self.assertTrue(gate.match_contracts(old, new))

    def test_changed_runtime_pin_is_rejected(self):
        old, new = self.source(), self.source()
        new["native/mobimind-runtime-pins.json"]["sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "contract differs"):
            gate.match_contracts(old, new)

    def test_new_native_source_member_is_rejected(self):
        old, new = self.source(), self.source()
        new[gate.CONTRACT_PREFIXES[0] + "extra.c"] = {}
        with self.assertRaisesRegex(ValueError, "membership"):
            gate.match_contracts(old, new)

    def test_missing_native_source_member_is_rejected(self):
        old, new = self.source(), self.source()
        del new[gate.CONTRACT_PREFIXES[1] + "native.c"]
        with self.assertRaisesRegex(ValueError, "membership"):
            gate.match_contracts(old, new)

    def test_mnn_original_verifier_receives_frozen_source(self):
        args = argparse.Namespace(kind="mnn", operation="verify", source_head="a" * 40,
                                  run_id="123", run_attempt="2", ndk=None, sdk_libs=None,
                                  compiler_identity=None)
        command = gate.original_argv(args, Path("/consumer"), Path("/producer"), Path("/bundle/producer"))
        self.assertEqual(command[command.index("--app-source") + 1], "/producer/" + gate.COMPONENT)
        self.assertEqual(command[command.index("--source-head") + 1], "a" * 40)
        self.assertIn("/consumer/" + gate.MNN_BINDER, command)
        self.assertEqual(command[command.index("--bundle") + 1], "/bundle/producer")

    def test_ui_original_builder_receives_unchanged_build_inputs(self):
        args = argparse.Namespace(kind="ui", operation="bind", source_head="a" * 40,
                                  run_id="123", run_attempt="2", ndk=Path("/ndk"),
                                  sdk_libs=Path("/sdk"), compiler_identity=Path("/compiler.json"))
        command = gate.original_argv(args, Path("/consumer"), Path("/producer"), Path("/bundle/producer"))
        self.assertIn("build", command)
        self.assertEqual(command[command.index("--app-source") + 1], "/producer/" + gate.COMPONENT)
        self.assertEqual(command[command.index("--ndk") + 1], "/ndk")
        self.assertEqual(command[command.index("--sdk-libs") + 1], "/sdk")

    def test_linux_consumer_cannot_replace_transferred_compiler_identity(self):
        args = argparse.Namespace(kind="mnn", operation="verify", source_head="a" * 40,
                                  run_id="123", run_attempt="2", ndk=None, sdk_libs=None,
                                  compiler_identity=Path("/new-compiler.json"))
        with self.assertRaisesRegex(ValueError, "only transferred"):
            gate.original_argv(args, Path("/consumer"), Path("/producer"), Path("/bundle/producer"))


class AdmissionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-runtime-admission-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "consumer").mkdir()
        (self.root / "frozen").mkdir()
        (self.root / "bundle/producer").mkdir(parents=True)
        self.args = argparse.Namespace(operation="bind", kind="mnn",
            consumer_root=self.root / "consumer", producer_root=self.root / "frozen",
            source_head="a" * 40, run_id="123", run_attempt="1", bundle=self.root / "bundle",
            compiler_identity=self.root / "compiler.json", ndk=None, sdk_libs=None)

    def test_original_verifier_failure_cannot_publish_consumer_binding(self):
        with mock.patch.object(gate, "verify_pair", return_value={"same": True}), \
             mock.patch.object(gate.subprocess, "run", return_value=argparse.Namespace(
                 returncode=2, stdout=b"", stderr=b"")), \
             mock.patch.object(gate, "check_runtime") as runtime:
            with self.assertRaisesRegex(ValueError, "original runtime"):
                gate.execute(self.args)
            runtime.assert_not_called()
        self.assertFalse((self.root / "bundle" / gate.BINDING).exists())

    def test_source_drift_after_original_operation_cannot_publish(self):
        with mock.patch.object(gate, "verify_pair", side_effect=[{"same": True}, {"same": False}]), \
             mock.patch.object(gate.subprocess, "run", return_value=argparse.Namespace(
                 returncode=0, stdout=b"", stderr=b"")), \
             mock.patch.object(gate, "check_runtime") as runtime:
            with self.assertRaisesRegex(ValueError, "source pair changed"):
                gate.execute(self.args)
            runtime.assert_not_called()
        self.assertFalse((self.root / "bundle" / gate.BINDING).exists())


if __name__ == "__main__":
    unittest.main()
