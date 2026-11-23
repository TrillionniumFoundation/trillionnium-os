"""CI binding tests use an actual pinned ELF in a temporary, explicitly synthetic checkout."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from build_identity import source_inputs
from vlm_ci_transfer import CI_FILES, WORKFLOW_REL, TRANSFER_NAME, perform


class VlmCiTransfer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hepta-vlm-ci-test-", dir="/tmp")
        cls.repo = Path(cls.temp.name) / "checkout"
        cls.source = cls.repo / "projects/synthetic-app"
        cls.source.mkdir(parents=True)
        # Copy the real build inputs, with no mutation of source or original runtime.
        paths = {row["path"] for row in source_inputs(ROOT)} | set(CI_FILES)
        native_manifest = json.loads((ROOT / "native/vlm-worker/SOURCE.json").read_text())
        paths.update("native/vlm-worker/" + row["path"] for row in native_manifest["files"])
        for relative in paths:
            target = cls.source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        workflow = cls.repo / WORKFLOW_REL
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: synthetic transfer fixture\non: workflow_dispatch\njobs: {}\n")
        cls.git("init", "-q")
        cls.git("add", ".")
        cls.git("-c", "user.email=fixture@example.invalid", "-c", "user.name=CI fixture",
                "commit", "-q", "-m", "synthetic fixture; no Android execution")
        cls.head = cls.git("rev-parse", "HEAD").strip()
        cls.runtime = Path(cls.temp.name) / "runtime"
        cls.runtime.mkdir()
        original = Path(os.environ["HEPTA_TEST_VLM_RUNTIME"])
        for name in ("BUILD-RECEIPT.json", "libhepta_local_vlm_runner.so"):
            shutil.copyfile(original / name, cls.runtime / name)
        cls.context = [cls.repo, cls.source, cls.runtime, cls.head, "fixture/hepta", "12345", "1"]

    @classmethod
    def git(cls, *args):
        return subprocess.check_output(["git", "-C", str(cls.repo), *args], text=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        (self.runtime / TRANSFER_NAME).unlink(missing_ok=True)

    def bind(self):
        return perform("bind", *self.context)

    def verify(self, **replacements):
        arguments = list(self.context)
        for index, value in replacements.items():
            arguments[int(index)] = value
        return perform("verify", *arguments)

    def changed_file_rejects(self, path, raw):
        original = path.read_bytes()
        try:
            path.write_bytes(raw)
            with self.assertRaises(RuntimeError):
                self.verify()
        finally:
            path.write_bytes(original)

    def test_same_checkout_and_attempt_accept_actual_artifact(self):
        self.bind()
        self.assertTrue(self.verify()["verified"])

    def test_wrong_checkout_sha(self):
        self.bind()
        with self.assertRaises(RuntimeError): self.verify(**{"3": "1" * 40})

    def test_other_repository(self):
        self.bind()
        with self.assertRaises(RuntimeError): self.verify(**{"4": "fixture/other"})

    def test_other_run(self):
        self.bind()
        with self.assertRaises(RuntimeError): self.verify(**{"5": "12346"})

    def test_other_attempt(self):
        self.bind()
        with self.assertRaises(RuntimeError): self.verify(**{"6": "2"})

    def test_receipt_byte_change(self):
        self.bind()
        path = self.runtime / "BUILD-RECEIPT.json"
        self.changed_file_rejects(path, path.read_bytes() + b"\n")

    def test_source_change(self):
        self.bind()
        path = self.source / "tools/build_vlm_worker.py"
        self.changed_file_rejects(path, path.read_bytes() + b"\n# changed\n")

    def test_workflow_change(self):
        self.bind()
        path = self.repo / WORKFLOW_REL
        self.changed_file_rejects(path, path.read_bytes() + b"# changed\n")

    def test_extra_transfer_claim(self):
        self.bind()
        path = self.runtime / TRANSFER_NAME
        value = json.loads(path.read_text())
        value["ordinary_app_qualified"] = True
        self.changed_file_rejects(path, json.dumps(value).encode())

    def test_duplicate_json_key(self):
        self.bind()
        path = self.runtime / TRANSFER_NAME
        self.changed_file_rejects(path, b'{"run_id":"12345",' + path.read_bytes()[1:])

    def test_boolean_type_cannot_be_numeric(self):
        self.bind()
        path = self.runtime / TRANSFER_NAME
        value = json.loads(path.read_text())
        value["device_qualification_claimed"] = 0
        self.changed_file_rejects(path, json.dumps(value).encode())

    def test_worker_size_cannot_be_float(self):
        self.bind()
        path = self.runtime / TRANSFER_NAME
        value = json.loads(path.read_text())
        value["worker"]["bytes"] = float(value["worker"]["bytes"])
        self.changed_file_rejects(path, json.dumps(value).encode())

    def test_compiler_identity_not_substitutable(self):
        path = self.runtime / "BUILD-RECEIPT.json"
        original = path.read_bytes()
        try:
            value = json.loads(original)
            value["compiler_wrapper_sha256"] = "0" * 64
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError): self.bind()
        finally:
            path.write_bytes(original)

    def test_producer_cannot_overwrite_old_transfer(self):
        self.bind()
        with self.assertRaises(FileExistsError): self.bind()


if __name__ == "__main__":
    unittest.main()
