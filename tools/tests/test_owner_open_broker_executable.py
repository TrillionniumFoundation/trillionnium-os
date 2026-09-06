from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_common import (  # noqa: E402
    BrokerError,
    open_validated_executable,
    validate_executable,
)


class ValidatedExecutableTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.executable = self.root / "upstream.sh"
        self.executable.write_text("#!/bin/sh\nprintf original\n", encoding="utf-8")
        self.executable.chmod(0o700)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_later_path_replacement_is_rejected_against_initial_identity(self) -> None:
        initial = validate_executable(self.executable, "--upstream")
        replacement = self.root / "replacement.sh"
        replacement.write_text("#!/bin/sh\nprintf replacement\n", encoding="utf-8")
        replacement.chmod(0o700)
        os.replace(replacement, self.executable)
        with self.assertRaisesRegex(BrokerError, "changed since initial validation"):
            open_validated_executable(
                self.executable,
                "--upstream",
                expected_identity=initial,
            )

    def test_pinned_descriptor_executes_original_after_path_swap(self) -> None:
        descriptor, _identity = open_validated_executable(self.executable, "--upstream")
        try:
            replacement = self.root / "replacement.sh"
            replacement.write_text("#!/bin/sh\nprintf replacement\n", encoding="utf-8")
            replacement.chmod(0o700)
            os.replace(replacement, self.executable)
            child = subprocess.Popen(
                [str(self.executable)],
                executable=f"/proc/self/fd/{descriptor}",
                pass_fds=(descriptor,),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = child.communicate(timeout=2)
            self.assertEqual(child.returncode, 0, stderr.decode())
            self.assertEqual(stdout, b"original")
        finally:
            os.close(descriptor)

    def test_symlink_replacement_is_rejected(self) -> None:
        initial = validate_executable(self.executable, "--upstream")
        target = self.root / "target.sh"
        target.write_text("#!/bin/sh\nprintf target\n", encoding="utf-8")
        target.chmod(0o700)
        self.executable.unlink()
        self.executable.symlink_to(target)
        with self.assertRaises(BrokerError):
            open_validated_executable(
                self.executable,
                "--upstream",
                expected_identity=initial,
            )


if __name__ == "__main__":
    unittest.main()
