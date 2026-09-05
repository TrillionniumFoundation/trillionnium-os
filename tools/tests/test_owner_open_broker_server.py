from __future__ import annotations

from pathlib import Path
import os
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_common import BrokerError  # noqa: E402
from owner_open_broker_server_v2 import BrokerServerMixin  # noqa: E402


class BrokerServerSocketSecurityTest(unittest.TestCase):
    def test_path_replacement_during_fd_chmod_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "broker.sock"
            replacement: socket.socket | None = None
            replacement_identity: tuple[int, int] | None = None
            original_fchmod = os.fchmod

            def replace_path(fd: int, mode: int) -> None:
                nonlocal replacement, replacement_identity
                original_fchmod(fd, mode)
                path.unlink()
                replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                replacement.bind(str(path))
                metadata = path.lstat()
                replacement_identity = (metadata.st_dev, metadata.st_ino)

            with mock.patch.object(
                os,
                "fchmod",
                side_effect=replace_path,
            ), self.assertRaisesRegex(BrokerError, "pathname changed"):
                BrokerServerMixin._bind_private_listener(path)

            self.assertIsNotNone(replacement)
            self.assertIsNotNone(replacement_identity)
            try:
                # The cleanup path must not unlink a competing inode that
                # appeared after the original listener was bound.
                metadata = path.lstat()
                self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
                self.assertEqual(
                    (metadata.st_dev, metadata.st_ino),
                    replacement_identity,
                )
            finally:
                replacement.close()


if __name__ == "__main__":
    unittest.main()
