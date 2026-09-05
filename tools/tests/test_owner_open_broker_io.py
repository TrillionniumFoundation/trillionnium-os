from __future__ import annotations

import os
from pathlib import Path
import socket
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_runtime import (  # noqa: E402
    send_all_bounded,
    write_all_bounded,
)


class BrokerBoundedIoTest(unittest.TestCase):
    @staticmethod
    def _fill_nonblocking_pipe(descriptor: int) -> None:
        original = os.get_blocking(descriptor)
        os.set_blocking(descriptor, False)
        try:
            while True:
                os.write(descriptor, b"x" * 65_536)
        except BlockingIOError:
            pass
        finally:
            os.set_blocking(descriptor, original)

    def test_upstream_pipe_write_timeout_is_finite_and_restores_mode(self) -> None:
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(write_fd, "wb", closefd=False)
        try:
            self._fill_nonblocking_pipe(write_fd)
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                write_all_bounded(
                    stream,
                    b"request-that-cannot-fit",
                    timeout_seconds=0.05,
                    label="test upstream",
                )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.5)
            self.assertTrue(os.get_blocking(write_fd))
        finally:
            stream.close()
            os.close(write_fd)
            os.close(read_fd)

    def test_client_socket_write_timeout_is_finite_without_reader_mode_mutation(self) -> None:
        sender, receiver = socket.socketpair()
        try:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4_096)
            original_mode = sender.getblocking()
            sender.setblocking(False)
            try:
                while True:
                    sender.send(b"x" * 65_536, socket.MSG_DONTWAIT)
            except BlockingIOError:
                pass
            sender.setblocking(original_mode)
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                send_all_bounded(
                    sender,
                    b"response-that-cannot-fit",
                    timeout_seconds=0.05,
                    label="test client",
                )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.5)
            self.assertEqual(sender.getblocking(), original_mode)
        finally:
            sender.close()
            receiver.close()


if __name__ == "__main__":
    unittest.main()
