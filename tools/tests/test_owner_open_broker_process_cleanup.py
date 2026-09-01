from __future__ import annotations

from pathlib import Path
import signal
import sys
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "owner-open"))

from owner_open_broker_base_v2 import (  # noqa: E402
    BrokerError,
    _ProcessIdentity,
    _send_bound_process_group_signal,
    terminate_upstream_bounded,
)


class _FakeProcess:
    pid = 1234

    def __init__(self) -> None:
        self.alive = True
        self.signals: list[signal.Signals] = []
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return None if self.alive else self.returncode

    def send_signal(self, value: signal.Signals) -> None:
        self.signals.append(value)
        self.alive = False
        self.returncode = -int(value)

    def wait(self, timeout: float | None = None) -> int:
        if self.alive:
            raise subprocess.TimeoutExpired("fake-upstream", timeout)
        assert self.returncode is not None
        return self.returncode


class BrokerProcessCleanupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = _ProcessIdentity(
            pid=1234,
            process_group=1234,
            session_id=1234,
            start_time_ticks=77,
            boot_id_sha256="a" * 64,
        )

    def test_group_signal_rejects_reused_leader_generation(self) -> None:
        replacement = _ProcessIdentity(
            pid=1234,
            process_group=1234,
            session_id=1234,
            start_time_ticks=78,
            boot_id_sha256="a" * 64,
        )
        with mock.patch(
            "owner_open_broker_base_v2._observe_process_identity",
            return_value=replacement,
        ), mock.patch("owner_open_broker_base_v2.os.kill") as group_signal:
            with self.assertRaisesRegex(BrokerError, "identity changed"):
                _send_bound_process_group_signal(self.identity, signal.SIGTERM)
        group_signal.assert_not_called()

    def test_uncertain_group_cleanup_signals_only_exact_child(self) -> None:
        process = _FakeProcess()
        with mock.patch(
            "owner_open_broker_base_v2._ensure_bound_process_group",
            side_effect=BrokerError("identity changed"),
        ), mock.patch("owner_open_broker_base_v2.os.kill") as group_signal:
            terminate_upstream_bounded(process, self.identity, grace_seconds=0)
        group_signal.assert_not_called()
        self.assertEqual(process.signals, [signal.SIGTERM])


if __name__ == "__main__":
    unittest.main()
