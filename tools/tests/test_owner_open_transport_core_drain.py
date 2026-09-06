"""Lock transport termination to ordered reader/waiter convergence."""

from pathlib import Path
import unittest


RUN = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/process/run.rs"
)
IO = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/process/io.rs"
)
STATE = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/entry/state.rs"
)


class TransportCoreDrainTests(unittest.TestCase):
    def test_exit_observation_cannot_bypass_ordered_core_frames(self) -> None:
        run = RUN.read_text(encoding="utf-8")
        io = IO.read_text(encoding="utf-8")
        state = STATE.read_text(encoding="utf-8")
        self.assertIn("CoreExited(std::result::Result<ExitStatus, String>)", state)
        self.assertIn("while core_reader_open || core_wait_open", run)
        self.assertIn("spawn_core_waiter(child, sender)", run)
        # Cleanup is now identity-bound and owned by the waiter; the old raw
        # PID-to-PGID helper would be unsafe under PID reuse.
        self.assertIn("wait_and_cleanup", io)
        self.assertIn("finish_core_child", io)
        self.assertNotIn("terminate_core_process_group(core_pid)", run)
        self.assertIn("CORE_READER_DRAIN_GRACE", run)
        self.assertNotIn("child.try_wait()", run)


if __name__ == "__main__":
    unittest.main()
