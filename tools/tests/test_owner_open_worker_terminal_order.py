"""Lock the single-channel terminal ordering invariant in the R5 Host."""

from pathlib import Path
import unittest


SOURCE = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v2.rs"
)


class WorkerTerminalOrderingTests(unittest.TestCase):
    def test_terminal_delivery_cannot_bypass_the_host_message_queue(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("catch_unwind(AssertUnwindSafe(|| {", text)
        self.assertIn(
            "worker_sender.send(HostMessage::TurnComplete(result))",
            text,
        )
        self.assertIn("Err(RecvTimeoutError::Timeout) => {}", text)
        self.assertNotIn("JoinHandle::is_finished", text)
        self.assertNotIn(
            "active turn worker exited without a terminal message",
            text,
        )


if __name__ == "__main__":
    unittest.main()
