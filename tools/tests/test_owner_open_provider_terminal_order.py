"""Lock provider terminal classification to ordered stdout delivery."""

from pathlib import Path
import unittest


SOURCE = Path("crates/trillionnium-owner-open-provider-jsonl/src/lib.rs")
PROCESS = Path("crates/trillionnium-owner-open-provider-jsonl/src/process.rs")


class ProviderTerminalOrderingTests(unittest.TestCase):
    def test_process_exit_cannot_bypass_the_stdout_reader_queue(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        process = PROCESS.read_text(encoding="utf-8")
        self.assertIn("let mut observed_exit = None::<(String, Instant)>;", text)
        self.assertIn("PROVIDER_OUTPUT_DRAIN_GRACE_MINIMUM", text)
        self.assertIn("wait for the ordered reader outcome (Line then Eof)", text)
        self.assertNotIn(
            '"process exited before turn terminal: {status}"',
            text,
        )
        self.assertIn("allow_natural_exit_grace", process)
        natural_wait = text.index("allow_natural_exit_grace(&mut child")
        forced_cleanup = text.index("finish_child(&mut child")
        self.assertLess(natural_wait, forced_cleanup)
        line_arm = text.index("Ok(ProviderOutput::Line(raw))")
        eof_arm = text.index("Ok(ProviderOutput::Eof)")
        timeout_arm = text.index(
            "Err(std::sync::mpsc::RecvTimeoutError::Timeout)"
        )
        self.assertLess(line_arm, eof_arm)
        self.assertLess(eof_arm, timeout_arm)


if __name__ == "__main__":
    unittest.main()
