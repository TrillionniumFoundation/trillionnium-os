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
        # Cleanup is now owned by ProviderChildGuard.  Keep the ordering
        # assertion at the public turn boundary while separately requiring
        # the concrete process helper to remain in the lifecycle module.
        forced_cleanup = text.index("let cleanup = child.finish()")
        # The guard keeps ownership in an Option so Drop can transfer the
        # exact Child to its bounded reaper; the explicit path borrows it via
        # child_mut after the identity binding has succeeded.
        self.assertIn("finish_child(self.child_mut()?", process)
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
