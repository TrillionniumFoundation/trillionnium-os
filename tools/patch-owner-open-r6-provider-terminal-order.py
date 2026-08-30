#!/usr/bin/env python3
"""One-shot exact patch for provider stdout/exit terminal ordering."""

from __future__ import annotations

from pathlib import Path


LIB = Path("crates/trillionnium-owner-open-provider-jsonl/src/lib.rs")
RUST_TEST = Path(
    "crates/trillionnium-owner-open-provider-jsonl/tests/terminal_ordering.rs"
)
STATIC_TEST = Path("tools/tests/test_owner_open_provider_terminal_order.py")


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"{label}: expected exactly one source match in {path}, observed {count}"
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(
        LIB,
        'pub const PROVIDER_PROTOCOL: &str = "trillionnium.owner-open.provider-jsonl.v1";\n',
        'pub const PROVIDER_PROTOCOL: &str = "trillionnium.owner-open.provider-jsonl.v1";\n'
        'const PROVIDER_OUTPUT_DRAIN_GRACE_MINIMUM: Duration = Duration::from_secs(2);\n',
        "provider output drain grace",
    )
    replace_once(
        LIB,
        '''            let mut terminal = None;
            let mut event_count = 0usize;
            let mut cancellation_sent = false;
            let mut cancellation_deadline = None::<Instant>;
''',
        '''            let mut terminal = None;
            let mut event_count = 0usize;
            let mut cancellation_sent = false;
            let mut cancellation_deadline = None::<Instant>;
            let mut observed_exit = None::<(String, Instant)>;
''',
        "provider exit observation state",
    )
    replace_once(
        LIB,
        '''                    Ok(ProviderOutput::Eof) => {
                        if cancellation_sent {
                            terminal = Some(ProviderTerminal::cancelled(
                                "provider exited after turn cancellation",
                            ));
                            continue;
                        }
                        let status = child
                            .try_wait()
                            .map_err(|error| JsonlProviderError::Io(error.to_string()))?;
                        return Err(JsonlProviderError::Interrupted(format!(
                            "EOF before turn terminal; status={status:?}"
                        )));
                    }
''',
        '''                    Ok(ProviderOutput::Eof) => {
                        if cancellation_sent {
                            terminal = Some(ProviderTerminal::cancelled(
                                "provider exited after turn cancellation",
                            ));
                            continue;
                        }
                        let status = match observed_exit.as_ref() {
                            Some((status, _)) => status.clone(),
                            None => format!(
                                "{:?}",
                                child
                                    .try_wait()
                                    .map_err(|error| JsonlProviderError::Io(error.to_string()))?
                            ),
                        };
                        return Err(JsonlProviderError::Interrupted(format!(
                            "EOF before turn terminal; status={status}"
                        )));
                    }
''',
        "ordered EOF failure",
    )
    replace_once(
        LIB,
        '''                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if let Some(status) = child
                            .try_wait()
                            .map_err(|error| JsonlProviderError::Io(error.to_string()))?
                        {
                            if cancellation_sent {
                                terminal = Some(ProviderTerminal::cancelled(format!(
                                    "provider exited after cancellation: {status}"
                                )));
                            } else {
                                return Err(JsonlProviderError::Interrupted(format!(
                                    "process exited before turn terminal: {status}"
                                )));
                            }
                        }
                    }
''',
        '''                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if observed_exit.is_none()
                            && let Some(status) = child
                                .try_wait()
                                .map_err(|error| JsonlProviderError::Io(error.to_string()))?
                        {
                            // Child exit and stdout delivery are observed by different
                            // threads. Exit must never overtake an already-read terminal
                            // line; wait for the ordered reader outcome (Line then Eof).
                            observed_exit = Some((status.to_string(), Instant::now()));
                        }
                        if let Some((status, observed_at)) = observed_exit.as_ref()
                            && observed_at.elapsed()
                                >= self
                                    .config
                                    .terminate_grace
                                    .max(PROVIDER_OUTPUT_DRAIN_GRACE_MINIMUM)
                        {
                            if cancellation_sent {
                                terminal = Some(ProviderTerminal::cancelled(format!(
                                    "provider exited after cancellation: {status}"
                                )));
                            } else {
                                return Err(JsonlProviderError::Interrupted(format!(
                                    "provider exited and stdout did not deliver a turn terminal within the drain grace: {status}"
                                )));
                            }
                        }
                    }
''',
        "timeout exit/reader ordering",
    )

    if RUST_TEST.exists() or STATIC_TEST.exists():
        raise SystemExit("refusing to overwrite an existing provider ordering regression")

    RUST_TEST.write_text(
        r'''use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use trillionnium_owner_open_call_registry::CallRegistry;
use trillionnium_owner_open_provider_jsonl::{JsonlProvider, JsonlProviderConfig};
use trillionnium_owner_open_turn_loop::{
    ProviderTerminalStatus, TurnRequest, TurnRunner,
};

fn request(attempt: usize) -> TurnRequest {
    TurnRequest {
        session_id: "session-provider-order".to_string(),
        profile_id: "owner-open".to_string(),
        task_id: "task-provider-order".to_string(),
        turn_id: format!("turn-provider-order-{attempt}"),
        turn_stream_id: format!("stream-provider-order-{attempt}"),
        user_input: "prove provider terminal ordering".to_string(),
    }
}

#[test]
fn immediate_provider_exit_cannot_overtake_its_terminal_line() {
    let registry = Arc::new(CallRegistry::default());
    let runner = TurnRunner::new(registry);
    let script = r#"
IFS= read -r start || exit 10
printf '%s\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":0,"summary":"ordered terminal"}'
exit 0
"#;

    for attempt in 0..64 {
        let mut provider = JsonlProvider::new(JsonlProviderConfig {
            executable: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), script.to_string()],
            poll_interval: Duration::from_nanos(1),
            terminate_grace: Duration::from_millis(20),
            ..JsonlProviderConfig::default()
        })
        .unwrap();
        let run = runner.run(request(attempt), &mut provider).unwrap();
        assert_eq!(
            run.terminal.status,
            ProviderTerminalStatus::Completed,
            "attempt {attempt} returned terminal {:?}",
            run.terminal
        );
        assert_eq!(run.terminal.summary.as_deref(), Some("ordered terminal"));
    }
}
''',
        encoding="utf-8",
    )
    STATIC_TEST.write_text(
        '''"""Lock provider terminal classification to ordered stdout delivery."""

from pathlib import Path
import unittest


SOURCE = Path("crates/trillionnium-owner-open-provider-jsonl/src/lib.rs")


class ProviderTerminalOrderingTests(unittest.TestCase):
    def test_process_exit_cannot_bypass_the_stdout_reader_queue(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("let mut observed_exit = None::<(String, Instant)>;", text)
        self.assertIn("PROVIDER_OUTPUT_DRAIN_GRACE_MINIMUM", text)
        self.assertIn("wait for the ordered reader outcome (Line then Eof)", text)
        self.assertNotIn(
            '"process exited before turn terminal: {status}"',
            text,
        )
        line_arm = text.index("Ok(ProviderOutput::Line(raw))")
        eof_arm = text.index("Ok(ProviderOutput::Eof)")
        timeout_arm = text.index(
            "Err(std::sync::mpsc::RecvTimeoutError::Timeout)"
        )
        self.assertLess(line_arm, eof_arm)
        self.assertLess(eof_arm, timeout_arm)


if __name__ == "__main__":
    unittest.main()
''',
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
