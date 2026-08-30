#!/usr/bin/env python3
"""One-shot exact patch for provider post-terminal natural exit ordering."""

from __future__ import annotations

from pathlib import Path


LIB = Path("crates/trillionnium-owner-open-provider-jsonl/src/lib.rs")
PROCESS = Path("crates/trillionnium-owner-open-provider-jsonl/src/process.rs")
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
        "use process::{ProviderOutput, finish_child, spawn_stderr_reader, spawn_stdout_reader};\n",
        "use process::{\n"
        "    ProviderOutput, allow_natural_exit_grace, finish_child, spawn_stderr_reader,\n"
        "    spawn_stdout_reader,\n"
        "};\n",
        "provider process imports",
    )
    replace_once(
        LIB,
        '''        drop(provider_stdin);
        let cleanup = finish_child(&mut child, pid, self.config.terminate_grace)
            .map_err(JsonlProviderError::Cleanup);
''',
        '''        drop(provider_stdin);
        let natural_exit_wait = if result.as_ref().is_ok_and(|terminal| {
            terminal.status == ProviderTerminalStatus::Completed
        }) {
            // A valid terminal frame may be read before the provider leader has
            // completed its ordinary exit. Do not manufacture a SIGTERM failure.
            allow_natural_exit_grace(&mut child, self.config.terminate_grace)
                .map_err(JsonlProviderError::Cleanup)
        } else {
            Ok(())
        };
        let cleanup = finish_child(&mut child, pid, self.config.terminate_grace)
            .map_err(JsonlProviderError::Cleanup);
''',
        "post-terminal natural exit grace",
    )
    replace_once(
        LIB,
        '''        let terminal = result?;
        if stdout_join.is_err() || stderr_join.is_err() {
''',
        '''        let terminal = result?;
        natural_exit_wait?;
        if stdout_join.is_err() || stderr_join.is_err() {
''',
        "natural exit result ordering",
    )

    natural_exit_helper = '''/// Allow a provider that emitted a valid completed terminal to perform its
/// ordinary zero-status exit before process-group cleanup escalates signals.
pub(crate) fn allow_natural_exit_grace(
    child: &mut Child,
    grace: Duration,
) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(grace.max(Duration::from_millis(250)))
        .unwrap_or_else(Instant::now);
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("provider natural-exit status failed: {error}"))?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

'''
    replace_once(
        PROCESS,
        "/// Reap the provider leader and prove its original process group is gone.\n",
        natural_exit_helper
        + "/// Reap the provider leader and prove its original process group is gone.\n",
        "natural provider exit helper",
    )

    replace_once(
        RUST_TEST,
        '''printf '%s\\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":0,"summary":"ordered terminal"}'
exit 0
''',
        '''printf '%s\\n' '{"protocol":"trillionnium.owner-open.provider-jsonl.v1","kind":"turn.complete","seq":0,"summary":"ordered terminal"}'
sleep 0.05
exit 0
''',
        "deterministic post-terminal exit race",
    )
    replace_once(
        STATIC_TEST,
        '''SOURCE = Path("crates/trillionnium-owner-open-provider-jsonl/src/lib.rs")
''',
        '''SOURCE = Path("crates/trillionnium-owner-open-provider-jsonl/src/lib.rs")
PROCESS = Path("crates/trillionnium-owner-open-provider-jsonl/src/process.rs")
''',
        "static process source",
    )
    replace_once(
        STATIC_TEST,
        '''        text = SOURCE.read_text(encoding="utf-8")
''',
        '''        text = SOURCE.read_text(encoding="utf-8")
        process = PROCESS.read_text(encoding="utf-8")
''',
        "static process read",
    )
    replace_once(
        STATIC_TEST,
        '''        self.assertNotIn(
            '"process exited before turn terminal: {status}"',
            text,
        )
''',
        '''        self.assertNotIn(
            '"process exited before turn terminal: {status}"',
            text,
        )
        self.assertIn("allow_natural_exit_grace", process)
        natural_wait = text.index("allow_natural_exit_grace(&mut child")
        forced_cleanup = text.index("finish_child(&mut child")
        self.assertLess(natural_wait, forced_cleanup)
''',
        "static natural-exit invariant",
    )


if __name__ == "__main__":
    main()
