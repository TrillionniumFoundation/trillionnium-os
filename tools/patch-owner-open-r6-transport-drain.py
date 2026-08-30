#!/usr/bin/env python3
"""One-shot exact patch for ordered transport core drain convergence."""

from __future__ import annotations

from pathlib import Path


IMPORTS = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/entry/imports.rs"
)
STATE = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/entry/state.rs"
)
IO_SOURCE = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/process/io.rs"
)
RUN_SOURCE = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/process/run.rs"
)
RUST_TEST = Path(
    "apps/trillionnium-owner-open-host/tests/r5_transport_core_drain.rs"
)
STATIC_TEST = Path("tools/tests/test_owner_open_transport_core_drain.py")


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
        IMPORTS,
        "use std::time::{Duration, SystemTime, UNIX_EPOCH};\n",
        "use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};\n",
        "Instant import",
    )
    replace_once(
        IMPORTS,
        "const TRANSPORT_POLL_INTERVAL: Duration = Duration::from_millis(20);\n",
        "const TRANSPORT_POLL_INTERVAL: Duration = Duration::from_millis(20);\n"
        "const CORE_READER_DRAIN_GRACE: Duration = Duration::from_secs(2);\n",
        "core drain grace",
    )
    replace_once(
        STATE,
        "    CoreFrame(Vec<u8>),\n    CoreEof,\n    CoreError(String),\n",
        "    CoreFrame(Vec<u8>),\n"
        "    CoreEof,\n"
        "    CoreError(String),\n"
        "    CoreExited(std::result::Result<ExitStatus, String>),\n",
        "core exit observation",
    )

    waiter = '''fn spawn_core_waiter(mut child: Child, sender: SyncSender<TransportMessage>) {
    thread::Builder::new()
        .name("owner-open-transport-core-waiter".to_string())
        .spawn(move || {
            let result = child
                .wait()
                .map_err(|error| format!("cannot wait for core Host: {error}"));
            let _ = sender.send(TransportMessage::CoreExited(result));
        })
        .expect("spawn transport core waiter");
}

fn terminate_core_process_group(pid: u32) -> Result<(), String> {
    let process_group = i32::try_from(pid)
        .map_err(|_| format!("core Host pid {pid} does not fit a process-group id"))?;
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(format!(
            "cannot terminate descendants in core Host process group {process_group}: {error}"
        ))
    }
}

'''
    replace_once(
        IO_SOURCE,
        "fn spawn_client_reader(sender: SyncSender<TransportMessage>, max_frame_bytes: usize) {\n",
        waiter
        + "fn spawn_client_reader(sender: SyncSender<TransportMessage>, max_frame_bytes: usize) {\n",
        "core waiter and process-group cleanup",
    )

    replace_once(
        RUN_SOURCE,
        '''    let limits = MechanicalLimits::default();
    let (mut child, mut core_stdin, core_stdout, core_stderr) = spawn_core(&options)?;
    spawn_stderr_drain(core_stderr);

    let (sender, receiver) = sync_channel(TRANSPORT_QUEUE_DEPTH);
    spawn_client_reader(sender.clone(), limits.max_frame_bytes);
    spawn_core_reader(core_stdout, sender, limits.max_frame_bytes);
''',
        '''    let limits = MechanicalLimits::default();
    let (child, mut core_stdin, core_stdout, core_stderr) = spawn_core(&options)?;
    let core_pid = child.id();
    spawn_stderr_drain(core_stderr);

    let (sender, receiver) = sync_channel(TRANSPORT_QUEUE_DEPTH);
    spawn_client_reader(sender.clone(), limits.max_frame_bytes);
    spawn_core_reader(core_stdout, sender.clone(), limits.max_frame_bytes);
    spawn_core_waiter(child, sender);
''',
        "core reader/waiter startup",
    )
    replace_once(
        RUN_SOURCE,
        '''    let mut client_open = true;
    let mut core_open = true;
    let mut terminal_error = None::<String>;

    while core_open {
''',
        '''    let mut client_open = true;
    let mut core_reader_open = true;
    let mut core_wait_open = true;
    let mut core_status = None::<ExitStatus>;
    let mut core_exit_deadline = None::<Instant>;
    let mut terminal_error = None::<String>;

    while core_reader_open || core_wait_open {
''',
        "core convergence state",
    )
    replace_once(
        RUN_SOURCE,
        '''            Ok(TransportMessage::CoreEof) => core_open = false,
            Ok(TransportMessage::CoreError(error)) => {
                terminal_error = Some(error);
                core_open = false;
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                    core_open = false;
                    if !status.success() {
                        terminal_error = Some(format!("core Host exited unsuccessfully: {status}"));
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => core_open = false,
''',
        '''            Ok(TransportMessage::CoreEof) => {
                core_reader_open = false;
                core_exit_deadline = None;
            }
            Ok(TransportMessage::CoreError(error)) => {
                terminal_error.get_or_insert(error);
                core_reader_open = false;
                core_exit_deadline = None;
            }
            Ok(TransportMessage::CoreExited(result)) => {
                core_wait_open = false;
                drop(core_stdin.take());
                match result {
                    Ok(status) => core_status = Some(status),
                    Err(error) => {
                        terminal_error.get_or_insert(error);
                    }
                }
                if let Err(error) = terminate_core_process_group(core_pid) {
                    terminal_error.get_or_insert(error);
                }
                if core_reader_open {
                    core_exit_deadline = Some(Instant::now() + CORE_READER_DRAIN_GRACE);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if core_exit_deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    terminal_error.get_or_insert_with(|| {
                        "core Host stdout did not close after leader exit and process-group cleanup"
                            .to_string()
                    });
                    core_reader_open = false;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                terminal_error.get_or_insert_with(|| {
                    "transport event channel disconnected before core lifecycle convergence"
                        .to_string()
                });
                core_reader_open = false;
                core_wait_open = false;
            }
''',
        "ordered core lifecycle convergence",
    )
    replace_once(
        RUN_SOURCE,
        '''    let status = child.wait().map_err(|error| error.to_string())?;
    if let Some(error) = terminal_error {
        return Err(error);
    }
    if !status.success() {
''',
        '''    if let Some(error) = terminal_error {
        return Err(error);
    }
    let status = core_status
        .ok_or_else(|| "core Host exit status was not observed".to_string())?;
    if !status.success() {
''',
        "final core status",
    )

    if RUST_TEST.exists() or STATIC_TEST.exists():
        raise SystemExit("refusing to overwrite an existing transport drain regression")

    RUST_TEST.write_text(
        r'''use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn transport_drains_the_final_core_frame_and_reaps_the_descendant_group() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("core-descendant.pid");
    let script = r#"
import json
import os
import sys
import time

pid = os.fork()
if pid == 0:
    time.sleep(30)
    os._exit(0)

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(str(pid))
    handle.flush()
    os.fsync(handle.fileno())

frame = {"kind": "hello.ack", "seq": 41, "payload": {"status": "ready"}}
sys.stdout.write(json.dumps(frame, separators=(",", ":")) + "\n")
sys.stdout.flush()
os._exit(0)
"#;

    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_trillionnium-owner-open-r5-host"))
        .arg("--transport-core")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .arg(&pid_file)
        .stdin(Stdio::null())
        .output()
        .expect("transport Host must start");

    assert!(
        output.status.success(),
        "status={:?}; stdout={}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.lines().any(|line| {
        let frame: serde_json::Value = serde_json::from_str(line).unwrap();
        frame.get("kind").and_then(serde_json::Value::as_str) == Some("hello.ack")
            && frame
                .get("payload")
                .and_then(|payload| payload.get("status"))
                .and_then(serde_json::Value::as_str)
                == Some("ready")
    }));

    let descendant = fs::read_to_string(&pid_file)
        .expect("core must publish the descendant pid")
        .trim()
        .parse::<i32>()
        .expect("descendant pid must be decimal");
    assert!(descendant > 1);

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let result = unsafe { libc::kill(descendant, 0) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            panic!("unexpected descendant liveness probe error: {error}");
        }
        assert!(
            Instant::now() < deadline,
            "core descendant {descendant} survived transport process-group cleanup"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
''',
        encoding="utf-8",
    )
    STATIC_TEST.write_text(
        '''"""Lock transport termination to ordered reader/waiter convergence."""

from pathlib import Path
import unittest


RUN = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/process/run.rs"
)
STATE = Path(
    "apps/trillionnium-owner-open-host/src/bin/r5_transport_host/entry/state.rs"
)


class TransportCoreDrainTests(unittest.TestCase):
    def test_exit_observation_cannot_bypass_ordered_core_frames(self) -> None:
        run = RUN.read_text(encoding="utf-8")
        state = STATE.read_text(encoding="utf-8")
        self.assertIn("CoreExited(std::result::Result<ExitStatus, String>)", state)
        self.assertIn("while core_reader_open || core_wait_open", run)
        self.assertIn("spawn_core_waiter(child, sender)", run)
        self.assertIn("terminate_core_process_group(core_pid)", run)
        self.assertIn("CORE_READER_DRAIN_GRACE", run)
        self.assertNotIn("child.try_wait()", run)


if __name__ == "__main__":
    unittest.main()
''',
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
