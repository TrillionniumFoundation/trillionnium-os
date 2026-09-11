from __future__ import annotations

import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest


from tools.tests.authenticated_python_bootstrap_fixture import load_authenticated_module

PATH = Path(__file__).resolve().parents[1] / "perf/run_product_baseline.py"
BENCH = load_authenticated_module(
    "product_baseline_cleanup", PATH, "tools/perf/run_product_baseline.py"
)


def live_task(pid: int) -> bool:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return False
    fields = raw.rsplit(b")", 1)[1].split()
    return bool(fields) and fields[0] not in (b"Z", b"X")


def wait_not_live(pid: int) -> None:
    deadline = time.monotonic() + 3.0
    while live_task(pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    if live_task(pid):
        raise AssertionError(f"descendant {pid} survived cleanup")


def wait_child_pid(path: Path, *, process: object | None = None) -> int:
    """Wait for one complete PID publication, not merely a created inode."""

    deadline = time.monotonic() + 3.0
    last_raw = b""
    while time.monotonic() < deadline:
        if process is not None:
            process.poll()
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            raw = b""
        last_raw = raw
        try:
            text = raw.decode("ascii")
            pid = int(text)
        except (UnicodeDecodeError, ValueError):
            time.sleep(0.01)
            continue
        if text == str(pid) and pid > 0:
            if process is None or process.poll() is not None:
                return pid
        time.sleep(0.01)
    raise AssertionError(f"child PID was not published atomically: {last_raw!r}")


class ProductBaselineProcessGroupCleanupTests(unittest.TestCase):
    def spawn_term_split_group(self) -> tuple[object, int]:
        script = r'''
import os
import signal
import sys
import time

child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)

print(child, flush=True)
signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit(0))
while True:
    time.sleep(1)
'''
        process = BENCH.subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=BENCH.subprocess.DEVNULL,
            stdout=BENCH.subprocess.PIPE,
            stderr=BENCH.subprocess.PIPE,
            start_new_session=True,
        )
        assert process.stdout is not None
        child = int(process.stdout.readline().decode("ascii").strip())
        self.assertTrue(live_task(child))
        return process, child

    def test_term_exits_leader_but_ignored_child_is_killed_before_reap(self) -> None:
        process, child = self.spawn_term_split_group()
        started = time.monotonic()
        BENCH.stop(process)
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertIsNotNone(process.returncode)
        wait_not_live(child)

    def test_poll_observes_exited_leader_without_releasing_group_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            child_path = Path(directory) / "child"
            script = r'''
import os
from pathlib import Path
import signal
import sys
import time

path = Path(sys.argv[1])
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)
temporary = path.with_name(path.name + ".tmp")
temporary.write_text(str(child), encoding="ascii")
os.replace(temporary, path)
os._exit(0)
'''
            process = BENCH.subprocess.Popen(
                [sys.executable, "-c", script, str(child_path)],
                stdin=BENCH.subprocess.DEVNULL,
                stdout=BENCH.subprocess.PIPE,
                stderr=BENCH.subprocess.PIPE,
                start_new_session=True,
            )
            child = wait_child_pid(child_path, process=process)
            self.assertEqual(process.poll(), 0)
            self.assertTrue(live_task(child))
            # poll() observed WNOWAIT; cleanup can still use the retained zombie
            # as the original session/PGID anti-reuse anchor.
            self.assertIsNone(process.returncode)
            BENCH.stop(process)
            wait_not_live(child)

    def test_timeout_collection_is_bounded_and_does_not_contaminate_next_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            child_path = Path(directory) / "child"
            script = r'''
import os
from pathlib import Path
import signal
import sys
import time

path = Path(sys.argv[1])
child = os.fork()
if child == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)
temporary = path.with_name(path.name + ".tmp")
temporary.write_text(str(child), encoding="ascii")
os.replace(temporary, path)
os._exit(0)
'''
            started = time.monotonic()
            with self.assertRaisesRegex(BENCH.BenchmarkError, "timed out"):
                BENCH.collect(
                    [sys.executable, "-c", script, str(child_path)],
                    [],
                    timeout=2.0,
                )
            self.assertLess(time.monotonic() - started, 5.0)
            child = wait_child_pid(child_path)
            wait_not_live(child)

            frames, observation = BENCH.collect(
                [sys.executable, "-c", "pass"], [], timeout=2.0
            )
            self.assertEqual(frames, [])
            self.assertEqual(observation["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
