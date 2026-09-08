from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest


PATH = Path(__file__).resolve().parents[1] / "perf/run_product_baseline.py"
SPEC = importlib.util.spec_from_file_location("product_baseline_cleanup", PATH)
BENCH = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(BENCH)


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
    path.write_text(str(os.getpid()), encoding="ascii")
    while True:
        time.sleep(1)
os._exit(0)
'''
            process = BENCH.subprocess.Popen(
                [sys.executable, "-c", script, str(child_path)],
                stdin=BENCH.subprocess.DEVNULL,
                stdout=BENCH.subprocess.PIPE,
                stderr=BENCH.subprocess.PIPE,
                start_new_session=True,
            )
            deadline = time.monotonic() + 3.0
            while (not child_path.exists() or process.poll() is None) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(process.poll(), 0)
            child = int(child_path.read_text(encoding="ascii"))
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
    path.write_text(str(os.getpid()), encoding="ascii")
    while True:
        time.sleep(1)
os._exit(0)
'''
            started = time.monotonic()
            with self.assertRaisesRegex(BENCH.BenchmarkError, "timed out"):
                BENCH.collect(
                    [sys.executable, "-c", script, str(child_path)],
                    [],
                    timeout=0.2,
                )
            self.assertLess(time.monotonic() - started, 5.0)
            child = int(child_path.read_text(encoding="ascii"))
            wait_not_live(child)

            frames, observation = BENCH.collect(
                [sys.executable, "-c", "pass"], [], timeout=2.0
            )
            self.assertEqual(frames, [])
            self.assertEqual(observation["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
