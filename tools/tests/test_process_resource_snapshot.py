from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[2] / 'tools/perf/collect_process_resource_snapshot.py'
SPEC = importlib.util.spec_from_file_location('process_resource_snapshot', PATH)
assert SPEC and SPEC.loader
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


@contextmanager
def owned_barrier_process():
    # Actual owned process with two live threads and eight retained descriptors.
    code = """import os,sys,threading
fds=[os.open(os.devnull,os.O_RDONLY) for _ in range(8)]
release=threading.Event()
started=[threading.Event(),threading.Event()]
def worker(index):
 started[index].set();release.wait(10)
threads=[threading.Thread(target=worker,args=(i,)) for i in range(2)]
for thread in threads:thread.start()
for event in started:event.wait(2)
print('READY',flush=True)
sys.stdin.buffer.read(1)
release.set()
for thread in threads:thread.join(2)
for fd in fds:os.close(fd)
"""
    child = subprocess.Popen([sys.executable, '-B', '-c', code], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert child.stdout and child.stdin
        if not select.select([child.stdout], [], [], 3)[0] or child.stdout.readline() != b'READY\n':
            raise AssertionError('owned barrier process did not become ready')
        raw = (Path('/proc') / str(child.pid) / 'stat').read_bytes()
        ticks = OBSERVER.parse_stat(raw, child.pid)['start_ticks']
        yield child, ticks
    finally:
        if child.poll() is None:
            try:
                assert child.stdin
                child.stdin.write(b'x')
                child.stdin.flush()
                child.wait(timeout=3)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream:
                stream.close()


@unittest.skipUnless(sys.platform.startswith('linux') and Path('/proc/sys/kernel/random/boot_id').exists(),
                     'requires live Linux procfs')
class ProcessResourceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.boot_sha = hashlib.sha256(Path('/proc/sys/kernel/random/boot_id').read_bytes()).hexdigest()

    def test_actual_live_threads_and_fds_retained_without_peak_or_install_claim(self):
        with owned_barrier_process() as (child, ticks):
            result = OBSERVER.collect([(child.pid, ticks)], expected_uid=os.getuid(), boot_id_sha256=self.boot_sha)
            self.assertEqual(result['decision'], 'SOURCE_PROCESS_SNAPSHOTS_RETAINED')
            row = result['processes'][0]
            self.assertEqual(row['pid'], child.pid)
            self.assertEqual(row['start_ticks'], ticks)
            self.assertGreaterEqual(len(row['tasks']), 3)
            self.assertGreaterEqual(len(row['fd_numbers_before']), 11)
            self.assertTrue(row['task_set_stable_at_endpoints'])
            self.assertTrue(row['fd_set_stable_at_endpoints'])
            for raw in (row['raw_stat_before'], row['raw_stat_after'], row['raw_files']['status']):
                self.assertEqual(hashlib.sha256(bytes.fromhex(raw['raw_hex'])).hexdigest(), raw['sha256'])
                self.assertLessEqual(raw['start_monotonic_ns'], raw['end_monotonic_ns'])
            for key in ('selected_subject_is_installed', 'complete_process_family', 'complete_lifetime',
                        'peak_observation_complete', 'resource_contract_complete', 'production_ready', 'public_release'):
                self.assertIs(result[key], False)
            self.assertIs(row['individual_HWM_is_process_lifetime_not_sample_peak'], True)
            self.assertNotIn('fd_peak', row['observations'])

    def test_actual_generation_owner_and_boot_mismatch_rejected(self):
        with owned_barrier_process() as (child, ticks):
            for selected, uid, boot in ([(child.pid, ticks + 1)], os.getuid(), self.boot_sha), \
                                      ([(child.pid, ticks)], (os.getuid() + 1) % (1 << 32), self.boot_sha), \
                                      ([(child.pid, ticks)], os.getuid(), '0' * 64):
                with self.subTest(selected=selected, uid=uid, boot=boot):
                    with self.assertRaises(OBSERVER.SnapshotError):
                        OBSERVER.collect(selected, expected_uid=uid, boot_id_sha256=boot)

    @unittest.skipUnless(hasattr(os, 'waitid') and hasattr(os, 'WNOWAIT'), 'requires Linux WNOWAIT')
    def test_real_exit_after_fd_sweep_cannot_be_admitted_as_live_process(self):
        with owned_barrier_process() as (child, ticks):
            original = OBSERVER.names
            sweeps = 0
            observed_zombie = []

            def release_after_last_sweep(parent, maximum, budget):
                nonlocal sweeps
                result = original(parent, maximum, budget)
                if maximum == OBSERVER.MAX_FDS_PER_PROCESS:
                    sweeps += 1
                    if sweeps == 2:
                        assert child.stdin
                        child.stdin.write(b'x')
                        child.stdin.flush()
                        actual = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
                        self.assertEqual(actual.si_pid, child.pid)
                        self.assertEqual(actual.si_status, 0)
                        state = OBSERVER.parse_stat((Path('/proc') / str(child.pid) / 'stat').read_bytes(), child.pid)['state']
                        observed_zombie.append(state)
                return result

            with mock.patch.object(OBSERVER, 'names', side_effect=release_after_last_sweep):
                with self.assertRaisesRegex(OBSERVER.SnapshotError, 'process is dead'):
                    OBSERVER.collect([(child.pid, ticks)], expected_uid=os.getuid(), boot_id_sha256=self.boot_sha)
            self.assertEqual(observed_zombie, ['Z'])

    def test_actual_cli_retains_source_only_report_and_exit2_on_wrong_generation(self):
        with owned_barrier_process() as (child, ticks):
            argv = [sys.executable, '-B', str(PATH), '--subject', f'{child.pid}:{ticks}',
                    '--uid', str(os.getuid()), '--boot-id-sha256', self.boot_sha]
            result = subprocess.run(argv, capture_output=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertIs(report['complete_lifetime'], False)
            self.assertIs(report['production_ready'], False)
            argv[4] = f'{child.pid}:{ticks + 1}'
            negative = subprocess.run(argv, capture_output=True, timeout=8)
            self.assertEqual(negative.returncode, 2)
            self.assertEqual(negative.stdout, b'')
            self.assertIn(b'generation differs', negative.stderr)

    def test_actual_cli_delayed_pipe_rejects_late_visible_report(self):
        with owned_barrier_process() as (child, ticks):
            argv = [sys.executable, '-B', str(PATH), '--subject', f'{child.pid}:{ticks}',
                    '--uid', str(os.getuid()), '--boot-id-sha256', self.boot_sha, '--seconds', '2']
            with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  pipesize=4096) as observer:
                try:
                    assert observer.stdout
                    self.assertTrue(select.select([observer.stdout], [], [], 3)[0])
                    first = os.read(observer.stdout.fileno(), 1)
                    self.assertEqual(first, b'{')
                    self.assertIsNone(observer.poll())
                    # An ordinary finite sink delay holds publication, not the
                    # observed workload. The report is larger than this pipe.
                    time.sleep(2.1)
                    self.assertIsNone(observer.poll())
                    stdout, stderr = observer.communicate(timeout=3)
                    visible = first + stdout
                    self.assertGreater(len(visible), 4096)
                    self.assertEqual(json.loads(visible)['decision'], 'SOURCE_PROCESS_SNAPSHOTS_RETAINED')
                    self.assertEqual(observer.returncode, 2)
                    self.assertIn(b'observer deadline exceeded', stderr)
                finally:
                    if observer.poll() is None:
                        observer.kill()
                        observer.communicate(timeout=3)

    def test_stat_comm_parsing_handles_parentheses_newlines_and_nonascii(self):
        fields = [b'S'] + [b'0'] * 49
        fields[11], fields[12], fields[17], fields[19] = b'12', b'34', b'3', b'56'
        raw = b'42 (private ) name\n\xff) ' + b' '.join(fields) + b'\n'
        parsed = OBSERVER.parse_stat(raw, 42)
        self.assertEqual((parsed['user_ticks'], parsed['system_ticks'], parsed['threads'], parsed['start_ticks']),
                         (12, 34, 3, 56))
        with self.assertRaises(OBSERVER.SnapshotError):
            OBSERVER.parse_stat(raw, 43)
        with self.assertRaises(OBSERVER.SnapshotError):
            OBSERVER.parse_stat(b'42 (x) S 1', 42)

    def test_duplicate_memory_overflow_and_invalid_numeric_status_rejected(self):
        base = b'Pid:\t42\nTgid:\t42\nUid:\t1000 1000 1000 1000\n'
        for bad in (base + b'Pid:\t42\n', base + b'VmHWM:\t18446744073709551615 kB\n',
                    base + b'voluntary_ctxt_switches:\t0.5\n'):
            with self.subTest(raw=bad):
                with self.assertRaises(OBSERVER.SnapshotError):
                    OBSERVER.parse_status(bad, 42, 42, 1000)
        with self.assertRaises(OBSERVER.SnapshotError):
            OBSERVER.parse_io(b'read_bytes: 1\nread_bytes: 2\nwrite_bytes: 0\n')
        with self.assertRaises(OBSERVER.SnapshotError):
            OBSERVER.parse_smaps_rollup(b'Rss: 1 kB\nRss: 2 kB\n')

    def test_explicit_finite_selection_and_budget_bounds(self):
        for seconds in (True, float('nan'), float('inf'), 0, 5.01):
            with self.subTest(seconds=seconds):
                with self.assertRaises(OBSERVER.SnapshotError):
                    OBSERVER.Budget(seconds)
        for subjects in ([], [(1, 0)] * 2, [(True, 0)], [(1, 0.0)], [(1, 1 << 64)], [(1 << 31, 0)]):
            with self.subTest(subjects=subjects):
                with self.assertRaises(OBSERVER.SnapshotError):
                    OBSERVER.collect(subjects, expected_uid=os.getuid(), boot_id_sha256=self.boot_sha)

    def test_non_proc_descriptor_and_kernel_directory_count_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            with open(Path(temp) / 'status', 'wb') as f:
                f.write(b'Pid: 42\n')
            selected = OBSERVER.Directory(os.open(temp, os.O_RDONLY | os.O_DIRECTORY))
            try:
                with self.assertRaisesRegex(OBSERVER.SnapshotError, 'not kernel procfs'):
                    OBSERVER.read_file(selected, 'status', OBSERVER.Budget(1))
            finally:
                selected.close()
        with owned_barrier_process() as (child, ticks):
            budget = OBSERVER.Budget(2)
            proc = OBSERVER.open_proc(budget)
            pid = OBSERVER.open_child(proc, str(child.pid), budget)
            fds = OBSERVER.open_child(pid, 'fd', budget)
            try:
                with self.assertRaisesRegex(OBSERVER.SnapshotError, 'entry count exceeds bound'):
                    OBSERVER.names(fds, 1, budget)
            finally:
                fds.close()
                pid.close()
                proc.close()


class ProcessSnapshotPublicationTests(unittest.TestCase):
    def setUp(self):
        self.clock = 100.0
        self.time_patch = mock.patch.object(OBSERVER.time, 'monotonic', side_effect=lambda: self.clock)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)
        self.budget = OBSERVER.Budget(1)
        self.sink = mock.Mock()
        self.sink.buffer.write.side_effect = lambda raw: len(raw)
        self.stdout_patch = mock.patch.object(OBSERVER.sys, 'stdout', self.sink)
        self.stdout_patch.start()
        self.addCleanup(self.stdout_patch.stop)

    def test_complete_write_and_flush_within_original_deadline_succeeds(self):
        OBSERVER.publish_stdout({'source_only': True}, self.budget)
        self.sink.buffer.write.assert_called_once_with(b'{"source_only":true}\n')
        self.sink.buffer.flush.assert_called_once_with()

    def test_expired_budget_prevents_serialization_and_output(self):
        self.clock = 101.0
        with mock.patch.object(OBSERVER.json, 'dumps') as dumps:
            with self.assertRaisesRegex(OBSERVER.SnapshotError, 'deadline exceeded'):
                OBSERVER.publish_stdout({}, self.budget)
        dumps.assert_not_called()
        self.sink.buffer.write.assert_not_called()

    def test_slow_serialization_is_charged_before_output(self):
        def serialize(*args, **kwargs):
            self.clock = 101.0
            return '{}'
        with mock.patch.object(OBSERVER.json, 'dumps', side_effect=serialize):
            with self.assertRaisesRegex(OBSERVER.SnapshotError, 'deadline exceeded'):
                OBSERVER.publish_stdout({}, self.budget)
        self.sink.buffer.write.assert_not_called()

    def test_slow_write_or_flush_rejects_visible_bytes(self):
        for delayed in ('write', 'flush'):
            with self.subTest(delayed=delayed):
                self.clock = 100.0
                self.sink.reset_mock()
                self.sink.buffer.write.side_effect = lambda raw: len(raw)
                self.sink.buffer.flush.side_effect = None
                def expire(*args):
                    self.clock = 101.0
                    return len(args[0]) if args else None
                getattr(self.sink.buffer, delayed).side_effect = expire
                with self.assertRaisesRegex(OBSERVER.SnapshotError, 'deadline exceeded'):
                    OBSERVER.publish_stdout({}, self.budget)
                self.sink.buffer.write.assert_called_once()
                if delayed == 'write':
                    self.sink.buffer.flush.assert_not_called()
                else:
                    self.sink.buffer.flush.assert_called_once()

    def test_short_or_unknown_write_is_not_retried_or_flushed(self):
        for count in (0, 1, None, True, 4):
            with self.subTest(count=count):
                self.sink.reset_mock()
                self.sink.buffer.write.side_effect = lambda raw: count
                with self.assertRaisesRegex(OBSERVER.SnapshotError, 'write incomplete'):
                    OBSERVER.publish_stdout({}, self.budget)
                self.sink.buffer.write.assert_called_once()
                self.sink.buffer.flush.assert_not_called()

    def test_publication_errors_and_cancellation_propagate_without_retry(self):
        for stage in ('write', 'flush'):
            for failure in (BrokenPipeError('closed sink'), KeyboardInterrupt()):
                with self.subTest(stage=stage, failure=type(failure).__name__):
                    self.sink.reset_mock()
                    self.sink.buffer.write.side_effect = lambda raw: len(raw)
                    self.sink.buffer.flush.side_effect = None
                    getattr(self.sink.buffer, stage).side_effect = failure
                    with self.assertRaises(type(failure)):
                        OBSERVER.publish_stdout({}, self.budget)
                    self.sink.buffer.write.assert_called_once()
                    if stage == 'flush':
                        self.sink.buffer.flush.assert_called_once()

    def test_report_byte_limit_precedes_output(self):
        with mock.patch.object(OBSERVER, 'MAX_REPORT_BYTES', 2):
            with self.assertRaisesRegex(OBSERVER.SnapshotError, 'report byte bound'):
                OBSERVER.publish_stdout({}, self.budget)
        self.sink.buffer.write.assert_not_called()

    def test_main_carries_collection_budget_into_publication(self):
        budgets = []
        def collect(subjects, *, expected_uid, boot_id_sha256, budget):
            budgets.append(budget)
            self.clock = 100.75
            return {'source_only': True}
        def publish(document, budget):
            self.assertIs(budget, budgets[0])
            self.assertEqual(budget.deadline, 101.0)
            self.clock = 101.0
            budget.check()
        argv = [str(PATH), '--subject', '42:1', '--uid', '1000',
                '--boot-id-sha256', '0' * 64, '--seconds', '1']
        with mock.patch.object(OBSERVER.sys, 'argv', argv), \
                mock.patch.object(OBSERVER, '_collect_with_budget', side_effect=collect), \
                mock.patch.object(OBSERVER, 'publish_stdout', side_effect=publish), \
                mock.patch.object(OBSERVER.sys, 'stderr', io.StringIO()) as stderr:
            self.assertEqual(OBSERVER.main(), 2)
            self.assertIn('observer deadline exceeded', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
