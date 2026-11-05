#!/usr/bin/env python3
"""Independent real-filesystem review; imports an immutable candidate snapshot.

Only temporary directories below this review directory are changed. No network,
phone, subprocess, or persistent acceptance state is used by these tests.
"""
import base64
import contextlib
import copy
import hashlib
import importlib
import itertools
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SOURCE = Path(sys.argv.pop(1)).resolve()
sys.path.insert(0, str(SOURCE))
D = importlib.import_module('daily_phone_local')
O = importlib.import_module('phone_observation_tools')
HERE = Path(__file__).resolve().parent
RUN = '20261105-220000-' + 'a' * 32
PROOFS = []


def native(raw=b'x'):
    terminal = {'kind': 'exited', 'exit_code': 0, 'error': None,
                'output_truncated': False, 'stdout_bytes': len(raw), 'stderr_bytes': 0}
    events = [{'kind': 'accepted'}, {'kind': 'started'},
              {'kind': 'output', 'stream': 'stdout', 'encoding': 'base64',
               'data': base64.b64encode(raw).decode(), 'byte_count': len(raw)},
              {'kind': 'terminal', 'terminal': copy.deepcopy(terminal)}]
    return {'call_id': 'independent', 'status': 'terminal', 'terminal': terminal,
            'events': [{'call_id': 'independent', 'tool': 'shell.exec', 'seq': i,
                        'event': event} for i, event in enumerate(events)]}


def fd_count():
    return len(os.listdir('/proc/self/fd'))


class IndependentReview(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='case-', dir=HERE)
        self.root = Path(self.temp.name) / 'evidence'
        self.root.mkdir()
        self.run = self.root / RUN
        self.run.mkdir()
        self.initial_fds = fd_count()

    def tearDown(self):
        self.assertEqual(fd_count(), self.initial_fds, 'production scanner leaked an FD')
        self.temp.cleanup()

    def put(self, name, data):
        path = self.run / name
        path.write_bytes(data)
        return path

    def at_snapshot(self, action):
        real = D.evidence_snapshot
        visits = []

        @contextlib.contextmanager
        def instrument(directory, evidence_root, *args, **kwargs):
            with real(directory, evidence_root, *args, **kwargs) as snapshot:
                if directory == self.run:
                    visits.append(directory)
                    action(snapshot, len(visits))
                yield snapshot
        return mock.patch.object(D, 'evidence_snapshot', instrument), visits

    def test_native_all_event_permutations(self):
        original = native()
        accepted = []
        for order in itertools.permutations(range(4)):
            reply = copy.deepcopy(original)
            reply['events'] = [reply['events'][i] for i in order]
            for index, row in enumerate(reply['events']):
                row['seq'] = index
            try:
                self.assertEqual(O.native_streams(reply, 'independent', 'shell.exec'), b'x')
            except O.ProviderError:
                continue
            accepted.append(order)
        self.assertEqual(accepted, [(0, 1, 2, 3)])
        zero = native(b'')
        del zero['events'][2]
        zero['events'][-1]['seq'] = 2
        self.assertEqual(O.native_streams(zero, 'independent', 'shell.exec'), b'')
        PROOFS.append({'test': self._testMethodName, 'permutations': 24, 'accepted': accepted,
                       'zero_output_success': True})

    def test_native_numeric_copies_and_unknown_event(self):
        rejected = 0
        for location in ('outer', 'nested', 'both'):
            for field, values in [('exit_code', [False, 0.0]), ('stdout_bytes', [True, 1.0]),
                                  ('stderr_bytes', [False, 0.0]), ('output_truncated', [0, 0.0])]:
                for value in values:
                    reply = native()
                    if location in ('outer', 'both'):
                        reply['terminal'][field] = value
                    if location in ('nested', 'both'):
                        reply['events'][-1]['event']['terminal'][field] = value
                    with self.assertRaises(O.ProviderError, msg=(location, field, value)):
                        O.native_streams(reply, 'independent', 'shell.exec')
                    rejected += 1
        for position in range(5):
            reply = native()
            reply['events'].insert(position, {'call_id': 'independent', 'tool': 'shell.exec',
                                             'seq': position, 'event': {'kind': 'future_event'}})
            for index, event in enumerate(reply['events']):
                event['seq'] = index
            with self.assertRaises(O.ProviderError):
                O.native_streams(reply, 'independent', 'shell.exec')
            rejected += 1
        PROOFS.append({'test': self._testMethodName, 'rejected': rejected})

    def test_real_tree_over_one_thousand_files(self):
        expected_bytes = 0
        for index in range(1200):
            directory = self.root / ('partition-%02d' % (index % 12))
            directory.mkdir(exist_ok=True)
            data = bytes([index % 251]) * (index % 97 + 1)
            (directory / ('item-%04d.bin' % index)).write_bytes(data)
            expected_bytes += len(data)
        peak_before_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        start = time.monotonic()
        actual = D.evidence_totals(self.root)
        duration = time.monotonic() - start
        peak_after_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        self.assertEqual(actual, (expected_bytes, 1200))
        PROOFS.append({'test': self._testMethodName, 'actual': actual, 'seconds': duration,
                       'process_peak_rss_before_kib': peak_before_kib,
                       'process_peak_rss_after_kib': peak_after_kib,
                       'platform': sys.platform, 'scope': 'host Linux process, not phone memory qualification'})

    def test_atomic_rename_counts_current_target_once(self):
        canonical = self.put('terminal.json', b'old')
        temporary = self.put('terminal.json.new', b'new replacement with greater length')
        expected = temporary.stat().st_size

        def rename(_snapshot, visit):
            if visit == 1:
                os.replace(temporary, canonical)
        instrument, visits = self.at_snapshot(rename)
        with instrument:
            actual = D.evidence_totals(self.root)
        self.assertEqual(actual, (expected, 1))
        self.assertEqual(len(visits), 2, 'rename requires a new complete pass')
        PROOFS.append({'test': self._testMethodName, 'totals': actual, 'directory_passes': len(visits)})

    def test_unlink_with_preexisting_canonical_is_not_rename(self):
        self.put('terminal.json', b'preexisting canonical')
        temporary = self.put('terminal.json.new', b'pending')
        instrument, _ = self.at_snapshot(lambda _snapshot, _visit: temporary.unlink())
        with instrument, self.assertRaises(RuntimeError):
            D.evidence_totals(self.root)

    def test_temporary_count_then_rename_then_canonical_count(self):
        temporary = self.put('terminal.json.new', b'new canonical after temporary was counted')
        canonical = self.put('terminal.json', b'old canonical')
        expected = temporary.stat().st_size
        real_snapshot, real_observe = D.evidence_snapshot, D.evidence_item_observation
        visits, observations, changed = [], [], []

        @contextlib.contextmanager
        def ordered_snapshot(directory, evidence_root, *args, **kwargs):
            with real_snapshot(directory, evidence_root, *args, **kwargs) as snapshot:
                if directory == self.run:
                    visits.append(True)
                    # Directory iteration order is unspecified: exercise a
                    # legitimate order where the pinned temporary comes first.
                    snapshot['entries'] = dict(sorted(snapshot['entries'].items(),
                        key=lambda pair: (pair[0] != temporary, pair[0].name)))
                yield snapshot

        def rename_after_observation(item, evidence_root, snapshot=None):
            value = real_observe(item, evidence_root, snapshot)
            if item.parent == self.run:
                observations.append(item.name)
            if item == temporary and not changed:
                changed.append(True)
                os.replace(temporary, canonical)
            return value

        with mock.patch.object(D, 'evidence_snapshot', ordered_snapshot):
            with mock.patch.object(D, 'evidence_item_observation', rename_after_observation):
                actual = D.evidence_totals(self.root)
        self.assertEqual(changed, [True])
        self.assertEqual(observations[:2], [temporary.name, canonical.name])
        self.assertEqual(len(visits), 2)
        self.assertEqual(actual, (expected, 1))
        PROOFS.append({'test': self._testMethodName, 'totals': actual,
                       'first_observations': observations[:2], 'directory_passes': len(visits)})

    def test_unlink_between_enumeration_and_open_fails(self):
        self.put('terminal.json', b'preexisting canonical')
        temporary = self.put('terminal.json.new', b'pending')
        original_open = os.open
        touched = []

        def unlink_before_open(path, flags, *args, **kwargs):
            if path == temporary.name and kwargs.get('dir_fd') is not None and not touched:
                touched.append(True)
                temporary.unlink()
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(D.os, 'open', unlink_before_open), self.assertRaises(FileNotFoundError):
            D.evidence_totals(self.root)
        self.assertEqual(touched, [True])

    def test_symlink_and_hardlink_rejected(self):
        target = self.put('target.bin', b'synthetic')
        link = self.root / 'directory-link'
        link.symlink_to(self.run, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            D.evidence_totals(self.root)
        link.unlink()
        link = self.put('temporary-placeholder', b'')
        link.unlink()
        link = self.run / 'terminal.json.new'
        link.symlink_to(target)
        with self.assertRaises((OSError, RuntimeError)):
            D.evidence_totals(self.root)
        link.unlink()
        os.link(target, self.run / 'alias.bin')
        with self.assertRaises(RuntimeError):
            D.evidence_totals(self.root)

    def test_descriptor_limit_releases_every_open_fd(self):
        for index in range(D.MAX_EVIDENCE_TEMP_FDS + 1):
            self.put('capture-%032x.json.new' % index, b'x')
        with self.assertRaisesRegex(RuntimeError, 'descriptor capacity'):
            D.evidence_totals(self.root)
        self.assertEqual(fd_count(), self.initial_fds)

    def test_global_budget_counts_small_directories_and_empty_entries(self):
        for index in range(11):
            directory = self.run / ('dir-%02d' % index)
            directory.mkdir()
            (directory / 'one').write_bytes(b'x')
        with mock.patch.object(D, 'MAX_EVIDENCE_SCAN_ENTRIES', 20):
            with self.assertRaisesRegex(RuntimeError, 'entry capacity'):
                D.evidence_totals(self.root)
        for directory in self.run.iterdir():
            (directory / 'one').unlink()
        with mock.patch.object(D, 'MAX_EVIDENCE_SCAN_ENTRIES', 11):
            with self.assertRaisesRegex(RuntimeError, 'entry capacity'):
                D.evidence_totals(self.root)

    def test_scan_retry_is_bounded_under_repeated_real_renames(self):
        canonical = self.put('terminal.json', b'old')
        temporary = self.run / 'terminal.json.new'
        real = D.evidence_snapshot
        visits = []

        @contextlib.contextmanager
        def mutate_each(directory, evidence_root, *args, **kwargs):
            if directory == self.run:
                temporary.write_bytes(b'new-' + bytes([len(visits)]))
            with real(directory, evidence_root, *args, **kwargs) as snapshot:
                if directory == self.run:
                    visits.append(True)
                    os.replace(temporary, canonical)
                yield snapshot
        with mock.patch.object(D, 'evidence_snapshot', mutate_each):
            with self.assertRaisesRegex(RuntimeError, 'bounded retry exhausted'):
                D.evidence_totals(self.root)
        self.assertEqual(len(visits), 3)

    def test_writer_lock_does_not_cover_data_fsync(self):
        canonical = self.run / 'terminal.json'
        temporary = self.run / 'terminal.json.new'
        in_fsync, release, lock_acquired = threading.Event(), threading.Event(), threading.Event()
        real_fsync = os.fsync
        errors = []

        def slow_fsync(fd):
            if threading.current_thread().name == 'independent-writer' and not in_fsync.is_set():
                in_fsync.set()
                if not release.wait(3):
                    raise TimeoutError('review release timed out')
            return real_fsync(fd)

        def writer():
            try:
                D.replace_evidence_bytes(canonical, temporary, b'controlled synthetic writer')
            except BaseException as error:
                errors.append(repr(error))

        def contender():
            with D._EVIDENCE_WRITE_LOCK:
                lock_acquired.set()

        before_active = D._EVIDENCE_WRITERS
        with mock.patch.object(D.os, 'fsync', slow_fsync):
            thread = threading.Thread(target=writer, name='independent-writer')
            thread.start()
            try:
                self.assertTrue(in_fsync.wait(2))
                other = threading.Thread(target=contender)
                other.start()
                self.assertTrue(lock_acquired.wait(1), 'data fsync held evidence lock')
                other.join(1)
                with self.assertRaisesRegex(RuntimeError, 'bounded retry exhausted'):
                    D.evidence_totals(self.root)
            finally:
                release.set()
                thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(D._EVIDENCE_WRITERS, before_active)
        self.assertEqual(D.evidence_totals(self.root), (len(b'controlled synthetic writer'), 1))
        PROOFS.append({'test': self._testMethodName, 'lock_acquired_during_data_fsync': True,
                       'active_write_scan': 'bounded fail closed', 'final_total_correct': True})


if __name__ == '__main__':
    started = time.monotonic()
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted(SOURCE.glob('*.py'))}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IndependentReview))
    record = {'source': str(SOURCE), 'source_sha256': hashes,
              'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
              'seconds': time.monotonic() - started, 'evidence': PROOFS,
              'scope': 'host-only independent review; no whole-case or phone credit'}
    (HERE / 'independent-review-final-results.json').write_text(json.dumps(record, indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
