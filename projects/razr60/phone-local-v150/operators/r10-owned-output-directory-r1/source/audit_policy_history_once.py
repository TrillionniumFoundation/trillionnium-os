#!/usr/bin/env python3
"""One fixed Mac host re-verification of the original property-policy adoption.

All historical source and data files are read only.  The original verifier's
verify_adoption function is called once using complete original byte bodies.
This program creates only a new, independently named host evidence directory.
It cannot apply policy, touch the phone, allocate a native epoch, or retry.
External owned-process capture and Root review are still required authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types

BASE = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/'
            'stock16-hepta-local-model-Root-v150-r1')
SOURCE = BASE/'epoch-policy-history-audit-source-1ad3-01/audit_policy_history_once.py'
OUT = BASE/'epoch-policy-history-audit-1ad3-01'
ADOPTION = {'path': str(BASE/'policy-runtime-properties-r10-live-02/POLICY-ADOPTION.json'),
            'bytes': 208226,
            'sha256': '527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'}
VERIFIER = {'path': str(BASE/'policy-runtime-properties-r10-independent-host-verifier-r1-candidate01/'
                        'source/policy_runtime_properties_verifier.py'),
            'bytes': 126796,
            'sha256': '74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
LIMITS = {'seconds': 90, 'original_paths': 555, 'original_unique_bytes': 32*1024*1024,
          'physical_read_bytes': 64*1024*1024, 'file_bytes': 16*1024*1024,
          'source_bytes': 131072, 'parent_depth': 48, 'directory_observations': 2048,
          'owned_fds': 64,
          'output_total_bytes': 1536*1024, 'readset_bytes': 1024*1024,
          'policy_summary_bytes': 65536, 'intent_bytes': 32768,
          'result_bytes': 32768, 'failure_bytes': 32768, 'stdout_bytes': 65536}
EXPECTED_SUMMARY = {
    'current_adoption_sha256': ADOPTION['sha256'],
    'runtime_policy': {'bytes': 2667740,
        'sha256': 'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'},
    'retirement_sha256': 'b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90',
    'prior_boundary_sha256': 'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
    'root_scope_decision_sha256': '5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132',
    'parent_adoption_sha256': 'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5',
    'verification_original_count': 554, 'verification_original_bytes': 31518321,
    'service_start_admitted': False, 'component_qualified': False, 'phone_calls': 0,
    'policy_writes': 0}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    need(type(raw) is bytes, 'original bytes required')
    return hashlib.sha256(raw).hexdigest()


def bare(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False)+'\n').encode('utf-8', 'strict')


def strict(raw):
    need(type(raw) is bytes and len(raw) <= LIMITS['file_bytes'], 'bounded JSON bytes required')
    def pairs(items):
        result = {}
        for key, item in items:
            need(type(key) is str and key not in result, 'duplicate JSON field')
            result[key] = item
        return result
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
        parse_constant=lambda _: need(False, 'nonfinite JSON value'))


def same(left, right):
    return encoded(left) == encoded(right)


def metadata(st):
    return [getattr(st, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def exact3(row):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'exact original descriptor required')
    path = Path(row['path'])
    need(type(row['path']) is str and path.is_absolute() and str(path) == row['path']
         and '..' not in path.parts and '\0' not in row['path'] and '//' not in row['path']
         and len(row['path'].encode()) <= 4096 and len(path.parts) <= LIMITS['parent_depth'],
         'canonical bounded original path required')
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= LIMITS['file_bytes']
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'bounded original size/SHA required')
    need(path.is_relative_to(BASE), 'only the fixed original Mac evidence namespace is readable')
    return path


class Budget:
    def __init__(self):
        self.started = time.monotonic()
        self.physical_read_bytes = 0
        self.output_bytes = 0
        self.peak_owned_fds = 0
        self.owned_output_fds = 0
        self.directories = {}

    def check(self):
        need(time.monotonic()-self.started <= LIMITS['seconds'], 'single fixed host audit deadline exceeded')

    def read_charge(self, count):
        need(type(count) is int and count >= 0, 'invalid physical read count')
        self.physical_read_bytes += count
        need(self.physical_read_bytes <= LIMITS['physical_read_bytes'], 'single physical read pool exceeded')
        self.check()

    def read_limit(self, requested):
        self.check()
        need(type(requested) is int and requested > 0, 'positive bounded read request required')
        result = min(requested, LIMITS['physical_read_bytes']-self.physical_read_bytes)
        need(result > 0, 'physical read pool exhausted before read')
        return result

    def output_reserve(self, count):
        need(type(count) is int and count >= 0, 'invalid output charge')
        need(self.output_bytes+count <= LIMITS['output_total_bytes'], 'owned output pool exceeded before write')
        self.output_bytes += count
        self.check()

    def fd_reserve(self, additional):
        count = self.owned_output_fds + additional
        need(type(additional) is int and additional >= 0 and count <= LIMITS['owned_fds'],
             'fixed owned FD bound exceeded before open')
        self.peak_owned_fds = max(self.peak_owned_fds, count)


def close_fds(fds):
    first = None
    while fds:
        fd = fds.pop()
        try:
            os.close(fd)
        except OSError as error:
            if first is None:
                first = error
    if first is not None:
        raise first


def parent_chain(path, budget, *, additional_fds=0):
    budget.check()
    fds = []
    chain = []
    try:
        budget.fd_reserve(additional_fds+1)
        root = os.open('/', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        fds.append(root)
        chain.append(('/', metadata(os.fstat(root))))
        current = Path('/')
        for part in path.parent.parts[1:]:
            budget.check()
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            need(stat.S_ISDIR(before.st_mode), 'ordinary source ancestor is not a directory')
            budget.fd_reserve(additional_fds+len(fds)+1)
            fd = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                         dir_fd=fds[-1])
            fds.append(fd)
            current /= part
            need(metadata(os.fstat(fd)) == metadata(before), 'source ancestor changed at open')
            chain.append((str(current), metadata(before)))
        need(len(fds)+1 <= LIMITS['parent_depth']+1, 'owned source FD bound exceeded')
        return fds, chain
    except BaseException:
        close_fds(fds)
        raise


def recheck_parents(path, fds, chain, budget):
    budget.check()
    need(len(fds) == len(chain), 'owned directory chain changed')
    for index, (named, expected) in enumerate(chain):
        need(metadata(os.fstat(fds[index])) == expected, 'held ordinary parent changed')
        if index:
            actual = os.stat(Path(named).name, dir_fd=fds[index-1], follow_symlinks=False)
            need(metadata(actual) == expected, 'named ordinary parent changed')
    other, reopened = parent_chain(path, budget, additional_fds=len(fds)+1)
    try:
        need(reopened == chain, 'canonical ordinary parent chain changed')
        named_leaf = os.stat(path.name, dir_fd=other[-1], follow_symlinks=False)
        budget.fd_reserve(len(fds)+len(other)+1)
        need(len(fds)+len(other)+1 <= 2*LIMITS['parent_depth']+1,
             'canonical bookend FD bound exceeded')
        return metadata(named_leaf)
    finally:
        close_fds(other)


def read_original(row, budget, *, expected_metadata=None):
    path = exact3(row)
    budget.check()
    parents, chain = parent_chain(path, budget)
    fd = None
    try:
        first = os.stat(path.name, dir_fd=parents[-1], follow_symlinks=False)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == row['bytes'],
             'original regular file identity differs before open')
        need(first.st_uid == os.geteuid() and not stat.S_IMODE(first.st_mode) & 0o022,
             'original owner/write permissions differ')
        identity = metadata(first)
        if expected_metadata is not None:
            need(same(identity, expected_metadata), 'historical original full9 changed')
        budget.fd_reserve(len(parents)+1)
        fd = os.open(path.name, os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,
                     dir_fd=parents[-1])
        need(metadata(os.fstat(fd)) == identity, 'opened original changed identity')
        parts = []
        total = 0
        while True:
            budget.check()
            raw = os.read(fd, budget.read_limit(min(65536, row['bytes']-total+1)))
            budget.read_charge(len(raw))
            if not raw:
                break
            parts.append(raw)
            total += len(raw)
            need(total <= row['bytes'], 'original grew past its exact length')
        raw = b''.join(parts)
        need(bare(raw) == {key: row[key] for key in ('bytes', 'sha256')}, 'complete original bytes differ')
        need(metadata(os.fstat(fd)) == identity
             and metadata(os.stat(path.name, dir_fd=parents[-1], follow_symlinks=False)) == identity,
             'held/named original bookend differs')
        need(recheck_parents(path, parents, chain, budget) == identity, 'canonical leaf full9 differs')
        # The full9 chain is an actual observation. It is not a claim that all
        # input FDs stayed open during the entire pure verification.
        for named, observed in chain:
            if named in budget.directories:
                need(budget.directories[named] == observed, 'historical parent changed across reads')
            else:
                budget.directories[named] = observed
                need(len(budget.directories) <= LIMITS['directory_observations'],
                     'directory observation bound exceeded')
        return raw, {**row, 'metadata': identity}
    finally:
        close_fds(parents+([fd] if fd is not None else []))


def observe_source_pin(budget):
    # Only this fixed new source may be observed without an already supplied
    # digest. Its authority is the independent caller/source manifest, not this
    # observation. Even the first digest read uses a nonblocking owned FD.
    parents, chain = parent_chain(SOURCE, budget)
    fd = None
    try:
        first = os.stat(SOURCE.name, dir_fd=parents[-1], follow_symlinks=False)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1
             and first.st_uid == os.geteuid() and not stat.S_IMODE(first.st_mode) & 0o022
             and 0 < first.st_size <= LIMITS['source_bytes'], 'bounded actual auditor source required')
        identity = metadata(first)
        budget.fd_reserve(len(parents)+1)
        fd = os.open(SOURCE.name, os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,
                     dir_fd=parents[-1])
        need(metadata(os.fstat(fd)) == identity, 'auditor source changed at open')
        parts = []
        total = 0
        while True:
            budget.check()
            part = os.read(fd, budget.read_limit(min(65536, first.st_size-total+1)))
            budget.read_charge(len(part))
            if not part:
                break
            total += len(part)
            need(total <= first.st_size, 'source exceeded exact initial size')
            parts.append(part)
        raw = b''.join(parts)
        need(len(raw) == first.st_size and metadata(os.fstat(fd)) == identity
             and recheck_parents(SOURCE, parents, chain, budget) == identity,
             'complete first source observation differs')
        return raw, identity
    finally:
        close_fds(parents+([fd] if fd is not None else []))


class OwnedOutput:
    def __init__(self, budget):
        self.budget = budget
        self.parent_fds, self.parent_chain = parent_chain(OUT, budget)
        self.fd = None
        self.members = {}
        try:
            try:
                os.stat(OUT.name, dir_fd=self.parent_fds[-1], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('fixed audit output already exists; no retry or new suffix')
            self.budget.fd_reserve(len(self.parent_fds)+1)
            os.mkdir(OUT.name, 0o700, dir_fd=self.parent_fds[-1])
            os.fsync(self.parent_fds[-1])
            self.fd = os.open(OUT.name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                              dir_fd=self.parent_fds[-1])
            self.identity = metadata(os.fstat(self.fd))
            self.budget.owned_output_fds = len(self.parent_fds)+1
            self.budget.fd_reserve(0)
            need(self.identity == metadata(os.stat(OUT.name, dir_fd=self.parent_fds[-1], follow_symlinks=False))
                 and self.identity[3] == os.geteuid() and stat.S_IMODE(self.identity[2]) == 0o700
                 and os.listdir(self.fd) == [], 'new owned evidence directory binding differs')
            # mkdir changes the immediate parent. Start the immutable
            # parent bookend only after that owned creation has completed.
            self.parent_chain = [(name, metadata(os.fstat(fd)))
                for fd, (name, _) in zip(self.parent_fds, self.parent_chain)]
        except BaseException:
            self.close()
            raise

    def check(self, *, verify_bodies=False):
        self.budget.check()
        current = metadata(os.fstat(self.fd))
        named = metadata(os.stat(OUT.name, dir_fd=self.parent_fds[-1], follow_symlinks=False))
        # Own member creation can change directory nlink, size and timestamps.
        # Keep device/inode/type+permissions/uid/gid fixed; current held/named
        # full9, the exact member set and every leaf's full9/nlink checks remain.
        need(current == named and current[:5] == self.identity[:5]
             and sorted(os.listdir(self.fd)) == sorted(self.members), 'owned output directory changed')
        reopened, chain = parent_chain(OUT, self.budget)
        try:
            need(len(reopened) == len(self.parent_fds)
                 and all(metadata(os.fstat(left)) == metadata(os.fstat(right)) == expected
                         for left, right, (_, expected) in zip(
                             self.parent_fds, reopened, self.parent_chain))
                 and metadata(os.stat(OUT.name, dir_fd=reopened[-1], follow_symlinks=False)) == current,
                 'owned output canonical path differs')
        finally:
            close_fds(reopened)
        for name, row in self.members.items():
            need(metadata(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == row['metadata'],
                 'already written output member changed identity')
            if verify_bodies:
                self.readback(name, row)

    def readback(self, name, row):
        self.budget.fd_reserve(1)
        read_fd = os.open(name, os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,
                          dir_fd=self.fd)
        try:
            need(metadata(os.fstat(read_fd)) == row['metadata'], 'new output changed before readback')
            parts = []
            total = 0
            while True:
                self.budget.check()
                part = os.read(read_fd, self.budget.read_limit(min(65536, row['bytes']-total+1)))
                self.budget.read_charge(len(part))
                if not part:
                    break
                total += len(part)
                need(total <= row['bytes'], 'owned output grew during readback')
                parts.append(part)
            raw = b''.join(parts)
            need(bare(raw) == {key: row[key] for key in ('bytes', 'sha256')}
                 and metadata(os.fstat(read_fd)) == row['metadata']
                 and metadata(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == row['metadata'],
                 'complete owned output readback differs')
            return raw
        finally:
            os.close(read_fd)

    def put(self, name, raw, maximum):
        need(type(name) is str and re.fullmatch(r'[A-Z-]+\.json', name)
             and name not in self.members and type(raw) is bytes and len(raw) <= maximum,
             'fixed bounded create-only output required')
        self.check()
        self.budget.output_reserve(len(raw))
        self.budget.fd_reserve(1)
        fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            written = 0
            while written < len(raw):
                self.budget.check()
                count = os.write(fd, raw[written:written+65536])
                need(count > 0, 'owned output write made no progress')
                written += count
            os.fsync(fd)
            info = metadata(os.fstat(fd))
            need(stat.S_ISREG(info[2]) and info[5] == 1 and info[6] == len(raw)
                 and info == metadata(os.stat(name, dir_fd=self.fd, follow_symlinks=False)),
                 'owned output write/bookend differs')
        finally:
            os.close(fd)
        os.fsync(self.fd)
        row = {'path': str(OUT/name), **bare(raw), 'metadata': info}
        self.members[name] = row
        self.check()
        need(self.readback(name, row) == raw, 'owned output complete bytes differ')
        self.check()
        return row

    def close(self):
        first = None
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError as error:
                first = error
            self.fd = None
        try:
            close_fds(self.parent_fds)
        except OSError as error:
            if first is None:
                first = error
        if first is not None:
            raise first
        self.budget.owned_output_fds = 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--execute-fixed-history-audit-once', action='store_true', required=True)
    args = parser.parse_args()
    need(args.execute_fixed_history_audit_once and Path(__file__) == SOURCE
         and sys.platform == 'darwin' and os.geteuid() == 501,
         'one actual fixed Mac source entry is required')
    os.umask(0o077)
    budget = Budget()
    output = None
    completed = False
    phase = 'new-owned-output'
    old_handler = signal.getsignal(signal.SIGALRM)
    def alarm(signum, frame):
        raise TimeoutError('fixed host audit alarm expired')
    signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, LIMITS['seconds'])
    try:
        output = OwnedOutput(budget)
        # The source pin is independently supplied by the reviewed caller and
        # later action authority. This self-read is a full9/byte observation,
        # never an authorization based on a self-reported source hash.
        source_probe, source_first = observe_source_pin(budget)
        source_raw, source_original = read_original({'path': str(SOURCE), **bare(source_probe)}, budget,
                                                     expected_metadata=source_first)
        intent = output.put('INTENT.json', encoded({
            'schema': 'hepta.native-guard.policy-history-host-audit-intent.v1',
            'source': source_original, 'adoption': ADOPTION, 'original_verifier': VERIFIER,
            'out': str(OUT), 'argv': [str(SOURCE), '--execute-fixed-history-audit-once'],
            'limits': LIMITS, 'original_verifier_function': 'verify_adoption',
            'original_main_calls': 0, 'phone_calls': 0, 'policy_writes': 0,
            'new_nonce_or_lease': False, 'automatic_retry': False}), LIMITS['intent_bytes'])
        phase = 'complete-original-inputs'
        adoption_raw, adoption_original = read_original(ADOPTION, budget)
        adoption = strict(adoption_raw)
        need(adoption['schema'] == 'hepta.runtime-properties-r10.policy-adoption.v1'
             and adoption['boot_id'] == BOOT and type(adoption['verification_originals']) is list,
             'fixed original adoption identity differs')
        rows = adoption['verification_originals']
        need(len(rows) == 554 and len({row['path'] for row in rows}) == 554
             and sum(row['bytes'] for row in rows) == 31518321,
             'complete original554 descriptor domain differs')
        need(sum(row['bytes'] for row in rows)*2 + ADOPTION['bytes']*2 + LIMITS['source_bytes']*3
             + 2*LIMITS['output_total_bytes']
             <= LIMITS['physical_read_bytes'], 'complete planned physical read cost exceeds source limit')
        cache = {}
        originals = {}
        rows_by_path = {}
        callback_counts = {}
        for row in rows:
            path = str(exact3(row))
            raw, original = read_original(row, budget)
            digest = row['sha256']
            if digest in cache:
                need(cache[digest] == raw, 'same digest supplied different original bytes')
            else:
                cache[digest] = raw
                need(sum(len(body) for body in cache.values()) <= LIMITS['original_unique_bytes'],
                     'one original unique-byte pool exceeded')
            originals[path] = original
            rows_by_path[path] = row
            callback_counts[path] = 0
        need(len(cache) == 332 and sum(map(len, cache.values())) == 23893406,
             'fixed original SHA union differs')
        need(same(rows_by_path[VERIFIER['path']], VERIFIER), 'actual original verifier row differs')
        phase = 'one-original-pure-verification'
        def get(row):
            budget.check()
            path = str(exact3(row))
            need(path in rows_by_path and same(row, rows_by_path[path]), 'unlisted verification original requested')
            raw = cache[row['sha256']]
            need(bare(raw) == {key: row[key] for key in ('bytes', 'sha256')}, 'cached original bytes changed')
            callback_counts[path] += 1
            return raw
        module = types.ModuleType('reviewed_original_policy_history')
        module.__file__ = VERIFIER['path']
        module.__reviewed_source_sha256__ = VERIFIER['sha256']
        verifier_raw = cache[VERIFIER['sha256']]
        exec(compile(verifier_raw, module.__file__, 'exec', optimize=0), module.__dict__)
        summary = module.verify_adoption(adoption_raw, read_pinned=get)
        budget.check()
        need(type(summary) is dict and all(key in summary and same(summary[key], expected)
             for key, expected in EXPECTED_SUMMARY.items()), 'original verifier complete summary differs')
        need(summary['full_rule'] == adoption['full_rule']
             and summary['current_policy_adoption']['bytes'] == ADOPTION['bytes']
             and summary['current_policy_adoption']['sha256'] == ADOPTION['sha256']
             and all(value > 0 for value in callback_counts.values()),
             'original function did not consume its whole declared domain')
        phase = 'complete-final-original-bookends'
        # No file stays open implicitly between first/final passes. Each pass
        # performs complete held/named/canonical full9 and whole-body checks.
        final_rows = []
        for path in sorted(originals):
            first = originals[path]
            raw, final = read_original(rows_by_path[path], budget, expected_metadata=first['metadata'])
            need(raw == cache[first['sha256']] and same(final, first), 'final historical original differs')
            final_rows.append({'original': rows_by_path[path], 'metadata_before': first['metadata'],
                'metadata_after': final['metadata'], 'physical_complete_reads': 2,
                'verifier_callback_reads': callback_counts[path]})
        final_adoption, after_adoption = read_original(ADOPTION, budget,
            expected_metadata=adoption_original['metadata'])
        need(final_adoption == adoption_raw and same(after_adoption, adoption_original), 'adoption changed')
        final_source, after_source = read_original({key: source_original[key]
            for key in ('path', 'bytes', 'sha256')}, budget, expected_metadata=source_original['metadata'])
        need(final_source == source_raw and same(after_source, source_original), 'audit source changed')
        readset_value = {'schema': 'hepta.native-guard.policy-history-complete-readset.v1',
            'adoption': {'original': ADOPTION, 'metadata_before': adoption_original['metadata'],
                         'metadata_after': after_adoption['metadata'], 'physical_complete_reads': 2},
            'verification_originals': final_rows, 'directories': [
                {'path': path, 'metadata': budget.directories[path]} for path in sorted(budget.directories)],
            'physical_read_bytes_through_input_rechecks': budget.physical_read_bytes,
            'unique_original_bytes': sum(map(len, cache.values())),
            'unique_original_objects': len(cache), 'descriptor_path_bytes': 31518321,
            'original_paths': 555, 'peak_owned_read_fds': budget.peak_owned_fds,
            'all_actual_reads_complete_and_bookended': True,
            'all_input_fds_held_through_entire_audit': False,
            'actual_source': source_original, 'actual_context': 'mac',
            'phone_metadata_substituted': False, 'originals_modified': False,
            'phone_calls': 0, 'policy_writes': 0}
        readset_raw = encoded(readset_value)
        summary_raw = encoded(summary)
        need(len(readset_raw) <= LIMITS['readset_bytes']
             and len(summary_raw) <= LIMITS['policy_summary_bytes'], 'final output bounds exceeded before writes')
        phase = 'retain-complete-result'
        readset_row = output.put('READSET.json', readset_raw, LIMITS['readset_bytes'])
        summary_row = output.put('POLICY-SUMMARY.json', summary_raw, LIMITS['policy_summary_bytes'])
        result = {'schema': 'hepta.native-guard.policy-history-host-reconciliation.v1',
            'state': 'ORIGINAL_POLICY_ADOPTION_FUNCTION_RETURNED_AND_ALL_INPUTS_RECHECKED',
            'source': source_original, 'intent': intent, 'original_adoption': adoption_original,
            'original_verifier': originals[VERIFIER['path']], 'readset': readset_row,
            'policy_summary': summary_row, 'original_function_calls': 1,
            'original_main_calls': 0, 'input_paths': 555, 'verification_originals': 554,
            'owned_input_fds_closed_after_each_bookend': True,
            'external_owned_process_completion_still_required': True,
            'physical_read_bytes_before_result_and_final_output_rechecks': budget.physical_read_bytes,
            'limits': LIMITS,
            'elapsed_seconds': time.monotonic()-budget.started,
            'phone_calls': 0, 'policy_writes': 0, 'case_credit': 0,
            'new_nonce_or_lease': False, 'fresh_phone_clearance': False,
            'component_qualified': False, 'business_qualified': False, 'automatic_retry': False}
        result_row = output.put('RESULT.json', encoded(result), LIMITS['result_bytes'])
        output.check(verify_bodies=True)
        output.close()
        output = None
        budget.check()
        final = encoded({'schema': 'hepta.native-guard.policy-history-host-audit-summary.v1',
            'state': 'ORIGINAL_POLICY_HISTORY_RETAINED_AND_OWNED_HOST_FDS_CLOSED',
            'result': result_row, 'readset': readset_row, 'policy_summary': summary_row,
            'external_owned_process_completion_still_required': True,
            'complete_physical_read_bytes': budget.physical_read_bytes,
            'owned_output_bytes': budget.output_bytes,
            'phone_calls': 0, 'policy_writes': 0, 'case_credit': 0,
            'new_nonce_or_lease': False, 'component_qualified': False})
        need(len(final) <= LIMITS['stdout_bytes'], 'final bounded host summary differs')
        completed = True
        sys.stdout.buffer.write(final)
        sys.stdout.buffer.flush()
        return 0
    except BaseException as error:
        failure = {'schema': 'hepta.native-guard.policy-history-host-audit-failure.v1',
            'state': 'HISTORY_AUDIT_FAILED_OR_UNKNOWN_NO_RETRY', 'phase': phase,
            'error_type': type(error).__name__, 'detail': str(error)[:2000],
            'out': str(OUT), 'source': str(SOURCE), 'elapsed_seconds': time.monotonic()-budget.started,
            'physical_read_bytes': budget.physical_read_bytes, 'phone_calls': 0,
            'policy_writes': 0, 'case_credit': 0, 'automatic_retry': False,
            'history_authority_granted': False}
        raw = encoded(failure)
        if output is not None:
            try:
                output.put('FAILURE.json', raw, LIMITS['failure_bytes'])
            except BaseException as retention_error:
                failure['failure_retention_error'] = type(retention_error).__name__
        sys.stderr.buffer.write(encoded(failure)[:LIMITS['failure_bytes']])
        sys.stderr.buffer.flush()
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        if output is not None:
            output.close()
        # This is only a source-local state. Actual controller/JOIN/double EOF
        # originals are required outside this process before any consumption.
        _ = completed


if __name__ == '__main__':
    raise SystemExit(main())
