#!/usr/bin/env python3
"""Retain bounded, generation-bound Linux process/task resource snapshots.

https://docs.kernel.org/filesystems/proc.html defines these kernel fields.
Selected processes must remain alive at the caller's work-end barrier. This
standalone observer never waits for, signals, stops, or changes a workload.
It does not discover descendants or prove complete lifetime coverage. Stable
endpoint task/FD sets do not establish a peak or exclude transient activity.
VmRSS is approximate; smaps_rollup is a separate sequential kernel observation.
No individual HWM is summed or presented as a simultaneous process-family peak.
Observe whole-process zero exit before admitting even a retained report. A
deadline check cannot preempt a blocked synchronous kernel syscall.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any

SCHEMA = 'org.trillionnium.linux-process-resource-snapshot.v1'
PROC_ROOT = Path('/proc')
PROC_MAGIC = 0x9FA0
U64_MAX = (1 << 64) - 1
MAX_SECONDS = 5.0
MAX_PROCESSES = 32
MAX_TASKS_PER_PROCESS = 128
MAX_TOTAL_TASKS = 256
MAX_FDS_PER_PROCESS = 4096
MAX_RAW_FILE_BYTES = 65536
MAX_TOTAL_RAW_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024


class SnapshotError(RuntimeError):
    pass


class Directory:
    """Retire a raw descriptor before its single close attempt; never retry."""
    def __init__(self, fd: int):
        self.fd: int | None = fd

    def fileno(self) -> int:
        if self.fd is None:
            raise SnapshotError('directory already closed')
        return self.fd

    def close(self) -> None:
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)


class Budget:
    def __init__(self, seconds: float):
        if type(seconds) not in (int, float) or not 0 < seconds <= MAX_SECONDS:
            raise SnapshotError('observer duration must be finite and within 0..5 seconds')
        self.deadline = time.monotonic() + seconds
        self.raw_bytes = 0
        self.tasks = 0

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise SnapshotError('observer deadline exceeded')

    def account(self, size: int) -> None:
        self.raw_bytes += size
        if self.raw_bytes > MAX_TOTAL_RAW_BYTES:
            raise SnapshotError('whole raw-kernel byte bound exceeded')
        self.check()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def identity(s: os.stat_result) -> list[int]:
    # Kernel pseudo-files have mutable contents; timestamps/size are not a seal.
    return [s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid]


def open_child(parent: Directory, name: str, budget: Budget) -> Directory:
    budget.check()
    if not name or '/' in name or name in ('.', '..'):
        raise SnapshotError('one literal directory component required')
    child = Directory(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=parent.fileno()))
    try:
        require_procfs(child.fileno())
        budget.check()
        return child
    except BaseException:
        child.close()
        raise


def require_procfs(fd: int) -> None:
    buffer = (ctypes.c_long * 64)()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.fstatfs(fd, ctypes.byref(buffer)) != 0 or buffer[0] != PROC_MAGIC:
        raise SnapshotError('selected descriptor is not kernel procfs')


def open_proc(budget: Budget) -> Directory:
    if not sys.platform.startswith('linux'):
        raise SnapshotError('Linux procfs required')
    budget.check()
    fd = Directory(os.open(PROC_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
    try:
        require_procfs(fd.fileno())
        budget.check()
        return fd
    except BaseException:
        fd.close()
        raise


def read_file(parent: Directory, name: str, budget: Budget) -> dict[str, Any]:
    budget.check()
    if '/' in name or name in ('', '.', '..'):
        raise SnapshotError('one kernel file component required')
    try:
        owner = io.FileIO(name, 'rb', opener=lambda selected, flags: os.open(
            selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent.fileno()))
    except (FileNotFoundError, PermissionError, ProcessLookupError) as error:
        return {'status': 'unavailable', 'reason': type(error).__name__}
    try:
        initial = os.fstat(owner.fileno())
        require_procfs(owner.fileno())
        entry = os.stat(name, dir_fd=parent.fileno(), follow_symlinks=False)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1 or identity(initial) != identity(entry):
            raise SnapshotError('kernel file descriptor does not match ordinary entry')
        started = time.monotonic_ns()
        pieces: list[bytes] = []
        size = 0
        while True:
            budget.check()
            block = owner.read(min(4096, MAX_RAW_FILE_BYTES + 1 - size))
            budget.check()
            if not block:
                break
            size += len(block)
            if size > MAX_RAW_FILE_BYTES:
                raise SnapshotError('kernel file byte bound exceeded')
            budget.account(len(block))
            pieces.append(block)
        raw = b''.join(pieces)
        if identity(os.fstat(owner.fileno())) != identity(initial) or identity(
                os.stat(name, dir_fd=parent.fileno(), follow_symlinks=False)) != identity(initial):
            raise SnapshotError('kernel file identity changed during read')
        return {'status': 'observed', 'raw_hex': raw.hex(), 'bytes': len(raw), 'sha256': sha256(raw),
                'identity': identity(initial), 'start_monotonic_ns': started,
                'end_monotonic_ns': time.monotonic_ns()}
    finally:
        owner.close()


def required_raw(row: dict[str, Any], name: str) -> bytes:
    if row['status'] != 'observed':
        raise SnapshotError(f'{name} unavailable: {row["reason"]}')
    return bytes.fromhex(row['raw_hex'])


def uint(raw: bytes, label: str) -> int:
    if not re.fullmatch(rb'0|[1-9][0-9]{0,19}', raw):
        raise SnapshotError(f'{label} is not a bounded unsigned integer')
    value = int(raw)
    if value > U64_MAX:
        raise SnapshotError(f'{label} exceeds uint64')
    return value


def parse_stat(raw: bytes, expected_pid: int) -> dict[str, int | str]:
    # comm may contain spaces, newlines and parentheses. The numeric suffix
    # begins after the final ') '; never split the entire stat line on spaces.
    head, separator, suffix = raw.rpartition(b') ')
    if not separator or not head.startswith(str(expected_pid).encode() + b' ('):
        raise SnapshotError('stat PID/comm framing differs')
    fields = suffix.split()
    if len(fields) < 22 or fields[0] not in (b'R', b'S', b'D', b'T', b't', b'Z', b'X', b'x', b'K', b'W', b'P', b'I'):
        raise SnapshotError('stat numeric suffix is incomplete')
    # Fields 14/15/20/22 are user/system ticks, num_threads and starttime.
    return {'pid': expected_pid, 'state': fields[0].decode('ascii'),
            'user_ticks': uint(fields[11], 'utime'), 'system_ticks': uint(fields[12], 'stime'),
            'threads': uint(fields[17], 'num_threads'), 'start_ticks': uint(fields[19], 'starttime')}


def parse_status(raw: bytes, expected_pid: int, expected_tgid: int, uid: int) -> dict[str, int]:
    selected = {'Pid', 'Tgid', 'Uid', 'voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches', 'VmRSS', 'VmHWM'}
    rows: dict[str, bytes] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(b':')
        if separator and key.decode('ascii', 'ignore') in selected:
            name = key.decode('ascii')
            if name in rows:
                raise SnapshotError('duplicate selected status field')
            rows[name] = value.strip()
    if uint(rows.get('Pid', b''), 'status Pid') != expected_pid or uint(rows.get('Tgid', b''), 'status Tgid') != expected_tgid:
        raise SnapshotError('status task/group identity differs')
    uids = rows.get('Uid', b'').split()
    if len(uids) != 4 or any(uint(v, 'status Uid') != uid for v in uids):
        raise SnapshotError('status UID tuple differs from selected owner')
    result = {name: uint(rows[name], name) for name in ('voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches') if name in rows}
    for name in ('VmRSS', 'VmHWM'):
        if name in rows:
            parts = rows[name].split()
            if len(parts) != 2 or parts[1] != b'kB':
                raise SnapshotError('status memory unit differs')
            value = uint(parts[0], name) * 1024
            if value > U64_MAX:
                raise SnapshotError('status memory byte conversion overflows')
            result[name + '_bytes'] = value
    return result


def parse_io(raw: bytes) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(b':')
        if key in (b'read_bytes', b'write_bytes') and separator:
            name = key.decode('ascii')
            if name in result:
                raise SnapshotError('duplicate selected I/O field')
            result[name] = uint(value.strip(), name)
    if set(result) != {'read_bytes', 'write_bytes'}:
        raise SnapshotError('process I/O accounting fields absent')
    return result


def parse_smaps_rollup(raw: bytes) -> int:
    rows = [line.partition(b':')[2].split() for line in raw.splitlines() if line.startswith(b'Rss:')]
    if len(rows) != 1 or len(rows[0]) != 2 or rows[0][1] != b'kB':
        raise SnapshotError('smaps_rollup Rss field differs')
    value = uint(rows[0][0], 'smaps_rollup Rss') * 1024
    if value > U64_MAX:
        raise SnapshotError('smaps_rollup RSS byte conversion overflows')
    return value


def names(parent: Directory, maximum: int, budget: Budget) -> list[int]:
    result = []
    with os.scandir(parent.fileno()) as entries:
        for entry in entries:
            budget.check()
            if not re.fullmatch(r'0|[1-9][0-9]{0,9}', entry.name):
                raise SnapshotError('non-numeric kernel directory entry')
            result.append(int(entry.name))
            if len(result) > maximum:
                raise SnapshotError('kernel directory entry count exceeds bound')
    if len(set(result)) != len(result):
        raise SnapshotError('duplicate kernel directory entry')
    return sorted(result)


def observe_process(proc: Directory, pid: int, start_ticks: int, uid: int, budget: Budget) -> dict[str, Any]:
    held = open_child(proc, str(pid), budget)
    try:
        initial = identity(os.fstat(held.fileno()))
        before = read_file(held, 'stat', budget)
        parsed = parse_stat(required_raw(before, 'initial stat'), pid)
        if parsed['start_ticks'] != start_ticks or parsed['state'] in ('Z', 'X', 'x'):
            raise SnapshotError('selected process generation differs or is dead')
        raw = {name: read_file(held, name, budget) for name in ('status', 'io', 'smaps_rollup')}
        status = parse_status(required_raw(raw['status'], 'process status'), pid, pid, uid)
        observed = dict(stat=parsed, status=status)
        if raw['io']['status'] == 'observed':
            observed['io'] = parse_io(required_raw(raw['io'], 'process io'))
        if raw['smaps_rollup']['status'] == 'observed':
            observed['smaps_rollup_rss_bytes'] = parse_smaps_rollup(required_raw(raw['smaps_rollup'], 'smaps_rollup'))
        tasks = open_child(held, 'task', budget)
        try:
            tids = names(tasks, MAX_TASKS_PER_PROCESS, budget)
            if pid not in tids:
                raise SnapshotError('leader absent from selected task directory')
            budget.tasks += len(tids)
            if budget.tasks > MAX_TOTAL_TASKS:
                raise SnapshotError('whole task count bound exceeded')
            task_rows = []
            for tid in tids:
                task = open_child(tasks, str(tid), budget)
                try:
                    stat_before = read_file(task, 'stat', budget)
                    task_stat = parse_stat(required_raw(stat_before, 'task stat'), tid)
                    if task_stat['state'] in ('Z', 'X', 'x'):
                        raise SnapshotError('selected task is dead')
                    task_status = read_file(task, 'status', budget)
                    task_values = parse_status(required_raw(task_status, 'task status'), tid, pid, uid)
                    stat_after = read_file(task, 'stat', budget)
                    final_task_stat = parse_stat(required_raw(stat_after, 'final task stat'), tid)
                    if final_task_stat['start_ticks'] != task_stat['start_ticks'] or final_task_stat['state'] in ('Z', 'X', 'x'):
                        raise SnapshotError('task generation changed or task is dead')
                    task_rows.append(dict(tid=tid, start_ticks=task_stat['start_ticks'], values=task_values,
                                          raw_stat_before=stat_before, raw_status=task_status, raw_stat_after=stat_after))
                finally:
                    task.close()
            tids_after = names(tasks, MAX_TASKS_PER_PROCESS, budget)
        finally:
            tasks.close()
        fds = open_child(held, 'fd', budget)
        try:
            fd_names = names(fds, MAX_FDS_PER_PROCESS, budget)
            fd_names_after = names(fds, MAX_FDS_PER_PROCESS, budget)
        finally:
            fds.close()
        final_status = read_file(held, 'status', budget)
        parse_status(required_raw(final_status, 'final process status'), pid, pid, uid)
        final = read_file(held, 'stat', budget)
        final_stat = parse_stat(required_raw(final, 'final process stat'), pid)
        if final_stat['start_ticks'] != start_ticks or final_stat['state'] in ('Z', 'X', 'x'):
            raise SnapshotError('process generation changed or process is dead')
        reopened = open_child(proc, str(pid), budget)
        try:
            if identity(os.fstat(reopened.fileno())) != initial or identity(os.fstat(held.fileno())) != initial:
                raise SnapshotError('PID path no longer names held process directory')
        finally:
            reopened.close()
        budget.check()
        return dict(pid=pid, start_ticks=start_ticks, expected_uid=uid, directory_identity=initial,
                    observations=observed, raw_stat_before=before, raw_files=raw, raw_stat_after=final,
                    raw_status_after=final_status, tasks=task_rows, task_ids_before=tids, task_ids_after=tids_after,
                    fd_numbers_before=fd_names, fd_numbers_after=fd_names_after,
                    task_set_stable_at_endpoints=tids == tids_after, fd_set_stable_at_endpoints=fd_names == fd_names_after,
                    individual_HWM_is_process_lifetime_not_sample_peak=True,
                    complete_lifetime_or_descendant_coverage=False, peak_observation_complete=False)
    finally:
        held.close()


def collect(subjects: list[tuple[int, int]], *, expected_uid: int, boot_id_sha256: str, seconds: float = 5.0) -> dict[str, Any]:
    budget = Budget(seconds)
    if type(expected_uid) is not int or not 0 <= expected_uid < 1 << 32:
        raise SnapshotError('explicit uint32 process owner UID required')
    if not isinstance(boot_id_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', boot_id_sha256):
        raise SnapshotError('explicit expected boot-ID SHA256 required')
    if not isinstance(subjects, list) or not 0 < len(subjects) <= MAX_PROCESSES:
        raise SnapshotError('select 1..32 explicit process generations')
    if any(not isinstance(s, tuple) or len(s) != 2 or type(s[0]) is not int or type(s[1]) is not int
           or not 0 < s[0] < 1 << 31 or not 0 <= s[1] <= U64_MAX for s in subjects):
        raise SnapshotError('each subject must be exact integer PID/start-ticks')
    if len({s[0] for s in subjects}) != len(subjects):
        raise SnapshotError('duplicate selected PID')
    started = time.monotonic_ns()
    proc = open_proc(budget)
    directories = [proc]
    try:
        current = proc
        for name in ('sys', 'kernel', 'random'):
            current = open_child(current, name, budget)
            directories.append(current)
        boot_before = read_file(current, 'boot_id', budget)
        boot_raw = required_raw(boot_before, 'boot ID')
        if not re.fullmatch(rb'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n', boot_raw) or sha256(boot_raw) != boot_id_sha256:
            raise SnapshotError('boot identity differs')
        rows = [observe_process(proc, pid, ticks, expected_uid, budget) for pid, ticks in subjects]
        boot_after = read_file(current, 'boot_id', budget)
        if required_raw(boot_after, 'final boot ID') != boot_raw:
            raise SnapshotError('boot identity changed')
        clock_ticks = os.sysconf('SC_CLK_TCK')
        if type(clock_ticks) is not int or not 0 < clock_ticks <= 1_000_000_000:
            raise SnapshotError('kernel clock-tick frequency unavailable')
        document = dict(schema=SCHEMA, decision='SOURCE_PROCESS_SNAPSHOTS_RETAINED',
                        observed_at_utc=datetime.now(timezone.utc).isoformat(), start_monotonic_ns=started,
                        end_monotonic_ns=time.monotonic_ns(), clock_ticks_per_second=clock_ticks,
                        boot_id_before=boot_before, boot_id_after=boot_after, processes=rows,
                        selected_subjects=subjects, selected_subject_is_installed=False,
                        same_namespace_procfs_only=True, complete_process_family=False, complete_lifetime=False,
                        runtime_stages_observed=False, resource_contract_complete=False,
                        caller_work_end_barrier_verified=False, peak_observation_complete=False,
                        observer_zero_exit_required=True, production_ready=False, public_release=False,
                        semantics=dict(cpu='Cumulative kernel tick fields; no child or interval attribution is inferred.',
                                       context_switches='Per-live-task raw fields; exited/transient threads remain uncovered.',
                                       io='Selected process cumulative raw read_bytes/write_bytes; no sample delta is inferred.',
                                       rss='VmRSS is approximate. smaps_rollup is a separate sequential observation.',
                                       peaks='Individual VmHWM is lifetime-scoped. Stable task/FD endpoints prove no peak.',
                                       membership='Explicit PID/start-ticks selections do not prove descendant or installation coverage.'))
        document['content_sha256'] = sha256(json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
        if len(json.dumps(document, sort_keys=True, allow_nan=False).encode()) > MAX_REPORT_BYTES:
            raise SnapshotError('report byte bound exceeded')
        budget.check()
    finally:
        for directory in reversed(directories):
            directory.close()
    budget.check()
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subject', action='append', required=True, metavar='PID:START_TICKS')
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--boot-id-sha256', required=True)
    parser.add_argument('--seconds', type=float, default=MAX_SECONDS)
    args = parser.parse_args()
    try:
        subjects = []
        for value in args.subject:
            if not re.fullmatch(r'[1-9][0-9]{0,9}:(?:0|[1-9][0-9]{0,19})', value):
                raise SnapshotError('subject must be PID:START_TICKS')
            pid, ticks = value.split(':')
            subjects.append((int(pid), int(ticks)))
        result = collect(subjects, expected_uid=args.uid, boot_id_sha256=args.boot_id_sha256, seconds=args.seconds)
        raw = (json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if len(raw) > MAX_REPORT_BYTES:
            raise SnapshotError('report byte bound exceeded')
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return 0
    except (SnapshotError, OSError, ValueError) as error:
        print('process resource observer: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
