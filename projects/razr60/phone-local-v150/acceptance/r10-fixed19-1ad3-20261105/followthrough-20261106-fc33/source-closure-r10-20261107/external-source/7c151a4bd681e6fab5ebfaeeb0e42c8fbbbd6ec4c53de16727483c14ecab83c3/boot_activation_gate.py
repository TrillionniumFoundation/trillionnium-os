#!/usr/bin/env python3
"""Read-only boot-aware activation, then the explicitly derived ledger verifier.

This program does not retire processes, create task resolutions, or authorize
replay. The outer sealed module checks Enforcing, policy and all source pins.
"""
import errno
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import MappingProxyType

BASE = Path('/var/lib/trillionnium/owner-open/phone-local-v150')
PAYLOAD = BASE / 'module-r10-activation-r1'
ORIGINAL = BASE / 'module-r5-activation/activation_original_gate.py'
ORIGINAL_SHA = '23ec1ee206635c0ce0b2dc28ca8281d4e5523d6245eac453b58531c708e1d68e'
ORIGINAL_BYTES = 15700
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
GONE = frozenset((errno.ENOENT, errno.ESRCH))
NATIVE_NS = ('cgroup', 'mnt', 'net', 'time', 'time_for_children', 'uts')
PF_KTHREAD = 0x00200000
GENERATION_PROOFS = {
    'R5-R3-ORIGINAL-RETIREMENT-PREFLIGHT.json': {
        'bytes': 13397, 'sha256': 'ed14d3bb3595ea167a7d8f7d82607b174b5e5c5fd4a850822a688331cf3834e3'},
    'R5-R3-REMAINING-ROLES-RECOVERY-RESULT.json': {
        'bytes': 10072, 'sha256': '09c620283732b0cb27c2f0f5adf88f6a7aea043516a0a36a470fdb39af7204cf'},
    'R5-R3-ACTUAL-REMAINING-RECOVERY-CAPTURE.json': {
        'bytes': 39439, 'sha256': '350f4119ef402229e18c2b25c9f2f9f7fc2217a87f356efd30a806e4eeaca687'},
}
# A bounded, explicitly reviewed exception for one documented PID generation.
# It never permits an old numeric PGID/SID, or a user process with this PID.
KERNEL_REUSE = {
    'profile': 'r5-r3-provider-retired-kernel-pid-reuse-v1',
    'pid': 13806, 'retired_start_ticks': 8351076,
    'originals': GENERATION_PROOFS,
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_json_key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')))


def identity(info):
    return tuple(getattr(info, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def private_read(path, limit, pin=None, size=None):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
            'noncanonical_private_parent')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and 0 < before.st_size <= limit, 'private_file_identity')
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after, named = os.fstat(fd), path.lstat()
        require(identity(before) == identity(after) == identity(named)
                and len(raw) == before.st_size, 'private_file_changed')
    finally:
        os.close(fd)
    require(size is None or len(raw) == size, 'private_file_size_pin')
    require(pin is None or hashlib.sha256(raw).hexdigest() == pin, 'private_file_sha_pin')
    return bytes(raw)


def parse_stat(raw, pid):
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536, 'proc_stat_size')
    require(raw.startswith(str(pid).encode() + b' (') and b') ' in raw, 'proc_stat_shape')
    tail = raw.rsplit(b') ', 1)[1].split()
    require(len(tail) >= 20 and len(tail[0]) == 1, 'proc_stat_fields')
    values = []
    for index in (1, 2, 3, 6, 19):
        require(tail[index].isdigit(), 'proc_stat_numeric')
        values.append(int(tail[index]))
    return dict(pid=pid, ppid=values[0], pgrp=values[1], session=values[2],
                flags=values[3], start_ticks=values[4],
                state=tail[0].decode('ascii'))


class ProcView:
    """The only production process reader. No caller-selected proc root."""
    @staticmethod
    def read(path, limit=65536, allow_empty=False):
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = bytearray()
            while len(raw) <= limit:
                block = os.read(fd, min(4096, limit + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            require((0 if allow_empty else 1) <= len(raw) <= limit, 'proc_read_bound')
            return bytes(raw)
        finally:
            os.close(fd)

    def boot(self):
        value = self.read('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        require(UUID.fullmatch(value) is not None, 'boot_id_format')
        return value

    def row(self, pid):
        try:
            return parse_stat(self.read('/proc/' + str(pid) + '/stat'), pid)
        except OSError as error:
            if error.errno in GONE:
                return None
            raise

    @staticmethod
    def pids():
        with os.scandir('/proc') as entries:
            return sorted(int(e.name) for e in entries if e.name.isascii() and e.name.isdigit())

    @staticmethod
    def link(path):
        return os.readlink(path)

    @staticmethod
    def names(path):
        with os.scandir(path) as entries:
            return tuple(sorted(entry.name for entry in entries))

    @staticmethod
    def own_identity():
        return os.getpid(), os.getpgrp(), os.getsid(0)

    def native_view(self):
        require(Path('/proc').resolve(strict=True) == Path('/proc'), 'proc_not_canonical')
        mounts = self.read('/proc/self/mountinfo', 1024 * 1024).decode('ascii').splitlines()
        proc_mounts = [line.split() for line in mounts if len(line.split()) > 6
                       and line.split()[4] == '/proc']
        require(len(proc_mounts) == 1 and ' - proc ' in ' '.join(proc_mounts[0]),
                'proc_mount_not_native_procfs')
        require(self.link('/proc/1/exe') == '/system/bin/init', 'native_init_exe')
        domain = self.read('/proc/1/attr/current', 256).rstrip(b'\x00\n')
        require(domain == b'u:r:init:s0', 'native_init_domain')
        init = self.row(1)
        require(init is not None and init['start_ticks'] == 0 and init['state'] != 'Z',
                'native_init_identity')
        pid, pgrp, session = self.own_identity()
        require(self.link('/proc/self') == str(pid), 'proc_self_link')
        own = self.row(pid)
        require(own is not None and (own['pid'], own['pgrp'], own['session']) == (pid, pgrp, session)
                and own['state'] != 'Z', 'own_proc_identity')
        # This kernel has CONFIG_PID_NS absent. Only the observed ENOENT pair
        # with the exact supported namespace entries is accepted. EACCES,
        # EPERM, EIO, a missing directory, or a newly present pid entry fail.
        for root in ('/proc/1/ns', '/proc/self/ns'):
            require(self.names(root) == NATIVE_NS, 'native_namespace_inventory')
            try:
                self.link(root + '/pid')
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
            else:
                raise ValueError('unexpected_pid_namespace_support')
        return own


def validate_binding(binding):
    require(set(binding) == {'schema', 'retirement_boot_id', 'retired_groups',
                            'same_boot_anchors', 'native_proc_profile', 'ledger_verifier',
                            'same_boot_kernel_pid_reuse'},
            'activation_binding_fields')
    require(binding['schema'] == 'hepta.module-r10-r1.activation-binding.v1', 'binding_schema')
    require(UUID.fullmatch(binding['retirement_boot_id']) is not None, 'retirement_boot_format')
    require(binding['native_proc_profile'] == 'leap-stock16-init-no-pid-ns-v1', 'native_profile')
    require(binding['same_boot_kernel_pid_reuse'] == KERNEL_REUSE,
            'kernel_reuse_profile_or_proof_pins')
    groups = binding['retired_groups']
    require(isinstance(groups, list) and 1 <= len(groups) <= 1024 and len(set(groups)) == len(groups)
            and all(type(n) is int and n > 1 for n in groups), 'retired_group_inventory')
    require(KERNEL_REUSE['pid'] in groups, 'kernel_reuse_original_pid_missing')
    anchors = binding['same_boot_anchors']
    require(isinstance(anchors, list) and 1 <= len(anchors) <= 64, 'anchor_inventory')
    seen = set()
    for row in anchors:
        require(set(row) == {'pid', 'start_ticks'} and type(row['pid']) is int and row['pid'] > 1
                and type(row['start_ticks']) is int and row['start_ticks'] >= 0
                and row['pid'] not in seen, 'anchor_identity')
        seen.add(row['pid'])
    verifier = binding['ledger_verifier']
    require(set(verifier) == {'bytes', 'sha256'} and type(verifier['bytes']) is int
            and 15700 < verifier['bytes'] <= 32768 and SHA.fullmatch(verifier['sha256']) is not None,
            'derived_verifier_identity')


def validate_generation_originals(binding, originals):
    """Validate retained original bytes; no reconstructed retirement receipt."""
    require(set(originals) == set(GENERATION_PROOFS), 'generation_original_inventory')
    for name, pin in GENERATION_PROOFS.items():
        raw = originals[name]
        require(type(raw) is bytes and len(raw) == pin['bytes']
                and hashlib.sha256(raw).hexdigest() == pin['sha256'],
                'generation_original_bytes_or_sha')
    pre = strict_json(originals['R5-R3-ORIGINAL-RETIREMENT-PREFLIGHT.json'])
    result = strict_json(originals['R5-R3-REMAINING-ROLES-RECOVERY-RESULT.json'])
    capture = strict_json(originals['R5-R3-ACTUAL-REMAINING-RECOVERY-CAPTURE.json'])
    pid, start = KERNEL_REUSE['pid'], KERNEL_REUSE['retired_start_ticks']
    require(pre['schema'] == 'hepta.r5-r3-retirement-preflight.v1'
            and pre['state'] == 'READY_FOR_DISABLE_AND_ONE_SUPERVISOR_TERM'
            and pre['boot_id'] == binding['retirement_boot_id']
            and pre['groups']['provider'] == [pid, pid, pid, start],
            'retired_original_generation')
    require(result['schema'] == 'hepta.r5-r3.remaining-role-recovery.v1'
            and result['state'] == 'ALL_FOUR_ORIGINAL_GROUPS_ABSENT_STATE_PRESERVED'
            and result['boot_id'] == pre['boot_id']
            and result['preserved_state'] == pre['preserved_state']
            and result['preserved_state_equal_original_preflight'] is True
            and result['original_partial_retirement_preserved'] is True
            and result['original_health_and_all_run_terminals_unchanged'] is True
            and result['automatic_replay'] is False
            and result['automatic_restart'] is False
            and result['old_task_rewritten'] is False
            and result['old_claims_deleted'] is False
            and result['operator_waitpid_join_claim'] is False
            and result['original_supervisor_exit_status'] == 'UNKNOWN_NO_RECORD_NO_SYNTHETIC_EXIT_CODE',
            'retired_original_absence_and_preservation')
    original_pin = GENERATION_PROOFS['R5-R3-ORIGINAL-RETIREMENT-PREFLIGHT.json']
    require(dict(name='PREFLIGHT.json', **original_pin) in result['original_failure_files'],
            'retired_original_preflight_link')
    scans = result['four_groups_two_independent_censuses']
    require(isinstance(scans, list) and len(scans) == 2, 'original_absence_two_censuses')
    for scan in scans:
        require(scan['members'] == [] and scan['kernel_group_absence'][str(pid)] == 'ESRCH'
                and type(scan['processes_scanned']) is int and scan['processes_scanned'] > 0
                and type(scan['monotonic_ns']) is int and scan['monotonic_ns'] > 0,
                'original_pid_group_session_absence')
    require(scans[1]['monotonic_ns'] > scans[0]['monotonic_ns'], 'original_census_order')
    require(capture['issues'] == [] and isinstance(capture['files'], list), 'original_capture_complete')
    files = {}
    for entry in capture['files']:
        name = entry['relative_path']
        require(name not in files, 'original_capture_duplicate')
        raw = base64.b64decode(entry['raw_base64'], validate=True)
        require(len(raw) == entry['bytes'] and hashlib.sha256(raw).hexdigest() == entry['sha256'],
                'original_capture_file_pin')
        files[name] = raw
    require(files['RESULT.json'] == originals['R5-R3-REMAINING-ROLES-RECOVERY-RESULT.json']
            and files['OPERATOR-EXIT'] == b'0\n'
            and files['OUTSIDE-BEFORE.txt'] == files['OUTSIDE-AFTER.txt']
            and files['recovery.stderr'] == b'' and len(files['COMPLETED']) > 0,
            'original_recovery_outer_exit_and_after_guard')
    # The captured, frozen recovery source itself executes the original full
    # PID/PGID/SID census and final PID absence. We do not execute it again.
    require(hashlib.sha256(files['recover_remaining.py']).hexdigest()
            == 'daafa0cdfad5c7851a577cf266990c39cfc6f9cdc3655527dd4abe949bddd160',
            'original_recovery_source_pin')
    return MappingProxyType({pid: start})


def load_generation_originals(binding, reader):
    originals = {name: reader(PAYLOAD / 'generation-originals' / name, pin['bytes'],
                              pin['sha256'], pin['bytes'])
                 for name, pin in GENERATION_PROOFS.items()}
    return validate_generation_originals(binding, originals)


def process_generation(row):
    return tuple(row[key] for key in ('pid', 'ppid', 'pgrp', 'session', 'start_ticks'))


def kernel_pid_reuse_identity(proc, row, retired_start):
    """This permits only the documented PID-only native kernel-thread case."""
    pid = row['pid']
    require(row['start_ticks'] > retired_start and row['ppid'] == 2
            and row['pgrp'] == row['session'] == 0 and row['flags'] & PF_KTHREAD
            and row['state'] in ('I', 'S', 'R', 'D'), 'not_new_kernel_thread_generation')
    root = '/proc/' + str(pid)
    fields = {}
    for line in proc.read(root + '/status').decode('ascii').splitlines():
        key, separator, value = line.partition(':')
        require(separator and key and key not in fields, 'kernel_status_shape_or_duplicate')
        fields[key] = value.split()
    expected = dict(Pid=[str(pid)], Tgid=[str(pid)], PPid=['2'], Kthread=['1'],
                    Uid=['0'] * 4, Gid=['0'] * 4, TracerPid=['0'])
    require(all(fields.get(key) == value for key, value in expected.items()),
            'kernel_thread_status_identity')
    require(proc.read(root + '/cmdline', 65536, allow_empty=True) == b'', 'kernel_thread_cmdline')
    domain = proc.read(root + '/attr/current', 256)
    require(domain in (b'u:r:kernel:s0', b'u:r:kernel:s0\x00', b'u:r:kernel:s0\n'),
            'kernel_thread_domain')
    try:
        proc.link(root + '/exe')
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise
    else:
        raise ValueError('kernel_thread_unexpected_executable')
    after = proc.row(pid)
    require(after is not None and process_generation(after) == process_generation(row)
            and after['flags'] & PF_KTHREAD and after['state'] in ('I', 'S', 'R', 'D'),
            'kernel_thread_generation_changed')
    return process_generation(after) + (domain,)


def census(binding, proc, proof_reader=None):
    validate_binding(binding)
    verified_generations = load_generation_originals(binding, private_read if proof_reader is None else proof_reader)
    boot = proc.boot()
    own = proc.native_view()
    same = boot == binding['retirement_boot_id']
    if same:
        for anchor in binding['same_boot_anchors']:
            row = proc.row(anchor['pid'])
            require(row is not None and row['start_ticks'] == anchor['start_ticks']
                    and row['state'] != 'Z', 'same_boot_native_anchor_changed')
    retired, inspected, gone = set(binding['retired_groups']), 0, 0
    verified_reuse = None
    for _ in range(2):
        pids = proc.pids()
        require(0 < len(pids) <= 100000 and len(set(pids)) == len(pids)
                and 1 in pids and own['pid'] in pids, 'proc_inventory_bound_or_view')
        seen_reuse = {}
        for pid in pids:
            row = proc.row(pid)
            if row is None:
                gone += 1
                continue
            inspected += 1
            if same:
                require(not retired.intersection((row['pgrp'], row['session'])),
                        'same_boot_retired_group_or_session_present')
                if row['pid'] in retired:
                    require(row['pid'] in verified_generations,
                            'same_boot_retired_group_or_session_present_unreviewed_pid')
                    seen_reuse[pid] = kernel_pid_reuse_identity(proc, row, verified_generations[pid])
        require(verified_reuse is None or verified_reuse == seen_reuse,
                'kernel_thread_reuse_changed_between_censuses')
        verified_reuse = seen_reuse
    require(proc.boot() == boot, 'boot_changed_during_census')
    own_after = proc.native_view()
    require(all(own_after[key] == own[key] for key in ('pid', 'pgrp', 'session', 'start_ticks')),
            'native_proc_identity_changed_during_census')
    for pid, expected in verified_reuse.items():
        current = proc.row(pid)
        require(current is not None, 'kernel_thread_reuse_disappeared_at_close')
        require(kernel_pid_reuse_identity(proc, current, verified_generations[pid]) == expected,
                'kernel_thread_reuse_changed_at_close')
    mode = 'same_boot_exact_retirement' if same else 'new_boot_process_epoch'
    epoch = MappingProxyType(dict(schema='hepta.module-r10-r1.verified-epoch.v1',
                                  original_boot_id=binding['retirement_boot_id'],
                                  current_boot_id=boot, mode=mode,
                                  original_source_sha256=ORIGINAL_SHA))
    report = dict(schema='hepta.module-r10-r1.read-only-census.v1', state='ACTIVATION_PROCESS_GATE_CLEAR',
                  epoch_mode=mode, retired_group_count=len(retired),
                  numeric_old_group_filter_applied=same, inspected_processes=inspected,
                  complete_censuses=2, verified_kernel_pid_reuse_count=len(verified_reuse),
                  kernel_pid_reuse_profile=KERNEL_REUSE['profile'],
                  retired_pgrp_and_session_exceptions=False,
                  userspace_pid_reuse_exceptions=False,
                  confirmed_enoent_or_esrch=gone, pid_namespace_support='observed_absent',
                  original_proof_ledger_validation_required=True, signals_sent=0,
                  task_submissions=0, effects_dispatched=0, old_request_replay_authorized=False)
    return epoch, report


def main():
    require(len(sys.argv) == 4 and sys.argv[1:3] == ['--check-and-chain', '--retirement-boot'],
            'explicit_check_and_chain_required')
    require(__debug__, 'optimized_python_is_not_accepted')
    require(os.getuid() == os.geteuid() == 0, 'root_required')
    binding = strict_json(private_read(PAYLOAD / 'activation-binding.json', 16384))
    require(binding.get('retirement_boot_id') == sys.argv[3], 'shell_retirement_epoch_mismatch')
    epoch, report = census(binding, ProcView())
    # Retain and verify the frozen original, even though the new explicit
    # derivative is what executes. Neither source is rewritten at runtime.
    private_read(ORIGINAL, ORIGINAL_BYTES, ORIGINAL_SHA, ORIGINAL_BYTES)
    verifier = binding['ledger_verifier']
    raw = private_read(PAYLOAD / 'ledger_gate_bootaware.py', 32768,
                       verifier['sha256'], verifier['bytes'])
    print(json.dumps(report, separators=(',', ':')), flush=True)
    exec(compile(raw, str(PAYLOAD / 'ledger_gate_bootaware.py'), 'exec', optimize=0),
         {'__name__': '__main__', '__file__': str(PAYLOAD / 'ledger_gate_bootaware.py'),
          '__activation_epoch__': epoch})
    require(ProcView().boot() == epoch['current_boot_id'], 'boot_changed_during_ledger_verification')


if __name__ == '__main__':
    main()
