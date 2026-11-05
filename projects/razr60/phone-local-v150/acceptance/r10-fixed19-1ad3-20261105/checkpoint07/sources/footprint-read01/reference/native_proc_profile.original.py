#!/usr/bin/env python3
"""Exact native proc profile extracted from reviewed boot gate 138c95a0.

Only ProcView/parse_stat/require are retained, byte for byte. No retirement,
old PID exception, ledger gate, role launch or process signal is included.
"""
import errno
import os
from pathlib import Path
import re
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
GONE = frozenset((errno.ENOENT, errno.ESRCH))
NATIVE_NS = ('cgroup', 'mnt', 'net', 'time', 'time_for_children', 'uts')
PROFILE = 'leap-stock16-init-no-pid-ns-v1'

def require(condition, reason):
    if not condition:
        raise ValueError(reason)

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
