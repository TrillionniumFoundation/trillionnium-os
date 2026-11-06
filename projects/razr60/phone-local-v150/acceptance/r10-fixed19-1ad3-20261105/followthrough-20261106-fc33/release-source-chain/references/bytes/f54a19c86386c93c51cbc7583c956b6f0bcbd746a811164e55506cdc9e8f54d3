#!/system/bin/sh
# Frozen argv only; never submits a task or automatically replays work.
set -eu
umask 077
# Validate the existing pinned GNU Python before the same-PID read-only gate.
# The final sidecar still receives only its two original values plus five
# reviewed Android values. No platform file is sourced or executed.
BB=/data/adb/magisk/busybox
SYS=/system/bin
ROOT=/data/trillionnium/owner-open/root
PY_NATIVE=$ROOT/usr/bin/python3
[ -f "$PY_NATIVE" ] && [ ! -L "$PY_NATIVE" ]
[ "$("$SYS/readlink" -f "$PY_NATIVE")" = "$PY_NATIVE" ]
[ "$("$SYS/stat" -c '%u:%g:%a:%h:%s' "$PY_NATIVE")" = 0:0:555:1:7843560 ]
[ "$("$SYS/sha256sum" "$PY_NATIVE")" = "f7ad87c414fc6a5126571b2ecca19351119ac10e54d0539de6a0a9300d81087f  $PY_NATIVE" ]
exec "$BB" env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
    "$BB" chroot "$ROOT" /usr/bin/python3 -I -B - <<'HEPTA_REVIEWED_SIDECAR_ENVIRONMENT_R7'
# Exact reviewed functions below are copied as source, not imported from mutable paths.
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
sys.dont_write_bytecode = True
ANDROID = Path('/proc/1/root')
def need(value, message):
    if not value:
        raise ValueError(message)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def metadata(value):
    return [getattr(value, key) for key in
            ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
             'st_size', 'st_mtime_ns', 'st_ctime_ns')]

REVIEWED_PLATFORM_CLASSPATH = {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'file': {'bytes': 5259, 'metadata': [65086, 136045, 33152, 1000, 1000, 1, 5259, 2313515747999998, 2313515747999998], 'path': '/proc/1/root/data/system/environ/classpath', 'sha256': '16a13f546a20ead8d4a4b100cc58527c26ffe59008729cb9cdaccafbf14db7c5'}, 'selinux_label': 'u:object_r:environ_system_data_file:s0'}

def parent_fd(path):
    """Walk directory FDs without links; only /proc/1/root is an explicit anchor.

    The GNU chroot cannot resolve that Android magic link lexically. Runtime
    startup separately binds the init PID namespace and the anchor inode.
    """
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2 <= len(path.parts) <= 64,
         'bounded absolute path required')
    if path.parts[:4] == ('/', 'proc', '1', 'root'):
        fd = os.open(ANDROID, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[4:]
    else:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = path.parts[1:]
    need(parts, 'file path required')
    try:
        for name in parts[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd); raise

def _reviewed_classpath_values(raw):
    """Parse the four fixed export records; expose only the two boot values."""
    need(type(raw) is bytes and raw.endswith(b'\n'), 'classpath must be original LF-terminated bytes')
    text = raw.decode('ascii')
    lines = text[:-1].split('\n')
    keys = ('BOOTCLASSPATH', 'DEX2OATBOOTCLASSPATH',
            'SYSTEMSERVERCLASSPATH', 'STANDALONE_SYSTEMSERVER_JARS')
    need(len(lines) == len(keys), 'classpath export count differs')
    values = {}; entries = {}
    for key, line in zip(keys, lines):
        tokens = line.split(' ')
        need(len(tokens) == 3 and tokens[:2] == ['export', key]
             and tokens[2], 'classpath export order or three-token grammar differs')
        paths = tokens[2].split(':')
        need(all(re.fullmatch(r'/(?:[A-Za-z0-9_+.-]+/)*[A-Za-z0-9_+.-]+\.jar', p)
                 and all(part not in ('.', '..') for part in p.split('/')[1:])
                 for p in paths), 'classpath entry is not one literal absolute jar path')
        values[key] = tokens[2]; entries[key] = paths
    dex = entries['DEX2OATBOOTCLASSPATH']; boot = entries['BOOTCLASSPATH']
    need(0 < len(dex) < len(boot) and boot[:len(dex)] == dex,
         'DEX2OATBOOTCLASSPATH is not the strict whole-entry boot prefix')
    return {key: values[key] for key in keys[:2]}

def reviewed_android_sidecar_environment(boot_id):
    """Read this exact boot's generated file without executing or sourcing it."""
    record = REVIEWED_PLATFORM_CLASSPATH
    need(isinstance(record, dict) and set(record) == {'boot_id', 'file', 'selinux_label'}
         and boot_id == record['boot_id']
         and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id,
         'reviewed Android classpath boot differs')
    row = record['file']; path = Path(row['path'])
    need(set(row) == {'path', 'bytes', 'sha256', 'metadata'}
         and str(path) == '/proc/1/root/data/system/environ/classpath'
         and row['bytes'] == 5259
         and row['sha256'] == '16a13f546a20ead8d4a4b100cc58527c26ffe59008729cb9cdaccafbf14db7c5',
         'reviewed Android classpath file differs')
    parent, name = parent_fd(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
    except BaseException:
        os.close(parent); raise
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and metadata(before) == row['metadata'],
             'reviewed Android classpath identity or metadata differs')
        label = os.getxattr(fd, 'security.selinux')
        canonical_label = record['selinux_label'].encode('ascii')
        need(label in (canonical_label, canonical_label+b'\0'),
             'reviewed Android classpath label differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(row['bytes']+1)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256']
             and metadata(os.fstat(fd)) == row['metadata']
             == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False))
             and os.getxattr(fd, 'security.selinux') == label,
             'reviewed Android classpath bytes or bookends differ')
        values = _reviewed_classpath_values(raw)
        second, leaf = parent_fd(path)
        try:
            need(leaf == name and metadata(os.stat(leaf, dir_fd=second, follow_symlinks=False))
                 == row['metadata'], 'reviewed Android classpath canonical path changed')
        finally:
            os.close(second)
    finally:
        os.close(fd); os.close(parent)
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id,
         'Android boot changed during classpath read')
    return {'PATH': '/system/bin:/vendor/bin', 'TMPDIR': '/data/local/tmp',
            'ANDROID_ART_ROOT': '/apex/com.android.art',
            'ANDROID_I18N_ROOT': '/apex/com.android.i18n',
            'ANDROID_TZDATA_ROOT': '/apex/com.android.tzdata', **values}

need(len(sys.argv) == 1 and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
     'only the already admitted Root sidecar launch is permitted')
need(os.getpid() == os.getpgrp() == os.getsid(0),
     'sidecar launch must preserve its admitted process group and session')
env = reviewed_android_sidecar_environment(REVIEWED_PLATFORM_CLASSPATH['boot_id'])
need(set(env) == {'PATH', 'TMPDIR', 'ANDROID_ART_ROOT', 'ANDROID_I18N_ROOT',
                 'ANDROID_TZDATA_ROOT', 'BOOTCLASSPATH', 'DEX2OATBOOTCLASSPATH'},
     'only the seven reviewed sidecar environment values are permitted')
command = [str(ANDROID/'data/adb/magisk/busybox'), 'chroot', str(ANDROID),
           '/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6',
           '--state-dir', '/data/trillionnium/owner-open/state/phone-local-v150/executor-r6']
os.execve(command[0], command, env)
HEPTA_REVIEWED_SIDECAR_ENVIRONMENT_R7
