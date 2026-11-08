#!/usr/bin/env python3
"""One Root-only codec environment differential; no worker/case qualification."""
import argparse
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

SCHEMA = 'hepta.codec-root-environment-diagnostic.v1'
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
ANDROID = '/proc/1/root'
BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'
OUT = BASE + '/codec-root-env-diagnostic-01'
JAR = '/data/local/tmp/hepta-phone-executor-v150-r6/helpers/screen-codec-v148r1.jar'
BUSYBOX = '/data/adb/magisk/busybox'
JAR_EXPECTED = (16064, 'bb1176b7707d1a2a67bcfd2bc9bd1b5db16036c3929f8eb1d8820b927ef62639')
BUSYBOX_EXPECTED = (1710600, '4d60ab3f5a59ebb2ca863f2f514e6924401b581e9b64f602665c008177626651')
CLASS = 'org.trillionnium.hepta.screen.ScreenshotCodec'
INVALID_ARGS = ['invalid']
LIFECYCLE_ENV = {'PATH': '/system/bin:/vendor/bin', 'TMPDIR': '/data/local/tmp'}
COMMON_COMMAND_ENV = {'CLASSPATH': JAR}
ADDED_ENV = {'ANDROID_ART_ROOT': '/apex/com.android.art',
             'ANDROID_I18N_ROOT': '/apex/com.android.i18n',
             'ANDROID_TZDATA_ROOT': '/apex/com.android.tzdata'}
CHILD_SECONDS = 8.0
CLEANUP_SECONDS = 1.0
OUTPUT_CAP = 262144
NATIVE_CASE_COUNT = 0
O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
O_SAFE_DIR = O_DIR | os.O_NOFOLLOW

def need(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')

def metadata(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]

def parent_fd(path):
    need(isinstance(path, str) and path.startswith('/') and '\x00' not in path, 'absolute path required')
    if path.startswith(ANDROID + '/'):
        fd = os.open(ANDROID, O_DIR)  # the sole explicit procfs root-anchor exception
        suffix = path[len(ANDROID) + 1:]
    else:
        fd = os.open('/', O_SAFE_DIR)
        suffix = path[1:]
    parts = suffix.split('/')
    need(parts and all(x not in ('', '.', '..') for x in parts), 'lexical path rejected')
    try:
        for name in parts[:-1]:
            nxt = os.open(name, O_SAFE_DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise

def read_stream(path, cap):
    parent, name = parent_fd(path)
    fd = -1
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        parts = []
        count = 0
        while True:
            chunk = os.read(fd, min(65536, cap + 1 - count))
            if not chunk:
                break
            parts.append(chunk)
            count += len(chunk)
            need(count <= cap, 'stream exceeded bound')
        return b''.join(parts)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)

def regular(path, expected=None, cap=2097152):
    parent, name = parent_fd(path)
    fd = -1
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap, 'regular file gate failed')
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        need(metadata(os.fstat(fd)) == metadata(before), 'file changed at open')
        raw = bytearray()
        while True:
            chunk = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            need(len(raw) <= cap, 'file exceeded bound')
        need(metadata(os.fstat(fd)) == metadata(before)
             and metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) == metadata(before), 'file changed while read')
        raw = bytes(raw)
        need(len(raw) == before.st_size, 'file length changed')
        if expected is not None:
            need((len(raw), sha(raw)) == expected, 'fixed artifact bytes differ')
        return raw, {'path': path, 'bytes': len(raw), 'sha256': sha(raw), 'metadata': metadata(before)}
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)

def fsync_directory(path):
    parent, name = parent_fd(path)
    fd = -1
    try:
        fd = os.open(name, O_SAFE_DIR, dir_fd=parent)
        os.fsync(fd)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)

def mkdir_once(path):
    parent, name = parent_fd(path)
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        fd = os.open(name, O_SAFE_DIR, dir_fd=parent)
        try:
            st = os.fstat(fd)
            need(st.st_uid == 0 and st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o700, 'private output directory differs')
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)

def output_fd(path):
    parent, name = parent_fd(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        os.fsync(parent)
        return fd
    finally:
        os.close(parent)

def write_all(fd, raw):
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        need(count > 0, 'output write stopped')
        view = view[count:]

def put(path, value):
    raw = value if isinstance(value, bytes) else encoded(value)
    fd = output_fd(path)
    try:
        write_all(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    parent, _ = parent_fd(path)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    after, descriptor = regular(path, (len(raw), sha(raw)), max(len(raw), 1))
    need(after == raw, 'output readback differs')
    return descriptor

def identity(pid):
    raw = read_stream('/proc/' + str(pid) + '/stat', 8192)
    text = raw.decode('ascii')
    end = text.rfind(')')
    need(end > 0 and int(text.split(' ', 1)[0]) == pid, 'proc identity parse failed')
    fields = text[end + 2:].split()
    need(len(fields) >= 20, 'proc stat too short')
    result = {'pid': pid, 'ppid': int(fields[1]), 'pgid': int(fields[2]),
              'sid': int(fields[3]), 'start_ticks': int(fields[19])}
    need(result['start_ticks'] > 0, 'owned child generation absent')
    return result

def group_absence(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return {'pgid': pid, 'absent': True, 'errno': errno.ESRCH}
    except PermissionError:
        return {'pgid': pid, 'absent': False, 'errno': errno.EPERM}
    return {'pgid': pid, 'absent': False, 'errno': 0}

def executable_original():
    link = ANDROID + '/system/bin/app_process'
    parent, name = parent_fd(link)
    try:
        st = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(name, dir_fd=parent)
            need(target == 'app_process64', 'unexpected app_process alias')
            record = {'path': link, 'kind': 'symlink', 'target': target, 'metadata': metadata(st)}
            need(metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) == record['metadata'], 'app_process alias changed')
        else:
            need(stat.S_ISREG(st.st_mode), 'app_process kind differs')
            record = {'path': link, 'kind': 'file'}
            target = 'app_process'
    finally:
        os.close(parent)
    raw, binary = regular(ANDROID + '/system/bin/' + target, cap=2097152)
    need(binary['metadata'][3] == 0 and binary['metadata'][2] & 0o111
         and not (binary['metadata'][2] & 0o022), 'app_process identity differs')
    return {'entry': record, 'binary': binary}

def precheck():
    need(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), 'Root identity required')
    own = identity(os.getpid())
    context = read_stream('/proc/' + str(os.getpid()) + '/attr/current', 256).rstrip(b'\x00\n').decode('ascii')
    need(context == 'u:r:magisk:s0', 'Root diagnostic domain differs')
    boot = read_stream('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
    need(boot == BOOT, 'boot differs')
    enforcing = read_stream(ANDROID + '/sys/fs/selinux/enforce', 8)
    need(enforcing.strip() == b'1', 'SELinux must remain Enforcing')
    anchor = os.stat(ANDROID)
    need(stat.S_ISDIR(anchor.st_mode) and (anchor.st_dev, anchor.st_ino) != (os.stat('/').st_dev, os.stat('/').st_ino), 'Android proc1 root anchor differs')
    _, jar = regular(ANDROID + JAR, JAR_EXPECTED)
    _, busybox = regular(ANDROID + BUSYBOX, BUSYBOX_EXPECTED)
    need(jar['metadata'][3:5] == [0, 0] and stat.S_IMODE(jar['metadata'][2]) == 0o644, 'JAR ownership or mode differs')
    need(busybox['metadata'][3:5] == [0, 0] and stat.S_IMODE(busybox['metadata'][2]) == 0o755, 'busybox ownership or mode differs')
    return {'boot_id': boot, 'uid': 0, 'gid': 0, 'supplementary_groups': os.getgroups(),
            'domain': context, 'self_identity': own, 'enforcing': True,
            'android_anchor': [anchor.st_dev, anchor.st_ino],
            'jar': jar, 'busybox': busybox, 'app_process': executable_original()}

def argv():
    return [ANDROID + BUSYBOX, 'chroot', ANDROID, '/system/bin/app_process', '/system/bin', CLASS] + INVALID_ARGS

def environment(treatment):
    value = dict(LIFECYCLE_ENV)
    value.update(COMMON_COMMAND_ENV)
    if treatment:
        value.update(ADDED_ENV)
    return value

def preview():
    return {'schema': SCHEMA, 'state': 'PREVIEW_ONLY_NO_PHONE_PATH_READ_OR_CHILD_PROCESS',
            'out': OUT, 'expected_boot_id': BOOT, 'child_argv': argv(),
            'baseline_lifecycle_environment': LIFECYCLE_ENV,
            'common_original_command_environment': COMMON_COMMAND_ENV,
            'baseline_effective_environment': environment(False),
            'treatment_effective_environment': environment(True),
            'only_treatment_difference': ADDED_ENV,
            'invalid_args': INVALID_ARGS, 'maximum_child_launches': 2,
            'per_child_timeout_seconds': CHILD_SECONDS, 'per_cleanup_wait_seconds': CLEANUP_SECONDS,
            'total_output_bytes_per_child_maximum': OUTPUT_CAP,
            'root_only': True, 'worker_uid_domain_qualification': False,
            'expected_treatment_java_entry_marker': {'exit_code': 20, 'schema': 'hepta.phone-screenshot.v1',
                'status': 'rejected', 'reason': 'shell_uid_required'},
            'sidecar_starts': 0, 'provider_starts': 0, 'screenshots': 0,
            'ui_commands': 0, 'native_case_count': 0, 'native_case_sends': 0,
            'new_native_nonces': 0, 'automatic_retry': False, 'automatic_adoption': False}

def run_child(name, treatment):
    directory = OUT + '/' + name
    mkdir_once(directory)
    env = environment(treatment)
    intent = put(directory + '/INTENT.json', {'schema': 'hepta.codec-root-owned-child-intent.v1',
        'name': name, 'argv': argv(), 'environment': env, 'start_new_session': True,
        'timeout_seconds': CHILD_SECONDS, 'automatic_retry': False, 'maximum_launches': 1})
    stdout_fd = output_fd(directory + '/stdout.original')
    stderr_fd = output_fd(directory + '/stderr.original')
    selector = selectors.DefaultSelector()
    child = None
    ident = None
    joined = False
    reason = None
    truncated = False
    bytes_seen = 0
    bytes_kept = 0
    signals = []
    began = time.monotonic()
    rc = None
    try:
        child = subprocess.Popen(argv(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, start_new_session=True, close_fds=True)
        ident = identity(child.pid)  # an unreaped direct child keeps this PID reserved
        need(ident['ppid'] == os.getpid() and ident['pgid'] == child.pid and ident['sid'] == child.pid,
             'dedicated child group or parent differs')
        put(directory + '/CHILD-IDENTITY.json', {'identity': ident, 'intent': intent,
            'root_parent': identity(os.getpid()), 'worker_qualification_claimed': False})
        for stream, fd in ((child.stdout, stdout_fd), (child.stderr, stderr_fd)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, fd)
        deadline = began + CHILD_SECONDS
        while selector.get_map():
            if time.monotonic() >= deadline:
                reason = 'timeout'
                break
            for key, _ in selector.select(min(0.05, max(0.0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                bytes_seen += len(chunk)
                room = OUTPUT_CAP - bytes_kept
                if room:
                    kept = chunk[:room]
                    write_all(key.data, kept)
                    bytes_kept += len(kept)
                if len(chunk) > room:
                    truncated = True
                    reason = 'output_limit'
                    break
            if reason is not None:
                break
        if reason is None:
            try:
                rc = child.wait(timeout=max(0.001, deadline - time.monotonic()))
                joined = True
            except subprocess.TimeoutExpired:
                reason = 'timeout'
        if reason is not None and not joined:
            # No poll/wait reaped the child. Recheck its generation before owned cleanup.
            need(identity(child.pid) == ident, 'child generation changed before owned cleanup')
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(child.pid, sig)
                    signals.append(int(sig))
                except ProcessLookupError:
                    pass
                try:
                    rc = child.wait(timeout=CLEANUP_SECONDS)
                    joined = True
                    break
                except subprocess.TimeoutExpired:
                    continue
        # Drain remaining bytes only; no new launch and no signal after a successful wait.
        drain_until = time.monotonic() + CLEANUP_SECONDS
        while selector.get_map() and time.monotonic() < drain_until:
            for key, _ in selector.select(0.05):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                bytes_seen += len(chunk)
                room = OUTPUT_CAP - bytes_kept
                if room:
                    kept = chunk[:room]
                    write_all(key.data, kept)
                    bytes_kept += len(kept)
                if len(chunk) > room:
                    truncated = True
                    if reason is None:
                        reason = 'output_limit'
        streams_complete = not selector.get_map() and not truncated
        if not streams_complete and reason is None:
            reason = 'streams_incomplete'
    except BaseException as error:
        if reason is None:
            reason = type(error).__name__ + ':' + str(error)[:512]
        # This direct Popen child has never been reaped here, so its PID is reserved.
        # Without a sampled generation, kill only that direct child, never a group.
        if child is not None and not joined:
            try:
                if ident is not None and identity(child.pid) == ident:
                    os.killpg(child.pid, signal.SIGKILL)
                elif ident is None:
                    os.kill(child.pid, signal.SIGKILL)
                else:
                    raise ValueError('owned child generation could not be rechecked')
                signals.append(int(signal.SIGKILL))
                rc = child.wait(timeout=CLEANUP_SECONDS)
                joined = True
            except BaseException:
                pass
        streams_complete = False
    finally:
        selector.close()
        if child is not None:
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
        for fd in (stdout_fd, stderr_fd):
            os.fsync(fd)
            os.close(fd)
        fsync_directory(directory)
    absence = []
    if child is not None and joined:
        absence.append(group_absence(child.pid))
        time.sleep(0.05)
        absence.append(group_absence(child.pid))
    out_raw, out_original = regular(directory + '/stdout.original', cap=OUTPUT_CAP)
    err_raw, err_original = regular(directory + '/stderr.original', cap=OUTPUT_CAP)
    complete = (reason is None and joined and len(absence) == 2 and all(x['absent'] for x in absence)
                and streams_complete and not truncated and type(rc) is int and rc >= 0)
    result = {'schema': 'hepta.codec-root-owned-child-result.v1', 'name': name,
        'intent': intent, 'argv': argv(), 'environment': env, 'child_identity': ident,
        'returncode': rc, 'real_child_wait_returned': joined, 'group_absence': absence,
        'captured_streams_complete': streams_complete, 'output_truncated': truncated,
        'bytes_seen': bytes_seen, 'bytes_retained': bytes_kept, 'stdout': out_original, 'stderr': err_original,
        'elapsed_seconds': round(time.monotonic() - began, 6), 'error': reason,
        'timeout': reason == 'timeout', 'owned_cleanup_signals': signals,
        'maximum_launches': 1, 'launch_count': int(child is not None),
        'automatic_retry': False, 'recorded_and_joined': complete}
    put(directory + '/PROCESS.json', result)
    return result, out_raw, err_raw

def source_bytes(expected):
    raw = globals().get('_REVIEWED_SOURCE_BYTES')
    if raw is None:
        raw, _ = regular(os.path.abspath(__file__), cap=65536)
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'reviewed source bytes missing')
    need(isinstance(expected, str) and len(expected) == 64 and all(x in '0123456789abcdef' for x in expected)
         and sha(raw) == expected, 'reviewed source SHA differs')
    return raw

def execute(expected):
    raw = source_bytes(expected)
    before = precheck()
    mkdir_once(OUT)
    put(OUT + '/SOURCE.original.py', raw)
    put(OUT + '/PRECHECK.json', before)
    intent = put(OUT + '/INTENT.json', {'schema': 'hepta.codec-root-environment-intent.v1',
        'source_sha256': expected, 'source_bytes': len(raw), 'preview': preview(),
        'maximum_child_launches': 2, 'automatic_retry': False})
    children = []
    raws = []
    try:
        for name, treatment in (('baseline', False), ('treatment', True)):
            need(precheck() == before, 'pre-child root or artifact bookend differs')
            result, stdout, stderr = run_child(name, treatment)
            children.append(result)
            raws.append((stdout, stderr))
            need(result['recorded_and_joined'], 'child failed bounded completion; no next child')
        after = precheck()
        need(after == before, 'post-child root or artifact bookend differs')
        put(OUT + '/AFTER.json', after)
        marker = None
        try:
            marker = json.loads(raws[1][0])
        except (UnicodeError, ValueError):
            pass
        baseline_shape = children[0]['returncode'] == 0 and raws[0][0] == b''
        java_marker = (children[1]['returncode'] == 20 and marker == {
            'schema': 'hepta.phone-screenshot.v1', 'status': 'rejected', 'reason': 'shell_uid_required'})
        matched = baseline_shape and java_marker
        final = {'schema': SCHEMA,
            'state': 'ROOT_ONLY_DIFFERENTIAL_MATCHED' if matched else 'ROOT_ONLY_DIFFERENTIAL_RECORDED_NOT_MATCHED',
            'intent': intent, 'source_sha256': expected, 'children': children,
            'baseline_empty_success_observed': baseline_shape, 'treatment_java_uid_rejection_observed': java_marker,
            'only_environment_difference': ADDED_ENV, 'artifact_bookends_equal': True,
            'worker_domain_qualification': False, 'screenshot_qualification': False,
            'component_qualified': False, 'physical_case_pass': False,
            'sidecar_starts': 0, 'provider_starts': 0, 'screenshots': 0, 'ui_commands': 0,
            'native_case_count': 0, 'native_case_sends': 0, 'new_native_nonces': 0,
            'automatic_retry': False, 'automatic_adoption': False}
        put(OUT + '/RESULT.json', final)
        print(encoded(final).decode('ascii'), end='', flush=True)
        return 0 if matched else 2
    except BaseException as error:
        failure = {'schema': SCHEMA, 'state': 'FAILED_RETAINED_NO_RETRY',
            'intent': intent, 'source_sha256': expected, 'children': children,
            'error': type(error).__name__ + ':' + str(error)[:1024],
            'automatic_retry': False, 'automatic_adoption': False,
            'worker_domain_qualification': False, 'component_qualified': False,
            'native_case_count': 0, 'new_native_nonces': 0}
        put(OUT + '/FAILURE.json', failure)
        print(encoded(failure).decode('ascii'), end='', flush=True)
        return 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-root-codec-diagnostic', action='store_true')
    parser.add_argument('--reviewed-source-sha256')
    args = parser.parse_args()
    if not args.execute_root_codec_diagnostic:
        print(encoded(preview()).decode('ascii'), end='')
        return 0
    need(args.reviewed_source_sha256 is not None, 'explicit source SHA required')
    return execute(args.reviewed_source_sha256)

if __name__ == '__main__':
    raise SystemExit(main())
