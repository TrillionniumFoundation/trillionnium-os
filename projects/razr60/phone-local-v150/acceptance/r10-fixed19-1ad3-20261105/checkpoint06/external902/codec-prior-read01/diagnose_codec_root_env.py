#!/usr/bin/env python3
"""One new Root-only codec child with pinned platform boot classpaths; no case qualification."""
import argparse
import base64
import errno
import hashlib
import json
import os
import re
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

SCHEMA = 'hepta.codec-root-classpath-diagnostic.v1'
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
ANDROID = '/proc/1/root'
BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'
OUT = BASE + '/codec-root-env-diagnostic-02'
PRIOR_OUT = BASE + '/codec-root-env-diagnostic-01'
PRIOR_SOURCE_EXPECTED = (21874, '5108b7332d5235cbb3849f6987922dd1338f28d2555f0542f2d0b62699a780aa')
PRIOR_FAILURE_RECORD = {'bytes': 4392, 'metadata': [65086, 157043, 33152, 0, 0, 1, 4392, 1793847526847927606, 1793847526847927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/FAILURE.json', 'sha256': 'fa7335a48b1246e8f108269b98fb96a102461ea188ae7fb148786b389edd444c'}
PRIOR_ORIGINAL_RECORDS = {'FAILURE.json': {'bytes': 4392, 'metadata': [65086, 157043, 33152, 0, 0, 1, 4392, 1793847526847927606, 1793847526847927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/FAILURE.json', 'sha256': 'fa7335a48b1246e8f108269b98fb96a102461ea188ae7fb148786b389edd444c'}, 'INTENT.json': {'bytes': 2107, 'metadata': [65086, 157020, 33152, 0, 0, 1, 2107, 1793847526323927606, 1793847526323927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/INTENT.json', 'sha256': '12de5c64bbb30fdf3d3b97bf283a58e7f07d832ad4199632b8b033f1b4fc820c'}, 'PRECHECK.json': {'bytes': 1201, 'metadata': [65086, 157019, 33152, 0, 0, 1, 1201, 1793847526323927606, 1793847526323927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/PRECHECK.json', 'sha256': '4b80e766c1b2f3f75750587b9d4fcd4fcc6f06c1315568d230749e783a71c49a'}, 'SOURCE.original.py': {'bytes': 21874, 'metadata': [65086, 157018, 33152, 0, 0, 1, 21874, 1793847526319927606, 1793847526319927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/SOURCE.original.py', 'sha256': '5108b7332d5235cbb3849f6987922dd1338f28d2555f0542f2d0b62699a780aa'}, 'baseline/CHILD-IDENTITY.json': {'bytes': 504, 'metadata': [65086, 157026, 33152, 0, 0, 1, 504, 1793847526343927606, 1793847526343927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/baseline/CHILD-IDENTITY.json', 'sha256': 'a1b7c7a42a2e72f0300d811288a75f07589d9b94ad69e12455f92219802cd15f'}, 'baseline/INTENT.json': {'bytes': 499, 'metadata': [65086, 157022, 33152, 0, 0, 1, 499, 1793847526331927606, 1793847526331927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/baseline/INTENT.json', 'sha256': '4776b280454f46b78a28f602f8be7baa6fa4a217dc65d77a15beae4e626098ad'}, 'baseline/PROCESS.json': {'bytes': 1776, 'metadata': [65086, 157027, 33152, 0, 0, 1, 1776, 1793847526491927606, 1793847526491927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/baseline/PROCESS.json', 'sha256': 'a63db1e9a38b89981364ab6c2863fbb1ab850fd4caba5073eeaa869935cb349c'}, 'baseline/stderr.original': {'bytes': 0, 'metadata': [65086, 157025, 33152, 0, 0, 1, 0, 1793847526335927606, 1793847526335927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/baseline/stderr.original', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'baseline/stdout.original': {'bytes': 0, 'metadata': [65086, 157024, 33152, 0, 0, 1, 0, 1793847526335927606, 1793847526335927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/baseline/stdout.original', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'treatment/CHILD-IDENTITY.json': {'bytes': 505, 'metadata': [65086, 157034, 33152, 0, 0, 1, 505, 1793847526511927606, 1793847526511927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/treatment/CHILD-IDENTITY.json', 'sha256': '3ea90db9857004ce8b51048adb1b9857faeba6a3cc515be37a47eed9d743d9c0'}, 'treatment/INTENT.json': {'bytes': 637, 'metadata': [65086, 156451, 33152, 0, 0, 1, 637, 1793847526503927606, 1793847526503927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/treatment/INTENT.json', 'sha256': 'e20ab2f8ce2da6c415222dda8b2bc22eaa32009c42f707ae493815d92337bf2c'}, 'treatment/PROCESS.json': {'bytes': 1919, 'metadata': [65086, 157039, 33152, 0, 0, 1, 1919, 1793847526839927606, 1793847526839927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/treatment/PROCESS.json', 'sha256': 'a77180f42d0ba2d507ad2e64585b911f6baa48bd3d6a45f00d11e85580441460'}, 'treatment/stderr.original': {'bytes': 0, 'metadata': [65086, 155206, 33152, 0, 0, 1, 0, 1793847526507927606, 1793847526507927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/treatment/stderr.original', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'treatment/stdout.original': {'bytes': 0, 'metadata': [65086, 157031, 33152, 0, 0, 1, 0, 1793847526507927606, 1793847526507927606], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/codec-root-env-diagnostic-01/treatment/stdout.original', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}}
PLATFORM_RECORD = {'bytes': 5259, 'metadata': [65086, 136045, 33152, 1000, 1000, 1, 5259, 2313515747999998, 2313515747999998], 'path': '/proc/1/root/data/system/environ/classpath', 'sha256': '16a13f546a20ead8d4a4b100cc58527c26ffe59008729cb9cdaccafbf14db7c5'}
PLATFORM_LABEL = 'u:object_r:environ_system_data_file:s0'
BCP_ENV = {'BOOTCLASSPATH': '/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/framework-location.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/qcom.fmradio.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system/framework/framework-ondeviceintelligence-platform.jar:/system_ext/framework/payjoy-api.jar:/apex/com.android.i18n/javalib/core-icu4j.jar:/apex/com.android.adservices/javalib/framework-adservices.jar:/apex/com.android.adservices/javalib/framework-sdksandbox.jar:/apex/com.android.appsearch/javalib/framework-appsearch.jar:/apex/com.android.bt/javalib/framework-bluetooth.jar:/apex/com.android.configinfrastructure/javalib/framework-configinfrastructure.jar:/apex/com.android.conscrypt/javalib/conscrypt.jar:/apex/com.android.crashrecovery/javalib/framework-crashrecovery.jar:/apex/com.android.devicelock/javalib/framework-devicelock.jar:/apex/com.android.healthfitness/javalib/framework-healthfitness.jar:/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar:/apex/com.android.media/javalib/updatable-media.jar:/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar:/apex/com.android.mediaprovider/javalib/framework-pdf.jar:/apex/com.android.mediaprovider/javalib/framework-pdf-v.jar:/apex/com.android.mediaprovider/javalib/framework-photopicker.jar:/apex/com.android.nfcservices/javalib/framework-nfc.jar:/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar:/apex/com.android.os.statsd/javalib/framework-statsd.jar:/apex/com.android.permission/javalib/framework-permission.jar:/apex/com.android.permission/javalib/framework-permission-s.jar:/apex/com.android.profiling/javalib/framework-profiling.jar:/apex/com.android.scheduling/javalib/framework-scheduling.jar:/apex/com.android.sdkext/javalib/framework-sdkextensions.jar:/apex/com.android.tethering/javalib/framework-connectivity.jar:/apex/com.android.tethering/javalib/framework-connectivity-b.jar:/apex/com.android.tethering/javalib/framework-connectivity-t.jar:/apex/com.android.tethering/javalib/framework-tethering.jar:/apex/com.android.uwb/javalib/framework-ranging.jar:/apex/com.android.uwb/javalib/framework-uwb.jar:/apex/com.android.virt/javalib/framework-virtualization.jar:/apex/com.android.wifi/javalib/framework-wifi.jar:/apex/com.motorola.enterprise/javalib/framework-moto-enterprise.jar:/apex/com.motorola.enterprise/javalib/moto-enterprise.jar:/apex/com.motorola.motosecure/javalib/framework-moto-secure.jar', 'DEX2OATBOOTCLASSPATH': '/apex/com.android.art/javalib/core-oj.jar:/apex/com.android.art/javalib/core-libart.jar:/apex/com.android.art/javalib/okhttp.jar:/apex/com.android.art/javalib/bouncycastle.jar:/apex/com.android.art/javalib/apache-xml.jar:/system/framework/framework.jar:/system/framework/framework-graphics.jar:/system/framework/framework-location.jar:/system/framework/ext.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/tcmiface.jar:/system/framework/qcom.fmradio.jar:/system/framework/QPerformance.jar:/system/framework/UxPerformance.jar:/system/framework/WfdCommon.jar:/system/framework/framework-ondeviceintelligence-platform.jar:/system_ext/framework/payjoy-api.jar:/apex/com.android.i18n/javalib/core-icu4j.jar'}
PLATFORM_EXPORT_KEYS = ('BOOTCLASSPATH', 'DEX2OATBOOTCLASSPATH', 'SYSTEMSERVERCLASSPATH', 'STANDALONE_SYSTEMSERVER_JARS')
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
        value.update(BCP_ENV)
    return value

def parse_platform_classpaths(raw):
    """Parse fixed export data; no shell evaluation, inheritance or fallback."""
    need(type(raw) is bytes and 0 < len(raw) <= 16384, 'bounded platform export bytes required')
    text = raw.decode('ascii')
    need(text.endswith('\n') and '\r' not in text and '\x00' not in text,
         'platform export framing differs')
    lines = text[:-1].split('\n')
    need(len(lines) == 4, 'platform export line count differs')
    values = {}
    for key, line in zip(PLATFORM_EXPORT_KEYS, lines):
        prefix = 'export ' + key + ' '
        need(line.startswith(prefix), 'platform export key or order differs')
        value = line[len(prefix):]
        need(value and re.fullmatch(r'[A-Za-z0-9_./:+-]+', value) is not None,
             'platform export contains shell syntax or whitespace')
        entries = value.split(':')
        need(0 < len(entries) <= 128 and len(set(entries)) == len(entries),
             'platform classpath entries are empty or repeated')
        for entry in entries:
            parts = entry.split('/')
            need(entry.startswith('/') and entry.endswith('.jar')
                 and all(part not in ('', '.', '..') for part in parts[1:]),
                 'platform classpath entry is not a canonical absolute jar path')
        values[key] = value
    selected = {key: values[key] for key in PLATFORM_EXPORT_KEYS[:2]}
    bcp = selected['BOOTCLASSPATH'].split(':')
    dex = selected['DEX2OATBOOTCLASSPATH'].split(':')
    need(len(dex) < len(bcp) and bcp[:len(dex)] == dex,
         'DEX2OATBOOTCLASSPATH is not a strict complete-entry prefix')
    return selected

def exact_original(row, cap=262144):
    need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256', 'metadata'},
         'full original descriptor required')
    raw, observed = regular(row['path'], (row['bytes'], row['sha256']), cap)
    need(observed == row, 'full original identity differs')
    return raw

def platform_original():
    parent, name = parent_fd(PLATFORM_RECORD['path'])
    fd = -1
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
             and metadata(st) == PLATFORM_RECORD['metadata'], 'platform file identity differs')
        label = os.getxattr(fd, 'security.selinux')
        need(label.rstrip(b'\x00').decode('ascii') == PLATFORM_LABEL, 'platform file label differs')
        chunks = []
        size = 0
        while True:
            part = os.read(fd, min(4096, 16385 - size))
            if not part:
                break
            chunks.append(part)
            size += len(part)
            need(size <= 16384, 'platform export exceeded bound')
        raw = b''.join(chunks)
        need((len(raw), sha(raw)) == (PLATFORM_RECORD['bytes'], PLATFORM_RECORD['sha256']),
             'platform export bytes differ')
        selected = parse_platform_classpaths(raw)
        need(selected == BCP_ENV, 'platform selected environment differs from fixed source')
        need(metadata(os.fstat(fd)) == PLATFORM_RECORD['metadata']
             and metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) == PLATFORM_RECORD['metadata']
             and os.getxattr(fd, 'security.selinux') == label, 'platform source changed while read')
        return raw, {'original': PLATFORM_RECORD, 'raw_selinux_base64': base64.b64encode(label).decode('ascii'),
                     'selected_environment': selected, 'only_selected_keys_exported': list(PLATFORM_EXPORT_KEYS[:2])}
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent)

def prior_known_closed(current_root):
    """Verify the fixed failed two-profile original; never rerun either child."""
    required = {'SOURCE.original.py', 'PRECHECK.json', 'INTENT.json', 'FAILURE.json'}
    required.update(name + '/' + entry for name in ('baseline', 'treatment')
                    for entry in ('INTENT.json', 'CHILD-IDENTITY.json', 'PROCESS.json', 'stdout.original', 'stderr.original'))
    need(set(PRIOR_ORIGINAL_RECORDS) == required, 'complete fixed predecessor originals required')
    retained = {}
    for name in sorted(required):
        row = PRIOR_ORIGINAL_RECORDS[name]
        need(row['path'] == PRIOR_OUT + '/' + name, 'predecessor original namespace differs')
        retained[name] = exact_original(row)
    need(PRIOR_ORIGINAL_RECORDS['FAILURE.json'] == PRIOR_FAILURE_RECORD,
         'independent predecessor failure descriptors differ')
    raw = retained['FAILURE.json']
    value = json.loads(raw)
    old_root = json.loads(retained['PRECHECK.json'])
    need(set(old_root) == set(current_root) and 'self_identity' in old_root,
         'predecessor Root precheck shape differs')
    need({k:v for k,v in old_root.items() if k != 'self_identity'} ==
         {k:v for k,v in current_root.items() if k != 'self_identity'},
         'predecessor/current boot, Root identity, anchor or artifact full9 differs')
    need(value['schema'] == 'hepta.codec-root-environment-diagnostic.v1'
         and value['state'] == 'FAILED_RETAINED_NO_RETRY'
         and value['source_sha256'] == PRIOR_SOURCE_EXPECTED[1]
         and value['automatic_retry'] is False and value['automatic_adoption'] is False
         and value['native_case_count'] == 0 and value['new_native_nonces'] == 0
         and value['component_qualified'] is False and value['worker_domain_qualification'] is False
         and value['error'] == 'ValueError:child failed bounded completion; no next child',
         'fixed predecessor failure semantics differ')
    source_raw = retained['SOURCE.original.py']
    source = PRIOR_ORIGINAL_RECORDS['SOURCE.original.py']
    need((len(source_raw), sha(source_raw)) == PRIOR_SOURCE_EXPECTED, 'predecessor source differs')
    originals = [PRIOR_ORIGINAL_RECORDS[name] for name in sorted(required)]
    need(value['intent'] == PRIOR_ORIGINAL_RECORDS['INTENT.json'], 'predecessor main intent identity differs')
    main_intent_raw = retained['INTENT.json']
    main_intent = json.loads(main_intent_raw)
    need(main_intent['schema'] == 'hepta.codec-root-environment-intent.v1'
         and main_intent['source_sha256'] == PRIOR_SOURCE_EXPECTED[1]
         and main_intent['source_bytes'] == PRIOR_SOURCE_EXPECTED[0]
         and main_intent['maximum_child_launches'] == 2 and main_intent['automatic_retry'] is False
         and main_intent['preview']['expected_boot_id'] == BOOT,
         'predecessor intent differs')
    children = value['children']
    need(type(children) is list and len(children) == 2, 'predecessor two child originals required')
    groups = []
    for index, (name, expected_rc, expected_complete) in enumerate((('baseline', 0, True), ('treatment', -6, False))):
        child = children[index]
        expected_env = dict(LIFECYCLE_ENV)
        expected_env.update(COMMON_COMMAND_ENV)
        if index:
            expected_env.update(ADDED_ENV)
        ident = child['child_identity']
        need(child['schema'] == 'hepta.codec-root-owned-child-result.v1'
             and child['name'] == name and child['argv'] == argv() and child['environment'] == expected_env
             and type(child['returncode']) is int and child['returncode'] == expected_rc
             and child['recorded_and_joined'] is expected_complete
             and child['real_child_wait_returned'] is True and child['captured_streams_complete'] is True
             and child['output_truncated'] is False and child['timeout'] is False
             and child['error'] is None and child['owned_cleanup_signals'] == []
             and child['launch_count'] == child['maximum_launches'] == 1
             and child['automatic_retry'] is False and child['bytes_seen'] == child['bytes_retained'] == 0
             and set(ident) == {'pid', 'ppid', 'pgid', 'sid', 'start_ticks'}
             and all(type(x) is int and x > 0 for x in ident.values())
             and ident['pid'] == ident['pgid'] == ident['sid'],
             'predecessor child was not exactly joined with its retained original status')
        pid = ident['pid']
        need(child['group_absence'] == [{'pgid': pid, 'absent': True, 'errno': errno.ESRCH}]*2,
             'predecessor lacks its original double group absence')
        need(retained[name + '/PROCESS.json'] == encoded(child), 'predecessor PROCESS original differs')
        need(json.loads(retained[name + '/CHILD-IDENTITY.json']) == {
            'identity': ident, 'intent': child['intent'], 'root_parent': old_root['self_identity'],
            'worker_qualification_claimed': False}, 'predecessor original child/parent generation differs')
        need(ident['ppid'] == old_root['self_identity']['pid'], 'predecessor real parent differs')
        expected_intent = {'schema': 'hepta.codec-root-owned-child-intent.v1',
            'name': name, 'argv': argv(), 'environment': expected_env, 'start_new_session': True,
            'timeout_seconds': CHILD_SECONDS, 'automatic_retry': False, 'maximum_launches': 1}
        need(child['intent'] == PRIOR_ORIGINAL_RECORDS[name + '/INTENT.json']
             and retained[name + '/INTENT.json'] == encoded(expected_intent), 'predecessor child intent differs')
        for key in ('stdout', 'stderr'):
            need(child[key] == PRIOR_ORIGINAL_RECORDS[name + '/' + key + '.original']
                 and retained[name + '/' + key + '.original'] == b'', 'predecessor original stream differs')
        groups.append(pid)
    need(len(set(groups)) == 2 and children[0]['child_identity']['ppid'] == children[1]['child_identity']['ppid'],
         'predecessor owned child identities collide')
    current_absence = [[group_absence(pid) for pid in groups]]
    time.sleep(0.05)
    current_absence.append([group_absence(pid) for pid in groups])
    need(all(row['absent'] is True and row['errno'] == errno.ESRCH
             for batch in current_absence for row in batch),
         'predecessor group is not currently absent; no cleanup or new child permitted')
    for row in originals:
        exact_original(row)
    return {'original_failure': PRIOR_FAILURE_RECORD, 'original_source': source,
            'originals': originals, 'known_closed_from_real_wait_and_absence': True,
            'original_baseline_returncode': 0, 'original_treatment_returncode': -6,
            'original_treatment_recorded_and_joined': False, 'current_group_absence': current_absence,
            'prior_precheck_matches_current_except_self_identity': True,
            'original_after_file_claimed': False,
            'predecessor_children_replayed': 0, 'automatic_retry': False}

def combined_precheck():
    root = precheck()
    prior = prior_known_closed(root)
    _, platform = platform_original()
    return {'root': root, 'prior': prior, 'platform': platform}

def preview():
    previous_env = dict(LIFECYCLE_ENV)
    previous_env.update(COMMON_COMMAND_ENV)
    previous_env.update(ADDED_ENV)
    return {'schema': SCHEMA, 'state': 'PREVIEW_ONLY_NO_PHONE_PATH_READ_OR_CHILD_PROCESS',
            'out': OUT, 'expected_boot_id': BOOT, 'child_argv': argv(),
            'prior_failed_diagnostic': PRIOR_FAILURE_RECORD,
            'platform_environment_original': PLATFORM_RECORD,
            'previous_treatment_environment': previous_env,
            'new_child_environment': environment(True),
            'only_environment_increment': BCP_ENV,
            'ignored_platform_keys': list(PLATFORM_EXPORT_KEYS[2:]),
            'invalid_args': INVALID_ARGS, 'maximum_child_launches': 1,
            'previous_children_replayed': 0, 'per_child_timeout_seconds': CHILD_SECONDS,
            'per_cleanup_wait_seconds': CLEANUP_SECONDS,
            'total_output_bytes_per_child_maximum': OUTPUT_CAP,
            'root_only': True, 'worker_uid_domain_qualification': False,
            'expected_java_entry_marker': {'exit_code': 20, 'schema': 'hepta.phone-screenshot.v1',
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
    before = combined_precheck()
    mkdir_once(OUT)
    put(OUT + '/SOURCE.original.py', raw)
    precheck_record = put(OUT + '/PRECHECK.json', before)
    platform_raw, platform_value = platform_original()
    need(platform_value == before['platform'], 'platform changed before original retention')
    put(OUT + '/PLATFORM-CLASSPATH.original', platform_raw)
    intent = put(OUT + '/INTENT.json', {'schema': 'hepta.codec-root-classpath-intent.v1',
        'source_sha256': expected, 'source_bytes': len(raw), 'preview': preview(),
        'precheck': precheck_record, 'maximum_child_launches': 1,
        'previous_children_replayed': 0, 'automatic_retry': False})
    children = []
    try:
        need(combined_precheck() == before, 'pre-child root/platform/predecessor bookend differs')
        child, stdout, stderr = run_child('classpath', True)
        children.append(child)
        need(child['recorded_and_joined'], 'new child failed bounded completion; no replay')
        after = combined_precheck()
        need(after == before, 'post-child root/platform/predecessor bookend differs')
        after_record = put(OUT + '/AFTER.json', after)
        marker = None
        try:
            marker = json.loads(stdout)
        except (UnicodeError, ValueError):
            pass
        matched = child['returncode'] == 20 and marker == {
            'schema': 'hepta.phone-screenshot.v1', 'status': 'rejected', 'reason': 'shell_uid_required'}
        final = {'schema': SCHEMA,
            'state': 'ROOT_ONLY_PLATFORM_CLASSPATH_JAVA_ENTRY_OBSERVED' if matched else 'ROOT_ONLY_PLATFORM_CLASSPATH_RECORDED_NOT_MATCHED',
            'intent': intent, 'precheck': precheck_record, 'after': after_record,
            'source_sha256': expected, 'children': children,
            'prior_failed_diagnostic': PRIOR_FAILURE_RECORD,
            'prior_known_closed': True, 'original_treatment_recorded_and_joined': False,
            'previous_children_replayed': 0, 'maximum_child_launches': 1,
            'platform_environment_original': PLATFORM_RECORD, 'only_environment_increment': BCP_ENV,
            'java_uid_rejection_observed': matched, 'artifact_and_input_bookends_equal': True,
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
            'intent': intent, 'precheck': precheck_record,
            'source_sha256': expected, 'children': children,
            'prior_failed_diagnostic': PRIOR_FAILURE_RECORD,
            'platform_environment_original': PLATFORM_RECORD,
            'previous_children_replayed': 0, 'maximum_child_launches': 1,
            'error': type(error).__name__ + ':' + str(error)[:1024],
            'automatic_retry': False, 'automatic_adoption': False,
            'worker_domain_qualification': False, 'component_qualified': False,
            'native_case_count': 0, 'new_native_nonces': 0}
        put(OUT + '/FAILURE.json', failure)
        print(encoded(failure).decode('ascii'), end='', flush=True)
        return 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-root-codec-classpath-diagnostic', action='store_true')
    parser.add_argument('--reviewed-source-sha256')
    args = parser.parse_args()
    if not args.execute_root_codec_classpath_diagnostic:
        print(encoded(preview()).decode('ascii'), end='')
        return 0
    need(args.reviewed_source_sha256 is not None, 'explicit source SHA required')
    return execute(args.reviewed_source_sha256)

if __name__ == '__main__':
    raise SystemExit(main())
