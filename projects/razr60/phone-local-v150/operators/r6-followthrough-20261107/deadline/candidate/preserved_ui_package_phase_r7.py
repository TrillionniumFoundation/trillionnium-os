#!/usr/bin/env python3
"""Restore five exact previous UI packages to the corrected Root12 guest. Inert by default.
Modern-style restoration is a separate required successor, never written here.

Uses only existing ADB smart sockets. Never starts or manages ADB, obtains root,
updates SystemUI, clears data, or edits permissions/USB configuration. This is
an ordinary matching-signed app-update successor to DSU installation, not proof
of restoration of old app-private data or of complete UI migration.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import struct
import stat
import subprocess
import time

SERIAL = 'ZY22LS7WZT'
RELEASE_READY = True  # Actual Root-provided host artifact pins; guest remains unobserved.
SLOT = 'r57-ui18-source-d8d7e73f9c6c-20261101-root12'
BUNDLE = 'd8d7e73f9c6cf9f185618ef8a633838567ac408913f663b4191787cb3548ba8c'
ROOT12_BOOT = 'c75d2d48-0b4f-4038-82d6-aa0b365b0bc9'
SLOT_ANCHOR = Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01/ROOT12-c75-actual-native-slot-anchor.json')
SLOT_ANCHOR_SHA = 'fda1c86733b491d3580bbc643dc0d58318e5cbe1ed2347db175283d09b0b646d'
OBSERVATION_SHA = 'f6e5c4815c2c5832366b4311fe00ebd578c41eeb01d68fd3a1e9ffc4cd73c437'
COLLECTOR_SHA = '0353078c4f4636062a603412d35e4dc2b753f46964001dee523e3df8f67f9f24'
DISPATCHER_SHA = '450d9f0c3a311488022ad2a4d8b5ae99a9b60cd4e7d23371cb5c1fb7ffb2553d'
SYSTEMUI = '2d92780fb72f7ee7167c7c7ac56fbd0b12d687f49ea0cfedfd4017294568f16f'
HOME = 'com.android.launcher3/com.android.launcher3.CustomizationPanelLauncher'
STAGE = '/data/local/tmp/codex-preserved-ui-root12-20261101'
JOURNAL = Path('/home/alex/codex-preserved-ui-root12-bootstrap-20261101-01/journal')
BOOT = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
PRESERVED = {
    'com.android.launcher3': ('c627fe7cc456d03e1df4842a17ba89560c0f7921736848ae55b9047f5fb15f6e',
                            '1b079cefcf24e1cfe8449124094d5fb6a5fe260666d7fd8b8b39a27f5d096250', 'HOME'),
    'org.trillionnium.owneropen': ('56c4e302cbe7448dffc9a0d8cfa8db2c2cb019fcb055fab36b815105dd55592f',
                                  '185bbbdfa0c4ab5b8f4a666f82b44c50e8f11d356f39af6572924e5cc7c4b12d', 'HEPTA'),
    'org.trillionnium.ui.moto.systemui.qs.v1': ('141198f39aad6c3a08effe8094dcf3438413b0fff0eef9b073f77c48fc5d04de', None, 'RRO'),
    'org.trillionnium.ui.moto.systemui.volumepower.v1': ('9a1b6d1014a9b0e212b36e8a16efa6af35ee5146d04e2e88fe0249c85b7f3b54', None, 'RRO'),
    'org.trillionnium.ui.moto.systemui.keyguard.v1': ('68a174e07d8ce0fcede333ea1f609bd1f2aed5832b150a62499da8fab5f56fa0', None, 'RRO'),
}


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()


def remaining_timeout(deadline, maximum=None):
    """Use one monotonic budget; timeout never means the remote effect stopped."""
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Whole shell observation deadline; outcome unknown, observe before any retry')
    return remaining if maximum is None else min(maximum, remaining)


def receive(s, count, deadline=None):
    data = b''
    while len(data) < count:
        if deadline is not None:
            s.settimeout(remaining_timeout(deadline, s.gettimeout()))
        b = s.recv(count - len(data))
        if deadline is not None:
            remaining_timeout(deadline)
        need(b, 'Existing ADB socket closed; observe before any retry')
        data += b
    return data


def request(s, command, deadline=None):
    data = command.encode()
    need(len(data) < 65536, 'ADB request bound')
    if deadline is not None:
        s.settimeout(remaining_timeout(deadline, s.gettimeout()))
    s.sendall(('%04x' % len(data)).encode() + data)
    result = receive(s, 4, deadline)
    if result == b'FAIL':
        raise RuntimeError(receive(s, int(receive(s, 4, deadline), 16), deadline).decode())
    need(result == b'OKAY', 'ADB service response')


def host(port, command, deadline=None):
    with socket.create_connection(('127.0.0.1', port), timeout=remaining_timeout(deadline, 5)) as s:
        request(s, command, deadline)
        return receive(s, int(receive(s, 4, deadline), 16), deadline).decode()


def route(c, deadline=None):
    """Read both existing servers; never migrate or manage either server."""
    need(os.uname().nodename == c['execution_host'] and os.getuid() == 1000,
         'Pinned ordinary Pocket4 host required')
    targets = []
    for port in (5037, 5061):
        result = subprocess.run(['ss', '-ltnp', 'sport = :' + str(port)],
                                capture_output=True, timeout=remaining_timeout(deadline, 5))
        need(result.returncode == 0, 'Listener read failed')
        need(set(re.findall(rb'pid=(\d+)', result.stdout)) ==
             {str(c['server_pids'][str(port)]).encode()}, 'Existing listener PID changed')
        need(host(port, 'host:version', deadline) == '0029', 'Existing server protocol changed')
        hits = [line.split() for line in host(port, 'host:devices-l', deadline).splitlines()
                if line.split() and line.split()[0] == SERIAL]
        need(len(hits) <= 1, 'Duplicate target serial in one server')
        if hits:
            line = hits[0]
            need(len(line) >= 2 and line[1] == 'device', 'Target route is not online')
            ids = [x[13:] for x in line if x.startswith('transport_id:')]
            need(len(ids) == 1 and re.fullmatch(r'[1-9][0-9]*', ids[0]),
                 'Actual unique transport ID required')
            targets.append((port, ids[0]))
    need(len(targets) == 1, 'Exactly one target across the two existing servers required')
    return targets[0]


def shell(command, c, transport, timeout=120):
    deadline = time.monotonic() + timeout
    need(route(c, deadline) == transport, 'Target route changed before wire; observe before retry')
    with socket.create_connection(('127.0.0.1', transport[0]), timeout=remaining_timeout(deadline, timeout)) as sock:
        request(sock, 'host:transport-id:' + transport[1], deadline)
        request(sock, 'shell,v2,raw:' + command, deadline)
        stdout, stderr, code = b'', b'', None
        while code is None:
            stream, length = struct.unpack('<BI', receive(sock, 5, deadline))
            need(length <= 8388608, 'Shell frame bound')
            payload = receive(sock, length, deadline)
            if stream == 1:
                stdout += payload
            elif stream == 2:
                stderr += payload
            elif stream == 3:
                code = int.from_bytes(payload, 'little')
            need(len(stdout) + len(stderr) <= 8388608, 'Shell output bound')
        remaining_timeout(deadline)
        return {'command': command, 'rc': code, 'route': list(transport),
                'stdout': stdout.decode('utf-8', 'replace'),
                'stderr': stderr.decode('utf-8', 'replace')}


def read(command, c, transport):
    result = shell(command, c, transport)
    need(result['rc'] == 0, 'Required read failed: ' + str(result))
    return result['stdout'].strip()


def active_slot(raw):
    data = bytearray()
    for line in raw.splitlines():
        m = re.match(r'^0x([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{8}\s+)+)', line)
        if m:
            need(int(m[1], 16) == len(data), 'Parcel offset')
            for word in m[2].split():
                data.extend(struct.pack('<I', int(word, 16)))
    need(len(data) >= 12 and data[:4] == b'\0' * 4, 'Parcel result')
    count = struct.unpack('<i', data[4:8])[0]
    need(0 < count <= 63, 'DSU slot string bound')
    end = 8 + count * 2
    need(len(data) >= end + 2 and data[end:] == b'\0' * (len(data) - end), 'Parcel padding')
    return data[8:end].decode('utf-16le')



def verified_ref(reference, limit=4194304):
    path = Path(reference['path'])
    need(path.is_absolute() and path.resolve() == path and stat.S_ISREG(path.lstat().st_mode)
         and path.stat().st_size == reference['bytes'] <= limit, 'Immutable anchor reference path/size changed')
    raw = path.read_bytes()
    need(len(raw) == reference['bytes'] and hashlib.sha256(raw).hexdigest() == reference['sha256'],
         'Immutable anchor reference bytes changed')
    return raw


def slot_anchor(c, expected_boot):
    """Historical actual native slot + continuous exact Boot, never fresh native."""
    need(expected_boot == ROOT12_BOOT, 'This native slot proof is scoped only to the proven c75 boot')
    raw = verified_ref({'path': str(SLOT_ANCHOR), 'sha256': SLOT_ANCHOR_SHA, 'bytes': 1397}, 16384)
    anchor = json.loads(raw)
    need(anchor['schema'] == 'root12.actual-native-slot.same-running-boot-anchor.v1'
         and anchor['created_by'] == 'Root' and anchor['serial'] == SERIAL
         and anchor['boot'] == ROOT12_BOOT and anchor['SDK'] == 37
         and anchor['SystemUI_sha256'] == SYSTEMUI and anchor['slot'] == SLOT
         and anchor['bundle_sha256'] == BUNDLE
         and anchor['no_intervening_DSU_startInstallation_or_switch_or_reboot'] is True,
         'This is not the exact controlled same-Boot slot anchor')
    reference = anchor['source_observation']
    need(reference['sha256'] == OBSERVATION_SHA and reference['bytes'] == 5597,
         'Actual formal native observation changed')
    observation = json.loads(verified_ref(reference, 65536))
    need(anchor['source_collector_sha256'] == observation['collector_sha256'] == COLLECTOR_SHA
         and anchor['source_dispatcher_sha256'] == observation['dispatcher_sha256'] == DISPATCHER_SHA,
         'Actual observer Source provenance changed')
    tools = Path('/home/alex/codex-deploy-dsu-ui18-current-source-tools-20261101-root12')
    need(digest(tools / 'collect_observation_ui18.py') == COLLECTOR_SHA
         and digest(tools / 'dsu_dispatch.py') == DISPATCHER_SHA, 'Actual captured observer Source bytes changed')
    need(observation['recorded_by'] == 'root' and observation['kind'] == 'guest'
         and observation['boot_id'] == observation['boot_id_after'] == ROOT12_BOOT
         and observation['sdk'] == 37 and observation['systemui_apk_sha256'] == SYSTEMUI
         and observation['serial'] == SERIAL and observation['uid'] == 2000
         and observation['physical_slot'] == '_a' and observation['selinux'] == 'Enforcing'
         and observation['boot_completed'] == '1' and observation['fingerprint'] == c['guest_fingerprint']
         and observation['vbmeta_digest'] == c['vbmeta_digest']
         and observation['gsi_status'] == ['running', 'installed', 'disabled']
         and observation['slot_read_method_verified_readonly'] is True
         and observation['active_dsu_slot'] == active_slot(observation['active_slot_wire']) == SLOT,
         'Archived actual native slot/first-last Boot/image/DSU proof differs')
    refs = observation['raw_evidence_refs']
    need(isinstance(refs, list) and 0 < len(refs) <= 64, 'Actual native observation raw references required')
    for reference in refs:
        verified_ref(reference)
    return {'slot': SLOT, 'boot': ROOT12_BOOT, 'anchor_sha256': SLOT_ANCHOR_SHA,
            'native_observation_sha256': OBSERVATION_SHA,
            'basis': 'previous_actual_native_slot_on_same_controlled_boot_plus_current_continuous_identity',
            'fresh_native_slot_getter': False}


def identity(c, expected_boot):
    proof = slot_anchor(c, expected_boot)
    transport = route(c)
    need(read('cat /proc/sys/kernel/random/boot_id', c, transport) == expected_boot,
         'Guest boot changed')
    checks = {'getprop ro.boot.serialno': SERIAL, 'id -u': '2000',
              'getprop ro.build.version.sdk': '37',
              'getprop ro.boot.slot_suffix': '_a', 'getenforce': 'Enforcing',
              'getprop sys.boot_completed': '1', 'am get-current-user': '0',
              'getprop ro.build.fingerprint': c['guest_fingerprint'],
              'getprop ro.boot.vbmeta.digest': c['vbmeta_digest'],
              'gsi_tool status': 'running\ninstalled\ndisabled'}
    for command, expected in checks.items():
        need(read(command, c, transport) == expected, 'Guest identity differs: ' + command)
    need(proof['slot'] == SLOT and proof['boot'] == expected_boot,
         'Proven Root12 slot must remain on its exact controlled boot')
    actual_package = package('com.android.systemui', c, transport)
    need(actual_package['sha256'] == SYSTEMUI, 'Actual corrected Root12 SystemUI required')
    pid = read('pidof com.android.systemui', c, transport)
    need(re.fullmatch(r'[1-9][0-9]*', pid), 'Unique live SystemUI PID required')
    need(read('cat /proc/sys/kernel/random/boot_id', c, transport) == expected_boot,
         'Guest boot changed after package hash')
    need(route(c) == transport, 'Route changed during identity read')
    diagnostic = read('getprop ro.gsid.image_running', c, transport)
    return {'boot': expected_boot, 'SystemUI_PID': pid, 'SystemUI': actual_package,
            'port': transport[0], 'transport_id': transport[1],
            'gsid_image_running_diagnostic_only': diagnostic, 'slot_proof': proof}


def package(name, c, transport):
    need(re.fullmatch(r'[A-Za-z0-9_.]+', name), 'Package name')
    result = shell('pm path --user 0 ' + shlex.quote(name), c, transport)
    if result['rc'] == 1 and not result['stdout'].strip() and not result['stderr'].strip():
        return {'package': name, 'path': None, 'sha256': None}
    need(result['rc'] == 0 and not result['stderr'].strip(), 'Package path read failed: ' + str(result))
    paths = result['stdout'].strip().splitlines()
    need(bool(paths), 'Unexpected empty successful package path')
    need(len(paths) == 1 and paths[0].startswith('package:/'), 'Single base APK required')
    path = paths[0][8:]
    row = read('sha256sum ' + shlex.quote(path), c, transport)
    need(re.fullmatch(r'[0-9a-f]{64}  /[^\n]+', row), 'Exact package SHA readback')
    return {'package': name, 'path': path, 'sha256': row.split()[0]}


def save(path, value):
    data = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with path.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def push(source, destination, c, transport):
    """AOSP sync to an inert staging APK; existing exact route only."""
    need(route(c) == transport, 'Target route changed before staging transfer')
    with socket.create_connection(('127.0.0.1', transport[0]), timeout=120) as sock:
        request(sock, 'host:transport-id:' + transport[1])
        request(sock, 'sync:')
        target = (destination + ',' + str(0o100644)).encode()
        sock.sendall(b'SEND' + struct.pack('<I', len(target)) + target)
        with Path(source).open('rb') as f:
            for b in iter(lambda: f.read(65536), b''):
                sock.sendall(b'DATA' + struct.pack('<I', len(b)) + b)
        sock.sendall(b'DONE' + struct.pack('<I', 0))
        state, length = struct.unpack('<4sI', receive(sock, 8))
        if state == b'FAIL':
            need(length <= 65536, 'SYNC failure bound')
            raise RuntimeError(receive(sock, length).decode())
        need(state == b'OKAY', 'SYNC SEND completion missing')


def guarded_shell(command, c, expected_boot, current):
    proof = slot_anchor(c, expected_boot)
    need(proof['slot'] == SLOT and proof['boot'] == current['boot'] == expected_boot,
         'Same-Boot archived native slot assertion failed before writing')
    transport = (current['port'], current['transport_id'])
    checks = {'getprop ro.boot.serialno': SERIAL, 'id -u': '2000',
              'getprop ro.build.version.sdk': '37',
              'getprop ro.boot.slot_suffix': '_a', 'getenforce': 'Enforcing',
              'getprop sys.boot_completed': '1', 'am get-current-user': '0',
              'getprop ro.build.fingerprint': c['guest_fingerprint'],
              'getprop ro.boot.vbmeta.digest': c['vbmeta_digest'],
              'gsi_tool status': 'running\ninstalled\ndisabled',
              'cat /proc/sys/kernel/random/boot_id': expected_boot,
              'pidof com.android.systemui': current['SystemUI_PID'],
              'sha256sum /system_ext/priv-app/SystemUI/SystemUI.apk':
                  SYSTEMUI + '  /system_ext/priv-app/SystemUI/SystemUI.apk'}
    wire = 'set -f\n' + ''.join('[ "$(' + query + ')" = ' + shlex.quote(wanted) + ' ] || exit 78\n'
                                  for query, wanted in checks.items())
    for query, wanted in [('cat /proc/sys/kernel/random/boot_id', expected_boot),
                          ('gsi_tool status', 'running\ninstalled\ndisabled'),
                          ('getprop ro.build.version.sdk', '37'),
                          ('am get-current-user', '0'),
                          ('pidof com.android.systemui', current['SystemUI_PID'])]:
        wire += '[ "$(' + query + ')" = ' + shlex.quote(wanted) + ' ] || exit 78\n'
    wire += command + '\n'
    return shell('sh -c ' + shlex.quote(wire), c, transport)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', nargs='?', default='plan', choices=['plan', 'capture', 'apply-packages'])
    p.add_argument('--config', type=Path)
    p.add_argument('--actor')
    p.add_argument('--expected-boot')
    p.add_argument('--out', type=Path)
    a = p.parse_args()
    if a.mode == 'plan':
        print(json.dumps({'phone_operations': 0, 'release_ready': RELEASE_READY,
                          'restore': 'exact HOME c627, HEPTA49, three RROs, HOME alias and real Global sleep1',
                          'remaining': ['modern native selection', 'Recents binding', 'effective RRO values', 'saved layout/widgets', 'complete UI migration']}))
        return
    need(RELEASE_READY and isinstance(SLOT, str) and isinstance(BUNDLE, str),
         'Draft is not armed; actual new bundle and slot are required before freeze')
    need(a.actor == 'root' and a.expected_boot and BOOT.fullmatch(a.expected_boot),
         'Explicit Root/current guest boot required')
    need(a.config and a.out and a.out.is_absolute() and not a.out.exists(),
         'Config and fresh absolute host output required')
    c = json.loads(a.config.read_text())
    need(c['schema'] == 'razr.preserved-ui-five-packages.bootstrap.v4' and
         c['slot'] == SLOT and c['bundle_sha256'] == BUNDLE and
         c['SystemUI_sha256'] == SYSTEMUI, 'Pinned corrected Root12 config')
    need(c['execution_host'] == 'alex-G1628-04' and
         c['server_pids'] == {'5037': 456268, '5061': 39400}, 'Existing host/server pins')
    need(len(c['packages']) == 5 and {x['package'] for x in c['packages']} == set(PRESERVED),
         'Five exact preserved packages')
    for app in c['packages']:
        need((app['sha256'], app['baseline_sha256'], app['kind']) == PRESERVED[app['package']],
             'Preserved package identities changed')
        need(re.fullmatch(r'[a-z0-9-]{1,32}', app['name']), 'Safe staging/action name required')
        need(digest(app['source']) == app['sha256'], 'Preserved APK changed')
    a.out.mkdir(mode=0o700)
    if a.mode == 'apply-packages':
        JOURNAL.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = JOURNAL.parent.lstat()
        need(JOURNAL.parent.resolve() == JOURNAL.parent and stat.S_ISDIR(st.st_mode)
             and st.st_uid == 1000 and not st.st_mode & 0o077, 'Canonical private journal required')
        fd = os.open(JOURNAL.parent / 'bootstrap.lock',
                     os.O_WRONLY | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        lock = os.fdopen(fd, 'a')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    before = identity(c, a.expected_boot)
    transport = (before['port'], before['transport_id'])
    save(a.out / 'BEFORE.json', {'identity': before,
         'packages': [package(x['package'], c, transport) for x in c['packages']],
         'modern': read('settings --user 0 get global show_panel_view_modern_style', c, transport),
         'legacy_modern': read('settings --user 0 get global show_panel_view_prc_style', c, transport),
         'doubletap': read('settings --user 0 get global put_display_to_sleep', c, transport),
         'home': read('cmd package resolve-activity --brief --user 0 -a android.intent.action.MAIN -c android.intent.category.HOME', c, transport),
         'overlays': read('cmd overlay list --user 0 com.android.systemui', c, transport)})
    if a.mode == 'capture':
        print(json.dumps({'state': 'READ_ONLY', 'out': str(a.out)}))
        return
    JOURNAL.mkdir(mode=0o700, exist_ok=True)
    need(JOURNAL.resolve() == JOURNAL and stat.S_ISDIR(JOURNAL.lstat().st_mode),
         'Canonical action journal required')

    def effect(name, operation):
        current = identity(c, a.expected_boot)
        save(JOURNAL / (name + '.intent.json'), {'boot': a.expected_boot, 'identity': current,
             'config_sha256': digest(a.config), 'source_sha256': digest(__file__),
             'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'no_replay': True})
        result = operation(current)
        save(JOURNAL / (name + '.result.json'), result)
        return result

    for app in c['packages']:
        current = identity(c, a.expected_boot)
        transport = (current['port'], current['transport_id'])
        installed = package(app['package'], c, transport)
        if installed['sha256'] == app['sha256']:
            continue
        need(installed['sha256'] == app['baseline_sha256'], 'Unexpected installed revision: ' + app['package'])
        destination = STAGE + '-' + app['name'] + '.apk'
        def stage(current, app=app, destination=destination):
            transport = (current['port'], current['transport_id'])
            need(read('if [ -e ' + shlex.quote(destination) + ' ]; then echo PRESENT; else echo ABSENT; fi', c, transport) == 'ABSENT',
                 'Fresh staging target required')
            push(app['source'], destination, c, transport)
            need(read('sha256sum ' + shlex.quote(destination), c, transport).split()[0] == app['sha256'],
                 'Staged APK hash differs')
            identity(c, a.expected_boot)
            return {'device_path': destination, 'sha256': app['sha256'], 'route': list(transport)}
        effect('stage-' + app['name'], stage)
        def install(current, app=app, destination=destination):
            r = guarded_shell('cmd package install -r -t --user 0 ' + shlex.quote(destination),
                              c, a.expected_boot, current)
            need(r['rc'] == 0 and r['stdout'].strip() == 'Success', 'Install outcome not confirmed: ' + str(r))
            transport = (current['port'], current['transport_id'])
            need(package(app['package'], c, transport)['sha256'] == app['sha256'], 'Installed APK differs')
            return r
        effect('install-' + app['name'], install)

    commands = [('enable-home-alias', 'pm enable --user 0 ' + HOME),
                ('select-home', 'cmd package set-home-activity --user 0 ' + HOME)]
    commands += [('enable-' + app['name'], 'cmd overlay enable --user 0 ' + app['package'])
                 for app in c['packages'] if app['kind'] == 'RRO']
    commands += [('doubletap-sleep', 'settings --user 0 put global put_display_to_sleep 1')]
    for name, command in commands:
        def run(current, command=command):
            r = guarded_shell(command, c, a.expected_boot, current)
            need(r['rc'] == 0, 'Configuration outcome not confirmed: ' + str(r))
            return r
        effect(name, run)
    after = identity(c, a.expected_boot)
    transport = (after['port'], after['transport_id'])
    packages = [package(app['package'], c, transport) for app in c['packages']]
    need(all(actual['sha256'] == wanted['sha256'] for actual, wanted in zip(packages, c['packages'])),
         'Five-package readback differs')
    resolved = read('cmd package resolve-activity --brief --user 0 -a android.intent.action.MAIN -c android.intent.category.HOME', c, transport)
    need(resolved.splitlines()[-1] == HOME, 'Declared HOME alias did not resolve')
    overlays = read('cmd overlay list --user 0 com.android.systemui', c, transport)
    for app in c['packages']:
        if app['kind'] == 'RRO':
            need('[x] ' + app['package'] in overlays, 'Preserved RRO not enabled')
    need(read('settings --user 0 get global put_display_to_sleep', c, transport) == '1',
         'Doubletap sleep preference differs')
    save(a.out / 'AFTER.json', {'identity': after, 'packages': packages, 'resolved_home': resolved,
         'overlays': overlays, 'state': 'FIVE_PACKAGES_HOME_RROS_AND_GLOBAL_SLEEP_RESTORED_MODERN_PENDING',
         'modern_raw': read('settings --user 0 get global show_panel_view_modern_style', c, transport),
         'legacy_raw': read('settings --user 0 get global show_panel_view_prc_style', c, transport),
         'remaining': ['Modern preference restoration through actual accepted native consumer', 'actual Recents/Quickstep UID and service binding',
                       '15 effective RRO dimensions', 'saved layout/widgets/private state restoration', 'targeted visual/interaction checks', 'complete SystemUI migration']})
    print(json.dumps({'state': 'FIVE_PACKAGES_HOME_RROS_AND_GLOBAL_SLEEP_RESTORED_MODERN_PENDING',
                      'out': str(a.out), 'full_restoration_proven': False}))


if __name__ == '__main__':
    main()
