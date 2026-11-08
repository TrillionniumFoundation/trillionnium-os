#!/usr/bin/env python3
"""Sole Root operator for COMP-01/NEG-01/NEG-02; inert unless --execute-once.

All component mappings and validators are the frozen actual-source CLI. Setup
is separately labelled operator work. No native task, provider execution,
model request, app-private edit, process signal, or uncertain action retry.
"""
import argparse
import base64
import fcntl
import importlib
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time
import types

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from component_core import (need, sha, encoded, strict, raw_file, put, load_inputs,
    wire_exchange, encoded_submit_point, PACKAGE, INPUT_ID, SUBMIT_ID, RECEIPT_ID,
    CONFIG_SHA, SEAL_SHA, SERVICE_SHA, INPUTS_SHA, CLIENT_SHA, COMPONENT_SHA,
    SERIAL, PHYSICAL_DISPLAY, TEXT_COMPONENT, VISUAL_COMPONENT)

P4_BASE = Path('/home/alex/razr60-local-model-v150')
F_SOURCE = Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved_ui_package_phase_r7.py')
F_SHA = '6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
CLIENT_PATH = '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py'
GNU_BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'


def verify_package(path, pin):
    need(path.parent.resolve(strict=True) / 'source' == HERE, 'package is not this executable directory')
    raw = raw_file(path)
    need(sha(raw) == pin, 'component operator package pin differs')
    value = strict(raw)
    need(value['schema'] == 'hepta.r9.component-operator-package.v1', 'component package schema differs')
    names = set()
    for row in value['files']:
        relative = Path(row['path'])
        need(not relative.is_absolute() and '..' not in relative.parts and str(relative) not in names,
             'unsafe or duplicate package path')
        names.add(str(relative))
        data = raw_file(path.parent / relative)
        need(len(data) == row['bytes'] and sha(data) == row['sha256'], 'component package file differs')
    need({'source/component_once_r9.py', 'source/component_core.py', 'source/component_support.py',
          'source/production-pins.json', 'reference/component_direct.py'} <= names, 'package inventory incomplete')
    need(sha(raw_file(path.parent / 'reference/component_direct.py')) == COMPONENT_SHA,
         'frozen component entry differs')
    return strict(raw_file(HERE / 'production-pins.json'))


def private_directory(path):
    need(path.parent.resolve(strict=True) == path.parent, 'private parent is noncanonical')
    try:
        path.mkdir(mode=0o700)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except FileExistsError:
        pass
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o700,
         'private output directory ownership or mode differs')


def bwrap_command(package, inputs, out, entry, argv):
    """RO actual source/client, RW only this output; same host monotonic clock."""
    return ['/usr/bin/bwrap', '--unshare-user', '--uid', '0', '--gid', '0',
        '--unshare-pid', '--unshare-net', '--unshare-ipc', '--unshare-uts',
        '--new-session', '--die-with-parent', '--ro-bind', '/usr', '/usr',
        '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
        '--symlink', 'usr/bin', '/bin', '--dir', '/etc', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--dir', str(Path(CLIENT_PATH).parent),
        '--ro-bind', str(inputs / 'client/tool_client_r6.py'), CLIENT_PATH,
        '--ro-bind', str(inputs), '/inputs', '--ro-bind', str(package), '/suite',
        '--bind', str(out), str(out), '--chdir', str(out), '--clearenv',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
        '/usr/bin/python3', '-I', '-B', '/suite/' + entry, *map(str, argv)]


def source_check_command(production_pins, boot):
    pins = {GNU_BASE + '/provider-r9-r2/source/' + name: pin for name, pin in production_pins.items()}
    pins.update({GNU_BASE + '/provider-r9-r2/SOURCE-SEAL-v150-r9.json': SEAL_SHA,
        GNU_BASE + '/local-config-r9-r2.json': CONFIG_SHA,
        GNU_BASE + '/PHONE-SERVICE-INPUTS-v150-r9-r2.json': SERVICE_SHA,
        CLIENT_PATH: CLIENT_SHA})
    payload = base64.b64encode(encoded({'pins': pins, 'boot': boot})).decode()
    code = """import base64,hashlib,json,os,stat,sys
from pathlib import Path
p=json.loads(base64.b64decode(sys.argv[1]));assert os.getuid()==0
assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot']
rows=[]
for name,want in sorted(p['pins'].items()):
 path=Path(name);assert path.parent.resolve(strict=True)==path.parent
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_uid==a.st_gid==0 and a.st_nlink==1 and a.st_size<=262144
  with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(262145)
  b,n=os.fstat(fd),path.lstat()
  assert all(getattr(a,k)==getattr(b,k)==getattr(n,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  assert len(raw)==a.st_size and hashlib.sha256(raw).hexdigest()==want
  rows.append({'path':name,'bytes':len(raw),'sha256':want})
 finally:os.close(fd)
assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==p['boot']
print(json.dumps({'schema':'hepta.r9.component-actual-source-read.v1','boot':p['boot'],'files':rows,'model_requests':0}))
"""
    inside = ('/data/adb/magisk/busybox timeout -s TERM -k 1 10 /data/adb/magisk/busybox chroot '
              '/data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c ' + shlex.quote(code) + ' ' + shlex.quote(payload))
    command = '/debug_ramdisk/su -c ' + shlex.quote(inside)
    need(len(('shell,v2,raw:' + command).encode()) < 65536, 'source observer exceeds short ADB request')
    return command


class Actor:
    def __init__(self, args, pins):
        self.args, self.pins, self.out = args, pins, args.out
        self.package = args.package.parent
        self.counter = 0
        self.setup_counter = 0
        self.host_counter = 0
        self.phone_stage = '/data/local/tmp/hepta-component-r9-' + args.label
        self.created = time.monotonic()
        self.deadline = self.created + 180
        raw = raw_file(F_SOURCE)
        need(sha(raw) == F_SHA, 'original existing-ADB transport bytes differ')
        self.f = types.ModuleType('pinned_original_adb_transport')
        self.f.__file__ = str(F_SOURCE)
        exec(compile(raw, str(F_SOURCE), 'exec'), self.f.__dict__)
        self.config = strict(raw_file(F_SOURCE.parent / 'preserved-ui-package-config.json'))
        self.route = self.f.route(self.config)
        sys.path.insert(0, str(args.inputs / 'provider/source'))
        self.guards = importlib.import_module('phone_task_guards')
        self.phone = importlib.import_module('phone_observation_tools')
        self.identity = {'schema': 'hepta.r9.operator-component-setup-identity.v1',
            'operator_id': args.operator_id, 'case_id': args.case_id, 'nonce': secrets.token_hex(16),
            'native_task_claim': False, 'model_requests': 0}
        put(self.out / 'SETUP-IDENTITY.json', self.identity)

    def basic_guard(self):
        return ('[ "$(id -u)" = 2000 ] || exit 78; '
            '[ "$(getprop ro.serialno)" = ' + shlex.quote(SERIAL) + ' ] || exit 78; '
            '[ "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(self.args.expected_boot) + ' ] || exit 78; ')

    def raw(self, command, tag, seconds=30):
        need(re.fullmatch('[a-z0-9-]{1,64}', tag) is not None, 'wire tag differs')
        remaining = int(self.deadline - time.monotonic())
        need(remaining >= 1, 'operator total 180-second bound exceeded')
        seconds = min(seconds, remaining)
        self.counter += 1
        prefix = self.out / ('wire-%03d-%s' % (self.counter, tag))
        put(prefix.with_suffix('.INTENT.json'), {'command': command,
            'wire_request_bytes': len(('shell,v2,raw:' + command).encode()),
            'p4_monotonic_ns': time.monotonic_ns(), 'automatic_retry': False})
        need(self.f.route(self.config) == self.route, 'existing ADB route changed; no redispatch')
        return wire_exchange(self.f, ('127.0.0.1', self.route[0]), self.route[1], command, prefix, seconds=seconds)

    def read(self, command, tag, seconds=30):
        receipt = self.raw(command, tag, seconds)
        need(receipt['exit_code'] == 0 and receipt['output_complete'] and receipt['stderr']['bytes'] == 0,
             'original readonly command has no clean complete terminal: ' + tag)
        return raw_file(Path(receipt['stdout']['path']), 8 * 1024 * 1024), receipt

    def cli(self, entry, argv, tag):
        verify_package(self.args.package, self.args.package_sha256)
        self.host_counter += 1
        prefix = self.out / ('host-%03d-%s' % (self.host_counter, tag))
        command = bwrap_command(self.package, self.args.inputs, self.out, entry, argv)
        result = subprocess.run(command, capture_output=True, timeout=15)
        put(prefix.with_suffix('.stdout'), result.stdout)
        put(prefix.with_suffix('.stderr'), result.stderr)
        put(prefix.with_suffix('.json'), {'argv': command, 'returncode': result.returncode,
            'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr),
            'phone_access_possible': False, 'production_function_replacements': 0})
        need(result.returncode == 0, 'actual isolated source CLI refused: ' + tag)
        return strict(result.stdout)

    def execute_command(self, command_file, command_sha, tag, trace=False, page=None, viewport=None,
                        effect_deadline=None):
        command = raw_file(command_file, 128 * 1024)
        need(sha(command) == command_sha and b'\0' not in command, 'reserved command bytes differ')
        destination = self.phone_stage + '/' + tag + '.sh'
        uid_file = self.phone_stage + '/' + tag + '.uid'
        intent = self.out / (tag + '.DISPATCH-INTENT.json')
        put(intent, {'command': str(command_file), 'command_sha256': command_sha,
            'phone_command_path': destination, 'uid_original_path': uid_file,
            'trace': trace, 'state': 'RESERVED_MAY_BE_UNKNOWN', 'automatic_retry': False,
            'model_requests': 0, 'native_task_claim': False})
        absent = self.basic_guard() + 'test ! -e ' + shlex.quote(destination) + ' && test ! -L ' + shlex.quote(destination)
        self.read(absent, tag + '-stage-absent')
        if effect_deadline is not None:
            need(time.monotonic() < effect_deadline, 'captured image expired before original sync')
        # Original AOSP sync transport sends data frames, never an oversized shell command.
        self.f.push(command_file, destination, self.config, self.route)
        put(self.out / (tag + '.SYNC.json'), {'state': 'ORIGINAL_SYNC_SEND_OKAY', 'path': destination,
            'source_sha256': command_sha, 'bytes': len(command), 'automatic_retry': False})
        if effect_deadline is not None:
            need(time.monotonic() < effect_deadline, 'captured image expired before original shell dispatch')
        wire = self.basic_guard() + 'umask 077; set -C; '
        wire += 'test -f ' + shlex.quote(destination) + ' && test ! -L ' + shlex.quote(destination) + ' || exit 78; '
        wire += '[ "$(stat -c %u ' + shlex.quote(destination) + ')" = 2000 ] || exit 78; '
        wire += '[ "$(sha256sum ' + shlex.quote(destination) + " | cut -d ' ' -f 1)\" = " + shlex.quote(command_sha) + ' ] || exit 78; '
        wire += 'chmod 0400 ' + shlex.quote(destination) + ' || exit 78; '
        wire += 'id -u >' + shlex.quote(uid_file) + ' || exit 78; '
        wire += '[ "$(cat ' + shlex.quote(uid_file) + ')" = 2000 ] || exit 78; '
        if page is not None:
            wire += self.guards.page_equality_guard(page)
        if viewport is not None:
            wire += '[ "$(dumpsys display | grep \'mViewports=\')" = ' + shlex.quote(viewport) + ' ] || exit 78; '
        wire += 'exec /system/bin/sh ' + ('-x ' if trace else '') + shlex.quote(destination)
        seconds = 45
        if effect_deadline is not None:
            seconds = min(seconds, int(effect_deadline - time.monotonic()))
            need(seconds >= 1, 'captured image expired before original shell dispatch')
        original = self.raw(wire, tag + '-execute', seconds)
        if effect_deadline is not None:
            need(original['p4_monotonic_finished_ns'] <= int(effect_deadline * 1_000_000_000),
                 'original guarded command did not terminate within capture age')
        uid_raw, uid_receipt = self.read(self.basic_guard() + 'cat ' + shlex.quote(uid_file), tag + '-actual-uid')
        need(uid_raw == b'2000\n', 'actual component shell execution UID differs')
        value = {'schema': 'hepta.r9.operator-command-execution.v1', 'command_sha256': command_sha,
            'execution_uid': 2000, 'execution_uid_original': uid_receipt['stdout'],
            'exit_code': original['exit_code'], 'output_complete': original['output_complete'],
            'stdout': original['stdout'], 'stderr': original['stderr'], 'dispatch_count': 1,
            'automatic_retry': False, 'native_task_claim': False, 'model_requests': 0,
            'operator_shell_trace': trace, 'raw_shell_v2_original': str(Path(original['stdout']['path']).with_suffix('').with_suffix('.wire.json'))}
        path = self.out / (tag + '.EXECUTION.json')
        put(path, value)
        return path, value

    def setup(self, kind, alias=None, previous=None, text=None):
        self.setup_counter += 1
        tag = 'setup-%02d-%s' % (self.setup_counter, kind)
        state = self.out / tag
        argv = ['--inputs', '/inputs', 'plan', '--state', state,
            '--identity', self.out / 'SETUP-IDENTITY.json', '--kind', kind, '--call-id', secrets.token_hex(16)]
        if alias is not None:
            argv += ['--alias', alias]
        if previous is not None:
            argv += ['--observation', previous['stdout_path'], '--observation-plan', previous['plan_path']]
        if text is not None:
            argv += ['--text', text]
        planned = self.cli('source/component_support.py', argv, tag + '-plan')
        execution_path, execution = self.execute_command(state / 'command.sh', planned['command_sha256'], tag)
        outcome = self.cli('source/component_support.py', ['--inputs', '/inputs', 'verify',
            '--plan', state / 'PLAN.json', '--execution', execution_path], tag + '-verify')
        return {'plan_path': state / 'PLAN.json', 'stdout_path': Path(execution['stdout']['path']),
                'outcome': outcome, 'execution': execution}

    def snapshot(self, tag, png=False):
        path = self.phone_stage + '/' + tag + '.png'
        command = self.basic_guard() + self.guards.page_capture('cbefore')
        command += "vbefore=$(dumpsys display | grep 'mViewports='); "
        if png:
            command += 'test ! -e ' + shlex.quote(path) + ' && test ! -L ' + shlex.quote(path) + ' || exit 78; '
            command += 'screencap -d ' + PHYSICAL_DISPLAY + ' -p ' + shlex.quote(path) + ' || exit 79; '
            command += 'pngsha=$(sha256sum ' + shlex.quote(path) + " | cut -d ' ' -f 1); "
            command += 'pngbytes=$(wc -c <' + shlex.quote(path) + " | tr -d '[:space:]'); "
        else:
            command += "pngsha=''; pngbytes=0; "
        command += self.guards.page_capture('cafter')
        command += "vafter=$(dumpsys display | grep 'mViewports='); "
        for source, target in [('cbefore', 'cb64'), ('cafter', 'ca64'), ('vbefore', 'vb64'), ('vafter', 'va64')]:
            command += self.guards.b64_variable(source, target)
        template = '{"page_before_b64":"%s","page_after_b64":"%s","viewport_before_b64":"%s","viewport_after_b64":"%s","png_sha256":"%s","png_bytes":%s}\n'
        command += 'printf ' + shlex.quote(template) + ' "$cb64" "$ca64" "$vb64" "$va64" "$pngsha" "$pngbytes"'
        raw, receipt = self.read(command, tag)
        value = strict(raw)
        page = self.guards.decode_text(value['page_before_b64'], 'independent before page')
        after = self.guards.decode_text(value['page_after_b64'], 'independent after page')
        viewport = self.guards.decode_text(value['viewport_before_b64'], 'independent before viewport')
        vp_after = self.guards.decode_text(value['viewport_after_b64'], 'independent after viewport')
        need(page == after and viewport == vp_after, 'independent observation crossed a page/display change')
        observed = self.guards.page_state(page)
        self.phone.validate_viewport(viewport)
        if png:
            need(re.fullmatch('[0-9a-f]{64}', value['png_sha256']) is not None and
                 type(value['png_bytes']) is int and 0 < value['png_bytes'] <= 8 * 1024 * 1024,
                 'independent PNG bounds differ')
        value.update(page=put(self.out / (tag + '.page.bin'), page.encode()),
            viewport=put(self.out / (tag + '.viewport.bin'), viewport.encode()),
            observed=observed, phone_png_path=path if png else None, original=receipt['stdout'])
        put(self.out / (tag + '.SNAPSHOT.json'), value)
        return value, page, viewport

    def probe_apk_identity(self, tag):
        raw, _ = self.read(self.basic_guard() + 'pm path ' + shlex.quote(PACKAGE), tag + '-paths')
        lines = raw.decode('utf-8', 'strict').splitlines()
        need(1 <= len(lines) <= 16 and all(x.startswith('package:/data/app/') and x.endswith('.apk') for x in lines),
             'actual public probe package paths differ')
        paths = sorted(x[len('package:'):] for x in lines)
        need(len(set(paths)) == len(paths), 'duplicate probe APK path')
        identities = []
        for index, path in enumerate(paths):
            command = self.basic_guard() + 'stat -c %s ' + shlex.quote(path) + ' && sha256sum ' + shlex.quote(path)
            raw, _ = self.read(command, tag + '-apk-' + str(index))
            rows = raw.decode('utf-8', 'strict').splitlines()
            need(len(rows) == 2 and rows[0].isdigit() and 0 < int(rows[0]) <= 100 * 1024 * 1024 and
                 re.fullmatch('[0-9a-f]{64}  ' + re.escape(path), rows[1]) is not None,
                 'actual public probe APK original hash differs')
            identities.append({'path': path, 'bytes': int(rows[0]), 'sha256': rows[1][:64]})
        put(self.out / (tag + '.json'), {'installed_public_package': PACKAGE, 'apks': identities,
            'source_equals_apk_not_asserted': True})
        return identities

    def component(self, operation, extra):
        return self.cli('reference/component_direct.py', [operation, '--state', self.out / 'component', *extra],
                        'component-' + operation)

    def mapped_component(self, step, page, viewport):
        state = self.out / 'component'
        raw = raw_file(state / ('dispatch-%02d.intent.json' % step))
        plan = strict(raw)
        deadline = None
        if step == 2:
            deadline = strict(raw_file(state / 'component.json'))['created_monotonic'] + 120
        _, execution = self.execute_command(state / ('dispatch-%02d.command.sh' % step),
            plan['command_sha256'], 'component-%02d' % step, plan['operator_shell_trace_required'], page, viewport, deadline)
        result = {'schema': 'hepta.operator-component-result.v1', 'plan_sha256': sha(raw),
            'command_sha256': plan['command_sha256'], 'operator_identity': plan['operator_identity'],
            'step': step, 'dispatch_count': 1, 'automatic_retry': False, 'native_task_claim': False,
            'model_requests': 0, 'execution_uid': execution['execution_uid'], 'transport': 'reviewed_operator_shell',
            'exit_code': execution['exit_code'], 'timed_out': False, 'output_truncated': False,
            'stdout': execution['stdout'], 'stderr': execution['stderr']}
        path = self.out / ('component-%02d.RESULT.json' % step)
        put(path, result)
        return path

    def run(self):
        begin, _ = self.read(source_check_command(self.pins, self.args.expected_boot), 'source-before', 20)
        before_sources = strict(begin)
        before_apk = self.probe_apk_identity('probe-before')
        self.read(self.basic_guard() + 'umask 077; mkdir ' + shlex.quote(self.phone_stage) + ' && '
            '[ "$(stat -c %u:%a ' + shlex.quote(self.phone_stage) + ')" = 2000:700 ]', 'reserve-phone-stage')
        initial_alias = '视觉挑战' if self.args.case_id == 'NEG-01' else 'Unicode验证'
        self.setup('open', alias=initial_alias)
        original_public = None
        if self.args.case_id == 'NEG-02':
            actual = self.setup('observe')
            text = 'component-' + self.identity['nonce'][:16] + '-A'
            self.setup('focus', previous=actual, text=text)
            original_public = self.setup('observe')
            state = strict(raw_file(Path(original_public['outcome']['public_state']['path'])))
            need(state['values'][INPUT_ID]['text'] == text and
                 state['values'][RECEIPT_ID]['text'] == '等待输入', 'fresh public input/Submit witness is not qualified')
        before, before_page, before_vp = self.snapshot('before-capture')
        target = VISUAL_COMPONENT if self.args.case_id == 'NEG-01' else TEXT_COMPONENT
        need(before['observed']['component'] == target, 'setup did not reach the actual intended probe')
        extra = ['--provider-source', '/inputs/provider/source', '--source-seal', '/inputs/provider/SOURCE-SEAL.json',
            '--source-seal-sha256', SEAL_SHA, '--config', '/inputs/production-config.json', '--config-sha256', CONFIG_SHA,
            '--operator-id', self.args.operator_id, '--case-id', self.args.case_id]
        if self.args.case_id == 'COMP-01':
            extra += ['--before-page', before['page']['path'], '--before-viewport', before['viewport']['path']]
        self.component('prepare', extra)
        result1 = self.mapped_component(1, before_page, before_vp)
        if self.args.case_id == 'COMP-01':
            after, _, _ = self.snapshot('after-return')
            self.component('verify', ['--result', result1, '--after-page', after['page']['path'],
                                     '--after-viewport', after['viewport']['path']])
        else:
            self.component('admit-capture', ['--result', result1])
            capture = strict(raw_file(self.out / 'component/capture-admitted.json'))
            if self.args.case_id == 'NEG-01':
                self.setup('open', alias='Unicode验证')
            else:
                # Initial focus is already established before the captured image.
                self.setup('focus', previous=original_public, text=text[:-1] + 'B')
            public_before = self.setup('observe')
            state = strict(raw_file(Path(public_before['outcome']['public_state']['path'])))
            need(state['values'][RECEIPT_ID]['text'] == '等待输入', 'public Submit witness already has an effect')
            current, page, viewport = self.snapshot('before-guard', png=True)
            need(current['observed']['component'] == TEXT_COMPONENT and
                 raw_file(Path(public_before['outcome']['page']['path'])) == page.encode() and
                 raw_file(Path(public_before['outcome']['viewport']['path'])) == viewport.encode(),
                 'independent public state and guard snapshot disagree')
            if self.args.case_id == 'NEG-02':
                original_state = strict(raw_file(Path(original_public['outcome']['public_state']['path'])))
                need(original_state['values'][SUBMIT_ID]['bounds'] == state['values'][SUBMIT_ID]['bounds'] and
                     state['values'][INPUT_ID]['text'] == text[:-1] + 'B', 'controlled visual edit moved Submit or lost its exact text')
                x, y = encoded_submit_point(original_state, capture['encoded_size'])
            else:
                # NEG01 tests changed foreground before any coordinate can be used.
                x, y = encoded_submit_point(state, capture['encoded_size'])
            self.component('prepare-tap', ['--current-page', current['page']['path'],
                '--current-viewport', current['viewport']['path'], '--current-png-sha256', current['png_sha256'],
                '--public-state', public_before['outcome']['public_state']['path'], '--encoded-x', x, '--encoded-y', y])
            result2 = self.mapped_component(2, page, viewport)
            public_after = self.setup('observe')
            end, end_page, end_vp = self.snapshot('after-guard')
            need(end_page == page and end_vp == viewport, 'independent after focus/display changed')
            # Retrieve the independent PNG by binary shell-v2 only after the guarded dispatch.
            png_raw, png_receipt = self.read(self.basic_guard() + 'cat ' + shlex.quote(current['phone_png_path']), 'independent-png-original')
            need(len(png_raw) == current['png_bytes'] and sha(png_raw) == current['png_sha256'] and
                 png_raw.startswith(b'\x89PNG\r\n\x1a\n'), 'independent PNG original differs')
            put(self.out / 'INDEPENDENT-PNG.json', png_receipt['stdout'])
            self.component('verify', ['--result', result2, '--public-state', public_after['outcome']['public_state']['path']])
        final, _ = self.read(source_check_command(self.pins, self.args.expected_boot), 'source-after', 20)
        need(strict(final) == before_sources, 'actual runtime source/config/service changed during component')
        need(self.probe_apk_identity('probe-after') == before_apk, 'public probe installed bytes changed during component')
        outcome = strict(raw_file(self.out / 'component/OUTCOME.json'))
        need(outcome['component_passed'] is True, 'component validator did not pass')
        return {'schema': 'hepta.r9.root-component-once-result.v1', 'state': 'DIRECT_COMPONENT_PASSED',
            'case_id': self.args.case_id, 'component_outcome': str(self.out / 'component/OUTCOME.json'),
            'component_only': True, 'native_task_qualification': False, 'model_qualification': False,
            'business_qualification': False, 'phone_model_requests': 0, 'native_tasks_submitted': 0,
            'numeric_public_counter_invented': False, 'automatic_retry': False,
            'phone_stage_retained': self.phone_stage, 'original_raw_streams_retained': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--case-id', choices=('COMP-01', 'NEG-01', 'NEG-02'), required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--operator-id', required=True)
    parser.add_argument('--expected-boot', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--execute-once', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    pins = verify_package(args.package, args.package_sha256)
    load_inputs(args.inputs, pins)
    need(re.fullmatch('[a-z0-9][a-z0-9-]{0,59}', args.label) is not None, 'unique lowercase operator label required')
    need(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', args.expected_boot) is not None, 'actual boot UUID required')
    need(0 < len(args.operator_id) <= 128 and all(32 <= ord(c) < 127 for c in args.operator_id),
         'explicit printable operator identity required')
    need(args.out == P4_BASE / 'component-r9' / args.label, 'exact dedicated P4 output root required')
    preview = {'schema': 'hepta.r9.root-component-once-preview.v1', 'case_id': args.case_id,
        'label': args.label, 'operator_id': args.operator_id, 'expected_boot': args.expected_boot,
        'package_sha256': args.package_sha256, 'inputs_manifest_sha256': INPUTS_SHA,
        'component_direct_sha256': COMPONENT_SHA, 'source_seal_sha256': SEAL_SHA,
        'configuration_sha256': CONFIG_SHA, 'service_inputs_sha256': SERVICE_SHA,
        'out': str(args.out), 'automatic_retry': False, 'component_only': True,
        'default_phone_calls': 0, 'model_requests': 0, 'native_tasks': 0,
        'negatives_use_original_sh_x': True, 'raw_shell_uid': 2000,
        'capture_max_age_seconds': 120, 'single_p4_orchestrator': True}
    if not args.execute_once:
        sys.stdout.buffer.write(encoded({'state': 'PREVIEW_NO_PHONE_ACCESS', **preview}))
        return 0
    need(os.getuid() == 1000 and P4_BASE.resolve(strict=True) == P4_BASE, 'ordinary existing P4 execution account required')
    private_directory(P4_BASE / 'component-r9')
    private_directory(P4_BASE / 'component-intents-r9')
    lock_path = P4_BASE / 'component-intents-r9/operator.lock'
    lock = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    args.out.mkdir(mode=0o700)
    directory_fd = os.open(args.out.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    put(args.out / 'PLAN.original.json', preview)
    # Durable across process/output restarts for this explicit Root label.
    put(P4_BASE / 'component-intents-r9' / (args.label + '.json'),
        {'plan_sha256': sha(encoded(preview)), 'output': str(args.out), 'state': 'MAY_BE_UNKNOWN_DO_NOT_REPLAY'})
    actor = None
    try:
        actor = Actor(args, pins)
        result = actor.run()
        put(args.out / 'RESULT.json', result)
        sys.stdout.buffer.write(encoded(result))
        return 0
    except BaseException as error:
        result = {'schema': 'hepta.r9.root-component-once-result.v1', 'state': 'STOPPED_OR_UNKNOWN_NO_REPLAY',
            'case_id': args.case_id, 'component_passed': False, 'error': type(error).__name__ + ': ' + str(error),
            'automatic_retry': False, 'native_task_qualification': False, 'model_qualification': False,
            'business_qualification': False, 'phone_model_requests': 0, 'native_tasks_submitted': 0}
        put(args.out / 'RESULT.json', result)
        sys.stdout.buffer.write(encoded(result))
        return 2
    finally:
        os.close(lock)


if __name__ == '__main__':
    raise SystemExit(main())
