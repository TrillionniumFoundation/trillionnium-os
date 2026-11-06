#!/usr/bin/env python3
"""One actual native connection for an isolated two-call component lease.

Only native HEPTA shell.exec may invoke execute. This process uses the pinned
client solely for read-only health/inspect and never executes an Android action.
Root witnesses are a separate, explicitly attributed operator input.
"""
import argparse
import base64
import copy
import os
from pathlib import Path
import re
import select
import socket
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from component_common import (need, sha, encoded, strict, read, pinned, put,
    private_dir, metadata, descriptor, scope, relative, verify_package,
    load_combination, verify_external, import_production, import_pinned,
    target_identity, root_operation_id, BASE, CLIENT, CLIENT_SHA, COMPONENT_EVIDENCE,
    PRODUCTION_EVIDENCE, PARENT_DOMAIN, WORKER_DOMAIN, MAGISK, ANDROID, MAX_FRAME)


class NativeCancelled(Exception):
    pass


class Channel:
    def __init__(self, conn, run, deadline, stopped):
        self.conn, self.run, self.deadline, self.stopped = conn, Path(run), deadline, stopped
        self.partial = bytearray(); self.total = 0; self.in_seq = self.out_seq = 0
        self.terminal_reserved = False; self.send_started = False
        self.inputs = open(self.run / 'provider-in.jsonl', 'xb', buffering=0)
        self.outputs = open(self.run / 'provider-out.jsonl', 'xb', buffering=0)

    def receive(self, expected=None, wait=True):
        while b'\n' not in self.partial:
            need(not self.stopped[0] and time.monotonic() < self.deadline,
                 'component stop/deadline; no retry')
            ready = select.select([self.conn], [], [], .05 if wait else 0)[0]
            if not ready:
                if not wait:
                    return None
                continue
            chunk = self.conn.recv(min(65536, MAX_FRAME + 1 - len(self.partial)))
            need(chunk, 'native EOF; no reconnect')
            self.partial.extend(chunk); self.total += len(chunk)
            need(len(self.partial) <= MAX_FRAME and self.total <= 4 * MAX_FRAME, 'native frame/turn byte bound')
        n = self.partial.index(10) + 1
        raw = bytes(self.partial[:n]); del self.partial[:n]
        self.inputs.write(raw); os.fsync(self.inputs.fileno())
        value = strict(raw)
        need(value.get('protocol') == 'trillionnium.owner-open.provider-jsonl.v1'
             and type(value.get('seq')) is int and value['seq'] == self.in_seq
             and self.in_seq < 4, 'native input sequence/protocol')
        self.in_seq += 1
        if value.get('kind') == 'turn.cancel':
            raise NativeCancelled(raw)
        need(value.get('kind') == expected, 'unexpected native frame')
        return raw

    def fence(self):
        need(self.receive('no_frame_before_dispatch', wait=False) is None and not self.partial,
             'unexpected/partial native frame before dispatch')

    def send(self, raw, *, kernel_frame=True, not_after_monotonic=None):
        need(not self.terminal_reserved, 'terminal already reserved; no resend')
        need(time.monotonic()<self.deadline and (not_after_monotonic is None
            or time.monotonic()<=not_after_monotonic),'actual native send deadline expired')
        value = strict(raw)
        need(value['seq'] == self.out_seq and value['protocol'] == 'trillionnium.owner-open.provider-jsonl.v1',
             'actual outbound sequence differs')
        if value['kind'] in ('turn.complete', 'turn.fail', 'turn.cancelled'):
            self.terminal_reserved = True
            put(self.run / 'terminal.json', {'kind': value['kind'],
                'scope': getattr(self, 'scope', None), 'native_terminal_independently_verified': False,
                'model_requests': 0, 'business_qualified': False,
                **{k: v for k, v in value.items() if k not in ('seq', 'kind', 'protocol')}})
        put(self.run / ('actual-wire-%02d.intent.json' % self.out_seq),
            {'frame': value, 'frame_sha256': sha(raw), 'kernel_frame': kernel_frame,
             'state': 'reserved_before_send_result_may_be_unknown', 'automatic_retry': False})
        self.outputs.write(raw); os.fsync(self.outputs.fileno())
        need(time.monotonic()<self.deadline and (not_after_monotonic is None
            or time.monotonic()<=not_after_monotonic),'actual native send expired while retaining intent')
        self.send_started = True
        self.conn.settimeout(min(2, max(.01, self.deadline - time.monotonic())))
        wire_start=time.monotonic()
        need(not_after_monotonic is None or wire_start<=not_after_monotonic,'capture expired immediately before sendall')
        self.conn.sendall(raw)
        put(self.run / ('actual-wire-%02d.sent.json' % self.out_seq),
            {'frame_sha256': sha(raw), 'sendall_returned': True, 'is_execution_confirmation': False,
             'clock':'phone time.monotonic','send_started_monotonic':wire_start,
             'send_returned_monotonic':time.monotonic()})
        self.out_seq += 1; self.send_started = False

    def terminal(self, kind, detail):
        # A reserved but unsent kernel call does not consume the native wire
        # sequence. Its original reservation remains, with an explicit abort.
        fields = {'error': detail} if kind == 'turn.fail' else {'summary': detail}
        self.send(encoded({'protocol': 'trillionnium.owner-open.provider-jsonl.v1',
            'seq': self.out_seq, 'kind': kind, **fields}), kernel_frame=False)

    def close(self):
        self.inputs.close(); self.outputs.close()
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.conn.close()


def original_bundle(run, phase, call, journal, client):
    """Retain distinct actual files and a separately labelled inspect response."""
    action = call['argv'][4]; command = base64.b64decode(call['argv'][6], validate=True)
    home = private_dir(Path(run) / (phase + '-originals'), create=True)
    action_root = private_dir(Path(journal) / 'actions' / action)
    need(sorted(p.name for p in action_root.iterdir()) == ['intent.json', 'receipt.json', 'stderr.bin', 'stdout.bin'],
         'original action incomplete or has pending/extra files')
    origins = {}; result = {}
    paths = {'intent': action_root / 'intent.json', 'receipt': action_root / 'receipt.json',
             'stdout': action_root / 'stdout.bin', 'stderr': action_root / 'stderr.bin',
             'client_claim': BASE / 'client-receipts' / (action + '.claim.json'),
             'client_result': BASE / 'client-receipts' / (action + '.result.json')}
    for name, path in paths.items():
        raw = read(path); result[name] = raw
        origins[name] = {'source_path': str(path), 'metadata': metadata(path.lstat()), **descriptor(raw)}
        put(home / (name + '.original'), raw)
    saved = strict(result['client_result']); trace = saved.get('client_transport')
    need(isinstance(trace, dict) and trace.get('schema') == 'hepta.client-transport-trace.v150.r6',
         'actual client transport original absent')
    directory = BASE / 'client-receipts' / (action + '.transport-r6')
    need(trace['directory'] == str(directory) and 1 <= len(trace['events']) <= 32,
         'client original transport directory differs')
    previous = None; transport_origins = []
    for i, row in enumerate(trace['events']):
        need(re.fullmatch(r'%02d-[a-z_]+\.json' % i, row['name']), 'transport event name/sequence')
        raw = pinned(directory / row['name'], {k: row[k] for k in ('bytes', 'sha256')})
        value = strict(raw)
        need(value.get('sequence') == i and value.get('previous_event_sha256') == previous
             and value.get('action_id') == action and value.get('command_sha256') == sha(command)
             and value.get('client_source_sha256') == CLIENT_SHA
             and value.get('endpoint') == 'hepta_phone_executor_v150_r6'
             and value.get('automatic_replay') is False, 'original client transport chain differs')
        put(home / ('transport-' + row['name']), raw)
        transport_origins.append({'source_path': str(directory / row['name']), **descriptor(raw)})
        previous = sha(raw)
    need(sorted(p.name for p in directory.iterdir()) == sorted(r['name'] for r in trace['events'])
         and trace['last_event_sha256'] == previous and trace['transport'] == value['transport']
         and trace['transport']['operation'] == 'execute'
         and trace['transport']['request_frame_complete'] is True
         and trace['transport']['response_frame_complete'] is True, 'client transport not complete')
    inspection = client.inspect(action, sha(command), True)  # READ ONLY; exactly once
    result['client_inspection'] = encoded(inspection)
    put(home / 'client-inspection.observation.json', result['client_inspection'])
    # Original stored files must still be identical after the separate read.
    for name, path in paths.items():
        need(read(path) == result[name] and metadata(path.lstat()) == origins[name]['metadata'],
             'original changed during inspection')
    put(home / 'ORIGINS.json', {'schema': 'hepta.native-guard.r6-original-origins.v1',
        'action_id': action, 'actual_command_sha256': sha(command), 'files': origins,
        'transport_events': transport_origins,
        'inspection_origin': 'actual decoded readonly client.inspect(include_output=true) response',
        'inspection_sha256': sha(result['client_inspection']), 'execute_requests_by_adapter': 0,
        'pending_receipt_observed_absent': True})
    return result, inspection


def verify_shell_wire(wire, stdout, stderr):
    """Reassemble every original shell-v2 stream frame, including EXIT."""
    need(wire.get('schema') == 'hepta.r9.operator-raw-shell-v2.v1'
         and wire.get('exit_code') == 0 and wire.get('original_exit_frame_received') is True
         and wire.get('output_complete') is True and wire.get('automatic_retry') is False
         and wire.get('error') is None and wire.get('command_utf8_sha256') == sha(wire['command'].encode())
         and wire.get('wire_request_bytes') == len(('shell,v2,raw:' + wire['command']).encode())
         and 0 < wire['wire_request_bytes'] < 65536, 'Root original shell-v2 terminal incomplete')
    need(type(wire.get('p4_monotonic_started_ns')) is int
         and type(wire.get('p4_monotonic_finished_ns')) is int
         and 0 < wire['p4_monotonic_started_ns'] <= wire['p4_monotonic_finished_ns'], 'Root original wire clock differs')
    for key, raw in [('stdout', stdout), ('stderr', stderr)]:
        need(all(wire[key][k] == v for k,v in descriptor(raw).items()), 'Root wire/raw stream pin differs')
    offsets = {1: 0, 2: 0}; streams = {1: stdout, 2: stderr}; exits = 0; closed = False
    need(isinstance(wire['frames'], list) and 1 <= len(wire['frames']) <= 4096, 'Root frame count bound')
    for row in wire['frames']:
        kind, length = row['stream'], row['bytes']
        need(type(length) is int and 0 <= length <= 8*1024*1024, 'Root original frame byte bound')
        if kind in streams:
            part = streams[kind][offsets[kind]:offsets[kind]+length]; offsets[kind] += length
            need(len(part) == length and sha(part) == row['sha256'], 'original Root stream frame differs')
        elif kind == 3:
            exits += 1; need(length in (1, 4) and row['sha256'] == sha(bytes(length)), 'Root exit frame differs')
        else:
            need(kind == 4 and not closed and length == 0 and row['sha256'] == sha(b''), 'unexpected Root wire frame')
            closed = True
    need(exits == 1 and offsets == {1: len(stdout), 2: len(stderr)}
         and wire['frames'][-1]['stream'] == 3, 'Root terminal/stream counts differ')


def operator_wire(command_sha, destination, uid_file, boot):
    """Exact unmodified frozen Actor.execute_command wrapper, trace=False."""
    import shlex
    basic = ('[ "$(id -u)" = 2000 ] || exit 78; '
        '[ "$(getprop ro.serialno)" = ' + shlex.quote('ZY22LS7WZT') + ' ] || exit 78; '
        '[ "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(boot) + ' ] || exit 78; ')
    wire = basic + 'umask 077; set -C; '
    wire += 'test -f ' + shlex.quote(destination) + ' && test ! -L ' + shlex.quote(destination) + ' || exit 78; '
    wire += '[ "$(stat -c %u ' + shlex.quote(destination) + ')" = 2000 ] || exit 78; '
    wire += '[ "$(sha256sum ' + shlex.quote(destination) + " | cut -d ' ' -f 1)\" = " + shlex.quote(command_sha) + ' ] || exit 78; '
    wire += 'chmod 0400 ' + shlex.quote(destination) + ' || exit 78; '
    wire += 'id -u >' + shlex.quote(uid_file) + ' || exit 78; '
    wire += '[ "$(cat ' + shlex.quote(uid_file) + ')" = 2000 ] || exit 78; '
    wire += 'exec /system/bin/sh ' + shlex.quote(destination)
    return wire, basic + 'cat ' + shlex.quote(uid_file)


def verify_operator_execution(files, prefix, stdout, expected_command, *, phase, nonce, boot):
    """Actual fixture shell bytes/UID witness; not worker qualification."""
    q = strict(files[prefix + '_execution']); wire = strict(files[prefix + '_wire'])
    intent = strict(files[prefix + '_intent']); uid_wire = strict(files[prefix + '_uid_wire'])
    command = files[prefix + '_command']; err = files[prefix + '_stderr']; uid = files[prefix + '_uid']
    need(command == expected_command and not err and uid == b'2000\n', 'Root command/UID/raw streams differ')
    need(q.get('schema') == 'hepta.r9.operator-command-execution.v1'
         and q.get('execution_uid') == 2000 and q.get('dispatch_count') == 1
         and q.get('exit_code') == 0 and q.get('output_complete') is True
         and q.get('automatic_retry') is False and q.get('native_task_claim') is False
         and q.get('model_requests') == 0 and q.get('operator_shell_trace') is False
         and q.get('command_sha256') == sha(command), 'original Root operator execution binding differs')
    destination = '/data/local/tmp/hepta-native-guard-' + nonce + '/' + phase + '-' + prefix + '.sh'
    uid_path = destination[:-3] + '.uid'
    need(intent.get('command_sha256') == sha(command) and intent.get('phone_command_path') == destination
         and intent.get('uid_original_path') == uid_path and intent.get('trace') is False
         and intent.get('state') == 'RESERVED_MAY_BE_UNKNOWN' and intent.get('automatic_retry') is False
         and intent.get('model_requests') == 0 and intent.get('native_task_claim') is False,
         'original Root fixture dispatch intent differs')
    expected_wire,expected_uid = operator_wire(sha(command), destination, uid_path, boot)
    need(wire['command'] == expected_wire and uid_wire['command'] == expected_uid,
         'Root original wire did not execute the one reviewed staged command/UID read')
    need(uid_wire['p4_monotonic_started_ns'] >= wire['p4_monotonic_finished_ns'], 'original UID read preceded execution')
    for key, raw in [('stdout', stdout), ('stderr', err)]:
        need(all(q[key][k] == wire[key][k] == v for k,v in descriptor(raw).items()), 'Root execution/raw stream pin differs')
    need(all(q['execution_uid_original'][k] == uid_wire['stdout'][k] == v for k,v in descriptor(uid).items()),
         'original execution UID descriptor differs')
    verify_shell_wire(wire, stdout, err);verify_shell_wire(uid_wire, uid, b'')


def verify_root_actor_originals(raw, plan_raw, files):
    """Retain every P4 actor original, with explicit references to large streams."""
    q=strict(raw);plan=strict(plan_raw)
    need(set(q)=={'schema','phase_plan_sha256','scope','contract_sha256','phase',
        'frozen_actor_source_sha256','frozen_core_source_sha256','frozen_transport_source_sha256',
        'files','fixture_prelude','installed_probe_before','installed_probe_after',
        'source_equals_apk_not_asserted','uid2000_fixture_only_not_native_worker_qualification',
        'model_requests','native_task_submissions','automatic_retry'}
        and q['schema']=='hepta.native-guard.root-actor-originals.v1'
        and q['phase_plan_sha256']==sha(plan_raw)
        and all(q[k]==plan[k] for k in ('scope','contract_sha256','phase')),
        'complete original Root actor scope differs')
    need(q['frozen_actor_source_sha256']=='1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'
        and q['frozen_core_source_sha256']=='705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f'
        and q['frozen_transport_source_sha256']=='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
        and q['source_equals_apk_not_asserted'] is True
        and q['uid2000_fixture_only_not_native_worker_qualification'] is True
        and q['model_requests']==q['native_task_submissions']==0 and q['automatic_retry'] is False,
        'Root actor source/qualification boundary differs')
    apks=q['installed_probe_before']
    need(apks==q['installed_probe_after'] and isinstance(apks,list) and 1<=len(apks)<=16,
        'actual public probe changed during Root fixture')
    for apk in apks:
        need(set(apk)=={'path','bytes','sha256'} and isinstance(apk['path'],str)
            and apk['path'].startswith('/data/app/') and apk['path'].endswith('.apk')
            and type(apk['bytes']) is int and 0<apk['bytes']<=100*1024*1024
            and re.fullmatch('[0-9a-f]{64}',apk['sha256']),'actual APK identity bound')
    need(len({p['path'] for p in apks})==len(apks),'duplicate original APK path')
    originals=q['files'];need(isinstance(originals,dict) and 1<=len(originals)<=256,'Root actor inventory count bound')
    referred=set();total=0
    for name,row in originals.items():
        need(isinstance(name,str) and Path(name).name==name and name not in ('.','..')
            and isinstance(row,dict) and set(row) in (
                {'source_path','source_metadata','bytes','sha256','raw_b64'},
                {'source_path','source_metadata','bytes','sha256','planned_file_key'}),
            'Root actor original descriptor differs')
        need(Path(row['source_path']).is_absolute() and Path(row['source_path']).name==name
            and isinstance(row['source_metadata'],list) and len(row['source_metadata'])==9,
            'Root actor original source identity absent')
        if 'planned_file_key' in row:
            key=row['planned_file_key'];need(key in files and key not in referred,'duplicate/missing planned original reference')
            data=files[key];referred.add(key)
        else:
            data=base64.b64decode(row['raw_b64'],validate=True)
            need(base64.b64encode(data).decode()==row['raw_b64'],'actor original base64 is not canonical')
        total+=len(data)
        need(len(data)<=8*1024*1024 and total<=16*1024*1024
            and descriptor(data)=={k:row[k] for k in ('bytes','sha256')},'actor raw original bytes differ')
    need(referred==set(files),'planned original omitted from complete actor capture')
    prelude=q['fixture_prelude']
    need(prelude is None or (q['phase']=='setup' and isinstance(prelude,dict)
        and prelude.get('schema')=='hepta.native-guard.root-text-fixture-prelude.v1'
        and prelude.get('scope')==plan['scope'] and prelude.get('contract_sha256')==plan['contract_sha256']
        and prelude.get('operation_id')==plan['operation_id']
        and prelude.get('native_worker_qualification') is False
        and prelude.get('model_requests')==0 and prelude.get('business_qualified') is False
        and prelude.get('automatic_retry') is False),'operator setup prelude must be explicit and unqualified')
    return q


def root_commands(kernel, phase, guards, token):
    import shlex
    serial = kernel.mapper._serial_guard()
    xml = '/data/local/tmp/hepta-native-guard-observe-' + token + '.xml'
    commands = {'public': guards.public_text_command(serial, token,
        'org.trillionnium.hepta.controlprobe', xml).encode()}
    if phase == 'setup' and kernel.contract['case_id'] == 'NEG-01':
        target = kernel.mapper.apps['视觉挑战']['component']
        return {'open': guards.app_open_command(serial, target, token,
                    kernel.mapper._focus_input_precondition()).encode()}
    if phase == 'before-guard':
        commands['png'] = (serial + 'exec /system/bin/screencap -d 4630947043778501779 -p').encode()
        if kernel.contract['case_id'] == 'NEG-01':
            target = kernel.mapper.apps['Unicode验证']['component']
            commands['disturbance'] = guards.app_open_command(serial, target, sha((token+':open').encode())[:32],
                    kernel.mapper._focus_input_precondition()).encode()
        else:
            # A labelled operator fixture edit, never a model-selected or
            # production typed-input success. The kernel independently checks
            # the exact page/viewport/public state before and after the guard.
            suffix = '-ng' + kernel.contract['nonce'][:8]
            commands['disturbance'] = (serial + guards.page_equality_guard(kernel.capture['page_state'])
                + '[ "$(dumpsys display | grep \'mViewports=\')" = '
                + shlex.quote(kernel.capture['viewport']) + ' ] || exit 68; '
                + 'exec /system/bin/input text ' + shlex.quote(suffix)).encode()
    return commands


def root_witness(home, phase, kernel, channel, guards):
    token = root_operation_id(kernel.scope,kernel.contract_sha,phase)
    commands = root_commands(kernel, phase, guards, token)
    put(Path(home)/('ROOT-'+phase.upper()+'-PLAN.json'), {
        'schema':'hepta.native-guard.root-phase-plan.v1','scope':kernel.scope,
        'contract_sha256':kernel.contract_sha,'phase':phase,'operation_id':token,
        'commands':{k:{'base64':base64.b64encode(v).decode(),**descriptor(v)} for k,v in commands.items()},
        'execution_order':(['disturbance','public','png'] if phase=='before-guard' else list(commands)),
        'operator_fixture_not_model_or_worker_qualification':True,
        'automatic_retry':False,'caller_must_retain_original_command_execution_and_wire':True})
    mailbox = Path(home) / 'operator' / (phase + '.json')
    while True:
        channel.fence()
        try:
            raw = read(mailbox, 65536)
        except FileNotFoundError:
            need(time.monotonic() < channel.deadline, 'Root witness deadline')
            time.sleep(.05); continue
        break
    value = strict(raw)
    need(set(value) == {'schema', 'phase', 'scope', 'contract_sha256', 'operation_id', 'files', 'provenance'}
         and value['schema'] == 'hepta.native-guard.root-witness.v1'
         and value['phase'] == phase and value['scope'] == kernel.scope
         and value['contract_sha256'] == kernel.contract_sha
         and value['operation_id'] == token, 'Root witness identity differs')
    required = {prefix+suffix for prefix in commands for suffix in ('','_execution','_wire','_command','_stderr','_uid','_uid_wire','_intent')}
    need(set(value['files']) == required, 'Root witness original inventory differs')
    files = {}
    saved = private_dir(kernel.run / ('root-' + phase + '-originals'), create=True)
    prov = value['provenance']
    need(prov['path'] == phase+'/PROVENANCE.json', 'one phase-only Root provenance required')
    prov_raw = pinned(Path(home)/'operator'/prov['path'], {k:prov[k] for k in ('bytes','sha256')}, 262144)
    provenance = strict(prov_raw)
    need(provenance.get('schema') == 'hepta.native-guard.root-original-provenance.v1'
         and provenance.get('phase_plan_sha256') == sha(read(Path(home)/('ROOT-'+phase.upper()+'-PLAN.json'),65536))
         and set(provenance.get('source_files',{})) == required
         and provenance.get('frozen_actor_source_sha256') == '1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'
         and provenance.get('frozen_transport_source_sha256') == '6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
         and provenance.get('uid2000_fixture_only_not_native_worker_qualification') is True,
         'Root fixture original source attribution differs')
    put(saved/'PROVENANCE.original.json', prov_raw)
    for name, row in value['files'].items():
        rel = relative(row['path']); need(rel.parts[0] == phase and len(rel.parts) == 2, 'Root witness left phase directory')
        files[name] = pinned(Path(home) / 'operator' / rel, {k: row[k] for k in ('bytes', 'sha256')}, 16*1024*1024)
        need(all(provenance['source_files'][name][k] == row[k] for k in ('bytes','sha256')),
             'Root source original pin differs from mailbox bytes')
        put(saved / (name + '.original'), files[name])
    for prefix, command in commands.items():
        verify_operator_execution(files,prefix,files[prefix],command,phase=phase,
            nonce=kernel.contract['nonce'],boot=strict(read(Path(home)/'LEASE.json'))['boot_id'])
    actor=provenance['actor_originals']
    need(actor['path']==phase+'/ACTOR-ORIGINALS.original.json','one phase-only Actor original envelope required')
    actor_raw=pinned(Path(home)/'operator'/actor['path'],{k:actor[k] for k in ('bytes','sha256')},16*1024*1024)
    verify_root_actor_originals(actor_raw,read(Path(home)/('ROOT-'+phase.upper()+'-PLAN.json'),65536),files)
    put(saved/'ACTOR-ORIGINALS.original.json',actor_raw)
    if phase == 'setup' and kernel.contract['case_id'] == 'NEG-01':
        guards.verify_app_open(strict(files['open']),token,kernel.mapper.apps['视觉挑战']['component'])
    if phase == 'before-guard' and kernel.contract['case_id'] == 'NEG-01':
        guards.verify_app_open(strict(files['disturbance']),sha((token+':open').encode())[:32],kernel.mapper.apps['Unicode验证']['component'])
    put(saved / 'MAILBOX.original.json', raw)
    return value['operation_id'], files


def run_connection(conn, run, home, kernel, ledger, client, journal, deadline, stopped,
                   *, witness_reader=root_witness, original_reader=original_bundle):
    channel = Channel(conn, run, deadline, stopped); pending_reserved = None
    phase = None; native_sent = set(); safe = False
    try:
        kernel.start(channel.receive('turn.start'))
        channel.scope = kernel.scope
        put(Path(run) / 'accepted.json', {'identity': kernel.scope, 'state': 'accepted_never_replay',
            'owner_request_sha256': sha(kernel.owner_raw), 'contract_sha256': kernel.contract_sha,
            'model_requests': 0, 'business_qualified': False})
        put(Path(home) / 'ACCEPTED.json', {'scope': kernel.scope, 'run_dir': str(run),
            'contract_sha256': kernel.contract_sha, 'native_tools_dispatched': 0})
        # Native Send leaves HEPTA in front. Root fixture setup must follow the
        # actual accepted scope for BOTH cases before the first screenshot.
        token, data = witness_reader(home, 'setup', kernel, channel, kernel.guards)
        if kernel.contract['case_id'] == 'NEG-02':
            kernel.setup_witness(data['public'], token)
        for phase in ('capture', 'guard'):
            if phase == 'guard':
                token, data = witness_reader(home, 'before-guard', kernel, channel, kernel.guards)
                kernel.before_guard_witness(data['public'], token, data['png'])
            channel.fence()
            raw = kernel.capture_call() if phase == 'capture' else kernel.guard_call()
            call = strict(raw)['call']; record = copy.deepcopy(kernel.mapper.calls[call['call_id']])
            original_wire = copy.deepcopy(record['wire_call'])
            # The durable global intent describes the ACTUAL trace-prefixed
            # native argv. The original mapper wire remains independently bound.
            record['wire_call'] = copy.deepcopy(call)
            ledger.reserve(record, kernel.scope)
            pending_reserved = record if record['semantic_tool'] == 'phone.tap' else None
            put(Path(run) / (phase + '-ledger-wire-binding.json'), {
                'action_id': record['capture_id'], 'scope': kernel.scope,
                'original_mapper_wire_sha256': sha(encoded(original_wire)),
                'actual_native_wire_sha256': sha(encoded(call)),
                'actual_command_sha256': sha(base64.b64decode(call['argv'][6], validate=True)),
                'global_ledger_reserved': pending_reserved is not None,
                'local_kernel_reservation_is_global_ledger': False})
            channel.fence()  # Cancellation before this actual frame remains known not dispatched.
            if phase=='guard':
                now=time.monotonic();age=now-kernel.capture['received_monotonic']
                need(0<=age<=120,'original capture expired before actual native guard frame')
                put(Path(run)/'guard-capture-age.original.json',{
                    'schema':'hepta.native-guard.actual-capture-age.v1','scope':kernel.scope,
                    'clock':'phone time.monotonic','capture_call_id':kernel.capture['call_id'],
                    'capture_phase_original_sha256':sha(read(Path(run)/'capture-phase.json')),
                    'actual_guard_frame_sha256':sha(raw),
                    'capture_received_monotonic':kernel.capture['received_monotonic'],
                    'guard_pre_send_monotonic':now,'age_seconds':age,'maximum_age_seconds':120,
                    'automatic_recapture':False,'model_requests':0})
            native_sent.add(call['call_id'])  # sendall may partially write; never automatically replay.
            channel.send(raw,not_after_monotonic=(kernel.capture['received_monotonic']+120 if phase=='guard' else None))
            reply = channel.receive('tool.result')
            originals, inspected = original_reader(run, phase, call, journal, client)
            if phase == 'capture':
                kernel.capture_result(reply, originals)
                put(Path(run)/'capture-clock.original.json',{
                    'schema':'hepta.native-guard.actual-capture-clock.v1','scope':kernel.scope,
                    'clock':'phone time.monotonic','capture_call_id':kernel.capture['call_id'],
                    'capture_phase_original_sha256':sha(read(Path(run)/'capture-phase.json')),
                    'native_result_sha256':sha(reply),'capture_received_monotonic':kernel.capture['received_monotonic'],
                    'after_admission_monotonic':time.monotonic(),'model_requests':0})
            else:
                # Record the independently inspected actual effect terminal
                # even when typed guard qualification subsequently fails.
                # The production resolver rejects pending/unjoined receipts
                # and never grants semantic or business success.
                ledger.resolve_inspected(record['capture_id'], inspected)
                pending_reserved = None
                kernel.guard_result(reply, originals)
            put(Path(home) / (phase.upper() + '-RESULT.json'), {'scope': kernel.scope,
                'contract_sha256': kernel.contract_sha, 'run_dir': str(run),
                'phase_state': kernel.state, 'native_call_id': call['call_id'],
                'native_terminal_sha256': sha(reply), 'component_qualified': False})
        token, data = witness_reader(home, 'after-guard', kernel, channel, kernel.guards)
        channel.fence()
        channel.send(kernel.after_guard_witness(data['public'], token))
        safe = True; return 0
    except BaseException as error:
        if pending_reserved is not None and pending_reserved['call_id'] not in native_sent:
            ledger.mark_not_dispatched(pending_reserved['capture_id'],
                'cancel_before_native_tool_frame' if isinstance(error, NativeCancelled)
                else 'transport_closed_before_native_tool_frame')
        cancelled = isinstance(error, NativeCancelled)
        if cancelled:
            raw = error.args[0]; value = strict(raw)
            need(value.get('turn') == kernel.scope, 'native cancellation scope differs')
            put(Path(run) / 'native-cancel.original.jsonl', raw)
        put(Path(run) / 'listener-failure.json', {'error': type(error).__name__ + ':' + str(error)[:1024],
            'kernel_state': kernel.state, 'phase': phase, 'native_calls_may_have_been_sent': sorted(native_sent),
            'source_reservations_are_not_sent_frames': True, 'automatic_retry': False,
            'native_turn_terminal_verified': False, 'component_qualified': False})
        if not channel.terminal_reserved:
            try:
                channel.terminal('turn.cancelled' if cancelled else 'turn.fail',
                    'Native component stopped; original state retained, no retry and no qualification.')
            except BaseException:
                pass
        return 70
    finally:
        channel.close()
        put(Path(home) / 'PROVIDER-ENDED.json', {'state': 'COMPONENT_PROVIDER_CONNECTION_ENDED',
            'kernel_observation_completed': safe, 'native_turn_verified': False,
            'automatic_restart': False, 'model_requests': 0, 'business_qualified': False,
            'component_qualified': False, 'original_cleanup_and_late_inventory_required': True})


def serve(args):
    package = Path(args.package); verify_package(package, args.package_sha256)
    home = private_dir(Path(args.lease)); lease_raw = read(home / 'LEASE.json', 131072)
    need(sha(lease_raw) == args.lease_sha256, 'one-use lease changed')
    lease = strict(lease_raw); need(lease['schema'] == 'hepta.native-guard.lease.v1', 'component lease schema')
    need(home == BASE / 'native-guard-r10-r1' / lease['label'], 'fixed new component namespace')
    need(os.getuid() == os.getgid() == 0 and target_identity(os.getpid())['domain'] == MAGISK,
         'component provider must be Root magisk, never bootstrap impersonation')
    bound_raw = read(home / 'BOUND-CONTRACT.json', 65536); bound = strict(bound_raw)
    need(bound['lease_sha256'] == sha(lease_raw) and bound['provider_source_sha256'] == sha(read(Path(__file__))),
         'bound provider/lease differs')
    c_raw = pinned(home / 'inputs/COMBINATION.json', lease['combination'])
    reviewed = strict(read(package.parent / 'reference/REVIEWED-PRODUCTION-PINS.json', private=False))
    c, cfg = load_combination(home / 'inputs', c_raw, reviewed); verify_external(c)
    modules = import_production(home / 'inputs/production')
    import native_guard_session_r2 as K
    owner_raw = read(home / 'owner-request.txt', 16000)
    need(sha(owner_raw) == bound['contract']['owner_request_sha256'], 'bound owner original changed')
    client_raw = read(CLIENT); need(sha(client_raw) == CLIENT_SHA, 'fixed r6 client changed')
    import types
    client = types.ModuleType('native_guard_pinned_client'); client.__file__ = str(CLIENT)
    exec(compile(client_raw, str(CLIENT), 'exec'), client.__dict__)
    sidecar = target_identity(bound['sidecar_identity']['identity'][0], bound['sidecar_identity']['identity'])
    need(sidecar == bound['sidecar_identity'], 'component sidecar identity changed before listen')
    health = client.request({'version': 1, 'op': 'health'}, timeout_s=3)
    need(health == bound['sidecar_health'] and health.get('state') == 'ready'
         and health.get('server_instance') == bound['contract']['executor_server_instance']
         and health.get('peer_context') == MAGISK and health.get('execute_authorized') is False,
         'component readonly sidecar readiness differs')
    put(home / 'PROVIDER-HEALTH.original.json', health)
    listener = socket.socket(fileno=args.listener_fd)
    need(listener.getsockname() == ('127.0.0.1', 18080)
         and listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0,
         'exact exclusively bound unstarted listener required')
    own = target_identity(os.getpid()); need(own['nnp'] == 0 and own['uid'] == own['gid'] == [0]*4,
                                           'provider process credentials differ')
    listener.listen(1); listener.settimeout(.1)
    now = time.monotonic_ns(); service_deadline = now + 420_000_000_000
    accept_deadline = now + 120_000_000_000
    need(time.time()*1000 + 420000 < lease['expires_unix_ms'], 'lease too short before listen')
    put(home / 'READY.json', {'schema': 'hepta.native-guard.ready.v1',
        'lease_sha256': sha(lease_raw), 'contract_sha256': sha(encoded(bound['contract'])),
        'combination_sha256': sha(c_raw), 'provider_source_sha256': sha(read(Path(__file__))),
        'identity': own, 'port': 18080, 'accepting_one_session': True,
        'ready_monotonic_ns': now, 'accept_deadline_monotonic_ns': accept_deadline,
        'service_deadline_monotonic_ns': service_deadline, 'model_requests': 0,
        'readiness_scope': 'isolated_component_transport_only', 'four_role_ready': False})
    stopped = [False]
    import signal
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda _s, _f: stopped.__setitem__(0, True))
    try:
        while not stopped[0] and time.monotonic_ns() < accept_deadline:
            try:
                conn, address = listener.accept()
            except socket.timeout:
                continue
            need(address[0] == '127.0.0.1', 'native connection not loopback')
            listener.close()  # Exactly one connection, including invalid owner/EOF.
            put(home / 'CONNECTION-ACCEPTED.json', {'accepted_monotonic_ns': time.monotonic_ns(),
                'peer_address': list(address), 'automatic_reconnect': False})
            run = private_dir(COMPONENT_EVIDENCE / bound['run_basename'], create=True)
            mapper = modules['phone_local_tools'].PhoneLocalTools(run, put, cfg['approved_apps'], cfg['executor'])
            kernel = K.NativeGuardSession(encoded(bound['contract']), owner_raw,
                run, home / 'claims', mapper, modules['phone_observation_tools'], modules['phone_task_guards'])
            ledger = modules['action_ledger'].ActionLedger(PRODUCTION_EVIDENCE, run)
            return run_connection(conn, run, home, kernel, ledger, client,
                ANDROID / lease['android_journal'].lstrip('/'),
                min(time.monotonic()+300, service_deadline/1e9), stopped)
        need(False, 'component accept expired; no automatic restart')
    finally:
        listener.close()


EPOCH_FIXTURE_CONSUMER_PROFILES = {'setup': {'schema': 'hepta.epoch.fixture-output-profile.v2', 'phase': 'setup', 'writer_schema': 'hepta.epoch.root-fixture-writer.v1', 'phase_limits': {'stream': 163840, 'command': 65536, 'metadata': 65536, 'envelope': 262144, 'final': 65536, 'total': 622592}, 'phase_domain_limits': {'generic': 65536, 'public': 98304, 'png': 0}, 'wire_domain_limits': {'generic': 16384, 'public': 32768, 'png': 1048576}, 'phase_files': 256, 'phase_frames': 4096, 'phase_wires': 96, 'metadata_file_bytes': 65536, 'command_file_bytes': 32768, 'wire_control_bytes': 262144, 'phase_control_bytes': 1048576, 'actor_envelope_bytes': 262144, 'writer_proof_bytes': 131072, 'index_bytes': 65536, 'result_bytes': 8192, 'failure_bytes': 8192, 'parent_stdout_bytes': 65536, 'parent_stderr_bytes': 65536, 'parent_terminal_bytes': 262144, 'parent_summary_bytes': 4096, 'parent_metadata_pool_bytes': 262144, 'parent_complete_output_pool_bytes': 524288, 'parent_raw_stream_pool_bytes': 262144, 'parent_raw_stream_files': 4, 'parent_raw_pool_includes_two_failure_prefix_fallback_files': True, 'parent_capture_runs': 1, 'parent_metadata_files': 16, 'shared_phase_pool_not_reset_per_wire': True, 'source_profile_is_not_case_capacity_admission': True, 'witness_plan_bytes': 32768, 'witness_provenance_bytes': 65536, 'witness_mailbox_bytes': 16384}, 'before-guard': {'schema': 'hepta.epoch.fixture-output-profile.v2', 'phase': 'before-guard', 'writer_schema': 'hepta.epoch.root-fixture-writer.v1', 'phase_limits': {'stream': 1146880, 'command': 65536, 'metadata': 65536, 'envelope': 131072, 'final': 65536, 'total': 1474560}, 'phase_domain_limits': {'generic': 65536, 'public': 32768, 'png': 1048576}, 'wire_domain_limits': {'generic': 16384, 'public': 32768, 'png': 1048576}, 'phase_files': 256, 'phase_frames': 4096, 'phase_wires': 96, 'metadata_file_bytes': 65536, 'command_file_bytes': 32768, 'wire_control_bytes': 262144, 'phase_control_bytes': 1048576, 'actor_envelope_bytes': 131072, 'writer_proof_bytes': 131072, 'index_bytes': 65536, 'result_bytes': 8192, 'failure_bytes': 8192, 'parent_stdout_bytes': 65536, 'parent_stderr_bytes': 65536, 'parent_terminal_bytes': 262144, 'parent_summary_bytes': 4096, 'parent_metadata_pool_bytes': 262144, 'parent_complete_output_pool_bytes': 524288, 'parent_raw_stream_pool_bytes': 262144, 'parent_raw_stream_files': 4, 'parent_raw_pool_includes_two_failure_prefix_fallback_files': True, 'parent_capture_runs': 1, 'parent_metadata_files': 16, 'shared_phase_pool_not_reset_per_wire': True, 'source_profile_is_not_case_capacity_admission': True, 'witness_plan_bytes': 32768, 'witness_provenance_bytes': 65536, 'witness_mailbox_bytes': 16384}, 'after-guard': {'schema': 'hepta.epoch.fixture-output-profile.v2', 'phase': 'after-guard', 'writer_schema': 'hepta.epoch.root-fixture-writer.v1', 'phase_limits': {'stream': 65536, 'command': 32768, 'metadata': 65536, 'envelope': 131072, 'final': 65536, 'total': 360448}, 'phase_domain_limits': {'generic': 32768, 'public': 32768, 'png': 0}, 'wire_domain_limits': {'generic': 16384, 'public': 32768, 'png': 1048576}, 'phase_files': 256, 'phase_frames': 4096, 'phase_wires': 96, 'metadata_file_bytes': 65536, 'command_file_bytes': 32768, 'wire_control_bytes': 262144, 'phase_control_bytes': 1048576, 'actor_envelope_bytes': 131072, 'writer_proof_bytes': 131072, 'index_bytes': 65536, 'result_bytes': 8192, 'failure_bytes': 8192, 'parent_stdout_bytes': 65536, 'parent_stderr_bytes': 65536, 'parent_terminal_bytes': 262144, 'parent_summary_bytes': 4096, 'parent_metadata_pool_bytes': 262144, 'parent_complete_output_pool_bytes': 524288, 'parent_raw_stream_pool_bytes': 262144, 'parent_raw_stream_files': 4, 'parent_raw_pool_includes_two_failure_prefix_fallback_files': True, 'parent_capture_runs': 1, 'parent_metadata_files': 16, 'shared_phase_pool_not_reset_per_wire': True, 'source_profile_is_not_case_capacity_admission': True, 'witness_plan_bytes': 32768, 'witness_provenance_bytes': 65536, 'witness_mailbox_bytes': 16384}}

def verify_epoch_shell_wire(wire, stdout, stderr):
    """Reassemble every original shell-v2 stream frame, including EXIT."""
    need(wire.get('schema') == 'hepta.epoch.operator-raw-shell-v2.v1'
         and wire.get('exit_code') == 0 and wire.get('original_exit_frame_received') is True
         and wire.get('output_complete') is True and wire.get('automatic_retry') is False
         and wire.get('error') is None and wire.get('command_utf8_sha256') == sha(wire['command'].encode())
         and wire.get('wire_request_bytes') == len(('shell,v2,raw:' + wire['command']).encode())
         and 0 < wire['wire_request_bytes'] < 65536, 'Root original shell-v2 terminal incomplete')
    need(type(wire.get('p4_monotonic_started_ns')) is int
         and type(wire.get('p4_monotonic_finished_ns')) is int
         and 0 < wire['p4_monotonic_started_ns'] <= wire['p4_monotonic_finished_ns'], 'Root original wire clock differs')
    for key, raw in [('stdout', stdout), ('stderr', stderr)]:
        need(all(wire[key][k] == v for k,v in descriptor(raw).items()), 'Root wire/raw stream pin differs')
    offsets = {1: 0, 2: 0}; streams = {1: stdout, 2: stderr}; exits = 0; closed = False
    need(isinstance(wire['frames'], list) and 1 <= len(wire['frames']) <= 4096, 'Root frame count bound')
    for row in wire['frames']:
        kind, length = row['stream'], row['bytes']
        need(type(length) is int and 0 <= length <= 8*1024*1024, 'Root original frame byte bound')
        if kind in streams:
            part = streams[kind][offsets[kind]:offsets[kind]+length]; offsets[kind] += length
            need(len(part) == length and sha(part) == row['sha256'], 'original Root stream frame differs')
        elif kind == 3:
            exits += 1; need(length in (1, 4) and row['sha256'] == sha(bytes(length)), 'Root exit frame differs')
        else:
            need(kind == 4 and not closed and length == 0 and row['sha256'] == sha(b''), 'unexpected Root wire frame')
            closed = True
    need(exits == 1 and offsets == {1: len(stdout), 2: len(stderr)}
         and wire['frames'][-1]['stream'] == 3, 'Root terminal/stream counts differ')
    verify_epoch_shell_wire_extension(wire, stdout, stderr)

def verify_epoch_operator_execution(files, prefix, stdout, expected_command, *, phase, nonce, boot):
    """Actual fixture shell bytes/UID witness; not worker qualification."""
    q = strict(files[prefix + '_execution']); wire = strict(files[prefix + '_wire'])
    intent = strict(files[prefix + '_intent']); uid_wire = strict(files[prefix + '_uid_wire'])
    command = files[prefix + '_command']; err = files[prefix + '_stderr']; uid = files[prefix + '_uid']
    need(command == expected_command and not err and uid == b'2000\n', 'Root command/UID/raw streams differ')
    need(q.get('schema') == 'hepta.epoch.operator-command-execution.v1'
         and q.get('execution_uid') == 2000 and q.get('dispatch_count') == 1
         and q.get('exit_code') == 0 and q.get('output_complete') is True
         and q.get('automatic_retry') is False and q.get('native_task_claim') is False
         and q.get('model_requests') == 0 and q.get('operator_shell_trace') is False
         and q.get('command_sha256') == sha(command), 'original Root operator execution binding differs')
    destination = '/data/local/tmp/hepta-native-guard-' + nonce + '/' + phase + '-' + prefix + '.sh'
    uid_path = destination[:-3] + '.uid'
    need(intent.get('command_sha256') == sha(command) and intent.get('phone_command_path') == destination
         and intent.get('uid_original_path') == uid_path and intent.get('trace') is False
         and intent.get('state') == 'RESERVED_MAY_BE_UNKNOWN' and intent.get('automatic_retry') is False
         and intent.get('model_requests') == 0 and intent.get('native_task_claim') is False,
         'original Root fixture dispatch intent differs')
    expected_wire,expected_uid = operator_wire(sha(command), destination, uid_path, boot)
    need(wire['command'] == expected_wire and uid_wire['command'] == expected_uid,
         'Root original wire did not execute the one reviewed staged command/UID read')
    need(uid_wire['p4_monotonic_started_ns'] >= wire['p4_monotonic_finished_ns'], 'original UID read preceded execution')
    for key, raw in [('stdout', stdout), ('stderr', err)]:
        need(all(q[key][k] == wire[key][k] == v for k,v in descriptor(raw).items()), 'Root execution/raw stream pin differs')
    need(all(q['execution_uid_original'][k] == uid_wire['stdout'][k] == v for k,v in descriptor(uid).items()),
         'original execution UID descriptor differs')
    verify_epoch_shell_wire(wire, stdout, err);verify_epoch_shell_wire(uid_wire, uid, b'')
    need(type(q) is dict and set(q) == {'schema', 'command_sha256', 'execution_uid',
         'execution_uid_original', 'exit_code', 'output_complete', 'stdout', 'stderr',
         'dispatch_count', 'automatic_retry', 'native_task_claim', 'model_requests',
         'operator_shell_trace', 'raw_shell_v2_original'}
         and all(type(q[k]) is int for k in ('execution_uid', 'exit_code', 'dispatch_count', 'model_requests')),
         'epoch execution exact typed fields differ')
    domain = 'png' if prefix == 'png' else 'public' if prefix in ('public', 'prelude-initial', 'prelude-focused') else 'generic'
    need(wire['domain'] == domain and uid_wire['domain'] == 'generic'
         and q['raw_shell_v2_original'] == str(Path(wire['stdout']['path']).with_suffix('').with_suffix('.wire.json'))
         and q['execution_uid_original']['path'] == uid_wire['stdout']['path'],
         'epoch source wire path or finite domain differs')

def epoch_fixture_typed_equal(left, right):
    return encoded(left) == encoded(right)


def epoch_fixture_consumer_profile(phase):
    need(phase in EPOCH_FIXTURE_CONSUMER_PROFILES, 'known fixture phase profile required')
    return EPOCH_FIXTURE_CONSUMER_PROFILES[phase]


def epoch_fixture_consumer_source():
    sources = globals().get('__reviewed_package_sources__')
    manifest = globals().get('__reviewed_package_manifest_raw__')
    need(type(sources) is dict and len(sources) == 32 and type(manifest) is bytes
         and globals().get('__actual_context__') in ('phone', 'mac', 'p4'),
         'complete actual package/context required for epoch fixture attribution')
    source = sources.get('source/root_fixture_once.py')
    need(type(source) is bytes and 0 < len(source) <= 131072,
         'exact reviewed epoch fixture source required')
    return descriptor(source), sha(manifest)


def verify_epoch_shell_wire_extension(wire, stdout, stderr):
    need(type(wire) is dict and type(stdout) is bytes and type(stderr) is bytes
         and type(wire.get('command')) is str and type(wire.get('transport_id')) is str
         and 0 < len(wire['transport_id'].encode()) <= 128
         and type(wire.get('wire_request_bytes')) is int
         and type(wire.get('exit_code')) is int
         and wire.get('schema') == 'hepta.epoch.operator-raw-shell-v2.v1'
         and wire.get('socket_eof_observed') is True and wire.get('socket_closed') is True
         and wire.get('socket_creation_attempted') is True and wire.get('socket_identity_registered') is True
         and wire.get('send_completion_unknown') is False and wire.get('partial_control') is None
         and wire.get('partial_frame') is None and wire.get('smart_failure') is None
         and wire.get('smart_reply_b64') is None and wire.get('cleanup_errors') == []
         and type(wire.get('explicit_signal_calls')) is int and wire['explicit_signal_calls'] == 0
         and wire.get('phone_process_join_or_cleanup_proven') is False
         and wire.get('old_core_wire_function_executed') is False
         and wire.get('socket_close_may_affect_remote_process') is True,
         'epoch wire provenance/EOF/owned-cleanup differs')
    need(type(wire.get('frame_count')) is int and wire['frame_count'] == len(wire['frames'])
         and 1 <= wire['frame_count'] <= 4096, 'epoch wire finite frame count differs')
    need(all(type(row) is dict and set(row) == {'stream', 'bytes', 'sha256'}
             and type(row['stream']) is int and row['stream'] in (1, 2, 3, 4)
             and type(row['bytes']) is int and 0 <= row['bytes'] <= 1048576
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
             for row in wire['frames']), 'epoch frame exact typed fields differ')
    need(wire.get('domain') in ('generic', 'public', 'png'), 'epoch output domain differs')
    maximum = {'generic': 16384, 'public': 32768, 'png': 1048576}[wire['domain']]
    need(type(wire.get('domain_output_limit')) is int and wire['domain_output_limit'] == maximum
         and len(stdout)+len(stderr) <= maximum, 'epoch domain byte cap differs')
    sent = 4+len(('host:transport-id:'+wire['transport_id']).encode())+4+wire['wire_request_bytes']
    received = 8+5*len(wire['frames'])+sum(row['bytes'] for row in wire['frames'] if row['stream'] in (3, 4))
    for key, value in [('send_bytes_offered', sent), ('control_received_bytes', received),
                       ('control_bytes_charged', sent+received+1)]:
        need(type(wire.get(key)) is int and wire[key] == value, 'actual epoch control accounting differs: '+key)
    need(wire['control_bytes_charged'] <= 262144,
         'epoch one-wire control budget exceeded')
    last = wire['frames'][-1]
    import struct
    need(wire.get('last_header_b64') == base64.b64encode(struct.pack('<BI', last['stream'], last['bytes'])).decode(),
         'actual last complete frame header differs')


def epoch_fixture_original_row(row, raw, name, parent):
    import stat
    need(type(row) is dict and type(raw) is bytes and type(name) is str
         and Path(name).name == name and name not in ('.', '..'), 'epoch original row/name differs')
    path = row.get('source_path', row.get('path'))
    info = row.get('source_metadata', row.get('metadata'))
    need(type(path) is str and Path(path).is_absolute() and str(Path(path)) == path
         and '..' not in Path(path).parts and Path(path).name == name and Path(path).parent == parent,
         'epoch original left the one actual actor directory')
    need(type(info) is list and len(info) == 9 and all(type(n) is int for n in info)
         and stat.S_ISREG(info[2]) and stat.S_IMODE(info[2]) == 0o600
         and info[5] == 1 and info[6] == len(raw), 'epoch raw full9/file kind differs')
    need(type(row.get('bytes')) is int and type(row.get('sha256')) is str
         and {k: row[k] for k in ('bytes', 'sha256')} == descriptor(raw),
         'epoch original raw byte pin differs')
    return tuple(info[:2])


def verify_epoch_root_actor_originals(raw, plan_raw, files, *, writer_raw, index_raw, result_raw):
    need(all(type(b) is bytes for b in (raw, plan_raw, writer_raw, index_raw, result_raw))
         and len(raw) <= 2097152 and len(writer_raw) <= 131072
         and len(index_raw) <= 65536 and len(result_raw) <= 8192,
         'bounded full epoch actor/index/writer/result originals required')
    q = strict(raw)
    plan = strict(plan_raw)
    index = strict(index_raw)
    writer = strict(writer_raw)
    result = strict(result_raw)
    required = {'schema', 'phase_plan_sha256', 'scope', 'contract_sha256', 'phase',
        'actor_reference_source_sha256', 'core_reference_source_sha256',
        'route_transport_reference_source_sha256', 'epoch_adapter_source',
        'old_core_wire_function_executed', 'original_actor_methods_modified_in_place',
        'writer_binding', 'writer_profile', 'files', 'fixture_prelude',
        'installed_probe_before', 'installed_probe_after', 'source_equals_apk_not_asserted',
        'uid2000_fixture_only_not_native_worker_qualification', 'model_requests',
        'native_task_submissions', 'automatic_retry'}
    need(type(q) is dict and set(q) == required and q['schema'] == 'hepta.epoch.root-actor-originals.v1'
         and q['phase_plan_sha256'] == sha(plan_raw)
         and all(epoch_fixture_typed_equal(q[k], plan[k]) for k in ('scope', 'contract_sha256', 'phase')),
         'explicit epoch actor original scope differs')
    source, package_sha = epoch_fixture_consumer_source()
    profile = epoch_fixture_consumer_profile(plan['phase'])
    need(len(plan_raw) <= profile['witness_plan_bytes'], 'source-fixed epoch plan bound differs')
    need(epoch_fixture_typed_equal(q['epoch_adapter_source'], source)
         and epoch_fixture_typed_equal(q['writer_profile'], profile)
         and q['actor_reference_source_sha256'] == '1c27b548e42c91391e12db125c23608a2d5fb9e28ae2713df17c271bddc58fa2'
         and q['core_reference_source_sha256'] == '705b982a46de0fd4427cd6a233687381c592ef74459f9818f3da15e20c03916f'
         and q['route_transport_reference_source_sha256'] == '6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
         and q['old_core_wire_function_executed'] is False
         and q['original_actor_methods_modified_in_place'] is False
         and q['source_equals_apk_not_asserted'] is True
         and q['uid2000_fixture_only_not_native_worker_qualification'] is True
         and type(q['model_requests']) is int and q['model_requests'] == 0
         and type(q['native_task_submissions']) is int and q['native_task_submissions'] == 0
         and q['automatic_retry'] is False, 'epoch source/profile attribution or qualification boundary differs')
    binding = q['writer_binding']
    need(type(binding) is dict and set(binding) == {'schema', 'lease_sha256', 'package_sha256',
          'phase_plan_sha256', 'adapter_source', 'admission', 'profile'}
         and binding['schema'] == 'hepta.epoch.fixture-writer-binding.v1'
         and binding['package_sha256'] == package_sha and binding['phase_plan_sha256'] == sha(plan_raw)
         and type(binding['lease_sha256']) is str and re.fullmatch('[0-9a-f]{64}', binding['lease_sha256'])
         and epoch_fixture_typed_equal(binding['adapter_source'], source)
         and epoch_fixture_typed_equal(binding['profile'], descriptor(encoded(profile))),
         'epoch actual source/lease/profile binding differs')
    originals = q['files']
    need(type(originals) is dict and 1 <= len(originals) <= 253
         and {'WRITER-ADMISSION.original.json', 'ACTOR-ATTEMPT.json'} <= set(originals),
         'complete actual actor prefix required')
    paths = [row.get('source_path') for row in originals.values()]
    need(all(type(p) is str for p in paths), 'actual prefix paths required')
    parent = Path(paths[0]).parent
    bodies = {}
    used_planned = set()
    identities = set()
    for name, row in originals.items():
        need(type(row) is dict and set(row) in (
            {'source_path', 'source_metadata', 'bytes', 'sha256', 'planned_file_key'},
            {'source_path', 'source_metadata', 'bytes', 'sha256', 'raw_b64'}),
            'epoch raw prefix exact fields differ')
        if 'planned_file_key' in row:
            key = row['planned_file_key']
            need(type(key) is str and key in files and key not in used_planned,
                 'epoch planned original missing or duplicated')
            used_planned.add(key)
            data = files[key]
        else:
            need(type(row['raw_b64']) is str and len(row['raw_b64']) <= 8*1024*1024,
                 'bounded prefix base64 required')
            data = base64.b64decode(row['raw_b64'], validate=True)
            need(base64.b64encode(data).decode() == row['raw_b64'], 'canonical prefix base64 required')
        identity = epoch_fixture_original_row(row, data, name, parent)
        need(identity not in identities, 'aliased actor output inode refused')
        identities.add(identity)
        bodies[name] = data
    need(used_planned == set(files), 'all planned originals required in actual prefix')
    need(epoch_fixture_typed_equal(binding['admission'], descriptor(bodies['WRITER-ADMISSION.original.json'])),
         'actual resource-admission original missing or changed')
    attempt = strict(bodies['ACTOR-ATTEMPT.json'])
    need(type(attempt) is dict and set(attempt) == {'phase_plan_sha256', 'lease_sha256', 'scope',
         'phase', 'state', 'automatic_retry', 'native_task_claim', 'model_requests', 'writer_binding', 'writer_profile'}
         and attempt['phase_plan_sha256'] == sha(plan_raw) and attempt['lease_sha256'] == binding['lease_sha256']
         and epoch_fixture_typed_equal(attempt['scope'], plan['scope']) and attempt['phase'] == plan['phase']
         and attempt['state'] == 'RESERVED_NO_AUTOMATIC_RETRY' and attempt['automatic_retry'] is False
         and attempt['native_task_claim'] is False and type(attempt['model_requests']) is int
         and attempt['model_requests'] == 0 and epoch_fixture_typed_equal(attempt.get('writer_binding'), binding)
         and epoch_fixture_typed_equal(attempt.get('writer_profile'), profile),
         'actual pre-action writer reservation/profile differs')
    apks = q['installed_probe_before']
    need(type(apks) is list and 1 <= len(apks) <= 16 and epoch_fixture_typed_equal(apks, q['installed_probe_after']),
         'installed actual public APK identity changed')
    for apk in apks:
        need(type(apk) is dict and set(apk) == {'path', 'bytes', 'sha256'}
             and type(apk['path']) is str and apk['path'].startswith('/data/app/') and apk['path'].endswith('.apk')
             and type(apk['bytes']) is int and 0 < apk['bytes'] <= 100*1024*1024
             and type(apk['sha256']) is str and re.fullmatch('[0-9a-f]{64}', apk['sha256']),
             'actual public APK descriptor differs')
    need(len({x['path'] for x in apks}) == len(apks), 'duplicate actual public APK path')
    for leaf in ('probe-before.json', 'probe-after.json'):
        need(epoch_fixture_typed_equal(strict(bodies[leaf]), {
            'installed_public_package': 'org.trillionnium.hepta.controlprobe', 'apks': apks,
            'source_equals_apk_not_asserted': True}), 'actual APK probe original differs from actor envelope')
    prelude = q['fixture_prelude']
    need(prelude is None or (q['phase'] == 'setup' and type(prelude) is dict
         and prelude.get('schema') == 'hepta.native-guard.root-text-fixture-prelude.v1'
         and epoch_fixture_typed_equal(prelude.get('scope'), plan['scope'])
         and prelude.get('contract_sha256') == plan['contract_sha256']
         and prelude.get('operation_id') == plan['operation_id']
         and prelude.get('native_worker_qualification') is False
         and prelude.get('model_requests') == 0 and prelude.get('business_qualified') is False
         and prelude.get('automatic_retry') is False), 'explicit unqualified actual prelude differs')
    need(set(index) == {'schema', 'phase_plan_sha256', 'files', 'actor_originals_file',
         'writer_proof_file', 'result_file', 'writer_binding', 'epoch_adapter_source'}
         and index['schema'] == 'hepta.epoch.root-original-index.v1'
         and index['phase_plan_sha256'] == sha(plan_raw)
         and epoch_fixture_typed_equal(index['writer_binding'], binding)
         and epoch_fixture_typed_equal(index['epoch_adapter_source'], source)
         and set(index['files']) == set(files)
         and index['actor_originals_file'] == str(parent/'ACTOR-ORIGINALS.json')
         and index['writer_proof_file'] == str(parent/'OUTPUT-WRITER.original.json')
         and index['result_file'] == str(parent/'RESULT.json'), 'epoch final index path/identity differs')
    for name, row in originals.items():
        if 'planned_file_key' in row:
            need(index['files'][row['planned_file_key']] == row['source_path'], 'actual index/source path differs')
    need(type(result) is dict and set(result) == {'schema', 'state', 'phase', 'original_index',
         'writer_proof_file', 'writer_binding', 'component_qualified', 'native_worker_qualification',
         'model_requests', 'automatic_retry', 'phone_stage_retained'}
         and result.get('schema') == 'hepta.epoch.root-fixture-result.v1'
         and result.get('state') == 'EPOCH_ROOT_FIXTURE_ORIGINALS_RETAINED_NOT_PUBLISHED'
         and result.get('phase') == plan['phase']
         and epoch_fixture_typed_equal(result.get('writer_binding'), binding)
         and result.get('component_qualified') is False and result.get('native_worker_qualification') is False
         and type(result.get('model_requests')) is int and result['model_requests'] == 0
         and result.get('automatic_retry') is False
         and result.get('original_index') == {'path': str(parent/'ORIGINAL-INDEX.json'), **descriptor(index_raw)}
         and result.get('writer_proof_file') == str(parent/'OUTPUT-WRITER.original.json'),
         'actual epoch result/index link differs')
    bodies.update({'ACTOR-ORIGINALS.json': raw, 'ORIGINAL-INDEX.json': index_raw, 'RESULT.json': result_raw})
    need(type(writer) is dict and set(writer) == {'schema', 'state', 'binding', 'phase', 'limits',
         'domain_limits', 'charged_before_self', 'domain_charged', 'phase_frames_charged',
         'wire_count', 'control_bytes_charged', 'all_wire_receipts_terminal', 'prefix_files',
         'self_file', 'self_file_excluded_from_prefix', 'self_raw_bytes_charged_separately_by_consumer',
         'charges_are_monotonic_reservations_not_refunded_actual_bytes', 'automatic_retry',
         'component_qualified', 'native_worker_qualification', 'old_core_wire_function_executed'}
         and writer.get('schema') == 'hepta.epoch.root-fixture-writer.v1'
         and writer.get('state') == 'ACTUAL_PHASE_OUTPUT_FILES_RETAINED_NOT_COMPONENT_QUALIFICATION'
         and writer.get('phase') == plan['phase']
         and epoch_fixture_typed_equal(writer.get('binding'), binding)
         and epoch_fixture_typed_equal(writer.get('limits'), profile['phase_limits'])
         and epoch_fixture_typed_equal(writer.get('domain_limits'), profile['phase_domain_limits'])
         and writer.get('all_wire_receipts_terminal') is True
         and writer.get('self_file') == 'OUTPUT-WRITER.original.json'
         and writer.get('self_file_excluded_from_prefix') is True
         and writer.get('self_raw_bytes_charged_separately_by_consumer') is True
         and writer.get('charges_are_monotonic_reservations_not_refunded_actual_bytes') is True
         and writer.get('automatic_retry') is False and writer.get('component_qualified') is False
         and writer.get('native_worker_qualification') is False
         and writer.get('old_core_wire_function_executed') is False,
         'actual complete writer proof differs')
    prefix = writer.get('prefix_files')
    need(type(prefix) is dict and set(prefix) == set(bodies) and len(prefix)+1 <= profile['phase_files'],
         'writer full actual output set differs')
    charged = {kind: 0 for kind in profile['phase_limits']}
    prefix_identities = set()
    for name, row in prefix.items():
        need(type(row) is dict and set(row) == {'kind', 'reserved_bytes', 'actual_written_bytes',
             'path', 'bytes', 'sha256', 'metadata'}, 'writer file exact fields differ')
        inode = epoch_fixture_original_row(row, bodies[name], name, parent)
        need(inode not in prefix_identities, 'writer prefix aliases an output inode')
        prefix_identities.add(inode)
        kind = row['kind']
        expected_kind = ('envelope' if name == 'ACTOR-ORIGINALS.json' else
            'final' if name in ('ORIGINAL-INDEX.json', 'RESULT.json') else
            'stream' if name.endswith(('.stdout.bin', '.stderr.bin')) else
            'command' if name.endswith('.command.sh') else 'metadata')
        need(kind in charged and kind != 'total' and type(row['reserved_bytes']) is int
             and kind == expected_kind
             and type(row['actual_written_bytes']) is int
             and row['reserved_bytes'] == row['actual_written_bytes'] == len(bodies[name]),
             'complete actual write/reservation equality differs')
        if name in originals:
            need(row['metadata'] == originals[name]['source_metadata'], 'writer/prefix full9 differs')
        charged[kind] += len(bodies[name])
        charged['total'] += len(bodies[name])
    need(epoch_fixture_typed_equal(charged, writer.get('charged_before_self')),
         'shared phase writer account cannot be recomputed')
    final_charged = dict(charged)
    final_charged['final'] += len(writer_raw)
    final_charged['total'] += len(writer_raw)
    need(all(final_charged[k] <= profile['phase_limits'][k] for k in final_charged),
         'actual body plus separate self-proof charge exceeds fixed phase budget')
    wires = []
    for name, body in bodies.items():
        if name.endswith('.wire.json'):
            wire = strict(body)
            base = name[:-len('.wire.json')]
            out = bodies[base+'.stdout.bin']
            err = bodies[base+'.stderr.bin']
            verify_epoch_shell_wire(wire, out, err)
            need(epoch_fixture_typed_equal(wire['epoch_writer_binding'], binding), 'wire belongs to another writer')
            intent = strict(bodies[base+'.INTENT.json'])
            need(type(intent) is dict and set(intent) == {'schema', 'command', 'wire_request_bytes',
                 'p4_monotonic_ns', 'automatic_retry', 'domain', 'writer_binding'}
                 and intent['schema'] == 'hepta.epoch.fixture-wire-intent.v1'
                 and intent['command'] == wire['command']
                 and type(intent['wire_request_bytes']) is int
                 and intent['wire_request_bytes'] == wire['wire_request_bytes']
                 and type(intent['p4_monotonic_ns']) is int
                 and 0 < intent['p4_monotonic_ns'] <= wire['p4_monotonic_started_ns']
                 and intent['automatic_retry'] is False and intent['domain'] == wire['domain']
                 and epoch_fixture_typed_equal(intent['writer_binding'], binding),
                 'actual pre-wire intent or source binding differs')
            wires.append((wire, out, err))
    need(1 <= len(wires) <= profile['phase_wires'], 'actual wire original count differs')
    wires.sort(key=lambda x: x[0]['p4_monotonic_started_ns'])
    frames = control = ended = 0
    domains = {k: 0 for k in profile['phase_domain_limits']}
    for wire, out, err in wires:
        need(wire['p4_monotonic_started_ns'] >= ended, 'wire original phase ordering differs')
        ended = wire['p4_monotonic_finished_ns']
        frames += wire['frame_count']
        control += wire['control_bytes_charged']
        domains[wire['domain']] += len(out)+len(err)
        need(wire['phase_frames_charged'] == frames and type(wire['phase_frames_charged']) is int
             and wire['phase_control_bytes_charged'] == control and type(wire['phase_control_bytes_charged']) is int
             and epoch_fixture_typed_equal(wire['phase_domain_charges'], domains),
             'wire did not consume one monotonic phase pool')
    need(type(writer.get('wire_count')) is int and writer['wire_count'] == len(wires)
         and type(writer.get('phase_frames_charged')) is int and writer['phase_frames_charged'] == frames
         and type(writer.get('control_bytes_charged')) is int and writer['control_bytes_charged'] == control
         and epoch_fixture_typed_equal(writer.get('domain_charged'), domains)
         and frames <= profile['phase_frames'] and control <= profile['phase_control_bytes']
         and all(domains[k] <= profile['phase_domain_limits'][k] for k in domains)
         and sum(domains.values()) == charged['stream'], 'complete phase domain/control/frame accounting differs')
    return {'schema': 'hepta.epoch.fixture-original-writer-verification.v1',
        'phase': plan['phase'], 'source': source, 'package_sha256': package_sha,
        'writer_proof': descriptor(writer_raw), 'all_actual_output_bytes': final_charged['total'],
        'charged': final_charged, 'domain_charged': domains, 'files': len(prefix)+1,
        'case_reservation_semantics_recomputed_by_this_function': False,
        'full_admission_original_retained': True, 'component_qualified': False}


def epoch_root_witness(home, phase, kernel, channel, guards):
    """Explicit epoch witness consumer; the old v1 function is untouched."""
    import component_common as C
    import witness_bundle as W
    need(globals().get('__actual_context__') == 'phone'
         and callable(getattr(C, '_owned_output_read', None))
         and callable(getattr(C, 'epoch_read_original', None)),
         'actual phone context and safe epoch original readers required')
    lease_raw = C._owned_output_read(Path(home)/'LEASE.json', 131072)
    lease = W.epoch_witness_lease(lease_raw)
    need(lease['nonce'] == kernel.contract['nonce'], 'epoch witness lease/contract identity differs')
    token = root_operation_id(kernel.scope, kernel.contract_sha, phase)
    commands = root_commands(kernel, phase, guards, token)
    plan = {'schema': 'hepta.native-guard.root-phase-plan.v1', 'scope': kernel.scope,
        'contract_sha256': kernel.contract_sha, 'phase': phase, 'operation_id': token,
        'commands': {key: {'base64': base64.b64encode(raw).decode(), **descriptor(raw)}
                     for key, raw in commands.items()},
        'execution_order': ['disturbance', 'public', 'png'] if phase == 'before-guard' else list(commands),
        'operator_fixture_not_model_or_worker_qualification': True, 'automatic_retry': False,
        'caller_must_retain_original_command_execution_and_wire': True}
    plan_raw = encoded(plan)
    need(len(plan_raw) <= 32768, 'serialized epoch phase plan exceeds its actual retained bound')
    put(Path(home)/('ROOT-'+phase.upper()+'-PLAN.json'), plan_raw)
    mailbox_path = Path(home)/'operator'/(phase+'.json')
    while True:
        channel.fence()
        try:
            mailbox_raw = C._owned_output_read(mailbox_path, 16384)
        except FileNotFoundError:
            need(time.monotonic() < channel.deadline, 'epoch Root witness deadline')
            time.sleep(.05)
            continue
        break
    value = strict(mailbox_raw)
    need(type(value) is dict and set(value) == {'schema', 'phase', 'scope', 'contract_sha256',
         'operation_id', 'files', 'provenance'} and value['schema'] == 'hepta.epoch.root-witness.v1'
         and all(encoded(value[k]) == encoded(plan[k])
                 for k in ('phase', 'scope', 'contract_sha256', 'operation_id')),
         'explicit epoch mailbox identity differs')
    required = {name+suffix for name in commands
                for suffix in ('', '_execution', '_wire', '_command', '_stderr', '_uid', '_uid_wire', '_intent')}
    need(type(value['files']) is dict and set(value['files']) == required,
         'complete epoch witness file set differs')
    members = {'mailbox.json': mailbox_raw, 'plan.original.json': plan_raw}
    pins = {}
    total = len(mailbox_raw)+len(plan_raw)

    def take(row, expected_path, maximum):
        nonlocal total
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
             and row['path'] == expected_path and type(row['bytes']) is int
             and 0 <= row['bytes'] <= maximum and type(row['sha256']) is str
             and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'exact bounded epoch member descriptor differs')
        need(expected_path not in members and len(members) < 32
             and total+row['bytes'] <= 16*1024*1024, 'shared epoch witness read/copy budget exhausted')
        path = Path(home)/'operator'/expected_path
        before = metadata(path.lstat())
        raw = C.epoch_read_original({'path': str(path), 'metadata': before,
                                    **{k: row[k] for k in ('bytes', 'sha256')}})
        need(before[6] == len(raw), 'epoch actual original length differs')
        members[expected_path] = raw
        pins[expected_path] = (path, before, raw)
        total += len(raw)
        return raw

    provenance_raw = take(value['provenance'], phase+'/PROVENANCE.json', 65536)
    provenance = strict(provenance_raw)
    for key, row in value['files'].items():
        take(row, phase+'/'+key+'.original', 1048576 if key == 'png' else 8*1024*1024)
    for key, leaf, maximum in (
        ('actor_originals', 'ACTOR-ORIGINALS.original.json', epoch_fixture_consumer_profile(phase)['actor_envelope_bytes']),
        ('writer_proof', 'OUTPUT-WRITER.original.json', 131072),
        ('original_index', 'ORIGINAL-INDEX.original.json', 65536),
        ('actor_result', 'RESULT.original.json', 8192)):
        take(provenance[key], phase+'/'+leaf, maximum)
    observed_plan, observed_commands, files, _verification = W.validate_epoch_witness_members(members, lease_raw)
    need(encoded(observed_plan) == encoded(plan) and observed_commands == commands,
         'actual epoch witness differs from current component command plan')
    # The pure v2 validator above rechecks the same existing reservation through
    # C.epoch_fixture_copy_admission. It must not grant a fresh pool here.
    need(C._owned_output_read(Path(home)/'LEASE.json', 131072) == lease_raw
         and C._owned_output_read(Path(home)/('ROOT-'+phase.upper()+'-PLAN.json'), 65536) == plan_raw,
         'actual epoch lease/plan changed before witness copies')
    for path, before, raw in pins.values():
        need(C.epoch_read_original({'path': str(path), 'metadata': before, **descriptor(raw)}) == raw
             and metadata(path.lstat()) == before,
             'actual epoch witness member changed before copy')
    saved = private_dir(kernel.run/('root-'+phase+'-originals'), create=True)
    for key, data in files.items():
        put(saved/(key+'.original'), data)
    for key, leaf in (('actor_originals', 'ACTOR-ORIGINALS.original.json'),
                      ('writer_proof', 'OUTPUT-WRITER.original.json'),
                      ('original_index', 'ORIGINAL-INDEX.original.json'),
                      ('actor_result', 'RESULT.original.json')):
        put(saved/leaf, members[provenance[key]['path']])
    put(saved/'PROVENANCE.original.json', provenance_raw)
    if phase == 'setup' and kernel.contract['case_id'] == 'NEG-01':
        guards.verify_app_open(strict(files['open']), token, kernel.mapper.apps['视觉挑战']['component'])
    if phase == 'before-guard' and kernel.contract['case_id'] == 'NEG-01':
        guards.verify_app_open(strict(files['disturbance']), sha((token+':open').encode())[:32],
                               kernel.mapper.apps['Unicode验证']['component'])
    put(saved/'MAILBOX.original.json', mailbox_raw)
    for path, before, raw in pins.values():
        need(C.epoch_read_original({'path': str(path), 'metadata': before, **descriptor(raw)}) == raw
             and metadata(path.lstat()) == before,
             'actual epoch witness member changed during copies')
    return value['operation_id'], files


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser()
    p.add_argument('--package', required=True); p.add_argument('--package-sha256', required=True)
    p.add_argument('--lease', required=True); p.add_argument('--lease-sha256', required=True)
    p.add_argument('--listener-fd', type=int, required=True)
    p.add_argument('--execute-native-listener-once', action='store_true')
    a = p.parse_args(); need(a.execute_native_listener_once, 'explicit reviewed lifecycle entry required')
    return serve(a)


def epoch_serve(args):
    package = Path(args.package); verify_package(package, args.package_sha256)
    stage=sys.modules.get('stage_component');budget=globals().get('__epoch_budget_check__')
    need(stage is not None and callable(budget) and stage.__dict__.get('__epoch_budget_check__') is budget,
         'actual stage module and same listener budget required')
    budget();home=private_dir(Path(args.lease))
    lease,lease_raw=stage.epoch_lifecycle_load_lease(home,args.lease_sha256)
    need(lease['schema']=='hepta.native-guard.epoch-lease.v1'
         and package==home/'package/MANIFEST.json' and lease['package_sha256']==args.package_sha256,
         'exact actual epoch listener lease and package required')
    need(home == BASE / 'native-guard-r10-r1' / lease['label'], 'fixed new component namespace')
    need(os.getuid() == os.getgid() == 0 and target_identity(os.getpid())['domain'] == MAGISK,
         'component provider must be Root magisk, never bootstrap impersonation')
    bound_raw = read(home / 'BOUND-CONTRACT.json', 65536); bound = strict(bound_raw)
    need(bound['lease_sha256'] == sha(lease_raw) and bound['provider_source_sha256'] == sha(read(Path(__file__))),
         'bound provider/lease differs')
    c_raw = pinned(home / 'inputs/COMBINATION.json', lease['combination'])
    reviewed = strict(read(package.parent / 'reference/REVIEWED-PRODUCTION-PINS.json', private=False))
    c, cfg = load_combination(home / 'inputs', c_raw, reviewed); verify_external(c)
    modules = import_production(home / 'inputs/production')
    import native_guard_session_r2 as K
    owner_raw = read(home / 'owner-request.txt', 16000)
    need(sha(owner_raw) == bound['contract']['owner_request_sha256'], 'bound owner original changed')
    client_raw = read(CLIENT); need(sha(client_raw) == CLIENT_SHA, 'fixed r6 client changed')
    import types
    client = types.ModuleType('native_guard_pinned_client'); client.__file__ = str(CLIENT)
    exec(compile(client_raw, str(CLIENT), 'exec'), client.__dict__)
    sidecar = target_identity(bound['sidecar_identity']['identity'][0], bound['sidecar_identity']['identity'])
    need(sidecar == bound['sidecar_identity'], 'component sidecar identity changed before listen')
    health = client.request({'version': 1, 'op': 'health'}, timeout_s=3)
    need(health == bound['sidecar_health'] and health.get('state') == 'ready'
         and health.get('server_instance') == bound['contract']['executor_server_instance']
         and health.get('peer_context') == MAGISK and health.get('execute_authorized') is False,
         'component readonly sidecar readiness differs')
    put(home / 'PROVIDER-HEALTH.original.json', health)
    listener = socket.socket(fileno=args.listener_fd)
    need(listener.getsockname() == ('127.0.0.1', 18080)
         and listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0,
         'exact exclusively bound unstarted listener required')
    own = target_identity(os.getpid()); need(own['nnp'] == 0 and own['uid'] == own['gid'] == [0]*4,
                                           'provider process credentials differ')
    listener.listen(1); listener.settimeout(.1)
    now = time.monotonic_ns(); service_deadline = now + 420_000_000_000
    accept_deadline = now + 120_000_000_000
    need(time.time()*1000 + 420000 < lease['expires_unix_ms'], 'lease too short before listen')
    put(home / 'READY.json', {'schema': 'hepta.native-guard.ready.v1',
        'lease_sha256': sha(lease_raw), 'contract_sha256': sha(encoded(bound['contract'])),
        'combination_sha256': sha(c_raw), 'provider_source_sha256': sha(read(Path(__file__))),
        'identity': own, 'port': 18080, 'accepting_one_session': True,
        'ready_monotonic_ns': now, 'accept_deadline_monotonic_ns': accept_deadline,
        'service_deadline_monotonic_ns': service_deadline, 'model_requests': 0,
        'readiness_scope': 'isolated_component_transport_only', 'four_role_ready': False})
    stopped = [False]
    import signal
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda _s, _f: stopped.__setitem__(0, True))
    try:
        while not stopped[0] and time.monotonic_ns() < accept_deadline:
            try:
                conn, address = listener.accept()
            except socket.timeout:
                continue
            need(address[0] == '127.0.0.1', 'native connection not loopback')
            listener.close()  # Exactly one connection, including invalid owner/EOF.
            put(home / 'CONNECTION-ACCEPTED.json', {'accepted_monotonic_ns': time.monotonic_ns(),
                'peer_address': list(address), 'automatic_reconnect': False})
            run = private_dir(COMPONENT_EVIDENCE / bound['run_basename'], create=True)
            mapper = modules['phone_local_tools'].PhoneLocalTools(run, put, cfg['approved_apps'], cfg['executor'])
            kernel = K.NativeGuardSession(encoded(bound['contract']), owner_raw,
                run, home / 'claims', mapper, modules['phone_observation_tools'], modules['phone_task_guards'])
            ledger = modules['action_ledger'].ActionLedger(PRODUCTION_EVIDENCE, run)
            return run_connection(conn, run, home, kernel, ledger, client,
                ANDROID / lease['android_journal'].lstrip('/'),
                min(time.monotonic()+300, service_deadline/1e9), stopped, witness_reader=epoch_root_witness)
        need(False, 'component accept expired; no automatic restart')
    finally:
        listener.close()


def epoch_main(operation, arguments):
    """Separate provider entry after the plain full32 first-exec bootstrap."""
    import component_common as C
    need(operation=='listener' and type(operation) is str and type(arguments) is list
         and all(type(x) is str and '\0' not in x for x in arguments),'explicit epoch listener arguments required')
    p=argparse.ArgumentParser()
    p.add_argument('--package',required=True);p.add_argument('--package-sha256',required=True)
    p.add_argument('--lease',required=True);p.add_argument('--lease-sha256',required=True)
    p.add_argument('--listener-fd',type=int,required=True)
    p.add_argument('--execute-native-listener-once',action='store_true')
    a=p.parse_args(arguments);need(a.execute_native_listener_once,'explicit epoch listener entry required')
    bootstrap=getattr(C,'epoch_lifecycle_bootstrap',None)
    need(callable(bootstrap),'actual full32 phone listener bootstrap is required')
    modules=bootstrap(Path(a.package),'phone',a.package_sha256,operation)
    need(type(modules) is dict and modules.get('component_listener') is sys.modules.get(__name__)
         and modules['component_listener'].epoch_main is epoch_main,
         'bootstrap must load this actual listener from the verified32 sources')
    budget=globals().get('__epoch_budget_check__')
    need(callable(budget) and modules['stage_component'].__dict__.get('__epoch_budget_check__') is budget
         and globals().get('__actual_context__')=='phone','one actual phone listener budget is required')
    budget()
    return epoch_serve(a)

if __name__ == '__main__':
    raise SystemExit(main())
