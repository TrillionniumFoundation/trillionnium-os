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
    private_dir, metadata, descriptor, scope, relative,
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
        and q['frozen_transport_source_sha256']=='06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0'
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
         and provenance.get('frozen_transport_source_sha256') == '06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0'
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


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser()
    p.add_argument('--package', required=True); p.add_argument('--package-sha256', required=True)
    p.add_argument('--lease', required=True); p.add_argument('--lease-sha256', required=True)
    p.add_argument('--listener-fd', type=int, required=True)
    p.add_argument('--execute-native-listener-once', action='store_true')
    a = p.parse_args(); need(a.execute_native_listener_once, 'explicit reviewed lifecycle entry required')
    return serve(a)


def verify_package(package, pin):
    # Explicit current-only route.  Common's historical C32 function is untouched.
    import late_boundary as LATE
    return LATE.verify_current_package(package, pin)


if __name__ == '__main__':
    raise SystemExit(main())
