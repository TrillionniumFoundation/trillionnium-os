#!/usr/bin/env python3
"""Host-only independent closure of original isolated native guard evidence.

All commands are compared as bytes. No command is executed, no service is
contacted and no device state is read. A failed but completely known native
lifecycle has an explicitly different, zero-credit closure state.
"""
import argparse
import ast
import base64
import copy
import gzip
import hashlib
import importlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))
import component_common as C
import late_boundary as LATE
import root_fixture_originals as FIXTURE

AUDITOR_SHA = 'da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf'
DECODER_SHA = 'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073'
MAX = 64*1024*1024
PLAN_FIELDS = {'schema', 'label', 'archive', 'capture_sha256', 'package', 'sender_dir',
    'sender_host_result', 'sender_local_once', 'sender_actor', 'request', 'previous', 'preserved_draft',
    'root_fixture_attempts'}


def zero(v):
    return type(v) is int and v == 0


def write(path, raw):
    path = Path(path)
    C.need(path.parent.resolve(strict=True) == path.parent, 'new host output parent changed')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    C.sync(path.parent)
    return C.descriptor(raw)


class Originals:
    def __init__(self):
        self.files = {}

    def read(self, path, maximum=MAX):
        p = Path(path)
        C.need(p.is_absolute() and p.resolve(strict=True) == p, 'canonical original host file required')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            C.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                   and 0 <= before.st_size <= maximum, 'bounded regular original required')
            raw = stream.read(maximum+1)
            C.need(len(raw) == before.st_size and C.metadata(before) == C.metadata(os.fstat(stream.fileno()))
                   == C.metadata(p.lstat()), 'original changed during host read')
        row = {'metadata': C.metadata(before), **C.descriptor(raw)}
        if str(p) in self.files:
            C.need(self.files[str(p)] == row, 'original changed between audit phases')
        self.files[str(p)] = row
        return raw

    def pinned(self, row):
        C.need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256'}
               and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX
               and isinstance(row['sha256'], str) and C.HASH.fullmatch(row['sha256']),
               'explicit original host byte descriptor required')
        raw = self.read(row['path'])
        C.need(C.descriptor(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'original host pin differs')
        return raw

    def recheck(self):
        for p, row in list(self.files.items()):
            C.need(C.metadata(Path(p).lstat()) == row['metadata'], 'original metadata changed after audit')
            C.need(C.descriptor(self.read(p)) == {k: row[k] for k in ('bytes', 'sha256')},
                   'original byte content changed after audit')


def validate_plan(plan):
    C.need(isinstance(plan, dict) and set(plan) == PLAN_FIELDS
           and plan['schema'] == 'hepta.native-guard.closure-plan.v1'
           and re.fullmatch('[a-z0-9-]{1,70}', plan['label'])
           and isinstance(plan['capture_sha256'], str) and C.HASH.fullmatch(plan['capture_sha256']),
           'explicit original component closure plan differs')
    C.need(plan['sender_dir'] == '/home/alex/codex-hepta-natural-'+plan['label']+'-root-v150',
           'actual original Pocket4 sender directory differs')
    attempts = plan['root_fixture_attempts']
    C.need(isinstance(attempts, list) and len(attempts) <= 3
           and all(isinstance(row, dict) and set(row) == {'phase','terminal'}
                   and row['phase'] in FIXTURE.PHASES for row in attempts),
           'explicit original Root fixture parent attempts required, including an explicit empty list')
    phases = [row['phase'] for row in attempts]
    C.need(phases == sorted(set(phases), key=FIXTURE.PHASES.index), 'Root fixture phases repeat or are unordered')
    return plan


def archive_files(raw, capture_sha256):
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as stream:
        plain = stream.read(MAX+8*1024*1024+1)
    C.need(len(plain) <= MAX+8*1024*1024, 'original archive expansion exceeds capture bound')
    values = {}; total = 0
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
        for member in archive:
            rel = C.relative(member.name)
            C.need(member.isfile() and not member.linkname and not member.pax_headers
                   and member.uid == member.gid == 0 and member.mode == 0o600 and member.mtime == 0
                   and member.name not in values and 0 <= member.size <= 16*1024*1024,
                   'original archive member type/path/metadata differs')
            C.need(len(values) < 8193, 'original archive member count exceeded')
            body = archive.extractfile(member).read(member.size+1)
            C.need(len(body) == member.size, 'original archive member truncated')
            total += len(body); C.need(total <= MAX+16*1024*1024, 'original archive byte bound')
            values[str(rel)] = body
    C.need('CAPTURE.json' in values and C.sha(values['CAPTURE.json']) == capture_sha256,
           'actual original capture pin differs')
    cap = C.strict(values['CAPTURE.json'])
    C.need(cap.get('schema') == 'hepta.native-guard.original-capture.v1'
           and cap.get('state') == 'ORIGINAL_BYTES_CAPTURED_FOR_INDEPENDENT_AUDIT'
           and cap.get('component_qualified') is False and cap.get('business_qualified') is False
           and zero(cap.get('model_requests')) and cap.get('automatic_retry') is False,
           'unqualified original capture envelope differs')
    C.need(set(values) == set(cap['files']) | {'CAPTURE.json'}, 'archive/capture complete file set differs')
    retained = 0
    for name, row in cap['files'].items():
        C.need(set(row) == {'path', 'bytes', 'sha256', 'source_path', 'source_metadata', 'kind'}
               and row['path'] == name and C.descriptor(values[name]) == {k: row[k] for k in ('bytes', 'sha256')},
               'captured original bytes differ')
        retained += len(values[name])
        if row['kind'] == 'original_file_bytes':
            p = Path(row['source_path']); m = row['source_metadata']
            C.need(p.is_absolute() and '..' not in p.parts and isinstance(m, list) and len(m) == 9
                   and all(type(n) is int for n in m) and stat.S_ISREG(m[2]) and m[5] == 1
                   and m[6] == row['bytes'], 'original file source identity absent')
        else:
            C.need(row['kind'] == 'derived_read_observation' and row['source_path'] is None
                   and row['source_metadata'] is None, 'derived observation masquerades as an original file')
    C.need(retained == cap['retained_bytes'], 'capture total byte accounting differs')
    return cap, values


def materialize(root, files):
    root.mkdir(mode=0o700)
    for name, raw in sorted(files.items()):
        p = root/C.relative(name); p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        C.need(p.parent.resolve() == p.parent, 'new snapshot path changed')
        write(p, raw)


def j(files, name):
    C.need(name in files, 'required original absent: '+name)
    return C.strict(files[name])


def load_package(originals, row, files):
    raw = originals.pinned(row); manifest = C.strict(raw)
    C.need(manifest.get('schema') == 'hepta.native-guard.adapter-package.v1'
           and manifest.get('state') == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED', 'reviewed adapter package required')
    root = Path(row['path']).parent; rows = manifest['files']; names = [v['path'] for v in rows]
    C.need(len(names) == len(set(names)) and 5 <= len(names) <= 32, 'adapter package inventory differs')
    for value in rows:
        name = str(C.relative(value['path'])); body = originals.pinned(
            {'path': str(root/name), 'bytes': value['bytes'], 'sha256': value['sha256']})
        C.need(files.get('home/package/'+name) == body, 'actual staged package differs from reviewed source')
    C.need(files.get('home/package/MANIFEST.json') == raw, 'actual staged package manifest differs')
    needed = {'reference/native_journal_audit.py', 'reference/decode_client_state.py',
              'reference/tool_client_r6.py', 'reference/REVIEWED-PRODUCTION-PINS.json',
              'source/component_common.py', 'source/component_listener.py',
              'source/component_lifecycle.py', 'source/component_snapshot.py',
              'source/native_guard_session_r2.py', 'source/late_boundary.py', 'source/close_component.py',
              'source/root_fixture_originals.py', 'source/run_root_fixture_phase.py',
              'source/root_fixture_once.py', 'source/witness_bundle.py'}
    C.need(needed <= set(names), 'closure source package incomplete')
    C.need(originals.read(Path(__file__), 1048576) == files['home/package/source/close_component.py']
           and originals.read(Path(LATE.__file__), 1048576) == files['home/package/source/late_boundary.py']
           and originals.read(Path(FIXTURE.__file__), 1048576) == files['home/package/source/root_fixture_originals.py'],
           'host collector source differs from actually staged reviewed package')
    for name, expected in [('native_journal_audit.py', AUDITOR_SHA),
                           ('decode_client_state.py', DECODER_SHA), ('tool_client_r6.py', C.CLIENT_SHA)]:
        C.need(C.sha(files['home/package/reference/'+name]) == expected, 'frozen independent parser differs')
    return manifest


def module_from_bytes(raw, name, filename):
    module = types.ModuleType(name); module.__file__ = str(filename)
    exec(compile(raw, str(filename), 'exec'), module.__dict__)
    return module


def identity_inputs(cap, files, request):
    lease = j(files, 'home/LEASE.json'); bound = j(files, 'home/BOUND-CONTRACT.json')
    C.need(C.sha(files['home/LEASE.json']) == cap['lease_sha256']
           and lease.get('schema') == 'hepta.native-guard.lease.v1'
           and lease['case_id'] in ('NEG-01', 'NEG-02'), 'actual lease original differs')
    home = C.BASE/'native-guard-r10-r1'/lease['label']
    run = C.COMPONENT_EVIDENCE/cap['run_basename']; scope = C.scope(cap['scope'])
    for key in ('boot_id', 'nonce', 'case_id', 'owner_request_sha256', 'package_sha256'):
        C.need(cap[key] == lease[key], 'capture/lease binding differs: '+key)
    C.need(re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+lease['nonce'], run.name)
           and C.sha(request) == lease['owner_request_sha256'] and request == files['home/owner-request.txt']
           and request == files['run/owner-request.original.txt'] and request.decode().count(lease['nonce']) == 1,
           'exact owner/native run binding differs')
    C.need(cap['files']['home/LEASE.json']['source_path'] == str(home/'LEASE.json')
           and cap['files']['run/provider-in.jsonl']['source_path'] == str(run/'provider-in.jsonl'),
           'original source namespace differs')
    C.need(bound['lease_sha256'] == cap['lease_sha256'] and bound['run_basename'] == run.name
           and bound['provider_source_sha256'] == C.sha(files['home/package/source/component_listener.py']),
           'actual bound component provider differs')
    contract = bound['contract']; contract_raw = C.encoded(contract)
    C.need(contract_raw == files['run/component-contract.original.json']
           and contract['owner_request_sha256'] == C.sha(request)
           and contract['nonce'] == lease['nonce'] and contract['case_id'] == lease['case_id']
           and all(contract['selected_'+k] == scope[k] == lease['selected_'+k]
                   for k in ('session_id', 'profile_id')), 'native component contract identity differs')
    accepted = j(files, 'home/ACCEPTED.json'); local = j(files, 'run/accepted.json')
    C.need(accepted['scope'] == scope and accepted['run_dir'] == str(run)
           and accepted['contract_sha256'] == C.sha(contract_raw)
           and local['identity'] == scope and local['owner_request_sha256'] == C.sha(request)
           and local['contract_sha256'] == C.sha(contract_raw) and local['state'] == 'accepted_never_replay',
           'actual accepted one-use scope differs')
    claim = j(files, 'home/claims/'+lease['nonce']+'.json')
    C.need(claim == {'schema': 'hepta.native-guard-component.claim.v1', 'scope': scope,
        'contract_sha256': C.sha(contract_raw), 'state': 'accepted_never_reuse',
        'run_dir': str(run), 'model_requests': 0}, 'original component claim differs')
    C.need(cap['combination_sha256'] == lease['combination']['sha256']
           == C.sha(files['home/inputs/COMBINATION.json'])
           and cap['retirement_proof_sha256'] == lease['retirement']['proof']['sha256']
           and cap['prior_boundary_sha256'] == (None if lease['prior_boundary'] is None
                                               else lease['prior_boundary']['sha256']),
           'retirement or component combination binding differs')
    return lease, bound, scope, home, run


def native_originals(cap, files, scope, request, auditor):
    raw = files['native/selected.jsonl']; C.need(raw.endswith(b'\n'), 'native JSONL is truncated')
    lines = raw.splitlines(keepends=True); records = [auditor.strict_loads(line) for line in lines]
    audit = auditor.verify_records(records, scope)
    C.need(audit['status'] == 'PASS' and not audit['errors'] and not audit['unsupported']
           and len(records) == audit['record_hashes_verified'] == audit['selected_scope_record_count'],
           'independent native record/hash/turn chain differs')
    frames = audit['frames']; C.need(sum(f['kind'] == 'turn.accepted' for f in frames) == 1
        and sum(f['kind'] == 'turn.end' for f in frames) == 1, 'native accepted/end not unique')
    origins = j(files, 'native/ORIGINS.json')
    C.need(origins['scope'] == scope and len(origins['selected_lines']) == len(lines)
           and origins['global_chain_complete'] is False, 'native original source inventory differs')
    sources = {r['source_path']: r for r in origins['sources']}
    C.need(len(sources) == len(origins['sources']), 'duplicate native source segment')
    for line, record, row in zip(lines, records, origins['selected_lines']):
        C.need(row['source_path'] in sources and {k: row[k] for k in ('bytes', 'sha256')} == C.descriptor(line)
               and row['store_seq'] == record['store_seq'] and row['turn_seq'] == record['turn_seq']
               and type(row['line_1based']) is int and row['line_1based'] > 0
               and type(row['offset']) is int and 0 <= row['offset']
               and row['offset']+len(line) <= sources[row['source_path']]['bytes'],
               'native original line provenance differs')
    incoming_raw = files['run/provider-in.jsonl'].splitlines(keepends=True)
    outgoing_raw = files['run/provider-out.jsonl'].splitlines(keepends=True)
    incoming, outgoing = ([C.strict(row) for row in rows] for rows in (incoming_raw, outgoing_raw))
    for rows in (incoming, outgoing):
        C.need([r['seq'] for r in rows] == list(range(len(rows)))
               and all(r.get('protocol') == 'trillionnium.owner-open.provider-jsonl.v1' for r in rows),
               'actual provider framing/sequence differs')
    C.need(incoming and incoming[0]['kind'] == 'turn.start'
           and {k: incoming[0]['turn'][k] for k in C.SCOPE} == scope
           and incoming[0]['turn']['user_input'].encode() == request
           and incoming_raw[0] == files['run/provider-in-00.jsonl'], 'original native start differs')
    endings = [v for v in outgoing if v['kind'] in ('turn.complete', 'turn.fail', 'turn.cancelled')]
    C.need(len(endings) == 1 and outgoing[-1] == endings[0], 'unique original provider terminal absent')
    status = {'turn.complete': 'completed', 'turn.fail': 'provider_failed', 'turn.cancelled': 'cancelled'}[endings[0]['kind']]
    C.need(frames[-1]['payload']['status'] == status, 'native/provider terminal class differs')
    terminal = j(files, 'run/terminal.json')
    C.need(terminal['kind'] == endings[0]['kind'] and terminal['scope'] == scope
           and terminal.get('native_terminal_independently_verified') is False
           and zero(terminal['model_requests']) and terminal['business_qualified'] is False,
           'saved provider terminal differs')
    calls = [v['call'] for v in outgoing if v['kind'] == 'tool.call']
    results = [v for v in incoming if v['kind'] == 'tool.result']
    C.need(len(calls) <= 2 and len(calls) == len(results)
           and len({v['call_id'] for v in calls}) == len(calls)
           and [v['call_id'] for v in calls] == [v['call_id'] for v in results],
           'actual native call/result count differs or an effect is unknown')
    C.need(len(outgoing) == len(calls)+1
           and all(v['kind'] in ('turn.start', 'tool.result', 'turn.cancel') for v in incoming)
           and sum(v['kind'] == 'turn.cancel' for v in incoming) <= 1,
           'unreviewed actual provider frame or extra operation')
    ids = {v['call_id'] for v in calls}
    C.need(all(not f.get('call_id') or f['call_id'] in ids for f in frames), 'foreign native effect present')
    for index, (value, body) in enumerate(zip(outgoing, outgoing_raw)):
        intent = j(files, 'run/actual-wire-%02d.intent.json'%index)
        sent = j(files, 'run/actual-wire-%02d.sent.json'%index)
        C.need(intent['frame'] == value and intent['frame_sha256'] == C.sha(body)
               and intent['automatic_retry'] is False and sent['frame_sha256'] == C.sha(body)
               and sent['sendall_returned'] is True and sent['is_execution_confirmation'] is False,
               'actual native wire send outcome is unknown')
    return {'audit': audit, 'frames': frames, 'records': records, 'lines': lines,
        'native_digest': records[0]['payload']['request_sha256'], 'status': status,
        'incoming': incoming, 'incoming_raw': incoming_raw, 'outgoing': outgoing,
        'outgoing_raw': outgoing_raw, 'calls': calls, 'results': results}


def native_stream_join(frames, call, result, streams):
    selected = [f for f in frames if f.get('call_id') == call['call_id']]
    for kind in ('tool.accepted', 'tool.started', 'tool.result'):
        C.need(sum(f['kind'] == kind for f in selected) == 1, 'native tool lifecycle lacks '+kind)
    terminal = next(f['payload'] for f in selected if f['kind'] == 'tool.result')
    for key in ('exit_code', 'error', 'output_truncated', 'stdout_bytes', 'stderr_bytes'):
        C.need(terminal.get(key) == result['terminal'].get(key), 'native/provider terminal differs')
    for name in ('stdout', 'stderr'):
        raw = b''.join(base64.b64decode(f['payload']['data'], validate=True)
                       for f in selected if f['kind'] == 'tool.'+name)
        C.need(raw == streams[name], 'native/provider original stream bytes differ')


def bound_r6(files, phase, call, streams, native_code, server_instance, sidecar_pid, recovery):
    """Known r6 terminal, including the fixed client's distinct failure trailer."""
    action = call['argv'][4]; command = base64.b64decode(call['argv'][6], validate=True)
    origin = j(files, 'run/'+phase+'-originals/ORIGINS.json')
    names = {'intent': 'intent.json', 'receipt': 'receipt.json', 'stdout': 'stdout.bin', 'stderr': 'stderr.bin'}
    bundle = {}
    for key, filename in names.items():
        raw = files['executor/actions/'+action+'/'+filename]
        C.need(raw == files['run/'+phase+'-originals/'+key+'.original'], 'sidecar original capture differs')
        bundle[key] = raw
    for key, suffix in [('client_claim', '.claim.json'), ('client_result', '.result.json')]:
        raw = files['client/'+action+suffix]
        C.need(raw == files['run/'+phase+'-originals/'+key+'.original'], 'client original capture differs')
        bundle[key] = raw
    bundle['client_inspection'] = files['run/'+phase+'-originals/client-inspection.observation.json']
    intent, receipt, claim, saved, inspected = (C.strict(bundle[k]) for k in
        ('intent', 'receipt', 'client_claim', 'client_result', 'client_inspection'))
    recovery.require_r6_terminal(receipt)
    for value in (intent, receipt):
        C.need(value.get('version') == 1 and value.get('executor_revision') == 6
               and value.get('action_id') == action and value.get('command_sha256') == C.sha(command)
               and value.get('server_instance') == server_instance and value.get('executor_context') == C.PARENT_DOMAIN
               and value.get('peer_context') == 'u:r:trillionnium_owner_open_bootstrap:s0'
               and value.get('peer_uid') == 0 and value.get('timeout_ms') == 60000
               and value.get('can_redispatch') is False, 'original r6 identity/admission differs')
    C.need(type(intent.get('created_unix_ms')) is int and intent['created_unix_ms'] > 0
           and intent['created_unix_ms'] == receipt.get('created_unix_ms')
           and receipt.get('intent_parent_sync_complete') is True, 'original intent durability differs')
    C.need(claim.get('version') == 1 and claim.get('client_revision') == 6
           and claim.get('client_source_sha256') == C.CLIENT_SHA and claim.get('endpoint') == C.SOCKET_NAME
           and claim.get('state') == 'intent' and claim.get('action_id') == action
           and claim.get('command_sha256') == C.sha(command) and claim.get('timeout_ms') == 60000,
           'original r6 client claim differs')
    C.need(set(saved) == {'version', 'protocol', 'duplicate', 'receipt', 'client_transport'}
           and saved['version'] == 1 and saved['protocol'] == 'hepta_phone_local_v150'
           and saved['duplicate'] is False and saved['receipt'] == receipt, 'stored r6 result differs')
    C.need(set(inspected) == {'version', 'protocol', 'duplicate', 'receipt', 'stdout_b64', 'stderr_b64'}
           and inspected['version'] == 1 and inspected['protocol'] == 'hepta_phone_local_v150'
           and inspected['duplicate'] is False and inspected['receipt'] == receipt,
           'actual independent readonly r6 inspection differs')
    for name in ('stdout', 'stderr'):
        raw = bundle[name]
        C.need(len(raw) == receipt.get(name+'_bytes') and C.sha(raw) == receipt.get(name+'_sha256')
               and base64.b64decode(inspected[name+'_b64'], validate=True) == raw,
               'r6 original stream/inspection differs')
    # This exact mapping and trailer are fixed by the retained 500e client.
    if receipt['state'] == 'completed' and type(receipt.get('exit_code')) is int and 0 <= receipt['exit_code'] <= 255:
        expected_code = receipt['exit_code']; expected_stderr = bundle['stderr']
    else:
        expected_code = {'timed_out': 72, 'cancelled': 73, 'output_limit_exceeded': 74}.get(receipt['state'], 75)
        error = {'client_error': 'effect_terminal_failure', 'action_id': action, 'receipt': receipt}
        expected_stderr = bundle['stderr'] + b'\nHEPTA_PHONE_LOCAL ' + json.dumps(
            error, ensure_ascii=False, separators=(',', ':')).encode() + b'\n'
    C.need(native_code == expected_code and streams['stdout'] == bundle['stdout']
           and streams['stderr'] == expected_stderr, 'native output is not the original fixed client terminal')
    trace = saved['client_transport']; previous = None; rows = trace['events']
    C.need(trace.get('schema') == 'hepta.client-transport-trace.v150.r6'
           and trace.get('directory') == str(C.BASE/'client-receipts'/(action+'.transport-r6'))
           and trace.get('automatic_replay') is False and 1 <= len(rows) <= 32,
           'original client transport binding differs')
    for index, row in enumerate(rows):
        C.need(re.fullmatch(r'%02d-[a-z_]+\.json'%index, row['name']), 'transport event order differs')
        raw = files['client/'+action+'.transport-r6/'+row['name']]
        C.need(C.descriptor(raw) == {k: row[k] for k in ('bytes', 'sha256')}
               and raw == files['run/'+phase+'-originals/transport-'+row['name']], 'client transport original differs')
        value = C.strict(raw)
        C.need(value.get('sequence') == index and value.get('previous_event_sha256') == previous
               and value.get('action_id') == action and value.get('command_sha256') == C.sha(command)
               and value.get('client_source_sha256') == C.CLIENT_SHA and value.get('endpoint') == C.SOCKET_NAME
               and value.get('automatic_replay') is False, 'client transport chain is not complete')
        previous = C.sha(raw)
    C.need(trace['last_event_sha256'] == previous and trace['transport'] == value['transport']
           and trace['transport']['operation'] == 'execute'
           and trace['transport']['request_frame_complete'] is True
           and trace['transport']['response_frame_complete'] is True, 'original transport completion is unknown')
    transport = trace['transport']
    payload = {'version': 1, 'op': 'execute', 'action_id': action,
               'command_sha256': C.sha(command), 'command': command.decode(), 'timeout_ms': 60000}
    payload_raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    frame = struct.pack('>I', len(payload_raw)) + payload_raw
    C.need(transport.get('phase') == 'transport_complete'
           and all(transport.get(k) is True for k in ('connected', 'peer_identity_verified', 'send_attempted',
                                                       'request_may_have_reached_executor'))
           and transport.get('peer_pid') == sidecar_pid and type(sidecar_pid) is int and sidecar_pid > 1
           and zero(transport.get('peer_uid')) and zero(transport.get('peer_gid'))
           and transport.get('peer_context') == C.PARENT_DOMAIN
           and transport.get('payload_sha256') == C.sha(payload_raw)
           and transport.get('request_frame_sha256') == C.sha(frame)
           and transport.get('request_frame_bytes') == transport.get('confirmed_send_bytes') == len(frame)
           and type(transport.get('response_body_bytes')) is int and 0 < transport['response_body_bytes'] <= 12*1024*1024
           and transport.get('confirmed_receive_bytes') == transport['response_body_bytes'] + 4
           and isinstance(transport.get('response_body_sha256'), str)
           and C.HASH.fullmatch(transport['response_body_sha256']),
           'original client transport peer or complete request/response accounting differs')
    C.need({p.split('/')[-1] for p in files if p.startswith('client/'+action+'.transport-r6/')}
           == {r['name'] for r in rows}, 'client transport directory has unaccounted originals')
    C.need(origin['schema'] == 'hepta.native-guard.r6-original-origins.v1'
           and origin['action_id'] == action and origin['actual_command_sha256'] == C.sha(command)
           and origin['inspection_origin'] == 'actual decoded readonly client.inspect(include_output=true) response'
           and origin['inspection_sha256'] == C.sha(bundle['client_inspection'])
           and origin['pending_receipt_observed_absent'] is True and zero(origin['execute_requests_by_adapter']),
           'r6 original provenance envelope differs')
    C.need({p.split('/')[-1] for p in files if p.startswith('executor/actions/'+action+'/')}
           == {'intent.json', 'receipt.json', 'stdout.bin', 'stderr.bin'}, 'pending/extra r6 action original exists')
    return receipt, bundle


def capture_provenance(cap, files, lease, home, run, inventory):
    journal = C.ANDROID/lease['android_journal'].lstrip('/')
    fixture = C.ANDROID/'data/local/tmp'/('hepta-native-guard-'+lease['nonce'])
    prefixes = {'home': home, 'run': run, 'executor': journal,
                'ledger': C.PRODUCTION_EVIDENCE/'action-ledger',
                'client': C.BASE/'client-receipts', 'fixture': fixture}
    sources = {}
    for name, row in cap['files'].items():
        if row['kind'] != 'original_file_bytes':
            C.need(name in {'after/AFTER-INVENTORY.json', 'observation/AFTER-ROLES.json',
                   'observation/proc-net-tcp.original', 'observation/proc-net-tcp6.original',
                   'observation/proc-net-unix.original', 'observation/FIXTURE-ABSENCE.json',
                   'native/selected.jsonl', 'native/ORIGINS.json',
                   'observation/NON-NATIVE-SIDEBRANCH.json'},
                   'unexpected derived observation in original snapshot')
            continue
        parts = Path(name).parts
        if parts[0] in prefixes:
            C.need(row['source_path'] == str(prefixes[parts[0]].joinpath(*parts[1:])),
                   'captured file original source path differs')
        elif parts[0] == 'prior-fixture':
            C.need(len(parts) >= 3 and re.fullmatch('[0-9a-f]{32}', parts[1])
                   and row['source_path'] == str(C.ANDROID/'data/local/tmp'/
                        ('hepta-native-guard-'+parts[1])/Path(*parts[2:])), 'prior fixture source path differs')
        elif parts[0] == 'non-native-sidebranch':
            binding = cap.get('non_native_sidebranch')
            C.need(isinstance(binding, dict) and len(parts) == 3
                   and parts[1] == binding.get('nonce'), 'non-native snapshot namespace differs')
            keys = [k for k,v in LATE.NON_NATIVE_CAPTURE_FILES.items() if v == parts[2]]
            C.need(len(keys) == 1 and row['source_path'] == binding[keys[0]]['path']
                   and row['source_metadata'] == binding[keys[0]]['metadata'],
                   'non-native original source path or identity differs')
        else:
            C.need(parts[0] in ('retirement', 'boundary-chain'), 'unreviewed original snapshot namespace')
        summary = {'metadata': row['source_metadata'], 'bytes': row['bytes'], 'sha256': row['sha256']}
        if row['source_path'] in sources:
            C.need(sources[row['source_path']] == summary, 'same source has inconsistent original copies')
        sources[row['source_path']] = summary
        existing = inventory['entries'].get(row['source_path'])
        if existing is not None:
            C.need(existing == {'kind': 'file', **summary}, 'captured source differs from final full inventory')
    directories = cap['directories']
    for source, row in directories.items():
        C.need(set(row) == {'metadata', 'names', 'capture_path'}
               and row['names'] == sorted(set(row['names'])), 'original directory inventory differs')
        if row['capture_path'] is None:
            C.need(source == '/var/lib/trillionnium/owner-open/turn-events.jsonl.segments',
                   'unknown uncopied original directory')
            continue
        names = {Path(p).name for p in sources if Path(p).parent == Path(source)}
        names.update(Path(p).name for p in directories if Path(p).parent == Path(source))
        C.need(sorted(names) == row['names'], 'captured tree omitted an original directory member')
        if source in inventory['entries']:
            C.need(inventory['entries'][source] == {'kind': 'directory', 'metadata': row['metadata'],
                                                  'names': row['names']}, 'directory changed across capture/inventory')
    for phase in ('capture', 'guard'):
        name = 'run/'+phase+'-originals/ORIGINS.json'
        if name not in files:
            continue
        origin = j(files, name); action = origin['action_id']
        actual_names = {key: 'executor/actions/'+action+'/'+filename for key, filename in
            (('intent','intent.json'), ('receipt','receipt.json'), ('stdout','stdout.bin'), ('stderr','stderr.bin'))}
        actual_names.update(client_claim='client/'+action+'.claim.json', client_result='client/'+action+'.result.json')
        C.need(set(origin['files']) == set(actual_names), 'r6 source file provenance set differs')
        for key, logical in actual_names.items():
            captured = cap['files'][logical]
            C.need(origin['files'][key] == {'source_path': captured['source_path'],
                'metadata': captured['source_metadata'], 'bytes': captured['bytes'], 'sha256': captured['sha256']},
                'r6 source file identity differs from independent final capture')
        expected_transport = [{'source_path': cap['files'][logical]['source_path'],
            'bytes': cap['files'][logical]['bytes'], 'sha256': cap['files'][logical]['sha256']}
            for logical in sorted(cap['files']) if logical.startswith('client/'+action+'.transport-r6/')]
        C.need(origin['transport_events'] == expected_transport,
               'r6 source transport originals differ from independent final capture')
    return sources


def verify_roles(files, lease, bound):
    ended = j(files, 'home/LIFECYCLE-ENDED.json'); after = j(files, 'observation/AFTER-ROLES.json')
    C.need(ended.get('schema') == 'hepta.native-guard.lifecycle-ended.v1'
           and ended.get('roles_joined_and_groups_absent') is True
           and ended.get('automatic_restart') is False and zero(ended.get('model_requests')),
           'original owned component roles have not joined')
    supervisor = j(files, 'home/SUPERVISOR.json'); roles = {'supervisor': supervisor['identity']}
    C.need(supervisor['domain'] == C.MAGISK and supervisor['uid'] == supervisor['gid'] == [0]*4
           and supervisor['nnp'] == 0 and supervisor['ppid'] == 1,
           'original supervisor credentials/init parent differ')
    home = C.BASE/'native-guard-r10-r1'/lease['label']; lease_sha = C.sha(files['home/LEASE.json'])
    python = j(files, 'home/inputs/COMBINATION.json')['artifacts']['python']['path']
    C.need(python == '/usr/bin/python3' and supervisor['exe'] == python,
           'original supervisor is not the actual reviewed GNU interpreter')
    expected = [python,'-I','-B',str(home/'package/source/component_lifecycle.py'),
        '--lease',str(home),'--lease-sha256',lease_sha,'--package',str(home/'package/MANIFEST.json'),
        '--package-sha256',lease['package_sha256'],'--execute-component-lifecycle-once']
    launch = j(files, 'home/DETACHED-LAUNCH-INTENT.json')
    launched = j(files, 'home/DETACHED-LAUNCH-RESULT.json')
    launcher = launch['launcher_identity']
    C.need(launch['schema'] == 'hepta.native-guard.detached-launch-intent.v1'
           and launch['lease_sha256'] == lease_sha and launch['supervisor_argv'] == expected
           and launch['retirement_sha256'] == lease['retirement']['proof']['sha256']
           and launch['maximum_forks'] == launch['maximum_execs'] == 1
           and launch['supervisor_parent_required_before_admission'] == 1
           and launch['automatic_retry'] is False and launch['readiness_asserted'] is False
           and zero(launch['model_requests']) and zero(launch['native_task_submissions'])
           and launcher['domain'] == C.MAGISK and launcher['uid'] == launcher['gid'] == [0]*4
           and launcher['nnp'] == 0 and launcher['exe'] == python,
           'original one-fork detached supervisor launch differs')
    C.need(launched['schema'] == 'hepta.native-guard.detached-launch-observation.v1'
           and launched['state'] == 'ONE_FORK_RETURNED_SUPERVISOR_NOT_YET_ADMITTED'
           and launched['lease_sha256'] == lease_sha and launched['fork_returned_pid'] == roles['supervisor'][0]
           and launched['launcher_identity'] == launcher['identity']
           and launched['readiness_asserted'] is False and launched['child_generation_not_inferred'] is True
           and launched['automatic_retry'] is False and zero(launched['model_requests'])
           and zero(launched['native_task_submissions'])
           and base64.b64decode(supervisor['argv_b64'],validate=True) == b'\0'.join(x.encode() for x in expected)+b'\0',
           'actual supervisor generation/argv is not the original detached child')
    for role in ('provider', 'sidecar'):
        spawned = j(files, 'home/'+role+'.SPAWNED.json'); joined = j(files, 'home/'+role+'.JOINED.json')
        roles[role] = spawned['identity']
        barrier = j(files, 'home/'+role+'.barrier.json'); admit = j(files, 'home/'+role+'.ADMIT.json')
        C.need(spawned['pid'] == roles[role][0] and spawned['automatic_retry'] is False
               and barrier == {'identity':roles[role],'parent_identity':roles['supervisor'],
                               'domain':C.MAGISK,'application_not_executed':True}
               and admit == {'identity':roles[role],'parent_identity':roles['supervisor'],
                             'lease_sha256':lease_sha,'role':role},
               'original role barrier/admission parent generation differs')
        spawn_intent = j(files,'home/'+role+'.SPAWN-INTENT.json')
        C.need(spawn_intent == {'role':role,'lease_sha256':lease_sha,'new_owned_session':True,
                               'no_model_role':True,'automatic_restart':False},
               'original role launch intent differs')
        C.need(joined == ended['roles'][role] and joined['identity'] == roles[role]
               and joined['role'] == role and joined['child_wait_returned'] is True
               and joined['dedicated_process_group_absent'] is True
               and type(joined['child_exit_code']) is int and joined.get('automatic_retry') is False,
               'original component join identity or disposition differs')
        C.need(joined['signals'] in ([],['SIGTERM_SYSCALL_RETURNED'],['ESRCH_AFTER_ONE_SIGNAL_ATTEMPT']),
               'original owned role has an unreviewed termination path')
        if joined['signals']:
            C.need(j(files,'home/'+role+'.TERM-INTENT.json') == {'target_identity':roles[role],
                'signal':'SIGTERM','via':'pidfd','maximum_signal_attempts':1,'automatic_retry':False},
                'original single pidfd termination intent differs')
        else:
            C.need('home/'+role+'.TERM-INTENT.json' not in files,
                   'signal intent without a known original signal outcome')
    C.need(bound['sidecar_identity']['identity'] == roles['sidecar']
           and bound['sidecar_identity']['domain'] == C.PARENT_DOMAIN
           and bound['sidecar_identity']['exe'] == C.SIDECAR
           and bound['sidecar_identity']['uid'] == bound['sidecar_identity']['gid'] == [0]*4
           and bound['sidecar_identity']['nnp'] == 0 and bound['sidecar_identity']['ppid'] == roles['supervisor'][0]
           and base64.b64decode(bound['sidecar_identity']['argv_b64'],validate=True) == b'\0'.join(
               x.encode() for x in [C.SIDECAR,'--state-dir',lease['android_journal']])+b'\0',
           'bound sidecar actual generation/parent/argv differs')
    ready = j(files,'home/READY.json'); provider = ready['identity']
    C.need(provider['identity'] == roles['provider'] and provider['ppid'] == roles['supervisor'][0]
           and provider['domain'] == C.MAGISK and provider['exe'] == python
           and provider['uid'] == provider['gid'] == [0]*4 and provider['nnp'] == 0
           and ready['schema'] == 'hepta.native-guard.ready.v1' and ready['lease_sha256'] == lease_sha
           and ready['contract_sha256'] == C.sha(C.encoded(bound['contract']))
           and ready['combination_sha256'] == lease['combination']['sha256']
           and ready['provider_source_sha256'] == bound['provider_source_sha256']
           and ready['port'] == 18080 and ready['accepting_one_session'] is True
           and ready['readiness_scope'] == 'isolated_component_transport_only'
           and ready['four_role_ready'] is False and zero(ready['model_requests']),
           'original provider readiness generation/parent/source differs')
    health = j(files,'home/SIDECAR-HEALTH.original.json')
    C.need(health == bound['sidecar_health'] == j(files,'home/PROVIDER-HEALTH.original.json')
           and health['state'] == 'ready' and health['executor_revision'] == 6
           and health['server_instance'] == bound['contract']['executor_server_instance']
           and health['executor_context'] == C.PARENT_DOMAIN and health['peer_context'] == C.MAGISK
           and health['execute_authorized'] is False and health['inference_endpoint'] is False,
           'component sidecar actual readonly health binding differs')
    C.need(after['schema'] == 'hepta.native-guard.after-role-observation.v1'
           and after['roles'] == roles and after['original_lifecycle_ended_sha256'] == C.sha(files['home/LIFECYCLE-ENDED.json'])
           and after['port_18080_listener_absent'] is True and after['r6_abstract_endpoint_absent'] is True,
           'independent final role/endpoint observation differs')
    for observations in [after['absence_observations']] + [ended['roles'][r]['absence'] for r in ('provider','sidecar')]:
        C.need(len(observations) == 2 and all(v.get('members') == [] and v.get('kernel_group_absence') is True
                   and type(v.get('numeric_pids')) is int and v['numeric_pids'] > 0
                   and type(v.get('observed_monotonic_ns')) is int for v in observations)
               and observations[0]['observed_monotonic_ns'] <= observations[1]['observed_monotonic_ns'],
               'original double census or kernel absence is incomplete')
    for name in ('tcp', 'tcp6'):
        rows = files['observation/proc-net-'+name+'.original'].splitlines()
        C.need(rows, 'original TCP table missing')
        for line in rows[1:]:
            cols = line.split(); C.need(len(cols) >= 10, 'truncated original TCP row')
            C.need(not (int(cols[1].rsplit(b':',1)[1],16) == 18080 and cols[3] == b'0A'),
                   'component listener still present in original table')
    rows = files['observation/proc-net-unix.original'].splitlines()
    C.need(rows, 'original UNIX table missing')
    for line in rows[1:]:
        cols = line.split(); C.need(len(cols) >= 7, 'truncated original UNIX row')
        C.need(len(cols) == 7 or cols[7] != ('@'+C.SOCKET_NAME).encode(), 'r6 endpoint still present')
    C.need(all(v[:3] == [v[0]]*3 and len(v) == 4 for v in roles.values())
           and len({v[0] for v in roles.values()}) == 3, 'component roles are not three unique owned sessions')
    return roles


def verify_retirement_copy(files, lease):
    for name, row in lease['retirement'].items():
        raw = files['retirement/'+name+'.original']
        C.need(C.descriptor(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'old retirement original changed')
    proof = j(files, 'retirement/proof.original'); before = j(files, 'retirement/preflight.original')
    bound = j(files, 'retirement/bound_inputs.original')
    C.need(proof.get('schema') == 'hepta.r9-r2-retirement-observation.v1'
           and proof.get('state') == 'ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED'
           and proof.get('boot_id') == lease['boot_id'] and proof.get('global_pending_clear') is True
           and proof.get('old_claims_deleted') is False and proof.get('old_task_terminal_rewritten') is False
           and proof.get('automatic_restart') is False and proof.get('automatic_replay') is False
           and before.get('groups') == proof.get('original_role_identities')
           and before.get('preserved_state') == proof.get('preserved_state')
           and bound.get('complete_current_accepted_case_union_verified') is True
           and files['retirement/disabled_flag.original'] == b'', 'original full retirement is not retained')
    retired = j(files, 'home/RETIRED-BASELINE-VERIFIED.json')
    C.need(retired['retirement_sha256'] == lease['retirement']['proof']['sha256']
           and retired['old_journal_lock_held_without_writing'] is True
           and retired['equality_is_not_claimed_after_component_actions'] is True,
           'component baseline did not retain original retirement boundary')
    C.need(retired['old_preserved_state_equal_before_new_actions'] is (lease['prior_boundary'] is None),
           'a late component wrongly claims old retirement equality')


def verify_prior_chain(cap, files, lease, inventory):
    current = lease['prior_boundary']; count = 0; seen = set(); seen_scope = set(); first = None; values = []
    while current is not None:
        C.need(count < 8, 'prior original boundary chain exceeds bound')
        nonce = Path(current['path']).stem; prefix = 'boundary-chain/'+nonce+'/'
        raw = files[prefix+'BOUNDARY.original.json']
        C.need(C.descriptor(raw) == {k: current[k] for k in ('bytes','sha256')}
               and cap['files'][prefix+'BOUNDARY.original.json']['source_metadata'] == current['metadata'],
               'prior boundary raw source identity differs')
        boundary = LATE.boundary_from_original(raw, original_descriptor=current,
            combination_sha256=cap['combination_sha256'], package_sha256=cap['package_sha256'])
        key = tuple(boundary['scope'][k] for k in C.SCOPE)
        C.need(nonce == boundary['nonce'] and nonce not in seen and key not in seen_scope
               and boundary['retirement'] == lease['retirement'] and boundary['boot_id'] == lease['boot_id'],
               'prior closed component/retirement differs')
        seen.add(nonce); seen_scope.add(key); count += 1
        for key, filename in [('inventory','INVENTORY.original.json'),('closure','CLOSURE.original.json')]:
            row = boundary[key]; data = files[prefix+filename]
            C.need(C.descriptor(data) == {k:row[k] for k in ('bytes','sha256')}
                   and cap['files'][prefix+filename]['source_path'] == row['path']
                   and cap['files'][prefix+filename]['source_metadata'] == row['metadata'],
                   'prior closed original source changed')
        boundary, old, _closed = LATE.closed_boundary_originals(raw,
            files[prefix+'INVENTORY.original.json'], files[prefix+'CLOSURE.original.json'],
            original_descriptor=current, combination_sha256=cap['combination_sha256'],
            package_sha256=cap['package_sha256'])
        C.need(set(old['roots']) <= set(inventory['roots']), 'final inventory omitted prior closed private roots')
        if first is None:
            first = old
        values.append(boundary); current = boundary['prior_boundary']
    LATE.require_failed_ancestor_tail(values)
    return first, count


def preserve_inventory(before, after, *, allowed_new, mutable_roots=()):
    LATE.inventory_value(before); LATE.inventory_value(after)
    entries = after['entries']; added = []
    for name, old in before['entries'].items():
        C.need(name in entries, 'previous original disappeared from complete late inventory')
        new = entries[name]
        if old['kind'] == 'file':
            C.need(new == old, 'previous original file bytes or identity changed')
        elif old['kind'] == 'directory':
            C.need(new['kind'] == 'directory' and new['metadata'][:5] == old['metadata'][:5]
                   and set(old['names']) <= set(new['names']), 'previous directory identity/member disappeared')
            if old['names'] == new['names']:
                C.need(new == old, 'unchanged original directory metadata changed')
            for leaf in set(new['names'])-set(old['names']):
                C.need(allowed_new(str(Path(name)/leaf)), 'unaccounted new original directory member')
        else:
            C.need(new == old, 'previous explicit absence changed')
    old_roots = [Path(p) for p in before['roots']]
    for name in entries:
        p = Path(name)
        if name not in before['entries'] and any(p == q or q in p.parents for q in old_roots):
            C.need(allowed_new(name), 'unaccounted late file/root addition')
            added.append(name)
    return added


def verify_non_native_sidebranch(cap, files, inventory):
    """Pure host audit of copied sideproof bytes and actual ended-role observations."""
    sidebranch = LATE.non_native_sidebranch()
    binding = sidebranch['binding']
    C.need(cap.get('non_native_sidebranch') == binding,
           'capture omitted or changed the fixed non-native sidebranch')
    prefix = 'non-native-sidebranch/'+binding['nonce']+'/'
    expected = {prefix+name for name in LATE.NON_NATIVE_CAPTURE_FILES.values()}
    C.need({name for name in files if name.startswith('non-native-sidebranch/')} == expected,
           'non-native original capture member set differs')
    for key, filename in LATE.NON_NATIVE_CAPTURE_FILES.items():
        name = prefix+filename; row = cap['files'][name]; original = binding[key]
        C.need(files[name] == sidebranch['raw'][key]
               and row['kind'] == 'original_file_bytes'
               and row['source_path'] == original['path']
               and row['source_metadata'] == original['metadata']
               and {k:row[k] for k in ('bytes','sha256')} ==
                   {k:original[k] for k in ('bytes','sha256')},
               'non-native copied original does not match reviewed full identity')
    observed = j(files, 'observation/NON-NATIVE-SIDEBRANCH.json')
    C.need(set(observed) == {'schema','binding','absence_observations','phone_tool_calls',
            'model_requests','native_submissions','native_scope_assigned',
            'native_case_count','component_qualified'}
           and observed['schema'] == 'hepta.native-guard.non-native-sidebranch-observation.v1'
           and observed['binding'] == binding
           and all(zero(observed[k]) for k in
                   ('phone_tool_calls','model_requests','native_submissions','native_case_count'))
           and observed['native_scope_assigned'] is False and observed['component_qualified'] is False,
           'non-native original observation overstates scope or qualification')
    observations = observed['absence_observations']
    C.need(isinstance(observations, list) and len(observations) == 2
           and all(v.get('members') == [] and v.get('kernel_group_absence') is True
                   and type(v.get('numeric_pids')) is int and v['numeric_pids'] > 0
                   and type(v.get('observed_monotonic_ns')) is int
                   and v['observed_monotonic_ns'] > 0 for v in observations)
           and observations[0]['observed_monotonic_ns'] <= observations[1]['observed_monotonic_ns'],
           'non-native three-role double absence is not complete')
    LATE.preserve_non_native_private(inventory, sidebranch)
    return sidebranch


def verify_ledger_inventory(cap, files, lease, home, run, inventory, native, modules):
    actions = [call['argv'][4] for call in native['calls']]
    dispatches = {phase: j(files, 'run/'+phase+'.dispatch-intent.json') for phase in ('capture','guard')
                  if 'run/'+phase+'.dispatch-intent.json' in files}
    C.need(cap['action_ids'] == [dispatches[p]['action_id'] for p in ('capture','guard') if p in dispatches],
           'capture reservation list differs from actual original intents')
    guard = dispatches.get('guard'); guard_id = None if guard is None else guard['action_id']
    base = str(C.PRODUCTION_EVIDENCE/'action-ledger'); client = str(C.BASE/'client-receipts')
    journal = str(C.ANDROID/lease['android_journal'].lstrip('/'))
    ledger_new = set()
    if guard_id is not None:
        ledger_new = {base+'/'+guard_id+'.'+suffix for suffix in ('intent.json','resolution.json','inspection.json')}
    def allowed(name):
        if name in ledger_new or name == str(run) or name.startswith(str(run)+'/'):
            return True
        if name == journal or name.startswith(journal+'/'):
            return True
        if (name == str(home/'claims') or name.startswith(str(home/'claims')+'/')
                or name == str(home/'operator') or name.startswith(str(home/'operator')+'/')):
            return True
        return any(name == client+'/'+action+suffix or name.startswith(client+'/'+action+suffix+'/')
                   for action in actions for suffix in ('.claim.json','.result.json','.transport-r6'))
    baseline = j(files, 'home/BASELINE-INVENTORY.json')
    common_roots = [str(p) for p in (C.PRODUCTION_EVIDENCE, C.COMPONENT_EVIDENCE,
        C.BASE/'client-receipts', C.BASE/'executor-r6', C.BASE/'provider-state/health-contracts/bindings',
        C.BASE/'provider-state/task-contracts/bindings', Path(journal))]
    expected_before = common_roots+[str(home/n) for n in ('inputs','package','claims','operator')]
    C.need(baseline['roots'] == expected_before, 'baseline omitted an entire required original root')
    added = preserve_inventory(baseline, inventory, allowed_new=allowed)
    prior, count = verify_prior_chain(cap, files, lease, inventory)
    sidebranch = LATE.non_native_sidebranch()
    current = lease['prior_boundary']
    C.need(current is not None and prior is not None, 'native predecessor is required for the fixed sidebranch')
    head_raw = files['boundary-chain/'+Path(current['path']).stem+'/BOUNDARY.original.json']
    head = LATE.boundary_from_original(head_raw, original_descriptor=current,
        combination_sha256=cap['combination_sha256'], package_sha256=cap['package_sha256'])
    prior = LATE.effective_prior_inventory(head, prior, sidebranch)
    admitted = j(files, 'home/RETIRED-BASELINE-VERIFIED.json')['explicit_late_boundary_verification']
    initial = LATE.is_pre_policy_ancestor(head)
    expected_inventory = sidebranch['binding']['inventory'] if initial else head['inventory']
    C.need(admitted.get('non_native_sidebranch') == sidebranch['binding']
           and admitted.get('previous_boundary') == current and admitted.get('closed_components') == count
           and admitted.get('inventory_selection') ==
               ('fixed_non_native_attempt05_after' if initial else 'current_native_head')
           and admitted.get('inventory_sha256') == expected_inventory['sha256']
           and admitted.get('roots') == prior['roots']
           and admitted.get('entries') == len(prior['entries'])
           and admitted.get('file_bytes_hashed') == prior['file_bytes_hashed'],
           'actual lifecycle did not admit the correct separate non-native preservation baseline')
    fixture = str(C.ANDROID/'data/local/tmp'/('hepta-native-guard-'+lease['nonce']))
    expected_after = list(dict.fromkeys(([] if prior is None else prior['roots'])+common_roots+[str(home),fixture]))
    C.need(inventory['roots'] == expected_after, 'late inventory omitted or added an unreviewed complete root')
    absent = {p for p,v in inventory['entries'].items() if v['kind']=='absent'}
    if absent:
        observation = j(files,'observation/FIXTURE-ABSENCE.json')
        C.need(observation['schema']=='hepta.native-guard.fixture-absence-set.v1'
               and observation['scope']==cap['scope'] and observation['absence_does_not_qualify_component'] is True
               and {v['path'] for v in observation['observations']}==absent
               and len(observation['observations'])==len(absent), 'original exact fixture absence set differs')
        for row in observation['observations']:
            C.need(row['schema']=='hepta.native-guard.fixture-absence.v1' and row['absence']=='ENOENT'
                   and type(row['observed_monotonic_ns']) is int and row['observed_monotonic_ns']>0
                   and len(row['canonical_parent_identity'])==5 and zero(row['ui_actions']),
                   'original canonical-parent fixture ENOENT observation incomplete')
    else:
        C.need('observation/FIXTURE-ABSENCE.json' not in files, 'unexpected fixture absence claim')
    if prior is not None:
        # The current component's private new roots were absent from the prior
        # boundary. Within all prior roots, permit only this exact global delta.
        preserve_inventory(prior, inventory, allowed_new=lambda n: n in ledger_new
            or n == str(run) or n.startswith(str(run)+'/')
            or any(n == client+'/'+a+s or n.startswith(client+'/'+a+s+'/')
                   for a in actions for s in ('.claim.json','.result.json','.transport-r6')))
    actual_action_dirs = {Path(name).parts[2] for name in files
                          if name.startswith('executor/actions/') and len(Path(name).parts) >= 4}
    C.need(actual_action_dirs == set(actions), 'new sidecar action set differs from actual native calls')
    if guard_id is not None:
        name = 'ledger/'+guard_id+'.intent.json'
        if name in files:
            intent = j(files, name); resolution = j(files, 'ledger/'+guard_id+'.resolution.json')
            semantic = j(files, 'run/semantic-'+C.sha(guard['actual_native_call']['call_id'].encode())+'.json')
            C.need(intent['schema'] == 'hepta.action-intent.v150.2' and intent['action_id'] == guard_id
                   and intent['semantic_identity'] == {k:cap['scope'][k] for k in C.SCOPE[:-1]}
                   and intent['call_id'] == guard['actual_native_call']['call_id']
                   and intent['semantic_tool'] == 'phone.tap' and intent['wire_tool'] == 'shell.exec'
                   and intent['command_sha256'] == guard['actual_command_sha256']
                   and intent['effect_fingerprint'] == modules['action_ledger'].fingerprint(semantic)
                   and intent['run_dir'] == str(run) and intent['automatic_replay'] is False
                   and intent['executor_binding'] == modules['retirement_recovery'].EXECUTOR_BINDING,
                   'new durable global intent differs from the actual traced native command')
            C.need(resolution['schema'] == 'hepta.action-resolution.v150.1'
                   and resolution['action_id'] == guard_id and resolution['intent_sha256'] == C.sha(files[name])
                   and resolution['business_verified'] is False and resolution['automatic_replay'] is False
                   and resolution['original_task_terminal_unchanged'] is True, 'new global resolution differs')
            if guard_id in actions:
                inspected = j(files, 'ledger/'+guard_id+'.inspection.json')
                C.need(inspected == j(files, 'run/guard-originals/client-inspection.observation.json')
                       and resolution['state'] == 'original_sidecar_terminal_independently_inspected'
                       and resolution['inspection_sha256'] == C.sha(files['ledger/'+guard_id+'.inspection.json'])
                       and resolution['original_exit_code'] == inspected['receipt']['exit_code']
                       and resolution['original_effect_state'] == inspected['receipt']['state'],
                       'actual guard original terminal is not resolved')
            else:
                C.need(resolution['state'] == 'known_not_dispatched'
                       and resolution['phase'] == 'provider_before_native_tool_frame'
                       and resolution['reason'] in ('cancel_before_native_tool_frame','transport_closed_before_native_tool_frame')
                       and 'ledger/'+guard_id+'.inspection.json' not in files,
                       'undispatched reservation is not explicitly resolved')
    for name in files:
        if name.startswith('ledger/') and name.endswith('.intent.json'):
            C.need(name[:-len('.intent.json')]+'.resolution.json' in files, 'global action remains pending')
    for index, call in enumerate(native['calls']):
        phase = ('capture','guard')[index]; binding = j(files, 'run/'+phase+'-ledger-wire-binding.json')
        original = dispatches[phase]['original_mapper_call']
        C.need(binding['action_id'] == call['argv'][4] and binding['scope'] == cap['scope']
               and binding['original_mapper_wire_sha256'] == C.sha(C.encoded(original))
               and binding['actual_native_wire_sha256'] == C.sha(C.encoded(call))
               and binding['actual_command_sha256'] == dispatches[phase]['actual_command_sha256']
               and binding['global_ledger_reserved'] is (phase == 'guard')
               and binding['local_kernel_reservation_is_global_ledger'] is False,
               'local reservation was confused with global actual-wire admission')
    return {'actual_actions': actions, 'new_inventory_entries': len(added), 'previous_closed_components': count}


def load_production(snapshot, files):
    root = snapshot/'home/inputs'
    reviewed = j(files, 'home/package/reference/REVIEWED-PRODUCTION-PINS.json')
    combo, cfg = C.load_combination(root, files['home/inputs/COMBINATION.json'], reviewed, private_inputs=False)
    names = ('provider_openai_compatible', 'phone_task_guards', 'phone_observation_tools',
             'task_postconditions', 'retirement_recovery', 'phone_local_tools', 'action_ledger')
    C.need(not set(names).intersection(sys.modules), 'production parser names already loaded; use a fresh host process')
    sys.dont_write_bytecode = True; sys.path.insert(0, str(root/'production'))
    modules = {name: importlib.import_module(name) for name in names}
    return combo, cfg, modules


def r6_wire(call_id, token, command, cfg):
    executor = cfg['executor']
    C.need(executor == {'mode': 'phone_local_sidecar', 'python': '/usr/bin/python3',
        'client_path': str(C.CLIENT), 'client_sha256': C.CLIENT_SHA, 'timeout_ms': 60000},
        'actual component fixed client configuration differs')
    return {'call_id': call_id, 'tool': 'shell.exec', 'argv': ['/usr/bin/python3', str(C.CLIENT),
        'execute', '--action-id', token, '--command-b64', base64.b64encode(command).decode(),
        '--timeout-ms', '60000']}


def verify_mapped_phase(parser, files, phase, decision, call, cfg, scope):
    parser.map(decision)  # Produces command text and new host metadata; never executes it.
    derived = parser.calls[decision['call_id']]
    C.need(derived['wire_tool'] == 'adb.exec' and derived['wire_call']['argv'][:3] == ['-s','ZY22LS7WZT','shell'],
           'reviewed inherited mapping transport changed')
    command = derived['wire_call']['argv'][3].encode()
    expected = r6_wire(decision['call_id'], derived['capture_id'], command, cfg)
    original = j(files, 'run/semantic-'+C.sha(decision['call_id'].encode())+'.json')
    expected_record = {**derived, 'wire_tool': 'shell.exec', 'wire_call': expected}
    C.need(original == expected_record, 'original semantic command differs from actual production mapper')
    dispatch = j(files, 'run/'+phase+'.dispatch-intent.json')
    trace = b'set -x; ' if phase == 'guard' else b''
    actual = copy.deepcopy(expected); actual['argv'][6] = base64.b64encode(trace+command).decode()
    C.need(call == actual and dispatch['schema'] == 'hepta.native-guard-component.dispatch.v1'
           and dispatch['scope'] == scope and dispatch['original_mapper_call'] == expected
           and dispatch['actual_native_call'] == actual and dispatch['action_id'] == derived['capture_id']
           and dispatch['trace_prefix'] == trace.decode()
           and dispatch['original_command_sha256'] == C.sha(command)
           and dispatch['actual_command_sha256'] == C.sha(trace+command)
           and dispatch['automatic_retry'] is False and zero(dispatch['model_requests'])
           and files['run/'+phase+'.original-command.sh'] == command
           and files['run/'+phase+'.native-command.sh'] == trace+command,
           'actual native wire is not the single reviewed mapping plus explicit trace')
    parser.calls[decision['call_id']] = original
    return original


def root_witness_originals(files, phase, context, listener, guards, lease):
    plan_raw = files['home/ROOT-'+phase.upper()+'-PLAN.json']; plan = C.strict(plan_raw)
    token = C.root_operation_id(context.scope, context.contract_sha, phase)
    commands = listener.root_commands(context, phase, guards, token)
    C.need(plan['schema'] == 'hepta.native-guard.root-phase-plan.v1' and plan['scope'] == context.scope
           and plan['contract_sha256'] == context.contract_sha and plan['phase'] == phase
           and plan['operation_id'] == token and plan['automatic_retry'] is False,
           'actual Root witness plan identity differs')
    C.need(plan['commands'] == {k: {'base64': base64.b64encode(v).decode(), **C.descriptor(v)}
                              for k,v in commands.items()}, 'Root witness command differs from reviewed production builders')
    prefix = 'run/root-'+phase+'-originals/'
    mailbox_raw = files[prefix+'MAILBOX.original.json']; mailbox = C.strict(mailbox_raw)
    C.need(mailbox_raw == files['home/operator/'+phase+'.json']
           and mailbox['schema'] == 'hepta.native-guard.root-witness.v1'
           and mailbox['phase'] == phase and mailbox['scope'] == context.scope
           and mailbox['contract_sha256'] == context.contract_sha and mailbox['operation_id'] == token,
           'Root witness original mailbox differs')
    required = {k+s for k in commands for s in ('','_execution','_wire','_command','_stderr','_uid','_uid_wire','_intent')}
    C.need(set(mailbox['files']) == required, 'Root original witness file set differs')
    actual = {}
    provenance_raw = files[prefix+'PROVENANCE.original.json']; provenance = C.strict(provenance_raw)
    C.need(provenance['phase_plan_sha256'] == C.sha(plan_raw)
           and set(provenance['source_files']) == required, 'Root original provenance plan differs')
    for key, row in mailbox['files'].items():
        raw = files[prefix+key+'.original']
        C.need(C.descriptor(raw) == {k:row[k] for k in ('bytes','sha256')}
               and row['path'].startswith(phase+'/') and len(Path(row['path']).parts) == 2
               and raw == files['home/operator/'+row['path']]
               and all(provenance['source_files'][key][k] == row[k] for k in ('bytes','sha256')),
               'Root witness stream does not match actual retained originals')
        actual[key] = raw
    for key, command in commands.items():
        listener.verify_operator_execution(actual, key, actual[key], command,
            phase=phase, nonce=lease['nonce'], boot=lease['boot_id'])
    actor_raw = files[prefix+'ACTOR-ORIGINALS.original.json']
    C.need(C.descriptor(actor_raw) == {k:provenance['actor_originals'][k] for k in ('bytes','sha256')}
           and actor_raw == files['home/operator/'+provenance['actor_originals']['path']],
           'complete original Root actor envelope differs')
    actor = listener.verify_root_actor_originals(actor_raw, plan_raw, actual)
    if phase == 'setup' and lease['case_id'] == 'NEG-01':
        guards.verify_app_open(C.strict(actual['open']), token, context.mapper.apps['视觉挑战']['component'])
    if phase == 'before-guard' and lease['case_id'] == 'NEG-01':
        guards.verify_app_open(C.strict(actual['disturbance']), C.sha((token+':open').encode())[:32],
                              context.mapper.apps['Unicode验证']['component'])
    return token, actual, actor['installed_probe_before']


def verify_actual_age(files, scope, native):
    capture = j(files, 'run/capture-phase.json')['capture']
    clock = j(files, 'run/capture-clock.original.json')
    age = j(files, 'run/guard-capture-age.original.json')
    sent = j(files, 'run/actual-wire-01.sent.json')
    for row in (clock, age):
        C.need(row['scope'] == scope and row['clock'] == 'phone time.monotonic'
               and row['capture_call_id'] == capture['call_id']
               and row['capture_received_monotonic'] == capture['received_monotonic']
               and row['capture_phase_original_sha256'] == C.sha(files['run/capture-phase.json'])
               and zero(row['model_requests']), 'actual phone clock original binding differs')
    C.need(clock['schema'] == 'hepta.native-guard.actual-capture-clock.v1'
           and age['schema'] == 'hepta.native-guard.actual-capture-age.v1'
           and clock['native_result_sha256'] == C.sha(native['incoming_raw'][1])
           and age['actual_guard_frame_sha256'] == C.sha(native['outgoing_raw'][1])
           and age['maximum_age_seconds'] == 120 and age['automatic_recapture'] is False,
           'original capture/guard clock identity differs')
    t = [capture['received_monotonic'], clock['after_admission_monotonic'],
         age['guard_pre_send_monotonic'], sent['send_started_monotonic'], sent['send_returned_monotonic']]
    C.need(all(type(v) in (int,float) and math.isfinite(v) and v > 0 for v in t)
           and t == sorted(t) and sent['clock'] == 'phone time.monotonic'
           and age['age_seconds'] == t[2]-t[0] and 0 <= t[2]-t[0] <= 120
           and 0 <= t[3]-t[0] <= 120, 'original capture expired before actual native guard dispatch')
    return {'actual_capture_to_guard_seconds': t[3]-t[0], 'maximum_seconds': 120,
            'clock': 'original phone time.monotonic', 'host_reparse_clock_is_not_qualification': True}


def consumed_root_attempt(files, phase, attempts):
    """A consumed native witness must be the same joined host Actor original."""
    C.need(phase in attempts and attempts[phase]['status'] == 'complete',
           'native witness lacks a fully known parent-owned Root fixture')
    attempt = attempts[phase]; prefix = 'run/root-'+phase+'-originals/'
    C.need(attempt['plan_raw'] == files['home/ROOT-'+phase.upper()+'-PLAN.json']
           and attempt['actor_originals_raw'] == files[prefix+'ACTOR-ORIGINALS.original.json'],
           'consumed Root witness differs from independently joined host originals')
    for key, raw in attempt['planned_files'].items():
        C.need(files.get(prefix+key+'.original') == raw,
               'consumed Root command/stream differs from its actual parent attempt')
    return attempt


def verify_root_fixture_inventory(cap, files, lease, scope, inventory, attempts):
    """All actual staged Root effects, including unconsumed ones, must account."""
    expected = {}; summary = {}
    for phase, value in attempts.items():
        C.need(value['status'] in ('complete','joined_no_ui_effect'), 'Root actor effect is still unknown')
        C.need(not (set(expected) & set(value['fixture_originals'])), 'Root fixture originals reused across phases')
        expected.update(value['fixture_originals'])
        summary[phase] = {'status':value['status'], 'phase_plan_sha256':C.sha(value['plan_raw']),
            'actor_originals':None if value['actor_originals_raw'] is None else C.descriptor(value['actor_originals_raw']),
            'fixture_originals':{name:C.descriptor(raw) for name,raw in value['fixture_originals'].items()},
            'evidence_summary':value['evidence_summary']}
    actual = {name[len('fixture/'):]:raw for name,raw in files.items() if name.startswith('fixture/')}
    C.need(actual == expected, 'unaccounted or missing actual Root phone fixture script/UID original')
    root = '/proc/1/root/data/local/tmp/hepta-native-guard-'+lease['nonce']
    C.need(root in inventory['roots'], 'complete inventory omitted Root fixture root')
    if not expected:
        FIXTURE.phone_fixture_absent(files, lease, scope)
    else:
        entry = inventory['entries'][root]
        C.need(entry['kind'] == 'directory' and entry['names'] == sorted(expected)
               and stat.S_ISDIR(entry['metadata'][2]) and stat.S_IMODE(entry['metadata'][2]) == 0o700
               and entry['metadata'][3:5] == [2000,2000], 'actual Root fixture directory topology/owner differs')
        C.need({name for name in inventory['entries'] if name.startswith(root+'/')}
               == {root+'/'+name for name in expected}, 'unaccounted nested or partial Root fixture original')
        for name, raw in expected.items():
            C.need(Path(name).name == name and name.endswith(('.sh','.uid')), 'Root fixture file is outside the reviewed effect pair')
            path = root+'/'+name; row = cap['files']['fixture/'+name]; entry = inventory['entries'][path]
            meta = entry['metadata']; mode = 0o400 if name.endswith('.sh') else 0o600
            C.need(entry['kind'] == 'file' and {k:entry[k] for k in ('bytes','sha256')} == C.descriptor(raw)
                   and stat.S_ISREG(meta[2]) and stat.S_IMODE(meta[2]) == mode
                   and meta[3:6] == [2000,2000,1] and meta[6] == len(raw)
                   and row['kind'] == 'original_file_bytes' and row['source_path'] == path
                   and row['source_metadata'] == meta and {k:row[k] for k in ('bytes','sha256')} == C.descriptor(raw),
                   'actual Root phone fixture byte/identity/UID origin differs')
    return {'all_actual_host_attempts_terminal':True, 'complete_phone_fixture_bijection':True,
            'host_phase_count':len(attempts), 'phone_fixture_files':len(expected), 'phases':summary,
            'unconsumed_host_phase_is_native_witness':False, 'business_qualified':False, 'model_requests':0}


def typed_reparse(out, files, lease, bound, scope, request, native, cfg, modules, K, listener, *, root_attempts):
    """Actual inherited mapping/parser plus separate r6 wire; zero tool execution."""
    derived = out/'derived'; derived.mkdir(mode=0o700)
    def record(path, value):
        C.need(Path(path).parent == derived, 'new parser artifact left its private host output')
        write(path, C.encoded(value))
    phone, guards, local = (modules[n] for n in ('phone_observation_tools','phone_task_guards','phone_local_tools'))
    parser = phone.PhoneTools(derived, record); parser.bind(scope)
    tasks = modules['task_postconditions']
    _apps, expected_scope = tasks.resolve_task_apps(None, C.sha(request), cfg['approved_apps'])
    C.need(j(files, 'run/task-app-scope.json') == expected_scope,
           'component has an unreviewed business contract or task scope')
    contract_raw = files['run/component-contract.original.json']
    kernel = object.__new__(K.NativeGuardSession)
    kernel.contract = bound['contract']; kernel.contract_sha = C.sha(contract_raw); kernel.scope = scope
    kernel.run = derived; kernel.owner_raw = request; kernel.mapper = parser
    kernel.phone, kernel.guards = phone, guards; kernel.state = 'BOUND'; kernel.setup = None
    kernel.out_seq = 2; kernel.outbound = []; kernel.in_seq = 1
    context = types.SimpleNamespace(scope=scope, contract=kernel.contract, contract_sha=kernel.contract_sha,
        mapper=types.SimpleNamespace(apps=cfg['approved_apps'], _serial_guard=parser._serial_guard,
                                   _focus_input_precondition=local.current_viewport_guard), capture=None)
    apks = []; receipts = []; bundles = []; streams_by_id = {}; typed_rejections = []
    if native['calls']:
        consumed_root_attempt(files, 'setup', root_attempts)
        token, witness, installed = root_witness_originals(files,'setup',context,listener,guards,lease)
        apks.append(installed)
        if lease['case_id'] == 'NEG-02':
            kernel.setup_witness(witness['public'], token)
    for index, (call, result) in enumerate(zip(native['calls'], native['results'])):
        phase = ('capture','guard')[index]
        call_id = 'guard_'+lease['nonce']+'_'+phase
        C.need(call['call_id'] == call_id, 'native component call ordering differs')
        if phase == 'capture':
            args = ['0']
        else:
            C.need(kernel.state == 'WAITING_ROOT_WITNESS', 'guard has no original admitted screenshot')
            context.capture = kernel.capture
            consumed_root_attempt(files, 'before-guard', root_attempts)
            token, witness, installed = root_witness_originals(files,'before-guard',context,listener,guards,lease)
            apks.append(installed)
            kernel.before_guard_witness(witness['public'], token, witness['png'])
            bound_xy = kernel.before_public[K.SUBMIT]['bounds']
            x1,y1,x2,y2 = map(int,re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',bound_xy).groups())
            w,h = kernel.capture['encoded_size']; x,y = round((x1+x2)*w/(2*1224)), round((y1+y2)*h/(2*2992))
            ox,oy = (2*x*1224+w)//(2*w),(2*y*2992+h)//(2*h)
            C.need(0 <= x < w and 0 <= y < h and x1 < ox < x2 and y1 < oy < y2,
                   'bound point is not the independently observed Submit control')
            args = [kernel.capture['call_id'],str(x),str(y)]; parser.round = 2
        decision = {'kind':'tool.call','tool':'phone.screenshot' if index==0 else 'phone.tap',
                    'call_id':call_id,'argv':args,'command':'','summary':'explicit native component phase',
                    'task_status':'in_progress'}
        verify_mapped_phase(parser,files,phase,decision,call,cfg,scope)
        raw = native['incoming_raw'][index+1]
        C.need(C.strict(raw) == result and raw == files['run/provider-in-%02d.jsonl'%(index+1)],
               'actual original tool result was not durably consumed')
        value, streams = K.native_streams(raw,index+1,call)
        native_stream_join(native['frames'],call,result,streams)
        receipt,bundle = bound_r6(files,phase,call,streams,value['terminal']['exit_code'],
                                 bound['contract']['executor_server_instance'],
                                 bound['sidecar_identity']['identity'][0],modules['retirement_recovery'])
        receipts.append(receipt);bundles.append(bundle);streams_by_id[call_id]=streams
        kernel.pending=call;kernel.state=phase.upper()+'_RESERVED'
        expected = 0 if index==0 else (70 if lease['case_id']=='NEG-01' else 71)
        if receipt['state']=='completed' and value['terminal']['exit_code']==expected:
            admitted = True
            try:
                if index == 0:
                    kernel.capture_result(raw,bundle)
                else:
                    kernel.guard_result(raw,bundle)
            except (ValueError, modules['provider_openai_compatible'].ProviderError) as error:
                C.need(native['status'] in ('provider_failed','cancelled')
                       and index == len(native['calls'])-1,
                       'independently rejected typed result cannot be followed by an effect or qualified')
                # r6 process/domain/streams and the native result were already
                # independently verified above. A typed rejection remains an
                # explicit failed observation, never component success.
                typed_rejections.append({'phase':phase,'call_id':call_id,
                    'native_result_sha256':C.sha(raw),'r6_receipt_sha256':C.sha(bundle['receipt']),
                    'error_type':type(error).__name__,'detail':str(error)[:1024],
                    'qualification':False,'safe_original_r6_terminal_already_verified':True})
                admitted = False
            if index==0 and admitted:
                original = j(files,'run/capture-phase.json')['capture']
                compared = {k:v for k,v in kernel.capture.items() if k not in ('path','received_monotonic')}
                C.need(compared == {k:v for k,v in original.items() if k not in ('path','received_monotonic')}
                       and original['path'] == str(C.COMPONENT_EVIDENCE/bound['run_basename']/('image-'+original['capture_id']+'.jpg'))
                       and files['run/image-'+original['capture_id']+'.jpg'] == Path(kernel.capture['path']).read_bytes(),
                       'independently parsed image differs from original capture')
        else:
            C.need(native['status'] in ('provider_failed','cancelled') and index == len(native['calls'])-1,
                   'failed original tool was followed by another effect or converted to success')
    qualified = native['status'] == 'completed'
    age = None
    if qualified:
        C.need(len(native['calls'])==2 and kernel.state=='WAITING_ROOT_AFTER_WITNESS',
               'component success lacks both original admitted capture and rejecting guard')
        consumed_root_attempt(files, 'after-guard', root_attempts)
        token,witness,installed = root_witness_originals(files,'after-guard',context,listener,guards,lease)
        apks.append(installed)
        actual = kernel.after_guard_witness(witness['public'],token)
        C.need(actual == native['outgoing_raw'][-1], 'component terminal differs from complete original public witness')
        age = verify_actual_age(files,scope,native)
        C.need(all(value == apks[0] for value in apks), 'public probe APK changed across independent fixture phases')
        ended = j(files,'home/LIFECYCLE-ENDED.json')
        C.need(ended['provider_observation_exit_zero'] is True and ended['failure'] is None
               and ended['roles']['provider']['child_exit_code']==0, 'component provider did not complete its actual witness path')
    else:
        C.need(native['status'] in ('provider_failed','cancelled')
               and 'run/listener-failure.json' in files, 'failed closure lacks its original failure boundary')
    return {'component_qualified':qualified,'actual_calls':len(native['calls']),
            'all_original_r6_terminals_verified':True,'unknown_effects':0,'age':age,
            'receipt_states':[r['state'] for r in receipts], 'typed_rejections':typed_rejections,
            'phone_calls':0,'commands_executed':0}


def sender_originals(originals, plan, files, request, scope, run, native, decoder, out):
    directory = Path(plan['sender_dir']); observed = {}
    def read(name):
        raw = originals.read(directory/name, 16*1024*1024); observed[name] = raw
        return C.strict(raw)
    host_raw = originals.pinned(plan['sender_host_result']); host = C.strict(host_raw)
    C.need(zero(host.get('rc')) and host.get('stderr') == '' and isinstance(host.get('stdout'), str),
           'original sender actor rc is not known zero; host job rc is insufficient')
    actor_output = C.strict(host['stdout'].strip().splitlines()[-1])
    C.need(actor_output.get('state') == 'ORIGINAL_NATIVE_TERMINAL_OBSERVED'
           and actor_output.get('native_status') == native['status']
           and actor_output.get('send_attempt_count') == 1 and actor_output.get('automatic_replay') is False
           and actor_output.get('prompt_sha256') == C.sha(request)
           and actor_output.get('out') == str(directory)
           and actor_output.get('business_success_verified') is False
           and actor_output.get('draft_restore') == {'state':'ORIGINAL_DRAFT_RESTORED',
                                                   'restore_attempts':1,'original_draft_submitted':False},
           'original actor terminal/single-Send/draft result differs')
    previous = C.strict(originals.pinned(plan['previous']))
    preserved = C.strict(originals.pinned(plan['preserved_draft']))
    old = C.scope(previous['identity']); old_digest = previous['request_sha256']
    C.need(scope != old and (scope['task_id'],scope['turn_id']) != (old['task_id'],old['turn_id'])
           and scope['session_id'] == old['session_id'] and scope['profile_id'] == old['profile_id']
           and C.HASH.fullmatch(old_digest), 'fresh native scope is not distinct from selected previous task')
    draft = base64.b64decode(preserved['exact_utf8_b64'], validate=True); draft.decode()
    C.need(draft and C.sha(draft) == preserved['utf8_sha256'] and draft != request,
           'original nonempty user draft binding differs')
    intent = C.strict(originals.pinned(plan['sender_local_once']))
    C.need(intent.get('task') == plan['label'] and intent.get('prompt', '').encode() == request
           and intent.get('prompt_sha256') == C.sha(request) and intent.get('previous_identity') == old
           and intent.get('previous_digest') == old_digest and intent.get('evidence_root_mode') == 'component'
           and intent.get('automatic_replay') is False and intent.get('supplied_app_commands') is False
           and intent.get('supplied_app_coordinates') is False,
           'original sender once intent/previous ownership differs')
    actor_raw = originals.pinned(plan['sender_actor']); assignments = {}
    for node in ast.parse(actor_raw).body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            key=node.targets[0].id
            if key in ('label','expected','preserved_draft','previous_identity','previous_digest','evidence_mode'):
                C.need(key not in assignments, 'generated actor reassigns a bound input')
                assignments[key]=ast.literal_eval(node.value)
    C.need(assignments == {'label':plan['label'],'expected':request.decode(),'preserved_draft':draft.decode(),
                          'previous_identity':old,'previous_digest':old_digest,'evidence_mode':'component'},
           'original generated actor does not bind the reviewed input bytes')
    once = read('SEND.once.json'); send_intent = read('SEND.MONOTONIC-INTENT.json'); window = read('SEND.MONOTONIC-WINDOW.json')
    C.need(once.get('prompt','').encode() == request and once.get('prompt_sha256') == C.sha(request)
           and once.get('automatic_replay') is False and once.get('supplied_app_commands') is False
           and once.get('supplied_app_coordinates') is False
           and send_intent.get('send_attempt_count') == 1 and send_intent.get('automatic_replay') is False
           and window.get('clock') == 'Pocket4 time.monotonic_ns' and window.get('automatic_replay') is False,
           'actual original one-Send attempt binding differs')
    times = [send_intent['p4_pre_send_monotonic_ns'],window['send_started_monotonic_ns'],window['send_returned_monotonic_ns']]
    C.need(all(type(v) is int and v>0 for v in times) and times == sorted(times), 'actual sender clock order differs')
    if window['send_status'] == 'tap_returned':
        sent = read('SEND.result.json'); C.need(zero(sent.get('rc')), 'original Send did not return zero')
        C.need(not (directory/'SEND.unknown.json').exists(), 'duplicate Send result/unknown originals')
    else:
        C.need(window['send_status'] == 'unknown', 'unreviewed Send outcome')
        unknown = read('SEND.unknown.json'); C.need(unknown.get('automatic_replay') is False, 'unknown Send permits replay')
        C.need(not (directory/'SEND.result.json').exists(), 'duplicate Send result/unknown originals')
    latency = read('SEND-NATIVE-LATENCY.json'); observation = latency['original_observation']
    C.need(latency.get('schema') == 'hepta.p4-send-native-terminal-latency.v150.r3'
           and latency.get('state') == 'ORIGINAL_NATIVE_TERMINAL_OBSERVED'
           and latency.get('owner_request_utf8_sha256') == C.sha(request) and latency.get('scope') == scope
           and latency.get('native_status') == native['status'] and latency.get('send_attempt_count') == 1
           and latency.get('automatic_send_retry') is False
           and latency.get('send_call_started_monotonic_ns') == times[1]
           and latency.get('send_call_returned_monotonic_ns') == times[2]
           and observation.get('native_request_sha256') == native['native_digest'],
           'original sender latency observation does not bind this exact native task')
    match = observation['match']; terminal = observation['native_terminal']
    start = base64.b64decode(match['provider_start_original_b64'], validate=True)
    end = base64.b64decode(terminal['raw_line_b64'], validate=True)
    C.need(match['scope'] == scope and match['run_dir'] == str(run)
           and match['provider_input_file'] == str(run/'provider-in.jsonl')
           and match['owner_utf8_sha256'] == C.sha(request)
           and start == native['incoming_raw'][0] and len(start) == match['provider_start_original_bytes']
           and C.sha(start) == match['provider_start_original_sha256']
           and end == native['lines'][-1] and len(end) == terminal['raw_line_bytes']
           and C.sha(end) == terminal['raw_line_sha256']
           and terminal['record'] == native['records'][-1] and terminal['frame'] == native['frames'][-1],
           'sender original native start/end bytes differ from independent full chain')
    C.need(type(latency.get('read_count')) is int and 1 <= latency['read_count'] <= 512,
           'original terminal observation count differs')
    last = read('LATENCY-%04d.original-read.json'%latency['read_count'])
    wire = last['original_wire_receipt']
    C.need(zero(wire.get('rc')) and C.strict(wire['stdout']) == observation and last['observation'] == observation,
           'original native terminal read wire differs')
    original_draft = read('PRESERVED-USER-DRAFT.json')
    C.need(original_draft['exact_text'].encode() == draft and original_draft['utf8_sha256'] == C.sha(draft)
           and original_draft['restore_required'] is True and original_draft['submitted_original_draft'] is False,
           'actual sender did not preserve the same original user draft')
    restore = read('DRAFT-RESTORE-RESULT.json'); restore_wire = read('PRESERVED-DRAFT-RESTORE.original.json')
    C.need(restore.get('state') == 'ORIGINAL_DRAFT_RESTORED' and restore.get('restore_attempts') == 1
           and restore.get('utf8_sha256') == C.sha(draft) and restore.get('original_draft_submitted') is False
           and restore.get('model_business_credit') is False and zero(restore_wire.get('rc'))
           and restore_wire.get('stderr') == '', 'original draft cleanup has not completed exactly once')
    value = C.strict(restore_wire['stdout'])
    C.need(value.get('schema') == 'hepta.focused-unicode-input.v1'
           and value.get('status') in ('set_verified','already_exact')
           and value.get('operation_id') == 'root-restore-'+plan['label'] and value.get('display_id') == 0
           and value.get('package') == 'org.trillionnium.owneropen'
           and value.get('view_id') == 'org.trillionnium.owneropen:id/ui_prompt'
           and value.get('own_automation_disconnected') is True
           and base64.b64decode(value['readback_text_b64'], validate=True) == draft
           and value.get('requested_utf8_sha256') == value.get('after_utf8_sha256') == C.sha(draft),
           'independent exact original draft readback differs')
    for name, identity, digest in [
        ('FINAL-PRE-SEND-SELECTED.original-read.json',old,old_digest),
        ('COMPONENT-FINAL-PRE-SEND-SELECTED.original-read.json',old,old_digest),
        ('RESTORE-SELECTED.original-read.json',scope,native['native_digest']),
        ('RESTORE-SELECTED-FINAL.original-read.json',scope,native['native_digest'])]:
        wire = read(name); C.need(zero(wire.get('rc')), 'original selection CAS read is not zero')
        raw = base64.b64decode(''.join(wire['stdout'].split()), validate=True)
        selected = decoder.decode_client_state(raw)
        C.need(selected['checksum_valid'] is True
               and all(selected[k] == identity[k] for k in ('session_id','task_id','turn_id'))
               and selected['turn_request_sha256'] == digest, 'original selected native identity CAS differs')
    gate = read('RESTORE-GLOBAL-GATE.original-read.json'); wire = gate['original_wire_receipt']
    C.need(gate['read_only'] is True and gate['no_retry'] is True and zero(wire.get('rc')),
           'original global restoration gate was not verified')
    gate_value = C.strict(wire['stdout'])
    C.need(gate_value.get('state') == 'original_retirement_verified' and gate_value.get('global_action_gate_clear') is True
           and gate_value.get('resolution_sha256') == intent['retirement_resolution_sha256'],
           'draft restoration bypassed original global action gate')
    target = out/'sender-originals'; target.mkdir(mode=0o700)
    for name, raw in observed.items():
        write(target/name,raw)
    for name,key in [('HOST-SEND-RESULT.original.json','sender_host_result'),('HOST-ONCE.original.json','sender_local_once'),
                     ('ACTOR.original.py','sender_actor'),('PREVIOUS.original.json','previous'),
                     ('PRESERVED-DRAFT.original.json','preserved_draft')]:
        write(target/name, originals.pinned(plan[key]))
    return {'original_actor_exit_zero':True,'send_attempts':1,'full_native_original_start_end_equal':True,
            'original_selection_cas_verified':True,'exact_original_draft_restored':True,
            'original_draft_submitted':False,'business_return_credit':False,'phone_calls':0}


def close(a):
    os.umask(0o077); originals = Originals()
    plan_raw = originals.read(Path(a.plan),262144)
    C.need(C.sha(plan_raw) == a.plan_sha256, 'closure plan original pin differs')
    plan = validate_plan(C.strict(plan_raw))
    archive = originals.pinned(plan['archive']); cap,files = archive_files(archive,plan['capture_sha256'])
    request = originals.pinned(plan['request']); load_package(originals,plan['package'],files)
    lease,bound,scope,home,run = identity_inputs(cap,files,request)
    C.need(cap['package_sha256'] == plan['package']['sha256'], 'actual component package is not the reviewed host package')
    out = Path(a.out)
    C.need(out.is_absolute() and out.parent.resolve(strict=True)==out.parent, 'new canonical host closure output required')
    out.mkdir(mode=0o700); C.sync(out.parent)
    write(out/'CLOSURE-INTENT.original.json',C.encoded({'schema':'hepta.native-guard.closure-intent.v1',
        'plan':C.descriptor(plan_raw),'capture_sha256':plan['capture_sha256'],'archive':plan['archive'],
        'phone_calls':0,'model_requests':0,'automatic_retry':False}))
    snapshot=out/'snapshot';materialize(snapshot,files)
    combo,cfg,modules = load_production(snapshot,files)
    C.need(bound['contract']['source_seal_sha256']==combo['source_seal']['sha256']
           and bound['contract']['configuration_sha256']==combo['configuration']['sha256'],
           'actual native contract source/config differs')
    auditor=module_from_bytes(files['home/package/reference/native_journal_audit.py'],'independent_native_auditor',
                             snapshot/'home/package/reference/native_journal_audit.py')
    decoder=module_from_bytes(files['home/package/reference/decode_client_state.py'],'original_selection_decoder',
                             snapshot/'home/package/reference/decode_client_state.py')
    K=module_from_bytes(files['home/package/source/native_guard_session_r2.py'],'original_component_parser',
                        snapshot/'home/package/source/native_guard_session_r2.py')
    listener=module_from_bytes(files['home/package/source/component_listener.py'],'original_component_wire_validator',
                               snapshot/'home/package/source/component_listener.py')
    native=native_originals(cap,files,scope,request,auditor)
    inventory_raw=files['after/AFTER-INVENTORY.json'];inventory=C.strict(inventory_raw);LATE.inventory_value(inventory)
    capture_provenance(cap,files,lease,home,run,inventory)
    sidebranch=verify_non_native_sidebranch(cap,files,inventory)
    verify_retirement_copy(files,lease);roles=verify_roles(files,lease,bound)
    root_attempts=FIXTURE.verify_attempts(originals,plan['root_fixture_attempts'],files,lease,scope,
                                        expected_package_sha256=cap['package_sha256'])
    parsed=typed_reparse(out,files,lease,bound,scope,request,native,cfg,modules,K,listener,
                         root_attempts=root_attempts)
    root_fixture=verify_root_fixture_inventory(cap,files,lease,scope,inventory,root_attempts)
    ledger=verify_ledger_inventory(cap,files,lease,home,run,inventory,native,modules)
    sender=sender_originals(originals,plan,files,request,scope,run,native,decoder,out)
    originals.recheck()
    FIXTURE.recheck_directories(originals)
    audit={k:v for k,v in native['audit'].items() if k not in ('selected_records','frames')}
    write(out/'NATIVE-AUDIT.original.json',C.encoded(audit))
    write(out/'AFTER-INVENTORY.original.json',inventory_raw)
    closed={'schema':'hepta.native-guard.original-closure.v1',
        'state':'ORIGINAL_NATIVE_COMPONENT_CLOSED' if parsed['component_qualified']
                else 'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED',
        'closed':True,'component_qualified':parsed['component_qualified'],'business_qualified':False,
        'four_role_qualification':False,'model_requests':0,'automatic_replay':False,
        'boot_id':lease['boot_id'],'nonce':lease['nonce'],'case_id':lease['case_id'],'scope':scope,
        'owner_request_sha256':C.sha(request),'lease_sha256':C.sha(files['home/LEASE.json']),
        'lease_source_path':str(home/'LEASE.json'),'package_sha256':cap['package_sha256'],
        'combination_sha256':cap['combination_sha256'],'retirement':lease['retirement'],
        'prior_boundary':lease['prior_boundary'],'inventory':C.descriptor(inventory_raw),
        'non_native_sidebranch':sidebranch['binding'],
        'component_role_identities':roles,'native_status':native['status'],'actual_native_calls':len(native['calls']),
        'unknown_effects':0,'native_hash_chain_and_terminal_verified':True,
        'two_original_r6_calls_verified':len(native['calls'])==2,
        'all_actual_r6_calls_verified':True,'global_ledger_delta_verified':True,
        'original_sender_and_draft_restoration_verified':True,
        'independent_role_and_endpoint_absence_verified':True,'all_prior_originals_preserved':True,
        'original_retirement_rewritten':False,'old_retirement_current_equality_claimed':False,
        'capture':C.descriptor(files['CAPTURE.json']),'archive':plan['archive'],
        'independent_native_audit':audit,'typed_reparse':parsed,'ledger':ledger,'sender':sender,
        'root_fixture':root_fixture,'root_fixture_attempts':plan['root_fixture_attempts'],
        'root_fixture_directory_originals':getattr(originals,'root_fixture_directories',{}),
        'root_fixture_absence_originals':getattr(originals,'root_fixture_absences',{}),
        'original_host_inputs':originals.files,'closure_source_sha256':C.sha(Path(__file__).read_bytes()),
        'phone_calls':0,'commands_executed':0,'boundary_published_here':False}
    write(out/'CLOSURE.original.json',C.encoded(closed))
    summary={k:closed[k] for k in ('state','closed','component_qualified','business_qualified',
             'native_status','actual_native_calls','unknown_effects','phone_calls','boundary_published_here')}
    summary['closure']=C.descriptor((out/'CLOSURE.original.json').read_bytes())
    write(out/'RESULT.json',C.encoded(summary));print(C.encoded(summary).decode(),end='')
    return 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan',required=True);p.add_argument('--plan-sha256',required=True)
    p.add_argument('--out',required=True);p.add_argument('--execute-host-closure-once',action='store_true')
    a=p.parse_args()
    if not a.execute_host_closure_once:
        print(C.encoded({'state':'HOST_PREVIEW_NO_ORIGINAL_CLOSURE','phone_calls':0,'model_requests':0,
                         'writes':0,'component_qualified':False}).decode(),end='');return 0
    return close(a)


if __name__=='__main__':
    raise SystemExit(main())
