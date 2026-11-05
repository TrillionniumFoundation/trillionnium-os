#!/usr/bin/env python3
"""Source-only native component session kernel. This file never opens a socket.

An independently reviewed one-use listener must pass actual native frames and
original Root observations to this kernel. It returns frames; it cannot execute
commands, signal services, create an acceptance nonce, or qualify a native turn.
The frozen printf probe and production fifteen-source provider are unchanged.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import time
import xml.etree.ElementTree as ET

PROTOCOL = 'trillionnium.owner-open.provider-jsonl.v1'
KEYS = ('session_id', 'profile_id', 'task_id', 'turn_id', 'turn_stream_id')
PACKAGE = 'org.trillionnium.hepta.controlprobe'
TEXT = PACKAGE + '/' + PACKAGE + '.TextEntryActivity'
VISUAL = PACKAGE + '/' + PACKAGE + '.VisualChallengeActivity'
INPUT = PACKAGE + ':id/unicode_input'
SUBMIT = PACKAGE + ':id/unicode_submit'
RECEIPT = PACKAGE + ':id/unicode_receipt'
READBACK = PACKAGE + ':id/unicode_readback'
CLIENT = '/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py'
CLIENT_SHA = '500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
PARENT = 'u:r:trillionnium_owner_open_phone_executor:s0'
WORKER = 'u:r:trillionnium_owner_open_phone_worker:s0'
BOOTSTRAP = 'u:r:trillionnium_owner_open_bootstrap:s0'
MAX_FRAME = 1024 * 1024


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode()


def strict(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON member')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def put(path, raw):
    path = Path(path)
    need(path.parent.resolve() == path.parent, 'canonical private output required')
    body = raw if isinstance(raw, bytes) else encoded(raw)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(body); out.flush(); os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {'path': str(path), 'bytes': len(body), 'sha256': sha(body)}


def public_state(raw, operation_id, phone, guards):
    """Derive the public witness from original typed XML, never a counter claim."""
    value = strict(raw)
    observed, viewport = guards.verify_public_text(value, operation_id, PACKAGE,
                                                   [INPUT, SUBMIT, RECEIPT])
    phone.validate_viewport(viewport)
    need(observed['component'] == TEXT, 'public witness is not TextEntry')
    xml = guards.decode_text(value['xml_b64'], 'operator original public XML', 196608)
    root = ET.fromstring(xml)
    state = {}
    for name in (INPUT, SUBMIT, RECEIPT, READBACK):
        nodes = [n for n in root.iter('node') if n.get('resource-id') == name]
        if name == READBACK and not nodes:
            state[name] = {'absent_in_original_xml': True}
            continue
        need(len(nodes) == 1, 'public witness node not unique')
        n = nodes[0]
        need(n.get('package') == PACKAGE and n.get('password') == 'false'
             and n.get('enabled') == 'true' and n.get('visible-to-user', 'true') == 'true',
             'public witness node is not eligible')
        text = n.get('text')
        need(isinstance(text, str) and '\0' not in text and len(text.encode()) <= 4096,
             'public witness text differs')
        bounds = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', n.get('bounds', ''))
        need(bounds is not None, 'public witness bounds missing')
        x1, y1, x2, y2 = map(int, bounds.groups())
        need(0 <= x1 < x2 <= 1224 and 0 <= y1 < y2 <= 2992, 'public witness off screen')
        state[name] = {k: n.get(k, '') for k in ('resource-id', 'class', 'text', 'content-desc',
            'package', 'password', 'enabled', 'focusable', 'focused', 'clickable', 'checkable',
            'checked', 'selected', 'scrollable', 'bounds')}
        state[name]['visible-to-user'] = n.get('visible-to-user', 'true')
    need(state[INPUT]['class'] == 'android.widget.EditText' and state[INPUT]['focusable'] == 'true'
         and state[SUBMIT]['class'] == 'android.widget.Button' and state[SUBMIT]['clickable'] == 'true'
         and state[SUBMIT]['text'] == '确认并读回'
         and state[RECEIPT]['class'] == 'android.widget.TextView', 'public controls differ')
    page = guards.decode_text(value['page_after_b64'], 'operator original page')
    return state, page, viewport


def native_streams(raw, expected_seq, call):
    need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_FRAME and raw.endswith(b'\n'),
         'bounded original native JSONL frame required')
    value = strict(raw)
    need(value.get('protocol') == PROTOCOL and type(value.get('seq')) is int
         and value['seq'] == expected_seq and value.get('kind') == 'tool.result'
         and value.get('call_id') == call['call_id'] and value.get('status') == 'terminal',
         'native result identity or sequence differs')
    terminal = value.get('terminal', {})
    need(terminal.get('kind') == 'exited' and type(terminal.get('exit_code')) is int
         and terminal.get('signal') is None and terminal.get('error') is None
         and terminal.get('output_truncated') is False, 'original native tool terminal unknown')
    rows = value.get('events'); need(isinstance(rows, list) and 3 <= len(rows) <= 4096, 'event bound')
    streams = {'stdout': bytearray(), 'stderr': bytearray()}; kinds = []
    for index, row in enumerate(rows):
        need(row.get('call_id') == call['call_id'] and row.get('tool') == 'shell.exec'
             and type(row.get('seq')) is int and row['seq'] == index, 'native event sequence differs')
        event = row.get('event', {}); kind = event.get('kind'); kinds.append(kind)
        need(kind in ('accepted', 'started', 'output', 'terminal'), 'unreviewed native event')
        if kind == 'output':
            need(event.get('stream') in streams and event.get('encoding') == 'base64', 'stream shape')
            b = base64.b64decode(event['data'], validate=True)
            need(type(event.get('byte_count')) is int and event['byte_count'] == len(b), 'stream size')
            streams[event['stream']].extend(b)
    need(kinds[:2] == ['accepted', 'started'] and kinds[-1] == 'terminal'
         and all(kinds.count(k) == 1 for k in ('accepted', 'started', 'terminal'))
         and rows[-1]['event'].get('terminal') == terminal, 'native lifecycle order')
    streams = {k: bytes(v) for k, v in streams.items()}
    need(sum(map(len, streams.values())) <= 600000, 'native output bound')
    for key, b in streams.items():
        need(type(terminal.get(key + '_bytes')) is int and terminal[key + '_bytes'] == len(b),
             'native terminal stream length differs')
    return value, streams


def verify_r6(bundle, call, streams, server_instance, expected_exit):
    """Check original bytes supplied by the separate read-only capture adapter.

    File origins, pending-file ENOENT, full inventory and native hash-chain
    authentication remain mandatory independent collector/lifecycle gates.
    """
    need(set(bundle) == {'intent', 'receipt', 'client_claim', 'client_result', 'client_inspection', 'stdout', 'stderr'},
         'complete original r6 bundle required')
    need(all(isinstance(v, bytes) for v in bundle.values()), 'original bytes required')
    intent, receipt, claim, client, inspected = (strict(bundle[k]) for k in
        ('intent', 'receipt', 'client_claim', 'client_result', 'client_inspection'))
    args = call['argv']; command = base64.b64decode(args[6], validate=True)
    need(len(args) == 9 and args[:3] == ['/usr/bin/python3', CLIENT, 'execute']
         and args[3] == '--action-id' and args[5] == '--command-b64'
         and args[7:] == ['--timeout-ms', '60000'], 'fixed reviewed r6 wire differs')
    for row in (intent, receipt):
        need(row.get('version') == 1 and row.get('executor_revision') == 6
             and row.get('action_id') == args[4] and row.get('command_sha256') == sha(command)
             and row.get('server_instance') == server_instance and row.get('executor_context') == PARENT
             and row.get('peer_context') == BOOTSTRAP and row.get('peer_uid') == 0
             and row.get('timeout_ms') == 60000 and row.get('can_redispatch') is False,
             'r6 command/generation/admission binding differs')
    need(intent.get('created_unix_ms') == receipt.get('created_unix_ms')
         and type(intent.get('created_unix_ms')) is int and intent['created_unix_ms'] > 0,
         'r6 original intent timestamp differs')
    need(receipt.get('state') == 'completed' and receipt.get('terminal') is True
         and receipt.get('exit_code') == expected_exit and type(receipt.get('exit_code')) is int
         and receipt.get('execution_context') == WORKER
         and receipt.get('execution_credentials_scope') == 'android_shell_uid2000'
         and receipt.get('handshake_stage') == 'worker_entry_after_exec_transition'
         and receipt.get('waitpid_identity_lost') is False
         and type(receipt.get('pid')) is int and receipt['pid'] > 1
         and receipt.get('pgid') == receipt['pid'] and receipt.get('dispatch_count') == 1,
         'r6 original worker terminal differs')
    for key in ('intent_parent_sync_complete', 'effect_started', 'process_group_established',
                'waitpid_joined', 'process_group_absent', 'execution_credentials_verified',
                'supplementary_groups_cleared', 'worker_domain_verified'):
        need(receipt.get(key) is True, 'r6 worker lifecycle incomplete: ' + key)
    for key in ('required_execution_uid', 'required_execution_gid', 'execution_uid', 'execution_euid',
                'execution_gid', 'execution_egid'):
        need(type(receipt.get(key)) is int and receipt[key] == 2000, 'r6 worker credentials differ')
    need(type(receipt.get('execution_supplementary_group_count')) is int
         and receipt['execution_supplementary_group_count'] == 0, 'worker supplementary groups')
    need(claim.get('version') == 1 and claim.get('client_revision') == 6
         and claim.get('client_source_sha256') == CLIENT_SHA and claim.get('endpoint') == 'hepta_phone_executor_v150_r6'
         and claim.get('state') == 'intent' and claim.get('action_id') == args[4]
         and claim.get('command_sha256') == sha(command) and claim.get('timeout_ms') == 60000,
         'original client claim differs')
    # R6 deliberately omits output duplication in its durable .result.json.
    # Keep that original distinct from this separately recorded read-only
    # inspect(include_output=true) observation; never fill fields into it.
    need(set(client) == {'version', 'protocol', 'duplicate', 'receipt', 'client_transport'}
         and client.get('version') == 1 and client.get('protocol') == 'hepta_phone_local_v150'
         and client.get('duplicate') is False and client.get('receipt') == receipt
         and isinstance(client.get('client_transport'), dict), 'original saved client result differs')
    need(set(inspected) == {'version', 'protocol', 'duplicate', 'receipt', 'stdout_b64', 'stderr_b64'}
         and inspected.get('version') == 1 and inspected.get('protocol') == 'hepta_phone_local_v150'
         and inspected.get('duplicate') is False and inspected.get('receipt') == receipt,
         'independent read-only client inspection differs')
    for key in ('stdout', 'stderr'):
        need(bundle[key] == streams[key] and len(bundle[key]) == receipt.get(key + '_bytes')
             and sha(bundle[key]) == receipt.get(key + '_sha256')
             and base64.b64decode(inspected[key + '_b64'], validate=True) == bundle[key],
             'original native/client/sidecar stream bytes differ')
    return receipt


class NativeGuardSession:
    """Two real native calls; no model rounds, listener, subprocess or fallback."""
    def __init__(self, contract_raw, owner_raw, run_dir, claim_dir, mapper, phone, guards):
        self.contract = strict(contract_raw); c = self.contract
        need(set(c) == {'schema', 'case_id', 'nonce', 'owner_request_sha256', 'selected_session_id',
             'selected_profile_id', 'source_seal_sha256', 'configuration_sha256', 'executor_server_instance'}
             and c['schema'] == 'hepta.native-guard-component.contract.v150.r10.1'
             and c['case_id'] in ('NEG-01', 'NEG-02'), 'explicit new component contract required')
        need(re.fullmatch('[0-9a-f]{32}', c['nonce']) and re.fullmatch('[0-9a-f]{32}', c['executor_server_instance']),
             'component nonce/instance shape')
        need(all(isinstance(c[k], str) and re.fullmatch('[0-9a-f]{64}', c[k])
                 for k in ('owner_request_sha256', 'source_seal_sha256', 'configuration_sha256')), 'component pins')
        need(isinstance(owner_raw, bytes) and 20 <= len(owner_raw) <= 16000 and b'\0' not in owner_raw
             and sha(owner_raw) == c['owner_request_sha256'] and owner_raw.decode().count(c['nonce']) == 1,
             'exact component owner request differs')
        need(all(isinstance(c[k], str) and 0 < len(c[k].encode()) <= 256 and '\0' not in c[k]
                 for k in ('selected_session_id', 'selected_profile_id')), 'selected session/profile')
        self.run = Path(run_dir); self.claims = Path(claim_dir)
        for p in (self.run, self.claims):
            s = p.lstat(); need(p.resolve() == p and stat.S_ISDIR(s.st_mode)
                and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700, 'private canonical state')
        need(mapper.binding is None and mapper.run_dir == self.run and not mapper.calls,
             'fresh actual production mapper required')
        self.mapper, self.phone, self.guards = mapper, phone, guards
        self.owner_raw, self.contract_sha = owner_raw, sha(contract_raw)
        self.state = 'NEW'; self.in_seq = 0; self.out_seq = 0; self.scope = None
        self.pending = None; self.capture = None; self.before_public = None; self.captured_at = None
        self.outbound = []; self.setup = None; self.unknown = False
        put(self.run / 'component-contract.original.json', contract_raw)
        put(self.run / 'owner-request.original.txt', owner_raw)

    def _frame(self, kind, **fields):
        value = {'protocol': PROTOCOL, 'seq': self.out_seq, 'kind': kind, **fields}
        raw = encoded(value); need(len(raw) <= MAX_FRAME, 'outgoing frame bound')
        put(self.run / ('provider-out-%02d.jsonl' % self.out_seq), raw)
        self.out_seq += 1; self.outbound.append(value)
        return raw

    def start(self, raw):
        need(self.state == 'NEW' and len(raw) <= MAX_FRAME and raw.endswith(b'\n'), 'one original start required')
        value = strict(raw); turn = value.get('turn')
        need(set(value) == {'protocol', 'seq', 'kind', 'turn'} and value['protocol'] == PROTOCOL
             and type(value['seq']) is int and value['seq'] == 0 and value['kind'] == 'turn.start'
             and isinstance(turn, dict) and set(turn) == set(KEYS) | {'user_input'}, 'native start shape')
        need(all(isinstance(turn[k], str) and 0 < len(turn[k].encode()) <= 256 and '\0' not in turn[k]
                 for k in KEYS) and turn['user_input'].encode() == self.owner_raw,
             'actual native scope or original owner changed')
        need(all(turn[k] == self.contract['selected_' + k] for k in ('session_id', 'profile_id')),
             'native selected session/profile changed')
        self.scope = {k: turn[k] for k in KEYS}
        put(self.claims / (self.contract['nonce'] + '.json'), {'schema': 'hepta.native-guard-component.claim.v1',
            'scope': self.scope, 'contract_sha256': self.contract_sha, 'state': 'accepted_never_reuse',
            'run_dir': str(self.run), 'model_requests': 0})
        put(self.run / 'provider-in-00.jsonl', raw)
        self.mapper.bind(self.scope)
        # There is no business task template or outcome in this component route.
        # The kernel exposes only screenshot and one guarded tap of the same probe package.
        resolved = self.mapper.configure_task_app_scope(None, sha(self.owner_raw))
        put(self.run / 'task-app-scope.json', resolved)
        self.state = 'BOUND'; self.in_seq = 1

    def setup_witness(self, public_raw, operation_id):
        need(self.state == 'BOUND' and self.setup is None and self.contract['case_id'] == 'NEG-02',
             'one original pre-capture public witness required')
        state, page, viewport = public_state(public_raw, operation_id, self.phone, self.guards)
        need(state[INPUT]['focused'] == 'true' and state[INPUT]['text']
             and state[RECEIPT]['text'] == '等待输入', 'setup focus/public Submit witness not ready')
        self.setup = (state, page, viewport)
        put(self.run / 'setup-public.original.json', public_raw)

    def _call(self, tool, phase, argv, trace=False):
        call_id = 'guard_' + self.contract['nonce'] + '_' + phase
        put(self.run / (phase + '.reservation.json'), {'state': 'reserved_before_mapping_no_retry',
            'scope': self.scope, 'call_id': call_id, 'contract_sha256': self.contract_sha})
        self.state = phase.upper() + '_RESERVED'
        decision = {'kind': 'tool.call', 'tool': tool, 'call_id': call_id, 'argv': argv,
                    'command': '', 'summary': 'explicit native component phase', 'task_status': 'in_progress'}
        self.mapper.map(decision)
        semantic = self.mapper.calls[call_id]; original = copy.deepcopy(semantic['wire_call'])
        args = original['argv']; need(original['tool'] == 'shell.exec' and len(args) == 9
            and args[:3] == ['/usr/bin/python3', CLIENT, 'execute'] and args[3] == '--action-id'
            and args[5] == '--command-b64' and args[7:] == ['--timeout-ms', '60000'], 'original mapped r6 call')
        command = base64.b64decode(args[6], validate=True); command.decode()
        need(0 < len(command) <= 128 * 1024 and b'\0' not in command, 'mapped shell command bound')
        call = copy.deepcopy(original)
        if trace:
            call['argv'][6] = base64.b64encode(b'set -x; ' + command).decode()
        put(self.run / (phase + '.original-command.sh'), command)
        put(self.run / (phase + '.native-command.sh'), base64.b64decode(call['argv'][6], validate=True))
        put(self.run / (phase + '.dispatch-intent.json'), {'schema': 'hepta.native-guard-component.dispatch.v1',
            'scope': self.scope, 'original_mapper_call': original, 'actual_native_call': call,
            'trace_prefix': 'set -x; ' if trace else '', 'action_id': args[4],
            'original_command_sha256': sha(command), 'actual_command_sha256': sha(base64.b64decode(call['argv'][6])),
            'dispatch_may_be_unknown': True, 'automatic_retry': False, 'model_requests': 0})
        self.pending = call
        return self._frame('tool.call', call=call)

    def capture_call(self):
        need(self.state == 'BOUND' and (self.contract['case_id'] == 'NEG-01' or self.setup is not None),
             'capture prerequisites missing or already reserved')
        return self._call('phone.screenshot', 'capture', ['0'])

    def capture_result(self, raw, originals):
        need(self.state == 'CAPTURE_RESERVED', 'no current capture')
        # Consumption is irreversible even if a parser rejects these bytes.
        self.state = 'CAPTURE_RESULT_CONSUMED_UNKNOWN'
        put(self.run / 'provider-in-01.jsonl', raw)
        value, streams = native_streams(raw, 1, self.pending)
        need(value['terminal']['exit_code'] == 0 and not streams['stderr'], 'capture native failure retained')
        verify_r6(originals, self.pending, streams, self.contract['executor_server_instance'], 0)
        content = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
        messages = [{'role': 'user', 'content': self.owner_raw.decode()},
                    {'role': 'tool', 'tool_call_id': self.pending['call_id'], 'content': content}]
        self.mapper.prepare(messages, copy.deepcopy(messages), 2)
        latest = self.mapper.latest; need(latest is not None, 'production capture parser did not admit image')
        expected = VISUAL if self.contract['case_id'] == 'NEG-01' else TEXT
        need(latest['observed_page']['component'] == expected, 'capture was not intended public fixture')
        if self.setup:
            need((latest['page_state'], latest['viewport']) == self.setup[1:], 'setup/capture page differs')
        self.capture = copy.deepcopy(latest); self.captured_at = latest['received_monotonic']
        put(self.run / 'capture-phase.json', {'capture': self.capture, 'component_phase': 2,
            'model_rounds': 0, 'root_disturbance_required': True, 'automatic_recapture': False})
        self.state = 'WAITING_ROOT_WITNESS'; self.in_seq = 2

    def before_guard_witness(self, public_raw, operation_id, png_raw):
        need(self.state == 'WAITING_ROOT_WITNESS' and 0 <= time.monotonic() - self.captured_at <= 120,
             'capture expired or disturbance already consumed')
        state, page, viewport = public_state(public_raw, operation_id, self.phone, self.guards)
        need(state[RECEIPT]['text'] == '等待输入', 'Submit witness already changed')
        need(isinstance(png_raw, bytes) and 32 <= len(png_raw) <= 16 * 1024 * 1024
             and png_raw[:8] == b'\x89PNG\r\n\x1a\n' and png_raw[12:16] == b'IHDR'
             and struct.unpack('>II', png_raw[16:24]) == (1224, 2992), 'original operator PNG geometry')
        if self.contract['case_id'] == 'NEG-01':
            need(self.guards.page_state(page)['component'] != self.capture['observed_page']['component'],
                 'foreground was not independently changed')
        else:
            need(page == self.capture['page_state'] and viewport == self.capture['viewport']
                 and sha(png_raw) != self.capture['source_png_sha256'], 'same-page changed-pixel prerequisite')
            prior = copy.deepcopy(self.setup[0]); changed = copy.deepcopy(state)
            need(prior[INPUT]['text'] != changed[INPUT]['text'], 'controlled edit did not change actual text')
            prior[INPUT].pop('text'); changed[INPUT].pop('text')
            need(prior == changed, 'controlled edit changed other public witness fields')
        self.before_public = state; self.guard_page = page; self.guard_viewport = viewport
        put(self.run / 'before-guard-public.original.json', public_raw)
        put(self.run / 'before-guard.png', png_raw)
        put(self.run / 'before-guard-witness.json', {'scope': self.scope, 'contract_sha256': self.contract_sha,
            'capture_call_id': self.capture['call_id'], 'page_sha256': sha(page.encode()),
            'viewport_sha256': sha(viewport.encode()), 'png_sha256': sha(png_raw),
            'public_state': state, 'operator_origin_not_native_result': True})
        self.state = 'ROOT_DISTURBANCE_OBSERVED'

    def guard_call(self):
        need(self.state == 'ROOT_DISTURBANCE_OBSERVED' and 0 <= time.monotonic() - self.captured_at <= 120,
             'one current disturbed capture required')
        bound = self.before_public[SUBMIT]['bounds']
        x1, y1, x2, y2 = map(int, re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bound).groups())
        w, h = self.capture['encoded_size']
        x, y = round((x1 + x2) * w / (2 * 1224)), round((y1 + y2) * h / (2 * 2992))
        ox, oy = (2 * x * 1224 + w) // (2 * w), (2 * y * 2992 + h) // (2 * h)
        need(0 <= x < w and 0 <= y < h and x1 < ox < x2 and y1 < oy < y2,
             'projected point is not inside the actual public Submit control')
        self.mapper.round = 2
        need(self.mapper.latest == self.capture, 'current capture changed')
        frame = self._call('phone.tap', 'guard', [self.capture['call_id'], str(x), str(y)], trace=True)
        need(self.mapper.latest is None, 'production mapper failed to consume the image')
        return frame

    def guard_result(self, raw, originals):
        need(self.state == 'GUARD_RESERVED', 'no original pending guard')
        self.state = 'GUARD_RESULT_CONSUMED_UNKNOWN'
        put(self.run / 'provider-in-02.jsonl', raw)
        value, streams = native_streams(raw, 2, self.pending)
        expected = 70 if self.contract['case_id'] == 'NEG-01' else 71
        need(value['terminal']['exit_code'] == expected and not streams['stdout'], 'guard did not reject as expected')
        verify_r6(originals, self.pending, streams, self.contract['executor_server_instance'], expected)
        commands = []
        for line in streams['stderr'].decode('utf-8', 'strict').splitlines():
            match = re.match(r'^\++\s+(.*)$', line)
            if match:
                try:
                    commands.append(shlex.split(match[1], posix=True))
                except ValueError:
                    pass  # Multiline page arguments are not command boundaries.
        need(commands and not any(words and words[0] in {'input', '/system/bin/input'} for words in commands),
             'original trace absent or input command observed')
        need(['exit', str(expected)] in commands, 'trace lacks actual guard exit')
        if expected == 71:
            pairs = [(r[1], r[3]) for r in commands if len(r) == 5 and r[0] == '['
                     and r[2] == '=' and r[4] == ']' and re.fullmatch('[0-9a-f]{64}', r[1])
                     and r[3] == self.capture['source_png_sha256']]
            need(len(pairs) == 1 and pairs[0][0] != pairs[0][1], 'actual unequal PNG comparison not proven')
            self.actual_guard_png_sha256 = pairs[0][0]
        put(self.run / 'negative-guard-observed.json', {'scope': self.scope, 'case_id': self.contract['case_id'],
            'guard_exit_code': expected, 'trace_sha256': sha(streams['stderr']), 'input_observed_in_trace': False,
            'worker_entry_is_not_ui_effect_proof': True, 'model_requests': 0,
            'native_turn_hash_chain_verified': False, 'component_qualified': False})
        self.state = 'WAITING_ROOT_AFTER_WITNESS'; self.in_seq = 3

    def after_guard_witness(self, public_raw, operation_id):
        need(self.state == 'WAITING_ROOT_AFTER_WITNESS', 'after witness out of order')
        state, page, viewport = public_state(public_raw, operation_id, self.phone, self.guards)
        need(state == self.before_public and page == self.guard_page and viewport == self.guard_viewport,
             'independent public effect witness/focus/viewport changed')
        put(self.run / 'after-guard-public.original.json', public_raw)
        put(self.run / 'component-observation.json', {'state': 'GUARD_AND_PUBLIC_WITNESS_OBSERVED',
            'scope': self.scope, 'contract_sha256': self.contract_sha, 'native_calls': 2, 'model_requests': 0,
            'business_qualified': False, 'component_qualified': False,
            'remaining_gates': ['original native five-scope hash-chain and terminal',
                'original client/sidecar file provenance and pending ENOENT',
                'Root observation original command/receipt provenance',
                'component process/worker retirement and late full preservation inventory']})
        self.state = 'PROVIDER_TERMINAL_RESERVED'
        return self._frame('turn.complete', summary='组件观察阶段已记录；无模型调用、无业务通过声明，等待独立原生终态与保留清单审计。')

    def cancel(self, raw):
        need(self.state not in {'NEW', 'PROVIDER_TERMINAL_RESERVED', 'CANCELLED'}, 'no cancellable accepted component')
        value = strict(raw)
        need(value.get('protocol') == PROTOCOL and type(value.get('seq')) is int and value['seq'] == self.in_seq
             and value.get('kind') == 'turn.cancel', 'original native cancellation sequence differs')
        put(self.run / 'native-cancel.original.jsonl', raw)
        self.state = 'CANCELLED'
        return self._frame('turn.cancelled', summary='组件已取消；保留原调用状态，不重发，原工具和进程终态需独立核验。')


if __name__ == '__main__':
    print(json.dumps({'state': 'SOURCE_ONLY_KERNEL_NO_LISTENER', 'phone_calls': 0,
        'model_requests': 0, 'real_nonces_generated': 0, 'deployment_authorized_here': False,
        'requires': 'Separately reviewed actual lifecycle/listener and original-evidence adapters.'}))
