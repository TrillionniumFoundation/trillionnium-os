"""Durable no-replay admission for typed phone mutations.

A new call_id is not new authority for the same recorded effect. Pending effects
block later mutations until an original receipt is independently inspected.
"""
import datetime
import base64
import contextlib
import fcntl
import threading
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from provider_openai_compatible import ProviderError, MAX_LINE
from task_postconditions import private_directory, private_json, write_exclusive
from retirement_recovery import (EXECUTOR_BINDING, ACTION_ID, RESOLUTION_STATE, PROOF_SHA256,
    VERIFIER_SHA256, ORIGINAL_EXECUTOR, validate_proof, retain_original_proof,
    validate_retired_resolution, require_r6_terminal)

MUTATIONS = {'phone.open_app', 'phone.tap', 'phone.input_text', 'phone.return_hepta',
             'phone.swipe', 'phone.long_press', 'phone.back', 'phone.home'}
BUSINESS_MUTATIONS = {'phone.tap', 'phone.input_text', 'phone.swipe', 'phone.long_press',
                      'phone.back', 'phone.home'}


def require(ok, message):
    if not ok:
        raise ProviderError('[action_no_replay] ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(record):
    kind = record['semantic_tool']
    if kind == 'phone.input_text':
        detail = {'kind': kind, 'package': record['package'], 'view_id': record['view_id'],
                  'before_utf8_sha256': sha(record['expected_text'].encode()),
                  'requested_utf8_sha256': record['requested_utf8_sha256']}
    elif kind in {'phone.tap', 'phone.swipe', 'phone.long_press', 'phone.back', 'phone.home'}:
        detail = {'kind': kind, 'package': record['package'],
                  'source_png_sha256': record['source_png_sha256'],
                  'page_state_sha256': record['page_state_sha256']}
        if kind in {'phone.tap', 'phone.long_press'}:
            detail['original_xy'] = record['original_xy']
        elif kind == 'phone.swipe':
            detail.update(original_start_xy=record['original_start_xy'],
                          original_end_xy=record['original_end_xy'])
        if kind in {'phone.swipe', 'phone.long_press'}:
            detail['duration_ms'] = record['duration_ms']
    elif kind == 'phone.open_app':
        detail = {'kind': kind, 'component': record['component']}
        navigation = record.get('navigation_reentry')
        if navigation is not None:
            # A fresh call or screenshot ID alone does not create a new
            # effect. This epoch advances only after the prior target launch
            # has an independently validated native receipt and a departure.
            detail.update(previous_verified_open_action_id=navigation['previous_action_id'],
                          source_component=navigation['source_component'],
                          source_page_state_sha256=navigation['source_page_state_sha256'],
                          source_viewport_sha256=navigation['source_viewport_sha256'])
    elif kind == 'phone.return_hepta':
        detail = {'kind': kind, 'component': 'org.trillionnium.owneropen/.OwnerOpenShellActivity'}
    else:
        return None
    return sha(json.dumps(detail, sort_keys=True, separators=(',', ':')).encode())


def locked(method):
    def wrapped(self, *args, **kwargs):
        with self.exclusive():
            return method(self, *args, **kwargs)
    return wrapped


class ActionLedger:
    def __init__(self, evidence, run_dir):
        self.directory = Path(evidence)/'action-ledger'
        self.directory.mkdir(mode=0o700, exist_ok=True)
        private_directory(self.directory)
        parent_fd = os.open(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.run_dir = Path(run_dir)
        self.mutex = threading.RLock()
        self.lock_depth = 0
        self.lock_fd = None

    @contextlib.contextmanager
    def exclusive(self):
        with self.mutex:
            if self.lock_depth == 0:
                fd = os.open(self.directory/'ledger.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                try:
                    info = os.fstat(fd)
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                            'action ledger lock identity differs')
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except BaseException:
                    os.close(fd)
                    raise
                self.lock_fd = fd
            self.lock_depth += 1
            try:
                yield
            finally:
                self.lock_depth -= 1
                if self.lock_depth == 0:
                    fd, self.lock_fd = self.lock_fd, None
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)

    @locked
    def intents(self):
        rows = []
        for path in sorted(self.directory.glob('*.intent.json')):
            item = private_json(path)
            require(item is not None, 'action intent disappeared during inspection')
            value, digest = item
            require(isinstance(value, dict) and value.get('schema') in {'hepta.action-intent.v150.1', 'hepta.action-intent.v150.2'}
                    and path.name == value.get('action_id', '') + '.intent.json',
                    'action intent identity/schema differs')
            if value['schema'] == 'hepta.action-intent.v150.2':
                require(value.get('executor_binding') == EXECUTOR_BINDING,
                        'new action intent is not bound to the pinned r6 executor')
            resolved = private_json(self.directory/(value['action_id']+'.resolution.json'))
            if resolved is not None:
                resolution, _digest = resolved
                if resolution.get('schema') == 'hepta.action-resolution.v150.2':
                    validate_retired_resolution(self.directory, value, digest, resolution)
                else:
                    require(resolution.get('schema') == 'hepta.action-resolution.v150.1'
                            and resolution.get('action_id') == value['action_id']
                            and resolution.get('intent_sha256') == digest
                            and resolution.get('automatic_replay') is False
                            and resolution.get('business_verified') is False,
                            'action resolution lost its original intent binding')
            rows.append((value, digest, None if resolved is None else resolved[0]))
        return rows

    @locked
    def reserve(self, record, identity):
        if record['semantic_tool'] not in MUTATIONS:
            return
        token, effect_key = record['capture_id'], fingerprint(record)
        require(re.fullmatch('[0-9a-f]{32}', token), 'action identity malformed')
        turn_key = {key: identity[key] for key in ('session_id', 'profile_id', 'task_id', 'turn_id')}
        rows = self.intents()
        for previous, _digest, resolution in rows:
            require(resolution is not None,
                    'an original action is unresolved; inspect its sidecar receipt before a new mutation: ' + previous['action_id'])
            if previous['effect_fingerprint'] == effect_key:
                same_turn = previous['semantic_identity'] == turn_key
                independent = False
                if not same_turn and record['semantic_tool'] in BUSINESS_MUTATIONS:
                    independent = self._independent_request(previous, resolution, turn_key)
                require(not same_turn and (record['semantic_tool'] not in BUSINESS_MUTATIONS or independent),
                        'recorded effect already attempted; new call_id/turn cannot replay the same bound effect')
        navigation = record.get('navigation_reentry')
        if navigation is not None:
            require(record['semantic_tool'] == 'phone.open_app',
                    'navigation context cannot authorize another input kind')
            linked = [(value, resolution) for value, _digest, resolution in rows
                      if value['action_id'] == navigation['previous_action_id']]
            require(len(linked) == 1 and linked[0][0]['semantic_identity'] == turn_key
                    and linked[0][0]['semantic_tool'] == 'phone.open_app'
                    and linked[0][0]['call_id'] == navigation['previous_call_id']
                    and linked[0][0]['effect_fingerprint'] == navigation['previous_effect_fingerprint']
                    and linked[0][1] is not None
                    and linked[0][1].get('state') == 'original_native_result_independently_validated',
                    'new navigation requires the original validated launch, never an unknown or merely inspected effect')
        wire = record['wire_call']
        require(wire.get('tool') == 'shell.exec'
                and wire.get('argv', [])[:3] == ['/usr/bin/python3', EXECUTOR_BINDING['client_path'], 'execute'],
                'new mutations must use the exact pinned r6 client')
        if wire['tool'] == 'shell.exec':
            argv = wire['argv']
            index = argv.index('--command-b64')
            import base64
            shell = base64.b64decode(argv[index+1], validate=True)
        else:
            shell = wire['argv'][-1].encode()
        value = {'schema': 'hepta.action-intent.v150.2', 'action_id': token,
                 'executor_binding': dict(EXECUTOR_BINDING),
                 'semantic_identity': turn_key, 'call_id': record['call_id'],
                 'semantic_tool': record['semantic_tool'], 'wire_tool': wire['tool'],
                 'effect_fingerprint': effect_key, 'command_sha256': sha(shell),
                 'run_dir': str(self.run_dir), 'state': 'reserved_before_native_dispatch_result_unknown',
                 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 'automatic_replay': False}
        if navigation is not None:
            value['navigation_reentry'] = dict(navigation)
        write_exclusive(self.directory/(token+'.intent.json'), value)

    def _independent_request(self, previous, resolution, turn_key):
        """New accepted owner turn authority; UI task IDs may span many turns."""
        if (previous['semantic_identity']['turn_id'] == turn_key['turn_id']
                or resolution.get('state') not in {'known_not_dispatched',
                                                  'original_native_result_independently_validated'}):
            return False
        key = sha(json.dumps([turn_key[name] for name in
                  ('session_id', 'profile_id', 'task_id', 'turn_id')], separators=(',', ':')).encode())
        claimed = private_json(self.directory.parent/'claims'/key)
        if claimed is None:
            return False
        claim, _digest = claimed
        if (claim.get('state') != 'accepted_no_redispatch' or claim.get('run_dir') != str(self.run_dir)
                or any(claim.get('identity', {}).get(name) != value for name, value in turn_key.items())
                or re.fullmatch('[0-9a-f]{64}', claim.get('request_sha256', '')) is None):
            return False
        accepted = private_json(self.run_dir/'accepted-owner-request.json', max_bytes=MAX_LINE)
        if accepted is None:
            return False
        owner, _digest = accepted
        if (owner.get('schema') != 'hepta.accepted-owner-request.v150.1'
                or owner.get('source') != 'accepted_turn_start_frame'
                or owner.get('identity') != claim.get('identity')
                or owner.get('request_sha256') != claim['request_sha256']):
            return False
        try:
            request = base64.b64decode(owner.get('request_utf8_b64', ''), validate=True)
            request.decode('utf-8', errors='strict')
        except (TypeError, ValueError, UnicodeError):
            return False
        if (not 0 < len(request) <= MAX_LINE // 2 or b'\0' in request
                or base64.b64encode(request).decode() != owner['request_utf8_b64']
                or sha(request) != claim['request_sha256']):
            return False
        if resolution['state'] == 'original_native_result_independently_validated':
            # Preserve and recheck the original receipt rather than treating a
            # process-only inspect or a model's success claim as verification.
            result = private_json(Path(previous['run_dir'])/('result-'+sha(previous['call_id'].encode())+'.json'),
                                  max_bytes=MAX_LINE)
            if (result is None or result[1] != resolution.get('native_result_sha256')
                    or result[0].get('call_id') != previous['call_id']):
                return False
        return True

    @locked
    def mark_not_dispatched(self, action_id, reason):
        require(reason in {'cancel_before_native_tool_frame', 'transport_closed_before_native_tool_frame'},
                'unsupported known-not-dispatched reason')
        selected = [(value, digest, resolved) for value, digest, resolved in self.intents()
                    if value['action_id'] == action_id and value['run_dir'] == str(self.run_dir)]
        require(len(selected) == 1 and selected[0][2] is None,
                'one owned unresolved pre-dispatch reservation required')
        value, digest, _resolved = selected[0]
        write_exclusive(self.directory/(action_id+'.resolution.json'),
                        {'schema': 'hepta.action-resolution.v150.1', 'action_id': action_id,
                         'intent_sha256': digest, 'state': 'known_not_dispatched',
                         'phase': 'provider_before_native_tool_frame', 'reason': reason,
                         'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         'business_verified': False, 'automatic_replay': False,
                         'original_task_terminal_unchanged': True})

    @locked
    def confirm_validated_results(self, phone_tools):
        # Called only after the actual original native result has passed the
        # typed mapper's full receipt/parser checks, never from model prose.
        facts = set(phone_tools.verified_facts) | set(getattr(phone_tools, 'local_observations', {}))
        for value, digest, resolution in self.intents():
            if resolution is not None or value['run_dir'] != str(self.run_dir) or value['call_id'] not in facts:
                continue
            result = self.run_dir/('result-'+sha(value['call_id'].encode())+'.json')
            raw = result.read_bytes()
            original = json.loads(raw)
            require(original.get('call_id') == value['call_id'], 'validated result call identity differs')
            write_exclusive(self.directory/(value['action_id']+'.resolution.json'),
                            {'schema': 'hepta.action-resolution.v150.1', 'action_id': value['action_id'],
                             'intent_sha256': digest, 'state': 'original_native_result_independently_validated',
                             'native_result_sha256': sha(raw),
                             'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                             'business_verified': False, 'automatic_replay': False,
                             'original_task_terminal_unchanged': True})

    @locked
    def resolve_inspected(self, action_id, inspected):
        require(isinstance(inspected, dict) and inspected.get('version') == 1
                and inspected.get('protocol') == 'hepta_phone_local_v150',
                'authenticated sidecar inspection protocol differs')
        selected = [(value, digest, resolved) for value, digest, resolved in self.intents()
                    if value['action_id'] == action_id]
        require(len(selected) == 1, 'original action intent missing or ambiguous')
        value, digest, resolved = selected[0]
        require(resolved is None, 'original action already resolved; do not rewrite its receipt')
        require(value.get('schema') == 'hepta.action-intent.v150.2'
                and value.get('executor_binding') == EXECUTOR_BINDING,
                'legacy action must not be inspected through the new executor endpoint')
        receipt = inspected.get('receipt')
        require(isinstance(receipt, dict) and receipt.get('action_id') == action_id
                and receipt.get('command_sha256') == value['command_sha256']
                and receipt.get('terminal') is True
                and receipt.get('state') in {'completed', 'failed', 'timed_out', 'cancelled', 'output_limit_exceeded'}
                and receipt.get('effect_started') is True
                and receipt.get('process_group_established') is True
                and receipt.get('waitpid_joined') is True
                and receipt.get('process_group_absent') is True,
                'original effect is still unconfirmed; retain pending gate and do not replay')
        require_r6_terminal(receipt)
        inspection_path = self.directory/(action_id+'.inspection.json')
        existing_inspection = private_json(inspection_path)
        if existing_inspection is None:
            inspection_sha = write_exclusive(inspection_path, inspected)
        else:
            # Recover a crash after the first durable write without overwriting
            # the original inspection or re-executing the action.
            previous, inspection_sha = existing_inspection
            require(previous == inspected, 'retained inspection differs from the original terminal receipt')
        write_exclusive(self.directory/(action_id+'.resolution.json'),
                        {'schema': 'hepta.action-resolution.v150.1', 'action_id': action_id,
                         'intent_sha256': digest, 'state': 'original_sidecar_terminal_independently_inspected',
                         'inspection_sha256': inspection_sha, 'original_effect_state': receipt['state'],
                         'original_exit_code': receipt.get('exit_code'),
                         'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         'business_verified': False, 'automatic_replay': False,
                         'original_task_terminal_unchanged': True})


    @locked
    def resolve_retired(self, action_id, raw_proof, executor_binding):
        """Append a non-execution finding; never manufacture a sidecar terminal."""
        require(action_id == ACTION_ID and executor_binding == EXECUTOR_BINDING,
                'retirement recovery is limited to the original action and new pinned executor')
        rows = self.intents()
        selected = [(value, digest, resolution) for value, digest, resolution in rows
                    if value['action_id'] == action_id]
        require(len(selected) == 1 and selected[0][2] is None,
                'one retained unresolved original action is required; never rewrite a resolution')
        require(all(value['action_id'] == action_id or resolution is not None
                    for value, _digest, resolution in rows),
                'another unresolved action still requires its own original receipt')
        value, digest, _resolution = selected[0]
        proof = validate_proof(raw_proof, value, digest)
        retained = self.directory/(action_id+'.retirement-proof.json')
        proof_sha = retain_original_proof(retained, raw_proof)
        require(proof_sha == PROOF_SHA256, 'retained original proof hash differs')
        resolution = {
            'schema': 'hepta.action-resolution.v150.2', 'action_id': action_id,
            'intent_sha256': digest, 'state': RESOLUTION_STATE,
            'retirement_proof_sha256': proof_sha, 'verifier_sha256': VERIFIER_SHA256,
            'retired_executor': dict(ORIGINAL_EXECUTOR), 'future_executor_binding': dict(EXECUTOR_BINDING),
            'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'business_verified': False, 'automatic_replay': False,
            'original_task_terminal_unchanged': True, 'old_effect_replay_forbidden': True,
        }
        validate_retired_resolution(self.directory, value, digest, resolution)
        write_exclusive(self.directory/(action_id+'.resolution.json'), resolution)
        return resolution
