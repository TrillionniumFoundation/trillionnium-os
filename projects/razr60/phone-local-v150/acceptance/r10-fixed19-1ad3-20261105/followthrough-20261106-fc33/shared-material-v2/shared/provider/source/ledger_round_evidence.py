"""Original intent-prefix evidence. Observation only; never authorizes replay.

The original ActionLedger remains the reservation/resolve authority. Every
write here precedes the native frame. A failure after reserve deliberately
leaves the real intent UNKNOWN and propagates; it is not cancellation, transport
closure, a receipt, or permission to retry.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from action_ledger import MUTATIONS
from provider_openai_compatible import ProviderError
from task_postconditions import write_exclusive

SCOPE_FIELDS = ('session_id', 'profile_id', 'task_id', 'turn_id', 'turn_stream_id')
MAX_INTENTS = 256
MAX_INTENT_BYTES = 16384
AUXILIARY_LIMITS = {'.resolution.json': 16384, '.inspection.json': 16384,
                    '.retirement-proof.json': 262144}
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ProviderError('ledger prefix evidence: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode()


def stat_key(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def read_original(path, limit=MAX_EVIDENCE_BYTES):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) == 0o600
                and 0 < before.st_size <= limit, 'original file identity/bound differs')
        blocks, size = [], 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            blocks.append(block)
            size += len(block)
            require(size <= limit, 'original file exceeds bound')
        raw = b''.join(blocks)
        after, named = os.fstat(fd), path.lstat()
        require(len(raw) == before.st_size
                and stat_key(before) == stat_key(after) == stat_key(named),
                'original file changed during read')
        return raw
    finally:
        os.close(fd)


def intent_entry(path, expected_sha):
    raw = read_original(path, MAX_INTENT_BYTES)
    require(sha(raw) == expected_sha, 'locked intent bytes differ from original ledger read')
    return {'name': path.name, 'bytes': len(raw), 'sha256': expected_sha,
            'raw_base64': base64.b64encode(raw).decode('ascii')}


def inventory(entries):
    return [{key: entries[name][key] for key in ('name', 'bytes', 'sha256')}
            for name in sorted(entries)]


class LedgerPrefix:
    def __init__(self, ledger, run_dir, scope, owner_text):
        self.ledger, self.run_dir = ledger, Path(run_dir)
        require(set(scope) == set(SCOPE_FIELDS)
                and all(isinstance(scope[k], str) and scope[k] for k in SCOPE_FIELDS),
                'accepted native scope differs')
        require(isinstance(owner_text, str) and owner_text and '\0' not in owner_text,
                'original owner text differs')
        self.scope, self.owner_sha = dict(scope), sha(owner_text.encode('utf-8', errors='strict'))
        self.directory = self.run_dir/'ledger-prefix'
        self.events, self.bindings, self.round_pending = [], [], None
        self.directory.mkdir(mode=0o700)
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700
                and self.directory.resolve() == self.directory,
                'private canonical evidence directory required')
        parent_fd = os.open(self.run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        with self.ledger.exclusive():
            rows, entries = self._locked_originals()
            self.entries = entries
            auxiliaries = self._locked_auxiliaries(rows)
            source = Path(__file__).resolve().parent
            pins = {name: sha((source/name).read_bytes()) for name in
                    ('ledger_round_evidence.py', 'provider_phone_local.py', 'action_ledger.py')}
            baseline = {
                'schema': 'hepta.ledger-baseline.v150.2',
                'scope': self.scope, 'semantic_identity': {k:self.scope[k] for k in SCOPE_FIELDS[:-1]},
                'owner_request_sha256': self.owner_sha, 'original_run_dir': str(self.run_dir),
                'source_sha256': pins, 'initial_intents': [entries[k] for k in sorted(entries)],
                'initial_inventory': inventory(entries),
                'initial_auxiliary_originals': auxiliaries,
                'initial_auxiliary_inventory_sha256': sha(canonical([
                    {k:v for k,v in row.items() if k != 'raw_base64'} for row in auxiliaries])),
                'auxiliary_absence_is_initial_observation_only': True,
                'inventory_sha256': sha(canonical(inventory(entries))),
                'same_lock_as_original_reservation': True,
                'observation_only': True, 'automatic_replay': False}
            self.baseline_sha = self._write('baseline.json', baseline)
        self.head = self.baseline_sha

    def _write(self, name, value):
        require(re.fullmatch(r'[a-z0-9.-]+\.json', name) is not None,
                'evidence filename differs')
        require(len(canonical(value)) + 1 <= MAX_EVIDENCE_BYTES, 'evidence exceeds bound')
        return write_exclusive(self.directory/name, value)

    def _locked_originals(self):
        require(self.ledger.lock_depth > 0, 'original ledger lock not held')
        rows = self.ledger.intents()
        require(len(rows) <= MAX_INTENTS, 'intent evidence count exceeds bound')
        names = sorted(path.name for path in self.ledger.directory.glob('*.intent.json'))
        expected = sorted(value['action_id'] + '.intent.json' for value, _sha, _res in rows)
        require(names == expected and len(names) == len(set(names)),
                'complete original intent inventory differs')
        entries = {}
        for value, digest, _resolution in rows:
            name = value['action_id'] + '.intent.json'
            require(re.fullmatch(r'[0-9a-f]{32}\.intent\.json', name) is not None,
                    'original intent filename differs')
            entries[name] = intent_entry(self.ledger.directory/name, digest)
        require(names == sorted(path.name for path in self.ledger.directory.glob('*.intent.json')),
                'original intent inventory changed under lock')
        return rows, entries


    def _locked_auxiliaries(self, rows):
        require(self.ledger.lock_depth > 0, 'original ledger lock not held')
        names = sorted(os.listdir(self.ledger.directory))
        require(len(names) <= 1024, 'original ledger directory exceeds bound')
        result = []
        for intent, _digest, resolution in rows:
            token = intent['action_id']
            for suffix, limit in sorted(AUXILIARY_LIMITS.items()):
                name = token + suffix
                try:
                    raw = read_original(self.ledger.directory/name, limit)
                except FileNotFoundError:
                    require(name not in names, 'named auxiliary disappeared under lock')
                    value = {'name': name, 'state': 'absent', 'lookup_errno': 2}
                    original = None
                else:
                    require(name in names, 'unnamed auxiliary appeared under lock')
                    value = {'name': name, 'state': 'captured', 'bytes': len(raw),
                             'sha256': sha(raw), 'raw_base64': base64.b64encode(raw).decode('ascii')}
                    original = json.loads(raw)
                if suffix == '.resolution.json':
                    require(original == resolution,
                            'original resolution differs from locked ledger read')
                result.append(value)
        require(names == sorted(os.listdir(self.ledger.directory)),
                'original ledger directory changed during baseline auxiliary read')
        return sorted(result, key=lambda value: value['name'])

    def _same_originals(self, entries):
        require(entries == self.entries,
                'untracked original intent addition/removal/change; no new model request')

    def before_request(self, number, request_id, allowed_call_id):
        require(self.round_pending is None and type(number) is int
                and number == len(self.bindings) + 1 and 1 <= number <= 8
                and isinstance(request_id, str) and re.fullmatch('[0-9a-f]{32}', request_id)
                and allowed_call_id == 'r%02d_%s' % (number, request_id[:16]),
                'request/round sequence differs')
        with self.ledger.exclusive():
            rows, entries = self._locked_originals()
            self._same_originals(entries)
            previous = self.bindings[-1]['sha256'] if self.bindings else None
            if self.bindings:
                item = self.bindings[-1]
                require(sha(read_original(self.directory/item['name'])) == item['sha256'],
                        'previous request binding changed')
            value = {
                'schema': 'hepta.ledger-round-boundary.v150.1',
                'scope': self.scope, 'owner_request_sha256': self.owner_sha,
                'round': number, 'request_id': request_id, 'allowed_call_id': allowed_call_id,
                'baseline_sha256': self.baseline_sha,
                'previous_request_binding_sha256': previous,
                'reservation_prefix': list(self.events),
                'reservation_chain_head_sha256': self.head,
                'intent_inventory': inventory(entries),
                'inventory_sha256': sha(canonical(inventory(entries))),
                'boundary': 'original_locked_intents_before_request_file_and_http',
                'observation_only': True, 'automatic_replay': False}
            digest = self._write('round-%02d-boundary.json' % number, value)
            self.round_pending = {'number': number, 'request_id': request_id,
                                  'allowed_call_id': allowed_call_id, 'boundary_sha256': digest}
            return rows, digest

    def bind_request(self, prefix):
        pending = self.round_pending
        require(pending is not None
                and prefix == self.run_dir/('local-%02d' % pending['number']),
                'request binding has no original boundary')
        raw = read_original(prefix.with_suffix('.request.json'))
        excluded = read_original(prefix.with_suffix('.open-replay-exclusions.json'))
        clock = read_original(prefix.with_suffix('.schema-clock.json'))
        value = {
            'schema': 'hepta.ledger-request-binding.v150.1',
            'scope': self.scope, 'owner_request_sha256': self.owner_sha,
            'round': pending['number'], 'request_id': pending['request_id'],
            'allowed_call_id': pending['allowed_call_id'],
            'baseline_sha256': self.baseline_sha,
            'boundary_sha256': pending['boundary_sha256'],
            'request_file': prefix.name + '.request.json',
            'request_sha256': sha(raw), 'request_bytes': len(raw),
            'exclusions_sha256': sha(excluded), 'schema_clock_sha256': sha(clock),
            'binding_before_http_worker_spawn': True,
            'observation_only': True, 'automatic_replay': False}
        name = 'round-%02d-request.json' % pending['number']
        digest = self._write(name, value)
        self.bindings.append({'name': name, 'sha256': digest, 'value': value})
        self.round_pending = None

    def reserve_before_frame(self, record):
        require(self.round_pending is None and self.bindings,
                'native reservation has no committed request binding')
        binding = self.bindings[-1]
        value = binding['value']
        require(record['call_id'] == value['allowed_call_id'],
                'native reservation belongs to a different request')
        with self.ledger.exclusive():
            _rows, entries = self._locked_originals()
            self._same_originals(entries)
            require(sha(read_original(self.directory/binding['name'])) == binding['sha256'],
                    'original request binding changed before reserve')
            # The original guard is authoritative and fsyncs its intent first.
            # Any exception after it returns leaves the actual UNKNOWN intent.
            # No cancellation/transport reason or resolution is fabricated here.
            self.ledger.reserve(record, self.scope)
            if record['semantic_tool'] not in MUTATIONS:
                return
            _rows, after = self._locked_originals()
            name = record['capture_id'] + '.intent.json'
            require(name not in entries and set(after) == set(entries) | {name}
                    and all(after[key] == entries[key] for key in entries),
                    'original reservation inventory is not exactly one new intent')
            semantic_path = self.run_dir/('semantic-' + sha(record['call_id'].encode()) + '.json')
            semantic_raw = read_original(semantic_path)
            require(json.loads(semantic_raw) == record,
                    'reservation differs from original typed semantic record')
            entry = after[name]
            event_number = len(self.events) + 1
            event = {
                'schema': 'hepta.ledger-reservation-event.v150.1',
                'scope': self.scope, 'owner_request_sha256': self.owner_sha,
                'baseline_sha256': self.baseline_sha, 'event_number': event_number,
                'previous_event_sha256': self.head,
                'round': value['round'], 'request_id': value['request_id'],
                'request_binding_sha256': binding['sha256'],
                'request_sha256': value['request_sha256'],
                'call_id': record['call_id'], 'action_id': record['capture_id'],
                'semantic_tool': record['semantic_tool'], 'semantic_file': semantic_path.name,
                'semantic_sha256': sha(semantic_raw),
                'wire_call_canonical_sha256': sha(canonical(record['wire_call'])),
                'intent': entry, 'inventory_after_sha256': sha(canonical(inventory(after))),
                'phase': 'original_reserve_durable_before_native_tool_frame',
                'native_dispatch_asserted': False, 'execution_success_asserted': False,
                'observation_only': True, 'automatic_replay': False}
            event_name = 'reservation-%03d.json' % event_number
            digest = self._write(event_name, event)
            self.entries, self.head = after, digest
            self.events.append({'name': event_name, 'sha256': digest})
