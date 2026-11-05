"""Root-owned bounded actor using the existing pinned phone transport.
No ADB lifecycle changes or automatic request/effect retries.
"""
from pathlib import Path
import argparse,datetime,hashlib,http.client,json,os,re,shlex,socket,stat,sys,time,types
BASE=Path('/home/alex/razr60-local-model-v150')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
FINGERPRINT='motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys'
PHONE='/data/local/tmp/hepta-phone-local-v150-r1'
def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as s:
  for b in iter(lambda:s.read(1048576),b''):h.update(b)
 return h.hexdigest()
def save(p,value):
 raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as s:s.write(raw);s.flush();os.fsync(s.fileno())
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
# Independent root_stdin kind. The historical shell/push/http branches below
# remain byte-identical and are never a fallback from this branch.
import base64 as _st_b64

ROOT_STDIN_SDK_NAME = 'preserved_ui_package_phase_r7_stdin.py'
ROOT_STDIN_SDK_PIN = {'bytes': 40759, 'sha256': '6da82bcb744fdc7d3757478f1182fedbf448bc024e39e0c0b428adb0212fe696'}  # Exact actual sibling source.
ROOT_STDIN_CONFIG = Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved-ui-package-config.json')
ROOT_STDIN_REQUEST_LIMIT = 131072
ROOT_STDIN_INPUT_LIMIT = 8 * 1024 * 1024
ROOT_STDIN_OUTPUT_LIMIT = 65536
ROOT_STDIN_PHASES = ('inputs.tar.gz', 'stage.py', 'setup.witness.tar.gz',
    'before-guard.witness.tar.gz', 'after-guard.witness.tar.gz', 'CLOSURE.json', 'INVENTORY.json')


def _st_need(value, message):
    if not value:
        raise ValueError(message)


def _st_exact(value, keys, message):
    _st_need(type(value) is dict and set(value) == set(keys), message)


def _st_encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode('utf-8')


def _st_strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            _st_need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def bad_constant(value):
        raise ValueError('non-JSON numeric constant: ' + value)
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=bad_constant)


def _st_meta(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def _st_full9(value, kind):
    _st_need(type(value) is list and len(value) == 9
             and all(type(n) is int and n >= 0 for n in value), 'exact full9 metadata required')
    _st_need((stat.S_ISREG(value[2]) if kind == 'file' else stat.S_ISDIR(value[2]))
             and value[1] > 0 and value[5] > 0, 'original object type or identity differs')


def _st_path(value):
    _st_need(type(value) is str and '\0' not in value and value.startswith('/')
             and value != '/' and str(Path(value)) == value and '..' not in Path(value).parts,
             'one canonical absolute original path required')
    return Path(value)


def _st_pin(value, *, full=False, limit=ROOT_STDIN_INPUT_LIMIT):
    _st_exact(value, {'path', 'bytes', 'sha256', 'metadata'} if full else {'path', 'bytes', 'sha256'},
              'exact original descriptor required')
    path = _st_path(value['path'])
    _st_need(type(value['bytes']) is int and 0 <= value['bytes'] <= limit
             and type(value['sha256']) is str
             and re.fullmatch(r'[0-9a-f]{64}', value['sha256']) is not None,
             'bounded original size and SHA required')
    if full:
        _st_full9(value['metadata'], 'file')
        _st_need(value['metadata'][5] == 1 and value['metadata'][6] == value['bytes'],
                 'single-link whole regular original required')
    return path


def _st_clock(deadline):
    _st_need(time.monotonic() < deadline, 'original actor operation deadline exhausted')


class _StdinOwnedFDs:
    def __init__(self):
        self.active = []
        self.opened = 0
        self.closed = 0
        self.registration_incomplete = False
        self.errors = []
        self.bytes_read = 0
        self.bytes_written = 0

    def open(self, *args, **kwargs):
        # If an asynchronous BaseException interrupts the return/registration
        # window, the final report cannot claim complete ownership knowledge.
        self.registration_incomplete = True
        try:
            fd = os.open(*args, **kwargs)
        except OSError:
            self.registration_incomplete = False
            raise
        self.active.append(fd)
        self.opened += 1
        self.registration_incomplete = False
        return fd

    def close(self, fd):
        if fd not in self.active:
            return
        # Once close was attempted its number is never retried: an interrupted
        # close may already have released it for reuse by another owner.
        self.active.remove(fd)
        try:
            os.close(fd)
            self.closed += 1
        except BaseException as error:
            self.errors.append({'fd': fd, 'type': type(error).__name__, 'detail': str(error)[:256]})
            raise

    def finish(self):
        for fd in list(reversed(self.active)):
            try:
                self.close(fd)
            except BaseException:
                pass
        return {'known_opened': self.opened, 'known_closed': self.closed,
                'known_remaining': list(self.active), 'close_errors': list(self.errors),
                'fd_registration_incomplete': self.registration_incomplete,
                'owned_known_fds_closed': not self.active and not self.errors,
                'complete_ownership_claimed': not self.active and not self.errors
                    and not self.registration_incomplete,
                'physical_file_bytes_read': self.bytes_read,
                'physical_file_bytes_written': self.bytes_written,
                'remote_cleanup_proven': False}


def _st_open_chain(path, owner):
    path = _st_path(str(path))
    chain = []
    try:
        root = owner.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        chain.append({'fd': root, 'path': '/', 'parent': None, 'name': None,
                      'metadata': _st_meta(os.fstat(root))})
        cursor = Path('/')
        for name in path.parts[1:-1]:
            parent = chain[-1]['fd']
            before = _st_meta(os.stat(name, dir_fd=parent, follow_symlinks=False))
            _st_full9(before, 'directory')
            fd = owner.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            dir_fd=parent)
            cursor = cursor / name
            row = {'fd': fd, 'path': str(cursor), 'parent': parent, 'name': name, 'metadata': before}
            chain.append(row)
            _st_need(_st_meta(os.fstat(fd)) == before == _st_meta(os.lstat(cursor)),
                     'ancestor changed during held no-follow open')
        _st_chain_check(chain)
        return chain
    except BaseException:
        for row in reversed(chain):
            owner.close(row['fd'])
        raise


def _st_chain_check(chain):
    for row in chain:
        held = _st_meta(os.fstat(row['fd']))
        _st_need(held == row['metadata'] == _st_meta(os.lstat(row['path'])),
                 'held/canonical ancestor full9 changed')
        if row['parent'] is not None:
            _st_need(held == _st_meta(os.stat(row['name'], dir_fd=row['parent'], follow_symlinks=False)),
                     'named ancestor was renamed or replaced')


def _st_read_fd(fd, size, deadline, owner):
    _st_clock(deadline)
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    count = 0
    while True:
        _st_clock(deadline)
        part = os.read(fd, min(65536, size - count + 1))
        if not part:
            break
        chunks.append(part)
        count += len(part)
        owner.bytes_read += len(part)
        _st_need(count <= size, 'regular original grew beyond its exact size')
    _st_need(count == size, 'regular original was truncated before EOF')
    _st_clock(deadline)
    return b''.join(chunks)


class _StdinOriginal:
    def __init__(self, pin, parent, owner, deadline, *, limit=ROOT_STDIN_INPUT_LIMIT):
        self.pin = pin
        self.path = _st_pin(pin, full=True, limit=limit)
        _st_exact(parent, {'path', 'metadata'}, 'source parent full9 descriptor required')
        _st_full9(parent['metadata'], 'directory')
        _st_need(parent['path'] == str(self.path.parent), 'source parent path differs')
        self.parent = parent
        self.owner = owner
        self.deadline = deadline
        self.chain = []
        self.fd = None
        try:
            _st_clock(deadline)
            self.chain = _st_open_chain(self.path, owner)
            _st_need(self.chain[-1]['metadata'] == parent['metadata'], 'source parent full9 differs')
            before = _st_meta(os.stat(self.path.name, dir_fd=self.chain[-1]['fd'], follow_symlinks=False))
            _st_need(before == pin['metadata'], 'source lstat differs from reviewed full9')
            self.fd = owner.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=self.chain[-1]['fd'])
            self.check()
            self.raw = _st_read_fd(self.fd, pin['bytes'], deadline, owner)
            _st_need(hashlib.sha256(self.raw).hexdigest() == pin['sha256'], 'whole original SHA differs')
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        _st_clock(self.deadline)
        _st_chain_check(self.chain)
        _st_need(_st_meta(os.fstat(self.fd)) == self.pin['metadata']
                 == _st_meta(os.stat(self.path.name, dir_fd=self.chain[-1]['fd'], follow_symlinks=False))
                 == _st_meta(os.lstat(self.path)), 'held/named/canonical source full9 differs')

    def reread(self):
        self.check()
        raw = _st_read_fd(self.fd, self.pin['bytes'], self.deadline, self.owner)
        _st_need(raw == self.raw and hashlib.sha256(raw).hexdigest() == self.pin['sha256'],
                 'whole original bytes changed after dispatch')
        self.check()
        return {'path': str(self.path), 'metadata': self.pin['metadata'],
                'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                'complete_second_read_and_EOF': True}

    def close(self):
        if self.fd is not None:
            self.owner.close(self.fd)
            self.fd = None
        for row in reversed(self.chain):
            self.owner.close(row['fd'])
        self.chain = []


def _st_observed_original(path, expected, owner, deadline, *, limit):
    path = _st_path(str(path))
    metadata = _st_meta(os.lstat(path))
    _st_full9(metadata, 'file')
    _st_need(metadata[5] == 1 and metadata[6] <= limit, 'bounded single-link actual regular source required')
    _st_exact(expected, {'bytes', 'sha256'}, 'exact source bytes/SHA required before reading code')
    pin = {'path': str(path), **expected, 'metadata': metadata}
    return _StdinOriginal(pin, {'path': str(path.parent), 'metadata': _st_meta(os.lstat(path.parent))},
                          owner, deadline, limit=limit)


class _StdinRun:
    def __init__(self, label, owner, deadline):
        _st_need(type(label) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,100}', label) is not None,
                 'fixed operator label required')
        self.path = BASE / 'operations' / label
        self.owner = owner
        self.deadline = deadline
        self.chain = _st_open_chain(self.path, owner)
        parent = self.chain[-1]
        _st_need(parent['metadata'][3:5] == [os.getuid(), os.getgid()]
                 and stat.S_IMODE(parent['metadata'][2]) == 0o700, 'existing private host operation parent required')
        before = sorted(os.listdir(parent['fd']))
        _st_need(len(before) <= 8192 and label not in before, 'operation already exists; no reopen or replay')
        _st_chain_check(self.chain)
        _st_clock(deadline)
        os.mkdir(label, mode=0o700, dir_fd=parent['fd'])
        after = _st_meta(os.fstat(parent['fd']))
        _st_need(after[:5] == parent['metadata'][:5]
                 and after[5] in (parent['metadata'][5], parent['metadata'][5] + 1)
                 and sorted(os.listdir(parent['fd'])) == sorted(before + [label]),
                 'operation parent has another concurrent mutation')
        parent['metadata'] = after  # Only this owned mkdir may change this parent.
        self.fd = owner.open(label, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent['fd'])
        self.metadata = _st_meta(os.fstat(self.fd))
        self.names = []
        self.files = {}
        _st_need(self.metadata[3:5] == [os.getuid(), os.getgid()]
                 and stat.S_IMODE(self.metadata[2]) == 0o700 and not os.listdir(self.fd),
                 'fresh owned operation directory differs')
        os.fsync(parent['fd'])
        self.check()

    def check(self):
        _st_clock(self.deadline)
        _st_chain_check(self.chain)
        _st_need(self.metadata == _st_meta(os.fstat(self.fd)) == _st_meta(os.lstat(self.path))
                 == _st_meta(os.stat(self.path.name, dir_fd=self.chain[-1]['fd'], follow_symlinks=False))
                 and sorted(os.listdir(self.fd)) == self.names,
                 'owned operation directory changed')
        for name, pin in self.files.items():
            _st_need(_st_meta(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == pin['metadata'],
                     'retained original path was renamed, replaced or modified')

    def put(self, name, raw, *, limit, check_deadline=True):
        _st_need(type(raw) is bytes and len(raw) <= limit and type(name) is str
                 and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', name) is not None and name not in self.names,
                 'one bounded create-only original required')
        # Failure retention remains bounded even after the network deadline.
        # It cannot publish success, and never resets a transport deadline.
        original_deadline = self.deadline
        if not check_deadline:
            self.deadline = float('inf')
        fd = None
        try:
            self.check()
            fd = self.owner.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                                 | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
            first = _st_meta(os.fstat(fd))
            _st_need(stat.S_ISREG(first[2]) and first[3:6] == [os.getuid(), os.getgid(), 1]
                     and stat.S_IMODE(first[2]) == 0o600 and first[6] == 0,
                     'fresh original output inode differs')
            offset = 0
            while offset < len(raw):
                if check_deadline:
                    _st_clock(original_deadline)
                n = os.write(fd, memoryview(raw)[offset:offset + 65536])
                _st_need(n > 0, 'owned output write made no progress')
                offset += n
                self.owner.bytes_written += n
            os.fsync(fd)
            observed = _st_read_fd(fd, len(raw), self.deadline, self.owner)
            final = _st_meta(os.fstat(fd))
            _st_need(observed == raw and first[:6] == final[:6]
                     and final == _st_meta(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
                     == _st_meta(os.lstat(self.path / name)), 'new original readback or held inode differs')
            os.fsync(self.fd)
            after = _st_meta(os.fstat(self.fd))
            _st_need(after[:6] == self.metadata[:6]
                     and sorted(os.listdir(self.fd)) == sorted(self.names + [name]),
                     'owned output directory has an unrelated mutation')
            self.metadata = after
            self.names = sorted(self.names + [name])
            pin = {'path': str(self.path / name), 'bytes': len(raw),
                   'sha256': hashlib.sha256(raw).hexdigest(), 'metadata': final}
            self.files[name] = pin
            self.check()
            return pin
        finally:
            if fd is not None:
                self.owner.close(fd)
            self.deadline = original_deadline


def _st_context(value):
    _st_exact(value, {'schema', 'epoch_id', 'ordinal', 'label', 'nonce', 'phase', 'identity',
                     'generation', 'destination_path', 'expected_parent', 'expected_members', 'input'},
              'complete receiver context required')
    _st_need(value['schema'] == 'hepta.native-guard.epoch-stdin-transfer-context.v1'
             and value['epoch_id'] == 'legacy902-active01' and type(value['ordinal']) is int
             and 1 <= value['ordinal'] <= 8 and type(value['label']) is str
             and re.fullmatch(r'[A-Za-z0-9_-]{1,100}', value['label']) is not None
             and type(value['nonce']) is str and re.fullmatch(r'[0-9a-f]{32}', value['nonce']) is not None
             and value['phase'] in ROOT_STDIN_PHASES, 'receiver context identity or phase differs')
    for name in ('identity', 'generation'):
        _st_pin(value[name])
    _st_exact(value['input'], {'bytes', 'sha256'}, 'bounded stdin pin required')
    _st_pin({'path': value['destination_path'], **value['input']})
    parent = value['expected_parent']
    _st_exact(parent, {'path', 'metadata', 'names'}, 'closed original private parent required')
    _st_path(parent['path'])
    _st_full9(parent['metadata'], 'directory')
    _st_need(parent['metadata'][3:5] == [0, 0] and stat.S_IMODE(parent['metadata'][2]) == 0o700
             and type(parent['names']) is list and all(type(n) is str for n in parent['names'])
             and parent['names'] == sorted(set(parent['names']))
             and set(parent['names']) <= set(ROOT_STDIN_PHASES) and value['phase'] not in parent['names']
             and value['destination_path'] == parent['path'] + '/' + value['phase'],
             'private parent membership or destination differs')
    members = value['expected_members']
    _st_need(type(members) is list and len(members) <= 6, 'complete prior phase members required')
    for row in members:
        _st_pin(row, full=True)
        _st_need(row['metadata'][3:6] == [0, 0, 1] and stat.S_IMODE(row['metadata'][2]) == 0o600,
                 'private prior member identity differs')
    _st_need([r['path'] for r in members] == [parent['path'] + '/' + name for name in parent['names']],
             'prior phase descriptors do not match the complete parent names')
    _st_need(len(_st_encoded(value)) <= 16384, 'receiver context bound')
    return value


def _st_request(value):
    _st_exact(value, {'schema', 'kind', 'root', 'command', 'timeout_seconds', 'source',
                     'source_parent', 'receipt_context', 'payload_budget_bytes'},
              'exact root-stdin request fields required')
    _st_need(value['schema'] == 'hepta.phone-local.root-stdin-request.v1'
             and value['kind'] == 'root_stdin' and value['root'] is True
             and type(value['command']) is str and '\0' not in value['command']
             and type(value['timeout_seconds']) is int and 1 <= value['timeout_seconds'] <= 300
             and type(value['payload_budget_bytes']) is int
             and 0 < value['payload_budget_bytes'] <= ROOT_STDIN_INPUT_LIMIT,
             'fixed root-stdin request or budget differs')
    source = _st_pin(value['source'], full=True)
    _st_exact(value['source_parent'], {'path', 'metadata'}, 'source parent full9 required')
    _st_full9(value['source_parent']['metadata'], 'directory')
    _st_need(value['source_parent']['path'] == str(source.parent), 'source parent path differs')
    context = _st_context(value['receipt_context'])
    _st_need(_st_encoded(context['input']) == _st_encoded({k: value['source'][k] for k in ('bytes', 'sha256')}),
             'receiver input does not bind the exact existing host original')
    command = '/debug_ramdisk/su -c ' + shlex.quote(value['command'])
    wire = len(('shell,v2,raw:' + command).encode('utf-8'))
    _st_need(wire < 65536 and wire + value['source']['bytes'] + ROOT_STDIN_OUTPUT_LIMIT
             <= value['payload_budget_bytes'], 'wire + whole stdin + output reservation exceed the shared pool')
    return command


def _st_receiver_receipt(raw, context):
    _st_need(type(raw) is bytes and len(raw) <= ROOT_STDIN_OUTPUT_LIMIT, 'bounded original receiver stdout required')
    value = _st_strict(raw)
    _st_exact(value, {'schema', 'state', 'context', 'input_bytes', 'input_sha256', 'stdin_eof',
        'destination', 'parent_before', 'parent_after', 'existing_members_rechecked',
        'created_exclusively', 'held_named_canonical_inode_equal', 'automatic_retry', 'overwritten_existing'},
        'complete original receiver success envelope required')
    _st_need(value['schema'] == 'hepta.native-guard.epoch-stdin-transfer-result.v1'
        and value['state'] == 'INPUT_EOF_AND_NEW_PRIVATE_FILE_FSYNCED_READBACK_VERIFIED'
        and _st_encoded(value['context']) == _st_encoded(context)
        and type(value['input_bytes']) is int and value['input_bytes'] == context['input']['bytes']
        and value['input_sha256'] == context['input']['sha256']
        and all(value[k] is True for k in ('stdin_eof', 'created_exclusively', 'held_named_canonical_inode_equal'))
        and value['automatic_retry'] is False and value['overwritten_existing'] is False,
        'receiver result fields do not match the actual requested input/context')
    destination = value['destination']
    _st_pin(destination, full=True)
    _st_need(destination['path'] == context['destination_path']
        and destination['bytes'] == context['input']['bytes']
        and destination['sha256'] == context['input']['sha256']
        and destination['metadata'][3:6] == [0, 0, 1]
        and stat.S_IMODE(destination['metadata'][2]) == 0o600, 'receiver new inode descriptor differs')
    _st_need(_st_encoded(value['parent_before']) == _st_encoded(context['expected_parent'])
        and _st_encoded(value['existing_members_rechecked']) == _st_encoded(context['expected_members']),
        'receiver original parent or members differ')
    after = value['parent_after']
    _st_exact(after, {'path', 'metadata', 'names'}, 'receiver complete final parent required')
    _st_full9(after['metadata'], 'directory')
    before = context['expected_parent']
    _st_need(after['path'] == before['path'] and after['metadata'][:6] == before['metadata'][:6]
        and type(after['names']) is list and after['names'] == sorted(before['names'] + [context['phase']]),
        'receiver parent had a different inode or an unrelated member change')
    return value


def _st_decode_original(value, limit):
    _st_exact(value, {'bytes', 'sha256', 'base64'}, 'complete SDK original descriptor required')
    _st_need(type(value['bytes']) is int and 0 <= value['bytes'] <= limit
             and type(value['base64']) is str and len(value['base64']) <= 4 * ((limit + 2) // 3),
             'SDK original envelope bound')
    raw = _st_b64.b64decode(value['base64'], validate=True)
    _st_need(len(raw) == value['bytes'] and hashlib.sha256(raw).hexdigest() == value['sha256']
             and _st_b64.b64encode(raw).decode('ascii') == value['base64'], 'SDK original bytes differ')
    return raw


def _st_actor_main(label, request_path, initial_raw, initial_req):
    started = time.monotonic()
    owner = _StdinOwnedFDs()
    run = None
    result_pin = None
    request_original = None
    stdin_original = None
    source_postcheck = None
    success = False
    deadline = None
    result_attempted = False
    phase = 'validate-request-before-dispatch'
    result = {'schema': 'hepta.phone-local.root-stdin-result.v1', 'label': label,
        'automatic_retry': False, 'automatic_replay': False, 'new_explicit_process_signal_calls': 0,
        'remote_cleanup_proven': False, 'receiver_source_authority_verified_here': False,
        'model_decision': False, 'native_task_result': False, 'component_case_passed': False,
        'transport_disconnect_may_trigger_adbd_SIGHUP': True,
        'payload_dispatch_count': 0, 'failure': None, 'transport': None,
        'local_filesystem_IO_is_not_preemptible': True,
        'legacy_route_and_baseline_gates_are_not_preempted': True}
    try:
        _st_need(type(initial_raw) is bytes and len(initial_raw) <= ROOT_STDIN_REQUEST_LIMIT,
                 'bounded complete root-stdin request required')
        req = _st_strict(initial_raw)
        _st_need(_st_encoded(req) == _st_encoded(initial_req), 'strict request interpretation differs')
        command = _st_request(req)
        deadline = started + req['timeout_seconds']
        request_original = _st_observed_original(request_path,
            {'bytes': len(initial_raw), 'sha256': hashlib.sha256(initial_raw).hexdigest()},
            owner, deadline, limit=ROOT_STDIN_REQUEST_LIMIT)
        _st_need(request_original.raw == initial_raw, 'request was replaced before dispatch')
        run = _StdinRun(label, owner, deadline)
        intent = {'schema': 'hepta.phone-local.root-stdin-intent.v1', 'label': label,
            'request': req, 'request_original': request_original.pin,
            'request_sha256': hashlib.sha256(initial_raw).hexdigest(),
            'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'automatic_retry': False, 'automatic_replay': False}
        run.put('intent.json', _st_encoded(intent), limit=ROOT_STDIN_REQUEST_LIMIT + 8192)
        run.put('request.original.json', initial_raw, limit=ROOT_STDIN_REQUEST_LIMIT)
        phase = 'whole-regular-input-before-dispatch'
        stdin_original = _StdinOriginal(req['source'], req['source_parent'], owner, deadline)
        result['source_original'] = req['source']
        result['stdin_original'] = run.put('stdin.original', stdin_original.raw, limit=ROOT_STDIN_INPUT_LIMIT)
        phase = 'load-exact-actual-sibling-sdk'
        _st_need(type(ROOT_STDIN_SDK_PIN) is dict, 'unbound SDK successor is not executable')
        actor_path = _st_path(__file__)
        sdk_path = actor_path.parent / ROOT_STDIN_SDK_NAME
        sdk_original = _st_observed_original(sdk_path, ROOT_STDIN_SDK_PIN, owner, deadline, limit=131072)
        result['sdk_original'] = sdk_original.pin
        f = types.ModuleType('v150_root_phone_stdin_actor')
        f.__file__ = str(sdk_path)
        exec(compile(sdk_original.raw, str(sdk_path), 'exec'), f.__dict__)
        sdk_original.reread()
        sdk_original.close()
        # The preserved config is an actual host file. Its own complete original
        # is retained; the new sibling SDK must not silently change config roots.
        config_meta = _st_meta(os.lstat(ROOT_STDIN_CONFIG))
        _st_full9(config_meta, 'file')
        _st_need(config_meta[5] == 1 and config_meta[6] <= 65536, 'original SDK config bound')
        config_fd_chain = _st_open_chain(ROOT_STDIN_CONFIG, owner)
        config_fd = owner.open(ROOT_STDIN_CONFIG.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                               dir_fd=config_fd_chain[-1]['fd'])
        _st_need(config_meta == _st_meta(os.fstat(config_fd)), 'config changed during held open')
        config_raw = _st_read_fd(config_fd, config_meta[6], deadline, owner)
        _st_need(config_meta == _st_meta(os.fstat(config_fd)) == _st_meta(os.lstat(ROOT_STDIN_CONFIG)),
                 'config original changed')
        _st_chain_check(config_fd_chain)
        owner.close(config_fd)
        for row in reversed(config_fd_chain):
            owner.close(row['fd'])
        result['config_original'] = run.put('config.original.json', config_raw, limit=65536)
        c = _st_strict(config_raw)
        phase = 'preserved-route-and-phone-baseline'
        t = f.route(c)
        _st_clock(deadline)
        baseline = f.shell('cat /proc/sys/kernel/random/boot_id; getprop ro.build.fingerprint; getprop sys.usb.config; getenforce; pidof adbd',
                           c, t, timeout=min(15, deadline - time.monotonic()))
        _st_need(baseline['rc'] == 0 and baseline['stdout'].splitlines()
                 == [BOOT, FINGERPRINT, 'adb', 'Enforcing', '3021'], 'phone baseline changed')
        run.put('baseline.json', _st_encoded(baseline), limit=65536)
        stdin_original.check()
        request_original.check()
        _st_clock(deadline)
        phase = 'single-root-stdin-dispatch'
        result['payload_dispatch_count'] = 1
        transported = f.shell_stdin(command, c, t, stdin_original.raw,
            timeout=deadline - time.monotonic(), payload_budget_bytes=req['payload_budget_bytes'])
        phase = 'retain-complete-or-partial-response-originals'
        # Raw output prefixes are retained even when the original operation
        # deadline expired. This bounded failure retention cannot cause a resend.
        wire_limit = f.SHELL_STDIN_INCOMING_WIRE_LIMIT + 1
        originals = {}
        transport_record = dict(transported)
        for key, name, limit in (
            ('stdout_original', 'stdout.original', wire_limit),
            ('stderr_original', 'stderr.original', wire_limit),
            ('incoming_wire_original', 'incoming-shell-wire.original', wire_limit),
            ('smart_socket_response_original', 'smart-socket-responses.original', 65552)):
            body = _st_decode_original(transported[key], limit)
            originals[key] = body
            transport_record[key] = run.put(name, body, limit=limit, check_deadline=False)
        result['transport'] = transport_record
        run.put('transport.json', _st_encoded(transport_record), limit=262144, check_deadline=False)
        phase = 'verify-original-receiver-envelope'
        _st_clock(deadline)
        _st_need(transported['transport_complete'] is True
            and transported['received_originals_complete'] is True
            and transported['socket_close_returned'] is True and transported['rc'] == 0
            and transported['stdin_complete_frame_payload_bytes'] == len(stdin_original.raw)
            and transported['close_stdin_frame_sent'] is True
            and transported['exit_frame_received'] is True and transported['socket_eof_observed'] is True,
            'stdin/EXIT/EOF/receiver status incomplete; no retry or file authority inferred')
        _st_need(not originals['stderr_original'], 'receiver success also emitted error bytes')
        result['receiver_receipt'] = _st_receiver_receipt(originals['stdout_original'], req['receipt_context'])
        phase = 'post-dispatch-whole-host-original-bookends'
        source_postcheck = stdin_original.reread()
        request_original.reread()
        stdin_original.close()
        request_original.close()
        _st_clock(deadline)
        result.update(state='RECEIVER_ORIGINALS_VERIFIED_PENDING_ACTOR_FD_CLOSE',
            source_postcheck=source_postcheck, receiver_receipt_structure_verified=True,
            shared_payload_bytes_charged=transported['shared_payload_bytes_charged'],
            elapsed_seconds=time.monotonic() - started)
        phase = 'publish-local-pending-result'
        result_attempted = True
        result_pin = run.put('result.json', _st_encoded(result), limit=524288)
        run.check()
        _st_clock(deadline)
        success = True
    except BaseException as error:
        result.update(state='PARTIAL_FAILED_OR_UNKNOWN_NO_RETRY',
            failure={'type': type(error).__name__, 'detail': str(error)[:2048], 'phase': phase},
            elapsed_seconds=time.monotonic() - started)
        if run is not None and not result_attempted:
            result_attempted = True
            try:
                result_pin = run.put('result.json', _st_encoded(result), limit=524288, check_deadline=False)
            except BaseException as retention_error:
                result['failure_retention_error'] = {'type': type(retention_error).__name__,
                    'detail': str(retention_error)[:512]}
    finally:
        cleanup = owner.finish()
    success = success and cleanup['complete_ownership_claimed']
    if success and time.monotonic() >= deadline:
        success = False
        result['failure'] = {'type': 'DeadlineAfterOwnedClose',
            'detail': 'original actor deadline expired before final stdout summary',
            'phase': 'owned-host-fd-close'}
    summary = {'schema': 'hepta.phone-local.root-stdin-summary.v1', 'label': label,
        'run': str(run.path) if run is not None else None,
        'status': ('ROOT_STDIN_ORIGINALS_RETAINED_AND_OWNED_HOST_FDS_CLOSED'
                   if success else 'PARTIAL_FAILED_OR_UNKNOWN_NO_RETRY'),
        'result': result_pin, 'failure': result.get('failure'),
        'failure_retention_error': result.get('failure_retention_error'),
        'payload_dispatch_count': result['payload_dispatch_count'], 'host_owned_fd_cleanup': cleanup,
        'automatic_retry': False, 'remote_cleanup_proven': False,
        'receiver_source_authority_verified_here': False,
        'transport_disconnect_may_trigger_adbd_SIGHUP': True,
        'elapsed_seconds': time.monotonic() - started}
    print(_st_encoded(summary).decode('utf-8'), end='')
    return 0 if success else 1



# Data-only publication wire. This does not grant source or action authority.
EPOCH_PUBLICATION_WIRE_MAX_BYTES = 49152
EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES = 2097152


def epoch_publication_wire_value(raw):
    import base64 as wb
    import hashlib as wh
    import json as wj
    import zlib as wz
    def require(ok, message):
        if not ok: raise ValueError(message)
    def encode(value):
        return (wj.dumps(value, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False)+'\n').encode('utf-8')
    def pairs(items):
        value={}
        for key,item in items:
            require(type(key) is str and key not in value,'duplicate publication wire field')
            value[key]=item
        return value
    def parse(body):
        return wj.loads(body.decode('utf-8','strict'),object_pairs_hook=pairs,
            parse_constant=lambda _value:require(False,'nonfinite publication wire data'))
    def bare(body): return {'bytes':len(body),'sha256':wh.sha256(body).hexdigest()}
    def exact_pin(value, maximum):
        require(type(value) is dict and set(value)=={'bytes','sha256'}
            and type(value['bytes']) is int and 0<value['bytes']<=maximum
            and type(value['sha256']) is str and len(value['sha256'])==64
            and all(x in '0123456789abcdef' for x in value['sha256']),
            'strict bounded publication wire byte pin required')
    require(type(raw) is bytes and 0<len(raw)<=EPOCH_PUBLICATION_WIRE_MAX_BYTES,
            'complete publication wire exceeds its source-fixed bound')
    value=parse(raw)
    require(type(value) is dict and set(value)=={'schema','encoding','uncompressed',
        'compressed','payload_base64'} and encode(value)==raw
        and value['schema']=='hepta.native-guard.epoch-publication-wire.v1'
        and value['encoding']=='zlib+base64','exact canonical publication wire required')
    exact_pin(value['uncompressed'],EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES)
    exact_pin(value['compressed'],EPOCH_PUBLICATION_WIRE_MAX_BYTES)
    text=value['payload_base64']
    require(type(text) is str and len(text)<=4*((EPOCH_PUBLICATION_WIRE_MAX_BYTES+2)//3),
            'bounded publication wire base64 required before decoding')
    packed=wb.b64decode(text,validate=True)
    require(wb.b64encode(packed).decode('ascii')==text
        and bare(packed)==value['compressed'],'canonical complete compressed pin differs')
    decoder=wz.decompressobj()
    body=decoder.decompress(packed,EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES+1)
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
        and len(body)<=EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES
        and bare(body)==value['uncompressed'],
        'publication data must be one complete bounded stream without tails or a second member')
    observation=parse(body)
    require(type(observation) is dict and encode(observation)==body
        and observation.get('schema')=='hepta.native-guard.epoch-publication-observation.v1',
        'publication observation must retain its canonical actual JSON bytes')
    return body


def epoch_publication_wire_from_original(raw):
    import base64 as wb
    import hashlib as wh
    import json as wj
    import zlib as wz
    if type(raw) is not bytes or not 0<len(raw)<=EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES:
        raise ValueError('source-fixed publication observation size exceeded before compression')
    packed=wz.compress(raw,9)
    value={'schema':'hepta.native-guard.epoch-publication-wire.v1','encoding':'zlib+base64',
        'uncompressed':{'bytes':len(raw),'sha256':wh.sha256(raw).hexdigest()},
        'compressed':{'bytes':len(packed),'sha256':wh.sha256(packed).hexdigest()},
        'payload_base64':wb.b64encode(packed).decode('ascii')}
    wire=(wj.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=False,
                   allow_nan=False)+'\n').encode('utf-8')
    if len(wire)>EPOCH_PUBLICATION_WIRE_MAX_BYTES:
        raise ValueError('complete serialized publication wire exceeds source-fixed output pool')
    if epoch_publication_wire_value(wire)!=raw:
        raise ValueError('publication wire lost original bytes')
    return wire


# Separate bounded publication transport. The fixed Root producer selects and
# authorizes the command; these request fields and transport results do not.
EPOCH_PUBLICATION_REQUEST_LIMIT = 131072
EPOCH_PUBLICATION_RESULT_LIMIT = 65536
EPOCH_PUBLICATION_TRANSPORT_POOL = 8 * 1024 * 1024
EPOCH_PUBLICATION_BASELINE_COMMAND = 'cat /proc/sys/kernel/random/boot_id; getprop ro.build.fingerprint; getprop sys.usb.config; getenforce; pidof adbd'


def _pr_request(value):
    _st_exact(value, {'schema', 'kind', 'root', 'command', 'timeout_seconds',
                     'payload_budget_bytes', 'expected_observation'},
              'exact separate publication request required')
    _st_need(value['schema'] == 'hepta.phone-local.epoch-publication-request.v1'
        and value['kind'] == 'epoch_publication_read' and value['root'] is True
        and type(value['command']) is str and '\0' not in value['command']
        and type(value['timeout_seconds']) is int and 1 <= value['timeout_seconds'] <= 300
        and type(value['payload_budget_bytes']) is int
        and 0 < value['payload_budget_bytes'] <= EPOCH_PUBLICATION_TRANSPORT_POOL,
        'publication command, explicit root or same operation budget differs')
    expected = value['expected_observation']
    _st_exact(expected, {'epoch_id', 'boot_id', 'generation', 'terminal',
                         'root_source_manifest', 'bridge_source'},
              'all actual observation links required; these are not source authority')
    _st_need(expected['epoch_id'] == 'legacy902-active01' and expected['boot_id'] == BOOT,
             'publication observation epoch or actual boot differs')
    for name in ('generation', 'terminal'):
        _st_pin(expected[name], full=True)
    for name in ('root_source_manifest', 'bridge_source'):
        _st_pin(expected[name])
    command = '/debug_ramdisk/su -c ' + shlex.quote(value['command'])
    wire = len(('shell,v2,raw:' + command).encode('utf-8'))
    _st_need(wire < 65536, 'publication command wire still must be smaller than 65536')
    return command


def _pr_current_config(owner, deadline):
    """Observe the fixed existing config and retain its exact held original."""
    path = ROOT_STDIN_CONFIG
    chain = _st_open_chain(path, owner); fd = None
    try:
        before = _st_meta(os.stat(path.name, dir_fd=chain[-1]['fd'], follow_symlinks=False))
        _st_full9(before, 'file')
        _st_need(before[5] == 1 and before[6] <= 65536, 'bounded fixed config original required')
        fd = owner.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=chain[-1]['fd'])
        _st_need(_st_meta(os.fstat(fd)) == before, 'fixed config was replaced at open')
        raw = _st_read_fd(fd, before[6], deadline, owner)
        _st_need(before == _st_meta(os.fstat(fd))
            == _st_meta(os.stat(path.name, dir_fd=chain[-1]['fd'], follow_symlinks=False))
            == _st_meta(os.lstat(path)), 'held/named/canonical fixed config differs')
        _st_chain_check(chain)
        pin = {'path': str(path), 'metadata': before, 'bytes': len(raw),
               'sha256': hashlib.sha256(raw).hexdigest()}
        parent = {'path': str(path.parent), 'metadata': chain[-1]['metadata']}
    finally:
        if fd is not None:
            owner.close(fd)
        for row in reversed(chain):
            owner.close(row['fd'])
    original = _StdinOriginal(pin, parent, owner, deadline, limit=65536)
    _st_need(original.raw == raw, 'fixed config complete second read differs')
    return original


def _pr_wire_reserve(sdk):
    # Two smart-socket service requests (each <65536), one CLOSE_STDIN frame,
    # bounded complete/prefix shell wire and bounded original smart replies.
    # Empty stdin adds no payload. This is a pre-dispatch upper reservation for
    # one new shell exchange, including framing, not just its output payload.
    _st_need(sdk.SHELL_STDIN_FRAME_COUNT == 1024
        and sdk.SHELL_STDIN_OUTPUT_LIMIT == 65536
        and sdk.SHELL_STDIN_INCOMING_WIRE_LIMIT == 65536 + 5 * 1024 + 1,
        'the exact reviewed SDK wire/output/frame bounds changed')
    return 2 * 65535 + 8 + 5 + sdk.SHELL_STDIN_INCOMING_WIRE_LIMIT + 1 + 65552


def _pr_retain_exchange(run, sdk, transported, prefix):
    """Retain every actual SDK prefix even if its exchange did not complete."""
    _st_need(prefix in ('baseline-', ''), 'only fixed baseline and publication streams exist')
    wire_limit = sdk.SHELL_STDIN_INCOMING_WIRE_LIMIT + 1
    raw = {}; record = dict(transported)
    for key, name, limit in (
        ('stdout_original', 'stdout.original', wire_limit),
        ('stderr_original', 'stderr.original', wire_limit),
        ('incoming_wire_original', 'incoming-shell-wire.original', wire_limit),
        ('smart_socket_response_original', 'smart-socket-responses.original', 65552)):
        body = _st_decode_original(transported[key], limit)
        raw[key] = body
        record[key] = run.put(prefix + name, body, limit=limit, check_deadline=False)
    run.put(prefix + 'transport.json', _st_encoded(record), limit=65536, check_deadline=False)
    return record, raw


def _pr_complete_exchange(transported, command, raw, *, reserve, remaining):
    _st_need(transported['schema'] == 'hepta.phone-local.shell-stdin-transport.v1'
        and transported['command'] == command
        and _st_encoded(transported['stdin_original']) == _st_encoded({
            'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()})
        and transported['transport_complete'] is True
        and transported['received_originals_complete'] is True
        and transported['socket_close_returned'] is True
        and type(transported['rc']) is int and transported['rc'] == 0
        and transported['stdin_payload_bytes_sent_to_socket'] == 0
        and transported['stdin_complete_frame_payload_bytes'] == 0
        and transported['close_stdin_frame_sent'] is True
        and transported['exit_frame_received'] is True
        and transported['socket_eof_observed'] is True
        and transported['exit_received_before_input_complete'] is False
        and transported['failure'] is None and transported['automatic_retry'] is False,
        'actual empty input/CLOSE_STDIN/EXIT/socket EOF is incomplete; never retry')
    _st_need(all(type(transported[k]) is int for k in ('stdin_payload_bytes_sent_to_socket',
        'stdin_complete_frame_payload_bytes', 'stdout_payload_bytes_received',
        'stderr_payload_bytes_received', 'command_wire_bytes', 'shared_payload_limit_bytes',
        'receiver_output_reservation_bytes', 'new_explicit_process_signal_calls'))
        and transported['command_wire_bytes'] == len(('shell,v2,raw:'+command).encode('utf-8'))
        and transported['shared_payload_limit_bytes'] == remaining
        and transported['receiver_output_reservation_bytes'] == 65536
        and transported['new_explicit_process_signal_calls'] == 0
        and transported['shared_payload_limit_satisfied'] is True,
        'exact integer counters and same requested shell payload reservation required')
    accounting = transported['carrier_accounting']
    keys = ('smart_socket_request_bytes_sent', 'smart_socket_response_bytes_received',
            'shell_protocol_bytes_sent', 'shell_protocol_bytes_received',
            'all_socket_bytes_sent', 'all_socket_bytes_received')
    _st_need(all(type(accounting.get(k)) is int and accounting[k] >= 0 for k in keys)
        and accounting['all_socket_bytes_sent'] == accounting['smart_socket_request_bytes_sent']
            + accounting['shell_protocol_bytes_sent']
        and accounting['all_socket_bytes_received'] == accounting['smart_socket_response_bytes_received']
            + accounting['shell_protocol_bytes_received']
        and accounting['smart_socket_response_bytes_received'] == len(raw['smart_socket_response_original'])
        and accounting['shell_protocol_bytes_received'] == len(raw['incoming_wire_original'])
        and transported['stdout_payload_bytes_received'] == len(raw['stdout_original'])
        and transported['stderr_payload_bytes_received'] == len(raw['stderr_original'])
        and type(transported['received_frames']) is int and 1 <= transported['received_frames'] <= 1024
        and type(transported['sent_frames']) is int and transported['sent_frames'] == 1,
        'actual original wire accounting or bounded empty-stdin frame set differs')
    charged = accounting['all_socket_bytes_sent'] + accounting['all_socket_bytes_received']
    _st_need(charged <= reserve <= remaining and not raw['stderr_original'],
             'one complete shell exchange exceeded the single reserved operation pool or emitted stderr')
    return charged


def _pr_observation_from_wire(wire, expected):
    raw = epoch_publication_wire_value(wire)
    value = _st_strict(raw)
    _st_exact(value, {'schema', 'state', 'epoch_id', 'boot_id', 'manifest', 'generation', 'terminal',
        'initial_manifest_sha256', 'final_manifest_sha256', 'file_count', 'retained_bytes',
        'source_reader_binding', 'rechecked_files', 'rechecked_directories', 'effects'},
        'full publication observation fields differ')
    _st_need(value['state'] == 'ACTUAL_COMPLETE_PUBLISHED_REGISTRY_READ'
        and value['epoch_id'] == expected['epoch_id'] and value['boot_id'] == expected['boot_id']
        and _st_encoded(value['generation']) == _st_encoded(expected['generation'])
        and _st_encoded(value['terminal']) == _st_encoded(expected['terminal']),
        'publication observation changes the caller-bound actual original links')
    _st_need(_st_encoded(value['source_reader_binding']) == _st_encoded({
        'root_source_manifest': expected['root_source_manifest'], 'bridge_source': expected['bridge_source'],
        'operation': 'epoch-publication-read'}), 'publication reader source links differ')
    manifest = value['manifest']
    _st_exact(manifest, {'schema', 'files', 'directories'}, 'complete publication manifest required')
    _st_need(manifest['schema'] == 'hepta.native-guard.epoch-capture-inputs.v1'
        and type(manifest['files']) is list and 1 <= len(manifest['files']) <= 8192
        and type(manifest['directories']) is list and 1 <= len(manifest['directories']) <= 30000,
        'publication manifest count or schema differs')
    for row in manifest['files']:
        _st_pin(row, full=True, limit=16*1024*1024)
    _st_need(len({row['path'] for row in manifest['files']}) == len(manifest['files']),
             'publication manifest file paths repeat')
    directory_paths = set()
    for row in manifest['directories']:
        _st_exact(row, {'path', 'metadata', 'names'}, 'complete directory observation required')
        _st_path(row['path']); _st_full9(row['metadata'], 'directory')
        _st_need(row['path'] not in directory_paths
            and type(row['names']) is list
            and all(type(n) is str and n not in ('', '.', '..') and '/' not in n and '\0' not in n
                    for n in row['names'])
            and row['names'] == sorted(set(row['names'])),
            'directory names must be a complete canonical unique observation')
        directory_paths.add(row['path'])
    _st_need(not directory_paths.intersection(row['path'] for row in manifest['files']),
        'one publication path cannot be both a file and a directory')
    digest = hashlib.sha256(_st_encoded(manifest)).hexdigest()
    expected_counts = {'file_count': len(manifest['files']), 'retained_bytes': sum(row['bytes'] for row in manifest['files']),
        'rechecked_files': len(manifest['files']), 'rechecked_directories': len(manifest['directories'])}
    _st_need(all(type(value[k]) is int and value[k] == n for k, n in expected_counts.items())
        and value['initial_manifest_sha256'] == value['final_manifest_sha256'] == digest,
        'complete manifest observation counts or initial/final digest differ')
    effects = {'ui_actions': 0, 'phone_native_dispatches': 0, 'model_requests': 0,
        'signals_sent': 0, 'source_original_writes': 0, 'nonces_generated': 0,
        'leases_created': 0, 'boundaries_published': 0, 'component_qualified': False, 'business_qualified': False}
    _st_need(_st_encoded(value['effects']) == _st_encoded(effects),
             'publication observation effect declaration differs')
    return raw


def _pr_actor_main(label, request_path, initial_raw, initial_req):
    started = time.monotonic(); owner = _StdinOwnedFDs()
    run = None; result_pin = None; success = False; result_attempted = False; deadline = None
    request_original = None; config_original = None
    phase = 'validate-publication-request-before-dispatch'
    result = {'schema': 'hepta.phone-local.epoch-publication-result.v1', 'label': label,
        'automatic_retry': False, 'automatic_replay': False, 'new_explicit_process_signal_calls': 0,
        'remote_cleanup_proven': False, 'publication_source_authority_verified_here': False,
        'model_decision': False, 'native_task_result': False, 'component_case_passed': False,
        'transport_disconnect_may_trigger_adbd_SIGHUP': True,
        'baseline_dispatch_count': 0, 'payload_dispatch_count': 0,
        'failure': None, 'transport': None, 'baseline_transport': None,
        'local_filesystem_IO_is_not_preemptible': True,
        'legacy_route_gate_is_not_preempted': True,
        'whole_case_or_reservation_pool_qualified_here': False}
    try:
        _st_need(type(initial_raw) is bytes and len(initial_raw) <= EPOCH_PUBLICATION_REQUEST_LIMIT,
                 'bounded complete separate publication request required')
        req = _st_strict(initial_raw)
        _st_need(_st_encoded(req) == _st_encoded(initial_req), 'strict request interpretation differs')
        command = _pr_request(req); deadline = started + req['timeout_seconds']
        request_original = _st_observed_original(request_path,
            {'bytes': len(initial_raw), 'sha256': hashlib.sha256(initial_raw).hexdigest()},
            owner, deadline, limit=EPOCH_PUBLICATION_REQUEST_LIMIT)
        _st_need(request_original.raw == initial_raw, 'publication request changed before dispatch')
        run = _StdinRun(label, owner, deadline)
        intent = {'schema': 'hepta.phone-local.epoch-publication-intent.v1', 'label': label,
            'request': req, 'request_original': request_original.pin,
            'request_sha256': hashlib.sha256(initial_raw).hexdigest(),
            'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'automatic_retry': False, 'automatic_replay': False,
            'publication_source_authority_verified_here': False}
        run.put('intent.json', _st_encoded(intent), limit=EPOCH_PUBLICATION_REQUEST_LIMIT + 8192)
        run.put('request.original.json', initial_raw, limit=EPOCH_PUBLICATION_REQUEST_LIMIT)
        result['empty_stdin'] = {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest(),
            'host_source_file': None, 'semantics': 'SOURCE_DEFINED_EMPTY_INPUT_AND_REAL_CLOSE_STDIN'}
        phase = 'load-exact-actual-sibling-sdk'
        actor_path = _st_path(__file__)
        sdk_path = actor_path.parent / ROOT_STDIN_SDK_NAME
        sdk_original = _st_observed_original(sdk_path, ROOT_STDIN_SDK_PIN, owner, deadline, limit=131072)
        result['sdk_original'] = sdk_original.pin
        sdk = types.ModuleType('v150_root_phone_publication_actor'); sdk.__file__ = str(sdk_path)
        exec(compile(sdk_original.raw, str(sdk_path), 'exec'), sdk.__dict__)
        sdk_original.reread(); sdk_original.close()
        reserve = _pr_wire_reserve(sdk)
        _st_need(2 * reserve <= req['payload_budget_bytes'],
                 'baseline and publication whole wire reservations exceed the single operation pool')
        config_original = _pr_current_config(owner, deadline)
        result['config_original'] = run.put('config.original.json', config_original.raw, limit=65536)
        config = _st_strict(config_original.raw)
        phase = 'preserved-route-and-bounded-empty-stdin-baseline'
        transport = sdk.route(config); _st_clock(deadline)
        result['baseline_dispatch_count'] = 1
        baseline = sdk.shell_stdin(EPOCH_PUBLICATION_BASELINE_COMMAND, config, transport, b'',
            timeout=min(15, deadline-time.monotonic()), payload_budget_bytes=req['payload_budget_bytes'])
        baseline_record, baseline_raw = _pr_retain_exchange(run, sdk, baseline, 'baseline-')
        result['baseline_transport'] = baseline_record
        baseline_charge = _pr_complete_exchange(baseline, EPOCH_PUBLICATION_BASELINE_COMMAND, baseline_raw,
            reserve=reserve, remaining=req['payload_budget_bytes'])
        _st_need(baseline_raw['stdout_original'].decode('utf-8', 'strict').splitlines()
            == [BOOT, FINGERPRINT, 'adb', 'Enforcing', '3021'], 'actual fixed phone baseline changed')
        remaining = req['payload_budget_bytes'] - baseline_charge
        _st_need(reserve <= remaining, 'publication cannot open another unreserved shell exchange')
        request_original.check(); config_original.check(); _st_clock(deadline)
        phase = 'single-empty-stdin-publication-dispatch'
        result['payload_dispatch_count'] = 1
        transported = sdk.shell_stdin(command, config, transport, b'',
            timeout=deadline-time.monotonic(), payload_budget_bytes=remaining)
        phase = 'retain-actual-complete-or-partial-publication-wire'
        record, raw = _pr_retain_exchange(run, sdk, transported, '')
        result['transport'] = record
        charged = _pr_complete_exchange(transported, command, raw, reserve=reserve, remaining=remaining)
        phase = 'verify-bounded-publication-data-wire'
        _st_clock(deadline)
        observation = _pr_observation_from_wire(raw['stdout_original'], req['expected_observation'])
        _st_clock(deadline)
        result['publication_wire_utf8'] = raw['stdout_original'].decode('utf-8', 'strict')
        result['publication_observation_original'] = run.put('PUBLICATION-OBSERVATION.original.json',
            observation, limit=EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES)
        result['expected_observation'] = req['expected_observation']
        result['wire_and_declared_observation_shape_verified'] = True
        result['whole_transport_pool'] = {'maximum_bytes': req['payload_budget_bytes'],
            'baseline_socket_bytes': baseline_charge, 'publication_socket_bytes': charged,
            'total_socket_bytes': baseline_charge + charged,
            'each_exchange_pre_reserved_bytes': reserve,
            'command_stdin_stdout_stderr_smart_replies_and_shell_framing_included': True,
            'unchanged_legacy_route_observations_are_not_shell_exchange_bytes': True}
        phase = 'post-dispatch-whole-host-original-bookends'
        result['request_postcheck'] = request_original.reread()
        result['config_postcheck'] = config_original.reread()
        request_original.close(); config_original.close(); _st_clock(deadline)
        result.update(state='PUBLICATION_WIRE_ORIGINALS_VERIFIED_PENDING_ACTOR_FD_CLOSE',
                      elapsed_seconds=time.monotonic()-started)
        phase = 'publish-local-pending-result'; result_attempted = True
        result_pin = run.put('result.json', _st_encoded(result), limit=EPOCH_PUBLICATION_RESULT_LIMIT)
        run.check(); _st_clock(deadline); success = True
    except BaseException as error:
        result.update(state='PARTIAL_FAILED_OR_UNKNOWN_NO_RETRY',
            failure={'type': type(error).__name__, 'detail': str(error)[:2048], 'phase': phase},
            elapsed_seconds=time.monotonic()-started)
        if run is not None and not result_attempted:
            result_attempted = True
            try:
                result_pin = run.put('result.json', _st_encoded(result),
                    limit=EPOCH_PUBLICATION_RESULT_LIMIT, check_deadline=False)
            except BaseException as retention_error:
                result['failure_retention_error'] = {'type': type(retention_error).__name__,
                    'detail': str(retention_error)[:512]}
    finally:
        cleanup = owner.finish()
    success = success and cleanup['complete_ownership_claimed']
    if success and time.monotonic() >= deadline:
        success = False
        result['failure'] = {'type': 'DeadlineAfterOwnedClose',
            'detail': 'original actor deadline expired before final stdout summary',
            'phase': 'owned-host-fd-close'}
    summary = {'schema': 'hepta.phone-local.epoch-publication-summary.v1', 'label': label,
        'run': str(run.path) if run is not None else None,
        'status': ('PUBLICATION_ORIGINALS_RETAINED_AND_OWNED_HOST_FDS_CLOSED'
                   if success else 'PARTIAL_FAILED_OR_UNKNOWN_NO_RETRY'),
        'result': result_pin, 'failure': result.get('failure'),
        'failure_retention_error': result.get('failure_retention_error'),
        'baseline_dispatch_count': result['baseline_dispatch_count'],
        'payload_dispatch_count': result['payload_dispatch_count'], 'host_owned_fd_cleanup': cleanup,
        'automatic_retry': False, 'remote_cleanup_proven': False,
        'publication_source_authority_verified_here': False,
        'transport_disconnect_may_trigger_adbd_SIGHUP': True,
        'elapsed_seconds': time.monotonic()-started}
    summary_raw = _st_encoded(summary)
    if len(summary_raw) > EPOCH_PUBLICATION_RESULT_LIMIT:
        success = False
        summary_raw = _st_encoded({'schema': 'hepta.phone-local.epoch-publication-summary.v1',
            'status': 'PARTIAL_FAILED_OR_UNKNOWN_NO_RETRY', 'summary_serialization_refused': True,
            'original_summary_bytes': len(summary_raw),
            'original_summary_sha256': hashlib.sha256(summary_raw).hexdigest(),
            'automatic_retry': False, 'complete_ownership_claimed_here': False})
    print(summary_raw.decode('utf-8'), end='')
    return 0 if success else 1


ap=argparse.ArgumentParser();ap.add_argument('label');ap.add_argument('request',type=Path);args=ap.parse_args()
assert re.fullmatch(r'[A-Za-z0-9_-]{1,100}',args.label)
raw=args.request.read_bytes(); req=json.loads(raw)
if type(req) is dict and req.get('kind') == 'root_stdin':
 raise SystemExit(_st_actor_main(args.label, args.request, raw, req))
if type(req) is dict and req.get('kind') == 'epoch_publication_read':
 raise SystemExit(_pr_actor_main(args.label, args.request, raw, req))
(BASE/'operations').mkdir(mode=0o700,exist_ok=True);run=BASE/'operations'/args.label;run.mkdir(mode=0o700)
start=time.monotonic()
save(run/'intent.json',{'schema':'hepta.phone-local.operator-intent.v150.1','label':args.label,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'request_sha256':hashlib.sha256(raw).hexdigest(),'request':req,'automatic_replay':False})
result={'schema':'hepta.phone-local.operator-result.v150.1','label':args.label,'model_decision':False,'native_task_result':False}
try:
 p=Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved_ui_package_phase_r7.py')
 b=p.read_bytes();assert hashlib.sha256(b).hexdigest()=='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
 f=types.ModuleType('v150_root_phone_actor');f.__file__=str(p);exec(compile(b,str(p),'exec'),f.__dict__)
 c=json.loads((p.parent/'preserved-ui-package-config.json').read_text());t=f.route(c)
 baseline=f.shell('cat /proc/sys/kernel/random/boot_id; getprop ro.build.fingerprint; getprop sys.usb.config; getenforce; pidof adbd',c,t,timeout=15)
 assert baseline['rc']==0 and baseline['stdout'].splitlines()==[BOOT,FINGERPRINT,'adb','Enforcing','3021'], 'Phone baseline changed'
 save(run/'baseline.json',baseline)
 kind=req['kind']
 if kind=='shell':
  command=req['command']
  if req.get('root'):command='/debug_ramdisk/su -c '+shlex.quote(command)
  result['phone']=f.shell(command,c,t,timeout=min(300,int(req.get('timeout_seconds',30))))
  result['status']='command_exited'
 elif kind=='push':
  p=Path(req['source']); info=p.lstat()
  assert stat.S_ISREG(info.st_mode) and not p.is_symlink() and sha_file(p)==req['sha256']
  dest=req['destination'];assert dest.startswith(PHONE+'/') and '..' not in Path(dest).parts
  check=f.shell('test ! -e '+shlex.quote(dest),c,t,timeout=10);assert check['rc']==0,'Destination exists; do not overwrite'
  save(run/'push-reserved.json',{'source':str(p),'destination':dest,'bytes':info.st_size,'sha256':req['sha256']})
  f.push(str(p),dest,c,t)
  observed=f.shell('sha256sum '+shlex.quote(dest)+'; stat -c %s '+shlex.quote(dest),c,t,timeout=90)
  result['readback']=observed
  assert observed['rc']==0 and observed['stdout'].splitlines()[0].split()[0]==req['sha256'] and int(observed['stdout'].splitlines()[1])==info.st_size
  result.update(status='pushed_and_hash_verified',bytes=info.st_size,sha256=req['sha256'])
 elif kind=='http':
  assert req.get('port',18087)==18087
  method=req.get('method','GET');path=req['path'];assert method in ('GET','POST') and path.startswith('/') and '\r' not in path and '\n' not in path
  body=json.dumps(req['body'],ensure_ascii=False,separators=(',',':')).encode() if 'body' in req else b''
  assert len(body)<=4*1024*1024
  headers={'Host':'127.0.0.1:18087','Connection':'close','Content-Type':'application/json','Content-Length':str(len(body))}
  if req.get('auth',False):
   key=(BASE/'private/llama-api.key').read_text().strip();assert re.fullmatch(r'[A-Za-z0-9_-]{32,128}',key);headers['Authorization']='Bearer '+key
  timeout=min(300,int(req.get('timeout_seconds',120)))
  with socket.create_connection(('127.0.0.1',t[0]),timeout=timeout) as sock:
   f.request(sock,'host:transport-id:'+t[1]);f.request(sock,'tcp:18087')
   packet=(method+' '+path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode()+body
   save(run/'http-dispatch-reserved.json',{'method':method,'path':path,'body_sha256':hashlib.sha256(body).hexdigest(),'auth':req.get('auth',False),'phone_tcp':18087,'through_existing_adb_transport':True})
   sock.sendall(packet);response=http.client.HTTPResponse(sock);response.begin();out=response.read(8*1024*1024+1);assert len(out)<=8*1024*1024
  result.update(status='http_response_received',http_status=response.status,response=out.decode('utf-8'),response_sha256=hashlib.sha256(out).hexdigest(),elapsed_seconds=time.monotonic()-start)
 else:raise RuntimeError('Unknown operation')
except BaseException as e:
 result.update(status='failed_or_unknown_no_retry',error=type(e).__name__,detail=str(e),automatic_replay=False)
result['elapsed_seconds']=time.monotonic()-start
save(run/'result.json',result)
print(json.dumps({'run':str(run),'status':result['status'],'sha256':sha_file(run/'result.json'),'elapsed_seconds':result['elapsed_seconds'],'http_status':result.get('http_status'),'phone_rc':result.get('phone',{}).get('rc'),'error':result.get('detail')},ensure_ascii=False))
sys.exit(1 if result['status']=='failed_or_unknown_no_retry' else 0)
