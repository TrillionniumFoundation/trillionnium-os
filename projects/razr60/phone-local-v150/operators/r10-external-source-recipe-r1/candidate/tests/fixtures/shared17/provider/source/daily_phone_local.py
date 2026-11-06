#!/usr/bin/env python3
"""Resident loopback phone-local VLM provider. Each durable semantic identity runs at most once.

This host produces decisions; it never runs the returned shell/adb actions.
Restarting the daemon or reconnecting transport never removes a turn claim.
"""
import argparse
import concurrent.futures
import contextlib
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid

PARENTS = {'action_ledger.py': '50620b2e27334b7cf311bd6b1c743d71c19c32887e5ed31a07fdf54dac0e7907', 'health_contracts.py': '00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d', 'ledger_round_evidence.py': '87d2b8731883dd06806a45851867332c568fe02deb2b9b8952094b86822e678d', 'model_health.py': '105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80', 'model_slot_cleanup.py': '9144bc864e245d63186f6b37760562e3b42554fdcc42ed792c9081761f315183', 'phone_local_http_worker.py': 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d', 'phone_local_tools.py': '0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54', 'phone_observation_tools.py': '17b8530680fd5cc76406d3249aecf077083bad107c54cd864ae83af298eae8ff', 'phone_task_guards.py': '1e14b8dd4eb4fa3e0d785c1663d376ff634116b904a72a9a38001febad1b4e6e', 'provider_codex_host.py': 'cbdeaaf819ef2fa2d67d3d9707dae86eac6303d6caa4bf194b37cd0816177039', 'provider_openai_compatible.py': '337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc', 'provider_phone_local.py': '082b02a473dc4d75d46a895895b64b96cf25ae24fc61795cb292fc70fd8d9ad6', 'retirement_recovery.py': 'dadea4bc0aed0afc3f46ebf714964ad529bc68670cc5a7892cbccc2a84c78ee3', 'task_postconditions.py': 'd4984cce3e25609d0bc3ef97475edfe74d4795244722e654eb654df3b6e6ceb3'}
WORKER_SHA = 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d'
IDENTITY = ('session_id', 'profile_id', 'task_id', 'turn_id')

# Only this daemon's atomic evidence writers share this lock. No network,
# child wait, data write or fsync runs while it is held. A scanner pins each
# enumerated temporary before these writers can rename it; uncoordinated
# disappearances before that observation remain errors.
_EVIDENCE_WRITE_LOCK = threading.RLock()
_EVIDENCE_GENERATION = 0
_EVIDENCE_WRITERS = 0
MAX_EVIDENCE_SCAN_ATTEMPTS = 3
MAX_EVIDENCE_TEMP_FDS = 256
MAX_EVIDENCE_SCAN_ENTRIES = 200000


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def file_identity(path):
    info = path.stat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()


for _name, _expected in PARENTS.items():
    require(sha(Path(__file__).resolve().with_name(_name)) == _expected, 'protocol source pin differs')
sys.path.insert(0, str(Path(__file__).resolve().parent))
from provider_phone_local import PhoneLocalAdapter, load_local_config, read_private_json, inspect_single_slot
from model_health import ModelHealth, ModelFailure
from model_slot_cleanup import load_binding, admission_identity, bounded_observer
from provider_openai_compatible import ProviderError, MAX_LINE


def private_dir(path):
    require(path.is_absolute() and path.parent.resolve() == path.parent, 'canonical absolute parent required')
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o700, 'private directory ownership/mode differs')


def sync_parent(path):
    fd = os.open(path.parent, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_json(path, value):
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=False)+'\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    sync_parent(path)


def replace_evidence_bytes(path, temporary, raw):
    """Keep the existing durable atomic write, coordinating its two name changes."""
    global _EVIDENCE_GENERATION, _EVIDENCE_WRITERS
    with _EVIDENCE_WRITE_LOCK:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        _EVIDENCE_GENERATION += 1
        _EVIDENCE_WRITERS += 1
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        with _EVIDENCE_WRITE_LOCK:
            os.replace(temporary, path)
            _EVIDENCE_GENERATION += 1
        sync_parent(path)
    finally:
        try:
            os.close(fd)
        finally:
            with _EVIDENCE_WRITE_LOCK:
                _EVIDENCE_GENERATION += 1
                _EVIDENCE_WRITERS -= 1


def replace_json(path, value):
    temporary = path.with_name(path.name+'.'+uuid.uuid4().hex+'.new')
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=False)+'\n').encode()
    replace_evidence_bytes(path, temporary, raw)


def seed_retained_claims(args):
    raw = args.retained_claims.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == args.retained_claims_sha256,
            'retained accepted identity inventory differs')
    rows = json.loads(raw)
    require(isinstance(rows, list) and len(rows) > 0, 'retained identity inventory is required')
    for row in rows:
        identity = row['identity']
        require(all(isinstance(identity.get(n), str) and identity[n] for n in IDENTITY),
                'retained semantic identity invalid')
        key = hashlib.sha256(json.dumps([identity[n] for n in IDENTITY],
                                      separators=(',', ':')).encode()).hexdigest()
        path = args.evidence/'claims'/key
        value = {'identity': identity, 'state': 'retained_pre_daily_accepted_no_redispatch',
                 'origin_receipt_sha256': row['origin_receipt_sha256']}
        try:
            create_json(path, value)
        except FileExistsError:
            prior = json.loads(path.read_bytes())
            require(all(prior['identity'][n] == identity[n] for n in IDENTITY),
                    'retained claim collision; service refused')


class DailyAdapter(PhoneLocalAdapter):
    def __init__(self, args, source, sink, run_dir, shutdown):
        super().__init__(args, source, sink, run_dir)
        self.shutdown = shutdown
        self.child_lock = threading.Lock()
        self.child = None
        self.health_attempt = None
        self.cleanup_binding = None
        self.cleanup_observer = None

    def atomic_record(self, path, value):
        # All inherited PhoneTools/PhoneLocalAdapter callbacks bind this method.
        # Serialization and durable publication match CodexAdapter.atomic_record.
        raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
        replace_evidence_bytes(path, path.with_suffix(path.suffix+'.new'), raw)

    def receive(self, expected=None, timeout=.05):
        if self.shutdown.is_set():
            self.cancelled.set()
        return super().receive(expected, timeout)

    def spawn_model(self, argv):
        with self.child_lock:
            if self.cancelled.is_set() or self.shutdown.is_set():
                raise ProviderError('cancelled before HTTP worker spawn; identity remains consumed')
            if self.args.slot_cleanup_binding is not None:
                require(sha(self.args.slot_cleanup_binding) == self.args.slot_cleanup_binding_sha256,
                        'model cleanup binding changed')
                binding = load_binding(self.args.slot_cleanup_binding)
                before = json.loads((self.run_dir/f'local-{self.round:02d}.slot-before.json').read_bytes())
                admission_identity(binding, self.local_config, before)
                self.cleanup_binding = binding
            if file_identity(Path(self.args.worker)) != self.args.worker_stat:
                self.shutdown.set()
                raise ProviderError('HTTP worker source metadata changed; service stopped accepting')
            self.atomic_record(self.run_dir/f'local-{self.round:02d}.spawn-intent.json',
                               {'argv_sha256': hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                                'state': 'attempt_reserved; actual_spawn_not_yet_observed'})
            _config, digest = read_private_json(self.args.config)
            require(digest == self.args.local_config_sha256, 'local configuration changed; restart requires inspection')
            self.health_attempt = self.args.model_health.begin()
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
            self.child = process
            # Save the child before any fallible receipt operation, so cleanup owns it.
            self.atomic_record(self.run_dir/f'local-{self.round:02d}.spawned.json',
                               {'pid': process.pid, 'process_group': process.pid, 'actual_spawn': True})
            return process

    def completion(self, messages):
        self.health_attempt = None
        try:
            result = super().completion(messages)
            if result is not None and self.health_attempt is not None:
                self.args.model_health.success(self.health_attempt)
            return result
        except ModelFailure as error:
            self.atomic_record(self.run_dir/f'local-{self.round:02d}.model-failure.json',
                               {**error.receipt(), 'model': self.args.model, 'attempt': self.health_attempt})
            if self.health_attempt is not None:
                self.args.model_health.failure(self.health_attempt, error)
            raise
        finally:
            self.join_child()

    def join_child(self):
        with self.child_lock:
            process = self.child
            if process is None:
                return
            # Always address our dedicated group, including leader-exited descendants.
            for number, grace in [(signal.SIGTERM, .3), (signal.SIGKILL, .2)]:
                try:
                    os.killpg(process.pid, number)
                except ProcessLookupError:
                    break
                deadline = time.monotonic()+grace
                while time.monotonic() < deadline:
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(.02)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise ProviderError('owned HTTP worker did not exit after kill; service cleanup unknown')
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                self.atomic_record(self.run_dir/f'local-{self.round:02d}.joined.json',
                                   {'pid': process.pid, 'child_wait_returned': True,
                                    'dedicated_process_group_absent': True})
                self.child = None
                if self.cleanup_binding is not None:
                    cleanup = bounded_observer(self.local_config, self.args.slot_cleanup_binding,
                        self.args.slot_cleanup_binding_sha256, self.cleanup_binding['server_identity'],
                        self.last_request_id, self.last_request_sha256, self.last_request_bytes,
                        self.run_dir, self.round, lambda child: setattr(self, 'cleanup_observer', child))
                    observation = {**cleanup['last_slot_observation'], 'cleanup_controller': cleanup}
                    admitted = cleanup['admitted']
                else:
                    observation = inspect_single_slot(self.local_config)
                    admitted = observation.get('observed') and observation.get('idle')
                # This is the existing per-round commit, after the bounded observer controller returns.
                self.atomic_record(self.run_dir/f'local-{self.round:02d}.slot-after.json', observation)
                if not admitted:
                    self.shutdown.set()
                    if not self.cancelled.is_set():
                        raise ProviderError('phone inference cleanup unconfirmed; inspect original slot/receipts before recovery')
                return
            raise ProviderError('dedicated HTTP worker process group still exists; cleanup unknown')


_EXPECTED_RUN_NAME = re.compile(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}\Z')
_EXPECTED_EVIDENCE_TEMP = re.compile(
    r'(?:codex-[0-9]{2}\.(?:spawn-intent|spawned|joined|images|model-failure)\.json\.new'
    r'|local-[0-9]{2}\.(?:spawn-intent|spawned|joined|images|model-failure|slot-before|slot-after|request|request-identity|decision|coordinate-map|worker-result|model-action|mapping)\.json\.new'
    r'|recovery-(?:inspection|unresolved)-[0-9a-f]{32}\.json\.new'
    r'|dispatch-[0-9]{3}\.json\.new|terminal\.json\.new|business-outcome\.json\.new|task-contract\.json\.new|health-contract\.json\.new|health-outcome\.json\.new'
    r'|(?:result|semantic)-[0-9a-f]{64}\.json\.new'
    r'|capture-[0-9a-f]{32}\.json\.new'
    r'|(?:connection-ended|cleanup-failure)\.json\.[0-9a-f]{32}\.new)\Z')


def expected_evidence_temporary(item, evidence_root):
    """Only the exact private run-level atomic-writer temporary grammar."""
    try:
        relative = item.relative_to(evidence_root)
    except ValueError:
        return False
    return (len(relative.parts) == 2 and _EXPECTED_RUN_NAME.fullmatch(relative.parts[0]) is not None
            and _EXPECTED_EVIDENCE_TEMP.fullmatch(relative.parts[1]) is not None)


def evidence_canonical(item, evidence_root):
    require(expected_evidence_temporary(item, evidence_root), 'unrecognized evidence temporary')
    if re.fullmatch(r'(?:connection-ended|cleanup-failure)\.json\.[0-9a-f]{32}\.new', item.name):
        return item.with_name(item.name.rsplit('.', 2)[0])
    return item.with_name(item.name[:-4])


def evidence_identity(info):
    return info.st_dev, info.st_ino


def evidence_regular(info):
    require(stat.S_ISREG(info.st_mode), 'evidence contains a non-regular file')
    require(info.st_nlink == 1, 'evidence contains a hard-linked or unlinked file')


@contextlib.contextmanager
def evidence_snapshot(directory, evidence_root, expected_identity=None, *, entry_budget=None):
    """Pin enumerated temporaries before a coordinated writer can rename them.

    Only temporary FDs are retained, with a fixed per-directory bound. Canonical
    files are identified by the directory enumeration and checked with nofollow
    stat. An uncoordinated disappearance before a temporary can be pinned fails
    closed; it is never inferred to be a rename from the target's existence.
    """
    if entry_budget is None:
        entry_budget = MAX_EVIDENCE_SCAN_ENTRIES
    require(type(entry_budget) is int and 0 <= entry_budget <= MAX_EVIDENCE_SCAN_ENTRIES,
            'evidence scan entry budget differs')
    require(directory.parent.resolve() == directory.parent, 'evidence directory has a symlink ancestor')
    parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    held = []
    try:
        with _EVIDENCE_WRITE_LOCK:
            parent = os.fstat(parent_fd)
            require(stat.S_ISDIR(parent.st_mode) and evidence_identity(directory.lstat()) == evidence_identity(parent),
                    'evidence directory identity changed')
            require(expected_identity is None or expected_identity == evidence_identity(parent),
                    'enumerated evidence directory identity changed')
            snapshot = {'directory': directory, 'parent_fd': parent_fd, 'parent_identity': evidence_identity(parent),
                        'entries': {}, 'renamed': False}
            with os.scandir(parent_fd) as entries:
                for entry in entries:
                    require(len(snapshot['entries']) < entry_budget, 'evidence scan entry capacity reached')
                    item = directory/entry.name
                    observed = {'identity': (parent.st_dev, entry.inode()),
                                'directory': entry.is_dir(follow_symlinks=False), 'fd': None}
                    if not observed['directory'] and expected_evidence_temporary(item, evidence_root):
                        require(len(held) < MAX_EVIDENCE_TEMP_FDS, 'evidence temporary descriptor capacity reached')
                        fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                        held.append(fd)
                        info = os.fstat(fd)
                        evidence_regular(info)
                        require(evidence_identity(info) == observed['identity'], 'enumerated evidence temporary identity changed')
                        observed['fd'] = fd
                    snapshot['entries'][item] = observed
        yield snapshot
        require(evidence_identity(directory.lstat()) == snapshot['parent_identity'],
                'evidence directory identity changed during scan')
    finally:
        for fd in reversed(held):
            os.close(fd)
        os.close(parent_fd)


def renamed_evidence_observation(item, evidence_root, snapshot, observed):
    require(observed['fd'] is not None, 'missing evidence has no pinned temporary identity')
    try:
        os.stat(item.name, dir_fd=snapshot['parent_fd'], follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError('evidence temporary did not disappear at rename')
    target = evidence_canonical(item, evidence_root)
    current = os.stat(target.name, dir_fd=snapshot['parent_fd'], follow_symlinks=False)
    pinned = os.fstat(observed['fd'])
    evidence_regular(current)
    evidence_regular(pinned)
    require(evidence_identity(current) == evidence_identity(pinned) == observed['identity'],
            'evidence rename target identity differs from pinned temporary')
    require(current.st_size == pinned.st_size, 'evidence rename target size changed during observation')
    snapshot['renamed'] = True
    return current, target


def evidence_item_observation(item, evidence_root, snapshot=None):
    if snapshot is None:
        # A pathname alone cannot prove a disappeared temporary was renamed.
        info = item.lstat()
        evidence_regular(info)
        return info, item
    require(item.parent == snapshot['directory'] and item in snapshot['entries'],
            'evidence item was not in the current directory snapshot')
    require(evidence_identity(snapshot['directory'].lstat()) == snapshot['parent_identity'],
            'evidence directory identity changed during observation')
    observed = snapshot['entries'][item]
    require(not observed['directory'], 'evidence size requested for a directory')
    try:
        info = os.stat(item.name, dir_fd=snapshot['parent_fd'], follow_symlinks=False)
    except FileNotFoundError:
        if observed['fd'] is None:
            raise
        return renamed_evidence_observation(item, evidence_root, snapshot, observed)
    evidence_regular(info)
    if evidence_identity(info) != observed['identity']:
        # A canonical may have been enumerated before an already pinned .new
        # atomically replaced it. Only that exact pinned object explains this.
        replacements = [(path, row) for path, row in snapshot['entries'].items()
                        if row['fd'] is not None and row['identity'] == evidence_identity(info)
                        and evidence_canonical(path, evidence_root) == item]
        require(observed['fd'] is None and len(replacements) == 1, 'evidence file identity changed')
        return renamed_evidence_observation(replacements[0][0], evidence_root, snapshot, replacements[0][1])
    if observed['fd'] is not None:
        pinned = os.fstat(observed['fd'])
        evidence_regular(pinned)
        require(evidence_identity(pinned) == observed['identity'], 'pinned evidence temporary identity changed')
    return info, item


def evidence_item_size(item, evidence_root, snapshot=None):
    """Return counted bytes; a proven rename counts its surviving canonical."""
    return evidence_item_observation(item, evidence_root, snapshot)[0].st_size


def evidence_totals(evidence_root):
    """Count a stable pass; discard and bound retries after proven renames.

    This is the capacity function used by serve. No missing pathname is skipped.
    The FD-pinned rename proof prevents inode reuse from validating an unlink.
    A changed canonical, unknown I/O failure or unproved external writer race
    remains an error. Generation tracking covers this daemon's atomic writers,
    not independent processes' writes or filesystem-wide snapshot consistency.
    """
    for _attempt in range(MAX_EVIDENCE_SCAN_ATTEMPTS):
        with _EVIDENCE_WRITE_LOCK:
            generation, active = _EVIDENCE_GENERATION, _EVIDENCE_WRITERS
        pending, counted, renamed, visited = [(evidence_root, None)], {}, False, 0
        while pending:
            directory, expected = pending.pop()
            with evidence_snapshot(directory, evidence_root, expected,
                                   entry_budget=MAX_EVIDENCE_SCAN_ENTRIES-visited) as snapshot:
                visited += len(snapshot['entries'])
                aliases = {row['identity']: (path, evidence_canonical(path, evidence_root))
                           for path, row in snapshot['entries'].items() if row['fd'] is not None}
                for item, observed in snapshot['entries'].items():
                    if observed['directory']:
                        pending.append((item, observed['identity']))
                        continue
                    info, resolved = evidence_item_observation(item, evidence_root, snapshot)
                    identity = evidence_identity(info)
                    # A pinned temporary may have been counted before its
                    # rename, then observed again under the canonical name.
                    # Normalize only that still-pinned pair, never arbitrary
                    # equal inode numbers at different paths.
                    alias = aliases.get(identity)
                    if alias is not None:
                        require(resolved in alias, 'evidence rename alias differs')
                        resolved = alias[1]
                    prior = counted.get(identity)
                    require(prior is None or prior[0] == resolved,
                            'evidence identity appeared at distinct paths')
                    counted[identity] = (resolved, max(info.st_size, prior[1] if prior else 0))
                # Recheck pinned entries even when they were counted before the
                # rename. This catches replacement after old-canonical counting.
                for item, observed in snapshot['entries'].items():
                    if observed['fd'] is not None:
                        evidence_item_observation(item, evidence_root, snapshot)
                renamed = renamed or snapshot['renamed']
        with _EVIDENCE_WRITE_LOCK:
            stable = not active and not _EVIDENCE_WRITERS and generation == _EVIDENCE_GENERATION
        if stable and not renamed:
            return sum(size for _path, size in counted.values()), len(counted)
    raise RuntimeError('evidence changed during capacity scan; bounded retry exhausted')


def raise_evidence_scan_error(error):
    # os.walk otherwise suppresses scandir errors and can undercount a lost run.
    raise error


def serve(args):
    os.umask(0o077)
    for directory in [args.state, args.evidence, args.evidence/'claims', args.cwd]:
        private_dir(directory)
    lock = os.open(args.state/'daemon.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    require(os.fstat(lock).st_uid == os.getuid() and stat.S_IMODE(os.fstat(lock).st_mode) == 0o600,
            'daemon lock ownership differs')
    require(sha(Path(args.worker)) == WORKER_SHA, 'selected HTTP worker byte pin differs; review update before restart')
    args.worker_stat = file_identity(Path(args.worker))
    seed_retained_claims(args)
    # A daemon crash/partial spawn cannot silently leave old model work running.
    # Keep all turn claims and require operator inspection of any unjoined round.
    for intent in list(args.evidence.glob('*/codex-*.spawn-intent.json')) + list(args.evidence.glob('*/local-*.spawn-intent.json')):
        joined = intent.with_name(intent.name.replace('.spawn-intent.json', '.joined.json'))
        require(joined.is_file(), 'unjoined prior inference-client round; inspect exact receipts before service restart')
    args.contracts = args.state/'task-contracts'
    for directory in [args.contracts, args.contracts/'templates', args.contracts/'bindings']:
        private_dir(directory)
    args.model_health = ModelHealth(args.state/'model-health-phone-local.json', args.model, replace_json)
    shutdown = threading.Event()
    adapters, workers_lock = set(), threading.Lock()
    slots = threading.BoundedSemaphore(args.workers)
    instance = uuid.uuid4().hex
    def stop(_number, _frame):
        shutdown.set()
    for number in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
        signal.signal(number, stop)
    def capacity():
        total, files = evidence_totals(args.evidence)
        free = os.statvfs(args.state)
        return (total < args.max_evidence_bytes-128*MAX_LINE*args.workers and files < 200000 and
                free.f_bavail*free.f_frsize > 256*MAX_LINE*args.workers)
    def work(connection, run_dir):
        adapter = None
        source = sink = None
        try:
            connection.settimeout(10)
            source, sink = connection.makefile('rb'), connection.makefile('w')
            adapter = DailyAdapter(args, source, sink, run_dir, shutdown)
            with workers_lock:
                adapters.add(adapter)
                if shutdown.is_set():
                    adapter.cancelled.set()
            adapter.run()
        except Exception as error:
            if adapter is not None and adapter.terminal is None:
                try:
                    adapter.emit('turn.fail', error=str(error)[:1024])
                except Exception:
                    pass
            replace_json(run_dir/'connection-ended.json',
                         {'error': type(error).__name__, 'claimed': bool(adapter and adapter.claimed),
                          'outcome': 'consult persisted terminal and dispatch receipts; never redispatch'})
        finally:
            cleanup_error = None
            operations = []
            if adapter is not None:
                operations += [adapter.join_child, adapter.frames.close, adapter.inputs.close]
            def end_socket():
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            operations += [end_socket]
            operations += [stream.close for stream in [source, sink] if stream is not None]
            operations += [connection.close]
            for operation in operations:
                try:
                    operation()
                except BaseException as error:
                    cleanup_error = cleanup_error or error
            with workers_lock:
                adapters.discard(adapter)
            slots.release()
            if cleanup_error is not None:
                shutdown.set()
                replace_json(run_dir/'cleanup-failure.json', {'error_class': type(cleanup_error).__name__,
                             'service_stopped_accepting': True, 'identity_never_released': True})
    with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', args.port))
        listener.listen(args.workers)
        listener.settimeout(.5)
        replace_json(args.state/'ready.json', {'schema': 'hepta.daily-provider.ready.v1',
                     'pid': os.getpid(), 'instance': instance, 'port': args.port,
                     'source_sha256': sha(Path(__file__)), 'http_worker_sha256': WORKER_SHA,
                     'model': args.model, 'workers': args.workers, 'accepting': True,
                     'readiness_scope': 'transport_only',
                     'model_health_path': str(args.state/'model-health-phone-local.json'),
                     'backend': 'phone_local_http', 'config_sha256': args.local_config_sha256,
                     'inference_location_operator_attestation': 'phone',
                     'service_manifest_sha256': args.local_config['service_manifest_sha256']})
        try:
            while not shutdown.is_set():
                if not slots.acquire(timeout=.5):
                    continue
                submitted = False
                connection = None
                try:
                    if not capacity():
                        raise ProviderError('evidence capacity reached; retain claims and archive evidence manually')
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    if shutdown.is_set():
                        continue
                    run_dir = args.evidence/(time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex)
                    run_dir.mkdir(mode=0o700)
                    pool.submit(work, connection, run_dir)
                    submitted = True
                finally:
                    if not submitted:
                        if connection is not None:
                            connection.close()
                        slots.release()
        finally:
            stop(0, None)
            listener.close()
            replace_json(args.state/'ready.json', {'schema': 'hepta.daily-provider.ready.v1',
                         'pid': os.getpid(), 'instance': instance, 'accepting': False})
    os.close(lock)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--state', type=Path, required=True)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--port', type=int, default=18082)
    p.add_argument('--workers', type=int, default=1)
    p.add_argument('--timeout', type=int, default=120)
    p.add_argument('--slot-cleanup-binding', type=Path,
                   help='next-combination private actual server identity binding; omitted preserves old cleanup')
    p.add_argument('--max-evidence-bytes', type=int, default=8*1024*MAX_LINE)
    p.add_argument('--retained-claims', type=Path, required=True)
    p.add_argument('--retained-claims-sha256', required=True)
    args = p.parse_args()
    require(args.workers == 1 and 1 <= args.timeout <= 300 and 1024 <= args.port <= 65535,
            'phone-local service requires one worker and bounded deadlines')
    require(args.max_evidence_bytes >= 1024*MAX_LINE, 'evidence capacity differs')
    args.config = args.config.expanduser().absolute()
    args.local_config, args.local_config_sha256 = load_local_config(args.config)
    args.model = args.local_config['model']
    if args.slot_cleanup_binding is not None:
        args.slot_cleanup_binding = args.slot_cleanup_binding.expanduser().absolute()
        load_binding(args.slot_cleanup_binding)
        args.slot_cleanup_binding_sha256 = sha(args.slot_cleanup_binding)
    args.state = args.state.expanduser().absolute()
    args.evidence, args.cwd = args.state/'evidence', args.state/'empty-cwd'
    args.worker = Path(__file__).resolve().with_name('phone_local_http_worker.py')
    serve(args)


if __name__ == '__main__':
    main()
