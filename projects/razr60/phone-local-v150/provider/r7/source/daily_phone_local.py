#!/usr/bin/env python3
"""Resident loopback phone-local VLM provider. Each durable semantic identity runs at most once.

This host produces decisions; it never runs the returned shell/adb actions.
Restarting the daemon or reconnecting transport never removes a turn claim.
"""
import argparse
import concurrent.futures
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

# Explicit source-candidate pins based on upstream 2d8ad42; never refreshed at runtime.
PARENTS = {
    'action_ledger.py': 'f02159cacff4b010276b9a62397e449ccf89040d2fde9a07a122715da342393e',
    'health_contracts.py': '00adea791c00eaac52f65716cb158ee73f38bdded96f1718578ec92f5091d32d',
    'model_health.py': '105b401fbab1c151e890a3e6e4774322eb62a9e7799744b4d3cef01b6e1c0f80',
    'phone_local_http_worker.py': 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d',
    'phone_local_tools.py': 'e21f49b6e46066200b4e2849d671f04c12930ace1bd5543c63df0e18b8bd5aea',
    'phone_observation_tools.py': '24ee4f67f2f2fc12f74512090915177b8ca035db80f0a5537120d69944aa78ca',
    'phone_task_guards.py': 'f522883ceb862e17d22d10c9f43cdc76683557c68369a49640da0e15052bcd59',
    'provider_codex_host.py': 'cbdeaaf819ef2fa2d67d3d9707dae86eac6303d6caa4bf194b37cd0816177039',
    'provider_openai_compatible.py': '337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc',
    'provider_phone_local.py': 'd11dfd1b1c477e83fac6fe05af3c4498ba7ded07c32432c942d24ad757695524',
    'retirement_recovery.py': '0e5e5c965e3e111e92c5b45eacbbf141996cfa0de4122bf98ad3c8d5f65af774',
    'task_postconditions.py': '25305e7f44f396edd2cd04b095701c6b91be9c66d9beae20bfe75b403f5df964',
}
WORKER_SHA = 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d'
IDENTITY = ('session_id', 'profile_id', 'task_id', 'turn_id')


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


def replace_json(path, value):
    temporary = path.with_name(path.name+'.'+uuid.uuid4().hex+'.new')
    create_json(temporary, value)
    os.replace(temporary, path)
    sync_parent(path)


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

    def receive(self, expected=None, timeout=.05):
        if self.shutdown.is_set():
            self.cancelled.set()
        return super().receive(expected, timeout)

    def spawn_model(self, argv):
        with self.child_lock:
            if self.cancelled.is_set() or self.shutdown.is_set():
                raise ProviderError('cancelled before HTTP worker spawn; identity remains consumed')
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
                observation = inspect_single_slot(self.local_config)
                self.atomic_record(self.run_dir/f'local-{self.round:02d}.slot-after.json', observation)
                if not observation.get('observed') or not observation.get('idle'):
                    self.shutdown.set()
                    if not self.cancelled.is_set():
                        raise ProviderError('phone inference cleanup unconfirmed; inspect original slot/receipts before recovery')
                return
            raise ProviderError('dedicated HTTP worker process group still exists; cleanup unknown')


_EXPECTED_RUN_NAME = re.compile(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}\Z')
_EXPECTED_EVIDENCE_TEMP = re.compile(
    r'(?:codex-[0-9]{2}\.(?:spawn-intent|spawned|joined|images|model-failure)\.json\.new'
    r'|local-[0-9]{2}\.(?:spawn-intent|spawned|joined|images|model-failure|slot-before|slot-after|request|decision|coordinate-map|worker-result)\.json\.new'
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


def evidence_item_size(item, evidence_root):
    """Count extant files; tolerate only an expected temporary's rename race.

    Atomic writers rename .new to its canonical record concurrently with the
    capacity walk. A disappeared canonical file, unknown name, missing parent,
    symlink or any other I/O failure remains an error, not an empty observation.
    """
    try:
        info = item.lstat()
    except FileNotFoundError:
        if not expected_evidence_temporary(item, evidence_root):
            raise
        parent = item.parent.lstat()
        require(stat.S_ISDIR(parent.st_mode), 'evidence temporary parent is not a real directory')
        return None
    require(stat.S_ISREG(info.st_mode), 'evidence contains a non-regular file')
    return info.st_size


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
        total, files = 0, 0
        for directory, _sub, names in os.walk(args.evidence, followlinks=False, onerror=raise_evidence_scan_error):
            for name in names:
                item = Path(directory)/name
                size = evidence_item_size(item, args.evidence)
                if size is None:
                    continue
                total += size
                files += 1
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
                     'configured_operation_profile':args.local_config.get('operation_profile', 'fixed19-v150-r7'),
                     'configured_context_tokens':args.local_config.get('context_tokens'),
                     'max_prompt_bytes':args.local_config['max_prompt_bytes'],
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
    args.state = args.state.expanduser().absolute()
    args.evidence, args.cwd = args.state/'evidence', args.state/'empty-cwd'
    args.worker = Path(__file__).resolve().with_name('phone_local_http_worker.py')
    serve(args)


if __name__ == '__main__':
    main()
