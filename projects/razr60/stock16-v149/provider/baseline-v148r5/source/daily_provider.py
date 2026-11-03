#!/usr/bin/env python3
"""Resident loopback Codex provider. Each durable semantic identity runs at most once.

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

PARENTS = {
    'provider_codex_host.py': '85c6f3d5def493d591f73b9820c89b1b6e3d78a609863879b4a19356c575a713',
    'provider_openai_compatible.py': 'de8225db666382df4ef99a1c5caeb2a30c2c1c5f17f8adb6c2a0a7d96dfb8ae0',
    'phone_observation_tools.py': '40232edb40b8261385da64b37ab27fb14883daa51cd8f0403006f0c4c40d276f',
}
CLI_SHA = '50ab38ba21d0d9f8346f32f41848382f15b556190f3c7a07e885a4fb73e379c8'
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
from provider_codex_host import CodexAdapter
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


class DailyAdapter(CodexAdapter):
    def __init__(self, args, source, sink, run_dir, shutdown):
        super().__init__(args, source, sink, run_dir)
        self.shutdown = shutdown
        self.child_lock = threading.Lock()
        self.child = None

    def receive(self, expected=None, timeout=.05):
        if self.shutdown.is_set():
            self.cancelled.set()
        return super().receive(expected, timeout)

    def spawn_codex(self, argv):
        with self.child_lock:
            if self.cancelled.is_set() or self.shutdown.is_set():
                raise ProviderError('cancelled before CLI spawn; identity remains consumed')
            if file_identity(Path(self.args.codex)) != self.args.cli_stat:
                self.shutdown.set()
                raise ProviderError('CLI executable metadata changed; service stopped accepting')
            self.atomic_record(self.run_dir/f'codex-{self.round:02d}.spawn-intent.json',
                               {'argv_sha256': hashlib.sha256(json.dumps(argv).encode()).hexdigest(),
                                'state': 'attempt_reserved; actual_spawn_not_yet_observed'})
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
            self.child = process
            # Save the child before any fallible receipt operation, so cleanup owns it.
            self.atomic_record(self.run_dir/f'codex-{self.round:02d}.spawned.json',
                               {'pid': process.pid, 'process_group': process.pid, 'actual_spawn': True})
            return process

    def completion(self, messages):
        try:
            return super().completion(messages)
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
                raise ProviderError('owned CLI did not exit after kill; service cleanup unknown')
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                self.atomic_record(self.run_dir/f'codex-{self.round:02d}.joined.json',
                                   {'pid': process.pid, 'child_wait_returned': True,
                                    'dedicated_process_group_absent': True})
                self.child = None
                return
            raise ProviderError('dedicated CLI process group still exists; cleanup unknown')


_EXPECTED_RUN_NAME = re.compile(r'[0-9]{8}-[0-9]{6}-[0-9a-f]{32}\Z')
_EXPECTED_EVIDENCE_TEMP = re.compile(
    r'(?:codex-[0-9]{2}\.(?:spawn-intent|spawned|joined|images)\.json\.new'
    r'|dispatch-[0-9]{3}\.json\.new|terminal\.json\.new'
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
    require(sha(Path(args.codex)) == CLI_SHA, 'selected CLI byte pin differs; review update before restart')
    args.cli_stat = file_identity(Path(args.codex))
    seed_retained_claims(args)
    # A daemon crash/partial spawn cannot silently leave old model work running.
    # Keep all turn claims and require operator inspection of any unjoined round.
    for intent in args.evidence.glob('*/codex-*.spawn-intent.json'):
        joined = intent.with_name(intent.name.replace('.spawn-intent.json', '.joined.json'))
        require(joined.is_file(), 'unjoined prior CLI round; inspect exact receipts before service restart')
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
                     'source_sha256': sha(Path(__file__)), 'cli_sha256': CLI_SHA,
                     'model': args.model, 'workers': args.workers, 'accepting': True})
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
    p.add_argument('--codex', type=Path, required=True)
    p.add_argument('--model', default='gpt-6.1-sol')
    p.add_argument('--port', type=int, default=18082)
    p.add_argument('--workers', type=int, default=2)
    p.add_argument('--timeout', type=int, default=120)
    p.add_argument('--max-evidence-bytes', type=int, default=8*1024*MAX_LINE)
    p.add_argument('--retained-claims', type=Path, required=True)
    p.add_argument('--retained-claims-sha256', required=True)
    args = p.parse_args()
    require(1 <= args.workers <= 4 and 1 <= args.timeout <= 300 and 1024 <= args.port <= 65535,
            'service bound invalid')
    require(args.max_evidence_bytes >= 1024*MAX_LINE and args.model == 'gpt-6.1-sol', 'selected model/capacity differs')
    args.state = args.state.expanduser().absolute()
    args.evidence, args.cwd = args.state/'evidence', args.state/'empty-cwd'
    args.codex = str(args.codex.resolve(strict=True))
    serve(args)


if __name__ == '__main__':
    main()
