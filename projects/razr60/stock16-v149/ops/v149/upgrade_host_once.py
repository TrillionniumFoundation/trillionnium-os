"""Root-reviewed, idle-only upgrade of the two owned Mac HEPTA jobs.

No phone, USB, ADB lifecycle, remote source, credentials or task-state mutations.
Every step is recorded; an interrupted upgrade is never automatically replayed.
"""
from pathlib import Path
import datetime, hashlib, json, os, plistlib, subprocess, time, sys

BASE = Path(__file__).resolve().parent
CANDIDATE = BASE.parent / 'stock16-hepta-task-provider-C-v149-r1'
INSTALL = Path.home() / 'Library/Application Support/HEPTA/provider/v149-r1'
STATE = INSTALL.parent / 'state'
AGENTS = Path.home() / 'Library/LaunchAgents'
LABELS = ['org.trillionnium.hepta.daily-provider', 'org.trillionnium.hepta.daily-bridge']
OLD_PIDS = None
STEPS = []

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def save(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    fd = os.open(BASE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync(BASE)

def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def run(argv, timeout=10):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    r = {'argv': argv, 'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
    STEPS.append(r)
    return r

def alive(pid):
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False

def wait_absent(pid):
    end = time.monotonic() + 12
    while alive(pid) and time.monotonic() < end: time.sleep(.1)
    assert not alive(pid), 'Owned service has not exited; no replacement started'

def claims():
    return {p.name: sha(p.read_bytes()) for p in (STATE / 'provider/evidence/claims').iterdir() if p.is_file()}

def write_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)

assert os.getuid() == 501
plan_raw = (CANDIDATE / 'INSTALL-PLAN.json').read_bytes()
assert len(sys.argv) == 3 and sha(plan_raw) == sys.argv[1]
plan = json.loads(plan_raw)
OLD_PIDS = plan['baseline_current_pids']
seal_raw = (CANDIDATE / 'SOURCE-SEAL.json').read_bytes()
assert sha(seal_raw) == sys.argv[2]
seal = json.loads(seal_raw)
for name, expected in plan['old_source_pins'].items():
    assert sha((INSTALL.with_name('v148-r5') / 'source' / name).read_bytes()) == expected
assert plan['claim_snapshot_sha256'] == sha((CANDIDATE / 'CURRENT-CLAIMS-SNAPSHOT.json').read_bytes())
assert json.loads((BASE / 'OLD-CLAIMS-SNAPSHOT.json').read_bytes()) == json.loads((CANDIDATE / 'CURRENT-CLAIMS-SNAPSHOT.json').read_bytes())
for name, pin in seal['files'].items():
    raw = (CANDIDATE / name).read_bytes()
    assert len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], name
for name in (CANDIDATE / 'source').glob('*.py'): compile(name.read_bytes(), str(name), 'exec')
assert str(INSTALL) == plan['install'] and str(STATE) == plan['state_unchanged']
assert not INSTALL.exists() and not INSTALL.is_symlink()
assert claims() == json.loads((BASE / 'OLD-CLAIMS-SNAPSHOT.json').read_text())
for label in LABELS:
    raw = (AGENTS / (label + '.plist')).read_bytes()
    assert sha(raw) == plan['plists'][label]['old_sha256']
    assert plistlib.loads(raw)['ProgramArguments'] == plan['plists'][label]['old_argv']
    result = run(['launchctl', 'print', 'gui/501/' + label])
    assert result['rc'] == 0 and ('pid = ' + str(OLD_PIDS[label])) in result['stdout']
    sockets = run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(OLD_PIDS[label]), '-iTCP', '-sTCP:ESTABLISHED'])
    assert sockets['rc'] == 1 and not sockets['stdout'], 'Active stream exists; no service stop'
for intent in (STATE / 'provider/evidence').glob('*/codex-*.spawn-intent.json'):
    assert intent.with_name(intent.name.replace('.spawn-intent.json', '.joined.json')).is_file()
for folder in (STATE / 'provider/evidence').iterdir():
    if folder.is_dir() and (folder / 'provider-in.jsonl').exists():
        assert (folder / 'terminal.json').is_file(), 'A prior accepted outcome needs inspection'
watch = run(['launchctl', 'print', 'gui/501/org.trillionnium.hepta.transport-watch'])
assert watch['rc'] == 0 and 'pid = 15612' in watch['stdout']
ready = json.loads((STATE / 'provider/ready.json').read_bytes())
assert ready['pid'] == OLD_PIDS[LABELS[0]] and ready['accepting'] is True
save('HOST-UPGRADE-V149-ONCE.intent.json', {'plan_sha256': sha(plan_raw), 'seal_sha256': sha(seal_raw),
     'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'old_ready': ready,
     'claims': claims(), 'steps_before_any_stop': STEPS, 'automatic_replay': False})

try:
    INSTALL.mkdir(mode=0o700)
    (INSTALL / 'source').mkdir(mode=0o700)
    for relative in sorted(plan['source_pins']) + ['retained-claims.json', 'register_task_contract.py']:
        write_file(INSTALL / relative, (CANDIDATE / relative).read_bytes())
    write_file(INSTALL / 'installed-source-seal.json', seal_raw)
    write_file(INSTALL / 'installed-plan.json', plan_raw)
    for label in reversed(LABELS):
        result = run(['launchctl', 'bootout', 'gui/501/' + label], timeout=35)
        assert result['rc'] == 0, result
        wait_absent(OLD_PIDS[label])
    sockets = run(['/usr/sbin/lsof', '-nP', '-iTCP:18082', '-sTCP:LISTEN'])
    assert sockets['rc'] == 1 and not sockets['stdout'], 'Provider port is still owned'
    for label in LABELS:
        target = AGENTS / (label + '.plist')
        assert sha(target.read_bytes()) == plan['plists'][label]['old_sha256']
        raw = (CANDIDATE / 'launchagents' / target.name).read_bytes()
        assert sha(raw) == plan['plists'][label]['new_sha256']
        temporary = target.with_name(target.name + '.v149-r1.new')
        write_file(temporary, raw); os.replace(temporary, target); sync(AGENTS)
    result = run(['launchctl', 'bootstrap', 'gui/501', str(AGENTS / (LABELS[0] + '.plist'))])
    assert result['rc'] == 0, result
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ready = json.loads((STATE / 'provider/ready.json').read_bytes())
        if ready.get('accepting') and ready.get('source_sha256') == plan['source_pins']['source/daily_provider.py']['sha256'] and ready.get('model') == 'gpt-6.1-sol': break
        time.sleep(.2)
    else: raise RuntimeError('New provider readiness not observed; do not send a task')
    assert alive(ready['pid']) and ready['pid'] != OLD_PIDS[LABELS[0]]
    result = run(['launchctl', 'bootstrap', 'gui/501', str(AGENTS / (LABELS[1] + '.plist'))])
    assert result['rc'] == 0, result
    time.sleep(1)
    jobs = [run(['launchctl', 'print', 'gui/501/' + label]) for label in LABELS]
    assert all(x['rc'] == 0 and 'state = running' in x['stdout'] for x in jobs)
    assert claims() == json.loads((BASE / 'OLD-CLAIMS-SNAPSHOT.json').read_text())
    assert alive(15612), 'Transport watcher unexpectedly changed'
    save('HOST-UPGRADE-V149-RESULT.json', {'status': 'PASS_TWO_OWNED_MAC_SERVICES_SWITCHED',
         'new_ready': ready, 'steps': STEPS, 'claims_unchanged': True,
         'transport_watch_pid_unchanged': 15612, 'phone_operations': 0})
    print(json.dumps({'status': 'PASS_TWO_OWNED_MAC_SERVICES_SWITCHED', 'ready': ready}))
except BaseException as error:
    save('HOST-UPGRADE-V149-FAILED.json', {'error': type(error).__name__, 'message': str(error),
         'steps': STEPS, 'no_automatic_replay_or_claim_removal': True})
    raise

