"""Root packaging of a reviewed, frozen provider candidate. No service actions."""
from pathlib import Path
import ast, copy, datetime, hashlib, json, os, plistlib, re, subprocess

BASE = Path(__file__).resolve().parent
OLD = Path.home() / 'Library/Application Support/HEPTA/provider/v148-r5'
INSTALL = OLD.with_name('v149-r1')
STATE = OLD.parent / 'state'
LABELS = ['org.trillionnium.hepta.daily-provider', 'org.trillionnium.hepta.daily-bridge']
EXPECTED = {
 'daily_provider.py':'359acc41a67d001f0c84269e450f05afd31801a397b28e1ff9e43a889bde391f',
 'provider_codex_host.py':'85c6f3d5def493d591f73b9820c89b1b6e3d78a609863879b4a19356c575a713',
 'phone_observation_tools.py':'40232edb40b8261385da64b37ab27fb14883daa51cd8f0403006f0c4c40d276f',
 'provider_openai_compatible.py':'de8225db666382df4ef99a1c5caeb2a30c2c1c5f17f8adb6c2a0a7d96dfb8ae0',
 'ssh_exec_persistent_bridge.py':'6a0b6da0ce197c5f91ac15dfa487a45265b946f54f0b5f0fb5aa7820aea06bec',
}
sha = lambda raw: hashlib.sha256(raw).hexdigest()

def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

def save(name, value):
    write(BASE/name, (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode())

assert os.getuid() == 501 and not INSTALL.exists()
for name, digest in EXPECTED.items():
    assert sha((OLD/'source'/name).read_bytes()) == digest, name
bridge = BASE/'source/ssh_exec_persistent_bridge.py'
if bridge.exists():
    assert bridge.read_bytes() == (OLD/'source/ssh_exec_persistent_bridge.py').read_bytes()
else:
    write(bridge, (OLD/'source/ssh_exec_persistent_bridge.py').read_bytes())
write(BASE/'retained-claims.json', (OLD/'retained-claims.json').read_bytes())
assert sha((BASE/'retained-claims.json').read_bytes()) == '929815622aa8ec0f278b9b3cca2fd3f99361cbb6e71f627871d3da16a85b856b'
sources = sorted((BASE/'source').glob('*.py'))
assert len(sources) == 8 and len(list((BASE/'source').iterdir())) == 8
pins = {}
for path in sources:
    raw = path.read_bytes(); compile(raw, str(path), 'exec')
    pins[str(path.relative_to(BASE))] = {'bytes':len(raw), 'sha256':sha(raw)}
tree = ast.parse((BASE/'source/daily_provider.py').read_bytes())
parents = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == 'PARENTS' for t in node.targets))
for name, digest in parents.items(): assert pins['source/'+name]['sha256'] == digest, name
assert pins['source/provider_openai_compatible.py']['sha256'] == EXPECTED['provider_openai_compatible.py']
assert pins['source/ssh_exec_persistent_bridge.py']['sha256'] == EXPECTED['ssh_exec_persistent_bridge.py']
claims = {p.name:sha(p.read_bytes()) for p in (STATE/'provider/evidence/claims').iterdir() if p.is_file()}
assert len(claims) == 15, 'Unexpected concurrent accepted turn; review first'
save('CURRENT-CLAIMS-SNAPSHOT.json', claims)
for name in ['launchagents','baseline-launchagents']: (BASE/name).mkdir(mode=0o700)
plists, pids = {}, {}
for label in LABELS:
    original = (Path.home()/'Library/LaunchAgents'/(label+'.plist')).read_bytes()
    previous = plistlib.loads(original)
    current = copy.deepcopy(previous)
    assert current['WorkingDirectory'] == str(OLD)
    current['WorkingDirectory'] = str(INSTALL)
    current['ProgramArguments'] = [v.replace('/provider/v148-r5/', '/provider/v149-r1/') for v in previous['ProgramArguments']]
    argv = current['ProgramArguments']
    if label.endswith('daily-provider'):
        assert argv[argv.index('--model')+1] == 'gpt-6.1-sol'
        assert argv[argv.index('--workers')+1] == '2'
    else:
        i = argv.index('--provider-sha256')+1
        assert argv[i] == EXPECTED['daily_provider.py']
        argv[i] = pins['source/daily_provider.py']['sha256']
    updated = plistlib.dumps(current, sort_keys=True)
    write(BASE/'baseline-launchagents'/(label+'.plist'), original)
    write(BASE/'launchagents'/(label+'.plist'), updated)
    state = subprocess.run(['launchctl','print','gui/501/'+label], capture_output=True, text=True, timeout=10)
    assert state.returncode == 0 and '\n\tstate = running\n' in state.stdout
    found = re.findall(r'^\tpid = ([0-9]+)$', state.stdout, re.M); assert len(found)==1
    pids[label] = int(found[0])
    plists[label] = {'old_sha256':sha(original), 'new_sha256':sha(updated),
                     'old_argv':previous['ProgramArguments'], 'new_argv':argv}
plan = {'schema':'hepta.provider-install-plan.v149.1', 'revision':'v149-r1', 'baseline':'v148-r5',
        'candidate':str(BASE), 'install':str(INSTALL), 'state_unchanged':str(STATE),
        'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'plists':plists,
        'baseline_current_pids':pids, 'source_pins':pins, 'old_source_pins':EXPECTED,
        'claim_snapshot_sha256':sha((BASE/'CURRENT-CLAIMS-SNAPSHOT.json').read_bytes()),
        'claim_count':len(claims), 'selected_model':'gpt-6.1-sol', 'workers':2,
        'transport_watch_preserved':True, 'wire_schema_unchanged':True,
        'phone_operations':0, 'model_operations':0, 'service_operations':0,
        'review_scope':['structured model health','explicit HEPTA return','request-bound task postconditions',
                        'public text receipt','whole task versus partial terminal','screenshot/focus tap guards'],
        'qualification':'candidate not yet installed; model availability and daily-use qualification not implied'}
save('INSTALL-PLAN.json', plan)
inventory = {str(p.relative_to(BASE)):{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}
             for p in sorted(BASE.rglob('*')) if p.is_file() and p.name != 'SOURCE-SEAL.json'
             and '__pycache__' not in p.parts}
save('SOURCE-SEAL.json', {'schema':'hepta.source-seal.v149.1','files':inventory})
print(json.dumps({'status':'CANDIDATE_PACKAGED_NOT_INSTALLED',
                  'source_pins':pins,'pids':pids,'claim_count':len(claims),
                  'plan_sha256':sha((BASE/'INSTALL-PLAN.json').read_bytes()),
                  'seal_sha256':sha((BASE/'SOURCE-SEAL.json').read_bytes())},ensure_ascii=False))
