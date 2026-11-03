"""Package trusted HEPTA navigation guidance only; no install or model calls."""
from pathlib import Path
import ast
import copy
import difflib
import hashlib
import json
import plistlib
import subprocess
import sys

BASE = Path(__file__).resolve().parent
OLD = BASE.parent / 'stock16-hepta-vision-provider-C-v148-r4'
ACTUAL = Path.home() / 'Library/Application Support/HEPTA/provider/v148-r4'
INSTALL = ACTUAL.with_name('v148-r5')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(name, value):
    (BASE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def normalized_provider(raw):
    tree = ast.parse(raw)
    tree.body = [node for node in tree.body if not (isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'PHONE_UI_INSTRUCTION'
                for target in node.targets))]
    return ast.dump(tree, include_attributes=False)


sources = sorted(path.name for path in (BASE / 'source').glob('*.py'))
require(len(sources) == 5, 'all five stage sources required')
for name in sources:
    previous = (OLD / 'source' / name).read_bytes()
    require(previous == (ACTUAL / 'source' / name).read_bytes(), 'actual r4 source differs')
    current = (BASE / 'source' / name).read_bytes()
    compile(current, str(BASE / 'source' / name), 'exec')
    if name == 'provider_codex_host.py':
        require(normalized_provider(previous) == normalized_provider(current), 'provider AST outside instruction changed')
    elif name == 'daily_provider.py':
        old_pin = sha((ACTUAL / 'source/provider_codex_host.py').read_bytes())
        new_pin = sha((BASE / 'source/provider_codex_host.py').read_bytes())
        require(previous.count(old_pin.encode()) == 1, 'old provider pin not unique')
        require(current == previous.replace(old_pin.encode(), new_pin.encode()), 'daily changed outside one provider pin')
    else:
        require(previous == current, 'tool/HTTP/bridge source changed')
require((BASE / 'retained-claims.json').read_bytes() == (ACTUAL / 'retained-claims.json').read_bytes(),
        'original claims seed differs')
tree = ast.parse((BASE / 'source/provider_codex_host.py').read_text())
instruction = next(ast.literal_eval(node.value) for node in tree.body
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
        and target.id == 'PHONE_UI_INSTRUCTION' for target in node.targets))
require('org.trillionnium.owneropen/.OwnerOpenShellActivity' in instruction,
        'verified own-session component absent')
require('Do not infer a HEPTA launcher from package names containing hepta.' in instruction,
        'guessing boundary absent')
require('observe the actual foreground/focus before claiming' in instruction,
        'actual return observation boundary absent')

checks = {}
for script, result in (
    ('offline_phone_tools_checks.py', 'OFFLINE-PHONE-TOOLS-CHECKS.json'),
    ('offline_legacy_checks.py', 'OFFLINE-LEGACY-CHECKS.json'),
    ('offline_capacity_race_checks.py', 'OFFLINE-CAPACITY-RACE-CHECKS.json')):
    completed = subprocess.run([sys.executable, '-B', str(BASE / script)], capture_output=True, text=True, timeout=45)
    require(completed.returncode == 0, completed.stderr)
    value = json.loads(completed.stdout)
    save(result, value)
    checks[result] = value['checks_passed']

pins = {str(path.relative_to(BASE)): {'sha256': sha(path.read_bytes()), 'bytes': path.stat().st_size}
        for path in sorted((BASE / 'source').glob('*.py'))}
old_daily_sha = sha((ACTUAL / 'source/daily_provider.py').read_bytes())
new_daily_sha = pins['source/daily_provider.py']['sha256']
diff = []
for name in ('provider_codex_host.py', 'daily_provider.py'):
    diff.extend(difflib.unified_diff((ACTUAL / 'source' / name).read_text().splitlines(keepends=True),
        (BASE / 'source' / name).read_text().splitlines(keepends=True),
        fromfile='actual-v148-r4/source/' + name, tofile='v148-r5/source/' + name))
(BASE / 'R4-TO-R5.diff').write_text(''.join(diff))
(BASE / 'launchagents').mkdir(exist_ok=True)
(BASE / 'baseline-launchagents').mkdir(exist_ok=True)
plists = {}
for label in ('org.trillionnium.hepta.daily-provider', 'org.trillionnium.hepta.daily-bridge'):
    actual_path = Path.home() / 'Library/LaunchAgents' / (label + '.plist')
    raw = actual_path.read_bytes()
    require(raw == (OLD / 'launchagents' / actual_path.name).read_bytes(), 'actual r4 plist differs')
    previous = plistlib.loads(raw)
    current = copy.deepcopy(previous)
    current['WorkingDirectory'] = str(INSTALL)
    current['ProgramArguments'] = [value.replace('/provider/v148-r4/', '/provider/v148-r5/')
        for value in previous['ProgramArguments']]
    argv = current['ProgramArguments']
    if label.endswith('daily-provider'):
        require(argv[argv.index('--model') + 1] == 'gpt-6.1-sol', 'fixed model changed')
    else:
        index = argv.index('--provider-sha256') + 1
        require(argv[index] == old_daily_sha, 'old bridge pin differs')
        argv[index] = new_daily_sha
    cooked = plistlib.dumps(current, sort_keys=True)
    (BASE / 'baseline-launchagents' / actual_path.name).write_bytes(raw)
    (BASE / 'launchagents' / actual_path.name).write_bytes(cooked)
    plists[label] = {'old_sha256': sha(raw), 'new_sha256': sha(cooked),
        'old_argv': previous['ProgramArguments'], 'new_argv': argv}

evidence = INSTALL.parent / 'state/provider/evidence'
claims = [{'name': path.name, 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}
          for path in sorted((evidence / 'claims').iterdir())]
require(len(claims) == 14, 'expected actual idle 14-claim inventory differs')
save('CURRENT-CLAIMS-SNAPSHOT.json', claims)
plan = copy.deepcopy(json.loads((OLD / 'INSTALL-PLAN.json').read_text()))
plan.update(candidate=str(BASE), install=str(INSTALL), baseline_installed_version='v148-r4',
    plists=plists, source_pins=pins, model_decision_schema_extended=False,
    selected_model_old='gpt-6.1-sol', selected_model_new='gpt-6.1-sol',
    baseline_current_pids={'provider': 39240, 'bridge': 39243},
    current_claim_count=len(claims), current_claim_snapshot_sha256=sha((BASE / 'CURRENT-CLAIMS-SNAPSHOT.json').read_bytes()),
    source_change_scope='Only PHONE_UI_INSTRUCTION adds verified own-session navigation target, plus daily provider source parent pin. Every provider function AST and all three tool/HTTP/bridge source files unchanged.',
    state_unchanged=str(INSTALL.parent / 'state'),
    switch=[
        'Root verifies idle, every prior tool terminal and every owned CLI child joined; preserve all 14 current claims and original successful/partial/failed/cancelled records.',
        'Stage all five sources plus original retained-claims.json at new v148-r5. Verify reviewed pins and unchanged CLI pin.',
        'Stop only owned daily-bridge, then daily-provider; leave transport-watch and all remote/phone services untouched.',
        'Atomically install reviewed two plists. Start provider; verify ready model=gpt-6.1-sol/source=new dailySHA/CLI/workers/port. Then start bridge and verify its ready identity.',
        'Use one fresh remaining navigation task only: restore existing submitted Probe via Recents, read its existing public receipt, then return to verified HEPTA activity. Do not repeat Unicode input or submission.',
        'If switching fails, Root restores exact baseline r4 plists and restarts r4 provider then bridge after the same ownership/idle checks. Retain every newly accepted identity.'],
    validation='Producer performs no model/service/phone actions. Root only verifies fresh remaining navigation: existing Probe receipt unchanged then actual HEPTA foreground; no repeated entry/submit or full-device acceptance.')
save('INSTALL-PLAN.json', plan)
save('R5-MINIMAL-CHECKS.json', {
    'actual_r4_five_source_baseline_matches': True,
    'provider_AST_identical_except_PHONE_UI_INSTRUCTION': True,
    'daily_exact_single_parent_pin_replacement': True,
    'three_other_sources_byte_identical': True,
    'verified_own_entry_and_actual_front_check_in_instruction': True,
    'no_name_guess_launcher_instruction_present': True,
    'both_actual_r4_plists_verified_before_transform': True,
    'fixed_sol_and_all_execution_limits_unchanged': True,
    'retained_claims_seed_byte_identical': True,
    'current_14_claim_inventory_preserved': True,
    'all_legacy_phone_capacity_checks': checks,
    'no_model_phone_ssh_service_or_live_state_mutation': True})
save('CANDIDATE-HANDOFF.json', {'status': 'SOURCE_CANDIDATE_READY_NOT_INSTALLED',
    'revision': 'v148-r5', 'baseline': 'actual installed v148-r4',
    'change': 'Trusted exact-phone HEPTA activity supplied in UI instruction, with explicit observation before reporting return. Semantic model still selects every action.',
    'source_pins': pins, 'plists': plists, 'checks': checks,
    'no_model_phone_ssh_service_actions': True,
    'same_sol_model_functions_deadlines_claims_wire_phone_tools_and_cli': True,
    'remaining_task_only': 'Read previous submitted Probe receipt then return HEPTA; no input or submission replay.'})
inventory = {str(path.relative_to(BASE)): {'sha256': sha(path.read_bytes()), 'bytes': path.stat().st_size}
    for path in sorted(BASE.rglob('*'))
    if path.is_file() and path.name != 'SOURCE-SEAL.json' and '__pycache__' not in path.parts}
save('SOURCE-SEAL.json', {'files': inventory, 'model_operations': 0, 'phone_operations': 0,
    'service_operations': 0, 'claims_changed': False})
print(json.dumps({'provider_sha256': pins['source/provider_codex_host.py']['sha256'],
    'daily_sha256': new_daily_sha, 'plists': {key: {name: value[name]
        for name in ('old_sha256', 'new_sha256')} for key, value in plists.items()},
    'seal_sha256': sha((BASE / 'SOURCE-SEAL.json').read_bytes()),
    'plan_sha256': sha((BASE / 'INSTALL-PLAN.json').read_bytes()), 'checks': checks,
    'current_claim_count': len(claims)}, indent=2))
