#!/usr/bin/env python3
"""Build a source-only fixed P4 collector from exact downloaded Mac originals."""
from pathlib import Path, PurePosixPath
import ast
import difflib
import gzip
import hashlib
import io
import json
import tarfile

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
DOWNLOAD = BASE / 'actual_external_902e_7c907661_01/mac-full-archive01'
PARENT = BASE / 'external902_mac_originals_candidate01/delivery-final01/package/source/collect_external902_originals.py'
PACKAGE = HERE / 'package'
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
LABEL = 'root-r10-neg01-7c907661-01'
NONCE = '902e851c3ca1f90deab3d880ab993774'
CHAIN_ROOT = '/home/alex/codex-native-guard-chain-r10-r1/' + NONCE
P4_OUT = '/home/alex/codex-hepta-external902-7c907661-originals-1ad3-01'
PARENT_PIN = (36689, '4ab7739134578d6ab641eeac07e9676721ca3c2967b29a2f5a2bb320c2041ebc')
ARCHIVE_PIN = (1796220, '55934b9f1fefecd4f1f30c677920935fc527a08e0a218138024b5d0230d88ffc')
MF_PIN = (263330, '06b153ea42ec72dfbc9c9d51a9b2b9e0c99815678484190c95bdeab76abd9966')
RUNTIME_SHA = '31da1d92d2d9c833cd053db15b0cc40824e750705d315a320206a2f7a52a6bfb'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def desc(path, raw=None):
    if raw is None:
        raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def exact(path, pin):
    raw = path.read_bytes()
    assert (len(raw), sha(raw)) == pin
    return raw


selected_root = HERE / 'selected-gzip-input'
selected_proof_path = selected_root / 'SELECTED-INPUTS-VERIFICATION.json'
selected_proof_raw = exact(selected_proof_path, (18906, '405801e5308c49401cf8fcd8ef35a66bce971561d4aa2f4e0548948ddc6ccb85'))
selected_proof = json.loads(selected_proof_raw)
assert selected_proof['state'] == 'ONE_COMPLETE_GZIP_MEMBER_MATCHES_SEPARATE_EXACT_PIN_FULL_ARCHIVE_STILL_INCOMPLETE'
assert selected_proof['original_xz_complete'] is False
gzip_path = selected_root / 'root-originals/material/component-inputs.tar.gz'
gzip_raw = exact(gzip_path, (471979, '989a78d8c9a844ea0f06859a9e9e2b66bafeacd4702a9b8388d6a031b7775afb'))
plain = gzip.decompress(gzip_raw)
assert len(plain) <= 16 * 1024 * 1024
material_raw = {}
with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
    for member in archive:
        path = PurePosixPath(member.name)
        assert member.isfile() and not member.issym() and not member.islnk()
        assert not path.is_absolute() and str(path) == member.name and '\0' not in member.name
        assert all(part not in ('', '.', '..') for part in path.parts)
        name = 'root-originals/material/tree/' + member.name
        assert name not in material_raw
        raw = archive.extractfile(member).read()
        assert len(raw) == member.size
        material_raw[name] = raw
assert len(material_raw) == 56
local_originals = {
    'root-originals/ROOT-PLAN.original.json': BASE / 'actual_external_902e_7c907661_01/ROOT-PLAN.original.json',
    'root-originals/ROOT-FAILURE.json': BASE / 'actual_external_902e_7c907661_01/ROOT-FAILURE.json',
    'root-originals/material/PREPARED.json': BASE / 'actual_external_902e_7c907661_01/material/PREPARED.json',
    'root-originals/material/component-inputs.tar.gz': gzip_path,
}
known = {
    'root-originals/ROOT-PLAN.original.json': (4783, '9a94108ffc737133ba879bd9cccd70c7ec3ae2f3da17eb689e5b1d5610789d58'),
    'root-originals/ROOT-FAILURE.json': (20867, '25f7bca3dfd2f10308e2d430704db54e393c12bd0add116065ff8666be85320b'),
    'root-originals/material/PREPARED.json': (2873, 'a8b8b355a9bde5db21123cf503be5f62a24d55226e154ce5ed95a428347d1898'),
    'root-originals/material/component-inputs.tar.gz': (471979, '989a78d8c9a844ea0f06859a9e9e2b66bafeacd4702a9b8388d6a031b7775afb'),
}
all_raw = {**material_raw, **{name: exact(path, known[name]) for name, path in local_originals.items()}}
root_path = B + '/native-guard-root-chains-r10-r1/' + LABEL
rows = {name: {'path': root_path + '/' + name[len('root-originals/'):],
              'bytes': len(raw), 'sha256': sha(raw)} for name, raw in all_raw.items()}


def original(name):
    if name.startswith('runtime-originals/'):
        return material_raw['root-originals/material/tree/package/' + name[len('runtime-originals/'):]]
    return all_raw[name]


fixed_trees = {
    'sender-originals': '/home/alex/codex-hepta-natural-' + LABEL + '-root-v150',
    'setup-fixture-originals': '/home/alex/codex-hepta-native-guard-fixtures-r10-r1/' + NONCE + '/setup',
    'material-originals': CHAIN_ROOT + '/material',
}
material = {}
for name, row in sorted(rows.items()):
    prefix = 'root-originals/material/tree/'
    if not name.startswith(prefix):
        continue
    raw = original(name)
    relative = 'tree/' + name[len(prefix):]
    material[relative] = {'path': CHAIN_ROOT + '/material/' + relative,
                          'bytes': len(raw), 'sha256': sha(raw)}
assert len(material) == 56
assert material['tree/package/MANIFEST.json']['sha256'] == RUNTIME_SHA
prepared_raw = original('root-originals/material/PREPARED.json')
prepared = json.loads(prepared_raw)
assert prepared['label'] == LABEL and prepared['nonce'] == NONCE
assert prepared['package_sha256'] == RUNTIME_SHA and prepared['archive_members'] == 56
archive_raw = original('root-originals/material/component-inputs.tar.gz')
assert (len(archive_raw), sha(archive_raw)) == (471979, '989a78d8c9a844ea0f06859a9e9e2b66bafeacd4702a9b8388d6a031b7775afb')

root_plan_raw = original('root-originals/ROOT-PLAN.original.json')
root_plan = json.loads(root_plan_raw)
extras = {}
for key, expected in {
        'request': (317, '526568aa9d2c95f333caf396f9873deaf8baca2df841e7a94100e04b28bb93eb'),
        'previous': (1428, '9133e2511a66a809be647cb8bb49e3afb351825db5e465f75b1f2f0b6d9d88f4'),
        'preserved_draft': (282, '9d801d675a461de996206b1bdc911309aeb40df599c49860ddc9699779d4e741')}.items():
    assert (root_plan[key]['bytes'], root_plan[key]['sha256']) == expected
    extras['sibling-input-originals/' + key + '.original'] = {
        'path': CHAIN_ROOT + '/inputs/' + key + '.original', 'bytes': expected[0], 'sha256': expected[1]}
extras['sibling-input-originals/component-inputs.tar.gz'] = {
    'path': CHAIN_ROOT + '/inputs/component-inputs.tar.gz', 'bytes': len(archive_raw), 'sha256': sha(archive_raw)}
stage = original('runtime-originals/source/stage_component.py')
assert (len(stage), sha(stage)) == (19116, '4d4692a284ddce37aae383fc537cac1e49e2fbb05ede4321f57d8f022dd62340')
extras['sibling-input-originals/stage_component.py'] = {
    'path': CHAIN_ROOT + '/inputs/stage_component.py', 'bytes': len(stage), 'sha256': sha(stage)}
expected_plans = {
    'ROOT-SETUP-PLAN.json': (6402, '824880935f6bfe854d4b1f096f7c7c593db7bb85d200153ddca3daea291f1607'),
    'BOUND-CONTRACT.json': (1842, '5b34b08df6897149afc321508481b755ac2e68d439131075ff8bb4f7e37c6b3b'),
    'ACCEPTED.json': (552, 'a3e0cdace4d9eb2f875beddd9556b8ee94f38820f086bc15387386660b6bb603'),
}
phone_home = '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/' + LABEL
private_root = BASE / 'actual_external_902e_7c907661_01/private-read01/phone-private-originals'
plan_raw, plan_source_pins = {}, {}
for name, pin in expected_plans.items():
    path = private_root / phone_home.lstrip('/') / name
    raw = exact(path, pin)
    plan_raw[name] = raw
    plan_source_pins[name] = {'path': phone_home + '/' + name, 'bytes': len(raw), 'sha256': sha(raw),
        'local_original': desc(path), 'observation_source': 'Later private read matching original Root fixture intent SHA'}
    extras['setup-plan-originals/' + name] = {
        'path': CHAIN_ROOT + '/plans/setup/' + name, 'bytes': len(raw), 'sha256': sha(raw)}
assert len(extras) == 8
failure_raw = original('root-originals/ROOT-FAILURE.json')
failure = json.loads(failure_raw)
assert len(failure['root_fixture_attempts']) == 1 and failure['root_fixture_attempts'][0]['phase'] == 'setup'
terminal = failure['root_fixture_attempts'][0]['terminal']
assert terminal == {'path': fixed_trees['setup-fixture-originals'] + '/HOST-TERMINAL.json',
    'bytes': 24411, 'sha256': '82b4faebc69bae4d2e917af81300d82483f0183b7d3f357aa594c57cd6926ff6'}

parent_raw = exact(PARENT, PARENT_PIN)
parent = parent_raw.decode()
parent_ast = ast.parse(parent)
parent_funcs = {node.name: ast.get_source_segment(parent, node) + '\n'
                for node in parent_ast.body if isinstance(node, ast.FunctionDef)}
helper_names = ('need', 'sha', 'enc', 'strict', 'metadata', 'descriptor', 'relative', 'check_time',
                'open_directory', 'check_directory', 'read_file', 'recheck_tree', 'put_new')
collect = parent_funcs['collect_tree']
replacements = [
    ("combined case/source/original byte budget exceeded", "combined P4 original byte budget exceeded"),
    ("    visit(SOURCE, 'root-originals')\n    for prefix, package in SOURCE_PACKAGES.items():\n        visit(Path(package['root']), prefix)",
     "    for prefix, path in FIXED_TREES.items():\n        visit(Path(path), prefix)"),
    ("and B in path.parents,", "and P4_BASE in path.parents,"),
    ("fixed additional source path must stay inside B", "fixed sibling original path must stay inside /home/alex"),
]
for before, after in replacements:
    assert collect.count(before) == 1
    collect = collect.replace(before, after)
reversed_collect = collect
for before, after in reversed(replacements):
    assert reversed_collect.count(after) == 1
    reversed_collect = reversed_collect.replace(after, before)
assert reversed_collect == parent_funcs['collect_tree']
reference = {'original_component_archive': rows['root-originals/material/component-inputs.tar.gz'],
    'selected_complete_gzip_whole_sha_verified': True,
    'whole_outer_xz_or_239_member_verification_claimed_here': False,
    'selection_origin': 'Complete member from native-version-pinned XZ prefix, independently matched to exact PREPARED archive pin',
    'original_root_plan': {key: rows['root-originals/ROOT-PLAN.original.json'][key] for key in ('path', 'bytes', 'sha256')},
    'original_prepared': {key: rows['root-originals/material/PREPARED.json'][key] for key in ('path', 'bytes', 'sha256')}}
header = "#!/usr/bin/env python3\n\"\"\"Collect fixed original P4 trees without executing any retained source or device operation.\"\"\"\n"
header += "import hashlib\nimport io\nimport json\nimport lzma\nimport os\nfrom pathlib import Path, PurePosixPath\nimport stat\nimport tarfile\nimport time\n\n"
header += "P4_BASE = Path('/home/alex')\nOUT = Path(" + repr(P4_OUT) + ")\n"
for name, value in [('LABEL', LABEL), ('NONCE', NONCE), ('FIXED_TREES', fixed_trees),
                    ('MATERIAL_FILES', material), ('ADDITIONAL_FIXED_FILES', extras),
                    ('SETUP_TERMINAL', terminal), ('RUNTIME_MANIFEST_SHA', RUNTIME_SHA),
                    ('MAC_MATERIAL_REFERENCE', reference)]:
    header += name + ' = ' + repr(value) + '\n'
header += "META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')\nMAX_FILES = 2048\nMAX_DIRECTORIES = 512\nMAX_BYTES = 64 * 1024 * 1024\nMAX_SECONDS = 100\n\n\n"
source = header + '\n\n'.join(parent_funcs[name].rstrip('\n') for name in helper_names[:11]) + '\n\n\n'
source += collect + '\n\n' + parent_funcs['recheck_tree'] + '\n\n' + parent_funcs['put_new'] + '\n\n'
source += (HERE / 'templates/collector_body.py').read_text()
source_raw = source.encode()
assert len(source_raw) <= 65536
tree = ast.parse(source)
compile(source, 'collect_external902_p4_originals.py', 'exec')
functions = {node.name: ast.get_source_segment(source, node) + '\n'
             for node in tree.body if isinstance(node, ast.FunctionDef)}
assert all(functions[name] == parent_funcs[name] for name in helper_names)
allowed_imports = {'hashlib', 'io', 'json', 'lzma', 'os', 'pathlib', 'stat', 'tarfile', 'time'}
assert not any(isinstance(node, ast.Import) and any(alias.name.split('.')[0] not in allowed_imports
    for alias in node.names) for node in ast.walk(tree))
assert not any(isinstance(node, ast.ImportFrom) and (node.level != 0 or node.module not in allowed_imports)
    for node in ast.walk(tree))
assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    and node.func.id in {'exec', 'eval', 'compile', '__import__'} for node in ast.walk(tree))

put(PACKAGE / 'source/collect_external902_p4_originals.py', source_raw)
put(PACKAGE / 'reference/collect_external902_mac_originals.original.py', parent_raw)
references = {
    'ROOT-PLAN.original.json': root_plan_raw,
    'ROOT-FAILURE.original.json': failure_raw,
    'PREPARED.original.json': prepared_raw,
    'runtime-MANIFEST.original.json': original('runtime-originals/MANIFEST.json'),
    **{'later-private-' + name: raw for name, raw in plan_raw.items()},
}
for name, raw in references.items():
    put(PACKAGE / 'reference' / name, raw)
put(PACKAGE / 'validation/collector-scope.patch', ''.join(difflib.unified_diff(
    parent.splitlines(True), source.splitlines(True), fromfile='reviewed-4ab773.py',
    tofile='fixed-external902-p4-collector.py')).encode())
derivation = {'schema': 'hepta.external902-p4-collector-source-derivation.v1',
    'state': 'SOURCE_ONLY_FIXED_ORIGINAL_READ_SCOPE_NOT_EXECUTED',
    'parent_collector': desc(PARENT), 'source': desc(PACKAGE / 'source/collect_external902_p4_originals.py'),
    'whole_byte_unchanged_helpers': list(helper_names),
    'collect_tree_exact_replacements': [{'before': a, 'after': b} for a, b in replacements],
    'collect_tree_inverse_exact': True, 'source_imported_or_main_executed': False,
    'output': P4_OUT, 'fixed_trees': fixed_trees, 'fixed_sibling_originals': extras,
    'material_members': len(material), 'material_reference': reference,
    'selected_complete_gzip_verification': desc(selected_proof_path),
    'whole_outer_xz_or_239_member_verification_claimed_here': False,
    'setup_plan_original_sources': plan_source_pins,
    'scope_changes': ['Three fixed P4 trees in place of Mac case/runtime/Root trees',
        'Five fixed sibling inputs and three actual setup plan originals',
        'P4 material tree must match all 56 original Mac material member pins',
        'Current P4 sender original branch is retained without replay or qualification',
        'Original Mac sender54589 unjoined/EOFfalse is preserved as historical fact'],
    'unchanged_budgets': {'MAX_FILES': 2048, 'MAX_DIRECTORIES': 512, 'MAX_BYTES': 67108864,
                          'MAX_SECONDS': 100, 'archive_framing_extra_bytes': 4194304},
    'process_start_calls': 0, 'phone_calls': 0, 'P4_calls': 0, 'signals_sent': 0,
    'case_pass': False, 'native_cleanup_or_boundary_publication_verified': False}
put(PACKAGE / 'validation/DERIVATION.json', enc(derivation))
source_pin = desc(PACKAGE / 'source/collect_external902_p4_originals.py')
wrapper = "import hashlib,sys\nbody=sys.stdin.buffer.read()\nassert len(body)==" + str(len(source_raw))
wrapper += " and hashlib.sha256(body).hexdigest()==" + repr(sha(source_raw)) + "\n"
wrapper += "exec(compile(body,'<fixed-external902-p4-collector>','exec'),{'__name__':'__main__','COLLECTOR_SOURCE':body})\n"
request = {'host': 'pocket4', 'executable': '/usr/bin/python3', 'args': ['-I', '-B', '-c', wrapper],
    'cwd': '/home/alex', 'stdin': source, 'timeout_seconds': 150,
    'idempotency_key': 'root-1ad3-external902-p4-originals01-20261105'}
put(HERE / 'CONTROLLER-REQUEST.json', enc(request))
put(PACKAGE / 'INTERFACE.json', enc({'schema': 'hepta.external902-p4-collector-interface.v1',
    'state': 'SOURCE_ONLY_NOT_EXECUTED', 'source': source_pin,
    'target_host': 'pocket4', 'new_output': P4_OUT, 'fixed_trees': fixed_trees,
    'pinned_sibling_files': extras, 'member_metadata': 'full9 held-fd and named bookends',
    'success_requires_actual_controller': {'exit_code': 0, 'output_complete': True, 'output_durable': True,
        'stdout_last_full_recheck_after_result': True, 'no_truncated_streams': True},
    'result_alone_is_not_final_success': True, 'phone_calls': 0, 'signals_sent': 0,
    'source_evaluation_or_subprocesses_inside_collector': 0,
    'separate_mac_actor_read': {'path': B + '/' + LABEL + '.actor.py', 'bytes': 82909,
        'sha256': 'e583b6183479f871bec64808304992f71972e6eed3566f6181ab9c870b245598',
        'already_downloaded_by_root': True, 'included_in_P4_collection': False},
    'original_mac_sender_join_or_EOF_retrofitted': False, 'case_pass': False}))
readme = '''# External902 fixed P4 original collection\n\nThis is a source-only candidate. No collector, P4 process, phone command, or target module was executed while preparing it.\n\nThe collector reads the complete fixed sender, setup-fixture, and material directories, plus eight explicitly pinned sibling input/plan files. The material tree must match all 56 original Mac member pins. The setup fixture remains limited to the already consumed setup phase.\n\nThe source uses O_RDONLY/O_NOFOLLOW reads, held file and directory identities, full nine-field metadata and byte rechecks, bounded membership, and three full observation bookends. It creates one new evidence directory and uses O_EXCL, fsync, and readback for all outputs. It never overwrites or removes prior evidence. The original P4 trees may have changed since the failed case; this is a later non-atomic observation.\n\nA successful evidence collection requires the actual controller to finish with return code zero, complete durable stdout/stderr, and a final stdout receipt after the last full recheck. RESULT.json alone does not establish success.\n\nThe original Mac sender PID 54589 remains NOT_JOINED with both EOF flags false. Later P4 records do not change that historical fact. This package performs no process census, cleanup, device operation, native qualification, or boundary publication. The Mac generated actor is outside this P4 collection and requires its own exact read.\n'''
put(PACKAGE / 'README.md', readme.encode())
file_pins = [{'path': str(path.relative_to(PACKAGE)), 'bytes': path.stat().st_size,
              'sha256': sha(path.read_bytes())} for path in sorted(PACKAGE.rglob('*')) if path.is_file()]
manifest = {'schema': 'hepta.external902-p4-original-collector-source-package.v1',
    'state': 'SOURCE_ONLY_FIXED_ORIGINAL_READ_SCOPE_NOT_EXECUTED', 'files': file_pins,
    'source': source_pin, 'phone_calls': 0, 'P4_processes_started': 0,
    'case_pass': False, 'original_sender_join_or_EOF_retrofitted': False}
put(PACKAGE / 'SOURCE-MANIFEST.json', enc(manifest))
print(json.dumps({'source': source_pin, 'manifest': desc(PACKAGE / 'SOURCE-MANIFEST.json'),
    'request': desc(HERE / 'CONTROLLER-REQUEST.json'), 'files': len(file_pins) + 1,
    'p4_out': P4_OUT, 'source_only': True}, sort_keys=True))
