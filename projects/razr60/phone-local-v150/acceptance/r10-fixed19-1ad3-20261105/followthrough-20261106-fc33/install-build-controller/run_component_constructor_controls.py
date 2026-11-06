#!/usr/bin/env python3
"""Host-only source construction controls; no current component success fixture."""
import ast
import hashlib
import json
from pathlib import Path
import types

ROOT = Path(__file__).resolve().parent
REVIEW = ROOT.parent
SOURCE = ROOT / 'derive_component_build_inputs_UNBOUND.py'


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def load(raw, name):
    module = types.ModuleType(name)
    module.__file__ = str(SOURCE)
    exec(compile(raw, str(SOURCE), 'exec'), module.__dict__)
    return module


def bind(raw, row):
    tree = ast.parse(raw)
    nodes = [n for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'FROZEN_INPUTS']
    assert len(nodes) == 1 and ast.literal_eval(nodes[0].value) is None
    node = nodes[0]; lines = raw.splitlines(keepends=True)
    assert node.lineno == node.end_lineno
    old = lines[node.lineno-1]
    lines[node.lineno-1] = ('FROZEN_INPUTS = ' + repr({k: row[k] for k in ('path', 'bytes', 'sha256')}) + '\n').encode()
    candidate = b''.join(lines)
    reverse = candidate.splitlines(keepends=True); reverse[node.lineno-1] = old
    assert b''.join(reverse) == raw
    return candidate


def main():
    raw = SOURCE.read_bytes(); module = load(raw, 'candidate_component_constructor')
    rows = []
    def check(name, action):
        action(); rows.append({'name': name, 'passed': True})
    calls = []
    def forbidden(row):
        calls.append(row)
        raise AssertionError('unexpected original read')
    def rejects(action, needle):
        try:
            action()
        except ValueError as error:
            assert needle in str(error), str(error)
        else:
            raise AssertionError('accepted')
    check('unbound rejects before JSON parsing and original callback', lambda: rejects(
        lambda: module.derive_component_build_inputs(b'not-json', read_pinned=forbidden), 'UNBOUND_ACTUAL_COMPONENT_BUILD_INPUTS_NO_IO'))
    assert not calls
    candidate = dict(schema=module.SCHEMA, case_results={'NEG-01': None, 'NEG-02': None},
        output_root=None, build_output_root=None, build_idempotency_key=None, build_timeout_seconds=180)
    candidate_raw = module.encoded(candidate)
    bound = load(bind(raw, dict(path=module.B + '/CONTROL-NOT-ACTUAL.json', **pin(candidate_raw))), 'control_only_bound_constructor')
    check('bound input with absent actual cases rejects before all original IO', lambda: rejects(
        lambda: bound.derive_component_build_inputs(candidate_raw, read_pinned=forbidden), 'UNBOUND_ACTUAL_CURRENT_NEG-01_NO_IO'))
    check('different complete input bytes reject before all original IO', lambda: rejects(
        lambda: bound.derive_component_build_inputs(candidate_raw+b' ', read_pinned=forbidden), 'exact bound construction input bytes'))
    assert not calls
    for value in (False, 0.0):
        check('descriptor rejects ' + repr(value) + ' as original byte count', lambda value=value: rejects(
            lambda: module.descriptor({'path': module.B+'/CONTROL', 'bytes': value, 'sha256': '0'*64}), 'typed bounded original'))
    check('canonical type-preserving equality distinguishes false from zero', lambda: (
        None if not module.same({'n': False}, {'n': 0}) else (_ for _ in ()).throw(AssertionError())))
    check('duplicate JSON descriptor key rejected', lambda: rejects(
        lambda: module.strict(b'{"path":1,"path":2}'), 'duplicate JSON'))
    # These bytes are actual published/frozen sources and original old04/06
    # result carriers. Only known host paths are mapped to exact retained bytes.
    bodies = {}
    source_base = REVIEW/'R5-actual-release-source-chain/derived'
    for f in source_base.rglob('*'):
        if f.is_file():
            bodies[module.SOURCE_ROOT+'/'+str(f.relative_to(source_base))] = f.read_bytes()
    runtime_base = REVIEW/'R5-root/runtime'
    runtime_root = str(Path(module.RUNTIME['path']).parent)
    for f in runtime_base.rglob('*'):
        if f.is_file():
            bodies[runtime_root+'/'+str(f.relative_to(runtime_base))] = f.read_bytes()
    carrier = json.loads((ROOT/'reference/old04-old06-root-results.original.mcp.json').read_bytes())
    for item in json.loads(carrier['content'][0]['text'])['files']:
        bodies[item['path']] = item['text'].encode()
    selected = []
    def original(row):
        assert row['path'] in bodies, row
        body = bodies[row['path']]
        assert pin(body) == {k: row[k] for k in ('bytes', 'sha256')}
        selected.append(row)
        return body
    pool = module.Pool(original)
    consumer, release, sources = module.source_context(pool)
    manifest, copies, source_bytes = module.runtime_sources(pool, consumer)
    seed = module.history_seed(pool, consumer, release, manifest, copies, source_bytes)
    check('actual frozen38 files and same actual source-chain consumer pins', lambda: (
        None if len(copies)==consumer.PACKAGE_FILE_COUNT==38 and consumer.PACKAGE_SHA==module.RUNTIME['sha256']
        else (_ for _ in ()).throw(AssertionError())))
    check('source-derived history has exact current20 keys and three actual case slots absent', lambda: (
        None if set(seed)==consumer.COMPONENT_FIELDS and all(seed[k]is None for k in ('latest_boundary','publish_result','originals'))
        else (_ for _ in ()).throw(AssertionError())))
    check('old source-parent qualified state is historical and cannot fill current slots', lambda: (
        None if manifest['source_parent_records'][0]['component_qualified'] is True
        and manifest['source_parent_qualification_is_current_tuple_credit'] is False
        and seed['latest_boundary'] is None
        else (_ for _ in ()).throw(AssertionError())))
    check('actual old failed Root result rejected as a current qualified case', lambda: rejects(
        lambda: module.collect_case('NEG-01', module.OLD['pre_policy']['root_result'], pool, consumer, source_bytes, module.PhoneOriginals()),
        'one actual completed current component Root result required'))
    pool.recheck()
    preview = module.encoded(seed)
    with (ROOT/'HISTORY-SEED-PREVIEW.UNBOUND.json').open('xb') as stream:
        stream.write(preview)
    result = {'schema':'hepta.fc33.component-constructor-source-controls.v1',
        'state':'SOURCE_CONTROLS_PASSED_CURRENT_COMPONENT_INPUTS_UNBOUND',
        'source':pin(raw), 'checks':rows, 'passed':len(rows),
        'history_seed_preview':pin(preview), 'actual_source_files_read':len(pool.rows),
        'actual_source_bytes_read':pool.total, 'all_read_originals_rechecked':True,
        'actual_new_component_positive_run':False, 'current_NEG01':None, 'current_NEG02':None,
        'actual_BUILD':None, 'actual_install':None, 'actual_READY':None,
        'phone_calls':0, 'native_dispatches':0, 'whole_case_credit':0,
        'limitation':'The complete component bundle can only be validated when both new original closures and their LEASE bytes actually exist.'}
    with (ROOT/'COMPONENT-CONTROL-RESULT.json').open('xb') as stream:
        stream.write(module.encoded(result))
    print(json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    main()
