#!/usr/bin/env python3
"""Independent host recomputation of one already published failed closure.

This driver calls the original pinned pure verification functions.  It does not
call the original close() or main(), manufacture a new native closure, or publish
a boundary.  The historical production modules are loaded from their real old
snapshot paths.  Only newly derived parser artifacts and this audit's records are
written under the independent output directory.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import time

sys.dont_write_bytecode = True
NONCE = '6077fc8f045572edc4acfb13ed7e09a8'
LABEL = 'root-r10-neg01-7c907661-diag01'
BASE = Path('/home/alex/codex-native-guard-chain-r10-r1') / NONCE
PACKAGE = BASE / 'material/tree/package'
SOURCE = PACKAGE / 'source/close_component.py'
PLAN = BASE / 'CLOSURE-PLAN.json'
OLD_OUT = BASE / 'closure'
OLD_SNAPSHOT = OLD_OUT / 'snapshot'
ORIGINAL_CLOSURE = OLD_OUT / 'CLOSURE.original.json'
OUT = Path('/home/alex/codex-hepta-diag6077-independent-closure-audit-1ad3-01')
DRIVER = Path('/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01/audit_existing_closure.py')
SOURCE_PIN = {'bytes': 99120, 'sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'}
PACKAGE_PIN = {'bytes': 18864, 'sha256': '8b9a3b24f2449022120f7f1ef15905ee9a07edac8062fcf46cf7bb0b0c8e7302'}
CLOSURE_PIN = {'bytes': 55184, 'sha256': '35af6a58a84413770bb14ede44eca83ac2774cd4591c7df1501b501cb1643335'}
PLAN_PIN = {'bytes': 2609, 'sha256': 'bb11e33d93583d0fa645cc76e078b6126c02de2a88f9afae7959ea43edd7f667'}
CAPTURE_PIN = {'bytes': 147334, 'sha256': 'ed525e3fb997cf342fc7b31b1cb7f97723f5f17cceda82faa9ab969188b2fb7b'}
ARCHIVE_PIN = {'bytes': 2412565, 'sha256': 'ec20f762bb98bfc93a96c9693ef63d702d2b36e2fd896408c6e919ae46a1fbad'}
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
COMBINATION = 'b4d4a221a4a516177cecf8e182a7ee9a494fc65feb85277cfdf10d28396d5709'
MAX = 64 * 1024 * 1024
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
FINAL_INPUTS = {'plan': {'bytes': 2609, 'sha256': 'bb11e33d93583d0fa645cc76e078b6126c02de2a88f9afae7959ea43edd7f667'}, 'closure': {'bytes': 55184, 'sha256': '35af6a58a84413770bb14ede44eca83ac2774cd4591c7df1501b501cb1643335'}, 'package': {'bytes': 18864, 'sha256': '8b9a3b24f2449022120f7f1ef15905ee9a07edac8062fcf46cf7bb0b0c8e7302'}}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def descriptor(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def metadata(value):
    return [getattr(value, name) for name in META]


def parent_fd(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2 <= len(path.parts) <= 64,
         'bounded absolute original path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


class Guard:
    """Separate driver observations; never added to original Originals.files."""
    def __init__(self):
        self.rows = {}
        self.unique_bytes = 0

    def read(self, path, pin=None, expected_metadata=None, maximum=MAX):
        path = Path(path)
        parent, leaf = parent_fd(path)
        fd = None
        try:
            parent_before = os.fstat(parent)
            before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 <= before.st_size <= maximum, 'bounded single-link regular original required')
            if expected_metadata is not None:
                need(metadata(before) == expected_metadata, 'historical full9 original changed')
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
            need(metadata(os.fstat(fd)) == metadata(before), 'original identity changed before open')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(maximum + 1)
            need(len(raw) == before.st_size, 'original truncated or oversized')
            need(metadata(before) == metadata(os.fstat(fd))
                 == metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False)),
                 'original full9 changed during read')
            need(metadata(parent_before) == metadata(os.fstat(parent)), 'original parent changed during read')
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)
        canonical, canonical_leaf = parent_fd(path)
        try:
            need(canonical_leaf == leaf and metadata(os.fstat(canonical)) == metadata(parent_before)
                 and metadata(os.stat(leaf, dir_fd=canonical, follow_symlinks=False)) == metadata(before),
                 'canonical original or parent changed')
        finally:
            os.close(canonical)
        row = {'metadata': metadata(before), **descriptor(raw)}
        if pin is not None:
            need(descriptor(raw) == pin, 'exact original byte pin differs')
        if str(path) in self.rows:
            need(self.rows[str(path)] == row, 'original changed across driver reads')
        else:
            self.unique_bytes += len(raw)
            need(self.unique_bytes <= MAX and len(self.rows) < 1024, 'driver original census exceeds bound')
            self.rows[str(path)] = row
        return raw

    def recheck(self):
        for path, row in list(self.rows.items()):
            self.read(path, {key: row[key] for key in ('bytes', 'sha256')}, row['metadata'])


def own_fds():
    value = {}
    names = os.listdir('/proc/self/fd')
    need(len(names) <= 256, 'own descriptor census exceeded')
    for name in names:
        need(name.isdigit(), 'unexpected own descriptor name')
        fd = int(name)
        try:
            item = os.fstat(fd)
        except OSError as error:
            need(error.errno in (2, 9), 'own descriptor observation unknown')
            continue
        value[fd] = (item.st_dev, item.st_ino, item.st_mode)
    return value


def put(name, raw):
    need(type(name) is str and '/' not in name and name not in ('', '.', '..'), 'single audit leaf required')
    need(OUT.is_absolute() and OUT.resolve(strict=True) == OUT, 'new audit directory changed')
    path = OUT / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(OUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {'path': str(path), **descriptor(raw)}


def fixed_package(guard):
    raw = guard.read(PACKAGE / 'MANIFEST.json', PACKAGE_PIN, maximum=1048576)
    manifest = strict(raw)
    need(manifest.get('schema') == 'hepta.native-guard.adapter-package.v1'
         and manifest.get('state') == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
         and type(manifest.get('files')) is list and len(manifest['files']) == 32,
         'actual31da complete package differs')
    names = set()
    bodies = {}
    for row in manifest['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
             and type(row['path']) is str, 'exact package source row required')
        rel = Path(row['path'])
        need(not rel.is_absolute() and '..' not in rel.parts and str(rel) == row['path']
             and rel.parts[0] in ('source', 'reference') and row['path'] not in names,
             'package source path differs')
        names.add(row['path'])
        bodies[row['path']] = guard.read(PACKAGE / rel,
            {key: row[key] for key in ('bytes', 'sha256')}, maximum=1048576)
    need(descriptor(bodies['source/close_component.py']) == SOURCE_PIN, 'original close9025 source differs')
    return raw, bodies


def historical_inputs(guard, original):
    values = original.get('original_host_inputs')
    need(type(values) is dict and 1 <= len(values) <= 512, 'original host-input census differs')
    allowed = (BASE,
        Path('/home/alex/codex-hepta-natural-' + LABEL + '-root-v150'),
        Path('/home/alex/codex-hepta-native-guard-fixtures-r10-r1') / NONCE)
    for name, row in values.items():
        path = Path(name)
        need(type(name) is str and path.is_absolute() and '..' not in path.parts
             and any(path == root or root in path.parents for root in allowed),
             'pinned old host input leaves its three fixed historical namespaces')
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'metadata'}
             and type(row['metadata']) is list and len(row['metadata']) == 9
             and all(type(x) is int for x in row['metadata']), 'original host-input row differs')
        guard.read(path, {key: row[key] for key in ('bytes', 'sha256')}, row['metadata'])


def verify_existing_snapshot_inputs(guard, files, original):
    # Only existing historical source/configuration inputs are used for imports.
    # No old snapshot file is created, rewritten, relabelled or given new metadata.
    names = [name for name in files if name.startswith('home/inputs/')]
    need(17 <= len(names) <= 32, 'historical snapshot input census differs')
    for name in names:
        need(name.startswith('home/inputs/') and '..' not in Path(name).parts,
             'historical snapshot relative path differs')
        path = OLD_SNAPSHOT / name
        raw = guard.read(path, descriptor(files[name]), maximum=16*1024*1024)
        need(raw == files[name], 'old snapshot bytes differ from retained capture')
    for name in ('phone_observation_tools', 'phone_task_guards', 'phone_local_tools'):
        path = OLD_SNAPSHOT / 'home/inputs/production' / (name + '.py')
        row = original['original_host_inputs'].get(str(path))
        need(row is not None, 'historical mapper source path was not consumed by original closure')
        guard.read(path, {key: row[key] for key in ('bytes', 'sha256')}, row['metadata'])


def original_closed_expression(raw):
    tree = ast.parse(raw)
    close = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'close']
    need(len(close) == 1, 'one original close function required')
    assignments = [node for node in close[0].body if isinstance(node, ast.Assign)
        and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'closed']
    need(len(assignments) == 1 and isinstance(assignments[0].value, ast.Dict),
         'one original complete closed-object expression required')
    node = assignments[0].value
    lines = raw.splitlines(keepends=True)
    begin = sum(map(len, lines[:node.lineno-1])) + node.col_offset
    end = sum(map(len, lines[:node.end_lineno-1])) + node.end_col_offset
    expression = raw[begin:end]
    compiled = compile(ast.Expression(node), str(SOURCE) + ':closed-value-evaluated-by-independent-auditor', 'eval')
    return compiled, {'source': str(SOURCE), 'source_sha256': SOURCE_PIN['sha256'],
        'first_line': node.lineno, 'last_line': node.end_lineno, **descriptor(expression)}


def recompute(module, originals, plan_raw, expected_raw, guard, source_raw, started):
    # Same validators and ordering as original9025 close(); target close/main are
    # never called. The only removed operations materialize a new snapshot or
    # name this derivation as a native closure. Original source bytes are unchanged.
    C = module['C']
    LATE = module['LATE']
    FIXTURE = module['FIXTURE']
    plan = module['validate_plan'](C.strict(plan_raw))
    need(plan['label'] == LABEL and plan['package'] == {'path': str(PACKAGE/'MANIFEST.json'), **PACKAGE_PIN}
         and plan['archive'] == {'path': str(BASE/'closure-inputs/ORIGINALS.tar.gz'), **ARCHIVE_PIN}
         and plan['capture_sha256'] == CAPTURE_PIN['sha256'], 'fixed actual original plan binding differs')
    archive = originals.pinned(plan['archive'])
    cap, files = module['archive_files'](archive, plan['capture_sha256'])
    need(descriptor(files['CAPTURE.json']) == CAPTURE_PIN, 'complete actual capture differs')
    request = originals.pinned(plan['request'])
    module['load_package'](originals, plan['package'], files)
    lease, bound, scope, home, run = module['identity_inputs'](cap, files, request)
    C.need(cap['package_sha256'] == plan['package']['sha256'],
           'actual component package is not the reviewed host package')
    need(lease['nonce'] == NONCE and lease['label'] == LABEL and lease['boot_id'] == BOOT
         and cap['combination_sha256'] == COMBINATION, 'fixed old native identity differs')
    original = strict(expected_raw)
    verify_existing_snapshot_inputs(guard, files, original)
    combo, cfg, modules = module['load_production'](OLD_SNAPSHOT, files)
    C.need(bound['contract']['source_seal_sha256'] == combo['source_seal']['sha256']
           and bound['contract']['configuration_sha256'] == combo['configuration']['sha256'],
           'actual native contract source/config differs')
    # These compile filenames are real old files; verify their actual retained bytes.
    for name in ('home/package/reference/native_journal_audit.py',
                 'home/package/reference/decode_client_state.py',
                 'home/package/source/native_guard_session_r2.py',
                 'home/package/source/component_listener.py'):
        need(guard.read(OLD_SNAPSHOT/name, descriptor(files[name]), maximum=1048576) == files[name],
             'real historical parser resource differs from capture')
    auditor = module['module_from_bytes'](files['home/package/reference/native_journal_audit.py'],
        'independent_native_auditor', OLD_SNAPSHOT/'home/package/reference/native_journal_audit.py')
    decoder = module['module_from_bytes'](files['home/package/reference/decode_client_state.py'],
        'original_selection_decoder', OLD_SNAPSHOT/'home/package/reference/decode_client_state.py')
    K = module['module_from_bytes'](files['home/package/source/native_guard_session_r2.py'],
        'original_component_parser', OLD_SNAPSHOT/'home/package/source/native_guard_session_r2.py')
    listener = module['module_from_bytes'](files['home/package/source/component_listener.py'],
        'original_component_wire_validator', OLD_SNAPSHOT/'home/package/source/component_listener.py')
    native = module['native_originals'](cap, files, scope, request, auditor)
    inventory_raw = files['after/AFTER-INVENTORY.json']
    inventory = C.strict(inventory_raw)
    LATE.inventory_value(inventory)
    module['capture_provenance'](cap, files, lease, home, run, inventory)
    sidebranch = module['verify_non_native_sidebranch'](cap, files, inventory)
    module['verify_retirement_copy'](files, lease)
    roles = module['verify_roles'](files, lease, bound)
    root_attempts = FIXTURE.verify_attempts(originals, plan['root_fixture_attempts'], files, lease, scope,
        expected_package_sha256=cap['package_sha256'])
    parsed = module['typed_reparse'](OUT, files, lease, bound, scope, request, native, cfg, modules, K,
        listener, root_attempts=root_attempts)
    root_fixture = module['verify_root_fixture_inventory'](cap, files, lease, scope, inventory, root_attempts)
    ledger = module['verify_ledger_inventory'](cap, files, lease, home, run, inventory, native, modules)
    sender = module['sender_originals'](originals, plan, files, request, scope, run, native, decoder, OUT)
    originals.recheck()
    FIXTURE.recheck_directories(originals)
    audit = {key: value for key, value in native['audit'].items() if key not in ('selected_records', 'frames')}
    compiled, expression = original_closed_expression(source_raw)
    # Evaluate the unchanged complete original object expression with the actual
    # original module globals and this driver's explicitly computed local values.
    # No globals/module/source identity is replaced; no field is deleted or normalized.
    values = {'lease': lease, 'parsed': parsed, 'scope': scope, 'request': request, 'files': files,
        'home': home, 'cap': cap, 'inventory_raw': inventory_raw, 'sidebranch': sidebranch,
        'roles': roles, 'native': native, 'plan': plan, 'audit': audit, 'ledger': ledger,
        'sender': sender, 'root_fixture': root_fixture, 'originals': originals}
    closed = eval(compiled, module, values)
    body = C.encoded(closed)
    recomputed = put('RECOMPUTED-EXPECTED-CLOSURE.json', body)
    put('RECOMPUTED-NATIVE-AUDIT.json', C.encoded(audit))
    put('RECOMPUTED-AFTER-INVENTORY.json', inventory_raw)
    guard.recheck()
    originals.recheck()
    FIXTURE.recheck_directories(originals)
    need(body == expected_raw and descriptor(body) == CLOSURE_PIN,
         'complete derived closed object is not byte-identical to existing failed closure')
    need(closed['component_qualified'] is False and closed['business_qualified'] is False
         and closed['state'] == 'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED',
         'failed historical closure was upgraded')
    return {'recomputed': recomputed, 'closed_object_expression': expression,
        'historical_original_host_inputs_exact': originals.files == original['original_host_inputs'],
        'pure_validator_counted_scope': 'All original9025 close validators and unchanged full closed-object expression',
        'elapsed_seconds': time.monotonic() - started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-independent-host-audit-once', action='store_true')
    args = parser.parse_args()
    if not args.execute_independent_host_audit_once:
        print(encoded({'state': 'SOURCE_ONLY_HOST_AUDIT_PREVIEW', 'final_inputs_bound': FINAL_INPUTS is not None,
            'phone_calls': 0, 'writes': 0, 'case_pass': False}).decode(), end='')
        return 0
    need(FINAL_INPUTS is not None, 'final original closure/input review has not been bound')
    need(FINAL_INPUTS == {'plan': PLAN_PIN, 'closure': CLOSURE_PIN, 'package': PACKAGE_PIN},
         'fixed reviewed final input bindings differ')
    need(Path(__file__) == DRIVER, 'driver must execute from its own separately retained real source path')
    before_fds = own_fds()
    guard = Guard()
    started = time.monotonic()
    created = False
    phase = 'original_inputs'
    try:
        driver_raw = guard.read(DRIVER, maximum=1048576)
        source_raw = guard.read(SOURCE, SOURCE_PIN, maximum=1048576)
        package_raw, package_files = fixed_package(guard)
        plan_raw = guard.read(PLAN, PLAN_PIN, maximum=262144)
        expected_raw = guard.read(ORIGINAL_CLOSURE, CLOSURE_PIN, maximum=1048576)
        original = strict(expected_raw)
        need(original.get('schema') == 'hepta.native-guard.original-closure.v1'
             and original.get('state') == 'ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
             and original.get('nonce') == NONCE and original.get('boot_id') == BOOT
             and original.get('package_sha256') == PACKAGE_PIN['sha256']
             and original.get('combination_sha256') == COMBINATION
             and original.get('component_qualified') is False and original.get('business_qualified') is False
             and original.get('closed') is True and original.get('boundary_published_here') is False,
             'fixed previously published failed-closure identity differs')
        historical_inputs(guard, original)
        guard.recheck()
        phase = 'new_audit_output'
        need(OUT.parent.resolve(strict=True) == OUT.parent and not OUT.is_symlink(),
             'new independent audit output parent changed')
        OUT.mkdir(mode=0o700)
        created = True
        put('AUDIT-INTENT.json', encoded({'schema': 'hepta.existing-failed-closure.independent-host-intent.v1',
            'driver': {'path': str(DRIVER), **descriptor(driver_raw)},
            'original_close_source': {'path': str(SOURCE), **SOURCE_PIN},
            'original_plan': {'path': str(PLAN), **PLAN_PIN},
            'original_closure': {'path': str(ORIGINAL_CLOSURE), **CLOSURE_PIN},
            'old_snapshot_resource_anchor': str(OLD_SNAPSHOT), 'new_derived_output': str(OUT),
            'original_main_calls': 0, 'original_close_calls': 0, 'phone_calls': 0,
            'snapshot_calls': 0, 'native_dispatches': 0, 'boundary_publications': 0,
            'automatic_retry': False, 'case_pass': False,
            'old_mac_sender_capture_unknown_preserved': True}))
        phase = 'original_pure_module_load'
        foreign = {'component_common', 'late_boundary', 'root_fixture_originals', 'component_listener',
            'component_lifecycle', 'native_guard_session_r2', 'witness_bundle', 'root_fixture_once',
            'phone_observation_tools', 'phone_task_guards', 'phone_local_tools', 'provider_openai_compatible',
            'task_postconditions', 'retirement_recovery', 'action_ledger'}
        need(not foreign.intersection(sys.modules), 'fresh host interpreter required for original source imports')
        # Force imports to read the actual checked .py files: -B only forbids
        # writes and alone does not prohibit loading a pre-existing bytecode cache.
        cache = OUT / 'bytecode-cache-must-remain-absent'
        need(not cache.exists() and not cache.is_symlink(), 'new bytecode lookup namespace is not absent')
        sys.pycache_prefix = str(cache)
        module = runpy.run_path(str(SOURCE), run_name='hepta_existing_closure_original_pure_functions')
        need(module.get('__file__') == str(SOURCE), 'actual original source filename differs')
        for name in ('C', 'LATE', 'FIXTURE'):
            item = module[name]
            need(Path(item.__file__).parent == PACKAGE/'source', 'original module was replaced or relocated')
        phase = 'independent_recompute'
        originals = module['Originals']()
        need(originals.read(PLAN, 262144) == plan_raw, 'original plan changed at pure verifier entry')
        proof = recompute(module, originals, plan_raw, expected_raw, guard, source_raw, started)
        phase = 'final_originals_and_own_fd_bookend'
        need(not cache.exists() and not cache.is_symlink(), 'bytecode cache unexpectedly written')
        guard.recheck()
        remaining = [{'fd': fd, 'identity': list(value)} for fd, value in own_fds().items()
                     if fd >= 3 and before_fds.get(fd) != value]
        need(not remaining, 'independent host audit left an unowned read descriptor')
        result = {'schema': 'hepta.existing-failed-closure.independent-host-byte-equality.v1',
            'state': 'EXISTING_FAILED_CLOSURE_FULL_OBJECT_RECOMPUTED_BYTE_EQUAL',
            'driver': {'path': str(DRIVER), **descriptor(driver_raw)},
            'original_close_source': {'path': str(SOURCE), **SOURCE_PIN},
            'original_plan': {'path': str(PLAN), **PLAN_PIN},
            'original_closure': {'path': str(ORIGINAL_CLOSURE), **CLOSURE_PIN}, **proof,
            'driver_original_observations': guard.rows,
            'new_host_derivation_only': True, 'original_main_calls': 0, 'original_close_calls': 0,
            'source_modules_replaced_or_relabelled': False, 'original_host_metadata_replaced': False,
            'complete_object_fields_deleted_or_normalized': False, 'phone_calls': 0,
            'native_dispatches': 0, 'sender_runs': 0, 'snapshot_calls': 0, 'boundary_publications': 0,
            'signals': 0, 'new_native_closure': False, 'eligible_for_publication': False,
            'fresh_phone_clearance': False, 'component_qualified': False, 'case_pass': False,
            'automatic_retry': False, 'old_mac_sender_capture_unknown_preserved': True,
            'owned_read_fd_bookend_complete': True}
        receipt = put('BYTE-EQUALITY.json', encoded(result))
        print(encoded({'state': result['state'], 'receipt': receipt,
            'phone_calls': 0, 'new_native_closure': False, 'case_pass': False}).decode(), end='')
        return 0
    except BaseException as error:
        failure = {'schema': 'hepta.existing-failed-closure.independent-host-failure.v1',
            'state': 'INDEPENDENT_RECOMPUTATION_FAILED_OR_UNKNOWN', 'phase': phase,
            'type': type(error).__name__, 'detail': str(error)[:4096], 'new_audit_directory_created': created,
            'original_main_calls': 0, 'original_close_calls': 0, 'phone_calls': 0,
            'source_or_original_outputs_changed': False, 'new_native_closure': False,
            'eligible_for_publication': False, 'old_mac_sender_capture_unknown_preserved': True,
            'case_pass': False, 'automatic_retry': False}
        if created:
            try:
                failure['retained_failure'] = put('AUDIT-FAILURE.json', encoded(failure))
            except BaseException as retention_error:
                failure['failure_retention_unknown'] = {'type': type(retention_error).__name__,
                    'detail': str(retention_error)[:1024]}
        print(encoded(failure).decode(), end='')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
