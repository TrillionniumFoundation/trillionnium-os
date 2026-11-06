"""Read retained originals and index existing results. Does not run any tests.

The returned verdict is explicitly host-source evidence, never an actual BUILD,
installation, READY or whole-case qualification. All callbacks are read-only.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

EVIDENCE = {'path': 'EVIDENCE-PINS.json', 'bytes': 4911,
            'sha256': 'f58dee410c82d5100ccb719f193ae3b9afe99f97fb44a65d8581f94419076ec4'}
CONDITIONS = {'path': 'CONDITION-MAP.json', 'bytes': 56609,
              'sha256': 'be89f0d2d1005c561f33658634c5c729ce6c2d94466f7515d9d0ee070aca054c'}
COMBINATION = '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'
NATIVE = 'references/native-v3/'
OWNED = 'neg14-owned-capacity01/'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def strict(raw):
    need(type(raw) is bytes, 'complete original bytes required')
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def relative(path):
    need(type(path) is str and path and not any(c in path for c in '\0\r\n\t'), 'plain relative path')
    p = PurePosixPath(path)
    need(not p.is_absolute() and str(p) == path and '..' not in p.parts, 'canonical relative path')
    return p.parts


class Originals:
    def __init__(self, read_pinned):
        self.callback = read_pinned
        self.rows = {}
        self.total = 0

    def read(self, row):
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'exact file descriptor')
        relative(row['path'])
        need(type(row['bytes']) is int and 0 <= row['bytes'] <= 4 * 1024 * 1024,
             'bounded complete file')
        need(type(row['sha256']) is str and len(row['sha256']) == 64
             and all(c in '0123456789abcdef' for c in row['sha256']), 'exact SHA256')
        raw = self.callback(dict(row))
        need(type(raw) is bytes and pin(raw) == {k: row[k] for k in ('bytes', 'sha256')},
             'complete original differs: ' + row['path'])
        old = self.rows.get(row['path'])
        need(old is None or old == (row, raw), 'path identity changed during observation')
        if old is None:
            self.total += len(raw)
            need(self.total <= 64 * 1024 * 1024 and len(self.rows) < 1024, 'bounded evidence set')
            self.rows[row['path']] = (dict(row), raw)
        return raw

    def recheck(self):
        for row, raw in list(self.rows.values()):
            need(self.callback(dict(row)) == raw, 'original changed before bookend: ' + row['path'])


def check_controller(start, status, read, expected_job, expected_result):
    need(start['audit_recorded'] is True and start['reused'] is False
         and start['job']['id'] == expected_job and start['job']['launch_state'] == 'launched'
         and start['job']['launch_error'] is None and start['launch']['ok'] is True,
         'original controller start not confirmed')
    need(status['job_id'] == read['job_id'] == expected_job
         and status['audit_recorded'] is True and read['audit_recorded'] is True
         and status['state'] == 'succeeded' and type(status['exit_code']) is int
         and status['exit_code'] == 0
         and all(status[key] is False for key in ('automatic_retry', 'cancelled', 'timed_out'))
         and all(status[key] is True for key in ('output_complete', 'output_durable', 'terminal_publication_confirmed')),
         'original controller terminal not successful/full/durable/no-retry')
    streams = {}
    for name in ('stdout', 'stderr'):
        stream = read[name]
        need(type(stream['bytes_hex']) is str, 'original hexadecimal stream')
        raw = bytes.fromhex(stream['bytes_hex'])
        need(stream['bytes_hex'] == raw.hex() and stream['text'].encode('utf-8') == raw
             and type(stream['offset']) is int and stream['offset'] == 0
             and type(stream['size']) is int and type(stream['next_offset']) is int
             and stream['size'] == stream['next_offset'] == len(raw) and stream['eof'] is True
             and status['log_bytes'][name] == {'seen': len(raw), 'stored': len(raw)}
             and status['log_synced'][name] is True and status['log_errors'][name] is None
             and status['log_truncated'][name] is False,
             'original complete double-EOF stream differs')
        streams[name] = raw
    need(streams['stderr'] == b'', 'unexpected controller stderr')
    stdout = strict(streams['stdout'])
    need({k: stdout['result'][k] for k in ('bytes', 'sha256')} == expected_result,
         'controller stdout does not bind the complete result')
    return {'job_id': expected_job, 'stdout_bytes': len(streams['stdout']), 'stderr_bytes': 0,
            'original_success_full_durable_double_EOF': True, 'automatic_retry': False}


def object_at(value, pointer):
    need(type(pointer) is str and pointer.startswith('/'), 'absolute JSON pointer')
    for item in pointer[1:].split('/'):
        key = item.replace('~1', '/').replace('~0', '~')
        value = value[int(key)] if type(value) is list else value[key]
    return value


def summarize_existing_evidence(*, read_pinned):
    pool = Originals(read_pinned)
    ep = strict(pool.read(EVIDENCE))
    mapping = strict(pool.read(CONDITIONS))
    need(ep['actual_BUILD'] is None and ep['installed_tuple'] is None
         and ep['historical_repeated_runs_combined'] is False, 'original evidence scope differs')
    files = {path: pool.read(dict(path=path, **row)) for path, row in ep['files'].items()}
    combo_raw = pool.read(mapping['current_combination'])
    combo = strict(combo_raw)
    need(pin(combo_raw)['sha256'] == COMBINATION, 'selected final shared combination differs')
    protocol = strict(pool.read(mapping['fixed_protocol']))
    neg14 = [row for row in protocol['cases'] if row['id'] == 'NEG-14']
    need(neg14 == [mapping['original_NEG14_definition']] and neg14[0]['layer'] == 'host_isolated',
         'original fixed NEG14 definition differs')
    candidate = strict(files[NATIVE + 'CANDIDATE-PINS.json'])
    expected = {PurePosixPath(row['path']).name: {k: row[k] for k in ('bytes', 'sha256')}
                for row in combo['production_files']}
    candidate_rows = {PurePosixPath(row['path']).name: {k: row[k] for k in ('bytes', 'sha256')}
                      for row in candidate['files'] if row['path'].startswith('candidate/source/')}
    need(len(expected) == len(candidate_rows) == mapping['source_count'] == 15 and expected == candidate_rows,
         'final shared15 and tested complete15 differ')
    source_symbols = {}
    for row in mapping['sources']:
        raw = pool.read({k: row[k] for k in ('path', 'bytes', 'sha256')})
        need(pin(raw) == expected[row['name']], 'source source-pin mismatch')
        tree = ast.parse(raw)
        symbols = set()
        for item in tree.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols.add(item.name)
            elif isinstance(item, ast.ClassDef):
                symbols.update(item.name + '.' + method.name for method in item.body
                               if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)))
        source_symbols[row['name']] = symbols
    need(set(source_symbols) == set(expected), 'source inventory is incomplete')
    result_paths = {
        'native': NATIVE + 'evidence/native-RESULT.original.json',
        'shared': NATIVE + 'evidence/shared-RESULT.original.json',
        'selected': NATIVE + 'evidence/selected-guards-RESULT.original.json',
        'owned': OWNED + 'actual/RUN01/RESULT.json',
    }
    results = {name: strict(files[path]) for name, path in result_paths.items()}
    original_counts = {'native': {'parser_cases': 73, 'consumer_chains': 12, 'trust_parser_cases': 40,
                                  'trust_consumer_chains': 11, 'dispatch_binding_cases': 9},
                       'shared': {'cases': 14}, 'selected': {'cases': 13}, 'owned': {'checks': 4}}
    for group, arrays in original_counts.items():
        result = results[group]
        need(result['fatal_error'] is None and all(result[key] == 0 and type(result[key]) is int
             for key in ('phone_calls', 'model_requests', 'native_dispatches')), 'unexpected non-host result')
        for array, count in arrays.items():
            rows = result[array]
            need(type(rows) is list and len(rows) == count and len({row['name'] for row in rows}) == count
                 and all(row['passed'] is True for row in rows), 'original run case census differs')
    for group in ('native', 'shared', 'selected'):
        need(results[group]['pins_sha256'] == pin(files[NATIVE + 'CANDIDATE-PINS.json'])['sha256'],
             'result is not bound to final15 pins')
    need(results['shared']['actual_imported_source_count'] == 15
         and results['selected']['source_count'] == 15
         and results['native']['ledger_binding']['passed'] is True
         and results['native']['ledger_binding']['stored_wire_call_hash_covers_all_three_dispatch_claims'] is True,
         'real shared-source/ledger evidence omitted')
    for row in results['shared']['cases'][:6]:
        name = row['name']
        missing = 'input' if 'confirmation' in name else 'public' if 'public' in name else 'return'
        need(row['actual_terminal']['kind'] == 'turn.fail'
             and row['business_outcome']['business_verified'] is False
             and row['missing_postconditions'] == [missing]
             and row['late_terminal_rejected_without_rewrite']['rejected'] is True,
             'business missing-condition outcome differs')
    race = next(row for row in results['shared']['cases'] if row['name'] == 'real_exclusive_binding_race')
    need(race['real_binding_files'] == 1 and race['threads_joined'] is True
         and sorted(row['accepted'] for row in race['outcomes']) == [False, True]
         and all(row['bindings_after'] == 0 for row in race['wrong_scopes_before_race'])
         and race['template_and_binding_unchanged_after_replays'] is True,
         'real once-only binding or wrong-scope non-consumption differs')
    old = next(row for row in results['shared']['cases'] if row['name'] == 'old_identity_real_pipe_admission')
    need(old['original_failed_turn_claim_and_binding_unchanged'] is True
         and all(row['actual_rejection']['rejected'] is True and row['mapped_calls'] == 0
                 and row['outgoing_frames'] == 0 and row['native_dispatches'] == 0 for row in old['attempts']),
         'old identity actual pipe admission differs')
    owned_pins = strict(files[OWNED + 'inputs/PINS.json'])
    for row in owned_pins['files']:
        body = pool.read(dict(row, path=OWNED + 'inputs/' + row['path']))
        if row['path'].startswith('provider/source/'):
            need(pin(body) == expected[PurePosixPath(row['path']).name], 'owned control source differs')
    owned_sources = {PurePosixPath(row['path']).name: {k: row[k] for k in ('bytes', 'sha256')}
                     for row in results['owned']['production_sources']}
    need(owned_sources == expected and results['owned']['source_count'] == 15,
         'new owned controls not bound to final15')
    capacity = next(row for row in results['owned']['checks'] if row['name'] == 'public_daily_logical_capacity_first_boundary_refusal')
    need(capacity['maximum'] == 1073741824 and capacity['below_limit'] == 939524095
         and capacity['first_rejected_total'] == 939524096
         and capacity['retained_claims']['retained_claim_bytes_and_full9_unchanged'] is True
         and capacity['retained_claims']['worker_spawned_records'] == 0
         and capacity['validate_executor_bypassed'] is False,
         'original logical-capacity first-refusal boundary differs')
    original_index = strict(files[OWNED + 'actual/RUN01/ORIGINALS.json'])
    for row in original_index['files']:
        source = row['source']
        need(len(source['full9']) == 9 and all(type(value) is int for value in source['full9'])
             and source['full9'][6] == source['bytes'], 'original full9 shape differs')
        pool.read({'path': OWNED + 'actual/RUN01/' + row['archive'],
                   'bytes': source['bytes'], 'sha256': source['sha256']})
    outer_path = OWNED + 'actual/RUN01/OUTER-RESULT.json'
    outer = strict(files[outer_path])
    need({k: outer['inner_result'][k] for k in ('bytes', 'sha256')} == pin(files[result_paths['owned']])
         and outer['FD_and_thread_baseline_restored'] is True
         and outer['original_child']['actual_direct_child_wait'] is True
         and outer['original_child']['group_after']['kernel'] == 'ESRCH'
         and outer['original_child']['group_after']['members'] == [], 'outer owned process closure differs')
    controllers = {}
    for group, prefix, job, result_path in [
        ('native', NATIVE + 'evidence/controller/native', '1a1b18b95c3-fc05-7980', result_paths['native']),
        ('shared', NATIVE + 'evidence/controller/shared', '1a1b18878e5-fc05-7966', result_paths['shared']),
        ('selected', NATIVE + 'evidence/controller/selected-guards', '1a1b19980ee-fc05-79c6', result_paths['selected']),
        ('owned', OWNED + 'controller/run', '1a1b1f12896-fc05-7b9d', outer_path),
    ]:
        controllers[group] = check_controller(*(strict(files[prefix + '.' + kind + '.original.json'])
                                                for kind in ('start', 'status', 'read')),
                                             job, pin(files[result_path]))
    for condition in mapping['conditions']:
        for reference in condition['source_symbols']:
            need(set(reference['symbols']) <= source_symbols[reference['name']], 'source symbol does not exist')
        for reference in condition['evidence']:
            raw = files[reference['path']]
            need(pin(raw) == {k: reference[k] for k in ('bytes', 'sha256')}, 'condition result pin differs')
            result = strict(raw)
            for selected in reference['selections']:
                item = object_at(result, selected['pointer'])
                need(item['name'] == selected['name'] and item['passed'] is True, 'condition pointer differs')
    pool.recheck()
    return {
        'schema': 'fc33.neg10-neg14.observed-final15-host-summary.v1',
        'state': 'OBSERVED_HOST_SOURCE_CONDITIONS_VERIFIED_ACTUAL_TUPLE_UNBOUND',
        'current_combination_sha256': COMBINATION, 'source_count': 15,
        'production_sources': [{'name': name, **row} for name, row in sorted(expected.items())],
        'condition_map': CONDITIONS, 'evidence_pins': EVIDENCE, 'fixed_protocol': mapping['fixed_protocol'],
        'condition_ids': [row['condition_id'] for row in mapping['conditions']],
        'original_run_groups_not_added_together': original_counts,
        'ledger_binding_single_existing_check': results['native']['ledger_binding']['passed'],
        'controllers': controllers, 'all_originals_bookended': True,
        'original_files_read': len(pool.rows), 'original_bytes_read': pool.total,
        'actual_BUILD': None, 'installed_tuple': None, 'actual_READY': None, 'whole_cases_closed': [],
        'remaining_explicit_gates': mapping['common_pending_gates'],
        'unmeasured_scope_not_additional_qualification_gates': mapping['unmeasured_scope_not_additional_qualification_gates'],
        'generation_trust_boundaries': results['native']['trust_boundaries'],
        'summary_did_not_run_tests': True, 'phone_calls': 0, 'model_requests': 0,
        'native_dispatches': 0, 'processes_started': 0,
    }


def local_reader(root):
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    def read(row):
        parts = relative(row['path'])
        held = [os.dup(root_fd)]
        try:
            for part in parts[:-1]:
                held.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=held[-1]))
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=held[-1])
            held.append(fd)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_size == row['bytes'], 'complete regular original')
            chunks = []
            remaining = row['bytes'] + 1
            while remaining:
                chunk = os.read(fd, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(tuple(getattr(before, key) for key in fields) == tuple(getattr(after, key) for key in fields),
                 'original changed during read')
            return b''.join(chunks)
        finally:
            for fd in reversed(held):
                os.close(fd)
    return root_fd, read


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-root', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    root_fd, reader = local_reader(args.package_root)
    try:
        result = summarize_existing_evidence(read_pinned=reader)
    finally:
        os.close(root_fd)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
