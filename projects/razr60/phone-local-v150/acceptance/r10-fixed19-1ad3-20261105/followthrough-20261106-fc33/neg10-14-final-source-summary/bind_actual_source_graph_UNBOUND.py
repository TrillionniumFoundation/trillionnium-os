"""Pure, fail-closed future binding of retained host checks to an actual release.

This source is deliberately UNBOUND. Review and bind only the exact descriptor
of a complete actual input after the real BUILD and install/start/READY originals
exist. No production source, reader constant, or reader gate is overridden here.
The installation reader invokes its original release reader and exact8 gates.
"""
import hashlib
import json
from pathlib import PurePosixPath
import sys
import types

FROZEN_INPUTS = None
SCHEMA = 'fc33.neg10-neg14.actual-source-graph-inputs.v1'
HOST_SUMMARY = {'bytes': 6016, 'sha256': 'c11b916174d3e2231a55f279a84132bd45b0c0f128c4142e5b73588e28dd1ae8'}
COMBINATION = '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def strict(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4 * 1024 * 1024, 'bounded complete JSON input')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def descriptor(row, maximum=64 * 1024 * 1024, metadata=False):
    need(type(row) is dict and set(row) in ({'path', 'bytes', 'sha256'},
                                           {'path', 'bytes', 'sha256', 'metadata'} if metadata else set()),
         'exact complete original descriptor')
    path = row['path']
    need(type(path) is str and path and not any(c in path for c in '\0\r\n\t'), 'plain path')
    parsed = PurePosixPath(path)
    need(parsed.is_absolute() and str(parsed) == path and '..' not in parsed.parts,
         'canonical absolute original path')
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= maximum
         and type(row['sha256']) is str and len(row['sha256']) == 64
         and all(c in '0123456789abcdef' for c in row['sha256']), 'bounded exact byte pin')
    return row


class Originals:
    def __init__(self, read_pinned):
        need(callable(read_pinned), 'read-only original callback')
        self.callback = read_pinned
        self.rows = {}
        self.total = 0

    def read(self, row):
        descriptor(row, metadata=True)
        raw = self.callback(dict(row))
        need(type(raw) is bytes and pin(raw) == {key: row[key] for key in ('bytes', 'sha256')},
             'complete original bytes differ')
        key = canonical(row)
        prior = self.rows.get(key)
        need(prior is None or prior[1] == raw, 'original changed during repeat read')
        if prior is None:
            self.total += len(raw)
            need(self.total <= 512 * 1024 * 1024 and len(self.rows) < 4096,
                 'complete bounded original pool exceeded')
            self.rows[key] = (dict(row), raw)
        return raw

    def recheck(self):
        for row, raw in list(self.rows.values()):
            need(self.callback(dict(row)) == raw, 'original changed before complete bookend')


def verify_actual_source_graph(inputs_raw, *, read_pinned):
    # Fail before parsing, imports of selected sources, or any read callback.
    need(FROZEN_INPUTS is not None, 'UNBOUND_ACTUAL_SOURCE_GRAPH_INPUTS_NO_IO')
    descriptor(FROZEN_INPUTS, 65536)
    need(type(inputs_raw) is bytes and pin(inputs_raw) ==
         {key: FROZEN_INPUTS[key] for key in ('bytes', 'sha256')}, 'exact frozen actual input bytes')
    value = strict(inputs_raw)
    need(type(value) is dict and set(value) == {
        'schema', 'host_summary', 'install_reader', 'release_reader', 'install_inputs', 'release_inputs'
    } and value['schema'] == SCHEMA, 'exact actual source-graph input contract')
    for key in ('host_summary', 'install_reader', 'release_reader', 'install_inputs', 'release_inputs'):
        descriptor(value[key], 4 * 1024 * 1024)
    need({key: value['host_summary'][key] for key in ('bytes', 'sha256')} == HOST_SUMMARY,
         'only this observed final15 host summary can be bound')
    pool = Originals(read_pinned)
    need(pool.read(FROZEN_INPUTS) == inputs_raw, 'frozen input original differs')
    summary = strict(pool.read(value['host_summary']))
    need(summary['state'] == 'OBSERVED_HOST_SOURCE_CONDITIONS_VERIFIED_ACTUAL_TUPLE_UNBOUND'
         and summary['current_combination_sha256'] == COMBINATION
         and summary['source_count'] == 15 and summary['all_originals_bookended'] is True
         and summary['actual_BUILD'] is None and summary['installed_tuple'] is None,
         'host-source evidence scope differs')
    install_raw = pool.read(value['install_inputs'])
    install_input = strict(install_raw)
    need(install_input['release_inputs'] == value['release_inputs'], 'same exact actual release input required')
    reader_raw = pool.read(value['install_reader'])
    pool.read(value['release_reader'])
    module_name = '_reviewed_neg10_14_install_reader_' + value['install_reader']['sha256']
    need(module_name not in sys.modules, 'reviewed source module identity is already active')
    module = types.ModuleType(module_name)
    module.__file__ = value['install_reader']['path']
    sys.modules[module_name] = module
    try:
        exec(compile(reader_raw, module.__file__, 'exec'), module.__dict__)
        need(module.FROZEN_INPUTS == value['install_inputs']
             and module.FROZEN_EXECUTION_PLAN == install_input['execution_plan']
             and module.SOURCES['release'] == value['release_reader'],
             'original reader must already bind these exact actual inputs; no override allowed')
        installed = module.verify_install_start_ready_originals(install_raw, read_pinned=pool.read)
    finally:
        del sys.modules[module_name]
    need(installed['state'] == 'VERIFIED_ACTUAL_INSTALL_START_READY_EXECUTION_ORIGINALS'
         and installed['actual_installer_and_READY_execution_qualified'] is True
         and installed['original_installer_delta_recomputed'] is True
         and installed['three_original_actor_terminals_and_outputs_verified'] is True
         and installed['all_retained_originals_bookended'] is True
         and installed['runtime_combination_sha256'] == COMBINATION
         and installed['READY_qualification_scope'] == 'TRANSPORT_ONLY_AT_ORIGINAL_OBSERVATION'
         and installed['business_qualified'] is False and installed['whole_production_scope_qualified'] is False,
         'actual original reader did not qualify the exact installed transport/source scope')
    # Resolve originals only through the already validated explicit original map.
    original_map = install_input['original_map']
    def retained(row):
        key = canonical(row)
        matches = [item for item in original_map if canonical(item['original']) == key]
        need(len(matches) == 1, 'exact declared original mapping required; no guessed aliases')
        body = pool.read(matches[0]['retained'])
        need(pin(body) == {name: row[name] for name in ('bytes', 'sha256')},
             'declared original and retained byte pins differ')
        return body
    release = strict(retained(value['release_inputs']))
    combo_raw = retained(release['combination'])
    need(pin(combo_raw)['sha256'] == COMBINATION
         and installed['actual_build_result_sha256'] == release['build_result']['sha256'],
         'actual BUILD and final shared combination differ')
    sources = {row['name']: {key: row[key] for key in ('bytes', 'sha256')}
               for row in summary['production_sources']}
    combo = strict(combo_raw)
    combo_sources = {PurePosixPath(row['path']).name: {key: row[key] for key in ('bytes', 'sha256')}
                     for row in combo['production_files']}
    need(len(sources) == len(combo_sources) == 15 and sources == combo_sources,
         'actual combination changes the tested source tuple')
    rows = release['shared_originals']
    need(type(rows) is list and len(rows) == 17 and len({row['name'] for row in rows}) == 17,
         'exact complete shared17 source graph')
    observed = {}
    for row in rows:
        name = row['name']
        if name.startswith('provider/source/'):
            filename = PurePosixPath(name).name
            need(name == 'provider/source/' + filename and filename in sources and filename not in observed,
                 'exact shared production member')
            observed[filename] = pin(retained(row['copy']))
    need(observed == sources, 'all15 actual shared originals must equal all15 tested full source bytes')
    pool.recheck()
    return {
        'schema': 'fc33.neg10-neg14.actual-source-graph-verdict.v1',
        'state': 'EXISTING_HOST_CONDITIONS_BOUND_TO_VERIFIED_ACTUAL_INSTALLED_SOURCE_GRAPH',
        'host_summary': value['host_summary'], 'actual_BUILD': release['build_result'],
        'actual_install_inputs': value['install_inputs'], 'actual_READY': installed['actual_ready_original'],
        'runtime_combination_sha256': COMBINATION,
        'production_combination_sha256': installed['production_combination_sha256'],
        'production_combination_manifest_sha256': installed['production_combination_manifest_sha256'],
        'release_pins': installed['release_pins'], 'all15_tested_source_bytes_equal_actual_shared': True,
        'original_release_reader_and_install_READY_gates_executed': True,
        'READY_qualification_scope': installed['READY_qualification_scope'],
        'original_host_run_groups_unchanged': summary['original_run_groups_not_added_together'],
        'condition_ids_bound': summary['condition_ids'],
        'unmeasured_scope_not_additional_qualification_gates': summary['unmeasured_scope_not_additional_qualification_gates'],
        'all_originals_bookended': True, 'original_files_read': len(pool.rows), 'original_bytes_read': pool.total,
        'whole_cases_closed': [], 'fixed19_credit': 0,
        'scope': 'Source/adoption binding only; final fixed19 qualification remains the original protocol decision, not a new task execution.',
        'phone_calls': 0, 'model_requests': 0, 'native_dispatches': 0, 'processes_started': 0,
    }
