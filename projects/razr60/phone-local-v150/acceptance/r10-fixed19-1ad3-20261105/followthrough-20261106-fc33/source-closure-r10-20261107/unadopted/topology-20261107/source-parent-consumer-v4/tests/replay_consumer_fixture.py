#!/usr/bin/env python3
"""Complete offline replay of actual frozen/current source-parent consumers.

Private originals are supplied by an exact retained bundle and its separately
retained supplement, or the same already collected 29-file Mac readset. Nothing
calls a phone, native service, stage, fresh admission or current observation.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import signal
import sys
import time
import types

V3_HARNESS_PIN = {'bytes': 22696, 'sha256': 'ef189c5e5fbbd0425cb39e440267e50eb2da24f8f0d595aac25354ec2e50ebe6'}
CURRENT_PACKAGE = {'bytes': 87655, 'sha256': '94e945e55f4cda2c9d2c4bd473f6fdb8ec6eca425610db4fd59af1814f5fca02'}
CURRENT_PLAN = {'bytes': 5194, 'sha256': '523aa7ce5eb64732ca40fcfba7d78fc30c93689b6acc0c25620ed2972b4d5366'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def module(raw, name):
    value = types.ModuleType(name); value.__file__ = '<offline-' + name + ':' + pin(raw)['sha256'] + '>'
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def old_current(anchor, sources, callback):
    saved_path = sys.path[:]; saved_dwb = sys.dont_write_bytecode
    present = 'component_common' in sys.modules; saved = sys.modules.get('component_common')
    try:
        sys.dont_write_bytecode = True
        common = module(sources['source/component_common.py'], 'exact-current-common')
        common.__reviewed_source_sha256__ = pin(sources['source/component_common.py'])['sha256']
        sys.modules['component_common'] = common
        parent = types.ModuleType('exact_frozen_current_consumer')
        parent.__file__ = '<exact-frozen-current-consumer:' + pin(anchor)['sha256'] + '>'
        parent.__reviewed_source_sha256__ = pin(anchor)['sha256']
        parent.__reviewed_package_sources__ = dict(sources)
        parent.__reviewed_package_sources__['source/late_boundary.py'] = anchor
        parent.__retained_stage_read_pinned__ = callback
        exec(compile(anchor, parent.__file__, 'exec'), parent.__dict__)
        return parent
    finally:
        sys.path[:] = saved_path; sys.dont_write_bytecode = saved_dwb
        if present:
            sys.modules['component_common'] = saved
        else:
            sys.modules.pop('component_common', None)


def outcome(target, method, args, kwargs, callback, *, derived, corrupt_at=None):
    callback.reset(corrupt_at); inputs = copy.deepcopy((args, kwargs)); before = copy.deepcopy(inputs)
    try:
        result = getattr(target, method)(*inputs[0], **inputs[1])
        if derived:
            need(result['schema'] == 'hepta.UNADOPTED.guarded-source-parent-consumer-result.v1'
                 and result['method'] == method
                 and result['historical_result_is_old_execution_attestation'] is False
                 and result['production_adopted'] is False and result['runtime_admission'] is False
                 and type(result['current_native_case_credit']) is int and result['current_native_case_credit'] == 0
                 and result['whole_stage_budget_verified'] is False,
                 'outer consumer must retain the new execution envelope and claim ceiling')
            need(result['consumer_execution_provenance'] == target.provenance(),
                 'complete actual current consumer provenance')
            result = result['guarded_historical_result']
        answer = {'accepted': True, 'result': result}
    except Exception as error:
        answer = {'accepted': False, 'exception_type': type(error).__name__, 'message': str(error)}
    need(inputs == before, 'current consumer must not mutate supplied originals')
    return answer, copy.deepcopy(callback.calls)


def compare(old, new, method, args, kwargs, callback, *, label, accepted, corrupt_at=None):
    left, left_reads = outcome(old, method, args, kwargs, callback, derived=False, corrupt_at=corrupt_at)
    right, right_reads = outcome(new, method, args, kwargs, callback, derived=True, corrupt_at=corrupt_at)
    need(left == right, 'complete current-consumer return/error differs: ' + label + ' ' +
         (str(left)[:250] + ' / ' + str(right)[:250] if not left['accepted'] or not right['accepted'] else ''))
    need(left_reads == right_reads, 'complete original callback sequence differs: ' + label)
    need(left['accepted'] is accepted, 'expected actual current-consumer acceptance differs: ' + label + ' ' + str(left)[:250])
    summary = {'case': label, 'method': method, 'accepted': accepted,
               'complete_result_or_exception_equal': True, 'callback_order_and_bytes_equal': True,
               'callback_reads': len(left_reads), 'callback_sequence': pin(encoded(left_reads))}
    if accepted:
        summary['complete_result'] = pin(encoded(left['result']))
    else:
        summary.update({key: left[key] for key in ('exception_type', 'message')})
    return summary, left


def run(files, helper, source, loader_raw, v3_source, v3_loader, inventory_function):
    loader = module(loader_raw, 'consumer-bound-loader'); candidate = loader.load_bound(source, source)
    inner_loader = module(v3_loader, 'v3-bound-loader'); producer = inner_loader.load_bound(v3_source, v3_source)
    anchor = files['anchor/current_late.py']; sources = {k: files['dependency/' + k] for k in producer.DEPENDENCIES}
    callback = helper.SuppliedOriginals(files)
    old = old_current(anchor, sources, callback)
    saved_path = sys.path[:]; saved_dwb = sys.dont_write_bytecode; saved_common = sys.modules.get('component_common')
    params = dict(current_source=anchor, sources=sources, v3_constructor_source=v3_source,
                  v3_loader_source=v3_loader, inventory_function=inventory_function,
                  read_pinned=callback, implementation_source=source)
    new = candidate.construct(**params)
    need(sys.path == saved_path and sys.dont_write_bytecode == saved_dwb
         and sys.modules.get('component_common') is saved_common,
         'current consumer construction must restore ambient import state')
    provenance = new.provenance()
    record = old.reviewed_source_parent_records()[0]
    get = lambda row: files['original/' + row['path'].lstrip('/')]
    raw = get(record['boundary']); inv = get(record['inventory']); closed = get(record['closure'])
    values = []; descriptors = []; raws = []; row = record['boundary']
    while row is not None:
        need(len(values) < 11, 'bounded real retained ancestor chain')
        current = get(row); value = json.loads(current)
        need(pin(current) == {k: row[k] for k in ('bytes', 'sha256')} and encoded(value) == current,
             'actual complete original boundary byte identity')
        values.append(value); descriptors.append(row); raws.append(current); row = value['prior_boundary']
    need(len(values) == 10, 'one exact source parent and nine failed ancestors')
    only = {'original_descriptor': record['boundary']}
    context = {'combination_sha256': old.REVIEWED_CURRENT_COMBINATION_SHA256,
               'package_sha256': CURRENT_PACKAGE['sha256']}
    kw = {**only, **context}
    positives = []
    positive_cases = [
        ('complete-outer-boundary', 'source_parent_boundary_from_original', (raw,), only),
        ('complete-outer-closure', 'source_parent_closed_boundary_originals', (raw, inv, closed), only),
        ('complete-outer-ten-boundary-tail', 'require_failed_ancestor_tail', (values,), {}),
        ('complete-generic-closure-dispatch', 'closed_boundary_originals', (raw, inv, closed), kw),
        ('complete-current-inventory', 'inventory_value', (json.loads(inv),), {}),
    ]
    for index, (raw_boundary, descriptor) in enumerate(zip(raws, descriptors)):
        positive_cases.append(('complete-generic-boundary-%02d' % index, 'boundary_from_original',
                               (raw_boundary,), {'original_descriptor': descriptor, **context}))
    for label, method, args, kwargs in positive_cases:
        summary, _ = compare(old, new, method, args, kwargs, callback, label=label, accepted=True)
        positives.append(summary)
    # A repeated full closure re-runs every real retained read, not a prior PASS.
    first, _ = compare(old, new, 'source_parent_closed_boundary_originals', (raw, inv, closed), only,
                        callback, label='repeated-complete-outer-closure', accepted=True)
    need(first['callback_reads'] > 0 and first['callback_sequence'] == positives[1]['callback_sequence'],
         'repeated closure must repeat the exact full retained-original callback sequence')
    positives.append(first)
    negatives = []
    cases = [
        ('outer-boundary-truncated', 'source_parent_boundary_from_original', (raw[:-1],), only),
        ('outer-boundary-wrong-type', 'source_parent_boundary_from_original', (raw.decode(),), only),
        ('outer-unselected-ancestor', 'source_parent_boundary_from_original', (raws[-1],), {'original_descriptor': descriptors[-1]}),
        ('outer-closure-inventory-truncated', 'source_parent_closed_boundary_originals', (raw, inv[:-1], closed), only),
        ('outer-closure-truncated', 'source_parent_closed_boundary_originals', (raw, inv, closed[:-1]), only),
        ('outer-boundary-priority-over-bad-closure', 'source_parent_closed_boundary_originals', (raw[:-1], inv[:-1], closed[:-1]), only),
        ('generic-context-priority', 'boundary_from_original', (raw,), {**kw, 'combination_sha256': '0' * 64,
          'original_descriptor': {**record['boundary'], 'metadata': []}}),
        ('generic-historical-package-reinterpretation', 'boundary_from_original', (raw,),
          {**kw, 'package_sha256': producer.PACKAGE}),
        ('generic-raw-descriptor-priority', 'closed_boundary_originals', (raw[:-1], inv[:-1], closed[:-1]), kw),
        ('tail-too-short', 'require_failed_ancestor_tail', (values[-9:],), {}),
        ('tail-too-long', 'require_failed_ancestor_tail', ([values[0]] * (old.MAX_CHAIN + 1),), {}),
        ('tail-reordered', 'require_failed_ancestor_tail', (values[:-2] + [values[-1], values[-2]],), {}),
        ('tail-duplicate', 'require_failed_ancestor_tail', (values[:-1] + [values[-2]],), {}),
    ]
    for index in range(9):
        changed = copy.deepcopy(record['boundary']); changed['metadata'][index] += 1
        cases.append(('outer-full9-field-%d' % index, 'source_parent_boundary_from_original', (raw,),
                      {'original_descriptor': changed}))
    wrong = {**record['boundary'], 'path': record['boundary']['path'] + '.other'}
    cases.append(('outer-exact-path', 'source_parent_boundary_from_original', (raw,), {'original_descriptor': wrong}))
    changed = copy.deepcopy(record['boundary']); changed['metadata'][1] += 1
    cases.append(('outer-full9-before-bad-inventory', 'source_parent_closed_boundary_originals',
                  (raw, inv[:-1], closed[:-1]), {'original_descriptor': changed}))
    cases.append(('generic-full9-before-bad-inventory', 'closed_boundary_originals',
                  (raw, inv[:-1], closed[:-1]), {**kw, 'original_descriptor': changed}))
    changed_values = copy.deepcopy(values); changed_values[0]['prior_boundary']['metadata'][1] += 1
    cases.append(('tail-full-prior-identity', 'require_failed_ancestor_tail', (changed_values,), {}))
    changed_values = copy.deepcopy(values); changed_values[-1]['actual_native_calls'] += 1
    cases.append(('tail-historical-call-accounting', 'require_failed_ancestor_tail', (changed_values,), {}))
    changed_inv = json.loads(inv); changed_inv['roots'].append(changed_inv['roots'][0])
    cases.append(('current-inventory-duplicate-root', 'inventory_value', (changed_inv,), {}))
    changed_inv = json.loads(inv); changed_inv['file_bytes_hashed'] += 1
    cases.append(('current-inventory-byte-accounting', 'inventory_value', (changed_inv,), {}))
    for label, method, args, kwargs in cases:
        summary, _ = compare(old, new, method, args, kwargs, callback, label=label, accepted=False)
        negatives.append(summary)
    for index in (0, 1):
        summary, _ = compare(old, new, 'source_parent_closed_boundary_originals', (raw, inv, closed), only,
            callback, label='consumer-original-read-corruption-%d' % index, accepted=False, corrupt_at=index)
        negatives.append(summary)
    # The pinned producer is in-process; the consumer is not an authenticator
    # for arbitrary externally supplied receipts. Exercise its schema/identity
    # gate directly using a real producer result and explicit synthetic faults.
    inner = producer.construct(sources=sources, inventory_function=inventory_function,
                              read_pinned=callback, implementation_source=v3_source)
    callback.reset()
    envelope = inner.boundary_from_original(raw, original_descriptor=record['boundary'],
        combination_sha256=producer.COMBINATION, package_sha256=producer.PACKAGE)
    scope = new._methods['source_parent_boundary_from_original'].__globals__
    consumer = scope['consume_source_parent_envelope']
    need(consumer(copy.deepcopy(envelope), 'boundary_from_original') == values[0], 'actual envelope consumer positive')
    faults = []
    for key, val in [('schema', 'hepta.native-guard.exact-source-parent-reader.v1'),
                     ('method', 'closed_boundary_originals'), ('historical_result_is_old_execution_attestation', True),
                     ('production_adopted', True), ('runtime_admission', True), ('current_native_case_credit', False),
                     ('current_native_case_credit', 1), ('whole_stage_budget_verified', True),
                     ('historical_result', [])]:
        broken = copy.deepcopy(envelope); broken[key] = val; faults.append((key + '=' + repr(val), broken))
    broken = copy.deepcopy(envelope); broken['unexpected'] = None; faults.append(('unexpected-field', broken))
    broken = copy.deepcopy(envelope); broken.pop('execution_provenance'); faults.append(('missing-provenance', broken))
    broken = copy.deepcopy(envelope); broken['execution_provenance']['actual_derived_execution_source']['sha256'] = '0' * 64
    faults.append(('wrong-actual-producer-code', broken))
    broken = copy.deepcopy(envelope); broken['execution_provenance']['historical_publisher_data_source']['sha256'] = '0' * 64
    faults.append(('wrong-historical-data-anchor', broken))
    envelope_rejections = []
    for label, broken in faults:
        try:
            consumer(broken, 'boundary_from_original')
        except ValueError as error:
            envelope_rejections.append({'case': label, 'exception_type': 'ValueError', 'message': str(error)})
        else:
            raise ValueError('consumer envelope fault must reject: ' + label)
    constructor_rejections = []
    for label, change in [('wrong-actual-constructor-declaration', {'implementation_source': source + b'\n'}),
                          ('wrong-frozen-current-source', {'current_source': anchor + b'\n'}),
                          ('wrong-v3-constructor-source', {'v3_constructor_source': v3_source + b'\n'}),
                          ('wrong-v3-loader-source', {'v3_loader_source': v3_loader + b'\n'}),
                          ('noncallable-original-reader', {'read_pinned': None})]:
        try:
            candidate.construct(**{**params, **change})
        except ValueError as error:
            constructor_rejections.append({'case': label, 'exception_type': 'ValueError', 'message': str(error)})
        else:
            raise ValueError('consumer constructor identity fault must reject: ' + label)
    need(values[0]['component_qualified'] is True and values[0]['actual_native_calls'] == 2
         and values[0]['retained_unstarted_stage']['original_sender_wait'] == 'UNKNOWN_UNCHANGED',
         'actual historical state is retained as historical data')
    return {'schema': 'hepta.UNADOPTED.complete-current-consumer-differential.v1', 'state': 'PASS',
        'constructor_source': pin(source), 'bound_loader_source': pin(loader_raw),
        'v3_constructor_source': pin(v3_source), 'v3_loader_source': pin(v3_loader),
        'inventory_function': pin(inventory_function), 'frozen_current_source': pin(anchor),
        'consumer_provenance': provenance, 'actual_R10_current_dispatch_package': CURRENT_PACKAGE,
        'actual_R10_plan_data_anchor': CURRENT_PLAN, 'package_is_dispatch_context_not_new_adoption': True,
        'positive_cases': positives, 'negative_cases': negatives,
        'consumer_envelope_rejections': envelope_rejections, 'constructor_rejections': constructor_rejections,
        'real_original_chain_length': len(values), 'inventory_roots': len(json.loads(inv)['roots']),
        'inventory_entries': len(json.loads(inv)['entries']), 'inventory_original': pin(inv),
        'all_current_consumer_results_and_rejections_equal': True, 'all_original_callbacks_equal': True,
        'repeated_full_closure_revalidated': True, 'original_unknown_retained': 'UNKNOWN_UNCHANGED',
        'historical_final04_component_qualified': True, 'historical_final04_actual_native_calls': 2,
        'current_native_case_credit': 0, 'production_adopted': False, 'runtime_admission': False,
        'whole_stage_budget_verified': False, 'complete_production_IO_metering_verified': False,
        'validation_result_cache': False, 'live_observation_cache': False,
        'new_current_prefix_positive_fixture_available': False,
        'retained_r9_adapter_selected': False, 'phone_calls': 0, 'native_requests': 0,
        'immutable_fixture_preload_outside_validations': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', type=Path, required=True, help='v1/v2 topology root')
    parser.add_argument('--v3', type=Path, required=True)
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--legacy-export', type=Path)
    parser.add_argument('--manifest-base64')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    need(bool(args.fixture) != bool(args.manifest_base64), 'one explicit private original source')
    def expired(_signum, _frame):
        raise TimeoutError('offline consumer differential deadline 240 seconds')
    signal.signal(signal.SIGALRM, expired); signal.setitimer(signal.ITIMER_REAL, 240)
    helper_raw = (args.v3 / 'tests/replay_source_parent_fixture.py').read_bytes()
    need(pin(helper_raw) == V3_HARNESS_PIN, 'exact v3 retained fixture reader')
    helper = module(helper_raw, 'exact_v3_fixture_helpers')
    if args.fixture:
        raw = helper.read_local(args.fixture); bundle = json.loads(raw)
        need(bundle['schema'] == 'hepta.private.source-parent-fixture.v1'
             and bundle['readset'] == bundle['readset_after'], 'exact retained collection bookends')
        files = {key: base64.b64decode(value, validate=True) for key, value in bundle['files'].items()}
        if bundle.get('missing_originals'):
            need(args.legacy_export is not None and len(bundle['missing_originals']) == 1,
                 'explicit exact supplemental legacy original')
            extra = json.loads(helper.read_local(args.legacy_export)); need(len(extra['found']) == 1, 'one exact supplement')
            found = extra['found'][0]; data = base64.b64decode(found['raw_base64'], validate=True)
            row = bundle['missing_originals'][0]
            need(pin(data) == {key: row[key] for key in ('bytes', 'sha256')}
                 and found['metadata_before'] == found['metadata_after'], 'exact supplemental bytes/full9')
            files['original/' + row['path'].lstrip('/')] = data
        fixture_identity = {'kind': 'immutable retained bundle plus explicit supplement', 'bundle': pin(raw),
                            'original_bundle_was_partial': not bundle['all_originals_complete']}
    else:
        raw = base64.b64decode(args.manifest_base64, validate=True); manifest = json.loads(raw)
        need(manifest['schema'] == 'hepta.offline.source-parent-mac-readset.v1'
             and len(manifest['files']) == 29, 'exact retained 29-file Mac readset')
        files = {key: helper.read_local(row['path'], {k: row[k] for k in ('bytes', 'sha256')}, row['metadata'])
                 for key, row in manifest['files'].items()}
        fixture_identity = {'kind': 'exact retained same-host file readset', 'manifest': pin(raw)}
    own = Path(__file__).resolve().parent.parent
    source = helper.read_local(own / 'candidate/source_parent_consumer.py')
    loader = helper.read_local(own / 'candidate/bound_loader.py')
    v3_source = helper.read_local(args.v3 / 'candidate/source_parent_reader.py')
    v3_loader = helper.read_local(args.v3 / 'candidate/bound_loader.py')
    inventory_source = helper.read_local(args.base / 'candidate/derived/source_parent_inventory_value.py')
    consumer_module = module(source, 'source_extractor_only')
    inventory_function = consumer_module.function_source(inventory_source, 'inventory_value')
    started = time.perf_counter()
    result = run(files, helper, source, loader, v3_source, v3_loader, inventory_function)
    result['complete_differential_elapsed_seconds'] = time.perf_counter() - started
    before = list(helper.READSET)
    for row in before:
        helper.read_local(row['path'], {k: row[k] for k in ('bytes', 'sha256')}, row['metadata'])
    need(helper.READSET[len(before):] == before, 'all actual original and candidate source bookends')
    result.update(fixture=fixture_identity, readset=before, readset_after=helper.READSET[len(before):],
                  all_original_and_source_bookends_unchanged=True)
    signal.setitimer(signal.ITIMER_REAL, 0)
    raw = encoded(result)
    if args.output:
        with args.output.open('xb') as stream:
            stream.write(raw)
    sys.stdout.buffer.write(raw)


if __name__ == '__main__':
    main()
