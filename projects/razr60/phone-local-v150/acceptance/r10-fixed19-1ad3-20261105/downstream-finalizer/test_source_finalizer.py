#!/usr/bin/env python3
"""Local source/FD checks; synthetic relationships are never physical case evidence.

No product main, network, subprocess, phone API, or signal is invoked. The actual
future seven-original production finalization remains a separate required run.
"""
import argparse
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import time
import types

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(path, name):
    raw = path.read_bytes()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, raw


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=HERE/'source/finalize_component_cancel_fault.py')
    parser.add_argument('--base-root', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    module, source_raw = load(args.source.resolve(), 'source_finalizer_under_review')
    cache = (args.base_root or (HERE.parent/'downstream_review_cache'
        if (HERE.parent/'downstream_review_cache').exists() else module.B)).resolve()
    out = (args.out or HERE/'evidence'/('source-check-'+str(time.time_ns()))).absolute()
    out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    out = out.parent.resolve()/out.name
    out.mkdir(mode=0o700)
    rows = []

    def check(name, fn):
        try:
            detail = fn()
            rows.append({'name': name, 'passed': True, 'detail': detail})
        except BaseException as error:
            rows.append({'name': name, 'passed': False, 'error_type': type(error).__name__, 'error': str(error)})
            raise

    def rejected(fn):
        try:
            fn()
        except (ValueError, FileExistsError) as error:
            return str(error)
        raise AssertionError('expected rejection did not occur')

    try:
        def default_no_reads():
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = module.main(['--plan', str(out/'NONEXISTENT.json'), '--plan-sha256', '0'*64])
            result = json.loads(stdout.getvalue())
            assert code == 0 and result['state'] == 'SOURCE_ONLY_NO_INPUTS_READ'
            assert result['phone_calls'] == 0 and result['physical_case_pass'] is False
            return result
        check('default_does_not_read_even_named_nonexistent_plan', default_no_reads)

        originals = module.Originals()
        base_descriptors = {key: {'path': str(cache/row[0]/'MANIFEST.json'),
            'bytes': row[1], 'sha256': row[2]} for key, row in module.BASES.items()}
        bases = {key: module.load_base(originals, key, row) for key, row in base_descriptors.items()}
        check('all_exact_reviewed_baseline_members_loaded', lambda: {
            'members': {key: len(value[2]) for key, value in bases.items()},
            'manifest_pins': base_descriptors})

        fixture = out/'SYNTHETIC-DEPENDENCY-FIXTURES-NOT-LIVE'
        fixture.mkdir(mode=0o700)
        fc = fixture/'final-consumer'
        (fc/'source').mkdir(mode=0o700, parents=True)
        ac = fixture/'acceptance'
        (ac/'operator').mkdir(mode=0o700, parents=True)
        raw = {'policy': b'not a policy: synthetic relationship fixture\n',
            'materializer': b'# deliberately unqualified materializer fixture\n'}
        actual = {'policy': module.descriptor(fixture/'policy.fixture', raw['policy'])}
        prior = {'bytes': 1, 'sha256': hashlib.sha256(b'prior-fixture').hexdigest()}
        refs = {key: {'path': str(fixture/(key+'.not-read.fixture')), 'bytes': 1,
            'sha256': hashlib.sha256(key.encode()).hexdigest()} for key in
            ('root_scope_decision', 'post_live_comparison', 'pre_live_expectation')}
        adoption = {'schema': 'hepta.runtime-properties-r10.policy-adoption.v1',
            'release_id': 'v150-r10-r1', 'boot_id': module.BOOT, 'actual_export': actual['policy'],
            'pre_policy_boundary': prior, **refs,
            'root_decision': {'schema': 'hepta.root.runtime-properties-policy-adoption-decision.v1',
                'decision': 'ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY',
                'actual_policy_sha256': actual['policy']['sha256'],
                'root_scope_decision_sha256': refs['root_scope_decision']['sha256'],
                'post_live_comparison_sha256': refs['post_live_comparison']['sha256'],
                'pre_live_expectation_sha256': refs['pre_live_expectation']['sha256'],
                'prior_boundary_sha256': prior['sha256'],
                'actual_live_binding_sha256': hashlib.sha256(b'not-live-binding').hexdigest(),
                'permission_atoms': [['allow', 'synthetic-source', 'synthetic-target', 'file', 'fixture-'+str(i)] for i in range(44)],
                'automatic_adoption': False, 'service_start_admitted': False, 'component_qualified': False}}
        raw['adoption'] = encoded(adoption)
        actual['adoption'] = module.descriptor(fixture/'adoption.fixture.json', raw['adoption'])
        runtime = {'revision': 'r10-r1-operator-r8', 'current_policy_sha256': actual['policy']['sha256'],
            'explicit_policy_adoption_sha256': actual['adoption']['sha256'], 'actual_combination_generated': True,
            'files': [{'path': 'synthetic-'+str(i)+'.fixture', 'bytes': 1,
                'sha256': hashlib.sha256(str(i).encode()).hexdigest()} for i in range(32)]}
        raw['runtime_manifest'] = encoded(runtime)
        actual['runtime_manifest'] = module.descriptor(fixture/'runtime.fixture.json', raw['runtime_manifest'])
        raw['consumer'] = ("# SYNTHETIC SOURCE FIXTURE; never execute a case\nPACKAGE_SHA="+repr(actual['runtime_manifest']['sha256'])
            +'\nCURRENT_POLICY_SHA='+repr(actual['policy']['sha256'])
            +'\nCURRENT_POLICY_ADOPTION_SHA='+repr(actual['adoption']['sha256'])+'\n').encode()
        actual['consumer'] = module.descriptor(fc/'source/release_boundaries.py', raw['consumer'])
        raw['readiness'] = ('# SYNTHETIC SOURCE FIXTURE\nBOUNDARY_CONSUMER_SHA256='+repr(actual['consumer']['sha256'])+'\n').encode()
        actual['readiness'] = module.descriptor(fc/'source/collect_r10_readiness.py', raw['readiness'])
        final = {'schema': 'hepta.r10.final-boundary-consumers.v8',
            'component_package_sha256': actual['runtime_manifest']['sha256'],
            'actual_policy_adoption_sha256': actual['adoption']['sha256'],
            'files': [{'path': 'source/release_boundaries.py', **module.pin(raw['consumer'])},
                {'path': 'source/collect_r10_readiness.py', **module.pin(raw['readiness'])}]}
        raw['final_consumer_manifest'] = encoded(final)
        actual['final_consumer_manifest'] = module.descriptor(fc/'MANIFEST.json', raw['final_consumer_manifest'])
        actual['materializer'] = module.descriptor(ac/'operator/materialize_case_r10.py', raw['materializer'])
        schema = 'hepta.r10.final-boundary-consumers.v8'
        plan = {'schema': module.PLAN_SCHEMA, 'base_packages': base_descriptors, 'actual': actual,
            'expected_final_consumer_schema': schema, 'output_root': str(out/'SYNTHETIC-DERIVATION-NOT-ACTUAL')}
        for key, value in raw.items():
            Path(actual[key]['path']).write_bytes(value)
        (fixture/'SCOPE.json').write_bytes(encoded({'synthetic': True, 'physical_case_evidence': False,
            'full_production_prepare_executed': False,
            'materializer_raw_not_available_locally': True,
            'actual_dependencies_and_adoption_not_yet_available': True}))

        def binding_checks():
            module.validate_actual_bindings(actual, raw, schema)
            failures = {}
            bad = dict(raw)
            bad['readiness'] = b"BOUNDARY_CONSUMER_SHA256='wrong'\n"
            failures['readiness_to_consumer'] = rejected(lambda: module.validate_actual_bindings(actual, bad, schema))
            bad = dict(raw)
            bad['consumer'] = raw['consumer'].replace(actual['runtime_manifest']['sha256'].encode(), b'0'*64)
            failures['consumer_to_runtime'] = rejected(lambda: module.validate_actual_bindings(actual, bad, schema))
            bad = dict(raw)
            broken = copy.deepcopy(adoption)
            broken['actual_export'] = {'path': str(fixture/'offline-candidate.fixture'), 'bytes': 1, 'sha256': '0'*64}
            bad['adoption'] = encoded(broken)
            failures['actual_export_not_offline_candidate'] = rejected(lambda: module.validate_actual_bindings(actual, bad, schema))
            broken = copy.deepcopy(adoption)
            broken['root_decision']['service_start_admitted'] = True
            bad['adoption'] = encoded(broken)
            failures['source_finalization_does_not_admit_service'] = rejected(lambda: module.validate_actual_bindings(actual, bad, schema))
            bad = dict(raw)
            broken = copy.deepcopy(final)
            broken['files'][0]['bytes'] += 1
            bad['final_consumer_manifest'] = encoded(broken)
            failures['final_consumer_member'] = rejected(lambda: module.validate_actual_bindings(actual, bad, schema))
            need_read = module.Originals()
            failures['unreviewed_materializer_blocked_by_full_validator'] = rejected(lambda: module.validate_actual(need_read, plan))
            assert 'materializer logic' in failures['unreviewed_materializer_blocked_by_full_validator']
            return {'synthetic_relationship_positive': True, 'mismatches_rejected': failures,
                'full_actual_adoption_verification_claimed': False}
        check('synthetic_crosslinks_and_real_materializer_rejection_gate', binding_checks)

        def delivery_descriptor_resolution():
            ac_raw = encoded({'files': [{'path': 'operator/materialize_case_r10.py', **module.pin(raw['materializer'])}]})
            (ac/'MANIFEST.json').write_bytes(ac_raw)
            delivery = {'schema': 'hepta.property-policy.final-boundary-cascade-delivery.v1',
                'state': 'HOST_ONLY_PUBLISHED', 'phone_calls': 0, 'nonce_generated': False,
                'final_release_generated': False, 'new_component_qualification': False,
                'module_replacement_reapplied': False,
                'reviewed_finalization': {'schema': 'hepta.property-policy.final-pin-freeze.v1',
                    'runtime_manifest': actual['runtime_manifest'], 'policy_adoption': actual['adoption'],
                    'actual_policy': module.pin(raw['policy'])},
                'consumer': actual['final_consumer_manifest'],
                'acceptance': module.descriptor(ac/'MANIFEST.json', ac_raw),
                'runtime_sources': {'release_boundaries.py': module.pin(raw['consumer']),
                    'collect_r10_readiness.py': module.pin(raw['readiness'])},
                'materializer': module.pin(raw['materializer'])}
            path = fixture/'DELIVERY.synthetic.json'
            body = encoded(delivery)
            path.write_bytes(body)
            result = module.plan_from_delivery(module.Originals(), module.descriptor(path, body), plan['output_root'])
            assert result['actual'] == actual
            assert result['expected_final_consumer_schema'] == schema
            broken = copy.deepcopy(delivery)
            broken['reviewed_finalization']['actual_policy']['sha256'] = '0'*64
            body = encoded(broken)
            path = fixture/'DELIVERY-mismatched.synthetic.json'
            path.write_bytes(body)
            reason = rejected(lambda: module.plan_from_delivery(module.Originals(), module.descriptor(path, body), plan['output_root']))
            return {'seven_descriptors_resolved_without_future_pin_invention': True,
                'mismatched_delivery_to_adoption_rejected': reason,
                'synthetic_only_full_prepare_still_rejects_materializer': True}
        check('actual_delivery_shape_resolves_exact_source_paths_and_pins', delivery_descriptor_resolution)

        root, outputs, packages, derivation = module.derive_sources(originals, plan, encoded(plan), bases)
        def unchanged_sources():
            counts = {}
            for key, (_, _, files) in bases.items():
                allowed = {'source/component_source_context.py', 'INTERFACE.json'} if key == 'component' else {'source/active_runtime_r10.py'}
                same = [name for name, value in files.items() if outputs[key+'/'+name] == value]
                assert set(files)-set(same) == allowed
                counts[key] = {'preserved': len(same), 'changed': sorted(allowed)}
            assert outputs['cancel/source/active_runtime_r10.py'] == outputs['fault/source/active_runtime_r10.py']
            active = outputs['cancel/source/active_runtime_r10.py']
            assert module.literal(active, 'PARENT_POLICY_SHA') == module.literal(bases['cancel'][2]['source/active_runtime_r10.py'], 'PARENT_POLICY_SHA')
            assert derivation['physical_case_pass'] is False and derivation['case_runs'] == 0
            interface = json.loads(outputs['component/INTERFACE.json'])
            assert interface['comp01']['cli'][3] == str(root/'component/source/prepare_direct_return_component.py')
            assert interface['neg03']['cli'][3] == str(root/'component/source/verify_unqualified_geometry_fixture.py')
            assert all(value is None for value in interface['future_inputs'].values())
            return counts
        check('only_allowlisted_context_interface_active_bytes_change', unchanged_sources)

        def real_package_inventory_and_create_only():
            writer = module.CreateOnlyTree(root)
            try:
                for name in sorted(outputs, key=lambda value: (value.endswith('/MANIFEST.json'), value)):
                    writer.put(name, outputs[name])
                writer.check()
                # This actual existing component verifier reads source-package originals only.
                context = types.ModuleType('derived_component_package_verifier')
                context.__file__ = str(root/'component/source/component_source_context.py')
                exec(compile(outputs['component/source/component_source_context.py'], context.__file__, 'exec'), context.__dict__)
                verified = context.verify_source_package(context.Originals(), root/'component', packages['component']['sha256'])
                assert len(verified['files']) == 9
                reason = rejected(lambda: module.CreateOnlyTree(root))
                writer.check()
                return {'existing_component_verifier_accepts_exact_nine_files': True,
                    'wrapper_metadata_stays_outside_component': True, 'reuse_rejected': reason,
                    'source_only_no_case_execution': True}
            finally:
                writer.close()
        check('actual_existing_component_verifier_and_create_only_output', real_package_inventory_and_create_only)

        def output_replacement():
            path = out/'OUTPUT-REPLACEMENT-FIXTURE'
            writer = module.CreateOnlyTree(path)
            try:
                writer.put('source.py', b'# same bytes do not imply same inode\n')
                (path/'source.py').rename(path/'created-inode-retained.original')
                (path/'source.py').write_bytes(b'# same bytes do not imply same inode\n')
                return {'same_byte_replacement_rejected': rejected(lambda: writer.filecheck('source.py'))}
            finally:
                writer.close()
        check('held_output_inode_replacement_rejected', output_replacement)

        def original_replacement():
            path = out/'INPUT-REPLACEMENT.fixture'
            body = b'original fixture\n'
            path.write_bytes(body)
            reader = module.Originals()
            row = module.descriptor(path, body)
            assert reader.read(row, 1024) == body
            path.rename(out/'INPUT-created-inode-retained.original')
            path.write_bytes(body)
            return {'same_byte_original_replacement_rejected': rejected(reader.recheck)}
        check('original_identity_rechecked_before_publication', original_replacement)
    finally:
        report = {'schema': 'hepta.r8.downstream-source-check.v1',
            'source': {'path': str(args.source.resolve()), 'bytes': len(source_raw),
                'sha256': hashlib.sha256(source_raw).hexdigest()},
            'cases': rows, 'passed': all(row['passed'] for row in rows),
            'synthetic_relationship_fixtures_not_physical_evidence': True,
            'full_actual_production_finalization_run': False,
            'phone_calls': 0, 'signals': 0, 'model_requests': 0, 'case_runs': 0,
            'physical_case_pass': False}
        (out/'TEST-RESULT.json').write_bytes(encoded(report))
        print(json.dumps({'passed': report['passed'], 'checks': len(rows),
            'report': str(out/'TEST-RESULT.json'), 'full_actual_production_finalization_run': False}))


if __name__ == '__main__':
    main()
