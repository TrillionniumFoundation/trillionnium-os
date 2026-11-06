#!/usr/bin/env python3
"""Exact-source host controls; no actual source adoption or physical execution.

Exercise the new closed dictionary allowance, R5 whole-root inverse, and the
constructor's zero-I/O unbound fence.  Actual BUILD/READY/roles are never faked.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import threading
import types

ROOT = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def module(path, name):
    m = types.ModuleType(name)
    m.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), m.__dict__)
    return m


def function_bytes(raw):
    lines = raw.splitlines(keepends=True)
    return {n.name: b''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(raw).body
            if isinstance(n, (ast.FunctionDef, ast.ClassDef))}


def resources():
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'fd_count': len(os.listdir('/proc/self/fd')), 'thread_ids': sorted(t.ident for t in threading.enumerate()),
            'child_cpu': [child.ru_utime, child.ru_stime]}


def main():
    assert len(sys.argv) == 2
    out = Path(sys.argv[1])
    assert out.is_absolute() and out.parent.resolve(strict=True) == out.parent
    os.umask(0o077)
    out.mkdir(mode=0o700)
    sys.dont_write_bytecode = True
    def audit(event, args):
        if event.startswith(('socket.', 'subprocess.')) or event in {
                'os.fork', 'os.system', 'os.posix_spawn', 'os.exec', 'os.kill', 'os.killpg'}:
            raise AssertionError('excluded external effect: ' + event)
    sys.addaudithook(audit)
    before = resources()
    constructor = module(ROOT / 'derive_negative_sources_UNBOUND.py', 'negative_source_constructor')
    builder = module(ROOT / 'build_physical_source_templates.py', 'negative_source_templates')
    rows = []
    def passed(name, **detail):
        rows.append({'name': name, 'passed': True, **detail})
    def rejected(name, fn, expected):
        try:
            fn()
        except ValueError as error:
            assert expected in str(error), str(error)
            passed(name, error_type=type(error).__name__, detail=str(error))
        else:
            raise AssertionError(name + ' unexpectedly accepted')
    called = []
    rejected('unbound_public_constructor_refuses_before_parse_or_IO',
             lambda: constructor.derive_negative_sources(b'not JSON', read_pinned=lambda row: called.append(row)),
             'UNBOUND_NEGATIVE_SOURCE_INPUTS_NO_IO')
    assert called == [] and constructor.FROZEN_INPUTS is None
    result, source_pins = builder.build()
    for name, (path, raw, proof) in result.items():
        assert raw == (ROOT / 'candidate/templates' / name).read_bytes() and proof['complete_inverse'] is True
    passed('three_source_templates_reconstructed_with_complete_inverse', source_graph=source_pins)
    physical_old_path = ROOT / 'reference/component-physical-final02/package/source/physical_component_common.py'
    physical_old = module(physical_old_path, 'old_physical_common')
    physical_new = module(ROOT / 'candidate/templates/physical-component/physical_component_common.py', 'new_physical_common')
    context_path = ROOT / 'reference/cpu-negative-capture-generation-final01/package/validation/parent-source-fixtures/component/source/component_source_context.py'
    context_old = context_path.read_bytes()
    source_root = ROOT.parent / 'source-audit-v3/candidate/source'
    expected_names = constructor.literal(context_old, 'SOURCE_PINS')
    source_pins = {name: (len((source_root / name).read_bytes()), sha((source_root / name).read_bytes())) for name in expected_names}
    changes = constructor.Changes(context_old)
    changes.rhs('SOURCE_PINS', source_pins)
    context_new = changes.finish()[0]
    allowed = {'MATERIALIZER', 'CONSUMER', 'CONSUMER_PIN', 'READINESS_PIN', 'RUNTIME_SHA',
               'POLICY_SHA', 'ADOPTION_SHA', 'SOURCE_PINS'}
    rejected('original_context_dictionary_incompatibility_reproduced',
             lambda: physical_old.verify_literal_increment(context_new, context_old, allowed, {'MATERIALIZER', 'CONSUMER'}),
             'frozen dependency must remain a literal')
    physical_new.verify_literal_increment(context_new, context_old, allowed, {'MATERIALIZER', 'CONSUMER'})
    passed('exact_four_real_source_pin_dictionary_accepted_by_new_source_gate')
    bad_values = [dict(source_pins, unexpected=(1, '0' * 64)),
                  dict(source_pins, **{'phone_observation_tools.py': (True, source_pins['phone_observation_tools.py'][1])}),
                  dict(source_pins, **{'phone_observation_tools.py': (55981, 'short')})]
    for label, value in zip(('unexpected_source_name', 'boolean_byte_count', 'short_digest'), bad_values):
        change = constructor.Changes(context_old)
        change.rhs('SOURCE_PINS', value)
        bad = change.finish()[0]
        rejected('closed_dictionary_' + label, lambda bad=bad: physical_new.verify_literal_increment(
            bad, context_old, allowed, {'MATERIALIZER', 'CONSUMER'}), 'exact four geometry source byte pins')
    altered = context_new.replace(b"need(len(source)==15", b"need(len(source)<=15", 1)
    assert altered != context_new
    rejected('extra_executable_change_rejected_by_whole_AST_inverse',
             lambda: physical_new.verify_literal_increment(altered, context_old, allowed, {'MATERIALIZER', 'CONSUMER'}),
             'dependency increment changed other reviewed executable logic')
    active_old = (ROOT / 'reference/physical-fault-final01/package/validation/operator-source-fixture/source/active_runtime_r10.py').read_bytes()
    changes = constructor.Changes(active_old)
    changes.rhs('CONFIG_SHA', builder.CONFIG_SHA)
    changes.rhs('SERVICE_SHA', builder.SERVICE_SHA)
    active_new = changes.finish()[0]
    physical_new.verify_literal_increment(active_new, active_old,
        {'CONSUMER_SHA', 'READINESS_SHA', 'POLICY_SHA', 'ADOPTION_SHA', 'CONFIG_SHA', 'SERVICE_SHA'})
    assert function_bytes(active_old) == function_bytes(active_new)
    passed('shared_active_six_literal_gate_preserves_all_actual_runtime_and_role_functions')
    negative_old_path = ROOT / 'reference/cpu-cancel-compat-candidate01/package/source/negative_originals.py'
    negative_old = module(negative_old_path, 'original_negative_assembly')
    negative_new = module(ROOT / 'candidate/templates/closure/negative_originals.py', 'new_negative_assembly')
    coordinator = (ROOT.parent / 'R5-root/root-chain/source/run_component_root_once.py').read_bytes()
    q2 = (ROOT / 'reference/cpu-cancel-compat-candidate01/package/reference/root-Q2-53b5.original.py').read_bytes()
    rejected('old_whole_root_template_refuses_reviewed_R5_source',
             lambda: negative_old.root_source(coordinator, q2), 'actual_R8_root_not_exact_reviewed_capture_template')
    assert negative_new.root_source(coordinator, q2) == coordinator
    assert function_bytes(negative_old_path.read_bytes()) == function_bytes(
        (ROOT / 'candidate/templates/closure/negative_originals.py').read_bytes())
    passed('new_exact_R5_whole_root_template_and_unchanged_Q2_transport_functions_pass')
    altered = coordinator + b'\n# unreviewed body change\n'
    rejected('root_body_outside_seven_slots_refused', lambda: negative_new.root_source(altered, q2),
             'actual_R8_root_not_exact_reviewed_capture_template')
    physical_fault_old = (ROOT / 'reference/physical-fault-final01/package/source/physical_fault_common.py').read_bytes()
    physical_fault_new = (ROOT / 'candidate/templates/physical-fault/physical_fault_common.py').read_bytes()
    old_functions, new_functions = function_bytes(physical_fault_old), function_bytes(physical_fault_new)
    assert set(old_functions) == set(new_functions)
    assert {name for name in old_functions if old_functions[name] != new_functions[name]} == {'generation_inputs', 'admit'}
    fault_module = module(ROOT / 'candidate/templates/physical-fault/physical_fault_common.py', 'fault_unbound_template')
    assert fault_module.FINAL_DEPENDENCIES is None
    rejected('physical_fault_unbound_gate_still_refuses_before_action', fault_module.final_dependencies,
             'future_actual_fault_dependencies_are_unfrozen')
    passed('all_fault_request_transport_and_scope_helpers_remain_byte_identical')
    index_raw = (ROOT / 'REVIEWED-INPUTS.json').read_bytes()
    constructor.exact_pin(index_raw, constructor.REFERENCE_INDEX)
    inventory = json.loads(index_raw)['files']
    for row in inventory:
        assert pin((ROOT / row['path']).read_bytes()) == {k: row[k] for k in ('bytes', 'sha256')}
    assert resources() == before
    passed('all_171_reference_originals_and_process_resources_unchanged', originals=len(inventory),
           before=before, after=resources())
    report = {'schema': 'fc33.negative-source-template-controls.v1', 'status': 'PASS',
              'control_count': len(rows), 'controls': rows, 'all_reference_originals_verified': len(inventory),
              'actual_source_chain_admission_executed': False, 'public_constructor_still_unbound': True,
              'actual_BUILD': None, 'actual_READY': None, 'actual_native_scope': None,
              'phone_calls': 0, 'model_calls': 0, 'signals_sent': 0, 'physical_case_pass': False,
              'full_constructor_positive_requires_real_source_chain_publication': True}
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    with (out / 'RESULT.json').open('xb') as handle:
        handle.write(raw)
    print(json.dumps({'status': 'PASS', 'controls': len(rows), 'result': pin(raw),
                      'full_constructor_positive_executed': False, 'phone_calls': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
