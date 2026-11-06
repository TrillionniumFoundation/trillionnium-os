#!/usr/bin/env python3
"""Necessary source-interface checks only; no fabricated freeze/BUILD/READY.

The only positive execution is an isolated local source-file publication. No R6
derivation succeeds in this check because its actual freeze slot remains None.
"""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import types

ROOT = Path(__file__).resolve().parent
REVIEW = ROOT.parent


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def load(p, name):
    raw = p.read_bytes(); value = types.ModuleType(name); value.__file__ = str(p)
    exec(compile(raw, str(p), 'exec'), value.__dict__)
    return value, raw


def main():
    M, source = load(ROOT / 'source/derive_r6_source_rebindings_UNBOUND.py', 'r6_source_interface_control')
    Q, binder = load(ROOT / 'source/bind_r6_source_input.py', 'r6_binding_interface_control')
    R, rraw = load(REVIEW / 'install-source-chain43/source/derive_reviewed_release_sources_UNBOUND.py', 'r6_parent_constructor_control')
    hraw = (REVIEW / 'install-build-controller/derive_component_build_inputs_UNBOUND.py').read_bytes()
    assert pin(rraw) == {k: M.CONSTRUCTOR[k] for k in ('bytes', 'sha256')}
    assert pin(hraw) == {k: M.HELPER[k] for k in ('bytes', 'sha256')}
    checks, callbacks = [], []
    def passed(name):
        checks.append(dict(name=name, passed=True))
    def forbidden(row):
        callbacks.append(row)
        raise AssertionError('no original callback allowed in an unbound control')
    def rejected(call, reason):
        try:
            call()
        except ValueError as error:
            assert reason in str(error), (reason, str(error))
        else:
            raise AssertionError('unbound source accepted')
    assert M.FROZEN_INPUTS is None
    rejected(lambda: M.derive_rebindings(b'not json', read_pinned=forbidden), 'UNBOUND_R6_SOURCE_REBINDING_NO_IO')
    assert not callbacks
    passed('unbound_public_entry_refuses_before_parse_or_callback')
    rejected(M.main, 'UNBOUND_R6_SOURCE_REBINDING_NO_IO')
    assert not callbacks
    passed('unbound_cli_refuses_before_argument_parse_or_host_IO')
    templates = sorted((ROOT / 'templates').glob('*.UNBOUND.json'))
    assert len(templates) == 4
    for template in templates:
        raw = template.read_bytes()
        row = dict(path=M.PACKAGE + '/templates/' + template.name, **pin(raw))
        M.FROZEN_INPUTS = row
        try:
            rejected(lambda: M.derive_rebindings(raw, read_pinned=forbidden), 'UNBOUND_R6_ACTUAL_SOURCE_INPUT_NO_IO')
        finally:
            M.FROZEN_INPUTS = None
        assert not callbacks
        passed(template.stem + '_refuses_unknown_actual_slot_before_original_callback')
    row = dict(M.CONSTRUCTOR, bytes=True)
    rejected(lambda: M.descriptor(row), 'typed bounded actual host original')
    passed('boolean_source_length_refused')
    row = dict(M.CONSTRUCTOR, bytes=float(M.CONSTRUCTOR['bytes']))
    rejected(lambda: M.descriptor(row), 'typed bounded actual host original')
    passed('float_source_length_refused')
    ctx = object.__new__(M.Context)
    ctx.R, ctx.r_raw, ctx.h_raw = R, rraw, hraw
    ctx.out = M.output_root(M.B + '/source-interface-control-only')
    d = dict(M.SOURCE_INPUT_PARENT)
    one, proof = ctx.change(rraw, {'FROZEN_INPUTS': d})
    two, proof2 = ctx.change(rraw, {'FROZEN_INPUTS': {'sha256': d['sha256'], 'bytes': d['bytes'], 'path': d['path']}})
    assert one == two and proof == proof2 and proof['complete_inverse'] is True
    reverse = R.Changes(one); reverse.rhs('FROZEN_INPUTS', None); restored, unused = reverse.finish()
    assert restored == rraw
    passed('actual_parent_input_descriptor_order_has_one_exact_byte_inverse')
    with tempfile.TemporaryDirectory(prefix='r6-source-writer-') as scratch:
        out = Path(scratch) / 'nested-source'
        files = {'source/nested/probe.txt': b'host source control\n',
                 'BINDING.json': b'{"purpose":"source writer control"}\n'}
        writer, proof = ctx.writer(files, 'BINDING.json')
        writer(out, files)
        assert {str(p.relative_to(out)): p.read_bytes() for p in out.rglob('*') if p.is_file()} == files
        assert proof['full_source_inverse']['complete_inverse'] is True
        passed('derived_closed_layout_writer_publishes_complete_nested_bytes_and_terminal')
        try:
            writer(out, files)
        except FileExistsError:
            pass
        else:
            raise AssertionError('create-only writer accepted existing output')
        assert {str(p.relative_to(out)): p.read_bytes() for p in out.rglob('*') if p.is_file()} == files
        passed('same_source_output_cannot_be_republished_or_overwritten')
    first = templates[0].read_bytes()
    row = dict(path=M.PACKAGE + '/templates/' + templates[0].name, **pin(first))
    rejected(lambda: Q.prepare(M, source, first, row, M.B + '/source-binding-control-only',
                              'host-source-control-only', 120, read_pinned=forbidden),
             'UNBOUND_R6_ACTUAL_SOURCE_INPUT_NO_IO')
    assert not callbacks
    passed('input_literal_binder_refuses_incomplete_actual_template_without_source_reads_or_publication')
    assert Q.SOURCE['bytes'] == len(source) and Q.SOURCE['sha256'] == pin(source)['sha256']
    assert M.FROZEN_INPUTS is None
    passed('binder_pins_exact_current_unbound_source')
    candidate = REVIEW / 'R6-root-final01/runtime/MANIFEST.json'
    candidate_raw = candidate.read_bytes(); value = json.loads(candidate_raw)
    late = (REVIEW / 'R6-root-final01/runtime/source/late_boundary.py').read_bytes()
    assert pin(late) == M.LATE_PIN
    records = R.literal(late, 'SOURCE_PARENT_RECORDS')
    chain = R.literal(late, 'HISTORICAL_FAILED_BOUNDARY_COUNT') + len(records) + R.literal(late, 'MAX_NEW_CURRENT_CASE_PREFIX')
    assert len(value['files']) == value['runtime_file_count'] == 38
    assert value['native_chain_cap'] == chain == 12 and value['component_role_cap'] == 3 * (chain + 2) == 42
    assert M.same(value['source_parent_records'], list(records))
    passed('actual_local_R6_candidate_record_counts_match_preserved_LATE_without_freeze_credit')
    carrier_path = REVIEW / 'R6-runtime-freeze01/ROOT-ACTUAL-FREEZE-CONTROLLER.original.json'
    carrier_raw = carrier_path.read_bytes(); carrier = json.loads(carrier_raw)
    C, unused = load(REVIEW / 'install-build-controller/verify_host_controller_originals.py', 'r6_actual_freeze_controller_control')
    job, status, streams = C.controller(carrier, code=0, complete=True)
    assert streams['stderr'] == b'' and len(streams['stdout']) == 1329
    actual_summary = json.loads(streams['stdout'])
    authority = dict(source=dict(path=carrier['request']['args'][0],
        bytes=24094, sha256='cbb8997c66172054afbd57acb349257d1a8804eff024dbbcb6deb0b438ebcdf3'))
    function = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'freeze_context')
    assignment = next(n for n in function.body if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == 'argv' for t in n.targets))
    namespace = dict(authority=authority)
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), '<exact-original-freezer-argv-expression>', 'exec'), namespace)
    assert namespace['argv'] == carrier['request']['args'] == job['args']
    assert job['idempotency_key'] == carrier['request']['idempotency_key'] == 'fc33-native-bound-runtime-r6-freeze-once01'
    assert actual_summary['runtime_manifest']['sha256'] == pin(candidate_raw)['sha256']
    passed('exact_R6_argv_expression_matches_real_complete_controller_without_inventing_I_or_B_flags')
    result = dict(schema='hepta.fc33.r6.source-rebinding-necessary-interface-controls.v1',
        state='SOURCE_INTERFACES_CHECKED_ACTUAL_R6_DERIVATION_UNBOUND', passed=True,
        source=pin(source), binder=pin(binder), checks=checks, control_count=len(checks),
        actual_local_runtime_candidate=dict(path=str(candidate), **pin(candidate_raw)),
        actual_freeze=None, actual_freeze_controller=dict(path=str(carrier_path), **pin(carrier_raw)), actual_BUILD=None, actual_READY=None,
        actual_R6_derivation_success=False, source_original_callbacks_in_unbound_controls=len(callbacks),
        actual_isolated_source_writer_executions=1, phone_calls=0, actor_dispatches=0,
        new_nonces=0, model_requests=0, fixed19_credit=0)
    raw = (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    with (ROOT / 'SOURCE-CONTROL-RESULT02.json').open('xb') as stream:
        stream.write(raw)
    print(json.dumps(dict(control_count=len(checks), result=pin(raw), phone_calls=0,
                         actual_R6_derivation_success=False), sort_keys=True))


if __name__ == '__main__':
    main()
