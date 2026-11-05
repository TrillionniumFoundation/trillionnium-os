#!/usr/bin/env python3
"""Create local source-only final02 from exact retained originals; no remote calls."""
import ast
import copy
import difflib
import hashlib
import json
from pathlib import Path
import sys
import types

sys.dont_write_bytecode = True
W = Path('/workspace/scratch/1ad3d6f55439')
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
STAGE = B/'native-guard-property-r8-freeze-preparation-final02-1ad3'
OUT = W/'r8_freeze_preparation_candidate01/delivery-final02/package'
F_PATH = W/'transport_fix/native-guard-property-r8-freeze-transport-candidate02-1ad3/source/freeze_property_runtime.py'
H_PATH = W/'r8_freeze_preparation_candidate01/delivery-final01/package/source/prepare_actual_r8_freeze.py'
N_PATH = W/'neg_root_plan_helper_r8/source/prepare_native_guard_root_plan.py'
P_PATH = W/'r8_freeze_preparation_candidate01/actual_parent/COMBINATION.original.json'
A_PATH = W/'independent_post_execution/POLICY-ADOPTION.original.json'
F_SHA = '62bcfb5a3ece55526d6e3e5c4c5158426d0e0119b5a04d4754cc7903434ea509'
H_SHA = '106f2ac9f40d32693dd992cbe27454f739674377700e21cfd284a335aa01194f'
N_SHA = '68df2c8e1dca7ee652d3fb960a262b59fbf20cbabb7c3e94b89b02884f82c78d'
P_SHA = 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
A_SHA = '527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False)+'\n').encode()


def pinned(path, size, digest):
    raw = path.read_bytes()
    assert len(raw) == size and sha(raw) == digest, str(path)
    return raw


def row(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def replace_exact(raw, old, new):
    assert old != new and raw.count(old) == 1
    updated = raw.replace(old, new, 1)
    assert updated.count(new) == 1 and updated.replace(new, old, 1) == raw
    return updated


def derive(raw, replacements):
    updated = raw
    for old, new in replacements:
        updated = replace_exact(updated, old, new)
    reverse = updated
    for old, new in reversed(replacements):
        reverse = replace_exact(reverse, new, old)
    assert reverse == raw
    compile(updated, '<source-only-derived>', 'exec')
    return updated


def module(raw, path, name):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    value.__reviewed_source_sha256__ = sha(raw)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def patch(before, after, old_name, new_name):
    return ''.join(difflib.unified_diff(before.decode().splitlines(True),
        after.decode().splitlines(True), fromfile=old_name, tofile=new_name)).encode()


def reject(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError('expected ValueError')


def main():
    assert not OUT.exists(), 'create-only package'
    original_f = pinned(F_PATH, 35375, F_SHA)
    original_h = pinned(H_PATH, 18226, H_SHA)
    original_n = pinned(N_PATH, 24237, N_SHA)
    parent_raw = pinned(P_PATH, 4702, P_SHA)
    adoption_raw = pinned(A_PATH, 208226, A_SHA)
    old_enc = b"def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\\n').encode()\n"
    extra_enc = (old_enc + b"\ndef combination_enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\\n').encode()\n")
    f_replacements = [
        (old_enc, extra_enc),
        (b'enc(parent_combo)==parent_combo_raw', b'combination_enc(parent_combo)==parent_combo_raw'),
        (b'combo_raw=enc(combo)', b'combo_raw=combination_enc(combo)'),
        (b'enc(reversed_combo)==parent_combo_raw', b'combination_enc(reversed_combo)==parent_combo_raw'),
    ]
    frozen_f = derive(original_f, f_replacements)
    f_descriptor = row(STAGE/'source/freeze_property_runtime.py', frozen_f)
    h_replacements = [
        (b"B/'native-guard-property-r8-freeze-transport-candidate02-1ad3/source/freeze_property_runtime.py'",
            ("B/'"+STAGE.name+"/source/freeze_property_runtime.py'").encode()),
        (("'bytes':35375,'sha256':'"+F_SHA+"'").encode(),
            ("'bytes':"+str(len(frozen_f))+",'sha256':'"+sha(frozen_f)+"'").encode()),
        (b'F.enc(parent)==parent_raw', b'F.combination_enc(parent)==parent_raw'),
        (b'combo_raw=F.enc(combination)', b'combo_raw=F.combination_enc(combination)'),
        (b"F.enc(reverse)==parent_raw,'only current live-policy field may change in combination'",
            b"F.combination_enc(reverse)==parent_raw,'only current live-policy field may change in combination'"),
        (b'exact reviewed62bc source required', b'exact reviewed compact source required'),
        (b'exact62bc source required for one-RHS binding', b'exact reviewed compact source required for one-RHS binding'),
        (b'whole-source inverse must be exact62bc', b'whole-source inverse must be exact reviewed compact source'),
        (b'reference/freeze_property_runtime.62bc.original.py', b'reference/freeze_property_runtime.compact.original.py'),
        (b'reviewed62bc/freeze_property_runtime.py', b'reviewed-compact/freeze_property_runtime.py'),
    ]
    frozen_h = derive(original_h, h_replacements)
    n_replacements = [(F_SHA.encode(), sha(frozen_f).encode())]
    frozen_n = derive(original_n, n_replacements)

    F = module(frozen_f, f_descriptor['path'], 'compact_combination_source_check')
    H = module(frozen_h, STAGE/'source/prepare_actual_r8_freeze.py', 'compact_preparer_source_check')
    N = module(frozen_n, STAGE/'neg-root-plan/source/prepare_native_guard_root_plan.py', 'compact_neg_source_check')
    original_F = module(original_f, F_PATH, 'original_62bc_source_check')
    parent = F.strict(parent_raw)
    adoption = H.strict(adoption_raw)
    assert H.FREEZER == f_descriptor and H.freezer_source(frozen_f).FINALIZATION is None
    assert F.combination_enc(parent) == parent_raw
    assert F.enc(parent) == original_F.enc(parent) and F.enc(parent) != parent_raw
    combo = copy.deepcopy(parent)
    combo['live_policy_sha256'] = adoption['actual_export']['sha256']
    combo_raw = F.combination_enc(combo)
    reverse_combo = copy.deepcopy(combo)
    reverse_combo['live_policy_sha256'] = F.PARENT_POLICY
    assert F.combination_enc(reverse_combo) == parent_raw
    assert [k for k in combo if combo[k] != parent[k]] == ['live_policy_sha256']
    assert len(combo_raw) == len(parent_raw) and sha(combo_raw) != P_SHA
    assert F.PARENT_COMBINATION == P_SHA and F.PARENT_POLICY == parent['live_policy_sha256']
    template_raw = pinned(W/'r8_freeze_preparation_candidate01/delivery-final01/package/reference/FREEZE-INPUTS.template.original.json',
        8368, 'debd3165e14bf357f13bfa3b997ea3bb0b23e5d2bb4a0a8b54078477deff2934')
    assert F.enc(F.strict(template_raw)) == template_raw
    assert F.FIXED == original_F.FIXED
    assert N.FREEZER_TEMPLATE_SHA == sha(frozen_f)
    actual_f = {'schema':'hepta.native-guard.property-policy-finalization.v1',
        'scope_decision':adoption['root_scope_decision'],
        'policy_adoption':row(A_PATH,adoption_raw),
        'verifier_source':dict(H.VERIFIER), 'actual_export':adoption['actual_export'],
        'combination_sha256':sha(combo_raw)}
    # This exercises only the literal-binding API with the actual local copy.
    # It is not the final canonical Mac binding and no bound source is saved.
    bound = H.bind_source(F, frozen_f, actual_f)
    assert F.fill(bound, 'FINALIZATION', actual_f, None) == frozen_f
    assert sha(N.set_literal(bound, 'FINALIZATION', actual_f, None)) == N.FREEZER_TEMPLATE_SHA
    assert sha(N.set_literal(F.fill(original_f, 'FINALIZATION', None, actual_f),
        'FINALIZATION', actual_f, None)) != N.FREEZER_TEMPLATE_SHA
    reject(lambda:H.freezer_source(original_f))
    reject(lambda:F.strict(b'{"key":1,"key":2}'))

    # Compare normalized ASTs independently of the exact text inverses above.
    old_tree, new_tree = ast.parse(original_f), ast.parse(frozen_f)
    new_tree.body = [n for n in new_tree.body if not (isinstance(n,ast.FunctionDef) and n.name=='combination_enc')]
    changed_calls = 0
    for node in ast.walk(new_tree):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='combination_enc':
            node.func.id='enc'; changed_calls += 1
    assert changed_calls == 3 and ast.dump(new_tree,include_attributes=False)==ast.dump(old_tree,include_attributes=False)
    old_tree, new_tree = ast.parse(original_h), ast.parse(frozen_h)
    calls = [n for n in ast.walk(new_tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
        and isinstance(n.func.value,ast.Name) and n.func.value.id=='F' and n.func.attr=='combination_enc']
    assert len(calls)==3
    generic_calls_before = [ast.dump(n,include_attributes=False) for n in ast.walk(old_tree)
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='enc']
    generic_calls_after = [ast.dump(n,include_attributes=False) for n in ast.walk(new_tree)
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='enc']
    assert len(generic_calls_before)-len(generic_calls_after)==3
    assert all(item in generic_calls_before for item in generic_calls_after)
    # Native NEG01/02 helper admits exactly the new reviewed template; no OR,
    # new source variant or relaxed finalization/role/history gate is added.
    old_tree,new_tree=ast.parse(original_n),ast.parse(frozen_n)
    for tree in (old_tree,new_tree):
        [n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name)
            and t.id=='FREEZER_TEMPLATE_SHA' for t in n.targets)][0].value=ast.Constant(value='EXACT_REVIEWED_TEMPLATE')
    assert ast.dump(old_tree,include_attributes=False)==ast.dump(new_tree,include_attributes=False)

    checks = [
        'actual_parent_4702_ba5c_is_exact_compact_sorted_utf8_lf',
        'original_pretty_encoder_reproduces_actual_rejection',
        'new_combination_encoder_reproduces_parent_bytes_exactly',
        'actual_adopted_export_changes_only_live_policy_sha256_and_byte_inverse_restores_parent',
        'pretty_input_template_and_generic_encoder_are_unchanged',
        'freezer_whole_source_inverse_to_62bc_and_only_three_combination_calls_plus_encoder',
        'preparer_whole_source_inverse_to_106f_with_explicit_pin_three_calls_and_provenance_labels',
        'freezer_all_fixed_pins_and_caps_history_gates_preserved',
        'preparer_exact_new_freezer_pin_accepts_new_and_rejects_old',
        'finalization_one_rhs_full_source_inverse_to_new_freezer',
        'neg_root_helper_single_pin_inverse_to_68df_and_exact_new_bound_freezer_identity',
        'old_bound_freezer_identity_not_admitted_by_new_neg_helper_pin',
        'duplicate_json_rejection_unchanged',
        'all_three_sources_compile_without_main_or_build_calls',
    ]
    report={'schema':'hepta.native-guard.r8-combination-encoding-local-checks.v1',
        'state':'SOURCE_COMPATIBILITY_CHECKS_PASSED_NO_RUNTIME_FREEZE',
        'checks':[{'name':name,'passed':True} for name in checks],
        'original_freezer':row(F_PATH,original_f),'original_preparer':row(H_PATH,original_h),
        'original_neg_helper':row(N_PATH,original_n),'actual_parent':row(P_PATH,parent_raw),
        'actual_adoption_original':row(A_PATH,adoption_raw),
        'source':f_descriptor,'preparer':row(STAGE/'source/prepare_actual_r8_freeze.py',frozen_h),
        'neg_root_helper':row(STAGE/'neg-root-plan/source/prepare_native_guard_root_plan.py',frozen_n),
        'comparison_only_combination':{'bytes':len(combo_raw),'sha256':sha(combo_raw),
            'actual_export_sha256':adoption['actual_export']['sha256'],
            'field_changed_only':'live_policy_sha256','runtime_output_written':False},
        'actual_adoption_reverified':False,'actual_export_body_read':False,
        'full_original_build_calls':0,'freezer_main_calls':0,'preparer_main_calls':0,
        'neg_plan_main_calls':0,'phone_calls':0,'remote_calls':0,'runtime_freezes':0,
        'native_nonces_created':0,'qualified_cases':0}
    replacements={'freezer':[{'before':a.decode(),'after':b.decode()} for a,b in f_replacements],
        'preparer':[{'before':a.decode(),'after':b.decode()} for a,b in h_replacements],
        'neg_root_plan':[{'before':a.decode(),'after':b.decode()} for a,b in n_replacements]}
    propagation={'schema':'hepta.native-guard.r8-compact-encoding-pin-propagation.v1',
        'active_updates':[
            {'source':'source/prepare_actual_r8_freeze.py','binding':'FREEZER exact3',
                'old_sha256':F_SHA,'new_descriptor':f_descriptor},
            {'source':'neg-root-plan/source/prepare_native_guard_root_plan.py','binding':'FREEZER_TEMPLATE_SHA',
                'old_sha256':F_SHA,'new_sha256':sha(frozen_f)}],
        'historical_files_kept_exact':['original62bc freezer','original106f preparer','original68df NEG helper',
            'originalba5c parent combination','delivery-final01','checkpoint04','old reviews and manifests'],
        'other_cached_downstream_executable_full_pin_hits':[],
        'searched':['*.py','*.json','*.md'],
        'runtime_pin_flow':'actual FREEZE-RESULT and its source/input descriptors propagate into cascade and Root plans',
        'source_only':True}
    files={
        'source/freeze_property_runtime.py':frozen_f,
        'source/prepare_actual_r8_freeze.py':frozen_h,
        'reference/freeze_property_runtime.62bc.original.py':original_f,
        'reference/prepare_actual_r8_freeze.106f.original.py':original_h,
        'reference/COMBINATION.ba5c.original.json':parent_raw,
        'reference/FREEZE-INPUTS.template.original.json':template_raw,
        'validation/FREEZER-COMBINATION-ENCODING.patch':patch(original_f,frozen_f,'original62bc/freeze_property_runtime.py','source/freeze_property_runtime.py'),
        'validation/PREPARER-INCREMENT.patch':patch(original_h,frozen_h,'original106f/prepare_actual_r8_freeze.py','source/prepare_actual_r8_freeze.py'),
        'validation/EXACT-REPLACEMENTS.json':enc(replacements),
        'validation/COMBINATION-ENCODING-CHECKS.json':enc(report),
        'validation/PIN-PROPAGATION.json':enc(propagation),
        'validation/build_r8_compact_final02.py':Path(__file__).read_bytes(),
    }
    n_files={
        'source/prepare_native_guard_root_plan.py':frozen_n,
        'reference/prepare_native_guard_root_plan.68df.original.py':original_n,
        'reference/freeze_property_runtime.compact.original.py':frozen_f,
        'PREPARE-NEG01.template.json':(W/'neg_root_plan_helper_r8/PREPARE-NEG01.template.json').read_bytes(),
        'PREPARE-NEG02.template.json':(W/'neg_root_plan_helper_r8/PREPARE-NEG02.template.json').read_bytes(),
        'validation/SOURCE-INCREMENT.patch':patch(original_n,frozen_n,'original68df/prepare_native_guard_root_plan.py','source/prepare_native_guard_root_plan.py'),
    }
    interface=json.loads((W/'neg_root_plan_helper_r8/INTERFACE.json').read_bytes())
    interface['staging_directory']=str(STAGE/'neg-root-plan')
    interface['reviewed_freezer_template']=f_descriptor
    n_files['INTERFACE.json']=enc(interface)
    n_files['README.md']=(
        '# R8 NEG01 / NEG02 plan helper for compact parent combination\n\n'
        'This source-only subpackage differs from the retained 68df helper only in '
        '`FREEZER_TEMPLATE_SHA`. It accepts the new compact-combination freezer plus '
        'its single explicit FINALIZATION literal. It does not accept the old 62bc '
        'freezer as an alternative. All actual freeze-output, Root3/runtime32, '
        'history, identity, request, role and source checks remain byte-identical.\n\n'
        'The actual completed R8 FREEZE-RESULT and caller-selected one-use identity '
        'are required. Neither is generated by this package. The default runs '
        'read-only validation; --execute-host-plan writes a fresh host plan only.\n\n'
        'CLI: `/usr/bin/python3 -I -B source/prepare_native_guard_root_plan.py '
        "--inputs-desc '<exact3 descriptor>' [--execute-host-plan]`.\n\n"
        'Templates remain unfilled. No actual plan validation, phone call, '
        'native submission or acceptance qualification was performed locally.\n'
    ).encode()
    n_manifest={'schema':'hepta.native-guard.r8-root-plan-preparation-source-package.v1',
        'state':'COMPACT_FREEZER_PIN_ONLY_SOURCE_REVIEWED_NOT_ACTUAL_VALIDATION',
        'files':[row(name,body) for name,body in sorted(n_files.items())],
        'parent_source':row(N_PATH,original_n),'reviewed_freezer_template_sha256':sha(frozen_f),
        'reviewed_root_template_sha256':N.ROOT_TEMPLATE_SHA,
        'whole_source_inverse_exact':True,'changed_rhs_only':'FREEZER_TEMPLATE_SHA',
        'actual_plan_created':False,'actual_validate_plan_called':False,
        'component_qualified':False,'native_submissions':0,'phone_calls':0,'random_identities_generated':0}
    n_files['SOURCE-MANIFEST.json']=enc(n_manifest)
    files.update({'neg-root-plan/'+name:body for name,body in n_files.items()})
    cli=['/usr/bin/python3','-I','-B',str(STAGE/'source/prepare_actual_r8_freeze.py'),
        '--policy-adoption-desc','<actual canonical adoption exact3 descriptor>',
        '--out','<fresh permitted native-guard-property-r8-freeze-actual-* directory>',
        '--execute-host-preparation']
    files['INTERFACE.json']=enc({'schema':'hepta.actual-r8-freeze-preparation.compact-source-interface.v1',
        'staging_directory':str(STAGE),'freezer':f_descriptor,
        'preparer':row(STAGE/'source/prepare_actual_r8_freeze.py',frozen_h),
        'unchanged_input_template':H.TEMPLATE,'independent_verifier':H.VERIFIER,
        'prepare_argv_template':cli,'fixed_runtime_out':str(F.OUT),
        'next_action':'Use actual prepared EXECUTION-ENTRY.json only after full original build succeeds',
        'no_automatic_runtime_freeze':True,'phone_calls':0,'native_nonces_created':0})
    files['README.md']=(
        '# Actual-parent compact combination compatibility — final02\n\n'
        'The actual retained R7 COMBINATION is 4702 bytes, SHA256 '+P_SHA+'. '
        'It is compact sorted UTF-8 JSON followed by LF. The original 62bc '
        'freezer and 106f preparer incorrectly used their pretty manifest/input '
        'encoder for that file; actual host preparation failed before outputs.\n\n'
        'The new freezer adds combination_enc and uses it at exactly three '
        'combination sites: parent identity, new one-field combination, and '
        'inverse identity. The generic enc function remains unchanged. The '
        'preparer uses those same three calls, pins the exact new freezer, and '
        'labels its new retained source accurately. The NEG plan subpackage '
        'changes only its freezer-template SHA. Exact old sources and actual '
        'parent bytes are retained under reference. No old output is replaced.\n\n'
        'The input template stays at its original canonical path and exact '
        'debd3165 pin. Actual source/adoption/74f4, historical byte and role '
        'checks, runtime32, Root3, verifier131072 and bundle32MiB remain intact.\n\n'
        'Local checks establish actual parent roundtrip, the adopted export '
        'hash single-field inverse, whole-source inverse, exact source pins '
        'and unchanged default JSON encoding. They do not run full build, '
        'verify the adoption, freeze R8, call the phone or qualify any case.\n\n'
        'Stage this closed package at `'+str(STAGE)+'`. Follow INTERFACE.json '
        'using the real canonical adoption descriptor and a fresh permitted '
        'host preparation directory. The preparer calls the complete original '
        'build before it creates output. Execute runtime freeze separately '
        'from the actual generated EXECUTION-ENTRY only after that succeeds.\n'
    ).encode()
    manifest={'schema':'hepta.actual-r8-freeze-preparation.source-package.v1',
        'state':'ACTUAL_PARENT_COMPACT_ENCODING_SOURCE_COMPATIBILITY_REVIEWED',
        'staging_directory':str(STAGE),
        'files':[row(name,body) for name,body in sorted(files.items())],
        'freezer':f_descriptor,'preparer':row(STAGE/'source/prepare_actual_r8_freeze.py',frozen_h),
        'neg_root_plan_manifest':row(STAGE/'neg-root-plan/SOURCE-MANIFEST.json',n_files['SOURCE-MANIFEST.json']),
        'freezer_parent_sha256':F_SHA,'preparer_parent_sha256':H_SHA,
        'parent_combination_sha256':P_SHA,'input_template_sha256':sha(template_raw),
        'verifier':H.VERIFIER,'source_only':True,'local_source_checks_passed':len(checks),
        'actual_build_preflight_run_locally':False,'actual_adoptions_created':0,
        'runtime_freezes':0,'phone_calls':0,'new_nonces':0}
    files['SOURCE-MANIFEST.json']=enc(manifest)
    OUT.mkdir(parents=True,mode=0o700)
    for name,body in sorted(files.items()):
        path=OUT/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with path.open('xb') as stream: stream.write(body)
        assert path.read_bytes()==body
    delivery={'schema':'hepta.actual-r8-freeze-preparation.delivery.v1',
        'state':manifest['state'],'package':str(OUT),'staging_directory':str(STAGE),
        'manifest':row(STAGE/'SOURCE-MANIFEST.json',files['SOURCE-MANIFEST.json']),
        'files':[row(name,body) for name,body in sorted(files.items())],
        'freezer':f_descriptor,'preparer':manifest['preparer'],
        'neg_root_helper':report['neg_root_helper'],
        'all_local_bytes_read_back':True,'runtime_freezes':0,'phone_calls':0,'new_nonces':0}
    delivery_raw=enc(delivery)
    with (OUT.parent/'DELIVERY.json').open('xb') as stream: stream.write(delivery_raw)
    print(enc({'manifest':delivery['manifest'],'freezer':f_descriptor,'preparer':manifest['preparer'],
        'neg_root_helper':report['neg_root_helper'],'checks':len(checks),
        'delivery':row(OUT.parent/'DELIVERY.json',delivery_raw)}).decode(),end='')


if __name__=='__main__':
    main()
