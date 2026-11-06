#!/usr/bin/env python3
"""Build a separate, unbound source candidate; never run a runtime member."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = HERE.parents[1]
PARENT = WORK / 'repo-evidence-readonly/checkpoint09/restored/originals/epoch_consumer_candidate01/two-domain-preview22'
PURE = HERE / 'inputs/epoch_native_candidate01/pure-api-draft02/source/epoch_runtime_source_increment.py'
OUT = HERE / 'external-recipe-consumers-r1'
REMOTE = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/epoch-external-recipe-consumers-2438-r1'
FILES = ['templates/release_boundaries.py', 'templates/make_component_boundary_inputs.py',
         'source/derive_final_cascade_property_r8.py', 'source/write_final_seal_interface_property_r8.py',
         'preparer/prepare_final_cascade.py']


def enc(v):
    return (json.dumps(v, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)+'\n').encode()


def canonical(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)+'\n').encode()


def pin(raw):
    return {'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest()}


def change(s, a, b, count=1):
    assert s.count(a) == count, (a[:180], s.count(a), count)
    return s.replace(a, b)


def assignment(s, name, value):
    nodes = [n for n in ast.parse(s).body if isinstance(n, ast.Assign)
             and len(n.targets)==1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id==name]
    assert len(nodes)==1
    n=nodes[0]; lines=s.splitlines(keepends=True)
    return ''.join(lines[:n.lineno-1])+name+' = '+repr(value)+'\n'+''.join(lines[n.end_lineno:])


def insert_pure(s, body, compact=False):
    nodes=ast.parse(s).body
    first=next(n for n in nodes if isinstance(n,ast.Import) and any(x.asname=='_esi_base64' for x in n.names))
    last=next(n for n in nodes if isinstance(n,ast.FunctionDef) and n.name=='epoch_historical_runtime_view')
    if compact:
        # Preserve Python suites exactly while retaining the parent's reviewed
        # one-space indentation convention; no executable compression.
        body=''.join((' ' *((len(line)-len(line.lstrip(' ')))//4)+line.lstrip(' '))
                     if line.startswith(' ') else line for line in body.splitlines(keepends=True))
    lines=s.splitlines(keepends=True)
    return ''.join(lines[:first.lineno-1])+body+''.join(lines[last.end_lineno:])


def main():
    assert not OUT.exists(), 'new isolated candidate directory required'
    originals={name:(PARENT/name).read_bytes() for name in FILES}
    sources={name:raw.decode() for name,raw in originals.items()}
    pure=PURE.read_text()
    pure=change(pure, 'EPOCH_SOURCE_RECIPE = None', 'EPOCH_SOURCE_RECIPE_DESCRIPTOR = None')
    pure=change(pure, "_ESI_PROOF_FIELDS = ('schema','state','runtime','combination','shared_materials',",
                "_ESI_PROOF_FIELDS = ('schema','state','runtime','combination','shared_materials','source_recipe',")
    helper='''def _esi_recipe_descriptor():
    row=EPOCH_SOURCE_RECIPE_DESCRIPTOR
    _esi_exact(row,('path','bytes','sha256'),'final source recipe descriptor is not frozen')
    path=row['path']
    _esi_need(type(path) is str and path.startswith('/') and '\\0' not in path
        and all(part not in ('','.','..') for part in path.split('/')[1:])
        and type(row['bytes']) is int and 0<row['bytes']<=65536
        and type(row['sha256']) is str and _ESI_HASH.fullmatch(row['sha256']),
        'canonical absolute bounded source-frozen recipe descriptor required')
    return dict(row)


def _esi_recipe_match(row):
    fixed=_esi_recipe_descriptor()
    _esi_need(_esi_same(row,fixed),'caller cannot substitute source recipe authority')
    return fixed


def epoch_recipe_original(frozen, read_original):
    """Use the enclosing original reader and its unchanged bookend/budget."""
    _esi_need(type(frozen) is dict and 'source_recipe' in frozen and callable(read_original),
              'explicit source recipe field and original reader required')
    row=_esi_recipe_match(frozen['source_recipe'])
    raw=read_original(row)
    _esi_data(raw)
    return raw


'''
    pure=change(pure, 'def _esi_data():\n    packet=EPOCH_SOURCE_RECIPE\n', helper+'''def _esi_data(recipe_raw):
    row=_esi_recipe_descriptor()
    _esi_pin(recipe_raw,{key:row[key] for key in ('bytes','sha256')},65536)
    packet=_esi_strict(recipe_raw)
    _esi_need(_esi_json_bytes(packet)==recipe_raw,'source recipe packet canonical JSON differs')
''')
    pure=change(pure, 'def _esi_dataset(runtime_raw,source_files,combination_raw,shared_files,expected):',
                'def _esi_dataset(runtime_raw,source_files,combination_raw,shared_files,expected,*,recipe_bytes=0):')
    pure=change(pure, 'names=[];total=len(runtime_raw)+len(combination_raw)',
                'names=[];total=len(runtime_raw)+len(combination_raw)+recipe_bytes')
    pure=change(pure, 'def _esi_checked(runtime_raw,source_files,combination_raw,shared_files):\n    recipe=_esi_data();_esi_dataset(runtime_raw,source_files,combination_raw,shared_files,recipe[\'current\'])',
                'def _esi_checked(runtime_raw,source_files,combination_raw,shared_files,*,recipe_raw):\n    recipe=_esi_data(recipe_raw)\n    _esi_dataset(runtime_raw,source_files,combination_raw,shared_files,recipe[\'current\'],\n                 recipe_bytes=len(recipe_raw))')
    for name in ('verify_epoch_runtime_increment','epoch_historical_runtime_view'):
        pure=change(pure, f'def {name}(runtime_raw,source_files,combination_raw,shared_files):',
                    f'def {name}(runtime_raw,source_files,combination_raw,shared_files,*,recipe_raw):')
    pure=change(pure, '_esi_checked(runtime_raw,source_files,combination_raw,shared_files)',
                '_esi_checked(runtime_raw,source_files,combination_raw,shared_files,recipe_raw=recipe_raw)',2)
    pure=change(pure, "'shared_materials':{name:_esi_bare(raw) for name,raw in sorted(shared_files.items())},",
                "'shared_materials':{name:_esi_bare(raw) for name,raw in sorted(shared_files.items())},\n        'source_recipe':_esi_recipe_descriptor(),")
    pure=pure.replace('epoch-runtime-increment-verification.v1','epoch-runtime-increment-verification.v2')
    doc=ast.parse(pure).body[0]
    pure_body=''.join(pure.splitlines(keepends=True)[doc.end_lineno:]).lstrip('\n')
    for name in FILES[:1]+FILES[2:4]:
        sources[name]=insert_pure(sources[name],pure_body,name.startswith('templates/'))

    name='templates/release_boundaries.py';s=sources[name]
    s=change(s, "'epoch_publication_inputs', 'epoch_publication_originals'}",
                "'epoch_publication_inputs', 'epoch_publication_originals', 'source_recipe'}")
    s=change(s, "  value = strict(raw)\n  inputs[name]", "  value = strict(raw)\n  if name == 'component':\n   _esi_recipe_match(value.get('source_recipe'))\n  inputs[name]")
    s=change(s, " shared_files = shared_runtime_originals(bundle, value, source)\n verify_epoch_runtime_increment(manifest_raw, source, combination_raw, shared_files)",
                " shared_files = shared_runtime_originals(bundle, value, source)\n recipe_raw = original_from(bundle, _esi_recipe_match(value['source_recipe']))\n verify_epoch_runtime_increment(manifest_raw, source, combination_raw, shared_files, recipe_raw=recipe_raw)")
    s=change(s, " 'shared_runtime_originals': shared_files}",
                " 'shared_runtime_originals': shared_files, 'component_combination_raw': combination_raw,\n 'epoch_source_recipe_raw': recipe_raw}")
    s=change(s, " prior = {name: sys.modules.get(name) for name in names}",
                " verify_epoch_runtime_increment(manifest_raw, source, state.get('component_combination_raw'),\n state.get('shared_runtime_originals'), recipe_raw=state.get('epoch_source_recipe_raw'))\n prior = {name: sys.modules.get(name) for name in names}")
    sources[name]=s

    for name in FILES[2:4]:
        s=sources[name]
        s=change(s, "    history_input_raw,history_input=epoch_policy_history_source_input(frozen,runtime_raw,read_original)",
                    "    recipe_raw=epoch_recipe_original(frozen,read_original)\n    history_input_raw,history_input=epoch_policy_history_source_input(frozen,runtime_raw,read_original)")
        s=change(s, 'gate(runtime_raw,runtime_files,combo_raw,shared)',
                    'gate(runtime_raw,runtime_files,combo_raw,shared,recipe_raw=recipe_raw)',2)
        s=change(s, "fields = {'schema','state','runtime','combination','shared_materials','parent_runtime','parent_combination',",
                    "fields = {'schema','state','runtime','combination','shared_materials','source_recipe','parent_runtime','parent_combination',")
        s=change(s, "and proof['runtime'] == bare(runtime_raw) and proof['combination'] == bare(combo_raw)",
                    "and proof['runtime'] == bare(runtime_raw) and proof['combination'] == bare(combo_raw)\n         and proof['source_recipe'] == _esi_recipe_descriptor()")
        s=change(s, "return {'proof':proof,'combination_raw':combo_raw,'shared_manifest_raw':shared_raw,",
                    "return {'proof':proof,'combination_raw':combo_raw,'shared_manifest_raw':shared_raw,\n            'source_recipe_raw':recipe_raw,")
        sources[name]=s

    name='source/derive_final_cascade_property_r8.py';s=sources[name]
    s=change(s,"'scope_decision', 'full_rule', 'shared_material_manifest', 'policy_history_input'}",
               "'scope_decision', 'full_rule', 'shared_material_manifest', 'policy_history_input', 'source_recipe'}")
    s=change(s,"'policy_verifier', 'scope_decision', 'full_rule', 'shared_material_manifest', 'policy_history_input'):",
               "'policy_verifier', 'scope_decision', 'full_rule', 'shared_material_manifest', 'policy_history_input', 'source_recipe'):")
    s=change(s,"    policy = value['actual_policy']", "    _esi_recipe_match(value['source_recipe'])\n    policy = value['actual_policy']")
    s=change(s,"    current_as_parent.pop('policy_history_input')", "    current_as_parent.pop('policy_history_input')\n    current_as_parent.pop('source_recipe')")
    s=change(s,"'CURRENT_SCOPE_DECISION_SHA':frozen['scope_decision']['sha256']}",
                "'CURRENT_SCOPE_DECISION_SHA':frozen['scope_decision']['sha256'],\n        'EPOCH_SOURCE_RECIPE_DESCRIPTOR':_esi_recipe_match(frozen['source_recipe'])}")
    s=change(s,'def actual_tail_check(helper_raw, constructor_raw, runtime_raw, runtime_files, package_sha, combination_sha):',
                'def actual_tail_check(helper_raw, constructor_raw, runtime_raw, runtime_files, package_sha, combination_sha, *, epoch_sources):')
    s=change(s,"                     'package_sources':runtime_files}",
                "                     'package_sources':runtime_files,\n                     'component_combination_raw':epoch_sources['combination_raw'],\n                     'shared_runtime_originals':epoch_sources['shared_files'],\n                     'epoch_source_recipe_raw':epoch_sources['source_recipe_raw']}")
    s=change(s,"        frozen['runtime_manifest']['sha256'], frozen['component_combination']['sha256'])",
                "        frozen['runtime_manifest']['sha256'], frozen['component_combination']['sha256'],\n        epoch_sources=epoch_sources)")
    sources[name]=s

    name='source/write_final_seal_interface_property_r8.py';s=sources[name]
    s=change(s,"'shared_material_manifest','policy_history_input'},", "'shared_material_manifest','policy_history_input','source_recipe'},")
    s=change(s,"    runtime_state={'actual_context':'mac','package_sources':runtime_files,'package_manifest_raw':mraw}",
                "    runtime_state={'actual_context':'mac','package_sources':runtime_files,'package_manifest_raw':mraw,\n        'component_combination_raw':epoch_sources['combination_raw'],\n        'shared_runtime_originals':epoch_sources['shared_files'],\n        'epoch_source_recipe_raw':epoch_sources['source_recipe_raw']}")
    s=change(s,"'CURRENT_POLICY_ADOPTION_SHA','CURRENT_SCOPE_DECISION_SHA'}}", "'CURRENT_POLICY_ADOPTION_SHA','CURRENT_SCOPE_DECISION_SHA','EPOCH_SOURCE_RECIPE_DESCRIPTOR'}}")
    s=change(s,"'CURRENT_SCOPE_DECISION_SHA':frozen['scope_decision']['sha256']},",
                "'CURRENT_SCOPE_DECISION_SHA':frozen['scope_decision']['sha256'],\n         'EPOCH_SOURCE_RECIPE_DESCRIPTOR':_esi_recipe_match(frozen['source_recipe'])},")
    s=change(s,"epoch_sources['combination_raw'],epoch_sources['shared_files']))==encode(increment_proof)",
                "epoch_sources['combination_raw'],epoch_sources['shared_files'],\n             recipe_raw=epoch_sources['source_recipe_raw']))==encode(increment_proof)")
    s=change(s,"        combination=combo,", "        combination=combo,source_recipe=_esi_recipe_descriptor(),")
    sources[name]=s

    name='templates/make_component_boundary_inputs.py';s=sources[name]
    s=change(s,"'epoch_publication_inputs', 'epoch_publication_originals'}", "'epoch_publication_inputs', 'epoch_publication_originals', 'source_recipe'}")
    s=change(s,"    manifest_raw = collect(plan['package_manifest'])", "    recipe_raw = collect(h._esi_recipe_match(plan['source_recipe']))\n    manifest_raw = collect(plan['package_manifest'])")
    s=change(s,"    # The final four-argument epoch capsule must be inserted before this source can run.\n    # Every new runtime byte, combination and shared17 original precedes the first exec.\n    h.verify_epoch_runtime_increment(manifest_raw, runtime_files, combination_raw, shared_files)",
                "    # The fixed external recipe joins the same charged original pool before exec.\n    h.verify_epoch_runtime_increment(manifest_raw, runtime_files, combination_raw, shared_files,\n                                     recipe_raw=recipe_raw)")
    s=change(s,"                     'package_manifest_raw':manifest_raw}",
                "                     'package_manifest_raw':manifest_raw,\n                     'component_combination_raw':combination_raw,\n                     'shared_runtime_originals':shared_files,'epoch_source_recipe_raw':recipe_raw}")
    s=change(s,"        component_combination=combination_copy, latest_boundary=boundary_rows[0],", "        component_combination=combination_copy, source_recipe=h._esi_recipe_descriptor(),\n        latest_boundary=boundary_rows[0],")
    sources[name]=s

    name='preparer/prepare_final_cascade.py';s=sources[name]
    s=change(s,"    parser.add_argument('--policy-history-input-desc', required=True)", "    parser.add_argument('--policy-history-input-desc', required=True)\n    parser.add_argument('--source-recipe-desc', required=True)")
    s=change(s,"'runtime_manifest','component_combination','shared_material_manifest','policy_history_input'},", "'runtime_manifest','component_combination','shared_material_manifest','policy_history_input','source_recipe'},")
    s=change(s,"'policy_history_input':strict(args.policy_history_input_desc)}", "'policy_history_input':strict(args.policy_history_input_desc),\n                'source_recipe':strict(args.source_recipe_desc)}")
    s=change(s,"'policy_history_input':fixed['policy_history_input']}", "'policy_history_input':fixed['policy_history_input'],'source_recipe':fixed['source_recipe']}")
    s=change(s,"             'POLICY-HISTORY-INPUT.original.json':epoch_sources['policy_history_input_raw'],", "             'POLICY-HISTORY-INPUT.original.json':epoch_sources['policy_history_input_raw'],\n             'EPOCH-SOURCE-RECIPE.original.json':epoch_sources['source_recipe_raw'],")
    s=s.replace('the four actual current epoch source inputs','the five actual current epoch source inputs')
    s=s.replace('shared manifest or history input', 'shared manifest, history input or recipe')
    sources[name]=s

    # Version all changed exact envelopes; no old caller can omit the new data original.
    versions={'epoch-runtime-increment-verification.v1':'epoch-runtime-increment-verification.v2',
              'component-boundary-inputs.v7':'component-boundary-inputs.v8',
              'component-boundary-construction-plan.v8':'component-boundary-construction-plan.v9',
              'component-boundary-construction-result.v7':'component-boundary-construction-result.v8',
              'property-policy.final-pin-freeze.v3':'property-policy.final-pin-freeze.v4'}
    for name,s in sources.items():
        for a,b in versions.items():s=s.replace(a,b)
        sources[name]=s
    # Mechanical template pin cascade; preserve all unrelated 17 template pins.
    derive=sources[FILES[2]]
    n=next(n for n in ast.parse(derive).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TEMPLATE_PINS' for t in n.targets))
    template_pins=ast.literal_eval(n.value)
    previous_pins={name:template_pins[name] for name in ('release_boundaries.py','make_component_boundary_inputs.py')}
    for name in previous_pins:template_pins[name]=pin(sources['templates/'+name].encode())
    sources[FILES[2]]=assignment(derive,'TEMPLATE_PINS',template_pins)
    # The preparer pins the new unbound generator sources; its manifest must
    # also be fixed, so manufacture that manifest as data without an execution claim.
    source_rows=[dict(path=name,**pin(sources[name].encode())) for name in FILES[2:4]]
    old_overrides=ast.literal_eval(next(n.value for n in ast.parse(originals[FILES[4]].decode()).body
        if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TEMPLATE_OVERRIDES' for t in n.targets)))
    overrides={name:{'parent':old_overrides[name]['parent'],
        'successor':dict(path=REMOTE+'/templates/'+name,**template_pins[name])} for name in previous_pins}
    template_manifest=ast.literal_eval(next(n.value for n in ast.parse(sources[FILES[4]]).body
        if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TEMPLATE_MANIFEST' for t in n.targets)))
    gen=enc({'schema':'hepta.inventory-prefix.final-generators.source-package.v1',
        'state':'SOURCE_ONLY_FINALIZATION_AND_DELIVERY_UNFILLED','template_source_manifest':template_manifest,
        'template_overrides':overrides,'files':source_rows})
    prep=sources[FILES[4]]
    for var,rel in [('SOURCE',FILES[2]),('INTERFACE',FILES[3])]:
        prep=assignment(prep,var,dict(path=REMOTE+'/'+rel,**pin(sources[rel].encode())))
    prep=assignment(prep,'TEMPLATE_OVERRIDES',overrides)
    prep=assignment(prep,'GENERATOR_MANIFEST',dict(path=REMOTE+'/GENERATOR-SOURCE-MANIFEST.json',**pin(gen)))
    sources[FILES[4]]=prep

    outputs={name:s.encode() for name,s in sources.items()}
    outputs['reference/epoch_runtime_source_increment.py']=pure.encode()
    outputs['GENERATOR-SOURCE-MANIFEST.json']=gen
    packet=json.loads((HERE/'recipe-budget-probe01/BOUND-DATA.TEST-ONLY.json').read_bytes())
    outputs['tests/fixtures/EPOCH-SOURCE-RECIPE.TEST-ONLY.json']=canonical(packet)
    # Portable test originals are bytes only; no test executes a runtime or
    # provider member. Reconstruct exactly the already measured TEST_ONLY set.
    import importlib.util
    spec=importlib.util.spec_from_file_location('recipe_test_data_builder',HERE/'measure_recipe_fit.py')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    captured={}
    helper.put=lambda name,raw:captured.setdefault(name,raw)
    helper.main()
    assert captured['BOUND-DATA.TEST-ONLY.json']==(HERE/'recipe-budget-probe01/BOUND-DATA.TEST-ONLY.json').read_bytes()
    measurement=json.loads(captured['MEASUREMENT.json'])
    codec=HERE/'inputs/codec-de120154'
    old_raw=(codec/'runtime32/MANIFEST.json').read_bytes();old=json.loads(old_raw)
    runtime={r['path']:(codec/'runtime32'/r['path']).read_bytes() for r in old['files']}
    for name,row in measurement['native_source_locations'].items():
        raw=Path(row['path']).read_bytes();assert pin(raw)=={k:row[k] for k in ('bytes','sha256')}
        runtime['source/'+name]=raw
    shared_root=HERE/'mechanical-shared17-candidate'
    shared_manifest_raw=(shared_root/'SHARED-MATERIALS.json').read_bytes()
    shared={r['path']:(shared_root/r['path']).read_bytes() for r in json.loads(shared_manifest_raw)['files']}
    production={k.rsplit('/',1)[1]:v for k,v in shared.items() if k.startswith('provider/source/')}
    runtime['reference/REVIEWED-PRODUCTION-PINS.json']=enc({k:pin(v)['sha256'] for k,v in production.items()})
    combo=json.loads((codec/'COMBINATION.json').read_bytes())
    seal={'schema':'hepta.native-guard.component-source-seal.v150.r10.1',
        'state':'REVIEWED_COMPONENT_BYTES_NOT_FINAL_RELEASE','intended_module_release':'v150-r10-r1',
        'configuration':pin(shared['local-config-r10-r1.json']),
        'phone_service_inputs_sha256':pin(shared['PHONE-SERVICE-INPUTS-v150-r10-r1.json'])['sha256'],
        'production_files':[dict(path='source/'+k,**pin(v)) for k,v in sorted(production.items())]}
    combo.update(source_seal=pin(canonical(seal)),configuration=pin(shared['local-config-r10-r1.json']),
        service_inputs=pin(shared['PHONE-SERVICE-INPUTS-v150-r10-r1.json']),
        production_files=[dict(path='production/'+k,**pin(v)) for k,v in sorted(production.items())])
    combo_raw=canonical(combo)
    value=dict(old);value['files']=[dict(path=r['path'],**pin(runtime[r['path']])) for r in old['files']]
    value['current_combination_sha256']=pin(combo_raw)['sha256']
    value['reviewed_production_pins_sha256']=pin(runtime['reference/REVIEWED-PRODUCTION-PINS.json'])['sha256']
    runtime_raw=enc(value)
    assert pin(runtime_raw)==measurement['pure_verifier_result']['runtime']
    assert pin(combo_raw)==measurement['pure_verifier_result']['combination']
    outputs.update({'tests/fixtures/runtime32/'+name:raw for name,raw in runtime.items()})
    outputs.update({'tests/fixtures/shared17/'+name:raw for name,raw in shared.items()})
    outputs['tests/fixtures/runtime32/MANIFEST.json']=runtime_raw
    outputs['tests/fixtures/shared17/SHARED-MATERIALS.json']=shared_manifest_raw
    outputs['tests/fixtures/COMBINATION.TEST-ONLY.json']=combo_raw
    outputs['tests/fixtures/TEMPLATE-SOURCE-MANIFEST.original.json']=(HERE/'inputs/mac-current/TEMPLATE-SOURCE-MANIFEST.json').read_bytes()
    changes=[]
    for name,raw in outputs.items():
        if name.endswith('.py'):
            ast.parse(raw);compile(raw,name,'exec')
            assert len(raw)<=131072,(name,len(raw))
        if name in originals:
            changes.extend(difflib.unified_diff(originals[name].decode().splitlines(True),raw.decode().splitlines(True),
                fromfile='preview22/'+name,tofile='external-recipe-r1/'+name))
    outputs['EXTERNAL-RECIPE.patch']=''.join(changes).encode()
    report={'schema':'hepta.epoch-external-recipe-source-candidate.v1',
        'state':'UNBOUND_SOURCE_ONLY_NOT_INSTALLABLE',
        'parent_sources':{name:pin(raw) for name,raw in originals.items()},
        'candidate_sources':{name:pin(raw) for name,raw in outputs.items() if name.endswith('.py')},
        'test_only_recipe':pin(outputs['tests/fixtures/EPOCH-SOURCE-RECIPE.TEST-ONLY.json']),
        'runtime_source_members_added':0,'runtime_member_count_unchanged':32,
        'recipe_original_limit':65536,'existing_decoded_original_pool_limit':33554432,
        'new_global_physical_read_limit_introduced':False,
        'source_recipe_descriptor_bound':False,'policy_authority_fabricated':False,
        'phone_calls':0,'runtime_source_executions':0,'case_credit':0,
        'source_pin_cascade':['release template + constructor template -> cascade TEMPLATE_PINS',
            'cascade + interface -> preparer source descriptors + generator manifest',
            'generator manifest -> preparer manifest descriptor'],
        'remaining_binding':['source_recipe descriptor in three pure consumers',
            'EPOCH_SOURCE_INPUTS and FINALIZATION including actual source_recipe',
            'actual policy/apply/adoption and all prior unbound authority slots',
            'actual template package lineage/remaining overrides integration']}
    outputs['SOURCE-DERIVATION.json']=enc(report)
    for name,raw in outputs.items():
        p=OUT/name;p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('xb') as f:f.write(raw)
    print(json.dumps({'path':str(OUT),'sources':report['candidate_sources'],'state':report['state']}))


if __name__=='__main__':main()
