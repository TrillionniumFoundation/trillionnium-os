# Explicit current epoch operations in the existing stage_component member.
# No operation is selected or executed at import time. Every operation uses the
# caller's already running clock and the complete, verified runtime source map.
import time
EPOCH_OPERATION_SOURCE_BINDING = None
EPOCH_ALLOCATION_PLAN_FIELDS = ('schema','epoch_id','boot_id','runtime','combination',
    'shared_materials','pure_verifier','derivation','root_source_manifest',
    'code_receipt','initialization','generation','root_authorization','case_id',
    'selected_session_id','selected_profile_id','authorization_request','sender_inputs','host_out')
EPOCH_INITIALIZE_PLAN_FIELDS = ('schema','epoch_id','boot_id','runtime','combination',
    'shared_materials','pure_verifier','derivation','root_source_manifest',
    'bootstrap_plan','root_authorization','initialization_inputs','host_out')
EPOCH_ALLOCATION_RESULT_FIELDS = ('schema','state','epoch_id','boot_id','ordinal',
    'claim','directory_binding','identity','owner_request','allocation_admission',
    'nonce','label','case_id','selected_session_id','selected_profile_id',
    'initialization','generation','prior_boundary','predecessor_terminal',
    'owner_request_utf8','scope','lease','automatic_retry','component_qualified',
    'business_qualified')
EPOCH_OPERATION_SECONDS = {'bootstrap-runtime':90,'initialize':90,'allocate':90,
    'stage':90,'scope-bind':30,'launch':60,'witness-publish':35,'role-end':40,
    'snapshot':75,'publish':90,'seal':60}
EPOCH_OPERATION_CONTEXT_FIELDS = {
    'initialize':('code_receipt',),
    'allocate':('code_receipt','initialization','generation'),
    'stage':('code_receipt','initialization','generation','reservation','identity'),
    'scope-bind':('code_receipt','initialization','generation','reservation','identity','lease'),
    'launch':('code_receipt','initialization','generation','reservation','identity','lease'),
    'witness-publish':('code_receipt','initialization','generation','reservation','identity','lease'),
    'role-end':('code_receipt','initialization','generation','reservation','identity','lease'),
    'snapshot':('code_receipt','initialization','generation','reservation','identity','lease'),
    'publish':('code_receipt','initialization','generation','reservation','identity','lease'),
    'seal':('code_receipt','initialization','generation','reservation','identity','lease')}
EPOCH_PHASES = ('setup','before-guard','after-guard')
EPOCH_SOURCE_ORDER = ('component_common','native_proc_profile','component_lifecycle',
    'stage_component','prepare_component','late_boundary','component_snapshot')
EPOCH_RESOURCE_KEYS = ('root_objects','inventory_entries','inventory_file_bytes',
    'capture_files','capture_bytes','consumer_decoded_bytes')
EPOCH_ALLOCATION_ADMISSION_FIELDS = ('schema','state','epoch_id','ordinal','boot_id',
    'anchor','initialization','generation','claim','identity','predecessor_terminal',
    'prior_boundary','preclaim_observation','resource_reservation','authorization_original',
    'nonce_generated_after_exclusive_claim','native_scope_assigned','component_qualified',
    'business_qualified','automatic_retry')
EPOCH_RESULT_FIELDS = {
    'initialize':('schema','state','epoch_id','boot_id','code_receipt','anchor','initialization',
        'generation','root_authorization','baseline_business_inventory','baseline_control_inventory',
        'inventory_spec','inventory_observation','resource_admission','artifact_installation',
        'nonces_generated','native_calls','component_qualified','business_qualified','automatic_retry'),
    'transfer':('schema','state','epoch_id','ordinal','phase','originals','automatic_retry','component_qualified'),
    'stage':('schema','state','epoch_id','ordinal','lease','stage_binding','stage_original',
        'automatic_retry','component_qualified'),
    'scope-bind':('schema','state','epoch_id','ordinal','scope_binding','launch_authorization',
        'scope','automatic_retry','component_qualified'),
    'launch':('schema','state','epoch_id','ordinal','role_launch_intent','detached_intent',
        'detached_result','supervisor_generation_inferred','readiness_asserted','automatic_retry','component_qualified'),
    'witness-publish':('schema','state','epoch_id','ordinal','phase','publication','actual_members',
        'automatic_retry','component_qualified'),
    'role-end':('schema','state','epoch_id','ordinal','role_end_originals','automatic_retry','component_qualified'),
    'snapshot':('schema','state','epoch_id','ordinal','capture','archive','result','copy_accounting','automatic_retry','component_qualified'),
    'seal':('schema','state','epoch_id','boot_id','seal','qualified_boundaries','automatic_retry','component_qualified')}
EPOCH_RESULT_IDENTITIES = {
    'initialize':('hepta.native-guard.epoch-initialization-result.v1','REGISTRY_BASELINE_CREATED_NO_CASE_OR_LEASE'),
    'transfer':('hepta.native-guard.epoch-transfer-result.v1','ACTUAL_PRIVATE_INPUT_COPIES_CREATED'),
    'stage':('hepta.native-guard.epoch-stage-result.v1','ACTUAL_PRIVATE_CASE_STAGED_NO_ROLES'),
    'scope-bind':('hepta.native-guard.epoch-scope-result.v1','ACTUAL_ACCEPTED_SCOPE_AND_FIXTURE_PERMISSION_BOUND'),
    'launch':('hepta.native-guard.epoch-launch-result.v1','ACTUAL_ONE_FORK_RECORDED_NO_READINESS_CLAIM'),
    'witness-publish':('hepta.native-guard.epoch-witness-result.v1','ACTUAL_COMPLETE_BOUNDED_WITNESS_PUBLISHED'),
    'role-end':('hepta.native-guard.epoch-role-end-result.v1','ACTUAL_OWNED_ROLE_END_ORIGINALS_AND_ABSENCE_OBSERVED'),
    'snapshot':('hepta.native-guard.epoch-snapshot-result.v1','ACTUAL_COMPLETE_CAPTURE_ARCHIVE_CREATED'),
    'seal':('hepta.native-guard.epoch-seal-result.v1','ACTUAL_TWO_QUALIFIED_NATIVE_BOUNDARIES_SEALED')}


def _est_modules(*, phone=False, budget_check=None):
    import hashlib
    common=sys.modules.get('component_common')
    need(common is not None,'actual reviewed common module must already be loaded')
    context=common.epoch_actual_context(globals())
    if phone:need(context=='phone','this operation requires the actual phone context')
    if budget_check is not None:
        need(callable(budget_check),'the enclosing operation budget is required');budget_check()
    raw=globals().get('__reviewed_package_manifest_raw__')
    bodies=globals().get('__reviewed_package_sources__')
    need(type(raw) is bytes and type(bodies) is dict,'complete original MF and32 source bodies required')
    value=common.strict(raw);rows=value.get('files')
    need(value.get('schema')=='hepta.native-guard.adapter-package.v1'
        and type(rows) is list and len(rows)==32 and len(bodies)==32,
        'exact current32 runtime source package required')
    declared=set()
    for row in rows:
        need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact source row required')
        relative=common.relative(row['path']);name=str(relative)
        need(name not in declared and name in bodies,'missing or duplicate current runtime source')
        declared.add(name);body=bodies[name]
        maximum=131072 if name.endswith('.py') else 16*1024*1024
        need(type(body) is bytes and type(row['bytes']) is int and 0<=row['bytes']<=maximum
            and len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256'],
            'whole current source body differs')
    need(declared==set(bodies),'unreviewed extra runtime body')
    found={}
    for name in EPOCH_SOURCE_ORDER:
        module=sys.modules.get(name);need(module is not None,'required current module not loaded: '+name)
        namespace=module.__dict__;path='source/'+name+'.py'
        need(common.epoch_actual_context(namespace)==context
            and namespace.get('__reviewed_package_sources__') is bodies
            and namespace.get('__reviewed_package_manifest_raw__')==raw
            and namespace.get('__reviewed_source_sha256__')==hashlib.sha256(bodies[path]).hexdigest(),
            'current module source or explicit context differs: '+name)
        found[name]=module
    need(found['stage_component'].__dict__ is globals(),'stage operation is not the verified module object')
    if budget_check is not None:budget_check()
    return common,found,value,raw,bodies


def _est_binding(common):
    value=EPOCH_OPERATION_SOURCE_BINDING
    common._ep_need(value is not None,'epoch operation source binding is not frozen')
    common._ep_exact(value,{'schema','epoch_id','boot_id','source_paths','combination',
        'shared_materials','root_template','bridge_template','root_authorization',
        'bootstrap_plan','initialization_inputs','host_out','case_out_root','authorization_requests','sender_inputs',
        'resource_model','retained_failed_native_branches','initialization_files',
        'new_artifacts'},'complete source-fixed epoch operation binding required')
    common._ep_need(value['schema']=='hepta.native-guard.epoch-operation-source-binding.v1'
        and value['epoch_id']==common.EPOCH_ID and value['boot_id']==common.epoch_binding_value()['boot_id'],
        'actual source-bound epoch and boot differ')
    for key in ('combination','shared_materials','root_authorization','bootstrap_plan','initialization_inputs'):
        common._ep_pin(value[key])
    common._ep_exact(value['source_paths'],{'runtime','pure_verifier','derivation','generation'},
        'fixed acyclic current source-origin paths required')
    for path in value['source_paths'].values():common._ep_path(path)
    for key in ('root_template','bridge_template'):
        common._ep_exact(value[key],{'bytes','sha256'},'whole unbound source template pin required')
        common._ep_need(type(value[key]['bytes']) is int and 0<value[key]['bytes']<=131072
            and type(value[key]['sha256']) is str and common.EPOCH_HASH.fullmatch(value[key]['sha256']),
            'source template byte identity differs')
    common._ep_path(value['host_out'])
    common._ep_path(value['case_out_root'])
    common._ep_exact(value['sender_inputs'],{'previous','preserved_draft','retirement_resolution'},
        'three independently retained sender input originals required')
    for original in value['sender_inputs'].values():_est_host3(common,original)
    requests=value['authorization_requests']
    common._ep_exact(requests,{'NEG-01','NEG-02'},'both source-frozen authorization templates required')
    for request in requests.values():
        common._ep_pin(request)
        common._ep_need(20<=request['bytes']<=16000,'authorization template is out of bounds')
    common._ep_need(type(value['initialization_files']) is list and value['initialization_files']
        and type(value['new_artifacts']) is list and len(value['new_artifacts'])==2,
        'explicit initialization carrier and two new artifact sources required')
    for row in value['initialization_files']:
        common._ep_exact(row,{'role','origin','relative_path'},'fixed initialization carrier fields differ')
        common._ep_pin(row['origin']);common.relative(row['relative_path'])
    return value


def _est_host3(common, value):
    common._ep_pin(value)
    common._ep_need(set(value)=={'path','bytes','sha256'},'host origin must remain exact3')
    return value


def _est_body(common, value, *, maximum, expected=None):
    import base64
    common._ep_exact(value,{'original','body_base64'},'complete original body carrier required')
    original=value['original'];_est_host3(common,original)
    common._ep_need(original['bytes']<=maximum and type(value['body_base64']) is str,
        'bounded canonical body carrier required')
    raw=base64.b64decode(value['body_base64'],validate=True)
    common._ep_need(base64.b64encode(raw).decode()==value['body_base64']
        and common._ep_bare(raw)=={k:original[k] for k in ('bytes','sha256')},
        'body carrier differs from its complete original')
    if expected is not None:common._ep_need(common._ep_same(original,expected),'unapproved body origin')
    return raw


def epoch_operation_result_value(operation,result,request):
    common,_modules,_manifest,_raw,_bodies=_est_modules()
    common._ep_need(type(request) is dict and request.get('operation')==operation
        and operation in EPOCH_OPERATION_CONTEXT_FIELDS and type(result) is dict,
        'a result must name its finite actual operation')
    action=request['payload'].get('action')
    if action in ('read-original','read-chunk','read-result'):
        common._ep_exact(result,{'schema','state','original','offset','bytes','sha256','base64','eof'},
            'complete fixed read result required')
        common._ep_need(result['schema']=='hepta.native-guard.epoch-read-original-result.v1'
            and result['state']=='ACTUAL_FIXED_ORIGINAL_CHUNK_READ'
            and common._ep_same(result['original'],request['payload']['expected'])
            and type(result['offset']) is int and result['offset']==request['payload']['offset']
            and type(result['bytes']) is int and 0<=result['bytes']<=request['payload']['limit']
            and type(result['eof']) is bool,'fixed read result changed its actual request')
        import base64
        raw=base64.b64decode(result['base64'],validate=True)
        common._ep_need(base64.b64encode(raw).decode()==result['base64']
            and common._ep_bare(raw)=={k:result[k] for k in ('bytes','sha256')}
            and result['eof']==(result['offset']+len(raw)==result['original']['bytes']),
            'fixed read piece bytes or EOF differ')
        return result
    if action=='observe-phase':
        common._ep_exact(result,{'schema','state','phase','lease','originals','automatic_retry','component_qualified'},
            'complete actual phase observation result required')
        common._ep_need(operation=='witness-publish'
            and result['schema']=='hepta.native-guard.epoch-observe-phase-result.v1'
            and result['state']=='ACTUAL_FIXED_PHASE_ORIGINALS_OBSERVED'
            and result['phase']==request['payload']['phase']
            and common._ep_same(result['lease'],request['context']['lease'])
            and result['automatic_retry'] is False and result['component_qualified'] is False,
            'observed phase result differs')
        names={'ACCEPTED.json','BOUND-CONTRACT.json','ROOT-'+result['phase'].upper()+'-PLAN.json'}
        common._ep_exact(result['originals'],names,'all three actual phase originals required')
        for pin in result['originals'].values():common._ep_pin(pin,original=True)
        return result
    if operation=='allocate':
        common._ep_exact(result,EPOCH_ALLOCATION_RESULT_FIELDS,'complete actual allocation result required')
        common._ep_need(result['schema']=='hepta.native-guard.epoch-allocation-result.v1'
            and result['state']=='EXCLUSIVE_CLAIM_AND_IDENTITY_CREATED_NO_SCOPE_OR_LEASE'
            and result['epoch_id']==common.EPOCH_ID and result['boot_id']==request['boot_id']
            and type(result['ordinal']) is int and 1<=result['ordinal']<=8
            and result['case_id'] in ('NEG-01','NEG-02')
            and common.EPOCH_NONCE.fullmatch(result['nonce'])
            and common.EPOCH_LABEL.fullmatch(result['label'])
            and result['scope'] is None and result['lease'] is None
            and result['automatic_retry'] is False and result['component_qualified'] is False
            and result['business_qualified'] is False,'allocation cannot invent readiness, scope or lease')
        for key in ('claim','directory_binding','identity','owner_request','allocation_admission',
                'initialization','generation','prior_boundary'):common._ep_pin(result[key],original=True)
        common._ep_need(type(result['owner_request_utf8']) is str
            and common._ep_bare(result['owner_request_utf8'].encode('utf-8'))==
                {k:result['owner_request'][k] for k in ('bytes','sha256')},
            'allocation owner body differs from its actual original')
        return result
    if operation=='publish' and action=='publish':
        common._ep_exact(result,common.EPOCH_PUBLISH_RESULT_FIELDS,'complete native publication result required')
        common._ep_need(result['schema']=='hepta.native-guard.epoch-boundary-publish-result.v1'
            and result['state']=='ORIGINAL_EPOCH_NATIVE_BOUNDARY_AND_TERMINAL_PUBLISHED'
            and result['native_boundary_created'] is True and result['automatic_replay'] is False
            and result['business_qualified'] is False,'publication result semantics differ')
        return result
    kind='transfer' if action in ('publish-inputs','transfer-closure') else operation
    common._ep_exact(result,EPOCH_RESULT_FIELDS[kind],'operation-specific result fields differ')
    schema,state=EPOCH_RESULT_IDENTITIES[kind]
    common._ep_need(result['schema']==schema and result['state']==state
        and result['epoch_id']==common.EPOCH_ID and result['automatic_retry'] is False
        and result['component_qualified'] is False,'actual operation result identity differs')
    if 'ordinal' in result:
        common._ep_need(type(result['ordinal']) is int and 1<=result['ordinal']<=8,
            'actual result slot ordinal differs')
    for key in ('code_receipt','anchor','initialization','generation','root_authorization','lease',
            'stage_binding','stage_original','scope_binding','launch_authorization','role_launch_intent',
            'detached_intent','detached_result','publication','capture','archive','result','seal'):
        if key in result:common._ep_pin(result[key],original=True,maximum=64*1024*1024)
    if kind=='transfer':
        common._ep_need(type(result['originals']) is dict and result['originals'],
            'actual complete private transfer copies required')
        for copies in result['originals'].values():
            common._ep_exact(copies,{'gnu','android'},'both private copies required')
            for pin in copies.values():common._ep_pin(pin,original=True)
            common._ep_need(all(copies['gnu'][k]==copies['android'][k] for k in ('bytes','sha256')),
                'private transfer bodies differ')
    if kind=='launch':
        common._ep_need(result['supervisor_generation_inferred'] is False
            and result['readiness_asserted'] is False,'fork return cannot infer child readiness')
    if kind=='initialize':
        common._ep_need(result['business_qualified'] is False
            and type(result['nonces_generated']) is int and result['nonces_generated']==0
            and type(result['native_calls']) is int and result['native_calls']==0,
            'registry initialization cannot create a case or report a native action')
    return result


def _est_auxiliary(name, *, budget_check):
    import types
    common,modules,_manifest,manifest_raw,bodies=_est_modules(budget_check=budget_check)
    dependencies={'native_guard_session_r2':(), 'component_listener':('native_guard_session_r2',),
        'witness_bundle':('component_listener',),
        'root_fixture_once':('witness_bundle',),
        'root_fixture_originals':('root_fixture_once',),
        'close_component':('root_fixture_originals',)}
    common._ep_need(name in dependencies,'auxiliary module is outside the fixed existing32 set')
    for required in dependencies[name]:_est_auxiliary(required,budget_check=budget_check)
    member='source/'+name+'.py';body=bodies[member];context=common.epoch_actual_context(globals())
    existing=sys.modules.get(name)
    if existing is not None:
        common._ep_need(existing.__dict__.get('__reviewed_package_sources__') is bodies
            and existing.__dict__.get('__reviewed_package_manifest_raw__')==manifest_raw
            and existing.__dict__.get('__reviewed_source_sha256__')==common._ep_sha(body)
            and common.epoch_actual_context(existing.__dict__)==context,
            'foreign auxiliary module cannot be reused')
        return existing
    physical=globals().get('__reviewed_package_physical_observation__')
    actual_path=(physical[member]['path'] if type(physical) is dict and member in physical
        else str(Path(__file__).parent/(name+'.py')))
    module=types.ModuleType(name);module.__file__=actual_path
    module.__dict__.update(__actual_context__=context,__reviewed_package_sources__=bodies,
        __reviewed_package_manifest_raw__=manifest_raw,__reviewed_source_sha256__=common._ep_sha(body),
        __reviewed_package_physical_observation__=physical,__epoch_budget_check__=budget_check)
    old_path=list(sys.path);sys.modules[name]=module
    try:
        budget_check();exec(compile(body,actual_path,'exec'),module.__dict__);budget_check()
    except BaseException:
        sys.modules.pop(name,None);raise
    finally:sys.path[:]=old_path
    return module


def epoch_prepare_material(plan_raw,allocation,*,budget_check):
    common,_modules,_manifest,_raw,_bodies=_est_modules(budget_check=budget_check)
    common._ep_need(common.epoch_actual_context(globals())=='mac','actual Mac materialization context required')
    module=_est_auxiliary('native_guard_session_r2',budget_check=budget_check)
    return module.epoch_host_prepare_material(plan_raw,allocation,common=common,
        stage=sys.modules['stage_component'],budget_check=budget_check)


def epoch_auxiliary_module(name,*,budget_check):
    return _est_auxiliary(name,budget_check=budget_check)


def epoch_installed_artifact_path(path):
    common,modules,_manifest,_raw,_bodies=_est_modules()
    return any(row['path']==path for row in modules['component_lifecycle'].EPOCH_INSTALLED_ARTIFACT_ALLOWANCE)


def epoch_installed_original_value(original,raw):
    common,modules,_manifest,_raw,_bodies=_est_modules()
    common._ep_pin(original,original=True)
    rows=[row for row in modules['component_lifecycle'].EPOCH_INSTALLED_ARTIFACT_ALLOWANCE
        if row['path']==original['path']]
    common._ep_need(len(rows)==1,'no source-fixed new artifact allowance for this path')
    expected=rows[0];metadata=original['metadata']
    common._ep_need(common._ep_bare(raw)=={k:expected[k] for k in ('bytes','sha256')}
        =={k:original[k] for k in ('bytes','sha256')}
        and metadata[3:6]==[expected['uid'],expected['gid'],1]
        and stat.S_IMODE(metadata[2])==expected['mode'],
        'new artifact full original differs from the one source-fixed body and metadata rule')
    return original


def epoch_initialization_extra_value(value,index,originals):
    common,modules,_manifest,manifest_raw,bodies=_est_modules()
    binding=_est_binding(common);receipt=value['code_receipt']
    raw=common._ep_manifest_raw(receipt,index,originals);code=common.strict(raw)
    common._ep_need(receipt['path']==common.EPOCH_REGISTRY_ROOT+'/code/01/BOOTSTRAP-CODE.json'
        and code.get('schema')=='hepta.native-guard.epoch-code-bootstrap-record.v1'
        and code.get('epoch_id')==common.EPOCH_ID and code.get('boot_id')==binding['boot_id']
        and common._ep_same(code.get('root_template'),binding['root_template'])
        and common._ep_same(code.get('bridge_template'),binding['bridge_template']),
        'initialization changed the actual installed code origin')
    files=code.get('files');common._ep_need(type(files) is list and len(files)==34,
        'actual MF32 and bridge installed originals required')
    paths=set()
    for row in files:
        common._ep_pin(row,original=True);common._ep_need(row['path'] not in paths,'installed source repeats')
        paths.add(row['path']);body=common._ep_manifest_raw(row,index,originals)
        root=common.EPOCH_REGISTRY_ROOT+'/code/01/package/'
        if row['path']==root+'MANIFEST.json':common._ep_need(body==manifest_raw,'installed code MF changed')
        elif row['path'].startswith(root):
            member=row['path'][len(root):]
            common._ep_need(member in bodies and body==bodies[member],'installed source body differs')
        else:common._ep_need(row['path']==common.EPOCH_REGISTRY_ROOT+'/code/01/phone_chain_bridge.py',
            'unapproved installed source member')
    required={common.EPOCH_REGISTRY_ROOT+'/code/01/package/'+member for member in bodies}
    required.update((common.EPOCH_REGISTRY_ROOT+'/code/01/package/MANIFEST.json',
        common.EPOCH_REGISTRY_ROOT+'/code/01/phone_chain_bridge.py'))
    common._ep_need(paths==required,'installed code closure is not the complete actual32')
    allowed=modules['component_lifecycle'].EPOCH_INSTALLED_ARTIFACT_ALLOWANCE
    rows=value['installed_artifacts'];common._ep_need(type(rows) is list and len(rows)==2,
        'both actually installed bounded artifacts required')
    for row,expected in zip(rows,allowed):
        common._ep_exact(row,{'role','path','presence','original'},'installed artifact phase row differs')
        common._ep_need(row['role']==expected['role'] and row['path']==expected['path']
            and row['presence']=='present','initialization cannot adopt an absent or other artifact')
        epoch_installed_original_value(row['original'],common._ep_manifest_raw(row['original'],index,originals))
    history=value['history_carriers']
    expected=[row for row in binding['initialization_files'] if row['role'].startswith('history-')]
    common._ep_need(type(history) is list and len(history)==len(expected),'complete fixed history carrier set required')
    for actual,fixed in zip(history,expected):
        common._ep_exact(actual,{'role','origin','carrier'},'history origin/carrier pair differs')
        common._ep_need(actual['role']==fixed['role'] and common._ep_same(actual['origin'],fixed['origin'])
            and actual['carrier']['path']==common.EPOCH_REGISTRY_ROOT+'/initialization/carriers/'+fixed['role']+'.original'
            and all(actual['carrier'][k]==fixed['origin'][k] for k in ('bytes','sha256')),
            'history carrier borrowed an origin path/metadata or changed its body')
        common._ep_manifest_raw(actual['carrier'],index,originals)
    common._ep_need(common._ep_same(value['retained_failed_native_branches'],
        epoch_retained_branch_records(history,index,originals)),
        'the separately retained failed native branch is not bound to its complete actual carriers')
    return value


def epoch_allocation_plan_value(plan_raw):
    common,_modules,_manifest,_raw,_bodies=_est_modules()
    binding=_est_binding(common);plan=common.strict(plan_raw)
    common._ep_exact(plan,EPOCH_ALLOCATION_PLAN_FIELDS,'exact pre-nonce allocation plan required')
    common._ep_need(plan['schema']=='hepta.native-guard.epoch-root-allocation-plan.v1'
        and plan['epoch_id']==common.EPOCH_ID and plan['boot_id']==binding['boot_id']
        and plan['case_id'] in ('NEG-01','NEG-02'),'allocation plan identity differs')
    for key in ('combination','shared_materials'):
        common._ep_need(common._ep_same(plan[key],binding[key]),'allocation source identity differs: '+key)
    for key in ('runtime','pure_verifier','derivation'):
        _est_host3(common,plan[key])
        common._ep_need(plan[key]['path']==binding['source_paths'][key],'fixed current source origin differs')
    common._ep_need(common._ep_bare(_raw)=={k:plan['runtime'][k] for k in ('bytes','sha256')},
        'allocation runtime is not the actual original loaded MF')
    _est_host3(common,plan['root_source_manifest'])
    for key in ('code_receipt','initialization','generation','root_authorization'):
        common._ep_pin(plan[key],original=True)
    for key in ('selected_session_id','selected_profile_id'):
        text=plan[key]
        common._ep_need(type(text) is str and 0<len(text.encode('utf-8'))<=256 and '\x00' not in text,
            'explicit actual selected native identity required')
    request=plan['authorization_request']
    common._ep_exact(request,{'origin','utf8'},'authorization origin and complete UTF8 template required')
    common._ep_need(common._ep_same(request['origin'],binding['authorization_requests'][plan['case_id']])
        and type(request['utf8']) is str,'source-frozen case authorization required')
    raw=request['utf8'].encode('utf-8')
    common._ep_need(common._ep_bare(raw)=={k:request['origin'][k] for k in ('bytes','sha256')}
        and 20<=len(raw)<=16000 and b'\x00' not in raw
        and request['utf8'].count('{{EPOCH_NONCE}}')==1,
        'preclaim authorization must contain exactly the reviewed nonce substitution')
    common._ep_need(plan['host_out']==binding['host_out'],'fixed new host output root differs')
    common._ep_exact(plan['sender_inputs'],{'previous','preserved_draft','retirement_resolution'},
        'complete original sender inputs are required before allocation')
    common._ep_need(common._ep_same(plan['sender_inputs'],binding['sender_inputs']),
        'allocation changed the fixed original sender input set')
    return plan


def epoch_initialize_plan_value(plan_raw):
    common,_modules,_manifest,_raw,_bodies=_est_modules()
    binding=_est_binding(common);plan=common.strict(plan_raw)
    common._ep_exact(plan,EPOCH_INITIALIZE_PLAN_FIELDS,'exact pre-initialization plan required')
    common._ep_need(plan['schema']=='hepta.native-guard.epoch-root-code-initialize-plan.v1'
        and plan['epoch_id']==common.EPOCH_ID and plan['boot_id']==binding['boot_id']
        and plan['host_out']==binding['host_out'],'initialization plan identity differs')
    for key in ('combination','shared_materials','bootstrap_plan','root_authorization','initialization_inputs'):
        common._ep_need(common._ep_same(plan[key],binding[key]),'initialization source identity differs: '+key)
    for key in ('runtime','pure_verifier','derivation'):
        _est_host3(common,plan[key])
        common._ep_need(plan[key]['path']==binding['source_paths'][key],'fixed current source origin differs')
    common._ep_need(common._ep_bare(_raw)=={k:plan['runtime'][k] for k in ('bytes','sha256')},
        'initialization runtime is not the actual original loaded MF')
    _est_host3(common,plan['root_source_manifest'])
    return plan


def epoch_operation_request_value(request, *, request_raw, code_observation, budget_check):
    common,modules,manifest,manifest_raw,bodies=_est_modules(phone=True,budget_check=budget_check)
    binding=_est_binding(common)
    common._ep_exact(request,{'schema','epoch_id','operation','boot_id','runtime','context','payload'},
        'exact finite epoch operation request required')
    operation=request['operation']
    common._ep_need(request['schema']=='hepta.native-guard.epoch-operation-request.v1'
        and request['epoch_id']==common.EPOCH_ID and request['boot_id']==binding['boot_id']
        and operation in EPOCH_OPERATION_CONTEXT_FIELDS
        and request['runtime']['path']==binding['source_paths']['runtime']
        and type(request_raw) is bytes and common._ep_same(common.strict(request_raw),request),
        'operation is not bound to the actual complete stdin original')
    context=request['context'];context_fields=EPOCH_OPERATION_CONTEXT_FIELDS[operation]
    if operation=='allocate' and type(request['payload']) is dict and request['payload'].get('action')=='read-original':
        context_fields=context_fields+('reservation','identity')
    common._ep_exact(context,context_fields,
        'operation has missing or future context originals')
    for original in context.values():common._ep_pin(original,original=True)
    common._ep_exact(code_observation,{'schema','actual_context','code_receipt','runtime_manifest',
        'sources','source_directories','bridge_source','root_source_manifest_origin','root_template',
        'bridge_template','source_action_authority_verified_here'},'actual code loader observation required')
    common._ep_need(code_observation['schema']=='hepta.native-guard.epoch-installed-code-observation.v1'
        and code_observation['actual_context']=='phone'
        and code_observation['source_action_authority_verified_here'] is False
        and common._ep_same(context['code_receipt'],code_observation['code_receipt'])
        and common._ep_bare(manifest_raw)=={k:request['runtime'][k] for k in ('bytes','sha256')},
        'actual installed code differs from the frozen generation')
    physical=globals().get('__reviewed_package_physical_observation__')
    common._ep_need(type(physical) is dict and common._ep_same(physical,code_observation['sources'])
        and set(physical)==set(bodies),'all32 actual source descriptors are required')
    package=common.EPOCH_REGISTRY_ROOT+'/code/01/package/'
    for name,raw in bodies.items():
        row=physical[name];common._ep_pin(row,original=True)
        common._ep_need(row['path']==package+name
            and common._ep_bare(raw)=={k:row[k] for k in ('bytes','sha256')},
            'installed source descriptor/body/path differs')
    modules['component_lifecycle'].native_root(binding['boot_id']);budget_check()
    return common,modules,binding


def epoch_source_location(namespace, package_path, member, package_sha256):
    common,_modules,_manifest,manifest_raw,bodies=_est_modules()
    common._ep_need(type(namespace) is dict and member in bodies
        and common._ep_sha(manifest_raw)==package_sha256
        and namespace.get('__reviewed_package_manifest_raw__')==manifest_raw
        and namespace.get('__reviewed_package_sources__') is bodies
        and namespace.get('__reviewed_source_sha256__')==common._ep_sha(bodies[member]),
        'source entry is not the current complete reviewed package')
    actual=Path(namespace.get('__file__',''));case_package=Path(package_path)
    installed=Path(common.EPOCH_REGISTRY_ROOT)/'code/01/package'/member
    common._ep_need(actual in (installed,case_package.parent/member),
        'actual source path is neither the fixed installed code nor this exact staged case')
    physical=namespace.get('__reviewed_package_physical_observation__')
    if actual==installed:
        common._ep_need(type(physical) is dict and member in physical,'physical installed source observation missing')
        common._ep_need(common.epoch_read_original(physical[member])==bodies[member],
            'actual installed source changed')
    else:
        common._ep_need(common.read(actual,131072)==bodies[member],'actual staged source changed')
    common._ep_need(common.read(case_package,262144)==manifest_raw,'actual case MF differs')
    return {'path':str(actual),'bytes':len(bodies[member]),'sha256':common._ep_sha(bodies[member])}


def epoch_lifecycle_load_lease(home, pin, *, require_live=True):
    common,_modules,_manifest,manifest_raw,_bodies=_est_modules(phone=True)
    home=common.private_dir(Path(home));raw=common.read(home/'LEASE.json',262144)
    common._ep_need(common._ep_sha(raw)==pin,'actual immutable epoch lease hash differs')
    lease=common.strict(raw)
    common._ep_exact(lease,{'schema','label','boot_id','case_id','nonce','owner_request_sha256',
        'selected_session_id','selected_profile_id','expires_unix_ms','combination','retirement',
        'prior_boundary','android_journal','package_sha256','epoch'},'complete epoch lease required')
    epoch=common.epoch_lease_protocol_value(lease)
    common._ep_need(home==common.BASE/'native-guard-r10-r1'/lease['label']
        and lease['case_id'] in ('NEG-01','NEG-02')
        and type(lease['nonce']) is str and common.EPOCH_NONCE.fullmatch(lease['nonce'])
        and type(lease['label']) is str and common.EPOCH_LABEL.fullmatch(lease['label'])
        and lease['boot_id']==common.epoch_binding_value()['boot_id']
        and lease['package_sha256']==common._ep_sha(manifest_raw)
        and lease['android_journal']==str(common.ANDROID_BASE/'native-guard-r10-r1'/lease['label']/'executor'),
        'epoch lease path, boot, case or actual package differs')
    identity=common.strict(common.epoch_read_original(epoch['identity']))
    reservation=common.strict(common.epoch_read_original(epoch['reservation']))
    common.epoch_identity_value(identity,reservation,epoch['reservation'],
        forbidden_nonces=common.epoch_forbidden_nonces())
    common._ep_need(all(common._ep_same(lease[key],identity[key]) for key in (
        'label','boot_id','case_id','nonce','selected_session_id','selected_profile_id','prior_boundary')),
        'epoch lease changed actual durable identity')
    owner=common.read(home/'owner-request.txt',16000)
    common._ep_need(20<=len(owner)<=16000 and b'\x00' not in owner
        and owner.decode('utf-8').count(lease['nonce'])==1
        and common._ep_sha(owner)==lease['owner_request_sha256']
        and owner==common.epoch_read_original(identity['owner_request']),
        'actual original owner request differs')
    common._ep_need(type(lease['expires_unix_ms']) is int and lease['expires_unix_ms']>0,
        'epoch lease deadline type differs')
    if require_live:
        common._ep_need(0<lease['expires_unix_ms']-time.time_ns()//1000000<=600000,
            'epoch lease expired or exceeds the original600s bound')
    return lease,raw


def epoch_lifecycle_verify_retired(lease, *, budget_check):
    common,modules,_manifest,_raw,_bodies=_est_modules(phone=True,budget_check=budget_check)
    common.epoch_lease_protocol_value(lease)
    stage=modules['stage_component']
    class CurrentEpoch:
        def verify_current(self, observed, *, combination_sha256, package_sha256):
            common._ep_need(common._ep_same(observed,lease)
                and combination_sha256==lease['combination']['sha256']
                and package_sha256==lease['package_sha256'],'retirement callback changed actual lease')
            return stage.epoch_current_admission(lease,budget_check=budget_check)
    budget_check()
    lock,proof=modules['component_lifecycle'].verify_retired(lease,late_boundary_module=CurrentEpoch())
    try:
        budget_check()
        common._ep_need(type(lock) is int and lock>=0 and type(proof) is dict
            and proof['old_journal_lock_held_without_writing'] is True
            and proof['old_preserved_state_equal_before_new_actions'] is False,
            'actual legacy read-only lock and new-domain proof required')
        return lock,proof
    except BaseException:
        os.close(lock);raise


class _ESTOriginals:
    def __init__(self, common, budget_check):
        self.c=common;self.check=budget_check;self.bytes_read=0;self.bytes_written=0
        self.files={};self.reads=[];self.writes=[];self.directories={};self.file_private={}
        common._ep_need(callable(budget_check),'enclosing operation budget required')

    def directory(self,path):
        self.check();row=self.c.epoch_read_directory(path);self.check()
        self.directories[row['path']]=row
        return row

    def read(self,path,*,expected=None,maximum=16*1024*1024,private=True):
        c=self.c;self.check();path=str(c._ep_path(path));chain,name=c._ep_parent_chain(path);fd=None
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=chain[-1][0])
            first=c._ep_metadata(os.fstat(fd))
            c._ep_need(stat.S_ISREG(first[2]) and first[5]==1 and 0<=first[6]<=maximum
                and first[6]<=64*1024*1024-self.bytes_read,'bounded complete operation original required')
            if private:c._ep_need(first[3:6]==[0,0,1] and stat.S_IMODE(first[2])==0o600,
                'operation original must be private root-owned regular data')
            if expected is not None:
                c._ep_pin(expected,original=True,maximum=maximum)
                c._ep_need(expected['path']==path and expected['metadata']==first,
                    'operation original differs before reading')
            self.bytes_read+=first[6];parts=[];left=first[6]+1
            while left:
                self.check();part=os.read(fd,min(65536,left))
                if not part:break
                parts.append(part);left-=len(part)
            raw=b''.join(parts)
            c._ep_need(len(raw)==first[6] and first==c._ep_metadata(os.fstat(fd))
                ==c._ep_metadata(os.stat(name,dir_fd=chain[-1][0],follow_symlinks=False))
                ==c._ep_metadata(Path(path).lstat()),'operation original full9 changed')
            c._ep_chain_check(chain,metadata_unchanged=True);self.check()
            pin={'path':path,**c._ep_bare(raw),'metadata':first}
            if expected is not None:c._ep_need(c._ep_same(pin,expected),'operation whole original SHA differs')
            if path in self.files:c._ep_need(c._ep_same(self.files[path],pin),'original changed between operation reads')
            self.files[path]=pin;self.reads.append(pin);self.file_private[path]=private
            return pin,raw
        finally:
            if fd is not None:os.close(fd)
            for item in reversed(chain):os.close(item[0])

    def absent(self,path):
        c=self.c;self.check();path=str(c._ep_path(path));chain,name=c._ep_parent_chain(path)
        try:
            parent=c._ep_metadata(os.fstat(chain[-1][0]));names=sorted(os.listdir(chain[-1][0]))
            c._ep_need(len(names)<=20000 and name not in names,'one-use destination already present')
            for _ in range(2):
                try:os.stat(name,dir_fd=chain[-1][0],follow_symlinks=False)
                except OSError as error:c._ep_need(error.errno==2,'destination absence unknown')
                else:c._ep_need(False,'one-use destination appeared')
            c._ep_need(parent==c._ep_metadata(os.fstat(chain[-1][0]))
                and sorted(os.listdir(chain[-1][0]))==names,'absence parent changed')
            c._ep_chain_check(chain,metadata_unchanged=True);self.check()
            return {'path':path,'absence':'ENOENT','parent':{'path':str(Path(path).parent),
                'metadata':parent,'names':names},'positive_enoent_checks':2}
        finally:
            for item in reversed(chain):os.close(item[0])

    def mkdir(self,path,*,expected_parent):
        c=self.c;self.check();path=str(c._ep_path(path));chain,name=c._ep_parent_chain(path);fd=None
        try:
            before={'path':str(Path(path).parent),'metadata':c._ep_metadata(os.fstat(chain[-1][0])),
                'names':sorted(os.listdir(chain[-1][0]))}
            c._ep_need(c._ep_same(before,expected_parent) and name not in before['names'],
                'new directory parent changed or destination already exists')
            c._ep_chain_check(chain,metadata_unchanged=True)
            os.mkdir(name,mode=0o700,dir_fd=chain[-1][0]);os.fsync(chain[-1][0])
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=chain[-1][0])
            first=c._ep_metadata(os.fstat(fd))
            c._ep_need(first[3:5]==[0,0] and stat.S_IMODE(first[2])==0o700
                and sorted(os.listdir(fd))==[] and first==c._ep_metadata(os.stat(name,
                    dir_fd=chain[-1][0],follow_symlinks=False)), 'new directory initial actual identity differs')
            after={'path':before['path'],'metadata':c._ep_metadata(os.fstat(chain[-1][0])),
                'names':sorted(os.listdir(chain[-1][0]))}
            c._ep_need(after['metadata'][:5]==before['metadata'][:5]
                and after['names']==sorted(before['names']+[name]),'unowned directory membership change')
            c._ep_chain_check(chain);self.check()
            row={'path':path,'metadata':first,'names':[]};self.directories[path]=row
            self.directories[before['path']]=after
            self.writes.append({'kind':'directory','path':path,'first_observed_metadata':first,
                'mkdir_inode_observed_atomically':False,'parent_before':before,'parent_after':after})
            return row
        finally:
            if fd is not None:os.close(fd)
            for item in reversed(chain):os.close(item[0])

    def write(self,path,raw,*,maximum,expected_parent):
        c=self.c;self.check();path=str(c._ep_path(path))
        c._ep_need(type(raw) is bytes and 0<=len(raw)<=maximum
            and len(raw)<=16*1024*1024-self.bytes_written,'prewrite operation body pool exceeded')
        chain,name=c._ep_parent_chain(path);fd=None
        try:
            before={'path':str(Path(path).parent),'metadata':c._ep_metadata(os.fstat(chain[-1][0])),
                'names':sorted(os.listdir(chain[-1][0]))}
            c._ep_need(c._ep_same(before,expected_parent) and name not in before['names'],
                'actual append-only parent or new original differs')
            c._ep_need(before['metadata'][3:5]==[0,0]
                and stat.S_IMODE(before['metadata'][2])==0o700,'private owned output parent required')
            c._ep_chain_check(chain,metadata_unchanged=True)
            self.bytes_written+=len(raw)
            fd=os.open(name,os.O_RDWR|os.O_NONBLOCK|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                0o600,dir_fd=chain[-1][0])
            initial=c._ep_metadata(os.fstat(fd))
            c._ep_need(stat.S_ISREG(initial[2]) and initial[3:6]==[0,0,1]
                and stat.S_IMODE(initial[2])==0o600,'new original type/owner/mode differs')
            offset=0
            while offset<len(raw):
                self.check();count=os.write(fd,raw[offset:offset+65536]);c._ep_need(count>0,'short original write')
                offset+=count
            os.fsync(fd);os.fsync(chain[-1][0]);final=c._ep_metadata(os.fstat(fd))
            c._ep_need(final[:6]==initial[:6] and final[6]==len(raw)
                and final==c._ep_metadata(os.stat(name,dir_fd=chain[-1][0],follow_symlinks=False)),
                'new original was substituted during write')
            os.lseek(fd,0,os.SEEK_SET);parts=[];left=len(raw)+1
            c._ep_need(len(raw)<=64*1024*1024-self.bytes_read,'new output readback pool exceeded')
            self.bytes_read+=len(raw)
            while left:
                self.check();part=os.read(fd,min(65536,left))
                if not part:break
                parts.append(part);left-=len(part)
            c._ep_need(b''.join(parts)==raw and final==c._ep_metadata(os.fstat(fd))
                ==c._ep_metadata(Path(path).lstat()),'new original complete readback changed')
            after={'path':before['path'],'metadata':c._ep_metadata(os.fstat(chain[-1][0])),
                'names':sorted(os.listdir(chain[-1][0]))}
            c._ep_need(after['metadata'][:5]==before['metadata'][:5]
                and after['names']==sorted(before['names']+[name]),'unexpected append-only directory change')
            c._ep_chain_check(chain);self.check()
            pin={'path':path,**c._ep_bare(raw),'metadata':final};self.files[path]=pin
            self.writes.append({'kind':'file','original':pin,'parent_before':before,'parent_after':after})
            self.directories[before['path']]=after
            return pin
        finally:
            if fd is not None:os.close(fd)
            for item in reversed(chain):os.close(item[0])

    def recheck(self):
        c=self.c
        for pin in list(self.files.values()):
            self.read(pin['path'],expected=pin,maximum=max(16*1024*1024,pin['bytes']),
                private=self.file_private.get(pin['path'],True))
        for path,expected in list(self.directories.items()):
            c._ep_need(c._ep_same(c.epoch_read_directory(path),expected),'owned directory final bookend differs')
        self.check()


def _est_context_identity(common,request,io,*,require_lease=False):
    context=request['context'];identity_pin=context.get('identity')
    common._ep_need(identity_pin is not None,'actual allocation identity is required')
    identity=common.strict(io.read(identity_pin['path'],expected=identity_pin)[1])
    reservation_pin=context['reservation'];reservation=common.strict(io.read(
        reservation_pin['path'],expected=reservation_pin)[1])
    common.epoch_identity_value(identity,reservation,reservation_pin,
        forbidden_nonces=common.epoch_forbidden_nonces())
    ordinal=identity['ordinal'];slot=common.EPOCH_REGISTRY_ROOT+'/slots/%02d/'%ordinal
    common._ep_need(identity_pin['path']==slot+'IDENTITY.json'
        and reservation_pin['path']==common.EPOCH_REGISTRY_ROOT+'/slots/%02d.CLAIM.json'%ordinal
        and context['initialization']['path']==common.EPOCH_REGISTRY_ROOT+'/INITIALIZATION.json',
        'operation identity escaped its fixed registry originals')
    common._ep_need(common._ep_same(identity['source_generation'],context['generation'])
        and identity['boot_id']==request['boot_id'],'operation changed actual identity source/boot')
    lease=None
    if require_lease:
        pin=context.get('lease');common._ep_pin(pin,original=True)
        raw=io.read(pin['path'],expected=pin,maximum=262144)[1]
        lease=common.strict(raw);common.epoch_lease_protocol_value(lease)
        common._ep_need(pin['path']==str(common.BASE/'native-guard-r10-r1'/identity['label']/'LEASE.json')
            and common._ep_same(lease['epoch']['identity'],identity_pin)
            and lease['nonce']==identity['nonce'],'operation lease belongs to another actual slot')
    return identity,reservation,lease


def _est_read_paths(common,operation,identity):
    slot=common.EPOCH_REGISTRY_ROOT+'/slots/%02d/'%identity['ordinal']
    home=str(common.BASE/'native-guard-r10-r1'/identity['label'])+'/'
    captures=str(common.BASE/'native-guard-snapshots-r10-r1'/(identity['label']+'-capture-01'))+'/'
    allowed={name:slot+name for name in ('DIRECTORY-BINDING.json','IDENTITY.json',
        'owner-request.original.txt','ALLOCATION-ADMISSION.json','ADMISSION.json','STAGE.json',
        'SCOPE-BINDING.json','LAUNCH.json','BOUNDARY.json','CLOSURE.json','AFTER-INVENTORY.json','COMMIT.json')}
    allowed['CLAIM.json']=common.EPOCH_REGISTRY_ROOT+'/slots/%02d.CLAIM.json'%identity['ordinal']
    prior=identity['prior_boundary']
    fixed=common.epoch_binding_value()
    historical={row['path']:row for row in fixed['fixed_inputs']}
    if identity['ordinal']==1:
        common._ep_need(prior['path'] in historical and common._ep_same(prior,historical[prior['path']]),
            'first slot predecessor is not a fixed actual historical original')
    else:
        common._ep_need(prior['path']==common.EPOCH_REGISTRY_ROOT+'/slots/%02d/BOUNDARY.json'%(identity['ordinal']-1),
            'later slot predecessor is not the immediately preceding actual published boundary')
    allowed['PRIOR-BOUNDARY.json']=prior['path']
    for name in ('LEASE.json','ACCEPTED.json','BOUND-CONTRACT.json','STAGE-COMPLETE.json',
            'RETIRED-BASELINE-VERIFIED.json','DETACHED-LAUNCH.json','LIFECYCLE-ENDED.json',
            'LIFECYCLE-FAILURE.json','PROVIDER-ENDED.json','OWNED-OUTPUTS.json'):
        allowed[name]=home+name
    for phase in EPOCH_PHASES:allowed['ROOT-'+phase.upper()+'-PLAN.json']=home+'ROOT-'+phase.upper()+'-PLAN.json'
    if operation=='snapshot':
        for name in ('CAPTURE.json','ORIGINALS.tar.gz','RESULT.json','PARTIAL-CAPTURE.json'):
            allowed[name]=captures+name
    if operation=='seal':allowed['SEALED.json']=common.EPOCH_REGISTRY_ROOT+'/SEALED.json'
    return allowed


def epoch_read_operation(request, *, budget_check):
    import base64
    common,_modules,_manifest,_raw,_bodies=_est_modules(phone=True,budget_check=budget_check)
    payload=request['payload']
    common._ep_exact(payload,{'schema','action','name','offset','limit','expected'},'fixed original chunk request required')
    common._ep_need(payload['schema']=='hepta.native-guard.epoch-read-original-payload.v1'
        and payload['action'] in ('read-original','read-chunk','read-result')
        and type(payload['offset']) is int and payload['offset']>=0
        and type(payload['limit']) is int and 1<=payload['limit']<=32768,
        'fixed read action, integer offset and bounded chunk required')
    io=_ESTOriginals(common,budget_check);identity,_reservation,_lease=_est_context_identity(common,request,io)
    allowed=_est_read_paths(common,request['operation'],identity);pin=payload['expected']
    common._ep_pin(pin,original=True,maximum=64*1024*1024)
    common._ep_need(payload['name'] in allowed and pin['path']==allowed[payload['name']]
        and payload['offset']<=pin['bytes'],'read escaped exact actual slot/case original')
    chain,name=common._ep_parent_chain(pin['path']);fd=None
    try:
        budget_check();fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=chain[-1][0])
        before=common._ep_metadata(os.fstat(fd))
        common._ep_need(before==pin['metadata'] and stat.S_ISREG(before[2])
            and before[3:6]==[0,0,1] and stat.S_IMODE(before[2])==0o600,
            'fixed read original changed its complete physical identity')
        count=min(payload['limit'],pin['bytes']-payload['offset'])
        raw=os.pread(fd,count,payload['offset'])
        common._ep_need(len(raw)==count and before==common._ep_metadata(os.fstat(fd))
            ==common._ep_metadata(os.stat(name,dir_fd=chain[-1][0],follow_symlinks=False))
            ==common._ep_metadata(Path(pin['path']).lstat()),'fixed original changed during chunk read')
        common._ep_chain_check(chain,metadata_unchanged=True);budget_check()
        return {'schema':'hepta.native-guard.epoch-read-original-result.v1',
            'state':'ACTUAL_FIXED_ORIGINAL_CHUNK_READ','original':pin,'offset':payload['offset'],
            'bytes':len(raw),'sha256':common._ep_sha(raw),'base64':base64.b64encode(raw).decode(),
            'eof':payload['offset']+len(raw)==pin['bytes']}
    finally:
        if fd is not None:os.close(fd)
        for item in reversed(chain):os.close(item[0])


def epoch_observe_phase(request, *, budget_check):
    common,_modules,_manifest,_raw,_bodies=_est_modules(phone=True,budget_check=budget_check)
    payload=request['payload'];common._ep_exact(payload,{'schema','action','phase'},'fixed phase observation required')
    common._ep_need(request['operation']=='witness-publish'
        and payload['schema']=='hepta.native-guard.epoch-observe-phase-payload.v1'
        and payload['action']=='observe-phase' and payload['phase'] in EPOCH_PHASES,
        'unreviewed phase observation')
    io=_ESTOriginals(common,budget_check);identity,_reservation,lease=_est_context_identity(
        common,request,io,require_lease=True)
    home=common.BASE/'native-guard-r10-r1'/identity['label']
    names=('ACCEPTED.json','BOUND-CONTRACT.json','ROOT-'+payload['phase'].upper()+'-PLAN.json')
    while True:
        budget_check();common._ep_need(time.time_ns()//1000000<lease['expires_unix_ms'],'phase lease expired')
        try:Path(home/names[-1]).lstat();break
        except OSError as error:common._ep_need(error.errno==2,'phase original existence unknown')
        for name in ('LIFECYCLE-FAILURE.json','LIFECYCLE-ENDED.json','PROVIDER-ENDED.json'):
            try:Path(home/name).lstat()
            except OSError as error:common._ep_need(error.errno==2,'end original existence unknown')
            else:common._ep_need(False,'component ended before the actual requested phase')
        time.sleep(0.1)
    rows={};values={}
    for name in names:
        pin,raw=io.read(home/name,maximum=65536);rows[name]=pin;values[name]=common.strict(raw)
    accepted=values[names[0]];bound=values[names[1]];plan=values[names[2]]
    common.scope(accepted['scope'])
    common._ep_need(bound['contract']['nonce']==identity['nonce']
        and bound['lease_sha256']==request['context']['lease']['sha256']
        and common._ep_sha(common.encoded(bound['contract']))==accepted['contract_sha256']
        and plan['phase']==payload['phase'] and common._ep_same(plan['scope'],accepted['scope'])
        and plan['contract_sha256']==accepted['contract_sha256'],'actual phase scope/contract differs')
    io.recheck()
    return {'schema':'hepta.native-guard.epoch-observe-phase-result.v1',
        'state':'ACTUAL_FIXED_PHASE_ORIGINALS_OBSERVED','phase':payload['phase'],
        'lease':request['context']['lease'],'originals':rows,'automatic_retry':False,
        'component_qualified':False}

# BEGIN PLAIN EPOCH OPERATION IMPLEMENTATIONS
_EST_CHILD_BOOTSTRAP = "import hashlib,json,os,re,stat,sys,time,types\nfrom pathlib import Path\ndef need(value,reason):\n if not value:raise ValueError(reason)\ndef pairs(items):\n out={}\n for key,value in items:\n  need(key not in out,'duplicate JSON key');out[key]=value\n return out\ndef strict(raw):\n return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))\ndef meta(s):\n return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]\nneed(len(sys.argv)==6,'fixed lifecycle bootstrap argv required')\npackage,pin,operation=sys.argv[1:4];arguments=strict(sys.argv[4]);expiry=int(sys.argv[5])\nneed(re.fullmatch(r'/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/[a-z0-9][a-z0-9-]{5,55}/package/MANIFEST.json',package)\n and re.fullmatch('[0-9a-f]{64}',pin) and operation in ('supervise','provider','sidecar','listener')\n and type(arguments) is list and len(arguments)<=13 and all(type(x) is str and '\\0' not in x for x in arguments),\n 'fixed actual case package and finite lifecycle operation required')\nneed(os.getuid()==os.getgid()==0 and 0<expiry-time.time_ns()//1000000<=600000,'actual bounded root lease required')\nstart=time.monotonic();booting=True\ndef check():\n need(time.time_ns()//1000000<expiry,'actual lifecycle lease expired')\n if booting:need(time.monotonic()-start<15,'whole-source first-exec bootstrap exceeded15 seconds')\ncheck()\nroot=str(Path(package).parent);seen={};dirs={};physical_bytes=0;file_reads=0;peak_fds=0\ndef parent(path):\n global peak_fds\n p=Path(path);need(p.is_absolute() and str(p)==path and '..' not in p.parts,'canonical source path required')\n rows=[]\n try:\n  fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);rows.append((fd,'/',meta(os.fstat(fd))))\n  for part in p.parts[1:-1]:\n   check();need(len(rows)<32,'source parent FD bound')\n   fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=rows[-1][0]);actual=str(Path(rows[-1][1])/part)\n   row=meta(os.fstat(fd));rows.append((fd,actual,row))\n   need(stat.S_ISDIR(row[2]) and row[3:5]==[0,0] and row==meta(Path(actual).lstat()),'source parent identity differs')\n  peak_fds=max(peak_fds,len(rows)+1);return rows,p.name\n except BaseException:\n  for fd,_path,_row in reversed(rows):os.close(fd)\n  raise\ndef parents_same(rows):\n for fd,path,row in rows:\n  need(row==meta(os.fstat(fd))==meta(Path(path).lstat()),'source parent full9 changed')\ndef finish(rows):\n for fd,_path,_row in reversed(rows):os.close(fd)\ndef read(path,maximum):\n global physical_bytes,file_reads\n check();rows,name=parent(path);fd=None\n try:\n  fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=rows[-1][0]);first=meta(os.fstat(fd))\n  need(stat.S_ISREG(first[2]) and first[3:6]==[0,0,1] and stat.S_IMODE(first[2])==0o600\n   and 0<=first[6]<=maximum and physical_bytes+first[6]<=16*1024*1024,'private bounded source original required')\n  physical_bytes+=first[6];file_reads+=1;parts=[];left=first[6]+1\n  while left:\n   check();part=os.read(fd,min(left,65536))\n   if not part:break\n   parts.append(part);left-=len(part)\n  raw=b''.join(parts)\n  need(len(raw)==first[6] and first==meta(os.fstat(fd))==meta(os.stat(name,dir_fd=rows[-1][0],follow_symlinks=False))\n   ==meta(Path(path).lstat()),'source original full9 changed')\n  parents_same(rows);value={'path':path,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'metadata':first}\n  if path in seen:need(value==seen[path],'source original changed between complete reads')\n  else:seen[path]=value\n  return raw\n finally:\n  if fd is not None:os.close(fd)\n  finish(rows)\ndef directory(path,expected):\n check();rows,name=parent(path);fd=None\n try:\n  fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=rows[-1][0]);first=meta(os.fstat(fd))\n  need(first[3:5]==[0,0] and stat.S_IMODE(first[2])==0o700,'private case source directory required')\n  names=sorted(os.listdir(fd));need(names==expected and len(names)<=64,'complete source directory closed set differs')\n  need(first==meta(os.fstat(fd))==meta(os.stat(name,dir_fd=rows[-1][0],follow_symlinks=False))==meta(Path(path).lstat()),\n   'source directory full9 changed');parents_same(rows)\n  value={'path':path,'metadata':first,'names':names}\n  if path in dirs:need(value==dirs[path],'source directory changed between complete observations')\n  else:dirs[path]=value\n finally:\n  if fd is not None:os.close(fd)\n  finish(rows)\nmanifest_raw=read(package,262144);need(hashlib.sha256(manifest_raw).hexdigest()==pin,'actual complete MF pin differs')\nmanifest=strict(manifest_raw);rows=manifest.get('files')\nneed(manifest.get('schema')=='hepta.native-guard.adapter-package.v1' and type(rows) is list and len(rows)==32,'exact MF32 required')\nbodies={};expected_dirs={root:{'MANIFEST.json'}};source_pins={}\nfor row in rows:\n need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact source row required')\n name=row['path'];relative=Path(name)\n need(type(name) is str and not relative.is_absolute() and str(relative)==name and '..' not in relative.parts\n  and '\\\\' not in name and '\\0' not in name and relative.parts[0] in ('source','reference','tests','validation')\n  and name not in bodies and type(row['bytes']) is int and row['bytes']>=0,'canonical complete source row required')\n maximum=131072 if name.endswith('.py') else 16*1024*1024\n need(row['bytes']<=maximum,'source member bound exceeded before reading')\n raw=read(root+'/'+name,maximum)\n need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'whole runtime member differs')\n bodies[name]=raw;source_pins[name]=seen[root+'/'+name]\n current=root\n for component in relative.parts:\n  expected_dirs.setdefault(current,set()).add(component);current=str(Path(current)/component)\nfor path,names in expected_dirs.items():directory(path,sorted(names))\norder=('component_common','native_proc_profile','component_lifecycle','stage_component','prepare_component','late_boundary','component_snapshot')\nmodules={};shared_check=check\nsaved_path=list(sys.path)\nfor name in order:\n member='source/'+name+'.py';need(member in bodies and name not in sys.modules,'unreviewed or already loaded source module')\n module=types.ModuleType(name);module.__file__=root+'/'+member\n module.__dict__.update(__actual_context__='phone',__reviewed_package_sources__=bodies,\n  __reviewed_package_manifest_raw__=manifest_raw,__reviewed_source_sha256__=hashlib.sha256(bodies[member]).hexdigest(),\n  __reviewed_package_physical_observation__=source_pins,__epoch_budget_check__=shared_check)\n sys.modules[name]=module;modules[name]=module;check();exec(compile(bodies[member],module.__file__,'exec'),module.__dict__)\n sys.path[:]=saved_path;check()\nif operation=='listener':\n for name in ('native_guard_session_r2','component_listener','witness_bundle'):\n  modules[name]=modules['stage_component']._est_auxiliary(name,budget_check=shared_check)\nneed(read(package,262144)==manifest_raw,'source manifest changed before application entry')\nfor name,raw in bodies.items():need(read(root+'/'+name,131072 if name.endswith('.py') else 16*1024*1024)==raw,'source changed before application entry')\nfor path,names in expected_dirs.items():directory(path,sorted(names))\nobservation={'schema':'hepta.native-guard.epoch-case-code-observation.v1','package':seen[package],\n 'sources':source_pins,'directories':list(dirs.values()),'physical_read_bytes':physical_bytes,\n 'file_reads':file_reads,'peak_owned_source_fds':peak_fds,'bootstrap_seconds':time.monotonic()-start}\nfor module in modules.values():module.__dict__['__epoch_case_code_observation__']=observation\ncheck();booting=False\nentry=modules['component_listener'] if operation=='listener' else modules['component_lifecycle']\nresult=entry.epoch_main(operation,arguments)\nneed(type(result) is int and 0<=result<=255,'lifecycle entry returned no explicit process result')\nraise SystemExit(result)\n"

def epoch_inventory_extended_fields(registry,failures):
    c,modules,_manifest,_raw,_bodies=_est_modules()
    extra=modules['component_lifecycle'].EPOCH_INVENTORY_EXTRA_ROOTS
    fields=('retained_native_fixtures','additional_prelaunch_fixture_absences','gnu_home_scan')
    c._ep_need(type(extra) is dict and all(name in extra for name in fields),
        'source-fixed complete extended inventory domains required')
    if registry is not None:
        c._ep_need(type(registry) is dict and type(failures) is dict,
            'actual registry and complete failure domain must be supplied together')
        initial=registry['initialization']['value']
        branches=initial['retained_failed_native_branches']
        c._ep_need(type(branches) is list and len(branches)==1
            and c._ep_same(branches,failures['retained_failed_native_branches'])
            and branches[0]['nonce']==extra['retained_native_fixtures'][0]['nonce']
            and c._ep_same(branches[0]['originals']['boundary'],
                extra['retained_native_fixtures'][0]['original_boundary']),
            'extended fixture domain changed the actual independently retained native branch')
    else:c._ep_need(failures is None,'initial fixed domain projection takes no invented registry')
    return {'schema':'hepta.native-guard.two-epoch-inventory-spec.v6',
        **{name:c._ep_strict(c._ep_encoded(extra[name])) for name in fields}}


def epoch_import_production(path,*,actual_context=None):
    import types
    c,_modules,_manifest,mf,bodies=_est_modules()
    context=c.epoch_actual_context(globals())
    c._ep_need(actual_context is None or actual_context==context,'production actual context differs')
    callback=globals().get('__epoch_budget_check__')
    c._ep_need(callable(callback),'production first-exec must use the enclosing actual clock')
    callback();path=Path(c._ep_path(str(path)))
    pins=c.strict(bodies['reference/REVIEWED-PRODUCTION-PINS.json'])
    c._ep_need(type(pins) is dict and len(pins)==15,'all15 reviewed production source pins required')
    owner={'phone':[0,0],'p4':[1000,1000],'mac':[501,20]}[context]
    directory=c.epoch_read_directory(str(path))
    c._ep_need(directory['metadata'][3:5]==owner
        and stat.S_IMODE(directory['metadata'][2])==0o700
        and directory['names']==sorted(pins),'production source directory is not the closed actual15')
    sources={};originals={};physical=0
    for name,sha256 in sorted(pins.items()):
        callback();c._ep_need(type(name) is str and re.fullmatch('[a-z_]+\\.py',name),
            'production source basename differs')
        location=path/name;first=c.metadata(location.lstat())
        c._ep_need(stat.S_ISREG(first[2]) and first[3:6]==owner+[1]
            and stat.S_IMODE(first[2])==0o600 and first[6]<=131072,
            'production source type/owner/mode/link/size differs')
        c._ep_need(physical+2*first[6]<=8*1024*1024,'complete production source double-read pool exceeded')
        raw=c.read(location,131072,private=False);physical+=len(raw)
        c._ep_need(c.sha(raw)==sha256 and len(raw)==first[6]
            and c.metadata(location.lstat())==first,'complete production source full9/bytes changed')
        sources[name]=raw;originals[name]={'path':str(location),**c._ep_bare(raw),'metadata':first}
    # This fixed closure includes every intra-package import of the four public modules.
    order=('provider_openai_compatible','phone_local_http_worker','phone_task_guards',
        'task_postconditions','retirement_recovery','phone_observation_tools','phone_local_tools','action_ledger')
    loaded={};saved_path=list(sys.path)
    for name in order:
        callback();raw=sources[name+'.py'];location=str(path/(name+'.py'))
        module=sys.modules.get(name)
        if module is not None:
            c._ep_need(module.__dict__.get('__epoch_production_source__')==originals[name+'.py']
                and module.__dict__.get('__epoch_production_runtime_raw__')==mf
                and module.__dict__.get('__actual_context__')==context
                and module.__file__==location,'foreign or changed production module already loaded')
        else:
            module=types.ModuleType(name);module.__file__=location
            module.__dict__.update(__actual_context__=context,__epoch_production_source__=originals[name+'.py'],
                __epoch_production_runtime_raw__=mf,__epoch_budget_check__=callback)
            sys.modules[name]=module
            try:exec(compile(raw,location,'exec'),module.__dict__)
            except BaseException:
                sys.modules.pop(name,None);raise
            finally:sys.path[:]=saved_path
        loaded[name]=module
    for name,raw in sorted(sources.items()):
        callback();location=path/name;original=originals[name]
        c._ep_need(c.metadata(location.lstat())==original['metadata']
            and c.read(location,131072,private=False)==raw
            and c.metadata(location.lstat())==original['metadata'],
            'production source changed after the whole-source first-exec gate')
        physical+=len(raw)
    c._ep_need(c._ep_same(c.epoch_read_directory(str(path)),directory),
        'production source directory changed during first-exec verification')
    callback()
    proof={'schema':'hepta.native-guard.epoch-production-source-observation.v1',
        'actual_context':context,'directory':directory,'originals':originals,
        'physical_read_bytes':physical,'file_reads':30}
    for module in loaded.values():module.__dict__['__epoch_production_source_observation__']=proof
    return {name:loaded[name] for name in ('phone_local_tools','phone_observation_tools','phone_task_guards','action_ledger')}


# The ordinary child program is kept as readable Python, included as one literal
# in this existing stage member. It is not a separate installed runtime member.
class _EpochCaseModules:
    def __init__(self,package,package_sha,*,budget_check):
        self.c,self.original_modules,_manifest,self.mf,self.current=_est_modules(phone=True,budget_check=budget_check)
        self.check=budget_check;self.package=Path(package);self.pin=package_sha
        self.c._ep_need(self.pin==self.c._ep_sha(self.mf)
            and self.package.name=='MANIFEST.json' and self.package.parent.name=='package'
            and self.package.parent.parent.parent==self.c.BASE/'native-guard-r10-r1'
            and self.c.EPOCH_LABEL.fullmatch(self.package.parent.parent.name),
            'only the current actual case package may bootstrap lifecycle code')
        self.io=_ESTOriginals(self.c,budget_check);self.saved={};self.modules={};self.path=None

    def __enter__(self):
        started=time.monotonic();c=self.c;mf_pin,mf_raw=self.io.read(self.package,maximum=262144)
        c._ep_need(mf_raw==self.mf,'actual case manifest is not the current complete source original')
        bodies={};physical={};expected={str(self.package.parent):{'MANIFEST.json'}}
        for row in c.strict(mf_raw)['files']:
            member=row['path'];relative=c.relative(member);path=self.package.parent/relative
            pin,raw=self.io.read(path,maximum=131072 if member.endswith('.py') else 16*1024*1024)
            c._ep_need(raw==self.current[member],'actual case source differs from the current generation')
            bodies[member]=raw;physical[member]=pin;parent=self.package.parent
            for part in relative.parts:
                expected.setdefault(str(parent),set()).add(part);parent=parent/part
        for path,names in expected.items():
            observed=self.io.directory(path)
            c._ep_need(observed['names']==sorted(names) and observed['metadata'][3:5]==[0,0]
                and stat.S_IMODE(observed['metadata'][2])==0o700,'case source closed set differs')
        runtime_names={Path(name).stem for name in bodies if name.startswith('source/') and name.endswith('.py')}
        reviewed=c.strict(bodies['reference/REVIEWED-PRODUCTION-PINS.json'])
        runtime_names.update(Path(name).stem for name in reviewed)
        self.saved={name:sys.modules.get(name) for name in runtime_names};self.path=list(sys.path)
        for name in runtime_names:sys.modules.pop(name,None)
        try:
            for name in EPOCH_SOURCE_ORDER:
                member='source/'+name+'.py';module=types.ModuleType(name)
                module.__file__=physical[member]['path']
                module.__dict__.update(__actual_context__='phone',__reviewed_package_sources__=bodies,
                    __reviewed_package_manifest_raw__=mf_raw,__reviewed_source_sha256__=c._ep_sha(bodies[member]),
                    __reviewed_package_physical_observation__=physical,__epoch_budget_check__=self.check)
                sys.modules[name]=module;self.modules[name]=module;self.check()
                exec(compile(bodies[member],module.__file__,'exec'),module.__dict__)
                sys.path[:]=self.path;self.check()
            self.io.recheck()
            observation={'schema':'hepta.native-guard.epoch-case-code-observation.v1',
                'package':mf_pin,'sources':physical,'directories':list(self.io.directories.values()),
                'physical_read_bytes':self.io.bytes_read,'file_reads':len(self.io.reads),
                'maximum_owned_source_fds':33,'bootstrap_seconds':time.monotonic()-started}
            for module in self.modules.values():module.__dict__['__epoch_case_code_observation__']=observation
            return self.modules
        except BaseException:
            self._restore();raise

    def _restore(self):
        for name,original in self.saved.items():
            if original is None:sys.modules.pop(name,None)
            else:sys.modules[name]=original
        if self.path is not None:sys.path[:]=self.path

    def __exit__(self,kind,value,traceback):
        self._restore()
        if kind is None:self.io.recheck()


def epoch_lifecycle_bootstrap(package,actual_context,package_sha,operation):
    budget=globals().get('__epoch_budget_check__')
    c,modules,_manifest,mf,bodies=_est_modules(phone=True,budget_check=budget)
    c._ep_need(actual_context=='phone' and operation in ('detached-launch','supervise','provider','sidecar','listener'),
        'only an actual finite phone lifecycle entry is permitted')
    package=Path(package);home=package.parent.parent
    c._ep_need(package==c.BASE/'native-guard-r10-r1'/home.name/'package/MANIFEST.json'
        and c.EPOCH_LABEL.fullmatch(home.name) and package_sha==c._ep_sha(mf),
        'lifecycle entry cannot substitute a virtual or shared code path')
    observation=globals().get('__epoch_case_code_observation__')
    c._ep_need(type(observation) is dict
        and observation.get('schema')=='hepta.native-guard.epoch-case-code-observation.v1'
        and observation.get('package',{}).get('path')==str(package),
        'actual first-exec case source observation is required')
    c._ep_need(c.epoch_read_original(observation['package'])==mf,'actual case source manifest changed')
    physical=globals().get('__reviewed_package_physical_observation__')
    c._ep_need(type(physical) is dict and set(physical)==set(bodies)
        and c._ep_same(physical,observation['sources']),'complete actual case source binding required')
    for name,raw in bodies.items():
        budget();pin=physical[name]
        c._ep_need(pin['path']==str(package.parent/name)
            and c.epoch_read_original(pin)==raw,'whole actual case source changed before lifecycle entry')
    for name,module in modules.items():
        c._ep_need(module.__file__==str(package.parent/'source'/(name+'.py'))
            and module.__dict__.get('__epoch_budget_check__') is budget,
            'actual lifecycle module path or single callback differs')
    for row in observation['directories']:
        budget();c._ep_need(c._ep_same(c.epoch_read_directory(row['path']),row),
            'actual case package directory changed before lifecycle entry')
    if operation=='listener':
        for name in ('native_guard_session_r2','component_listener','witness_bundle'):
            modules[name]=_est_auxiliary(name,budget_check=budget)
    budget();return modules


def epoch_lifecycle_child_argv(package,package_sha,operation,arguments):
    c,_modules,_manifest,mf,_bodies=_est_modules(phone=True,
        budget_check=globals().get('__epoch_budget_check__'))
    package=Path(package);home=package.parent.parent
    c._ep_need(operation in ('supervise','provider','sidecar','listener')
        and type(arguments) is list and len(arguments)<=13
        and all(type(item) is str and '\0' not in item for item in arguments)
        and package_sha==c._ep_sha(mf),'fixed child source and finite argv required')
    c._ep_need(arguments.count('--lease')==arguments.count('--lease-sha256')==1
        and arguments.count('--package')==arguments.count('--package-sha256')==1,
        'child argv must bind its complete actual lease and source')
    c._ep_need(arguments[arguments.index('--lease')+1]==str(home)
        and arguments[arguments.index('--package')+1]==str(package)
        and arguments[arguments.index('--package-sha256')+1]==package_sha,
        'child argv changed its actual immutable package or case')
    lease,_raw=epoch_lifecycle_load_lease(home,arguments[arguments.index('--lease-sha256')+1])
    arguments_raw=c._ep_encoded(arguments)
    argv=[sys.executable,'-I','-B','-c',_EST_CHILD_BOOTSTRAP,str(package),package_sha,
        operation,arguments_raw.decode('utf-8'),str(lease['expires_unix_ms'])]
    c._ep_need(len(c.encoded(argv))<=12000,'plain child first-exec bootstrap exceeds owned-output argv reservation')
    return argv


def epoch_resource_reservation_value(value):
    c,_modules,_manifest,mf,_bodies=_est_modules();binding=_est_binding(c)
    c._ep_exact(value,{'schema','epoch_id','boot_id','case_id','generation','observation',
        'source_model','runtime_manifest','remaining_qualification_cases','measured','profiles',
        'copy_overhead','arithmetic','producer_limits','copy_ledger','native_calls_authorized',
        'component_qualified','business_qualified','automatic_retry'},
        'the complete source-bound preclaim resource reservation is required')
    c._ep_need(value['schema']=='hepta.native-guard.epoch-resource-reservation.v1'
        and value['epoch_id']==c.EPOCH_ID and value['boot_id']==binding['boot_id']
        and value['case_id'] in ('NEG-01','NEG-02') and value['case_id'] in value['remaining_qualification_cases']
        and type(value['native_calls_authorized']) is int and value['native_calls_authorized']==0
        and value['component_qualified'] is False and value['business_qualified'] is False
        and value['automatic_retry'] is False,'preclaim resource accounting cannot grant a native action')
    c._ep_pin(value['generation'],original=True)
    for key in ('observation','source_model','runtime_manifest'):
        c._ep_exact(value[key],{'bytes','sha256'},'complete canonical resource input byte identity required')
        c._ep_need(type(value[key]['bytes']) is int and 0<value[key]['bytes']<=16*1024*1024
            and type(value[key]['sha256']) is str and c.EPOCH_HASH.fullmatch(value[key]['sha256']),
            'resource input byte identity is not bounded')
    model=binding['resource_model'];epoch_resource_model_value(model)
    c._ep_need(value['source_model']==c._ep_bare(c._ep_encoded(model))
        and value['runtime_manifest']==c._ep_bare(mf)
        and c._ep_same(value['producer_limits'],model['producer_limits'])
        and c._ep_same(value['copy_ledger'],model['copy_ledger'])
        and c._ep_same(value['copy_overhead'],model['copy_overhead'])
        and c._ep_same(value['profiles'],[model['profiles'][case] for case in value['remaining_qualification_cases']]),
        'resource reservation changed an actual producer or complete copy bound')
    expected=c.epoch_resource_forecast(value['measured'],value['profiles'],
        additional_profile_copies=value['copy_overhead'],
        remaining_qualification_cases=value['remaining_qualification_cases'])
    c._ep_need(c._ep_same(expected,value['arithmetic']),'all shared resource arithmetic must be recomputed')
    return value


def epoch_resource_model_value(model):
    c,modules,_manifest,_mf,_bodies=_est_modules()
    c._ep_exact(model,{'schema','profiles','copy_overhead','producer_limits','copy_ledger',
        'historical_consumer_originals','historical_consumer_proof'},
        'complete fixed producer and copy accounting model required')
    c._ep_need(model['schema']=='hepta.native-guard.epoch-source-resource-model.v1',
        'resource source model schema differs')
    c._ep_exact(model['profiles'],{'NEG-01','NEG-02'},'both finite qualification producer profiles are mandatory')
    for profile in model['profiles'].values():
        c._ep_exact(profile,set(EPOCH_RESOURCE_KEYS)|{'producer_proof','copy_plan'},
            'complete source-frozen qualification profile required')
        for key in EPOCH_RESOURCE_KEYS:
            c._ep_need(type(profile[key]) is int and profile[key]>=0,'resource counts must be nonnegative integers')
        for key in ('producer_proof','copy_plan'):_est_host3(c,profile[key])
    c._ep_exact(model['copy_overhead'],EPOCH_RESOURCE_KEYS,'all repeated proof/copy domains must be charged')
    c._ep_need(all(type(n) is int and n>=0 for n in model['copy_overhead'].values()),
        'copy overhead must be explicitly bounded in every pool')
    c._ep_exact(model['producer_limits'],{'fixture','owned_role_output','native_output','snapshot',
        'closure_outputs','operation_transport','case_protocol'},'the complete final producer graph is required')
    limits=model['producer_limits'];lifecycle=modules['component_lifecycle']
    c._ep_need(type(limits['fixture']) is dict and limits['fixture']
        and type(limits['owned_role_output']) is dict and limits['owned_role_output'].get('per_stream_bytes')==lifecycle.OWNED_OUTPUT_LIMIT
        and limits['owned_role_output'].get('roles')==3 and limits['owned_role_output'].get('streams_per_role')==2
        and limits['native_output']=={'per_action_combined_bytes':600000,'maximum_actions_per_case':2},
        'actual finite fixture, six-role-stream and native producer limits are required')
    rows=model['copy_ledger'];c._ep_need(type(rows) is list and rows and len(rows)<=256,
        'finite complete per-producer copy graph is required')
    seen=set()
    for row in rows:
        c._ep_exact(row,{'name','producer','maximum_body_bytes','maximum_count','copies','pool'},
            'each source-fixed writer/copy domain must be explicit')
        c._ep_need(type(row['name']) is str and row['name'] not in seen
            and row['producer'] in limits and row['pool'] in (
                'physical_read','physical_write','inventory','snapshot','consumer','transport')
            and all(type(row[key]) is int and row[key]>=0 for key in ('maximum_body_bytes','maximum_count','copies')),
            'resource graph repeats, leaves a pool, or uses unbounded writer data')
        seen.add(row['name'])
    originals=model['historical_consumer_originals'];_est_host3(c,model['historical_consumer_proof'])
    c._ep_need(type(originals) is list and 1<=len(originals)<=8192,
        'actual historical consumer body union is mandatory')
    paths=set()
    for row in originals:
        _est_host3(c,row);c._ep_need(row['path'] not in paths,'historical physical callback path repeats');paths.add(row['path'])
    return model


def epoch_allocation_admission_value(value,*,identity,identity_pin,reservation,reservation_pin,
        initialization,index,originals):
    c,_modules,_manifest,_mf,_bodies=_est_modules()
    c._ep_exact(value,EPOCH_ALLOCATION_ADMISSION_FIELDS,'complete actual allocation admission required')
    c._ep_need(value['schema']=='hepta.native-guard.epoch-allocation-admission.v1'
        and value['state']=='PRECLAIM_OBSERVATION_AND_CAPACITY_BOUND_TO_EXCLUSIVE_IDENTITY'
        and value['epoch_id']==c.EPOCH_ID and type(value['ordinal']) is int
        and value['ordinal']==identity['ordinal']==reservation['ordinal']
        and value['boot_id']==identity['boot_id']
        and value['nonce_generated_after_exclusive_claim'] is True
        and value['native_scope_assigned'] is False and value['component_qualified'] is False
        and value['business_qualified'] is False and value['automatic_retry'] is False,
        'allocation admission cannot claim a scope, native action or qualification')
    c._ep_need(type(initialization) is dict and set(initialization)>= {'value','original'},
        'the independently verified actual initialization is required')
    expected={'anchor':initialization['value']['anchor'],'initialization':initialization['original'],
        'generation':reservation['generation'],'claim':reservation_pin,'identity':identity_pin,
        'predecessor_terminal':identity['predecessor_terminal'],'prior_boundary':identity['prior_boundary']}
    for key,pin in expected.items():
        c._ep_need(c._ep_same(value[key],pin),'allocation admission changed actual '+key)
        if pin is not None:c._ep_manifest_raw(pin,index,originals)
    c._ep_need({key:value['anchor'][key] for key in ('path','bytes','sha256')}==reservation['anchor'],
        'allocation changed the independent historical anchor identity')
    resource=epoch_resource_reservation_value(value['resource_reservation'])
    observation=value['preclaim_observation']
    c._ep_need(type(observation) is dict
        and observation.get('schema')=='hepta.native-guard.epoch-preclaim-observation.v1'
        and observation.get('epoch_id')==c.EPOCH_ID and observation.get('boot_id')==identity['boot_id']
        and c._ep_bare(c._ep_encoded(observation))==resource['observation']
        and c._ep_same(resource,reservation['resource_reservation'])
        and c._ep_same(resource['generation'],reservation['generation'])
        and c._ep_same(value['authorization_original'],reservation['authorization_request']['origin']),
        'complete actual preclaim observation or authorization/resource value differs')
    epoch_preclaim_observation_value(observation,resource,initialization=initialization,
        index=index,originals=originals)
    return value


def epoch_role_launch_intent_value(value,*,identity,identity_pin,lease_pin,generation,index,originals):
    c,_modules,_manifest,_mf,_bodies=_est_modules()
    c._ep_exact(value,{'schema','epoch_id','ordinal','identity','lease','generation','scope',
        'maximum_forks','automatic_retry','component_qualified','business_qualified'},
        'complete one-fork intent is required before lifecycle admission')
    c._ep_need(value['schema']=='hepta.native-guard.epoch-role-launch-intent.v1'
        and value['epoch_id']==c.EPOCH_ID and type(value['ordinal']) is int
        and value['ordinal']==identity['ordinal'] and c._ep_same(value['identity'],identity_pin)
        and c._ep_same(value['lease'],lease_pin) and c._ep_same(value['generation'],generation)
        and value['scope'] is None and type(value['maximum_forks']) is int and value['maximum_forks']==1
        and value['automatic_retry'] is False and value['component_qualified'] is False
        and value['business_qualified'] is False,'one-fork intent changed source, identity or admission semantics')
    for pin in (identity_pin,lease_pin,generation):c._ep_manifest_raw(pin,index,originals)
    return value


def _est_private_record(io,path,value,maximum=16*1024*1024):
    raw=value if type(value) is bytes else io.c._ep_encoded(value)
    return io.write(path,raw,maximum=maximum,expected_parent=io.directory(str(Path(path).parent)))


def _est_operation_state(request,*,budget_check,lease_required=True):
    c,modules,_manifest,_mf,_bodies=_est_modules(phone=True,budget_check=budget_check)
    io=_ESTOriginals(c,budget_check)
    identity,claim,lease=_est_context_identity(c,request,io,require_lease=lease_required)
    initial_raw=io.read(request['context']['initialization']['path'],
        expected=request['context']['initialization'])[1]
    initial=c.strict(initial_raw);c._ep_exact(initial,c.EPOCH_INITIALIZATION_FIELDS,'actual complete initialization required')
    c._ep_need(initial['schema']=='hepta.native-guard.epoch-registry-initialization.v2'
        and c._ep_same(initial['generation'],request['context']['generation'])
        and c._ep_same(initial['code_receipt'],request['context']['code_receipt']),
        'operation changed actual initialization source or code receipt')
    generation=c.strict(io.read(initial['generation']['path'],expected=initial['generation'])[1])
    c.epoch_generation_value(generation)
    c._ep_need(generation['runtime']['sha256']==c._ep_sha(_mf)
        and generation['runtime']['bytes']==len(_mf),'operation generation is not the loaded whole package')
    slot=c.EPOCH_REGISTRY_ROOT+'/slots/%02d'%identity['ordinal']
    home=str(c.BASE/'native-guard-r10-r1'/identity['label'])
    if lease_required:
        c._ep_need(time.time_ns()//1000000<lease['expires_unix_ms'],'actual operation lease expired')
    return c,modules,io,identity,claim,lease,initial,generation,slot,home


def _est_transport_copy(io,identity,members,*,first=False):
    c=io.c;gnu=c.EPOCH_REGISTRY_ROOT+'/slots/%02d/transport'%identity['ordinal']
    android=c.EPOCH_ANDROID_TRANSPORT_ROOT+'/%02d'%identity['ordinal']
    c._ep_need(type(members) is dict and members and set(members)<=set(c.EPOCH_TRANSPORT_FILES)
        and all(type(raw) is bytes for raw in members.values()),'fixed complete private transfer members required')
    c._ep_need(sum(map(len,members.values()))<=8*1024*1024,
        'all decoded transfer input bodies share the original8MiB pool')
    if first:
        for root in (gnu,android):
            absence=io.absent(root)
            io.mkdir(root,expected_parent=absence['parent'])
    else:
        for root in (gnu,android):
            row=io.directory(root)
            c._ep_need(set(row['names'])<=set(c.EPOCH_TRANSPORT_FILES)
                and not set(members)&set(row['names']),'partial or repeated transfer is not retryable')
    result={}
    for name,raw in sorted(members.items()):
        copies={}
        for view,root in (('gnu',gnu),('android',android)):
            copies[view]=_est_private_record(io,root+'/'+name,raw,8*1024*1024)
        c._ep_need(all(copies['gnu'][key]==copies['android'][key] for key in ('bytes','sha256')),
            'both actual private transfer views must retain every input byte')
        result[name]=copies
    return result


def epoch_stage_inputs(request,*,budget_check):
    state=_est_operation_state(request,budget_check=budget_check,lease_required=False)
    c,_modules,io,identity,claim,_lease,initial,_generation,slot,_home=state
    payload=request['payload'];c._ep_exact(payload,{'schema','action','members'},'exact first private stage transfer required')
    c._ep_need(payload['schema']=='hepta.native-guard.epoch-stage-inputs-payload.v1'
        and payload['action']=='publish-inputs','unreviewed stage transfer action')
    c._ep_exact(payload['members'],{'archive','stage_source'},'one archive and exact current stage source required')
    epoch_resource_reservation_value(claim['resource_reservation'])
    members={'inputs.tar.gz':_est_body(c,payload['members']['archive'],maximum=8*1024*1024),
        'stage.py':_est_body(c,payload['members']['stage_source'],maximum=131072)}
    c._ep_need(members['stage.py']==globals()['__reviewed_package_sources__']['source/stage_component.py'],
        'private transport stage source is not the actual current whole member')
    with c.epoch_acquire_registry_lock(initial) as lock:
        io.absent(slot+'/STAGE.json');io.absent(slot+'/ROLE-LAUNCH-INTENT.json')
        copied=_est_transport_copy(io,identity,members,first=True);lock.check();io.recheck()
    return {'schema':'hepta.native-guard.epoch-transfer-result.v1','state':'ACTUAL_PRIVATE_INPUT_COPIES_CREATED',
        'epoch_id':c.EPOCH_ID,'ordinal':identity['ordinal'],'phase':'stage','originals':copied,
        'automatic_retry':False,'component_qualified':False}


def epoch_validate_stage_archive(files,identity,claim,context):
    c,_modules,_manifest,mf,bodies=_est_modules()
    for key in ('LEASE.json','owner-request.txt','sender-contract.json','package/MANIFEST.json',
            'inputs/COMBINATION.json','inputs/EPOCH-CLAIM.original.json','inputs/EPOCH-ALLOCATION-ADMISSION.original.json'):
        c._ep_need(key in files,'mandatory epoch material archive member absent')
    lease_raw=files['LEASE.json'];lease=c.strict(lease_raw);epoch=c.epoch_lease_protocol_value(lease)
    c._ep_exact(lease,{'schema','label','boot_id','case_id','nonce','owner_request_sha256',
        'selected_session_id','selected_profile_id','expires_unix_ms','combination','retirement',
        'prior_boundary','android_journal','package_sha256','epoch'},'complete actual epoch lease required')
    c._ep_need(files['package/MANIFEST.json']==mf and lease['package_sha256']==c._ep_sha(mf)
        and all(c._ep_same(lease[key],identity[key]) for key in ('label','boot_id','case_id','nonce',
            'selected_session_id','selected_profile_id','prior_boundary'))
        and all(c._ep_same(epoch[key],context[key]) for key in ('initialization','generation','reservation','identity')),
        'material archive changed the actual claimed identity or generation')
    expected={'package/MANIFEST.json','LEASE.json','owner-request.txt','sender-contract.json',
        'inputs/COMBINATION.json','inputs/SOURCE-SEAL.original.json','inputs/configuration.original.json',
        'inputs/service-inputs.original.json','inputs/PRIOR-BOUNDARY.original.json',
        'inputs/EPOCH-CLAIM.original.json','inputs/EPOCH-ALLOCATION-ADMISSION.original.json'}
    for name,raw in bodies.items():
        key='package/'+name;c._ep_need(files.get(key)==raw,'archive source body differs');expected.add(key)
    reviewed=c.strict(bodies['reference/REVIEWED-PRODUCTION-PINS.json'])
    c._ep_need(type(reviewed) is dict and len(reviewed)==15,'complete current production source set required')
    for name,pin in reviewed.items():
        c._ep_need(type(name) is str and re.fullmatch('[a-z_]+\\.py',name),'production source filename differs')
        key='inputs/production/'+name;expected.add(key)
        c._ep_need(key in files and c._ep_sha(files[key])==pin,'production source archive body differs')
    c._ep_need(set(files)==expected and len(files)<=80,'extra or missing exact material archive member')
    c._ep_need(c._ep_bare(files['inputs/COMBINATION.json'])==lease['combination']
        and c._ep_bare(files['inputs/PRIOR-BOUNDARY.original.json'])==
            {k:identity['prior_boundary'][k] for k in ('bytes','sha256')}
        and files['inputs/EPOCH-CLAIM.original.json']==c._ep_encoded(claim),
        'actual combination, predecessor or whole claim changed in material')
    admission=c.strict(files['inputs/EPOCH-ALLOCATION-ADMISSION.original.json'])
    c._ep_need(c._ep_same(admission['claim'],context['reservation'])
        and c._ep_same(admission['identity'],context['identity'])
        and c._ep_same(admission['resource_reservation'],claim['resource_reservation']),
        'material admission does not belong to the actual whole claim')
    owner=files['owner-request.txt'];c._ep_need(20<=len(owner)<=16000 and b'\0' not in owner
        and owner.decode('utf-8').count(identity['nonce'])==1
        and c._ep_bare(owner)=={k:identity['owner_request'][k] for k in ('bytes','sha256')}
        and c._ep_sha(owner)==lease['owner_request_sha256'],'whole postclaim owner request differs')
    c._ep_need(type(lease['expires_unix_ms']) is int
        and 465000<=lease['expires_unix_ms']-time.time_ns()//1000000<=510000,
        'actual510s lease has insufficient remaining stage budget; it is never extended')
    return lease,lease_raw


def epoch_stage_case(request,*,budget_check):
    c,modules,io,identity,claim,_lease,initial,generation,slot,home=_est_operation_state(
        request,budget_check=budget_check,lease_required=False)
    payload=request['payload'];c._ep_exact(payload,{'schema','action','archive','stage_source'},'actual two stage inputs required')
    c._ep_need(payload['schema']=='hepta.native-guard.epoch-stage-payload.v1' and payload['action']=='stage',
        'explicit actual stage operation required')
    for key,name in (('archive','inputs.tar.gz'),('stage_source','stage.py')):
        c._ep_pin(payload[key],original=True)
        c._ep_need(payload[key]['path']==slot+'/transport/'+name,'stage input escaped this claimed slot')
    source=io.read(payload['stage_source']['path'],expected=payload['stage_source'],maximum=131072)[1]
    c._ep_need(source==globals()['__reviewed_package_sources__']['source/stage_component.py'],
        'transported stage source changed')
    raw=io.read(payload['archive']['path'],expected=payload['archive'],maximum=8*1024*1024)[1]
    files=archive_members(raw);lease,lease_raw=epoch_validate_stage_archive(files,identity,claim,request['context'])
    epoch_resource_reservation_value(claim['resource_reservation'])
    old_lock=None;created=[];started=False
    with c.epoch_acquire_registry_lock(initial) as lock:
        io.absent(slot+'/STAGE.json');io.absent(slot+'/ROLE-LAUNCH-INTENT.json')
        old_lock,retired=epoch_lifecycle_verify_retired(lease,budget_check=budget_check)
        try:
            parent=io.absent(home)['parent']
            android_home=str(c.ANDROID/lease['android_journal'].lstrip('/'))
            android_home=str(Path(android_home).parent)
            io.absent(android_home)
            io.absent(str(c.ANDROID/'data/local/tmp'/('hepta-native-guard-'+identity['nonce'])))
            io.mkdir(home,expected_parent=parent);started=True
            created.append({'path':home,'metadata':io.directories[home]['metadata'],'selinux':None})
            for name,body in sorted(files.items()):
                destination=Path(home)/name;parents=[];p=destination.parent
                while p!=Path(home):parents.append(p);p=p.parent
                for p in reversed(parents):
                    if str(p) not in io.directories:
                        row=io.mkdir(p,expected_parent=io.directory(str(p.parent)))
                        created.append({'path':str(p),'metadata':row['metadata'],'selinux':None})
                _est_private_record(io,destination,body,8*1024*1024)
            for name in ('claims','operator'):
                row=io.mkdir(Path(home)/name,expected_parent=io.directory(home))
                created.append({'path':str(Path(home)/name),'metadata':row['metadata'],'selinux':None})
            budget_check();layout=create_isolated_journal(c,Path(home),lease,created);budget_check()
            # Only our explicitly owned executor addition may change the home row.
            io.directories[home]=io.directory(home)
            actual_lease,_actual_raw=epoch_lifecycle_load_lease(home,c._ep_sha(lease_raw))
            c._ep_need(c._ep_same(actual_lease,lease),'new actual staged lease changed')
            combo,_cfg=c.load_combination(Path(home)/'inputs',files['inputs/COMBINATION.json'],
                c.strict(files['package/reference/REVIEWED-PRODUCTION-PINS.json']),actual_context='phone')
            budget_check();artifacts=c.verify_external(combo);budget_check()
            result={'schema':'hepta.native-guard.private-stage.v1','state':'PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES',
                'lease_sha256':c._ep_sha(lease_raw),'package_sha256':lease['package_sha256'],
                'archive_sha256':payload['archive']['sha256'],'archive_source':payload['archive']['path'],
                'archive_metadata':payload['archive']['metadata'],'members':len(files),'created_directories':created,
                'journal_layout':layout,'retirement_verified_before_writes':retired,
                'existing_artifacts_read_only':artifacts,'existing_files_overwritten':0,'service_launches':0,
                'model_requests':0,'native_tasks':0,'existing_helper_or_policy_changes':0,
                'automatic_retry':False,'component_qualified':False}
            complete=_est_private_record(io,Path(home)/'STAGE-COMPLETE.json',result)
            lease_pin=io.files[home+'/LEASE.json']
            binding={'schema':'hepta.native-guard.epoch-stage-binding.v1','epoch_id':c.EPOCH_ID,
                'ordinal':identity['ordinal'],'identity':request['context']['identity'],'lease':lease_pin,
                'stage_original':complete,'package_manifest':io.files[home+'/package/MANIFEST.json'],
                'phase_source':io.files[home+'/package/source/stage_component.py'],
                'inventory_roots':[android_home,home,str(c.ANDROID/'data/local/tmp'/('hepta-native-guard-'+identity['nonce']))]}
            binding_pin=_est_private_record(io,slot+'/STAGE.json',binding,65536)
            lock.check();io.recheck()
            return {'schema':'hepta.native-guard.epoch-stage-result.v1','state':'ACTUAL_PRIVATE_CASE_STAGED_NO_ROLES',
                'epoch_id':c.EPOCH_ID,'ordinal':identity['ordinal'],'lease':lease_pin,
                'stage_binding':binding_pin,'stage_original':complete,'automatic_retry':False,'component_qualified':False}
        except BaseException as error:
            if started:
                # Failure is retained under the one already consumed identity; no cleanup or re-open.
                try:_est_private_record(io,Path(home)/'STAGE-FAILURE.json',{'error_type':type(error).__name__,
                    'detail':str(error)[:1024],'created_directories':created,'automatic_retry':False,'automatic_cleanup':False},262144)
                except BaseException:pass
            raise
        finally:
            if old_lock is not None:os.close(old_lock)


class _ESTBoundedText:
    def __init__(self):self.parts=[];self.bytes=0
    def write(self,value):
        raw=value.encode('utf-8');need(self.bytes+len(raw)<=65536,'bounded lifecycle summary exceeded')
        self.parts.append(value);self.bytes+=len(raw);return len(value)
    def flush(self):pass


def epoch_launch_case(request,*,budget_check):
    c,_modules,io,identity,claim,lease,initial,_generation,slot,home=_est_operation_state(request,budget_check=budget_check)
    c._ep_exact(request['payload'],{'schema','action'},'fixed one-fork launch request required')
    c._ep_need(request['payload']=={'schema':'hepta.native-guard.epoch-launch-payload.v1','action':'launch'}
        and lease['expires_unix_ms']-time.time_ns()//1000000>=450000,
        'launch must leave the original435s supervisor and420s listener budgets')
    epoch_resource_reservation_value(claim['resource_reservation'])
    with c.epoch_acquire_registry_lock(initial) as lock:
        stage_pin,stage_raw=io.read(slot+'/STAGE.json',maximum=65536)
        stage=c.strict(stage_raw);c._ep_need(c._ep_same(stage['lease'],request['context']['lease']),
            'launch changed actual staged lease')
        for name in ('ROLE-LAUNCH-INTENT.json','ADMISSION.json','SCOPE-BINDING.json','LAUNCH.json','COMMIT.json'):
            io.absent(slot+'/'+name)
        intent={'schema':'hepta.native-guard.epoch-role-launch-intent.v1','epoch_id':c.EPOCH_ID,
            'ordinal':identity['ordinal'],'identity':request['context']['identity'],
            'lease':request['context']['lease'],'generation':request['context']['generation'],'scope':None,
            'maximum_forks':1,'automatic_retry':False,'component_qualified':False,'business_qualified':False}
        intent_pin=_est_private_record(io,slot+'/ROLE-LAUNCH-INTENT.json',intent,65536);lock.check()
    # The supervisor must acquire its own short registry lock. Never hold this lock across the fork.
    import contextlib
    summary=_ESTBoundedText()
    with _EpochCaseModules(Path(home)/'package/MANIFEST.json',lease['package_sha256'],budget_check=budget_check) as modules:
        arguments=['--lease',home,'--lease-sha256',request['context']['lease']['sha256'],
            '--package',home+'/package/MANIFEST.json','--package-sha256',lease['package_sha256'],
            '--execute-detached-launch-once']
        with contextlib.redirect_stdout(summary):
            result=modules['component_lifecycle'].epoch_main('detached-launch',arguments)
        c._ep_need(type(result) is int and result==0,'actual one-fork launcher did not return successfully')
    intent_actual=io.read(home+'/DETACHED-LAUNCH-INTENT.json',maximum=65536)[0]
    result_actual,result_raw=io.read(home+'/DETACHED-LAUNCH-RESULT.json',maximum=16384)
    c._ep_need(''.join(summary.parts).encode('utf-8')==result_raw,'actual launcher summary differs from its original')
    io.recheck()
    return {'schema':'hepta.native-guard.epoch-launch-result.v1','state':'ACTUAL_ONE_FORK_RECORDED_NO_READINESS_CLAIM',
        'epoch_id':c.EPOCH_ID,'ordinal':identity['ordinal'],'role_launch_intent':intent_pin,
        'detached_intent':intent_actual,'detached_result':result_actual,
        'supervisor_generation_inferred':False,'readiness_asserted':False,
        'automatic_retry':False,'component_qualified':False}

