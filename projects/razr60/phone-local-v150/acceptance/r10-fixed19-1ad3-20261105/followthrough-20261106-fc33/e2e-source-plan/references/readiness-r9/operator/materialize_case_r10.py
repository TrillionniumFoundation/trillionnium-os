#!/usr/bin/env python3
"""Fresh five-kind r10 acceptance bytes bound to a real sealed release; never register or Send.

No phone/model/socket call. Root must run the real readiness and sender guards
before dispatch. A host seal or this material is never a business PASS.
"""
import argparse,ast,hashlib,json,os,re,secrets,stat,types
from pathlib import Path

BASE=Path(__file__).resolve().parent
GNU='/var/lib/trillionnium/owner-open/phone-local-v150'
LEGACY_SHA='f2b2416cd895e9235fc36cbad07cc32f763420410fc48829c99ac9c566a3fb81'
QUALIFICATION_SHA='e3e10557b7ece137916c7cb8bb9b5c049224c851dd47546f9a729a9a98557d81'
REGISTER_SHA='b0f0f2f3175a8807072eca6f560d5b30396591a9fb940017bdb39937b44a8c7c'
HEALTH_REGISTER_SHA='deba53529e1c39e1a591b6e8a185857d2e0de4e08f21281fcc656945061a1e7b'
STRICT_FOCUS_SHA='c8ec62529d88a29872c313052cdd335dc7611b11089db87531008b35d926e855'
PARENT_FOCUS_SHA='b2bcd131f80a113ad2957021f3bfbc1dbf9a1c6cda463f84b3a6c3acb9c8b99c'
HELPER_TARGET='/data/local/tmp/hepta-phone-executor-v150-r9-r1/helpers/focus-text-input-v150-r9.jar'
NATIVE_SERVER_SHA='dbca8b3c6d024c414d018146e73df996cae51b18c8cf5d3bdab6b776318a348c'
CALC='com.motorola.cn.calculator'
SETTINGS='com.android.settings'
ABOUT=SETTINGS+'/com.android.settings.Settings$MyDeviceInfoActivity'
DETAILS=SETTINGS+'/com.android.settings.SubSettings'
CASES={'health':'HEALTH','visual':'E2E-01','unicode':'E2E-02','calculator':'E2E-03','settings':'E2E-04'}

def require(ok,why):
    if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(value):return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def strict(raw):
    def pairs(items):
        out={}
        for key,value in items:require(key not in out,'duplicate JSON field');out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def read(path,maximum=8*1024*1024,*,allow_empty=False):
    p=Path(path).absolute();require(p.parent.resolve()==p.parent,'noncanonical input parent')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and (0 if allow_empty else 1)<=before.st_size<=maximum,'bounded regular input required')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maximum+1)
        after,named=os.fstat(fd),p.lstat()
        require(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k)
                for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink')),'input changed during read')
        return raw
    finally:os.close(fd)
def pinned(path,digest,maximum=8*1024*1024,*,allow_empty=False):
    require(isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest),'exact SHA256 required')
    raw=read(path,maximum,allow_empty=allow_empty);require(sha(raw)==digest,'input pin differs: '+str(path));return raw
def write_new(path,raw):
    require(path.parent.resolve()==path.parent,'noncanonical output parent')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}

def module_original(directory,row):
    rel=Path(row['path']);require(not rel.is_absolute() and '..' not in rel.parts
        and str(rel)==row['path'],'unsafe module input path')
    maximum=32*1024*1024 if row['path']=='evidence/RELEASE-BOUNDARIES.json' else 8*1024*1024
    require(type(row['bytes']) is int and 0<=row['bytes']<=maximum,'bounded module input size required')
    raw=pinned(Path(directory)/'module'/rel,row['sha256'],maximum=row['bytes'],allow_empty=row['bytes']==0)
    require(len(raw)==row['bytes'],'module file size differs')
    return raw

def validate_release(directory,build_sha):
    directory=Path(directory).absolute()
    require(directory.resolve()==directory and directory.is_dir(),'canonical release directory required')
    report_raw=pinned(directory/'BUILD-RESULT.json',build_sha,65536);report=strict(report_raw)
    require(report.get('schema')=='hepta.r10.integration-build.v1'
            and report.get('state')=='SEALED_ACTUAL_RETIREMENT_BOUND'
            and report.get('production_source_count')==15,'pending/source-only release cannot materialize a task')
    seal_raw=pinned(directory/'provider/SOURCE-SEAL-v150-r10.json',report['source_seal_sha256'],262144)
    config_raw=pinned(directory/'local-config-r10-r1.json',report['configuration_sha256'],65536)
    service_raw=pinned(directory/'PHONE-SERVICE-INPUTS-v150-r10-r1.json',report['service_inputs_sha256'],262144)
    manifest_raw=pinned(directory/'module/MODULE-MANIFEST-v150-r10-r1.json',report['module_manifest_sha256'],1048576)
    seal,config,manifest=strict(seal_raw),strict(config_raw),strict(manifest_raw)
    require(seal.get('schema')=='hepta.provider-r10.actual-integration-seal.v1'
            and seal.get('module_release')=='v150-r10-r1' and seal.get('state')=='HOST_FROZEN_PHONE_NOT_STARTED'
            and seal['configuration']=={'bytes':len(config_raw),'sha256':sha(config_raw)}
            and config.get('service_manifest_sha256')==sha(service_raw)
            and seal.get('phone_service_inputs_sha256')==sha(service_raw),'source/config/service seal differs')
    rows=seal.get('production_files');require(isinstance(rows,list) and len(rows)==15,'full 15-source seal required')
    paths=[row.get('path') for row in rows]
    require(len(set(paths))==15 and all(isinstance(p,str) and re.fullmatch(r'source/[a-z_]+\.py',p) for p in paths),'source path set differs')
    require({p.name for p in (directory/'provider/source').glob('*.py')}=={Path(p).name for p in paths},'unsealed production source present or missing')
    source={}
    for row in rows:
        raw=pinned(directory/'provider'/row['path'],row['sha256'],1048576)
        require(len(raw)==row['bytes'],'source size differs');source[Path(row['path']).name]=raw
    require(manifest.get('schema')=='hepta.module-r10-r1.file-manifest.v1'
            and manifest.get('release_id')=='v150-r10-r1','module manifest identity differs')
    binding_raw=pinned(directory/'module/seal-binding.json',manifest['binding_sha256'],1048576);binding=strict(binding_raw)
    require(binding.get('schema')=='hepta.module-r10-r1.exact-integration.v1'
            and binding.get('release_id')=='v150-r10-r1'
            and binding.get('original_retirement_required') is False
            and binding.get('old_claims_and_actions_preserved') is True
            and binding.get('provider_source_seal_sha256')==sha(seal_raw)
            and binding.get('configuration_sha256')==sha(config_raw)
            and binding.get('service_inputs_sha256')==sha(service_raw)
            and binding.get('server_binary_sha256')==NATIVE_SERVER_SHA
            and binding.get('retirement_sha256')==report.get('retirement_sha256')==manifest.get('retirement_sha256')
            and isinstance(binding.get('retirement_sha256'),str)
            and re.fullmatch('[0-9a-f]{64}',binding['retirement_sha256']),
            'full integration/actual retirement binding differs')
    require(read(directory/'module/SEALED',128)==b'HEPTA_PHONE_LOCAL_V150_R10_R1_REVIEWED_INPUTS_BOUND\n','actual sealed marker missing')
    for row in manifest['files']:
        module_original(directory,row)
    require(binding['payloads']==manifest['payload_files'],'module payload binding differs')
    helper_rows=[x for x in binding['payloads'] if x['path']==HELPER_TARGET]
    require(len(helper_rows)==1 and helper_rows[0]['sha256']==STRICT_FOCUS_SHA and helper_rows[0]['bytes']==20732,'strict unique helper not in real release')
    tree=ast.parse(source['phone_observation_tools.py'])
    helper_pins={n.targets[0].id:ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign)
                 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('FOCUS_INPUT_JAR','FOCUS_INPUT_JAR_SHA256')}
    require(helper_pins=={'FOCUS_INPUT_JAR':HELPER_TARGET,'FOCUS_INPUT_JAR_SHA256':STRICT_FOCUS_SHA},'production helper mapping pin differs')
    operators={x['path']:x for x in seal['operator_helpers']}
    for name,pin in [('register_task_contract.py',REGISTER_SHA),('register_health_contract.py',HEALTH_REGISTER_SHA)]:
        require(name in operators and operators[name]['sha256']==pin,'required registration helper not sealed')
        raw=pinned(directory/'provider'/name,pin,65536);require(len(raw)==operators[name]['bytes'],'registration helper size differs')
    apps=config['approved_apps'];expected_packages={CALC,SETTINGS,'org.trillionnium.hepta.controlprobe'}
    require(set(x['component'].split('/')[0] for x in apps.values())==expected_packages,'reviewed package scope differs')
    require(apps.get('settings_about',{}).get('component')==ABOUT
            and apps.get('计算器',{}).get('component')==CALC+'/.Calculator'
            and apps.get('Unicode验证',{}).get('component')=='org.trillionnium.hepta.controlprobe/.TextEntryActivity'
            and apps.get('视觉挑战',{}).get('component')=='org.trillionnium.hepta.controlprobe/.VisualChallengeActivity'
            and apps.get('设置',{}).get('component')==SETTINGS+'/.homepage.SettingsHomepageActivity'
            and len(apps)==5,'reviewed alias/component mapping differs')
    return {'directory':str(directory),'report':report,'report_raw':report_raw,'source_seal_raw':seal_raw,
            'config_raw':config_raw,'service_raw':service_raw,'binding_raw':binding_raw,'binding':binding,
            'combination_sha256':sha(canonical(binding)),'source':source}

def legacy_module():
    p=BASE/'references/materialize_case_r4.py';raw=pinned(p,LEGACY_SHA,16384)
    m=types.ModuleType('original_fresh_materializer_r4');m.__file__=str(p)
    exec(compile(raw,str(p),'exec'),m.__dict__);return m

def qualified_routes():
    raw=pinned(BASE/'RUNTIME-COMPONENT-QUALIFICATION.json',QUALIFICATION_SHA,16384);q=strict(raw)
    require(q.get('schema')=='hepta.runtime-app-component-qualification.v150.2'
            and q.get('model_requests')==q.get('native_tasks')==0 and q.get('not_model_e2e') is True,
            'operator component provenance differs')
    c=q['calculator'];s=q['settings'];v=s['anchor_value']
    require(c['helper_sha256']==PARENT_FOCUS_SHA and c['focus_then_input_exact'] is True
            and c['single_equals_and_actual_result'] is True,'parent actual input route qualification absent')
    require(s['actual_component']==DETAILS and s['exact_match'] is True
            and v['selector_schema']=='hepta.public-text-anchor.v150.1'
            and v['relation']=='same_direct_preference_text_container'
            and v['title_view_id']=='android:id/title' and v['anchor_text']=='Android 版本'
            and v['value_view_id']=='android:id/summary'
            and v['text']==s['independent_public_system_value']
            and sha(v['text'].encode())==v['utf8_sha256'],'actual unique row or independent reference differs')
    return raw,q

def selected_app_entries(kind, allowed_apps, config):
    """Explicit operator authorization only; no case-to-app inference or default."""
    require(isinstance(allowed_apps, (list, tuple)) or allowed_apps is None,
            'allowed apps must be explicit repeated aliases')
    aliases = list(allowed_apps or [])
    if kind == 'health':
        require(not aliases, 'HEALTH has no app scope and cannot authorize tools')
        return []
    require(1 <= len(aliases) <= 64 and all(isinstance(a, str) and 0 < len(a.encode()) <= 128
            and '\0' not in a for a in aliases) and len(set(aliases)) == len(aliases),
            'business material requires a nonempty explicit app subset without duplicates')
    registry = config.get('approved_apps')
    require(isinstance(registry, dict), 'sealed app registry absent')
    entries = []
    for alias in aliases:
        require(alias in registry and isinstance(registry[alias], dict)
                and isinstance(registry[alias].get('component'), str),
                'explicit alias not in the sealed app registry')
        target = registry[alias]['component']
        require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_.$]*/(?:\.)?[A-Za-z][A-Za-z0-9_.$]*', target)
                and target.split('/')[0] != 'org.trillionnium.owneropen',
                'app target malformed or reserved for typed HEPTA return')
        entries.append({'alias': alias, 'component': target})
    return sorted(entries, key=lambda item: item['alias'])

def validate_material_app_scope(meta, request, scope_raw, config):
    """Recheck material bytes before a Root workflow can stage the contract."""
    if meta['kind'] == 'health':
        require(scope_raw is None and meta.get('template_schema') is None
                and 'app_scope' not in meta and 'app_scope_sha256' not in meta,
                'HEALTH cannot carry business app authority')
        return None
    require(meta.get('template_schema') == 'hepta.task-template.v150.3'
            and isinstance(scope_raw, bytes) and 0 < len(scope_raw) <= 16384,
            'business material requires an explicit bounded v150.3 app scope file')
    scope = strict(scope_raw)
    require(isinstance(scope, dict) and set(scope) == {'schema','owner_request_sha256','apps'}
            and scope['schema'] == 'hepta.task-app-scope.v1'
            and scope['owner_request_sha256'] == sha(request) == meta['request_sha256']
            and isinstance(scope['apps'], list)
            and all(isinstance(x, dict) and set(x) == {'alias','component'} for x in scope['apps']),
            'material scope schema or owner bytes differ')
    expected = selected_app_entries(meta['kind'], [x['alias'] for x in scope['apps']], config)
    require(scope['apps'] == expected and meta.get('app_scope') == scope
            and meta.get('app_scope_sha256') == sha(canonical(scope)),
            'material app tuples, canonical scope digest or metadata differ')
    return scope

def materialize(kind,nonce,release,text=None,allowed_apps=None):
    require(kind in CASES and re.fullmatch('[0-9a-f]{32}',nonce),'case/fresh nonce shape')
    require(kind=='unicode' or text is None,'only Unicode accepts a text file')
    entries = selected_app_entries(kind, allowed_apps, strict(release['config_raw']))
    old=legacy_module();old.SEAL=sha(release['source_seal_raw'])
    if kind in {'health','visual','unicode'}:
        if kind=='unicode' and text is None:
            marker=secrets.token_hex(12)
            text=('本机验收·'+marker+' 🦉📱\n第二行：原样保留 "双引号" \'单引号\' 与 $HOME $(echo literal) ; & | < > '
                  +chr(96)+'反引号'+chr(96)+' \\')
        raw,conditions,extras,meta=old.materialize(kind,nonce,text)
        meta['template_schema']=None if kind=='health' else 'hepta.task-template.v149.1'
    else:
        qraw,q=qualified_routes();extras={'runtime-route-qualification.json':qraw}
        if kind=='calculator':
            a,b,c=(11+secrets.randbelow(19) for _ in range(3))
            expression='('+str(a)+'×'+str(b)+')+'+str(c);result=str(a*b+c)
            require(len(result)<=3 and expression!=q['calculator']['expression'],'fresh bounded formatting-qualified expression required')
            request=('本次 nonce='+nonce+'。打开“计算器”，在实际界面完整输入表达式 '+expression
                     +'，只点击一次等于。公开读回真实计算结果，核验后返回 HEPTA。不要直接输入计算答案；'
                     '结果必须来自本次 App 求值，不能用心算或旧结果替代。动作结果不确定时不重复执行，如实报告。')
            conditions=[{'id':'calculator_expression','kind':'text_readback_exact','package':CALC,
                         'view_id':CALC+':id/formula_or_result','utf8_sha256':sha(expression.encode())},
                        {'id':'calculator_result','kind':'public_text_exact','package':CALC,
                         'view_id':CALC+':id/formula_or_result','utf8_sha256':sha(result.encode())},
                        {'id':'return','kind':'foreground_hepta'}]
            extras.update({'expected-expression.txt':expression.encode(),'expected-result.txt':result.encode()})
            meta={'template_schema':'hepta.task-template.v149.1','arithmetic':{'a':a,'b':b,'c':c},
                  'expression_utf8_sha256':sha(expression.encode()),'expected_result_utf8_sha256':sha(result.encode()),
                  'maximum_input_attempts':1,'maximum_evaluation_attempts':1,
                  'result_view_id':CALC+':id/formula_or_result','input_contract':'hepta.focused-unicode-input.v2',
                  'qualified_parent_helper_sha256':PARENT_FOCUS_SHA,'release_helper_sha256':STRICT_FOCUS_SHA,
                  'strict_helper_native_qualification_is_not_asserted_by_parent_operator_evidence':True}
        else:
            v=q['settings']['anchor_value']
            request=('本次 nonce='+nonce+'。打开设置中公开的“关于手机”页面，按实际界面导航，'
                     '只读取“Android 版本”的当前值。不得更改设置、权限、网络或账户状态。'
                     '结果必须来自本次实际公开页面的原文。无需返回 HEPTA；无法验证时如实报告。')
            conditions=[{'id':'public_setting_value','kind':'public_text_anchor_exact','package':SETTINGS,
                         'component':DETAILS,'title_view_id':v['title_view_id'],'anchor_text':v['anchor_text'],
                         'value_view_id':v['value_view_id'],'utf8_sha256':v['utf8_sha256']}]
            extras['independent-public-reference.json']=enc({'schema':'hepta.independent-public-setting-reference.v1',
                'source_qualification_sha256':QUALIFICATION_SHA,'text':q['settings']['independent_public_system_value'],
                'utf8_sha256':v['utf8_sha256'],'source':'actual read-only getprop paired with operator UI qualification',
                'not_a_prefilled_owner_or_model_answer':True})
            meta={'template_schema':'hepta.task-template.v150.2','approved_entry_alias':'settings_about',
                  'approved_entry_component':ABOUT,'public_result_component':DETAILS,
                  'only_public_readonly_navigation':True,'return_requested':False,
                  'contract_recipe_extension':'explicit_v150_2_unique_direct_preference_row_anchor'}
        raw=request.encode();meta.update({'case':CASES[kind],'kind':kind,'nonce':nonce,
            'request_sha256':sha(raw),'request_utf8_bytes':len(raw),'request_has_trailing_newline':False,
            'contract_required':True,'business_contract_required':True,'health_contract_required':False,
            'registration_helper':'register_task_contract.py','coverage':'entire_request',
            'business_qualification_eligible':True,'registered':False,'dispatched':False,'automatic_replay':False,
            'phone_operations':0,'model_operations':0})
    require(raw.decode().count(nonce)==1,'nonce must occur exactly once')
    if kind != 'health':
        scope = {'schema': 'hepta.task-app-scope.v1', 'owner_request_sha256': sha(raw), 'apps': entries}
        packages = {entry['component'].split('/')[0] for entry in entries}
        require(all('package' not in condition or condition['package'] in packages for condition in conditions),
                'explicit app scope cannot satisfy postconditions for an unauthorized package')
        extras['app-scope.json'] = enc(scope)
        meta.update(template_schema='hepta.task-template.v150.3', app_scope=scope,
                    app_scope_sha256=sha(canonical(scope)),
                    app_scope_authority='explicit_operator_alias_subset_bound_to_exact_request',
                    app_scope_is_not_an_action_plan=True)
    meta.update({'schema':'hepta.fresh-acceptance-material.v150.r10.1','release_id':'v150-r10-r1',
        'candidate_source_seal_sha256':sha(release['source_seal_raw']),
        'combination_sha256':release['combination_sha256'],
        'combination_manifest_sha256':sha(release['binding_raw']),
        'release_build_result_sha256':sha(release['report_raw']),
        'service_inputs_sha256':sha(release['service_raw']),'provider_config_sha256':sha(release['config_raw']),
        'original_materializer_sha256':LEGACY_SHA if kind in {'health','visual','unicode'} else None,
        'source_only_binding_forbidden':True,'phone_readiness_checked_here':False,
        'actual_native_sender_and_ready_gates_required':True,'max_tool_calls':7,'max_model_rounds':8,
        'counts_as_fixed19':kind!='health','counts_as_model_business_pass':False})
    validate_material_app_scope(meta, raw, extras.get('app-scope.json'), strict(release['config_raw']))
    return raw,conditions,extras,meta

def registration_argv(meta,session_id,profile_id):
    for v in (session_id,profile_id):require(isinstance(v,str) and 0<len(v.encode())<=256 and '\0' not in v,'known scope differs')
    remote=GNU+'/cases-r10-r1/'+meta['nonce']
    args=['/usr/bin/python3','-B',GNU+'/provider-r10-r1/'+meta['registration_helper'],
          '--state',GNU+'/provider-state','--request-file',remote+'/request.txt',
          '--session-id',session_id,'--profile-id',profile_id,'--nonce',meta['nonce']]
    if meta['kind']!='health':args+=['--postconditions-file',remote+'/postconditions.json',
                                    '--coverage','entire_request','--template-schema',meta['template_schema'],
                                    '--app-scope-file',remote+'/app-scope.json']
    return remote,args

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind',choices=tuple(CASES));p.add_argument('--release-dir',type=Path,required=True)
    p.add_argument('--build-result-sha256',required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--session-id',required=True);p.add_argument('--profile-id',required=True)
    p.add_argument('--allowed-app', action='append',
                   help='Explicit approved alias; repeat for a reviewed subset. Required for business, forbidden for HEALTH.')
    p.add_argument('--text-file',type=Path);a=p.parse_args()
    require(a.kind=='unicode' or a.text_file is None,'text_file_only_for_unicode')
    release=validate_release(a.release_dir,a.build_result_sha256)
    selected_app_entries(a.kind, a.allowed_app, strict(release['config_raw']))
    text=read(a.text_file,4096).decode('utf-8',errors='strict') if a.text_file else None
    out=a.out.absolute();require(out.parent.is_dir() and out.parent.resolve()==out.parent,'new canonical output parent required')
    os.umask(0o077);out.mkdir(mode=0o700) # Deliberately never recycles an output path.
    intent={'kind':a.kind,'release_build_result_sha256':sha(release['report_raw']),
            'explicit_allowed_apps':a.allowed_app,
            'fresh_nonce_not_yet_allocated':True,'registration_calls':0,'send_attempts':0,'automatic_replay':False}
    files=[write_new(out/'MATERIALIZATION-INTENT.json',enc(intent))]
    nonce=secrets.token_hex(16)
    raw,conditions,extras,meta=materialize(a.kind,nonce,release,text,a.allowed_app)
    remote,args=registration_argv(meta,a.session_id,a.profile_id)
    files.append(write_new(out/'request.txt',raw))
    if conditions is not None:files.append(write_new(out/'postconditions.json',enc(conditions)))
    for name,data in extras.items():files.append(write_new(out/name,data))
    files.append(write_new(out/'combination.json',release['binding_raw']))
    files.append(write_new(out/'release-build-result.json',release['report_raw']))
    files.append(write_new(out/'REGISTRATION-ARGV.json',enc({'schema':'hepta.r10.registration-plan.v1',
        'argv':args,'phone_case_directory':remote,'execute_here':False,'send_attempts':0,
        'selected_scope_must_be_rechecked_by_frozen_sender':True})))
    meta.update(phone_case_directory=remote,files=list(files))
    files.append(write_new(out/'material.json',enc(meta)))
    print(json.dumps({'state':'fresh_bytes_only_no_registration_no_send','case':meta['case'],
        'nonce':nonce,'request_sha256':meta['request_sha256'],'combination_sha256':meta['combination_sha256'],
        'template_schema':meta['template_schema'],'phone_case_directory':remote,'files':files,
        'phone_calls':0,'model_requests':0,'automatic_replay':False},ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()
