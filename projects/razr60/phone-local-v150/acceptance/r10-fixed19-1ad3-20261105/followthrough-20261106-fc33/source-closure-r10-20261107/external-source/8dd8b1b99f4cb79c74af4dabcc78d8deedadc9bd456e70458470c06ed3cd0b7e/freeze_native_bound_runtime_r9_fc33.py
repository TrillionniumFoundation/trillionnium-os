#!/usr/bin/env python3
"""Refreeze one exact successor using the actual R6 reader and held publisher.

No nonce, phone, subprocess or network operation is permitted. REVIEWED_INPUTS
is filled only by the reviewed derivation after the complete admission source
closure and real disposition originals exist. Publication is create-only.
"""
import argparse,ast,base64,copy,hashlib,json,os,re,stat,sys,types,zlib
from pathlib import Path
sys.dont_write_bytecode=True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
OUT=B/'native-guard-r10-r1-operator-fc33-native-v3-r9'
PARENT_FREEZER={'path':str(B/'followthrough-fc33-runtime-r6-review01/freeze_native_bound_runtime_r6_fc33.py'),'bytes':24094,'sha256':'cbb8997c66172054afbd57acb349257d1a8804eff024dbbcb6deb0b438ebcdf3'}
PARENT_PREPARER={'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r8-review01/prepare_native_bound_components_r8_fc33.py', 'bytes': 25742, 'sha256': 'fda4a8793ef8d613345e746d89a6880e47dd32ec28f1f083a723cedad21d5624'}
HELPER={'path':str(B/'library-checkpoint02-resume-a1055-r1/restored/integration-review/diagnostic-root-plan-candidate01/source/prepare_diagnostic_root_plan_once.py'),'bytes':35690,'sha256':'4708d037d58fd5b40e2a15210887ce58d9e7d0857ef27057855031591ee7faf9'}
EXTERNAL_PARENT_PINS={
    'dependencies/p4/preserved_ui_package_phase_r7.py':{'bytes':24731,'sha256':'6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'},
    'dependencies/mac/control_send_once.py':{'bytes':6301,'sha256':'ca200ab35d39ec42232e853c785ab298958858cb4f03e2092231d1ccc638fc70'},
    'dependencies/p4/phone_once.py':{'bytes':5652,'sha256':'179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'}}
REVIEWED_INPUTS={'delta_bundle': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r9-review01/RUNTIME-DELTA.json.gz', 'bytes': 472227, 'sha256': 'd22c2b171b50f5b2c7d03d0e13b89e0f2011538c00cec26066619bec70bfcf49'}, 'validation_originals': [{'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r9-review01/HOST-CONTROLS.json', 'bytes': 1021, 'sha256': '4b3c2db45ea538eae71038ea560fbdcf6ab44b2a33188d50a2571597ef71ede1'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r9-review01/INDEPENDENT-WHOLE-SOURCE-REVIEW.json', 'bytes': 15229, 'sha256': '973211d35935dbfdbc8cbac65b91c83f30a67f8d860ba545f85f0635c55e9335'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r9-review01/INDEPENDENT-CORE-SOURCE-REVIEW.json', 'bytes': 11131, 'sha256': '5469ea94960121138753bc81a2507c033dcf499c92d5f2b8f5e190effe637b11'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r9-review01/INDEPENDENT-ADMISSION-SOURCE-REVIEW.json', 'bytes': 6506, 'sha256': '0520b85652213a490b3893be8449119277ef0d91329d1c31bd759dc5a957c5e5'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r9-review01/ACTUAL-MAC-RETAINED-R8-VERIFICATION.json', 'bytes': 1817, 'sha256': 'ce5d7afa1d86303fab4b4743fa289e5c1fe17b3e22f628ae38c3be21b105f9ca'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r9-review01/ACTUAL-MAC-RETAINED-R8-RESULT.original.json', 'bytes': 6978, 'sha256': 'da35558dabc9c8d061fd96ab891d39697a8220a8d03042a43787be0b936dda8d'}]}
MAXIMUM=33554432
KEYS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
_PUBLICATION=False

def need(v,m):
    if not v:raise ValueError(m)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def meta(v):return [getattr(v,k)for k in KEYS]
def exact3(row):return {k:row[k]for k in ('path','bytes','sha256')}
def audit(event,args):
    if event.startswith(('subprocess.','socket.')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill','os.killpg','os.putenv','os.unsetenv','ctypes.dlopen','ctypes.dlsym'}:
        raise PermissionError('source refreeze excludes process, signal and network operations')
    if event=='open':
        path,mode,flags=args
        writes=(type(mode)is str and any(c in mode for c in 'wax+')) or (type(flags)is int and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        need(not writes or _PUBLICATION,'writes require the original held-directory publisher')
    if event=='os.mkdir':need(_PUBLICATION,'directory creation requires held publication')
    if event in {'os.remove','os.unlink','os.rmdir','os.rename','os.replace','os.symlink','os.link','os.chmod','os.chown','os.truncate','os.utime','os.chflags'}:
        raise PermissionError('existing originals and namespaces are immutable')
def initial(row):
    p=Path(row['path']);need(p.is_absolute() and p.resolve(strict=True)==p,'canonical exact source')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==row['bytes'],'complete regular source')
        with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(row['bytes']+1)
        need(pin(raw)=={k:row[k]for k in ('bytes','sha256')}and meta(a)==meta(os.fstat(fd))==meta(p.lstat()),'source full9/byte bookends')
        return raw
    finally:os.close(fd)
def module(raw,name,path):
    m=types.ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m

def validate_delta(bundle,prior,parent_files,h):
    need(type(bundle)is dict and set(bundle)=={'schema','assembly','files'}
        and bundle['schema']=='hepta.fc33.r9.whole-runtime-delta.v1','exact successor delta envelope')
    a=bundle['assembly']
    need(a['state']=='SOURCE_ASSEMBLED_WITH_TYPED_R6_DISPOSITION_RETAINED_R7_AND_STAGED_R8'
        and a['target_root']==str(OUT)and a['parent_freeze']==exact3(prior['self_descriptor'])
        and a['runtime_members']==38 and a['root_members']==3 and a['shared_members']==17
        and a['new_nonces']==a['phone_calls']==a['fixed19_credit']==0
        and a['execution_eligible']is False and a['actual_host_freeze_executed']is False
        and a['original_native_previous_roots']==44 and a['effective_initial_roots']==49
        and a['after_NEG01_roots']==52 and a['after_NEG02_roots']==55,
        'complete source selection cannot claim execution or inherit case credit')
    rows=bundle['files'];need(type(rows)is list and 0<len(rows)<=64,'bounded successor delta')
    allowed={'runtime/source/'+n+'.py'for n in ('component_lifecycle','component_snapshot','close_component','late_boundary','send_new_native_guard_task_r10_r4')}
    allowed.update({'runtime/MANIFEST.json','root-chain/source/run_component_root_once.py','root-chain/source/phone_chain_bridge.py',
        'root-chain/SOURCE-MANIFEST.json','dependencies/BUDGET.json','dependencies/DEPENDENCIES.json','reference/R9-SOURCE-INVERSES.json'})
    allowed.update('dependencies/admission/'+n+'.py'for n in ('admission_entry','bound02_disposition','build_fence_plan','verify_retained_preaccept','verify_retained_staged_r8','prepare_fresh_admission_input'))
    need({r['path']for r in rows}==allowed and len(rows)==len(allowed),'closed complete source/dependency delta family')
    delta={}
    for row in rows:
        need(set(row)=={'path','bytes','sha256','base64'},'exact whole delta member')
        raw=base64.b64decode(row['base64'],validate=True);need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'delta original pin')
        if row['path'].endswith('.py'):compile(raw,row['path'],'exec')
        delta[row['path']]=raw
    need(a['files']==[dict(path=n,**pin(raw))for n,raw in sorted(delta.items())],'complete delta assembly manifest')
    files=dict(parent_files);files.update(delta)
    for key,name,count in [('runtime_manifest','runtime/MANIFEST.json',38),('root_manifest','root-chain/SOURCE-MANIFEST.json',3)]:
        need(a[key]==dict(path=str(OUT/name),**pin(files[name])),'actual exact successor manifest')
        manifest=h.strict(files[name]);members=manifest['files'];old=h.strict(parent_files[name])['files']
        need(len(members)==count and {r['path']for r in members}=={r['path']for r in old},'unchanged exact member-name set')
        for row in members:
            target=str(Path(name).parent/row['path']);need(pin(files[target])=={k:row[k]for k in ('bytes','sha256')},'whole manifest member pin')
    for name,raw in parent_files.items():
        if name not in delta:need(files[name]==raw,'unchanged complete actual parent member: '+name)
        if name.startswith(('runtime/reference/','shared/','retained-history/','retained-source-parent/'))or name in ('COMBINATION.json','SOURCE-SEAL.json','SOURCE-INPUTS.json','ARTIFACTS.json','SOURCE-PARENT-RECORDS.json'):
            need(files[name]==raw,'historical/shared original changed: '+name)
    need(files['runtime/source/component_common.py']==parent_files['runtime/source/component_common.py']
        and files['runtime/source/stage_component.py']==parent_files['runtime/source/stage_component.py']
        and files['dependencies/BUDGET.json']==parent_files['dependencies/BUDGET.json'],
        'common, stage and original wall-time/byte budgets remain exact')
    need(pin(files['runtime/source/component_lifecycle.py'])=={'bytes':48643,'sha256':'eb43d1f5df1b0e4295770c82328fd17e09b9eaa766861f3803928a0b1f9f4e18'},
        'only the exact selected initial-sidecar-r2 lifecycle source')
    need(len(files['runtime/source/late_boundary.py'])<262144,'unchanged bounded late source size')
    proof=h.strict(files['reference/R9-SOURCE-INVERSES.json'])
    required={n for n in delta if n.endswith('.py')and n.startswith(('runtime/','root-chain/'))}
    need(set(proof['derivations'])==required,'every changed existing source requires complete actual-parent inverse')
    for name,row in proof['derivations'].items():
        need(row['candidate']==pin(files[name])and row['complete_byte_inverse']is True,'complete inverse candidate source')
        raw=files[name]
        for change in reversed(row['changes']):
            at=change['offset'];new=change['new_utf8'].encode();old=change['old_utf8'].encode()
            need(type(at)is int and at>=0 and raw[at:at+len(new)]==new,'exact complete inverse byte offset')
            raw=raw[:at]+old+raw[at+len(new):]
        need(pin(raw)==row['parent']==pin(parent_files[name]),'complete inverse must reach exact actual R8 source')
    def prior_function(raw):
        text=raw.decode();tree=ast.parse(text)
        return ast.get_source_segment(text,next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate_current_prior')).encode()
    old=prior_function(parent_files['root-chain/source/run_component_root_once.py'])
    new=prior_function(files['root-chain/source/run_component_root_once.py'])
    change=proof['validate_current_prior_exact_count_adaptation']
    need(proof['existing_validate_current_prior_unchanged']is False
         and change['before']==pin(old)and change['after']==pin(new)
         and new.count(change['new_utf8'].encode())==1
         and new.replace(change['new_utf8'].encode(),change['old_utf8'].encode())==old
         and change['all_other_function_bytes_identical']is True,
         'only the independently reviewed explicit typed retained-count block may change')
    return files,a

def verify_current_readers(files,h,prior,assembly,o):
    """Run the existing pure phone-family readers against current selected bytes."""
    package=h.strict(files['runtime/MANIFEST.json'])
    sources={r['path']:files['runtime/'+r['path']]for r in package['files']}
    original=sys.modules.get('component_common');oldpath=sys.path[:]
    try:
        common=module(sources['source/component_common.py'],'component_common',OUT/'runtime/source/component_common.py')
        sys.modules['component_common']=common
        late=types.ModuleType('exact_r7_late_source_validation');late.__file__=str(OUT/'runtime/source/late_boundary.py')
        late.__reviewed_source_sha256__=pin(sources['source/late_boundary.py'])['sha256']
        late.__reviewed_package_sources__=sources
        exec(compile(sources['source/late_boundary.py'],late.__file__,'exec'),late.__dict__)
        def old39(row):
            need(row==late.reviewed_v3_runtime_diagnostic_ancestor()['inventory'],'only exact retained old39 source callback')
            raw=files['retained-history/native-00/inventory.original.json']
            need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'whole retained old39 original bytes');return raw
        late.__retained_stage_read_pinned__=old39
        retained=late.install_retained_preaccept_host_reader(lambda row:o.read(exact3(row)))
        need(retained['retained_preaccept_binding']==assembly['retained_preaccept_binding'],
             'same actual retained proof through exact host/phone byte mapping')
        late.install_retained_failed_staged_host_reader(lambda row:o.read(exact3(row)))
        staged=late.retained_failed_staged()
        need(staged['retained_failed_staged_binding']==assembly['retained_failed_staged_binding'],
             'same complete actual R8 staged proof through the explicit second host mapping')
        late.validate_current_package_manifest(package)
        late.current_context(prior['combination']['sha256'],assembly['runtime_manifest']['sha256'])
        records=late.reviewed_source_parent_records()
        need(records==h.strict(files['SOURCE-PARENT-RECORDS.json'])and len(records)==1,'exact actual source-parent reader')
        histories=[]
        for i,record in enumerate(records):
            prefix='retained-source-parent/%02d/'%i
            raw={key:files[prefix+key+'.original.json']for key in ('boundary','inventory','closure')}
            value,inventory,closure=late.closed_boundary_originals(raw['boundary'],raw['inventory'],raw['closure'],
                original_descriptor=record['boundary'],combination_sha256=prior['combination']['sha256'],
                package_sha256=assembly['runtime_manifest']['sha256'])
            previous=h.strict(files[prefix+'ACTUAL-PREVIOUS-INPUT.json'])
            need(previous['identity']==value['scope']and previous['late_boundary']==record['boundary']
                and previous['component_qualified']is True,'original source parent credit remains its own')
            selected,selected_pin,selection=late.effective_current_prior_inventory(value,inventory,late.non_native_sidebranches())
            need(late.validate_r9_prior_selection(value,inventory,selected,selected_pin,selection,next_case='NEG-01')==49,
                 'complete native44 original plus separately proved R7three and R8two')
            histories.append(value)
        tail=sorted(n for n in files if re.fullmatch(r'retained-history/native-\d\d/boundary.original.json',n))
        need(len(tail)==9,'all nine exact failed ancestors')
        histories.extend(h.strict(files[n])for n in tail);late.require_failed_ancestor_tail(histories)
        need(late.SOURCE_PARENT_INVENTORY_ROOT_COUNT==44 and late.MAX_CURRENT_INVENTORY_ROOTS==50
            and late.MAX_CHAIN==12 and late.COMPONENT_ROLE_CAP==42 and late.MAX_FIXTURE_ROOTS==14,'unchanged finite phone resource contract')
        return {'state':'PURE_CURRENT_SOURCE_AND_RETAINED_ORIGINALS_ACCEPTED','runtime_members':38,
            'source_parent_count':1,'failed_ancestor_count':9,'actual_phone_inventory_observed':False,
            'native_source_parent_roots':44,'retained_preaccept_roots':3,'retained_failed_staged_roots':2,'effective_initial_roots':49,
            'retained_preaccept_binding':retained['retained_preaccept_binding'],
            'retained_failed_staged_binding':staged['retained_failed_staged_binding'],
            'retained_failed_staged_role_count':0,'retained_failed_staged_native_terminal':None,
            'retained_failed_staged_global_unknown_effect_count':None,
            'phone_manifest_mapping_is_actual_phone_readback':False,
            'current_case_credit':0,'phone_calls':0,'existing_phone_live_rechecks_required':True}
    finally:
        sys.path[:]=oldpath
        if original is None:sys.modules.pop('component_common',None)
        else:sys.modules['component_common']=original

def admission_preflight(files,h,o):
    names=('build_fence_plan', 'verify_retained_preaccept', 'verify_retained_staged_r8', 'bound02_disposition', 'admission_entry');saved={n:sys.modules.get(n)for n in names}
    try:
        for name in names:
            rel='dependencies/admission/'+name+'.py';raw=files[rel]
            m=module(raw,name,OUT/rel);sys.modules[name]=m
        entry=sys.modules['admission_entry'];D=sys.modules['bound02_disposition']
        need(type(entry.RESOLUTION)is dict and type(entry.RETAINED_PREACCEPT)is dict
             and type(entry.RETAINED_FAILED_STAGED)is dict,'all exact original dispositions must be source-bound before refreeze')
        # This is the original-data disposition verifier only, not fresh admission.
        result=D.verify_disposition(entry.RESOLUTION,read_pinned=lambda row:o.read(exact3(row)))
        need(result['state']=='RETIRED_WITH_ORIGINAL_OUTCOME_UNKNOWN'and result['original_terminal']is None
            and result['fresh_execution_eligible']is False and result['native_case_credit']is False
            and all(v is None for v in result['effect_counts'].values()),'original unknown semantics changed')
        retained=D.verify_retained_preaccept(entry.RETAINED_PREACCEPT,read_pinned=lambda row:o.read(exact3(row)))
        need(retained['native_case_credit']==0 and retained['native_terminal']is None
             and retained['global_unknown_effect_count']is None
             and retained['original_roles_joined_and_groups_absent']is False,
             'actual retained failure remains separate from original R6 disposition')
        staged=D.verify_retained_failed_staged(entry.RETAINED_FAILED_STAGED,retained=retained,
             read_pinned=lambda row:o.read(exact3(row)))
        need(staged['native_case_credit']==0 and staged['native_terminal']is None
             and staged['global_unknown_effect_count']is None and staged['component_role_identities']=={}
             and staged['original_remote_cleanup_boolean']is False and staged['historical_gate_failure_cause']=='UNKNOWN',
             'the original R8 failure cannot be converted to a terminal, role or case qualification')
        return {'original_R6_disposition':result,'retained_R7_preaccept':
            {k:retained[k]for k in ('state','retained_preaccept_binding','native_case_credit',
             'native_terminal','global_unknown_effect_count','original_roles_joined_and_groups_absent')},
             'retained_R8_staged':{k:staged[k]for k in('state','retained_failed_staged_binding',
                 'native_case_credit','native_terminal','global_unknown_effect_count','original_remote_cleanup_boolean',
                 'historical_gate_failure_cause','component_role_identities')},'fresh_execution_eligible':False}
    finally:
        for name,old in saved.items():
            if old is None:sys.modules.pop(name,None)
            else:sys.modules[name]=old

def main():
    global _PUBLICATION
    p=argparse.ArgumentParser();p.add_argument('--freeze-reviewed-host-runtime',required=True);args=p.parse_args()
    need(type(REVIEWED_INPUTS)is dict and set(REVIEWED_INPUTS)=={'delta_bundle','validation_originals'},
        'UNBOUND_EXACT_SUCCESSOR_SOURCE_AND_REVIEW_NO_IO_OR_PUBLICATION')
    need(type(REVIEWED_INPUTS['validation_originals'])is list and len(REVIEWED_INPUTS['validation_originals'])>=2,
        'actual independent source/inverse and effect-boundary controls required')
    sys.addaudithook(audit)
    own=Path(__file__).absolute();own_row={'path':str(own),'bytes':own.stat().st_size,'sha256':args.freeze_reviewed_host_runtime}
    ownraw=initial(own_row)
    parent=module(initial(PARENT_FREEZER),'exact_r6_freezer_for_publisher',PARENT_FREEZER['path'])
    pre=module(initial(PARENT_PREPARER),'exact_r6_successor02_reader',PARENT_PREPARER['path'])
    h=module(initial(HELPER),'exact_host_original_reader',HELPER['path']);o=h.Originals()
    for row in (own_row,PARENT_FREEZER,PARENT_PREPARER,HELPER):o.read(row)
    # The unchanged actually executed R8 reader verifies its original successful
    # controller, all actual input generations, all 145 outputs and both terminals.
    prior,parent_files,_entry,parent_controller=pre.verify_freeze(h,o)
    prior=dict(prior,self_descriptor=pre.FROZEN_INPUTS['freeze'])
    need(OUT.parent.resolve(strict=True)==OUT.parent and not os.path.lexists(OUT),'one new canonical source namespace')
    packed=o.read(REVIEWED_INPUTS['delta_bundle'])
    need(len(packed)<=1048576,'unchanged reviewed compressed delta bound')
    decoder=zlib.decompressobj(16+zlib.MAX_WBITS);unpacked=decoder.decompress(packed,8*1024*1024+1)
    need(len(unpacked)<=8*1024*1024 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
        'one complete bounded gzip delta with unchanged original limits')
    bundle=h.strict(unpacked)
    files,assembly=validate_delta(bundle,prior,parent_files,h)
    current_reader_validation=verify_current_readers(files,h,prior,assembly,o)
    disposition=admission_preflight(files,h,o)
    package=h.strict(files['runtime/MANIFEST.json']);root=h.strict(files['root-chain/SOURCE-MANIFEST.json'])
    deps=h.strict(files['dependencies/DEPENDENCIES.json'])
    need(deps['execution_eligible']is False and deps['new_nonces']==deps['phone_calls']==deps['fixed19_credit']==0,'dependencies source-only scope')
    for row in deps['selected_files']:
        raw=files[row['retained_member']]
        need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'complete selected external source pin')
    source_pins={n:dict(path=str(OUT/'dependencies/admission'/(n+'.py')),**pin(files['dependencies/admission/'+n+'.py']))
        for n in ('build_fence_plan', 'verify_retained_preaccept', 'verify_retained_staged_r8', 'bound02_disposition', 'admission_entry')}
    need(package['original_attempt_admission_sources']==root['followthrough_execution_admission']['sources']
        ==deps['typed_disposition_consumer_and_entry_adapter']['sources']==source_pins,'one exact five-source admission dependency closure')
    for name in ('root-chain/source/run_component_root_once.py','runtime/source/send_new_native_guard_task_r10_r4.py'):
        need(h.literal(files[name],'ADMISSION_SOURCE_PINS')==source_pins,'actual selected entry binds the complete same admission closure')
    need(root['explicit_execution_dependencies']==dict(path=str(OUT/'dependencies/DEPENDENCIES.json'),**pin(files['dependencies/DEPENDENCIES.json']))
        and deps['budget']==pin(files['dependencies/BUDGET.json']),'exact external dependencies and unchanged budget inputs')
    need(package['current_combination_sha256']==root['current_combination_sha256']==prior['combination']['sha256'],
        'one unchanged production combination')
    for name,value in {'PKG':assembly['runtime_manifest']['sha256'],
        'COMBINATION':prior['combination']['sha256'],'SHARED':prior['shared_materials']['sha256'],
        'SENDER':pin(files['runtime/source/send_new_native_guard_task_r10_r4.py'])['sha256'],
        'ACTOR':pin(files['dependencies/p4/phone_once.py'])['sha256']}.items():
        need(h.literal(files['root-chain/source/run_component_root_once.py'],name)==value,'exact selected Root binding: '+name)
    need(h.literal(files['root-chain/source/phone_chain_bridge.py'],'PKG')==assembly['runtime_manifest']['sha256'],
        'exact selected phone bridge package')
    validations=[]
    for i,row in enumerate(REVIEWED_INPUTS['validation_originals']):
        raw=o.read(row);files['validation/r9-%02d.original.json'%i]=raw;validations.append(row)
    pub_raw=o.read(parent.PUBLISHER);publish,publisher_proof,publisher_body=parent.publisher(pub_raw)
    files.update({'reference/R8-FREEZE-RESULT.original.json':o.read(pre.FROZEN_INPUTS['freeze']),
        'reference/R8-HOST-VALIDATION.original.json':parent_files['HOST-VALIDATION.json'],
        'reference/R8-SOURCE-ASSEMBLY.original.json':parent_files['SOURCE-ASSEMBLY.original.json'],
        'FREEZER-SOURCE.original.py':ownraw,'SOURCE-ASSEMBLY.original.json':enc(assembly),
        'reference/HELD-DIRECTORY-PUBLISHER.py':publisher_body})
    checks=copy.deepcopy(prior['checks'])
    checks.update(schema='hepta.fc33.native-bound.host-validation.v1',
        parent_actual_freeze=pre.FROZEN_INPUTS['freeze'],parent_actual_controller=parent_controller,
        current_original_disposition=disposition,publisher=publisher_proof,validation_originals=validations,
        current_phone_reader_pure_source_validation=current_reader_validation,
        phone_live_inventory_and_late_boundary_readers_unchanged=False,
        source_parent44_originals_and_all_legacy_validators_preserved=True,
        retained_R7_explicit_typed_host_and_phone_adapter=True,
        retained_R8_explicit_typed_host_and_phone_adapter=True,
        failed_R8_two_roots_zero_roles_and_original_unknowns_preserved=True,
        actual_phone_retained_original_publication_attested=False,
        current_runtime_admission_requires_fresh_explicit_input=True,
        actual_external_dependency_deployment_readback=None,phone_calls=0,full19_qualified=False)
    files['HOST-VALIDATION.json']=enc(checks);o.recheck()
    output_rows={name:dict(path=str(OUT/name),**pin(raw))for name,raw in sorted(files.items())}
    result={'schema':'hepta.fc33.native-bound.actual-host-freeze.v1','state':'FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED',
        'source':own_row,'output':str(OUT),'parent_freeze':pre.FROZEN_INPUTS['freeze'],
        'shared_derivation':prior['shared_derivation'],'reviewed_delta_bundle':REVIEWED_INPUTS['delta_bundle'],
        'actual_input_files':copy.deepcopy(o.rows),'files':output_rows,
        'runtime_manifest':output_rows['runtime/MANIFEST.json'],'root_chain_manifest':output_rows['root-chain/SOURCE-MANIFEST.json'],
        'shared_materials':output_rows['shared/SHARED-MATERIALS.json'],'dependencies':output_rows['dependencies/DEPENDENCIES.json'],
        'combination':output_rows['COMBINATION.json'],'actual_adoption':prior['actual_adoption'],'actual_policy':prior['actual_policy'],
        'checks':checks,'payload_bytes':sum(map(len,files.values())),'terminal_copies':2,'result_bytes':0,'complete_directory_bytes':0,
        'maximum_complete_directory_bytes':MAXIMUM,'all_inputs_bookended_before_publication':True,'all_output_files_read_back':True,
        'terminal_record_is_last':True,'automatic_retry':False,'phone_calls':0,'native_submissions':0,'new_nonces':0,
        'full19_qualified':False,'production_ready':False,'rollback_admission_is_separate_required_gate':True}
    for _ in range(16):
        raw=enc(result);n=len(raw)
        if result['result_bytes']==n and result['complete_directory_bytes']==result['payload_bytes']+2*n:break
        result.update(result_bytes=n,complete_directory_bytes=result['payload_bytes']+2*n)
    else:raise ValueError('complete terminal byte accounting did not stabilize')
    need(result['complete_directory_bytes']<=MAXIMUM,'whole successor bounded including both terminal copies')
    files['FREEZE-RESULT.json']=raw;files['DERIVATION.json']=raw
    _PUBLICATION=True
    try:publish(OUT,files)
    finally:_PUBLICATION=False
    freeze={'path':str(OUT/'FREEZE-RESULT.json'),**pin(raw)}
    need(initial(freeze)==raw and initial({'path':str(OUT/'DERIVATION.json'),**pin(raw)})==raw,'both actual terminal readbacks')
    print(json.dumps({'state':result['state'],'freeze':freeze,'runtime_manifest':result['runtime_manifest'],
        'root_chain_manifest':result['root_chain_manifest'],'combination':result['combination'],
        'dependencies':result['dependencies'],'complete_directory_bytes':result['complete_directory_bytes'],
        'phone_calls':0,'full19_qualified':False},sort_keys=True))
if __name__=='__main__':main()
