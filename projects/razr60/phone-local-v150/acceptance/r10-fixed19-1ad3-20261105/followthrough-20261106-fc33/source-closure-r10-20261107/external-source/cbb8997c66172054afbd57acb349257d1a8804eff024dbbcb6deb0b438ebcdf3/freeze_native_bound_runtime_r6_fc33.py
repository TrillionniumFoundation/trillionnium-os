#!/usr/bin/env python3
"""Freeze reviewed R6 sources and actual history. No phone, process or network calls."""
import ast,base64,copy,gzip,hashlib,json,os,re,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
R4=B/'native-guard-r10-r1-operator-final-v3-getattr-a1055-r4'
OUT=B/'native-guard-r10-r1-operator-fc33-native-v3-r6'
MATERIAL=B/'followthrough-20261106-fc33-shared-material-v3-01'
OLD_PREPARER={'path':str(B/'final-runtime-actual-adoption-source-a1055-r1/source/prepare_final_component_plan_v4.py'),'bytes':59395,'sha256':'77c7c1007f951e35843f6a4e0908fd7652bd9bc30ce3527c978233abc840d6e2'}
OLD_FREEZE={'path':str(R4/'FREEZE-RESULT.json'),'bytes':607602,'sha256':'2562f9b429ca5cd81fb477fd67baf71d4164405f8808b2953f35622038563107'}
MATERIAL_DERIVATION={'path':str(MATERIAL/'DERIVATION.json'),'bytes':19087,'sha256':'adaba62c40a49d61f0f809ad5f389ca52d900ec4b6415de829a5f9a708a738e3'}
PUBLISHER={'path':'/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/followthrough-20261106-fc33-source-propagation01/derive_reviewed_source_material_v3.py','bytes':16399,'sha256':'842f893107dfff481e516419da3fd9b1e2c2445378903012658530d83429ac82'}
CLEANUP_HOME=B/'owned-unstarted-stage-cleanup-neg02-final04-a1055-candidate01/foreign-retained-reference01/cleanup02-import01'
CLEANUP_READER={'path':str(CLEANUP_HOME/'source/verify_owned_current44_cleanup.py'),'bytes':69563,'sha256':'265134fb8632097388a85164be1c8d160533183415cfd725ae2e70da02b61ff2'}
CLEANUP_INPUTS={'path':str(CLEANUP_HOME/'INPUTS.json'),'bytes':774,'sha256':'2edb818d53b320cb402154bf8dfc750a6a7c1cb8d64929ac9e3f5a7e3135058b'}
# The constructor fills only this exact literal after actual controls are read.
REVIEWED_INPUTS = {'delta_bundle': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r6-review01/RUNTIME-DELTA.json.gz', 'bytes': 354879, 'sha256': '9e55afe114fb1a87280f6cebeb515f33ff9b3b02ddfb81ffba7decb345246852'}, 'validation_originals': [{'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-source-parent-late01/CONTROL-RESULT01/RESULT.json', 'bytes': 6931, 'sha256': '7bd2fc99b5bb2ae912b28b41ed2fb0ca920f30844cf51bf98cdf3bbf0ecf52f9'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-source-parent-late01/CONTROL-RESULT01/ROOT-VERIFIER-ORIGINAL-TRANSPORT.json', 'bytes': 4704, 'sha256': '45a1c022c8135b60e39d811ee5ec22724903cb07d1c226fc11724a335743f73e'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-trace-controls-v2-RESULT.json', 'bytes': 3555, 'sha256': '9151c6281a8bd50ebd816c0ef737eebed4a8abd9bd912de72f889ede34b33df5'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r6-review01/UI-HOST-CONTROLS.original.json', 'bytes': 5402, 'sha256': '7cdd420fd5f5055509b0659a109d5932bcc7a3ce27e440a4957db091fbd07348'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r6-review01/BUDGET-REVIEW.json', 'bytes': 10265, 'sha256': '5bd89ce7a882e33417fb5b96b4b3d1314c11c7894506539ee4669a6d10f3fe8e'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r6-review01/SOURCE-INVERSE-REVIEW.json', 'bytes': 5616, 'sha256': 'a06e6de57574cd719771d060fef41fc12ca5bc846f1b738ce91d0e51f7c85851'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r6-review01/FINAL-INDEPENDENT-REVIEW.json', 'bytes': 11661, 'sha256': '34ab4c9d164ae634e938a1c5a4348778c6e2d7735f6e4c5a75b045c7957b7125'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r6-review01/R6-SOURCE-DELTA.json', 'bytes': 4898, 'sha256': '1eaae749a6b58b1b5006e86c680c9944d8c84cd3aa5e0fd1beea4f5441721d0d'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r6-review01/ASSEMBLY.json', 'bytes': 9976, 'sha256': 'a299c6c520d34bd92a4b43812c97ca0b575824692fec2e08f2993b1c04d42e74'}, {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r5/FREEZE-RESULT.json', 'bytes': 1039896, 'sha256': 'd6ae0199011ddb9bfa86d8d0c4b9818e3a9037141f5441e85d43085874fd4a3c'}]}
MAXIMUM=33554432
KEYS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
_PUBLICATION=False

def need(v,s):
    if not v:raise ValueError(s)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def meta(v):return [getattr(v,k) for k in KEYS]
def exact3(row):return {k:row[k] for k in ('path','bytes','sha256')}
def audit(event,args):
    if event.startswith(('subprocess.','socket.')) or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill','os.killpg','os.putenv','os.unsetenv','ctypes.dlopen','ctypes.dlsym'}:
        raise PermissionError('host source freeze excludes process, signal and network operations')
    if event=='open':
        path,mode,flags=args
        writes=(type(mode)is str and any(c in mode for c in 'wax+')) or (type(flags)is int and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        need(not writes or _PUBLICATION,'writes require the held-directory publication phase')
    if event=='os.mkdir':need(_PUBLICATION,'directories require the held-directory publication phase')
    if event in {'os.remove','os.unlink','os.rmdir','os.rename','os.replace','os.symlink','os.link','os.chmod','os.chown','os.truncate','os.utime','os.chflags'}:
        raise PermissionError('source originals and existing namespaces are immutable')

def initial(row):
    p=Path(row['path']);need(p.is_absolute() and p.resolve(strict=True)==p,'canonical pinned source')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==row['bytes'],'whole pinned source')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(row['bytes']+1)
        need(pin(raw)=={k:row[k]for k in ('bytes','sha256')}and meta(before)==meta(os.fstat(fd))==meta(p.lstat()),'source full9 and byte bookends')
        return raw
    finally:os.close(fd)

def module(raw,name,path):
    m=types.ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m

def publisher(raw):
    text=raw.decode();tree=ast.parse(text)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='publish_material']
    need(len(nodes)==1,'one exact original publisher')
    original=ast.get_source_segment(text,nodes[0])+'\n'
    old=" directories=('', 'shared', 'shared/provider', 'shared/provider/source', 'reference')\n"
    new=(" need(0<len(files)<=256 and sum(map(len,files.values()))<=33554432,'complete bounded runtime file set')\n"
         " parents={str(parent)for name in files for parent in Path(name).parents if str(parent)!='.'}\n"
         " need(len(parents)<=128,'bounded runtime directory set')\n"
         " directories=('',)+tuple(sorted(parents,key=lambda p:(len(Path(p).parts),p)))\n")
    need(original.count(old)==1,'only the closed directory inventory is extended')
    candidate=original.replace(old,new,1)
    need(candidate.replace(new,old,1)==original,'exact complete publisher inverse')
    # The original publication body, same FD ownership, all full9 checks and
    # terminal-last protocol, now operates on this reviewed complete file tree.
    ns=module(raw,'fc33_material_publisher_parent',PUBLISHER['path'])
    exec(compile(candidate,'<reviewed-bounded-runtime-publisher>','exec'),ns.__dict__)
    return ns.publish_material,{'parent_function':pin(original.encode()),'candidate_function':pin(candidate.encode()),
        'only_directory_inventory_and_bounds_changed':True,'exact_whole_function_inverse':True},candidate.encode()

def main():
    global _PUBLICATION
    need(len(sys.argv)==3 and sys.argv[1]=='--freeze-reviewed-host-runtime','explicit source-only freeze mode')
    need(type(REVIEWED_INPUTS)is dict and set(REVIEWED_INPUTS)=={'delta_bundle','validation_originals'},
         'UNBOUND_ACTUAL_REVIEW_INPUTS_NO_IO_OR_PUBLICATION')
    need(type(REVIEWED_INPUTS['validation_originals'])is list and len(REVIEWED_INPUTS['validation_originals'])>=2,
         'actual history and trace verification originals required')
    sys.addaudithook(audit)
    own=Path(__file__).absolute();ownraw=initial({'path':str(own),'bytes':own.stat().st_size,'sha256':sys.argv[2]})
    oldraw=initial(OLD_PREPARER);old=module(oldraw,'fc33_exact_r4_preparer',OLD_PREPARER['path'])
    h,helper_raw=old.load_helpers();o=h.Originals()
    o.read(OLD_PREPARER);o.read({'path':str(old.HELPER),**old.HELPER_PIN})
    source={'path':str(own),**pin(ownraw)};need(o.read(source)==ownraw,'executed source changed')
    prior,parent_files,_,_=old.verify_frozen(h,o,OLD_FREEZE)
    need(OUT.parent.resolve(strict=True)==OUT.parent and not os.path.lexists(OUT),'fresh canonical runtime output required')
    material_raw=o.read(MATERIAL_DERIVATION);material=h.strict(material_raw)
    need(material['state']=='DERIVED_SHARED_SOURCE_MATERIAL_ONLY'
         and material['combination']=={'bytes':4695,'sha256':'7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}
         and material['changed_sources']==['daily_phone_local.py','phone_local_tools.py','phone_observation_tools.py','provider_codex_host.py','provider_phone_local.py']
         and material['source_count']==15 and material['shared_member_count']==17
         and material['exact_object_inverses_verified']is True and material['phone_calls']==0,
         'one exact actual final five-source material derivation required')
    for row in material['input_originals']:
        o.read(exact3(row));need(o.rows[row['path']]==row,'actual shared input generation changed')
    shared_files={}
    for row in material['files']:
        p=Path(row['path']);need(not p.is_absolute()and str(p)==row['path']and '..'not in p.parts,'canonical shared member')
        shared_files[row['path']]=o.read({'path':str(MATERIAL/p),**{k:row[k]for k in ('bytes','sha256')}})
    packed=o.read(REVIEWED_INPUTS['delta_bundle'])
    need(len(packed)<=1048576,'reviewed delta bundle compressed bound')
    import zlib
    decoder=zlib.decompressobj(16+zlib.MAX_WBITS);unpacked=decoder.decompress(packed,8*1024*1024+1)
    need(len(unpacked)<=8*1024*1024 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'one complete bounded gzip delta')
    bundle=h.strict(unpacked);assembly=bundle['assembly']
    need(bundle['schema']=='hepta.fc33.reviewed-runtime-delta-bundle.v1'
         and assembly['state']=='SOURCE_CANDIDATE_NO_PHONE_QUALIFICATION'
         and assembly['phone_calls']==assembly['new_nonces']==0 and assembly['runtime_member_count']==38
         and assembly['root_member_count']==3 and assembly['material_derivation']==pin(material_raw),
         'complete reviewed source assembly required')
    allowed={'runtime/source/'+n+'.py'for n in ('close_component','native_guard_session_r2','component_lifecycle','component_snapshot','root_fixture_originals','prepare_component','stage_component','root_fixture_once','sender_native_guard_ready_r10_r4','send_new_native_guard_task_r10_r4','late_boundary')}
    allowed.update({'runtime/reference/REVIEWED-PRODUCTION-PINS.json','runtime/reference/source_parent_late_boundary_r4.py','runtime/MANIFEST.json','root-chain/source/run_component_root_once.py','root-chain/source/phone_chain_bridge.py','root-chain/SOURCE-MANIFEST.json'})
    need(len(bundle['files'])==len(allowed)==17 and {r['path']for r in bundle['files']}==allowed,'closed exact runtime delta set')
    delta={}
    for row in bundle['files']:
        need(set(row)=={'path','bytes','sha256','base64'},'exact delta member')
        raw=base64.b64decode(row['base64'],validate=True)
        need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'whole candidate source pin')
        if row['path'].endswith('.py'):compile(raw,row['path'],'exec')
        delta[row['path']]=raw
    need([{ 'path':name,**pin(raw)}for name,raw in sorted(delta.items())]==assembly['files'],'assembly delta inventory differs')
    files={name:raw for name,raw in parent_files.items() if name.startswith(('runtime/','root-chain/','retained-history/'))
           or name in {'ARTIFACTS.json','POLICY-ADOPTION.original.json','FULL-HISTORICAL-ANCESTOR-PINS.json'}}
    files.update(delta)
    files.update({name:raw for name,raw in shared_files.items() if name.startswith('shared/') or name in {'COMBINATION.json','SOURCE-SEAL.json','SOURCE-INPUTS.json'}})
    package=h.strict(files['runtime/MANIFEST.json']);root=h.strict(files['root-chain/SOURCE-MANIFEST.json'])
    need(pin(files['runtime/MANIFEST.json'])==assembly['runtime_manifest'] and pin(files['root-chain/SOURCE-MANIFEST.json'])==assembly['root_manifest'],'exact candidate manifests')
    for name,manifest,count in [('runtime',package,38),('root-chain',root,3),('shared',h.strict(files['shared/SHARED-MATERIALS.json']),17)]:
        rows=manifest['files'];need(len(rows)==len({r['path']for r in rows})==count,'exact complete manifest count')
        for row in rows:need(pin(files[name+'/'+row['path']])=={k:row[k]for k in ('bytes','sha256')},'frozen file content differs from manifest')
    runtime_sources={row['path']:files['runtime/'+row['path']]for row in package['files']}
    original_common=sys.modules.get('component_common');oldpath=sys.path[:]
    try:
        common=module(runtime_sources['source/component_common.py'],'component_common',OUT/'runtime/source/component_common.py')
        sys.modules['component_common']=common
        late=types.ModuleType('fc33_exact_new_late');late.__file__=str(OUT/'runtime/source/late_boundary.py')
        late.__reviewed_source_sha256__=pin(runtime_sources['source/late_boundary.py'])['sha256'];late.__reviewed_package_sources__=runtime_sources
        exec(compile(runtime_sources['source/late_boundary.py'],late.__file__,'exec'),late.__dict__)
        def old39(row):
            expected=late.reviewed_v3_runtime_diagnostic_ancestor()['inventory']
            need(row==expected,'only exact retained old39 source callback')
            raw=parent_files['retained-history/native-00/inventory.original.json'];need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'exact complete retained old39 bytes');return raw
        late.__retained_stage_read_pinned__=old39
        late.validate_current_package_manifest(package);late.current_context(material['combination']['sha256'],assembly['runtime_manifest']['sha256'])
        records=late.reviewed_source_parent_records();need(len(records)==1,'actual single source-parent prefix')
        histories=[]
        for index,record in enumerate(records):
            home=Path(record['closed_previous']['path']).parent
            previous_raw=o.read(record['closed_previous']);previous=h.strict(previous_raw)
            got={}
            for kind,name in [('boundary','LATE-BOUNDARY.original.json'),('inventory','INVENTORY.json'),('closure','CLOSURE.json')]:
                got[kind]=o.read({'path':str(home/name),**{k:record[kind][k]for k in ('bytes','sha256')}})
                files['retained-source-parent/%02d/'%index+kind+'.original.json']=got[kind]
            value,inventory,closure=late.closed_boundary_originals(got['boundary'],got['inventory'],got['closure'],original_descriptor=record['boundary'],combination_sha256=material['combination']['sha256'],package_sha256=assembly['runtime_manifest']['sha256'])
            need(previous['late_boundary']==record['boundary'] and previous['identity']==value['scope'] and previous['component_qualified']is value['component_qualified'] and previous['known_all_dispatched_tools_confirmed_terminal']is True,'actual closed previous differs')
            histories.append(value);files['retained-source-parent/%02d/'%index+'ACTUAL-PREVIOUS-INPUT.json']=previous_raw
        tail=sorted(name for name in parent_files if re.fullmatch(r'retained-history/native-\d\d/boundary.original.json',name))
        need(len(tail)==9,'complete unchanged nine failed boundary originals')
        histories.extend(h.strict(parent_files[name])for name in tail);late.require_failed_ancestor_tail(histories)
        need(histories[0]['component_qualified']is True and all(v['component_qualified']is False for v in histories[1:]),'historical outcomes must retain original meaning')
        need(late.SOURCE_PARENT_INVENTORY_ROOT_COUNT==44 and late.MAX_CURRENT_INVENTORY_ROOTS==50 and late.MAX_CHAIN==12 and late.COMPONENT_ROLE_CAP==42 and late.MAX_FIXTURE_ROOTS==14,'finite actual source-parent resource contract')
        # This is the already completed restoration's original pure public API.
        cleanup_reader_raw=o.read(CLEANUP_READER);cleanup_inputs=o.read(CLEANUP_INPUTS)
        cleanup_reader=module(cleanup_reader_raw,'fc33_actual_cleanup_reader',CLEANUP_READER['path'])
        def read_cleanup(row):
            raw=o.read(exact3(row))
            if 'metadata'in row:need(o.rows[row['path']]['metadata']==row['metadata'],'cleanup original full9 differs')
            return raw
        cleanup=cleanup_reader.verify_owned_unstarted_stage_cleanup(cleanup_inputs,read_pinned=read_cleanup)
        need(cleanup['state']=='VERIFIED_OWNED_UNSTARTED_STAGE_CLEANUP' and cleanup['fixed19_credit']==0
             and cleanup['old_final02_original_sender_wait']=='UNKNOWN_UNCHANGED'
             and cleanup['closure']['sha256']=='c19e5d51712452dd38c9ddb0c6ef240f372a1d563225581634d5f27d53d84d10'
             and cleanup['post_cleanup_fresh_current44_admission_required']is True,'actual recovery closure remains mandatory')
        after=h.strict(cleanup['after_inventory_raw'])
        need(late.inventory_value(after)==late.inventory_value(inventory),'recovery must restore the actual source-parent complete44 inventory; elapsed scan time is not an inventory entry')
        files['recovery/READER.original.py']=cleanup_reader_raw;files['recovery/INPUTS.original.json']=cleanup_inputs
        files['recovery/CLOSED.original.json']=o.read(exact3(cleanup['closure']))
        files['recovery/AFTER-INVENTORY.original.json']=cleanup['after_inventory_raw']
        files['SOURCE-PARENT-RECORDS.json']=enc(records)
        fields=late.manifest_source_parent_binding()
    finally:
        sys.path[:]=oldpath
        if original_common is None:sys.modules.pop('component_common',None)
        else:sys.modules['component_common']=original_common
    validations=[]
    for index,row in enumerate(REVIEWED_INPUTS['validation_originals']):
        raw=o.read(row);files['validation/%02d.original.json'%index]=raw;validations.append(row)
    root_source=files['root-chain/source/run_component_root_once.py']
    for name,value in {'PKG':assembly['runtime_manifest']['sha256'],'COMBINATION':material['combination']['sha256'],
        'SHARED':material['shared_manifest']['sha256'],'CONFIG':material['configuration']['sha256'],'SERVICE':material['service_inputs']['sha256'],
        'SENDER':pin(runtime_sources['source/send_new_native_guard_task_r10_r4.py'])['sha256'],'READY_HELPER':pin(runtime_sources['source/sender_native_guard_ready_r10_r4.py'])['sha256']}.items():
        need(h.literal(root_source,name)==value,'root exact frozen binding: '+name)
    need(h.literal(files['root-chain/source/phone_chain_bridge.py'],'PKG')==assembly['runtime_manifest']['sha256'],'bridge exact runtime binding')
    need(root['fixed_shared_material_root']==str(OUT/'shared') and root['current_combination_sha256']==package['current_combination_sha256']==material['combination']['sha256'],'one exact actual material root and combination')
    pub_raw=o.read(PUBLISHER);publish,publisher_proof,publisher_body=publisher(pub_raw)
    files.update({'FREEZER-SOURCE.original.py':ownraw,'SOURCE-ASSEMBLY.original.json':enc(assembly),
        'SHARED-DERIVATION.original.json':material_raw,'reference/R4-FREEZE-RESULT.original.json':o.read(OLD_FREEZE),
        'reference/R4-HOST-VALIDATION.original.json':parent_files['HOST-VALIDATION.json'],
        'reference/HELD-DIRECTORY-PUBLISHER.py':publisher_body})
    checks={'schema':'hepta.fc33.native-bound.host-validation.v1','case_order':['NEG-01','NEG-02'],
        'historical_failed_count':9,'source_parent_count':1,'old_source_parent_qualified':True,
        'source_parent_current_credit':False,'runtime_members':38,'root_members':3,'shared_members':17,
        'resource_contract':fields,'recovery_closure':cleanup['closure'],'fresh_phone_admission_required':True,
        'actual_policy_unchanged':prior['actual_policy'],'actual_adoption_unchanged':prior['actual_adoption'],
        'publisher':publisher_proof,'validation_originals':validations,'phone_calls':0,'full19_qualified':False}
    files['HOST-VALIDATION.json']=enc(checks)
    o.recheck()
    output_rows={name:{'path':str(OUT/name),**pin(raw)}for name,raw in sorted(files.items())}
    result={'schema':'hepta.fc33.native-bound.actual-host-freeze.v1','state':'FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED',
        'source':source,'output':str(OUT),'parent_freeze':OLD_FREEZE,'shared_derivation':MATERIAL_DERIVATION,
        'reviewed_delta_bundle':REVIEWED_INPUTS['delta_bundle'],'actual_input_files':copy.deepcopy(o.rows),
        'files':output_rows,'runtime_manifest':output_rows['runtime/MANIFEST.json'],
        'root_chain_manifest':output_rows['root-chain/SOURCE-MANIFEST.json'],'shared_materials':output_rows['shared/SHARED-MATERIALS.json'],
        'combination':output_rows['COMBINATION.json'],'actual_adoption':prior['actual_adoption'],'actual_policy':prior['actual_policy'],
        'checks':checks,'payload_bytes':sum(map(len,files.values())),'terminal_copies':2,
        'result_bytes':0,'complete_directory_bytes':0,'maximum_complete_directory_bytes':MAXIMUM,
        'all_inputs_bookended_before_publication':True,'all_output_files_read_back':True,
        'terminal_record_is_last':True,'automatic_retry':False,'phone_calls':0,'native_submissions':0,'new_nonces':0,
        'full19_qualified':False,'production_ready':False,'rollback_admission_is_separate_required_gate':True}
    for _ in range(12):
        raw=enc(result);n=len(raw)
        if result['result_bytes']==n and result['complete_directory_bytes']==result['payload_bytes']+2*n:break
        result['result_bytes']=n;result['complete_directory_bytes']=result['payload_bytes']+2*n
    else:raise ValueError('bounded result byte accounting did not stabilize')
    need(result['complete_directory_bytes']<=MAXIMUM,'complete freeze includes both terminal copies within32MiB')
    files['FREEZE-RESULT.json']=raw;files['DERIVATION.json']=raw
    _PUBLICATION=True
    try:publish(OUT,files)
    finally:_PUBLICATION=False
    freeze={'path':str(OUT/'FREEZE-RESULT.json'),**pin(raw)}
    need(initial(freeze)==raw and initial({'path':str(OUT/'DERIVATION.json'),**pin(raw)})==raw,'both complete terminal publications')
    print(json.dumps({'state':result['state'],'freeze':freeze,'runtime_manifest':result['runtime_manifest'],
        'root_chain_manifest':result['root_chain_manifest'],'combination':result['combination'],
        'complete_directory_bytes':result['complete_directory_bytes'],'phone_calls':0,'full19_qualified':False},sort_keys=True))

if __name__=='__main__':main()
