import hashlib,json,os,re,shlex,stat,subprocess,sys,time,types
from pathlib import Path
B=Path('/home/alex/hepta-local-007f-20261111')
D=B/'background-notes-adapters-v56-r1'
SRC=B/'v56-main-core101-materialized-host-r2/source'
ORIGINAL=B/'background-notes-v56-lfm3-normal-r1'
OUT=B/'background-notes-v56-lfm3-normal-independent-replay-r1'
TASK='b5b05eb09df64032ab4aeb1d5707b85b'
RESULT_SHA='8e4f37def7612d81bf96c9ccd96ea5b0858bdf9849683f5112953469671e1601'
BUILD=B/'v56-main-sign-r1/RESULT.json'
BUILD_SHA='e27e74e94b0668c1c07b04863c9aaabf1b3235f9ff2d0d0d8bd9a346e46b2c6b'
APK_SHA='067ab5a286b100404fa2b00e341964cd70f005907988dc11eb486c9a4b3bab62'
CFG_SHA='b1fa9a0f9f23562b667217063ce491eeb5bfe489f3dd45044d1ae733e2056ef2'
PINS={
    "background_notes_plan.py": "4bf77a52d012b4d5fe2fcfdcfea59649058c74d94202afcaacf0cb92e81c7bad",
    "fixed_intent_v6_acceptance.py": "f090a85780318ffefbad82a51d740a0965acb7369a12390698f8300031271652",
    "controller_workflow_evidence.py": "419ae165511e42a017bf079ebd0b984e5b0b9ddfe04b4731cfd692e072dd8795",
    "controller_idle_evidence.py": "0bfd580463b8fb8cfd7fec5f76d70bfc8893da23c4c91a3426b38ce5b5a5894d",
    "prepare_background_notes_v56_r1.py": "e841c36ed2e4489b82cb3a0f5e08e484e00ac018c7575bd7e892cfc1f1aeb6ee",
    "run_background_notes_v56_r1.py": "8c58648825dd27035cd3271bfc5e57f912bfa9121dfbd39406da750e8a648834",
    "live_inflight_window.py": "3f3faa3b692257710f48651d48f1a39405f0fb511fd94658af2617ded9443671",
    "main_user_inflight.py": "cb2aa959ec91e5aa7b680526d8add656f5a91e085321ce833701368beba367a0",
    "moto_note_body_evidence_v51.py": "091bcb7a633c9fec1e668b637fb3619de712c441db99f2164c47c4b3ba629e94"
}
PREPARATION=B/'background-notes-v56-lfm3-normal-prepare-r1/RESULT.json'
PREPARATION_SHA='61a7aa90efb1fffb14e4f21cdec6c389b4ecb1bf644a559c95f8d9e747cc743a'
PLAN_SHA='fe089149f2ff8c383eb851a7bee7f6dd5e206fbec2d1e757ff83d113a535d4ea'
PREFERENCES_SHA='c9364dde8c0b52e7890835d720967987f708e972b397fcc3f76d9d76a667137f'
SOURCE_INVENTORY=B/'v56-main-core101-materialized-host-r2/SOURCE-INVENTORY.json'
SOURCE_INVENTORY_SHA='ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e'
PROJECTION_SOURCE_PINS={
    'src/org/trillionnium/hepta/local/PhoneObservation.java':'9dc1033ffc989b2a957e0999bb40d5c48d97117d89150a173141ae7cc7eff8d0',
    'src/org/trillionnium/hepta/local/BackgroundSession.java':'0045e81d6578a071de8dbdedd3c589afeb6025cf52d6c76fceb0e30e11e3dec6'}


def need(ok,message):
    if not ok:raise RuntimeError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def raw(path,maximum=32<<20,allow_empty=False):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and all(not p.is_symlink() for p in (path,*path.parents)),'unsafe original path')
    with path.open('rb') as f:
        a=os.fstat(f.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and (0 if allow_empty else 1)<=a.st_size<=maximum,'original type/size differs')
        value=f.read(maximum+1);b=os.fstat(f.fileno())
    def identity(s):return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(len(value)==a.st_size and identity(a)==identity(b)==identity(path.stat()),'original changed while read')
    return value
def encoded(v):return(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def write(path,value,binary=False):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    need(all(not p.is_symlink() for p in (path,*path.parents)),'output link refused')
    value=value if binary else encoded(value)
    with path.open('xb') as f:f.write(value);f.flush();os.fsync(f.fileno())
    need(raw(path,allow_empty=True)==value,'output readback differs')
def snapshot(root):
    out={};total=0
    for directory,dirs,files in os.walk(root,followlinks=False):
        need(all(not (Path(directory)/n).is_symlink() for n in dirs),'source directory link')
        for name in files:
            p=Path(directory)/name;r=raw(p,allow_empty=True);total+=len(r)
            need(total<=256<<20 and len(out)<20000,'bounded original tree exceeded')
            st=p.stat();out[str(p.relative_to(root))]={'bytes':len(r),'sha256':sha(r),'identity':[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]}
    return out
def module(name,path,pin):
    need(name not in sys.modules,'preloaded namespace refused')
    b=raw(path);need(sha(b)==pin,'source pin differs '+str(path))
    m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m
    exec(compile(b,str(path),'exec',dont_inherit=True),m.__dict__)
    return m
need(sha(raw(ORIGINAL/'RESULT.json'))==RESULT_SHA and sha(raw(BUILD))==BUILD_SHA,'actual original/result build differs')
need(sha(raw(PREPARATION))==PREPARATION_SHA and sha(raw(SOURCE_INVENTORY))==SOURCE_INVENTORY_SHA,
     'actual dual UI preparation or signed source inventory differs')
need(not OUT.exists() and all(not p.is_symlink() for p in OUT.parents),'new independent output required')
# Exclusive claim is outside handler; a second entry never writes this output.
OUT.mkdir(mode=0o700)
report={'schema':'hepta.v56-normal-independent-replay.v1','all_scoped_checks_passed':False,
        'qualified':False,'original_collector_changed':False,'phone_actions':0,'checks':{},
        'original_result_sha256':RESULT_SHA,'original_qualified':False,
        'scope':'Native raw-byte/IDs/owned workflow and sampled main coexistence replay; root visual review remains independent. No new device observation.'}
try:
    write(OUT/'REPLAY.py',sys.argv[1].encode(),True)
    before=snapshot(ORIGINAL);write(OUT/'ORIGINAL-INVENTORY.json',before)
    source_originals={str(D/name):raw(D/name) for name in PINS}
    need(all(sha(b)==PINS[Path(p).name] for p,b in source_originals.items()),'runtime source closure differs')
    source_originals[str(BUILD)]=raw(BUILD)
    source_originals[str(PREPARATION)]=raw(PREPARATION)
    source_originals[str(SOURCE_INVENTORY)]=raw(SOURCE_INVENTORY)
    inventory=json.loads(source_originals[str(SOURCE_INVENTORY)].decode('utf-8','strict'))
    need(isinstance(inventory,list),'actual signed source inventory format differs')
    for relative,pin in PROJECTION_SOURCE_PINS.items():
        value=raw(SRC/relative)
        rows=[r for r in inventory if r.get('path')==relative]
        need(len(rows)==1 and type(rows[0].get('bytes')) is int and rows[0]['bytes']==len(value)
             and rows[0].get('sha256')==pin==sha(value),'actual compiled projection source differs')
        source_originals[str(SRC/relative)]=value
    report['current_verifier_binding']={'production_sources':PROJECTION_SOURCE_PINS,
        'source_inventory_sha256':SOURCE_INVENTORY_SHA,'current_verifier_pins':PINS,
        'verifier_sources_modified':False,'legacy_projection_adapter_used':False,
        'original_frames_modified':False,'missing_fields_synthesized':False,
        'complete_actual_selection_plus_generation_display_checked':True}
    h=module('normal56_archive_collector',D/'run_background_notes_v56_r1.py',PINS['run_background_notes_v56_r1.py'])
    profiles=h.load_pinned('model_profiles',SRC/'tools/model_profiles.py')
    wr=h.load_pinned('warm_receipts',SRC/'tools/warm_receipts.py')
    pa=h.load_pinned('phone_acceptance',SRC/'tools/phone_acceptance.py')
    binder=h.load_action_binder(SRC/'tools',pa,wr)
    workflow=module('normal56_archive_workflow',D/'controller_workflow_evidence.py',PINS['controller_workflow_evidence.py'])
    main=module('normal56_archive_main_context',D/'main_user_inflight.py',PINS['main_user_inflight.py'])
    live=h.load_pinned('live_inflight_window',D/'live_inflight_window.py')
    h.MAIN_INFLIGHT=main
    idle=module('normal56_archive_idle',D/'controller_idle_evidence.py',PINS['controller_idle_evidence.py'])
    def no_process(*a,**kw):raise RuntimeError('host replay cannot create any process or device transport')
    subprocess.Popen=no_process
    pa.Adb.__init__=no_process
    original=h.strict(raw(ORIGINAL/'RESULT.json'));terminal_raw=raw(ORIGINAL/'evidence/task/result.json')
    need(original['task_id']==TASK and original['qualified'] is False and original['machine_checks_passed'] is False,'original collector identity/false scope differs')
    need(original['runtime_config_sha256']==CFG_SHA and original['expected_apk_sha256']==APK_SHA and original['expected_app_uid']==10481,'actual runtime differs')
    preparation_raw=raw(ORIGINAL/'PREPARATION-ORIGINAL.json',2<<20)
    need(preparation_raw==source_originals[str(PREPARATION)] and sha(preparation_raw)==PREPARATION_SHA
         and original.get('preparation_sha256')==PREPARATION_SHA and original.get('plan_sha256')==PLAN_SHA,
         'actual source-bound dual UI preparation differs')
    report['original_workflow_report']={'verified':original.get('controller_workflow_proof',{}).get('verified'),
        'missing_or_invalid':original.get('controller_workflow_proof',{}).get('missing_or_invalid'),
        'raw_object_sha256':sha(encoded(original.get('controller_workflow_proof'))),
        'original_result_unchanged':True}
    report['original_coexistence_report']={'checks':original.get('coexistence',{}).get('checks'),
        'missing':original.get('coexistence',{}).get('missing'),
        'raw_object_sha256':sha(encoded(original.get('coexistence'))),'original_result_unchanged':True}
    proof=idle.verify(ORIGINAL,RESULT_SHA,original['last_session'],terminal_raw,TASK,10481,APK_SHA,CFG_SHA,
        binder,pa,wr,BUILD,BUILD_SHA,SRC/'src/org/trillionnium/hepta/local/LocalTaskController.java')
    write(OUT/'CONTROLLER-IDLE-PROOF.json',proof)
    report['checks']['native_original_collection_and_le32_replayed']=proof.get('idle_compatible') is True
    need(proof.get('idle_compatible') is True,'native/idle replay failed: '+str(proof.get('missing_or_invalid')))
    reader=idle.Reader()
    private,bound,context,caller_pin=idle.prepare_binder(workflow,reader,binder,pa,wr,BUILD,
        SRC/'src/org/trillionnium/hepta/local/LocalTaskController.java',original['installed_identity_before']['hepta'],TASK)
    collection=h.strict(raw(ORIGINAL/'evidence/collection.json'))
    archive=workflow.Collected(ORIGINAL/'evidence',collection,private)
    terminal=h.strict(terminal_raw);bootstrap=archive.bound_obj('task/background-bootstrap.json')
    chain=workflow.analyze_workflow(ORIGINAL/'evidence',collection,terminal,original['last_session'],
        original['plan'],original['installed_identity_before']['notes'],bootstrap,bound,private,wr,
        preparation_raw,PREPARATION_SHA,PLAN_SHA)
    write(OUT/'CONTROLLER-WORKFLOW-PROOF.json',chain)
    report['checks']['actual_native_parent_and_typed_save_list_reopen']=chain.get('verified') is True
    need(chain.get('verified') is True,'typed workflow replay failed: '+str(chain.get('missing_or_invalid')))
    plan_rules=h.load_pinned('background_notes_plan',D/'background_notes_plan.py')
    preparation=h.strict(preparation_raw)
    expected_selection=plan_rules.background_selection_from_preparation(original['plan'],preparation)
    preference_raw=plan_rules.original_preference_bytes(preparation)
    need(len(preference_raw)==653 and sha(preference_raw)==PREFERENCES_SHA
         and all(raw(ORIGINAL/name,65536)==preference_raw for name in
                 ('PREPARATION-UI-CHOICE-ORIGINAL.xml','BEFORE-TASK-UI-CHOICE.xml','AFTER-TASK-UI-CHOICE.xml'))
         and original.get('ui_preferences_original_sha256')==PREFERENCES_SHA
         and original.get('ui_preferences_unchanged') is True,'original actual 653-byte dual UI preference changed')
    actual_owner=archive.bound_obj('task/owner.json')
    actual_cleanup=archive.bound_obj('task/background-cleanup.json')
    owner_selection=expected_selection['owner_task_selection']
    need(expected_selection['allowed_packages']==['com.motorola.stylus']
         and expected_selection['bootstrap_package']=='com.motorola.stylus'
         and expected_selection['bootstrap_source']=='owner_intent_within_explicit_ui_selection'
         and owner_selection['original_ui_allowed_packages']==['com.motorola.stylus','org.trillionnium.hepta.webhelper']
         and owner_selection['effective_allowed_packages']==['com.motorola.stylus']
         and owner_selection['effective_scope_strictly_smaller'] is True
         and owner_selection['changes_saved_preferences'] is False
         and all(workflow._equal(v,expected_selection) for v in
                 (actual_owner.get('background_request'),bootstrap.get('selection'),actual_cleanup.get('selection'),
                  original.get('recomputed_effective_background_request')))
         and workflow._equal(chain.get('recomputed_owner_task_selection'),owner_selection)
         and workflow._equal(original.get('original_ui_selection'),preparation['background_selection']),
         'actual task failed to retain full OWNER-derived Notes-only selection within original dual UI choice')
    report['checks']['actual_dual_ui_preferences_preserved_and_effective_notes_only']=True
    report['actual_owner_task_selection']={'preparation_sha256':PREPARATION_SHA,
        'original_preference_bytes':len(preference_raw),'original_preference_sha256':sha(preference_raw),
        'original_ui_selection':preparation['background_selection'],'expected_selection':expected_selection,
        'actual_owner_bootstrap_cleanup_bound':True,'actual_task_scope_observed':True,
        'observation_source_literal_is_legacy_projection':False,'observation_owner_task_selection_is_absent':False,
        'complete_actual_selection_plus_generation_display_checked':True}

    args=types.SimpleNamespace(out=ORIGINAL,expected_uid=10481,adb='/usr/bin/adb',adb_host='127.0.0.1',
        adb_port=5037,serial='ZY22LS7WZT',main_physical_display_id='4630947043778501779')
    # Recompute system rows using the original unchanged parser and exact archived
    # five-command groups. No command is sent; timestamp fields remain archived.
    commands=sorted((ORIGINAL/'commands').glob('*.json'))
    starts=[i for i,p in enumerate(commands) if re.fullmatch(r'[0-9]{5}-displays.json',p.name)]
    sample_paths=sorted((ORIGINAL/'system').glob('sample-*.json'))
    need(len(starts)==len(sample_paths) and len(starts)>=3,'system sample/command membership differs')
    samples=[];system_refs=[]
    expected_words=[('displays',['cmd','display','get-displays']),('window-displays',['dumpsys','window','displays']),
        ('input-dispatcher',['dumpsys','input']),('activity-displays',['dumpsys','activity','activities']),
        ('process-uid',['ps','-A','-o','UID,PID,PPID,ARGS'])]
    class RecordedCommands:
        def __init__(self,paths):self.paths=paths;self.index=0;self.refs=[]
        def command(self,words,label,timeout=8):
            need(self.index<5,'unexpected extra replay command')
            wanted,argv=expected_words[self.index];path=self.paths[self.index];self.index+=1
            need(label==wanted and words==argv and re.fullmatch(r'[0-9]{5}-'+re.escape(label)+r'\.json',path.name),'system command order differs')
            metadata=h.strict(raw(path));stdout=main.command_stream(path.with_suffix('.stdout.bin'),8<<20);stderr=main.command_stream(path.with_suffix('.stderr.bin'),4096)
            actual=[args.adb,'-H',args.adb_host,'-P',str(args.adb_port),'-s',args.serial,'shell','-T',shlex.join(words)]
            need(metadata.get('argv')==actual and type(metadata.get('exit_code')) is int and metadata['exit_code']==0
                 and metadata.get('client_timed_out') is False and metadata.get('stdin_bytes')==0
                 and metadata.get('stdin_sha256') is None and not stderr
                 and type(metadata.get('started_wall_s')) in (int,float)
                 and type(metadata.get('elapsed_s')) in (int,float)
                 and metadata['elapsed_s']>=0,'original system command triplet differs')
            self.refs.append({'metadata':str(path),'metadata_sha256':sha(raw(path)),'stdout_sha256':sha(stdout)})
            return 0,stdout
    for index,(start,path) in enumerate(zip(starts,sample_paths)):
        need(path.name=='sample-%04d.json'%index,'original sample index sequence differs')
        old=h.strict(raw(path));need(old['index']==index,'sample payload index differs')
        group=commands[start:start+5];need(len(group)==5,'system commands missing')
        numbers=[int(p.name[:5]) for p in group];need(numbers==list(range(numbers[0],numbers[0]+5)),'interleaved system command group')
        archived=RecordedCommands(group)
        row=h.system_snapshot(archived,OUT/'system-replay',index,'com.motorola.stylus',phase=old['main_user_phase'])
        need(archived.index==5,'system group was not exhausted')
        ignored={'started_monotonic_s','ended_monotonic_s'}
        need(main.same_value({k:v for k,v in row.items() if k not in ignored},{k:v for k,v in old.items() if k not in ignored}),'actual system row differs from original five raw commands')
        row['started_monotonic_s']=old['started_monotonic_s'];row['ended_monotonic_s']=old['ended_monotonic_s']
        samples.append(row);system_refs.extend(archived.refs)
    report['checks']['system_samples_recomputed_from_raw_commands']=True
    by_file={Path(n).name:archive.bound_obj(n) for n in archive.manifest
        if re.fullmatch(r'task/step-[0-9]{2}(?:-tool-child-[0-9]{2})?-(?:before|after)\.json|task/step-[0-9]{2}-notes-workflow-observation-[1-5]\.json',n)}
    actions=[]
    for name in sorted(n for n in archive.manifest if n.startswith('task/') and workflow.classify_action_file(Path(n).name)=='model_action'):
        action=archive.bound_obj(name);filename=Path(name).name
        before_row=by_file[filename.replace('-action.json','-before.json')]
        binding=bound(ORIGINAL/'evidence',ORIGINAL/'evidence'/name,action,before_row,h.digest(original['instruction'].encode()))
        need(binding.get('verified') is True,'independent original parent model binding failed')
        actions.append({'file':filename,'run_id':action.get('model_run_id'),'model_binding_valid':True,
            'accepted':action.get('accepted'),'dispatched':action.get('dispatched'),'stale':action.get('stale')})
    need(len(actions)==1 and actions[0]['run_id']==chain['parent']['parent_run_id'],'one actual native create parent required')
    main_proof=main.verdict(h,live,args,original,samples,actions,by_file,chain,
        expected_background_selection=expected_selection,preparation_original_sha256=PREPARATION_SHA)
    write(OUT/'MAIN-COEXISTENCE-PROOF.json',main_proof)
    report['checks']['eight_original_main_coexistence_checks']=main_proof.get('machine_checks_passed') is True
    active_samples=[r for r in samples if r.get('displays',{}).get(chain['display_id'],{}).get('name')=='hepta-bg-'+chain['generation']]
    children=[{'file':Path(x['action_file']).name} for x in chain['children']]
    policy=h.display_policy_assessment(ORIGINAL/'evidence/task',bootstrap,actions+children,active_samples,TASK,
        chain['generation'],chain['display_id'],10481,original['prestart_formal_service_binding']['app_pid'])
    write(OUT/'DISPLAY-POLICY-PROOF.json',policy)
    report['checks']['actual_numeric_owned_display_policy']=policy.get('verified') is True
    final_png=archive.bound('task/'+chain['final_observation_id']+'.png')
    with h.png_rgba(final_png) as img:
        need(sha(final_png)==chain['final_screen_sha256'] and img.size==(720,1280),'final full PNG differs from workflow')
    report['checks']['original_final_owned_display_png']=True
    report['checks']['last_two_system_samples_release']=all(not row['errors']
        and chain['display_id'] not in row['displays'] and chain['display_id'] not in row['task_display_ids']
        and not any(h.BROKER_ENTRY in p['args'] or 'libhepta_local_runner.so' in p['args'] for p in row['processes']) for row in samples[-2:])
    metadata=[]
    for group in collection.get('associated_runs',[])+collection.get('task_model_sessions',[]):
        for item in group.get('files',[]):
            if Path(item['path']).name in ('app-receipt.json','native-result.json','app-session-receipt.json','native-session-result.json'):
                value=archive.bound(item['path'])
                metadata.append({'path':item['path'],'bytes':len(value),'sha256':sha(value),'original':h.strict(value)})
    write(OUT/'NATIVE-ORIGINAL-RECEIPTS.json',{'schema':'hepta.original-native-metadata-export.v1','records':metadata,
        'units_unchanged':True,'full_machine_memavailable_not_rss_or_peak':True,'host_only':True})
    need(archive.unchanged() and reader.unchanged(),'bound evidence changed during replay')
    need(snapshot(ORIGINAL)==before and all(raw(Path(p))==b for p,b in source_originals.items()),
         'original/current verifier before-after identity changed')
    report['checks']['original_tree_and_runtime_sources_unchanged']=True
    report.update(all_scoped_checks_passed=all(report['checks'].values()),task_id=TASK,
        workflow_id=chain['workflow_id'],display_id=chain['display_id'],generation=chain['generation'],
        sample_count=len(samples),main_checks=main_proof['checks'],main_missing=main_proof.get('missing'),
        native_input_ids=proof.get('actual_input_ids'),body_sha256=chain['body_sha256'],
        source_pins=PINS,source_context=context,system_original_command_refs=system_refs,
        final_png_sha256=sha(final_png),final_png_original={'path':str(ORIGINAL/'evidence/task'/(chain['final_observation_id']+'.png')),
            'bytes':len(final_png),'sha256':sha(final_png),'dimensions':[720,1280]},
        original_tree_files=len(before),native_original_record_count=len(metadata),
        current_device_state_observed=False,root_visual_review_required=True)
except Exception as error:
    report['error']=type(error).__name__+': '+str(error)
write(OUT/'RESULT.json',report)
summary={k:v for k,v in report.items() if k not in ('system_original_command_refs','source_pins','source_context','native_input_ids')}
summary['result']={'path':str(OUT/'RESULT.json'),'bytes':len(raw(OUT/'RESULT.json')),'sha256':sha(raw(OUT/'RESULT.json'))}
write(OUT/'SUMMARY.json',summary)
print(json.dumps(summary,ensure_ascii=False),flush=True)
raise SystemExit(0 if report['all_scoped_checks_passed'] else 2)
