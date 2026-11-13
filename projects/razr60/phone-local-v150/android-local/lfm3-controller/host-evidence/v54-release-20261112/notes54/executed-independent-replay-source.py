import hashlib,json,os,re,shlex,stat,subprocess,sys,time,types
from pathlib import Path
B=Path('/home/alex/hepta-local-007f-20261111')
D=B/'background-notes-adapters-v54-r1'
SRC=B/'v54-main-host-r4/source'
ORIGINAL=B/'background-notes-v54-lfm3-normal-r1'
OUT=B/'background-notes-v54-lfm3-normal-independent-replay-r1'
DERIVED=OUT/'verifiers'
TASK='9b07550f62414bb5a9ccc16cc2db60e2'
RESULT_SHA='2d85991282f6a02834fcb492e8470ec7561a47fb9f524b750e319f7b1a3fae7d'
BUILD=B/'v54-main-host-r4/assembly-r1/RESULT.json'
BUILD_SHA='eadc9dbb63b411015571a488377be6a8704c9f78415169a5164c8f13571f0f72'
APK_SHA='0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a'
CFG_SHA='b1fa9a0f9f23562b667217063ce491eeb5bfe489f3dd45044d1ae733e2056ef2'
PINS={
    "background_notes_plan.py": "df4aa09037d41709dbfa0efae522776f023fc1481859f22a0e078a22f015daff",
    "fixed_intent_v6_acceptance.py": "9b858dd02d34558ab6c898209378a2de3d34b38b6f1aa2a099da788273b3f2ba",
    "controller_workflow_evidence.py": "405ed06f6302623e36dc39803ebe7781bb349b396851d0bfe6fa46f2ce6b6350",
    "controller_idle_evidence.py": "8ef4e544b5ac6f62f17ff37715de7a4be5d051f2312802580d404f15512b7240",
    "prepare_background_notes_v54_r1.py": "5e1db9854154042f3124afc1a2890c567a3fa32dedc41f80f237b0bd260e4d90",
    "run_background_notes_v54_r1.py": "2fa7d0670786dcc3933974056acc03026e7ffd091f9f4b3218936ae60646df39",
    "live_inflight_window.py": "3f3faa3b692257710f48651d48f1a39405f0fb511fd94658af2617ded9443671",
    "main_user_inflight.py": "79450f5c07b48958821d388a729223890fcd7f2cd0c085e85e15c48aadee167d",
    "moto_note_body_evidence_v51.py": "091bcb7a633c9fec1e668b637fb3619de712c441db99f2164c47c4b3ba629e94"
}
PREPARATION=B/'background-notes-v54-lfm3-normal-prepare-r1/RESULT.json'
PREPARATION_SHA='0b15a45a5149651f542add385bb2cb3a90120ae117d4d7e190ad56010e90dda0'
PLAN_SHA='46a375026c4de1f29bdd428de36c5141a4eb1ccf0afdea00538b4aaf95ec319b'
PREFERENCES_SHA='c9364dde8c0b52e7890835d720967987f708e972b397fcc3f76d9d76a667137f'
SOURCE_INVENTORY=B/'v54-main-host-r4/SOURCE-INVENTORY.json'
SOURCE_INVENTORY_SHA='8675c0c438cdf10f599c23a3a6305a5678fd59270f09b4f73a43f7a67bf2237d'
PROJECTION_SOURCE_PINS={
    'src/org/trillionnium/hepta/local/PhoneObservation.java':'9aeda02ab6fc541e9a8e04841093355c6055b590042f334b47fb55595ce5ca95',
    'src/org/trillionnium/hepta/local/BackgroundSession.java':'0045e81d6578a071de8dbdedd3c589afeb6025cf52d6c76fceb0e30e11e3dec6'}
DERIVED_PINS={"controller_workflow_evidence.py":"1188e4ad4666614cfce38d0f74b60819dd2c0e32ebf9cac6cdbd74bcf649791e","controller_idle_evidence.py":"285f6575f5dc1eaaaff61b591cd8e0171e250ea0799a196ba298bd1cad6478db","main_user_inflight.py":"4aa6e0f8db9229e1764d9ee79220ed8fa3eb7ddc3bd5526a857fd179870afe30"}
PROJECTION_REPLACEMENT=("                and _equal({k: bg.get(k) for k in self.selection}, self.selection))","                # Exact nine-field projection emitted by signed v54 PhoneObservation.backgroundJson().\n                # Full OWNER-derived Selection is independently bound in __init__, action and cleanup.\n                # This compares original bytes; it never adds the absent owner_task_selection to a frame.\n                and _equal(bg, {\n                    'mode': self.selection['mode'], 'generation': self.generation, 'display_id': self.display,\n                    'allowed_packages': self.selection['allowed_packages'],\n                    'bootstrap_package': self.selection['bootstrap_package'],\n                    'bootstrap_source': 'owner_selected_initial_app',\n                    'bootstrap_model_issued': self.selection['bootstrap_model_issued'],\n                    'home_allowed': self.selection['home_allowed'],\n                    'main_display_fallback': self.selection['main_display_fallback']}))")
IDLE_REPLACEMENT=("WORKFLOW_SHA = '405ed06f6302623e36dc39803ebe7781bb349b396851d0bfe6fa46f2ce6b6350'","WORKFLOW_SHA = '1188e4ad4666614cfce38d0f74b60819dd2c0e32ebf9cac6cdbd74bcf649791e'")
MAIN_REPLACEMENTS=[["def verdict(h,live,args,report,samples,actions,by_file,child_proof):","def verdict(h,live,args,report,samples,actions,by_file,child_proof,*,\n            expected_background_selection,preparation_original_sha256):"],["        need(context=={'owner':report['instruction'],'config_sha256':report['runtime_config_sha256'],\n            'display_id':candidate['display_id'],'background_generation':candidate['generation'],\n            'model_sha256':report['expected_model_sha256'],'body':report['plan']['body'],\n            'notes_identity':report['installed_identity_before']['notes']},'live context differs from original runtime/task')","        # Both added context values come from independently rehashed preparation and OWNER recomputation.\n        # The full nine-field context is compared; no extra field is discarded or self-attested.\n        need(same_value(context,{'owner':report['instruction'],'config_sha256':report['runtime_config_sha256'],\n            'display_id':candidate['display_id'],'background_generation':candidate['generation'],\n            'model_sha256':report['expected_model_sha256'],'body':report['plan']['body'],\n            'notes_identity':report['installed_identity_before']['notes'],\n            'expected_background_selection':expected_background_selection,\n            'preparation_original_sha256':preparation_original_sha256}),\n            'live context differs from original runtime/task/preparation')"]]

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
report={'schema':'hepta.v54-normal-independent-replay.v1','all_scoped_checks_passed':False,
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
    # Fresh output-only copies. Original deployed verifier files are never overwritten.
    for name in ('background_notes_plan.py','fixed_intent_v6_acceptance.py','moto_note_body_evidence_v51.py',
                 'controller_workflow_evidence.py','controller_idle_evidence.py','main_user_inflight.py'):
        value=source_originals[str(D/name)]
        changes=[PROJECTION_REPLACEMENT] if name=='controller_workflow_evidence.py' else [IDLE_REPLACEMENT] if name=='controller_idle_evidence.py' else MAIN_REPLACEMENTS if name=='main_user_inflight.py' else []
        for old_text,new_text in changes:
            need(value.count(old_text.encode())==1,'explicit derived verifier patch cardinality differs')
            value=value.replace(old_text.encode(),new_text.encode())
        if changes:
            need(sha(value)==DERIVED_PINS[name],'derived verifier bytes differ')
        write(DERIVED/name,value,True)
    derived_before=snapshot(DERIVED)
    report['source_projection_derivation']={'production_sources':PROJECTION_SOURCE_PINS,
        'source_inventory_sha256':SOURCE_INVENTORY_SHA,'original_verifier_pins':PINS,
        'derived_verifier_pins':DERIVED_PINS,'changes':['one exact nine-field observation projection comparison','idle verifier binds the derived workflow SHA','main verdict accepts two independently bound context arguments and compares the complete nine-field live context'],
        'original_frames_modified':False,'missing_fields_synthesized':False,
        'full_owner_bootstrap_action_cleanup_selection_predicates_unchanged':True}
    h=module('normal54_archive_collector',D/'run_background_notes_v54_r1.py',PINS['run_background_notes_v54_r1.py'])
    profiles=h.load_pinned('model_profiles',SRC/'tools/model_profiles.py')
    wr=h.load_pinned('warm_receipts',SRC/'tools/warm_receipts.py')
    pa=h.load_pinned('phone_acceptance',SRC/'tools/phone_acceptance.py')
    binder=h.load_action_binder(SRC/'tools',pa,wr)
    workflow=module('normal54_archive_workflow_projection',DERIVED/'controller_workflow_evidence.py',DERIVED_PINS['controller_workflow_evidence.py'])
    main=module('normal54_archive_main_context',DERIVED/'main_user_inflight.py',DERIVED_PINS['main_user_inflight.py'])
    live=h.load_pinned('live_inflight_window',D/'live_inflight_window.py')
    h.MAIN_INFLIGHT=main
    idle=module('normal54_archive_idle_projection',DERIVED/'controller_idle_evidence.py',DERIVED_PINS['controller_idle_evidence.py'])
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
        'observation_source_literal_is_legacy_projection':True,'observation_owner_task_selection_is_absent':True}

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
    need(snapshot(ORIGINAL)==before and all(raw(Path(p))==b for p,b in source_originals.items())
         and snapshot(DERIVED)==derived_before,'original/source or fresh verifier before-after identity changed')
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
