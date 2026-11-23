#!/usr/bin/env python3
"""Complete Notes adapters with bundled synthetic shapes or an explicit archived capture. Host only."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,stat,subprocess,sys,time
sys.dont_write_bytecode=True
JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
CAPTURE_SHA='e0c6a2c1eee8d0d490df7ffd381149ffa443ab4c756bd4fdc41f960ef115db9c'
SYNTHETIC_SHA='8b44610ab210e5882d5de0cb61583992ccb626ed021b63af277f47407c3af201'
SYNTHETIC_BYTES=18714
def need(v,m):
    if not v:raise RuntimeError(m)
def raw(p):
    need(p.resolve()==p and p.is_absolute(),'absolute non-symlink input')
    s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'regular input')
    b=p.read_bytes();a=p.stat();need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns) and len(b)==s.st_size,'input changed');return b
def pin(p):
    b=raw(p);return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def put(p,j):
    with p.open('x',encoding='utf-8') as f:json.dump(j,f,indent=2,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())
def main():
    ap=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar'):ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--actual-failure-terminal',type=Path,help='Optional original 8a2c broker terminal for byte-exact projection verification')
    ap.add_argument('--actual-census',type=Path,help='Explicit external archived replay; default is the bundled synthetic derived fixture')
    a=ap.parse_args();s=a.source.resolve(strict=True);out=a.output.absolute();jdk=a.java_home.resolve(strict=True);jar=a.json_jar.resolve(strict=True)
    own=Path(__file__).resolve().parent
    capture=(a.actual_census if a.actual_census is not None else own/'synthetic-notes-census.json').resolve(strict=True)
    actual_capture=a.actual_census is not None
    input_mode='actual_archived_capture' if actual_capture else 'synthetic_derived_fixture'
    need(s not in out.parents and out!=s,'output outside source');out.mkdir(parents=True,exist_ok=False)
    need(pin(jar)['sha256']==JSON_SHA and pin(jar)['bytes']==78332,'fixed JSON jar')
    expected_sha,expected_bytes=(CAPTURE_SHA,44577) if actual_capture else (SYNTHETIC_SHA,SYNTHETIC_BYTES)
    need(pin(capture)['sha256']==expected_sha and pin(capture)['bytes']==expected_bytes,'exact input provenance and bytes')
    spec=importlib.util.spec_from_file_location('notes_actual_reflection_fixture',own/'prepare_fixture.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    stubs=module.prepare(out/'android-host-ports')
    bg=s/'src/org/trillionnium/hepta/background'
    production=['BrokerProtocol','PublicPermissionControllerUi','FixedIntentTools','FixedIntentTarget','ProfileIdentity','ProfileTarget','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','PublicOwnGroupTaskFence','PublicOwnGroupPolicy','PublicOwnGroupPhysicalFence','PublicPersonalNotesCustody','BackgroundTaskOrganizer','PublicPersonalNotesReader']
    files=[bg/(n+'.java') for n in production]+[s/'tests/public-own-group-policy/PublicPhysicalAuditHostTest.java',own/'NotesTaskInfoReaderHostTest.java']+stubs
    private_names=['ProfileIdentity','ProfileTarget','WindowOwnership','BrokerProtocol','PublicPermissionControllerUi','PublicOwnGroupPolicy','FixedIntentTools','BackgroundOwnedTaskPolicy','BackgroundOwnedSingleTask','ProfileTaskPolicy','ProfileOwnedTask','ProfilePermissionTransient','ProfileDisplayCustody','PublicOwnGroupPhysicalFence','PublicProfileRecentHistory']
    private_files=[bg/(n+'.java') for n in private_names]+[s/'tests/profile-broker/ProfileBrokerHostTest.java']
    failure_case=own/'8a2c-first-failure.json'
    retained=json.loads(failure_case.read_text())
    need(retained['broker_sha256']=='836ebb841a80d531b6be62bdb2fcc1ac6f4ddccb8a7e14eb60c7eb28a2e3c73d'
         and retained['broker_bytes']==4333 and retained['failure_reason']=='NOTES_ROOT_CENSUS_CHANGED'
         and retained['actual_root_read_failure'] is None and retained['absence_reads']==2 and retained['cleanup_known'] is True
         and retained['later_owned_tasks']==[{'task_id':1825,'user_id':0,'display_id':502,'actual_effective_uid':10382,
             'parent_id':-1,'serialized_token_grants_authority':False}], 'historical sample is unclassified; later cleanup is a different read')
    tracked=list(dict.fromkeys(files+private_files+[own/'prepare_fixture.py',Path(__file__).resolve(),capture,failure_case,jar,jdk/'bin/javac',jdk/'bin/java',jdk/'lib/ct.sym']))
    if a.actual_failure_terminal is not None:
        terminal=a.actual_failure_terminal.resolve(strict=True)
        original=raw(terminal)
        need(len(original)==retained['broker_bytes'] and hashlib.sha256(original).hexdigest()==retained['broker_sha256'], 'exact 8a2c original required')
        broker=json.loads(original);failure=broker['personal_notes_task_info_diagnostics']['first_runtime_failure'];cleanup=broker['personal_notes_cleanup']
        later=[{key:task[key] for key in retained['later_owned_tasks'][0]} for task in cleanup['actual_observed_tasks']]
        need(failure['reason']==retained['failure_reason'] and failure['actual_root_read_failure'] is None
             and later==retained['later_owned_tasks'] and all(cleanup[key]==retained[key] for key in ('absence_reads','cleanup_known','launch_dispatched')),
             'actual first failure and independent later cleanup must match the minimized record')
        tracked.append(terminal)
    before=[pin(p) for p in tracked]
    need(pin(bg/'BackgroundTaskOrganizer.java')['sha256']=='70eeb8e550dc77638687d5fa224fc2cd014f20991a1df94a232685244d9904ec','approved organizer differs')
    need(pin(bg/'PublicPersonalNotesReader.java')['sha256']=='d988d18616fee3759aad614a8c246caad1e2e61189416be534cd6d898d9c92e4','approved reader differs')
    need(pin(s/'tests/profile-broker/ProfileBrokerHostTest.java')['sha256']=='5880a651260aa18566364f4dbca427c5adbba8048eee7f1b8a3d55f4a6f69e04','original private test bytes differ')
    classes=out/'classes';classes.mkdir();pc=out/'private-classes';pc.mkdir()
    env=dict(os.environ)
    for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH'):env.pop(k,None)
    env.update(JAVA_HOME=str(jdk),PATH=str(jdk/'bin')+':/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    flags=['--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-proc:none']
    commands=[('compile-reflection',[jdk/'bin/javac',*flags,'-cp',jar,'-d',classes,*files]),
        ('reflection-cases',[jdk/'bin/java','-ea','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.background.NotesTaskInfoReaderHostTest',capture,input_mode]),
        ('compile-original-private',[jdk/'bin/javac',*flags,'-cp',jar,'-d',pc,*private_files]),
        ('original-private-cases',[jdk/'bin/java','-ea','-cp',str(pc)+os.pathsep+str(jar),'org.trillionnium.hepta.background.ProfileBrokerHostTest'])]
    report={'schema':'hepta.notes-task-info-reader-gate.v2','all_pass':False,'phone_operations':0,'android_runtime':False,'hardware_qualification_claimed':False,'framework_and_binder_fixtures_synthetic':True,'input_fixture':pin(capture),'input_mode':input_mode,'archived_capture_replayed':actual_capture,'reference_capture_sha256':CAPTURE_SHA,'inputs_before':before,'stages':[]}
    report['first_root_historical_failure']={'original_replayed':a.actual_failure_terminal is not None,'census_shape_recorded':False,'retained':retained}
    try:
        for name,argv in commands:
            t=time.monotonic();argv=list(map(str,argv))
            with (out/(name+'.stdout')).open('xb') as so,(out/(name+'.stderr')).open('xb') as se:p=subprocess.run(argv,cwd=s,env=env,stdout=so,stderr=se,timeout=120)
            row={'name':name,'argv':argv,'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-t,'stdout':pin(out/(name+'.stdout')),'stderr':pin(out/(name+'.stderr'))};report['stages'].append(row)
            print(json.dumps({'stage':name,'exit_code':p.returncode}),flush=True);need(p.returncode==0,name+' failed')
            if name=='reflection-cases':
                cases=json.loads(raw(out/(name+'.stdout')).decode().splitlines()[-1])
                need(cases['schema']=='hepta.notes-task-info-reader-host.v2' and cases['all_pass'] is True and cases['input_values_rehydrated'] is True and cases['synthetic_binder_tokens'] is True and cases['phone_operations']==cases['get_child_tasks_calls']==cases['mutation_calls']==0,'typed reflection receipt')
                need(cases['input_mode']==input_mode and cases['input_sha256']==expected_sha and cases['archived_capture_replayed'] is actual_capture and cases['actual_capture_sha256']==(CAPTURE_SHA if actual_capture else None) and cases['reference_capture_sha256']==CAPTURE_SHA,'input provenance differs')
                need(len(cases['case_names'])==cases['cases']==len(set(cases['case_names']))==71 and cases['assertions']==238,'all original cases and assertions retained');report['reflection_cases']=cases
                extra=cases.get('empty_activity',{})
                need(extra.get('schema')=='hepta.notes-empty-activity-host.v1' and extra.get('all_pass') is True
                     and extra.get('cases')==14 and extra.get('assertions')==59
                     and len(extra.get('case_names',[]))==len(set(extra.get('case_names',[])))==14
                     and extra.get('framework_and_binder_fixtures_synthetic') is True
                     and type(extra.get('phone_operations')) is int and extra['phone_operations']==0,
                     'exact empty-activity and diagnostic cases required')
                first=cases['first_root_bootstrap']
                need(first['cases']==22 and len(set(first['case_names']))==22 and first['assertions']==116 and first['phone_operations']==0, 'all first-root resample cases required')
                stable=cases.get('taskinfo_stability',{})
                need(stable.get('schema')=='hepta.notes-taskinfo-stability-host.v1' and stable.get('all_pass') is True
                     and stable.get('cases')==12 and stable.get('assertions')==60
                     and len(stable.get('case_names',[]))==len(set(stable.get('case_names',[])))==12
                     and stable.get('maximum_complete_samples')==3 and stable.get('maximum_frame_ms')==1500
                     and stable.get('intent_redispatches')==stable.get('phone_operations')==0
                     and stable.get('framework_and_binder_fixtures_synthetic') is True,
                     'bounded read-only TaskInfo convergence and immutable-identity refusal cases required')
            elif name=='original-private-cases':
                cases=json.loads(raw(out/(name+'.stdout')).decode().splitlines()[0]);need(cases['passed'] is True and cases['cases']==47 and cases['assertions']==449,'unchanged original private assertions');report['original_private_cases']=cases
        report['all_pass']=True
    except BaseException as error:report['error']=type(error).__name__+': '+str(error)
    finally:
        report['inputs_after']=[pin(p) for p in tracked];report['inputs_unchanged']=report['inputs_before']==report['inputs_after'];report['all_pass']=report['all_pass'] and report['inputs_unchanged']
        put(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'result':pin(out/'RESULT.json'),'reflection_cases':report.get('reflection_cases',{}).get('cases')}),flush=True)
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
