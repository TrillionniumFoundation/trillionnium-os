#!/usr/bin/env python3
"""Scoped v32/Orvena-4B ordinary smoke staging. Default plan is host-only.
prepare freezes only an actual successful Orvena selector result. Phone phases
require --execute --exclusive-idle-window. Never install, select a model, submit
a nonce, stop/kill, repair permissions, retry a UI action, or change networking.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, io, json, os, re, stat, subprocess, sys, time
from pathlib import Path
from types import SimpleNamespace, ModuleType
HERE = Path(__file__).resolve().parent
PACKAGE = 'org.trillionnium.hepta.local'
Q=None;SOURCE=None;APK_SHA=None;CONFIG=None;CONFIG_SHA=None;CANDIDATE=None;UID=None;OBSERVER_SHA=None
CORE_SHA='49f1ce7e51815ddab990bbdaf49dad7a2497cb2bb539a49690f6be75e60df24a'
MODEL_SHA='c5d6df6e9a0828fa3068dfc6f6ca2ff6c4d950adc7e60e4b7202ece61595aa57'
INSTRUCTION='打开系统设置，进入“应用”页面，停留在这个页面。'
INSTRUCTION_SHA='13e2d90d46fe98e90e96758a3136ae9a1a866bc2874cd98b9c54e6328fe65d92'
CASE = dict(case_id="core-settings-apps-01", instruction=INSTRUCTION, expected_package="com.android.settings",
            expected_visible_text=["特殊应用权限", "应用管理"], text_match="exact", required_actions=[],
            assertion="apps_management", goal_visits=[], precondition=None, setup_home=True, timeout_seconds=540)
def need(value, message):
    if not value: raise RuntimeError(message)
def sha(data): return hashlib.sha256(data).hexdigest()
def read(path, limit=8 << 20):
    p=Path(path); s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=limit, "nonregular/linked/large host file: "+str(p))
    b=p.read_bytes(); need(len(b)==s.st_size, "host file changed"); return b
def obj(data):
    def pairs(items):
        v={}
        for k,x in items:
            need(k not in v, "duplicate JSON key"); v[k]=x
        return v
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda v: (_ for _ in ()).throw(ValueError(v)))
def encoded(v): return (json.dumps(v,ensure_ascii=False,indent=2,allow_nan=False)+"\n").encode()
def write(path, data):
    p=Path(path); p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb") as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
def save(path, v): write(path,encoded(v))
def module(path,name):
    path=Path(path).resolve(strict=True); raw=read(path)
    m=ModuleType(name); m.__file__=str(path); sys.modules[name]=m
    exec(compile(raw,str(path),"exec",dont_inherit=True),m.__dict__); return m
def configure(binding, package_manifest):
    global Q, SOURCE, APK_SHA, CONFIG, CONFIG_SHA, CANDIDATE, UID, OBSERVER_SHA
    Q=binding; SOURCE=Path(binding['source_directory']); APK_SHA=binding['candidate']['apk_sha256']
    CONFIG=binding['runtime_config']; CONFIG_SHA=binding['runtime_config_sha256']; CANDIDATE=binding['candidate']; UID=binding['app_uid']
    OBSERVER_SHA=package_manifest['files']['ordinary/ordinary_start_observer.py']['sha256']
    host_contract()

def host_contract():
    need(Q is not None,'actual qualified binding not configured')
    inputs={row['path']:row['sha256'] for row in obj(Q['raw_files']['build-identity.json'])['source_inputs']}
    main=read(SOURCE/'src/org/trillionnium/hepta/local/MainActivity.java')
    need(sha(main)==inputs.get('src/org/trillionnium/hepta/local/MainActivity.java'),'actual compiled MainActivity differs')
    need(sha(read(HERE/'ordinary_start_observer.py'))==OBSERVER_SHA,'observer differs')
    need(sha(read(HERE/'core_assertions.py'))==CORE_SHA,'frozen goal oracle differs')
    need(sha(INSTRUCTION.encode())==INSTRUCTION_SHA,'instruction differs')
def build_report_binding(r):
    expected=dict(actual_build_identity_sha256=Q['build_identity_sha256'],
        actual_build_identity_asset='assets/hepta-build-identity.json',
        complete_source_inventory_sha256=Q['complete_source_inventory_sha256'],
        portable_source_inventory_sha256=Q['portable_source_inventory_sha256'],source_commit=Q['source_commit'],
        source_tree='81955c2053ba24cab0783c9cb7636a49c0f186de',
        build_receipt_sha256=sha(Q['raw_files']['mac-build-receipt.json']),
        static_acceptance_sha256=sha(Q['raw_files']['static-acceptance.json']))
    for key,value in expected.items(): need(r.get(key)==value,'actual build receipt differs: '+key)
    for key in ('host_checks_sha256','host_gate_qualification_sha256'):
        need(isinstance(r.get(key),str) and re.fullmatch(r'[0-9a-f]{64}',r[key]),'host gate receipt missing: '+key)
    return dict(expected,host_checks_sha256=r['host_checks_sha256'],host_gate_qualification_sha256=r['host_gate_qualification_sha256'])
def upgrade_proof(raw,m,helper_sha,selector_sha):
    r=obj(raw)
    need(r.get('schema')=='hepta.upgrade-v32-once.v1' and r.get('status')=='upgrade_verified'
         and r.get('phone_contacted') is True and r.get('actual_build_identity_sha256')==Q['build_identity_sha256']
         and r.get('complete_source_inventory_sha256')==Q['complete_source_inventory_sha256']
         and r.get('portable_source_inventory_sha256')==Q['portable_source_inventory_sha256']
         and r.get('source_commit')==Q['source_commit']
         and r.get('new_apk_sha256')==APK_SHA and r.get('expected_uid')==UID
         and r.get('script_sha256')==helper_sha and r.get('selector_sha256')==selector_sha,
         'requires actual exact v32 upgrade/source/asset proof')
    build_report_binding(r)
    for key in ('install_readback_verified','ordinary_launch_verified','permission_free_host_apk_bound_to_installed_bytes','same_signing_certificate_verified'):
        need(r.get(key) is True,'upgrade proof lacks '+key)
    for key in ('identity_after_install','identity_after_main'):
        x=r.get(key,{})
        need(x.get('package')==PACKAGE and x.get('apk_sha256')==APK_SHA and x.get('version_code')==32 and x.get('uid')==UID,
             'upgrade installed identity differs')
    return m.apk_permission_proof(raw,CANDIDATE)
def validate_selection(raw,candidate,config_raw,selector_sha):
    r=obj(raw)
    need(r.get('schema')=='hepta.select-runtime-once.v3-observed-accessibility'
         and r.get('status')=='configuration_verified' and r.get('phone_contacted') is True,
         'requires actual successful selector result')
    need(r.get('script_sha256')==selector_sha and r.get('actual_build_identity_sha256')==Q['build_identity_sha256']
         and r.get('complete_source_inventory_sha256')==Q['complete_source_inventory_sha256']
         and r.get('portable_source_inventory_sha256')==Q['portable_source_inventory_sha256']
         and r.get('source_commit')==Q['source_commit']
         and r.get('expected_apk_sha256')==APK_SHA and r.get('expected_uid')==UID,'selector actual identity differs')
    expected_candidate=dict(CANDIDATE,uid=UID,config_sha256=CONFIG_SHA,**build_report_binding(r))
    need(candidate==expected_candidate and obj(config_raw)==CONFIG and sha(config_raw)==CONFIG_SHA,'candidate/config differs')
    need(r.get('selected_config')==CONFIG and r.get('final_configuration_sha256')==CONFIG_SHA
         and r.get('model_full_sha_verified')==MODEL_SHA,'selection readback/model SHA differs')
    model=r.get('selected_model',{})
    need(model.get('file')=='Orvena-4B.Q4_K_M.gguf' and model.get('bytes')==2783447904
         and model.get('sha256')==MODEL_SHA and model.get('architecture')=='qwen35','selected model differs')
    for key in ('configuration_replacement_verified','ordinary_launch_verified','journals_unchanged','final_no_native_worker_observed'):
        need(r.get(key) is True,'selector lacks '+key)
    for key in ('identity_before','identity_after'):
        x=r.get(key,{})
        need(x.get('package')==PACKAGE and x.get('apk_sha256')==APK_SHA and x.get('version_code')==32 and x.get('uid')==UID,
             'selector installed identity differs')
    return r
def prepare(args):
    host_contract(); selection=args.selection.resolve(strict=True)
    upgrade_helper=read(args.upgrade_helper); selector_helper=read(args.selector_helper)
    upgrade_sha,selector_sha=sha(upgrade_helper),sha(selector_helper)
    need(upgrade_sha=='b6619f7e9e15c1aa465c4af0a405667fe288a0579c6a2240cb9afaef4c6b02d4'
         and selector_sha=='3fb80f4bf8ebd153d2d448415f9f1512a29a209697f1468545df069532a40721',
         'reviewed v32 upgrade/selector helper bytes differ')
    proof_raw=read(args.upgrade_proof);need(sha(proof_raw)==args.upgrade_proof_sha256,'upgrade result SHA differs')
    observer=module(HERE/'ordinary_start_observer.py','orvena_scoped_prepare_observer')
    upgrade_proof(proof_raw,observer,upgrade_sha,selector_sha)
    selection_raw=read(selection/'RESULT.json');need(sha(selection_raw)==args.selection_result_sha256,'selector result SHA differs')
    candidate_raw=read(selection/'candidate.json');config_raw=read(selection/'runtime-config.json')
    validate_selection(selection_raw,obj(candidate_raw),config_raw,selector_sha)
    out=args.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    projected_candidate=encoded(CANDIDATE)
    for name,raw in {'selection-result.json':selection_raw,'selection-candidate.json':candidate_raw,
        'candidate.json':projected_candidate,'runtime-config.json':config_raw,
        'upgrade-proof.json':proof_raw,'upgrade-helper.py':upgrade_helper,'selector-helper.py':selector_helper,
        'instruction.txt':INSTRUCTION.encode()}.items():write(out/name,raw)
    argv=[sys.executable,'-B',str(HERE/'ordinary_start_observer.py'),'prepare',
          '--source-dir',str(SOURCE),'--driver-dir',str(HERE.parent/'drivers'),
          '--candidate',str(out/'candidate.json'),'--runtime-config',str(out/'runtime-config.json'),
          '--instruction-file',str(out/'instruction.txt'),'--apk-permission-proof',str(out/'upgrade-proof.json'),
          '--qualification-binding',Q['binding_path'],'--qualification-binding-sha256',Q['binding_sha256'],
          '--output',str(out/'bundle')]
    result=subprocess.run(argv,capture_output=True,timeout=90)
    write(out/'prepare.stdout',result.stdout);write(out/'prepare.stderr',result.stderr)
    need(result.returncode==0,'scoped observer prepare failed; original evidence retained')
    manifest=read(out/'bundle/BUNDLE-MANIFEST.json')
    prepared=dict(schema='hepta.orvena-v32-ordinary-prepared.v1',phone_contacted=False,
        actual_build_identity_sha256=Q['build_identity_sha256'],qualification_binding_sha256=Q['binding_sha256'],
        expected_scope_sha256=Q['scope_sha256'],candidate=CANDIDATE,runtime_config_sha256=CONFIG_SHA,
        instruction_sha256=INSTRUCTION_SHA,selection_result_sha256=sha(selection_raw),candidate_sha256=sha(projected_candidate),
        selection_candidate_sha256=sha(candidate_raw),
        upgrade_proof_sha256=sha(proof_raw),upgrade_helper_sha256=upgrade_sha,selector_helper_sha256=selector_sha,
        launcher_sha256=sha(read(Path(__file__))),observer_sha256=OBSERVER_SHA,core_oracle_sha256=CORE_SHA,
        bundle_manifest_sha256=sha(manifest),model_load_qualified=None,task_goal_verified=None,
        maximum_start_attempts=1,automatic_retry=False)
    save(out/'PREPARED.json',prepared)
    print(json.dumps(dict(prepared=str(out),prepared_sha256=sha(read(out/'PREPARED.json')),
        bundle_sha256=sha(manifest),phone_contacted=False),ensure_ascii=False))
def prepared(args):
    host_contract();p=args.prepared.resolve(strict=True)
    raw=read(p/'PREPARED.json');need(sha(raw)==args.prepared_sha256,'prepared SHA differs');v=obj(raw)
    need(v.get('schema')=='hepta.orvena-v32-ordinary-prepared.v1' and v.get('candidate')==CANDIDATE
         and v.get('launcher_sha256')==sha(read(Path(__file__)))
         and v.get('qualification_binding_sha256')==Q['binding_sha256'] and v.get('expected_scope_sha256')==Q['scope_sha256'],
         'prepared/helper/scope identity differs')
    selector_sha=sha(read(p/'selector-helper.py'));upgrade_sha=sha(read(p/'upgrade-helper.py'))
    need(selector_sha==v['selector_helper_sha256'] and upgrade_sha==v['upgrade_helper_sha256'],'helper evidence changed')
    selection=read(p/'selection-result.json');need(sha(selection)==v['selection_result_sha256'],'selection changed')
    candidate_raw=read(p/'candidate.json');need(sha(candidate_raw)==v['candidate_sha256'],'candidate changed')
    need(obj(candidate_raw)==CANDIDATE,'derived exact core candidate differs')
    selected_raw=read(p/'selection-candidate.json');need(sha(selected_raw)==v['selection_candidate_sha256'],'original selected candidate changed')
    validate_selection(selection,obj(selected_raw),read(p/'runtime-config.json'),selector_sha)
    observer=module(HERE/'ordinary_start_observer.py','orvena_scoped_ordinary_observer')
    plan=observer.bundle(p/'bundle',v['bundle_manifest_sha256'])
    proof=read(p/'bundle/apk-permission-proof.json');need(sha(proof)==v['upgrade_proof_sha256'],'upgrade evidence changed')
    upgrade_proof(proof,observer,upgrade_sha,selector_sha)
    need(plan['candidate']==CANDIDATE and plan['runtime_config_sha256']==CONFIG_SHA
         and plan['instruction']==INSTRUCTION and plan['instruction_sha256']==INSTRUCTION_SHA
         and plan['actual_build_identity_sha256']==Q['build_identity_sha256']
         and plan['qualification_binding_sha256']==Q['binding_sha256'],'frozen observer plan differs')
    ac,iv,suite,_=observer.load_helpers(p/'bundle/tools')
    return p,v,observer,plan,ac,iv,suite
def phone_args(args):
    need(args.execute and args.exclusive_idle_window,"phone phase requires --execute --exclusive-idle-window")
    need(Path(args.adb).is_absolute() and Path(args.adb).is_file(),"absolute existing adb required")
    need(args.adb_host in ("127.0.0.1","::1") and 1<=args.adb_port<=65535,"existing local ADB endpoint required")
    scope=module(HERE.parent/'drivers/qualification_scope.py','qualification_scope')
    scope.require_device_target(args,Q,display=True)
    args.command_timeout=15; args.arm_timeout=600; args.poll_seconds=1; args.minimum_background_samples=3
def service_check(cli,parent):
    _,data=cli.command(["dumpsys","activity","services",PACKAGE],label="main-accessibility-service",timeout=30)
    need(len(data)<=4<<20,"services output too large")
    component=re.compile(r"org[.]trillionnium[.]hepta[.]local/(?:[.]|org[.]trillionnium[.]hepta[.]local[.])HeptaAccessibilityService")
    blocks=list(re.finditer(r"(?ms)^(\s*\* ServiceRecord\{[^\n]*\n)(.*?)(?=^\s*\* ServiceRecord\{|\Z)",data.decode()))
    blocks=[x.group(0) for x in blocks if component.search(x.group(1))]
    need(len(blocks)==1 and re.search(r"app=ProcessRecord\{[^\n]*\b"+str(parent["pid"])+r":org[.]trillionnium[.]hepta[.]local/",blocks[0])
         and "received=true" in blocks[0] and "hasBound=true" in blocks[0],"main accessibility service is not uniquely active/bound")
    _,data=cli.command(["dumpsys","accessibility"],label="accessibility-crash-check",timeout=30)
    need(len(data)<=4<<20,"accessibility output too large")
    crashes=re.findall(r"Crashed services:\s*\{(.*?)\}",data.decode(),re.S)
    need(crashes and all(not component.search(x) for x in crashes),"main accessibility service crash record present/unknown")
def live(args,out,m,plan,ac,iv,require_scope=True):
    plan['_scope_module'].require_device_target(args,Q,display=True)
    # Scope installation takes its baseline before a scope is required. Keep
    # every other idle/identity check, and leave the caller's scoped plan intact
    # for the mandatory post-install readback and subsequent task stages.
    idle_plan=plan if require_scope else {k:v for k,v in plan.items() if k not in ('_qualification','_scope_module')}
    iv.require_existing_adb_server(args,out,"before")
    ro=m.ObserverAdb(args,out/"readonly",iv); cli=ac.Adb(args,out/"ui-commands")
    need(ro._read(["am","get-current-user"],"current-user",4096)[1].strip()==b"0","Android user differs")
    raw=ro._read(["pm","path",PACKAGE],"apk-path",16384)[1]
    hit=re.fullmatch(rb"package:(/data/app/[^\s]+/base[.]apk)\r?\n",raw); need(hit is not None,"APK path ambiguous")
    actual=ro._read(["sha256sum",hit.group(1).decode()],"apk-sha",4096,timeout=30)[1].decode().split()[0]
    need(actual==APK_SHA,"installed APK differs; any different APK requires a new plan")
    package_raw=ro._read(["dumpsys","package",PACKAGE],"package",4<<20)[1]
    details=iv.parse_package_dump(package_raw,0)
    uid=int(ro.app_read(["id","-u"],"app-uid",4096)[1])
    need(uid==UID and details["app_id"]==uid and details["version_code"]==32 and details["current_user_installed"] is True,"installed UID/version differs")
    proof=m.permission_observation(details,package_raw,actual,plan.get("apk_permission_proof"))
    parent=m.parent_identity(ro); need(parent["uid"]==uid,"parent UID differs")
    first=m.idle_snapshot(ro,uid,idle_plan); time.sleep(0.25)
    need(m.idle_snapshot(ro,uid,idle_plan)==first,"idle/config not stable"); m.parent_identity(ro,parent)
    service_check(cli,parent)
    save(out/"LIVE-IDENTITY.json",dict(apk_sha256=actual,parent=parent,initial_idle=first,permission=proof))
    return ro,cli,parent,first
def observer_argv(args,p,v,run):
    return [sys.executable,"-B",str(HERE/"ordinary_start_observer.py"),"observe",
            "--bundle",str(p/"bundle"),"--bundle-sha256",v["bundle_manifest_sha256"],"--output",str(run),
            "--adb",args.adb,"--adb-host",args.adb_host,"--adb-port",str(args.adb_port),"--serial",args.serial,
            "--logical-display-id","0","--physical-display-id",args.physical_display_id,
            "--input-width",str(args.input_width),"--input-height",str(args.input_height),
            "--arm-timeout","600","--command-timeout","15","--poll-seconds","1","--minimum-background-samples","3"]
def prefill(args,p,v,m,plan,ac,iv,suite):
    out=args.output.resolve(); run=args.run_output.resolve()
    need(not out.exists() and not run.exists(),"new prefill/run output required")
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    save(p/"prefill-reservation.json",dict(output=str(out),run_output=str(run),attempts=1,automatic_retry=False))
    ro,cli,parent,initial=live(args,out,m,plan,ac,iv)
    # The case's setup_home is test setup, never credited as a model action.
    _,raw=cli.command(["cmd","package","resolve-activity","--brief","--user","0","-a","android.intent.action.MAIN","-c","android.intent.category.HOME"],label="resolve-home")
    need(len(raw)<=16384,"HOME resolver output too large")
    homes=[x.strip() for x in raw.decode().splitlines() if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]+/[A-Za-z0-9_.$]+",x.strip())]
    need(len(homes)==1 and homes[0]==Q["scope"]["launcher_component"],"HOME component differs from scope"); home=homes[0].split("/")[0]
    save(out/"HOME-INTENT.json",dict(command=["input","-d","0","keyevent","KEYCODE_HOME"],attempts=1,task_action=False))
    cli.command(["input","-d","0","keyevent","KEYCODE_HOME"],label="setup-home-once")
    deadline=time.monotonic()+4
    while True:
        focus=ro.focus()
        if focus["package"]==home: break
        need(time.monotonic()<deadline,"HOME focus not established; no retry"); time.sleep(0.2)
    home_ui=ro.png("before-prefill-home")
    need(home_ui["focus"]["package"]==home,"HOME changed before prefill")
    need(m.idle_snapshot(ro,UID,plan)==initial,"session/config changed during HOME setup")
    launch=plan['_scope_module'].ordinary_intent(INSTRUCTION,Q)
    need(not any(x in launch for x in ("auto_task","auto_run","auto_mobi_probe","auto_ui_venus_probe","test_nonce")),"automatic trigger prohibited")
    save(out/"MAIN-INTENT.json",dict(launch_words=launch,attempts=1,task_execution_requested=False,tap_attempts=0,automatic_retry=False))
    _,raw=cli.command(launch,label="ordinary-main-prefill",timeout=30)
    need(re.search(rb"(?m)^Status: ok\s*$",raw),"MAIN launch not acknowledged; do not replay")
    need(m.idle_snapshot(ro,UID,plan)==initial,"task/session changed during prefill")
    m.parent_identity(ro,parent); service_check(cli,parent)
    save(out/"PREFILL.json",dict(prepared_sha256=args.prepared_sha256,prefill_acknowledged=True,task_started=False,tap_attempts=0,
                               initial_idle=initial,parent=parent,home_component=homes[0],home_ui=home_ui,run_output=str(run),
                               instruction_sha256=INSTRUCTION_SHA,expected_scope_sha256=Q["scope_sha256"],qualification_binding_sha256=Q["binding_sha256"]))
    argv=observer_argv(args,p,v,run); started=time.monotonic(); proc=subprocess.Popen(argv)
    fields=Path("/proc/%d/stat"%proc.pid).read_text().rsplit(")",1)[1].split()
    save(out/"OBSERVER-PROCESS.json",dict(pid=proc.pid,start_ticks=int(fields[19]),argv=argv,launch_monotonic=started,
                                        launch_wall_ms=int(time.time()*1000),arm_timeout_s=600))
    print(json.dumps(dict(event="PREFILLED_OBSERVER_STARTED_NO_START_TAP",prefill=str(out),run_output=str(run),observer_pid=proc.pid)),flush=True)
    code=proc.wait()
    save(out/"OBSERVER-EXIT.json",dict(pid=proc.pid,exit_code=code,wall_ms=int(time.time()*1000)))
    return code
def armed(run,prefill,ready,process):
    need(ready.get("event")=="ARMED_AWAITING_ROOT_START" and ready.get("instruction")==INSTRUCTION
         and ready.get("phone_actions_sent")==0 and ready.get("expected_scope_sha256")==Q["scope_sha256"]
         and ready.get("qualification_binding_sha256")==Q["binding_sha256"],"READY differs")
    need(not (run/"RESULT.json").exists() and not (prefill/"OBSERVER-EXIT.json").exists(),"observer ended; never tap")
    proc=Path("/proc/%d"%process["pid"]); fields=(proc/"stat").read_text().rsplit(")",1)[1].split()
    need(fields[0] not in ("Z","X","x") and int(fields[19])==process["start_ticks"],"observer process identity changed")
    need((proc/"cmdline").read_bytes().rstrip(b"\0").decode().split("\0")==process["argv"],"observer command changed")
    age=time.monotonic()-process["launch_monotonic"]; wall=(int(time.time()*1000)-ready["wall_ms"])/1000
    need(0<=age<570 and 0<=wall<570,"outside conservative observer arm window")
    return dict(pid=process["pid"],start_ticks=process["start_ticks"],age_seconds=age,ready_age_seconds=wall)
def start(args,p,v,m,plan,ac,iv,suite):
    from PIL import Image
    pre=args.prefill.resolve(strict=True); pf=obj(read(pre/"PREFILL.json")); run=Path(pf["run_output"])
    need(pf["prepared_sha256"]==args.prepared_sha256 and pf["instruction_sha256"]==INSTRUCTION_SHA and pf.get("expected_scope_sha256")==Q["scope_sha256"]
         and pf.get("qualification_binding_sha256")==Q["binding_sha256"],"prefill identity differs")
    ready_raw=read(run/"READY.json"); need(sha(ready_raw)==args.ready_sha256,"reviewed READY differs"); ready=obj(ready_raw)
    reference=read(run/"ready.png",24<<20); need(sha(reference)==args.reviewed_image_sha256,"reviewed image differs")
    need(ready["ready_ui"]["sha256"]==sha(reference),"READY image binding differs")
    process=obj(read(pre/"OBSERVER-PROCESS.json"))
    need(process["argv"]==observer_argv(args,p,v,run),"observer argv is not this frozen run")
    first_arm=armed(run,pre,ready,process)
    out=args.output.resolve(); out.mkdir(mode=0o700,parents=True,exist_ok=False)
    ro,cli,parent,idle=live(args,out,m,plan,ac,iv)
    need(parent==ready["parent"]==pf["parent"] and idle==pf["initial_idle"],"parent/prior idle differs")
    need(set(ro.list_children("files/control-tasks",directories=True))==set(ready["baseline_tasks"]),"new task appeared before Start")
    focus=ro.focus(); need(focus["package"]==PACKAGE and focus["component"]==PACKAGE+".MainActivity","ordinary MainActivity not focused")
    fresh_ui=ro.png("immediately-before"); need(fresh_ui["focus"]["package"]==PACKAGE and fresh_ui["focus"]["component"]==focus["component"],"focus changed")
    fresh=read(out/"readonly/immediately-before.png",24<<20)
    a=Image.open(io.BytesIO(reference)).convert("RGBA"); b=Image.open(io.BytesIO(fresh)).convert("RGBA")
    x0,y0,x1,y1=args.review_rectangle; x,y=args.start_point
    need(a.size==b.size==(1224,2992) and 0<=x0<x1<=1224 and 0<=y0<y1<=2992 and x0<x<x1 and y0<y<y1,"invalid reviewed instruction+Start rectangle")
    need(a.crop(tuple(args.review_rectangle)).tobytes()==b.crop(tuple(args.review_rectangle)).tobytes(),"reviewed instruction+Start pixels changed")
    need(m.idle_snapshot(ro,UID,plan)==idle,"session/config changed before tap"); m.parent_identity(ro,parent)
    final_arm=armed(run,pre,ready,process)
    intent=dict(schema="hepta.orvena-v32-ordinary-start.v1",instruction_sha256=INSTRUCTION_SHA,
                expected_scope_sha256=Q["scope_sha256"],qualification_binding_sha256=Q["binding_sha256"],
                ready_sha256=sha(ready_raw),reference_sha256=sha(reference),fresh_sha256=sha(fresh),
                review_rectangle=args.review_rectangle,start_point=args.start_point,
                operator_review_required="The rectangle contains the exact Chinese instruction and the enabled ordinary Start button.",
                first_arm=first_arm,final_arm=final_arm,tap_attempts=1,automatic_retry=False,
                prepared_sha256=args.prepared_sha256,prefill=str(pre),run_output=str(run),wall_ms=int(time.time()*1000))
    # Create-once reservation is written before the uncertain physical action.
    save(p/"start-reservation.json",intent); save(out/"INTENT.json",intent)
    cli.command(["input","-d","0","tap",str(x),str(y)],label="ordinary-start-once")
    save(out/"RESULT.json",dict(tap_exit_observed=True,tap_attempts=1,task_start_not_inferred_from_exit=True,automatic_retry=False))
    print("ORDINARY_START_TAP_ACKNOWLEDGED_ONCE",flush=True)
def copy_evidence(source,dest):
    pins={}; total=0; count=0
    for top in ("task","runs"):
        base=source/top; need(base.is_dir() and not base.is_symlink(),"missing original "+top)
        for p in sorted(base.rglob("*")):
            need(not p.is_symlink(),"symlink in original evidence")
            if p.is_dir(): continue
            b=read(p,16<<20); count+=1; total+=len(b)
            need(count<=2000 and total<=256<<20,"evidence copy bound exceeded")
            rel=p.relative_to(source); write(dest/rel,b); pins[str(rel)]=dict(bytes=len(b),sha256=sha(b))
    for name in ("collection.json",):
        path=source/name
        if path.is_file():
            b=read(path); write(dest/name,b); pins[name]=dict(bytes=len(b),sha256=sha(b))
    return pins
def collect_goal(args,p,v,m,plan,ac,iv,suite):
    run=args.run_output.resolve(strict=True); raw=read(run/"RESULT.json")
    need(sha(raw)==args.observer_result_sha256,"observer result differs"); result=obj(raw)
    task_id=result.get("task_id")
    need(re.fullmatch(r"[0-9a-f]{32}",task_id or "") and result.get("cleanup_known") is True
         and result.get("candidate")==CANDIDATE and result.get("instruction_sha256")==INSTRUCTION_SHA
         and result.get("qualification_binding_sha256")==Q["binding_sha256"] and result.get("expected_scope_sha256")==Q["scope_sha256"],
         "original observer has no bound known-clean terminal; no UiAutomation")
    terminal=result.get("task_result",{})
    need(terminal.get("task_id")==task_id and terminal.get("cleanup_known") is True
         and terminal.get("external_model") is False and terminal.get("automatic_replay") is False,"task terminal differs")
    out=args.output.resolve(); out.mkdir(mode=0o700,parents=True,exist_ok=False)
    ro,cli,parent,idle=live(args,out,m,plan,ac,iv)
    need(parent==result["parent"] and idle["control"].get("task_id")==task_id
         and idle["control"].get("origin")=="user_button" and idle["control"].get("debug_nonce_sha256") is None
         and idle["control"].get("instruction_sha256")==INSTRUCTION_SHA
         and idle["control"].get("status")==terminal.get("status"),"current idle is not this ordinary terminal")
    write(out/"original-observer-RESULT.json",raw)
    pins=copy_evidence(run,out); save(out/"ORIGINAL-EVIDENCE.json",dict(original_run=str(run),observer_sha256=sha(raw),files=pins))
    before_png=ro.png("goal-before-xml")
    save(out/"UI-CAPTURE-INTENT.json",dict(task_id=task_id,terminal_only=True,cleanup_known=True,
                                         temporary_phone_xml=True,may_rebind_accessibility=True,
                                         private_nonce_submitted=False,task_actions=0))
    ui=ac.capture_ui(cli,out,"ui-final")
    need(m.idle_snapshot(ro,UID,plan)==idle,"journals/config changed during terminal UI capture")
    m.parent_identity(ro,parent)
    after_png=ro.png("goal-current")
    need(m.idle_snapshot(ro,UID,plan)==idle,"state changed around final screenshot")
    service_check(cli,parent)
    oracle=module(HERE/"core_assertions.py","orvena_npu_ordinary_core_assertions")
    goal=oracle.evaluate_case(out,CASE,suite,ac,APK_SHA)
    technical=(result.get("observation_status")=="complete" and result.get("technical_evidence_complete") is True
               and result.get("all_native_bindings_verified") is True and result.get("background_verified") is True
               and result.get("errors")==[])
    review=dict(schema="hepta.orvena-v32-ordinary-goal-review.v1",task_id=task_id,observer_result_sha256=sha(raw),
                instruction_sha256=INSTRUCTION_SHA,candidate=CANDIDATE,technical_gate_passed=technical,
                expected_scope_sha256=Q["scope_sha256"],qualification_binding_sha256=Q["binding_sha256"],
                task_status=terminal.get("status"),model_reported_success=terminal.get("model_reported_success"),
                goal=goal,before_xml_png=before_png,current_png=after_png,
                independent_visual_review="Root must review goal-current.png and require agreement with the exact XML markers and Settings foreground.",
                full_phone_acceptance=False,automatic_retry=False,phone_task_actions_sent=0,
                evidence_boundary="Original observer/task/run files unchanged; this is a new host evidence view with terminal-only XML.")
    save(out/"GOAL-REVIEW.json",review)
    print(json.dumps(dict(goal_review=str(out/"GOAL-REVIEW.json"),goal=goal.get("all_passed"),
                          technical_gate_passed=technical,current_png=str(out/"readonly/goal-current.png"),
                          full_phone_acceptance=False),ensure_ascii=False))
def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qualification-binding',type=Path,required=True)
    p.add_argument('--qualification-binding-sha256',required=True)
    p.add_argument('--package-sha256',required=True)
    sub=p.add_subparsers(dest='mode',required=True)
    q=sub.add_parser('prepare')
    for name in ('selection','upgrade-proof','upgrade-helper','selector-helper','output'):
        q.add_argument('--'+name,type=Path,required=True)
    q.add_argument('--selection-result-sha256',required=True);q.add_argument('--upgrade-proof-sha256',required=True)
    return p
def main():
    sys.dont_write_bytecode=True;args=parser().parse_args()
    sys.path.insert(0,str(HERE.parent/'drivers'))
    scope=module(HERE.parent/'drivers/qualification_scope.py','qualification_scope')
    binding=scope.load_binding(args.qualification_binding,args.qualification_binding_sha256)
    manifest=scope.verify_package(HERE.parent,args.package_sha256)
    configure(binding,manifest)
    prepare(args);return 0
if __name__=="__main__":
    raise SystemExit(main())
