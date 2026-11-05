#!/usr/bin/env python3
"""P4 Root operator: observe, CAS, and tap the unchanged HEPTA Cancel once.

Default mode validates and prints a reviewable plan without phone access. Only
--execute-once enables the reviewed ADB UI route. This program never sends a
provider frame, starts a task/model, changes app state files, signals a process,
or retries an uncertain UI action. All physical PASS decisions remain external.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import sys
sys.dont_write_bytecode = True
import time
import types

HERE=Path(__file__).resolve().parent
P4_BASE=Path('/home/alex/razr60-local-model-v150')
F_SOURCE=Path('/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved_ui_package_phase_r7.py')
F_SHA='6d7597e55af1ba8330029352076b2c6715172056e6ea28dea97b57c7775fd35b'
F_CONFIG=F_SOURCE.parent/'preserved-ui-package-config.json'
STATE_DIR='/data/user/0/org.trillionnium.owneropen/files/'
SELECTED_READ=('test ! -e '+STATE_DIR+'owner-client-session-v1.pending && '
    'base64 '+STATE_DIR+'owner-client-session-v1.bin && '
    'test ! -e '+STATE_DIR+'owner-client-session-v1.pending')
HEPTA_COMPONENT='org.trillionnium.owneropen/.OwnerOpenShellActivity'


def raw_file(path,limit=4*1024*1024):
    path=Path(path)
    if path.parent.resolve(strict=True)!=path.parent:raise ValueError('noncanonical local source parent')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or not 0<=a.st_size<=limit:
            raise ValueError('local file type/size differs')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(limit+1)
        b,n=os.fstat(fd),path.lstat()
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        if len(raw)!=a.st_size or any(getattr(a,k)!=getattr(b,k) or getattr(a,k)!=getattr(n,k) for k in fields):
            raise ValueError('local original changed during read')
        return raw
    finally:os.close(fd)


def verify_package(manifest_path,pin):
    if manifest_path.parent.resolve(strict=True)/'source'!=HERE:
        raise ValueError('operator package is not the executable source directory')
    raw=raw_file(manifest_path,65536)
    if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('operator package manifest differs')
    m=json.loads(raw)
    if m.get('schema')!='hepta.r10.native-cancel-operator-package.v1':raise ValueError('operator package schema')
    rows=m['files'];seen=set();loaded={}
    for row in rows:
        p=Path(row['path'])
        if p.is_absolute() or '..' in p.parts or str(p) in seen:raise ValueError('operator package relative path')
        seen.add(str(p));b=raw_file(manifest_path.parent/p)
        if len(b)!=row['bytes'] or hashlib.sha256(b).hexdigest()!=row['sha256']:raise ValueError('operator file pin differs: '+str(p))
        loaded[str(p)]=b
    expected={'source/'+name for name in ('cancel_native_once_r10.py','cancel_phase.py','observe_cancel_phase_r10.py',
        'decode_client_state.py','native_journal_audit.py','production-pins.json','reviewed_page_projection.py','active_runtime_r10.py')}
    if not expected<=set(loaded) or raw_file(HERE/'cancel_native_once_r10.py')!=loaded['source/cancel_native_once_r10.py']:
        raise ValueError('operator executable not in reviewed package')
    if m.get('reviewed_production_source_pins')!=json.loads(loaded['source/production-pins.json']):
        raise ValueError('reviewed production source map differs from operator manifest')
    return loaded,m


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def save_new(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as f:f.write(raw);f.flush();os.fsync(fd)
    finally:os.close(fd)
    sync_dir(path.parent)


def private_directory(path):
    if path.parent.resolve(strict=True)!=path.parent:raise ValueError('noncanonical private directory parent')
    try:path.mkdir(mode=0o700);sync_dir(path.parent)
    except FileExistsError:pass
    s=path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:
        raise ValueError('private operator directory metadata differs')


def load_reviewed_helpers(loaded):
    """Compile pinned bytes directly. No sys.path or bytecode cache can substitute a helper."""
    sys.dont_write_bytecode = True
    pins=json.loads(loaded['source/production-pins.json'])
    modules={}
    for name in ('active_runtime_r10','cancel_phase','decode_client_state','reviewed_page_projection'):
        path=HERE/(name+'.py');raw=loaded['source/'+name+'.py']
        module=types.ModuleType(name);module.__file__=str(path)
        if name=='active_runtime_r10':module._REVIEWED_PRODUCTION_PINS=pins
        sys.modules[name]=module
        exec(compile(raw,str(path),'exec',optimize=0),module.__dict__)
        modules[name]=module
    guards=modules['cancel_phase'];decoder=modules['decode_client_state'];page=modules['reviewed_page_projection']
    for name in ('need','sha','strict','encoded','validate_plan','phase_ready','selected_matches','unique_ui_node','HEPTA'):
        globals()[name]=getattr(guards,name)
    globals()['decode_client_state']=decoder.decode_client_state
    for name in ('PAGE_STATE_COMMAND','page_state','validate_viewport'):globals()[name]=getattr(page,name)
    return modules


def require_final_execution_dependencies(manifest, modules):
    active=modules['active_runtime_r10']
    active.require_final_dependencies()
    need(manifest.get('reviewed_boundary_consumer_sha256')==active.CONSUMER_SHA
         and manifest.get('reviewed_readiness_sha256')==active.READINESS_SHA,
         'selected final consumer/readiness pins differ from the executable source')


def build_observer_request(plan,scope_hint,loaded):
    # Every source is from the already verified package. Future READY and task
    # scope are data; this function performs no runtime, file or network read.
    names=('active_runtime_r10.py','cancel_phase.py','native_journal_audit.py',
        'observe_cancel_phase_r10.py','production-pins.json')
    embedded={name:loaded['source/'+name].decode('utf-8') for name in names}
    payload={'plan':plan,'scope_hint':scope_hint,'source':embedded}
    raw=encoded(payload);need(len(raw)<=262144,'bounded observer decompressed payload')
    wire=base64.b64encode(gzip.compress(raw,mtime=0)).decode()
    bootstrap=(
        "import base64,zlib,json,sys,types,hashlib\nsys.dont_write_bytecode=True\n"
        "packed=base64.b64decode(sys.argv[1],validate=True);d=zlib.decompressobj(31)\n"
        "b=d.decompress(packed,262145)\n"
        "assert len(b)<=262144 and d.eof and not d.unused_data and not d.unconsumed_tail\n"
        "assert len(b)=="+str(len(raw))+" and hashlib.sha256(b).hexdigest()=="+repr(sha(raw))+"\n"
        "p=json.loads(b);pins=json.loads(p['source']['production-pins.json'])\n"
        "a=types.ModuleType('active_runtime_r10');a._REVIEWED_PRODUCTION_PINS=pins\n"
        "a.__file__='<reviewed-active-runtime-r10>';sys.modules['active_runtime_r10']=a\n"
        "exec(compile(p['source']['active_runtime_r10.py'],a.__file__,'exec'),a.__dict__)\n"
        "m=types.ModuleType('cancel_phase');m.__file__='<reviewed-cancel-phase-r10>';sys.modules['cancel_phase']=m\n"
        "exec(compile(p['source']['cancel_phase.py'],m.__file__,'exec'),m.__dict__)\n"
        "n={'__name__':'reviewed_observer','_REVIEWED_NATIVE_AUDIT_SOURCE':p['source']['native_journal_audit.py'].encode('utf-8'),"
        "'_REVIEWED_PRODUCTION_PINS':pins}\n"
        "exec(compile(p['source']['observe_cancel_phase_r10.py'],'reviewed-cancel-live-observer-r10','exec'),n)\n"
        "print(json.dumps(n['observe'](p['plan'],p['scope_hint']),ensure_ascii=False,separators=(',',':'),allow_nan=False))\n")
    command=('/data/adb/magisk/busybox timeout -s TERM -k 1 8 /data/adb/magisk/busybox chroot '
        '/data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '+shlex.quote(bootstrap)+' '+shlex.quote(wire))
    root_command='/debug_ramdisk/su -c '+shlex.quote(command)
    adb=('shell,v2,raw:'+root_command).encode()
    need(len(command.encode())<62000 and len(adb)<65536,'actual quoted ADB request exceeds fixed bound')
    return {'command':root_command,'payload_bytes':len(raw),'adb_wire_bytes':len(adb),
        'bootstrap_sha256':sha(bootstrap.encode()),'phone_calls':0}


class Actor:
    def __init__(self,plan,raw,loaded,out):
        self.plan,self.plan_raw,self.loaded,self.out=plan,raw,loaded,out
        self.counter=0;self.cancel_attempted=False;self.navigation_attempted=False
        self.target=None;self.original_phase=None
        # All module bytes are pinned above; the old file is imported, not run as
        # a CLI, and only its existing route/shell methods are used.
        b=raw_file(F_SOURCE,65536);need(sha(b)==F_SHA,'reviewed original ADB transport differs')
        self.f=types.ModuleType('reviewed_original_adb_transport');self.f.__file__=str(F_SOURCE)
        exec(compile(b,str(F_SOURCE),'exec'),self.f.__dict__)
        self.config=strict(raw_file(F_CONFIG,65536));self.route=self.f.route(self.config)
        self.save('PLAN.original.json',raw)
        self.save('BEGIN.json',encoded({'schema':'hepta.r10.native-cancel-operator-begin.v1',
            'plan_sha256':sha(raw),'p4_monotonic_ns':time.monotonic_ns(),'route':self.route,
            'case_id':plan['case_id'],'task_submissions':0,'provider_connections':0,'automatic_retry':False}))

    def save(self,name,raw):
        save_new(self.out/name,raw)

    def shell(self,command,tag,seconds=12):
        self.counter+=1;started=time.monotonic_ns();result=None;error=None
        def expired(_signal,_frame):raise TimeoutError('one original operator call total deadline')
        need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'preexisting alarm')
        previous=signal.getsignal(signal.SIGALRM);signal.signal(signal.SIGALRM,expired)
        try:
            signal.setitimer(signal.ITIMER_REAL,seconds)
            result=self.f.shell(command,self.config,self.route,timeout=seconds-1)
            need(result['rc']==0,'original operator command nonzero: '+str(result['rc']))
            return result
        except BaseException as exc:
            error={'type':type(exc).__name__,'message':str(exc)[:1024]};raise
        finally:
            signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
            self.save('%03d-%s.original.json'%(self.counter,tag),encoded({'p4_monotonic_started_ns':started,
                'p4_monotonic_finished_ns':time.monotonic_ns(),'command':command,'original_wire_receipt':result,
                'error':error,'automatic_retry':False}))

    def selected(self,tag):
        r=self.shell('/debug_ramdisk/su -c '+shlex.quote(SELECTED_READ),tag,10)
        raw=base64.b64decode(''.join(r['stdout'].split()),validate=True)
        value=decode_client_state(raw)
        if self.target:selected_matches(value,self.target)
        return value,raw

    def observe(self,tag):
        # The actual active gate rechecks the supplied r10 READY generations,
        # six release pins and owner-bound v150.3 scope. No idle gate is called.
        request=build_observer_request(self.plan,self.target['scope'] if self.target else None,self.loaded)
        r=self.shell(request['command'],tag,12)
        value=strict(r['stdout'])
        need(value['boot_id']==self.plan['expected_boot'] and value['owner_request_sha256']==self.plan['owner_request_sha256'], 'observer output binding')
        self.save('%03d-%s.observation.json'%(self.counter,tag),encoded(value))
        return value

    def page(self,tag):
        command=('hepta_p=$('+PAGE_STATE_COMMAND+'); hepta_v=$(dumpsys display | grep "mViewports="); '
            'printf \'{"page_b64":"%s","viewport_b64":"%s"}\\n\' '
            '"$(printf %s "$hepta_p" | base64 | tr -d \'\\r\\n\')" '
            '"$(printf %s "$hepta_v" | base64 | tr -d \'\\r\\n\')"')
        r=self.shell(command,tag,10);value=strict(r['stdout'])
        raw=base64.b64decode(value['page_b64'],validate=True).decode()
        viewport=base64.b64decode(value['viewport_b64'],validate=True).decode()
        page=page_state(raw)
        # This is the exact reviewed production viewport parser, projected as
        # a pure host function. Original bytes guard the subsequent operator tap.
        validate_viewport(viewport)
        return {'raw':raw,'viewport':viewport,'page':page}

    def dump(self,tag):
        path='/data/local/tmp/hepta-native-cancel-r10-'+self.plan['nonce']+'-'+str(self.counter+1)+'.xml'
        command='test ! -e '+path+' && test ! -L '+path+' && uiautomator dump '+path+' && cat '+path
        return self.shell(command,tag,16)['stdout']

    def guarded_tap(self,node,page,selected_raw,tag,cancel=False):
        need(page['page']['component']==HEPTA,'tap is not in actual HEPTA window')
        selected_b64=base64.b64encode(selected_raw).decode()
        command='[ "$(getprop ro.serialno)" = ZY22LS7WZT ] || exit 64; '
        command+='[ "$(cat /proc/sys/kernel/random/boot_id)" = '+shlex.quote(self.plan['expected_boot'])+' ] || exit 65; '
        command+='[ "$(id -u)" = 2000 ] || exit 66; '
        command+='hepta_selected=$(/debug_ramdisk/su -c '+shlex.quote(SELECTED_READ)+') || exit 67; '
        command+='[ "$(printf %s "$hepta_selected" | tr -d \'\\r\\n\')" = '+shlex.quote(selected_b64)+' ] || exit 68; '
        command+='hepta_p=$('+PAGE_STATE_COMMAND+'); [ "$hepta_p" = '+shlex.quote(page['raw'])+' ] || exit 70; '
        command+='hepta_v=$(dumpsys display | grep "mViewports="); [ "$hepta_v" = '+shlex.quote(page['viewport'])+' ] || exit 71; '
        command+='input tap '+str(node['x'])+' '+str(node['y'])
        self.save(tag+'.intent.json',encoded({'schema':'hepta.r10.native-cancel-ui-intent.v1',
            'plan_sha256':sha(self.plan_raw),'scope':self.target['scope'],'native_request_sha256':self.target['native_request_sha256'],
            'selected_record_sha256':sha(selected_raw),'ui_node':node,'command_sha256':sha(command.encode()),
            'p4_monotonic_ns':time.monotonic_ns(),'cancel_attempt':cancel,'automatic_retry':False,
            'transport':'original_HEPTA_UI','provider_frame_injection':False}))
        if cancel:self.cancel_attempted=True
        return self.shell(command,tag,12)

    def sender_ready(self):
        path=Path('/home/alex/codex-hepta-natural-'+self.plan['sender_label']+'-root-v150')
        if not path.is_dir():return False
        window=path/'SEND.MONOTONIC-WINDOW.json'
        if not window.exists():return False
        files={name:raw_file(path/name,262144) for name in ('SEND.once.json','SEND.MONOTONIC-INTENT.json',
            'SEND.MONOTONIC-WINDOW.json','FINAL-PRE-SEND-UI.json')}
        once,mark,period,ui=[strict(files[name]) for name in ('SEND.once.json','SEND.MONOTONIC-INTENT.json',
            'SEND.MONOTONIC-WINDOW.json','FINAL-PRE-SEND-UI.json')]
        need(once['prompt_sha256']==self.plan['owner_request_sha256'] and once['prompt'].encode()==validate_plan(self.plan)
            and once['automatic_replay'] is False and mark['send_attempt_count']==1 and
            period['send_started_monotonic_ns']>=mark['p4_pre_send_monotonic_ns'] and
            period['send_returned_monotonic_ns']>=period['send_started_monotonic_ns'] and
            period['send_status'] in ('tap_returned','unknown'), 'sender original binding differs')
        need(not (path/'SEND-NATIVE-LATENCY.json').exists() and not (path/'ACTOR-FAILURE.json').exists(),
            'sender already terminal/restoring; no cancellation race')
        need(ui['rc']==0,'original sender UI capture failed')
        unique_ui_node(ui['stdout'],'org.trillionnium.owneropen:id/ui_send')
        need('org.trillionnium.owneropen' in ui['stdout'],'pre-Send HEPTA UI original absent')
        self.save('SENDER-ORIGINALS.json',encoded({name:{'path':str(path/name),'bytes':len(raw),'sha256':sha(raw),
            'raw_b64':base64.b64encode(raw).decode()} for name,raw in files.items()}))
        return True

    def run(self):
        deadline=time.monotonic()+self.plan['wait_seconds'];ready=False;read_count=0
        while time.monotonic()+12<deadline:
            if not ready:
                ready=self.sender_ready()
                if not ready:time.sleep(.25);continue
            read_count+=1
            try:observation=self.observe('WAIT-%03d'%read_count)
            except (ValueError,OSError,TimeoutError):
                time.sleep(.25);continue  # read-only observation, never action replay
            if observation['state']!='NO_MATCHING_ACCEPTED_TASK':
                self.target=observation
            if phase_ready(self.plan,observation):
                self.original_phase=observation;break
            time.sleep(.25)
        need(self.original_phase is not None,'finite phase wait ended; zero Cancel')
        selected,raw=self.selected('PHASE-SELECTED')
        page=self.page('PHASE-PUBLIC-FOREGROUND')
        expected=HEPTA if self.plan['case_id']=='NEG-08' else self.plan['probe_component']
        need(page['page']['component']==expected,'independent public effect/foreground precondition differs')
        self.save('PHASE-ARMED.json',encoded({'original_observation':self.original_phase,'independent_page':page,
            'selected_identity':selected,'p4_monotonic_ns':time.monotonic_ns(),
            'task_effect_boundary':'zero_dispatches' if self.plan['case_id']=='NEG-08' else 'one_original_open_with_independent_probe_foreground',
            'physical_case_pass':False}))
        guards=P4_BASE/'native-cancel-intents-r10';private_directory(guards)
        save_new(guards/(self.plan['owner_request_sha256']+'.json'),encoded({'plan_sha256':sha(self.plan_raw),
            'scope':self.target['scope'],'out':str(self.out),'p4_monotonic_ns':time.monotonic_ns(),
            'one_operator_sequence_reserved':True,'automatic_retry':False}))
        if self.plan['case_id']=='NEG-09':
            # Root explicitly approved this operator-only navigation. It never
            # satisfies a model return postcondition or a task effect counter.
            self.save('OPERATOR-HEPTA-NAVIGATION.intent.json',encoded({'scope':self.target['scope'],
                'from':page,'model_return_postcondition':False,'task_tool_dispatch':False,'automatic_retry':False}))
            self.navigation_attempted=True
            nav=self.shell('am start -W -n '+HEPTA_COMPONENT,'OPERATOR-HEPTA-NAVIGATION',12)
            need(re.findall(r'^Status:\s*(\S+)\s*$',nav['stdout'],re.MULTILINE)==['ok']
                and not re.search(r'^\s*(?:Error|Exception|SecurityException)\b',nav['stdout'],re.MULTILINE), 'operator HEPTA navigation failed')
            page=self.page('OPERATOR-HEPTA-FOREGROUND')
            need(page['page']['component']==HEPTA,'operator navigation did not foreground HEPTA')
        xml=self.dump('TASK-CONTROL-UI')
        summary=unique_ui_node(xml,'org.trillionnium.owneropen:id/ui_task_summary')
        selected,raw=self.selected('TASK-CONTROL-SELECTED');page=self.page('TASK-CONTROL-FOREGROUND')
        self.guarded_tap(summary,page,raw,'OPEN-CURRENT-TASK')
        xml=self.dump('CANCEL-UI');node=unique_ui_node(xml,'org.trillionnium.owneropen:id/ui_cancel')
        # Re-observe the actual original model and dispatch prefix after operator
        # navigation. No stale first-effect handshake can authorize this tap.
        final=self.observe('FINAL-PRE-CANCEL')
        need(phase_ready(self.plan,final,self.original_phase),'same original phase no longer active')
        self.target=final
        selected,raw=self.selected('FINAL-PRE-CANCEL-SELECTED');page=self.page('FINAL-PRE-CANCEL-FOREGROUND')
        self.save('CANCEL-PHASE-WINDOW.json',encoded({'before':self.original_phase,'final':final,
            'p4_monotonic_ns':time.monotonic_ns(),'operator_navigation_separate':self.navigation_attempted,
            'model_return_postcondition':False,'physical_case_pass':False}))
        self.guarded_tap(node,page,raw,'CANCEL-ONCE',cancel=True)
        # All subsequent operations are reads. The original sender may now
        # restore its preserved draft; this actor performs no further UI action.
        after_deadline=time.monotonic()+75;last=None;post_count=0
        while time.monotonic()+12<after_deadline:
            post_count+=1
            try:last=self.observe('AFTER-CANCEL-%03d'%post_count)
            except (ValueError,OSError,TimeoutError):
                time.sleep(.25);continue
            if last.get('native_terminal') and last.get('model',{}).get('assessment',{}).get('admitted') is True:break
            time.sleep(.25)
        accepted=False;cancelled=False;drained=False;prefix_same=False;image_interrupted=False
        if last and last.get('state')=='BOUND_ORIGINAL_PHASE_OBSERVED':
            accepted=(last['cancel_acceptances']==1 and last['cancel_acceptance_frames'][0]['payload'].get('status')=='requested'
                and last['cancel_acceptance_frames'][0]['payload'].get('automatic_redispatch') is False)
            cancelled=bool(last['native_terminal'] and last['native_terminal']['payload'].get('status')=='cancelled')
            prefix_same=last['calls']==self.original_phase['calls']
            m=last.get('model') or {};original=self.original_phase['model']
            drained=(m.get('request_id')==original['request_id'] and m.get('request_sha256')==original['request_sha256']
                and m.get('server_identity')==original['server_identity'] and m.get('assessment',{}).get('admitted') is True)
            point=m.get('original_cancel_safe_point') or {}
            image_interrupted=(drained and m.get('image_count')==1 and
                m.get('assessment',{}).get('server_cancel_acknowledged') is True and
                point.get('phase')=='cpu_image_encode' and point.get('abort_callback_observed') is True and
                point.get('compute_synchronized') is True and point.get('queue_handoff_completed') is True and
                point.get('model_retry_count')==0 and point.get('partial_result_not_dispatched') is True)
        result={'schema':'hepta.r10.native-cancel-once-result.v1','state':'ORIGINAL_CANCEL_AND_DRAIN_OBSERVED' if
            accepted and cancelled and drained and prefix_same else 'UNKNOWN_OR_PHASE_MISSED_RETAIN_ORIGINALS',
            'case_id':self.plan['case_id'],'scope':self.target['scope'],'owner_request_sha256':self.plan['owner_request_sha256'],
            'cancel_tap_attempts':1,'cancel_acceptance_observed':accepted,'native_cancelled_observed':cancelled,
            'original_model_terminal_release_idle_observed':drained,'dispatch_prefix_unchanged':prefix_same,
            'operator_navigation_separate':self.navigation_attempted,'model_return_postcondition':False,
            'actual_image_request':self.original_phase['model']['image_count']==1,
            'image_encoder_interruption_phase_proven':image_interrupted,'automatic_retry':False,
            'task_submissions':0,'model_requests':0,'provider_frame_injections':0,'physical_case_pass':False,
            'independent_original_capture_and_late_closure_required':True,'last_original_observation':last}
        self.save('RESULT.json',encoded(result));return result


def main():
    p=argparse.ArgumentParser();p.add_argument('--plan',type=Path,required=True)
    p.add_argument('--package',type=Path,required=True);p.add_argument('--package-sha256',required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--execute-once',action='store_true')
    args=p.parse_args();os.umask(0o077)
    loaded,manifest=verify_package(args.package,args.package_sha256)
    modules=load_reviewed_helpers(loaded)
    raw=raw_file(args.plan,65536);plan=strict(raw);validate_plan(plan)
    need(args.out.is_absolute() and args.out.name==plan['label'],'new output must use exact operator label')
    observe_preview=build_observer_request(plan,None,loaded)
    preview={'schema':'hepta.r10.native-cancel-operator-preview.v1','state':'VALIDATED_NO_PHONE',
        'plan_sha256':sha(raw),'package_sha256':args.package_sha256,'case_id':plan['case_id'],
        'out':str(args.out),'observer_payload_bytes':observe_preview['payload_bytes'],
        'observer_adb_wire_bytes':observe_preview['adb_wire_bytes'],
        'readiness_original_sha256':plan['runtime_binding']['readiness']['sha256'],
        'task_template_sha256':plan['task_template_sha256'],
        'once_route':'HEPTA49 ui_cancel -> durable selected CAS -> OwnerOpenClient.cancelTurn',
        'operator_navigation_before_cancel':plan['case_id']=='NEG-09','automatic_retry':False,
        'task_submissions':0,'model_requests':0,'phone_calls':0,'physical_case_pass':False}
    if not args.execute_once:
        print(json.dumps(preview,sort_keys=True));return
    require_final_execution_dependencies(manifest,modules)
    need(args.out.parent==P4_BASE/'cancel-native-r10','execute output outside reviewed P4 root')
    private_directory(args.out.parent);args.out.mkdir(mode=0o700);sync_dir(args.out.parent)
    save_new(args.out/'PACKAGE-PREVIEW.json',encoded(preview))
    actor=None
    try:
        actor=Actor(plan,raw,loaded,args.out);result=actor.run()
        print(json.dumps({k:v for k,v in result.items() if k!='last_original_observation'},sort_keys=True))
        if result['state']!='ORIGINAL_CANCEL_AND_DRAIN_OBSERVED':raise SystemExit(2)
    except BaseException as error:
        if isinstance(error,SystemExit):raise
        failure={'schema':'hepta.r10.native-cancel-operator-failure.v1','state':'HELD_OR_UNKNOWN_NO_RETRY',
            'error_type':type(error).__name__,'error':str(error)[:1024],
            'cancel_tap_attempts':int(bool(actor and actor.cancel_attempted)),
            'operator_navigation_attempted':bool(actor and actor.navigation_attempted),'automatic_retry':False,
            'physical_case_pass':False,'retained_originals':str(args.out)}
        save_new(args.out/'FAILURE.json',encoded(failure));print(json.dumps(failure,sort_keys=True));raise SystemExit(2)


if __name__=='__main__':main()
