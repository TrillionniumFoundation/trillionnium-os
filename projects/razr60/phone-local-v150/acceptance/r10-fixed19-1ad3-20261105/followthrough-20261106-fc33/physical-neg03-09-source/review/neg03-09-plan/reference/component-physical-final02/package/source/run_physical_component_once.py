#!/usr/bin/env python3
"""Root-only COMP01 return or NEG03 physical rotation, with one-use phases.

Preview performs no I/O. Execution requires actual sealed dependencies and an
explicit plan. Unknown transport never triggers an automatic phone action.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import sys
import time
import types
import zlib

SSH=['/usr/bin/ssh','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22',
    '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','pocket4-usb4-fast']
P4_BASE=Path('/home/alex/codex-physical-components-r10-r1')
CAPTURE_SHA='f12a251542894d0e8c0dedc9d62eb96d4f39e2b1d563f849c2f60e6ee02580e3'


def stage_program():
    return "import sys,json,base64,hashlib,os,stat\nfrom pathlib import Path\nv=json.loads(sys.stdin.buffer.read(262145));r=Path(v['root']);parent=r.parent\nassert parent==Path('/home/alex/codex-physical-components-r10-r1') and len(r.name)==32\nos.umask(0o077)\nif not parent.exists():parent.mkdir(mode=0o700)\nassert parent.resolve(strict=True)==parent and stat.S_IMODE(parent.stat().st_mode)==0o700\nr.mkdir(mode=0o700);(r/'source').mkdir(mode=0o700);(r/'phases').mkdir(mode=0o700)\ndef put(p,b):\n fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())\n fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)\nassert set(v['source'])=={'owned_capture.py','p4_component_dispatch_once.py'}\nfor name,row in v['source'].items():\n b=base64.b64decode(row['base64'],validate=True);assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']\n compile(b,str(r/'source'/name),'exec');put(r/'source'/name,b)\nbody=base64.b64decode(v['case'],validate=True);put(r/'CASE.original.json',body)\nprint(json.dumps({'state':'EXACT_SOURCE_AND_CASE_STAGED_NO_PHONE','case_sha256':hashlib.sha256(body).hexdigest(),'phone_calls':0}))\n"


def bootstrap(manifest_sha):
    root=Path(__file__).resolve().parent.parent
    path=root/'SOURCE-MANIFEST.json'
    if path.resolve(strict=True)!=path:
        raise ValueError('canonical source manifest required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not 0<st.st_size<=262144:
            raise ValueError('bounded manifest required')
        raw=os.read(fd,st.st_size+1)
    finally:
        os.close(fd)
    if len(raw)!=st.st_size or hashlib.sha256(raw).hexdigest()!=manifest_sha:
        raise ValueError('explicit source manifest pin differs')
    value=json.loads(raw)
    rows=[r for r in value['files'] if r['path']=='source/physical_component_common.py']
    if len(rows)!=1:
        raise ValueError('one pinned common source required')
    p=root/rows[0]['path']
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        body=os.read(fd,rows[0]['bytes']+1)
    finally:
        os.close(fd)
    if len(body)!=rows[0]['bytes'] or hashlib.sha256(body).hexdigest()!=rows[0]['sha256']:
        raise ValueError('common source pin differs')
    S=types.ModuleType('physical_component_common')
    S.__file__=str(p)
    exec(compile(body,str(p),'exec'),S.__dict__)
    originals=S.Originals()
    manifest_row=S.desc(path,raw)
    mf,files=S.load_members(originals,manifest_row)
    S.need(mf['schema']=='hepta.physical-component.root-source-package.v1'
        and files['source/run_physical_component_once.py']==originals.known(Path(__file__).resolve(),131072)[1]
        and S.sha(files['source/owned_capture.py'])==CAPTURE_SHA,'reviewed complete physical source package required')
    capture=S.module(files['source/owned_capture.py'],root/'source/owned_capture.py','physical_owned_capture')
    return root,S,originals,manifest_row,files,capture


class RootCase:
    def __init__(self,S,C,plan,plan_raw,manifest_row,files,admitted,originals):
        self.S,self.C,self.plan,self.plan_raw=S,C,plan,plan_raw
        self.manifest_row,self.files,self.admitted,self.originals=manifest_row,files,admitted,originals
        self.out=Path(plan['out'])
        expected=S.B/'physical-components-r10-r1'/plan['label']
        S.need(self.out==expected and not self.out.exists() and not self.out.is_symlink(),
            'one new fixed Root case namespace required; reconcile an existing attempt')
        if not self.out.parent.exists():
            C.newdir(self.out.parent)
        S.need(self.out.parent.resolve(strict=True)==self.out.parent,'canonical Root output parent required')
        C.newdir(self.out)
        self.started=time.monotonic_ns()
        self.deadline=time.monotonic()+300
        self.usage_before=resource.getrusage(resource.RUSAGE_SELF)
        self.remote=P4_BASE/plan['nonce']
        self.phase_order=[]
        self.phase_rows={}
        self.last_completed=False
        self.last_actor_joined=False
        self.last_phase=None
        self.rotation_attempted=False
        self.restored=False
        C.put(self.out/'ROOT-PLAN.original.json',plan_raw)
        C.put(self.out/'SOURCE-MANIFEST.original.json',originals.read(manifest_row))
        C.put(self.out/'ROOT-INTENT.json',S.enc({'schema':'hepta.physical-component.root-intent.v1',
            'case_id':plan['case_id'],'label':plan['label'],'nonce':plan['nonce'],
            'request':plan['request'],'source_package':manifest_row,
            'maximum_phone_actor_starts':5,'maximum_return_dispatches':1 if plan['case_id']=='COMP-01' else 0,
            'maximum_rotation_setting_phases':2 if plan['case_id']=='NEG-03' else 0,
            'maximum_elapsed_seconds':300,'automatic_retry':False,'new_identity_retry':False,
            'native_task_scope_created':False,'model_requests':0,'signals_sent_by_root':0}))
        self.owner=C.OwnedCapture(self.out/'transport')
        C.newdir(self.out/'phone-originals')
        C.newdir(self.out/'plans')
        self.p4_case={'schema':'hepta.physical-component.p4-case.v1','nonce':plan['nonce'],
            'case_id':plan['case_id'],'label':plan['label'],'root_plan_sha256':S.sha(plan_raw),
            'root_source_manifest':manifest_row,'automatic_retry':False,'phone_actor_starts_per_phase':1}
        self.p4_case_raw=S.enc(self.p4_case)
        C.put(self.out/'P4-CASE.original.json',self.p4_case_raw)

    def remaining(self,maximum):
        left=self.deadline-time.monotonic()
        self.S.need(left>0,'original physical case deadline expired; no extension')
        return min(maximum,left)

    def recheck(self):
        self.originals.recheck()
        self.admitted['C'].recheck_source_package(self.admitted['co'],self.admitted['package'])

    def stage(self):
        S,C=self.S,self.C
        files={name:self.files['source/'+name] for name in ('owned_capture.py','p4_component_dispatch_once.py')}
        values={name:{'bytes':len(raw),'sha256':S.sha(raw),'base64':S.b64(raw)} for name,raw in files.items()}
        packet={'root':str(self.remote),'case':S.b64(self.p4_case_raw),'source':values}
        program=stage_program()
        result=self.owner.execute_process('p4-stage',SSH+[shlex.join(['/usr/bin/python3','-I','-B','-c',program])],
            self.remaining(30),input_raw=S.enc(packet))
        v=S.strict(result)
        S.need(v['state']=='EXACT_SOURCE_AND_CASE_STAGED_NO_PHONE' and v['case_sha256']==S.sha(self.p4_case_raw)
            and v['phone_calls']==0,'actual P4 staging receipt differs')

    def dispatch(self,phase,request):
        S,C=self.S,self.C
        S.need(phase not in self.phase_order and len(self.phase_order)<5,'phase already consumed or phone budget exhausted')
        self.recheck()
        self.phase_order.append(phase)
        self.last_phase=phase
        self.last_completed=False
        self.last_actor_joined=False
        packet={'schema':'hepta.physical-component.p4-phase.v1','case_sha256':S.sha(self.p4_case_raw),
            'nonce':self.plan['nonce'],'case_id':self.plan['case_id'],'phase':phase,'request':request}
        C.put(self.out/'plans'/(phase+'.json'),S.enc(packet))
        argv=['/usr/bin/python3','-I','-B',str(self.remote/'source/p4_component_dispatch_once.py'),
            '--case-root',str(self.remote),'--self-sha256',S.sha(self.files['source/p4_component_dispatch_once.py']),
            '--execute-one-phone-actor']
        raw=self.owner.execute_process('phone-'+phase,SSH+[shlex.join(argv)],
            self.remaining(request['timeout_seconds']+55),input_raw=S.enc(packet))
        bundle=S.strict(raw)
        S.need(bundle['schema']=='hepta.physical-component.p4-original-export.v1'
            and type(bundle['plain_bytes']) is int and 0<bundle['plain_bytes']<=64*1024*1024,
            'bounded original P4 export required')
        packed=S.decode(bundle['gzip_base64'],16*1024*1024)
        S.need(len(packed)==bundle['gzip_bytes'] and S.sha(packed)==bundle['gzip_sha256'],'P4 packed original differs')
        d=zlib.decompressobj(31)
        plain=d.decompress(packed,64*1024*1024+1)
        S.need(len(plain)==bundle['plain_bytes'] and S.sha(plain)==bundle['plain_sha256']
            and d.eof and not d.unused_data and not d.unconsumed_tail,'P4 bounded original decoder differs')
        payload=S.strict(plain)
        remote_phase=self.remote/'phases'/phase
        S.need(payload['schema']=='hepta.physical-component.p4-originals.v1' and payload['root']==str(remote_phase)
            and type(payload['files']) is list and 1<=len(payload['files'])<=128,'P4 original phase differs')
        out=self.out/'phone-originals'/phase
        C.newdir(out)
        originals={};mapping=[]
        for row in payload['files']:
            rel=S.relative(row['relative'])
            S.need(str(rel) not in originals and row['original']['path']==str(remote_phase/rel),'unique original origin required')
            body=S.decode(row['base64'],64*1024*1024)
            S.need(row['original']==S.desc(remote_phase/rel,body),'P4 original byte binding differs')
            path=out/rel
            for parent in reversed(path.parent.parents):
                if parent==out or out in parent.parents:
                    if not parent.exists():C.newdir(parent)
            if not path.parent.exists():C.newdir(path.parent)
            C.put(path,body)
            originals[str(rel)]=body
            mapping.append({'original':row['original'],'retained':S.desc(path,body)})
        C.put(out/'ORIGINAL-MAP.json',S.enc(mapping))
        complete=S.strict(originals['DISPATCH-RESULT.json'])
        intent=S.strict(originals['DISPATCH-INTENT.json'])
        operation=S.strict(originals['OPERATION.original.json'])
        wrapper=S.strict(originals['WRAPPER.original.json'])
        S.need(S.strict(originals['PHASE.original.json'])==packet
            and originals['REQUEST.original.json']==S.enc(request)
            and complete['state']=='ONE_ORIGINAL_PHONE_ACTOR_JOINED_WITH_COMPLETE_HOST_CAPTURE'
            and complete['case_sha256']==S.sha(self.p4_case_raw) and complete['phase']==phase
            and complete['nonce']==self.plan['nonce'] and complete['actor_starts']==1
            and intent['maximum_actor_starts']==1 and intent['automatic_retry'] is False
            and complete['request_sha256']==S.sha(S.enc(request))
            and operation=={'actor_rc':0,'wrapper_sha256':S.sha(originals['WRAPPER.original.json']),'wrapper':wrapper},
            'actual P4 original chain differs')
        self.last_actor_joined=True
        rows={name:S.desc(out/rel,originals[rel]) for name,rel in
            (('request','REQUEST.original.json'),('wrapper','WRAPPER.original.json'),('operation','OPERATION.original.json'))}
        self.phase_rows[phase]=rows
        self.recheck()
        phone=wrapper['phone']
        S.need(phone['rc']==0 and phone['stderr']=='','actual phone phase nonzero or stderr; no retry')
        self.last_completed=True
        return phone['stdout'].encode(),rows

    def host_entry(self,mode,plan):
        S,C=self.S,self.C
        path=self.out/'plans'/('component-'+mode+'.json')
        raw=S.enc(plan);C.put(path,raw)
        out=self.out/('host-'+mode)
        source=Path(self.plan['component_package']['path']).parent/'source/prepare_direct_return_component.py'
        argv=['/usr/bin/python3','-I','-B',str(source),'--mode',mode,'--plan',str(path),
            '--plan-sha256',S.sha(raw),'--package-manifest-sha256',self.plan['component_package']['sha256'],
            '--out',str(out),'--execute-host-once']
        self.owner.execute_process('host-'+mode,argv,self.remaining(60))
        return out

    def comp01(self,modules):
        S,C=self.S,self.C
        D=self.admitted['D']
        p={'schema':'hepta.fixed19.comp01.direct-return-plan.v1','case_id':'COMP-01',
            'release':self.plan['release'],'label':self.plan['label'],'nonce':self.plan['nonce'],
            'request':self.plan['request'],'baseline':None,'prepared':None,'actual_return':None}
        first=self.host_entry('baseline-request',p)
        baseline_request=S.strict(C.read(first/'BASELINE-REQUEST.json',65536))
        baseline_raw,baseline_rows=self.dispatch('baseline',baseline_request)
        baseline=D.validate_baseline(self.admitted['C'],modules['phone_observation_tools'],
            modules['phone_task_guards'],baseline_raw,self.plan['nonce'],self.admitted['pins'])
        C.put(self.out/'BASELINE-STDOUT.original.json',baseline_raw)
        p['baseline']=baseline_rows
        prepared_dir=self.host_entry('prepare-return',p)
        prepared_raw=C.read(prepared_dir/'PREPARED.json',65536)
        prepared=S.strict(prepared_raw)
        p['prepared']=S.desc(prepared_dir/'PREPARED.json',prepared_raw)
        live,_=self.dispatch('live-before',S.live_request(self.admitted))
        S.validate_live(S.strict(live),self.admitted)
        effect=self.originals.read(prepared['actual_request'],65536)
        result,returned=self.dispatch('return',S.strict(effect))
        C.put(self.out/'RETURN-STDOUT.original.json',result)
        p['actual_return']=returned
        self.host_entry('verify-return',p)
        post,_=self.dispatch('post-state',baseline_request)
        value=S.strict(post)
        observed=modules['phone_task_guards'].page_state(S.decode(value['page_b64'],16384).decode())
        modules['phone_observation_tools'].validate_viewport(S.decode(value['viewport_b64'],16384).decode())
        S.need(value['schema']==baseline['value']['schema'] and value['nonce']==self.plan['nonce']
            and value['boot_id']==baseline['value']['boot_id'] and value['stay_on']==baseline['value']['stay_on']
            and value['fingerprint_b64']==baseline['value']['fingerprint_b64']
            and value['viewport_b64']==baseline['value']['viewport_b64']
            and observed['component']==modules['phone_task_guards'].HEPTA_FULL_COMPONENT,
            'actual post-return state or settings restoration differs')
        C.put(self.out/'POST-STATE.original.json',post)
        after,_=self.dispatch('live-after',S.live_request(self.admitted))
        S.validate_live(S.strict(after),self.admitted)
        self.restored=True

    def neg03(self,modules):
        S,C=self.S,self.C
        live,_=self.dispatch('live-before',S.live_request(self.admitted))
        S.validate_live(S.strict(live),self.admitted)
        req,recipe=S.physical_request(modules,self.plan['nonce'],'portrait-baseline')
        raw,_=self.dispatch('portrait-baseline',req)
        baseline=S.parse_physical(modules,raw,self.plan['nonce'],'portrait-baseline')
        C.put(self.out/'PHYSICAL-BASELINE.original.json',raw)
        C.put(self.out/'PHYSICAL-BASELINE.png',baseline['png'])
        restore,restore_recipe=S.physical_request(modules,self.plan['nonce'],'restore-positive',baseline)
        C.put(self.out/'RESTORE-REQUEST.prepared.json',S.enc(restore))
        C.put(self.out/'RESTORE-RECIPE.json',S.enc(restore_recipe))
        req,recipe=S.physical_request(modules,self.plan['nonce'],'rotate-negative',baseline)
        C.put(self.out/'ROTATION-RECIPE.json',S.enc(recipe))
        self.rotation_attempted=True
        negative_error=None
        try:
            raw,_=self.dispatch('rotate-negative',req)
            C.put(self.out/'PHYSICAL-NEGATIVE.original.json',raw)
            negative=S.parse_physical(modules,raw,self.plan['nonce'],'rotate-negative')
            C.put(self.out/'PHYSICAL-NEGATIVE.png',negative['png'])
        except BaseException as error:
            negative_error=error
        if not self.last_completed or self.last_phase!='rotate-negative':
            raise RuntimeError('original rotation actor completion unknown; inspect joined original before the one restore') from negative_error
        raw,_=self.dispatch('restore-positive',restore)
        C.put(self.out/'PHYSICAL-RESTORED.original.json',raw)
        restored=S.parse_physical(modules,raw,self.plan['nonce'],'restore-positive')
        C.put(self.out/'PHYSICAL-RESTORED.png',restored['png'])
        S.need(all(restored['value'][key]==baseline['value'][key] for key in
            ('stay_on','accelerometer_rotation','user_rotation','fingerprint_b64'))
            and restored['observed']==baseline['observed'] and restored['viewport']==baseline['viewport'],
            'original run settings, foreground or viewport not restored')
        self.restored=True
        if negative_error is not None:
            raise negative_error
        after,_=self.dispatch('live-after',S.live_request(self.admitted))
        S.validate_live(S.strict(after),self.admitted)

    def finish(self,source_root):
        S,C=self.S,self.C
        self.recheck()
        cleanup=self.owner.close_owned_host_outputs()
        S.need(cleanup=={'stream_cleanup_errors':[],'host_children':[]},'host cleanup not closed')
        usage=resource.getrusage(resource.RUSAGE_SELF)
        value={'schema':'hepta.physical-component.execution-complete.v1',
            'state':'EXECUTION_ORIGINALS_COMPLETE_PENDING_INDEPENDENT_CLOSURE',
            'case_id':self.plan['case_id'],'label':self.plan['label'],'nonce':self.plan['nonce'],
            'root_plan_sha256':S.sha(self.plan_raw),'source_package':self.manifest_row,
            'release_pins':self.admitted['pins'],'phase_order':self.phase_order,'phase_originals':self.phase_rows,
            'restoration_observed':self.restored,'phone_actor_calls':len(self.phase_order),
            'native_submissions':0,'model_requests':0,'input_dispatches':0,'automatic_retry':False,
            'component_case_passed':False,'host_cleanup':cleanup,
            'metrics':{'latency':{'start_monotonic_ns':self.started,'end_monotonic_ns':time.monotonic_ns()},
                'usage':{'model_requests':0,'tokens':0,'phone_actor_calls':len(self.phase_order)},
                'cost':{'model_billed_usd':0,'basis':'no model request in this direct component'},
                'resources':{'user_cpu_seconds':usage.ru_utime-self.usage_before.ru_utime,
                    'system_cpu_seconds':usage.ru_stime-self.usage_before.ru_stime,
                    'process_maxrss':usage.ru_maxrss,'maxrss_unit':'bytes' if sys.platform=='darwin' else 'KiB'}}}
        C.put(self.out/'EXECUTION-COMPLETE.json',S.enc(value))
        argv=['/usr/bin/python3','-I','-B',str(source_root/'source/verify_physical_component.py'),
            '--case',str(self.out),'--plan-sha256',S.sha(self.plan_raw),
            '--source-manifest-sha256',self.manifest_row['sha256'],'--execute-host-closure']
        self.owner.execute_process('independent-closure',argv,self.remaining(60))
        final=C.read(self.out/'CLOSURE.json',1048576)
        v=S.strict(final)
        S.need(v['state']=='PHYSICAL_ORIGINALS_VERIFIED_PENDING_ROOT_VERIFIER_JOIN'
            and v['physical_originals_verified'] is True and v['component_case_passed'] is False,
            'independent component closure did not pass')
        cleanup=self.owner.close_owned_host_outputs()
        S.need(cleanup=={'stream_cleanup_errors':[],'host_children':[]}
            and self.owner.steps[-1]['phase']=='independent-closure'
            and self.owner.steps[-1]['state']=='ORIGINAL_HOST_CHILD_JOINED'
            and self.owner.steps[-1]['returncode']==0,'independent verifier has not joined with complete host cleanup')
        finished=time.monotonic_ns()
        S.need(finished/1e9<=self.deadline,'original total case deadline passed before final Root qualification')
        final_value={'schema':'hepta.physical-component.root-result.v1',
            'state':'ORIGINAL_PHYSICAL_COMPONENT_CLOSED','case_id':self.plan['case_id'],
            'nonce':self.plan['nonce'],'source_package':self.manifest_row,'root_plan_sha256':S.sha(self.plan_raw),
            'closure':S.desc(self.out/'CLOSURE.json',final),'component_case_passed':True,
            'independent_verifier_child':self.owner.steps[-1],
            'independent_verifier_capture':C.filedesc(self.out/'transport/independent-closure/OUTPUT-CAPTURE.json'),
            'host_cleanup':cleanup,'latency':{'start_monotonic_ns':self.started,'end_monotonic_ns':finished,
                'elapsed_seconds':(finished-self.started)/1e9,'original_maximum_seconds':300},
            'model_qualified':False,'native_task_qualified':False,'business_verified':False,'automatic_retry':False}
        C.put(self.out/'ROOT-RESULT.json',S.enc(final_value))
        return final_value


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan',type=Path)
    p.add_argument('--plan-sha256')
    p.add_argument('--source-manifest-sha256')
    p.add_argument('--execute-physical-case-once',action='store_true')
    p.add_argument('--validate-plan-only',action='store_true')
    a=p.parse_args()
    if a.execute_physical_case_once and a.validate_plan_only:
        raise ValueError('choose one explicit plan-validation or execution mode')
    if not a.execute_physical_case_once and not a.validate_plan_only:
        print(json.dumps({'state':'SOURCE_ONLY_NO_INPUTS_READ_NO_PHONE','cases':['COMP-01','NEG-03'],
            'phone_calls':0,'nonce_generated':False,'component_case_passed':False}))
        return 0
    root,S,originals,mf,files,C=bootstrap(a.source_manifest_sha256)
    plan_row,raw=originals.known(a.plan,262144)
    S.need(plan_row['sha256']==a.plan_sha256,'actual Root plan pin differs')
    plan=S.strict(raw)
    admitted=S.admit(plan,originals,root)
    S.need(plan['label'].startswith('comp01-' if plan['case_id']=='COMP-01' else 'neg03-'),
        'case-specific label required')
    if a.validate_plan_only:
        S.need(Path(plan['out'])==S.B/'physical-components-r10-r1'/plan['label']
            and not Path(plan['out']).exists() and not Path(plan['out']).is_symlink(),
            'future case output must be exact and unused')
        originals.recheck();admitted['C'].recheck_source_package(admitted['co'],admitted['package'])
        print(json.dumps({'state':'ACTUAL_HOST_PLAN_VALIDATED_NO_PHONE','case_id':plan['case_id'],
            'plan':plan_row,'source_package':mf,'release_pins':admitted['pins'],
            'phone_calls':0,'process_starts':0,'output_created':False,'component_case_passed':False},sort_keys=True))
        return 0
    os.umask(0o077)
    case=RootCase(S,C,plan,raw,mf,files,admitted,originals)
    try:
        case.stage()
        with S.actual_modules(admitted) as modules:
            if plan['case_id']=='COMP-01':case.comp01(modules)
            else:case.neg03(modules)
        result=case.finish(root)
        print(json.dumps({'state':result['state'],'case_id':plan['case_id'],'component_case_passed':True,
            'model_qualified':False,'native_task_qualified':False,'business_verified':False},sort_keys=True))
        return 0
    except BaseException as error:
        cleanup=case.owner.close_owned_host_outputs()
        C.put(case.out/'FAILED-OR-UNKNOWN.json',S.enc({'schema':'hepta.physical-component.root-failure.v1',
            'state':'ORIGINAL_CASE_RETAINED_NO_AUTOMATIC_REPLAY','error_type':type(error).__name__,
            'detail':str(error)[:1024],'phase_order':case.phase_order,'last_phase':case.last_phase,
            'last_phone_actor_joined':case.last_actor_joined,'last_phone_phase_succeeded':case.last_completed,
            'rotation_attempted':case.rotation_attempted,
            'restoration_observed':case.restored,'host_cleanup':cleanup,'automatic_retry':False,
            'new_identity_retry':False,'component_case_passed':False,
            'restore_requires_inspection':case.rotation_attempted and not case.restored}))
        raise


if __name__=='__main__':
    raise SystemExit(main())
