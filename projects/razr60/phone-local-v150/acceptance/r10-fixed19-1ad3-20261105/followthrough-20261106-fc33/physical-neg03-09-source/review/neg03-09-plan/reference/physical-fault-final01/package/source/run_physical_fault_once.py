#!/usr/bin/env python3
"""Root-only one-Send physical NEG04/05/07 coordinator; default is zero-I/O preview."""
import argparse,base64,hashlib,json,os,re,shlex,sys,time,types,zlib
from pathlib import Path
SSH=['/usr/bin/ssh','-J','ai395-usb4','-o','HostName=10.77.0.4','-p','22','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','pocket4-usb4-fast']
P4_BASE=Path('/home/alex/codex-physical-faults-r10-r1')
CAPTURE_SHA='f12a251542894d0e8c0dedc9d62eb96d4f39e2b1d563f849c2f60e6ee02580e3'

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
    rows=[r for r in value['files'] if r['path']=='source/physical_fault_common.py']
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
    S=types.ModuleType('physical_fault_common')
    S.__file__=str(p)
    exec(compile(body,str(p),'exec'),S.__dict__)
    originals=S.Originals()
    manifest_row=S.desc(path,raw)
    mf,files=S.load_members(originals,manifest_row)
    S.need(mf['schema']=='hepta.physical-fault.root-source-package.v1'
        and files['source/'+Path(__file__).name]==originals.known(Path(__file__).resolve(),131072)[1]
        and S.sha(files['source/owned_capture.py'])==CAPTURE_SHA,'reviewed complete physical source package required')
    capture=S.module(files['source/owned_capture.py'],root/'source/owned_capture.py','physical_owned_capture')
    return root,S,originals,manifest_row,files,capture


def stage_program():
    return "import sys,json,base64,hashlib,os,stat,re\nfrom pathlib import Path\nv=json.loads(sys.stdin.buffer.read(262145));r=Path(v['root']);parent=r.parent\nassert parent==Path('/home/alex/codex-physical-faults-r10-r1') and re.fullmatch('[0-9a-f]{32}',r.name)\nos.umask(0o077)\nif not parent.exists():parent.mkdir(mode=0o700)\nassert parent.resolve(strict=True)==parent and stat.S_IMODE(parent.stat().st_mode)==0o700\nr.mkdir(mode=0o700);(r/'source').mkdir(mode=0o700);(r/'phases').mkdir(mode=0o700)\ndef put(p,b):\n fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())\n fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)\nassert set(v['source'])=={'owned_capture.py','p4_fault_dispatch_once.py','capture_fault_p4.py'}\nfor name,row in v['source'].items():\n b=base64.b64decode(row['base64'],validate=True);assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']\n compile(b,str(r/'source'/name),'exec');put(r/'source'/name,b)\nbody=base64.b64decode(v['case'],validate=True);put(r/'CASE.original.json',body)\nprint(json.dumps({'state':'EXACT_SOURCE_AND_CASE_STAGED_NO_PHONE','case_sha256':hashlib.sha256(body).hexdigest(),'phone_calls':0}))\n"


def finish_async(C,owner,name,started):
    child,d,so,se=started
    try:
        rc=owner.join_host_capture(name,child)
    finally:
        errors=owner.stop_host_capture(name)
        errors+=owner.persist_host_capture(name)
        errors+=C.close_streams_owned([(name+':stdout',so),(name+':stderr',se)])
        owner._owned_host_streams.pop(name,None)
    C.need(not errors,'original_async_capture_finalization_failed')
    capture=owner._owned_host_captures[name]
    out=b''.join(capture['chunks']['stdout']);err=b''.join(capture['chunks']['stderr'])
    owner.verify_host_capture_outputs(name)
    result={'state':'ORIGINAL_HOST_CHILD_JOINED','phase':name,'pid':child.pid,'returncode':rc,
        'stdout':C.desc(d/'stdout.original',out),'stderr':C.desc(d/'stderr.original',err),'automatic_retry':False}
    C.put(d/'RESULT.json',C.enc(result));owner.steps.append(result)
    owner._owned_host_children.pop(name,None);owner._owned_host_deadlines.pop(name,None)
    owner._owned_host_captures.pop(name,None)
    C.need(rc==0 and err==b'','original_async_child_failed_no_retry')
    return out


class RootCase:
    def __init__(self,S,C,plan,plan_raw,manifest,files,admitted,originals):
        self.S,self.C,self.plan,self.plan_raw=S,C,plan,plan_raw
        self.manifest,self.files,self.admitted,self.originals=manifest,files,admitted,originals
        self.out=Path(plan['out']);self.remote=P4_BASE/plan['nonce']
        S.need(not self.out.exists() and not self.out.is_symlink(),'existing_original_attempt_must_not_restart')
        if not self.out.parent.exists():C.newdir(self.out.parent)
        C.newdir(self.out);C.newdir(self.out/'plans');C.newdir(self.out/'phone-originals')
        self.started=time.monotonic_ns();self.deadline=time.monotonic()+1200
        self.owner=C.OwnedCapture(self.out/'transport');self.pending={};self.phone_returns={}
        C.put(self.out/'ROOT-PLAN.original.json',plan_raw)
        C.put(self.out/'SOURCE-MANIFEST.original.json',originals.read(manifest))
        self.p4_case={'schema':'hepta.physical-fault.p4-case.v1','nonce':plan['nonce'],'case_id':plan['case_id'],
            'label':plan['label'],'root_plan_sha256':S.sha(plan_raw),'root_source_manifest':manifest,
            'automatic_retry':False,'phone_actor_starts_per_phase':1}
        self.p4_case_raw=S.enc(self.p4_case)
        C.put(self.out/'P4-CASE.original.json',self.p4_case_raw)
        C.put(self.out/'ROOT-INTENT.json',S.enc({'schema':'hepta.physical-fault.root-intent.v1',
            'case_id':plan['case_id'],'nonce':plan['nonce'],'root_plan_sha256':S.sha(plan_raw),
            'source_package':manifest,'maximum_Send':1,'maximum_signal_actor_invocations':1,
            'phone_watch_budget_seconds':240,'native_task_original_deadline_seconds':300,
            'post_task_host_collection_budget_seconds':1200,'automatic_retry':False,
            'unknown_is_not_permission_to_restore_or_repeat':True,'signals_sent_by_root':0}))

    def budget(self,seconds):
        self.S.need(time.monotonic()+seconds<=self.deadline,'insufficient_original_host_collection_budget')
        return seconds

    def recheck(self):self.originals.recheck()

    def stage(self):
        S,C=self.S,self.C
        selected={name:self.files['source/'+name] for name in
            ('owned_capture.py','p4_fault_dispatch_once.py','capture_fault_p4.py')}
        packet={'root':str(self.remote),'case':S.b64(self.p4_case_raw),
            'source':{name:{'bytes':len(raw),'sha256':S.sha(raw),'base64':S.b64(raw)} for name,raw in selected.items()}}
        raw=S.enc(packet);S.need(len(raw)<=262144,'bounded_P4_source_stage_packet')
        self.owner.execute_process('p4-stage',SSH+[shlex.join(['/usr/bin/python3','-I','-B','-c',stage_program()])],
            self.budget(45),input_raw=raw)

    def begin_phone(self,name,request,async_start=False):
        S,C=self.S,self.C
        self.recheck()
        packet={'schema':'hepta.physical-fault.p4-phase.v1','case_sha256':S.sha(self.p4_case_raw),
            'nonce':self.plan['nonce'],'case_id':self.plan['case_id'],'phase':name,'request':request}
        raw=S.enc(packet);S.need(len(raw)<=131072,'bounded_original_P4_phase_packet')
        C.put(self.out/'plans'/(name+'.json'),raw)
        argv=['/usr/bin/python3','-I','-B',str(self.remote/'source/p4_fault_dispatch_once.py'),
            '--case-root',str(self.remote),'--self-sha256',S.sha(self.files['source/p4_fault_dispatch_once.py']),
            '--execute-one-phone-actor']
        returned=self.owner.execute_process('phone-'+name,SSH+[shlex.join(argv)],
            self.budget(request['timeout_seconds']+55),input_raw=raw,async_start=async_start)
        if async_start:
            self.pending[name]=returned;return None
        return self.retain_phone(name,returned)

    def finish_phone(self,name):
        self.S.need(name in self.pending,'one_existing_async_phone_phase_required')
        raw=finish_async(self.C,self.owner,'phone-'+name,self.pending.pop(name))
        return self.retain_phone(name,raw)

    def retain_phone(self,name,raw):
        S,C=self.S,self.C
        # Use the same strict bounded decoder as the independent verifier;
        # qualification still happens in a separate owned verifier process.
        O=S.module(self.files['source/fault_originals.py'],'fault_originals.py','fault_originals')
        sys.modules['fault_originals']=O
        P=S.module(self.files['source/fault_projections.py'],'fault_projections.py','fault_projections')
        sys.modules['fault_projections']=P;sys.modules['physical_fault_common']=S
        V=S.module(self.files['source/verify_physical_fault.py'],'verify_physical_fault.py','fault_retention_decoder')
        remote=str(self.remote/'phases'/name)
        files=V.unpack_p4_export(raw,remote);out=self.out/'phone-originals'/name;C.newdir(out)
        mapping=[]
        for rel,body in files.items():
            path=out/S.relative(rel)
            for parent in reversed(path.parent.parents):
                if parent==out or out in parent.parents:
                    if not parent.exists():C.newdir(parent)
            if not path.parent.exists():C.newdir(path.parent)
            C.put(path,body)
            mapping.append({'original':S.desc(remote+'/'+rel,body),'retained':S.desc(path,body)})
        C.put(out/'ORIGINAL-MAP.json',S.enc(mapping))
        result=S.strict(files['DISPATCH-RESULT.json']);wrapper=S.strict(files['WRAPPER.original.json'])
        S.need(result['state']=='ONE_ORIGINAL_PHONE_ACTOR_JOINED_WITH_COMPLETE_HOST_CAPTURE' and
             result['phase']==name and result['nonce']==self.plan['nonce'] and result['phone_rc']==0,
             'original_phone_phase_failed_or_unknown_no_retry')
        phone=wrapper['phone'];S.need(phone['rc']==0 and phone['stderr']=='','original_phone_result_not_zero')
        self.phone_returns[name]=phone['stdout'].encode()
        return phone['stdout'].encode()

    def sender(self):
        S,C=self.S,self.C;p=self.plan;values=p['sender_inputs']
        args=['/usr/bin/python3','-I','-B',p['sender_source']['path'],p['label'],values['request']['path'],
            values['previous']['path'],'--preserved-draft',values['preserved_draft']['path'],
            '--retirement-resolution',values['retirement_resolution']['path'],'--evidence-root','production']
        preview=self.owner.execute_process('sender-preview',args,self.budget(30))
        value=S.strict(preview);S.need(value['state']=='BUILT_ONLY_NO_PHONE' and value['phone_calls']==value['send_attempts']==0,
                                     'unchanged_sender_preview_required')
        actor=S.B/(p['label']+'.preview.actor.py')
        body=C.read(actor,262144);S.need(S.sha(body)==value['actor_sha256'],'exact_preview_actor_pin')
        C.put(self.out/'SENDER-PREVIEW.original.json',preview)
        C.put(self.out/'SENDER-PREVIEW-ACTOR.original.py',body)
        self.pending['sender']=self.owner.execute_process('negative-sender',args+['--execute-once'],
            self.budget(660),async_start=True)

    def collect_phone(self,result):
        S,C=self.S,self.C;w=self.admitted['watch'];scope=result['scope'];run=result['run']
        ready=S.strict(S.decode(w['runtime_binding']['readiness']['raw_b64'],32768));role=ready['roles']['model']['identity']
        identity={'schema':'hepta.llama-server-identity.v1','boot_id':w['expected_boot'],
            **dict(zip(('pid','pgid','sid','start_ticks'),role))}
        # app_scope hashing is a pinned pure production function, not a new
        # task template or a replacement model decision.
        import ast
        post_tree=ast.parse(self.files['reference/task_postconditions.py'])
        post_node=next(n for n in post_tree.body if isinstance(n,ast.FunctionDef) and n.name=='app_scope_hash')
        post_ns={'hashlib':hashlib,'json':json}
        exec(compile(ast.Module(body=[post_node],type_ignores=[]),'<exact-app-scope-hash>','exec'),post_ns)
        plan={'schema':'hepta.physical-fault.phone-capture-plan.v1',
            'state':'ROOT_REVIEWED_EXISTING_NEGATIVE_ORIGINAL_CAPTURE','nonce':w['nonce'],'case_id':w['case_id'],
            'owner_request_sha256':w['owner_request_sha256'],'request_b64':w['owner_request_b64'],
            'combination_sha256':self.plan['combination_sha256'],'sender_scope':scope,
            'native_request_sha256':result['final_observation'].get('native_request_sha256'),
            'sender_run':run,'sender_label':w['sender_label'],'operator_label':w['operation_id'],
            'operator_plan_sha256':result['actor_plan_sha256'],'operator_package_sha256':w['fault_package_sha256'],
            'release_pins':w['release_pins'],'runtime_binding':w['runtime_binding'],
            'runtime':{'boot_id':w['expected_boot'],'server_identity':identity,
                       'binding_sha256':ready['actual_binding']['sha256']},
            'task_template_sha256':w['task_template_sha256'],'app_scope_sha256':post_ns['app_scope_hash'](w['app_scope']),
            'watch_plan_sha256':S.sha(self.admitted['watch_raw']),
            'watch_source_sha256':S.sha(self.files['source/watch_physical_fault_once.py'])}
        # Compute the native envelope digest through the frozen cancel_phase
        # pure function; no client or native admission is performed here.
        ns={};tree=__import__('ast').parse(self.admitted['operator_sources']['source/cancel_phase.py'])
        n=next(n for n in tree.body if isinstance(n,__import__('ast').FunctionDef) and n.name=='native_request_digest')
        ns.update(hashlib=hashlib,json=json,sha=S.sha)
        exec(compile(__import__('ast').Module(body=[n],type_ignores=[]),'<exact-native-request-digest>','exec'),ns)
        plan['native_request_sha256']=ns['native_request_digest'](scope,self.admitted['owner'])
        raw=S.enc(plan);C.put(self.out/'plans/PHONE-CAPTURE.json',raw)
        request=S.source_request(self.files['source/capture_fault_phone.py'],raw,'capture')
        response=S.strict(self.begin_phone('capture',request));S.need(response['export_complete'] is True and response['issues']==[],
            'complete_actual_phone_original_capture_required')
        archive=response['archive'];chunks=[]
        for index in range((archive['bytes']+524287)//524288):
            row=S.strict(self.begin_phone('archive-chunk-%03d'%index,S.archive_chunk_request(archive,index)))
            chunk=S.decode(row['base64'],524288)
            S.need(row['offset']==index*524288 and row['bytes']==len(chunk) and row['sha256']==S.sha(chunk),
                   'actual_original_archive_chunk_binding')
            chunks.append(chunk)
        body=b''.join(chunks);S.need(len(body)==archive['bytes'] and S.sha(body)==archive['sha256'],
                                   'full_actual_phone_archive_pin')
        C.put(self.out/'PHONE-ORIGINALS.tar.gz',body)
        return plan,S.desc(self.out/'plans/PHONE-CAPTURE.json',raw),S.desc(self.out/'PHONE-ORIGINALS.tar.gz',body)

    def collect_p4(self,scope):
        S,C=self.S,self.C
        inp=S.P4+'/fault-p4-capture-inputs-r1/'+self.plan['nonce']
        plan={'schema':'hepta.physical-fault.p4-sender-capture-plan.v1','case_id':self.plan['case_id'],
            'nonce':self.plan['nonce'],'sender_label':self.plan['label'],'owner_request_sha256':S.sha(self.admitted['owner']),
            'scope':scope,'out':S.P4+'/fault-p4-original-captures-r1/'+self.plan['nonce']}
        body=S.enc(plan);C.put(self.out/'plans/P4-CAPTURE.json',body)
        code=S.p4_plan_stage_program(inp,S.sha(body))
        self.owner.execute_process('p4-capture-plan',SSH+[shlex.join(['/usr/bin/python3','-I','-B','-c',code])],
            self.budget(30),input_raw=body)
        argv=['/usr/bin/python3','-I','-B',str(self.remote/'source/capture_fault_p4.py'),'--plan',inp+'/PLAN.json',
            '--plan-sha256',S.sha(body),'--self-sha256',S.sha(self.files['source/capture_fault_p4.py']),
            '--execute-read-once']
        output=self.owner.execute_process('p4-sender-capture',SSH+[shlex.join(argv)],self.budget(90))
        result=S.strict(output);archive=result['archive'];chunks=[]
        S.need(0<archive['bytes']<=64*1024*1024,'bounded_original_P4_archive')
        for index in range((archive['bytes']+524287)//524288):
            code=S.p4_archive_chunk_program(archive,index)
            out=self.owner.execute_process('p4-archive-chunk-%03d'%index,
                SSH+[shlex.join(['/usr/bin/python3','-I','-B','-c',code])],self.budget(30))
            row=S.strict(out);b=S.decode(row['base64'],524288);S.need(row['offset']==index*524288 and row['bytes']==len(b) and row['sha256']==S.sha(b),
                'P4_original_chunk_pin');chunks.append(b)
        raw=b''.join(chunks);S.need(len(raw)==archive['bytes'] and S.sha(raw)==archive['sha256'],'complete_original_P4_archive_pin')
        C.put(self.out/'P4-SENDER-ORIGINALS.tar.gz',raw)
        return S.desc(self.out/'P4-SENDER-ORIGINALS.tar.gz',raw),S.desc(self.out/'plans/P4-CAPTURE.json',body)

    def run(self,root):
        S,C=self.S,self.C
        self.stage()
        source=self.files['source/watch_physical_fault_once.py']
        stage_request,bundle_ref=S.operator_stage_request(self.admitted['operator_bundle'],self.plan['nonce'])
        stage_result=S.strict(self.begin_phone('operator-stage',stage_request))
        S.need(stage_result=={'state':'EXACT_STATIC_OPERATOR_BUNDLE_STAGED_NO_TASK','original':bundle_ref,
            'new_send':0,'new_signal':0},'exact_static_operator_bundle_stage')
        self.begin_phone('watch',S.source_request(source,self.admitted['watch_raw'],'watch',bundle_ref),True)
        self.begin_phone('armed-read',S.armed_request(self.admitted['watch'],source,self.admitted['watch_raw']))
        self.sender()
        watch=S.strict(self.finish_phone('watch'))
        sender_raw=finish_async(C,self.owner,'negative-sender',self.pending.pop('sender'))
        original=C.read(S.B/(self.plan['label']+'.send-result.json'),16*1024*1024)
        S.need(original==sender_raw,'actual_sender_stdout_and_retained_result_differ')
        outer=S.strict(sender_raw);S.need(outer.get('rc')==0 and outer.get('stderr')=='','actual_sender_unknown_no_replay')
        actual_actor=C.read(S.B/(self.plan['label']+'.actor.py'),262144)
        S.need(actual_actor==C.read(self.out/'SENDER-PREVIEW-ACTOR.original.py',262144),'executed_sender_actor_differs_from_preview')
        cp,cp_row,phone_archive=self.collect_phone(watch)
        p4_archive,p4_plan=self.collect_p4(watch['scope'])
        sys.modules['physical_fault_common']=S
        O=S.module(self.files['source/fault_originals.py'],'fault_originals.py','fault_originals');sys.modules['fault_originals']=O
        P=S.module(self.files['source/fault_projections.py'],'fault_projections.py','fault_projections');sys.modules['fault_projections']=P
        V=S.module(self.files['source/verify_physical_fault.py'],'verify_physical_fault.py','fault_phase_descriptors')
        phases={step['phase']:V.phase_rows(self.out,step['phase'],self.originals) for step in self.owner.steps}
        sender={key:self.originals.known(S.B/(self.plan['label']+suffix),16*1024*1024)[0] for key,suffix in
            (('generated_actor','.actor.py'),('send_result','.send-result.json'),('local_once','.local-once.json'))}
        execution={'schema':'hepta.physical-fault.execution-originals.v1','case_id':self.plan['case_id'],
            'nonce':self.plan['nonce'],'root_plan_sha256':S.sha(self.plan_raw),'source_package':self.manifest,
            'scope':watch['scope'],'provider_run':watch['run'],'native_request_sha256':cp['native_request_sha256'],
            'p4_case':self.p4_case,'phases':phases,'sender':sender,'phone_capture_plan':cp_row,
            'phone_archive':phone_archive,'p4_archive':p4_archive,'p4_capture_plan':p4_plan,
            'automatic_retry':False,'physical_case_pass':False}
        raw=S.enc(execution);C.put(self.out/'EXECUTION.original.json',raw)
        self.recheck()
        args=['/usr/bin/python3','-I','-B',str(root/'source/verify_fault_once.py'),
            '--source-manifest-sha256',self.manifest['sha256'],'--plan',str(self.out/'ROOT-PLAN.original.json'),
            '--plan-sha256',S.sha(self.plan_raw),'--execution',str(self.out/'EXECUTION.original.json'),
            '--execution-sha256',S.sha(raw),'--out',str(self.out/'closure'),'--execute-verify-once']
        self.owner.execute_process('independent-closure',args,self.budget(180))
        closure_raw=C.read(self.out/'closure/CLOSURE.json',16*1024*1024);closure=S.strict(closure_raw)
        S.need(closure['state']=='PHYSICAL_FAULT_ORIGINALS_VERIFIED_PENDING_ROOT_VERIFIER_JOIN' and
            closure['physical_originals_verified'] is True and closure['physical_case_pass'] is False,
            'actual_independent_originals_verifier_not_complete')
        cleanup=self.owner.close_owned_host_outputs()
        S.need(cleanup=={'stream_cleanup_errors':[],'host_children':[]} and
            self.owner.steps[-1]['phase']=='independent-closure' and self.owner.steps[-1]['returncode']==0,
            'actual_Root_verifier_child_and_outputs_not_joined')
        S.need(time.monotonic()<=self.deadline,'original_Root_collection_deadline_expired')
        result={'schema':'hepta.physical-fault.root-result.v1','state':'ACTUAL_PHYSICAL_FAULT_ORIGINALS_AND_VERIFIER_JOINED',
            'case_id':self.plan['case_id'],'nonce':self.plan['nonce'],'source_package':self.manifest,
            'root_plan_sha256':S.sha(self.plan_raw),'execution':S.desc(self.out/'EXECUTION.original.json',raw),
            'closure':S.desc(self.out/'closure/CLOSURE.json',closure_raw),'verifier_child':self.owner.steps[-1],
            'verifier_capture':C.filedesc(self.out/'transport/independent-closure/OUTPUT-CAPTURE.json'),
            'host_cleanup':cleanup,'started_monotonic_ns':self.started,'finished_monotonic_ns':time.monotonic_ns(),
            'maximum_host_collection_seconds':1200,'physical_case_pass':True,'host_isolated_not_inferred':True,
            'whole_case_pass':False,'business_verified':False,'automatic_retry':False,'new_identity_retry':False}
        C.put(self.out/'ROOT-RESULT.json',S.enc(result));return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-manifest-sha256');p.add_argument('--plan',type=Path);p.add_argument('--plan-sha256')
    p.add_argument('--execute-once',action='store_true');args=p.parse_args()
    if not args.execute_once:
        print(json.dumps({'state':'SOURCE_PREVIEW_NO_IO_NO_PHONE','cases':['NEG-04','NEG-05','NEG-07'],
                          'phone_calls':0,'send_attempts':0,'signals':0,'physical_case_pass':False},sort_keys=True));return 0
    root,S,originals,mf,files,C=bootstrap(args.source_manifest_sha256)
    S.final_dependencies()
    row,raw=originals.known(args.plan,65536);S.need(row['sha256']==args.plan_sha256,'explicit_exact_root_plan_pin')
    plan=S.strict(raw);admitted=S.admit(plan,originals,files)
    os.umask(0o077);case=RootCase(S,C,plan,raw,mf,files,admitted,originals)
    try:
        result=case.run(root);print(json.dumps({'state':result['state'],'case_id':result['case_id'],
            'physical_case_pass':True,'whole_case_pass':False,'business_verified':False,'automatic_retry':False},sort_keys=True))
        return 0
    except BaseException as error:
        cleanup=case.owner.close_owned_host_outputs()
        C.put(case.out/'FAILED-OR-UNKNOWN.json',S.enc({'state':'ORIGINAL_ATTEMPT_RETAINED_NO_RETRY',
            'case_id':plan['case_id'],'nonce':plan['nonce'],'error_type':type(error).__name__,'detail':str(error)[:2000],
            'steps':case.owner.steps,'host_cleanup':cleanup,'physical_case_pass':False,'automatic_retry':False,
            'remote_cleanup_inferred_from_local_capture':False,'remaining_async_phases':sorted(case.pending),
            'signals_sent_by_root':0,'one_original_attempt_must_be_reconciled_before_any_new_action':True}))
        raise


if __name__=='__main__':raise SystemExit(main())
