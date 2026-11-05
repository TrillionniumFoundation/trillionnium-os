#!/usr/bin/env python3
"""Host-only independent closure of raw component originals; never dispatch."""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import shlex
import stat
import sys
import time
import types
import zlib

sys.dont_write_bytecode=True
ACTOR_SHA='179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'
P4=Path('/home/alex/razr60-local-model-v150')
PHASE_FILES={'DISPATCH-INTENT.json','DISPATCH-RESULT.json','PHASE.original.json',
    'REQUEST.original.json','WRAPPER.original.json','OPERATION.original.json',
    'capture/phone-actor/INTENT.json','capture/phone-actor/CHILD.json',
    'capture/phone-actor/OUTPUT-CAPTURE.json','capture/phone-actor/RESULT.json',
    'capture/phone-actor/stdout.original','capture/phone-actor/stderr.original'}


def bootstrap(manifest_sha):
    """Do not execute even the sibling loader before its explicit package pin."""
    root=Path(__file__).resolve().parent.parent
    path=root/'SOURCE-MANIFEST.json'
    def read(p,limit):
        if p.resolve(strict=True)!=p:
            raise ValueError('canonical verifier source required')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=limit:
                raise ValueError('bounded verifier source required')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw=stream.read(before.st_size+1)
            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            if len(raw)!=before.st_size or any(getattr(before,k)!=getattr(os.fstat(fd),k)
                    or getattr(before,k)!=getattr(p.lstat(),k) for k in fields):
                raise ValueError('verifier source changed')
            return raw
        finally:
            os.close(fd)
    def strict(raw):
        def pairs(rows):
            value={}
            for k,v in rows:
                if k in value:raise ValueError('duplicate manifest key')
                value[k]=v
            return value
        return json.loads(raw,object_pairs_hook=pairs)
    raw=read(path,262144)
    if hashlib.sha256(raw).hexdigest()!=manifest_sha:
        raise ValueError('explicit verifier source manifest pin differs')
    mf=strict(raw)
    rows=[r for r in mf['files'] if r['path']=='source/run_physical_component_once.py']
    if len(rows)!=1:
        raise ValueError('one explicitly pinned root loader required')
    row=rows[0];p=root/row['path'];body=read(p,131072)
    if len(body)!=row['bytes'] or hashlib.sha256(body).hexdigest()!=row['sha256']:
        raise ValueError('root loader source differs')
    R=types.ModuleType('physical_component_pinned_root_loader');R.__file__=str(p)
    exec(compile(body,str(p),'exec'),R.__dict__)
    result=R.bootstrap(manifest_sha)
    if result[4]['source/verify_physical_component.py']!=read(Path(__file__).resolve(),131072):
        raise ValueError('actual independent verifier differs')
    return R,result


def known_json(S,O,path,limit=1048576):
    row,raw=O.known(path,limit)
    return S.strict(raw),raw,row


def capture(S,O,directory,phase,argv,input_raw,maximum,origin=None):
    """Verify held-child, bounded double-EOF, and the original inode binding.

    P4 originals are exact retained copies; their original inode metadata is
    checked internally against the pinned CHILD and capture records. Local
    original logs additionally retain the observed current inode metadata.
    """
    directory=Path(directory);origin=directory if origin is None else Path(origin)
    expected={'INTENT.json','CHILD.json','OUTPUT-CAPTURE.json','RESULT.json',
        'stdout.original','stderr.original'}
    if input_raw is not None:expected.add('stdin.original')
    S.need({p.name for p in directory.iterdir()}==expected,'capture inventory contains missing or uncertain artifacts')
    intent,iraw,_=known_json(S,O,directory/'INTENT.json',65536)
    child,_,_=known_json(S,O,directory/'CHILD.json',65536)
    receipt,_,_=known_json(S,O,directory/'OUTPUT-CAPTURE.json',65536)
    result,_,_=known_json(S,O,directory/'RESULT.json',65536)
    S.need(intent['schema']=='hepta.native-guard.root-host-command.v1' and intent['phase']==phase
        and intent['argv']==argv and intent['maximum_starts']==1 and intent['automatic_retry'] is False
        and intent['signals_on_timeout'] is False and type(intent['maximum_wait_seconds']) in (int,float)
        and 0<intent['maximum_wait_seconds']<=maximum
        and intent['deadline_scope']=='popen_start_through_child_join_pipe_eof_and_output_verification'
        and intent['input_transport']=='retained_readonly_regular_fd_child_reads_within_execution_budget'
        and intent['output_transport']=='owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence'
        and intent['output_limit_bytes_per_stream']==64*1024*1024
        and intent['hard_bound_on_filesystem_spawn_or_cleanup'] is False,
        'reviewed single-start bounded capture intent differs')
    S.need(intent['stdin_sha256']==(None if input_raw is None else S.sha(input_raw)),
        'capture original input differs')
    if input_raw is not None:
        S.need(O.known(directory/'stdin.original',262144)[1]==input_raw,'retained input differs')
    S.need(set(result)=={'state','phase','pid','returncode','stdout','stderr','automatic_retry'}
        and result['state']=='ORIGINAL_HOST_CHILD_JOINED' and result['phase']==phase
        and type(result['pid']) is int and result['pid']>0 and type(result['returncode']) is int
        and result['returncode']==0 and result['automatic_retry'] is False,
        'actual original child must have joined successfully')
    S.need(child['pid']==result['pid'] and child['maximum_starts']==1
        and child['source_intent_sha256']==S.sha(iraw)
        and child['deadline_validity']=='this_running_coordinator_only',
        'held child identity does not bind its original intent')
    missing=child['identity_missing_only_if_actual_child_already_joined']
    S.need(type(missing) is bool and ((missing and child['pgid'] is None and child['sid'] is None)
        or (not missing and child['pgid']==child['pid']==child['sid'])),
        'original new-session child identity differs')
    S.need(receipt['schema']=='hepta.native-guard.host-output-capture.v1'
        and receipt['phase']==phase and receipt['pid']==result['pid']
        and receipt['source_intent_sha256']==S.sha(iraw)
        and receipt['output_limit_bytes_per_stream']==64*1024*1024
        and receipt['worker_started'] is True and receipt['worker_joined'] is True
        and receipt['pipe_reader_owner']=='closed_by_worker'
        and receipt['child_wait_returned'] is True and receipt['child_returncode']==0
        and receipt['stdout_eof'] is True and receipt['stderr_eof'] is True
        and receipt['prefix_only_or_unknown'] is False and receipt['error'] is None
        and receipt['persist_errors']==[] and receipt['pipe_close_errors']==[]
        and receipt['automatic_retry'] is False and receipt['signals_sent']==0
        and receipt['remote_terminal_or_cleanup_proven'] is False,
        'complete joined double-EOF capture required; it does not itself prove remote terminal')
    deadline=child['execution_deadline_monotonic']
    S.need(type(deadline) in (int,float) and math.isfinite(deadline)
        and receipt['execution_deadline_monotonic']==deadline
        and receipt['deadline_validity']=='this_running_coordinator_only','capture deadline differs')
    start=deadline-intent['maximum_wait_seconds']
    observed=[receipt['child_join_observed_monotonic']]+list(receipt['eof_observed_monotonic'].values())
    S.need(set(receipt['eof_observed_monotonic'])=={'stdout','stderr'}
        and all(type(t) in (int,float) and math.isfinite(t) and start<=t<=deadline for t in observed),
        'child join and both EOFs must be inside the original execution budget')
    bodies={}
    for name in ('stdout','stderr'):
        row,raw=O.known(directory/(name+'.original'),64*1024*1024)
        expected_row=S.desc(origin/(name+'.original'),raw)
        proof=receipt['files'][name];before=child['original_output_identities'][name]
        S.need(result[name]==expected_row
            and receipt['captured'][name]=={'bytes':len(raw),'sha256':S.sha(raw)}
            and {k:proof[k] for k in ('path','bytes','sha256')}==expected_row
            and proof['original_created_inode_bound'] is True,
            'captured pipe digest must bind the actual original output file')
        metadata=proof['metadata']
        S.need(set(before)==set(metadata)==set(S.META) and before['st_size']==0
            and metadata['st_size']==len(raw) and metadata['st_nlink']==1
            and stat.S_ISREG(metadata['st_mode']) and stat.S_IMODE(metadata['st_mode'])==0o600
            and all(before[k]==metadata[k] for k in
                ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')),
            'capture output path/inode was replaced or not privately created')
        if origin==directory:
            S.need(metadata=={k:getattr((directory/(name+'.original')).lstat(),k) for k in S.META},
                'local original log metadata changed since its held-fd verification')
        bodies[name]=raw
    S.need(bodies['stderr']==b'','successful original host command has unexpected stderr')
    return {'intent':intent,'child':child,'result':result,'capture':receipt,
        'stdout':bodies['stdout'],'started':start,'completed':max(observed)}


def export_payload(S,raw,allow_failure=False):
    value=S.strict(raw)
    S.need(set(value)=={'schema','plain_bytes','plain_sha256','gzip_bytes','gzip_sha256','gzip_base64'}
        and value['schema']=='hepta.physical-component.p4-original-export.v1'
        and type(value['plain_bytes']) is int and 0<value['plain_bytes']<=64*1024*1024,
        'bounded exact original export required')
    packed=S.decode(value['gzip_base64'],16*1024*1024)
    S.need(len(packed)==value['gzip_bytes'] and S.sha(packed)==value['gzip_sha256'],'packed original export differs')
    decoder=zlib.decompressobj(31);plain=decoder.decompress(packed,64*1024*1024+1)
    S.need(len(plain)==value['plain_bytes'] and S.sha(plain)==value['plain_sha256']
        and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
        'original export expanded outside its exact bound')
    value=S.strict(plain)
    S.need(set(value)=={'schema','root','files'} and value['schema']=='hepta.physical-component.p4-originals.v1'
        and type(value['files']) is list and len(value['files']) in
            ((len(PHASE_FILES),len(PHASE_FILES)+1) if allow_failure else (len(PHASE_FILES),)),
        'complete exact P4 phase inventory required')
    return value


def phone_phase(R,S,O,case,plan,files,p4case_raw,phase,request):
    remote=R.P4_BASE/plan['nonce'];remote_phase=remote/'phases'/phase
    packet={'schema':'hepta.physical-component.p4-phase.v1','case_sha256':S.sha(p4case_raw),
        'nonce':plan['nonce'],'case_id':plan['case_id'],'phase':phase,'request':request}
    packet_raw=S.enc(packet)
    S.need(O.known(case/'plans'/(phase+'.json'),131072)[1]==packet_raw,'Root phase plan differs from exact recipe')
    argv=['/usr/bin/python3','-I','-B',str(remote/'source/p4_component_dispatch_once.py'),
        '--case-root',str(remote),'--self-sha256',S.sha(files['source/p4_component_dispatch_once.py']),
        '--execute-one-phone-actor']
    host=capture(S,O,case/'transport'/('phone-'+phase),'phone-'+phase,
        R.SSH+[shlex.join(argv)],packet_raw,request['timeout_seconds']+55)
    payload=export_payload(S,host['stdout'])
    result=verify_phase_originals(R,S,O,case/'phone-originals'/phase,plan,p4case_raw,phase,request,payload)
    result['host']=host
    return result


def verify_phase_originals(R,S,O,out,plan,p4case_raw,phase,request,payload,allow_failure=False):
    remote=R.P4_BASE/plan['nonce'];remote_phase=remote/'phases'/phase
    packet={'schema':'hepta.physical-component.p4-phase.v1','case_sha256':S.sha(p4case_raw),
        'nonce':plan['nonce'],'case_id':plan['case_id'],'phase':phase,'request':request}
    packet_raw=S.enc(packet)
    S.need(payload['root']==str(remote_phase),'original export names another case phase')
    wanted=set(PHASE_FILES)
    if allow_failure and any(row.get('relative')=='FAILED-OR-UNKNOWN.json' for row in payload['files']):
        wanted.add('FAILED-OR-UNKNOWN.json')
    actual_files={str(p.relative_to(out)) for p in out.rglob('*') if p.is_file() or p.is_symlink()}
    S.need(actual_files==wanted|{'ORIGINAL-MAP.json'},'retained original phase inventory differs')
    bodies={};mapping=[]
    for row in payload['files']:
        S.need(type(row) is dict and set(row)=={'relative','original','base64'},'exact exported original required')
        name=str(S.relative(row['relative']))
        S.need(name in wanted and name not in bodies,'extra or duplicate exported original')
        body=S.decode(row['base64'],64*1024*1024)
        S.need(row['original']==S.desc(remote_phase/name,body),'P4 original path/bytes differ')
        retained,local=O.known(out/name,64*1024*1024)
        S.need(local==body,'retained original differs from actual complete SSH stdout')
        mapping.append({'original':row['original'],'retained':retained});bodies[name]=body
    S.need(set(bodies)==wanted and known_json(S,O,out/'ORIGINAL-MAP.json')[0]==mapping,
        'exact original-to-retained map differs')
    request_raw=S.enc(request);label='pc-'+plan['nonce']+'-'+phase
    actor=P4/'ops/phone_once.py';request_path=P4/'requests'/(label+'.json')
    actor_argv=['/usr/bin/python3','-I','-B',str(actor),label,str(request_path)]
    local=capture(S,O,out/'capture/phone-actor','phone-actor',actor_argv,None,
        request['timeout_seconds']+20,remote_phase/'capture/phone-actor')
    intent=S.strict(bodies['DISPATCH-INTENT.json']);result=S.strict(bodies['DISPATCH-RESULT.json'])
    S.need(bodies['PHASE.original.json']==packet_raw and bodies['REQUEST.original.json']==request_raw
        and intent['schema']=='hepta.physical-component.p4-dispatch-intent.v1'
        and intent['phase']==phase and intent['case_sha256']==S.sha(p4case_raw)
        and intent['nonce']==plan['nonce'] and intent['case_id']==plan['case_id'] and intent['label']==label
        and intent['request']==S.desc(request_path,request_raw) and intent['argv']==actor_argv
        and intent['actor_source']['path']==str(actor) and intent['actor_source']['sha256']==ACTOR_SHA
        and 0<intent['actor_source']['bytes']<=65536 and intent['maximum_actor_starts']==1
        and intent['automatic_retry'] is False and intent['signals_sent']==0,'P4 one-actor intent differs')
    wrapper=S.strict(bodies['WRAPPER.original.json']);operation=S.strict(bodies['OPERATION.original.json'])
    S.need(operation=={'actor_rc':0,'wrapper_sha256':S.sha(bodies['WRAPPER.original.json']),'wrapper':wrapper},
        'original actor result wrapper chain differs')
    phone=wrapper['phone']
    S.need(type(phone['rc']) is int and phone['rc']==0 and isinstance(phone['stdout'],str)
        and phone['stderr']=='','actual phone phase is not a complete success')
    S.need(result['schema']=='hepta.physical-component.p4-dispatch-result.v1'
        and result['state']=='ONE_ORIGINAL_PHONE_ACTOR_JOINED_WITH_COMPLETE_HOST_CAPTURE'
        and result['phase']==phase and result['nonce']==plan['nonce'] and result['case_id']==plan['case_id']
        and result['label']==label and result['case_sha256']==S.sha(p4case_raw)
        and result['request_sha256']==S.sha(request_raw) and result['actor_child']==local['result']
        and result['wrapper_original']==S.desc(P4/'operations'/label/'result.json',bodies['WRAPPER.original.json'])
        and result['phone_rc']==0 and result['actor_starts']==1 and result['automatic_retry'] is False
        and result['signals_sent']==0 and result['phone_effect_qualified'] is False,
        'P4 dispatch closure does not prove the exact one actor')
    for stream in ('stdout','stderr'):
        body=phone[stream].encode()
        S.need(result['phone_'+stream+'_bytes']==len(body)
            and result['phone_'+stream+'_sha256']==S.sha(body),'phone raw stream binding differs')
    start,end=intent['started_monotonic_ns'],result['finished_monotonic_ns']
    S.need(type(start) is int and type(end) is int and 0<start<=end
        and start/1e9<=local['started']<=local['completed']<=end/1e9,
        'P4 actor lifetime is not within its dispatch observation')
    rows={name:S.desc(out/rel,bodies[rel]) for name,rel in
        (('request','REQUEST.original.json'),('wrapper','WRAPPER.original.json'),('operation','OPERATION.original.json'))}
    return {'stdout':phone['stdout'].encode(),'rows':rows,'p4_started':start,'p4_finished':end}


def host_entry(R,S,O,case,plan,mode,expected_plan):
    path=case/'plans'/('component-'+mode+'.json');raw=S.enc(expected_plan)
    S.need(O.known(path,262144)[1]==raw,'direct host plan differs')
    source=Path(plan['component_package']['path']).parent/'source/prepare_direct_return_component.py'
    out=case/('host-'+mode)
    argv=['/usr/bin/python3','-I','-B',str(source),'--mode',mode,'--plan',str(path),
        '--plan-sha256',S.sha(raw),'--package-manifest-sha256',plan['component_package']['sha256'],
        '--out',str(out),'--execute-host-once']
    original=capture(S,O,case/'transport'/('host-'+mode),'host-'+mode,argv,None,60)
    reply=S.strict(original['stdout']);value,body,row=known_json(S,O,out/'RESULT.json',16*1024*1024)
    S.need(reply['result']==row and reply['component_case_passed'] is False and reply['phone_calls']==0
        and value['schema']=='hepta.fixed19.comp01.host-entry-result.v1' and value['case_id']=='COMP-01'
        and value['mode']==mode and value['source_package']==plan['component_package']
        and value['phone_calls_by_this_entry']==0 and value['component_case_passed'] is False
        and value['native_task_qualified'] is False and value['model_qualified'] is False
        and value['business_verified'] is False and value['automatic_retry'] is False
        and value['isolation']['network_or_process_attempts']==0 and value['isolation']['writes_outside_output']==0,
        'original host entry changed its scope or actual result binding')
    S.need(O.known(out/'PLAN.original.json',262144)[1]==raw,'host entry retained another plan')
    return value,original


def close_case(R,S,O,C,root,case,plan,plan_raw,mf,files,admitted,final_audit=False):
    S.need(case==S.B/'physical-components-r10-r1'/plan['label'] and case.resolve(strict=True)==case
        and plan['out']==str(case),'exact existing original case namespace required')
    S.need(not (case/'FAILED-OR-UNKNOWN.json').exists() and not (case/'recovery').exists()
        and ((case/'CLOSURE.json').exists() if final_audit else not (case/'CLOSURE.json').exists()),
        'uncertain, recovered or incorrectly closed case cannot receive fresh PASS')
    audit=admitted['C'].audit_no_effects(case)
    done,done_raw,done_row=known_json(S,O,case/'EXECUTION-COMPLETE.json',1048576)
    S.need(done['schema']=='hepta.physical-component.execution-complete.v1'
        and done['state']=='EXECUTION_ORIGINALS_COMPLETE_PENDING_INDEPENDENT_CLOSURE'
        and done['case_id']==plan['case_id'] and done['label']==plan['label'] and done['nonce']==plan['nonce']
        and done['root_plan_sha256']==S.sha(plan_raw) and done['source_package']==mf
        and done['release_pins']==admitted['pins'] and done['restoration_observed'] is True
        and done['phone_actor_calls']==5 and done['native_submissions']==done['model_requests']==done['input_dispatches']==0
        and done['automatic_retry'] is False and done['component_case_passed'] is False
        and done['host_cleanup']=={'stream_cleanup_errors':[],'host_children':[]},
        'original execution remains incomplete or changed scope')
    intent,_,_=known_json(S,O,case/'ROOT-INTENT.json',65536)
    S.need(intent['schema']=='hepta.physical-component.root-intent.v1' and intent['case_id']==plan['case_id']
        and intent['label']==plan['label'] and intent['nonce']==plan['nonce'] and intent['request']==plan['request']
        and intent['source_package']==mf and intent['maximum_phone_actor_starts']==5
        and intent['maximum_return_dispatches']==(1 if plan['case_id']=='COMP-01' else 0)
        and intent['maximum_rotation_setting_phases']==(2 if plan['case_id']=='NEG-03' else 0)
        and intent['maximum_elapsed_seconds']==300 and intent['automatic_retry'] is False
        and intent['new_identity_retry'] is False and intent['native_task_scope_created'] is False
        and intent['model_requests']==intent['signals_sent_by_root']==0,'original case intent differs')
    latency=done['metrics']['latency'];start,end=latency['start_monotonic_ns'],latency['end_monotonic_ns']
    S.need(type(start) is int and type(end) is int and 0<start<=end and (end-start)/1e9<=300,
        'case execution exceeded its original total budget')
    S.need(O.known(case/'SOURCE-MANIFEST.original.json',262144)[1]==O.read(mf,262144),
        'original source manifest differs')
    p4case={'schema':'hepta.physical-component.p4-case.v1','nonce':plan['nonce'],
        'case_id':plan['case_id'],'label':plan['label'],'root_plan_sha256':S.sha(plan_raw),
        'root_source_manifest':mf,'automatic_retry':False,'phone_actor_starts_per_phase':1}
    p4raw=S.enc(p4case)
    S.need(O.known(case/'P4-CASE.original.json',262144)[1]==p4raw,'original P4 case differs')
    remote=R.P4_BASE/plan['nonce']
    values={name:{'bytes':len(files['source/'+name]),'sha256':S.sha(files['source/'+name]),
        'base64':S.b64(files['source/'+name])} for name in ('owned_capture.py','p4_component_dispatch_once.py')}
    stage_packet=S.enc({'root':str(remote),'case':S.b64(p4raw),'source':values})
    staged=capture(S,O,case/'transport/p4-stage','p4-stage',R.SSH+[shlex.join(
        ['/usr/bin/python3','-I','-B','-c',R.stage_program()])],stage_packet,30)
    S.need(S.strict(staged['stdout'])=={'state':'EXACT_SOURCE_AND_CASE_STAGED_NO_PHONE',
        'case_sha256':S.sha(p4raw),'phone_calls':0},'original staging result differs')
    ordered=[staged];phase_rows={};p4times=[];proof={};restoration={}
    def phone(phase,request):
        result=phone_phase(R,S,O,case,plan,files,p4raw,phase,request)
        ordered.append(result['host']);phase_rows[phase]=result['rows']
        p4times.append((result['p4_started'],result['p4_finished']))
        return result['stdout'],result['rows']
    with S.actual_modules(admitted) as modules:
        if plan['case_id']=='COMP-01':
            D=admitted['D'];obs=modules['phone_observation_tools'];guards=modules['phone_task_guards']
            direct={'schema':'hepta.fixed19.comp01.direct-return-plan.v1','case_id':'COMP-01',
                'release':plan['release'],'label':plan['label'],'nonce':plan['nonce'],'request':plan['request'],
                'baseline':None,'prepared':None,'actual_return':None}
            _,host=host_entry(R,S,O,case,plan,'baseline-request',direct);ordered.append(host)
            baseline_request=D.baseline_request(obs,guards,plan['nonce'])
            S.need(known_json(S,O,case/'host-baseline-request/BASELINE-REQUEST.json',65536)[0]==baseline_request,
                'original prepared baseline request differs')
            raw,rows=phone('baseline',baseline_request)
            baseline=D.validate_baseline(admitted['C'],obs,guards,raw,plan['nonce'],admitted['pins'])
            S.need(O.known(case/'BASELINE-STDOUT.original.json',65536)[1]==raw,'baseline stdout differs')
            direct['baseline']=rows
            _,host=host_entry(R,S,O,case,plan,'prepare-return',direct);ordered.append(host)
            prepared,prepared_raw,prepared_row=known_json(S,O,case/'host-prepare-return/PREPARED.json',65536)
            direct['prepared']=prepared_row
            identity={'schema':'hepta.operator-direct-component-identity.v1','case_id':'COMP-01',
                'label':plan['label'],'nonce':plan['nonce'],'request_sha256':plan['request']['sha256']}
            call_id='comp01-return-'+plan['nonce']
            token=S.sha(json.dumps([identity,call_id],sort_keys=True,separators=(',',':')).encode())[:32]
            serial_guard='[ "$(getprop ro.serialno)" = '+shlex.quote(obs.SERIAL)+' ] || exit 64; '
            mapped_shell=guards.return_command(serial_guard,token)
            expected,prefix=D.effect_request(guards,baseline,mapped_shell)
            semantic=S.strict(O.read(prepared['semantic_original'],65536))
            wire={'call_id':call_id,'tool':'adb.exec','argv':['-s',obs.SERIAL,'shell',mapped_shell]}
            S.need(prepared['schema']=='hepta.fixed19.comp01.prepared-return.v1'
                and prepared['identity']==identity and prepared['capture_id']==token and prepared['call_id']==call_id
                and prepared['source_package']==plan['component_package'] and prepared['release_pins']==admitted['pins']
                and prepared['baseline']==rows and prepared['production_mapping_calls']==1 and prepared['phone_dispatches']==0
                and prepared['component_case_passed'] is False and prepared['automatic_retry'] is False
                and semantic['capture_id']==token and semantic['turn']==identity and semantic['call_id']==call_id
                and semantic['semantic_tool']=='phone.return_hepta' and semantic['wire_tool']=='adb.exec'
                and semantic['wire_call']==wire and S.strict(O.read(prepared['mapped_wire'],65536))==wire
                and S.strict(O.read(prepared['actual_request'],65536))==expected
                and prepared['pre_effect_read_only_prefix']=={'bytes':len(prefix.encode()),'sha256':S.sha(prefix.encode())}
                and mapped_shell.count('am start -W -n ')==1 and 'input -d ' not in mapped_shell,
                'exact one-production-mapping preparation or identity differs')
            raw,_=phone('live-before',S.live_request(admitted));S.validate_live(S.strict(raw),admitted)
            raw,rows=phone('return',expected);direct['actual_return']=rows
            value=S.strict(raw);observed,viewport=guards.verify_return(value,token);obs.validate_viewport(viewport)
            S.need(O.known(case/'RETURN-STDOUT.original.json',65536)[1]==raw,'actual return stdout differs')
            report,host=host_entry(R,S,O,case,plan,'verify-return',direct);ordered.append(host)
            S.need(report['state']=='ORIGINAL_TYPED_RETURN_VERIFIED_PENDING_ROOT_TRANSPORT_AND_RESTORATION_AUDIT'
                and report['original_return_and_viewport_parsers_passed'] is True and report['observed']==observed
                and report['operation_id']==token and report['launch_exit_code']==0,'original typed return verification differs')
            raw,_=phone('post-state',baseline_request);post=S.strict(raw)
            post_page=guards.page_state(S.decode(post['page_b64'],16384).decode())
            obs.validate_viewport(S.decode(post['viewport_b64'],16384).decode())
            S.need(set(post)==set(baseline['value']) and all(post[k]==baseline['value'][k] for k in
                ('schema','nonce','boot_id','stay_on','fingerprint_b64','viewport_b64'))
                and post_page['component']==guards.HEPTA_FULL_COMPONENT
                and O.known(case/'POST-STATE.original.json',65536)[1]==raw,
                'actual post-return focus or unchanged setting/display baseline differs')
            raw,_=phone('live-after',S.live_request(admitted));S.validate_live(S.strict(raw),admitted)
            proof={'launch_attempts':1,'launch_exit_code':0,'actual_focused_component':post_page['component'],
                'original_return_parser':True,'original_viewport_parser':True,'native_task_identity_fabricated':False}
            restoration={'kind':'intended_HEPTA_focus_and_unchanged_original_settings',
                'settings_written':0,'stay_on_unchanged':True,'viewport_unchanged':True,
                'boot_fingerprint_unchanged':True,'current_runtime_idle_after':True,
                'foreground_baseline_restored':False,'intended_return_focus_observed':True}
        else:
            raw,_=phone('live-before',S.live_request(admitted));S.validate_live(S.strict(raw),admitted)
            expected,_=S.physical_request(modules,plan['nonce'],'portrait-baseline')
            raw,_=phone('portrait-baseline',expected);baseline=S.parse_physical(modules,raw,plan['nonce'],'portrait-baseline')
            S.need(O.known(case/'PHYSICAL-BASELINE.original.json',32*1024*1024)[1]==raw
                and O.known(case/'PHYSICAL-BASELINE.png',S.MAX_PNG)[1]==baseline['png'],'baseline physical originals differ')
            negative_req,negative_recipe=S.physical_request(modules,plan['nonce'],'rotate-negative',baseline)
            restore_req,restore_recipe=S.physical_request(modules,plan['nonce'],'restore-positive',baseline)
            S.need(known_json(S,O,case/'RESTORE-REQUEST.prepared.json',65536)[0]==restore_req
                and known_json(S,O,case/'RESTORE-RECIPE.json',65536)[0]==restore_recipe
                and known_json(S,O,case/'ROTATION-RECIPE.json',65536)[0]==negative_recipe,
                'original baseline inverse or qualification recipe differs')
            raw,_=phone('rotate-negative',negative_req);negative=S.parse_physical(modules,raw,plan['nonce'],'rotate-negative')
            S.need(O.known(case/'PHYSICAL-NEGATIVE.original.json',32*1024*1024)[1]==raw
                and O.known(case/'PHYSICAL-NEGATIVE.png',S.MAX_PNG)[1]==negative['png'],'negative physical originals differ')
            raw,_=phone('restore-positive',restore_req);restored=S.parse_physical(modules,raw,plan['nonce'],'restore-positive')
            S.need(O.known(case/'PHYSICAL-RESTORED.original.json',32*1024*1024)[1]==raw
                and O.known(case/'PHYSICAL-RESTORED.png',S.MAX_PNG)[1]==restored['png']
                and all(restored['value'][k]==baseline['value'][k] for k in
                    ('stay_on','accelerometer_rotation','user_rotation','fingerprint_b64'))
                and restored['observed']==baseline['observed'] and restored['viewport']==baseline['viewport'],
                'actual original settings, focus and viewport restoration differ')
            raw,_=phone('live-after',S.live_request(admitted));S.validate_live(S.strict(raw),admitted)
            proof={'physical_rotation_observed':1,'external_display_physical_tested':False,
                'qualification_guard_sha256':negative_recipe['guard_sha256'],
                'qualification_guard_exit_code':negative['value']['guard_rc'],'after_guard_marker_reached':False,
                'input_commands':0,'production_parser_rejection':negative['production_rejection'],
                'fresh_actual_pngs':{k:v['png_info'] for k,v in
                    (('baseline',baseline),('negative',negative),('restored',restored))},
                'host_six_axis_fixture':plan['fixture_result'],'fixture_is_separate_from_actual_phone_observations':True}
            restoration={'kind':'same_run_observed_settings_inverse_and_portrait_positive_control',
                'rotation_setting_phases':2,'stay_on_unchanged':True,'foreground_baseline_restored':True,
                'accelerometer_rotation_restored':True,'user_rotation_restored':True,
                'viewport_restored':True,'current_runtime_idle_after':True}
    expected_order=['baseline','live-before','return','post-state','live-after'] if plan['case_id']=='COMP-01' \
        else ['live-before','portrait-baseline','rotate-negative','restore-positive','live-after']
    S.need(list(phase_rows)==expected_order==done['phase_order'] and done['phase_originals']==phase_rows
        and {p.name for p in (case/'phone-originals').iterdir()}==set(expected_order),
        'exact one-use physical phase order differs')
    S.need(all(first[1]<=second[0] for first,second in zip(p4times,p4times[1:])),
        'original P4 phone actors overlapped or changed order')
    S.need(all(a['completed']<=b['started'] for a,b in zip(ordered,ordered[1:])),
        'host original steps overlapped or changed order')
    S.need(start/1e9<=ordered[0]['started'] and ordered[-1]['completed']<=end/1e9,
        'original component host actions are outside total-case observations')
    expected_transport={r['result']['phase'] for r in ordered}|{'independent-closure'}
    S.need({p.name for p in (case/'transport').iterdir()}==expected_transport,
        'unexpected additional host action directory in this case')
    admitted['C'].recheck_source_package(admitted['co'],admitted['package']);O.recheck()
    S.need(audit['network_or_process_attempts']==0 and audit['writes_outside_output']==0,
        'independent closure attempted an external effect')
    metrics=dict(done['metrics']);metrics['evidence']={'root_plan':S.desc(case/'ROOT-PLAN.original.json',plan_raw),
        'execution_original':done_row,'phone_phase_originals':phase_rows,'independent_original_count':len(O.seen),
        'source_package':mf};metrics['restoration']=restoration
    S.need(set(metrics)=={'latency','usage','cost','resources','evidence','restoration'},'six required metric groups missing')
    result={'schema':'hepta.physical-component.closure.v1',
        'state':'PHYSICAL_ORIGINALS_VERIFIED_PENDING_ROOT_VERIFIER_JOIN',
        'case_id':plan['case_id'],'label':plan['label'],'nonce':plan['nonce'],'source_package':mf,
        'release_pins':admitted['pins'],'component_case_passed':False,'physical_originals_verified':True,
        'physical_component_observed':True,'root_must_join_this_verifier_before_case_pass':True,
        'model_qualified':False,'native_task_qualified':False,'business_verified':False,
        'automatic_retry':False,'phone_actor_starts':5,'input_dispatches':0,'proof':proof,
        'metrics':metrics,'independent_host_isolation':audit,
        'transport_scope':'local and P4 original children joined with double EOF; phone wrapper rc and typed effects separately verified',
        'source_only_fixture_cannot_establish_physical_pass':True}
    if final_audit:
        closure_raw=O.known(case/'CLOSURE.json',1048576)[1]
        S.need(closure_raw==S.enc(result),'independent original proof differs on exact final read-only reconstruction')
        argv=['/usr/bin/python3','-I','-B',str(root/'source/verify_physical_component.py'),
            '--case',str(case),'--plan-sha256',S.sha(plan_raw),
            '--source-manifest-sha256',mf['sha256'],'--execute-host-closure']
        actual=capture(S,O,case/'transport/independent-closure','independent-closure',argv,None,60)
        reply=S.strict(actual['stdout'])
        S.need(reply['state']==result['state'] and reply['case_id']==plan['case_id']
            and reply['component_case_passed'] is False and reply['physical_originals_verified'] is True
            and reply['phone_calls_by_closure']==0,'actual independent verifier response differs')
        final,_,final_row=known_json(S,O,case/'ROOT-RESULT.json',1048576)
        timing=final['latency']
        S.need(final['schema']=='hepta.physical-component.root-result.v1'
            and final['state']=='ORIGINAL_PHYSICAL_COMPONENT_CLOSED' and final['case_id']==plan['case_id']
            and final['nonce']==plan['nonce'] and final['source_package']==mf
            and final['root_plan_sha256']==S.sha(plan_raw)
            and final['closure']==S.desc(case/'CLOSURE.json',closure_raw)
            and final['component_case_passed'] is True and final['model_qualified'] is False
            and final['native_task_qualified'] is False and final['business_verified'] is False
            and final['automatic_retry'] is False and final['independent_verifier_child']==actual['result']
            and O.read(final['independent_verifier_capture'],65536)==
                O.known(case/'transport/independent-closure/OUTPUT-CAPTURE.json',65536)[1]
            and final['host_cleanup']=={'stream_cleanup_errors':[],'host_children':[]}
            and timing['start_monotonic_ns']==start and timing['original_maximum_seconds']==300
            and type(timing['end_monotonic_ns']) is int and end<=timing['end_monotonic_ns']
            and timing['elapsed_seconds']==(timing['end_monotonic_ns']-start)/1e9<=300
            and end/1e9<=actual['started']<=actual['completed']<=timing['end_monotonic_ns']/1e9,
            'final Root original lacks an actual joined verifier, closure binding or bounded complete lifetime')
        O.recheck()
        return {'state':'ORIGINAL_PHYSICAL_COMPONENT_CLOSED','case_id':plan['case_id'],
            'component_case_passed':True,'physical_originals_verified':True,'root_result':final_row,
            'phone_calls_by_closure':0,'readonly_final_original_audit':True}
    C.put(case/'CLOSURE.json',S.enc(result))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',type=Path);parser.add_argument('--plan-sha256')
    parser.add_argument('--source-manifest-sha256');parser.add_argument('--execute-host-closure',action='store_true')
    parser.add_argument('--audit-final-originals-only',action='store_true')
    args=parser.parse_args()
    if args.execute_host_closure and args.audit_final_originals_only:
        raise ValueError('choose one proof creation or read-only final original audit')
    if not args.execute_host_closure and not args.audit_final_originals_only:
        print(json.dumps({'state':'SOURCE_ONLY_NO_INPUTS_READ_NO_PHONE','phone_calls':0,'component_case_passed':False}))
        return 0
    R,(root,S,O,mf,files,C)=bootstrap(args.source_manifest_sha256)
    _,raw=O.known(args.case/'ROOT-PLAN.original.json',262144)
    S.need(S.sha(raw)==args.plan_sha256,'explicit original root plan pin differs')
    plan=S.strict(raw);admitted=S.admit(plan,O,root)
    result=close_case(R,S,O,C,root,args.case,plan,raw,mf,files,admitted,final_audit=args.audit_final_originals_only)
    print(json.dumps({'state':result['state'],'case_id':result['case_id'],
        'component_case_passed':result['component_case_passed'],
        'physical_originals_verified':True,
        'phone_calls_by_closure':0,'native_task_qualified':False,'model_qualified':False},sort_keys=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
