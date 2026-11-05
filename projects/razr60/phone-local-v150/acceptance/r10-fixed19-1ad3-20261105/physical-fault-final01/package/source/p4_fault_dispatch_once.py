#!/usr/bin/env python3
"""One P4-owned invocation of the already pinned phone actor; no retries."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

P4 = Path('/home/alex/razr60-local-model-v150')
CASE_ROOT = Path('/home/alex/codex-physical-faults-r10-r1')
ACTOR_SHA = '179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'
CAPTURE_SHA = 'f12a251542894d0e8c0dedc9d62eb96d4f39e2b1d563f849c2f60e6ee02580e3'
CAPTURE_BYTES = 29065
PHASES = {'operator-stage','watch','armed-read','capture'} | {'archive-chunk-%03d'%i for i in range(128)}
PLAIN_LIMIT = 64*1024*1024
PACKED_LIMIT = 16*1024*1024


def need(value,message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def load_capture(root):
    path=root/'source/owned_capture.py'
    need(path.resolve(strict=True)==path,'canonical staged capture source required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==CAPTURE_BYTES,
            'exact staged capture source required')
        body=os.read(fd,CAPTURE_BYTES+1)
        need(len(body)==CAPTURE_BYTES and sha(body)==CAPTURE_SHA,'staged capture source hash differs')
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(all(getattr(before,k)==getattr(os.fstat(fd),k)==getattr(path.lstat(),k) for k in fields),
            'capture source changed')
    finally:
        os.close(fd)
    mod=types.ModuleType('owned_physical_component_capture')
    mod.__file__=str(path)
    exec(compile(body,str(path),'exec'),mod.__dict__)
    return mod


def relative(path):
    p=Path(path)
    need(isinstance(path,str) and str(p)==path and not p.is_absolute()
        and '..' not in p.parts and path not in ('','.'),'canonical relative export required')
    return p


def export_tree(C,directory):
    rows=[]
    total=0
    for path in sorted(directory.rglob('*')):
        st=path.lstat()
        need(not stat.S_ISLNK(st.st_mode),'symlink in owned operation evidence')
        if stat.S_ISDIR(st.st_mode):
            need(stat.S_IMODE(st.st_mode)==0o700,'private evidence directory required')
            continue
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,'regular original evidence required')
        body=C.read(path,PLAIN_LIMIT)
        total+=len(body)
        need(total<=PLAIN_LIMIT and len(rows)<128,'owned evidence export bound')
        rows.append({'relative':str(path.relative_to(directory)),
            'original':C.desc(path,body),'base64':base64.b64encode(body).decode()})
    raw=enc({'schema':'hepta.physical-fault.p4-originals.v1','root':str(directory),'files':rows})
    need(len(raw)<=PLAIN_LIMIT,'bounded original export envelope required')
    packed=gzip.compress(raw,mtime=0)
    need(len(packed)<=PACKED_LIMIT,'bounded compressed original export required')
    return {'schema':'hepta.physical-fault.p4-original-export.v1','plain_bytes':len(raw),
        'plain_sha256':sha(raw),'gzip_bytes':len(packed),'gzip_sha256':sha(packed),
        'gzip_base64':base64.b64encode(packed).decode()}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--case-root',type=Path,required=True)
    p.add_argument('--self-sha256',required=True)
    p.add_argument('--execute-one-phone-actor',action='store_true')
    p.add_argument('--inspect-joined-phase',choices=sorted(PHASES))
    args=p.parse_args()
    need(not (args.execute_one_phone_actor and args.inspect_joined_phase),'one explicit dispatcher mode required')
    if not args.execute_one_phone_actor and not args.inspect_joined_phase:
        print(json.dumps({'state':'SOURCE_PREVIEW_NO_INPUT_READ_NO_PHONE','phone_calls':0}))
        return 0
    root=args.case_root
    need(root.parent==CASE_ROOT and re.fullmatch('[0-9a-f]{32}',root.name)
        and root.resolve(strict=True)==root,'canonical explicit case root required')
    C=load_capture(root)
    source=Path(__file__).resolve(strict=True)
    need(source==root/'source/p4_fault_dispatch_once.py'
        and sha(C.read(source,131072))==args.self_sha256,'actual staged dispatcher source differs')
    case_raw=C.read(root/'CASE.original.json',262144)
    case=strict(case_raw)
    need(case['schema']=='hepta.physical-fault.p4-case.v1' and case['nonce']==root.name
        and case['case_id'] in ('NEG-04','NEG-05','NEG-07'),'fixed staged fault case differs')
    if args.inspect_joined_phase:
        phase=args.inspect_joined_phase
        out=root/'phases'/phase
        result_raw=C.read(out/'DISPATCH-RESULT.json',65536)
        intent_raw=C.read(out/'DISPATCH-INTENT.json',65536)
        child_raw=C.read(out/'capture/phone-actor/RESULT.json',65536)
        capture_raw=C.read(out/'capture/phone-actor/OUTPUT-CAPTURE.json',65536)
        result,intent,child=strict(result_raw),strict(intent_raw),strict(child_raw)
        need(result['state']=='ONE_ORIGINAL_PHONE_ACTOR_JOINED_WITH_COMPLETE_HOST_CAPTURE'
            and result['phase']==phase and result['nonce']==case['nonce']
            and result['case_sha256']==sha(case_raw) and result['actor_child']==child
            and child['state']=='ORIGINAL_HOST_CHILD_JOINED' and child['returncode']==0,
            'actual joined original required for inspection')
        need(result['phone_rc']==0,'inspection requires an actual successful original phone terminal')
        rows={name:{'original':C.desc(out/path,body),'base64':base64.b64encode(body).decode()}
            for name,path,body in [('result','DISPATCH-RESULT.json',result_raw),
                ('intent','DISPATCH-INTENT.json',intent_raw),('child','capture/phone-actor/RESULT.json',child_raw),
                ('capture','capture/phone-actor/OUTPUT-CAPTURE.json',capture_raw)]}
        print(json.dumps({'schema':'hepta.physical-fault.p4-joined-inspection.v1',
            'state':'ACTUAL_PRIOR_ACTOR_JOINED_INSPECT_ONLY','nonce':case['nonce'],'phase':phase,
            'files':rows,'original_export':export_tree(C,out),
            'phone_calls':0,'process_starts':0,'new_identity':False},sort_keys=True))
        return 0
    raw=sys.stdin.buffer.read(131073)
    need(0<len(raw)<=131072,'bounded exact phase request required')
    value=strict(raw)
    need(type(value) is dict and set(value)=={'schema','case_sha256','nonce','case_id','phase','request'}
        and value['schema']=='hepta.physical-fault.p4-phase.v1'
        and value['case_sha256']==sha(case_raw) and value['nonce']==case['nonce']
        and value['case_id']==case['case_id'] and value['phase'] in PHASES,'phase/case identity differs')
    phase=value['phase']
    allowed=PHASES
    need(phase in allowed,'phase belongs to another fault case')
    request=value['request']
    need(type(request) is dict and set(request)=={'kind','root','timeout_seconds','command'}
        and request['kind']=='shell' and request['root'] is True
        and type(request['timeout_seconds']) is int
        and request['timeout_seconds']==(260 if phase=='watch' else 120 if phase=='capture' else 30)
        and isinstance(request['command'],str) and '\0' not in request['command'],
        'bounded explicit root shell request required')
    import shlex
    wire=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(request['command'])).encode()
    need(len(wire)<65536,'original exclusive ADB request budget exceeded')
    actor=P4/'ops/phone_once.py'
    actor_raw=C.read(actor,65536)
    need(sha(actor_raw)==ACTOR_SHA,'reviewed P4 phone actor source differs')
    label='pf-'+case['nonce']+'-'+phase
    request_path=P4/'requests'/(label+'.json')
    actor_out=P4/'operations'/label
    need(not request_path.exists() and not request_path.is_symlink()
        and not actor_out.exists() and not actor_out.is_symlink(),'one-use phone actor label already exists')
    phases=root/'phases'
    need(phases.resolve(strict=True)==phases,'canonical existing phases directory required')
    out=phases/phase
    os.umask(0o077)
    C.newdir(out)
    C.put(out/'PHASE.original.json',raw)
    request_raw=enc(request)
    C.put(out/'REQUEST.original.json',request_raw)
    C.put(request_path,request_raw)
    argv=['/usr/bin/python3','-I','-B',str(actor),label,str(request_path)]
    intent={'schema':'hepta.physical-fault.p4-dispatch-intent.v1','phase':phase,
        'case_sha256':sha(case_raw),'nonce':case['nonce'],'case_id':case['case_id'],'label':label,
        'request':C.desc(request_path,request_raw),'actor_source':C.desc(actor,actor_raw),
        'argv':argv,'maximum_actor_starts':1,'automatic_retry':False,'signals_sent':0,
        'started_monotonic_ns':time.monotonic_ns(),'started_unix_ns':time.time_ns()}
    C.put(out/'DISPATCH-INTENT.json',enc(intent))
    owner=C.OwnedCapture(out/'capture')
    try:
        owner.execute_process('phone-actor',argv,request['timeout_seconds']+20)
        need(len(owner.steps)==1 and owner.steps[0]['state']=='ORIGINAL_HOST_CHILD_JOINED'
            and owner.steps[0]['returncode']==0,'actual actor child has not joined successfully')
        wrapper_path=actor_out/'result.json'
        wrapper_raw=C.read(wrapper_path,32*1024*1024)
        wrapper=strict(wrapper_raw)
        phone=wrapper.get('phone')
        need(type(phone) is dict and type(phone.get('rc')) is int
            and isinstance(phone.get('stdout'),str) and isinstance(phone.get('stderr'),str),
            'complete actual phone wrapper fields required')
        operation={'actor_rc':0,'wrapper_sha256':sha(wrapper_raw),'wrapper':wrapper}
        C.put(out/'WRAPPER.original.json',wrapper_raw)
        C.put(out/'OPERATION.original.json',enc(operation))
        C.put(out/'ACTOR-INTENT.original.json',C.read(actor_out/'intent.json',131072))
        C.put(out/'ACTOR-BASELINE.original.json',C.read(actor_out/'baseline.json',65536))
        need(C.read(request_path,65536)==request_raw and C.read(actor,65536)==actor_raw,
            'request or actor source changed across its sole invocation')
        cleanup=owner.close_owned_host_outputs()
        need(cleanup=={'stream_cleanup_errors':[],'host_children':[]},'owned host output cleanup failed')
        result={'schema':'hepta.physical-fault.p4-dispatch-result.v1',
            'state':'ONE_ORIGINAL_PHONE_ACTOR_JOINED_WITH_COMPLETE_HOST_CAPTURE',
            'phase':phase,'nonce':case['nonce'],'case_id':case['case_id'],'label':label,
            'case_sha256':sha(case_raw),'request_sha256':sha(request_raw),
            'wrapper_original':C.desc(wrapper_path,wrapper_raw),'actor_child':owner.steps[0],
            'phone_rc':phone['rc'],'phone_stdout_bytes':len(phone['stdout'].encode()),
            'phone_stdout_sha256':sha(phone['stdout'].encode()),
            'phone_stderr_bytes':len(phone['stderr'].encode()),
            'phone_stderr_sha256':sha(phone['stderr'].encode()),
            'finished_monotonic_ns':time.monotonic_ns(),'finished_unix_ns':time.time_ns(),
            'actor_starts':1,'automatic_retry':False,'signals_sent':0,'phone_effect_qualified':False}
        C.put(out/'DISPATCH-RESULT.json',enc(result))
        print(json.dumps(export_tree(C,out),sort_keys=True,separators=(',',':')))
        return 0
    except BaseException as error:
        cleanup=owner.close_owned_host_outputs()
        C.put(out/'FAILED-OR-UNKNOWN.json',enc({'state':'ORIGINALS_PRESERVED_NO_PHONE_RETRY',
            'error_type':type(error).__name__,'detail':str(error)[:1024],
            'steps':owner.steps,'host_cleanup':cleanup,'automatic_retry':False,'signals_sent':0,
            'restoration_requires_actual_completed_original_reconciliation':True}))
        raise


if __name__=='__main__':
    raise SystemExit(main())
