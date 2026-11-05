#!/usr/bin/env python3
"""One host-only independent closure, or read-only final Root receipt audit."""
import argparse,base64,hashlib,json,os,re,shlex,signal,sys,time,types
from pathlib import Path
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


def modules(S,root,files):
    sys.modules['physical_fault_common']=S
    for name in ('fault_originals','fault_projections','verify_physical_fault'):
        module=S.module(files['source/'+name+'.py'],root/'source'/(name+'.py'),name)
        sys.modules[name]=module
    return sys.modules['verify_physical_fault'],sys.modules['fault_originals']


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-manifest-sha256');p.add_argument('--plan',type=Path);p.add_argument('--plan-sha256')
    p.add_argument('--execution',type=Path);p.add_argument('--execution-sha256');p.add_argument('--out',type=Path)
    p.add_argument('--execute-verify-once',action='store_true');p.add_argument('--audit-final-originals-only',action='store_true')
    args=p.parse_args()
    if not args.execute_verify_once and not args.audit_final_originals_only:
        print(json.dumps({'state':'SOURCE_PREVIEW_NO_CASE_READ_NO_PHONE','phone_calls':0,'signals':0,
            'new_tasks':0,'physical_case_pass':False},sort_keys=True));return 0
    if args.execute_verify_once and args.audit_final_originals_only:raise ValueError('one_explicit_verifier_mode')
    root,S,originals,mf,files,C=bootstrap(args.source_manifest_sha256)
    S.final_dependencies()
    plan_row,plan_raw=originals.known(args.plan,65536)
    S.need(plan_row['sha256']==args.plan_sha256,'actual_root_plan_original_hash')
    plan=S.strict(plan_raw);admitted=S.admit(plan,originals,files)
    execution_row,execution_raw=originals.known(args.execution,16*1024*1024)
    S.need(execution_row['sha256']==args.execution_sha256 and args.plan==Path(plan['out'])/'ROOT-PLAN.original.json'
        and args.execution==Path(plan['out'])/'EXECUTION.original.json' and args.out==Path(plan['out'])/'closure',
        'exact_actual_original_closure_paths')
    execution=S.strict(execution_raw)
    S.need(execution['source_package']==mf,'actual_execution_source_manifest')
    V,O=modules(S,root,files)
    ctx={'plan':plan,'plan_raw':plan_raw,'execution':execution,'originals':originals,'files':files,'admitted':admitted}
    S.need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'preexisting_verification_alarm')
    def expired(_n,_f):raise TimeoutError('independent_original_verification_deadline')
    previous=signal.getsignal(signal.SIGALRM);signal.signal(signal.SIGALRM,expired)
    started=time.monotonic_ns();signal.setitimer(signal.ITIMER_REAL,170)
    if args.execute_verify_once:
        os.umask(0o077);C.newdir(args.out)
        C.put(args.out/'INTENT.json',S.enc({'schema':'hepta.physical-fault.closure-intent.v1',
            'source_package':mf,'root_plan':plan_row,'execution':execution_row,'maximum_seconds':170,
            'phone_calls':0,'new_tasks':0,'signals':0,'automatic_retry':False}))
    try:
        closure=V.verify(ctx);originals.recheck()
        body=S.enc(closure)
        if args.audit_final_originals_only:
            actual=originals.known(args.out/'CLOSURE.json',16*1024*1024)
            S.need(actual[1]==body,'independent_original_closure_rebuild_differs')
            result_row,result_raw=originals.known(Path(plan['out'])/'ROOT-RESULT.json',16*1024*1024)
            result=S.strict(result_raw)
            args0=['/usr/bin/python3','-I','-B',str(root/'source/verify_fault_once.py'),
                '--source-manifest-sha256',mf['sha256'],'--plan',str(args.plan),'--plan-sha256',args.plan_sha256,
                '--execution',str(args.execution),'--execution-sha256',args.execution_sha256,
                '--out',str(args.out),'--execute-verify-once']
            rows=V.phase_rows(plan['out'],'independent-closure',originals)
            output=O.host_phase(originals,rows,'independent-closure',args0,180,None)
            summary=S.strict(output)
            S.need(result.get('schema')=='hepta.physical-fault.root-result.v1' and
                result.get('state')=='ACTUAL_PHYSICAL_FAULT_ORIGINALS_AND_VERIFIER_JOINED' and
                result['case_id']==plan['case_id'] and result['nonce']==plan['nonce'] and
                result['source_package']==mf and result['root_plan_sha256']==S.sha(plan_raw) and
                result['execution']==execution_row and result['closure']==actual[0] and
                result['verifier_child']==S.strict(originals.read(rows['result'])) and
                result['verifier_capture']==rows['output_capture'] and
                result['host_cleanup']=={'stream_cleanup_errors':[],'host_children':[]} and
                0<result['finished_monotonic_ns']-result['started_monotonic_ns']<=1200_000_000_000 and
                result['physical_case_pass'] is True and result['whole_case_pass'] is False and
                result['business_verified'] is False and result['automatic_retry'] is False and
                summary['closure']==actual[0] and summary['physical_case_pass'] is False,
                'actual_final_Root_verifier_lifetime_and_capture_not_closed')
            originals.recheck()
            print(json.dumps({'state':'ACTUAL_PHYSICAL_FAULT_FINAL_ORIGINALS_AUDITED',
                'case_id':plan['case_id'],'physical_case_pass':True,'whole_case_pass':False,
                'phone_calls':0,'signals':0,'new_tasks':0,'root_result':result_row},sort_keys=True))
            return 0
        C.put(args.out/'CLOSURE.json',body)
        C.put(args.out/'ORIGINAL-READ-SET.json',S.enc({'schema':'hepta.physical-fault.original-read-set.v1',
            'originals':[originals.seen[k] for k in sorted(originals.seen)],'all_originals_rechecked':True,
            'case_id':plan['case_id'],'source_package':mf,'phone_calls':0}))
        originals.recheck()
        print(json.dumps({'state':closure['state'],'case_id':plan['case_id'],
            'closure':S.desc(args.out/'CLOSURE.json',body),'physical_case_pass':False,
            'physical_originals_verified':True,'pending_root_verifier_join':True,
            'phone_calls':0,'signals':0,'new_tasks':0},sort_keys=True))
        return 0
    except BaseException as error:
        if args.execute_verify_once:
            C.put(args.out/'FAILED.json',S.enc({'state':'ACTUAL_ORIGINALS_NOT_VERIFIED',
                'error_type':type(error).__name__,'error':str(error)[:2000],'physical_case_pass':False,
                'phone_calls':0,'signals':0,'automatic_retry':False,
                'originals_read':[originals.seen[k] for k in sorted(originals.seen)]}))
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)


if __name__=='__main__':raise SystemExit(main())
