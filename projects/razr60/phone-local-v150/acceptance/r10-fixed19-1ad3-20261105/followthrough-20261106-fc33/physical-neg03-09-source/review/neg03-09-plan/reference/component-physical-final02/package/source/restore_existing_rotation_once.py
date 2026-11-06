#!/usr/bin/env python3
"""One same-case inverse after raw inspection of the original completed actor.

This is a separate bounded restoration action, never a restart of NEG03 and
never case acceptance. An existing restore phase/request is not replayed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import time
import types

sys.dont_write_bytecode=True


def load_verifier(manifest_sha):
    root=Path(__file__).resolve().parent.parent
    def read(path,maximum):
        if path.resolve(strict=True)!=path:raise ValueError('canonical pinned recovery source required')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=maximum:
                raise ValueError('bounded recovery source required')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(before.st_size+1)
            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            if len(raw)!=before.st_size or any(getattr(before,k)!=getattr(os.fstat(fd),k)
                    or getattr(before,k)!=getattr(path.lstat(),k) for k in fields):
                raise ValueError('recovery source changed')
            return raw
        finally:os.close(fd)
    raw=read(root/'SOURCE-MANIFEST.json',262144)
    if hashlib.sha256(raw).hexdigest()!=manifest_sha:raise ValueError('recovery source manifest pin differs')
    value=json.loads(raw);rows=[r for r in value['files'] if r['path']=='source/verify_physical_component.py']
    if len(rows)!=1:raise ValueError('one exact independent verifier required')
    row=rows[0];path=root/row['path'];body=read(path,131072)
    if len(body)!=row['bytes'] or hashlib.sha256(body).hexdigest()!=row['sha256']:
        raise ValueError('independent verifier source differs')
    V=types.ModuleType('physical_restore_original_verifier');V.__file__=str(path)
    exec(compile(body,str(path),'exec'),V.__dict__)
    R,boot=V.bootstrap(manifest_sha)
    if boot[4]['source/restore_existing_rotation_once.py']!=read(Path(__file__).resolve(),131072):
        raise ValueError('actual restoration entry source differs')
    return V,R,boot


def retain(S,C,out,payload,remote):
    C.newdir(out);mapping=[];seen=set()
    for row in payload['files']:
        name=str(S.relative(row['relative']))
        S.need(name not in seen,'duplicate inspection member');seen.add(name)
        body=S.decode(row['base64'],64*1024*1024)
        S.need(row['original']==S.desc(remote/name,body),'inspection original bytes/origin differ')
        path=out/name
        parents=[];p=path.parent
        while p!=out:
            parents.append(p);p=p.parent
        for p in reversed(parents):
            if not p.exists():C.newdir(p)
        C.put(path,body)
        mapping.append({'original':row['original'],'retained':S.desc(path,body)})
    C.put(out/'ORIGINAL-MAP.json',S.enc(mapping))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',type=Path);parser.add_argument('--plan-sha256')
    parser.add_argument('--source-manifest-sha256')
    parser.add_argument('--inspect-original-then-restore-once',action='store_true')
    args=parser.parse_args()
    if not args.inspect_original_then_restore_once:
        print(json.dumps({'state':'SOURCE_ONLY_NO_INPUTS_READ_NO_PHONE','phone_calls':0,
            'new_identity':False,'component_case_passed':False}))
        return 0
    V,R,(root,S,O,mf,files,C)=load_verifier(args.source_manifest_sha256)
    _,plan_raw=O.known(args.case/'ROOT-PLAN.original.json',262144)
    S.need(S.sha(plan_raw)==args.plan_sha256,'exact original case plan pin differs')
    plan=S.strict(plan_raw)
    S.need(plan['case_id']=='NEG-03' and plan['rotation_authorized'] is True
        and args.case==S.B/'physical-components-r10-r1'/plan['label']
        and plan['out']==str(args.case) and args.case.resolve(strict=True)==args.case,
        'one original explicitly authorized physical rotation case required')
    S.need(not (args.case/'ROOT-RESULT.json').exists() and not (args.case/'CLOSURE.json').exists()
        and not (args.case/'EXECUTION-COMPLETE.json').exists(),
        'closed or complete cases are not restoration-recovery inputs')
    intent,_,_=V.known_json(S,O,args.case/'ROOT-INTENT.json',65536)
    S.need(intent['nonce']==plan['nonce'] and intent['source_package']==mf
        and intent['case_id']=='NEG-03' and intent['maximum_rotation_setting_phases']==2
        and intent['automatic_retry'] is False and intent['new_identity_retry'] is False,
        'original inverse authorization or source package differs')
    admitted=S.admit(plan,O,root)
    p4_raw=O.known(args.case/'P4-CASE.original.json',262144)[1]
    expected_case={'schema':'hepta.physical-component.p4-case.v1','nonce':plan['nonce'],
        'case_id':'NEG-03','label':plan['label'],'root_plan_sha256':S.sha(plan_raw),
        'root_source_manifest':mf,'automatic_retry':False,'phone_actor_starts_per_phase':1}
    S.need(p4_raw==S.enc(expected_case),'same original P4 case required')
    baseline_raw=O.known(args.case/'PHYSICAL-BASELINE.original.json',32*1024*1024)[1]
    prepared=O.known(args.case/'RESTORE-REQUEST.prepared.json',65536)[1]
    with S.actual_modules(admitted) as modules:
        baseline_request,_=S.physical_request(modules,plan['nonce'],'portrait-baseline')
        baseline_original=V.phone_phase(R,S,O,args.case,plan,files,p4_raw,'portrait-baseline',baseline_request)
        S.need(baseline_original['stdout']==baseline_raw,'baseline must bind actual original P4 and Root captures')
        baseline=S.parse_physical(modules,baseline_raw,plan['nonce'],'portrait-baseline')
        restore,recipe=S.physical_request(modules,plan['nonce'],'restore-positive',baseline)
        rotate,_=S.physical_request(modules,plan['nonce'],'rotate-negative',baseline)
        S.need(prepared==S.enc(restore),'stored inverse differs from this actual baseline')
        rotation_packet={'schema':'hepta.physical-component.p4-phase.v1','case_sha256':S.sha(p4_raw),
            'nonce':plan['nonce'],'case_id':'NEG-03','phase':'rotate-negative','request':rotate}
        S.need(O.known(args.case/'plans/rotate-negative.json',131072)[1]==S.enc(rotation_packet),
            'original authorized rotation was not prepared with the same baseline')
        # This create-only recovery namespace is also the local once guard.
        out=args.case/'recovery';os.umask(0o077);C.newdir(out)
        C.put(out/'RESTORATION-INTENT.json',S.enc({'schema':'hepta.physical-component.restore-only-intent.v1',
            'original_plan_sha256':S.sha(plan_raw),'source_package':mf,'nonce':plan['nonce'],
            'maximum_inspection_requests':1,'maximum_phone_actor_starts':1,'maximum_seconds':90,
            'existing_P4_restore_phase_is_never_replayed':True,'new_identity':False,
            'automatic_retry':False,'original_case_deadline_extended':False,
            'separate_restoration_only_budget_seconds':90,'component_case_passed':False}))
        owner=C.OwnedCapture(out/'transport');deadline=time.monotonic()+90
        remote=R.P4_BASE/plan['nonce']
        def remaining(maximum):
            left=deadline-time.monotonic();S.need(left>0,'original restoration-only budget expired')
            return min(maximum,left)
        recovery=None
        try:
            argv=['/usr/bin/python3','-I','-B',str(remote/'source/p4_component_dispatch_once.py'),
                '--case-root',str(remote),'--self-sha256',S.sha(files['source/p4_component_dispatch_once.py']),
                '--inspect-joined-phase','rotate-negative']
            raw=owner.execute_process('inspect-original-rotation',R.SSH+[shlex.join(argv)],remaining(30))
            checked=V.capture(S,O,out/'transport/inspect-original-rotation','inspect-original-rotation',
                R.SSH+[shlex.join(argv)],None,30)
            S.need(checked['stdout']==raw,'read-only inspection capture differs')
            inspection=S.strict(raw)
            S.need(inspection['schema']=='hepta.physical-component.p4-joined-inspection.v1'
                and inspection['state']=='ACTUAL_PRIOR_ACTOR_JOINED_INSPECT_ONLY'
                and inspection['nonce']==plan['nonce'] and inspection['phase']=='rotate-negative'
                and inspection['phone_calls']==inspection['process_starts']==0
                and inspection['new_identity'] is False,'actual original joined inspection required')
            payload=V.export_payload(S,S.enc(inspection['original_export']),allow_failure=True)
            originals=out/'inspected-rotation-originals'
            retain(S,C,originals,payload,remote/'phases/rotate-negative')
            inspected=V.verify_phase_originals(R,S,O,originals,plan,p4_raw,'rotate-negative',rotate,payload,
                allow_failure=True)
            # Crucially this checks phone rc=0 as well as the joined P4 child.
            # A joined SSH/Python process alone cannot authorize a new setting.
            S.need(baseline_original['p4_finished']<=inspected['p4_started'],
                'original P4 rotation must follow its observed baseline; host clocks are not compared')
            C.put(out/'JOINED-ORIGINAL-RECONCILED.json',S.enc({'state':'ORIGINAL_P4_AND_PHONE_TERMINAL_RECONCILED',
                'nonce':plan['nonce'],'original_phase':'rotate-negative','original_phone_rc':0,
                'new_phone_calls_so_far':0,'automatic_retry':False,'component_case_passed':False}))
            # Use the same reviewed dispatcher with the same consumed phase identity.
            # Its atomic phase and actor-request creation rejects a race with the
            # original coordinator, even if that coordinator is still finishing.
            recovery=R.RootCase.__new__(R.RootCase)
            recovery.S,recovery.C,recovery.plan,recovery.plan_raw=S,C,plan,plan_raw
            recovery.manifest_row,recovery.files,recovery.admitted,recovery.originals=mf,files,admitted,O
            recovery.out,recovery.remote,recovery.owner,recovery.deadline=out,remote,owner,deadline
            recovery.p4_case,recovery.p4_case_raw=expected_case,p4_raw
            recovery.phase_order=['live-before','portrait-baseline','rotate-negative'];recovery.phase_rows={}
            recovery.last_completed=False;recovery.last_actor_joined=False;recovery.last_phase=None
            recovery.rotation_attempted=True;recovery.restored=False
            C.newdir(out/'plans');C.newdir(out/'phone-originals')
            response,_=recovery.dispatch('restore-positive',restore)
            closed=V.phone_phase(R,S,O,out,plan,files,p4_raw,'restore-positive',restore)
            S.need(closed['stdout']==response,'restoration original response differs')
            restored=S.parse_physical(modules,response,plan['nonce'],'restore-positive')
            S.need(all(restored['value'][k]==baseline['value'][k] for k in
                ('stay_on','accelerometer_rotation','user_rotation','fingerprint_b64'))
                and restored['observed']==baseline['observed'] and restored['viewport']==baseline['viewport'],
                'original observed settings, focus and qualified geometry not restored')
            C.put(out/'RESTORED-STDOUT.original.json',response)
            C.put(out/'RESTORED.png',restored['png'])
            cleanup=owner.close_owned_host_outputs()
            S.need(cleanup=={'stream_cleanup_errors':[],'host_children':[]},'restoration host cleanup incomplete')
            O.recheck();admitted['C'].recheck_source_package(admitted['co'],admitted['package'])
            value={'schema':'hepta.physical-component.restore-only-result.v1',
                'state':'ORIGINAL_ROTATION_BASELINE_RESTORED_WITHOUT_CASE_PASS','nonce':plan['nonce'],
                'original_case':str(args.case),'original_plan_sha256':S.sha(plan_raw),'source_package':mf,
                'phone_actor_starts':1,'phone_input_commands':0,'new_identity':False,'automatic_retry':False,
                'original_case_replayed':False,'original_case_deadline_extended':False,
                'component_case_passed':False,'model_qualified':False,'native_task_qualified':False,
                'restoration':{'same_run_settings_restored':True,'same_foreground_restored':True,
                    'actual_portrait_qualification_guard_passed':True,'screenshot':restored['png_info']},
                'host_cleanup':cleanup,'independent_restore_originals':closed['rows']}
            C.put(out/'RESTORATION-RESULT.json',S.enc(value))
            print(json.dumps({'state':value['state'],'nonce':plan['nonce'],'component_case_passed':False},sort_keys=True))
            return 0
        except BaseException as error:
            cleanup=owner.close_owned_host_outputs()
            C.put(out/'FAILED-OR-UNKNOWN.json',S.enc({'state':'ORIGINAL_RESTORATION_RETAINED_NO_REPLAY',
                'error_type':type(error).__name__,'detail':str(error)[:1024],
                'restore_dispatch_attempted':recovery is not None,
                'last_actor_joined':False if recovery is None else recovery.last_actor_joined,
                'last_phone_phase_succeeded':False if recovery is None else recovery.last_completed,
                'host_cleanup':cleanup,'component_case_passed':False,'automatic_retry':False,'new_identity':False}))
            raise


if __name__=='__main__':
    raise SystemExit(main())
