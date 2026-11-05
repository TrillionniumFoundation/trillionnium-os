#!/usr/bin/env python3
"""Observe a fresh physical phase, call the frozen signal actor once, retain originals.

The actor is unchanged. This coordinator does no Send, tool dispatch, Cancel,
service signal, CONT or transport replay. A missed phase consumes this watch
attempt and cannot be turned into a physical pass. NEG07's visibility fence is
observed while the original r6 receipt is still nonterminal. The four raw
copies and fence are fsynced before a third unchanged pending-receipt read;
only then may a later receipt be observed. No retrospective fence is accepted.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types

FINAL_DEPENDENCIES = None
BASE = Path('/var/lib/trillionnium/owner-open/phone-local-v150')
CASE_IDS = ('NEG-04','NEG-05','NEG-07')
SCOPE = ('session_id','profile_id','task_id','turn_id','turn_stream_id')
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ACTOR_SHA = 'cd5100c0f12dc77b275a55893aa31fdc7d6b5ec61839635b70c0c9a11f0cbb1e'
TOTAL_SECONDS = 240
WAIT_SECONDS = 140
FOLLOWUP_SECONDS = 90
MAX_FILE = 4*1024*1024


def need(value,reason):
    if not value:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate_json_key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_json')))


def enc(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()


def metadata(value):return {name:getattr(value,name) for name in META}


def read_original(path,maximum=MAX_FILE):
    path=Path(path)
    need(path.parent.resolve(strict=True)==path.parent,'noncanonical_original_parent')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
             0<=before.st_size<=maximum,'bounded_regular_original')
        pieces=[];total=0
        while True:
            body=os.read(fd,min(65536,maximum+1-total))
            if not body:break
            pieces.append(body);total+=len(body);need(total<=maximum,'original_stream_bound')
        raw=b''.join(pieces);after=os.fstat(fd);named=path.lstat()
        need(metadata(before)==metadata(after)==metadata(named) and len(raw)==before.st_size,
             'original_changed_during_read')
        return raw,{'path':str(path),'bytes':len(raw),'sha256':sha(raw),
                    'stat_before':metadata(before),'stat_after':metadata(after),'eof':True}
    finally:os.close(fd)


def put(directory,name,raw):
    need(type(raw) is bytes and re.fullmatch('[A-Za-z0-9._-]{1,128}',name),'private_original_output')
    need(directory.resolve(strict=True)==directory,'private_output_parent_changed')
    fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        offset=0
        while offset<len(raw):
            n=os.write(fd,raw[offset:]);need(n>0,'private_output_short_write');offset+=n
        os.fsync(fd)
        value=os.fstat(fd)
    finally:os.close(fd)
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    need(metadata(value)==metadata((directory/name).lstat()),'private_output_name_replaced')
    return {'path':str(directory/name),'bytes':len(raw),'sha256':sha(raw)}


def final_dependencies():
    final=FINAL_DEPENDENCIES
    need(type(final) is dict and set(final)=={'fault_package_sha256','active_source_sha256',
        'runtime_package_sha256','consumer_sha256','readiness_sha256','policy_adoption_sha256',
        'live_policy_sha256'},'future_actual_fault_dependencies_are_unfrozen')
    need(all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for v in final.values()),
         'final_fault_dependency_hashes')
    return final


def validate_plan(plan):
    fields={'schema','case_id','operation_id','sender_label','nonce','expected_boot',
        'owner_request_b64','owner_request_sha256','previous_scope','roles','release_pins',
        'expected_probe_component','android_shell_exe','android_shell_sha256','busybox_sha256',
        'app_scope','task_template_sha256','runtime_binding','fault_package_sha256'}
    need(type(plan) is dict and set(plan)==fields and
         plan['schema']=='hepta.physical-fault.watch-plan.v1' and plan['case_id'] in CASE_IDS,
         'fixed_fault_watch_plan_fields')
    need(re.fullmatch('[a-z0-9][a-z0-9-]{5,69}',plan['sender_label']) and
         re.fullmatch('[a-z0-9][a-z0-9-]{5,69}',plan['operation_id']) and
         re.fullmatch('[0-9a-f]{32}',plan['nonce']),'fresh_existing_case_labels')
    owner=base64.b64decode(plan['owner_request_b64'],validate=True)
    need(base64.b64encode(owner).decode()==plan['owner_request_b64'] and 20<=len(owner)<=16000 and
         sha(owner)==plan['owner_request_sha256'] and owner.decode().count(plan['nonce'])==1 and b'\0' not in owner,
         'original_owner_bytes_and_nonce')
    need(type(plan['previous_scope']) is dict and set(plan['previous_scope'])==set(SCOPE),
         'actual_previous_semantic_scope')
    need(all(type(v) is str and 0<len(v.encode())<=256 and '\0' not in v for v in plan['previous_scope'].values()),
         'actual_previous_scope_values')
    return owner


def load_actor(bundle,final):
    need(type(bundle) is dict and set(bundle)=={'manifest_b64','sources'},'exact_fault_bundle')
    raw=base64.b64decode(bundle['manifest_b64'],validate=True);manifest=strict(raw)
    need(sha(raw)==final['fault_package_sha256'],'actual_fault_package_pin')
    body=base64.b64decode(bundle['sources']['source/signal_fault_once_r10.py'],validate=True)
    need(sha(body)==ACTOR_SHA,'unchanged_single_pidfd_actor_required')
    module=types.ModuleType('reviewed_physical_fault_actor')
    module.__file__='reviewed_physical_fault_actor.py';module._INLINE_BUNDLE=bundle
    exec(compile(body,module.__file__,'exec'),module.__dict__)
    module.load_bundle(final['fault_package_sha256'])
    need(sha(base64.b64decode(bundle['sources']['source/active_runtime_r10.py'],validate=True))==
         final['active_source_sha256'],'actual_shared_active_source_pin')
    for name,key in (('CONSUMER_SHA','consumer_sha256'),('READINESS_SHA','readiness_sha256'),
                     ('POLICY_SHA','live_policy_sha256'),('ADOPTION_SHA','policy_adoption_sha256')):
        need(getattr(module.active,name)==final[key],'actual_shared_active_generation')
    return module,manifest


def locate_task(owner,previous):
    evidence=BASE/'provider-state/evidence'
    need(evidence.resolve(strict=True)==evidence,'canonical_provider_evidence')
    directories=sorted(p for p in evidence.iterdir()
        if re.fullmatch('[0-9]{8}-[0-9]{6}-[0-9a-f]{32}',p.name))
    need(len(directories)<=512,'provider_search_bound')
    matches=[]
    for directory in directories:
        try:raw,_=read_original(directory/'provider-in.jsonl')
        except FileNotFoundError:continue
        first=raw.split(b'\n',1)[0]
        if not first or b'\n' not in raw:continue
        start=strict(first);turn=start.get('turn',{})
        if start.get('kind')!='turn.start' or type(turn.get('user_input')) is not str:
            continue
        if turn['user_input'].encode()!=owner:continue
        scope={k:turn.get(k) for k in SCOPE}
        need(all(type(v) is str and 0<len(v.encode())<=256 and '\0' not in v for v in scope.values()),
             'actual_admitted_scope_shape')
        need([scope[k] for k in SCOPE[:-1]]!=[previous[k] for k in SCOPE[:-1]],
             'old_semantic_identity_cannot_be_reused')
        matches.append((directory.name,scope))
    need(len(matches)<=1,'same_owner_has_multiple_admissions')
    return matches[0] if matches else None


def actor_plan(plan,found):
    value={k:v for k,v in plan.items() if k not in ('sender_label','fault_package_sha256')}
    value.update(schema='hepta.r10.signal-fault-plan.v1',run=found[0],scope=found[1])
    return value


def claim_path(scope):
    key=sha(json.dumps([scope[k] for k in SCOPE[:-1]],ensure_ascii=True,separators=(',',':')).encode())
    return BASE/'provider-state/evidence/claims'/key


def terminal_deadline(incoming,call_id):
    rows=[r for r in incoming if r.get('kind')=='tool.result' and r.get('call_id')==call_id]
    if not rows:return None
    need(len(rows)==1,'duplicate_original_native_result')
    row=rows[0]
    need(row.get('status')=='terminal' and type(row.get('terminal')) is dict and
         row['terminal'].get('kind')=='timed_out','original_native_result_is_not_a_deadline')
    return row


def four_fence(directory,plan,name,receipt_path=None,require_pending=False):
    run=BASE/'provider-state/evidence'/plan['run']
    paths={'terminal':run/'terminal.json','provider_input':run/'provider-in.jsonl',
           'provider_output':run/'provider-out.jsonl','claim':claim_path(plan['scope'])}
    start=time.monotonic_ns();pending_before=pending_after=None
    if receipt_path is not None:
        pending_before=read_original(receipt_path,262144)
        if require_pending:
            rv=strict(pending_before[0])
            need(rv.get('terminal') is False and rv.get('state')=='running',
                 'late_receipt_already_terminal_before_fence')
    originals={key:read_original(path) for key,path in paths.items()}
    for key,path in paths.items():
        need(read_original(path)==originals[key],'four_original_fence_changed_before_commit')
    if receipt_path is not None:
        pending_after=read_original(receipt_path,262144)
        need(pending_before==pending_after,'receipt_advanced_during_before_late_fence')
    end=time.monotonic_ns();records={}
    for key,(raw,row) in originals.items():
        retained=put(directory,name+'-'+key+'.original',raw)
        records[key]={'original':row,'retained':retained}
    value={'schema':'hepta.physical-fault.four-original-visibility-fence.v1',
        'case_id':plan['case_id'],'owner_request_sha256':plan['owner_request_sha256'],
        'scope':plan['scope'],'run':plan['run'],'name':name,'originals':records,
        'clock':'phone time.monotonic_ns same watch process','started_monotonic_ns':start,
        'finished_monotonic_ns':end,'all_four_raw_files_bookended_equal':True,
        'pending_receipt':None if pending_before is None else {'original':pending_before[1],
            'raw_b64':base64.b64encode(pending_before[0]).decode()},
        'pending_receipt_unchanged_across_reads':pending_before==pending_after,
        'original_production_files_written':0,'automatic_redispatch':False}
    fence=put(directory,name+'-FENCE.json',enc(value))
    if require_pending:
        # All four raw copies and their fence have already been fsynced. A
        # third exact read proves the original receipt still has not advanced
        # at this later point; failure retains the first attempt, never retakes
        # a before-late image from a different time.
        durable_pending=read_original(receipt_path,262144)
        need(durable_pending==pending_before,'late_receipt_advanced_before_fence_durable_bookend')
        put(directory,name+'-DURABILITY.json',enc({
            'schema':'hepta.physical-fault.before-late-durable-bookend.v1',
            'fence':fence,'same_original_pending_receipt':durable_pending[1],
            'observed_after_all_four_copies_and_fence_fsync_monotonic_ns':time.monotonic_ns(),
            'receipt_still_running_after_fence_persistence':True,
            'automatic_retry':False}))
    return value,originals


def final_observation(directory,actor,plan,case_id,deadline):
    run=BASE/'provider-state/evidence'/plan['run'];pre=None;late=None
    pre_signal=strict(read_original(BASE/'fault-injections-r10-r1'/plan['owner_request_sha256']/'PRE-SIGNAL.json')[0])
    calls=pre_signal['phase']['calls']
    action=calls[0]['action_id'] if calls else None
    call_id=calls[0]['call_id'] if calls else None
    receipt_path=BASE/'executor-r6/actions'/action/'receipt.json' if action else None
    last_error=None
    while time.monotonic()<deadline:
        try:
            incoming_raw,_=read_original(run/'provider-in.jsonl')
            incoming=actor.observation.jlines(incoming_raw)
            terminal_raw,_=read_original(run/'terminal.json',262144);terminal=strict(terminal_raw)
            need(terminal.get('kind')=='turn.fail','fault_task_must_remain_failed_not_business_success')
            if case_id=='NEG-07' and pre is None:
                result=terminal_deadline(incoming,call_id)
                need(result is not None,'original_native_deadline_not_yet_observed')
                pre,unused=four_fence(directory,plan,'PRE-LATE',receipt_path,True)
                put(directory,'ORIGINAL-DEADLINE-RESULT.json',enc(result))
            business_raw,business_row=read_original(run/'business-outcome.json',262144)
            business=strict(business_raw)
            need(business.get('business_verified') is False,'negative_business_result_must_remain_false')
            if receipt_path is not None:
                receipt_raw,receipt_row=read_original(receipt_path,262144);receipt=strict(receipt_raw)
                need(receipt.get('terminal') is True and receipt.get('state') in
                     ('completed','failed','timed_out','cancelled','output_limit_exceeded'),
                     'original_r6_cleanup_not_terminal_yet')
                need(receipt.get('waitpid_joined') is True and receipt.get('process_group_absent') is True and
                     receipt.get('waitpid_identity_lost') is False,'original_r6_cleanup_not_proven')
                if case_id=='NEG-07':
                    need(pre is not None,'cannot_reconstruct_before_late_fence_after_receipt')
                    late={'original':receipt_row,'observed_monotonic_ns':time.monotonic_ns(),
                          'original_dispatch_identity':{'action_id':action,'call_id':call_id}}
                    put(directory,'LATE-RECEIPT.original.json',receipt_raw)
                    put(directory,'LATE-RECEIPT-OBSERVATION.json',enc(late))
            post,raws=four_fence(directory,plan,'POST-LATE' if case_id=='NEG-07' else 'FINAL')
            if pre is not None:
                for key in pre['originals']:
                    need(pre['originals'][key]['original']==post['originals'][key]['original'],
                         'late_result_rewrote_original_terminal_streams_or_claim')
            put(directory,'FINAL-BUSINESS.original.json',business_raw)
            native=actor.observation.native_records(plan['scope'])
            put(directory,'FINAL-NATIVE-OBSERVATION.json',enc(native))
            return {'pre_late_fence':pre,'late_receipt_observation':late,'final_fence':post,
                    'final_business_original':business_row,'final_native_observation_sha256':sha(enc(native))}
        except (FileNotFoundError,ValueError) as error:
            last_error={'type':type(error).__name__,'detail':str(error)[:512]}
            # Once a fence name exists, any incomplete/failed finalization is
            # retained and cannot be retried under the same output names.
            if (directory/'PRE-LATE-FENCE.json').exists() and pre is None:raise
            if (directory/'POST-LATE-FENCE.json').exists() or (directory/'FINAL-FENCE.json').exists():raise
            if (directory/'LATE-RECEIPT.original.json').exists():raise
            if case_id=='NEG-07' and str(error)=='late_receipt_already_terminal_before_fence':raise
            time.sleep(min(.01,max(0,deadline-time.monotonic())))
    raise TimeoutError('bounded_final_original_observation_expired:'+str(last_error))


def execute(plan_raw,source,bundle):
    final=final_dependencies()  # before owner/path/phone reads
    plan=strict(plan_raw);owner=validate_plan(plan)
    need(plan['fault_package_sha256']==final['fault_package_sha256'],'watch_final_package_binding')
    actor,manifest=load_actor(bundle,final)
    need(os.getuid()==os.geteuid()==0 and os.readlink('/proc/1/exe')=='/system/bin/init',
         'actual_native_android_root_required')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['expected_boot'],'actual_boot_changed')
    need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'preexisting_alarm_must_not_be_overwritten')
    started=time.monotonic();deadline=started+TOTAL_SECONDS
    def expired(_n,_f):raise TimeoutError('original_fault_watch_deadline')
    previous=signal.getsignal(signal.SIGALRM);signal.signal(signal.SIGALRM,expired)
    root=BASE/'fault-watch-r10-r1'
    need(root.parent.resolve(strict=True)==root.parent,'canonical_fault_watch_parent')
    try:root.mkdir(mode=0o700)
    except FileExistsError:pass
    st=root.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700
        and root.resolve(strict=True)==root,'private_original_watch_parent')
    directory=root/plan['owner_request_sha256'];directory.mkdir(mode=0o700)
    put(directory,'PLAN.original.json',plan_raw);put(directory,'SOURCE.original.py',source)
    put(directory,'OPERATOR-MANIFEST.original.json',base64.b64decode(bundle['manifest_b64'],validate=True))
    attempted=False
    try:
        signal.setitimer(signal.ITIMER_REAL,max(.001,deadline-time.monotonic()))
        with actor.active.verified_runtime(plan['runtime_binding'],plan['expected_boot']):
            # The immutable READY binding and images are checked before the
            # one sender may act. Later phase probes use the original current()
            # checks within this same verified-runtime scope.
            armed={'schema':'hepta.physical-fault.watch-armed.v1','case_id':plan['case_id'],
                'nonce':plan['nonce'],'owner_request_sha256':plan['owner_request_sha256'],
                'watch_plan_sha256':sha(plan_raw),'watch_source_sha256':sha(source),
                'fault_package_sha256':final['fault_package_sha256'],'pid':os.getpid(),
                'started_monotonic_ns':int(started*1e9),'absolute_deadline_monotonic_ns':int(deadline*1e9),
                'phase_wait_seconds':WAIT_SECONDS,'actor_maximum_seconds':30,
                'followup_maximum_seconds':FOLLOWUP_SECONDS,'signals':0,'send_attempts':0,
                'source_only_or_synthetic':False,'automatic_retry':False}
            put(directory,'ARMED.json',enc(armed))
            wait_end=min(deadline-FOLLOWUP_SECONDS,started+WAIT_SECONDS)
            selected=None;last_error=None
            while time.monotonic()<wait_end:
                found=locate_task(owner,plan['previous_scope'])
                if found is None:
                    time.sleep(.05);continue
                if selected is None:selected=found
                need(found==selected,'observed_original_scope_or_run_changed')
                bound=actor_plan(plan,found);actor.validate_plan(bound)
                try:
                    phase=actor.task_phase(bound,owner)
                    if plan['case_id']!='NEG-04':actor.sidecar_worker(bound,phase)
                except (FileNotFoundError,ValueError) as error:
                    last_error={'type':type(error).__name__,'detail':str(error)[:512]}
                    # These are read-only probes, not calls to execute().
                    # The frozen actor's durable action namespace is untouched.
                    time.sleep(.01);continue
                actor_raw=actor.encoded(bound)
                put(directory,'ACTOR-PLAN.original.json',actor_raw)
                action_end=min(deadline,time.monotonic()+30)
                signal.setitimer(signal.ITIMER_REAL,max(.001,action_end-time.monotonic()))
                attempted=True
                result=actor.execute(bound,final['fault_package_sha256'])
                signal.setitimer(signal.ITIMER_REAL,max(.001,deadline-time.monotonic()))
                need(result['state']=='ONE_PIDFD_ACTION_RETURNED' and result['physical_case_pass'] is False,
                     'original_single_action_unknown')
                put(directory,'ACTOR-RETURN.original.json',enc(result))
                after=final_observation(directory,actor,bound,plan['case_id'],
                    min(deadline,time.monotonic()+FOLLOWUP_SECONDS))
                answer={'schema':'hepta.physical-fault.watch-result.v1',
                    'state':'ONE_FAULT_AND_FINAL_ORIGINAL_OBSERVATION_RETAINED',
                    'case_id':plan['case_id'],'nonce':plan['nonce'],'scope':bound['scope'],'run':bound['run'],
                    'sender_label':plan['sender_label'],'operator_label':plan['operation_id'],
                    'owner_request_sha256':plan['owner_request_sha256'],'actor_plan_sha256':sha(actor_raw),
                    'watch_plan_sha256':sha(plan_raw),'watch_source_sha256':sha(source),
                    'fault_package_sha256':final['fault_package_sha256'],'actor_return':result,
                    'final_observation':after,'started_monotonic_ns':int(started*1e9),
                    'finished_monotonic_ns':time.monotonic_ns(),'total_budget_seconds':TOTAL_SECONDS,
                    'phone_ui_actions':0,'task_submissions':0,'model_requests':0,'tool_dispatches':0,
                    'signal_actor_invocations':1,'automatic_retry':False,'followup_signals':0,
                    'physical_case_pass':False,'independent_original_closure_required':True}
                put(directory,'RESULT.json',enc(answer))
                return answer
            raise TimeoutError('original_phase_window_missed_zero_action:'+str(last_error))
    except BaseException as error:
        put(directory,'FAILURE.json',enc({'state':'UNKNOWN_NO_RETRY' if attempted else 'PHASE_MISSED_NO_SIGNAL',
            'case_id':plan['case_id'],'watch_plan_sha256':sha(plan_raw),'signal_path_entered':attempted,
            'error_type':type(error).__name__,'error':str(error)[:1024],
            'physical_case_pass':False,'automatic_retry':False,'followup_signals':0,
            'remote_cleanup_proven':False}))
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-watch-once',action='store_true')
    args=parser.parse_args()
    if not args.execute_watch_once:
        print(enc({'state':'SOURCE_PREVIEW_NO_PHONE_READ','cases':CASE_IDS,'phone_calls':0,
            'signals':0,'final_dependencies_frozen':FINAL_DEPENDENCIES is not None}).decode(),end='')
        return 0
    final_dependencies()
    packet=globals().get('_REVIEWED_PACKET');source=globals().get('_REVIEWED_SOURCE_BYTES')
    need(type(packet) is dict and type(source) is bytes and 0<len(source)<=65536,
         'exact_reviewed_watch_source_packet')
    raw=base64.b64decode(packet['plan_b64'],validate=True)
    need(0<len(raw)<=65536 and sha(raw)==packet['plan_sha256'] and sha(source)==packet['source_sha256'],
         'exact_reviewed_watch_plan_and_source')
    answer=execute(raw,source,packet['operator_bundle'])
    print(enc(answer).decode(),end='')
    return 0


if __name__=='__main__':raise SystemExit(main())
