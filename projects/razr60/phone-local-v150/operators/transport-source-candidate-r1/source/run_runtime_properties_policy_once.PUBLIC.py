# PUBLIC REVIEW PROJECTION. Not private original bytes or an executable package.
# Operational paths, identities and private runtime bindings are required placeholders.
#!/usr/bin/env python3
"""One Root policy transaction; no native case nonce and no automatic replay.

The immutable plan and pre-live expectation are fsynced before any phone phase.
Every actual phase uses the reviewed r4-derived transport. Original phone_once
semantics and the closed04 validation namespace are preserved. Unknown work
must be reconciled under its original operation identity before continuation.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import types

B=Path('/REQUIRED_PRIVATE_WORKSPACE')
BOOT='REQUIRED_PRIVATE_BOOT_ID_001'
NONCE='REQUIRED_PRIVATE_NONCE_001'
ORIGINAL_TRANSPORT_SOURCE=B/'REQUIRED_PRIVATE_ORIGINAL_R4_SOURCE.py'
ORIGINAL_TRANSPORT_SHA='REQUIRED_PRIVATE_SHA256_013'
TRANSPORT_SOURCE=Path(__file__).resolve().parent.parent/'reference/REQUIRED_PRIVATE_FIXED_R4_SOURCE.py'
TRANSPORT_SHA='REQUIRED_PRIVATE_SHA256_015'
TRANSPORT_BYTES=51032
TRANSPORT_PLAN=B/'REQUIRED_PRIVATE_CLOSED04_PLAN.json'
TRANSPORT_PLAN_SHA='REQUIRED_PRIVATE_SHA256_014'
OUT=B/'REQUIRED_PRIVATE_POLICY_OUTPUT'
NATIVE_CODE='/REQUIRED_PRIVATE_NATIVE_CODE'
GNU_CODE='/REQUIRED_PRIVATE_GNU_CODE'
HERE=Path(__file__).resolve().parent
HASH=re.compile('[0-9a-f]{64}\\Z')

def need(value,message):
    if not value:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
    def pairs(rows):
        out={}
        for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def load_transport():
    raw=TRANSPORT_SOURCE.read_bytes()
    need(len(raw)==TRANSPORT_BYTES and sha(raw)==TRANSPORT_SHA,'reviewed r4 transport repair source differs')
    sys.dont_write_bytecode=True
    module=types.ModuleType('reviewed_r4_transport_fixed')
    module.__file__=str(TRANSPORT_SOURCE)
    exec(compile(raw,str(TRANSPORT_SOURCE),'exec'),module.__dict__)
    need(module.read(TRANSPORT_SOURCE)==raw,'transport repair source changed')
    original=module.read(ORIGINAL_TRANSPORT_SOURCE)
    need(len(original)==43438 and sha(original)==ORIGINAL_TRANSPORT_SHA,
         'original closed04 transport source differs')
    need(module.read(HERE.parent/'reference/run_component_root_once.r4.original.py')==original,
         'retained r4 transport original differs')
    # The closed04 plan binds the old coordinator's exact package and namespace.
    # Preserve that read-only validation anchor; source provenance remains the
    # explicitly pinned repaired reference above. No old source or pin is changed.
    module.HERE=ORIGINAL_TRANSPORT_SOURCE.parent
    module.__reviewed_source_path__=str(TRANSPORT_SOURCE)
    module.__reviewed_source_sha256__=TRANSPORT_SHA
    module.__legacy_validation_source_path__=str(ORIGINAL_TRANSPORT_SOURCE)
    return module,raw

def validate(m,raw):
    p=strict(raw)
    fields={'schema','boot_id','prepared','stage_requests','apply_request','binding',
        'pre_live_expectation','capture_source','verifier_source','transport_root_plan',
        'source_package','driver_source','out'}
    need(isinstance(p,dict) and set(p)==fields and p['schema']=='hepta.root.runtime-properties-live-plan.v1'
         and p['boot_id']==BOOT and p['out']==str(OUT),'exact Root policy plan differs')
    sources=strict(m.pin(p['source_package']))
    need(sources['schema']=='hepta.root.runtime-properties-live-source-package.v1'
         and Path(p['source_package']['path']).parent==HERE.parent
         and {r['path'] for r in sources['files']}=={
             'source/run_runtime_properties_policy_once.py','reference/run_component_root_once.r4.original.py',
             'reference/run_component_root_once.r4.transport_fixed.py'}
         and len(sources['files'])==3,'exact reviewed Root policy source package required')
    for row in sources['files']:
        source=m.read(HERE.parent/row['path'])
        need(len(source)==row['bytes'] and sha(source)==row['sha256'],'Root driver source changed')
    need(p['driver_source']['path']==str(HERE/'run_runtime_properties_policy_once.py')
         and m.pin(p['driver_source'])==m.read(HERE/'run_runtime_properties_policy_once.py'),
         'explicit current driver original differs')
    need(m.read(HERE.parent/'reference/run_component_root_once.r4.original.py')==m.read(ORIGINAL_TRANSPORT_SOURCE),
         'reviewed original transport reference differs')
    need(m.read(HERE.parent/'reference/run_component_root_once.r4.transport_fixed.py')==m.read(TRANSPORT_SOURCE)
         and m.__reviewed_source_path__==str(TRANSPORT_SOURCE) and m.__reviewed_source_sha256__==TRANSPORT_SHA
         and m.__legacy_validation_source_path__==str(ORIGINAL_TRANSPORT_SOURCE)
         and m.HERE==ORIGINAL_TRANSPORT_SOURCE.parent,
         'reviewed repaired transport or original validation namespace differs')
    need(p['transport_root_plan']=={'path':str(TRANSPORT_PLAN),'bytes':4715,'sha256':TRANSPORT_PLAN_SHA},
         'only the original closed04 transport namespace is authorized')
    original=m.pin(p['transport_root_plan']);transport_plan,_=m.validate_plan(original)
    need(transport_plan['nonce']==NONCE,'no new native nonce may be created')
    prepared_raw=m.pin(p['prepared']);prepared=strict(prepared_raw)
    need(prepared['schema']=='hepta.runtime-properties-r10.live-host-preparation.v1'
         and prepared['state']=='ACTUAL_INPUTS_BOUND_HOST_PREPARED_NOT_EXECUTED'
         and prepared['phone_calls']==prepared['policy_apply_attempts']==0
         and prepared['automatic_retry'] is False and prepared['automatic_rollback'] is False
         and prepared['policy_adoption_authorized'] is False,'actual reviewed preparation required')
    need(p['stage_requests']==prepared['stage_requests'] and p['apply_request']==prepared['apply_request'],
         'Root requests do not belong to the exact prepared transaction')
    binding_raw=m.pin(p['binding']);binding=strict(binding_raw)
    need({k:p['binding'][k] for k in ('bytes','sha256')}==prepared['binding'],
         'Root plan binding differs from actual preparation')
    verifier_raw=m.pin(p['verifier_source'])
    need({k:p['verifier_source'][k] for k in ('bytes','sha256')}==binding['verifier_source'],
         'Root verifier is not the actual bound verifier source')
    verifier=types.ModuleType('reviewed_root_runtime_properties_live_verifier')
    verifier.__file__=p['verifier_source']['path'];verifier.__reviewed_source_sha256__=sha(verifier_raw)
    exec(compile(verifier_raw,verifier.__file__,'exec'),verifier.__dict__)
    expectation_raw=m.pin(p['pre_live_expectation'])
    expectation=verifier.verify_pre_live_expectation(expectation_raw,read_pinned=m.pin)
    need(expectation['binding']==p['binding'] and expectation['boot_id']==BOOT,
         'predeclared policy expectation belongs to another transaction')
    stages=strict(m.pin(p['stage_requests']))
    need(isinstance(stages,list) and 2<=len(stages)<=9,'one to eight stage parts plus final required')
    wanted=['runtimeprops-stage-'+str(i).zfill(2) for i in range(len(stages)-1)]+['runtimeprops-stage-final']
    need([r['phase'] for r in stages]==wanted and all(set(r)=={'phase','request'} for r in stages),
         'fixed stage request order or fields differ')
    requests=[]
    for row in stages:
        request_raw=m.pin(row['request']);request=strict(request_raw)
        need(set(request)=={'kind','root','timeout_seconds','command'} and request['kind']=='shell'
             and request['root'] is True and type(request['timeout_seconds']) is int
             and request['timeout_seconds']==40 and isinstance(request['command'],str),
             'exact reviewed bounded stage shell request required')
        need(len(('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(request['command'])).encode())<65536,
             'stage request exceeds the actual ADB service limit')
        requests.append((row['phase'],row['request'],request_raw,request))
    apply_raw=m.pin(p['apply_request']);apply=strict(apply_raw)
    wanted_command='/data/adb/magisk/busybox sh '+NATIVE_CODE+'/apply_runtime_properties_once.sh --execute-reviewed-single-runtime-properties-apply '+p['binding']['sha256']
    need(set(apply)=={'kind','root','timeout_seconds','command'} and apply['kind']=='shell'
         and apply['root'] is True and type(apply['timeout_seconds']) is int
         and apply['timeout_seconds']==240 and apply['command']==wanted_command,
         'the sole live apply command differs')
    m.pin(p['capture_source'])
    return p,transport_plan,requests,(apply_raw,apply),verifier

def exact_phase_operation(m,out,phase):
    directory=out/('phone-'+phase)
    result=strict(m.read(directory/'RESULT.json'))
    need(result['state']=='ORIGINAL_HOST_CHILD_JOINED'
         and type(result['returncode']) is int and result['returncode']==0
         and result['automatic_retry'] is False,'original phase is not authoritatively joined')
    operation_raw=m.pin(result['stdout'])
    need(m.pin(result['stderr'])==b'','original host phase stderr is not clean')
    operation=strict(operation_raw)
    need(set(operation)=={'actor_rc','wrapper_sha256','wrapper'}
         and type(operation['actor_rc']) is int,'original operation fields differ')
    wrapper=operation['wrapper'];phone=wrapper.get('phone')
    need(isinstance(phone,dict) and type(phone.get('rc')) is int and isinstance(phone.get('stdout'),str)
         and isinstance(phone.get('stderr'),str),'original phone command result is incomplete')
    return operation_raw,operation,result['stdout']

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--execute-root-runtime-properties-policy-once',action='store_true')
    a=parser.parse_args(argv);need(HASH.fullmatch(a.plan_sha256),'explicit plan hash required')
    m,_source=load_transport();raw=m.read(a.plan)
    need(sha(raw)==a.plan_sha256,'Root policy plan bytes differ')
    p,transport_plan,requests,apply_pair,verifier=validate(m,raw)
    if not a.execute_root_runtime_properties_policy_once:
        print(json.dumps({'state':'HOST_PREVIEW_NO_PHONE_NO_POLICY_APPLY','plan_sha256':sha(raw),
            'phone_calls':0,'policy_apply_calls':0,'new_native_case_nonces':0},sort_keys=True));return 0
    os.umask(0o077);m.newdir(OUT);m.put(OUT/'ROOT-POLICY-PLAN.original.json',raw)
    root_plan=m.filedesc(OUT/'ROOT-POLICY-PLAN.original.json')
    intent={'schema':'hepta.root.runtime-properties-live-intent.v1','state':'ONE_EXPLICIT_POLICY_APPLY_DECLARED_BEFORE_PHONE_PHASES',
        'plan_sha256':sha(raw),'pre_live_expectation':p['pre_live_expectation'],'binding':p['binding'],
        'source_package':p['source_package'],'driver_source':p['driver_source'],'verifier_source':p['verifier_source'],
        'maximum_apply_attempts':1,'automatic_retry':False,'automatic_rollback':False,
        'automatic_policy_adoption':False,'new_native_case_nonces':0,'native_case_sends':0}
    m.put(OUT/'ROOT-LIVE-INTENT.json',encode(intent));intent_row=m.filedesc(OUT/'ROOT-LIVE-INTENT.json')
    c=m.Chain.__new__(m.Chain);c.p=transport_plan;c.out=OUT;c.steps=[]
    c.remote_root='/REQUIRED_PRIVATE_HOST_HOME/codex-native-guard-chain-r10-r1/'+NONCE
    phases=[];apply_calls=0
    try:
        # Repeat the pure pins after creating the durable intent, before any phone call.
        verifier.verify_pre_live_expectation(m.pin(p['pre_live_expectation']),read_pinned=m.pin)
        need(m.pin(p['pre_live_expectation'])==m.pin(intent['pre_live_expectation'])
             and m.pin(p['binding'])==m.pin(intent['binding']),'live intent originals changed')
        for phase,row,request_raw,request in requests:
            need(m.pin(row)==request_raw,'stage request changed after plan admission')
            m.put(OUT/(phase+'.REQUEST.original.json'),request_raw)
            phases.append(phase);c.phone(phase,request)
        apply_raw,apply=apply_pair
        need(m.pin(p['apply_request'])==apply_raw,'single apply request changed after stage')
        verifier.verify_pre_live_expectation(m.pin(p['pre_live_expectation']),read_pinned=m.pin)
        m.put(OUT/'runtimeprops-live-apply.REQUEST.original.json',apply_raw)
        phases.append('runtimeprops-live-apply');apply_calls+=1
        apply_error=None
        try:c.phone('runtimeprops-live-apply',apply)
        except Exception as error:apply_error={'type':type(error).__name__,'message':str(error)[:1024]}
        # A known nonzero original may already contain a complete failure export.
        # Unknown/no-final originals fail here; no new key repeats the apply.
        operation_raw,operation,operation_row=exact_phase_operation(m,OUT,'runtimeprops-live-apply')
        need(operation['wrapper']['phone']['stdout'].lstrip().startswith('{'),
             'original apply produced no structured export; reconcile original stderr without replay')
        output=strict(operation['wrapper']['phone']['stdout'].encode('utf-8'))
        need(isinstance(output,dict) and set(output)=={'report','export'},'actual apply did not export complete original records')
        export=output['export']
        need(export['state']=='ORIGINAL_EXPORT_COMPLETE' and export['binding_sha256']==p['binding']['sha256'],
             'actual original export identity differs')
        wrapper_remote='/REQUIRED_PRIVATE_HOST_HOME/razr60-local-model-v150/operations/ng-'+NONCE+'-runtimeprops-live-apply/result.json'
        got=c.remote_read('runtimeprops-wrapper-original',{'actor_wrapper':wrapper_remote})
        wrapper=got['files']['actor_wrapper']
        wrapper_raw=base64.b64decode(wrapper['base64'],validate=True)
        need(len(wrapper_raw)==wrapper['bytes'] and sha(wrapper_raw)==wrapper['sha256']==operation['wrapper_sha256']
             and strict(wrapper_raw)==operation['wrapper'],'independent actor wrapper raw differs')
        m.put(OUT/'ACTOR-WRAPPER.original.json',wrapper_raw);wrapper_row=m.filedesc(OUT/'ACTOR-WRAPPER.original.json')
        chunks=[]
        need(type(export['archive']['bytes']) is int and 0<export['archive']['bytes']<=8*1024*1024
             and HASH.fullmatch(export['archive']['sha256']),'bounded original archive required')
        if export['inline_archive'] is True:
            need(isinstance(export['archive_gzip_base64'],str),'inline actual original archive absent')
            archive=base64.b64decode(export['archive_gzip_base64'],validate=True)
            need(len(archive)==export['archive']['bytes'] and sha(archive)==export['archive']['sha256'],
                 'inline original archive bytes differ')
        else:
            need(export['inline_archive'] is False and export['archive_gzip_base64'] is None
                 and export['read_chunk_bytes']==524288,'fixed chunk-only original export required')
            count=(export['archive']['bytes']+524287)//524288
            need(1<=count<=16,'original archive chunk count')
            parts=[]
            for index in range(count):
                phase='runtimeprops-export-'+str(index).zfill(2)
                command=m.ENV+'/usr/bin/python3 -I -B '+GNU_CODE+'/guard_live_runtime_properties.py --binding-sha256 '+p['binding']['sha256']+' --export-chunk-read-only '+str(index)
                phases.append(phase)
                c.phone(phase,{'kind':'shell','root':True,'timeout_seconds':40,'command':command})
                chunk_operation_raw,chunk_operation,_row=exact_phase_operation(m,OUT,phase)
                chunk_raw=chunk_operation['wrapper']['phone']['stdout'].encode('utf-8');chunk=strict(chunk_raw)
                need(chunk['schema']=='hepta.runtime-properties-r10.original-export-chunk.v1'
                     and chunk['binding_sha256']==p['binding']['sha256'] and chunk['archive']==export['archive']
                     and chunk['index']==index and chunk['offset']==index*524288,
                     'original export chunk identity or order differs')
                piece=base64.b64decode(chunk['base64'],validate=True)
                need(len(piece)==chunk['bytes']==min(524288,export['archive']['bytes']-index*524288)
                     and sha(piece)==chunk['sha256'],'original chunk bytes differ')
                path=OUT/(phase+'.PHONE-STDOUT.original.json');m.put(path,chunk_raw)
                chunks.append(m.filedesc(path));parts.append(piece)
            archive=b''.join(parts)
            need(len(archive)==export['archive']['bytes'] and sha(archive)==export['archive']['sha256'],
                 'complete original archive differs')
        capture_argv=['/usr/bin/python3','-I','-B',p['capture_source']['path'],
            '--prepared',p['prepared']['path'],'--prepared-sha256',p['prepared']['sha256'],
            '--original-operation',operation_row['path'],'--original-operation-sha256',operation_row['sha256'],
            '--actor-wrapper',wrapper_row['path'],'--actor-wrapper-sha256',wrapper_row['sha256']]
        for row in chunks:capture_argv+=['--chunk-file',row['path'],'--chunk-sha256',row['sha256']]
        capture_argv+=['--out',str(OUT/'capture'),'--execute-host-capture']
        m.pin(p['capture_source']);c.execute_process('runtimeprops-host-capture',capture_argv,120)
        captured=m.filedesc(OUT/'capture/HOST-CAPTURE.json');capture=strict(m.pin(captured))
        clean=(apply_error is None and operation['actor_rc']==0 and operation['wrapper']['phone']['rc']==0
               and capture['clean_apply_observed'] is True)
        execution={'schema':'hepta.root.runtime-properties-live-execution.v1',
            'state':'ORIGINAL_POLICY_APPLY_CAPTURED_PENDING_INDEPENDENT_COMPARISON' if clean else 'FAILED_POLICY_APPLY_CAPTURED_NO_ADOPTION',
            'root_plan':root_plan,'root_intent':intent_row,'prepared':p['prepared'],'binding':p['binding'],
            'pre_live_expectation':p['pre_live_expectation'],'source_package':p['source_package'],'driver_source':p['driver_source'],
            'verifier_source':p['verifier_source'],'capture_source':p['capture_source'],
            'original_operation':operation_row,'actor_wrapper':wrapper_row,'host_capture':captured,
            'stage_phase_count':len(requests),'policy_apply_calls':apply_calls,
            'policy_apply_phase':'runtimeprops-live-apply','phone_phase_names':phases,'phone_calls':len(phases),
            'steps':c.steps,'automatic_retry':False,'automatic_rollback':False,
            'automatic_policy_adoption':False,'new_native_case_nonces':0,'native_case_sends':0,
            'known_apply_error':apply_error}
        m.put(OUT/'ROOT-EXECUTION.json',encode(execution))
        print(json.dumps({'state':execution['state'],'root_execution':m.filedesc(OUT/'ROOT-EXECUTION.json'),
            'host_capture':captured,'policy_apply_calls':apply_calls,'phone_calls':len(phases),
            'new_native_case_nonces':0,'native_case_sends':0},sort_keys=True))
        return 0 if clean else 2
    except BaseException as error:
        host_cleanup=c.close_owned_host_outputs()
        m.put(OUT/'ROOT-FAILURE.json',encode({'schema':'hepta.root.runtime-properties-live-failure.v1',
            'host_cleanup':host_cleanup,
            'state':'ORIGINAL_TRANSACTION_STOPPED_NO_REPLAY','error_type':type(error).__name__,
            'detail':str(error)[:2048],'root_plan':root_plan,'root_intent':intent_row,
            'policy_apply_calls':apply_calls,'phone_phase_names':phases,'steps':c.steps,
            'automatic_retry':False,'automatic_rollback':False,'automatic_policy_adoption':False,
            'new_native_case_nonces':0,'native_case_sends':0}))
        raise

if __name__=='__main__':
    raise SystemExit('PUBLIC_SOURCE_PROJECTION_REVIEW_ONLY_NOT_INSTALLABLE')
