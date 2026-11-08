#!/usr/bin/env python3
"""Prepare one fresh component plan after a complete successful R6 host freeze."""
import argparse,copy,hashlib,json,os,re,secrets,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
FROZEN=B/'native-guard-r10-r1-operator-fc33-native-v3-r7'
HELPER={'path':str(B/'library-checkpoint02-resume-a1055-r1/restored/integration-review/diagnostic-root-plan-candidate01/source/prepare_diagnostic_root_plan_once.py'),'bytes':35690,'sha256':'4708d037d58fd5b40e2a15210887ce58d9e7d0857ef27057855031591ee7faf9'}
LABELS={'NEG-01': 'root-r10-neg01-fc33-r7-bound01', 'NEG-02': 'root-r10-neg02-fc33-r7-bound01'}
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
# Bind only after Root reads the original complete controller terminal.
FROZEN_INPUTS = {'freeze': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r7/FREEZE-RESULT.json', 'bytes': 1213628, 'sha256': '09f3eeb868be814aad1e019a9bd8c1b70c8564019345fad4934db03d9ca93928'}, 'source': {'bytes': 22897, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r7-review01/freeze_native_bound_runtime_r7_fc33.py', 'sha256': '54f2ff21867000eeba39a8745d9f5ab1a6f989163028fb4f653f16b5cc77d3f5'}, 'controller': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-runtime-r7-review01/R7-FREEZE-CONTROLLER-ORIGINALS.json', 'bytes': 8793, 'sha256': '83d32fa4a2210404a6043ff9e70289da5ea6c8ba90448b5186e7b9e55a624b94'}}
KEYS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def need(v,s):
    if not v:raise ValueError(s)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def meta(v):return [getattr(v,k)for k in KEYS]
def exact3(row):return {k:row[k]for k in ('path','bytes','sha256')}
def initial(row):
    p=Path(row['path']);need(p.is_absolute()and p.resolve(strict=True)==p,'canonical helper original')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==row['bytes'],'complete exact helper original')
        with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(row['bytes']+1)
        need(pin(raw)=={k:row[k]for k in ('bytes','sha256')}and meta(a)==meta(os.fstat(fd))==meta(p.lstat()),'helper full9 and SHA bookends');return raw
    finally:os.close(fd)
def module(raw,name,path):
    m=types.ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m

def controller_value(h,value):
    need(type(value)is dict and value.get('isError')is False and type(value.get('content'))is list
         and len(value['content'])==1 and value['content'][0].get('type')=='text','complete original controller text envelope')
    return h.strict(value['content'][0]['text'])

def verify_controller(h,o,f,freeze_row):
    carrier=h.strict(o.read(FROZEN_INPUTS['controller']))
    need(carrier['schema']=='hepta.fc33.actual-runtime-freeze-controller-originals.v1'
         and set(carrier)=={'schema','request','start','status','read'},'all four original freeze controller records')
    request=carrier['request'];start=controller_value(h,carrier['start']);status=controller_value(h,carrier['status']);read=controller_value(h,carrier['read'])
    expected_args=[f['source']['path'],'--freeze-reviewed-host-runtime',f['source']['sha256']]
    need(request['host']=='mac'and request['executable']=='/usr/bin/python3'and request['args']==expected_args
         and request['idempotency_key']=='fc33-native-bound-runtime-r7-freeze-once01',
         'actual controller must have executed this exact frozen source once')
    job=start['job'];need(start['reused']is False and job['host']=='mac'and job['executable']==request['executable']
         and job['args']==request['args']and job['idempotency_key']==request['idempotency_key']
         and job['launch_error']is None and job['launch_state']=='launched'
         and job['id']==status['job_id']==read['job_id'],'same original launch and terminal identity')
    need(status['state']=='succeeded'and type(status['exit_code'])is int and status['exit_code']==0
         and status['cancelled']is status['timed_out']is status['automatic_retry']is False
         and status['output_complete']is status['output_durable']is status['terminal_publication_confirmed']is True,
         'complete successful original freeze terminal required')
    streams={}
    for name in ('stdout','stderr'):
        row=read[name];log=status['log_bytes'][name]
        need(type(row['bytes_hex'])is str and re.fullmatch('(?:[0-9a-f]{2})*',row['bytes_hex'])is not None,'canonical full output hex')
        raw=bytes.fromhex(row['bytes_hex']);n=len(raw)
        need(all(type(x)is int for x in (row['offset'],row['next_offset'],row['size'],log['seen'],log['stored']))
             and row['offset']==0 and row['next_offset']==row['size']==log['seen']==log['stored']==n
             and row['eof']is True and status['log_truncated'][name]is False
             and status['log_synced'][name]is True and status['log_errors'][name]is None,
             'one complete durable controller stream and exact byte counts')
        streams[name]=raw
    need(streams['stderr']==b''and streams['stdout'].endswith(b'\n'),'successful complete original freeze output')
    summary=h.strict(streams['stdout'])
    need(summary['state']==f['state']and summary['freeze']==freeze_row
         and summary['runtime_manifest']==f['runtime_manifest']and summary['root_chain_manifest']==f['root_chain_manifest']
         and summary['combination']==f['combination']and summary['complete_directory_bytes']==f['complete_directory_bytes']
         and type(summary['phone_calls'])is int and summary['phone_calls']==0 and summary['full19_qualified']is False,
         'actual complete freeze stdout must bind these exact final files')
    return {'job_id':job['id'],'actual_controller':FROZEN_INPUTS['controller'],
        'exit_code':0,'both_streams_eof':True,'automatic_retry':False,'all_terminal_copies_required':True}

def verify_tree(expected):
    found=set();directories=[]
    def walk(p):
        first=p.lstat();need(stat.S_ISDIR(first.st_mode)and stat.S_IMODE(first.st_mode)==0o700 and p.resolve(strict=True)==p,'canonical private frozen directory')
        names=sorted(os.listdir(p));directories.append((p,meta(first),names))
        for name in names:
            q=p/name;s=q.lstat()
            if stat.S_ISDIR(s.st_mode):walk(q)
            else:
                need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'complete private single-link freeze member')
                found.add(str(q.relative_to(FROZEN)))
    walk(FROZEN)
    need(found==set(expected)and len(found)<=256 and len(directories)<=129,'no unknown or omitted frozen members')
    for p,before,names in directories:need(meta(p.lstat())==before and sorted(os.listdir(p))==names,'frozen directory generation or members changed')

def verify_freeze(h,o):
    row=FROZEN_INPUTS['freeze'];need(row['path']==str(FROZEN/'FREEZE-RESULT.json'),'one exact actual freeze namespace')
    raw=o.read(row);f=h.strict(raw)
    need(f['schema']=='hepta.fc33.native-bound.actual-host-freeze.v1'and f['state']=='FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED'
         and f['source']==FROZEN_INPUTS['source']and f['output']==str(FROZEN)
         and all(type(f[k])is int and f[k]==0 for k in ('phone_calls','native_submissions','new_nonces'))
         and f['full19_qualified']is f['production_ready']is False and f['automatic_retry']is False
         and f['rollback_admission_is_separate_required_gate']is True,'actual source-only current freeze')
    need(o.read(f['source'])==o.read(f['files']['FREEZER-SOURCE.original.py']),'exact source actually executed and retained')
    need(o.read({'path':str(FROZEN/'DERIVATION.json'),**pin(raw)})==raw,'terminal-last DERIVATION must exactly equal FREEZE-RESULT')
    transport=verify_controller(h,o,f,row)
    for name,item in f['actual_input_files'].items():
        need(name==item['path']and set(item)=={'path','bytes','sha256','metadata'},'exact original frozen input record')
        o.read(exact3(item));need(o.rows[name]==item,'frozen original input no longer has its actual nine-field generation')
    files={}
    for name,item in f['files'].items():
        p=Path(name);need(not p.is_absolute()and str(p)==name and '..'not in p.parts and item['path']==str(FROZEN/p),'exact frozen relative namespace')
        files[name]=o.read(item)
    need(f['result_bytes']==len(raw)and f['terminal_copies']==2
         and sum(map(len,files.values()))==f['payload_bytes']
         and f['payload_bytes']+2*len(raw)==f['complete_directory_bytes']<=33554432,
         'complete frozen payload and both terminal copies byte accounting')
    verify_tree(set(files)|{'FREEZE-RESULT.json','DERIVATION.json'})
    for name,count,key in [('runtime/MANIFEST.json',38,'runtime_manifest'),('root-chain/SOURCE-MANIFEST.json',3,'root_chain_manifest'),('shared/SHARED-MATERIALS.json',17,'shared_materials')]:
        m=h.strict(files[name]);rows=m['files'];need(f[key]==f['files'][name]and len(rows)==len({r['path']for r in rows})==count,'actual frozen manifest cardinality')
        for member in rows:need(pin(files[str(Path(name).parent/member['path'])])=={k:member[k]for k in ('bytes','sha256')},'actual complete manifest member')
    need(f['combination']==f['files']['COMBINATION.json']and f['checks']==h.strict(files['HOST-VALIDATION.json'])
         and f['checks']['source_parent_current_credit']is False and f['checks']['historical_failed_count']==9
         and f['checks']['source_parent_count']==1 and f['checks']['fresh_phone_admission_required']is True,
         'whole source/history context without inherited current credit')
    package=h.strict(files['runtime/MANIFEST.json']);root=h.strict(files['root-chain/SOURCE-MANIFEST.json'])
    need(package['current_combination_sha256']==root['current_combination_sha256']==f['combination']['sha256']
         and package['source_parent_records']==h.strict(files['SOURCE-PARENT-RECORDS.json']),
         'one exact current tuple and retained source parent')
    entry=f['files']['root-chain/source/run_component_root_once.py'];need(h.literal(files['root-chain/source/run_component_root_once.py'],'PKG')==f['runtime_manifest']['sha256'],'actual root package constant')
    return f,files,entry,transport

ADMISSION_SOURCE_PINS={'build_fence_plan': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r7/dependencies/admission/build_fence_plan.py', 'bytes': 8645, 'sha256': '7089b91b3c1cb93fbca6c3cee28f339819ed9e438d76c8f21004adae31c33313'}, 'bound02_disposition': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r7/dependencies/admission/bound02_disposition.py', 'bytes': 71658, 'sha256': '7c92196717e5bcb8eb4e094b8b7317fee17197cf52e917e6f9e17eaa439281a1'}, 'admission_entry': {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r7/dependencies/admission/admission_entry.py', 'bytes': 7170, 'sha256': '54f4a05b2935c2befba6f775171894bb5cce05afe38fb74af0ca81ddb4b3f223'}}

def load_original_admission():
    # Every import in the three-source closure is pinned before it is executed.
    import sys,types,stat
    keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    verified={}
    for name in ('build_fence_plan','bound02_disposition','admission_entry'):
        row=ADMISSION_SOURCE_PINS[name];path=Path(row['path'])
        if not (path.is_absolute() and path.resolve(strict=True)==path):
            raise ValueError('canonical exact admission source required')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            if not (stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes']):
                raise ValueError('admission source identity/size differs')
            with os.fdopen(fd,'rb',closefd=False)as stream:raw=stream.read(row['bytes']+1)
            after=os.fstat(fd);named=path.lstat()
            if not (len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'] and
                    all(getattr(before,k)==getattr(after,k)==getattr(named,k)for k in keys)):
                raise ValueError('admission source byte/full9 bookend differs')
        finally:os.close(fd)
        verified[name]=(path,raw)
    for name,(path,raw)in verified.items():
        module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
        exec(compile(raw,str(path),'exec'),module.__dict__)
    return sys.modules['admission_entry']

def require_original_attempt_admission(stage,selected=None):
    entry=load_original_admission()
    context=None if selected is None else entry.preparation_context(selected)
    return entry.require_original_admission(stage,context)


def selected_context(h,o,args):
    require_original_attempt_admission('preparer-selected-context')
    f,files,entry,transport=verify_freeze(h,o)
    label=LABELS[args.case];directory,out=h.require_unused(label)
    previous_row={'path':args.previous,'bytes':args.previous_bytes,'sha256':args.previous_sha256}
    previous_raw=o.read(previous_row);previous=h.strict(previous_raw);home=Path(previous_row['path']).parent
    need(Path(previous_row['path'])==home/'ACTUAL-PREVIOUS-INPUT.json'and home.parent==B/'native-guard-root-chains-r10-r1'
         and previous['known_all_dispatched_tools_confirmed_terminal']is True,'actual completed predecessor standard namespace')
    record=h.strict(files['SOURCE-PARENT-RECORDS.json'])[0]
    if args.case=='NEG-01':need(previous_row==record['closed_previous'],'new first case must follow exact reviewed source-parent head')
    else:need(home.name==LABELS['NEG-01'],'second new case must follow this exact new first case')
    parent_raw=o.raw(home/'ROOT-PLAN.original.json',1048576);parent=h.strict(parent_raw)
    need(parent['case_id']=='NEG-01'and parent['boot_id']==BOOT and parent['live_policy_sha256']==f['actual_policy']['sha256']
         and previous['identity']['session_id']==parent['session_id']and previous['identity']['profile_id']=='owner-open'
         and previous['component_qualified']is True and previous['terminal']=={'status':'completed'},
         'actual qualified predecessor and unchanged boot/policy/session required')
    if args.case=='NEG-01':
        need(previous['late_boundary']==record['boundary']and previous['identity']==record['scope'],'exact source-parent outcome and native scope')
    else:
        need(parent['package']==f['runtime_manifest']and parent['source_package']==f['root_chain_manifest']
             and parent['policy_adoption']==f['actual_adoption'],'same final tuple current qualified NEG01 required')
    owner=o.read(parent['request']);need(len(owner)==317 and owner.count(parent['nonce'].encode())==1 and b'\0'not in owner,'exact retained public owner request')
    boundary_raw=o.raw(home/'LATE-BOUNDARY.original.json',16777216);descriptor_raw=o.raw(home/'LATE-BOUNDARY-DESCRIPTOR.json',1048576)
    descriptor=h.strict(descriptor_raw);boundary=h.strict(boundary_raw)
    need(previous['late_boundary']==descriptor and {k:descriptor[k]for k in ('bytes','sha256')}==pin(boundary_raw)
         and boundary['nonce']==parent['nonce']and boundary['scope']==previous['identity'],'complete actual prior boundary identity')
    admission_row={'path':args.original_attempt_admission,'bytes':args.original_attempt_admission_bytes,'sha256':args.original_attempt_admission_sha256}
    admission_raw=o.read(admission_row);admission_value=h.strict(admission_raw)
    need(set(admission_value)=={'schema','resolution','fresh_observation'} and
        admission_value['schema']=='hepta.r6.bound02.admission-operator-input.v1' and
        admission_value['resolution']==load_original_admission().RESOLUTION,'same typed original disposition input')
    updates={'original_attempt_admission':admission_row,'case_id':args.case,'package':f['runtime_manifest'],'source_package':f['root_chain_manifest'],
        'shared_materials':f['shared_materials'],'shared_root':str(FROZEN/'shared'),'artifacts':f['files']['ARTIFACTS.json'],
        'policy_adoption':f['actual_adoption'],'live_policy_sha256':f['actual_policy']['sha256'],'previous':previous_row,
        'prior_boundary_descriptor':{'path':str(home/'LATE-BOUNDARY-DESCRIPTOR.json'),**pin(descriptor_raw)},
        'prior_boundary_original':{'path':str(home/'LATE-BOUNDARY.original.json'),**pin(boundary_raw)}}
    nonces=set(h.CONSUMED_NONCES)|{parent['nonce']}
    for name,raw in files.items():
        if re.fullmatch(r'retained-(?:history/native-\d\d|source-parent/\d\d)/boundary.original.json',name):nonces.add(h.strict(raw)['nonce'])
    manifest=h.strict(files['runtime/MANIFEST.json'])
    nonces.update(b['nonce']for b in manifest['non_native_sidebranches']);nonces.add(manifest['retained_unstarted_stage']['nonce'])
    nonces.add('660f586740b3d85d68c053f54a21e059')
    nonces.update({'e2fdaccd43cec9da1df4d77783db8fdb','9b37081161d7bcbc3adf76d2e6ec7841','4fce1e327941e723a4f1d4c838acf684','5f94c6a88805eefb0e2320cae5265d46','731dc46ccaad6e5717306d0c5f029a82'})
    return {'directory':directory,'out':out,'parent':parent,'parent_raw':parent_raw,'owner':owner,
        'freeze':f,'outputs':files,'entry':entry,'root_raw':files['root-chain/source/run_component_root_once.py'],
        'updates':updates,'prior_descriptor':descriptor,'selected_label':label,'consumed_nonces':nonces,
        'actual_previous':previous_row,'case_id':args.case,'freeze_controller':transport}

def create(h,o,c,source,source_raw,preview):
    require_original_attempt_admission('prepare-before-create',c)
    directory,out=h.require_unused(c['selected_label']);need((directory,out)==(c['directory'],c['out']),'fresh selected namespaces unchanged')
    o.recheck();os.umask(0o077);h.reserve(directory);attempts=0;generated=0
    try:
        h.put(directory/'GENERATION-INTENT.json',h.enc({'schema':'hepta.fc33.component-plan-intent.v1','source':source,
            'freeze':FROZEN_INPUTS['freeze'],'freeze_controller':FROZEN_INPUTS['controller'],'case_id':c['case_id'],
            'label':c['selected_label'],'actual_previous':c['actual_previous'],'maximum_nonce_generations':1,'phone_calls':0,'automatic_retry':False}))
        attempts=1;nonce=secrets.token_hex(16);generated=1
        need(re.fullmatch('[0-9a-f]{32}',nonce)and nonce not in c['consumed_nonces'],'one generated nonce collision; no automatic second draw')
        identity=h.put(directory/'IDENTITY.original.json',h.enc({'schema':'hepta.fc33.component-plan-identity.v1','label':c['selected_label'],
            'case_id':c['case_id'],'nonce':nonce,'generation_count':1,'automatic_retry':False,'phone_calls':0}))
        parent=c['parent'];old=c['owner'];owner=old.replace(parent['nonce'].encode(),nonce.encode())
        need(len(owner)==317 and owner.count(nonce.encode())==1 and owner.replace(nonce.encode(),parent['nonce'].encode())==old,'only public request nonce changed')
        request={'path':str(directory/'REQUEST.txt'),**pin(owner)}
        plan=copy.deepcopy(parent);plan.update(c['updates']);plan.update(label=c['selected_label'],nonce=nonce,out=str(out),request=request)
        allowed={'case_id','label','nonce','out','request','package','source_package','shared_materials','shared_root','artifacts','policy_adoption','live_policy_sha256','previous','prior_boundary_descriptor','prior_boundary_original','original_attempt_admission'}
        need(set(plan)==set(parent)|{'original_attempt_admission'}and all(plan[k]==parent[k]for k in parent if k not in allowed),'only reviewed plan fields changed')
        h.put(directory/'REQUEST.txt',owner);validation=h.validate_current_plan(o,h.enc(plan),c);o.recheck()
        plan_row=h.put(directory/'ROOT-PLAN.json',h.enc(plan));h.put(directory/'PREPARE.original.py',source_raw)
        evidence=h.put(directory/'PREPARATION-EVIDENCE.json',h.enc({'schema':'hepta.fc33.component-plan-evidence.v1',
            'source':source,'actual_freeze':FROZEN_INPUTS['freeze'],'actual_freeze_controller':c['freeze_controller'],
            'identity':identity,'actual_previous':c['actual_previous'],'historical_preview':preview,'actual_pure_validation':validation,
            'complete_tuple_originals_bookended':True,'actual_input_files':copy.deepcopy(o.rows),
            'changed_fields':sorted(k for k in plan if k not in parent or plan[k]!=parent[k]),'only_public_request_nonce_changed':True,
            'new_nonces':1,'phone_calls':0,'root_executions':0,'automatic_retry':False,'fixed19_credit':0,
            'fresh_phone_and_latest_head_rollback_admission_required':True,'private_draft_bytes_or_inner_digest_output':False}))
        o.recheck()
        result={'schema':'hepta.fc33.component-plan-result.v1','state':'ONE_NEW_COMPONENT_PLAN_PREPARED_NO_PHONE_EXECUTION',
            'source':source,'plan':plan_row,'entry':c['entry'],'evidence':evidence,'actual_freeze':FROZEN_INPUTS['freeze'],
            'actual_previous':c['actual_previous'],'case_id':c['case_id'],'label':c['selected_label'],'nonce':nonce,
            'actual_pure_validate_plan_passed':True,'phone_calls':0,'root_executions':0,'automatic_retry':False,'fixed19_credit':0,
            'exact_argv':['/usr/bin/python3','-I','-B',c['entry']['path'],'--plan',plan_row['path'],'--plan-sha256',plan_row['sha256'],'--execute-root-chain-once']}
        result_row=h.put(directory/'RESULT.json',h.enc(result));return dict(result,result=result_row)
    except BaseException as error:
        h.put(directory/'PREPARATION-FAILURE.json',h.enc({'schema':'hepta.fc33.component-plan-failure.v1',
            'state':'HOST_GENERATION_RETAINED_NO_AUTOMATIC_RETRY','source':source,'label':c['selected_label'],
            'error_type':type(error).__name__,'nonce_generation_count':generated,'nonce_generation_attempts':attempts,
            'phone_calls':0,'root_executions':0,'automatic_retry':False}));raise

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--reviewed-source-sha256',required=True)
    ap.add_argument('--case',choices=sorted(LABELS),required=True);ap.add_argument('--previous',required=True)
    ap.add_argument('--previous-bytes',type=int,required=True);ap.add_argument('--previous-sha256',required=True)
    ap.add_argument('--original-attempt-admission',required=True);ap.add_argument('--original-attempt-admission-bytes',type=int,required=True)
    ap.add_argument('--original-attempt-admission-sha256',required=True)
    ap.add_argument('--create-host-plan-once',action='store_true');args=ap.parse_args()
    require_original_attempt_admission('preparer-main')
    need(type(FROZEN_INPUTS)is dict and set(FROZEN_INPUTS)=={'freeze','source','controller'},'UNBOUND_ACTUAL_FREEZE_OR_SUCCESSFUL_CONTROLLER_NO_IO_OR_NONCE')
    helper_raw=initial(HELPER);h=module(helper_raw,'fc33_exact_plan_helpers',HELPER['path']);sys.addaudithook(h.audit)
    o=h.Originals();need(o.read(HELPER)==helper_raw,'executed helper unchanged')
    source_path=Path(__file__).absolute();source_raw=o.raw(source_path,1048576)
    need(pin(source_raw)['sha256']==args.reviewed_source_sha256,'exact reviewed current preparer source')
    source={'path':str(source_path),**pin(source_raw)}
    c=selected_context(h,o,args);preview=h.historical_validation_carrier(o,c);o.recheck();h.require_unused(c['selected_label'])
    if not args.create_host_plan_once:
        result={'schema':'hepta.fc33.component-plan-preview.v1','state':'EXACT_FROZEN_TUPLE_AND_PURE_ROOT_VALIDATION_PASSED_NO_IDENTITY',
            'source':source,'actual_freeze':FROZEN_INPUTS['freeze'],'actual_freeze_controller':c['freeze_controller'],
            'actual_previous':c['actual_previous'],'case_id':c['case_id'],'label':c['selected_label'],'historical_validation':preview,
            'new_nonces':0,'phone_calls':0,'root_executions':0,'fixed19_credit':0,'fresh_phone_admission_required':True}
    else:result=create(h,o,c,source,source_raw,preview)
    print(h.enc(result).decode(),end='')

if __name__=='__main__':main()
