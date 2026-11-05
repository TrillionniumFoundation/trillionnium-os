import ast,difflib,hashlib,json,os,re,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
os.umask(0o077)
B=Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1")
L=B/'policy-runtime-properties-r10-live-02'
D=B/'policy-runtime-properties-r10-post-retention-r2-final01'
PARENT=B/'policy-runtime-properties-r10-post-retention-r2-candidate01'
V_PIN={'path':str(L/'capture/originals/policy_runtime_properties_verifier.original.py'),'bytes':124306,'sha256':'5cd18af19e1cd4cbe98542996fa41960bc36f697c6687ce201312b8ceda91c00'}
EXEC_PIN={'path':str(L/'ROOT-EXECUTION.json'),'bytes':21536,'sha256':'d5173756537a5303b78573b21b43d57e64bfdfe75010115b55b1fe925b1da849'}
HOST_PIN={'path':str(L/'capture/HOST-CAPTURE.json'),'bytes':1580,'sha256':'e9f7e22ee0187cb65ff5ca5cdd6c23284f7f6adc5d2f28c0364935de5d61e04d'}
SOURCE_PIN={'path':str(PARENT/'source/retain_actual_live_inputs.py'),'bytes':19679,'sha256':'a57e4d95a02ebdf9cffff55fd0bdac58ea67a4d273f9ab419b039cfac0e97381'}
PARENT_MF={'path':str(PARENT/'MANIFEST.json'),'bytes':7288,'sha256':'2f8fcaa065e207a598f6d9c031d69aeb1b2b5cf0a535ce2293c6ed6606d9f16a'}
AFTER={'bytes':2667740,'sha256':'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'}
BEFORE={'bytes':2667608,'sha256':'50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'}
seen={};raws={};calls=[];written={}
def need(v,m):
    if not v:raise ValueError(m)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def meta(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def desc(path,raw):return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def strict(raw):
    def pairs(rows):
        d={}
        for k,v in rows:need(k not in d,'duplicate key');d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def read(row):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact3 host input')
    p=Path(row['path'])
    need(p.is_absolute() and B in p.parents and p.resolve(strict=True)==p and '..' not in p.parts,'canonical explicit project input')
    need(type(row['bytes']) is int and 0<=row['bytes']<=32*1024*1024 and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded input pin')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==row['bytes'],'regular single-link actual original')
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(row['bytes']+1)
        md=meta(s);need(md==meta(os.fstat(fd))==meta(p.lstat()),'actual input metadata changed')
    finally:os.close(fd)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'actual raw bytes differ')
    if str(p) in seen:need(seen[str(p)]==dict(row,metadata=md) and raws[str(p)]==raw,'original changed between reads')
    else:
        need(len(seen)<512 and sum(len(v) for v in raws.values())+len(raw)<=128*1024*1024,'bounded source read set')
    seen[str(p)]=dict(row,metadata=md);raws[str(p)]=raw;calls.append(dict(row));return raw
def put(path,raw):
    need(path.parent.resolve(strict=True)==path.parent,'canonical fresh output parent')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    row=desc(path,raw);need(read(row)==raw,'new artifact readback');written[str(path)]=row
    return row
def recheck():
    for row in list(seen.values()):read({k:row[k] for k in ('path','bytes','sha256')})
def functions(raw):
    lines=raw.splitlines(keepends=True)
    return {n.name:b''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
def assignment(raw,name):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    need(len(nodes)==1,'one explicit assignment');n=nodes[0];lines=raw.splitlines(keepends=True)
    start=sum(map(len,lines[:n.lineno-1]))+n.col_offset
    end=sum(map(len,lines[:n.end_lineno-1]))+n.end_col_offset
    return n,start,end
need(D.parent.resolve(strict=True)==D.parent and not D.exists() and not D.is_symlink(),'fresh source finalization directory')
D.mkdir(mode=0o700)
for name in ('source','validation','development'): (D/name).mkdir(mode=0o700)
program=put(D/'development/bind_actual_live_inputs.py',PROGRAM.encode())
intent=put(D/'validation/INTENT.json',enc({'schema':'hepta.runtime-properties-r10.provenance-finalization-intent.v1','root_execution':EXEC_PIN,'host_capture':HOST_PIN,'captured_verifier':V_PIN,'retention_parent':SOURCE_PIN,'maximum_pure_verifier_calls':1,'phone_operations':0,'policy_writes':0,'retention_executions':0,'comparison_executions':0,'policy_adoption_authorized':False}))
phase='read_actual_originals'
try:
    old=read(SOURCE_PIN);read(PARENT_MF)
    executable_raw=read(EXEC_PIN);execution=strict(executable_raw)
    host_raw=read(HOST_PIN);host=strict(host_raw)
    need(execution['schema']=='hepta.root.runtime-properties-live-execution.v2' and execution['state']=='ORIGINAL_POLICY_APPLY_CAPTURED_PENDING_INDEPENDENT_COMPARISON','actual Root v2 terminal')
    need(execution['host_capture']==HOST_PIN and execution['policy_apply_calls']==1 and execution['known_apply_error'] is None,'exact actual Root operation')
    archive_pin={'path':str(L/'capture/ORIGINALS.tar.gz'),**host['archive']}
    cap_pin={'path':str(L/'capture/originals/CAPTURE.json'),**host['capture']}
    archive_raw=read(archive_pin);cap_raw=read(cap_pin);cap=strict(cap_raw)
    need(host['files']==105 and cap['file_count']==104 and len(cap['files'])==104,'exact complete actual capture size')
    rows={}
    for r in cap['files']:
        need(type(r) is dict and set(r)=={'path','original_path','bytes','sha256','metadata'} and re.fullmatch('[A-Za-z0-9_.-]{1,100}',r['path']) and r['path'] not in ('.','..') and r['path'] not in rows,'flat unique original index')
        rows[r['path']]={'path':str(L/'capture/originals'/r['path']),'bytes':r['bytes'],'sha256':r['sha256']}
    names=set(rows)|{'CAPTURE.json'};original_dir=L/'capture/originals'
    dir_before=meta(original_dir.lstat())
    need(stat.S_ISDIR(original_dir.lstat().st_mode) and set(os.listdir(original_dir))==names,'complete existing original directory')
    for r in rows.values():read(r)
    v_raw=read(V_PIN);need(rows['policy_runtime_properties_verifier.original.py']==V_PIN,'actual captured verifier pin')
    V=types.ModuleType('reviewed_actual_runtime_properties_provenance_v2')
    V.__file__=V_PIN['path'];V.__reviewed_source_sha256__=V_PIN['sha256']
    exec(compile(v_raw,V_PIN['path'],'exec'),V.__dict__)
    need(V.MANDATORY_LIVE_FILES<=set(rows),'mandatory source input names')
    live={'schema':'hepta.runtime-properties-r10.live-provenance-inputs.v1',
        **{k:execution[k] for k in ('prepared','host_capture','original_operation','actor_wrapper','pre_live_expectation','root_plan','root_intent')},
        'root_execution':EXEC_PIN,'archive':archive_pin,'capture_manifest':cap_pin,
        'originals':{name:rows[name] for name in sorted(V.MANDATORY_LIVE_FILES)}}
    live_raw=enc(live)
    verified_paths=set()
    def verify_read(row):
        verified_paths.add(row['path']);return read(row)
    phase='complete_actual_verify_live_capture'
    summary=V.verify_live_capture(live,read_pinned=verify_read)
    need(summary['phone_calls']==0 and summary['policy_adoption_authorized'] is False and summary['comparison_route']=='verified_semantic_export' and summary['expected_live_export'] is None,'pure provenance only')
    need(summary['actual_before_policy']==BEFORE and summary['actual_after_policy']==AFTER and summary['provenance_inputs_sha256']==sha(live_raw),'actual current image and original live inputs')
    need(set(summary['original_files'])==names and len(summary['original_files'])==105,'all105 actual archive bodies')
    for name,raw in summary['original_files'].items():
        row=cap_pin if name=='CAPTURE.json' else rows[name]
        need(read(row)==raw,'retained original differs from actual archive')
    need(set(os.listdir(original_dir))==names and meta(original_dir.lstat())==dir_before,'complete original directory bookend')
    phase='finalize_one_actual_assignment'
    recheck()
    live_pin=put(L/'LIVE-PROVENANCE-INPUTS.json',live_raw)
    actual={'live_provenance_inputs':live_pin,'verifier_source':V_PIN,'root_execution':EXEC_PIN}
    node,start,end=assignment(old,'ACTUAL_INPUTS')
    need(ast.literal_eval(node.value) is None and old[start:end]==b'ACTUAL_INPUTS=None','unpublished exact parent assignment')
    replacement=('ACTUAL_INPUTS='+repr(actual)).encode()
    new=old[:start]+replacement+old[end:]
    compile(new,str(D/'source/retain_actual_live_inputs.py'),'exec')
    n,a,z=assignment(new,'ACTUAL_INPUTS')
    need(ast.literal_eval(n.value)==actual and new[:a]+b'ACTUAL_INPUTS=None'+new[z:]==old,'whole source inverse to a57e')
    need(functions(new)==functions(old),'all old functions/classes unchanged')
    source_pin=put(D/'source/retain_actual_live_inputs.py',new)
    patch=''.join(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),fromfile='parent/source/retain_actual_live_inputs.py',tofile='source/retain_actual_live_inputs.py')).encode()
    patch_pin=put(D/'validation/ACTUAL-INPUTS-INCREMENT.patch',patch)
    request={'schema':'hepta.runtime-properties-r10.post-live-retention-request.v1',
        'live_provenance_inputs':live_pin,'verifier_source':V_PIN,'collector_source':source_pin,
        'root_output':str(L),'out':str(B/'policy-runtime-properties-r10-post-live-root02-retention01'),
        'p4_out':'/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1/post-live-root02-inputs01'}
    request_raw=enc(request);request_pin=put(D/'RETENTION-REQUEST.json',request_raw)
    cli=['/usr/bin/python3','-I','-B',source_pin['path'],'--request',request_pin['path'],'--request-sha256',request_pin['sha256'],'--execute-host-retention']
    summary_keys=('parent','candidate','root_scope_decision','parent_adoption_history','binding_sha256','host_capture_sha256','provenance_inputs_sha256','root_transaction','actual_before_policy','actual_after_policy','comparison_route','expected_live_export','policy_adoption_authorized','phone_calls')
    compact={k:summary[k] for k in summary_keys}
    admission={'schema':'hepta.runtime-properties-r10.actual-live-provenance-admission.v1',
        'state':'ACTUAL_LIVE_ORIGINALS_VERIFIED_PENDING_HOST_RETENTION_REVIEW',
        'verifier_source':V_PIN,'live_provenance_inputs':live_pin,'root_execution':EXEC_PIN,
        'host_capture':HOST_PIN,'capture_manifest':cap_pin,'archive':archive_pin,
        'capture_files':105,'mandatory_originals':len(live['originals']),
        'verifier_callback_unique_paths':len(verified_paths),
        'verifier_callback_raw_bytes':sum(seen[p]['bytes'] for p in verified_paths),
        'complete_archive_and105_copies_verified':True,'original_directory_names_and_full9_unchanged':True,
        'summary':compact,'phone_operations':0,'policy_writes':0,'retention_executions':0,'comparison_executions':0,'policy_adoption_authorized':False}
    admission_pin=put(D/'validation/LIVE-PROVENANCE-ADMISSION.json',enc(admission))
    inverse_pin=put(D/'validation/SOURCE-INVERSE.json',enc({'schema':'hepta.runtime-properties-r10.actual-input-source-derivation.v1','parent':SOURCE_PIN,'new_source':source_pin,'patch':patch_pin,'assignment':'ACTUAL_INPUTS','actual_inputs':actual,'all_functions_classes_byte_identical':True,'whole_source_inverse_byte_exact':True,'reconstructed_parent_sha256':sha(new[:a]+b'ACTUAL_INPUTS=None'+new[z:]),'runtime_or_transport_logic_changed':False,'retention_executions':0,'comparison_executions':0,'phone_operations':0}))
    interface_pin=put(D/'INTERFACE.json',enc({'schema':'hepta.runtime-properties-r10.actual-post-retention-interface.v1','source':source_pin,'request':request_pin,'actual_inputs':actual,'cli':cli,'execution_requires_root_review':True,'post_comparison_is_separate_explicit_operation':True,'phone_operations':0,'policy_writes':0,'policy_adoption_authorized':False}))
    phase='final_original_bookends'
    recheck()
    need(set(os.listdir(original_dir))==names and meta(original_dir.lstat())==dir_before,'final capture directory changed')
    originals_pin=put(D/'validation/ORIGINAL-READ-SET.json',enc({'schema':'hepta.runtime-properties-r10.provenance-original-read-set.v1','files':[seen[p] for p in sorted(seen) if p not in written],'verifier_callback_paths':sorted(verified_paths),'capture_directory':{'path':str(original_dir),'metadata':dir_before,'names':sorted(names)},'raw_full9_preserved_in_python':True,'all_originals_rechecked':True}))
    mf={'schema':'hepta.runtime-properties-r10.retention-final-source-package.v1','state':'ACTUAL_LIVE_INPUTS_FROZEN_NOT_EXECUTED','parent_source':SOURCE_PIN,'parent_manifest':PARENT_MF,'source':source_pin,'live_provenance_inputs':live_pin,'request':request_pin,'admission':admission_pin,'source_inverse':inverse_pin,'original_read_set':originals_pin,'files':[written[p] for p in sorted(written) if Path(p).is_relative_to(D)],'phone_operations':0,'policy_writes':0,'retention_executions':0,'comparison_executions':0,'policy_adoption_authorized':False}
    mf_pin=put(D/'MANIFEST.json',enc(mf))
    result={'schema':'hepta.runtime-properties-r10.actual-retention-source-finalization.v1','state':'ACTUAL_PROVENANCE_AND_SINGLE_ASSIGNMENT_SOURCE_READY_FOR_ROOT_REVIEW','manifest':mf_pin,'live_provenance_inputs':live_pin,'source':source_pin,'patch':patch_pin,'request':request_pin,'admission':admission_pin,'source_inverse':inverse_pin,'original_read_set':originals_pin,'actual_after_policy':AFTER,'capture_originals':105,'verifier_callback_unique_paths':len(verified_paths),'verifier_callback_raw_bytes':sum(seen[p]['bytes'] for p in verified_paths),'cli':cli,'phone_operations':0,'policy_writes':0,'retention_executions':0,'comparison_executions':0,'policy_adoption_authorized':False}
    result_pin=put(D/'RESULT.json',enc(result))
    print(json.dumps(dict(result,result=result_pin),sort_keys=True))
except BaseException as e:
    failure={'schema':'hepta.runtime-properties-r10.actual-retention-source-finalization-failure.v1','state':'HOST_FINALIZATION_STOPPED_NO_REPLAY','phase':phase,'error_type':type(e).__name__,'error':str(e)[:4096],'written_files':list(written.values()),'phone_operations':0,'policy_writes':0,'retention_executions':0,'comparison_executions':0}
    try:put(D/'FAILURE.json',enc(failure))
    except BaseException:pass
    raise
