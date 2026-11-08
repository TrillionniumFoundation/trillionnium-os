#!/usr/bin/env python3
"""Pure independent current41 proof reader after exact owned final03 cleanup.

The caller pins this complete source and the proof, and supplies read_pinned
for the retained host originals. read_pinned must preserve full9 bookends when
a descriptor includes metadata and must reject symlink/special-file aliases.
No phone, subprocess, policy, network or file mutation is performed here.
The caller separately verifies the complete owned-cleanup closure family and
cross-checks the returned cleanup descriptor. This reader independently checks
the actual later fresh admission and its full original transport/source chain.
"""
import ast,base64,hashlib,json,pathlib,re,shlex,stat,types,zlib
FROZEN_PROOF={'bytes': 22415, 'sha256': '3101f464e956dd931679fe7dc35bab941718f4a265e96efc78813a76178fded7'}
EXPECTED_BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
EXPECTED_POLICY={'bytes':2667752,'sha256':'69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'}
EXPECTED_ADOPTION={'bytes':32638,'sha256':'98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7'}
EXPECTED_HEAD={'bytes':21325,'sha256':'fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66'}
EXPECTED_CHECKS={'same_boot_and_enforcing','ordinary_native_root_and_proc_view','complete_current_source_full9_and_labels',
 'latest_closed_history_and_both_non_native_branches','all_current_roles_absent_twice','all_declared_endpoints_absent',
 'original_retirement_and_disable_unchanged','protected_ui_adbd_rootfs_mounts_unchanged',
 'all_43_original_service_records_unchanged','complete_global_pending_gate_under_borrowed_ledger_fd',
 'complete_sibling_policy_history_unchanged','no_intervening_policy_load_or_owner_change',
 'exact_adopted_post_is_current_live_precondition','full_actual_supplied_policy_checked_against_kernel',
 'all_declared_original_locks_exclusive_and_continuously_held','all_source_and_original_bookends_rechecked'}
REQUIRED_INPUTS=set(["admission_source","binding","request","request_runner","launcher","operation","intent","baseline","phone_stdout","root_capture","historical_inventory","historical_projection","historical_host_verification","historical_late_source","policy_adoption_verifier","snapshot_source","fresh_source","cleanup_projection","cleanup_closure","cleanup_host_verification","preservation_manifest","cleanup_after_inventory","fresh_inventory","cleanup_audit_intent","cleanup_audit_result"])
RUNNER_TEMPLATE="#!/usr/bin/env python3\n\"\"\"Exactly one frozen operator request; preserve every unknown result.\"\"\"\nimport base64,hashlib,json,os,stat,sys\nfrom pathlib import Path\nACTOR_SHA='179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22'\nLABEL=__LABEL__\nREQUEST_PIN=__REQUEST_PIN__\ndef need(ok,why):\n    if not ok:raise ValueError(why)\ndef pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}\ndef meta(s):return [getattr(s,n)for n in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]\ndef pairs(items):\n    out={}\n    for key,value in items:need(key not in out,'duplicate key');out[key]=value\n    return out\npayload=sys.stdin.buffer.read(262145)\nneed(len(payload)<=262144 and sys.flags.isolated and sys.dont_write_bytecode and __debug__,'bounded isolated frozen request')\nvalue=json.loads(payload,object_pairs_hook=pairs)\nneed(set(value)=={'request_raw_base64'},'exact frozen request input')\nraw=base64.b64decode(value['request_raw_base64'],validate=True)\nneed(pin(raw)==REQUEST_PIN,'exact reviewed request differs')\nrequest=json.loads(raw,object_pairs_hook=pairs)\nneed(set(request)=={'kind','root','timeout_seconds','command'}and request['kind']=='shell'and request['root']is True\n    and type(request['timeout_seconds'])is int and 1<=request['timeout_seconds']<=300,'bounded exact existing operator request')\nbase=Path('/home/alex/razr60-local-model-v150');actor=base/'ops/phone_once.py'\nfd=os.open(actor,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\ntry:\n    before=os.fstat(fd)\n    need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=65536,'bounded actor original')\n    with os.fdopen(fd,'rb',closefd=False)as stream:actor_raw=stream.read(65537)\n    need(len(actor_raw)==before.st_size and meta(before)==meta(os.fstat(fd))==meta(actor.lstat()),'actor original changed')\nfinally:os.close(fd)\nneed(pin(actor_raw)['sha256']==ACTOR_SHA,'exact original actor changed')\nrequest_path=base/'requests'/(LABEL+'.json')\nneed(not(base/'operations'/LABEL).exists()and not request_path.exists(),'single-dispatch label exists; reconcile original without replay')\nfd=os.open(request_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)\nwith os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())\nfd=os.open(request_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)\ntry:os.fsync(fd)\nfinally:os.close(fd)\nsys.argv=[str(actor),LABEL,str(request_path)]\nexec(compile(actor_raw,str(actor),'exec'),{'__name__':'__main__','__file__':str(actor)})\n"

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
 def pairs(items):
  v={}
  for k,x in items:need(k not in v,'duplicate JSON key');v[k]=x
  return v
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite'))
def module(raw,name,path):
 m=types.ModuleType(name);m.__file__=str(path);m.__reviewed_source_sha256__=pin(raw)['sha256']
 exec(compile(raw,str(path),'exec'),m.__dict__);return m
def unwrap(raw):
 v=strict(raw)
 for _ in range(3):
  if type(v)is dict and 'content'in v:
   texts=[x['text']for x in v['content']if x.get('type')=='text'];need(len(texts)==1,'one exact MCP text');v=strict(texts[0])
  else:break
 return v

def verify_postcleanup_current41(proof_raw,*,read_pinned):
    """Recompute the new actual gate proof, retaining both independent inventory raw originals."""
    need(type(FROZEN_PROOF)is dict and set(FROZEN_PROOF)=={'bytes','sha256'}
         and type(FROZEN_PROOF['bytes'])is int and 0<FROZEN_PROOF['bytes']<=262144
         and type(FROZEN_PROOF['sha256'])is str and re.fullmatch('[0-9a-f]{64}',FROZEN_PROOF['sha256']),
         'actual post-cleanup proof is not yet bound')
    need(type(proof_raw)is bytes and pin(proof_raw)==FROZEN_PROOF and callable(read_pinned),
         'exact actual proof and pinned-original reader required')
    proof=strict(proof_raw)
    need(type(proof)is dict and set(proof)=={'schema','state','job','inputs','originals'}
         and proof['schema']=='hepta.current41.postcleanup-original-proof-inputs.v1'
         and proof['state']=='ACTUAL_POSTCLEANUP_CURRENT41_ORIGINALS_BOUND'
         and type(proof['inputs'])is dict and set(proof['inputs'])==REQUIRED_INPUTS,
         'complete new original input family required')
    need(type(proof['job'])is dict and set(proof['job'])=={'id','idempotency_key','operation_label'}
         and all(type(v)is str and re.fullmatch('[A-Za-z0-9_.-]{1,160}',v)for v in proof['job'].values()),
         'exact original durable job and once-request names')
    need(type(proof['originals'])is list and 1<=len(proof['originals'])<=96,'bounded complete retained original map')
    pool={};BOOK={}
    for row in proof['originals']:
        need(type(row)is dict and set(row)=={'path','bytes','sha256','metadata'}
             and type(row['path'])is str and pathlib.Path(row['path']).is_absolute()
             and '..'not in pathlib.Path(row['path']).parts and row['path']not in pool
             and type(row['bytes'])is int and 0<=row['bytes']<=
             (16*1024*1024 if row['path']in {proof['inputs'][k]['path']for k in('cleanup_audit_intent','cleanup_audit_result')}else 8*1024*1024)
             and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
             'unique bounded exact retained host original')
        m=row['metadata']
        need(type(m)is list and len(m)==9 and all(type(n)is int for n in m)
             and stat.S_ISREG(m[2])and m[5]==1 and m[6]==row['bytes'],'retained complete regular-file full9')
        pool[row['path']]=row
    for descriptor in proof['inputs'].values():
        need(type(descriptor)is dict and set(descriptor)=={'path','bytes','sha256'}
             and descriptor['path']in pool
             and descriptor=={k:pool[descriptor['path']][k]for k in ('path','bytes','sha256')},
             'every named input is an exact member of the original map')
    def path(name):return pathlib.Path(proof['inputs'][name]['path'])
    def read(where,expected=None):
        name=str(where);need(name in pool,'undeclared retained path')
        row=pool[name]
        if expected is not None:
            need({k:row[k]for k in ('bytes','sha256')}=={k:expected[k]for k in ('bytes','sha256')},
                 'retained byte pin differs from actual source or original descriptor')
            if 'metadata'in expected:need(row['metadata']==expected['metadata'],'retained original full9 differs')
        raw=read_pinned(row)
        need(type(raw)is bytes and pin(raw)=={k:row[k]for k in ('bytes','sha256')},'complete original byte identity')
        if name in BOOK:need(BOOK[name]==row,'original descriptor changed')
        BOOK[name]=row
        return raw
    source=read(path('admission_source'))
    bound=read(path('binding'))
    A=module(source,'pinned_postcleanup_admission_contract',path('admission_source'));binding=A.validate_binding(strict(bound))
    need(A.CHECKS==EXPECTED_CHECKS and A.ACTUAL==EXPECTED_POLICY and A.ADOPTION==EXPECTED_ADOPTION
     and A.V3_HEAD==EXPECTED_HEAD and A.BOOT==EXPECTED_BOOT and A.CLEANUP_PROJECTION is not None,
     'exact actual policy/head and post-cleanup admission family required')
    request_raw=read(path('request'))
    request=strict(request_raw)
    operation_raw=read(path('operation'))
    operation=strict(operation_raw)
    intent_raw=read(path('intent'));baseline_raw=read(path('baseline'))
    intent=strict(intent_raw);baseline=strict(baseline_raw)
    label=proof['job']['operation_label'];job=proof['job']['id'];job_key=proof['job']['idempotency_key']
    need(job!='1a1af72a3d6-fc05-689a' and label!='ng-a1055ce2622e-rollback-current41-readonly01',
     'old pre-final03 current41 execution cannot qualify as post-cleanup observation')
    need(intent['label']==label and intent['request']==request and intent['request_sha256']==pin(request_raw)['sha256']
     and intent['automatic_replay']is False,'exact dispatched original request/intent')
    need(baseline['rc']==0 and baseline['stdout'].splitlines()==[A.BOOT,
     'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys','adb','Enforcing','3021'],'actual unchanged device baseline')
    need(operation['schema']=='hepta.phone-local.operator-result.v150.1'and operation['label']==label
     and operation['status']=='command_exited'and operation['phone']['rc']==0
     and operation['model_decision']is False and operation['native_task_result']is False,'actual readonly actor success')
    need(operation['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(request['command'])
     and operation['phone']['route']==baseline['route']and operation['phone']['stderr']=='','exact root command/route and complete stderr')
    stdout=read(path('phone_stdout'))
    need(stdout==operation['phone']['stdout'].encode('utf-8')and len(stdout)<=8*1024*1024,
     'exact full original phone receipt within original actor8MiB bound')
    r=strict(stdout)
    root_raw=read(path('root_capture'))
    root=strict(root_raw);files={}
    for row in root['files']:files[pathlib.Path(row['path']).name]=read(row['path'],row)
    need(len(files)==7 and root['job_id']==job and root['phone_dispatch_count']==1 and root['original_process_wait_exit']==0
     and root['complete_output']is True and root['original_double_EOF']is True
     and root['original_655c_sender_wait']=='UNKNOWN_UNCHANGED'and root['fixed19_credit']==0,'Root complete original single dispatch')
    start=unwrap(files['ROOT-PROCESS-START.original.mcp.json']);status=unwrap(files['ROOT-PROCESS-STATUS.original.mcp.json']);stream=unwrap(files['ROOT-PROCESS-READ.original.mcp.json'])
    need(start['job']['id']==job and start['reused']is False and start['job']['idempotency_key']==job_key
     and start['job']['launch_state']=='launched','original authoritative first job')
    need(status['job_id']==job and status['state']=='succeeded'and status['exit_code']==0
     and status['output_complete']is True and status['output_durable']is True
     and status['timed_out']is False and status['cancelled']is False
     and all(status['log_truncated'][k]is False and status['log_synced'][k]is True and status['log_errors'][k]is None for k in ('stdout','stderr')),
     'original durable complete nontruncated terminal')
    need(stream['job_id']==job and stream['stdout']['text'].encode()==files['ROOT-STDOUT.original']
     and stream['stderr']['text'].encode()==files['ROOT-STDERR.original']==b''
     and strict(files['ROOT-STDOUT.original'])==root['actual_actor']
     and root['actual_actor']['sha256']==pin(operation_raw)['sha256'],'authoritative original stdout tied to exact operation')
    dispatch=strict(files['ROOT-DISPATCH.original.json'])
    need('timeout_seconds'not in dispatch and dispatch['idempotency_key']==start['job']['idempotency_key']
     and base64.b64decode(strict(dispatch['stdin'])['request_raw_base64'],validate=True)==request_raw,
     'exact frozen payload without outer hard kill timeout')

    runner=read(path('request_runner'))
    expected_runner=RUNNER_TEMPLATE.replace('__LABEL__',repr(label)).replace('__REQUEST_PIN__',repr(pin(request_raw))).encode()
    need(runner==expected_runner and dispatch['host']==start['job']['host']=='pocket4'
     and dispatch['executable']==start['job']['executable']=='/usr/bin/python3'
     and dispatch['args']==start['job']['args']==['-I','-B','-c',runner.decode()],
     'actual original tool job executes the exact request-pinned unchanged once runner')
    for name in ('stdout','stderr'):
     original=files['ROOT-'+name.upper()+'.original'];part=stream[name]
     need(part['offset']==0 and part['eof']is True and part['next_offset']==part['size']==len(original)
      and status['log_bytes'][name]['seen']==status['log_bytes'][name]['stored']==len(original),
      'complete original authority stream, size, dualEOF and durable storage agree')
    launcher=read(path('launcher'))
    need(shlex.split(request['command'])[-5:]==['/usr/bin/python3','-I','-B','-c',launcher.decode()]
     and len(('shell,v2,raw:'+operation['phone']['command']).encode())<65536,
     'exact original bounded two-layer phone launcher')
    assignments=[n for n in ast.parse(launcher).body if isinstance(n,ast.Assign)and len(n.targets)==1
     and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='p']
    need(len(assignments)==1 and ast.unparse(assignments[0].value.func)=='base64.b85decode'
     and len(assignments[0].value.args)==1 and not assignments[0].value.keywords,'exact reviewed base85 packet statement')
    compressed=base64.b85decode(ast.literal_eval(assignments[0].value.args[0]))
    decoder=zlib.decompressobj();packet=decoder.decompress(compressed,4*1024*1024+1)
    need(len(packet)<=4*1024*1024 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
     and packet==source+b'\0'+bound,'original request actually contains these entire source and binding bytes')

    need(r['schema']=='hepta.parent-dir.complete-current-rollback-admission.v1'and r['phase']=='pre'
     and r['readonly_check_only']is True and r['binding_sha256']==pin(bound)['sha256']and r['boot_id']==A.BOOT
     and r['current_boundary']==binding['current_boundary']and r['bound_family']==binding['bound_family']
     and r['actual_supplied_policy']==r['actual_adopted_post']==A.ACTUAL and r['actual_adoption']==A.ADOPTION,
     'actual current41 exact binding/adoption/kernel precondition')
    need(set(r['checks'])==A.CHECKS and len(r['checks'])==16 and all(v is True for v in r['checks'].values()),
     'all original16 gates actually returned true')
    need(all(r[k]==0 for k in ('model_requests_here','native_calls_here','new_children_here','phone_writes_here','policy_loads_here','signals_here'))
     and r['source_and_original_bookends_complete']is True and r['read_only_owned_lock_release_after_complete_check']is True
     and r['read_only_phase_cooperative_seconds_cap']==90.0,'actual readonly completion and locks released after checks')
    inventory_raw=read(path('historical_inventory'),A.STAGE_CURRENT_INVENTORY);inventory=strict(inventory_raw)
    projection_raw=read(path('historical_projection'),A.STAGE_PROJECTION);projected=A.stage_projection(projection_raw)
    obs=strict(projected['observation_projection_raw'])['selected_actual_fields'];required=strict(projected['original_map_projection_raw'])['files']
    late_raw=read(path('historical_late_source'),A.FINAL_LATE)
    tree=ast.parse(late_raw);node=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='inventory_value'][0]
    fragment=b''.join(late_raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
    ns={'C':types.SimpleNamespace(need=need,HASH=re.compile('[0-9a-f]{64}')),'Path':pathlib.Path,'re':re,'stat':stat}
    exec(compile(fragment,'<unchanged actual inventory validator>','exec'),ns);validate_inventory=ns['inventory_value'];iv=validate_inventory(inventory)
    history=r['history'];roles=history['all_role_identities']
    need(history['native_generations']==9 and history['component_roles']==33 and history['retired_roles']==4
     and len(roles)==len({tuple(x)for x in roles})==37 and history['branch_nonces']==A.BRANCHES
     and history['final_prefix_cases']==[]and history['inventory_roots']==inventory['roots']and len(inventory['roots'])==41
     and history['inventory_semantics_sha256']==hashlib.sha256(A.enc(iv)).hexdigest()
     and history['effective_inventory_original']==A.STAGE_CURRENT_INVENTORY,'complete original history/current41 semantics')
    need(len(history['absence_observations'])==2 and all(x['members']==[]and x['kernel_group_absence']is True
     and type(x['numeric_pids'])is int and 0<x['numeric_pids']<=4096 for x in history['absence_observations']),
     'two real original37-role group absence observations')
    need(r['runtime']['member_count']==36 and {k:r['runtime']['manifest'][k]for k in ('bytes','sha256')}==A.V3_PACKAGE
     and r['runtime']['ordinary_unpinned_bytecode_imports']==0,'actual historical native9 runtime is d30/36')
    Vpath=path('policy_adoption_verifier')
    V=module(read(Vpath,A.VERIFIER),'actual6a3_independent_lock_observation',Vpath)
    V.verify_lock_observation(r['locks_before'],inventory);V.verify_lock_observation(r['locks_after'],inventory)
    need(r['locks_before']==r['locks_after'],'same original13 exclusive OFDs before/after')
    book=r['original_bookends'];need(book['complete_full9_byte_and_label_bookends_equal']is True
     and book['file_count']==len(book['files'])==924,'complete actual924 tracked file bookends including two durable audits')
    tracked={}
    for row in book['files']:
     p=row['path'];m=row['metadata']
     need(p not in tracked and len(m)==9 and all(type(v)is int for v in m)and stat.S_ISREG(m[2])and m[5]==1
     and row['bytes']==m[6]and re.fullmatch('[0-9a-f]{64}',row['sha256'])and type(row['selinux'])is str,
     'unique complete tracked regular original')
     if row['private']:need(m[3:5]==[0,0]and stat.S_IMODE(m[2])==0o600,'actual private original permissions')
     tracked[p]=row
    for row in required:
     found=tracked[row['path']]
     need(all(found[k]==row[k]for k in ('path','bytes','sha256','metadata'))
     and found['selinux'].encode()+b'\0'==base64.b64decode(row['selinux_raw_b64'],validate=True)
     and found['private']is True,'all63 independently mapped stage originals in live bookends')
    directories=book['directories'];need(len(directories)==len({x['path']for x in directories})==51,'complete actual51 directory bookends including the exact staging parent')
    for row in directories:
     m=row['metadata'];need(len(m)==9 and stat.S_ISDIR(m[2])and row['names']==sorted(set(row['names']))
     and type(row['selinux'])is str,'actual directory full9/name/label')
    stage=r['retained_stage']
    need(stage['binding']==projected['binding']and stage['historical_phone_projection']==A.STAGE_PROJECTION
     and stage['host_full_original_reverification']==A.STAGE_HOST_VERIFICATION
     and stage['actual_host_closure']==A.STAGE_CLOSURE and stage['actual_inventory']==A.STAGE_CURRENT_INVENTORY
     and stage['historical_full_validator_executed_on_host']is True and stage['historical_full_validator_executed_on_phone']is False
     and stage['all_required_private_originals_read_with_full9_and_labels']is True
     and stage['required_original_count']==63 and stage['original_sender_wait']=='UNKNOWN_UNCHANGED',
     'full host proof versus actual phone fresh scopes kept distinct')
    read(path('historical_host_verification'),A.STAGE_HOST_VERIFICATION)
    snapshot_path=path('snapshot_source')
    snapshot_raw=read(snapshot_path,{'bytes':25527,'sha256':'6ef0949460c0f76cf5288803bae6285d8fe34443cc491b73b181aadfea2d3493'})
    nodes=[x for x in ast.parse(snapshot_raw).body if isinstance(x,ast.FunctionDef)and x.name=='endpoint_absence'];need(len(nodes)==1,'exact endpoint parser')
    node=nodes[0];endpoint_function=b''.join(snapshot_raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
    Fpath=path('fresh_source')

    F=module(read(Fpath,A.STAGE_FRESH),'actual_postcleanup_fresh_contract',Fpath)
    cleanup_raw=read(path('cleanup_projection'),A.CLEANUP_PROJECTION)
    cleanup,expected_stage_tree=F.cleanup_context(cleanup_raw,obs,projected['binding'])
    need(F.CLEANUP_PROJECTION==A.CLEANUP_PROJECTION and stage['actual_final03_cleanup_projection']==A.CLEANUP_PROJECTION,
     'same exact host-verified cleanup projection is required by actual source and receipt')
    cleanup_closed_raw=read(path('cleanup_closure'),cleanup['cleanup_closure']);cleanup_closed=strict(cleanup_closed_raw)
    need(cleanup_closed['schema']=='hepta.native-guard.owned-unstarted-stage-cleanup.v1'
     and all(cleanup_closed[k]==cleanup[k]for k in ('original_scope','retained_stage_closure','preservation_manifest',
     'host_verification','after_inventory','retained_stage_parent_profiles','fresh_required_absence_paths','audit_originals')),
     'complete cleanup closure and precise phone projection refer to the same originals')
    read(path('cleanup_host_verification'),cleanup['host_verification']);read(path('preservation_manifest'),cleanup['preservation_manifest'])
    cleanup_after_raw=read(path('cleanup_after_inventory'),cleanup['after_inventory'])
    cleanup_after=strict(cleanup_after_raw);cleanup_after_value=validate_inventory(cleanup_after)
    encoded_inventory=history['fresh_inventory_original']
    need(type(encoded_inventory)is dict and set(encoded_inventory)=={'bytes','sha256','encoding','zlib_base64'}
     and encoded_inventory['encoding']=='zlib9-base64'and type(encoded_inventory['bytes'])is int
     and 0<encoded_inventory['bytes']<=2*1024*1024,'actual complete inventory transport descriptor')
    compressed_inventory=base64.b64decode(encoded_inventory['zlib_base64'],validate=True)
    decoder=zlib.decompressobj();fresh_raw=decoder.decompress(compressed_inventory,encoded_inventory['bytes']+1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
     and pin(fresh_raw)=={k:encoded_inventory[k]for k in ('bytes','sha256')}
     and fresh_raw==read(path('fresh_inventory'),encoded_inventory),'exact complete fresh inventory original without reconstruction')
    fresh_inventory=strict(fresh_raw);fresh_value=validate_inventory(fresh_inventory)
    need(cleanup_after_value==fresh_value==iv and len(fresh_value['roots'])==41
     and history['inventory_semantics_sha256']==hashlib.sha256(A.enc(fresh_value)).hexdigest(),
     'both independent complete actual inventory raw originals have the same full comparison view')
    need(proof['inputs']['cleanup_after_inventory']==cleanup['after_inventory']
     and proof['inputs']['cleanup_closure']==cleanup['cleanup_closure'],
     'consumer receives exact cleanup original references, not the older historical raw')
    audit_raws={};audit_expected_rows=[]
    for row in cleanup['audit_originals']:
        role='cleanup_audit_intent'if row['path'].endswith('.CLEANUP-INTENT.json')else 'cleanup_audit_result'
        audit_raws[row['path']]=read(path(role),{k:row[k]for k in('bytes','sha256')})
        found=tracked[row['path']]
        need(all(found[k]==row[k]for k in('path','bytes','sha256','metadata'))and found['private']is True
         and found['selinux'].encode()+b'\0'==base64.b64decode(row['selinux_raw_b64'],validate=True),
         'both complete actual audit originals in phone full9/label bookends')
        audit_expected_rows.append(found)
    audit_result=strict(audit_raws[next(p for p in audit_raws if p.endswith('.CLEANUP-RESULT.json'))])
    audit_parent_profiles=audit_result['audit_scope_parent_profiles']
    need(audit_parent_profiles==cleanup_closed['audit_scope_parent_profiles'],
         'complete original durable RESULT and full host closure bind the same staging parent proof')
    expected_audit_parent=F.audit_parent_profile(audit_parent_profiles)
    need([row for row in directories if row['path']==str(F.ARCHIVE.parent)]==[expected_audit_parent],
         'actual staging parent full9/names/label independently tracked and matched')
    audit_profiles_pin=pin(enc(audit_parent_profiles))
    expected_absent={str(A.STAGE_HOME/name)for name in F.ABSENT_NAMES_FROM_ACTUAL_COLLECTOR}|{str(F.FIXTURE)}
    fresh=r['retained_stage_fresh_observations'];need(len(fresh)==2,'two complete actual stage fresh observations')
    endpoint_proofs=[];censuses=[];cleaned_censuses=[]
    for observation in fresh:
     need(observation['boot_id']==A.BOOT and observation['label']==F.LABEL and observation['nonce']==F.NONCE
     and observation['actual_inventory']==A.STAGE_CURRENT_INVENTORY and observation['complete_stage_tree']==expected_stage_tree
     and observation['lease_expired_observed']is True and observation['original_lease_expires_unix_ms']==1793938876735
     and observation['original_sender_wait']=='UNKNOWN_UNCHANGED'and observation['borrowed_owner_locks_reacquired']is False,
     'fresh complete stage/aliases/expiry/unknown unchanged')
     need(all(observation[k]==0 for k in ('new_children_here','new_component_roles','new_fixtures','new_native_credit',
     'phone_writes_here','policy_loads_here','signals_sent_here')),'fresh phase has no mutation or credit')
     absent=observation['required_absences'];need(len(absent)==len(expected_absent)and {x['path']for x in absent}==expected_absent,
     'all actual launch markers and precise fixture absence observed')
     for x in absent:
      need(x['errno']==2 and len(x['parent_metadata'])==9 and stat.S_ISDIR(x['parent_metadata'][2])
       and type(x['observed_monotonic_ns'])is int and len(base64.b64decode(x['parent_selinux_raw_b64'],validate=True))<=512,
       'precise ENOENT with actual parent metadata/label')
     census=observation['scope_process_census'];need(census['matches']==[]and census['errors']==[]
     and census['original_parent_wait_inferred']is False and 0<census['enumerated_pids']<=4096
     and census['inspected_pids']+len(census['disappeared_pids'])+1==census['enumerated_pids']
     and 0<=census['finished_monotonic_ns']-census['started_monotonic_ns']<2_000_000_000,
     'fresh complete role/marker proc census under original2s bound')
     censuses.append(census)

     need(observation['cleanup_projection']==A.CLEANUP_PROJECTION
      and observation['cleanup_closure']==cleanup['cleanup_closure']
      and observation['cleanup_host_verification']==cleanup['host_verification']
      and observation['cleanup_preservation_manifest']==cleanup['preservation_manifest']
      and observation['cleanup_after_inventory']==cleanup['after_inventory']
      and observation['cleaned_original_scope']==cleanup['original_scope']
      and observation['post_cleanup_parent_profiles']==cleanup['retained_stage_parent_profiles'],
      'actual original fresh record binds the exact completed cleanup and post full9 profiles')
     removed=observation['cleanup_required_absences']
     need(len(removed)==7 and {x['path']for x in removed}==set(F.CLEANUP_ABSENT_PATHS)
      and all(x['errno']==2 and len(x['parent_metadata'])==9 and stat.S_ISDIR(x['parent_metadata'][2])
       and type(x['observed_monotonic_ns'])is int and len(base64.b64decode(x['parent_selinux_raw_b64'],validate=True))<=512
       for x in removed),'all seven removed paths independently observed ENOENT with parent full9/labels')
     cleaned=observation['cleaned_scope_process_census']
     need(cleaned['matches']==[]and cleaned['errors']==[]and cleaned['original_parent_wait_inferred']is False
      and 0<cleaned['enumerated_pids']<=4096
      and cleaned['inspected_pids']+len(cleaned['disappeared_pids'])+1==cleaned['enumerated_pids']
      and 0<=cleaned['finished_monotonic_ns']-cleaned['started_monotonic_ns']<2_000_000_000
      and cleaned['collector_pid_excluded']==census['collector_pid_excluded']
      and census['finished_monotonic_ns']<cleaned['started_monotonic_ns'],
      'same original collector separately rechecks exact consumed final03 markers after final02 census')
     cleaned_censuses.append(cleaned)
     audit=observation['cleanup_audit_observation']
     need(audit['files']==sorted(audit_expected_rows,key=lambda row:row['path'])
      and audit['complete_raw_bytes_read']==sum(len(raw)for raw in audit_raws.values())
      and audit['full9_and_labels_matched']is True and audit['result_parent_profiles_original']==audit_profiles_pin
      and audit['observed_parent']==expected_audit_parent,
      'each fresh phase completely read both audit files and matched the exact actual staging parent')
     tables={k:base64.b64decode(v,validate=True)for k,v in observation['endpoint_table_originals_base64'].items()}
     need(set(tables)=={'tcp','tcp6','unix'}and all(len(v)<=2*1024*1024 for v in tables.values()),'complete bounded original endpoint tables')
     lookup={'/proc/net/tcp':'tcp','/proc/net/tcp6':'tcp6','/proc/net/unix':'unix'}
     parser={'C':types.SimpleNamespace(need=need,SOCKET_NAME='hepta_phone_executor_v150_r6'),
     'bounded_proc':lambda p:tables[lookup[p]],'time':types.SimpleNamespace(monotonic_ns=lambda:observation['endpoints']['observed_monotonic_ns'])}
     exec(compile(endpoint_function,'<unchanged actual endpoint parser with exact captured raw tables>','exec'),parser)
     observed_tables,recomputed=parser['endpoint_absence']()
     need(observed_tables==tables and recomputed==observation['endpoints'],'independent raw TCP/UNIX endpoint recomputation')
     endpoint_proofs.append({'tables':{k:pin(v)for k,v in tables.items()},'recomputed':recomputed})
    need(censuses[0]['collector_pid_excluded']==censuses[1]['collector_pid_excluded']
     and censuses[0]['finished_monotonic_ns']<censuses[1]['started_monotonic_ns'],'ordered same original collector phases')
    need(cleaned_censuses[0]['collector_pid_excluded']==cleaned_censuses[1]['collector_pid_excluded']
     and cleaned_censuses[0]['finished_monotonic_ns']<censuses[1]['started_monotonic_ns'],
     'both cleaned-scope censuses belong to the same ordered original gate')
    namespace=r['policy_namespace']
    need(len(namespace['retained_policy_roots'])==26 and namespace['inventory_original']==binding['policy_inventory']
     and namespace['historical_root_owned_modes']==[0o600,0o644]and namespace['group_or_other_writable_allowed']is False
     and namespace['only_this_new_output_allowed']is None,'actual complete26 policy history unchanged')

    need(set(BOOK)==set(pool),'declared original map contains omitted or unused evidence')
    for row in list(BOOK.values()):read(row['path'],row)
    return {'schema':'hepta.current41.postcleanup-original-verification.v1','state':'VERIFIED_POSTCLEANUP_CURRENT41',
     'boot_id':A.BOOT,'runtime_policy':A.ACTUAL,'current_adoption_sha256':A.ADOPTION['sha256'],
     'prior_boundary_sha256':A.V3_HEAD['sha256'],'native_generation_count':9,'component_role_count':33,
     'retired_role_count':4,'inventory_root_count':41,'fixture_root_count':11,'lock_aliases':24,'lock_OFDs':13,
     'cleanup_closure':proof['inputs']['cleanup_closure'],
     'cleanup_after_inventory':proof['inputs']['cleanup_after_inventory'],'fresh_inventory':proof['inputs']['fresh_inventory'],
     'fresh_inventory_value':fresh_value,'cleanup_and_fresh_inventory_values_equal':True,
     'consumed_nonce':F.CLEANED_NONCE,'original_scope':cleanup['original_scope'],
     'post_cleanup_parent_profiles':cleanup['retained_stage_parent_profiles'],
     'final03_required_absence_verified':True,'observed_after_cleanup':True,'all_16_gates_verified':True,
     'observation_order_basis':'actual completed cleanup projection bound in original request and exact post profiles observed',
     'original_sender_wait':'UNKNOWN_UNCHANGED','native_case_credit':0,'fixed19_credit':0,
     'candidate_runtime_qualified_on_phone':False,'native_current_manifest':A.V3_PACKAGE,'native_current_member_count':36,
     'retained_stage_historical_manifest':F.PACKAGE_SHA,'full_historical_inventory_comparison_view':iv,
     'original_P4_job':job,'original_idempotency_key':job_key,'original_authority_capture':pin(root_raw),
     'original_actor_status':'command_exited','phone_rc':0,'original_host_wait_exit':0,'original_host_dual_EOF':True,
     'actual_admission_source':pin(source),'actual_admission_binding':pin(bound),'actual_request':pin(request_raw),
     'actual_operation':pin(operation_raw),'actual_phone_stdout':pin(stdout),'actual_proof':pin(proof_raw),
     'fresh_inventory_export_is_original_same_census_without_resampling':True,
     'complete_host_vs_fresh_phone_proof_scopes_kept_distinct':True,
     'cleanup_full_originals_reverification_required_by_caller':True,
     'durable_cleanup_audit_original_count':2,'durable_cleanup_audit_parent_count':1,
     'cleanup_audit_originals':cleanup['audit_originals'],'cleanup_audit_parent_profiles':audit_parent_profiles,
     'all63_stage_originals_full9_labels_independently_matched':True,'original_locks_before_after_equal':True,
     'released_after_complete_check':True,'tracked_file_originals':len(tracked),'tracked_directory_originals':len(directories),
     'fresh_stage_observation_count':2,'old_required_absence_count_each':len(expected_absent),'new_required_absence_count_each':7,
     'fresh_process_censuses':censuses,'cleaned_scope_process_censuses':cleaned_censuses,
     'raw_endpoint_recomputation':endpoint_proofs,'all_host_original_bookends':list(BOOK.values()),
     'phone_calls_here':0,'policy_loads_here':0,'file_writes_here':0,
     'must_rebind_after_new_native_stage_or_shared_parent_change':True}

