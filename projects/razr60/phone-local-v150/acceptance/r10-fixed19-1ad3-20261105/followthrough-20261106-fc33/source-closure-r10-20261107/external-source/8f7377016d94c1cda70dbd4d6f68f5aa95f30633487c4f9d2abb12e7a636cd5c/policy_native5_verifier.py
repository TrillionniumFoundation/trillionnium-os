#!/usr/bin/env python3
"""Pure verification for the explicitly approved Native5 twelve-atom transition.

All original bytes enter through an explicit read_pinned callback. This module
does not read the device, open a socket, write a file, run a command or adopt a
policy. A reviewed original is not a claim that a screenshot now succeeds.
"""
import ast
import base64
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import shlex
import tarfile
import zlib

BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'
NATIVE_BASE = '/data/trillionnium/owner-open/state/phone-local-v150'
CODE_NAME = 'policy-native5-r10-live-code-r2'
OUT_NAME = 'policy-native5-r10-live-02'
DECISION = {'bytes': 6660, 'sha256': '3a30afe60a37c224114e9414b8d290c574eb56185820ebe4584156d2d10a13fb'}
PARENT = {'bytes': 2667548, 'sha256': '296b09d9c844d2916b0dbdb0765c71cbcb8411790b58f5823798aa872205b659'}
PARENT_ADOPTION = {'bytes': 7425, 'sha256': '7899e446ef77d9f05aab7f22298ff9470e04a5253c2397ec6cf292543daac87e'}
RETIREMENT = 'b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90'
RETIREMENT_DESCRIPTOR = {'bytes': 2220, 'sha256': 'e3c8411f3d85440018392597d4f9f8795cfd7a60c44fc1680068a60949d20999'}
RETIREMENT_HOST_CLOSURE = {'bytes': 2489, 'sha256': '14c4bfeb4932067b682cc47b0472f3f2e994cac6ae72a33662ad702b73a4a906'}
PACKAGE = {'bytes': 5284, 'sha256': '1cd57949621b36e46dc72d3df55e6ec3814fa76fb046c15ae71524463e3e8996'}
COMBINATION_SHA256 = '7f5929ae709239f8a5d92314146d2b63151bb06746d160da7961a3de29c486af'
BOUNDARY_DESCRIPTOR = {'bytes': 367, 'sha256': '62037d01adbe5b464183d55b6c5757bc5bded5b9c821cfb295c4b36c53057535'}
BOUNDARY = {'path': BASE+'/native-guard-boundaries-r10-r1/c705647dd4ebb5d421be1041a9c41ca6.json',
    'bytes': 4748, 'sha256': '3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12',
    'metadata': [65086,149437,33152,0,0,1,4748,1793828404835934900,1793828404835934900]}
BOUNDARY_CLOSURE = {'bytes': 49087, 'sha256': '559f2440fdd1c9f43c64399351f3fda0be95890d21cbde4aea211751e5f9aa81'}
BOUNDARY_INVENTORY = {'bytes': 633600, 'sha256': 'e48c39003bd26f65dde74958f0081a89c23027da19a11afd4fc2a81414c5c349'}
LEGACY_BOUNDARY = {'bytes': 5003, 'sha256': 'ee008c3b2adec701be4c0bdfd38ca7ac0d650da9b7783f51d3fe4638bfdc5b58'}
LEGACY_CLOSURE = {'bytes': 119753, 'sha256': 'b8a27617eaff8dda0f1c61b5aa14a89d7014a157e0b33280b14162c7591bcaa3'}
LEGACY_INVENTORY = {'bytes': 563365, 'sha256': '145d5937cd328ed568b1af9c73f7d331211d1c44cfad8ecf960b47d91f308eee'}
PARENT_RULE = {'bytes': 13175, 'sha256': 'dd9303a46c0016c98cce26b8a2fa199e045038f70148817d72fa6034e86dd0e3'}
FULL_RULE = {'bytes': 14130, 'sha256': 'aeda92123f1d043de2c53dd345dd7372b98da7b776299d57bda531dda868e4a1'}
PARSER = {'bytes': 2630712, 'sha256': '68154a7adabfada7940572f95477885dd6da01ea8b1f3e95abef9495a066382c'}
WORKER = 'trillionnium_owner_open_phone_worker'
ROWS = [(WORKER,'hal_graphics_allocator_service','service_manager',['find']),
    (WORKER,'hal_graphics_mapper_service','service_manager',['find']),
    (WORKER,'same_process_hal_file','file',['getattr','open','read','map','execute']),
    (WORKER,'hal_graphics_allocator_default','binder',['call']),
    (WORKER,'userdebug_or_eng_prop','file',['getattr','open','read','map'])]
ATOMS = [['allow',src,target,kind,perm] for src,target,kind,perms in ROWS for perm in perms]
RULE = ''.join(' '.join(atom)+'\n' for atom in ATOMS).encode('utf-8')
ARGV = ['/data/adb/magisk/magiskpolicy','--live','--apply',NATIVE_BASE+'/'+OUT_NAME+'/native5.delta.rule']
APPROVAL = {'maximum_apply_attempts':1,'apply_timeout_seconds':45,'kill_grace_seconds':5,
    'automatic_retry':False,'automatic_rollback':False,'automatic_policy_adoption':False,
    'post_live_complete_comparison_required':True,'service_start_admitted':False}

# These are filled only after the actual independent candidate comparison and
# reviewed source manifest exist. No caller-supplied pin can lift this gate.
REVIEWED_OFFLINE_COMPARISON = {'bytes': 203554, 'sha256': '9ab96c5f75c6d6796ca5fa98c37662b37e6b9c29749d250b7480bfb005f6b5da'}
REVIEWED_COMPARISON_SOURCES = {'candidate_av_source': {'bytes': 17720, 'path': '/home/alex/razr60-local-model-v150/policy-native5-r10-r1/offline-candidate02/reference/policy_av_query.original.c', 'sha256': '262b264c79d12c1cd2af146808ac1c5998f6aa0159515a17796c381e12630a3c'}, 'candidate_av_tool': {'bytes': 34976, 'path': '/home/alex/razr60-local-model-v150/sepol-offline-query-r1-20261104/build-01/policy_av_query', 'sha256': '86f6d18eab7271d9a5688e5f7b03ed5b55740b9679e7dd078661573ad67f0c90'}, 'comparator': {'bytes': 51027, 'path': '/home/alex/razr60-local-model-v150/policy-native5-r10-r1/offline-candidate02/source/full_policy_compare_native5.py', 'sha256': '9973d09a175022e6dc590c6b578a0b5871090206a7dff1999e1fa3eb93388ee5'}, 'existing_tools': {'bytes': 19446, 'path': '/home/alex/razr60-local-model-v150/policy-native5-r10-r1/offline-candidate02/reference/EXISTING-PRIVATE-POLICY-TOOLS.original.json', 'sha256': 'b41918ef19a0c00b0ab2295c278f204b8d66c654e8dacad05db0dea232fbd288'}, 'image_comparator': {'bytes': 294608, 'path': '/home/alex/razr60-local-model-v150/policy-native5-r10-r1/offline-candidate02/actual-01/policy_native5_image', 'sha256': '740d1f51ffdbe60aa0d2ed9566e17452b02ea6f014c3a060c3830160304c1844'}, 'image_comparator_source': {'bytes': 19590, 'path': '/home/alex/razr60-local-model-v150/policy-native5-r10-r1/offline-candidate02/source/policy_native5_image.c', 'sha256': 'c0226042048a3b4b02e6e9704b61a537ef32e8e81bfffeb6464ed728964ab5e0'}}
REVIEWED_POST_COMPARATOR_SOURCE = {'bytes': 53614, 'sha256': 'e921c6f1062cd592a905fc49102cc1e960503ea0aed27d33c5810a8603d57696'}
REVIEWED_COMPARISON_RUNNERS = {'offline_candidate': {'bytes': 16608, 'sha256': 'fa26e9610f3c838a3e43d91651b484981c3e0b40a057fe6a42177216349d425b'}, 'post_live_export': {'bytes': 9301, 'sha256': '702cf3f6e3563cf4ca84acf4b8565ef5ae9c9962052e8a91c2caa3d83ab77bb8'}}
ROOT_DRIVER = {'bytes':19050,'sha256':'b9f0914d63f619f840b4e38117b28c1cc3a0df29316cb22b92c8c0b1f6caaa92'}
ROOT_SOURCE_PACKAGE = {'bytes':430,'sha256':'f9781ca9b8909a7da58f8bba5569091f8f0c184441be21e0c7606ca97cbba828'}
ROOT_TRANSPORT_SOURCE = {'bytes':43438,'sha256':'860aaf747e89411efa993783b950f709b1d8ac5d7b606575065bdff74ef98e22'}

def need(ok,message):
    if not ok: raise ValueError(message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def descriptor(raw):
    need(type(raw) is bytes,'original bytes required')
    return {'bytes':len(raw),'sha256':sha(raw)}
def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode('utf-8')
def strict(raw):
    need(type(raw) is bytes,'strict JSON requires original bytes')
    def pairs(items):
        out={}
        for k,v in items:
            need(k not in out,'duplicate JSON key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def exact(value,expected):
    need(isinstance(value,dict) and all(k in value and type(value[k]) is type(v) and value[k]==v
        for k,v in expected.items()),'exact expected fields differ')
def byte_pin(row,*,maximum=32*1024*1024,allow_empty=False):
    need(isinstance(row,dict) and set(row)=={'bytes','sha256'}
        and type(row['bytes']) is int and (0 if allow_empty else 1)<=row['bytes']<=maximum
        and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),
        'bounded explicit byte pin required')
    return row
def file_descriptor(row,*,maximum=32*1024*1024):
    need(isinstance(row,dict) and set(row)=={'path','bytes','sha256'},'exact host original descriptor required')
    p=PurePosixPath(row['path']);need(p.is_absolute() and str(p)==row['path'] and '..' not in p.parts
        and '\0' not in row['path'],'canonical absolute original path required')
    byte_pin({k:row[k] for k in ('bytes','sha256')},maximum=maximum,allow_empty=True)
    return row
def bytes_match(raw,row):
    need(descriptor(raw)=={k:row[k] for k in ('bytes','sha256')},'original byte pin differs')
    return raw

PRIOR_FAILED_TRANSACTION = {'path':'/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/policy-native5-r10-preflight-reconciliation-01/RECONCILIATION.json',
    'bytes':4606,'sha256':'cc8ea602e3d9930dec45f912f752d2121308af2195156aee384becde1e3cfbf6'}

def verify_prior_failed_transaction(raw,*,read_pinned):
    """Recheck only the fixed, independently reconciled preflight failure."""
    bytes_match(raw,PRIOR_FAILED_TRANSACTION);closed=strict(raw)
    exact(closed,{'schema':'hepta.root.native5-preflight-failure-closure.v1',
        'state':'KNOWN_PRE_POLICY_FAILURE_RECONCILED_NO_REPLAY','actual_magiskpolicy_invocations':0,
        'failed_root_apply_phase_calls':1,'known_preflight_exit_code':1,'current_policy':PARENT,
        'lock_paths':6,'unique_lock_inodes':4,'automatic_retry':False,'signals':0,
        'native_case_sends':0,'new_native_case_nonces':0,
        'root_cause':'INVENTORY_ALIAS_PATHS_OPEN_SAME_INODE_TWICE_WHILE_FIRST_FLOCK_HELD'})
    def get(row):
        file_descriptor(row);return bytes_match(read_pinned(row),row)
    names=('actor_wrapper','original_failure','original_guard','original_operation',
        'original_shell','phone_read_only_source','phone_reconciliation')
    originals={name:get(closed[name]) for name in names}
    wrapper=strict(originals['actor_wrapper']);operation=strict(originals['original_operation'])
    need(set(operation)=={'actor_rc','wrapper_sha256','wrapper'},'prior original operation fields')
    exact(operation,{'actor_rc':0,'wrapper_sha256':sha(originals['actor_wrapper']),'wrapper':wrapper})
    exact(wrapper,{'schema':'hepta.phone-local.operator-result.v150.1','status':'command_exited',
        'label':'ng-c705647dd4ebb5d421be1041a9c41ca6-native5-live-apply',
        'model_decision':False,'native_task_result':False})
    ph=wrapper['phone'];exact(ph,{'rc':1,'stdout':''})
    need(isinstance(ph['stderr'],str) and ph['stderr'].endswith(
        'BlockingIOError: [Errno 11] Resource temporarily unavailable\n')
        and 'in preflight\n' in ph['stderr'] and 'ls=locks(inventory)' in ph['stderr']
        and 'in locks\n' in ph['stderr'],'prior exact preflight lock failure stream')
    guard=originals['original_guard'].decode('utf-8');shell=originals['original_shell'].decode('utf-8')
    pre=next(n for n in ast.parse(guard).body if isinstance(n,ast.FunctionDef) and n.name=='preflight')
    pre_text=ast.get_source_segment(guard,pre)
    need(pre_text.index('ls=locks(inventory)')<pre_text.index('D.mkdir(')<pre_text.index("record('APPLY-INTENT.json'"),
        'original preflight failure was not before reservation')
    need(shell.startswith('#!/system/bin/sh\nset -eu\n')
        and shell.index('--preflight-once\n')<shell.index('set +e\n')<
        shell.index('/data/adb/magisk/magiskpolicy --live --apply '),'original shell effect ordering differs')
    failure=strict(originals['original_failure'])
    exact(failure,{'schema':'hepta.root.native5-live-failure.v1','state':'ORIGINAL_TRANSACTION_STOPPED_NO_REPLAY',
        'error_type':'JSONDecodeError','policy_apply_calls':1,'automatic_retry':False,
        'automatic_rollback':False,'automatic_policy_adoption':False,
        'new_native_case_nonces':0,'native_case_sends':0})
    phases=['native5-stage-%02d'%i for i in range(8)]+['native5-stage-final','native5-live-apply']
    need(failure['phone_phase_names']==phases and len(failure['steps'])==10,'prior exact original phase set')
    for i,step in enumerate(failure['steps']):
        exact(step,{'phase':'phone-'+phases[i],'state':'ORIGINAL_HOST_CHILD_JOINED',
            'returncode':0,'automatic_retry':False})
        need(type(step['pid']) is int and step['pid']>0 and get(step['stderr'])==b'','prior joined host child and stderr')
        stepraw=get(step['stdout']);stepvalue=strict(stepraw)
        exact(stepvalue,{'actor_rc':0})
        if i==9:
            need(stepraw==originals['original_operation'],'prior failed operation is not the actual terminal step')
        else:exact(stepvalue['wrapper']['phone'],{'rc':0,'stderr':''})
    prior_plan_raw=get(failure['root_plan']);prior_plan=strict(prior_plan_raw)
    prior_intent=strict(get(failure['root_intent']))
    exact(prior_plan,{'schema':'hepta.root.native5-live-plan.v1','boot_id':BOOT})
    exact(prior_intent,{'schema':'hepta.root.native5-live-intent.v1','plan_sha256':sha(prior_plan_raw),
        'maximum_apply_attempts':1,'automatic_retry':False,'automatic_rollback':False,
        'automatic_policy_adoption':False,'new_native_case_nonces':0,'native_case_sends':0})
    steps=closed['steps'];need(len(steps)==2,'two independently completed reconciliation host steps')
    out=[]
    for phase,step in zip(('native5-failed-wrapper-original','phone-native5-fail-reconcile-01'),steps):
        exact(step,{'phase':phase,'state':'ORIGINAL_HOST_CHILD_JOINED','returncode':0,'automatic_retry':False})
        need(type(step['pid']) is int and step['pid']>0 and get(step['stderr'])==b'','reconciliation host terminal')
        out.append(strict(get(step['stdout'])))
    exact(out[0],{'state':'ORIGINAL_HOST_FILES_READ'})
    retained=out[0]['files']['actor_wrapper']
    need(set(out[0]['files'])=={'actor_wrapper'} and retained['path']==
        '/home/alex/razr60-local-model-v150/operations/ng-c705647dd4ebb5d421be1041a9c41ca6-native5-live-apply/result.json',
        'independent original wrapper path')
    wrapper_raw=base64.b64decode(retained['base64'],validate=True)
    need(base64.b64encode(wrapper_raw).decode('ascii')==retained['base64']
        and wrapper_raw==originals['actor_wrapper'],'independent original wrapper bytes differ')
    bytes_match(wrapper_raw,retained)
    rop=out[1];exact(rop,{'actor_rc':0})
    rw=rop['wrapper'];exact(rw,{'schema':'hepta.phone-local.operator-result.v150.1','status':'command_exited',
        'label':'ng-c705647dd4ebb5d421be1041a9c41ca6-native5-fail-reconcile-01',
        'model_decision':False,'native_task_result':False})
    exact(rw['phone'],{'rc':0,'stderr':''})
    outer=shlex.split(rw['phone']['command'])
    need(len(outer)==3 and outer[:2]==['/debug_ramdisk/su','-c'],'read-only reconciliation root wrapper')
    argv=shlex.split(outer[2])
    need(argv[:-2]==shlex.split(STAGE_ENV_PREFIX) and argv[-2]=='-c'
        and argv[-1].encode('utf-8')==originals['phone_read_only_source'],'actual read-only source command differs')
    observed=strict(rw['phone']['stdout'].encode('utf-8'))
    need(observed==strict(originals['phone_reconciliation']),'actual read-only stdout differs from retained original')
    exact(observed,{'schema':'hepta.native5-r10.failed-preflight-read-only-reconciliation.v1',
        'state':'ORIGINAL_PREFLIGHT_EXITED_BEFORE_OUTPUT_RESERVATION_AND_BEFORE_POLICY_WRITE',
        'boot_id':BOOT,'policy':PARENT,'phone_file_writes':0,'policy_apply_calls':0,
        'flock_calls':0,'signals':0,'automatic_retry':False,'new_native_case_nonces':0,'native_case_sends':0,
        'matching_external_lock_holders':[],'failed_output_paths_absent':[
            BASE+'/policy-native5-r10-live-01','/proc/1/root'+NATIVE_BASE+'/policy-native5-r10-live-01']})
    tree=ast.parse(originals['phone_read_only_source']);node=tree.body[0]
    need(isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
        and node.targets[0].id=='LOCKS','read-only fixed lock declaration')
    expected=sorted(ast.literal_eval(node.value),key=lambda x:x['path'])
    need(len(expected)==6 and observed['locks']==[
        {k:r[k] for k in ('path','metadata','bytes','sha256')} for r in expected],'all six original lock paths/full9/bytes')
    groups={};identities={}
    for row in observed['locks']:
        m=row['metadata'];need(len(m)==9 and all(type(x) is int and x>=0 for x in m),'exact original full-nine metadata')
        key=tuple(m[:2]);value=(m,row['bytes'],row['sha256'])
        need(key not in identities or identities[key]==value,'aliased original lock metadata or bytes differ')
        identities[key]=value;groups.setdefault(key,[]).append(row['path'])
    need(len(groups)==4 and observed['unique_inodes']==[
        {'device':k[0],'inode':k[1],'paths':paths} for k,paths in groups.items()],'complete four inode alias partition')
    record=observed['proc_locks'];lockraw=base64.b64decode(record['base64'],validate=True)
    bytes_match(lockraw,record)
    need(base64.b64encode(lockraw).decode('ascii')==record['base64'],'canonical original proc locks bytes')
    targets={(((dev>>8)&0xfff)|((dev>>32)&~0xfff),(dev&0xff)|((dev>>12)&~0xff),ino) for dev,ino in groups}
    for line in lockraw.decode('ascii').splitlines():
        for token in line.split():
            if re.fullmatch('[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9]+',token):
                a,b,c=token.split(':');need((int(a,16),int(b,16),int(c)) not in targets,
                    'original retained inode had an external lock holder')
    return {'schema':'hepta.native5-r10.exact-prior-failure-recheck.v1',
        'prior_failed_transaction_sha256':sha(raw),'phone_reconciliation_sha256':sha(originals['phone_reconciliation']),
        'state':'FIXED_KNOWN_PREFLIGHT_FAILURE_RECHECKED','actual_magiskpolicy_invocations':0,
        'all_six_path_originals_retained':True,'unique_lock_inodes':4,'phone_calls':0,'policy_writes':0}

def root_scope(raw):
    bytes_match(raw,DECISION);v=strict(raw)
    exact(v,{'schema':'hepta.root.native5.policy-scope-decision.v1',
        'state':'TWELVE_ATOM_HOST_CANDIDATE_SELECTED_LIVE_APPLY_PENDING_SOURCE_REVIEW',
        'permission_atom_count':12,'primary_atoms':8,'stderr_property_atoms':4,
        'existing_fd_use_retained':True,'live_policy_writes':0,'native_qualification':False,
        'static_dependency_observations_are_not_dynamic_resolution_proof':True})
    need([(r['source'],r['target'],r['class'],r['permissions']) for r in v['rows']]==ROWS,
         'Root selected exactly five edges and twelve atoms')
    need({k:v['parent_policy'][k] for k in ('bytes','sha256')}==PARENT
        and {k:v['parent_adoption_history'][k] for k in ('bytes','sha256')}==PARENT_ADOPTION,
        'Root original parent policy/adoption differs')
    return v

def validate_complete_comparison(report,*,expected_kind,root_scope_decision):
    """Check the complete new report schema, not a renamed historical PASS."""
    need(expected_kind in ('offline_candidate','post_live_export'),'explicit comparison kind')
    decision=root_scope(root_scope_decision)
    exact(report,{'schema':'hepta.native5-r10.complete-policy-comparison.v1',
        'state':'EXACT_TWELVE_APPROVED_PERMISSION_DELTA_VERIFIED','comparison_kind':expected_kind,
        'approved_rule_atoms':ATOMS,'phone_operations':0,'active_policy_writes':0,
        'live_policy_adoption_authorized':False,'business_qualified':False})
    for key in ('parent','candidate','root_scope_decision','parent_adoption_history'):
        file_descriptor(report[key])
    need({k:report['parent'][k] for k in ('bytes','sha256')}==PARENT
        and {k:report['root_scope_decision'][k] for k in ('bytes','sha256')}==DECISION
        and {k:report['parent_adoption_history'][k] for k in ('bytes','sha256')}==PARENT_ADOPTION,
        'complete comparison is for another policy/decision/history')
    exact(report['semantic_delta'],{'added_atoms':ATOMS,'removed_atoms':[],
        'all_raw_TE_counter_delta_bound':True,'unconditional_only':True})
    exact(report['coverage'],{'all_TE_rules_enumerated':True,'multiplicity_preserved':True,
        'conditional_expression_and_branch_preserved':True,'explicit_xperm_type_and_all_integers':True,
        'actual_conditional_list_empty':True,'actual_conditional_avtab_count':0,
        'unsupported_rule_kinds':[],'errors':[]})
    full=report['full_image_comparison']
    exact(full,{'all_enumerated_roundtrip_semantics_preserved':True,
        'all_orbit_members_structurally_and_semantically_verified':True})
    image=full['result']
    exact(image,{'schema':'hepta.official-libsepol-native5-full-image-comparison.v1',
        'complete_input_consumption':True,'cycle_bound':4,'all_cycles_close_at_first_image':True,
        'all_cycle_representatives_stable':True,
        'normalization':'lexicographic-minimum-complete-official-serialization-cycle',
        'only_approved_delta_full_image_equal':True,'negative_missing_atom_rejected':True,
        'negative_unapproved_binder_change_rejected':True,'negative_unknown_handling_rejected':True})
    exact(image,{'approved_rule_atoms':ATOMS,'approved_permission_atom_count':12,
        'baseline_conditional_list_empty':True,'candidate_conditional_list_empty':True,
        'baseline_boolean_count':0,'candidate_boolean_count':0,
        'baseline_conditional_avtab_nodes':0,'candidate_conditional_avtab_nodes':0})
    need(type(image['approved_new_allow_nodes']) is int and 0<=image['approved_new_allow_nodes']<=5,
        'unexpected compiled allow-key expansion')
    orbits=image['serialization_orbits']
    need(isinstance(orbits,list) and [r.get('name') for r in orbits]==
        ['parent','candidate','expected','negative-handle-unknown','negative-binder-change'],
        'complete official serialization cycle set differs')
    for r in orbits:
        need(set(r)=={'name','length','selected_index'} and type(r['length']) is int
            and 1<=r['length']<=4 and type(r['selected_index']) is int
            and 1<=r['selected_index']<=r['length'],'bounded complete serialization cycle differs')
    need(type(image['raw_serializer_idempotent']) is bool
        and image['raw_serializer_idempotent']==all(r['length']==1 for r in orbits),
        'raw idempotence may not be invented')
    av=report['full_av_checks']
    exact(av,{'all_compiled_AV_nodes_validated':True,'all_symbolic_AV_permission_atoms_compared':True,
        'parent_original_query_reexecuted':False,'candidate_complete_compute_av_verified':True,
        'candidate_approved_permission_count':12,'existing_apex_search_unchanged':True,
        'existing_fd_use_preserved_by_complete_TE_counter':True})
    need(len(av['parent_original_compute_av'])==len(av['candidate_complete_compute_av'])==5,
        'all five approved AV edges required')
    for (src,target,cl,perms),row in zip(ROWS,av['candidate_complete_compute_av']):
        exact(row,{'schema':'hepta.offline-policy-av.v1','state':'COMPLETE_OFFLINE_AV_QUERY',
            'denied_requested':'0x00000000','denial_reason_mask':0})
        context=('u:r:' if cl=='binder' else 'u:object_r:')+target+':s0'
        query=row['query']
        need(set(query)=={'source','target','class','class_value','source_type_value','target_type_value',
            'source_policy_permissive','source_policy_neveraudit'}
            and {k:query[k] for k in ('source','target','class')}==
                {'source':'u:r:'+src+':s0','target':context,'class':cl}
            and all(type(query[k]) is int and query[k]>0 for k in
                ('class_value','source_type_value','target_type_value'))
            and query['source_policy_permissive'] is False and query['source_policy_neveraudit'] is False
            and row['policy']['sha256']==report['candidate']['sha256']
            and row['policy']['bytes']==report['candidate']['bytes']
            and row['policy']['input_unchanged'] is True
            and [p['name'] for p in row['permissions']]==perms
            and all(p['policy_allowed'] is True and p['denial_reason_mask']==0 for p in row['permissions']),
            'actual candidate full AV does not allow exactly the approved query')
    checks=report['checks']
    need(isinstance(checks,list) and 15<=len(checks)<=64
        and all(isinstance(x,dict) and x.get('passed') is True for x in checks)
        and type(report['check_count']) is type(report['passed_count']) is int
        and report['check_count']==report['passed_count']==len(checks),'complete comparison checks did not all pass')
    if expected_kind=='offline_candidate':
        need(report['construction_original_semantic_delta_flag_preserved'] is False,
            'construction-only original flag must remain false')
    return report

def verified_offline(raw,decision_raw):
    need(isinstance(REVIEWED_OFFLINE_COMPARISON,dict) and isinstance(REVIEWED_COMPARISON_SOURCES,dict),
        'actual independent comparison/source review pins are not frozen')
    bytes_match(raw,REVIEWED_OFFLINE_COMPARISON)
    v=validate_complete_comparison(strict(raw),expected_kind='offline_candidate',root_scope_decision=decision_raw)
    need(v['sources']==REVIEWED_COMPARISON_SOURCES,'actual reviewed comparator sources differ')
    return v


def reviewed_source_sha256():
    value=globals().get('__reviewed_source_sha256__')
    need(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value),
        'caller must inject the digest of the exact reviewed verifier raw bytes')
    return value


def decode_original_archive(raw,caprow,binding_sha):
    need(type(raw) is bytes and 0<len(raw)<=8*1024*1024,'bounded actual original archive required')
    z=zlib.decompressobj(31);data=z.decompress(raw,26*1024*1024+1)
    need(len(data)<=26*1024*1024 and z.eof and not z.unconsumed_tail and not z.unused_data,
        'complete bounded gzip required')
    files={}
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as tf:
        members=tf.getmembers();need(15<=len(members)<=97,'bounded original member count')
        for m in members:
            need(m.isfile() and not m.issym() and not m.islnk()
                and re.fullmatch('[A-Za-z0-9_.-]{1,100}',m.name) and m.name not in ('.','..')
                and m.name not in files and 0<=m.size<=8*1024*1024 and m.uid==m.gid==0
                and m.mode==0o600 and not m.pax_headers,'exact regular original tar member required')
            stream=tf.extractfile(m);need(stream is not None,'missing member body')
            b=stream.read(m.size+1);need(len(b)==m.size,'incomplete member body');files[m.name]=b
    need('CAPTURE.json' in files and descriptor(files['CAPTURE.json'])==caprow,'capture raw bytes differ')
    cap=strict(files['CAPTURE.json'])
    exact(cap,{'schema':'hepta.native5-r10.live-original-capture.v1','state':'CAPTURED_EXISTING_APPLY_ORIGINALS',
        'binding_sha256':binding_sha,'new_effects':0,'policy_adoption_authorized':False,'business_qualified':False})
    rows=cap['files']
    need(isinstance(rows,list) and len({r['path'] for r in rows})==len(rows)==cap['file_count']
        and set(files)=={r['path'] for r in rows}|{'CAPTURE.json'},'complete original inventory differs')
    total=0
    for row in rows:
        need(set(row)=={'path','original_path','bytes','sha256','metadata'}
            and row['original_path']==BASE+'/'+OUT_NAME+'/'+row['path'],'original source path differs')
        b=bytes_match(files[row['path']],row);m=row['metadata']
        need(isinstance(m,list) and len(m)==9 and all(type(x) is int and x>=0 for x in m)
            and m[2]==0o100600 and m[3:6]==[0,0,1] and m[6]==len(b),'actual private metadata differs')
        total+=len(b)
    need(total==cap['total_bytes'] and total<=24*1024*1024,'complete archive byte budget differs')
    return files,cap


MANDATORY_LIVE_FILES = {
    'BINDING.original.json','ACTUAL-RETIREMENT-INPUTS.original.json','RETIREMENT-HOST-CLOSURE.original.json',
    'ROOT-SCOPE-DECISION.original.json','PARENT-ADOPTION-HISTORY.original.json',
    'LATEST-BOUNDARY-DESCRIPTOR.original.json','CLOSED-COMPONENT-PACKAGE.original.json',
    'OFFLINE-COMPLETE-COMPARISON.original.json','PRECHECK.json','APPLY-INTENT.json','COMMAND-RETURN.json',
    'POLICY-APPLY.json','live-policy-before.bin','live-policy-after.bin','policy.stdout','policy.stderr',
    'native5.delta.rule','parent-candidate.rule','full-candidate.rule','ORIGINAL-SOURCE-PATHS.json',
    'guard_live_native5.original.py','policy_native5_verifier.original.py','apply_native5_once.original.sh',
    'closed-04-BOUNDARY.original.json','closed-04-INVENTORY.original.json','closed-04-CLOSURE.original.json',
    'closed-03-BOUNDARY.original.json','closed-03-INVENTORY.original.json','closed-03-CLOSURE.original.json',
    'closed-source-component_common.original.py','closed-source-native_proc_profile.original.py',
    'closed-source-component_lifecycle.original.py','closed-source-component_snapshot.original.py',
    'closed-source-late_boundary.original.py','STAGE-INTENT.original.json','STAGE-COMPLETE.original.json'}


def verify_apply_originals(files,binding_sha):
    need(MANDATORY_LIVE_FILES<=set(files),'complete original policy transaction files missing')
    raw=files['BINDING.original.json'];need(sha(raw)==binding_sha,'actual binding raw differs')
    b=validate_binding(raw,decision_raw=files['ROOT-SCOPE-DECISION.original.json'],
        comparison_raw=files['OFFLINE-COMPLETE-COMPARISON.original.json'],
        retirement_raw=files['ACTUAL-RETIREMENT-INPUTS.original.json'],
        parent_adoption_raw=files['PARENT-ADOPTION-HISTORY.original.json'],
        boundary_descriptor_raw=files['LATEST-BOUNDARY-DESCRIPTOR.original.json'],
        package_raw=files['CLOSED-COMPONENT-PACKAGE.original.json'])
    for name,key in (('guard_live_native5.original.py','guard_source'),
                     ('policy_native5_verifier.original.py','verifier_source'),
                     ('apply_native5_once.original.sh','shell_source')):
        bytes_match(files[name],b[key])
    need(b['verifier_source']['sha256']==reviewed_source_sha256(),'actual apply used another verifier source')
    for name,row in b['component_sources'].items():
        bytes_match(files['closed-source-'+name+'.original.py'],row)
    need(files['native5.delta.rule']==RULE and files['full-candidate.rule']==files['parent-candidate.rule']+RULE,
        'rule bytes are not exact parent plus the twelve approved atoms')
    bytes_match(files['parent-candidate.rule'],PARENT_RULE);bytes_match(files['full-candidate.rule'],FULL_RULE)
    for name,pin in [('live-policy-before.bin',PARENT),('closed-04-BOUNDARY.original.json',BOUNDARY),
        ('closed-04-CLOSURE.original.json',BOUNDARY_CLOSURE),('closed-04-INVENTORY.original.json',BOUNDARY_INVENTORY),
        ('closed-03-BOUNDARY.original.json',LEGACY_BOUNDARY),('closed-03-CLOSURE.original.json',LEGACY_CLOSURE),
        ('closed-03-INVENTORY.original.json',LEGACY_INVENTORY)]:bytes_match(files[name],pin)
    latest=strict(files['closed-04-BOUNDARY.original.json']);old=strict(files['closed-03-BOUNDARY.original.json'])
    need(latest['prior_boundary']==old_boundary_descriptor(old,latest['prior_boundary'])
        and old['prior_boundary'] is None and latest['combination_sha256']==old['combination_sha256']==COMBINATION_SHA256,
        'original latest04-to03 tail differs')
    pre=strict(files['PRECHECK.json']);intent=strict(files['APPLY-INTENT.json']);ret=strict(files['COMMAND-RETURN.json'])
    report=strict(files['POLICY-APPLY.json'])
    exact(pre,{'schema':'hepta.native5-r10.live-precheck.v1','state':'LATEST_CLOSED_BOUNDARY_VERIFIED_FOR_SINGLE_APPLY',
        'binding_sha256':binding_sha,'boot_id':BOOT,'parent_policy':PARENT,'root_scope_decision':DECISION,
        'approved_rule':descriptor(RULE),'policy_apply_attempts':0,'automatic_retry':False,'automatic_rollback':False})
    exact(intent,{'schema':'hepta.native5-r10.single-apply-intent.v1','binding_sha256':binding_sha,
        'precheck_sha256':sha(files['PRECHECK.json']),'argv':ARGV,'maximum_apply_attempts':1,
        'root_scope_decision_sha256':DECISION['sha256'],'pre_policy_boundary_sha256':BOUNDARY['sha256'],
        'apply_timeout_seconds':45,'kill_grace_seconds':5,'automatic_retry':False,
        'automatic_rollback':False,'automatic_policy_adoption':False})
    exact(ret,{'schema':'hepta.native5-r10.actual-command-return.v1','return_code':0,
        'argv':ARGV,'binding_sha256':binding_sha,'apply_attempts':1,'maximum_apply_attempts':1,
        'apply_timeout_seconds':45,'kill_grace_seconds':5,'automatic_retry':False,'automatic_rollback':False})
    exact(report,{'schema':'hepta.native5-r10.actual-live-apply.v1',
        'state':'ACTUAL_SINGLE_APPLY_REQUIRES_INDEPENDENT_LIVE_COMPARISON','binding_sha256':binding_sha,
        'return_code':0,'apply_attempts':1,'maximum_apply_attempts':1,'argv':ARGV,
        'apply_timeout_seconds':45,'kill_grace_seconds':5,'parent_policy':PARENT,'approved_rule_atoms':ATOMS,
        'delta_rule':descriptor(RULE),'full_rule':FULL_RULE,'root_scope_decision':DECISION,
        'pre_policy_boundary':BOUNDARY,'actual_parser_sha256':PARSER['sha256'],
        'boot_id':BOOT,'enforcing':True,'postcheck_error':None,'clean_apply_observed':True,
        'automatic_retry':False,'automatic_rollback':False,'policy_adoption_authorized':False,
        'independent_live_complete_comparison_required':True,'service_start_admitted':False,
        'model_requests':0,'task_submissions':0,'ui_actions':0,'service_starts':0,'service_stops':0,'business_qualified':False})
    need(report['offline_candidate']==b['offline_candidate']
        and report['complete_offline_comparison']==b['complete_offline_comparison']
        and report['actual_live_policy']==descriptor(files['live-policy-after.bin'])
        and report['actual_live_policy']!=PARENT and files['policy.stdout']==files['policy.stderr']==b''
        and report['stdout']==report['stderr']==descriptor(b'')
        and report['precheck_sha256']==sha(files['PRECHECK.json'])
        and report['intent_sha256']==sha(files['APPLY-INTENT.json']), 'actual apply/streams/export originals disagree')
    need(type(report['live_bytes_equal_offline_candidate']) is bool
        and report['live_bytes_equal_offline_candidate']==(report['actual_live_policy']==b['offline_candidate']),
        'kernel export equality is an observation, never a precondition')
    post=report['postchecks']
    exact(post,{'complete_original_state_equal':True,'complete_service_records_equal':True,
        'original_UI_adbd_rootfs_mounts_preserved':True,'old_module_disabled':True,
        'old_retirement_current_equality_claimed':False})
    prestate=pre['pre_policy_boundary_verification'];poststate=post['pre_policy_boundary_verification']
    for state in (prestate,poststate):
        exact(state,{'schema':'hepta.native5-r10.pre-policy-boundary-verification.v1',
            'state':'EXACT_LATEST04_AND_EXTERNAL03_CUMULATIVE_ORIGINALS_UNCHANGED',
            'previous_boundary':BOUNDARY,'closed_components':2,'inventory_sha256':BOUNDARY_INVENTORY['sha256'],
            'original_retirement_sha256':RETIREMENT,'old_retirement_current_equality_claimed':False,
            'original_retirement_rewritten':False,'phone_tool_calls':0,'model_requests':0,'signals':0,'writes':0})
        need(state['roots']==latest['roots'] and len(state['absence_observations'])==2,
            'complete latest roots and two group absences required')
        for absence in state['absence_observations']:
            need(absence['members']==[] and absence['kernel_group_absence'] is True,'owned role absence incomplete')
    need({k:v for k,v in prestate.items() if k not in ('absence_observations','endpoints')}==
         {k:v for k,v in poststate.items() if k not in ('absence_observations','endpoints')},
         'original cumulative state changed across apply')
    for gate in (pre['global_gate'],post['global_gate']):
        need(gate['exit_code']==0 and gate['read_only'] is True,'global pending gate failed')
    need(pre['locks']==post['locks'] and all(x['exclusive_nonblocking_acquired'] is True for x in post['locks']),
         'original journal/claim locks differ or are held')
    need(type(pre['observed_monotonic_ns']) is type(intent['issued_monotonic_ns']) is type(ret['observed_monotonic_ns']) is int
        and 0<pre['observed_monotonic_ns']<=intent['issued_monotonic_ns']<=ret['observed_monotonic_ns'],
        'actual phone operation ordering differs')
    return b,report


def old_boundary_descriptor(old,row):
    need({k:row[k] for k in ('bytes','sha256')}==LEGACY_BOUNDARY
        and old['nonce']=='88d68d88130d3c74e6c950a6346357c1'
        and old['component_qualified'] is False and old['actual_native_calls']==0,
        'exact failed external ancestor required')
    return row


def expectation_value(binding_raw,*,binding_descriptor,decision_descriptor,comparison_descriptor):
    file_descriptor(binding_descriptor);file_descriptor(decision_descriptor);file_descriptor(comparison_descriptor)
    bytes_match(binding_raw,binding_descriptor);b=strict(binding_raw)
    need(b['schema']=='hepta.native5-r10.live-apply-binding.v1' and b['root_approval']==APPROVAL
        and b['root_scope_decision']==DECISION and b['pre_policy_boundary']==BOUNDARY
        and b['parent_policy']==PARENT and b['approved_rule_atoms']==ATOMS,
        'actual reviewed binding is required before expectation')
    need({k:decision_descriptor[k] for k in ('bytes','sha256')}==DECISION
        and {k:comparison_descriptor[k] for k in ('bytes','sha256')}==b['complete_offline_comparison'],
        'expectation source original pins differ')
    return {'schema':'hepta.native5-r10.policy-pre-live-expectation.v1','release_id':'v150-r10-r1',
        'boot_id':BOOT,'binding':binding_descriptor,'root_scope_decision':decision_descriptor,
        'offline_comparison':comparison_descriptor,'parent_policy':PARENT,'offline_candidate':b['offline_candidate'],
        'comparison_route':'verified_semantic_export','expected_live_export':None,'approved_rule':descriptor(RULE),
        'retirement_sha256':RETIREMENT,'prior_boundary_sha256':BOUNDARY['sha256'],
        'parent_adoption_sha256':PARENT_ADOPTION['sha256'],'policy_adoption_authorized':False,
        'service_start_admitted':False,'phone_calls':0,'policy_writes':0}


def verify_pre_live_expectation(expectation_raw,*,read_pinned):
    v=strict(expectation_raw)
    binding=read_pinned(file_descriptor(v['binding']));bytes_match(binding,v['binding'])
    decision=read_pinned(file_descriptor(v['root_scope_decision']));root_scope(decision)
    comparison=read_pinned(file_descriptor(v['offline_comparison']));verified_offline(comparison,decision)
    need(strict(binding)['verifier_source']['sha256']==reviewed_source_sha256(),
        'pre-live expectation is bound to another verifier source')
    need(v==expectation_value(binding,binding_descriptor=v['binding'],decision_descriptor=v['root_scope_decision'],
        comparison_descriptor=v['offline_comparison']),'explicit pre-load semantic/null expectation differs')
    return v


def descriptor_key(row):
    file_descriptor(row);return (row['path'],row['bytes'],row['sha256'])


def original_process(value,get,*,argv,outer=False):
    """Read the actual original streams; no child is run by this verifier."""
    exact(value,{'argv':argv,'returncode':0,'timed_out':False,
        'captured_streams_complete':True,'automatic_retry':False})
    if outer:
        exact(value,{'phone_operations':0,'active_policy_writes':0})
        need(value['input_originals_before']==value['input_originals_after']
            and type(value['started_epoch_ns']) is type(value['ended_epoch_ns']) is int
            and 0<value['started_epoch_ns']<=value['ended_epoch_ns'],
            'original host execution input or timestamp bookends differ')
        need(type(value['elapsed_seconds']) in (int,float) and 0<=value['elapsed_seconds']<=900,
            'bounded original host elapsed time required')
    else:exact(value,{'host_only':True})
    need(get(value['stderr'])==b'','original comparison child stderr is not empty')
    return strict(get(value['stdout']))


def verify_comparison_proof(index_raw,*,expected_kind,read_pinned,decision_raw,live_summary=None,live_inputs_raw=None):
    """Verify the retained source/process proof without rerunning policy parsers.

    The official image cycle is retained separately. This gate reads its raw C
    output and the actual audited comparator output, not every cycle image.
    Original P4 paths are resolved only through the explicit origin map.
    """
    index=strict(index_raw)
    fields={'schema','comparison_kind','report','plan','process','execution','files','origin_map',
        'complete_archive','complete_archive_manifest',
        'complete_comparison_outputs_retained_elsewhere','all_orbit_images_embedded',
        'phone_operations','active_policy_writes'}
    need(set(index)==fields,'explicit complete proof-index fields differ')
    exact(index,{'schema':'hepta.native5-r10.adoption-proof-inputs.v1',
        'comparison_kind':expected_kind,'complete_comparison_outputs_retained_elsewhere':True,
        'all_orbit_images_embedded':False,'phone_operations':0,'active_policy_writes':0})
    # These references preserve the separately retained complete evidence.
    # Their orbit images are not implicitly copied into the runtime bundle.
    file_descriptor(index['complete_archive'],maximum=256*1024*1024)
    file_descriptor(index['complete_archive_manifest'])
    rows=index['files'];need(isinstance(rows,list) and 4<=len(rows)<=512,'bounded complete proof file set')
    retained={};by_path={};total=0
    for row in rows:
        key=descriptor_key(row);need(row['path'] not in by_path,'duplicate retained proof path')
        raw=bytes_match(read_pinned(row),row);retained[key]=raw;by_path[row['path']]=row;total+=len(raw)
    need(total<=16*1024*1024,'bounded small proof original set required')
    mappings=index['origin_map'];need(isinstance(mappings,list) and len(mappings)==len(rows),
        'one explicit original-to-retained mapping per proof original required')
    original={};reverse={};original_paths=set()
    for item in mappings:
        need(set(item)=={'original','retained'},'exact original/retained mapping required')
        a,b=item['original'],item['retained'];ka,kb=descriptor_key(a),descriptor_key(b)
        need(a['path'] not in original_paths and ka not in original and kb in retained and kb not in reverse
            and a['bytes']==b['bytes'] and a['sha256']==b['sha256'],
            'explicit original copy mapping is missing, duplicated, or changed')
        original_paths.add(a['path']);original[ka]=retained[kb];reverse[kb]=a
    def get(row):
        key=descriptor_key(row);need(key in original,'required original absent from explicit proof map')
        return original[key]
    top={}
    for key in ('report','plan','process','execution'):
        identity=descriptor_key(index[key]);need(identity in retained and identity in reverse,'top proof original is not indexed')
        top[key]=(reverse[identity],retained[identity])
    report_raw=top['report'][1];report=validate_complete_comparison(strict(report_raw),
        expected_kind=expected_kind,root_scope_decision=decision_raw)
    if expected_kind=='offline_candidate':verified_offline(report_raw,decision_raw)
    else:
        need(isinstance(REVIEWED_POST_COMPARATOR_SOURCE,dict),'reviewed post-comparator source is not frozen')
        need({k:report['sources']['comparator'][k] for k in ('bytes','sha256')}==REVIEWED_POST_COMPARATOR_SOURCE,
            'actual post report uses another source revision')
    sources=report['sources'];plan=strict(top['plan'][1]);process=strict(top['process'][1]);execution=strict(top['execution'][1])
    for key in ('root_scope_decision','parent','candidate'):
        need(plan[key]==report[key],'comparison plan/report input differs')
    need(plan['parent_adoption']==report['parent_adoption_history'],'comparison history input differs')
    bytes_match(get(plan['root_scope_decision']),DECISION);bytes_match(get(plan['parent_adoption']),PARENT_ADOPTION)
    need(get(plan['delta_rule'])==RULE and get(plan['full_rule'])==get(plan['parent_rule'])+RULE,
        'proof rules are not exact approved bytes')
    bytes_match(get(plan['parent_rule']),PARENT_RULE);bytes_match(get(plan['full_rule']),FULL_RULE)
    for name in ('comparator','image_comparator','image_comparator_source','existing_tools','candidate_av_tool','candidate_av_source'):
        get(sources[name])
    common_sources={k:v for k,v in sources.items() if k not in ('comparator','live_provenance_verifier','image_build_result')}
    need(isinstance(REVIEWED_COMPARISON_SOURCES,dict) and all(
        {q:v[q] for q in ('bytes','sha256')}=={q:REVIEWED_COMPARISON_SOURCES[k][q] for q in ('bytes','sha256')}
        for k,v in common_sources.items()),'complete comparator binary/tool source pins differ')
    for name,key in [('image_comparator','image_comparator'),('image_comparator_source','image_comparator_source'),
        ('existing_tools','tool_inventory'),('candidate_av_tool','candidate_av_tool'),('candidate_av_source','candidate_av_source')]:
        need(sources[name]==plan[key],'report source does not identify original plan input')
    output=str(PurePosixPath(top['report'][0]['path']).parent)
    argv=['/usr/bin/python3','-I','-B',sources['comparator']['path'],'--plan',top['plan'][0]['path'],
        '--plan-sha256',top['plan'][0]['sha256'],'--out',output,'--execute-host-only']
    result=original_process(process,get,argv=argv,outer=True)
    exact(result,{'state':report['state'],'checks':15,'result':top['report'][0],
        'new_atoms':12,'removed_atoms':0,'phone_operations':0,'active_policy_writes':0})
    need(isinstance(REVIEWED_COMPARISON_RUNNERS,dict) and expected_kind in REVIEWED_COMPARISON_RUNNERS,
        'reviewed actual host comparison runner source is not frozen')
    bytes_match(get(execution['source']),REVIEWED_COMPARISON_RUNNERS[expected_kind])
    exact(execution,{'schema':'hepta.native5.actual-host-execution.v1',
        'plan':top['plan'][0],'comparison_process':top['process'][0],'report':top['report'][0],
        'root_scope_decision':plan['root_scope_decision'],'parent':plan['parent'],'candidate':plan['candidate'],
        'returncode':0,'timed_out':False,'captured_streams_complete':True,'automatic_retry':False,
        'all_originals_rechecked':True,'check_count':15,'passed_count':15,'phone_operations':0,
        'active_policy_writes':0,'live_policy_adoption_authorized':False,'business_qualified':False})
    wanted_state=('ACTUAL_HOST_CONSTRUCTION_AND_COMPLETE_COMPARISON_FINISHED' if expected_kind=='offline_candidate'
        else 'ACTUAL_HOST_POST_LIVE_COMPLETE_COMPARISON_FINISHED')
    need(execution['state']==wanted_state,'actual comparison execution kind differs')
    proof_rows=report['retained_originals'];need(isinstance(proof_rows,list),'complete original child index required')
    children={}
    for row in proof_rows:
        name=PurePosixPath(row['path']).name;need(name not in children,'duplicate original child filename');children[name]=row
    def child(label,argv):
        row=children.get(label+'.PROCESS.json');need(row is not None,'missing actual original child terminal')
        value=strict(get(row));need(value['stdout']==children.get(label+'.stdout.original')
            and value['stderr']==children.get(label+'.stderr.original'),'child index and terminal streams differ')
        return original_process(value,get,argv=argv)
    image=child('complete-image',[plan['image_comparator']['path'],'--compare-twelve-approved-native5',
        plan['parent']['path'],plan['candidate']['path'],output+'/normalized'])
    need(image==report['full_image_comparison']['result'],'complete C image output differs from report')
    parent_rows=plan['parent_av_originals'];need(parent_rows==report['full_av_checks']['parent_original_compute_av']
        and len(parent_rows)==5,'original five-edge AV input set differs')
    expected_parent_hashes=['6390d8bcf2391bb8596b6c7ca4fdece74b99dcb5374900c15dc43a3829418a10',
        '0915b3442cd1802f70bf3b389a99a6b5aa5fa9124d391fabb8aed76a4faf2cc7',
        'deddecb8c318fbe49a6f9d0e6efa4c68738cf0993ad4f45da50d0ab8c1e50a58',
        'cfd2a37a8d859737b0814035b256304cb3acbda074ba707e78eb9c2ee39b5f14',
        '4dffcf63b0da23dc95bac4c87d97e3b144c555af7d695e1fcd76fe4f8e904b18']
    for i,((src,target,kind,perms),old_desc) in enumerate(zip(ROWS,parent_rows)):
        old_raw=get(old_desc);need(sha(old_raw)==expected_parent_hashes[i],'original parent complete-AV output differs')
        old=strict(old_raw);context=('u:r:' if kind=='binder' else 'u:object_r:')+target+':s0'
        cmd=[plan['candidate_av_tool']['path'],'--policy',plan['candidate']['path'],'--sha256',plan['candidate']['sha256'],
            '--source','u:r:'+src+':s0','--target',context,'--class',kind]
        for perm in perms:cmd+=['--perm',perm]
        new=child('candidate-complete-av-%02d'%(i+1),cmd)
        need(new==report['full_av_checks']['candidate_complete_compute_av'][i] and new['query']==old['query'],
            'complete AV original full query or result changed')
        before={r['name']:r for r in old['permissions']}
        need(len(before)==len(old['permissions']) and all(before[n]['policy_allowed'] is False
            and before[n]['denial_reason_mask']==1 for n in perms),'original approved parent bits were not TE denied')
        for item in new['permissions']:
            need(all(item[k]==before[item['name']][k] for k in
                ('name','bit','auditallow_bit','auditdeny_bit','denied_with_auditdeny_clear')),
                'AV identity/audit behavior changed outside exact policy bits')
        need(all(new[k]==old[k] for k in ('decided','auditallow','auditdeny')),'AV audit/decision vector changed')
    apex_raw=get(plan['parent_apex_original']);need(sha(apex_raw)=='692842c819c20cc6cfc03b59686da0473ba5cea64996bb354c01168344e242a4',
        'actual original APEX query differs')
    apex=child('candidate-existing-apex-search',[plan['candidate_av_tool']['path'],'--policy',plan['candidate']['path'],
        '--sha256',plan['candidate']['sha256'],'--source','u:r:'+WORKER+':s0',
        '--target','u:object_r:apex_mnt_dir:s0','--class','dir','--perm','search'])
    before=strict(apex_raw)
    need(all(apex[k]==before[k] for k in ('query','requested','allowed','denied_requested','denial_reason_mask',
        'decided','auditallow','auditdeny','permissions')),'existing APEX permission changed')
    if expected_kind=='offline_candidate':
        receipt=strict(get(plan['construction_receipt']));need(plan['construction_receipt']==report['construction_original']
            and execution['construction_receipt']==plan['construction_receipt'],'original construction linkage differs')
        exact(receipt,{'schema':'hepta.native5.offline-construction-receipt.v1',
            'state':'COMPLETE_OFFLINE_CANDIDATE_CONSTRUCTION','parent':plan['parent'],'candidate':plan['candidate'],
            'root_scope_decision':plan['root_scope_decision'],'semantic_delta_verified':False,
            'phone_operations':0,'active_policy_writes':0,'input_originals_unchanged':True})
        need(receipt['image_constructor']==plan['image_comparator']
            and receipt['image_constructor_source']==plan['image_comparator_source']
            and execution['build']==receipt['build_result'],'actual construction source/build linkage differs')
        build_desc=receipt['build_result']
        constructed=original_process(strict(get(receipt['process'])),get,argv=[plan['image_comparator']['path'],
            '--construct-twelve-approved-native5',plan['parent']['path'],str(PurePosixPath(plan['candidate']['path']).parent)],outer=True)
        exact(constructed,{'schema':'hepta.official-libsepol-native5-candidate-construction.v1',
            'state':'CANDIDATE_CONSTRUCTED_NOT_YET_SEMANTICALLY_VERIFIED','approved_rule_atoms':ATOMS,
            'approved_permission_atom_count':12,'parent_bytes':PARENT['bytes'],'candidate_bytes':plan['candidate']['bytes'],
            'complete_input_consumption':True,'semantic_delta_verified':False,'phone_operations':0,'active_policy_writes':0})
    else:
        need(live_summary is not None and type(live_inputs_raw) is bytes,'actual independent live-chain proof required')
        build_desc=plan['image_build_result'];proof=report['post_live_originals']
        need(sources['image_build_result']==build_desc and sources['live_provenance_verifier']==plan['live_verifier_source'],
            'post actual source input linkage differs')
        need(sha(get(plan['live_verifier_source']))==reviewed_source_sha256()
            and get(plan['live_provenance_inputs'])==live_inputs_raw,'post used another verifier or live original input')
        exact(proof,{'schema':'hepta.native5.post-live-originals-recheck.v1',
            'live_provenance_inputs':plan['live_provenance_inputs'],'input_original_map':plan['input_original_map'],
            'live_provenance_raw_sha256':sha(live_inputs_raw),'live_provenance_verifier':plan['live_verifier_source'],
            'actual_reviewed_verifier_source_executed':True,'actual_original_parent':live_summary['parent'],
            'actual_original_candidate':live_summary['candidate'],'binding_sha256':live_summary['binding_sha256'],
            'host_capture_sha256':live_summary['host_capture_sha256'],
            'provenance_inputs_canonical_sha256':live_summary['provenance_inputs_sha256'],
            'root_transaction':live_summary['root_transaction'],'image_build_result':build_desc,
            'phone_operations':0,'active_policy_writes':0,'policy_adoption_authorized':False})
        # The post process retained a separate P4 copy of each original Mac
        # input. Its explicit map must be consistent with this proof map.
        map_rows=plan['input_original_map'];need(isinstance(map_rows,list) and 1<=len(map_rows)<=512,
            'bounded post live-original map required')
        by_original={}
        for row in map_rows:
            need(set(row)=={'original','retained'},'post live original mapping fields differ')
            a,b=row['original'],row['retained'];key=descriptor_key(a);file_descriptor(b)
            need(key not in by_original and a['bytes']==b['bytes'] and a['sha256']==b['sha256'],
                'post original mapping duplicated or changed')
            by_original[key]=b
        for name,field in [('parent','parent'),('candidate','candidate'),('root_scope_decision','root_scope_decision'),
            ('parent_adoption_history','parent_adoption')]:
            need(by_original.get(descriptor_key(live_summary[name]))==plan[field],
                'actual live original does not map to exact independently parsed bytes')
    build=strict(get(build_desc))
    exact(build,{'schema':'hepta.native5.actual-host-build.v1','returncode':0,
        'source':plan['image_comparator_source'],'binary':plan['image_comparator']})
    need(get(build['stdout'])==get(build['stderr'])==b'','actual original compiler streams differ')
    need(build['static_library']['sha256']=='2174eb5cfde7050e7c82e7805675a45c62cc54e27547ea62517b3e4d2e96400b'
        and build['runtime_library']['sha256']=='c1e965eaae791bc4abc1fc2336a5433d7c483e5117778dbd06234b3fa9172092',
        'complete-image official library provenance differs')
    return {'report':report,'report_descriptor':index['report'],'original_report_descriptor':top['report'][0],
        'plan':plan,'execution':execution,'proof_index_sha256':sha(index_raw),
        'small_originals_read':len(rows),'small_original_bytes':total,'all_orbit_images_read_by_consumer':False}


ADOPTION_FIELDS={'schema','release_id','boot_id','root_scope_decision','parent_adoption_history',
    'parent_policy','actual_export','offline_candidate','delta_rule','parent_rule','full_rule',
    'retirement_descriptor','retirement_host_closure','pre_policy_boundary_descriptor','pre_policy_boundary',
    'offline_comparison','post_live_comparison','offline_proof_inputs','post_live_proof_inputs',
    'live_provenance','pre_live_expectation','verification_originals','root_decision'}


def adoption_decision(value,live):
    return {'schema':'hepta.root.native5-policy-adoption-decision.v1',
        'decision':'ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY',
        'actual_policy_sha256':value['actual_export']['sha256'],'root_scope_decision_sha256':DECISION['sha256'],
        'post_live_comparison_sha256':value['post_live_comparison']['sha256'],
        'actual_live_binding_sha256':live['binding_sha256'],
        'pre_live_expectation_sha256':value['pre_live_expectation']['sha256'],
        'prior_boundary_sha256':BOUNDARY['sha256'],'permission_atoms':ATOMS,
        'automatic_adoption':False,'service_start_admitted':False,'component_qualified':False}


def validate_adoption_value(value,*,read_pinned,require_root_decision=True):
    need(isinstance(value,dict) and set(value)==ADOPTION_FIELDS,'exact new adoption fields required')
    exact(value,{'schema':'hepta.native5-r10.policy-adoption.v1','release_id':'v150-r10-r1','boot_id':BOOT,
        'parent_policy':PARENT,'pre_policy_boundary':BOUNDARY})
    pool=value['verification_originals'];need(isinstance(pool,list) and 1<=len(pool)<=1024,
        'bounded explicit verification-original inventory required')
    originals={};paths={};used=set();total=0
    for row in pool:
        key=descriptor_key(row);need(row['path'] not in paths,'duplicate verification-original path')
        paths[row['path']]=row;originals[key]=row;total+=row['bytes']
    need(total<=32*1024*1024,'adoption verification-original raw byte bound')
    def get(row):
        key=descriptor_key(row);need(key in originals,'verification depends on an unlisted original')
        raw=bytes_match(read_pinned(row),row);used.add(key);return raw
    raw={k:get(value[k]) for k in ('root_scope_decision','parent_adoption_history','actual_export',
        'delta_rule','parent_rule','full_rule','retirement_descriptor','retirement_host_closure',
        'pre_policy_boundary_descriptor','offline_comparison','post_live_comparison','offline_proof_inputs',
        'post_live_proof_inputs','live_provenance','pre_live_expectation')}
    root_scope(raw['root_scope_decision']);bytes_match(raw['parent_adoption_history'],PARENT_ADOPTION)
    bytes_match(raw['retirement_descriptor'],RETIREMENT_DESCRIPTOR)
    bytes_match(raw['retirement_host_closure'],RETIREMENT_HOST_CLOSURE)
    bytes_match(raw['pre_policy_boundary_descriptor'],BOUNDARY_DESCRIPTOR)
    need(strict(raw['pre_policy_boundary_descriptor'])==BOUNDARY,'adoption prior full-nine boundary differs')
    need(raw['delta_rule']==RULE and raw['full_rule']==raw['parent_rule']+RULE,
        'adoption full policy rule source differs')
    bytes_match(raw['parent_rule'],PARENT_RULE);bytes_match(raw['full_rule'],FULL_RULE)
    live_inputs=strict(raw['live_provenance']);live=verify_live_capture(live_inputs,read_pinned=get)
    need(live_inputs['pre_live_expectation']==value['pre_live_expectation']
        and live['candidate']==value['actual_export']
        and descriptor(raw['actual_export'])==live['actual_after_policy'],
        'adoption actual-export/pre-expectation source differs from live originals')
    need(value['offline_candidate']==live['binding']['offline_candidate'],'offline candidate pin was rewritten')
    offline=verify_comparison_proof(raw['offline_proof_inputs'],expected_kind='offline_candidate',
        read_pinned=get,decision_raw=raw['root_scope_decision'])
    post=verify_comparison_proof(raw['post_live_proof_inputs'],expected_kind='post_live_export',
        read_pinned=get,decision_raw=raw['root_scope_decision'],live_summary=live,live_inputs_raw=raw['live_provenance'])
    need(offline['report_descriptor']==value['offline_comparison']
        and post['report_descriptor']==value['post_live_comparison'], 'adoption proof report identity differs')
    need(descriptor(raw['offline_comparison'])==live['binding']['complete_offline_comparison']
        and {k:post['report']['candidate'][k] for k in ('bytes','sha256')}==live['actual_after_policy'],
        'independent comparisons do not identify actual approved before/after bytes')
    decision=adoption_decision(value,live)
    if require_root_decision:need(value['root_decision']==decision,'explicit Root actual-export adoption is missing')
    else:need(value['root_decision'] is None,'preview inputs cannot contain a prewritten adoption decision')
    need(set(originals)==used,'verification-original inventory contains unconsumed or unrelated originals')
    return {'runtime_policy':live['actual_after_policy'],'full_rule':value['full_rule'],
        'retirement_sha256':RETIREMENT,'prior_boundary_sha256':BOUNDARY['sha256'],
        'root_scope_decision_sha256':DECISION['sha256'],'parent_adoption_sha256':PARENT_ADOPTION['sha256'],
        'actual_live_binding_sha256':live['binding_sha256'],'root_decision':decision,
        'parent_policy':PARENT,'current_policy_adoption':{'schema':value['schema'],'boot_id':BOOT},
        'offline_proof':{k:offline[k] for k in ('proof_index_sha256','small_originals_read','small_original_bytes','all_orbit_images_read_by_consumer')},
        'post_live_proof':{k:post[k] for k in ('proof_index_sha256','small_originals_read','small_original_bytes','all_orbit_images_read_by_consumer')},
        'verification_original_count':len(used),'verification_original_bytes':total,
        'service_start_admitted':False,'component_qualified':False,'phone_calls':0,'policy_writes':0}


def verify_adoption(adoption_raw,*,read_pinned):
    """Read only raw reviewed originals; an explicit Root decision is mandatory."""
    value=strict(adoption_raw);summary=validate_adoption_value(value,read_pinned=read_pinned)
    summary['current_adoption_sha256']=sha(adoption_raw)
    summary['current_policy_adoption']={**summary['current_policy_adoption'],**descriptor(adoption_raw)}
    return summary


def verify_live_capture(live_inputs,*,read_pinned):
    """Independent post-comparison input gate; it never requires its own post report."""
    need(isinstance(live_inputs,dict) and set(live_inputs)=={'schema','prepared','host_capture',
        'original_operation','actor_wrapper','archive','capture_manifest','pre_live_expectation','originals',
        'root_plan','root_intent','root_execution'},
        'explicit complete live provenance fields differ')
    need(live_inputs['schema']=='hepta.native5-r10.live-provenance-inputs.v1','live provenance schema differs')
    def get(row):
        file_descriptor(row);raw=read_pinned(row);return bytes_match(raw,row)
    values={key:get(live_inputs[key]) for key in ('prepared','host_capture','original_operation',
        'actor_wrapper','archive','capture_manifest','pre_live_expectation','root_plan','root_intent','root_execution')}
    prepared=strict(values['prepared']);host=strict(values['host_capture']);op=strict(values['original_operation'])
    wrapper=strict(values['actor_wrapper'])
    exact(prepared,{'schema':'hepta.native5-r10.live-host-preparation.v1',
        'state':'ACTUAL_INPUTS_BOUND_HOST_PREPARED_NOT_EXECUTED','phone_calls':0,'policy_apply_attempts':0,
        'automatic_retry':False,'automatic_rollback':False,'policy_adoption_authorized':False})
    binding_sha=prepared['binding']['sha256']
    need(set(op)=={'actor_rc','wrapper_sha256','wrapper'} and type(op['actor_rc']) is int and op['actor_rc']==0
        and op['wrapper_sha256']==sha(values['actor_wrapper']) and op['wrapper']==wrapper,
        'independent original actor wrapper differs from host operation')
    ph=wrapper.get('phone');need(isinstance(ph,dict) and type(ph.get('rc')) is int and ph['rc']==0
        and isinstance(ph.get('stdout'),str) and ph.get('stderr')=='','actual phone command did not complete cleanly')
    output=strict(ph['stdout'].encode('utf-8'));need(set(output)=={'report','export'},'single complete actual stdout JSON required')
    export=output['export']
    exact(export,{'schema':'hepta.native5-r10.live-original-export.v1','state':'ORIGINAL_EXPORT_COMPLETE',
        'binding_sha256':binding_sha,'automatic_retry':False,'policy_adoption_authorized':False,'business_qualified':False})
    need(export['archive']['path']==BASE+'/'+OUT_NAME+'/ORIGINALS.tar.gz'
        and descriptor(values['archive'])=={k:export['archive'][k] for k in ('bytes','sha256')}
        and descriptor(values['capture_manifest'])==export['capture'],'actual export archive/index bytes differ')
    files,cap=decode_original_archive(values['archive'],export['capture'],binding_sha)
    need(files['CAPTURE.json']==values['capture_manifest'],'original capture manifest differs')
    originals=live_inputs['originals'];need(isinstance(originals,dict) and set(originals)==MANDATORY_LIVE_FILES,
        'exact mandatory live original descriptor map required')
    for name,row in originals.items():need(get(row)==files[name],'host original copy is not the actual archive member')
    binding,report=verify_apply_originals(files,binding_sha)
    need(report==output['report'] and descriptor(files['BINDING.original.json'])==prepared['binding'],
        'original report or binding differs from actual executed transaction')
    exact(host,{'schema':'hepta.native5-r10.host-original-capture.v1',
        'state':'ORIGINALS_CAPTURED_PENDING_INDEPENDENT_LIVE_COMPARISON','binding_sha256':binding_sha,
        'original_operation_sha256':sha(values['original_operation']),'wrapper_sha256':sha(values['actor_wrapper']),
        'actor_rc':0,'phone_rc':0,'archive':descriptor(values['archive']),'capture':export['capture'],
        'clean_apply_observed':True,'actual_live_policy':descriptor(files['live-policy-after.bin']),
        'policy_adoption_authorized':False,'independent_live_complete_comparison_required':True,
        'service_start_admitted':False,'business_qualified':False,'phone_calls':0,'policy_apply_attempts':0,
        'automatic_retry':False,'automatic_rollback':False})
    need(host['files']==len(files) and host['original_live_policy_path']==originals['live-policy-after.bin']['path']
        and host['original_parent_policy_path']==originals['live-policy-before.bin']['path'],
        'host capture actual export paths differ')
    expectation=verify_pre_live_expectation(values['pre_live_expectation'],read_pinned=read_pinned)
    need({k:expectation['binding'][k] for k in ('bytes','sha256')}==descriptor(files['BINDING.original.json'])
        and expectation['offline_candidate']==binding['offline_candidate'],'pre-load expectation bound another transaction')
    root_transaction=verify_root_transaction(live_inputs,values,prepared,expectation,files,get)
    return {'parent':originals['live-policy-before.bin'],'candidate':originals['live-policy-after.bin'],
        'root_scope_decision':originals['ROOT-SCOPE-DECISION.original.json'],
        'parent_adoption_history':originals['PARENT-ADOPTION-HISTORY.original.json'],
        'binding_sha256':binding_sha,'host_capture_sha256':sha(values['host_capture']),
        'provenance_inputs_sha256':sha(encoded(live_inputs)),'live_report':report,
        'original_files':files,'capture':cap,'binding':binding,'pre_live_expectation':expectation,
        'root_transaction':root_transaction,'actual_before_policy':PARENT,'actual_after_policy':descriptor(files['live-policy-after.bin']),
        'comparison_route':'verified_semantic_export','expected_live_export':None,
        'policy_adoption_authorized':False,'phone_calls':0}


def verify_stage_program(source_raw,*,phase,stage):
    """Inspect the actual raw stage program; no stage code is executed here."""
    text=source_raw.decode('utf-8');tree=ast.parse(text)
    is_final=phase=='native5r2-stage-final'
    names=['BOOT','PARENT','STAGE'] if is_final else ['BOOT','PARENT','STAGE','INDEX','PART_BASE64']
    values={}
    for name,node in zip(names,tree.body):
        need(isinstance(node,ast.Assign) and len(node.targets)==1
            and isinstance(node.targets[0],ast.Name) and node.targets[0].id==name,
            'stage code changed its literal declaration boundary')
        values[name]=ast.literal_eval(node.value)
    expected=ast.parse(STAGE_BASE+(STAGE_FINAL if is_final else STAGE_PART))
    observed=ast.Module(body=tree.body[len(names):],type_ignores=[])
    need(ast.dump(observed,include_attributes=False)==ast.dump(expected,include_attributes=False),
        'actual stage code is not the reviewed limited file staging program')
    need(values['BOOT']==BOOT and values['PARENT']==PARENT['sha256'] and values['STAGE']==stage,
        'stage code constants do not bind the actual single stage identity')
    if is_final:return None
    index=int(phase.rsplit('-',1)[1]);need(type(values['INDEX']) is int and values['INDEX']==index,'stage prefix order differs')
    raw=base64.b64decode(values['PART_BASE64'],validate=True)
    need(base64.b64encode(raw).decode('ascii')==values['PART_BASE64'] and len(raw)<=16384,
        'canonical bounded stage part required')
    bytes_match(raw,stage['parts'][index]);return raw


def verify_root_transaction(live,values,prepared,expectation,files,get):
    plan=strict(values['root_plan']);intent=strict(values['root_intent']);execution=strict(values['root_execution'])
    fields={'schema','boot_id','prepared','stage_requests','apply_request','binding','pre_live_expectation',
        'capture_source','verifier_source','transport_root_plan','source_package','driver_source','out','prior_failed_transaction'}
    need(set(plan)==fields,'actual Root live plan fields differ')
    exact(plan,{'schema':'hepta.root.native5-live-plan.v2','boot_id':BOOT})
    need(plan['prior_failed_transaction']==PRIOR_FAILED_TRANSACTION,'exact closed predecessor descriptor required')
    verify_prior_failed_transaction(get(plan['prior_failed_transaction']),read_pinned=get)
    need(plan['prepared']==live['prepared'] and plan['pre_live_expectation']==live['pre_live_expectation']
        and plan['binding']==expectation['binding'] and plan['stage_requests']==prepared['stage_requests']
        and plan['apply_request']==prepared['apply_request'],'Root plan is not the one actual prepared request set')
    bytes_match(get(plan['driver_source']),ROOT_DRIVER);bytes_match(get(plan['source_package']),ROOT_SOURCE_PACKAGE)
    source_package=strict(get(plan['source_package']));base=PurePosixPath(plan['source_package']['path']).parent
    exact(source_package,{'schema':'hepta.root.native5-live-source-package.v1'})
    expected={'source/run_native5_policy_once.py':ROOT_DRIVER,
        'reference/run_component_root_once.r4.original.py':ROOT_TRANSPORT_SOURCE}
    need(len(source_package['files'])==2 and {r['path'] for r in source_package['files']}==set(expected),
        'Root driver source package fields differ')
    for row in source_package['files']:
        need({k:row[k] for k in ('bytes','sha256')}==expected[row['path']], 'Root original source revision differs')
        retained={'path':str(base/row['path']),**expected[row['path']]};get(retained)
    need({k:plan['verifier_source'][k] for k in ('bytes','sha256')}==descriptor(files['policy_native5_verifier.original.py']),
        'Root selected another actual verifier source')
    # This source is retained as a host original; the decoded archive is also
    # independently reconstructed by this verifier, rather than trusting it.
    get(plan['capture_source']);get(plan['transport_root_plan'])
    exact(intent,{'schema':'hepta.root.native5-live-intent.v2',
        'state':'ONE_EXPLICIT_POLICY_APPLY_DECLARED_BEFORE_PHONE_PHASES',
        'plan_sha256':sha(values['root_plan']),'pre_live_expectation':plan['pre_live_expectation'],
        'binding':plan['binding'],'source_package':plan['source_package'],'driver_source':plan['driver_source'],
        'verifier_source':plan['verifier_source'],'prior_failed_transaction':plan['prior_failed_transaction'],'maximum_apply_attempts':1,
        'automatic_retry':False,'automatic_rollback':False,'automatic_policy_adoption':False,
        'new_native_case_nonces':0,'native_case_sends':0})
    same={'root_plan':live['root_plan'],'root_intent':live['root_intent'],
        **{k:plan[k] for k in ('prepared','binding','pre_live_expectation','source_package','driver_source','verifier_source','capture_source','prior_failed_transaction')},
        **{k:live[k] for k in ('original_operation','actor_wrapper','host_capture')}}
    exact(execution,{'schema':'hepta.root.native5-live-execution.v2',
        'state':'ORIGINAL_POLICY_APPLY_CAPTURED_PENDING_INDEPENDENT_COMPARISON',
        **same,'policy_apply_calls':1,'policy_apply_phase':'native5r2-live-apply',
        'automatic_retry':False,'automatic_rollback':False,'automatic_policy_adoption':False,
        'new_native_case_nonces':0,'native_case_sends':0,'known_apply_error':None})
    stages=strict(get(plan['stage_requests']));provenance=strict(get(prepared['stage_request_provenance']))
    need(isinstance(stages,list) and 2<=len(stages)<=9 and isinstance(provenance,list)
        and len(stages)==len(provenance)==execution['stage_phase_count'], 'bounded exact stage original count')
    wanted=['native5r2-stage-%02d'%i for i in range(len(stages)-1)]+['native5r2-stage-final']
    need([r['phase'] for r in stages]==wanted and all(set(r)=={'phase','request'} for r in stages),
        'exact original stage request order differs')
    stage_raw=files['STAGE-INTENT.original.json'];stage=strict(stage_raw);complete=strict(files['STAGE-COMPLETE.original.json'])
    need(sha(stage_raw)==prepared['stage_identity_sha256']==complete['stage_identity_sha256'],
        'actual stage completion is not bound to preparation')
    actual_parts=[]
    for row,source_row in zip(stages,provenance):
        need(set(source_row)=={'phase','request','source','adb_service_bytes'}
            and row=={k:source_row[k] for k in ('phase','request')},'stage provenance mapping differs')
        request=strict(get(row['request']));source=get(source_row['source'])
        exact(request,{'kind':'shell','root':True,'timeout_seconds':40})
        need(set(request)=={'kind','root','timeout_seconds','command'}
            and request['command']==STAGE_ENV_PREFIX+'-c '+shlex.quote(source.decode('utf-8')),
            'actual stage request is not the exact reviewed bounded program')
        wire=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(request['command'])).encode('utf-8')
        need(len(wire)<65536 and len(wire)==source_row['adb_service_bytes'],'actual fixed transport wire bound differs')
        part=verify_stage_program(source,phase=row['phase'],stage=stage)
        if part is not None:actual_parts.append(part)
    compressed=b''.join(actual_parts);bytes_match(compressed,stage['compressed'])
    need(len(compressed)<=131072 and 0<stage['plain']['bytes']<=2097152,'bounded full stage envelope')
    z=zlib.decompressobj(31);plain=z.decompress(compressed,stage['plain']['bytes']+1)
    need(z.eof and not z.unconsumed_tail and not z.unused_data,'complete original stage gzip')
    bytes_match(plain,stage['plain']);envelope=strict(plain)
    aliases={'BINDING.json':'BINDING.original.json','guard_live_native5.py':'guard_live_native5.original.py',
        'policy_native5_verifier.py':'policy_native5_verifier.original.py','apply_native5_once.sh':'apply_native5_once.original.sh'}
    expected_names={'BINDING.json','guard_live_native5.py','policy_native5_verifier.py','apply_native5_once.sh',
        'ROOT-SCOPE-DECISION.original.json','PARENT-ADOPTION-HISTORY.original.json','ACTUAL-RETIREMENT-INPUTS.original.json',
        'RETIREMENT-HOST-CLOSURE.original.json','LATEST-BOUNDARY-DESCRIPTOR.original.json',
        'CLOSED-COMPONENT-PACKAGE.original.json','OFFLINE-COMPLETE-COMPARISON.original.json',
        'native5.delta.rule','parent-candidate.rule','full-candidate.rule'}
    need(set(envelope)==set(stage['files'])==expected_names and complete['files']==stage['files'],
        'actual stage envelope file set differs')
    for name,value in envelope.items():
        raw=base64.b64decode(value,validate=True);bytes_match(raw,stage['files'][name])
        need(raw==files[aliases.get(name,name)],'actual executed file differs from bound stage envelope')
    apply=strict(get(plan['apply_request']))
    need(apply=={'kind':'shell','root':True,'timeout_seconds':240,'command':'/data/adb/magisk/busybox sh '+NATIVE_BASE+'/'+CODE_NAME+
        '/apply_native5_once.sh --execute-reviewed-single-native5-apply '+plan['binding']['sha256']},
        'actual single policy request differs')
    phases=execution['phone_phase_names'];need(isinstance(phases,list) and len(phases)==len(set(phases))
        and type(execution['phone_calls']) is int and len(phases)==execution['phone_calls']
        and phases[:len(wanted)+1]==wanted+['native5r2-live-apply'],'actual phone operation sequence differs')
    remaining=phases[len(wanted)+1:]
    need(remaining==['native5r2-export-%02d'%i for i in range(len(remaining))] and len(remaining)<=16,
        'only bounded existing-archive read chunks may follow the one apply')
    steps=execution['steps'];need(isinstance(steps,list) and len(steps)==len(phases)+2,
        'all phone/independent wrapper/capture host original terminals required')
    needed=['phone-'+p for p in wanted+['native5r2-live-apply']]+['native5r2-wrapper-original']+[
        'phone-'+p for p in remaining]+['native5r2-host-capture']
    need([s['phase'] for s in steps]==needed,'actual original host step sequence differs')
    for step in steps:
        exact(step,{'state':'ORIGINAL_HOST_CHILD_JOINED','returncode':0,'automatic_retry':False})
        need(type(step['pid']) is int and step['pid']>0,'actual joined host child identity required')
        out=get(step['stdout']);need(get(step['stderr'])==b'','actual host step stderr is not empty')
        value=strict(out)
        if step['phase'].startswith('phone-'):
            need(type(value.get('actor_rc')) is int and value['actor_rc']==0
                and value['wrapper']['phone']['rc']==0 and value['wrapper']['phone']['stderr']=='',
                'actual stage/apply/chunk original did not complete cleanly')
    return {'schema':'hepta.native5-r10.root-transaction-recheck.v1','root_plan_sha256':sha(values['root_plan']),
        'root_intent_sha256':sha(values['root_intent']),'root_execution_sha256':sha(values['root_execution']),
        'driver_source_sha256':ROOT_DRIVER['sha256'],'prior_failed_transaction_sha256':PRIOR_FAILED_TRANSACTION['sha256'],
        'pre_expectation_declared_before_phone_by_exact_source':True,
        'exact_stage_programs_and_payload_rebuilt':True,'policy_apply_calls':1,'automatic_retry':False,
        'native_case_sends':0,'new_native_case_nonces':0}

def validate_binding(raw,*,decision_raw,comparison_raw,retirement_raw,parent_adoption_raw,boundary_descriptor_raw,package_raw):
    v=strict(raw)
    fields={'schema','boot_id','root_scope_decision','parent_adoption_history','retirement_descriptor',
        'retirement_host_closure','pre_policy_boundary_descriptor','pre_policy_boundary','component_package',
        'component_sources','complete_offline_comparison','approved_rule_atoms','parent_policy','offline_candidate',
        'delta_rule','parent_rule','full_rule','guard_source','verifier_source','shell_source','root_approval'}
    need(set(v)==fields,'explicit Native5 live binding fields differ')
    exact(v,{'schema':'hepta.native5-r10.live-apply-binding.v1','boot_id':BOOT,'approved_rule_atoms':ATOMS,
        'parent_policy':PARENT,'retirement_descriptor':RETIREMENT_DESCRIPTOR,
        'retirement_host_closure':RETIREMENT_HOST_CLOSURE,'root_scope_decision':DECISION,
        'parent_adoption_history':PARENT_ADOPTION,'pre_policy_boundary_descriptor':BOUNDARY_DESCRIPTOR,
        'pre_policy_boundary':BOUNDARY,'component_package':PACKAGE,'delta_rule':descriptor(RULE),
        'parent_rule':PARENT_RULE,'full_rule':FULL_RULE,'root_approval':APPROVAL})
    root_scope(decision_raw);bytes_match(parent_adoption_raw,PARENT_ADOPTION)
    history=strict(parent_adoption_raw)
    need({k:history['actual_export'][k] for k in ('bytes','sha256')}==PARENT,
        'actual parent adoption history differs')
    bytes_match(retirement_raw,RETIREMENT_DESCRIPTOR);bytes_match(package_raw,PACKAGE)
    bytes_match(boundary_descriptor_raw,BOUNDARY_DESCRIPTOR)
    need(strict(boundary_descriptor_raw)==BOUNDARY,'full-nine latest boundary descriptor differs')
    comparison=verified_offline(comparison_raw,decision_raw)
    need(v['complete_offline_comparison']==descriptor(comparison_raw)
        and v['offline_candidate']=={k:comparison['candidate'][k] for k in ('bytes','sha256')},
        'actual complete offline comparison is not bound')
    for k in ('guard_source','verifier_source','shell_source'):
        byte_pin(v[k],maximum=262144)
    manifest=strict(package_raw);rows={r['path']:r for r in manifest['files']}
    names=['component_common','native_proc_profile','component_lifecycle','component_snapshot','late_boundary']
    need(set(v['component_sources'])==set(names),'exact raw dependency set required')
    for name in names:
        row=v['component_sources'][name];file_descriptor(row)
        expected=rows['source/'+name+'.py']
        need(row['path']==BASE+'/native-guard-r10-r1/root-r10-neg01-20261104-04/package/source/'+name+'.py'
            and {k:row[k] for k in ('bytes','sha256')}=={k:expected[k] for k in ('bytes','sha256')},
            'component pure verifier source left the actual closed package')
    return v

# Literal reviewed stage programs; parsed only, never executed by this verifier.
STAGE_BASE = "\nfrom pathlib import Path\nimport base64,hashlib,json,os,stat,zlib\nB=Path('/var/lib/trillionnium/owner-open/phone-local-v150')\nC=B/'policy-native5-r10-live-code-r2';A=Path('/proc/1/root')\ndef need(ok,msg):\n if not ok:raise ValueError(msg)\ndef sha(raw):return hashlib.sha256(raw).hexdigest()\ndef enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\\n').encode()\ndef sync(p):\n fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n try:os.fsync(fd)\n finally:os.close(fd)\ndef private(p):\n s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700 and p.resolve(strict=True)==p,'private canonical stage directory')\ndef read(p,limit):\n fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)\n try:\n  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==a.st_gid==0 and stat.S_IMODE(a.st_mode)==0o600 and 0<=a.st_size<=limit,'private bounded stage original')\n  with os.fdopen(fd,'rb',closefd=False) as f:r=f.read(limit+1)\n  z,n=os.fstat(fd),p.lstat();keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')\n  need(len(r)==a.st_size and all(getattr(a,k)==getattr(z,k)==getattr(n,k) for k in keys),'stage original raced')\n  return r\n finally:os.close(fd)\ndef put(p,b):\n fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)\n with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())\n sync(p.parent);need(read(p,len(b))==b,'stage readback differs')\nneed(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'Root credentials')\nneed(Path('/proc/self/attr/current').read_bytes().rstrip(b'\\0\\n')==b'u:r:magisk:s0','Root domain')\nneed(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT,'fixed boot')\nneed((A/'sys/fs/selinux/enforce').read_bytes() in (b'1',b'1\\n'),'Enforcing')\np=(A/'sys/fs/selinux/policy').read_bytes();need(len(p)==2667548 and sha(p)==PARENT,'actual parent296b')\nprivate(B);os.umask(0o077)\n"
STAGE_PART = "\nneed(type(INDEX) is int and 0<=INDEX<len(STAGE['parts'])<=8,'bounded exact chunk index')\nif INDEX==0:\n C.mkdir(mode=0o700);sync(B);private(C)\n n=A/'data/trillionnium/owner-open/state/phone-local-v150'/C.name\n need((n.stat().st_dev,n.stat().st_ino)==(C.stat().st_dev,C.stat().st_ino),'GNU/native mapping')\n (C/'.stage-parts').mkdir(mode=0o700);sync(C)\n put(C/'STAGE-INTENT.json',enc(STAGE))\nelse:\n private(C);need(read(C/'STAGE-INTENT.json',65536)==enc(STAGE),'same original stage identity')\nneed(sorted(p.name for p in C.iterdir())==['.stage-parts','STAGE-INTENT.json'],'stage namespace has unexpected contents')\nQ=C/'.stage-parts';private(Q)\nneed(sorted(p.name for p in Q.iterdir())==['part-%02d.bin'%i for i in range(INDEX)],'stage parts are not the exact unreplayed prefix')\ndata=base64.b64decode(PART_BASE64,validate=True);row=STAGE['parts'][INDEX]\nneed(len(data)==row['bytes']<=16384 and sha(data)==row['sha256'],'stage chunk bytes')\nput(Q/('part-%02d.bin'%INDEX),data)\nprint(json.dumps({'schema':'hepta.native5-r10.live-stage-part.v1','state':'EXACT_PART_STAGED_NO_POLICY_APPLY',\n 'binding_sha256':STAGE['binding_sha256'],'stage_identity_sha256':sha(enc(STAGE)),'index':INDEX,\n 'bytes':len(data),'sha256':sha(data),'policy_apply_attempts':0,'automatic_retry':False},sort_keys=True))\n"
STAGE_FINAL = "\nprivate(C);need(read(C/'STAGE-INTENT.json',65536)==enc(STAGE),'same original stage identity')\nneed(sorted(p.name for p in C.iterdir())==['.stage-parts','STAGE-INTENT.json'],'unconsumed code namespace required')\nQ=C/'.stage-parts';private(Q)\nneed(sorted(p.name for p in Q.iterdir())==['part-%02d.bin'%i for i in range(len(STAGE['parts']))],'complete exact stage chunk set')\npieces=[]\nfor i,row in enumerate(STAGE['parts']):\n b=read(Q/('part-%02d.bin'%i),16384);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'original stage chunk differs');pieces.append(b)\ncompressed=b''.join(pieces)\nneed(len(compressed)==STAGE['compressed']['bytes']<=131072 and sha(compressed)==STAGE['compressed']['sha256'],'compressed stage bytes')\nz=zlib.decompressobj(31);raw=z.decompress(compressed,STAGE['plain']['bytes']+1)\nneed(len(raw)==STAGE['plain']['bytes']<=2097152 and z.eof and not z.unconsumed_tail and not z.unused_data and sha(raw)==STAGE['plain']['sha256'],'complete bounded stage envelope')\ndef pairs(items):\n v={}\n for k,x in items:need(k not in v,'duplicate stage key');v[k]=x\n return v\nvalue=json.loads(raw,object_pairs_hook=pairs)\nneed(set(value)==set(STAGE['files']),'exact reviewed staged file set')\nfiles={k:base64.b64decode(v,validate=True) for k,v in value.items()}\nfor name,b in files.items():\n need('/' not in name and name not in ('.','..') and '\\0' not in name,'stage file name')\n row=STAGE['files'][name];need(len(b)==row['bytes'] and sha(b)==row['sha256'],'staged file original bytes')\nneed(sha(files['BINDING.json'])==STAGE['binding_sha256'],'stage binding')\nfor name,b in sorted(files.items()):put(C/name,b)\ncomplete={'schema':'hepta.native5-r10.live-code-stage.v1','state':'CREATE_ONLY_CODE_STAGED_NO_POLICY_APPLY',\n 'files':STAGE['files'],'binding_sha256':STAGE['binding_sha256'],'stage_identity_sha256':sha(enc(STAGE)),\n 'policy_apply_attempts':0,'phone_service_changes':0,'automatic_retry':False}\nput(C/'STAGE-COMPLETE.json',enc(complete));print(json.dumps(complete,sort_keys=True))\n"
STAGE_ENV_PREFIX = '/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B '
