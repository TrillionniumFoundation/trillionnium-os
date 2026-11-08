#!/usr/bin/env python3
"""Independent, file-callback-only verification of the one-getattr adoption.

Import and every public verifier perform no device access or policy load.
Original bytes enter only through read_pinned. Actual exported policy bytes
are mandatory; the offline candidate is a proposal identity, never a live pin.
The reviewed f821 historical adoption is an explicit ancestry anchor. Its full
554-original verification remains in the retained, actual host-freeze evidence;
it is not silently duplicated into a new 32 MiB runtime original pool.
"""
import base64
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import types

BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
BASE='/var/lib/trillionnium/owner-open/phone-local-v150'
NATIVE_BASE='/data/trillionnium/owner-open/state/phone-local-v150'
PARENT={'bytes':2667740,'sha256':'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'}
OFFLINE={'bytes':2667752,'sha256':'30515257588fbbe0c4fe0d9939304a93e741444c7c3a6a912bc90b98e64b6c98'}
PARENT_ADOPTION={'bytes':208226,'sha256':'527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'}
PARENT_HOST_VALIDATION={'bytes':45480,'sha256':'3ca7c8c55928c51677794bb0c882ba0a608b8dc246adbd714a2bb42cd699b449'}
RETIREMENT='b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90'
CORE={'bytes':30369,'sha256':'25073ee556b6656690143eef7c4526d090f78703f3688af805fc6e2f71e30cbd'}
ADMISSION={'bytes':52137,'sha256':'e8718efdb60b2c83dcdd83b757589ade9c18869136292465eebe0b3bc681d4a3'}
DRIVER={'bytes':7455,'sha256':'df0876be0380ddacb71f8b508ac42f85f332b5714f7fdd086a6357741f985871'}
PROTECTED={'bytes':13024,'sha256':'7e3b0f9981abc82b7b67400ec75c1c479338f7a196486325a25efb73a17d0019'}
HELD_GATE={'bytes':11485,'sha256':'9a0855f9f8fe4579b62328bef6c675fd424a66ef1f583b0f703533b57b864714'}
GLOBAL_GATE={'bytes':15700,'sha256':'23ec1ee206635c0ce0b2dc28ca8281d4e5523d6245eac453b58531c708e1d68e'}
CAPTURE_SOURCE={'bytes': 7920, 'sha256': '88939d88cfbaf811bb732be617337215c507437a95d051fec2247ca420f3c4ca'}
COMPARISON_SOURCE={'bytes': 25853, 'sha256': 'ff7e655de6d0cc016cc6e1e39c640acc8fd2848479e544b4bd3340a88d721a13'}
IMAGE_SOURCE={'bytes':19439,'sha256':'411ca82f822eb873cec069f68c0088c5f6c1e055e33bad53e291a08198d2f117'}
IMAGE_BINARY={'bytes':294600,'sha256':'26f00f0ed45d7e1847910fca6c3c6c499da4863d4ca2562fc0fc7d09b2693eb8'}
SNAPSHOT_SOURCE={'bytes':14301,'sha256':'b29b139b1493b2c25a5d2ab3faf2a0632a1c3ea8900116683eb51fa002a7f9c8'}
SCOPE={'bytes':3060,'sha256':'21f99ceb95d92961b8895d41af966ed259760d70f76ec10f13a5b3b8586ba115'}
OFFLINE_PROOF={'bytes':20757,'sha256':'6ebef0320779a0bc7d77398e3062f0fe1f947bd99aae4be7821e51e4d1e4fe8b'}
AV_TOOL={'bytes':34976,'sha256':'86f6d18eab7271d9a5688e5f7b03ed5b55740b9679e7dd078661573ad67f0c90'}
AV_SOURCE={'bytes':17720,'sha256':'262b264c79d12c1cd2af146808ac1c5998f6aa0159515a17796c381e12630a3c'}
TOOL_INVENTORY={'bytes':19446,'sha256':'b41918ef19a0c00b0ab2295c278f204b8d66c654e8dacad05db0dea232fbd288'}
BUSYBOX={'bytes':1710600,'sha256':'4d60ab3f5a59ebb2ca863f2f514e6924401b581e9b64f602665c008177626651'}
ATOM=['allow','trillionnium_owner_open_phone_worker','system_data_file','dir','getattr']
RULE=b'allow trillionnium_owner_open_phone_worker system_data_file dir { getattr }\n'
PARENT_RULE={'bytes':17284,'sha256':'424e1c680d37583f039c8cc5e2727200b3f9ad8fd29d35616173a5102b0218d1'}
FULL_RULE={'bytes':17437,'sha256':'442e0852a99a7ea4490e1985e5ff5db0c97654e996c5f90c33c21326a67b2083'}
HASH=re.compile('[0-9a-f]{64}\\Z')
JOURNAL_NAMES={'ADAPTER-PLAN.original.json','live-policy-before.bin','delta.rule','PRECHECK.json',
 'CHILD-PLAN.original.json','APPLY-INTENT.json','CHILD-READY.original.json','CHILD-ADMIT.json',
 'CHILD-RESULT.json','policy.stdout','policy.stderr','live-policy-after.bin','TERMINAL.json'}
CHECK_NAMES=['official-complete-image-only-one-proposed-atom',
 'parent-official-roundtrip-preserves-all-enumerated-semantics',
 'candidate-official-roundtrip-preserves-all-enumerated-semantics',
 'complete-TE-counter-exact-one-unconditional-permission','all-non-TE-and-symbol-memberships-preserved',
 'complete-libsepol-roles-and-roundtrips-preserved','complete-libsepol-users-and-roundtrips-preserved',
 'complete-libsepol-initialsids-and-roundtrips-preserved','complete-libsepol-fs_uses-and-roundtrips-preserved',
 'complete-libsepol-unlabeled_filesystems-and-roundtrips-preserved',
 'complete-genfs-path-class-context-and-roundtrips-preserved','effective-dir-AV-adds-getattr-only']

def need(ok,reason):
    if not ok: raise ValueError(reason)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def descriptor(raw):
    need(type(raw)is bytes,'original bytes required')
    return {'bytes':len(raw),'sha256':sha(raw)}

def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(items):
        result={}
        for k,v in items:
            need(k not in result,'duplicate JSON key');result[k]=v
        return result
    need(type(raw)is bytes,'raw JSON bytes required')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))

def exact(value,wanted):
    need(type(value)is dict and all(k in value and type(value[k])is type(v) and value[k]==v for k,v in wanted.items()),
         'exact typed fields differ: '+','.join(wanted))

def byte_pin(value):
    need(type(value)is dict and set(value)=={'bytes','sha256'} and type(value['bytes'])is int
         and 0<=value['bytes']<=64*1024*1024 and type(value['sha256'])is str and HASH.fullmatch(value['sha256']),
         'bounded exact byte pin required')
    return value

def file_descriptor(value):
    need(type(value)is dict and {'path','bytes','sha256'}<=set(value)
         <={'path','bytes','sha256','metadata'},'exact retained original descriptor required')
    byte_pin({k:value[k] for k in ('bytes','sha256')});p=PurePosixPath(value['path'])
    need(p.is_absolute() and str(p)==value['path'] and '..' not in p.parts,'canonical original path required')
    if 'metadata' in value: full9(value['metadata'],value['bytes'])
    return value

def full9(value,size=None):
    need(type(value)is list and len(value)==9 and all(type(x)is int and x>=0 for x in value)
         and stat.S_ISREG(value[2]) and value[5]==1 and (size is None or value[6]==size),'regular original full9 required')
    return value

def key(value):
    file_descriptor(value);return (value['path'],value['bytes'],value['sha256'])

def bytes_match(raw,value):
    need(descriptor(raw)=={k:value[k] for k in ('bytes','sha256')},'original byte identity differs')
    return raw

def load_reviewed(raw,pin,name):
    bytes_match(raw,pin);module=types.ModuleType(name);module.__file__='/reviewed-host-input/'+name+'.py'
    module.__reviewed_source_sha256__=sha(raw)
    exec(compile(raw,module.__file__,'exec'),module.__dict__);return module

def reviewed_source_sha256():
    value=globals().get('__reviewed_source_sha256__')
    need(type(value)is str and HASH.fullmatch(value),'caller must inject the exact reviewed raw verifier digest')
    return value

def expected_scope(binding_raw,binding):
    return {'schema':'hepta.parent-dir.actual-scope-decision.v1',
        'state':'ACTUAL_V3_BOUND_SINGLE_GETATTR_TRANSITION','boot_id':BOOT,
        'binding':descriptor(binding_raw),'current_boundary':binding['current_boundary'],
        'parent_policy':PARENT,'parent_adoption':PARENT_ADOPTION,'offline_candidate':OFFLINE,
        'permission_atoms':[ATOM],'grant_scope':'all directories labeled system_data_file',
        'path_only_authorization':False,'maximum_policy_loads':1,'automatic_retry':False,
        'automatic_rollback':False,'policy_adopted':False,'business_qualified':False}

def verify_capture_operation(operation_raw,wrapper_raw,stdout_raw):
    operation=strict(operation_raw);wrapper=strict(wrapper_raw)
    need(set(operation)=={'actor_rc','wrapper_sha256','wrapper'},'original capture operation shape')
    exact(operation,{'actor_rc':0,'wrapper_sha256':sha(wrapper_raw),'wrapper':wrapper})
    phone=wrapper.get('phone');need(type(phone)is dict,'original capture phone return required')
    exact(phone,{'rc':0,'stderr':''})
    need(type(phone.get('stdout'))is str and phone['stdout'].encode()==stdout_raw,
         'manifest is not the complete original phone stdout')
    return strict(stdout_raw)

def linux_dev_major(device):
    """Decode the Linux/glibc uint64 dev_t recorded by the phone."""
    need(type(device)is int and 0<=device<1<<64,'Linux dev_t must be a uint64 integer')
    return ((device&0x00000000000fff00)>>8)|((device&0xfffff00000000000)>>32)

def linux_dev_minor(device):
    """Decode the Linux/glibc uint64 dev_t, independently of this host ABI."""
    need(type(device)is int and 0<=device<1<<64,'Linux dev_t must be a uint64 integer')
    return (device&0x00000000000000ff)|((device&0x00000ffffff00000)>>12)

def verify_lock_observation(value,inventory):
    expected={p:r for p,r in inventory['entries'].items() if r.get('kind')=='file'
        and (PurePosixPath(p).name.endswith('.lock') or PurePosixPath(p).name=='lock')}
    exact(value,{'path_count':24,'inode_count':13,'all_exclusive_ofds_observed':True,
                 'borrowed_fds_relocked_or_closed_here':False})
    need(set(value)=={'aliases','held_ofds','path_count','inode_count','all_exclusive_ofds_observed',
        'borrowed_fds_relocked_or_closed_here'} and len(expected)==24,'complete actual lock fields/set')
    rows=value['aliases'];need(type(rows)is list and len(rows)==24,'complete lock alias originals')
    found={};aliases={}
    for row in rows:
        p=row['path'];need(p not in found and p in expected,'unknown or duplicate lock alias')
        m=full9(row['metadata'],0);original=expected[p]
        need(row['bytes']==0 and row['sha256']==sha(b'') and row['metadata']==original['metadata']
             and {k:row[k] for k in ('bytes','sha256')}=={k:original[k] for k in ('bytes','sha256')}
             and row['private'] is True and type(row['selinux'])is str,'lock original/full9 differs')
        found[p]=row;aliases.setdefault(tuple(m[:2]),[]).append(p)
    need(set(found)==set(expected) and len(aliases)==13 and sorted(map(len,aliases.values()))==[1,1]+[2]*11,
         'current lock topology differs')
    need(type(value['held_ofds'])is list and len(value['held_ofds'])==13,'one exclusive open description per inode')
    seen=set()
    for row in value['held_ofds']:
        m=full9(row['metadata'],0);inode=tuple(m[:2]);need(inode in aliases and inode not in seen,'held inode differs')
        names=[p for p in aliases[inode] if p.startswith(BASE+'/')]
        need(names==[row['path']] and row['metadata']==found[row['path']]['metadata'],
             'held OFD must identify the canonical GNU alias')
        exact(row,{'exclusive_flock_attached_to_borrowed_fd':True,'borrowed_fd_closed_or_relocked_here':False})
        match=re.fullmatch(r'lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s+(\d+)\s+'
            r'([0-9a-fA-F]+):([0-9a-fA-F]+):(\d+)\s+0\s+EOF',row['kernel_flock'])
        need(match is not None and int(match[1])==row['kernel_owner_pid_observed']
             and int(match[2],16)==linux_dev_major(m[0]) and int(match[3],16)==linux_dev_minor(m[0])
             and int(match[4])==m[1] and type(row['kernel_owner_pid_observed'])is int
             and row['kernel_owner_pid_observed']>0 and type(row['fdinfo_bytes'])is int
             and 0<row['fdinfo_bytes']<=65536 and HASH.fullmatch(row['fdinfo_sha256']),
             'actual whole-file exclusive fdinfo observation required')
        seen.add(inode)
    return found

def verify_admission_receipts(pre,post,binding,binding_raw,inventory,code_raws,cause):
    source_pins={n:descriptor(code_raws[n]) for n in ('continuous_policy_transaction.py',
        'current_policy_admission.py','protected_originals.py','held_ledger_gate.py','apply_parent_dir_once.py')}
    original_sets=[];lock_sets=[]
    for phase,value in [('pre',pre),('post',post)]:
        exact(value,{'schema':'hepta.parent-dir.current-admission-result.v1','phase':phase,
            'state':'COMPLETE_CURRENT_ADMISSION_OBSERVED_UNDER_CONTINUOUS_LOCKS','binding_sha256':sha(binding_raw),
            'boot_id':BOOT,'offline_candidate_is_live_adoption':False,'policy_writes_here':0,
            'native_calls_here':0,'model_requests_here':0,'signals_here':0,'business_qualified':False,
            'atomic_whole_phone_snapshot':False,'read_only_phase_cooperative_seconds_cap':70.0})
        exact(value['sources'],{'files':len(binding['code_members'])+1,'source_pins':source_pins,
            'original_protected_function_bodies_changed':False,
            'original_guard_read_checks_retained_with_additional_full9_label_tracking':True})
        exact(value['runtime'],{'manifest':binding['runtime_manifest'],'member_count':binding['runtime_file_count'],
            'ordinary_unpinned_bytecode_imports':0})
        native=value['native_operator'];exact(native,{'domain':'u:r:magisk:s0','uid':[0]*4,'gid':[0]*4,'nnp':0})
        history=value['history'];exact(history,{'state':'ACTUAL_NINE_NATIVE_TWO_BRANCH_ORIGINALS_VERIFIED',
            'previous_boundary':binding['current_boundary'],'inventory_original':binding['current_inventory'],
            'native_generations':9,'branch_nonces':binding['expected_branch_nonces'],'component_roles':33,
            'retired_roles':4,'inventory_roots':binding['expected_inventory_roots'],'history_or_caps_changed':False,
            'old_retirement_current_equality_claimed':False,'original_retirement_rewritten':False,'new_native_case_credit':0})
        roles=history['all_role_identities'];need(type(roles)is list and len(roles)==37
             and len({tuple(x) for x in roles})==37 and all(type(r)is list and len(r)==4
             and all(type(x)is int and x>1 for x in r) and r[:3]==[r[0]]*3 for r in roles),
             'complete 37 distinct owned role generations')
        need(type(history['absence_observations'])is list and len(history['absence_observations'])==2,
             'two original role absence observations required')
        for observation in history['absence_observations']:
            exact(observation,{'members':[],'kernel_group_absence':True})
            need(type(observation['numeric_pids'])is int and 0<observation['numeric_pids']<=4096
                 and type(observation['observed_monotonic_ns'])is int and observation['observed_monotonic_ns']>0,
                 'complete bounded process census evidence')
        need(history['absence_observations'][0]['observed_monotonic_ns']<=
             history['absence_observations'][1]['observed_monotonic_ns'],'absence observation order')
        exact(history['endpoints'],{'port_18080_listener_absent':True,'r6_abstract_endpoint_absent':True,'socket_connections':0})
        need(set(history['endpoint_table_descriptors'])=={'tcp','tcp6','unix'},'all original endpoint tables required')
        for row in history['endpoint_table_descriptors'].values():byte_pin(row)
        need(HASH.fullmatch(history['inventory_semantics_sha256']),'complete inventory semantic identity')
        artifact=value['combination_artifacts'];exact(artifact,{'combination':binding['current_combination'],
            'sealed_parent_policy_sha256':PARENT['sha256'],'actual_export_checked_against_kernel':value['actual_policy'],
            'on_disk_combination_modified':False,'offline_candidate_used_as_live_expectation':False,
            'post_observation_is_policy_adoption':False})
        exact(value['parent_adoption'],{'original':binding['parent_adoption'],'actual_parent_export':PARENT,
            'historical_verifier_rerun_on_phone':False,'current_admission_uses_historical_five_role_gate':False,
            'full_historical_adoption_verification_remains_host_input_gate':True})
        need(value['actual_v3_cause']==cause,'independent actual stack/receipt recomputation differs')
        protected=value['protected'];exact(protected,{'retained_service_record_count':43,'original_retirement_rewritten':False})
        need(set(protected['retirement_files'])=={'bound_inputs','disabled_flag','preflight','probe','proof'}
             and protected['retirement_files']['proof']['sha256']==RETIREMENT
             and len(protected['service_records'])==43 and len(protected['service_originals'])==43,
             'complete retained retirement and service originals required')
        exact(protected['disable'],{'bytes':0,'sha256':sha(b''),'old_module_disabled':True})
        need(protected['disable']['metadata']==protected['retirement_files']['disabled_flag']['metadata'],
             'full original disable identity differs')
        exact(protected['old_both_ports_and_r6_endpoint'],{'r6_endpoint_absent':True,'listening_ports_absent':[18080,18087]})
        protected_state=protected['protected_state']
        need(protected_state['adbd']['identity'][0]==3021 and protected_state['adbd']['exe'] in
             ('/apex/com.android.adbd/bin/adbd','/system/bin/adbd') and protected_state['anchors']
             and HASH.fullmatch(protected_state['pid1_mountinfo_sha256']),'protected UI/adbd/rootfs/mount evidence required')
        book=value['original_bookends'];exact(book,{'complete_full9_byte_and_label_bookends_equal':True})
        need(type(book['files'])is list and len(book['files'])==book['file_count'] and 1<=book['file_count']<=2048,
             'complete tracked original file inventory')
        originals={}
        for row in book['files']:
            need(row['path'] not in originals and type(row['private'])is bool and type(row['selinux'])is str,
                 'duplicate or incomplete tracked original')
            full9(row['metadata'],row['bytes']);byte_pin({k:row[k] for k in ('bytes','sha256')});originals[row['path']]=row
        for name,raw in code_raws.items():
            row=originals[binding['code_directory']+'/'+name]
            need({k:row[k] for k in ('bytes','sha256')}==descriptor(raw),'admission did not bookend applied source')
        for name in ('current_inventory','current_boundary','current_combination','runtime_manifest','policy_inventory',
                     'retirement_descriptor','global_gate_original','parent_adoption'):
            original=binding[name];row=originals[original['path']]
            need(all(row[k]==original[k] for k in original),'required complete source/data bookend differs')
        original_sets.append(originals)
        before=verify_lock_observation(value['locks_before'],inventory)
        after=verify_lock_observation(value['locks_after'],inventory)
        need(before==after,'lock alias bytes/full9/labels changed within admission');lock_sets.append(before)
        pending=value['global_pending_gate'];exact(pending,{'schema':'hepta.global-gate.borrowed-exclusive-ledger-result.v1',
            'original_source_sha256':GLOBAL_GATE['sha256'],'borrowed_fd_closed_or_relocked_here':False,
            'original_gate_seconds_cap':5.0,'subprocesses':0,'native_calls':0,'model_requests':0,'policy_writes':0})
        raw=base64.b64decode(pending['original_stdout_base64'],validate=True)
        need(descriptor(raw)==pending['original_stdout_descriptor'] and strict(raw)==pending['original_result'],
             'complete original global gate stdout differs')
        exact(pending['original_result'],{'state':'original_retirement_verified','global_action_gate_clear':True,
             'phone_writes':0,'effects_dispatched':0})
        exact(pending['adaptation'],{'original_source_bytes':GLOBAL_GATE['bytes'],
            'original_source_sha256':GLOBAL_GATE['sha256'],'exact_substitutions':3,
            'all_other_source_bytes_equal_after_inverse':True,'all_original_assertion_asts_equal':True,
            'standalone_flock_calls_in_adapted_program':0,'original_output_expression_unchanged':True})
        need(type(pending['elapsed_ns'])is int and 0<pending['elapsed_ns']<5000000000
             and len(pending['held_fd_observations'])>=3,'whole-function global gate timing and OFD observations')
        namespace=value['policy_namespace'];exact(namespace,{'inventory_original':binding['policy_inventory'],
            'only_this_new_output_allowed':binding['output'],'cooperative_protocol_lock_ownership':True,
            'arbitrary_uncooperative_root_exclusion_claimed':False})
        need(HASH.fullmatch(namespace['inventory_semantics_sha256']),'complete retained sibling policy identity')
    need(original_sets[0]==original_sets[1] and lock_sets[0]==lock_sets[1],
         'complete original/source full9/labels or held locks changed across load')
    need(pre['original_bookends']['directories']==post['original_bookends']['directories'],
         'complete preserved directory full9/name/label bookends changed')
    for name in ('parent_profiles','actual_v3_cause','parent_adoption','runtime','sources'):
        need(pre[name]==post[name],'pre/post complete retained state differs: '+name)
    for name in ('disable','retirement_files','protected_state','service_records','service_originals'):
        need(pre['protected'][name]==post['protected'][name],'pre/post protected state differs: '+name)
    for name in ('inventory_semantics_sha256','all_role_identities'):
        need(pre['history'][name]==post['history'][name],'pre/post history differs')
    need(pre['combination_artifacts']['artifacts']==post['combination_artifacts']['artifacts'],
         'pre/post actual artifacts changed')
    ns0,ns1=pre['policy_namespace'],post['policy_namespace']
    need(ns0['inventory_semantics_sha256']==ns1['inventory_semantics_sha256']
         and set(ns1['base_names'])==set(ns0['base_names'])|{PurePosixPath(binding['output']).name}
         and ns0['base_profile']['metadata'][:5]==ns1['base_profile']['metadata'][:5]
         and ns0['base_profile']['selinux']==ns1['base_profile']['selinux'],
         'intervening sibling policy/BASE change')
    exact(post,{'complete_original_state_equal_to_pre':True})
    return lock_sets[0]

DURABLE_WRAPPER={'bytes':19471,'sha256':'927648740b128d289509c29d4cf9cc244c350d722c1997c6419ec32e5a591aa5'}
DURABLE_CAPTURE={'bytes':7018,'sha256':'57ad0cc067a1d69e1821882c597f3b4cc903481041df10bf6629fe110b4745b5'}
DURABLE_NAMES={'LAUNCH-INTENT.json','DRIVER-READY.json','DRIVER-ADMIT.json','DRIVER-EXEC-INTENT.json',
    'driver.stdout','driver.stderr','DRIVER-TERMINAL.json'}

def verify_durable_driver_capture(value,binding_raw,binding,cap,code,files,supervisor,actual,*,get,original):
    """Verify all seven actual outer originals; original transport stays separate."""
    need(type(value)is dict and set(value)=={'operation','wrapper','stdout'},
         'complete separate outer-capture provenance required')
    outer=verify_capture_operation(get(value['operation']),get(value['wrapper']),get(value['stdout']))
    exact(outer,{'schema':'hepta.parent-dir.durable-driver-original-manifest.v1',
        'state':'COMPLETE_DURABLE_DRIVER_ORIGINALS_READ','boot_id':BOOT,'binding_sha256':sha(binding_raw),
        'capture_source':DURABLE_CAPTURE,'wrapper_source':DURABLE_WRAPPER,'file_count':7,
        'complete_original_bookends_equal':True,'original_wait_rewritten':False,
        'core_policy_child_wait_is_separate':True,'phone_file_writes':0,'policy_loads':0,
        'new_children':0,'cleanup_signals':0,'policy_adopted':False})
    for field,name in [('binding_original','BINDING.json'),('capture_original','capture_durable_driver.py'),
                       ('wrapper_original','durable_apply_once.py')]:
        source_row=next(r for r in cap['files'] if r['category']=='code' and r['name']==name)
        need(outer[field]=={k:source_row[k] for k in ('path','bytes','sha256','metadata','selinux')},
             'outer capture and original admitted source generation differ')
    bytes_match(code['durable_apply_once.py'],DURABLE_WRAPPER)
    bytes_match(code['capture_durable_driver.py'],DURABLE_CAPTURE)
    job=str(PurePosixPath(BASE).parent/'policy-parent-dir-original-jobs'/PurePosixPath(binding['output']).name)
    directory=outer['directory'];need(set(directory)=={'path','metadata','names','selinux'},
        'complete actual outer directory original required')
    m=directory['metadata']
    need(directory['path']==job and set(directory['names'])==DURABLE_NAMES and len(directory['names'])==7
        and type(m)is list and len(m)==9 and all(type(n)is int and n>=0 for n in m)
        and m[2]==0o40700 and m[3:5]==[0,0] and type(directory['selinux'])is str and directory['selinux'],
        'exact private seven-member outer journal differs')
    raws={};rows={};total=0
    need(type(outer['files'])is list and len(outer['files'])==7,'all seven actual outer originals required')
    for row in outer['files']:
        need(type(row)is dict and set(row)=={'name','path','bytes','sha256','metadata','selinux'}
            and row['name']in DURABLE_NAMES and row['name']not in raws and row['path']==job+'/'+row['name'],
            'unique exact outer-original namespace differs')
        raw=original({k:row[k] for k in ('path','bytes','sha256','metadata')});full9(row['metadata'],len(raw))
        need(row['metadata'][2]==0o100600 and row['metadata'][3:5]==[0,0]
            and type(row['selinux'])is str and row['selinux'],'private outer original profile differs')
        rows[row['name']]=row;raws[row['name']]=raw;total+=len(raw)
    need(set(raws)==DURABLE_NAMES and total==outer['raw_file_bytes']<=5*1024*1024,
        'complete outer original bytes/budget differ')
    argv=['/usr/bin/python3','-I','-B',binding['code_directory']+'/apply_parent_dir_once.py',
          '--execute-once','--binding',binding['code_directory']+'/BINDING.json',
          '--binding-sha256',sha(binding_raw),'--self-sha256',DRIVER['sha256']]
    intent=strict(raws['LAUNCH-INTENT.json'])
    exact(intent,{'schema':'hepta.parent-dir.detached-launch-intent.v1','boot_id':BOOT,
        'binding_sha256':sha(binding_raw),'wrapper_sha256':DURABLE_WRAPPER['sha256'],'journal':job,
        'driver_argv':argv,'maximum_apply_dispatches':1,'automatic_retry':False,'automatic_rollback':False,
        'transport_timeout_does_not_authorize_replay':True,'source_original':outer['wrapper_original'],
        'binding_original':outer['binding_original']})
    token=intent['token'];need(type(token)is str and re.fullmatch('[0-9a-f]{32}',token),
        'one actual launch token required')
    ready=strict(raws['DRIVER-READY.json']);identity=ready['identity']
    need(type(identity)is list and len(identity)==4 and all(type(n)is int and n>1 for n in identity)
        and identity[:3]==[identity[0]]*3 and identity==supervisor,
        'same-PID exec is not the actual core continuous owner generation')
    exact(ready,{'schema':'hepta.parent-dir.detached-driver-ready.v1','identity':identity,
        'binding_sha256':sha(binding_raw),'wrapper_sha256':DURABLE_WRAPPER['sha256'],
        'intent_sha256':sha(raws['LAUNCH-INTENT.json']),'token':token,'driver_argv':argv,'stdin_is_devnull':True})
    need(type(ready['ppid'])is int and ready['ppid']>1 and ready['ppid']!=identity[0],
        'original outer parent PID required')
    streams=ready['stdio_regular_files'];need(type(streams)is list and len(streams)==2,
        'original driver stdout/stderr regular-file identities required')
    for entry,fd,name in zip(streams,(1,2),('driver.stdout','driver.stderr')):
        need(set(entry)=={'fd','path','metadata'} and entry['fd']==fd and entry['path']==job+'/'+name,
             'original regular stream descriptor differs')
        before=full9(entry['metadata'],0);after=rows[name]['metadata']
        need(before[:6]==after[:6] and before[2]==0o100600 and before[3:5]==[0,0],
             'same original stream inode/security must survive driver exec and wait')
    admit=strict(raws['DRIVER-ADMIT.json'])
    need(admit=={'schema':'hepta.parent-dir.detached-driver-admit.v1','identity':identity,
        'binding_sha256':sha(binding_raw),'ready_sha256':sha(raws['DRIVER-READY.json']),
        'intent_sha256':sha(raws['LAUNCH-INTENT.json']),'token':token},
        'exact ready-token-bound original driver barrier required')
    need(strict(raws['DRIVER-EXEC-INTENT.json'])=={'schema':'hepta.parent-dir.detached-driver-exec.v1',
        'identity':identity,'argv':argv,'binding_sha256':sha(binding_raw),
        'admit_sha256':sha(raws['DRIVER-ADMIT.json']),'driver_source':DRIVER,'maximum_driver_execs':1},
        'one original same-PID driver exec differs')
    terminal=strict(raws['DRIVER-TERMINAL.json'])
    exact(terminal,{'schema':'hepta.parent-dir.detached-driver-terminal.v1',
        'state':'ORIGINAL_DRIVER_JOINED_GROUP_ABSENT','binding_sha256':sha(binding_raw),
        'wrapper_sha256':DURABLE_WRAPPER['sha256'],'driver_identity':identity,'admitted':True,
        'driver_waitpid_returned':True,'driver_returncode':0,
        'driver_wait_scope':'original_detached_apply_driver_only',
        'policy_child_wait_provenance':'separate_core_CHILD-RESULT.json','errors':[],
        'automatic_retry':False,'automatic_rollback':False,'policy_adopted':False,
        'actual_policy_identity_requires_original_core_export':True})
    for field,name in [('stdout','driver.stdout'),('stderr','driver.stderr')]:
        need(terminal[field]=={k:rows[name][k] for k in ('path','bytes','sha256','metadata','selinux')},
             'complete original driver stream/full9 linkage differs')
    need(raws['driver.stderr']==b'','successful original apply driver stderr must be empty')
    signals=terminal['outer_signals_observed']
    need(type(signals)is list and len(signals)<=16 and all(type(n)is int and n in (1,2,14,15) for n in signals),
         'bounded observed outer signals must not be invented or forwarded')
    absence=terminal['driver_group_absence']
    exact(absence,{'state':'ORIGINAL_DRIVER_GROUP_AND_SESSION_ABSENT','identity':identity,
        'members':[],'kernel_group_absence':True,'cleanup_signals':0,
        'observation_does_not_reclassify_prior_transport_wait':True})
    need(type(absence['numeric_pids'])is int and 1<=absence['numeric_pids']<=4096
        and type(absence['observed_monotonic_ns'])is int and absence['observed_monotonic_ns']>0,
        'complete actual independent post-wait driver census required')
    core_terminal=next(r for r in cap['files'] if r['category']=='journal' and r['name']=='TERMINAL.json')
    report=strict(raws['driver.stdout'])
    need(report=={'schema':'hepta.parent-dir.single-driver-result.v1',
        'state':'ACTUAL_EXPORT_PENDING_INDEPENDENT_PROOF','binding_sha256':sha(binding_raw),
        'driver_sha256':DRIVER['sha256'],'terminal_original':{k:core_terminal[k] for k in ('path','bytes','sha256','metadata')},
        'owner_result':{'terminal_persisted':True,'child_joined':True,'group_absent':True,'error':None,'policy_adopted':False},
        'actual_post_policy':actual,'policy_adopted':False,'business_qualified':False,
        'automatic_retry':False,'automatic_rollback':False,'new_native_tasks':0,
        'full_actual_export_and_semantic_comparison_still_required':True},
        'complete original driver stdout must bind actual core terminal/export')
    need(bytes_match(files['TERMINAL.json'],core_terminal)is files['TERMINAL.json'],
        'actual core terminal bytes differ')
    return {'original_driver_identity':identity,'original_driver_waitpid_returned':True,'driver_returncode':0,
        'original_driver_group_absence':absence,'complete_original_regular_streams':True,
        'outer_original_file_count':7,'outer_original_raw_bytes':total,'outer_wrapper_source':DURABLE_WRAPPER,
        'outer_capture_source':DURABLE_CAPTURE,'same_PID_exec_core_owner_verified':True,
        'policy_child_wait_is_separate':True,'prior_transport_wait_reclassified':False}

def verify_live_capture(live_raw,*,read_pinned):
    value=strict(live_raw)
    need(set(value)=={'schema','capture_operation','capture_wrapper','capture_stdout','original_map',
        'load_transport_originals','load_transport_completion_observation','scope_decision','durable_capture'},'exact live provenance fields')
    exact(value,{'schema':'hepta.parent-dir.actual-live-provenance.v1'})
    retained_reads={}
    def get(row):
        file_descriptor(row);retained_reads[key(row)]={k:row[k] for k in ('path','bytes','sha256')}
        return bytes_match(read_pinned(row),row)
    cap=verify_capture_operation(get(value['capture_operation']),get(value['capture_wrapper']),get(value['capture_stdout']))
    need(CAPTURE_SOURCE is not None,'reviewed capture source not sealed')
    exact(cap,{'schema':'hepta.parent-dir.readonly-journal-capture.v1','state':'COMPLETE_ORIGINAL_MANIFEST_READ',
        'boot_id':BOOT,'capture_source':CAPTURE_SOURCE,'continuous_core':CORE,'all_originals_rechecked':True,
        'full_contents_returned_inline':False,'host_must_read_every_indexed_original':True,
        'phone_writes':0,'policy_loads':0,'new_children':0,'locks_acquired':0,
        'transport_wait_reclassified':False,'policy_adopted':False,'business_qualified':False})
    mappings=value['original_map'];need(type(mappings)is list and 1<=len(mappings)<=1024,'bounded exact original-copy map')
    by_origin={};origin_descriptors={};used=set()
    for row in mappings:
        need(set(row)=={'original','retained'},'explicit original/copy pair required')
        a,b=row['original'],row['retained'];k=key(a);file_descriptor(b)
        need(k not in by_origin and {x:a[x] for x in ('bytes','sha256')}=={x:b[x] for x in ('bytes','sha256')},
             'original mapping duplicated or byte identities differ');by_origin[k]=b;origin_descriptors[k]=a
    def original(row):
        k=key(row);need(k in by_origin,'required actual original absent from explicit copy map')
        if 'metadata' in row:need(origin_descriptors[k].get('metadata')==row['metadata'],
             'retained original copy map rewrites the actual source full9')
        used.add(k)
        return get(by_origin[k])
    files={};code={};capture_paths=set();total=0
    need(type(cap['files'])is list and len(cap['files'])<=80,'bounded complete capture file list')
    for row in cap['files']:
        need(set(row)=={'category','name','path','metadata','selinux','bytes','sha256'} and row['path'] not in capture_paths,
             'complete unique capture file fields')
        d={k:row[k] for k in ('path','bytes','sha256','metadata')};raw=original(d);full9(row['metadata'],len(raw))
        need(row['metadata'][2]==0o100600 and row['metadata'][3:5]==[0,0] and type(row['selinux'])is str
             and row['selinux'],'captured original ownership/mode/label differs')
        category=row['category'];need(category in ('code','journal'),'capture category differs')
        need(row['path']==cap['directories'][category]['path']+'/'+row['name'],'capture file escaped its namespace')
        container=code if category=='code' else files
        need(row['name'] not in container,'duplicate captured member');container[row['name']]=raw
        capture_paths.add(row['path']);total+=len(raw)
    need(total==cap['raw_file_bytes']<=12*1024*1024 and set(files)==JOURNAL_NAMES,'complete raw capture set/budget')
    binding_raw=code['BINDING.json'];binding=strict(binding_raw)
    need(descriptor(binding_raw)==cap['binding'] and set(code)=={'BINDING.json',*binding['code_members']},
         'exact captured binding and all staged members')
    known={'continuous_policy_transaction.py':CORE,'current_policy_admission.py':ADMISSION,
        'protected_originals.py':PROTECTED,'held_ledger_gate.py':HELD_GATE,'apply_parent_dir_once.py':DRIVER,
        'capture_policy_journal.py':CAPTURE_SOURCE,'durable_apply_once.py':DURABLE_WRAPPER,
        'capture_durable_driver.py':DURABLE_CAPTURE}
    for name,pin in binding['code_members'].items():bytes_match(code[name],pin)
    for name,pin in known.items():bytes_match(code[name],pin)
    adapter=load_reviewed(code['current_policy_admission.py'],ADMISSION,'parent_dir_current_admission')
    adapter.validate_binding(binding)
    need(cap['directories']['code']['path']==binding['code_directory']
         and cap['directories']['journal']['path']==binding['output']
         and set(cap['directories']['code']['names'])==set(code)
         and set(cap['directories']['journal']['names'])==set(files),'capture directory/binding bookends differ')
    for directory in cap['directories'].values():
        m=directory['metadata'];need(type(m)is list and len(m)==9 and all(type(x)is int and x>=0 for x in m)
            and m[2]==0o40700 and m[3:5]==[0,0] and type(directory['selinux'])is str and directory['selinux'],
            'capture namespace security/full9 profile differs')
    head=strict(original(binding['current_boundary']));inventory=strict(original(binding['current_inventory']))
    closed=strict(original(head['closure']))
    need(head['nonce']==binding['head_nonce'] and head['boot_id']==BOOT
         and head['prior_boundary']==adapter.PREDECESSOR and head['inventory']==binding['current_inventory']
         and head['combination_sha256']==binding['current_combination']['sha256']
         and head['package_sha256']==binding['runtime_manifest']['sha256'],'actual head/combination/source linkage differs')
    c=binding['causal_observation']
    cause=adapter.validate_causal_originals(original(c['stderr']),original(c['receipt']),binding,closed,inventory)
    scope_raw=get(value['scope_decision']);need(strict(scope_raw)==expected_scope(binding_raw,binding),
         'actual Root scope fingerprint does not bind this single transition')
    pre=strict(files['PRECHECK.json']);terminal=strict(files['TERMINAL.json'])
    exact(terminal,{'schema':'hepta.parent-dir.actual-load-terminal.v1',
        'state':'ACTUAL_EXPORT_REQUIRES_INDEPENDENT_COMPARISON','error':None,'offline_candidate':OFFLINE,
        'admission_binding':sha(binding_raw),'policy_adopted':False,'business_qualified':False,'native_tasks':0,
        'automatic_retry':False,'automatic_rollback':False,'complete_semantic_comparison_still_required':True})
    parent=descriptor(files['live-policy-before.bin']);actual=descriptor(files['live-policy-after.bin'])
    need(parent==PARENT and actual!=PARENT and 0<actual['bytes']<=4*1024*1024
         and terminal['actual_post_policy']==actual,'actual before/post export linkage differs')
    post=terminal['postchecks'];need(pre['actual_policy']==parent and post['actual_policy']==actual,
         'complete admission did not observe these exact policy exports')
    locks=verify_admission_receipts(pre,post,binding,binding_raw,inventory,code,cause)
    pre_originals={r['path']:r for r in pre['original_bookends']['files']}
    for row in cap['files']:
        if row['category']=='code':
            old=pre_originals[row['path']]
            need(all(old[k]==row[k] for k in ('metadata','bytes','sha256','selinux')),
                 'captured source generation differs from actual loaded/bookended source')
    pre_dirs={r['path']:r for r in pre['original_bookends']['directories']}
    need(pre_dirs[binding['code_directory']]==cap['directories']['code'],
         'captured code namespace differs from actual admitted full9/names/label')
    held=terminal['held_lock_rows'];need(len(held)==24,'terminal complete held lock recheck required')
    for row in held:
        old=locks[row['path']];need(set(row)=={'path','metadata','bytes','sha256','same_open_description_held'}
            and row['same_open_description_held'] is True
            and all(row[k]==old[k] for k in ('path','metadata','bytes','sha256')),'terminal held lock changed')
    need(len({r['path'] for r in held})==24,'duplicate terminal lock alias')
    plan=strict(files['ADAPTER-PLAN.original.json'])
    need(plan=={'schema':'hepta.parent-dir.single-load-plan.v1','boot_id':BOOT,'source':CORE,
        'busybox':BUSYBOX,'output':binding['output'],'admission_binding':sha(binding_raw)},'exact one-load adapter plan differs')
    child_plan=strict(files['CHILD-PLAN.original.json']);cp_sha=sha(files['CHILD-PLAN.original.json'])
    need(set(child_plan)==set(plan)|{'supervisor_identity','inherited_lock_identities'}
         and all(child_plan[k]==v for k,v in plan.items()),'original child plan differs')
    supervisor=child_plan['supervisor_identity'];need(type(supervisor)is list and len(supervisor)==4
         and all(type(x)is int and x>0 for x in supervisor),'original owner generation required')
    need(pre['native_operator']['identity']==post['native_operator']['identity']==supervisor
         and supervisor not in pre['history']['all_role_identities'],
         'original continuous owner identity changed or belongs to a required absent role')
    expected_inodes={tuple(r['metadata'][:2]):r['metadata'] for r in held}
    inherited=child_plan['inherited_lock_identities'];need(len(inherited)==13
         and {tuple(m[:2]):m for m in inherited}==expected_inodes,'child inherited complete continuously held inode set')
    argv=['/proc/1/root/data/adb/magisk/busybox','chroot','/proc/1/root','/data/adb/magisk/magiskpolicy',
        '--live','--apply',NATIVE_BASE+'/'+PurePosixPath(binding['output']).name+'/delta.rule']
    intent=strict(files['APPLY-INTENT.json']);need(intent=={'schema':'hepta.parent-dir.single-apply-intent.v1',
        'parent_policy':PARENT,'offline_candidate':OFFLINE,'argv':argv,'child_plan_sha256':cp_sha,
        'admission_binding':sha(binding_raw),'maximum_apply_dispatches':1,'automatic_retry':False,'automatic_rollback':False},
        'one exact literal apply intent required')
    need(files['delta.rule']==RULE,'exact one getattr atom required')
    ready=strict(files['CHILD-READY.original.json']);exact(ready,{'schema':'hepta.policy-child-ready.v1','plan_sha256':cp_sha})
    process=ready['process'];identity=process['identity']
    need(type(identity)is list and len(identity)==4 and all(type(x)is int and x>0 for x in identity)
         and identity[:3]==[identity[0]]*3 and process['ppid']==supervisor[0],
         'actual owned policy child/session/parent generation differs')
    need(strict(files['CHILD-ADMIT.json'])=={'identity':identity,'child_plan_sha256':cp_sha,
        'may_execute_after_barrier_write':True,'maximum_dispatches':1},'one child barrier identity differs')
    child=strict(files['CHILD-RESULT.json']);exact(child,{'state':'ORIGINAL_CHILD_JOINED_GROUP_ABSENT',
        'pid':identity[0],'identity':identity,'child_wait_returned':True,'returncode':0,'group_absent':True,
        'signals':[],'errors':[],'error_count':0,'quarantine_observed':False,'automatic_retry':False})
    need(set(child['streams'])=={'stdout','stderr'},'both original streams required')
    for stream in ('stdout','stderr'):
        need(files['policy.'+stream]==b'' and child['streams'][stream]=={
            **descriptor(b''),'observed_bytes':0,'eof':True,'truncated':False},'original child stream not clean and complete')
    need(terminal['child']==dict(child,state='JOINED'),'durable terminal did not preserve the original joined child')
    records=value['load_transport_originals'];need(type(records)is list and 1<=len(records)<=16,
         'original dispatch/transport records must be retained')
    for row in records:get(row)
    need(value['load_transport_completion_observation'] in ('COMPLETE','FAILED','UNKNOWN'),
         'original transport outcome must remain explicit')
    durable=verify_durable_driver_capture(value['durable_capture'],binding_raw,binding,cap,code,files,supervisor,actual,
        get=get,original=original)
    need(set(by_origin)==used,'live original map contains unused/unrelated copies')
    return {'binding':binding,'binding_sha256':sha(binding_raw),'parent':PARENT,'runtime_policy':actual,
        'actual_export_original':next(r for r in cap['files'] if r['category']=='journal' and r['name']=='live-policy-after.bin'),
        'actual_export_retained':by_origin[(binding['output']+'/live-policy-after.bin',actual['bytes'],actual['sha256'])],
        'actual_parent_retained':by_origin[(binding['output']+'/live-policy-before.bin',PARENT['bytes'],PARENT['sha256'])],
        'root_scope_decision_sha256':sha(scope_raw),'prior_boundary_sha256':binding['current_boundary']['sha256'],
        'parent_adoption_sha256':PARENT_ADOPTION['sha256'],'retirement_sha256':RETIREMENT,
        'actual_v3_cause':cause,'original_child':child,'original_outer_driver':durable,'continuous_lock_paths':24,'continuous_lock_inodes':13,
        'actual_pre_and_post_admission_verified':True,'complete_policy_comparison_still_required':True,
        'original_transport_completion_observation':value['load_transport_completion_observation'],
        'verification_originals_read':list(retained_reads.values()),
        'transport_unknown_reclassified':False,'phone_calls':0,'policy_writes':0,'policy_adopted':False}

def validate_full_proof_value(proof):
    exact(proof,{'schema':'hepta.parent-dir.complete-offline-one-atom-proof.v1',
        'state':'EXACT_ONE_DIRECTORY_GETATTR_ATOM_VERIFIED_OFFLINE','scope_sha256':SCOPE['sha256'],
        'proposed_atoms':[ATOM],'check_count':12,'passed_count':12,'input_originals_rechecked':True,
        'phone_operations':0,'kernel_policy_loads':0,'active_policy_writes':0,'component_qualified':False,'business_qualified':False})
    checks=proof['checks'];need([c['name'] for c in checks]==CHECK_NAMES and all(c['passed'] is True for c in checks),
         'all twelve complete proof checks required')
    image=checks[0]['details'];exact(image,{'schema':'hepta.official-libsepol-parent-dir-getattr-full-image-comparison.v1',
        'proposed_rule_atoms':[ATOM],'proposed_permission_atom_count':1,'cycle_bound':4})
    for name in ('complete_input_consumption','baseline_conditional_list_empty','candidate_conditional_list_empty',
        'all_cycles_close_at_first_image','all_cycle_representatives_stable','only_proposed_delta_full_image_equal',
        'negative_missing_atom_rejected','negative_unproposed_binder_change_rejected','negative_unknown_handling_rejected'):
        need(image[name] is True,'complete image/negative-control check failed: '+name)
    te=checks[3]['details'];need(te['added']==[[['allow',ATOM[1],ATOM[2],'dir',['unconditional'],'permission','getattr'],1]]
        and te['removed']==[],'complete symbolic counter delta differs')
    nonte=checks[4]['details'];need(type(nonte)is dict and set(nonte)=={'booleans','classes_with_common',
         'common_permissions','conditionals','metadata','symbolic_tables','type_attributes','types'} and all(r['equal'] is True
         and r['parent_sha256']==r['candidate_sha256'] and HASH.fullmatch(r['parent_sha256']) for r in nonte.values()),
         'complete non-TE/symbol table difference')
    for row in checks[5:11]:
        need(len(row['counts'])==len(row['sha256'])==4 and len(set(row['counts']))==len(set(row['sha256']))==1,
             'complete libsepol table/roundtrip difference')
    exact(checks[11],{'parent_allowed':'0x10000000','candidate_allowed':'0x10000010',
        'scope_is_all_system_data_file_directories_not_path_only':True})
    return image

def original_process(value,get,argv):
    exact(value,{'argv':argv,'returncode':0,'timed_out':False,'output_complete':True,
        'original_child_wait_returned':True,'automatic_retry':False,'host_only':True})
    need(type(value['started_monotonic_ns'])is int and type(value['ended_monotonic_ns'])is int
         and 0<value['started_monotonic_ns']<=value['ended_monotonic_ns'],'actual host child monotonic times')
    need(get(value['stderr'])==b'','actual proof child stderr nonempty')
    return strict(get(value['stdout']))

def verify_post_proof(index_raw,*,read_pinned,live):
    index=strict(index_raw)
    need(set(index)=={'schema','report','plan','execution','retention','original_map','complete_archive','complete_archive_manifest',
        'all_orbit_images_embedded','complete_comparison_outputs_retained_elsewhere'},'complete proof-index fields')
    exact(index,{'schema':'hepta.parent-dir.actual-post-proof-inputs.v1','all_orbit_images_embedded':False,
        'complete_comparison_outputs_retained_elsewhere':True})
    file_descriptor(index['complete_archive']);file_descriptor(index['complete_archive_manifest'])
    mapped={};used=set()
    for row in index['original_map']:
        need(set(row)=={'original','retained'},'complete proof mapping pair')
        a,b=row['original'],row['retained'];k=key(a);file_descriptor(b)
        need(k not in mapped and {x:a[x] for x in ('bytes','sha256')}=={x:b[x] for x in ('bytes','sha256')},
             'duplicate or changed proof mapping');mapped[k]=b
    need(1<=len(mapped)<=256,'bounded retained proof original set')
    def get(row):
        k=key(row);need(k in mapped,'proof input not in explicit original map');used.add(k)
        return bytes_match(read_pinned(mapped[k]),row)
    report=strict(get(index['report']));plan=strict(get(index['plan']));execution=strict(get(index['execution']))
    exact(report,{'schema':'hepta.parent-dir.actual-export-complete-proof.v1',
        'state':'ACTUAL_EXPORTED_BYTES_COMPLETE_ONE_ATOM_COMPARISON_PASSED','live_provenance_sha256':live['provenance_sha256'],
        'actual_parent':PARENT,'actual_export':live['runtime_policy'],'phone_operations':0,'policy_loads':0,
        'policy_adopted':False,'business_qualified':False,'input_originals_rechecked':True})
    need(COMPARISON_SOURCE is not None and report['source']['bytes']==COMPARISON_SOURCE['bytes']
         and report['source']['sha256']==COMPARISON_SOURCE['sha256'],'actual complete-comparison source differs')
    bytes_match(get(report['source']),COMPARISON_SOURCE)
    need(set(plan)=={'schema','output','parent','candidate','live_provenance','live_verifier','input_original_map',
          'comparator_source'} and plan['schema']=='hepta.parent-dir.actual-post-comparison-plan.v1'
         and plan['output']==str(PurePosixPath(index['report']['path']).parent)
         and plan['parent']=={k:report['parent'][k] for k in ('path','bytes','sha256')}
         and plan['candidate']=={k:report['candidate'][k] for k in ('path','bytes','sha256')}
         and plan['live_provenance']['sha256']==live['provenance_sha256'], 'actual complete-comparison plan differs')
    need(plan['comparator_source']=={k:report['source'][k] for k in ('path','bytes','sha256')},
         'plan used a different invocation source')
    verifier_raw=get(plan['live_verifier']);need(sha(verifier_raw)==reviewed_source_sha256()
        and get(report['sources']['live_verifier'])==verifier_raw,'post proof did not execute this independent live verifier')
    copied={}
    for row in plan['input_original_map']:
        need(set(row)=={'original','retained'},'post proof must preserve actual host-copy provenance')
        a,b=row['original'],row['retained'];k=key(a);file_descriptor(b)
        need(k not in copied and {q:a[q] for q in ('bytes','sha256')}=={q:b[q] for q in ('bytes','sha256')},
             'post proof input copy duplicated or changed')
        get(b);copied[k]=b
    need(set(copied)=={key(r) for r in live['verification_originals_read']}
         and copied[key(live['actual_parent_retained'])]==plan['parent']
         and copied[key(live['actual_export_retained'])]==plan['candidate'],
         'complete original live provenance did not map to exact compared host bytes')
    for name,pin in [('image_source',IMAGE_SOURCE),('image_binary',IMAGE_BINARY),('snapshot_source',SNAPSHOT_SOURCE),
        ('scope',SCOPE),('av_tool',AV_TOOL),('av_source',AV_SOURCE),('tool_inventory',TOOL_INVENTORY)]:
        bytes_match(get(report['sources'][name]),pin)
    bytes_match(get(report['parent']),PARENT);bytes_match(get(report['candidate']),live['runtime_policy'])
    bytes_match(get(plan['live_provenance']),{'bytes':live['provenance_bytes'],'sha256':live['provenance_sha256']})
    proof=strict(get(report['complete_proof']));image=validate_full_proof_value(proof)
    need(proof['parent']==report['parent'] and proof['candidate']==report['candidate'],
         'complete semantic proof identifies other actual input bytes')
    records=report['process_originals'];need(type(records)is dict and set(records)=={
        'complete-image','parent-role_user','parent-genfs','candidate-role_user','candidate-genfs',
        'parent_normalized-role_user','parent_normalized-genfs','candidate_normalized-role_user','candidate_normalized-genfs',
        'parent-dir-av','candidate-dir-av'},'complete original process set differs')
    output=plan['output'];sources=report['sources'];tool_inventory=strict(get(sources['tool_inventory']))
    image_result=original_process(strict(get(records['complete-image'])),get,[sources['image_binary']['path'],
        '--compare-offline-parent-dir-getattr',plan['parent']['path'],plan['candidate']['path'],output+'/normalized'])
    need(image_result==image,'actual C process output differs from proof report')
    manifest=strict(get(index['complete_archive_manifest']))
    exact(manifest,{'schema':'hepta.parent-dir.actual-proof-full-archive.v1',
        'actual_export':live['runtime_policy'],'runtime_32MiB_budget_claimed':False,'phone_operations':0})
    archived={};archive_raw_bytes=0
    for row in manifest['files']:
        relative=row['relative_path'];p=PurePosixPath(relative)
        need(not p.is_absolute() and '..' not in p.parts and str(p)==relative and relative not in archived
             and row['path']==output+'/'+relative,'full archive file inventory paths differ')
        file_descriptor({k:row[k] for k in ('path','bytes','sha256','metadata')})
        archived[relative]=row;archive_raw_bytes+=row['bytes']
    need(archive_raw_bytes==manifest['raw_member_bytes'],'full archive raw-byte accounting differs')
    orbits=image['serialization_orbits'];need(type(orbits)is list and len(orbits)==5
         and {x['name'] for x in orbits}=={'parent','candidate','expected','negative-handle-unknown','negative-binder-change'},
         'complete official serializer orbit set')
    expected_normalized={'normalized/parent.normalized.bin','normalized/candidate.normalized.bin',
        'normalized/expected-proposed-atoms.normalized.bin'}
    selected={}
    for orbit in orbits:
        need(set(orbit)=={'name','length','selected_index'} and type(orbit['length'])is int
             and 1<=orbit['length']<=4 and type(orbit['selected_index'])is int
             and 1<=orbit['selected_index']<=orbit['length'],'bounded actual serializer orbit')
        names=['normalized/'+orbit['name']+'.orbit-%02d.bin'%i for i in range(1,orbit['length']+1)]
        expected_normalized.update(names)
        selected[orbit['name']]=archived[names[orbit['selected_index']-1]]
    need({n for n in archived if n.startswith('normalized/')}==expected_normalized,
         'full normalization or negative-control binary omitted from actual archive manifest')
    normalized={n:{k:archived['normalized/'+n+'.normalized.bin'][k] for k in ('bytes','sha256')}
        for n in ('parent','candidate','expected-proposed-atoms')}
    need(normalized['candidate']==normalized['expected-proposed-atoms']
         and normalized['parent']!=normalized['candidate'],'complete expected/candidate image identity relationship differs')
    for name,keyname in [('parent','parent'),('candidate','candidate'),('expected','expected-proposed-atoms')]:
        need({k:selected[name][k] for k in ('bytes','sha256')}==normalized[keyname],
             'selected official orbit is not the retained normalized image')
    need(all({k:selected[n][k] for k in ('bytes','sha256')}!=normalized['candidate']
        for n in ('negative-handle-unknown','negative-binder-change')),'negative image equals accepted complete image')
    need(all('proof/'+n+'.non-te-tables.json.gz' in archived for n in
        ('parent','candidate','parent_normalized','candidate_normalized')) and all(
        'proof/'+n+'.all-te-atoms.jsonl.gz' in archived for n in ('parent','candidate')),
        'full symbolic table originals not retained in actual complete archive')
    tables={};paths={'parent':plan['parent']['path'],'candidate':plan['candidate']['path'],
        'parent_normalized':output+'/normalized/parent.normalized.bin',
        'candidate_normalized':output+'/normalized/candidate.normalized.bin'}
    for name,path in paths.items():
        tables[name]={kind:original_process(strict(get(records[name+'-'+kind])),get,[row['path'],path])
            for kind,row in tool_inventory['readers'].items()}
    for table in ('roles','users','initialsids','fs_uses','unlabeled_filesystems'):
        need(all(tables[n]['role_user'][table]==tables['parent']['role_user'][table] for n in tables),
             'raw complete libsepol table differs: '+table)
    need(all(tables[n]['genfs']['genfs']==tables['parent']['genfs']['genfs'] for n in tables),'raw complete genfs table differs')
    perms=['getattr','search','open','read','write','add_name','remove_name','setattr']
    av={}
    for name in ('parent','candidate'):
        d=plan[name];argv=[sources['av_tool']['path'],'--policy',d['path'],'--sha256',d['sha256'],
            '--source','u:r:'+ATOM[1]+':s0','--target','u:object_r:system_data_file:s0','--class','dir']
        for p in perms:argv+=['--perm',p]
        av[name]=original_process(strict(get(records[name+'-dir-av'])),get,argv)
        need(av[name]==proof['effective_av'][name] and av[name]['policy']['sha256']==d['sha256']
             and av[name]['policy']['bytes']==d['bytes'] and av[name]['policy']['input_unchanged'] is True,
             'effective AV policy/raw result identity differs')
    need(int(av['parent']['allowed'],16)==0x10000000 and int(av['candidate']['allowed'],16)==0x10000010,
         'effective AV change extends beyond getattr')
    need({p['name']:p['policy_allowed'] for p in av['candidate']['permissions']}=={
        p:p in ('getattr','search') for p in perms},'directory content or mutation permission changed')
    for k in ('query','decided','auditallow','auditdeny'):
        need(av['parent'][k]==av['candidate'][k],'AV identity/audit behavior changed')
    exact(execution,{'schema':'hepta.parent-dir.actual-post-host-execution.v1','state':'COMPLETE_HOST_PROOF_ONLY',
        'source':report['source'],'plan':index['plan'],'report':index['report'],'returncode':0,
        'all_originals_rechecked':True,'check_count':12,'passed_count':12,'phone_operations':0,'policy_loads':0,
        'automatic_retry':False,'policy_adopted':False,'business_qualified':False})
    retention=strict(get(index['retention']))
    exact(retention,{'schema':'hepta.parent-dir.actual-post-run-result.v1','state':'ACTUAL_COMPLETE_PROOF_FINISHED',
        'report':index['report'],'plan':index['plan'],'execution':index['execution'],
        'archive':index['complete_archive'],'archive_manifest':index['complete_archive_manifest'],
        'actual_export':live['runtime_policy'],'checks':12,'passed':12,
        'runtime_proof_index_requires_actual_copy_map':True,'phone_operations':0,'policy_loads':0,'policy_adopted':False})
    need(set(mapped)==used,'proof original map contains unused/unrelated originals')
    return {'proof_index_sha256':sha(index_raw),'actual_export':live['runtime_policy'],
        'check_count':12,'passed_count':12,'original_process_count':11,
        'full_image_exact_one_atom':True,'all_three_negative_controls_rejected':True,
        'all_orbit_images_read_by_runtime_consumer':False,'complete_archive':index['complete_archive'],
        'complete_archive_manifest':index['complete_archive_manifest']}

ADOPTION_FIELDS={'schema','release_id','boot_id','parent_adoption_history','parent_history_host_validation',
    'parent_policy','actual_export','offline_candidate','delta_rule','parent_rule','full_rule','root_scope_decision',
    'live_provenance','offline_proof','post_live_proof_inputs','verification_originals','root_decision'}

def adoption_decision(value,live):
    return {'schema':'hepta.root.parent-dir.actual-policy-adoption-decision.v1',
        'decision':'ADOPT_INDEPENDENTLY_VERIFIED_ACTUAL_EXPORTED_POLICY','boot_id':BOOT,
        'actual_policy_sha256':live['runtime_policy']['sha256'],'actual_live_binding_sha256':live['binding_sha256'],
        'root_scope_decision_sha256':live['root_scope_decision_sha256'],
        'prior_boundary_sha256':live['prior_boundary_sha256'],'parent_adoption_sha256':PARENT_ADOPTION['sha256'],
        'post_live_proof_inputs_sha256':value['post_live_proof_inputs']['sha256'],'permission_atoms':[ATOM],
        'grant_scope':'all directories labeled system_data_file','path_only_authorization':False,
        'automatic_adoption':False,'automatic_rollback':False,'service_start_admitted':False,'component_qualified':False}

def validate_adoption_value(value,*,read_pinned,require_root_decision=True):
    need(type(value)is dict and set(value)==ADOPTION_FIELDS,'exact new actual adoption fields required')
    exact(value,{'schema':'hepta.parent-dir.policy-adoption.v1','release_id':'v150-parent-dir-getattr-r1',
        'boot_id':BOOT,'parent_policy':PARENT,'offline_candidate':OFFLINE})
    originals={};paths=set();used=set();total=0
    need(type(value['verification_originals'])is list and 1<=len(value['verification_originals'])<=1024,
         'bounded verification original pool')
    for row in value['verification_originals']:
        k=key(row);need(k not in originals and row['path'] not in paths,'duplicate verification original')
        originals[k]=row;paths.add(row['path']);total+=row['bytes']
    need(total<=32*1024*1024,'actual runtime verification-original raw-byte budget exceeded')
    def get(row):
        k=key(row);need(k in originals,'verification depends on an unlisted original');used.add(k)
        return bytes_match(read_pinned(originals[k]),row)
    parent_raw=get(value['parent_adoption_history']);bytes_match(parent_raw,PARENT_ADOPTION)
    parent=strict(parent_raw);need(parent['boot_id']==BOOT
        and {k:parent['actual_export'][k] for k in ('bytes','sha256')}==PARENT
        and parent['root_decision']['actual_policy_sha256']==PARENT['sha256'],'unchanged parent ancestry differs')
    history_raw=get(value['parent_history_host_validation']);bytes_match(history_raw,PARENT_HOST_VALIDATION)
    history=strict(history_raw)['unchanged_actual_policy_adoption']
    need(history['current_adoption_sha256']==PARENT_ADOPTION['sha256'] and history['runtime_policy']==PARENT
        and history['verification_original_count']==554 and history['verification_original_bytes']==31518321,
        'actual retained full parent history validation differs')
    delta=get(value['delta_rule']);parent_rule=get(value['parent_rule']);full_rule=get(value['full_rule'])
    need(delta==RULE,'only one exact directory-getattr rule is allowed');bytes_match(parent_rule,PARENT_RULE)
    # The reviewed full rule includes its existing trailing formatting. Its
    # exact hash, rather than a newly formatted concatenation, is authoritative.
    bytes_match(full_rule,FULL_RULE)
    need(full_rule==parent_rule+b'\n# Single directory metadata permission for the verified /data/local parent.\n'+RULE,
         'reviewed full rule is not the original parent plus the single literal delta')
    offline=strict(bytes_match(get(value['offline_proof']),OFFLINE_PROOF));validate_full_proof_value(offline)
    live_raw=get(value['live_provenance']);live=verify_live_capture(live_raw,read_pinned=get)
    live['provenance_sha256']=sha(live_raw);live['provenance_bytes']=len(live_raw)
    need(value['actual_export']==live['actual_export_retained']
        and descriptor(get(value['actual_export']))==live['runtime_policy']
        and value['root_scope_decision']['sha256']==live['root_scope_decision_sha256'],
        'new adoption does not identify the actual original export/scope')
    scope_raw=get(value['root_scope_decision']);need(sha(scope_raw)==live['root_scope_decision_sha256'],'scope original differs')
    post=verify_post_proof(get(value['post_live_proof_inputs']),read_pinned=get,live=live)
    decision=adoption_decision(value,live)
    if require_root_decision:need(value['root_decision']==decision,'explicit actual Root adoption decision required')
    else:need(value['root_decision'] is None,'preview cannot contain a prewritten adoption decision')
    need(set(originals)==used,'verification-original pool contains unused or unrelated files')
    return {'runtime_policy':live['runtime_policy'],'full_rule':value['full_rule'],
        'retirement_sha256':RETIREMENT,'prior_boundary_sha256':live['prior_boundary_sha256'],
        'root_scope_decision_sha256':live['root_scope_decision_sha256'],'parent_adoption_sha256':PARENT_ADOPTION['sha256'],
        'actual_live_binding_sha256':live['binding_sha256'],'root_decision':decision,'parent_policy':PARENT,
        'current_policy_adoption':{'schema':value['schema'],'boot_id':BOOT},
        'post_live_proof':post,'actual_v3_cause':live['actual_v3_cause'],
        'verification_original_count':len(used),'verification_original_bytes':total,
        'parent_full_history_originals_retained_separately':True,'parent_full_history_recursively_embedded':False,
        'service_start_admitted':False,'component_qualified':False,'phone_calls':0,'policy_writes':0}

def verify_adoption(adoption_raw,*,read_pinned):
    value=strict(adoption_raw);result=validate_adoption_value(value,read_pinned=read_pinned)
    result['current_adoption_sha256']=sha(adoption_raw)
    result['current_policy_adoption']={**result['current_policy_adoption'],**descriptor(adoption_raw)}
    return result
