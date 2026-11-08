#!/usr/bin/env python3
"""Pure, fixed ready-but-not-accepted diag02 sidebranch verification.

This module never opens files, imports a runtime, executes a command, or observes
a current process. Callers supply all three original byte strings. A reviewed
caller must separately preserve the phone originals' full metadata bookends.
Diag02 remains outside every native scope, chain and case count.
Closure and sideproof entry points reject ACTUAL_BINDING=None. This source
cannot create a closure or substitute a later observation for the old sender wait.
"""
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import stat

BASE='/var/lib/trillionnium/owner-open/phone-local-v150'
LABEL='root-r10-neg01-7c907661-diag02'
NONCE='8daaaad6a322963e87973613c1fac762'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
HOME=BASE+'/native-guard-r10-r1/'+LABEL
JOURNAL='/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+LABEL+'/executor'
FIXTURE='/proc/1/root/data/local/tmp/hepta-native-guard-'+NONCE
PUBLICATION_ROOT=BASE+'/native-guard-nonnative-boundaries-r10-r1/'+NONCE
OWNER='caa9a5091e758975ef1b94903f0cd06705f88ef8c9fe94cc8a17e773240a777f'
PACKAGE={'bytes': 21251, 'sha256': '8e5ba081f1780da2ec73a3c103e7a27f6a0ba4e6e15ceab502fa8221ed410863'}
COMBINATION={'bytes': 4695, 'sha256': '765e66acedee58e41de0ef45b6ea8061709e5b63a7aef43437876349289e86ec'}
LEASE={'bytes': 2504, 'sha256': '9c420ebd9b1e7b24847fab5e2851921c3857f80c9281514e806a8bbe8ac790e3'}
POLICY='f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'
ADOPTION='527374778e62717d837d546cfa56bd144c8415b52006a9be4a33935c8592d08a'
RETIREMENT='b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90'
PRIOR='621f82a3c071c755f4460f591ac1faa92ec6940b2a19c7a4d76948668abf669e'
CAPTURE_SOURCE='7bb8e477a1b3d034e327ecdffdd5a3d0f6ac2308b7abed3758cb81f205605b4e'
ROLES={'provider': [12992, 12992, 12992, 24670040], 'sidecar': [12988, 12988, 12988, 24670008], 'supervisor': [12457, 12457, 12457, 24667528]}
# Only a later reviewed one-literal derivation may bind actual capture originals.
ACTUAL_BINDING={'schema': 'hepta.diag02.non-native-actual-binding.v1', 'state': 'ACTUAL_CAPTURE_ORIGINALS_BOUND', 'scope_profile': 'diag02_ready_observed_no_send', 'capture': {'bytes': 165154, 'sha256': 'baa17623e93c0a9893da87bbde654d7a96a161857aed065441d14a631b3c45d6'}, 'archive': {'bytes': 2854019, 'sha256': '5d0f5dd0e3da4fbe7bc8130785bfeb7addd928eb1f563947772db5bd19630ed1'}, 'after_inventory': {'bytes': 1031582, 'sha256': '10fe1e2d389cf8aa4928593abb207406ae63e84519339da25c722b03bee9c67d'}, 'capture_driver': '2f3bd85ad40ad9d99f5994fbee38af238b4c7542291e3075daf6bb9f0ed78fb0'}
CAPTURE=None if ACTUAL_BINDING is None else ACTUAL_BINDING.get('capture')
ARCHIVE=None if ACTUAL_BINDING is None else ACTUAL_BINDING.get('archive')
AFTER=None if ACTUAL_BINDING is None else ACTUAL_BINDING.get('after_inventory')
CAPTURE_DRIVER=None if ACTUAL_BINDING is None else ACTUAL_BINDING.get('capture_driver')
SCOPE_PROFILE='diag02_ready_observed_no_send'
UNKNOWN_EFFECTS_SCOPE='this fixed no-Send sidebranch after all independently verified closure gates; not entire device'
NATIVE_PREDECESSOR={'bytes': 9998, 'metadata': [65086, 149888, 33152, 0, 0, 1, 9998, 1793894221355909793, 1793894221355909793], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/6077fc8f045572edc4acfb13ed7e09a8.json', 'sha256': '621f82a3c071c755f4460f591ac1faa92ec6940b2a19c7a4d76948668abf669e'}
EXPECTED_ROOTS=['/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/evidence', '/var/lib/trillionnium/owner-open/phone-local-v150/client-receipts', '/var/lib/trillionnium/owner-open/phone-local-v150/executor-r6', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/health-contracts/bindings', '/var/lib/trillionnium/owner-open/phone-local-v150/provider-state/task-contracts/bindings', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-03', '/proc/1/root/data/local/tmp/hepta-native-guard-88d68d88130d3c74e6c950a6346357c1', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261104-04', '/proc/1/root/data/local/tmp/hepta-native-guard-c705647dd4ebb5d421be1041a9c41ca6', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-05', '/proc/1/root/data/local/tmp/hepta-native-guard-e4c3ccb0b2d706be3b7bf105ae772405', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-06', '/proc/1/root/data/local/tmp/hepta-native-guard-154588e3a15591a21ec18950d18e3ecd', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-07', '/proc/1/root/data/local/tmp/hepta-native-guard-16805e43f9787c44c262d5b6c6d8ed95', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-20261105-08', '/proc/1/root/data/local/tmp/hepta-native-guard-2b0b103ee6de7a422064b9571266bf5d', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-01', '/proc/1/root/data/local/tmp/hepta-native-guard-902e851c3ca1f90deab3d880ab993774', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag01', '/proc/1/root/data/local/tmp/hepta-native-guard-6077fc8f045572edc4acfb13ed7e09a8', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02/executor', '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-7c907661-diag02', '/proc/1/root/data/local/tmp/hepta-native-guard-8daaaad6a322963e87973613c1fac762']
PRESERVED_NON_NATIVE_SIDEBRANCHES=[{'closure': {'bytes': 164095, 'metadata': [65086, 153455, 33152, 0, 0, 1, 164095, 1793843548839929123, 1793843548839929123], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/e4c3ccb0b2d706be3b7bf105ae772405/CLOSURE.original.json', 'sha256': 'd464bac786ef208d8fa0390587bd3bb7616a13985fb064716a209aa2394458f6'}, 'inventory': {'bytes': 664638, 'metadata': [65086, 143754, 33152, 0, 0, 1, 664638, 1793843548843929123, 1793843548843929123], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/e4c3ccb0b2d706be3b7bf105ae772405/AFTER-INVENTORY.original.json', 'sha256': '87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}, 'nonce': 'e4c3ccb0b2d706be3b7bf105ae772405', 'proof': {'bytes': 4650, 'metadata': [65086, 147519, 33152, 0, 0, 1, 4650, 1793843550651929122, 1793843550651929122], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-nonnative-boundaries-r10-r1/e4c3ccb0b2d706be3b7bf105ae772405/SIDE-PROOF.original.json', 'sha256': '1bf6bca5ae5aaa5d5803b708070680e92d3f072f9541f38b09783787cfae7b9c'}, 'schema': 'hepta.native-guard.reviewed-non-native-attempt.v1', 'sources': {'capture': '3e72353d8bd0dec122f10f5f3f5a6fe50e6dfb5251a41e51fc89974d4d4867bb', 'capture_driver': '17fe5e803ff55f6f752ebadfab11163c619e5de42a4ee09d5c1e549df7635d80', 'closer': '508fb5d474ff4fcc2e32586a186c5cb3d9b511ed98dc284c202a216ceb59e3f6', 'publisher': '2185e2fbdad9b5a2c8f2f54891fcd29ae1d90651ac68ded8c72c4914d490bb97', 'sender_verifier': '3117035c31ab46e865a93a4ff797388c18d4e9e6c669bc5d4b48ae9711f1842e', 'verifier': 'a4ec44ac1f09fc7919dce17acf46e6db83ca468f58f53ad7622b520b557d04e4'}}]
INVENTORY_READER_PROVENANCE={'current': {'bytes': 3041, 'sha256': '4afd8432a8caa1d521f982255599a8e861ffc2b812c75e7372227e17bf3d4ece'}, 'only_delta': 'fixture root limit8 to fixed9; original runtime unmodified', 'original': {'bytes': 3041, 'sha256': '72106d464cf062e8d59d1964e745792c592e6b311a1775d219f760a80a08a92d'}}
SOURCE_KEYS={'verifier','closer','sender_verifier','publisher','capture','capture_driver'}
CLOSURE_SOURCE_KEYS=SOURCE_KEYS-{'publisher'}
FACTS={'native_send_attempts': 0, 'native_case_count': 0, 'native_scope_assigned': False, 'native_case_created': False, 'native_terminal_invented': False, 'component_qualified': False, 'business_qualified': False, 'unknown_effects': 0, 'root_fixture_attempts': 0, 'actual_operator_input_and_restore_ui_occurred': True, 'original_draft_restored': True, 'original_selected_native_predecessor_preserved': True, 'original_sender_ssh_returncode': 2, 'host_parent_wait_receipt_available': False, 'host_child_wait_returned_claimed': False, 'host_sender_process_absent_twice': True, 'component_children_waited': True, 'component_supervisor_absent_twice': True, 'component_and_historical_groups_absent_twice': True, 'port_18080_listener_absent': True, 'r6_abstract_endpoint_absent': True, 'fixture_absent': True, 'claims_empty': True, 'pre_native_paths_absent': True, 'native_nonce_absent_in_complete_bounded_scan': True, 'native_hash_chain_verified': False, 'host_native_store_full_bytes_available': False, 'original_complete_inventory_unchanged_during_capture': True, 'original_native_predecessor_inventory_preserved': True, 'automatic_retry': False, 'automatic_restart': False, 'automatic_policy_change': False, 'scope_profile': 'diag02_ready_observed_no_send', 'unknown_effects_scope': 'this fixed no-Send sidebranch after all independently verified closure gates; not entire device', 'global_unknown_effect_count': None, 'historical_native_count': 7, 'previous_non_native_count': 1, 'cumulative_component_role_count': 27, 'current_frozen_role_cap': 30, 'role_cap_changed': False, 'current_ready_original_verified': True, 'accepted_connection_absent': True, 'original_host_sender_pid': 50521, 'original_supervisor_wait_claimed': False, 'previous05_originals_preserved': True, 'current_eight_external_artifacts_unchanged': True, 'explicit_fixed_nine_fixture_inventory_reader_verified': True}
CHECKS={'actual_original_root_steps','actual_package_and_staged_inputs','actual_ready_without_acceptance_originals','actual_role_generations_and_joins','all_host_originals_rechecked','bounded_native_nonce_absence_original','capture_provenance','complete_archive_originals','complete_baseline_delta','complete_prior_native_inventory_preservation','current_eight_external_artifact_bookends','explicit_nine_fixture_inventory_reader','fixed_seven_native_and_previous05_preserved','independent_role_and_endpoint_absence','original_sender_no_send','original_sender_restore_and_selected_predecessor','pre_native_and_fixture_absence'}
CLOSURE_FIELDS={'after_inventory','archive','boot_id','capture','combination','component_role_identities','facts','input_originals','label','lease','native_predecessor','nonce','observations','originals','owner_request_sha256','package','policy_adoption_sha256','preserved_non_native_sidebranches','private_roots','retirement','roots','runtime_policy_sha256','schema','scope_profile','sources','state','verified_checks'}
PROOF_FIELDS={'boot_id','business_qualified','closure','combination','component_qualified','component_role_identities','inventory','label','native_case_count','native_predecessor','nonce','package','policy_adoption_sha256','preserved_non_native_sidebranches','private_roots','publication_checks','retirement_sha256','roots','runtime_policy_sha256','schema','scope_profile','sources','state'}
PUBLICATION_CHECKS={'complete_current_inventory_equal': True, 'all_three_role_groups_absent_twice': True, 'native_predecessor_originals_rechecked': True, 'old_retirement_originals_rechecked': True, 'port_18080_listener_absent': True, 'r6_abstract_endpoint_absent': True, 'phone_ui_actions': 0, 'native_submissions': 0, 'signals': 0, 'service_launches': 0, 'policy_writes': 0, 'automatic_retry': False, 'native_scope_created': False, 'proof_directory_excluded_from_inventory': True, 'previous_non_native05_originals_rechecked': True, 'seven_native_ancestors_preserved': True, 'cumulative_component_role_count': 27, 'current_frozen_role_cap': 30, 'role_cap_changed': False, 'global_unknown_effect_count': None}


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(raw):
    need(type(raw) is bytes,'original raw bytes required')
    return hashlib.sha256(raw).hexdigest()


def pin(raw):return {'bytes':len(raw),'sha256':sha(raw)}


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,
                       allow_nan=False)+'\n').encode()


def strict(raw,maximum=16*1024*1024):
    need(type(raw) is bytes and len(raw)<=maximum,'bounded original JSON bytes required')
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value,'duplicate original JSON key');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _x:(_ for _ in ()).throw(ValueError('nonfinite original JSON')))


def same_types(actual,expected):
    if isinstance(expected,dict):
        return type(actual) is dict and set(actual)==set(expected) and all(
            same_types(actual[k],v) for k,v in expected.items())
    if isinstance(expected,list):
        return type(actual) is list and len(actual)==len(expected) and all(
            same_types(a,b) for a,b in zip(actual,expected))
    return type(actual) is type(expected) and actual==expected


def hash_value(value):
    need(type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value),'exact SHA256 required')
    return value


def absolute(value):
    need(type(value) is str and '\x00' not in value,'absolute original path required')
    p=PurePosixPath(value)
    need(p.is_absolute() and '..' not in p.parts and str(p)==value,'canonical lexical original path required')
    return p


def metadata(value):
    need(type(value) is list and len(value)==9 and all(type(x) is int for x in value),
         'all nine exact metadata integers required')
    need(value[0]>=0 and value[1]>0 and value[2]>=0 and all(x>=0 for x in value[3:7]),
         'original metadata values differ')
    return value


def descriptor(row,*,phone=False,maximum=16*1024*1024):
    need(type(row) is dict and set(row)=={'path','bytes','sha256','metadata'},
         'exact original descriptor with full nine metadata fields required')
    absolute(row['path']);hash_value(row['sha256']);m=metadata(row['metadata'])
    need(type(row['bytes']) is int and 0<=row['bytes']<=maximum and row['bytes']==m[6]
         and stat.S_ISREG(m[2]) and m[5]==1,'original file type/length/link differs')
    if phone:need(m[3]==m[4]==0 and stat.S_IMODE(m[2])==0o600,'phone original ownership/mode differs')
    return row


def descriptor3(row,maximum=64*1024*1024):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact host byte descriptor required')
    absolute(row['path']);hash_value(row['sha256'])
    need(type(row['bytes']) is int and 0<=row['bytes']<=maximum,'host original byte bound differs')
    return row


def verify_raw(raw,row,*,phone=True):
    descriptor(row,phone=phone)
    need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'reviewed original byte pin differs')
    return raw


def inventory_value(value):
    need(type(value) is dict and set(value)=={'schema','roots','entries','file_bytes_hashed',
        'elapsed_seconds','inventory_is_closure_or_retirement'},'complete inventory fields differ')
    need(value['schema']=='hepta.native-guard.complete-inventory.v1'
        and value['inventory_is_closure_or_retirement'] is False
        and type(value['elapsed_seconds']) in (int,float)
        and math.isfinite(value['elapsed_seconds']) and value['elapsed_seconds']>=0,
        'complete inventory identity/time differs')
    roots=value['roots'];entries=value['entries']
    need(type(roots) is list and 0<len(roots)<=64 and len(set(roots))==len(roots),
         'bounded unique complete roots required')
    paths=[absolute(x) for x in roots]
    need(all(a==b or not (a in b.parents or b in a.parents) for a in paths for b in paths),
         'inventory roots unexpectedly overlap')
    need(type(entries) is dict and len(entries)<=30000 and set(roots)<=set(entries),
         'complete root entries missing or excessive')
    total=0
    for name,row in entries.items():
        p=absolute(name)
        need(any(p==r or r in p.parents for r in paths),'entry outside complete inventory roots')
        need(type(row) is dict,'inventory row must be object')
        kind=row.get('kind')
        if kind=='absent':
            need(set(row)=={'kind','absence'} and row['absence']=='ENOENT' and name in roots
                 and re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}',name),
                 'only exact fixture root ENOENT may be absent')
        elif kind=='directory':
            need(set(row)=={'kind','metadata','names'} and stat.S_ISDIR(metadata(row['metadata'])[2]),
                 'directory inventory row differs')
            names=row['names']
            need(type(names) is list and len(names)<=20000 and names==sorted(set(names))
                and all(type(n) is str and n not in ('','.','..') and '/' not in n and '\x00' not in n
                        for n in names),'complete directory names differ')
            need(all(str(p/n) in entries for n in names),'directory lists unrecorded child')
        elif kind=='file':
            need(set(row)=={'kind','metadata','bytes','sha256'},'file inventory row differs')
            m=metadata(row['metadata']);hash_value(row['sha256'])
            need(stat.S_ISREG(m[2]) and m[5]==1 and type(row['bytes']) is int
                and 0<=row['bytes']<=64*1024*1024 and m[6]==row['bytes'],'file inventory bound/type differs')
            total+=row['bytes']
        else:need(False,'unknown inventory kind')
        if name not in roots:
            parent=entries.get(str(p.parent))
            need(parent and parent['kind']=='directory' and p.name in parent['names'],
                 'unlisted or orphan inventory member')
    need(type(value['file_bytes_hashed']) is int and total==value['file_bytes_hashed']
        and total<=512*1024*1024,'complete file-byte accounting differs')
    return {k:v for k,v in value.items() if k!='elapsed_seconds'}


def actual_binding():
    """Return the reviewed actual originals, never a source-only placeholder."""
    value=ACTUAL_BINDING
    need(type(value) is dict and set(value)=={'schema','state','scope_profile','capture',
        'archive','after_inventory','capture_driver'},'actual capture binding is not reviewed; closure is unavailable')
    need(value['schema']=='hepta.diag02.non-native-actual-binding.v1'
        and value['state']=='ACTUAL_CAPTURE_ORIGINALS_BOUND'
        and value['scope_profile']==SCOPE_PROFILE,'only the fixed diag02 actual capture may bind')
    for name,maximum in [('capture',16*1024*1024),('archive',64*1024*1024),
                         ('after_inventory',16*1024*1024)]:
        row=value[name]
        need(type(row) is dict and set(row)=={'bytes','sha256'}
            and type(row['bytes']) is int and 0<row['bytes']<=maximum,
            'strict positive bounded actual byte pin required')
        hash_value(row['sha256'])
    hash_value(value['capture_driver'])
    need(same_types(CAPTURE,value['capture']) and same_types(ARCHIVE,value['archive'])
        and same_types(AFTER,value['after_inventory']) and CAPTURE_DRIVER==value['capture_driver'],
        'derived actual original aliases differ')
    return value


def _sources(value,keys):
    actual=actual_binding()
    need(type(value) is dict and set(value)==keys,'exact source identity set required')
    for source in value.values():hash_value(source)
    need(value['capture']==CAPTURE_SOURCE and value['capture_driver']==actual['capture_driver'],
         'actual frozen capture sources changed')
    need(globals().get('__reviewed_source_sha256__')==value['verifier'],
         'caller must inject the independently pinned exact verifier source hash')


def _attempt(value):
    need(value['label']==LABEL and value['nonce']==NONCE and value['boot_id']==BOOT
        and value['package']==PACKAGE and value['combination']==COMBINATION
        and value['runtime_policy_sha256']==POLICY and value['policy_adoption_sha256']==ADOPTION,
        'only the actual diag02 fixed package/policy tuple is supported')
    need(value['scope_profile']==SCOPE_PROFILE,'fixed ready-but-not-accepted profile required')
    need(same_types(value['component_role_identities'],ROLES),'actual three role generations differ')
    prior=descriptor(value['native_predecessor'],phone=True)
    need(same_types(prior,NATIVE_PREDECESSOR),'native predecessor must remain exact actual6077 full9')
    need(value['private_roots']==[HOME,JOURNAL,FIXTURE],'fixed private roots differ')
    roots=value['roots']
    need(same_types(roots,EXPECTED_ROOTS),'all exact33 roots and nine fixture roots must be retained')
    preserved=value['preserved_non_native_sidebranches']
    need(same_types(preserved,PRESERVED_NON_NATIVE_SIDEBRANCHES),
        'the original independent05 sidebranch record cannot be dropped or replaced')
    for record in preserved:
        for key in ('proof','closure','inventory'):descriptor(record[key],phone=True)
    pub=PurePosixPath(PUBLICATION_ROOT)
    need(all(pub!=absolute(p) and pub not in absolute(p).parents and absolute(p) not in pub.parents
             for p in roots),'proof publication must not inventory itself')


def validate_closed_attempt(closure_raw,inventory_raw,*,expected_sources):
    """Check closure facts and the actual immutable after-inventory, without I/O."""
    actual_binding()
    closed=strict(closure_raw);need(type(closed) is dict and set(closed)==CLOSURE_FIELDS,
                                  'exact non-native closure fields required')
    need(closed['schema']=='hepta.native-guard.non-native-attempt-closure.v2'
        and closed['state']=='ORIGINAL_PRE_NATIVE_ATTEMPT_FAILED_CLOSED',
        'this is not a completed non-native closure')
    _attempt(closed);_sources(closed['sources'],CLOSURE_SOURCE_KEYS)
    need(closed['sources']==expected_sources,'explicit reviewed closure source identities differ')
    need(closed['owner_request_sha256']==OWNER and closed['lease']==LEASE
        and closed['capture']==CAPTURE and closed['archive']==ARCHIVE
        and closed['after_inventory']==AFTER and pin(inventory_raw)==AFTER,
        'actual capture/lease/owner/inventory originals differ')
    need(same_types(closed['facts'],FACTS),'non-native facts/qualification must remain exact')
    need(type(closed['verified_checks']) is dict and set(closed['verified_checks'])==CHECKS
        and all(v is True for v in closed['verified_checks'].values()),'independent closure gate missing')
    retirement=closed['retirement']
    need(type(retirement) is dict and set(retirement)=={'proof','preflight','probe','bound_inputs','disabled_flag'},
         'original five retirement files required')
    for item in retirement.values():descriptor(item,phone=True)
    need(retirement['proof']['sha256']==RETIREMENT,'original retirement differs')
    inv=strict(inventory_raw);canonical=inventory_value(inv)
    need(inv['roots']==closed['roots'],'complete after-inventory roots differ')
    need(inv['entries'][FIXTURE]=={'kind':'absent','absence':'ENOENT'},'actual fixture absence missing')
    for name in [HOME,JOURNAL]:
        need(inv['entries'][name]['kind']=='directory','actual private directory original missing')
    need(type(closed['originals']) is dict and len(closed['originals'])>=6,
         'host input provenance missing')
    for row in closed['originals'].values():descriptor3(row)
    need(type(closed['input_originals']) is list and 0<len(closed['input_originals'])<=1024,
         'stable original read inventory missing or excessive')
    seen=set()
    for row in closed['input_originals']:
        descriptor(row,maximum=64*1024*1024)
        need(row['path'] not in seen,'duplicate host original path');seen.add(row['path'])
    need(type(closed['observations']) is dict,'independent detailed observations required')
    return closed,inv,canonical


def verify_sidebranch(proof_raw,closure_raw,inventory_raw,*,expected_record):
    """Return a binding for exactly the reviewed published diag02 sidebranch, separately preserving05."""
    actual_binding()
    e=expected_record
    need(type(e) is dict and set(e)=={'schema','nonce','proof','closure','inventory','sources'}
        and e['schema']=='hepta.native-guard.reviewed-non-native-attempt.v2'
        and e['nonce']==NONCE,'explicit fixed reviewed sidebranch record required')
    _sources(e['sources'],SOURCE_KEYS)
    names={'proof':'SIDE-PROOF.original.json','closure':'CLOSURE.original.json',
           'inventory':'AFTER-INVENTORY.original.json'}
    for key,raw in [('proof',proof_raw),('closure',closure_raw),('inventory',inventory_raw)]:
        need(e[key]['path']==PUBLICATION_ROOT+'/'+names[key],'published original namespace differs')
        verify_raw(raw,e[key])
    closed,inv,canonical=validate_closed_attempt(closure_raw,inventory_raw,
        expected_sources={k:v for k,v in e['sources'].items() if k!='publisher'})
    value=strict(proof_raw)
    need(type(value) is dict and set(value)==PROOF_FIELDS
        and value['schema']=='hepta.native-guard.non-native-attempt-boundary.v2'
        and value['state']=='CLOSED_PRE_NATIVE_ATTEMPT_AND_CUMULATIVE_ORIGINALS_PRESERVED',
        'exact published non-native sideproof required')
    _attempt(value)
    need(value['sources']==e['sources'] and value['closure']==e['closure']
        and value['inventory']==e['inventory'],'actual published source/original bindings differ')
    need(value['scope_profile']==closed['scope_profile']
        and same_types(value['preserved_non_native_sidebranches'],closed['preserved_non_native_sidebranches'])
        and value['roots']==closed['roots'] and value['private_roots']==closed['private_roots']
        and value['native_predecessor']==closed['native_predecessor']
        and value['retirement_sha256']==RETIREMENT
        and type(value['native_case_count']) is int and value['native_case_count']==0
        and value['component_qualified'] is False and value['business_qualified'] is False
        and same_types(value['publication_checks'],PUBLICATION_CHECKS),
        'publication facts/preservation cannot qualify a native case')
    binding={'schema':'hepta.native-guard.non-native-sidebranch-binding.v2',
        'scope_profile':SCOPE_PROFILE,'preserved_non_native_sidebranches':PRESERVED_NON_NATIVE_SIDEBRANCHES,
        'nonce':NONCE,'proof':e['proof'],'closure':e['closure'],'inventory':e['inventory'],
        'component_role_identities':ROLES,'preserved_roots':closed['roots'],
        'private_roots':closed['private_roots'],'native_predecessor':closed['native_predecessor'],
        'native_case_count':0,'component_qualified':False}
    return {'schema':'hepta.native-guard.non-native-sidebranch-verification.v2',
        'scope_profile':SCOPE_PROFILE,'preserved_non_native_sidebranches':PRESERVED_NON_NATIVE_SIDEBRANCHES,
        'label':LABEL,'nonce':NONCE,'boot_id':BOOT,'proof':e['proof'],'closure':e['closure'],
        'inventory':e['inventory'],'preserved_roots':closed['roots'],'private_roots':closed['private_roots'],
        'inventory_value':canonical,'component_role_identities':ROLES,
        'native_predecessor':closed['native_predecessor'],'package_sha256':PACKAGE['sha256'],
        'combination_sha256':COMBINATION['sha256'],'policy_sha256':POLICY,
        'policy_adoption_sha256':ADOPTION,'originals':[e['proof'],e['closure'],e['inventory']],
        'native_case_count':0,'component_qualified':False,'binding':binding}


def validate_private_preservation(summary,current_inventory):
    """Future native heads may add originals elsewhere, never mutate attempt05."""
    current=inventory_value(current_inventory)
    need(summary['nonce']==NONCE and summary['private_roots']==[HOME,JOURNAL,FIXTURE],
         'fixed reviewed sidebranch summary required')
    old=summary['inventory_value']
    need(set(summary['preserved_roots'])<=set(current['roots']),'non-native cumulative roots were dropped')
    for root in summary['private_roots']:
        before={k:v for k,v in old['entries'].items() if k==root or k.startswith(root+'/')}
        after={k:v for k,v in current['entries'].items() if k==root or k.startswith(root+'/')}
        need(before==after,'closed non-native private originals changed or gained entries')
    return True
