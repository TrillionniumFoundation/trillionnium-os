#!/usr/bin/env python3
"""Pure, fixed attempt05 sidebranch verification.

This module never opens files, imports a runtime, executes a command, or observes
a current process. Callers supply all three original byte strings. A reviewed
caller must separately preserve the phone originals' full metadata bookends.
Attempt05 remains outside every native scope, chain and case count.
"""
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import stat

BASE='/var/lib/trillionnium/owner-open/phone-local-v150'
LABEL='root-r10-neg01-20261105-05'
NONCE='e4c3ccb0b2d706be3b7bf105ae772405'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
HOME=BASE+'/native-guard-r10-r1/'+LABEL
JOURNAL='/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+LABEL+'/executor'
FIXTURE='/proc/1/root/data/local/tmp/hepta-native-guard-'+NONCE
PUBLICATION_ROOT=BASE+'/native-guard-nonnative-boundaries-r10-r1/'+NONCE
OWNER='592b45a023fe54fe085d2ee91aa7d11b4c6d52a66d19e353001a38acf1c10079'
PACKAGE={'bytes':6253,'sha256':'9c2e08ce171d8212b5f21abbc97ded5ba2fb578e221a8579db8aef3568ff969e'}
COMBINATION={'bytes':4702,'sha256':'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'}
LEASE={'bytes':2496,'sha256':'4420765e2968387b861e938726349e17e18d798fd2e11c5deaa46ee57f2f0541'}
POLICY='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
ADOPTION='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
RETIREMENT='b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90'
PRIOR='3216ab18adcafa0dda95e8a93ad35a2070e7aec286d7a518794918068ce31d12'
CAPTURE={'bytes':131936,'sha256':'b44d88692fd766409565202dc09aa03b655248f03d537c897f2755b002ee3aee'}
ARCHIVE={'bytes':1481782,'sha256':'bec66c33c0d777350c5943fc6f1d2d2bc8ac6afd4b1930cb51a0439fbbf4a4bd'}
AFTER={'bytes':664638,'sha256':'87103089914885fff5632781f18fbe36895ed181f01997eac6c3b49449b5579e'}
CAPTURE_SOURCE='3e72353d8bd0dec122f10f5f3f5a6fe50e6dfb5251a41e51fc89974d4d4867bb'
CAPTURE_DRIVER='17fe5e803ff55f6f752ebadfab11163c619e5de42a4ee09d5c1e549df7635d80'
ROLES={'supervisor':[23779,23779,23779,18132959],
       'provider':[23913,23913,23913,18133299],
       'sidecar':[23911,23911,23911,18133265]}
SOURCE_KEYS={'verifier','closer','sender_verifier','publisher','capture','capture_driver'}
CLOSURE_SOURCE_KEYS=SOURCE_KEYS-{'publisher'}
FACTS={
    'native_send_attempts':0,'native_case_count':0,'native_scope_assigned':False,
    'native_case_created':False,'native_terminal_invented':False,'component_qualified':False,
    'business_qualified':False,'unknown_effects':0,'root_fixture_attempts':0,
    'actual_operator_input_and_restore_ui_occurred':True,'original_draft_restored':True,
    'original_selected_native_predecessor_preserved':True,
    'original_sender_ssh_returncode':2,'host_parent_wait_receipt_available':False,
    'host_child_wait_returned_claimed':False,'host_sender_process_absent_twice':True,
    'component_children_waited':True,'component_supervisor_absent_twice':True,
    'component_and_historical_groups_absent_twice':True,
    'port_18080_listener_absent':True,'r6_abstract_endpoint_absent':True,
    'fixture_absent':True,'claims_empty':True,'pre_native_paths_absent':True,
    'native_nonce_absent_in_complete_bounded_scan':True,
    'native_hash_chain_verified':False,'host_native_store_full_bytes_available':False,
    'original_complete_inventory_unchanged_during_capture':True,
    'original_native_predecessor_inventory_preserved':True,
    'automatic_retry':False,'automatic_restart':False,'automatic_policy_change':False}
CHECKS={'capture_provenance','complete_archive_originals','actual_package_and_staged_inputs',
        'actual_original_root_steps','actual_role_generations_and_joins',
        'independent_role_and_endpoint_absence','pre_native_and_fixture_absence',
        'bounded_native_nonce_absence_original','complete_baseline_delta',
        'complete_prior_native_inventory_preservation','original_sender_no_send',
        'original_sender_restore_and_selected_predecessor','all_host_originals_rechecked'}
CLOSURE_FIELDS={'schema','state','label','nonce','boot_id','owner_request_sha256','package','combination',
 'lease','runtime_policy_sha256','policy_adoption_sha256','retirement','native_predecessor',
 'roots','private_roots','component_role_identities','after_inventory','sources','facts',
 'verified_checks','capture','archive','originals','observations','input_originals'}
PROOF_FIELDS={'schema','state','label','nonce','boot_id','package','combination','runtime_policy_sha256',
 'policy_adoption_sha256','retirement_sha256','native_predecessor','closure','inventory',
 'roots','private_roots','component_role_identities','sources','native_case_count',
 'component_qualified','business_qualified','publication_checks'}
PUBLICATION_CHECKS={'complete_current_inventory_equal':True,'all_three_role_groups_absent_twice':True,
 'native_predecessor_originals_rechecked':True,'old_retirement_originals_rechecked':True,
 'port_18080_listener_absent':True,'r6_abstract_endpoint_absent':True,
 'phone_ui_actions':0,'native_submissions':0,'signals':0,'service_launches':0,
 'policy_writes':0,'automatic_retry':False,'native_scope_created':False,
 'proof_directory_excluded_from_inventory':True}


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


def _sources(value,keys):
    need(type(value) is dict and set(value)==keys,'exact source identity set required')
    for source in value.values():hash_value(source)
    need(value['capture']==CAPTURE_SOURCE and value['capture_driver']==CAPTURE_DRIVER,
         'actual frozen capture sources changed')
    need(globals().get('__reviewed_source_sha256__')==value['verifier'],
         'caller must inject the independently pinned exact verifier source hash')


def _attempt(value):
    need(value['label']==LABEL and value['nonce']==NONCE and value['boot_id']==BOOT
        and value['package']==PACKAGE and value['combination']==COMBINATION
        and value['runtime_policy_sha256']==POLICY and value['policy_adoption_sha256']==ADOPTION,
        'only the actual attempt05 fixed package/policy tuple is supported')
    need(same_types(value['component_role_identities'],ROLES),'actual three role generations differ')
    prior=descriptor(value['native_predecessor'],phone=True)
    need(prior['path']==BASE+'/native-guard-boundaries-r10-r1/c705647dd4ebb5d421be1041a9c41ca6.json'
        and prior['bytes']==4748 and prior['sha256']==PRIOR,'native predecessor must remain actual04')
    need(value['private_roots']==[HOME,JOURNAL,FIXTURE],'fixed private roots differ')
    roots=value['roots']
    need(type(roots) is list and all(p in roots for p in value['private_roots']),
         'complete inventory must retain all attempt05 roots')
    pub=PurePosixPath(PUBLICATION_ROOT)
    need(all(pub!=absolute(p) and pub not in absolute(p).parents and absolute(p) not in pub.parents
             for p in roots),'proof publication must not inventory itself')


def validate_closed_attempt(closure_raw,inventory_raw,*,expected_sources):
    """Check closure facts and the actual immutable after-inventory, without I/O."""
    closed=strict(closure_raw);need(type(closed) is dict and set(closed)==CLOSURE_FIELDS,
                                  'exact non-native closure fields required')
    need(closed['schema']=='hepta.native-guard.non-native-attempt-closure.v1'
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
    """Return a binding for exactly the reviewed published attempt05 sidebranch."""
    e=expected_record
    need(type(e) is dict and set(e)=={'schema','nonce','proof','closure','inventory','sources'}
        and e['schema']=='hepta.native-guard.reviewed-non-native-attempt.v1'
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
        and value['schema']=='hepta.native-guard.non-native-attempt-boundary.v1'
        and value['state']=='CLOSED_PRE_NATIVE_ATTEMPT_AND_CUMULATIVE_ORIGINALS_PRESERVED',
        'exact published non-native sideproof required')
    _attempt(value)
    need(value['sources']==e['sources'] and value['closure']==e['closure']
        and value['inventory']==e['inventory'],'actual published source/original bindings differ')
    need(value['roots']==closed['roots'] and value['private_roots']==closed['private_roots']
        and value['native_predecessor']==closed['native_predecessor']
        and value['retirement_sha256']==RETIREMENT
        and type(value['native_case_count']) is int and value['native_case_count']==0
        and value['component_qualified'] is False and value['business_qualified'] is False
        and same_types(value['publication_checks'],PUBLICATION_CHECKS),
        'publication facts/preservation cannot qualify a native case')
    binding={'schema':'hepta.native-guard.non-native-sidebranch-binding.v1',
        'nonce':NONCE,'proof':e['proof'],'closure':e['closure'],'inventory':e['inventory'],
        'component_role_identities':ROLES,'preserved_roots':closed['roots'],
        'private_roots':closed['private_roots'],'native_predecessor':closed['native_predecessor'],
        'native_case_count':0,'component_qualified':False}
    return {'schema':'hepta.native-guard.non-native-sidebranch-verification.v1',
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
