#!/usr/bin/env python3
"""Pure reconstruction of the actual final02 retained-stage inventory.

No file, device, process, transport, lock or policy operation is implemented.
The caller supplies a complete exact old39 original and a compact projection
taken from the complete actual41 original. This function does not create an
observation. Its output must byte-match that actual original, including elapsed.
"""
import hashlib
import json
import math
import re
import stat
from pathlib import PurePosixPath

PRIOR={'bytes':1182289,'sha256':'bd880b6dbfe1a870eab9d0dc6e3916e8bc539d115975c5b983c65742fbab6242'}
HEAD={'bytes':21325,'sha256':'fd7766538b0ff88bea73ce66e0de4728caf3771f88c8441bb4d2844fb13b6c66'}
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
LABEL='root-r10-neg01-a1055-final02'
NONCE='d11e31c9ac94920d47998ca88a97e98f'
HOME='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/'+LABEL
ANDROID_HOME='/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+LABEL
EXECUTOR=ANDROID_HOME+'/executor'
FIXTURE='/proc/1/root/data/local/tmp/hepta-native-guard-'+NONCE
SCHEMA='hepta.expired-unstarted-stage.exact-inventory-extension.v1'
FIELDS={'schema','boot_id','label','nonce','native_boundary','prior_inventory','actual_inventory',
        'roots','entries','elapsed_seconds'}

def need(ok, reason):
    if not ok:
        raise ValueError(reason)

def descriptor(raw):
    need(type(raw) is bytes, 'raw bytes required')
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def strict(raw):
    need(type(raw) is bytes and len(raw)<=4*1024*1024,'bounded exact JSON bytes')
    def pairs(items):
        out={}
        for key,value in items:
            need(key not in out,'duplicate JSON key')
            out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,
                      parse_constant=lambda _:need(False,'nonfinite JSON'))

def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),
                       ensure_ascii=False,allow_nan=False)+'\n').encode()

def bytepin(value):
    need(type(value) is dict and set(value)=={'bytes','sha256'}
         and type(value['bytes']) is int and 0<value['bytes']<=4*1024*1024
         and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),
         'bounded exact byte descriptor')
    return value

def under(path,root):
    p,r=PurePosixPath(path),PurePosixPath(root)
    return p==r or r in p.parents

def private_directory(row):
    need(type(row) is dict and set(row)=={'kind','metadata','names'}
         and row['kind']=='directory' and type(row['metadata']) is list
         and len(row['metadata'])==9 and all(type(v) is int for v in row['metadata']),
         'exact directory row')
    m=row['metadata']
    need(stat.S_ISDIR(m[2]) and stat.S_IMODE(m[2])==0o700 and m[3:5]==[0,0]
         and type(row['names']) is list and row['names']==sorted(set(row['names'])),
         'retained stage private directory')
    return row

def reconstruct(prior_raw, extension_raw, *, validate_inventory):
    """Return exact actual41 bytes/value after complete pure topology validation."""
    need(descriptor(prior_raw)==PRIOR,'exact closed old39 raw original required')
    old=strict(prior_raw);validate_inventory(old)
    ext=strict(extension_raw)
    need(type(ext) is dict and set(ext)==FIELDS and ext['schema']==SCHEMA,
         'exact typed retained-stage extension fields')
    need((ext['boot_id'],ext['label'],ext['nonce'])==(BOOT,LABEL,NONCE)
         and ext['native_boundary']==HEAD and ext['prior_inventory']==PRIOR,
         'fixed expired unstarted stage cannot be another family')
    target=bytepin(ext['actual_inventory'])
    need(len(old['roots'])==39 and HOME not in old['roots'] and EXECUTOR not in old['roots']
         and FIXTURE not in old['roots'],'original39 never included this stage or fixture')
    roots=ext['roots'];entries=ext['entries'];elapsed=ext['elapsed_seconds']
    need(type(roots) is list and len(roots)==len(set(roots))==41
         and set(roots)==set(old['roots'])|{HOME,EXECUTOR}
         and FIXTURE not in roots,'exact old39 plus two retained roots; no fixture/native credit')
    need(type(entries) is dict and 5<=len(entries)<=256
         and not set(entries)&set(old['entries'])
         and all(type(p) is str and sum(under(p,r)for r in (HOME,EXECUTOR))==1 for p in entries),
         'complete compact extension stays in only its two new roots')
    need(type(elapsed) in (int,float) and math.isfinite(elapsed) and elapsed>=0,
         'retain finite actual elapsed exactly')
    for path,row in entries.items():
        m=row.get('metadata')
        need(type(m) is list and len(m)==9 and all(type(v) is int for v in m),'original full9 in every new row')
        if row.get('kind')=='directory':
            private_directory(row)
        else:
            need(row.get('kind')=='file' and stat.S_ISREG(m[2]) and stat.S_IMODE(m[2])==0o600
                 and m[3:6]==[0,0,1],'original root-owned600 single-link staged member')
    gnu_exec=private_directory(entries[HOME+'/executor'])
    android_exec=private_directory(entries[EXECUTOR])
    need(gnu_exec==android_exec and gnu_exec['names']==[],'empty exact GNU/Android executor alias pair')
    need(private_directory(entries[HOME+'/claims'])['names']==[]
         and private_directory(entries[HOME+'/operator'])['names']==[],
         'unstarted claims/operator directories stay empty')
    private_directory(entries[HOME])
    for path in entries:
        need(not(PurePosixPath(path).name.endswith('.lock')or PurePosixPath(path).name=='lock'),
             'retained unstarted stage may add no lock inode or alias')
    value=dict(old,roots=roots,entries={**old['entries'],**entries},
               elapsed_seconds=elapsed)
    value['file_bytes_hashed']=sum(row['bytes']for row in value['entries'].values()if row['kind']=='file')
    validate_inventory(value)
    raw=encoded(value)
    need(descriptor(raw)==target,'complete reconstructed actual41 bytes/hash differ')
    selected=dict(value,roots=old['roots'],
                  entries={p:r for p,r in value['entries'].items()if any(under(p,root)for root in old['roots'])})
    selected['file_bytes_hashed']=sum(r['bytes']for r in selected['entries'].values()if r['kind']=='file')
    need(validate_inventory(selected)==validate_inventory(old),'complete original39 semantic projection differs')
    before={p:r for p,r in old['entries'].items()if r.get('kind')=='file'
            and(PurePosixPath(p).name.endswith('.lock')or PurePosixPath(p).name=='lock')}
    after={p:r for p,r in value['entries'].items()if r.get('kind')=='file'
           and(PurePosixPath(p).name.endswith('.lock')or PurePosixPath(p).name=='lock')}
    need(before==after and len(after)==24 and len({tuple(r['metadata'][:2])for r in after.values()})==13,
         'retained stage changes no declared24/13 lock topology')
    return raw,value

def project_actual(prior_raw, actual_raw, *, validate_inventory):
    """Host-only pure extraction; requires the actual complete captured raw input."""
    old=strict(prior_raw);actual=strict(actual_raw);validate_inventory(old);validate_inventory(actual)
    need(descriptor(prior_raw)==PRIOR,'exact old39 original')
    ext={'schema':SCHEMA,'boot_id':BOOT,'label':LABEL,'nonce':NONCE,
         'native_boundary':HEAD,'prior_inventory':PRIOR,'actual_inventory':descriptor(actual_raw),
         'roots':actual['roots'],'entries':{p:r for p,r in actual['entries'].items()if p not in old['entries']},
         'elapsed_seconds':actual['elapsed_seconds']}
    compact=encoded(ext)
    rebuilt,value=reconstruct(prior_raw,compact,validate_inventory=validate_inventory)
    need(rebuilt==actual_raw and value==actual,'actual full original must be canonical bytes, not a compare-only view')
    return compact

# Compact fixed-family validator. Complete observations were validated by the pinned host closure.
# This reader proves exact historical projections and private preservation, not fresh process absence.
import base64
import zlib

CAPTURE_SOURCE = {'bytes':34007,'sha256':'5dfb7b621454ff905e057573b7271216bf7a2889f2d7682d994e2ab3d87d2c05'}
CAPTURE_REQUEST = {'bytes':5422,'sha256':'104ccf9e9c1c71fe3e567b46ad832f48741cd6c7ad6fd5cb0cb9d159d7b754fc'}
ACTUAL_INVENTORY = {'bytes':1206630,'sha256':'fe8f37a3e4fb5ce46514e14c80b4e5ef8986d4653a8ad4a991bc463caaf78aa6'}
ACTUAL_OBSERVATIONS = {'bytes':1200485,'sha256':'da74addf5ae9c0bf3d78ad5639ac7b6101b44988af1e03c9632ad99f0d7d64ba'}
LIVE_POLICY = {'bytes':2667752,'sha256':'69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'}
OWNER = '6de75a64f417dbff9d86916168921e73b5de6cbd3228bc46a74735eb844d4cf9'
LEASE_SHA = '1b7f957ddfff0660cc409a9924a1128a215d7446d07726e422f772d8df6a00aa'
PACKAGE_SHA = '459626990f472ca2accfefae8a007ebffcfff6995c3d65f11fba3f003db1413f'
COMBINATION_SHA = '02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708'
STATE_LABEL = b'u:object_r:trillionnium_owner_open_state_file:s0\0'
EXECUTOR_LABEL = b'u:object_r:trillionnium_owner_open_phone_executor_data_file:s0\0'
BUNDLE_FIELDS = {'schema','closure_projection_raw','request_raw','observation_projection_raw','original_map_projection_raw',
 'extension_raw','lease_raw','stage_raw','staged_members'}
CLOSURE_PIN = {'bytes':65567,'sha256':'38a93ca265e0bb1b35ae80ab8309f389991e8c9a300700508e09841df3313e76'}
CLOSURE_PROJECTION_PIN = {'bytes': 9310, 'sha256': '850be3b4a55215105f17aabe6336610593dcdd9a3788c8fdc2d9f8f8d040dda5'}
OBSERVATION_PROJECTION = {'bytes':18262,'sha256':'aa3efe0f8edf3b119e21ae45afa8efe9163886156ae6d91860ad4233e5be5046'}
ORIGINAL_MAP_PROJECTION = {'bytes':28683,'sha256':'c85679f94659026587e24e91ae922ba94c1d3d7070cd83fca6a265754d238423'}
ORIGINAL_MAP_PIN = {'bytes':46513,'sha256':'906c16661ba90a2bc4887b256f04fc2451f0cf8018aba071dc82b6a8811a89bc'}
PROJECTION_SOURCE_PIN = {'bytes':3256,'sha256':'af9791a4e31022fd892cb2cd8be5b1070210613ed899b3f35c4db45315e624dd'}
HOST_CORE_PIN = {'bytes':29059,'sha256':'8042130efbe14998089b96aab6a9665859ceed62599232ade33b3c57cdcc9afb'}
EXTENSION_PIN = {'bytes':28788,'sha256':'f0dd45dba084f4cae8da54f8b5d4ba01f6457a94098b1ea670451268f9ce09a1'}
ABSENT_NAMES = ('READY.json','END.json','ENDED.json','ACCEPTED.json','BOUND-CONTRACT.json',
 'DETACHED-LAUNCH-INTENT.json','DETACHED-LAUNCH-RESULT.json','SUPERVISOR.json',
 'LIFECYCLE-ATTEMPT.json','LIFECYCLE-ENDED.json','LIFECYCLE-FAILURE.json',
 'RETIRED-BASELINE-VERIFIED.json','BASELINE-INVENTORY.json','PORT-RESERVED.json',
 'SIDECAR-HEALTH.original.json','PROVIDER-SPAWNED.json','PROVIDER-STARTED.json',
 'PROVIDER-JOINED.json','SIDECAR-SPAWNED.json','SIDECAR-STARTED.json',
 'SIDECAR-JOINED.json','supervisor.stdout','supervisor.stderr','STAGE-FAILURE.json')

def _decode(value, maximum=4*1024*1024):
    need(type(value) is str,'original base64 string')
    raw=base64.b64decode(value,validate=True)
    need(len(raw)<=maximum,'bounded embedded original')
    return raw

def _full9(value):
    need(type(value) is list and len(value)==9 and all(type(v)is int for v in value),'exact full9')
    return value

# Full endpoint parser stays in the pinned host validator; fresh gates are separate.
def _expected_tree(members):
    need(type(members)is dict and len(members)==60,'fixed complete60 archive member pins')
    files=set(members)|{'STAGE-COMPLETE.json'};directories={'.','claims','operator','executor'}
    for name,row in members.items():
        p=PurePosixPath(name)
        need(not p.is_absolute()and str(p)==name and '..'not in p.parts
             and type(row)is dict and set(row)=={'bytes','sha256'},'relative staged member pin')
        bytepin(row)
    for name in files:
        p=PurePosixPath(name).parent
        while str(p)!='.':
            directories.add(str(p));p=p.parent
    names={name:[]for name in directories}
    for name in files|(directories-{'.'}):
        names[str(PurePosixPath(name).parent)].append(PurePosixPath(name).name)
    return files,{name:sorted(value)for name,value in names.items()}

def validate_compact_payload(payload, prior_raw, *, validate_inventory):
    """Verify frozen historical projections; current processes and paths require fresh caller gates."""
    need(type(payload)is dict and set(payload)==BUNDLE_FIELDS
         and payload['schema']=='hepta.expired-unstarted-stage.compact-historical-utf8-bundle.v1','exact fixed bundle')
    raw={}
    for name in BUNDLE_FIELDS:
        if name.endswith('_raw'):
            need(type(payload[name])is str,'exact UTF-8 original text required')
            raw[name]=payload[name].encode('utf-8')
            need(len(raw[name])<=4*1024*1024,'bounded exact original text bytes')
    need(descriptor(raw['request_raw'])==CAPTURE_REQUEST and descriptor(raw['closure_projection_raw'])==CLOSURE_PROJECTION_PIN
         and descriptor(raw['observation_projection_raw'])==OBSERVATION_PROJECTION
         and descriptor(raw['original_map_projection_raw'])==ORIGINAL_MAP_PROJECTION
         and descriptor(raw['extension_raw'])==EXTENSION_PIN,'exact fixed historical originals/projections')
    q=strict(raw['request_raw']);lease=strict(raw['lease_raw']);stage=strict(raw['stage_raw'])
    cp=strict(raw['closure_projection_raw'])
    need(set(cp)=={'schema','original','selected_actual_fields','omitted_host_originals_count',
         'omitted_host_originals_canonical_descriptor','omitted_rows_remain_in_complete_host_closure'}
         and cp['schema']=='hepta.expired-unstarted-stage.host-closure-projection.v1'
         and cp['original']==CLOSURE_PIN and cp['omitted_rows_remain_in_complete_host_closure']is True
         and type(cp['omitted_host_originals_count'])is int and cp['omitted_host_originals_count']>=100,
         'explicit closure field projection keeps exact full original provenance')
    bytepin(cp['omitted_host_originals_canonical_descriptor'])
    closure=cp['selected_actual_fields']
    op=strict(raw['observation_projection_raw']);omap=strict(raw['original_map_projection_raw'])
    need(set(op)=={'schema','original','selected_actual_fields','canonical_object_descriptors',
         'canonical_object_descriptors_are_derived_not_separate_original_files','full_census_and_endpoint_originals_embedded',
         'complete_originals_still_required_for_host_closure'}
         and op['schema']=='hepta.unstarted-stage.named-field-observation-projection.v1'
         and op['original']==ACTUAL_OBSERVATIONS
         and op['canonical_object_descriptors_are_derived_not_separate_original_files']is True
         and op['full_census_and_endpoint_originals_embedded']is False
         and op['complete_originals_still_required_for_host_closure']is True,'explicit projection without full census claim')
    obs=op['selected_actual_fields']
    need(set(op['canonical_object_descriptors'])=={'historical_absence','scope_process_census','endpoint_observations'},
         'all three original observation categories')
    for values in op['canonical_object_descriptors'].values():
        need(type(values)is list and len(values)==2,'two original objects in each category')
        for row in values:bytepin(row)
    need(set(omap)=={'schema','original','full_original_count','selected_original_count','files',
         'omitted_originals_remain_in_host_closure_evidence'}
         and omap['schema']=='hepta.unstarted-stage.exact-private-original-map-projection.v1'
         and omap['original']==ORIGINAL_MAP_PIN and omap['full_original_count']==104
         and omap['selected_original_count']==63 and omap['omitted_originals_remain_in_host_closure_evidence']is True,
         'exact private subset keeps full map provenance')
    need(q['schema']=='hepta.unstarted-stage.capture-request.v1'and q['source']==CAPTURE_SOURCE
         and q['scope']=={'boot_id':BOOT,'label':LABEL,'nonce':NONCE,'package_sha256':PACKAGE_SHA,
             'lease_sha256':LEASE_SHA,'combination_sha256':COMBINATION_SHA,'policy_sha256':LIVE_POLICY['sha256']},
         'exact retained failed scope')
    need(q['maximum_whole_seconds']==45 and q['host_actor_timeout_seconds']==70
         and q['budgets']=={'inventory_seconds':30,'process_census_seconds':2,'inventory_entries':30000,
         'inventory_root_hard_limit':64,'inventory_file_bytes':64*1024*1024,'inventory_total_bytes':512*1024*1024,
         'evidence_file_bytes':16*1024*1024,'evidence_total_bytes':32*1024*1024,
         'future_reviewed_inventory_roots':47,'native_cap':11,'role_cap':39,'fixture_cap':13,
         'lease_seconds':600,'prelaunch_seconds':510,'listener_seconds':420},'reviewed finite bounds')
    need(descriptor(raw['lease_raw'])=={'bytes':2502,'sha256':LEASE_SHA}
         and lease['label']==LABEL and lease['nonce']==NONCE and lease['boot_id']==BOOT
         and lease['owner_request_sha256']==OWNER and lease['package_sha256']==PACKAGE_SHA,
         'original lease/owner unchanged')
    need(obs['schema']=='hepta.unstarted-stage.phone-observations.v1'
         and obs['state']=='EXPIRED_UNSTARTED_STAGE_OBSERVED_NO_ROLE_LAUNCH_OR_FIXTURE'
         and (obs['boot_id'],obs['label'],obs['nonce'])==(BOOT,LABEL,NONCE)
         and obs['original_lease_expires_unix_ms']==lease['expires_unix_ms']==1793938876735
         and obs['original_sender_wait']=='UNKNOWN_UNCHANGED',
         'fixed actual expired unstarted observation')
    for key in ('native_boundary_published','old_history_or_originals_rewritten','new_fixture_created',
                'whole_case_pass'):
        need(obs[key]is False,'retention must not assert launch/business/full admission')
    need(obs['native_case_credit']==obs['phone_file_writes']==0
         and obs['current_inventory_root_count']==41
         and obs['new_retained_roots']==[HOME,EXECUTOR],
         'independent zero-role retained-stage accounting')
    need(descriptor(raw['stage_raw'])==q['stage_original']
         and stage['schema']=='hepta.native-guard.private-stage.v1'
         and stage['state']=='PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES'
         and stage['members']==60 and stage['lease_sha256']==LEASE_SHA
         and stage['package_sha256']==PACKAGE_SHA and stage['archive_sha256']==q['archive']['sha256'],
         'actual stage original')
    actual_raw,actual=reconstruct(prior_raw,raw['extension_raw'],validate_inventory=validate_inventory)
    need(descriptor(actual_raw)==ACTUAL_INVENTORY,'actual41 precise canonical raw bytes')
    need(len(omap['files'])==63,'complete private61 plus two original transport files')
    rows={}
    for row in omap['files']:
        need(type(row)is dict and set(row)=={'path','bytes','sha256','metadata','selinux_raw_b64','retained_member'}
             and row['path']not in rows,'exact original descriptor map')
        m=_full9(row['metadata'])
        need(stat.S_ISREG(m[2])and m[5]==1 and type(row['bytes'])is int and 0<=row['bytes']<=16*1024*1024
             and re.fullmatch('[0-9a-f]{64}',row['sha256']),'captured regular original')
        rows[row['path']]=row
    files,names=_expected_tree(payload['staged_members'])
    observed=obs['stage_before'];need(observed==obs['stage_after'],'stage full9/label/name bookends')
    need(set(observed)=={'directories','aliases','file_count','archive_member_count'}
         and observed['file_count']==61 and observed['archive_member_count']==60
         and set(observed['directories'])==set(names)and len(names)==9,'complete stage tree')
    for relative,expected_names in names.items():
        path=HOME if relative=='.'else HOME+'/'+relative
        row=observed['directories'][relative]
        label=EXECUTOR_LABEL if relative=='executor'else STATE_LABEL
        need(set(row)=={'path','metadata','names','selinux_raw_b64'}and row['path']==path
             and row['names']==expected_names and _decode(row['selinux_raw_b64'],512)==label,
             'stage directory names/label')
        inv=private_directory(actual['entries'][path])
        need(inv['metadata']==_full9(row['metadata'])and inv['names']==expected_names,'directory exact inventory original')
    expected_file_paths={HOME+'/'+name for name in files}
    need({path for path in actual['entries']if under(path,HOME)and actual['entries'][path]['kind']=='file'}==expected_file_paths,
         'no missing/extra staged file')
    for name in files:
        path=HOME+'/'+name;row=rows[path];item=actual['entries'][path]
        expected=q['stage_original']if name=='STAGE-COMPLETE.json'else payload['staged_members'][name]
        need({k:row[k]for k in('bytes','sha256')}==expected=={k:item[k]for k in('bytes','sha256')}
             and row['metadata']==item['metadata']and _decode(row['selinux_raw_b64'],512)==STATE_LABEL,
             'every complete staged original full9/label/pin')
    expected_aliases=[(HOME,ANDROID_HOME,STATE_LABEL),(HOME+'/executor',EXECUTOR,EXECUTOR_LABEL),
                      (str(PurePosixPath(HOME).parent),str(PurePosixPath(ANDROID_HOME).parent),STATE_LABEL)]
    need(len(observed['aliases'])==3,'exact aliases plus shared parent')
    for pair,(g,a,label)in zip(observed['aliases'],expected_aliases):
        need(set(pair)=={'gnu','android','same_inode_and_full9'}and pair['same_inode_and_full9']is True,
             'alias observation')
        left,right=pair['gnu'],pair['android']
        need(left['path']==g and right['path']==a and _full9(left['metadata'])==_full9(right['metadata'])
             and left['names']==right['names']and _decode(left['selinux_raw_b64'],512)==label
             and left['selinux_raw_b64']==right['selinux_raw_b64'],'alias exact one inode/full9')
    need(stage['journal_layout']['journal']['metadata']==actual['entries'][EXECUTOR]['metadata'],
         'original freshly created executor remains exact and empty')
    need(len(obs['historical_role_generations'])==33
         and len({tuple(row)for row in obs['historical_role_generations']})==33,'33 frozen historical generations')
    for roles in obs['historical_role_generations']:
        need(type(roles)is list and len(roles)==4 and all(type(n)is int and n>1 for n in roles)
             and roles[0]==roles[1]==roles[2],'exact original role generations')
    # The host core parsed both original census/endpoint tables and checked all13 held OFDs.
    # Their exact raw pins remain in the complete CLOSURE; this projection makes no fresh absence claim.
    need(closure['core_source']['bytes']==HOST_CORE_PIN['bytes']
         and closure['core_source']['sha256']==HOST_CORE_PIN['sha256']
         and closure['capture_original_map']==ORIGINAL_MAP_PIN,'complete host closure exact verification provenance')
    need(closure['schema']=='hepta.expired-unstarted-stage.host-closure.v1'
         and closure['state']=='EXPIRED_UNSTARTED_STAGE_RETAINED'
         and (closure['boot_id'],closure['label'],closure['nonce'])==(BOOT,LABEL,NONCE)
         and closure['native_predecessor']==lease['prior_boundary']
         and closure['original_inventory']==q['prior_inventory']
         and closure['after_inventory']==ACTUAL_INVENTORY
         and closure['capture_source']==CAPTURE_SOURCE and closure['capture_request']==CAPTURE_REQUEST
         and closure['capture_observations']==ACTUAL_OBSERVATIONS,'actual independent host closure')
    need(closure['facts']=={'new_native_case_count':0,'new_component_role_generation_count':0,'new_fixture_count':0,
          'new_inventory_root_count':2,'original_Mac_sender_wait':'UNKNOWN_UNCHANGED',
          'sender_Send_count':0,'sender_UI_preparation_performed':True,'original_draft_restored_once':True,
          'old9_native_family_scopes_unchanged':True,'old33_role_generations_unchanged':True,
          'old_two_non_native_branches_unchanged':True,'old39_inventory_exactly_preserved':True,
          'closed_stage_retained_in_place':True,'new_scope_claims_absent':True,'native_boundary_published':False,
          'component_qualified':False,'business_qualified':False,'fixed19_credit':0},
          'retention accounting cannot grant qualification or repair original wait')
    need(closure['original_root_failure']['sha256']=='8bc7b7b913d15a51a4fe782a8045d7abd9ddd623ca3960933daf01405a7c6769'
         and closure['sender_proof']['report']['sha256']=='6860efcf68d4b3a89e639e3c64dc351fa6515d8f0ffc7bad9c68d5340d0fa5aa'
         and closure['sender_proof']['readonly_verifier']['sha256']=='d0f5123d2326bdb83bf48b30d11d6adf896cbaa68104d521f08fecca4d32272b'
         and closure['sender_proof']['actual_original_child_wait_returned']is True
         and closure['sender_proof']['actual_original_child_returncode']==0
         and closure['sender_proof']['actual_dual_eof']is True,'independent original sender verification process')
    required=[{k:row[k]for k in('path','bytes','sha256','metadata','selinux_raw_b64')}for path,row in rows.items()
              if path.startswith(HOME+'/')or path in (
                '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/'+LABEL+'.tar.gz',
                '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/'+LABEL+'.stage.py')]
    need(len(required)==63,'all61 staged originals plus2 GNU transport originals')
    return {'closure':CLOSURE_PIN,'closure_projection':cp,'closure_projection_raw':raw['closure_projection_raw'],
      'closure_projection_descriptor':CLOSURE_PROJECTION_PIN,'inventory_raw':actual_raw,'inventory':actual,
      'inventory_value':validate_inventory(actual),'observation_projection_raw':raw['observation_projection_raw'],
      'original_map_projection_raw':raw['original_map_projection_raw'],'extension_raw':raw['extension_raw'],
      'request_raw':raw['request_raw'],
      'private_roots':[HOME,EXECUTOR],'lease':{k:rows[HOME+'/LEASE.json'][k]for k in('path','bytes','sha256','metadata')},
      'required_originals':required,'original_sender_wait':'UNKNOWN_UNCHANGED'}

def verify_retained_unstarted_stage(*, read_pinned, validate_inventory):
    """Verify the one frozen historical zero-role family; no I/O except injected original reader."""
    source_identity=globals().get('__reviewed_source_sha256__')
    need(type(source_identity)is str and re.fullmatch('[0-9a-f]{64}',source_identity),
         'caller must inject independently pinned typed reader identity')
    decoder=zlib.decompressobj()
    raw=decoder.decompress(base64.b64decode(FIXED_PAYLOAD_ZLIB_BASE64,validate=True),4*1024*1024+1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
         and descriptor(raw)==FIXED_PAYLOAD_PIN,'complete fixed original bundle')
    payload=strict(raw)
    need(type(payload['request_raw'])is str,'exact request UTF-8 text')
    request=strict(payload['request_raw'].encode('utf-8'))
    original=read_pinned(request['prior_inventory'])
    need(descriptor(original)==PRIOR,'original old39 readback before reconstruction')
    result=validate_compact_payload(payload,original,validate_inventory=validate_inventory)
    again=read_pinned(request['prior_inventory'])
    need(again==original,'old39 original source bookends')
    result['binding']={'schema':'hepta.native-guard.retained-unstarted-stage-binding.v1',
      'scope_profile':'expired_private_stage_no_roles_no_Send','boot_id':BOOT,'label':LABEL,'nonce':NONCE,
      'reader_source_sha256':source_identity,'closure':CLOSURE_PIN,'closure_projection':CLOSURE_PROJECTION_PIN,
      'inventory':ACTUAL_INVENTORY,'observations':ACTUAL_OBSERVATIONS,'original_map':ORIGINAL_MAP_PIN,
      'observation_projection':OBSERVATION_PROJECTION,'original_map_projection':ORIGINAL_MAP_PROJECTION,
      'projection_source':PROJECTION_SOURCE_PIN,'host_core_source':HOST_CORE_PIN,
      'native_predecessor':result['closure_projection']['selected_actual_fields']['native_predecessor'],'private_roots':[HOME,EXECUTOR],
      'native_case_count':0,'component_role_identities':{},'fixture_root_count':0,
      'component_qualified':False,'original_sender_wait':'UNKNOWN_UNCHANGED'}
    return result

def validate_private_preservation(summary,current_inventory,*,validate_inventory):
    """Later native generations may add their own roots but never consume this stage."""
    current=validate_inventory(current_inventory)
    need(summary['private_roots']==[HOME,EXECUTOR]and summary['binding']['nonce']==NONCE,
         'exact retained-stage summary')
    old=summary['inventory_value']
    need(set(old['roots'])<=set(current['roots']),'retained cumulative roots dropped')
    for root in (HOME,EXECUTOR):
        before={p:r for p,r in old['entries'].items()if under(p,root)}
        after={p:r for p,r in current['entries'].items()if under(p,root)}
        need(before==after,'expired stage originals changed or gained a child')
    need(FIXTURE not in current['entries'],'unstarted stage acquired an inventoried fixture later')
    # This inventory rejection does not prove current ENOENT. Call require_fresh_fixture_absence separately.
    return True

def require_fresh_fixture_absence(*, lstat):
    """Phone caller supplies os.lstat under its already-held admission locks.
    Host history readers must not call this as a substitute for phone observation.
    No signal, launch, mutation or retry is implemented.
    """
    import errno
    import time
    parent=str(PurePosixPath(FIXTURE).parent)
    before=lstat(parent)
    need(stat.S_ISDIR(before.st_mode),'fixture parent is a real directory')
    started=time.monotonic_ns()
    try:
        lstat(FIXTURE)
    except FileNotFoundError as exc:
        need(exc.errno==errno.ENOENT,'precise fixture ENOENT required')
    else:
        raise ValueError('retained unstarted scope acquired a fixture')
    after=lstat(parent)
    fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    a=[getattr(before,k)for k in fields];b=[getattr(after,k)for k in fields]
    need(a==b,'fixture parent changed across actual lstat')
    return {'path':FIXTURE,'errno':errno.ENOENT,'parent_metadata':a,
            'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns(),
            'original_wait_inferred':False}

FIXED_PAYLOAD_PIN = {'bytes': 134371, 'sha256': '98d1684df03dca8d0c008859bb7f8870e67974199b9cc6ba6525969e3a681136'}
FIXED_PAYLOAD_ZLIB_BASE64 = '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'
