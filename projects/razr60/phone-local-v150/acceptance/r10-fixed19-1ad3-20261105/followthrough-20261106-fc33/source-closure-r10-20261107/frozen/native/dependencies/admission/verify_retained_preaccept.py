#!/usr/bin/env python3
"""Pure verification of the one retained R7 preaccept failure.

This module consumes actual, byte-pinned originals. It never observes a process,
opens a device file, signals, publishes a boundary, or grants a native case.
The original two-role boolean and missing native terminal remain unchanged.
"""
import ast
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import io
import tarfile
import types
import zlib

LABEL = 'root-r10-neg01-fc33-r7-bound01'
NONCE = '4808fbf1e81fd1542e7ffb60d7f57ca6'
BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
BASE = '/var/lib/trillionnium/owner-open/phone-local-v150'
HOME = BASE+'/native-guard-r10-r1/'+LABEL
JOURNAL = '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/'+LABEL+'/executor'
FIXTURE = '/proc/1/root/data/local/tmp/hepta-native-guard-'+NONCE
ROLES = {'supervisor':[12513,12513,12513,39102689], 'sidecar':[14026,14026,14026,39106597]}
PACKAGE = {'bytes':61701,'sha256':'643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}
LEASE = {'bytes':2506,'sha256':'03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}
COMBINATION = {'bytes':4695,'sha256':'7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}
CAPTURE = {'bytes':7667691,'sha256':'7c31091e088a71195fcdf3cf9e4506153a1acdd43fdafbe54cd08007d7f74a7e'}
OBSERVER_SOURCE = {'bytes':14661,'sha256':'79d08928f57915264ac0d467491dc5b86df3bb39c50916ff8a04095a378390b8'}
OWNER = 'd39e94a205b7d49fc78a7298213942d378e2d9dd6e0e3861a707f183cd05cd73'
MAX_ORIGINAL = 16*1024*1024
MAX_COMPRESSED = 4*1024*1024
EXPECTED_PINS = {'actor_failure': {'bytes': 134, 'sha256': 'b9bdc97b7e7f778c77e03b390a3b59c9f42521707f089e177f3b48810402c3b2'},
 'capture': {'bytes': 7667691, 'sha256': '7c31091e088a71195fcdf3cf9e4506153a1acdd43fdafbe54cd08007d7f74a7e'},
 'draft_restore': {'bytes': 1630, 'sha256': '8171c5053068e4f7bdb812231fad3026527cdbeebfaeec5474c4b83649b0db1b'},
 'manifest': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'},
 'observer_read': {'bytes': 1406, 'sha256': '0112fa532e3be7aa02871841cffe07d04624ccf14ec54164a8b0fc17c34de6bc'},
 'observer_request': {'bytes': 387, 'sha256': '1b20ecabea591bc63a7066e483447fee7f05157a126fae354edd793db32b7f7c'},
 'observer_start': {'bytes': 1413, 'sha256': '47b618b244b948c5f3b6c25a1bc571c4e5ab04bf11a98a61330eae5bb4e58c86'},
 'observer_status': {'bytes': 951, 'sha256': 'b2b7e433e86e7fc2bcc1abbc6b8eef35e8beb2e6183e334a74165aa05645a8a1'},
 'old_inventory': {'bytes': 1345535, 'sha256': '4bd70b72d2a92a6c963912159d9e978fc681a35ddb30c03a2c741700bf47cde4'},
 'operation': {'bytes': 1741576, 'sha256': '854eadbbd94b4f8da8317b86abcf82b04532ef5fd1eea052a85a576bcb66dc52'},
 'owned_child': {'bytes': 3088, 'sha256': 'd57fe89ac2d4b8ae5b6a96a3c1636af84e040300f6a0bc9ebefc50da3ef9d50f'},
 'phone_request': {'bytes': 8282, 'sha256': '85159371cb2e5d95266cbc6727db5f1cc6e4f5f895ad0c1d7971e9405df173bd'},
 'plan': {'bytes': 5184, 'sha256': 'a66a9f75300955d3beb57d6cc79abba6c5f316adf61f46b76f9c34bd1598e398'},
 'prepared': {'bytes': 1039, 'sha256': '94728ba67a654a07728140c1419bdc4b5b16942bb66934b737576124be118688'},
 'preserved_draft': {'bytes': 180, 'sha256': 'b60c6be1928d5490e6ebd57dba67769796a779e5e58eefeb7fb70f071348b661'},
 'previous': {'bytes': 1426, 'sha256': 'fcdf8a456f663d6963d3cd9caf231a210aad92d8f5e192a71917381d10ea10f0'},
 'prior_boundary': {'bytes': 29342, 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'},
 'prompt_input': {'bytes': 2050, 'sha256': '90345695a81388fbf9bd5f6d878a33274ad7530b17c43cdf4f9115b73f7a0dd2'},
 'request_text': {'bytes': 317, 'sha256': 'd39e94a205b7d49fc78a7298213942d378e2d9dd6e0e3861a707f183cd05cd73'},
 'restore_gate': {'bytes': 27050, 'sha256': '924b746f6bce8c697b393dfc90fd469a86ca8e3af678d68232a236134819d6b9'},
 'restore_result': {'bytes': 222, 'sha256': '48b1e1f4865919702ef7c57cabfcd978d32f6d967de47e500bff9870fb6e8db1'},
 'restore_selected': {'bytes': 727, 'sha256': '9daa8e44c4d7515ae045c47bfef4695144782c62ba9332b8c64d3a4b7b93fbc0'},
 'root_failure': {'bytes': 13873, 'sha256': 'adf6650b3811dc7a44b3ea1b3bfb9117a07543ba3b285e7cf556dbffb912832f'},
 'root_manifest': {'bytes': 53736, 'sha256': '440aab78d6f51b38218be68b1c0b1e40f8c36b5db13a66ec9c145cce49993a53'},
 'root_read': {'bytes': 4255, 'sha256': 'aa36f17e6239b31c9e249bf377dd8639a7ce4f737a98e5311d5d8abb77bfa843'},
 'root_request': {'bytes': 705, 'sha256': '733bc9c33c5623542a49f3c180f5f4cd5640f2b23474082f68d7773933c7db17'},
 'root_start': {'bytes': 1829, 'sha256': '234b3c0312a4ce7c71cd72cd5249362412a5acf5ee0f0014781a59d79076e238'},
 'root_status': {'bytes': 950, 'sha256': '7608a69d051c9078aac25426680bb638884a8595b3d126a7022d2cca154b3dbd'},
 'sender_stderr': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
 'sender_stdout': {'bytes': 680, 'sha256': 'ca4207aa72b0993cb2bceeec104fa207be70b1dee156e210f01dcd381ed37e83'},
 'source_common': {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'},
 'source_late': {'bytes': 181669, 'sha256': '0a9f52cf8fb71177d0816f561cce279811a7182e986c12912d9431bde5997cda'},
 'source_lifecycle': {'bytes': 40451,
                      'sha256': '5968facb7879582051f102fe63064ec3c01616b150089d17c010ccf4f873b234'},
 'source_observer': {'bytes': 14661, 'sha256': '79d08928f57915264ac0d467491dc5b86df3bb39c50916ff8a04095a378390b8'},
 'source_root': {'bytes': 82587, 'sha256': '4a0157b808fa2d99b5b32dcbd97a32359c409580be3733c5bd464af37961a69f'},
 'source_sender': {'bytes': 46588, 'sha256': 'b9c1a06c002daaf2a153421ab687b1139f957071e8153365a1f8544f2803d296'},
 'source_snapshot': {'bytes': 27776, 'sha256': '1478e2f9c77a0e02145cb4b5172ad561f17cf3ea8668e96d56997547f209ea41'},
 'source_state_decoder': {'bytes': 4116,
                          'sha256': 'a3e619926a4688ebfefd55ad1074cb386240f9828613781b7fd547bcf0c70073'}}


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    need(type(raw) is bytes, 'original bytes required')
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()


def strict(raw):
    need(type(raw) is bytes and len(raw)<=MAX_ORIGINAL, 'bounded complete JSON original')
    def pairs(rows):
        value={}
        for k,v in rows:
            need(k not in value,'duplicate original JSON key');value[k]=v
        return value
    def nonfinite(_):
        raise ValueError('nonfinite original JSON')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=nonfinite)


def same(a,b):
    return encoded(a)==encoded(b)


def original_descriptor(row):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact input descriptor')
    p=PurePosixPath(row['path'])
    need(p.is_absolute() and str(p)==row['path'] and '..' not in p.parts and '\0' not in str(p), 'canonical input path')
    need(type(row['bytes']) is int and 0<=row['bytes']<=MAX_ORIGINAL
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'original input byte pin')
    return row


def mcp(raw):
    value=strict(raw)
    need(value.get('isError') is False and type(value.get('content')) is list and len(value['content'])==1
         and value['content'][0].get('type')=='text','one successful original MCP text result')
    return strict(value['content'][0]['text'].encode())


def controller(raw, prefix, *, job, code):
    request=strict(raw[prefix+'_request']);start=mcp(raw[prefix+'_start'])
    status=mcp(raw[prefix+'_status']);output=mcp(raw[prefix+'_read'])
    record=start['job']
    need(record['id']==status['job_id']==output['job_id']==job and start['reused'] is False
         and record['launch_state']=='launched' and record['launch_error'] is None, 'one actual original job identity')
    need(record['executable']==request['executable'] and record['args']==request['args']
         and record['host']==request['host'] and record['idempotency_key']==request['idempotency_key'], 'actual job/request binding')
    need(status['exit_code']==code and status['state']==('succeeded' if code==0 else 'failed')
         and all(status[k] is True for k in ('output_complete','output_durable','terminal_publication_confirmed'))
         and all(status[k] is False for k in ('timed_out','cancelled','automatic_retry')), 'actual terminal and durable complete streams')
    streams={}
    for name in ('stdout','stderr'):
        row=output[name];data=bytes.fromhex(row['bytes_hex'])
        need(row['offset']==0 and row['eof'] is True and row['next_offset']==row['size']==len(data)
             and data.decode()==row['text'],'entire original stream, not a prefix')
        streams[name]=data
    return request,streams


def readers(raw):
    # Execute only immutable, already pinned definitions. No reader __main__ runs.
    common=types.ModuleType('retained_r7_original_common')
    exec(compile(raw['source_common'],'<exact R7 Common>','exec'),common.__dict__)
    tree=ast.parse(raw['source_late'])
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='inventory_value']
    need(len(nodes)==1,'one unchanged complete inventory reader')
    namespace={'C':common,'Path':Path,'re':re,'stat':stat}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact R7 inventory reader>','exec'),namespace)
    decoder=types.ModuleType('retained_r7_original_state_decoder')
    exec(compile(raw['source_state_decoder'],'<exact original client-state decoder>','exec'),decoder.__dict__)
    return common,namespace['inventory_value'],decoder.decode_client_state


def decode_operation(raw):
    request=strict(raw['phone_request']);op=strict(raw['operation'])
    need(request['kind']=='shell' and request['root'] is True and request['timeout_seconds']==180,
         'original read-only observation request')
    need(op['schema']=='hepta.phone-local.operator-result.v150.1' and op['label']=='ro-r7-preaccept-4808fbf1-02'
         and op['status']=='command_exited' and op['model_decision'] is False and op['native_task_result'] is False,
         'actual read-only observation identity')
    wire=op['phone']
    need(wire['rc']==0 and wire['stderr']=='' and wire['route']==[5037,'23']
         and shlex.split(wire['command'])==['/debug_ramdisk/su','-c',request['command']], 'original observation command and exit')
    env=strict(wire['stdout'].encode())
    need(set(env)=={'schema','raw_bytes','raw_sha256','compressed_bytes','compressed_sha256','zlib_base64'}
         and env['schema']=='hepta.r7.preaccept.original-observation-zlib.v1','complete original lossless envelope')
    need(type(env['raw_bytes']) is int and 0<env['raw_bytes']<=MAX_ORIGINAL
         and type(env['compressed_bytes']) is int and 0<env['compressed_bytes']<=MAX_COMPRESSED,'original output bounds')
    packed=base64.b64decode(env['zlib_base64'],validate=True)
    need(pin(packed)=={'bytes':env['compressed_bytes'],'sha256':env['compressed_sha256']},'compressed original byte pin')
    codec=zlib.decompressobj();captured=codec.decompress(packed,MAX_ORIGINAL+1)
    need(codec.eof and not codec.unused_data and not codec.unconsumed_tail and len(captured)<=MAX_ORIGINAL,
         'single complete bounded zlib stream')
    need(pin(captured)==CAPTURE=={'bytes':env['raw_bytes'],'sha256':env['raw_sha256']}
         and captured==raw['capture'],'exact decoded capture original')
    return strict(captured)


def retained_original(value, inventory, readset):
    need(value['state']=='ORIGINAL_BYTES_READ','required original file was actually read')
    data=base64.b64decode(value['base64'],validate=True);p=value['path']
    need(pin(data)=={k:value[k] for k in ('bytes','sha256')},'captured file raw pin')
    meta=value['metadata']
    need(type(meta) is list and len(meta)==9 and all(type(n) is int for n in meta)
         and stat.S_ISREG(meta[2]) and meta[5]==1 and meta[6]==len(data),'full9 original file identity')
    need(readset[p]=={k:value[k] for k in ('path','bytes','sha256','metadata')}
         and inventory['entries'][p]=={'kind':'file','metadata':meta,**pin(data)},'raw original/readset/inventory binding')
    return data


def explicit_absence(value, inventory):
    need(set(value)=={'path','state','parent_metadata','historical_execution_inferred'}
         and value['state']=='CURRENT_EXPLICIT_ENOENT' and value['historical_execution_inferred'] is False,
         'named absence is a current observation, not a historical inference')
    p=PurePosixPath(value['path']);parent=inventory['entries'][str(p.parent)]
    need(value['path'] not in inventory['entries'] and parent['kind']=='directory'
         and parent['metadata']==value['parent_metadata'] and p.name not in parent['names'], 'exact absent leaf and held parent')


def raw_census(value, common):
    pids=value['begin_pids']
    need(pids==value['end_pids']==sorted(set(pids)) and len(pids)<=4096
         and value['new_pids']==value['gone_pids']==value['read_disappearances']==[]
         and value['original_identities']==ROLES and value['absence_is_not_inferred_from_missing_rows'] is True,
         'complete stable original process-stat census')
    need([r['pid'] for r in value['rows']]==pids,'every numeric PID has its actual raw stat')
    for row in value['rows']:
        data=base64.b64decode(row['raw_base64'],validate=True)
        need(len(data)<=8192 and pin(data)=={k:row[k] for k in ('bytes','sha256')},'raw process-stat bytes')
        parsed=common.stat_identity(data,row['pid'],census=True)
        need(same(parsed,row['parsed']),'independent original process-stat parser')
        need(not any(common.generation(parsed)==v or parsed['pgid']==v[1] or parsed['sid']==v[2]
                     for v in ROLES.values()),'original owned generation/group/session is still present')
    return len(pids)


def raw_endpoints(value, common, source):
    raw={}
    for name,row in value['raw_tables'].items():
        data=base64.b64decode(row['base64'],validate=True)
        need(pin(data)=={k:row[k] for k in ('bytes','sha256')},'original endpoint table bytes');raw[name]=data
    need(set(raw)=={'tcp','tcp6','unix'},'all original endpoint tables')
    tree=ast.parse(source);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='endpoint_absence']
    need(len(nodes)==1,'one unchanged endpoint parser')
    def supplied(path):
        need(path in ('/proc/net/tcp','/proc/net/tcp6','/proc/net/unix'),'exact endpoint input name')
        return raw[path.rsplit('/',1)[1]]
    ns={'C':common,'bounded_proc':supplied,'time':types.SimpleNamespace(monotonic_ns=lambda:value['original_reader_result']['observed_monotonic_ns'])}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact original endpoint reader>','exec'),ns)
    observed,verdict=ns['endpoint_absence']()
    need(observed==raw and same(verdict,value['original_reader_result']),'independent unchanged endpoint verdict')


def verify_phone(raw, common, inventory_reader):
    value=decode_operation(raw)
    need(value['schema']=='hepta.r7.preaccept.original-observation.v1' and value['state']=='READONLY_ORIGINALS_CAPTURED'
         and value['label']==LABEL and value['nonce']==NONCE and value['boot_id']==BOOT
         and value['observer_source_sha256']==OBSERVER_SOURCE['sha256'] and pin(raw['source_observer'])==OBSERVER_SOURCE
         and value['package']==PACKAGE and value['lease']==LEASE and value['actual_original_role_identities']==ROLES,
         'one actual failed R7 identity and source')
    need(value['errors']==[] and value['full_inventory_entries_equal'] is True
         and value['bookends']=={'all_read_originals_bookended':True,'named_absence_count':17,'read_file_count':64},
         'complete error-free capture and all original bookends')
    for k in ('native_acceptance','native_terminal','global_unknown_effect_count'):
        need(value[k] is None,'original unknowns must remain null')
    need(value['retirement_or_execution_authorization'] is False and value['automatic_retry'] is False
         and all(type(value[k]) is int and value[k]==0 for k in ('case_credit','phone_file_writes','ui_calls',
                    'native_submissions','model_requests','signals_other_than_exact_group_membership_query')),
         'read-only observation cannot supply execution or case credit')
    before=value['full_inventory_before'];after=value['full_inventory_after'];old=strict(raw['old_inventory'])
    need(inventory_reader(before)==inventory_reader(after),'both complete raw inventories independently equal')
    inventory_reader(old)
    need(len(old['roots'])==44 and len(old['entries'])==3823 and len(after['roots'])==47
         and len(after['entries'])==3918 and after['file_bytes_hashed']==49087670,'exact observed inventory accounting')
    need(after['roots']==old['roots']+[JOURNAL,HOME,FIXTURE]
         and all(after['entries'].get(k)==v for k,v in old['entries'].items()), 'all old44 full9 originals preserved')
    need(after['entries'][FIXTURE]=={'kind':'absent','absence':'ENOENT'},'original fixture currently absent')
    readset=value['source_and_original_readset'];need(len(readset)==64,'complete original readset')
    files={}
    for row in list(value['current_original_files'].values())+list(value['milestones'].values())+[
        value['failure_original'],value['lifecycle_end_original'],value['supervisor_original']]:
        if row['state']=='ORIGINAL_BYTES_READ':
            data=retained_original(row,after,readset)
            need(row['path'] not in files or files[row['path']]==data,'duplicate capture aliases differ');files[row['path']]=data
        else:explicit_absence(row,after)
    manifest=strict(raw['manifest']);need(pin(raw['manifest'])==PACKAGE and len(manifest['files'])==38,'exact staged package38')
    member_pins={r['path']:{k:r[k] for k in ('bytes','sha256')} for r in manifest['files']}
    for source,member in {'source_common':'source/component_common.py','source_lifecycle':'source/component_lifecycle.py',
         'source_snapshot':'source/component_snapshot.py','source_late':'source/late_boundary.py',
         'source_sender':'source/send_new_native_guard_task_r10_r4.py','source_state_decoder':'reference/decode_client_state.py'}.items():
        need(pin(raw[source])==member_pins[member],'verifier source belongs to the actual staged package')
    for row in manifest['files']:
        p=HOME+'/package/'+row['path'];entry=after['entries'][p]
        need(entry['kind']=='file' and {k:entry[k] for k in ('bytes','sha256')}=={k:row[k] for k in ('bytes','sha256')}
             and readset[p]=={'path':p,**{k:entry[k] for k in ('bytes','sha256','metadata')}},'all38 staged member pins and full9')
    def doc(name):return strict(files[HOME+'/'+name])
    lease=doc('LEASE.json');need(pin(files[HOME+'/LEASE.json'])==LEASE and lease['nonce']==NONCE
         and lease['combination']==COMBINATION and lease['owner_request_sha256']==OWNER
         and lease['package_sha256']==PACKAGE['sha256'] and lease['boot_id']==BOOT,'actual lease and product tuple')
    need(value['started_unix_ms']>lease['expires_unix_ms'] and value['ended_unix_ms']>=value['started_unix_ms'],
         'the consumed original lease is expired; no extension')
    ended=doc('LIFECYCLE-ENDED.json');failure=doc('LIFECYCLE-FAILURE.json');supervisor=doc('SUPERVISOR.json')
    need(failure=={'detail':'bounded target argv','type':'ValueError'} and ended['failure']==failure
         and set(ended['roles'])=={'sidecar'} and ended['roles_joined_and_groups_absent'] is False
         and ended['supervisor_exit_not_yet_independently_observed'] is True
         and ended['native_turn_terminal_verified'] is False,'preserve original failure and incomplete two-role verdict')
    joined=doc('sidecar.JOINED.json')
    need(same(joined,ended['roles']['sidecar']) and joined['identity']==ROLES['sidecar']
         and joined['child_exit_code']==-15 and joined['child_wait_returned'] is True
         and joined['dedicated_process_group_absent'] is True and joined['signals']==['SIGTERM_SYSCALL_RETURNED']
         and joined['automatic_retry'] is False,'actual one spawned child TERM/wait originals')
    need(supervisor['identity']==ROLES['supervisor'] and supervisor['ppid']==1
         and doc('LIFECYCLE-ATTEMPT.json')['identity']==ROLES['supervisor'],'actual detached supervisor generation')
    need(doc('sidecar.SPAWNED.json')['identity']==ROLES['sidecar']
         and doc('sidecar.SPAWNED.json')['pid']==ROLES['sidecar'][0],'actual spawned child generation')
    barrier=doc('sidecar.barrier.json');admit=doc('sidecar.ADMIT.json')
    need(barrier=={'application_not_executed':True,'domain':'u:r:magisk:s0','identity':ROLES['sidecar'],'parent_identity':ROLES['supervisor']}
         and admit=={'identity':ROLES['sidecar'],'lease_sha256':LEASE['sha256'],'parent_identity':ROLES['supervisor'],'role':'sidecar'},
         'actual child barrier and one-use admit')
    need(doc('sidecar.TERM-INTENT.json')=={'automatic_retry':False,'maximum_signal_attempts':1,'signal':'SIGTERM',
         'target_identity':ROLES['sidecar'],'via':'pidfd'},'original single owned signal intent')
    absent=('BOUND-CONTRACT.json','READY.json','ACCEPTED.json','PROVIDER-ENDED.json','SIDECAR-HEALTH.original.json')+tuple(
        'provider.'+s for s in ('SPAWN-INTENT.json','SPAWNED.json','barrier.json','ADMIT.json','TERM-INTENT.json','JOINED.json','stdout','stderr'))
    for name in absent:explicit_absence(value['milestones'][name],after)
    need(after['entries'][HOME+'/claims']['names']==[] and after['entries'][HOME+'/operator']['names']==[]
         and after['entries'][JOURNAL]['names']==['sidecar.stderr','sidecar.stdout'],'actual current claims/operator/executor namespace')
    need(all(files[p]==b'' for p in (JOURNAL+'/sidecar.stdout',JOURNAL+'/sidecar.stderr',HOME+'/supervisor.stdout',HOME+'/supervisor.stderr')),
         'retained actual empty component logs')
    counts=[raw_census(value[k],common) for k in ('census_before','census_after')]
    need(counts==[964,962],'the two actual complete censuses')
    for row in value['original_group_absence_observations']+joined['absence']:
        need(row['kernel_group_absence'] is True and row['members']==[] and type(row['observed_monotonic_ns']) is int,
             'actual kernel group absence observations')
    need(len(value['original_group_absence_observations'])==len(value['endpoint_observations'])==len(joined['absence'])==2,
         'two independent original group/endpoint observations')
    for row in value['endpoint_observations']:raw_endpoints(row,common,raw['source_snapshot'])
    return value,after,lease


def verify_host(raw, lease, decode_state):
    request,streams=controller(raw,'root',job='1a1b5a1a0fe-12894-81',code=1)
    need(streams['stdout']==b'' and len(streams['stderr'])==1235
         and b'component ended before phase' in streams['stderr'],'actual Root failure streams')
    plan=strict(raw['plan']);need(plan['label']==LABEL and plan['nonce']==NONCE and plan['case_id']=='NEG-01'
         and {k:plan['package'][k] for k in ('bytes','sha256')}==PACKAGE
         and plan['request']['sha256']==OWNER,'actual Root plan identity')
    root_manifest=strict(raw['root_manifest'])
    need(pin(raw['root_manifest'])=={k:plan['source_package'][k] for k in ('bytes','sha256')}
         and len(root_manifest['files'])==3,'actual Root source manifest')
    root_row=next(r for r in root_manifest['files'] if r['path']=='source/run_component_root_once.py')
    need(pin(raw['source_root'])=={k:root_row[k] for k in ('bytes','sha256')},'actual original Root source bytes')
    need('--plan' in request['args'] and '--plan-sha256' in request['args']
         and request['args'][request['args'].index('--plan-sha256')+1]==pin(raw['plan'])['sha256'],'actual request pins actual plan')
    root=strict(raw['root_failure']);phases=('prepare-material','host-stage-material','phone-push-material','phone-copy-material',
       'phone-push-stage-source','phone-copy-stage-source','phone-stage','sender-preview','sender-prepared','phone-launch','phone-plan-setup')
    need(tuple(s['phase'] for s in root['steps'])==phases and all(s['state']=='ORIGINAL_HOST_CHILD_JOINED'
         and s['returncode']==0 and s['automatic_retry'] is False for s in root['steps']), 'all11 actual known host phase producers joined')
    need(root['root_fixture_attempts']==[] and root['signals_sent_by_coordinator']==0
         and root['component_qualified'] is False and root['business_qualified'] is False
         and all(root[k] is False for k in ('automatic_retry','new_identity_retry','send_again')),'Root failure facts preserved')
    owned=strict(raw['owned_child']);need(root['host_cleanup']=={'host_children':[owned],'stream_cleanup_errors':[]},'one actual sender cleanup receipt')
    out=owned['output_capture']
    need(owned['child_wait_returned'] is True and owned['returncode']==0 and owned['signals_sent']==0
         and owned['cleanup_errors']==[] and owned['remote_terminal_or_cleanup_proven'] is False
         and out['remote_terminal_or_cleanup_proven'] is False,'host join does not claim remote retirement')
    need(all(out[k] is True for k in ('child_wait_returned','worker_started','worker_joined','stdout_eof','stderr_eof'))
         and out['error'] is None and out['persist_errors']==out['pipe_close_errors']==[]
         and out['prefix_only_or_unknown'] is False,'actual complete sender child capture')
    for n in ('stdout','stderr'):
        need(out['captured'][n]==pin(raw['sender_'+n]) and {k:out['files'][n][k] for k in ('bytes','sha256')}==pin(raw['sender_'+n]),
             'sender raw streams match original owned capture')
    wire=strict(raw['sender_stdout']);actor=strict(wire['stdout'].encode())
    need(wire['rc']==2 and wire['stderr']=='' and raw['sender_stderr']==b''
         and actor['state']=='PRE_SEND_OR_ACTOR_FAILURE' and actor['native_status'] is None
         and actor['send_attempt_count']==0 and actor['prompt_sha256']==OWNER
         and actor['automatic_replay'] is False and actor['business_success_verified'] is False, 'actual no-Send actor failed outcome')
    prepared=strict(raw['prepared']);need(prepared['nonce']==NONCE and prepared['owner_request_sha256']==OWNER
         and prepared['send_attempt_count']==0 and prepared['provider_started_by_sender'] is False
         and prepared['ready_path']==HOME+'/READY.json','original prepared no-Send binding')
    preserved=strict(raw['preserved_draft']);draft=preserved['exact_text'].encode()
    need(hashlib.sha256(draft).hexdigest()==preserved['utf8_sha256'] and preserved['submitted_original_draft'] is False,'exact original private draft')
    effects=[]
    for name,wanted in (('prompt_input',raw['request_text']),('draft_restore',draft)):
        w=strict(raw[name]);need(w['rc']==0 and w['stderr']=='' and w['route']==[5037,'23'],'actual original UI return')
        result=strict(w['stdout'].encode());observed=base64.b64decode(result['readback_text_b64'],validate=True)
        need(observed==wanted and result['requested_utf8_sha256']==result['after_utf8_sha256']==pin(wanted)['sha256']
             and result['action_accepted'] is True and result['action_attempted'] is True
             and result['own_automation_disconnected'] is True, 'complete actual input/restore and exact text return')
        effects.append({'operation':name,'raw_receipt':pin(raw[name]),'returned_utf8':pin(observed)})
    restored=strict(raw['restore_result'])
    need(restored['state']=='ORIGINAL_DRAFT_RESTORED' and restored['restore_attempts']==1
         and restored['original_draft_submitted'] is False and restored['model_business_credit'] is False
         and restored['utf8_sha256']==pin(draft)['sha256']
         and actor['draft_restore']=={k:restored[k] for k in ('state','restore_attempts','original_draft_submitted')},'original exact draft restoration result')
    selected=strict(raw['restore_selected']);need(selected['rc']==0 and selected['stderr']=='','actual selected-state read')
    identity=decode_state(base64.b64decode(b''.join(selected['stdout'].encode().split()),validate=True))
    gate=strict(raw['restore_gate'])['original_wire_receipt'];need(gate['rc']==0 and gate['stderr']=='','actual old-resolution gate read')
    g=strict(gate['stdout'].encode());prior=strict(raw['prior_boundary']);previous=strict(raw['previous']);scope=prior['scope']
    need(pin(raw['prior_boundary'])=={k:lease['prior_boundary'][k] for k in ('bytes','sha256')}
         =={k:plan['prior_boundary_original'][k] for k in ('bytes','sha256')}
         and prior['nonce']!=NONCE,'exact unchanged actual native predecessor original')
    need(pin(raw['previous'])=={k:plan['previous'][k] for k in ('bytes','sha256')}
         and previous['identity']==scope,'actual closed previous identity belongs to this native boundary')
    need(g['global_action_gate_clear'] is True and g['old_request_replay_authorized'] is False
         and identity['session_id']==lease['selected_session_id']==scope['session_id']
         and identity['task_id']==scope['task_id'] and identity['turn_id']==scope['turn_id']
         and identity['turn_request_sha256']==previous['request_sha256'],'actual original selected predecessor remains selected')
    _observation_request,observation_streams=controller(raw,'observer',job='1a1b5c1aa40-12894-e2',code=0)
    need(observation_streams['stderr']==b'','actual read-only observer host stderr')
    return {'known_root_job_terminal':'failed','root_exit_code':1,'known_phase_children_joined':11,
            'sender_host_joined':True,'sender_host_exit_code':0,'actor_exit_code':2,'send_attempt_count':0,
            'root_fixture_attempts':0,'root_coordinator_signals':0,'actual_ui_receipts':effects,
            'original_draft_restored':True,'selected_predecessor_preserved':True,
            'original_root_namespace_anchor':{'path':plan['out']+'/ROOT-FAILURE.json',**pin(raw['root_failure'])},
            'original_remote_cleanup_boolean':False,'global_unknown_effect_count':None}


def verify_retained_preaccept(inputs_raw, *, read_pinned):
    inputs=strict(inputs_raw)
    need(type(EXPECTED_PINS) is dict and inputs.get('schema')=='hepta.r7.retained-preaccept-inputs.v1'
         and set(inputs)=={'schema','files'} and set(inputs['files'])==set(EXPECTED_PINS),'fixed complete original input set')
    raw={}
    for name,desc in inputs['files'].items():
        original_descriptor(desc);need({k:desc[k] for k in ('bytes','sha256')}==EXPECTED_PINS[name],'fixed actual original pin: '+name)
        data=read_pinned(desc);need(pin(data)==EXPECTED_PINS[name],'read actual original bytes: '+name);raw[name]=data
    common,inventory_reader,decode_state=readers(raw)
    observation,inventory,lease=verify_phone(raw,common,inventory_reader)
    host=verify_host(raw,lease,decode_state)
    return {'schema':'hepta.r7.retained-preaccept-verification.v1',
        'state':'ACTUAL_FAILED_PREACCEPT_SPAWNED_SCOPE_RETIRED_ORIGINALS_RETAINED',
        'label':LABEL,'nonce':NONCE,'boot_id':BOOT,'scope_profile':'one_sidecar_preaccept_no_Send',
        'package':PACKAGE,'combination':COMBINATION,'lease':LEASE,
        'component_role_identities':ROLES,'spawned_child_roles':['sidecar'],
        'original_roles_joined_and_groups_absent':False,'supervisor_wait_exit_code':None,
        'supervisor_and_sidecar_generations_absent_twice':True,'current_endpoints_absent_twice':True,
        'original_native_predecessor':lease['prior_boundary'],'capture':CAPTURE,
        'inventory':pin(encoded(inventory)),'inventory_roots':inventory['roots'],
        'private_roots':[HOME,JOURNAL,FIXTURE],'old44_original_entries_preserved':3823,
        'original_files_bookended':64,'named_current_absences_bookended':17,
        'claims_empty':True,'operator_empty':True,'current_executor_names':['sidecar.stderr','sidecar.stdout'],
        'host':host,'original_root_namespace_anchor':host['original_root_namespace_anchor'],
        'original_nonce_consumed':True,'original_lifecycle_attempt_and_ended_preserved':True,
        'native_scope_assigned':False,'native_terminal':None,'native_case_credit':0,
        'component_qualified':False,'business_qualified':False,'four_role_qualification':False,
        'global_unknown_effect_count':None,'historical_argv_predicate_cause':'UNKNOWN',
        'automatic_retry':False,'standalone_execution_authorized':False,
        'original_input_pins':EXPECTED_PINS,'inventory_value':inventory}


def verify_retained_preaccept_archive(descriptor, *, read_pinned):
    """One portable, lossless original archive; no extraction or file writes.

    The host and phone may place the same archive at different canonical paths.
    Every member is still required to match the fixed actual original byte pin.
    Neither the manifest nor a caller supplies an eligibility or credit boolean.
    """
    original_descriptor(descriptor);manifest_raw=read_pinned(descriptor)
    need(pin(manifest_raw)=={k:descriptor[k] for k in ('bytes','sha256')},'retained archive manifest bytes')
    manifest=strict(manifest_raw)
    need(set(manifest)=={'schema','archive','raw_archive'}
         and manifest['schema']=='hepta.r7.retained-preaccept-archive.v1','typed retained archive manifest')
    packed_desc=original_descriptor(manifest['archive']);need(packed_desc['bytes']<=MAX_COMPRESSED,'bounded compressed retained originals')
    packed=read_pinned(packed_desc);need(pin(packed)=={k:packed_desc[k] for k in ('bytes','sha256')},'complete compressed retained archive')
    codec=zlib.decompressobj();archive=codec.decompress(packed,MAX_ORIGINAL+1)
    need(codec.eof and not codec.unused_data and not codec.unconsumed_tail and len(archive)<=MAX_ORIGINAL
         and pin(archive)==manifest['raw_archive'],'single bounded complete retained archive')
    payloads={};inputs={};next_offset=0
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as tf:
        members=tf.getmembers()
        need(len(members)==len(EXPECTED_PINS)
             and [m.name for m in members]==['originals/'+k for k in sorted(EXPECTED_PINS)],'complete canonical retained original member order')
        for member in members:
            name=member.name
            need(name.startswith('originals/') and name.count('/')==1,'flat canonical original member')
            key=name.split('/',1)[1]
            need(key in EXPECTED_PINS and key not in payloads and member.type==tarfile.REGTYPE
                 and member.linkname=='' and member.pax_headers=={} and member.uid==member.gid==member.mtime==0
                 and member.uname==member.gname=='' and member.mode==0o400
                 and member.size==EXPECTED_PINS[key]['bytes'] and member.offset==next_offset
                 and member.offset_data==next_offset+512,'one exact ordinary immutable archive member')
            next_offset+=512+((member.size+511)//512)*512
            stream=tf.extractfile(member);need(stream is not None,'original member contents')
            data=stream.read(MAX_ORIGINAL+1)
            need(pin(data)==EXPECTED_PINS[key],'actual retained original member bytes')
            payloads[key]=data
            inputs[key]={'path':'/retained-r7-preaccept/'+NONCE+'/'+key,**EXPECTED_PINS[key]}
    need(len(archive)==((next_offset+1024+10239)//10240)*10240
         and archive[next_offset:]==bytes(len(archive)-next_offset),'exact complete tar terminator and zero padding')
    need(set(payloads)==set(EXPECTED_PINS),'no omitted original member')
    def supplied(row):
        key=PurePosixPath(row['path']).name
        need(key in inputs and row==inputs[key],'exact in-memory original descriptor')
        return payloads[key]
    result=verify_retained_preaccept(encoded({'schema':'hepta.r7.retained-preaccept-inputs.v1','files':inputs}),read_pinned=supplied)
    result['evidence_archive']={'archive':pin(packed),'raw_archive':pin(archive)}
    result['retained_preaccept_binding']={'schema':'hepta.r7.retained-preaccept-binding.v1',
        **{k:result[k] for k in ('label','nonce','boot_id','package','combination','lease',
           'evidence_archive','inventory','component_role_identities','private_roots','original_native_predecessor')},
        'native_case_credit':0,'component_qualified':False}
    return result


def validate_private_preservation(verified, current_inventory, *, inventory_reader):
    need(verified['schema']=='hepta.r7.retained-preaccept-verification.v1'
         and verified['label']==LABEL and verified['nonce']==NONCE
         and verified['native_case_credit']==0 and verified['standalone_execution_authorized'] is False,
         'exact verified retained preaccept scope')
    inventory_reader(current_inventory);old=verified['inventory_value']
    need(set(old['roots'])<=set(current_inventory['roots']),'retained cumulative roots cannot be dropped')
    for root in (HOME,JOURNAL,FIXTURE):
        before={k:v for k,v in old['entries'].items() if k==root or k.startswith(root+'/')}
        after={k:v for k,v in current_inventory['entries'].items() if k==root or k.startswith(root+'/')}
        need(before==after,'retained R7 private originals changed or gained a file')
    return True
