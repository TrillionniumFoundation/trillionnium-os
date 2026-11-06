#!/usr/bin/env python3
"""Explicit isolated-component readiness for a versioned sender derivation.

This helper never opens the provider socket, starts a role or submits a task.
Its contract is selected by Root together with an independently reviewed
adapter package hash. It does not accept the historical fixed printf contract.
"""
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: need(False, 'nonfinite JSON'))


def private_read(path, maximum):
    path = Path(path)
    need(path.is_absolute() and path.parent.resolve() == path.parent, 'canonical private parent required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_uid == os.getuid()
             and not a.st_mode & 0o077 and a.st_size <= maximum, 'private file identity differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        b = os.fstat(fd); c = path.lstat()
        names = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(raw) == a.st_size and all(getattr(a,k) == getattr(b,k) == getattr(c,k) for k in names),
             'private original changed during read')
        return raw
    finally:
        os.close(fd)


def validate_contract(c):
    need(isinstance(c,dict) and set(c) == {'schema','label','nonce','case_id','boot_id',
        'owner_request_sha256','selected_session_id','selected_profile_id','expires_unix_ms',
        'package_sha256','lease_sha256','combination_sha256'}
        and c['schema'] == 'hepta.native-guard.sender-contract.v1'
        and c['case_id'] in ('NEG-01','NEG-02'), 'explicit native guard sender contract required')
    need(isinstance(c['label'],str) and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',c['label'])
         and re.fullmatch('[0-9a-f]{32}',c['nonce'])
         and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',c['boot_id']),
         'component lease identity shape')
    for key in ('owner_request_sha256','package_sha256','lease_sha256','combination_sha256'):
        need(isinstance(c[key],str) and re.fullmatch('[0-9a-f]{64}',c[key]), 'component exact byte hash required')
    for key in ('selected_session_id','selected_profile_id'):
        need(isinstance(c[key],str) and 0 < len(c[key].encode()) <= 256 and '\0' not in c[key],
             'selected native session/profile required')
    need(type(c['expires_unix_ms']) is int and c['expires_unix_ms'] > 0, 'explicit fixed lease expiry required')
    return c


def binding(contract_path, owner_bytes, identity, package_path, package_sha256):
    raw = private_read(Path(contract_path).absolute(), 16384)
    c = validate_contract(strict(raw))
    need(isinstance(owner_bytes,bytes) and sha(owner_bytes) == c['owner_request_sha256']
         and owner_bytes.decode().count(c['nonce']) == 1, 'exact Root owner request differs')
    need(c['selected_session_id'] == identity['session_id'] and c['selected_profile_id'] == identity['profile_id'],
         'original selected session/profile differs')
    manifest_path = Path(package_path).absolute()
    manifest_raw = private_read(manifest_path,262144)
    need(sha(manifest_raw) == package_sha256 == c['package_sha256'], 'explicit reviewed adapter package pin differs')
    manifest = strict(manifest_raw)
    need(manifest.get('schema') == 'hepta.native-guard.adapter-package.v1'
         and manifest.get('state') == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED', 'component package type differs')
    rows = manifest['files']; names = [r['path'] for r in rows]
    need(len(names) == len(set(names)) and 5 <= len(names) <= 32, 'component package inventory bound')
    index = {}
    for row in rows:
        relative = Path(row['path'])
        need(str(relative) == row['path'] and not relative.is_absolute() and '..' not in relative.parts,
             'canonical package path required')
        data = private_read(manifest_path.parent / relative,8*1024*1024)
        need(len(data) == row['bytes'] and sha(data) == row['sha256'], 'component package member differs')
        index[row['path']] = row
    helper = index['source/sender_native_guard_ready_r10_r4.py']
    need(helper['sha256'] == sha(Path(__file__).read_bytes()), 'selected package does not contain this exact readiness helper')
    home = '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/' + c['label']
    return {'schema':'hepta.native-guard.sender-binding.v1','contract':c,'contract_sha256':sha(raw),
        'contract_bytes':len(raw),'contract_original_b64':base64.b64encode(raw).decode(),
        'source_sha256':index['source/component_listener.py']['sha256'],
        'common_pin':{k:index['source/component_common.py'][k] for k in ('bytes','sha256')},
        'lifecycle_pin':{k:index['source/component_lifecycle.py'][k] for k in ('bytes','sha256')},
        'phone_home':home,'phone_contract_path':home+'/sender-contract.json',
        'phone_ready_path':home+'/READY.json','phone_source_path':home+'/package/source/component_listener.py'}


def validate_ready_observation(value, binding, previous=None, minimum_remaining_ns=15000000000):
    import base64,hashlib,json,re
    def check(ok, why):
        if not ok:
            raise ValueError(why)
    def digest(raw):
        return hashlib.sha256(raw).hexdigest()
    def original(key, parsed):
        raw = base64.b64decode(value[key+'_original_b64'],validate=True)
        check(digest(raw) == value[key+'_sha256'] and json.loads(raw) == parsed, 'original readiness bytes differ')
        return raw
    c = binding['contract']; r = value.get('ready',{}); b = value.get('bound',{}); roles = value.get('current_roles',{})
    check(value.get('schema') == 'hepta.native-guard.readiness-observation.v1'
          and value.get('state') == 'ready_observed', 'component readiness not observed')
    check(value.get('contract_sha256') == binding['contract_sha256']
          and value.get('provider_source_sha256') == binding['source_sha256']
          and value.get('package_sha256') == c['package_sha256'] and value.get('boot_id') == c['boot_id'],
          'component input pins or boot differ')
    original('ready',r);original('bound',b)
    combo = value.get('combination',{})
    original('combination',combo)
    check(value['combination_sha256'] == c['combination_sha256']
          and combo.get('schema') == 'hepta.native-guard.component-combination.v150.r10.1'
          and combo.get('state') == 'REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY',
          'original component combination differs')
    check(r.get('schema') == 'hepta.native-guard.ready.v1'
          and r.get('lease_sha256') == c['lease_sha256'] and r.get('combination_sha256') == c['combination_sha256']
          and r.get('provider_source_sha256') == binding['source_sha256'] and r.get('port') == 18080
          and r.get('accepting_one_session') is True and r.get('model_requests') == 0
          and r.get('readiness_scope') == 'isolated_component_transport_only' and r.get('four_role_ready') is False,
          'component ready original contract differs')
    bc = b.get('contract',{})
    check(b.get('schema') == 'hepta.native-guard.bound-contract.v1' and b.get('lease_sha256') == c['lease_sha256']
          and b.get('provider_source_sha256') == binding['source_sha256']
          and set(bc) == {'schema','case_id','nonce','owner_request_sha256','selected_session_id','selected_profile_id',
                         'source_seal_sha256','configuration_sha256','executor_server_instance'}
          and bc.get('schema') == 'hepta.native-guard-component.contract.v150.r10.1'
          and bc.get('source_seal_sha256') == combo.get('source_seal',{}).get('sha256')
          and bc.get('configuration_sha256') == combo.get('configuration',{}).get('sha256')
          and all(bc.get(k) == c[k] for k in ('case_id','nonce','owner_request_sha256','selected_session_id','selected_profile_id')),
          'actual native component contract differs')
    canonical = (json.dumps(bc,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    check(digest(canonical) == r['contract_sha256'] and re.fullmatch('[0-9a-f]{32}',bc.get('executor_server_instance','')),
          'actual bound kernel contract bytes or executor instance differ')
    check(set(roles) == {'supervisor','provider','sidecar'} and roles['provider'] == r['identity']
          and roles['sidecar'] == b['sidecar_identity'] and roles['supervisor'] == value.get('supervisor'),
          'actual live process identity differs')
    original('supervisor',value['supervisor'])
    for name,row in roles.items():
        ident = row.get('identity',[])
        check(len(ident) == 4 and all(type(x) is int and x > 1 for x in ident)
              and ident[:3] == [ident[0]]*3 and row.get('uid') == row.get('gid') == [0]*4 and row.get('nnp') == 0,
              'owned role process identity/credentials differ')
        domain = 'u:r:trillionnium_owner_open_phone_executor:s0' if name == 'sidecar' else 'u:r:magisk:s0'
        check(row.get('domain') == domain, 'owned role security domain differs')
    check(roles['provider']['ppid'] == roles['sidecar']['ppid'] == roles['supervisor']['identity'][0],
          'owned component parent changed')
    health = b.get('sidecar_health',{})
    check(health.get('executor_revision') == 6 and health.get('state') == 'ready'
          and health.get('server_instance') == bc['executor_server_instance']
          and health.get('execute_authorized') is False and health.get('inference_endpoint') is False,
          'component parent readiness is not read-only')
    check(value.get('claim_absent') is True and value.get('connection_absent') is True
          and value.get('ended_absent') is True and value.get('retirement_originals_bound') is True
          and value.get('old_groups_absent') is True and value.get('socket_connections') == 0,
          'component consumed, ended or original retirement not verified')
    times = [r.get(k) for k in ('ready_monotonic_ns','accept_deadline_monotonic_ns','service_deadline_monotonic_ns')]
    now,wall = value.get('phone_monotonic_ns'),value.get('phone_unix_ms')
    check(all(type(x) is int and x > 0 for x in times+[now,wall]), 'phone clock shape differs')
    ready,accept,service = times
    check(ready <= now < accept < service and accept-ready == 120000000000
          and service-ready == 420000000000, 'component windows changed')
    check(accept-now >= minimum_remaining_ns and value.get('remaining_accept_ns') == accept-now
          and c['expires_unix_ms']-wall >= minimum_remaining_ns//1000000, 'component acceptance margin expired')
    if previous is not None:
        check(value['ready_sha256'] == previous['ready_sha256']
              and value['bound_sha256'] == previous['bound_sha256']
              and value['current_roles'] == previous['current_roles'], 'component readiness generation changed')
    return value


VALIDATOR_SOURCE = inspect.getsource(validate_ready_observation)

PHONE_SOURCE = r'''
import base64,hashlib,json,os,stat,sys,time,types
from pathlib import Path
sys.dont_write_bytecode=True
B=__BOUND__
def need(ok,why):
 if not ok:raise ValueError(why)
def initial_read(path,maximum):
 path=Path(path)
 need(path.is_absolute() and path.parent.resolve()==path.parent,'canonical GNU package parent')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd)
  need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=maximum,'private bootstrap source identity')
  with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maximum+1)
  after=os.fstat(fd);named=path.lstat()
  names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(named,k) for k in names),'bootstrap source changed')
  return raw
 finally:os.close(fd)
home=Path(B['phone_home']);c=B['contract'];cp=home/'package/source/component_common.py'
raw=initial_read(cp,262144)
need(len(raw)==B['common_pin']['bytes'] and hashlib.sha256(raw).hexdigest()==B['common_pin']['sha256'],'pinned common source differs')
C=types.ModuleType('component_common');C.__file__=str(cp);sys.modules['component_common']=C
exec(compile(raw,str(cp),'exec'),C.__dict__)
manifest=C.verify_package(home/'package/MANIFEST.json',c['package_sha256'])
profile_path=home/'package/source/native_proc_profile.py'
profile_rows=[row for row in manifest['files'] if row['path']=='source/native_proc_profile.py']
need(len(profile_rows)==1 and 'native_proc_profile' not in sys.modules,'one fresh pinned native proc profile required')
profile_raw=C.pinned(profile_path,{key:profile_rows[0][key] for key in ('bytes','sha256')})
profile=types.ModuleType('native_proc_profile');profile.__file__=str(profile_path)
sys.modules['native_proc_profile']=profile
exec(compile(profile_raw,str(profile_path),'exec'),profile.__dict__)
L=C.import_pinned(home/'package/source/component_lifecycle.py',B['lifecycle_pin'],'sender_readonly_lifecycle')
lease,lease_raw=L.load_lease(home,c['lease_sha256']);L.native_root(c['boot_id'])
need(all(lease[k]==c[k] for k in ('label','nonce','case_id','boot_id','owner_request_sha256','selected_session_id','selected_profile_id','expires_unix_ms','package_sha256')) and lease['combination']['sha256']==c['combination_sha256'],'phone lease differs from selected Root contract')
need(C.read(home/'sender-contract.json')==base64.b64decode(B['contract_original_b64'],validate=True),'original sender contract differs')
combo_raw=C.pinned(home/'inputs/COMBINATION.json',lease['combination'])
combo,_=C.load_combination(home/'inputs',combo_raw,C.strict(C.read(home/'package/reference/REVIEWED-PRODUCTION-PINS.json')))
C.verify_external(combo)
for name,pin in lease['retirement'].items():
 path=Path(pin['path']);C.pinned(path,{k:pin[k] for k in ('bytes','sha256')},16*1024*1024)
 need(C.metadata(path.lstat())==pin['metadata'],'original retirement identity differs')
proof=C.strict(C.read(Path(lease['retirement']['proof']['path']),16*1024*1024))
need(proof['state']=='ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED','original retirement state differs')
C.absent_groups(list(proof['original_role_identities'].values()))
need(not list(C.private_dir(home/'claims').iterdir()),'component one-use claim already exists')
for name in ('CONNECTION-ACCEPTED.json','ACCEPTED.json','PROVIDER-ENDED.json','LIFECYCLE-ENDED.json','LIFECYCLE-FAILURE.json'):
 try:(home/name).lstat()
 except FileNotFoundError:pass
 else:need(False,'component already consumed or ended')
try:ready_raw=C.read(home/'READY.json',65536)
except FileNotFoundError:
 print(json.dumps({'state':'waiting_for_ready','contract_sha256':B['contract_sha256'],'nonce':c['nonce'],'owner_request_sha256':c['owner_request_sha256'],'claim_absent':True,'ended_absent':True},separators=(',',':')))
 raise SystemExit(0)
ready=C.strict(ready_raw);bound_raw=C.read(home/'BOUND-CONTRACT.json',65536);bound=C.strict(bound_raw)
supervisor_raw=C.read(home/'SUPERVISOR.json',16384);supervisor=C.strict(supervisor_raw)
roles={name:C.target_identity(row['identity'][0],row['identity']) for name,row in [('provider',ready['identity']),('sidecar',bound['sidecar_identity']),('supervisor',supervisor)]}
python=combo['artifacts']['python']['path']
super_argv=[python,'-I','-B',str(home/'package/source/component_lifecycle.py'),'--lease',str(home),'--lease-sha256',c['lease_sha256'],'--package',str(home/'package/MANIFEST.json'),'--package-sha256',c['package_sha256'],'--execute-component-lifecycle-once']
spawn=C.strict(C.read(home/'provider.SPAWNED.json',65536));argv=spawn['argv'];need(argv[-2]=='--listener-fd' and argv[-1].isdigit(),'original provider listener fd absent')
provider_argv=[python,'-I','-B',str(home/'package/source/component_listener.py'),'--package',str(home/'package/MANIFEST.json'),'--package-sha256',c['package_sha256'],'--lease',str(home),'--lease-sha256',c['lease_sha256'],'--listener-fd',argv[-1],'--execute-native-listener-once']
sidecar_argv=[C.SIDECAR,'--state-dir',lease['android_journal']]
for name,wanted in [('supervisor',super_argv),('provider',provider_argv),('sidecar',sidecar_argv)]:
 actual=base64.b64decode(roles[name]['argv_b64'],validate=True)
 need(actual==b'\0'.join(x.encode() for x in wanted)+b'\0' and roles[name]['argv_sha256']==C.sha(actual),'actual owned role argv differs')
 need(roles[name]['exe']==(C.SIDECAR if name=='sidecar' else python),'actual owned role executable differs')
now=time.monotonic_ns();wall=time.time_ns()//1000000
value={'schema':'hepta.native-guard.readiness-observation.v1','state':'ready_observed','contract_sha256':B['contract_sha256'],'provider_source_sha256':B['source_sha256'],'package_sha256':c['package_sha256'],'boot_id':c['boot_id'],'ready':ready,'ready_sha256':C.sha(ready_raw),'ready_original_b64':base64.b64encode(ready_raw).decode(),'bound':bound,'bound_sha256':C.sha(bound_raw),'bound_original_b64':base64.b64encode(bound_raw).decode(),'supervisor':supervisor,'supervisor_sha256':C.sha(supervisor_raw),'supervisor_original_b64':base64.b64encode(supervisor_raw).decode(),'current_roles':roles,'combination':combo,'combination_sha256':C.sha(combo_raw),'combination_original_b64':base64.b64encode(combo_raw).decode(),'claim_absent':True,'connection_absent':True,'ended_absent':True,'retirement_originals_bound':True,'old_groups_absent':True,'socket_connections':0,'phone_monotonic_ns':now,'phone_unix_ms':wall,'remaining_accept_ns':ready['accept_deadline_monotonic_ns']-now}
__VALIDATOR__
validate_ready_observation(value,B)
need(C.read(home/'READY.json',65536)==ready_raw and C.read(home/'BOUND-CONTRACT.json',65536)==bound_raw,'ready originals changed after process read')
print(json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False))
'''


def phone_probe(bound):
    validate_contract(bound['contract'])
    return PHONE_SOURCE.replace('__BOUND__',repr(bound)).replace('__VALIDATOR__',VALIDATOR_SOURCE)
