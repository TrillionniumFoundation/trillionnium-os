#!/usr/bin/env python3
"""Root-reviewed guards/export for one exact forty-four-atom runtime-property live apply.

This module never loads policy. The separately reviewed shell has the sole
magiskpolicy invocation. Importing this module performs no phone reads/writes.
"""
from pathlib import Path
import argparse
import base64
import errno
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time
import types

BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
A=Path('/proc/1/root')
NATIVE_BASE='/data/trillionnium/owner-open/state/phone-local-v150'
CODE=BASE/'policy-runtime-properties-r10-live-code-r1'
D=BASE/'policy-runtime-properties-r10-live-01'
RET=BASE/'module-retire-r9-r2-for-r10-r1-01'
RETCODE=BASE/'module-r10-r1-retirement-code-r1'
MOD=A/'data/adb/modules/trillionnium_hepta_phone_local_v150_r9_r2'
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
CLAIM=A/'data/adb/trillionnium-hepta-phone-local-v150-r9-r2'/BOOT
OLD='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
TOOL='68154a7adabfada7940572f95477885dd6da01ea8b1f3e95abef9495a066382c'
DELTA='fa32d9ae9dfd1f8e9100ebb966a327bf059ed53d307b58be9ed69c8c9b90c1d6'
FULL='424e1c680d37583f039c8cc5e2727200b3f9ad8fd29d35616173a5102b0218d1'
PROBE='d1fe1478ee9699b5a1199aa4c2b96a2a405f7cafd0b5707071cfd2238dbe5df4'
BOUND='607f832e4f1b0904a67e1102c3653543961aa71e55aa7a309cd6911c6234ec61'
RETIREMENT='b139e096969f5a860f5e7cb9e3e988db3d0b2e868528dd4c38b8c9411df4fb90'
RET_PRE='5205cd79b2f117d775c5574c63110b33e9b55f7cb69f5e212e034b8c4e9c9254'
RET_OPERATOR='34c0d883814726ad09a2e94f48f246da3916771ba4d8a3dcd2ba6d6be0ca33e8'
RET_DESCRIPTOR='e3c8411f3d85440018392597d4f9f8795cfd7a60c44fc1680068a60949d20999'
RET_HOST_CLOSURE='14c4bfeb4932067b682cc47b0472f3f2e994cac6ae72a33662ad702b73a4a906'
DISABLE_META='84f327b113269aa1700504641f843ee9213b6705f5b1c54ce34a387949c12e3e'
GATE='23ec1ee206635c0ce0b2dc28ca8281d4e5523d6245eac453b58531c708e1d68e'
ROLES={'supervisor':[12797,12797,12797,12578704],'model':[13191,13191,13191,12579079],
       'sidecar':[14188,14188,14188,12579627],'provider':[15160,15160,15160,12579905]}
RULE=b'allow trillionnium_owner_open_phone_worker build_attestation_prop file getattr\nallow trillionnium_owner_open_phone_worker build_attestation_prop file open\nallow trillionnium_owner_open_phone_worker build_attestation_prop file read\nallow trillionnium_owner_open_phone_worker build_attestation_prop file map\nallow trillionnium_owner_open_phone_worker dalvik_config_prop file getattr\nallow trillionnium_owner_open_phone_worker dalvik_config_prop file open\nallow trillionnium_owner_open_phone_worker dalvik_config_prop file read\nallow trillionnium_owner_open_phone_worker dalvik_config_prop file map\nallow trillionnium_owner_open_phone_worker dalvik_dynamic_config_prop file getattr\nallow trillionnium_owner_open_phone_worker dalvik_dynamic_config_prop file open\nallow trillionnium_owner_open_phone_worker dalvik_dynamic_config_prop file read\nallow trillionnium_owner_open_phone_worker dalvik_dynamic_config_prop file map\nallow trillionnium_owner_open_phone_worker dalvik_runtime_prop file getattr\nallow trillionnium_owner_open_phone_worker dalvik_runtime_prop file open\nallow trillionnium_owner_open_phone_worker dalvik_runtime_prop file read\nallow trillionnium_owner_open_phone_worker dalvik_runtime_prop file map\nallow trillionnium_owner_open_phone_worker default_prop file getattr\nallow trillionnium_owner_open_phone_worker default_prop file open\nallow trillionnium_owner_open_phone_worker default_prop file read\nallow trillionnium_owner_open_phone_worker default_prop file map\nallow trillionnium_owner_open_phone_worker odsign_prop file getattr\nallow trillionnium_owner_open_phone_worker odsign_prop file open\nallow trillionnium_owner_open_phone_worker odsign_prop file read\nallow trillionnium_owner_open_phone_worker odsign_prop file map\nallow trillionnium_owner_open_phone_worker persist_debug_prop file getattr\nallow trillionnium_owner_open_phone_worker persist_debug_prop file open\nallow trillionnium_owner_open_phone_worker persist_debug_prop file read\nallow trillionnium_owner_open_phone_worker persist_debug_prop file map\nallow trillionnium_owner_open_phone_worker qemu_sf_lcd_density_prop file getattr\nallow trillionnium_owner_open_phone_worker qemu_sf_lcd_density_prop file open\nallow trillionnium_owner_open_phone_worker qemu_sf_lcd_density_prop file read\nallow trillionnium_owner_open_phone_worker qemu_sf_lcd_density_prop file map\nallow trillionnium_owner_open_phone_worker radio_prop file getattr\nallow trillionnium_owner_open_phone_worker radio_prop file open\nallow trillionnium_owner_open_phone_worker radio_prop file read\nallow trillionnium_owner_open_phone_worker radio_prop file map\nallow trillionnium_owner_open_phone_worker system_prop file getattr\nallow trillionnium_owner_open_phone_worker system_prop file open\nallow trillionnium_owner_open_phone_worker system_prop file read\nallow trillionnium_owner_open_phone_worker system_prop file map\nallow trillionnium_owner_open_phone_worker vendor_mot_hw_prop file getattr\nallow trillionnium_owner_open_phone_worker vendor_mot_hw_prop file open\nallow trillionnium_owner_open_phone_worker vendor_mot_hw_prop file read\nallow trillionnium_owner_open_phone_worker vendor_mot_hw_prop file map\n'
ARGV=['/data/adb/magisk/magiskpolicy','--live','--apply',NATIVE_BASE+'/'+D.name+'/runtime-properties.delta.rule']
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
RET_PATHS={'proof':(RET/'RETIREMENT.json',37869,RETIREMENT),
 'preflight':(RET/'PREFLIGHT.json',703888,RET_PRE),
 'probe':(RETCODE/'retirement_probe.py',766658,PROBE),
 'bound_inputs':(RETCODE/'BOUND-INPUTS.json',848888,BOUND),
 'disabled_flag':(MOD/'disable',0,hashlib.sha256(b'').hexdigest())}

def need(value,label):
    if not value:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def metadata(s):return [getattr(s,k) for k in META]
def strict(raw):
    def pairs(items):
        value={}
        for k,v in items:need(k not in value,'duplicate JSON key');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def descriptor(raw):return {'bytes':len(raw),'sha256':sha(raw)}
def exact(value,expected):
    need(isinstance(value,dict) and all(k in value and type(value[k]) is type(v) and value[k]==v for k,v in expected.items()),'exact expected fields differ')
def bounded_descriptor(row,with_metadata=False):
    keys={'path','bytes','sha256'}|({'metadata'} if with_metadata else set())
    need(isinstance(row,dict) and set(row)==keys and isinstance(row['path'],str) and Path(row['path']).is_absolute()
         and type(row['bytes']) is int and 0<=row['bytes']<=8*1024*1024
         and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'invalid exact original descriptor')
    if with_metadata:
        m=row['metadata'];need(isinstance(m,list) and len(m)==9 and all(type(x) is int and x>=0 for x in m)
            and m[2]==stat.S_IFREG|0o600 and m[3:6]==[0,0,1] and m[6]==row['bytes'],'private original metadata')

def read(path,limit=8*1024*1024,pin=None,size=None,private=False,expected_metadata=None):
    path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=limit,'bounded regular original: '+str(path))
        if private:need(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600,'private original: '+str(path))
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(limit+1)
        need(len(raw)==s.st_size and metadata(s)==metadata(os.fstat(fd))==metadata(path.lstat()),'original changed: '+str(path))
    finally:os.close(fd)
    need((pin is None or sha(raw)==pin) and (size is None or len(raw)==size),'original byte pin: '+str(path))
    if expected_metadata is not None:need(metadata(s)==expected_metadata,'original metadata pin: '+str(path))
    return raw,metadata(s)
def kernel_read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        raw=bytearray()
        while True:
            part=os.read(fd,min(65536,limit+1-len(raw)))
            if not part:return bytes(raw)
            raw.extend(part);need(len(raw)<=limit,'kernel read bound')
    finally:os.close(fd)
def private_dir(path,canonical=True):
    path=Path(path);s=path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'private directory')
    if canonical:need(path.resolve(strict=True)==path,'noncanonical directory')
    return {'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
def put(name,raw):
    need(re.fullmatch('[A-Za-z0-9_.-]{1,100}',name) and name not in ('.','..'),'output name')
    fd=os.open(D/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    dfd=os.open(D,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(dfd)
    finally:os.close(dfd)
def record(name,value):put(name,encoded(value))


VERIFIER_SHA256 = '30e846ef165e8bc4d602eb5ae945020dd4c1380d9c2aa4dc8e94ab22fbf3517f'
_VERIFIER = None
def V():
    global _VERIFIER
    if _VERIFIER is None:
        need(isinstance(VERIFIER_SHA256,str) and re.fullmatch('[0-9a-f]{64}',VERIFIER_SHA256),
            'the actual reviewed runtime-property verifier is not frozen')
        path=Path(__file__).parent/'policy_runtime_properties_verifier.py'
        raw=read(path,262144,VERIFIER_SHA256)[0]
        module=types.ModuleType('reviewed_runtime_properties_policy_verifier');module.__file__=str(path)
        module.__reviewed_source_sha256__=VERIFIER_SHA256
        exec(compile(raw,str(path),'exec'),module.__dict__);_VERIFIER=module
    return _VERIFIER

def metadata_from_inventory(row):
    need(row.get('kind')=='file','retained lock must be a regular original')
    return row['metadata']

def boundary_summary_identity(value):
    # Monotonic observation time/proc-count varies. The original identity,
    # complete inventory and unchanged-root assertions are compared separately.
    return {k:v for k,v in value.items() if k not in ('absence_observations','endpoints')}

def boundary_modules(binding):
    sys.dont_write_bytecode=True
    names=('component_common','native_proc_profile','component_lifecycle','component_snapshot','late_boundary')
    root=Path(V().PACKAGE_ROOT)
    for path in (root.parent.parent,root.parent,root,root/'source',root/'reference'):private_dir(path)
    package_raw=read(root/'MANIFEST.json',262144,V().PACKAGE['sha256'],V().PACKAGE['bytes'],True)[0]
    need(binding['component_sources']==V().component_source_rows(package_raw),'fixed closed package source set')
    modules={};rows={};supplied={}
    for name,row in binding['component_sources'].items():
        raw,meta=read(row['path'],16*1024*1024,row['sha256'],row['bytes'],True)
        supplied[name]=raw;rows[name]={**row,'metadata':meta}
    for name in names:
        key='source/'+name+'.py';row=rows[key];raw=supplied[key]
        if name in sys.modules:
            module=sys.modules[name]
            need(getattr(module,'__reviewed_source_sha256__',None)==row['sha256']
                and getattr(module,'__file__',None)==row['path']
                and getattr(module,'__reviewed_package_sources__',None)==supplied,
                'unreviewed or differently bound dependency already imported')
        else:
            module=types.ModuleType(name);module.__file__=row['path']
            module.__reviewed_source_sha256__=row['sha256']
            module.__reviewed_package_sources__=supplied
            sys.modules[name]=module
            try:exec(compile(raw,row['path'],'exec'),module.__dict__)
            except BaseException:
                del sys.modules[name];raise
        modules[name]=module
    return modules,rows,supplied

def validate_retirement_descriptor(raw):
    need(len(raw)==2220 and sha(raw)==RET_DESCRIPTOR,'actual Root-frozen retirement descriptor required')
    v=strict(raw);exact(v,{'schema':'hepta.native-guard.retirement-original-input.v1','boot_id':BOOT})
    need(set(v)=={'schema','boot_id','files'} and set(v['files'])==set(RET_PATHS),'complete frozen retirement set')
    for key,(path,n,h) in RET_PATHS.items():
        row=v['files'][key];bounded_descriptor(row,True)
        need(row['path']==str(path) and row['bytes']==n and row['sha256']==h,'fixed current retirement original differs')
    return v

def validate_comparison(raw):
    decision=read(CODE/'ROOT-SCOPE-DECISION.original.json',pin=V().DECISION['sha256'],size=V().DECISION['bytes'],private=True)[0]
    return V().verified_offline(raw,decision)

def validate_binding(raw,retirement_raw,comparison_raw,*,decision_raw,parent_adoption_raw,boundary_descriptor_raw,package_raw):
    validate_retirement_descriptor(retirement_raw)
    return V().validate_binding(raw,decision_raw=decision_raw,comparison_raw=comparison_raw,
        retirement_raw=retirement_raw,parent_adoption_raw=parent_adoption_raw,
        boundary_descriptor_raw=boundary_descriptor_raw,package_raw=package_raw)

def inputs(binding_sha):
    private_dir(BASE);private_dir(CODE)
    raw=read(CODE/'BINDING.json',pin=binding_sha,private=True)[0]
    names={'ACTUAL-RETIREMENT-INPUTS.original.json':V().RETIREMENT_DESCRIPTOR,
        'RETIREMENT-HOST-CLOSURE.original.json':V().RETIREMENT_HOST_CLOSURE,
        'ROOT-SCOPE-DECISION.original.json':V().DECISION,
        'PARENT-ADOPTION-HISTORY.original.json':V().PARENT_ADOPTION,
        'LATEST-BOUNDARY-DESCRIPTOR.original.json':V().BOUNDARY_DESCRIPTOR,
        'CLOSED-COMPONENT-PACKAGE.original.json':V().PACKAGE}
    copies={name:read(CODE/name,pin=row['sha256'],size=row['bytes'],private=True)[0] for name,row in names.items()}
    copies['OFFLINE-COMPLETE-COMPARISON.original.json']=read(CODE/'OFFLINE-COMPLETE-COMPARISON.original.json',private=True)[0]
    v=validate_binding(raw,copies['ACTUAL-RETIREMENT-INPUTS.original.json'],copies['OFFLINE-COMPLETE-COMPARISON.original.json'],
        decision_raw=copies['ROOT-SCOPE-DECISION.original.json'],parent_adoption_raw=copies['PARENT-ADOPTION-HISTORY.original.json'],
        boundary_descriptor_raw=copies['LATEST-BOUNDARY-DESCRIPTOR.original.json'],package_raw=copies['CLOSED-COMPONENT-PACKAGE.original.json'])
    for name,key in (('guard_live_runtime_properties.py','guard_source'),('policy_runtime_properties_verifier.py','verifier_source'),('apply_runtime_properties_once.sh','shell_source')):
        read(CODE/name,pin=v[key]['sha256'],size=v[key]['bytes'],private=True)
    copies['runtime-properties.delta.rule']=read(CODE/'runtime-properties.delta.rule',len(RULE),DELTA,len(RULE),True)[0]
    copies['parent-candidate.rule']=read(CODE/'parent-candidate.rule',V().PARENT_RULE['bytes'],V().PARENT_RULE['sha256'],V().PARENT_RULE['bytes'],True)[0]
    copies['full-candidate.rule']=read(CODE/'full-candidate.rule',V().FULL_RULE['bytes'],V().FULL_RULE['sha256'],V().FULL_RULE['bytes'],True)[0]
    need(copies['runtime-properties.delta.rule']==RULE and copies['full-candidate.rule']==copies['parent-candidate.rule']+RULE,
        'exact forty-four-atom delta and retained parent rule required')
    copies['BINDING.original.json']=raw
    stage_raw=read(CODE/'STAGE-INTENT.json',65536,private=True)[0]
    complete_raw=read(CODE/'STAGE-COMPLETE.json',65536,private=True)[0]
    stage,complete=strict(stage_raw),strict(complete_raw)
    expected={name:descriptor(read(CODE/name,private=True)[0]) for name in (
        'guard_live_runtime_properties.py','policy_runtime_properties_verifier.py','apply_runtime_properties_once.sh','BINDING.json',
        'ROOT-SCOPE-DECISION.original.json','PARENT-ADOPTION-HISTORY.original.json',
        'ACTUAL-RETIREMENT-INPUTS.original.json','RETIREMENT-HOST-CLOSURE.original.json',
        'LATEST-BOUNDARY-DESCRIPTOR.original.json','CLOSED-COMPONENT-PACKAGE.original.json',
        'OFFLINE-COMPLETE-COMPARISON.original.json','runtime-properties.delta.rule','parent-candidate.rule','full-candidate.rule')}
    exact(complete,{'schema':'hepta.runtime-properties-r10.live-code-stage.v1','state':'CREATE_ONLY_CODE_STAGED_NO_POLICY_APPLY',
        'files':expected,'binding_sha256':binding_sha,'stage_identity_sha256':sha(stage_raw),
        'policy_apply_attempts':0,'phone_service_changes':0,'automatic_retry':False})
    exact(stage,{'schema':'hepta.runtime-properties-r10.code-stage-intent.v1','binding_sha256':binding_sha,
        'files':expected,'policy_apply_attempts':0,'automatic_retry':False})
    copies['STAGE-INTENT.original.json']=stage_raw;copies['STAGE-COMPLETE.original.json']=complete_raw
    return v,copies

def environment():
    need(os.getuid()==os.geteuid()==0,'root required')
    need(kernel_read('/proc/self/attr/current',256).rstrip(b'\0\n')==b'u:r:magisk:s0','operator domain')
    need(kernel_read('/proc/sys/kernel/random/boot_id',128).strip().decode()==BOOT,'boot changed')
    need(os.readlink('/proc/1/exe')=='/system/bin/init'
        and kernel_read('/proc/1/attr/current',256).rstrip(b'\0\n')==b'u:r:init:s0','native init view')
    need(kernel_read(A/'sys/fs/selinux/enforce',16) in (b'1',b'1\n'),'not Enforcing')
    read(A/'data/adb/magisk/magiskpolicy',4*1024*1024,TOOL,2630712)

def frozen_module(retirement_raw):
    v=validate_retirement_descriptor(retirement_raw);raws={};rows={}
    private_dir(RET);private_dir(RETCODE);private_dir(MOD,False)
    for key,row in v['files'].items():
        raw,meta=read(row['path'],pin=row['sha256'],size=row['bytes'],private=True,expected_metadata=row['metadata'])
        raws[key]=raw;rows[key]=dict(row)
    m=types.ModuleType('fixed_r9_r2_retirement_readonly');m.__file__=str(RETCODE/'retirement_probe.py')
    exec(compile(raws['probe'],m.__file__,'exec'),m.__dict__)
    need(m.BOUND==strict(raws['bound_inputs']) and {k:list(v) for k,v in m.GROUPS.items()}==ROLES
        and m.BOUND['boot']==BOOT,'frozen retirement definitions differ')
    # No common/preflight/retire/main/write or original_global_gate call on m.
    m.anchors()
    return m,raws,rows

def disabled(row):
    raw,s=read(row['path'],1,row['sha256'],0,True,expected_metadata=row['metadata'])
    read(MOD/'MODULE-MANIFEST-v150-r9-r2.json',262144,
        'd7f276064d32ed6421a9b44e02db9c2374a637828434ec4373417d9235031c58',private=True)
    try:(MOD/'remove').lstat()
    except FileNotFoundError as e:need(e.errno==errno.ENOENT,'remove marker absence')
    else:raise ValueError('old module remove marker exists')
    recorded=read(RET/'DISABLE-METADATA.txt',25,DISABLE_META,25,True)[0].decode().strip()
    current=':'.join(str(x) for x in (s[0],s[1],s[3],s[4],format(stat.S_IMODE(s[2]),'o'),s[5],s[6]))
    need(current==recorded,'original disable inode/metadata differs')
    return {'metadata':s,'bytes':len(raw),'sha256':sha(raw),'old_module_disabled':True}

def retired(raws):
    r=strict(raws['proof']);pre=strict(raws['preflight'])
    opraw=read(RET/'OPERATOR-RESULT.json',4096,RET_OPERATOR,388,True)[0];op=strict(opraw)
    exact(r,{'schema':'hepta.r9-r2-retirement-observation.v1','state':'ORIGINAL_FOUR_GROUPS_ABSENT_STATE_PRESERVED',
        'boot_id':BOOT,'original_role_identities':ROLES,'server_lock_now_unheld':True,'global_pending_clear':True,
        'old_claims_deleted':False,'old_task_terminal_rewritten':False,'model_requests':0,'ui_actions':0,
        'operator_waitpid_join_claim':False,'automatic_restart':False,'automatic_replay':False,'original_effect_count':18})
    exact(op,{'schema':'hepta.r9-r2-retirement-operator.v1','state':'R9_R2_RETIRED_ORIGINALS_PRESERVED',
        'retirement_sha256':RETIREMENT,'supervisor_original_exit_code':143,'original_service_record_count':43,
        'operator_waitpid_join_claim':False,'live_policy_unchanged':True,'new_model_requests':0,'new_task_submissions':0,'automatic_replay':False})
    exact(pre,{'schema':'hepta.r9-r2-retirement-preflight.v1','state':'READY_FOR_DISABLE_AND_ONE_SUPERVISOR_TERM','boot_id':BOOT,'groups':ROLES})
    need(pre['preserved_state']==r['preserved_state'],'retirement preflight state differs')
    checks=r['two_independent_censuses'];need(isinstance(checks,list) and len(checks)==2,'retirement census count')
    for row in checks:
        need(row['members']==[] and row['kernel_group_absence']=={str(v[0]):'ESRCH' for v in ROLES.values()},'retirement groups not absent')
    return r,pre,opraw

def service_originals():
    private_dir(CLAIM,False);private_dir(RET/'original-service')
    tsv,tsvmeta=read(RET/'ORIGINAL-SERVICE-RECORDS.tsv',65536,private=True)
    rows=[];raws={'RETIREMENT-SERVICE-RECORDS.original.tsv':tsv};origins={}
    for line in tsv.decode().splitlines():
        name,meta,pin=line.split('\t');need(re.fullmatch('[A-Za-z0-9_.-]+',name) and name not in ('.','..'),'service name')
        need(name not in {r['name'] for r in rows},'duplicate service record')
        b,s=read(CLAIM/name,262144,pin=pin,private=True)
        copied=read(RET/'original-service'/name,262144,pin,len(b),True)[0]
        observed=':'.join(str(x) for x in (s[0],s[1],s[3],s[4],format(stat.S_IMODE(s[2]),'o'),s[5],s[6],s[7]//10**9,s[8]//10**9))
        need(observed==meta and copied==b,'service original changed')
        rows.append({'name':name,'bytes':len(b),'sha256':pin,'metadata':s,'recorded_metadata':meta})
        fn='service-'+name+'.original';raws[fn]=b;origins[fn]={'path':str(CLAIM/name),'bytes':len(b),'sha256':pin,'metadata':s}
    need(len(rows)==43 and sorted(r['name'] for r in rows)==sorted(p.name for p in CLAIM.iterdir()),'complete service original set differs')
    need({'exit-code','terminal-scope','model.stop','sidecar.stop','provider.stop'}<={r['name'] for r in rows},'service originals incomplete')
    need(read(CLAIM/'exit-code',32,private=True)[0].strip()==b'143','original supervisor exit differs')
    return rows,raws,origins

def quiet(m):
    out=[];groups=[v[0] for v in ROLES.values()]
    for i in range(2):
        row=m.census(groups);need(row['members']==[],'old process/group/session still present')
        row['kernel_group_absence']=m.kernel_absence(groups);out.append(row)
        if i==0:time.sleep(.2)
    return out
def endpoints():
    raw=kernel_read('/proc/net/unix',1048576)
    need(b'hepta_phone_executor_v150_r6' not in raw,'r6 endpoint present')
    values={'unix_sha256':sha(raw)}
    for name in ('tcp','tcp6'):
        data=kernel_read('/proc/net/'+name,1048576);values[name+'_sha256']=sha(data)
        for line in data.splitlines()[1:]:
            f=line.split();need(len(f)>=4,'TCP table shape')
            need(not(f[3]==b'0A' and int(f[1].rsplit(b':',1)[1],16) in (18080,18087)),'owned listener present')
    return {'r6_endpoint_absent':True,'listening_ports_absent':[18080,18087],'table_hashes':values}
def locks(inventory):
    entries=inventory['entries'];paths=sorted(Path(p) for p,r in entries.items()
        if r.get('kind')=='file' and (Path(p).name.endswith('.lock') or Path(p).name=='lock'))
    need(BASE/'executor-r6/server.lock' in paths and 1<=len(paths)<=512,'complete retained lock set differs')
    fds=[];rows=[];held={}
    try:
        for path in paths:
            raw,s=read(path,private=True);row=entries[str(path)]
            need(metadata_from_inventory(row)==s and row['sha256']==sha(raw) and row['bytes']==len(raw),
                'retained lock is not the original inventory file')
            key=tuple(s[:2])
            if key not in held:
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd)
                need(metadata(os.fstat(fd))==s,'lock inode changed')
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);held[key]=(fd,raw,s)
            fd,original,identity=held[key]
            need(raw==original and s==identity and metadata(os.fstat(fd))==s,'lock alias original differs')
            after,after_s=read(path,private=True)
            need(after==raw and after_s==s and metadata(path.lstat())==s,'lock changed')
            rows.append({'path':str(path),'metadata':s,'sha256':sha(raw),'exclusive_nonblocking_acquired':True})
        # All distinct inode locks remain held until every path has been rechecked.
        for path,row in zip(paths,rows):
            fd,original,identity=held[tuple(row['metadata'][:2])]
            after,after_s=read(path,private=True)
            need(after==original and after_s==identity==row['metadata']
                and metadata(os.fstat(fd))==identity and metadata(path.lstat())==identity,
                'retained lock changed during complete alias census')
    finally:
        for fd in fds:os.close(fd)
    return rows
def global_gate(phase):
    path=BASE/'module-r5-activation/activation_original_gate.py';read(path,15700,GATE,15700,True)
    p=subprocess.run(['/usr/bin/python3','-B',str(path),'--check-and-chain'],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
    need(len(p.stdout)<=65536 and len(p.stderr)<=65536,'global gate output bound')
    value={'source_sha256':GATE,'exit_code':p.returncode,'stdout_b64':base64.b64encode(p.stdout).decode(),
        'stderr_b64':base64.b64encode(p.stderr).decode(),'read_only':True}
    record('GLOBAL-GATE-'+phase+'.json',value);need(p.returncode==0,'original global pending gate rejected')
    return value

def proc_identity(pid):
    before=kernel_read('/proc/%d/stat'%pid,65536)
    need(before.startswith(str(pid).encode()+b' (') and b') ' in before,'proc shape')
    f=before.rsplit(b') ',1)[1].split();need(len(f)>=20 and f[0] not in (b'Z',b'X',b'x'),'protected process not live')
    identity=[pid]+[int(f[i]) for i in (2,3,19)]
    exe=os.readlink('/proc/%d/exe'%pid);domain=kernel_read('/proc/%d/attr/current'%pid,256)
    after=kernel_read('/proc/%d/stat'%pid,65536);g=after.rsplit(b') ',1)[1].split()
    need(after.startswith(str(pid).encode()+b' (') and len(g)>=20 and g[0] not in (b'Z',b'X',b'x')
         and identity==[pid]+[int(g[i]) for i in (2,3,19)],'protected process generation changed')
    return {'identity':identity,'exe':exe,'domain_b64':base64.b64encode(domain).decode()}
def protected(m):
    m.anchors();anchors={str(pid):proc_identity(pid) for pid in m.ANCHORS}
    adbd=proc_identity(3021);need(adbd['exe'] in ('/apex/com.android.adbd/bin/adbd','/system/bin/adbd'),'original adbd executable')
    path=A/'data/trillionnium/owner-open/root';s=path.lstat()
    need(stat.S_ISDIR(s.st_mode),'native GNU root directory')
    return {'anchors':anchors,'adbd':adbd,
        'rootfs_directory':{'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)},
        'pid1_mountinfo_sha256':sha(kernel_read('/proc/1/mountinfo',4194304))}
def preserved(binding):
    modules,source_rows,source_raws=boundary_modules(binding)
    C=modules['component_common'];L=modules['late_boundary']
    modules['component_lifecycle'].native_root(BOOT)
    retirement=V().strict(read(CODE/'ACTUAL-RETIREMENT-INPUTS.original.json',private=True)[0])['files']
    chain,originals=L.chain_originals(binding['pre_policy_boundary'],
        combination_sha256=V().COMBINATION_SHA256,package_sha256=V().PACKAGE['sha256'],
        boot_id=BOOT,retirement=retirement)
    need(len(chain)==5 and [b['nonce'] for b,_,_ in chain]==[r['nonce'] for r in V().CLOSED_HISTORY],
        'exact latest08 then07,06,04,03 closed native chain required')
    copies={};origins={}
    for record,(boundary,_inventory,_closure) in zip(V().CLOSED_HISTORY,chain):
        need(boundary['component_qualified'] is False and boundary['native_status']=='provider_failed'
            and boundary['actual_native_calls']==record['actual_native_calls']
            and boundary['package_sha256']==record['package_sha256']
            and boundary['combination_sha256']==record['combination_sha256']
            and boundary['inventory']==record['inventory'] and boundary['closure']==record['closure'],
            'closed historical generation or native credit differs')
        for kind in ('boundary','inventory','closure'):
            row=record[kind];name='closed-'+record['attempt']+'-'+kind.upper()+'.original.json'
            copies[name]=L.original(row);origins[name]=row
    # These three original phone full4 identities are read independently of
    # their same-byte package copies. No second archive copy is introduced.
    side=L.non_native_sidebranch(phone_originals=True)
    need(side['binding']==V().NON_NATIVE_BINDING
        and chain[0][0]['non_native_sidebranch']==side['binding'],
        'fixed non-native05 sidebranch binding changed')
    L.preserve_non_native_private(chain[0][1],side)
    _proof,retired_roles=L.retired_originals(retirement,BOOT)
    component_roles=[role for boundary,_,_ in chain for role in boundary['component_role_identities'].values()]
    component_roles+=list(side['binding']['component_role_identities'].values())
    need(len(component_roles)==len({tuple(r) for r in component_roles})==18,
        'actual native and separate non-native role union differs')
    roles=retired_roles+component_roles
    need(len(roles)==len({tuple(r) for r in roles})==22,'retired and closed component role identities repeat')
    observed=L.current_inventory(chain[0][1]);L.preserve_non_native_private(observed,side)
    absence=[C.absent_groups(roles),C.absent_groups(roles)]
    _tables,ep=modules['component_snapshot'].endpoint_absence()
    L.recheck_originals(originals+list(retirement.values())+side['originals'])
    for name,row in source_rows.items():
        out=V().COMPONENT_SOURCE_MEMBERS[name]
        copies[out]=source_raws[name];origins[out]=row
        again,meta=read(row['path'],16*1024*1024,row['sha256'],row['bytes'],True,row['metadata'])
        need(again==copies[out] and meta==row['metadata'],'closed package raw source changed')
    V().verify_closed_history(copies,read(CODE/'CLOSED-COMPONENT-PACKAGE.original.json',private=True)[0])
    summary={'schema':'hepta.runtime-properties-r10.pre-policy-boundary-verification.v1',
        'state':'EXACT_LATEST08_NATIVE_CHAIN_AND_NON_NATIVE05_ORIGINALS_UNCHANGED',
        'previous_boundary':binding['pre_policy_boundary'],'closed_components':5,
        'inventory_sha256':chain[0][0]['inventory']['sha256'],'roots':observed['roots'],
        'entries':len(observed['entries']),'file_bytes_hashed':observed['file_bytes_hashed'],
        'non_native_sidebranch':side['binding'],'native_case_credit_for_sidebranch':0,
        'component_role_identities':component_roles,'component_source_originals':source_rows,
        'original_retirement_sha256':RETIREMENT,'absence_observations':absence,'endpoints':ep,
        'old_retirement_current_equality_claimed':False,'original_retirement_rewritten':False,
        'phone_tool_calls':0,'model_requests':0,'signals':0,'writes':0}
    return summary,observed,copies,origins

def preflight(binding_sha):
    environment();binding,copies=inputs(binding_sha)
    m,raws,rows=frozen_module(copies['ACTUAL-RETIREMENT-INPUTS.original.json'])
    _r,_original_pre,opraw=retired(raws)
    disable=disabled(rows['disabled_flag']);state,inventory,boundary_copies,boundary_origins=preserved(binding)
    before=kernel_read(A/'sys/fs/selinux/policy',4194304)
    need(descriptor(before)==V().PARENT,'actual kernel-export parent50f differs before reservation')
    protected_before=protected(m);ep=endpoints();ls=locks(inventory)
    service,service_copies,origins=service_originals();copies.update(service_copies)
    copies.update(boundary_copies);origins.update(boundary_origins)
    for key,raw in raws.items():
        name='retirement-'+key+'.original';copies[name]=raw;origins[name]=rows[key]
    copies['RETIREMENT-OPERATOR.original.json']=opraw
    for name,out in (('guard_live_runtime_properties.py','guard_live_runtime_properties.original.py'),
                     ('policy_runtime_properties_verifier.py','policy_runtime_properties_verifier.original.py'),
                     ('apply_runtime_properties_once.sh','apply_runtime_properties_once.original.sh')):
        copies[out]=read(CODE/name,private=True)[0]
    # This new exclusive namespace is outside all retained component roots.
    # Failure consumes it; no path clears the intent or retries the apply.
    D.mkdir(mode=0o700);private_dir(D)
    fd=os.open(BASE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    native=A/NATIVE_BASE.lstrip('/')/D.name
    need((native.stat().st_dev,native.stat().st_ino)==(D.stat().st_dev,D.stat().st_ino),'GNU/native output mapping')
    for name,raw in copies.items():put(name,raw)
    put('live-policy-before.bin',before);record('ORIGINAL-SOURCE-PATHS.json',origins)
    gate=global_gate('pre')
    pre={'schema':'hepta.runtime-properties-r10.live-precheck.v1','state':'LATEST_CLOSED_BOUNDARY_VERIFIED_FOR_SINGLE_APPLY',
        'binding_sha256':binding_sha,'boot_id':BOOT,'disable':disable,'retirement_files':rows,
        'pre_policy_boundary_verification':state,'protected_state':protected_before,'service_records':service,
        'endpoints':ep,'locks':ls,'global_gate':gate,'parent_policy':descriptor(before),'approved_rule':descriptor(RULE),
        'root_scope_decision':V().DECISION,'complete_offline_comparison':binding['complete_offline_comparison'],
        'observed_monotonic_ns':time.monotonic_ns(),'policy_apply_attempts':0,
        'automatic_retry':False,'automatic_rollback':False}
    record('PRECHECK.json',pre)
    environment();need(protected(m)==protected_before,'protected state changed before intent')
    need(kernel_read(A/'sys/fs/selinux/policy',4194304)==before,'parent changed before intent')
    need(disabled(rows['disabled_flag'])==disable,'disable changed before intent')
    state2,inventory2,_copies,_origins=preserved(binding)
    need(boundary_summary_identity(state2)==boundary_summary_identity(state),'closed original boundary changed before intent')
    endpoints();locks(inventory2);read(D/'runtime-properties.delta.rule',len(RULE),DELTA,len(RULE),True)
    for name in ('policy.stdout','policy.stderr'):put(name,b'')
    record('APPLY-INTENT.json',{'schema':'hepta.runtime-properties-r10.single-apply-intent.v1','binding_sha256':binding_sha,
        'precheck_sha256':sha(encoded(pre)),'argv':ARGV,'root_scope_decision_sha256':V().DECISION['sha256'],
        'pre_policy_boundary_sha256':V().BOUNDARY['sha256'],'maximum_apply_attempts':1,
        'apply_timeout_seconds':45,'kill_grace_seconds':5,'issued_monotonic_ns':time.monotonic_ns(),
        'automatic_retry':False,'automatic_rollback':False,'automatic_policy_adoption':False})
    return 0

def export_originals(binding_sha):
    private_dir(D)
    need(not (D/'CAPTURE.json').exists() and not (D/'ORIGINALS.tar.gz').exists(),'original export namespace already consumed')
    names=sorted(p.name for p in D.iterdir());need(15<=len(names)<=112,'bounded original file count')
    files={};rows=[];total=0
    for name in names:
        need(re.fullmatch('[A-Za-z0-9_.-]{1,100}',name),'original export name')
        raw,meta=read(D/name,8*1024*1024,private=True);total+=len(raw);need(total<=24*1024*1024,'original export total bound')
        files[name]=raw;rows.append({'path':name,'original_path':str(D/name),'bytes':len(raw),'sha256':sha(raw),'metadata':meta})
    V().check_capture_members(files,allow_failed=True)
    capture={'schema':'hepta.runtime-properties-r10.live-original-capture.v1','state':'CAPTURED_EXISTING_APPLY_ORIGINALS',
        'binding_sha256':binding_sha,'files':rows,'total_bytes':total,'file_count':len(rows),
        'new_effects':0,'policy_adoption_authorized':False,'business_qualified':False}
    capraw=encoded(capture);put('CAPTURE.json',capraw);files['CAPTURE.json']=capraw
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as tf:
        for name,raw in sorted(files.items()):
            info=tarfile.TarInfo(name);info.size=len(raw);info.mode=0o600;info.uid=info.gid=0;info.mtime=0
            tf.addfile(info,io.BytesIO(raw))
    archive=gzip.compress(stream.getvalue(),mtime=0);need(len(archive)<=8*1024*1024,'compressed export bound')
    put('ORIGINALS.tar.gz',archive)
    for row in rows:read(D/row['path'],pin=row['sha256'],size=row['bytes'],private=True,expected_metadata=row['metadata'])
    result={'schema':'hepta.runtime-properties-r10.live-original-export.v1','state':'ORIGINAL_EXPORT_COMPLETE',
        'binding_sha256':binding_sha,'capture':descriptor(capraw),'archive':{'path':str(D/'ORIGINALS.tar.gz'),**descriptor(archive)},
        'files':len(files),'original_bytes':total,'automatic_retry':False,'policy_adoption_authorized':False,
        'business_qualified':False,'inline_archive':len(archive)<=1200000,'read_chunk_bytes':524288}
    record('EXPORT.json',result)
    if result['inline_archive']:result['archive_gzip_base64']=base64.b64encode(archive).decode()
    else:result['archive_gzip_base64']=None
    need(len(json.dumps(result,separators=(',',':')).encode())<1800000,'phone output bound')
    return result

def postflight(binding_sha,rc):
    private_dir(D);need(type(rc) is int and 0<=rc<=255,'actual command return code')
    binding,copies=inputs(binding_sha);pre_raw=read(D/'PRECHECK.json',private=True)[0];pre=strict(pre_raw)
    intent=read(D/'APPLY-INTENT.json',private=True)[0]
    exact(pre,{'schema':'hepta.runtime-properties-r10.live-precheck.v1','state':'LATEST_CLOSED_BOUNDARY_VERIFIED_FOR_SINGLE_APPLY',
        'binding_sha256':binding_sha,'boot_id':BOOT,'policy_apply_attempts':0,'automatic_retry':False,'automatic_rollback':False})
    exact(strict(intent),{'schema':'hepta.runtime-properties-r10.single-apply-intent.v1','binding_sha256':binding_sha,
        'precheck_sha256':sha(pre_raw),'argv':ARGV,'maximum_apply_attempts':1,
        'root_scope_decision_sha256':V().DECISION['sha256'],'pre_policy_boundary_sha256':V().BOUNDARY['sha256'],
        'apply_timeout_seconds':45,'kill_grace_seconds':5,'automatic_retry':False,
        'automatic_rollback':False,'automatic_policy_adoption':False})
    record('COMMAND-RETURN.json',{'schema':'hepta.runtime-properties-r10.actual-command-return.v1','return_code':rc,
        'argv':ARGV,'binding_sha256':binding_sha,'apply_attempts':1,'maximum_apply_attempts':1,
        'apply_timeout_seconds':45,'kill_grace_seconds':5,'automatic_retry':False,'automatic_rollback':False,
        'observed_monotonic_ns':time.monotonic_ns()})
    live=kernel_read(A/'sys/fs/selinux/policy',4194304);put('live-policy-after.bin',live)
    out=read(D/'policy.stdout',1048576,private=True)[0];err=read(D/'policy.stderr',1048576,private=True)[0]
    before=read(D/'live-policy-before.bin',4194304,OLD,V().PARENT['bytes'],True)[0]
    error=None;post={}
    try:
        environment();m,raws,rows=frozen_module(copies['ACTUAL-RETIREMENT-INPUTS.original.json'])
        retired(raws);need(disabled(rows['disabled_flag'])==pre['disable'],'disable changed')
        state,inventory,_copies,_origins=preserved(binding)
        need(boundary_summary_identity(state)==boundary_summary_identity(pre['pre_policy_boundary_verification']),
            'latest closed original state changed after apply')
        need(protected(m)==pre['protected_state'],'UI/adbd/rootfs/mount identity changed')
        service,_,_=service_originals();need(service==pre['service_records'],'original service records changed')
        gate=global_gate('post')
        post={'pre_policy_boundary_verification':state,'endpoints':endpoints(),'locks':locks(inventory),
            'global_gate':gate,'complete_original_state_equal':True,'complete_service_records_equal':True,
            'original_UI_adbd_rootfs_mounts_preserved':True,'old_module_disabled':True,
            'old_retirement_current_equality_claimed':False}
        read(D/'runtime-properties.delta.rule',len(RULE),DELTA,len(RULE),True)
        read(D/'full-candidate.rule',V().FULL_RULE['bytes'],V().FULL_RULE['sha256'],V().FULL_RULE['bytes'],True)
    except BaseException as e:error={'type':type(e).__name__,'message':str(e),'automatic_retry':False}
    enforce=kernel_read(A/'sys/fs/selinux/enforce',16);boot=kernel_read('/proc/sys/kernel/random/boot_id',128).strip().decode()
    report={'schema':'hepta.runtime-properties-r10.actual-live-apply.v1','state':'ACTUAL_SINGLE_APPLY_REQUIRES_INDEPENDENT_LIVE_COMPARISON',
        'binding_sha256':binding_sha,'return_code':rc,'apply_attempts':1,'maximum_apply_attempts':1,
        'argv':ARGV,'apply_timeout_seconds':45,'kill_grace_seconds':5,'parent_policy':descriptor(before),
        'actual_live_policy':descriptor(live),'approved_rule_atoms':V().ATOMS,'delta_rule':descriptor(RULE),
        'full_rule':V().FULL_RULE,'offline_candidate':binding['offline_candidate'],
        'root_scope_decision':V().DECISION,'pre_policy_boundary':V().BOUNDARY,
        'complete_offline_comparison':binding['complete_offline_comparison'],'actual_parser_sha256':TOOL,
        'live_bytes_equal_offline_candidate':descriptor(live)==binding['offline_candidate'],
        'boot_id':boot,'enforcing':enforce in (b'1',b'1\n'),'stdout':descriptor(out),'stderr':descriptor(err),
        'precheck_sha256':sha(pre_raw),'intent_sha256':sha(intent),'postchecks':post,'postcheck_error':error,
        'automatic_retry':False,'automatic_rollback':False,'policy_adoption_authorized':False,
        'independent_live_complete_comparison_required':True,'service_start_admitted':False,
        'model_requests':0,'task_submissions':0,'ui_actions':0,'service_starts':0,'service_stops':0,'business_qualified':False}
    report['clean_apply_observed']=rc==0 and out==err==b'' and report['enforcing'] and boot==BOOT and error is None and sha(live)!=OLD
    record('POLICY-APPLY.json',report);export=export_originals(binding_sha)
    print(json.dumps({'report':report,'export':export},sort_keys=True,separators=(',',':')))
    return 0 if report['clean_apply_observed'] else 2

def export_chunk(binding_sha,index):
    private_dir(D);need(type(index) is int and 0<=index<16,'chunk index bound')
    e=strict(read(D/'EXPORT.json',262144,private=True)[0]);need(e['binding_sha256']==binding_sha,'export binding')
    archive,meta=read(D/'ORIGINALS.tar.gz',8*1024*1024,e['archive']['sha256'],e['archive']['bytes'],True)
    offset=index*524288;need(offset<len(archive),'chunk beyond original archive')
    chunk=archive[offset:offset+524288]
    print(json.dumps({'schema':'hepta.runtime-properties-r10.original-export-chunk.v1','binding_sha256':binding_sha,
        'archive':e['archive'],'index':index,'offset':offset,'bytes':len(chunk),'sha256':sha(chunk),
        'base64':base64.b64encode(chunk).decode(),'source_metadata':meta,'phone_writes':0,'apply_attempts':0},sort_keys=True))
    return 0

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binding-sha256',required=True)
    g=p.add_mutually_exclusive_group();g.add_argument('--preflight-once',action='store_true');g.add_argument('--postflight-once',type=int)
    g.add_argument('--export-chunk-read-only',type=int)
    a=p.parse_args(argv);need(re.fullmatch('[0-9a-f]{64}',a.binding_sha256),'binding hash')
    if not a.preflight_once and a.postflight_once is None and a.export_chunk_read_only is None:
        print(json.dumps({'state':'PREVIEW_NO_PHONE_READ_NO_APPLY','policy_apply_attempts':0}));return 0
    os.umask(0o077)
    def expired(*_):raise TimeoutError('bounded read-only guard deadline')
    signal.signal(signal.SIGALRM,expired);signal.alarm(70)
    try:
        if a.preflight_once:return preflight(a.binding_sha256)
        if a.postflight_once is not None:return postflight(a.binding_sha256,a.postflight_once)
        return export_chunk(a.binding_sha256,a.export_chunk_read_only)
    finally:signal.alarm(0)

if __name__=='__main__':raise SystemExit(main())
