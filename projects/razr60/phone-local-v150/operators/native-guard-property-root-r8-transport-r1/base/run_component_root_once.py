#!/usr/bin/env python3
# PUBLIC PROJECTION: required private bindings removed; review and host tests only.
# Not an installable package. Original None execution guards remain in place.
"""Root-only one-identity orchestration of the frozen native-guard package.

Default is a host preview. No nonce is generated. The 600-second lease is
fixed only after explicit execution starts. Any unknown/failure stops without
replay, extension, second Send, or signalling an unknown process.
"""
import argparse
import ast
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import time
import types

B=Path('/REQUIRED_PRIVATE_WORKSPACE')
G='/REQUIRED_PHONE_GUEST_STATE_ROOT'
N='/REQUIRED_PHONE_NATIVE_STATE_ROOT'
BOOT='REQUIRED_DEVICE_BOOT_ID'
PKG=None  # Frozen only after actual new-policy adoption and runtime source review.
COMBINATION=None
VERIFIER_SHA=None
VERIFIER_BYTES=None
POLICY_SHA=None
ADOPTION_SHA=None
ROOT_SCOPE_SHA=None
SENDER='REQUIRED_SENDER_SOURCE_SHA256'
READY_HELPER='REQUIRED_READY_HELPER_SOURCE_SHA256'
ACTOR='REQUIRED_ACTOR_SOURCE_SHA256'
RET='REQUIRED_RETIREMENT_DESCRIPTOR_SHA256'
SHARED='REQUIRED_SHARED_MATERIALS_SHA256'
CONFIG='REQUIRED_CONFIG_SHA256'
SERVICE='REQUIRED_SERVICE_INPUTS_SHA256'
MATERIAL_ROOT=B/'REQUIRED_SHARED_MATERIAL_DIRECTORY'
SSH=['ssh','-J','REQUIRED_SSH_JUMP_HOST.invalid','-o','HostName=REQUIRED_SSH_ADDRESS.invalid','-p','22','-o','BatchMode=yes',
     '-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','REQUIRED_SSH_TARGET.invalid','/usr/bin/python3','-I','-B','-']
ENV='REQUIRED_PHONE_EXECUTION_ENVIRONMENT '
HERE=Path(__file__).resolve().parent

def need(v,s):
    if not v:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(b):
    def pairs(v):
        d={}
        for k,x in v:need(k not in d,'duplicate JSON key');d[k]=x
        return d
    return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def desc(p,b):return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def read(p,n=64*1024*1024):
    p=Path(p);need(p.is_absolute() and p.resolve(strict=True)==p,'canonical original')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=n,'bounded regular original')
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(n+1)
        z=os.fstat(fd);s=p.lstat();keys=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(len(b)==a.st_size and all(getattr(a,k)==getattr(z,k)==getattr(s,k) for k in keys),'changed original')
    finally:os.close(fd)
    return b
def pin(row):
    need(isinstance(row,dict) and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
        and row['bytes']>=0 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact original descriptor')
    b=read(row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'original pin');return b
def put(p,b):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    syncdir(p.parent)
def syncdir(p):
    fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
def newdir(p):
    p.mkdir(mode=0o700);syncdir(p);syncdir(p.parent)
def original_stream(p):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    os.fsync(fd);syncdir(p.parent);return os.fdopen(fd,'wb')
def finish_stream(stream):
    stream.flush();os.fsync(stream.fileno());stream.close()
def filedesc(p):return desc(p,read(p))

REMOTE_IO='''from pathlib import Path
import base64,hashlib,json,os,stat,subprocess
os.umask(0o077)
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\\n').encode()
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)
def newdir(p):
 p.mkdir(mode=0o700);syncdir(p);syncdir(p.parent)
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 syncdir(p.parent)
def stream(p):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 os.fsync(fd);syncdir(p.parent);return os.fdopen(fd,'wb')
def finish(f):f.flush();os.fsync(f.fileno());f.close()
def private_dir(p,create=False):
 if create:
  try:newdir(p)
  except FileExistsError:pass
 s=p.lstat();assert p.resolve(strict=True)==p and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700
def parents(root,relative):
 p=root;private_dir(p)
 for part in relative.parts:
  assert part not in ('','..','.');p=p/part;private_dir(p,True)
 return p
'''

def validate_adoption(adoption,expected_live_sha256,adoption_raw):
    need(isinstance(VERIFIER_SHA,str) and re.fullmatch('[0-9a-f]{64}',VERIFIER_SHA)
         and type(VERIFIER_BYTES) is int and 0<VERIFIER_BYTES<=131072
         and all(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value)
                 for value in (POLICY_SHA,ADOPTION_SHA,ROOT_SCOPE_SHA)),
         'new policy adoption verifier is not frozen')
    need(expected_live_sha256==POLICY_SHA
         and isinstance(expected_live_sha256,str) and re.fullmatch('[0-9a-f]{64}',expected_live_sha256)
         and expected_live_sha256 not in ('REQUIRED_PRIOR_POLICY_SHA256_01',
             'REQUIRED_PRIOR_POLICY_SHA256_02',
             'REQUIRED_PRIOR_POLICY_SHA256_03','0'*64),
         'explicit adopted property-policy hash required')
    need(strict(adoption_raw)==adoption,'new adoption must be its exact supplied original')
    path=HERE.parent/'reference/policy_native5_verifier.py';raw=read(path,131072)
    need(len(raw)==VERIFIER_BYTES and sha(raw)==VERIFIER_SHA,'new policy verifier source differs')
    module=types.ModuleType('exact_root_native5_policy_verifier');module.__file__=str(path)
    module.__reviewed_source_sha256__=sha(raw)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    state=module.verify_adoption(adoption_raw,read_pinned=pin)
    need(state['current_adoption_sha256']==sha(adoption_raw)==ADOPTION_SHA
         and state['parent_adoption_sha256']=='REQUIRED_PARENT_ADOPTION_SHA256'
         and state['root_scope_decision_sha256']==ROOT_SCOPE_SHA
         and state['prior_boundary_sha256']=='REQUIRED_PRIOR_BOUNDARY_SHA256',
         'new adoption original, parent, scope or REQUIRED_CLOSED_PREDECESSOR transition differs')
    actual=pin(adoption['actual_export'])
    need(state['runtime_policy']=={'bytes':len(actual),'sha256':sha(actual)}
         and sha(actual)==expected_live_sha256,'complete explicit property-policy adoption recheck differs')
    return state['runtime_policy']


def validate_sender_marker(marker,contract_raw,prepared,owner_sha,nonce,provider_sha):
    need(marker['schema']=='hepta.native-guard.sender-prepared.v1' and marker['state']=='PREPARED_NO_SEND'
        and type(marker['send_attempt_count']) is int and marker['send_attempt_count']==0 and marker['provider_started_by_sender'] is False,
        'only the actual no-Send rendezvous admits one launch')
    need(marker['nonce']==nonce and marker['owner_request_sha256']==owner_sha
        and marker['contract_sha256']==sha(contract_raw)==prepared['sender_contract_sha256']
        and marker['provider_source_sha256']==provider_sha,'original sender prepared identity differs')

def prior_reader(runtime,manifest):
    # Pin every package byte before injecting the exact historical reference.
    # No ordinary import may substitute an unindexed bytecode file.
    package_sources={}
    for row in manifest['files']:
        raw=read(runtime/row['path'])
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'prior reader complete package pin')
        need(row['path'] not in package_sources,'duplicate prior reader package member')
        package_sources[row['path']]=raw
    saved=sys.modules.get('component_common');old_path=list(sys.path);old_dwb=sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode=True
        loaded={}
        for name in ('component_common','late_boundary'):
            rel='source/'+name+'.py';rows=[r for r in manifest['files'] if r['path']==rel]
            need(len(rows)==1,'single reviewed prior-reader source required')
            raw=package_sources[rel];row=rows[0]
            need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'reviewed prior-reader bytes changed')
            mod=types.ModuleType(name);mod.__file__=str(runtime/rel)
            if name=='component_common':sys.modules[name]=mod
            else:
                mod.__reviewed_source_sha256__=sha(raw)
                mod.__reviewed_package_sources__=package_sources
            exec(compile(raw,mod.__file__,'exec'),mod.__dict__);loaded[name]=mod
        return loaded['late_boundary']
    finally:
        if saved is None:sys.modules.pop('component_common',None)
        else:sys.modules['component_common']=saved
        sys.path[:]=old_path;sys.dont_write_bytecode=old_dwb


def validate_current_prior(p,previous,runtime,manifest):
    need(p['prior_boundary_descriptor'] is not None and p['prior_boundary_original'] is not None,
         'current policy generation must retain its actual closed predecessor')
    prior=strict(pin(p['prior_boundary_descriptor']));original=pin(p['prior_boundary_original'])
    need(sha(original)==prior['sha256'] and len(original)==prior['bytes'],'explicit prior boundary original')
    reader=prior_reader(runtime,manifest)
    boundary=reader.boundary_from_original(original,original_descriptor=prior,
        combination_sha256=COMBINATION,package_sha256=PKG)
    need(boundary['nonce']!=p['nonce'] and boundary['scope']==previous['identity']
         and previous.get('known_all_dispatched_tools_confirmed_terminal') is True,
         'new component must use its actual terminal predecessor native scope')
    need(boundary['schema']==reader.SCHEMA,
         'REQUIRED_EARLIER_GENERATIONS cannot replace the already published REQUIRED_CLOSED_PREDECESSOR predecessor')
    need(not reader.is_pre_policy_ancestor(boundary)
         and not reader.is_environment_parent_ancestor(boundary),
         'R8 cannot bypass the exact closed REQUIRED_CLOSED_PREDECESSOR property-policy predecessor')
    parent=reader.is_property_parent_ancestor(boundary)
    if parent:
        need(p['case_id']=='NEG-01' and prior==reader.reviewed_property_parent_ancestors()[0]['boundary']
             and p['previous']['bytes']=='REQUIRED_PREVIOUS_INPUT_BYTES'
             and p['previous']['sha256']=='REQUIRED_CLOSED_PREDECESSOR_INPUT_SHA256',
             'the new generation must enter through the exact closed REQUIRED_CLOSED_PREDECESSOR native predecessor; REQUIRED_EARLIER_PREDECESSOR cannot substitute')
    else:
        need(boundary['package_sha256']==PKG and boundary['combination_sha256']==COMBINATION,
             'current predecessor has a different package or policy generation')
    closed_row=previous.get('closed_component')
    need(isinstance(closed_row,dict) and type(closed_row.get('bytes')) is int
         and 0<closed_row['bytes']<=16*1024*1024,
         'predecessor needs its bounded original host closure')
    home=Path(p['prior_boundary_original']['path']).parent
    need(Path(p['prior_boundary_original']['path'])==home/'LATE-BOUNDARY.original.json'
         and Path(closed_row.get('path',''))==home/'CLOSURE.json',
         'predecessor closure and boundary must be the same standard closed case')
    if parent:
        need(home==B/'REQUIRED_CLOSED_PREDECESSOR_DIRECTORY',
             'REQUIRED_CLOSED_PREDECESSOR originals must retain their original Root namespace')
    closed_raw=pin(closed_row);inventory_row=boundary['inventory']
    need(type(inventory_row['bytes']) is int and 0<inventory_row['bytes']<=16*1024*1024,
         'predecessor needs its bounded cumulative inventory')
    inventory_raw=read(home/'INVENTORY.json',inventory_row['bytes'])
    verified,_inventory,closed=reader.closed_boundary_originals(
        original,inventory_raw,closed_raw,original_descriptor=prior,
        combination_sha256=COMBINATION,package_sha256=PKG)
    need(verified==boundary and boundary['prior_boundary'] is not None,
         'predecessor must retain the exact complete prior chain')
    closers=[row for row in manifest['files'] if row['path']=='source/close_component.py']
    need(len(closers)==1 and re.fullmatch('[0-9a-f]{64}',closers[0]['sha256']),
         'current package must contain one explicit closure source')
    expected_closer=reader.PROPERTY_PARENT_CLOSURE_SHA256 if parent else closers[0]['sha256']
    need(closed.get('closure_source_sha256')==expected_closer,
         'predecessor closure origin differs from its executed generation')
    need(previous.get('late_boundary')==prior
         and previous.get('component_qualified') is boundary['component_qualified']
         and isinstance(previous.get('terminal'),dict)
         and previous['terminal'].get('status')==boundary['native_status'],
         'previous native terminal or qualification differs from the published closure')
    failed=(closed['state']=='ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
            and closed['component_qualified'] is False
            and closed['native_status'] in ('provider_failed','cancelled')
            and type(closed['unknown_effects']) is int and closed['unknown_effects']==0)
    passed=(closed['state']=='ORIGINAL_NATIVE_COMPONENT_CLOSED'
            and closed['component_qualified'] is True and closed['native_status']=='completed')
    need((p['case_id']==boundary['case_id'] and failed)
         or (not parent and boundary['case_id']=='NEG-01' and p['case_id']=='NEG-02' and passed),
         'only a closed unqualified same-case failure or current qualified NEG01-to-NEG02 progression is allowed')
    need(pin(closed_row)==closed_raw
         and read(home/'INVENTORY.json',inventory_row['bytes'])==inventory_raw
         and pin(p['prior_boundary_original'])==original
         and strict(pin(p['prior_boundary_descriptor']))==prior,
         'predecessor originals changed during host admission')
    need(boundary['boot_id']==p['boot_id']
         and boundary['retirement']==strict(pin(p['retirement_descriptor']))['files'],
         'component predecessor boot or actual retirement differs')



def validate_plan(raw):
    need(isinstance(PKG,str) and re.fullmatch('[0-9a-f]{64}',PKG)
         and isinstance(COMBINATION,str) and re.fullmatch('[0-9a-f]{64}',COMBINATION)
         and all(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value)
                 for value in (POLICY_SHA,ADOPTION_SHA,ROOT_SCOPE_SHA,VERIFIER_SHA))
         and type(VERIFIER_BYTES) is int and 0<VERIFIER_BYTES<=131072,
         'new policy runtime and current combination are not frozen')
    p=strict(raw)
    required={'schema','label','case_id','nonce','boot_id','session_id','profile_id','request','previous','preserved_draft',
        'sender_retirement_resolution','package','shared_materials','shared_root','artifacts','policy_adoption','live_policy_sha256',
        'retirement_descriptor','retirement_originals','prior_boundary_descriptor','prior_boundary_original','source_package','out'}
    need(set(p)==required and p['schema']=='hepta.native-guard.root-chain-plan.v1','exact Root orchestration plan')
    need(re.fullmatch('[a-z0-9][a-z0-9-]{5,35}',p['label']) and p['case_id'] in ('NEG-01','NEG-02')
        and re.fullmatch('[0-9a-f]{32}',p['nonce']) and p['boot_id']==BOOT,'explicit new Root identity')
    need(p['package']['sha256']==PKG and p['retirement_descriptor']['sha256']==RET,'frozen package/actual retirement')
    source_package=strict(pin(p['source_package']))
    need(source_package['schema']=='hepta.native-guard.root-chain-source-package.v1'
        and Path(p['source_package']['path']).parent==HERE.parent
        and {r['path'] for r in source_package['files']}=={'source/phone_chain_bridge.py','source/run_component_root_once.py',
            'reference/policy_native5_verifier.py'}
        and len(source_package['files'])==3,'explicit reviewed coordinator source package required')
    for row in source_package['files']:
        b=read(HERE.parent/row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'coordinator source pin')
    owner=pin(p['request']);need(20<=len(owner)<=16000 and owner.decode().count(p['nonce'])==1 and b'\0' not in owner,'exact owner nonce binding')
    previous=strict(pin(p['previous']));need(previous['identity']['session_id']==p['session_id']
        and previous['identity']['profile_id']==p['profile_id'],'actual selected previous session/profile')
    draft=strict(pin(p['preserved_draft']));d=base64.b64decode(draft['exact_utf8_b64'],validate=True)
    need(d and sha(d)==draft['utf8_sha256'] and d!=owner,'nonempty preserved draft')
    manifest=strict(pin(p['package']));need(manifest['schema']=='hepta.native-guard.adapter-package.v1','package schema')
    runtime=Path(p['package']['path']).parent
    for row in manifest['files']:
        b=read(runtime/row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'frozen package bytes')
    validate_current_prior(p,previous,runtime,manifest)
    for name,h in (('send_new_native_guard_task_r10_r4.py',SENDER),('sender_native_guard_ready_r10_r4.py',READY_HELPER)):
        need(sha(read(B/name))==h,'original B-root sender helper pin')
    pin(p['sender_retirement_resolution']);pin(p['artifacts']);pin(p['retirement_descriptor'])
    need(p['shared_materials']['sha256']==SHARED and p['shared_materials']['bytes']=='REQUIRED_SHARED_MATERIAL_BYTES'
        and Path(p['shared_root'])==MATERIAL_ROOT,'actual same-builder shared production material required')
    shared=strict(pin(p['shared_materials']));rows=shared['files'];root=Path(p['shared_root'])
    need(shared['schema']=='hepta.r10.shared-production-materials.v1'
        and shared['state']=='HOST_SHARED_PRODUCTION_BYTES_NOT_INSTALLABLE'
        and shared['release_id']=='v150-r10-r1' and shared['production_source_count']==15
        and shared['phone_calls']==0 and shared['phone_qualification'] is False
        and shared['policy_adoption_inferred'] is False,'actual shared material state differs')
    reviewed=strict(read(runtime/'reference/REVIEWED-PRODUCTION-PINS.json'))
    expected={'provider/source/'+name for name in reviewed}|{'local-config-r10-r1.json','PHONE-SERVICE-INPUTS-v150-r10-r1.json'}
    need(len(rows)==17 and {r['path'] for r in rows}==expected,'complete same-builder shared material set')
    for row in rows:
        b=read(root/row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'shared material exact bytes')
        if row['path'].startswith('provider/source/'):need(row['sha256']==reviewed[Path(row['path']).name],'actual 15 production source pins')
    need(sha(read(root/'local-config-r10-r1.json'))==CONFIG and sha(read(root/'PHONE-SERVICE-INPUTS-v150-r10-r1.json'))==SERVICE,
        'actual shared configuration/service bytes differ')
    adoption_raw=pin(p['policy_adoption']);validate_adoption(strict(adoption_raw),p['live_policy_sha256'],adoption_raw)
    out=Path(p['out']);need(out.parent==B/'native-guard-root-chains-r10-r1' and out.name==p['label'],'fixed new Root output namespace')
    return p,manifest

class Chain:
    def __init__(self,plan,raw):
        self.p=plan;self.out=Path(plan['out']);newdir(self.out)
        put(self.out/'ROOT-PLAN.original.json',raw)
        self.steps=[];self.sender=None;self.sender_files=None
        self.remote_root='/REQUIRED_REMOTE_CHAIN_ROOT/'+plan['nonce']
        self.material=None;self.lease=None;self.prepared=None;self.root_attempts=[]
        self.bridge=read(HERE/'phone_chain_bridge.py',65536)
        source_manifest=strict(pin(plan['source_package']))
        bridge_row=next(r for r in source_manifest['files'] if r['path']=='source/phone_chain_bridge.py')
        need(len(self.bridge)==bridge_row['bytes'] and sha(self.bridge)==bridge_row['sha256'],'reviewed bridge bytes changed')
        compile(self.bridge,'phone_chain_bridge.py','exec')
    def execute_process(self,name,argv,timeout,input_raw=None,async_start=False):
        need(re.fullmatch('[a-z0-9-]{1,55}',name),'phase name')
        d=self.out/name;newdir(d)
        intent={'schema':'hepta.native-guard.root-host-command.v1','phase':name,'argv':argv,
            'stdin_sha256':None if input_raw is None else sha(input_raw),'maximum_starts':1,
            'maximum_wait_seconds':timeout,'automatic_retry':False,'signals_on_timeout':False}
        put(d/'INTENT.json',enc(intent))
        if input_raw is not None:put(d/'stdin.original',input_raw)
        stdout=original_stream(d/'stdout.original');stderr=original_stream(d/'stderr.original')
        child=subprocess.Popen(argv,stdin=subprocess.PIPE if input_raw is not None else subprocess.DEVNULL,
            stdout=stdout,stderr=stderr,start_new_session=True,close_fds=True)
        if input_raw is not None:child.stdin.write(input_raw);child.stdin.close()
        try:group,session=os.getpgid(child.pid),os.getsid(child.pid)
        except ProcessLookupError:
            need(child.poll() is not None,'host child identity unknown before wait')
            group=session=None
        put(d/'CHILD.json',enc({'pid':child.pid,'pgid':group,'sid':session,
            'source_intent_sha256':sha(enc(intent)),'maximum_starts':1,
            'identity_missing_only_if_actual_child_already_joined':group is None}))
        if async_start:return child,d,stdout,stderr
        try:rc=child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            put(d/'UNKNOWN.json',enc({'state':'OWNED_HOST_CHILD_NOT_JOINED_NO_SIGNAL_OR_RETRY','pid':child.pid,'automatic_retry':False}))
            finish_stream(stdout);finish_stream(stderr);raise RuntimeError('unknown original phase '+name)
        finish_stream(stdout);finish_stream(stderr);o=read(d/'stdout.original');e=read(d/'stderr.original')
        result={'state':'ORIGINAL_HOST_CHILD_JOINED','phase':name,'pid':child.pid,'returncode':rc,
            'stdout':desc(d/'stdout.original',o),'stderr':desc(d/'stderr.original',e),'automatic_retry':False}
        put(d/'RESULT.json',enc(result));self.steps.append(result)
        need(rc==0,'original phase failed; no replay: '+name)
        return o
    def remote(self,name,code,timeout=60):
        compile(code,'root_p4_'+name,'exec')
        raw=self.execute_process(name,SSH,timeout,code.encode())
        return strict(raw)
    def remote_files(self,name,files,create_root=False):
        payload={path:base64.b64encode(raw).decode() for path,raw in files.items()}
        pins={path:[len(raw),sha(raw)] for path,raw in files.items()}
        code=REMOTE_IO+"R=Path("+repr(self.remote_root)+")\n"
        if create_root:code+="private_dir(R.parent,True)\nnewdir(R)\n"
        code+="private_dir(R)\nfiles="+repr(payload)+"\npins="+repr(pins)+"\n"
        code+="for rel,data in files.items():\n p=Path(rel);assert not p.is_absolute() and '..' not in p.parts\n b=base64.b64decode(data,validate=True);assert [len(b),hashlib.sha256(b).hexdigest()]==pins[rel]\n parents(R,p.parent);q=R/p;put(q,b)\n assert q.read_bytes()==b\nprint(json.dumps({'state':'EXACT_NEW_HOST_FILES_WRITTEN','files':pins},sort_keys=True))\n"
        return self.remote(name,code,90)
    def remote_read(self,name,paths,wait_path=None,wait_seconds=0,prepared=False):
        code="from pathlib import Path\nimport base64,hashlib,json,os,stat,time\npaths="+repr(paths)+"\n"
        if wait_path:
            code+="p=Path("+repr(wait_path)+");deadline=time.monotonic()+"+repr(wait_seconds)+"\nwhile not p.exists():\n assert time.monotonic()<deadline,'one original wait expired'\n time.sleep(.1)\n"
        code+="rows={}\nfor key,path in paths.items():\n p=Path(path);assert p.resolve(strict=True)==p\n fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n with os.fdopen(fd,'rb') as f:\n  a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=16777216\n  b=f.read(16777217);z=os.fstat(f.fileno())\n assert len(b)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)\n rows[key]={'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'base64':base64.b64encode(b).decode()}\n"
        if prepared:
            code+="v=json.loads(base64.b64decode(rows['prepared']['base64']));assert v['state']=='PREPARED_NO_SEND' and v['send_attempt_count']==0 and v['provider_started_by_sender'] is False\nassert v['pre_send_deadline_monotonic_ns']-time.monotonic_ns()>40_000_000_000,'insufficient original sender margin'\n"
        code+="print(json.dumps({'state':'ORIGINAL_HOST_FILES_READ','files':rows},sort_keys=True))\n"
        return self.remote(name,code,wait_seconds+30)
    def remote_program(self,name,argv,timeout):
        code=REMOTE_IO+"R=Path("+repr(self.remote_root)+")\nD=R/"+repr(name)+"\nnewdir(D)\nargv="+repr(argv)+"\n"
        code+="put(D/'ARGV.json',enc(argv))\no=stream(D/'stdout.original');e=stream(D/'stderr.original');p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=o,stderr=e,start_new_session=True)\n"
        code+="try:rc=p.wait(timeout="+repr(timeout)+")\nexcept subprocess.TimeoutExpired:\n put(D/'UNKNOWN.json',enc({'pid':p.pid,'automatic_retry':False,'signals_sent':0}));raise\nfinally:finish(o);finish(e)\nr={'returncode':rc,'stdout':(D/'stdout.original').read_text(),'stderr':(D/'stderr.original').read_text(),'automatic_retry':False}\nput(D/'RESULT.json',enc(r))\nprint(json.dumps(r,sort_keys=True))\n"
        value=self.remote(name,code,timeout+30)
        need(value['returncode']==0,'actual P4 child failed; no replay: '+name)
        return value
    def phone(self,tag,req):
        need(req['kind'] in ('shell','push') and type(req['timeout_seconds']) is int and 0<req['timeout_seconds']<=300,'fixed phone actor bound')
        if req['kind']=='shell':
            need(req.get('root') is True,'explicit reviewed root shell request required')
            wire=('shell,v2,raw:/REQUIRED_PHONE_ROOT_SHELL -c '+shlex.quote(req['command'])).encode()
            need(len(wire)<65536,'fixed ADB wire bound')
        label='ng-'+self.p['nonce']+'-'+tag
        need(re.fullmatch('[a-z0-9-]{1,70}',label),'fixed one-use phone label')
        code=REMOTE_IO+"B=Path('/REQUIRED_REMOTE_ACTOR_WORKSPACE');a=B/'ops/phone_once.py'\nassert hashlib.sha256(a.read_bytes()).hexdigest()=="+repr(ACTOR)+"\nlabel="+repr(label)+"\nreq="+repr(req)+"\np=B/'requests'/(label+'.json')\nput(p,enc(req))\n"
        code+="D=Path("+repr(self.remote_root)+")/"+repr('phone-'+tag)+"\nnewdir(D)\no=stream(D/'actor.stdout');e=stream(D/'actor.stderr')\np=subprocess.Popen(['/usr/bin/python3','-I','-B',str(a),label,str(B/'requests'/(label+'.json'))],stdout=o,stderr=e,start_new_session=True)\n"
        code+="try:rc=p.wait(timeout="+repr(req['timeout_seconds']+20)+")\nexcept subprocess.TimeoutExpired:\n put(D/'UNKNOWN.json',enc({'pid':p.pid,'automatic_retry':False,'signals_sent':0}));raise\nfinally:finish(o);finish(e)\nraw=(B/'operations'/label/'result.json').read_bytes();v={'actor_rc':rc,'wrapper_sha256':hashlib.sha256(raw).hexdigest(),'wrapper':json.loads(raw)}\nput(D/'ORIGINAL-OPERATION.json',enc(v))\nprint(json.dumps(v,sort_keys=True))\n"
        result=self.remote('phone-'+tag,code,req['timeout_seconds']+55)
        need(result['actor_rc']==0,'phone actor unknown/nonzero; inspect original without replay')
        w=result['wrapper']
        if req['kind']=='push':
            need(w['status']=='pushed_and_hash_verified' and w['sha256']==req['sha256'] and w['readback']['rc']==0,'actual push not confirmed')
            return w
        ph=w['phone'];need(type(ph['rc']) is int and ph['rc']==0,'actual phone command failed; no new key retry');return strict(ph['stdout'])
    def bridge_call(self,tag,operation,extra=(),timeout=40):
        argv=['phone_chain_bridge.py',operation,'--label',self.p['label']]
        if self.lease:argv+=['--lease-sha256',self.prepared['lease']['sha256']]
        argv+=list(extra)+['--execute-root-bridge-once']
        code='import sys\nsys.argv='+repr(argv)+'\n'+self.bridge.decode()
        command=ENV+'/usr/bin/python3 -I -B -c '+shlex.quote(code)
        return self.phone(tag,{'kind':'shell','root':True,'timeout_seconds':timeout,'command':command})
    def push_copy(self,tag,remote_path,name,byte_size,digest):
        self.phone('push-'+tag,{'kind':'push','source':remote_path,'destination':'/REQUIRED_PHONE_PUSH_PREFIX/'+name,
            'sha256':digest,'timeout_seconds':90})
        return self.bridge_call('copy-'+tag,'copy-input',['--name',name,'--bytes',str(byte_size),'--sha256',digest])
    def frozen_phone(self,tag,argv,timeout=90):
        return self.phone(tag,{'kind':'shell','root':True,'timeout_seconds':timeout,'command':ENV+shlex.join(argv)})
    def remaining(self,minimum=1):
        left=(self.lease['expires_unix_ms']-time.time_ns()//1000000)/1000
        need(left>minimum,'same lease exhausted; no extension/restart');return left

    def run(self):
        p=self.p;runtime=Path(p['package']['path']).parent;shared=Path(p['shared_root'])
        expiry=time.time_ns()//1000000+600000
        put(self.out/'CHAIN-INTENT.json',enc({'schema':'hepta.native-guard.root-chain-intent.v1','nonce':p['nonce'],
            'label':p['label'],'case_id':p['case_id'],'lease_expires_unix_ms':expiry,'maximum_native_sends':1,
            'maximum_detached_launches':1,'automatic_retry':False,'automatic_lease_extension':False,'model_requests':0}))
        args=['/usr/bin/python3','-I','-B',str(runtime/'source/prepare_component.py')]
        values={'label':p['label'],'case-id':p['case_id'],'nonce':p['nonce'],'boot-id':BOOT,'session-id':p['session_id'],
            'profile-id':p['profile_id'],'package':p['package']['path'],'package-sha256':PKG,
            'production-source':str(shared/'provider/source'),'config-file':str(shared/'local-config-r10-r1.json'),
            'config-sha256':sha(read(shared/'local-config-r10-r1.json')),
            'service-file':str(shared/'PHONE-SERVICE-INPUTS-v150-r10-r1.json'),'service-sha256':sha(read(shared/'PHONE-SERVICE-INPUTS-v150-r10-r1.json')),
            'artifacts-file':p['artifacts']['path'],'artifacts-sha256':p['artifacts']['sha256'],'live-policy-sha256':p['live_policy_sha256'],
            'retirement-descriptor':p['retirement_descriptor']['path'],'retirement-descriptor-sha256':RET,
            'retirement-originals':p['retirement_originals'],'owner-request-file':p['request']['path'],
            'owner-request-sha256':p['request']['sha256'],'expires-unix-ms':expiry,'out':str(self.out/'material')}
        if p['prior_boundary_descriptor']:
            values.update({'prior-boundary-descriptor':p['prior_boundary_descriptor']['path'],
                'prior-boundary-descriptor-sha256':p['prior_boundary_descriptor']['sha256'],'prior-boundary-original':p['prior_boundary_original']['path']})
        for k,v in values.items():args+=['--'+k,str(v)]
        self.execute_process('prepare-material',args,30)
        self.material=self.out/'material';self.prepared=strict(read(self.material/'PREPARED.json'))
        self.lease=strict(read(self.material/'tree/LEASE.json'));self.remaining(480)
        files={}
        for file in (self.material/'tree').rglob('*'):
            if file.is_file():files['material/tree/'+str(file.relative_to(self.material/'tree'))]=read(file)
        archive=read(self.material/'component-inputs.tar.gz');files['inputs/component-inputs.tar.gz']=archive
        files['inputs/stage_component.py']=read(runtime/'source/stage_component.py')
        for k in ('request','previous','preserved_draft'):files['inputs/'+k+'.original']=pin(p[k])
        self.remote_files('host-stage-material',files,True)
        for tag,name,rel in [('material',p['label']+'.tar.gz','inputs/component-inputs.tar.gz'),('stage-source',p['label']+'.stage.py','inputs/stage_component.py')]:
            b=files[rel];self.push_copy(tag,self.remote_root+'/'+rel,name,len(b),sha(b))
        home=self.prepared['phone_home'];staging=G+'/native-guard-staging-r10-r1/'
        self.frozen_phone('stage',['/usr/bin/python3','-I','-B',staging+p['label']+'.stage.py',
            '--archive',staging+p['label']+'.tar.gz','--archive-sha256',sha(archive),
            '--lease-sha256',self.prepared['lease']['sha256'],'--package-sha256',PKG,'--execute-private-stage-once'],90)
        self.remaining(465)
        sender=['/usr/bin/python3','-I','-B',str(B/'send_new_native_guard_task_r10_r4.py'),p['label'],p['request']['path'],p['previous']['path'],
            '--preserved-draft',p['preserved_draft']['path'],'--retirement-resolution',p['sender_retirement_resolution']['path'],
            '--evidence-root','component','--component-contract',str(self.material/'tree/sender-contract.json'),
            '--component-package',p['package']['path'],'--component-package-sha256',PKG]
        self.execute_process('sender-preview',sender,20)
        self.sender=self.execute_process('sender-execute',sender+['--execute-once'],600,async_start=True)
        sender_dir='/REQUIRED_REMOTE_SENDER_PREFIX/'+p['label']+'-root-v150'
        marker=self.remote_read('sender-prepared',{'prepared':sender_dir+'/COMPONENT-PREPARED-NO-SEND.json'},
            sender_dir+'/COMPONENT-PREPARED-NO-SEND.json',90,True)
        mr=strict(base64.b64decode(marker['files']['prepared']['base64'],validate=True))
        contract_raw=read(self.material/'tree/sender-contract.json')
        provider_sha=next(r['sha256'] for r in strict(pin(p['package']))['files'] if r['path']=='source/component_listener.py')
        validate_sender_marker(mr,contract_raw,self.prepared,p['request']['sha256'],p['nonce'],provider_sha)
        # Frozen listener requires more than 420 seconds before its sole listen.
        # Leave a small launch margin; never extend the original 600-second lease.
        self.remaining(510)
        self.frozen_phone('launch',self.prepared['root_detached_launcher_argv'],60)
        for phase in ('setup','before-guard','after-guard'):
            self.remaining(25)
            value=self.bridge_call('plan-'+phase,'phase-originals',['--phase',phase],timeout=75 if phase=='setup' else 40)
            need(value['state']=='ACTUAL_PHASE_ORIGINALS_READ','component ended before phase; preserve, no additional Root UI')
            phasefiles={}
            for name,row in value['files'].items():
                raw=base64.b64decode(row['base64'],validate=True);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'original phase file')
                phasefiles['plans/'+phase+'/'+name]=raw
            self.remote_files('store-plan-'+phase,phasefiles)
            directory=self.remote_root+'/plans/'+phase+'/';planrow=value['files']['ROOT-'+phase.upper()+'-PLAN.json']
            parent='/REQUIRED_REMOTE_FIXTURE_ROOT/'+p['nonce']+'/'+phase
            entry=self.remote_root+'/material/tree/package/source/'
            argv=['/usr/bin/python3','-I','-B',entry+'run_root_fixture_phase.py','--material',self.remote_root+'/material/tree',
                '--lease-sha256',self.prepared['lease']['sha256'],'--package-sha256',PKG,
                '--plan',directory+'ROOT-'+phase.upper()+'-PLAN.json','--plan-sha256',planrow['sha256'],
                '--bound-contract',directory+'BOUND-CONTRACT.json','--bound-contract-sha256',value['files']['BOUND-CONTRACT.json']['sha256'],
                '--accepted',directory+'ACCEPTED.json','--accepted-sha256',value['files']['ACCEPTED.json']['sha256'],
                '--out',parent,'--execute-root-fixture-phase-once']
            put(self.out/('ROOT-FIXTURE-'+phase+'.INTENT.json'),enc({'phase':phase,'parent_out':parent,
                'expected_terminal_path':parent+'/HOST-TERMINAL.json','argv':argv,'maximum_child_starts':1,
                'terminal_unknown_until_actual_original_read':True,'automatic_retry':False}))
            self.remote_program('fixture-'+phase,argv,min(250,max(1,int(self.remaining())-5)))
            terminal=self.remote_read('fixture-originals-'+phase,{'terminal':parent+'/HOST-TERMINAL.json','index':parent+'/actor/ORIGINAL-INDEX.json'})
            tr=terminal['files']['terminal'];tv=strict(base64.b64decode(tr['base64'],validate=True))
            need(tv['state']=='OWNED_ROOT_FIXTURE_CHILD_JOINED' and tv['child_wait_returned'] is True
                and tv['child_returncode']==0 and len(tv['group_absence_observations'])==2,'actual Root actor unknown')
            self.root_attempts.append({'phase':phase,'terminal':{k:tr[k] for k in ('path','bytes','sha256')}})
            packout=self.remote_root+'/witness-'+phase
            packargv=['/usr/bin/python3','-I','-B',entry+'witness_bundle.py','pack','--plan',directory+'ROOT-'+phase.upper()+'-PLAN.json',
                '--plan-sha256',planrow['sha256'],'--original-index',parent+'/actor/ORIGINAL-INDEX.json',
                '--original-index-sha256',terminal['files']['index']['sha256'],'--nonce',p['nonce'],'--boot-id',BOOT,'--out',packout]
            packed=strict(self.remote_program('pack-'+phase,packargv,30)['stdout'])
            row=packed['archive'];self.push_copy('witness-'+phase,packout+'/witness.tar.gz',p['label']+'-'+phase+'.witness.tar.gz',row['bytes'],row['sha256'])
            self.frozen_phone('publish-'+phase,['/usr/bin/python3','-I','-B',home+'/package/source/witness_bundle.py','publish',
                '--lease',home,'--lease-sha256',self.prepared['lease']['sha256'],'--archive',staging+p['label']+'-'+phase+'.witness.tar.gz',
                '--archive-sha256',row['sha256'],'--execute-publish-original-bytes-once'],35)
        child,d,so,se=self.sender
        try:rc=child.wait(timeout=380)
        except subprocess.TimeoutExpired:raise RuntimeError('original sender still running; no signal/replay')
        finally:finish_stream(so);finish_stream(se)
        put(d/'JOINED.json',enc({'pid':child.pid,'returncode':rc,'wait_returned':True,'automatic_retry':False}))
        need(rc==0,'original sender child failed')
        sent=strict(read(B/(p['label']+'.send-result.json')))
        need(sent.get('rc')==0 and sent.get('stderr')=='','actual P4 sender failed/unknown; retain originals')
        actor_result=strict(sent['stdout'].strip().splitlines()[-1])
        need(actor_result['state']=='ORIGINAL_NATIVE_TERMINAL_OBSERVED' and actor_result['draft_restore']['state']=='ORIGINAL_DRAFT_RESTORED',
            'native terminal/draft restoration not proven')
        self.bridge_call('role-end','role-end')
        capture_out=G+'/native-guard-snapshots-r10-r1/'+p['label']+'-capture-01'
        snap=self.frozen_phone('snapshot',['/usr/bin/python3','-I','-B',home+'/package/source/component_snapshot.py',
            '--lease',home,'--lease-sha256',self.prepared['lease']['sha256'],'--package-sha256',PKG,'--out',capture_out,
            '--execute-original-snapshot-once'],100)
        archive=snap['archive'];need(0<archive['bytes']<=64*1024*1024,'actual snapshot archive bound')
        chunks=[]
        for index in range((archive['bytes']+524287)//524288):
            row=self.bridge_call('chunk-'+str(index),'snapshot-chunk',['--sha256',archive['sha256'],'--bytes',str(archive['bytes']),'--index',str(index)],35)
            b=base64.b64decode(row['base64'],validate=True);need(len(b)==row['bytes'] and sha(b)==row['sha256'] and row['offset']==index*524288,'actual snapshot chunk')
            chunks.append(b)
        body=b''.join(chunks);need(len(body)==archive['bytes'] and sha(body)==archive['sha256'],'full actual snapshot hash')
        put(self.out/'ORIGINALS.tar.gz',body)
        hostfiles={'closure-inputs/ORIGINALS.tar.gz':body}
        for source,key in ((B/(p['label']+'.send-result.json'),'sender_host_result'),(B/(p['label']+'.local-once.json'),'sender_local_once'),
            (B/(p['label']+'.actor.py'),'sender_actor')):hostfiles['closure-inputs/'+key+'.original']=read(source)
        self.remote_files('stage-closure-inputs',hostfiles)
        def remote_desc(relative,raw):return desc(self.remote_root+'/'+relative,raw)
        closure={'schema':'hepta.native-guard.closure-plan.v1','label':p['label'],
            'archive':remote_desc('closure-inputs/ORIGINALS.tar.gz',body),'capture_sha256':snap['capture']['sha256'],
            'package':remote_desc('material/tree/package/MANIFEST.json',pin(p['package'])),'sender_dir':sender_dir,
            'request':remote_desc('inputs/request.original',pin(p['request'])),
            'previous':remote_desc('inputs/previous.original',pin(p['previous'])),
            'preserved_draft':remote_desc('inputs/preserved_draft.original',pin(p['preserved_draft'])),
            'root_fixture_attempts':self.root_attempts}
        for key in ('sender_host_result','sender_local_once','sender_actor'):
            closure[key]=remote_desc('closure-inputs/'+key+'.original',hostfiles['closure-inputs/'+key+'.original'])
        cr=enc(closure);self.remote_files('stage-closure-plan',{'CLOSURE-PLAN.json':cr});closeout=self.remote_root+'/closure'
        self.remote_program('close',['/usr/bin/python3','-I','-B',entry+'close_component.py','--plan',self.remote_root+'/CLOSURE-PLAN.json',
            '--plan-sha256',sha(cr),'--out',closeout,'--execute-host-closure-once'],150)
        closed=self.remote_read('closed-originals',{'closure':closeout+'/CLOSURE.original.json','inventory':closeout+'/AFTER-INVENTORY.original.json'})
        for key,extension in (('closure','CLOSURE.json'),('inventory','INVENTORY.json')):
            row=closed['files'][key];put(self.out/extension,base64.b64decode(row['base64'],validate=True))
            self.push_copy('closed-'+key,row['path'],p['label']+'.'+extension,row['bytes'],row['sha256'])
        published=self.frozen_phone('late-publish',['/usr/bin/python3','-I','-B',home+'/package/source/late_boundary.py',
            '--lease',home,'--lease-sha256',self.prepared['lease']['sha256'],'--closure',staging+p['label']+'.CLOSURE.json',
            '--closure-sha256',closed['files']['closure']['sha256'],'--inventory',staging+p['label']+'.INVENTORY.json',
            '--inventory-sha256',closed['files']['inventory']['sha256'],'--execute-publish-once'],100)
        boundary=self.bridge_call('boundary-read','boundary-original')['file']
        need({k:boundary[k] for k in ('path','bytes','sha256','metadata')}==published['boundary'],'actual published boundary')
        put(self.out/'LATE-BOUNDARY.original.json',base64.b64decode(boundary['base64'],validate=True))
        put(self.out/'LATE-BOUNDARY-DESCRIPTOR.json',enc({k:boundary[k] for k in ('path','bytes','sha256','metadata')}))
        value=strict(read(self.out/'CLOSURE.json'))
        latency=self.remote_read('latest-previous-original',{'latency':sender_dir+'/SEND-NATIVE-LATENCY.json'})
        lat=strict(base64.b64decode(latency['files']['latency']['base64'],validate=True));need(lat['scope']==value['scope'],'closed previous scope')
        previous={'schema':'hepta.native-guard.closed-previous.v1','identity':value['scope'],
            'request_sha256':lat['original_observation']['native_request_sha256'],'terminal':{'status':value['native_status']},
            'known_all_dispatched_tools_confirmed_terminal':True,'complete_business_success':False,
            'component_qualified':value['component_qualified'],'closed_component':filedesc(self.out/'CLOSURE.json'),
            'late_boundary':{k:boundary[k] for k in ('path','bytes','sha256','metadata')},'automatic_replay':False}
        put(self.out/'ACTUAL-PREVIOUS-INPUT.json',enc(previous))
        final={'state':'ORIGINAL_COMPONENT_CLOSED_AND_LATE_BOUNDARY_PUBLISHED','component_qualified':value['component_qualified'],
            'business_qualified':False,'model_requests':0,'four_role_qualification':False,'native_status':value['native_status'],
            'scope':value['scope'],'late_boundary':published['boundary'],'previous':filedesc(self.out/'ACTUAL-PREVIOUS-INPUT.json'),
            'automatic_retry':False,'steps':self.steps}
        put(self.out/'ROOT-RESULT.json',enc(final));print(json.dumps({k:v for k,v in final.items() if k!='steps'},sort_keys=True));return 0

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--plan',type=Path,required=True);a.add_argument('--plan-sha256',required=True)
    a.add_argument('--execute-root-chain-once',action='store_true');v=a.parse_args()
    raw=read(v.plan,262144);need(sha(raw)==v.plan_sha256,'Root plan pin')
    if not v.execute_root_chain_once:
        print(json.dumps({'state':'HOST_PREVIEW_NO_PHONE_NO_NONCE_NO_LEASE','plan_sha256':sha(raw),
            'phone_calls':0,'native_sends':0,'lease_fixed':False,'requires':'All explicit actual original descriptors, Root policy adoption, and execute flag.'},sort_keys=True));return 0
    p,_=validate_plan(raw);os.umask(0o077)
    parent=Path(p['out']).parent
    try:newdir(parent)
    except FileExistsError:pass
    need(parent.resolve(strict=True)==parent and stat.S_IMODE(parent.stat().st_mode)==0o700,'private Root output parent')
    c=Chain(p,raw)
    try:return c.run()
    except BaseException as error:
        value={'state':'FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION',
            'error_type':type(error).__name__,'detail':str(error)[:1024],'steps':c.steps,'root_fixture_attempts':c.root_attempts,
            'automatic_retry':False,'new_identity_retry':False,'send_again':False,'signals_sent_by_coordinator':0,
            'policy_changes':0,'model_requests':0,'component_qualified':False,'business_qualified':False,
            'note':'Inspect existing process/actor/phone receipts. No missing record is treated as no effect.'}
        put(c.out/'ROOT-FAILURE.json',enc(value));raise
if __name__=='__main__':raise SystemExit(main())
