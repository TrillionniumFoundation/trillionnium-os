#!/usr/bin/env python3
"""Exact raw production source and sealed-release input for two component cases.
Importing this module performs no file I/O. No phone or subprocess API is used.
"""
import ast
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

sys.dont_write_bytecode=True
B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
MATERIALIZER=B/'scoped-acceptance-v150-r10-r1-readiness-r8/operator/materialize_case_r10.py'
MATERIALIZER_PIN=(24834,'b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290')
CONSUMER=B/'r10-boundary-consumers-final-r7/source/release_boundaries.py'
CONSUMER_PIN=(58505, 'a791a7493fe8544aa44b910dd627f405f71678a048f9df94df91529a54fdf703')
READINESS_PIN=(16405, '345723406df0c523ab55b167bb52f5ceb9432d387ffe3b4aa5b1e5442465e392')
RUNTIME_SHA='683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'
POLICY_SHA='50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
ADOPTION_SHA='a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
PROTOCOL_PIN=(37318,'c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0')
SOURCE_PINS={
 'provider_openai_compatible.py':(17730,'337c83284fece94c0dd477a30029c63017b7eb00aab55a747b89b193823820bc'),
 'phone_task_guards.py':(22825,'87d88e0e9f93b31cf69bf0e4cdb9c62fd20e03c2192a0ffec621eb84c26bba86'),
 'phone_observation_tools.py':(38774,'f16c77c1b4509babcea5fc2e8d0a7ae8ab43b3cd58e6640441b44ecd4bccb6df'),
 'phone_local_tools.py':(13813,'0302a8bac9dac18234c9493aa512e1efcf43d7cc5eaab884882dad42c2182c54')}
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return {'bytes':len(raw),'sha256':sha(raw)}
def encode(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
 def pairs(rows):
  value={}
  for key,item in rows:
   need(key not in value,'duplicate JSON key');value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def metadata(st):return tuple(getattr(st,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
class Originals:
 def __init__(self):self.seen={}
 def read(self,path,size,digest,maximum=1048576):
  path=Path(path)
  need(path.is_absolute() and path.resolve(strict=True)==path,'canonical original required')
  need(type(size) is int and 0<=size<=maximum and isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest),'exact original pin required')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd)
   need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==size,'original metadata differs')
   with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(size+1)
   need(len(raw)==size and sha(raw)==digest and metadata(st)==metadata(os.fstat(fd))==metadata(path.lstat()),'original changed')
  finally:os.close(fd)
  key=str(path);record={'path':key,**pin(raw),'metadata':list(metadata(st))}
  need(key not in self.seen or self.seen[key]==record,'original changed across reads')
  self.seen[key]=record
  return raw
 def descriptor(self,row,maximum=1048576):
  need(isinstance(row,dict) and set(row)=={'path','bytes','sha256'},'exact descriptor required')
  return self.read(row['path'],row['bytes'],row['sha256'],maximum)
 def recheck(self):
  for row in tuple(self.seen.values()):
   self.read(row['path'],row['bytes'],row['sha256'],max(1048576,row['bytes']))
def verify_source_package(originals,root,manifest_sha):
 root=Path(root)
 need(root.is_absolute() and root.resolve(strict=True)==root,'canonical source package required')
 raw_path=root/'MANIFEST.json'
 fd=os.open(raw_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<st.st_size<=262144,'bounded source manifest required')
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(st.st_size+1)
  need(metadata(st)==metadata(os.fstat(fd))==metadata(raw_path.lstat()) and len(raw)==st.st_size,'manifest changed')
 finally:os.close(fd)
 need(sha(raw)==manifest_sha,'explicit source-package manifest pin differs')
 originals.read(raw_path,len(raw),manifest_sha)
 value=strict(raw)
 need(set(value)=={'schema','state','files'} and value['schema']=='hepta.fixed19.comp01-neg03.source-package.v1'
      and value['state']=='HOST_SOURCE_CANDIDATE_NOT_EXECUTED','source package schema differs')
 rows=value['files'];need(isinstance(rows,list) and 5<=len(rows)<=16,'bounded complete source package required')
 names=set()
 for row in rows:
  need(isinstance(row,dict) and set(row)=={'path','bytes','sha256'},'source row differs')
  rel=Path(row['path'])
  need(not rel.is_absolute() and str(rel)==row['path'] and all(x not in ('','..','.') for x in rel.parts)
       and rel.parts[0] in {'source','reference','INTERFACE.json','NEG03-PLAN.template.json','COMP01-PLAN.template.json'}
       and row['path'] not in names,'source member path differs')
  names.add(row['path']);originals.read(root/rel,row['bytes'],row['sha256'],262144)
 need({'source/component_source_context.py','source/prepare_direct_return_component.py',
       'source/verify_unqualified_geometry_fixture.py','reference/original-protocol.json'}<=names,'source package omitted a required original')
 expected_files=names|{'MANIFEST.json'}
 expected_dirs={str(Path(name).parent) for name in expected_files if str(Path(name).parent)!='.'}
 need(expected_dirs=={'source','reference'},'source directory set differs')
 observed=set();directories={}
 for directory in [root,root/'source',root/'reference']:
  st=directory.lstat()
  need(stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode)==0o700,'source directory must remain private')
  children=sorted(os.listdir(directory))
  for name in children:
   path=directory/name;actual=path.lstat()
   need(not stat.S_ISLNK(actual.st_mode),'source symlink rejected')
   if stat.S_ISREG(actual.st_mode):observed.add(str(path.relative_to(root)))
   else:need(stat.S_ISDIR(actual.st_mode) and str(path.relative_to(root)) in expected_dirs,'unexpected source member type/path')
  need(metadata(st)==metadata(directory.lstat()) and children==sorted(os.listdir(directory)),'source directory changed')
  directories[str(directory)]={'metadata':list(metadata(st)),'names':children}
 need(observed==expected_files,'extra or missing source-package member')
 return {'descriptor':{'path':str(raw_path),**pin(raw)},'directories':directories,'files':sorted(expected_files)}
def recheck_source_package(originals,package):
 originals.recheck()
 for path,row in package['directories'].items():
  p=Path(path);before=metadata(p.lstat())
  need(list(before)==row['metadata'] and sorted(os.listdir(p))==row['names']
       and metadata(p.lstat())==before,'source package directory changed')
def read_plan(originals,path,digest):
 path=Path(path)
 need(path.is_absolute(),'absolute plan path required')
 size=path.lstat().st_size
 return originals.read(path,size,digest,65536)
def syncdir(path):
 fd=os.open(path,os.O_RDONLY)
 try:os.fsync(fd)
 finally:os.close(fd)
def fresh_directory(path):
 path=Path(path)
 need(path.is_absolute() and path.parent.resolve(strict=True)==path.parent,'canonical fresh parent required')
 try:path.lstat()
 except FileNotFoundError:pass
 else:raise ValueError('create-only output exists')
 path.mkdir(mode=0o700);syncdir(path.parent)
 return path
def put(path,raw):
 path=Path(path)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 syncdir(path.parent)
 return {'path':str(path),**pin(raw)}
def raw_module(raw,path,name):
 module=types.ModuleType(name);module.__file__=str(path)
 exec(compile(raw,str(path),'exec',optimize=0),module.__dict__)
 return module
def protocol(originals,case_id):
 root=Path(__file__).resolve(strict=True).parent.parent
 raw=originals.read(root/'reference/original-protocol.json',*PROTOCOL_PIN)
 value=strict(raw);rows=[r for r in value['cases'] if r['id']==case_id]
 need(value['case_count']==19 and len(value['cases'])==19 and len(rows)==1
      and rows[0]['layer']=='component_direct','original component contract differs')
 return raw,rows[0]
def sealed_sources(originals,release):
 need(isinstance(release,dict) and set(release)=={'path','build_result_sha256'}
      and isinstance(release['build_result_sha256'],str) and re.fullmatch('[0-9a-f]{64}',release['build_result_sha256']),'an actual Root-reviewed sealed release is required')
 root=Path(release['path']);need(root.is_absolute() and root.resolve(strict=True)==root,'canonical release root required')
 mraw=originals.read(MATERIALIZER,*MATERIALIZER_PIN)
 m=raw_module(mraw,MATERIALIZER,'reviewed_component_case_materializer')
 result=m.validate_release(root,release['build_result_sha256'])
 report=result['report'];binding=result['binding'];source=result['source']
 need(report['policy_sha256']==POLICY_SHA and report['policy_adoption_inputs_sha256']==ADOPTION_SHA
      and binding['policy_sha256']==POLICY_SHA and binding['policy_adoption_inputs_sha256']==ADOPTION_SHA,
      'actual sealed policy/adoption differs')
 need(len(source)==15,'complete actual fifteen-source release required')
 for name,raw in source.items():
  need(originals.read(root/'provider/source'/name,len(raw),sha(raw))==raw,'sealed raw source changed')
 for name,(size,digest) in SOURCE_PINS.items():
  need(name in source and pin(source[name])=={'bytes':size,'sha256':digest},'frozen geometry/return production source differs')
 hraw=originals.read(CONSUMER,*CONSUMER_PIN)
 need(originals.read(root/'provider/release_boundaries.py',*CONSUMER_PIN)==hraw,'actual release consumer source differs')
 originals.read(root/'provider/collect_r10_readiness.py',*READINESS_PIN)
 sealed_operators=strict(result['source_seal_raw'])['operator_helpers']
 need(isinstance(sealed_operators,list),'sealed operator helper inventory required')
 for name,(size,digest) in [('release_boundaries.py',CONSUMER_PIN),('collect_r10_readiness.py',READINESS_PIN)]:
  rows=[row for row in sealed_operators if row.get('path')==name]
  need(rows==[{'path':name,'bytes':size,'sha256':digest}],'sealed operator helper row differs')
 h=raw_module(hraw,CONSUMER,'reviewed_component_case_boundary_consumer')
 need(h.PACKAGE_SHA==RUNTIME_SHA,'R6 component runtime differs')
 manifest_raw=m.pinned(root/'module/MODULE-MANIFEST-v150-r10-r1.json',report['module_manifest_sha256'],1048576)
 originals.read(root/'module/MODULE-MANIFEST-v150-r10-r1.json',len(manifest_raw),sha(manifest_raw))
 manifest=strict(manifest_raw)
 for member in manifest['files']:
  rel=Path(member['path'])
  need(not rel.is_absolute() and '..' not in rel.parts and str(rel)==member['path'],'unsafe sealed module member')
  maximum=33554432 if member['path']=='evidence/RELEASE-BOUNDARIES.json' else 8388608
  originals.read(root/'module'/rel,member['bytes'],member['sha256'],maximum)
 marker=m.read(root/'module/SEALED',128)
 need(marker==b'HEPTA_PHONE_LOCAL_V150_R10_R1_REVIEWED_INPUTS_BOUND\n','actual sealed marker differs')
 originals.read(root/'module/SEALED',len(marker),sha(marker))
 rows=[r for r in manifest['files'] if r['path']=='evidence/RELEASE-BOUNDARIES.json']
 need(len(rows)==1 and rows[0]['bytes']<=33554432 and rows[0]['sha256']==binding['release_boundary_bundle_sha256'],'exact boundary member differs')
 row=rows[0];bundle=originals.read(root/'module/evidence/RELEASE-BOUNDARIES.json',row['bytes'],row['sha256'],33554432)
 state=h.validate_bundle(bundle,binding['release_boundary_bundle_sha256'], actual_context='mac')
 need(state['component_input_sha256']==binding['component_boundary_inputs_sha256']
      and state['policy_adoption_sha256']==ADOPTION_SHA
      and state['runtime_policy']['sha256']==POLICY_SHA,'sealed full boundary source differs')
 h.validate_shared_materials(state,source,result['config_raw'],result['service_raw'])
 need(state['native_chain_domains_flattened'] is False and state['legacy_native_count']==6
      and 1<=state['active_native_count']<=8 and len(state['legacy_chain'])==6,
      'sealed consumer omitted the separate legacy and active native domains')
 qualified={b['case_id'] for b,_i,c in state['chain']
            if b.get('package_sha256')==RUNTIME_SHA and c.get('closed') is True
            and c.get('component_qualified') is True}
 need({'NEG-01','NEG-02'}<=qualified,'actual new qualified component cases are still required')
 for name,raw in [('BUILD-RESULT.json',result['report_raw']),('provider/SOURCE-SEAL-v150-r10.json',result['source_seal_raw']),
                  ('local-config-r10-r1.json',result['config_raw']),('PHONE-SERVICE-INPUTS-v150-r10-r1.json',result['service_raw']),
                  ('module/seal-binding.json',result['binding_raw'])]:
  originals.read(root/name,len(raw),sha(raw))
 return result,{'source_seal_sha256':report['source_seal_sha256'],
  'configuration_sha256':report['configuration_sha256'],'service_inputs_sha256':report['service_inputs_sha256'],
  'module_manifest_sha256':report['module_manifest_sha256'],
  'component_boundary_inputs_sha256':binding['component_boundary_inputs_sha256'],
  'policy_adoption_inputs_sha256':ADOPTION_SHA,'policy_sha256':POLICY_SHA,
  'component_runtime_sha256':RUNTIME_SHA,'boundary_consumer_sha256':CONSUMER_PIN[1],
  'readiness_source_sha256':READINESS_PIN[1],'boot_id':h.BOOT}
@contextmanager
def production_modules(source):
 names=('provider_openai_compatible','phone_task_guards','phone_observation_tools')
 old={name:sys.modules.get(name) for name in names}
 modules={}
 try:
  for name in names:
   raw=source[name+'.py'];need(pin(raw)==dict(zip(('bytes','sha256'),SOURCE_PINS[name+'.py'])),'raw production module differs')
   module=types.ModuleType(name);module.__file__='pinned-production/'+name+'.py'
   sys.modules[name]=module
   exec(compile(raw,module.__file__,'exec',optimize=0),module.__dict__);modules[name]=module
  yield modules
 finally:
  for name in names:
   if old[name] is None:sys.modules.pop(name,None)
   else:sys.modules[name]=old[name]
def b64(raw):return base64.b64encode(raw).decode()
def decode64(text,maximum):
 need(isinstance(text,str),'base64 string required')
 raw=base64.b64decode(text,validate=True)
 need(len(raw)<=maximum and b64(raw)==text,'canonical bounded base64 required')
 return raw
def audit_no_effects(output):
 output=Path(output);observed={'network_or_process_attempts':0,'writes_outside_output':0,'allowed_mutations':0}
 def allowed(path):
  try:p=Path(os.path.abspath(os.fsdecode(path)))
  except TypeError:return False
  return p==output or output in p.parents
 def audit(event,args):
  if event in {'socket.__new__','socket.connect','socket.bind','subprocess.Popen','os.system','os.fork','os.posix_spawn','os.exec','pty.spawn','os.kill','os.killpg'}:
   observed['network_or_process_attempts']+=1
   raise PermissionError('component host fixture forbids process/network/signal: '+event)
  if event=='open' and len(args)>2 and isinstance(args[0],(str,bytes,os.PathLike)):
   flags=args[2]
   if isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
    if not allowed(args[0]):
     observed['writes_outside_output']+=1;raise PermissionError('write outside explicit fixture output')
    observed['allowed_mutations']+=1
  if event in {'os.mkdir','os.remove','os.rmdir','os.chmod','os.rename','os.link','os.symlink','os.truncate'}:
   for path in args[:2] if event in {'os.rename','os.link','os.symlink'} else args[:1]:
    if isinstance(path,(str,bytes,os.PathLike)):
     if not allowed(path):observed['writes_outside_output']+=1;raise PermissionError('mutation outside explicit fixture output')
     observed['allowed_mutations']+=1
 sys.addaudithook(audit)
 return observed
