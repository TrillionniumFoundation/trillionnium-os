"""Bound Root bridge: copy a new archive, read actual plans, or export originals.

No UI, policy write, process signal, model request, or service lifecycle call.
The caller separately invokes the frozen component entries for those operations.
"""
import argparse
import ast,contextlib,importlib.abc,importlib.util,io,shlex,sys,tarfile,types
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
G=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
A=Path('/proc/1/root')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
PKG='a33474b4479b8bb47acb6407525e30e82151e9f4b83dc0081851051003b144d7'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(v,s):
 if not v:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
def read(p,n=16*1024*1024):
 p=Path(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=n,'bounded original')
  with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(n+1)
  z=os.fstat(fd);s=p.lstat();need(len(b)==a.st_size and all(getattr(a,k)==getattr(z,k)==getattr(s,k) for k in META),'unstable original')
 finally:os.close(fd)
 return b,[getattr(a,k) for k in META]
def put(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def root():
 need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'Root bridge required')
 need(Path('/proc/self/attr/current').read_bytes().rstrip(b'\0\n')==b'u:r:magisk:s0','Root domain')
 need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==BOOT,'boot')
 need(G.resolve(strict=True)==G and G.stat().st_uid==G.stat().st_gid==0
 and stat.S_IMODE(G.stat().st_mode)==0o700,'canonical private base')
def descriptor(p,include_bytes=True,maximum=16*1024*1024):
 b,m=read(p,maximum);value={'path':str(p),'bytes':len(b),'sha256':sha(b),'metadata':m}
 if include_bytes:value['base64']=base64.b64encode(b).decode()
 return value
def context(label,lease_sha):
 need(re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',label) and re.fullmatch('[0-9a-f]{64}',lease_sha),'explicit label/lease')
 home=G/'native-guard-r10-r1'/label
 b,_=read(home/'LEASE.json');need(sha(b)==lease_sha,'actual lease pin');v=json.loads(b)
 need(v['label']==label and v['boot_id']==BOOT and v['package_sha256']==PKG,'actual lease binding')
 m,_=read(home/'package/MANIFEST.json');need(sha(m)==PKG,'actual package')
 for row in json.loads(m)['files']:
  b,_=read(home/'package'/row['path']);need(len(b)==row['bytes'] and sha(b)==row['sha256'],'package source pin')
 return home,v
def execute(a):
 root();os.umask(0o077)
 if a.operation=='copy-input':
  need(re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',a.label),'label')
  need(re.fullmatch('[0-9a-f]{64}',a.sha256) and type(a.bytes) is int and 0<=a.bytes<=32*1024*1024,'exact transferred file')
  allowed={a.label+'.tar.gz',a.label+'.stage.py',a.label+'.CLOSURE.json',a.label+'.INVENTORY.json'}
  allowed.update(a.label+'-'+p+'.witness.tar.gz' for p in ('setup','before-guard','after-guard'))
  need(a.name in allowed,'explicit one-case staging file')
  source=A/'data/local/tmp/hepta-phone-local-v150-r1'/('hepta-native-guard-'+a.name)
  b,m=read(source,32*1024*1024);need(len(b)==a.bytes and sha(b)==a.sha256,'actual pushed bytes')
  target=G/'native-guard-staging-r10-r1'
  try:s=target.lstat()
  except FileNotFoundError:
   target.mkdir(mode=0o700)
   for parent in (target,target.parent):
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
   s=target.lstat()
  need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'private staging root')
  put(target/a.name,b)
  return {'state':'EXACT_INPUT_COPIED_CREATE_ONLY','source':str(source),'source_metadata':m,
  'target':descriptor(target/a.name,False,32*1024*1024),'effects':0}
 home,lease=context(a.label,a.lease_sha256)
 if a.operation=='phase-originals':
  need(a.phase in ('setup','before-guard','after-guard'),'phase')
  target=home/('ROOT-'+a.phase.upper()+'-PLAN.json');deadline=time.monotonic()+(60 if a.phase=='setup' else 25)
  while True:
   try:target.lstat();break
   except FileNotFoundError as e:need(e.errno==2,'plan read error')
   for name in ('LIFECYCLE-FAILURE.json','PROVIDER-ENDED.json','LIFECYCLE-ENDED.json'):
    try:(home/name).lstat()
    except FileNotFoundError:continue
    return {'state':'ORIGINAL_COMPONENT_ENDED_BEFORE_PHASE','phase':a.phase,'original':descriptor(home/name),'effects':0}
   need(time.monotonic()<deadline and time.time_ns()//1000000<lease['expires_unix_ms'],'one bounded original phase wait expired')
   time.sleep(.1)
  rows={name:descriptor(home/name) for name in ('ACCEPTED.json','BOUND-CONTRACT.json',target.name)}
  accepted=json.loads(base64.b64decode(rows['ACCEPTED.json']['base64']));bound=json.loads(base64.b64decode(rows['BOUND-CONTRACT.json']['base64']))
  plan=json.loads(base64.b64decode(rows[target.name]['base64']))
  need(plan['scope']==accepted['scope'] and plan['phase']==a.phase and plan['contract_sha256']==accepted['contract_sha256']
  and bound['lease_sha256']==a.lease_sha256,'actual accepted phase binding')
  return {'state':'ACTUAL_PHASE_ORIGINALS_READ','phase':a.phase,'scope':accepted['scope'],'files':rows,'effects':0}
 if a.operation=='role-end':
  deadline=time.monotonic()+30
  while True:
   try:(home/'LIFECYCLE-ENDED.json').lstat();break
   except FileNotFoundError as e:need(e.errno==2,'role end read error')
   need(time.monotonic()<deadline,'one bounded original role-end wait expired');time.sleep(.1)
  return {'state':'LIFECYCLE_END_ORIGINAL_READ','file':descriptor(home/'LIFECYCLE-ENDED.json'),'effects':0}
 if a.operation=='snapshot-chunk':
  path=G/'native-guard-snapshots-r10-r1'/(a.label+'-capture-01')/'ORIGINALS.tar.gz'
  b,m=read(path,64*1024*1024);need(len(b)==a.bytes and sha(b)==a.sha256,'actual snapshot archive')
  need(type(a.index) is int and 0<=a.index<(len(b)+524287)//524288,'chunk index')
  offset=a.index*524288;raw=b[offset:offset+524288]
  return {'state':'ORIGINAL_SNAPSHOT_CHUNK','archive_sha256':sha(b),'archive_bytes':len(b),'metadata':m,
  'index':a.index,'offset':offset,'bytes':len(raw),'sha256':sha(raw),'base64':base64.b64encode(raw).decode(),'effects':0}
 if a.operation=='boundary-original':
  return {'state':'ORIGINAL_LATE_BOUNDARY_READ','file':descriptor(G/'native-guard-boundaries-r10-r1'/(lease['nonce']+'.json')),'effects':0}
 raise ValueError('unreviewed bridge operation')
def main():
 p=argparse.ArgumentParser();p.add_argument('operation',choices=('copy-input','phase-originals','role-end','snapshot-chunk','boundary-original'))
 p.add_argument('--label',required=True);p.add_argument('--lease-sha256');p.add_argument('--phase');p.add_argument('--name')
 p.add_argument('--sha256');p.add_argument('--bytes',type=int);p.add_argument('--index',type=int)
 p.add_argument('--execute-root-bridge-once',action='store_true');a=p.parse_args()
 if not a.execute_root_bridge_once:print(json.dumps({'state':'PREVIEW_NO_PHONE_READ_OR_WRITE'}));return 0
 print(json.dumps(execute(a),sort_keys=True,separators=(',',':')));return 0
EPOCH_PUBLICATION_WIRE_MAX_BYTES = 49152
EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES = 2097152
def epoch_publication_wire_value(raw):
 import base64 as wb
 import hashlib as wh
 import json as wj
 import zlib as wz
 def require(ok, message):
  if not ok: raise ValueError(message)
 def encode(value):
  return (wj.dumps(value, sort_keys=True, separators=(',', ':'),
  ensure_ascii=False, allow_nan=False)+'\n').encode('utf-8')
 def pairs(items):
  value={}
  for key,item in items:
   require(type(key) is str and key not in value,'duplicate publication wire field')
   value[key]=item
  return value
 def parse(body):
  return wj.loads(body.decode('utf-8','strict'),object_pairs_hook=pairs,
  parse_constant=lambda _value:require(False,'nonfinite publication wire data'))
 def bare(body): return {'bytes':len(body),'sha256':wh.sha256(body).hexdigest()}
 def exact_pin(value, maximum):
  require(type(value) is dict and set(value)=={'bytes','sha256'}
  and type(value['bytes']) is int and 0<value['bytes']<=maximum
  and type(value['sha256']) is str and len(value['sha256'])==64
  and all(x in '0123456789abcdef' for x in value['sha256']),
  'strict bounded publication wire byte pin required')
 require(type(raw) is bytes and 0<len(raw)<=EPOCH_PUBLICATION_WIRE_MAX_BYTES,
 'complete publication wire exceeds its source-fixed bound')
 value=parse(raw)
 require(type(value) is dict and set(value)=={'schema','encoding','uncompressed',
 'compressed','payload_base64'} and encode(value)==raw
 and value['schema']=='hepta.native-guard.epoch-publication-wire.v1'
 and value['encoding']=='zlib+base64','exact canonical publication wire required')
 exact_pin(value['uncompressed'],EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES)
 exact_pin(value['compressed'],EPOCH_PUBLICATION_WIRE_MAX_BYTES)
 text=value['payload_base64']
 require(type(text) is str and len(text)<=4*((EPOCH_PUBLICATION_WIRE_MAX_BYTES+2)//3),
 'bounded publication wire base64 required before decoding')
 packed=wb.b64decode(text,validate=True)
 require(wb.b64encode(packed).decode('ascii')==text
 and bare(packed)==value['compressed'],'canonical complete compressed pin differs')
 decoder=wz.decompressobj()
 body=decoder.decompress(packed,EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES+1)
 require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
 and len(body)<=EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES
 and bare(body)==value['uncompressed'],
 'publication data must be one complete bounded stream without tails or a second member')
 observation=parse(body)
 require(type(observation) is dict and encode(observation)==body
 and observation.get('schema')=='hepta.native-guard.epoch-publication-observation.v1',
 'publication observation must retain its canonical actual JSON bytes')
 return body
def epoch_publication_wire_from_original(raw):
 import base64 as wb
 import hashlib as wh
 import json as wj
 import zlib as wz
 if type(raw) is not bytes or not 0<len(raw)<=EPOCH_PUBLICATION_OBSERVATION_MAX_BYTES:
  raise ValueError('source-fixed publication observation size exceeded before compression')
 packed=wz.compress(raw,9)
 value={'schema':'hepta.native-guard.epoch-publication-wire.v1','encoding':'zlib+base64',
 'uncompressed':{'bytes':len(raw),'sha256':wh.sha256(raw).hexdigest()},
 'compressed':{'bytes':len(packed),'sha256':wh.sha256(packed).hexdigest()},
 'payload_base64':wb.b64encode(packed).decode('ascii')}
 wire=(wj.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=False,
 allow_nan=False)+'\n').encode('utf-8')
 if len(wire)>EPOCH_PUBLICATION_WIRE_MAX_BYTES:
  raise ValueError('complete serialized publication wire exceeds source-fixed output pool')
 if epoch_publication_wire_value(wire)!=raw:
  raise ValueError('publication wire lost original bytes')
 return wire
EPOCH_BRIDGE_BINDING = None
EPOCH_BRIDGE_PUBLICATION_SECONDS = 90
def _eb_exact(value, fields, message):
 need(type(value) is dict and set(value) == set(fields), message)
def _eb_encoded(value):
 return (json.dumps(value, sort_keys=True, separators=(',', ':'),
 ensure_ascii=False, allow_nan=False)+'\n').encode('utf-8')
def _eb_strict(raw):
 def pairs(items):
  result = {}
  for key, value in items:
   need(type(key) is str and key not in result, 'duplicate epoch bridge field')
   result[key] = value
  return result
 return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
 parse_constant=lambda _x: need(False, 'nonfinite epoch bridge value'))
def _eb_pin(row, *, original=False, maximum=16*1024*1024):
 _eb_exact(row, {'path', 'bytes', 'sha256', 'metadata'} if original
 else {'path', 'bytes', 'sha256'}, 'exact epoch bridge original pin required')
 path = row['path']
 need(type(path) is str and Path(path).is_absolute() and str(Path(path)) == path
 and '..' not in Path(path).parts and '\0' not in path,
 'canonical absolute original path required')
 need(type(row['bytes']) is int and 0 <= row['bytes'] <= maximum
 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
 'bounded typed complete original identity required')
 if original:
  value = row['metadata']
  need(type(value) is list and len(value) == 9
  and all(type(x) is int and x >= 0 for x in value)
  and stat.S_ISREG(value[2]) and value[5] == 1 and value[6] == row['bytes'],
  'actual regular original full9 required')
 return row
def epoch_bridge_binding_value():
 value = EPOCH_BRIDGE_BINDING
 _eb_exact(value, {'schema', 'runtime', 'combination', 'shared_materials',
 'pure_verifier', 'source_derivation', 'generation', 'bridge_template_slots',
 'template'}, 'actual final epoch bridge generation is not bound')
 need(value['schema'] == 'hepta.native-guard.epoch-bridge-source-binding.v1'
 and value['bridge_template_slots'] == ['EPOCH_BRIDGE_BINDING'],
 'only the one explicitly reviewed bridge source slot may change')
 for name in ('runtime', 'combination', 'shared_materials', 'pure_verifier',
 'source_derivation', 'generation'):
  _eb_pin(value[name])
  need(value[name]['bytes'] > 0, 'source binding cannot be an empty original')
 _eb_exact(value['template'], {'bytes', 'sha256'}, 'unbound bridge template pin required')
 need(type(value['template']['bytes']) is int and 0 < value['template']['bytes'] <= 131072
 and type(value['template']['sha256']) is str
 and re.fullmatch('[0-9a-f]{64}', value['template']['sha256']),
 'complete reviewed bridge template identity required')
 return value
def epoch_bridge_publication_context(value, *, binding):
 _eb_exact(value, {'epoch_id', 'boot_id', 'generation', 'terminal',
 'root_source_manifest', 'bridge_source'}, 'publication expected-observation fields differ')
 need(value['epoch_id'] == 'legacy902-active01' and value['boot_id'] == BOOT,
 'fixed epoch and original boot are mandatory')
 for name in ('generation', 'terminal'):
  _eb_pin(value[name], original=True)
 for name in ('root_source_manifest', 'bridge_source'):
  _eb_pin(value[name], maximum=131072)
 need({key: value['generation'][key] for key in ('path', 'bytes', 'sha256')}
 == binding['generation'], 'actual source catalog differs from the bound bridge')
 return value
class _EpochBridgeRuntime:
 """Read the whole actual package before executing any current module.

    The physical paths in this loader are real GNU phone files. A retained
    complete raw map is used for imports after the whole manifest/source gate;
    no historical source is executed and no virtual path is used as full9.
    """
 def __init__(self, package, manifest, budget_check):
  need(callable(budget_check), 'one publication clock must cover every source read')
  self.package = Path(package)
  self.expected = manifest
  self.check = budget_check
  self.held = []
  self.directories = {}
  self.bodies = {}
  self.originals = {}
  self.modules = {}
  self.finder = None
  self.saved_path = None
  self.saved_dont_write = None
  self.names = {}
 def metadata(self, value):
  return [getattr(value, key) for key in META]
 def original(self, path, pin, *, private=True):
  self.check()
  path = Path(path)
  _eb_pin(pin)
  need(str(path) == pin['path'], 'physical source path differs from its exact pin')
  descriptor = None
  parents = []
  filefd = None
  try:
   parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
   parents.append((parent, None, None, self.metadata(os.fstat(parent))))
   for name in path.parts[1:-1]:
    self.check()
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    | os.O_CLOEXEC, dir_fd=parent)
    parents.append((child, parent, name, self.metadata(os.fstat(child))))
    parent = child
   before = self.metadata(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
   need(stat.S_ISREG(before[2]) and before[5] == 1 and before[6] == pin['bytes'],
   'exact regular source required before opening')
   if private:
    need(before[3:6] == [0, 0, 1] and stat.S_IMODE(before[2]) == 0o600,
    'actual phone source must be a root-owned private regular file')
   filefd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
   | os.O_CLOEXEC, dir_fd=parent)
   need(self.metadata(os.fstat(filefd)) == before, 'source changed while opening')
   parts = []
   left = pin['bytes'] + 1
   while left:
    self.check()
    part = os.read(filefd, min(65536, left))
    if not part:
     break
    parts.append(part)
    left -= len(part)
   raw = b''.join(parts)
   need(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'],
   'complete phone source bytes differ from their fixed pin')
   need(self.metadata(os.fstat(filefd)) == before
   == self.metadata(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
   == self.metadata(path.lstat()), 'held/named/canonical original full9 changed')
   for fd, previous, name, initial in parents:
    need(self.metadata(os.fstat(fd)) == initial and (previous is None
    or self.metadata(os.stat(name, dir_fd=previous, follow_symlinks=False)) == initial),
    'source parent changed during the complete read')
   descriptor = dict(pin, metadata=before)
   self.held.append((filefd, parents, path, descriptor, raw))
   filefd = None
   parents = []
   return raw, descriptor
  finally:
   if filefd is not None:
    os.close(filefd)
   for item in reversed(parents):
    os.close(item[0])
 def recheck(self):
  for fd, parents, path, original, raw in self.held:
   self.check()
   before = original['metadata']
   need(self.metadata(os.fstat(fd)) == before
   == self.metadata(os.stat(path.name, dir_fd=parents[-1][0], follow_symlinks=False))
   == self.metadata(path.lstat()), 'a held publication source was renamed or changed')
   os.lseek(fd, 0, os.SEEK_SET)
   digest = hashlib.sha256()
   count = 0
   while count <= len(raw):
    self.check()
    part = os.read(fd, min(65536, len(raw)+1-count))
    if not part:
     break
    count += len(part)
    digest.update(part)
   need(count == len(raw) and digest.hexdigest() == original['sha256'],
   'retained current source bytes changed at the final bookend')
   for parent, previous, name, initial in parents:
    held = self.metadata(os.fstat(parent))
    need(held == initial and (previous is None
    or self.metadata(os.stat(name, dir_fd=previous, follow_symlinks=False)) == held),
    'canonical source parent changed across publication')
  for path, (fd, initial, names) in self.directories.items():
   self.check()
   need(self.metadata(os.fstat(fd)) == initial == self.metadata(Path(path).lstat())
   and sorted(os.listdir(fd)) == names, 'actual package directory changed')
 def __enter__(self):
  import importlib.abc
  import importlib.util
  import sys
  loader = self
  try:
   _eb_pin(self.expected, maximum=262144)
   pin = dict(self.expected, path=str(self.package/'MANIFEST.json'))
   self.manifest_raw, manifest_original = self.original(self.package/'MANIFEST.json', pin)
   manifest = _eb_strict(self.manifest_raw)
   rows = manifest.get('files')
   need(manifest.get('schema') == 'hepta.native-guard.adapter-package.v1'
   and manifest.get('state') == 'HOST_REVIEWED_NOT_PHONE_QUALIFIED'
   and type(rows) is list and len(rows) == 32,
   'actual exactly32 runtime manifest required before any target import')
   total = len(self.manifest_raw)
   for row in rows:
    _eb_exact(row, {'path', 'bytes', 'sha256'}, 'exact32 source row required')
    relative, size = row['path'], row['bytes']
    need(type(relative) is str and relative.startswith(('source/', 'reference/'))
    and len(relative.split('/')) == 2 and relative.split('/')[1] not in ('', '.', '..')
    and '\0' not in relative and relative not in self.bodies and type(size) is int
    and size > 0 and ((relative.endswith('.py') and size <= 131072)
    or (relative.endswith('.json') and size <= 16*1024*1024)),
    'source path/type/byte bound differs')
    total += size
    need(total <= 32*1024*1024, 'one complete package byte pool exceeded')
    body, original = self.original(self.package/relative,
    dict(row, path=str(self.package/relative)))
    self.bodies[relative] = body
    self.originals[relative] = original
    if relative.endswith('.py'):
     name = Path(relative).stem
     need(name not in self.names, 'reviewed module names are ambiguous')
     self.names[name] = relative
   for relative in ('', 'source', 'reference'):
    self.check()
    path = self.package/relative
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
     initial = self.metadata(os.fstat(fd))
     names = sorted(os.listdir(fd))
     wanted = ['MANIFEST.json', 'reference', 'source'] if not relative else sorted(
     p.split('/')[1] for p in self.bodies if p.startswith(relative+'/'))
     need(initial[3:5] == [0, 0] and stat.S_IMODE(initial[2]) == 0o700
     and initial == self.metadata(path.lstat()) and names == wanted,
     'whole private package directory is not the exact manifest closed set')
     self.directories[str(path)] = (fd, initial, names)
     fd = None
    finally:
     if fd is not None:
      os.close(fd)
   required = ('component_common', 'native_proc_profile', 'component_lifecycle',
   'stage_component', 'prepare_component', 'late_boundary', 'component_snapshot')
   need(all(name in self.names and self.names[name].startswith('source/') for name in required)
   and all(name not in sys.modules for name in self.names),
   'foreign or missing current modules before whole32 gate')
   self.recheck()
   class Finder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
     if fullname in loader.names:
      return importlib.util.spec_from_loader(fullname, self,
      origin=str(loader.package/loader.names[fullname]))
     return None
    def create_module(self, spec):
     return None
    def exec_module(self, module):
     relative = loader.names[module.__name__]
     raw = loader.bodies[relative]
     module.__dict__.update({'__file__': str(loader.package/relative),
     '__actual_context__': 'phone',
     '__reviewed_package_manifest_raw__': loader.manifest_raw,
     '__reviewed_package_sources__': loader.bodies,
     '__reviewed_source_sha256__': sha(raw),
     '__reviewed_package_physical_observation__': loader.originals,
     '__epoch_budget_check__': loader.check})
     loader.modules[module.__name__] = module
     loader.check()
     exec(compile(raw, str(loader.package/relative), 'exec'), module.__dict__)
     loader.check()
   self.saved_path = list(sys.path)
   self.saved_dont_write = sys.dont_write_bytecode
   sys.dont_write_bytecode = True
   self.finder = Finder()
   sys.meta_path.insert(0, self.finder)
   for name in required:
    __import__(name)
   self.manifest = manifest
   self.manifest_original = manifest_original
   return self
  except BaseException:
   self.__exit__(None, None, None)
   raise
 def __exit__(self, kind, error, traceback):
  import sys
  errors = []
  if self.finder is not None:
   try:
    need(self.finder in sys.meta_path, 'publication source finder was replaced')
    sys.meta_path.remove(self.finder)
   except BaseException as failure:
    errors.append(failure)
  for name, module in self.modules.items():
   if sys.modules.get(name) is module:
    del sys.modules[name]
   elif name in sys.modules:
    errors.append(ValueError('a reviewed publication module was replaced'))
  if self.saved_path is not None:
   sys.path[:] = self.saved_path
   sys.dont_write_bytecode = self.saved_dont_write
  for fd, parents, _path, _original, _raw in reversed(self.held):
   for handle in [fd]+[item[0] for item in reversed(parents)]:
    try:
     os.close(handle)
    except BaseException as failure:
     errors.append(failure)
  for fd, _initial, _names in self.directories.values():
   try:
    os.close(fd)
   except BaseException as failure:
    errors.append(failure)
  self.held = []
  self.directories = {}
  if errors:
   raise ValueError('owned publication source cleanup was incomplete: '+
   ','.join(type(item).__name__ for item in errors))
  return False
def _epoch_bridge_empty_stdin(check):
 import fcntl
 import select
 original = fcntl.fcntl(0, fcntl.F_GETFL)
 try:
  fcntl.fcntl(0, fcntl.F_SETFL, original | os.O_NONBLOCK)
  while True:
   check()
   try:
    raw = os.read(0, 1)
   except BlockingIOError:
    select.select([0], [], [], .05)
    continue
   need(raw == b'', 'publication operation requires actual empty stdin EOF')
   return
 finally:
  fcntl.fcntl(0, fcntl.F_SETFL, original)
def _epoch_bridge_kernel_read(path, maximum):
 fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
 try:
  value = bytearray()
  while len(value) <= maximum:
   raw = os.read(fd, maximum+1-len(value))
   if not raw:
    break
   value.extend(raw)
  need(len(value) <= maximum, 'fixed Root kernel identity read exceeds its exact bound')
  return bytes(value)
 finally:
  os.close(fd)
def epoch_bridge_publication_read(arguments, *, budget_check=None):
 binding = epoch_bridge_binding_value()
 deadline = time.monotonic()+EPOCH_BRIDGE_PUBLICATION_SECONDS
 def check():
  if budget_check is not None:budget_check()
  need(time.monotonic() < deadline, 'one full publication source/read/bookend clock expired')
 need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0,
 'actual Root credentials required for the fixed publication read')
 need(_epoch_bridge_kernel_read('/proc/self/attr/current', 128).rstrip(b'\0\n') == b'u:r:magisk:s0'
 and _epoch_bridge_kernel_read('/proc/sys/kernel/random/boot_id', 64).decode().strip() == BOOT,
 'actual fixed native Root domain and boot differ')
 _epoch_bridge_empty_stdin(check)
 label = arguments.label
 need(type(label) is str and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}', label)
 and type(arguments.lease_bytes) is int and 0 < arguments.lease_bytes <= 262144
 and type(arguments.lease_sha256) is str
 and re.fullmatch('[0-9a-f]{64}', arguments.lease_sha256),
 'one actual case label and complete lease identity required')
 text = arguments.observation_context_base64
 need(type(text) is str and len(text) <= 16384, 'bounded canonical publication context required')
 raw_context = base64.b64decode(text, validate=True)
 need(base64.b64encode(raw_context).decode('ascii') == text,
 'publication context encoding is not canonical')
 expected = epoch_bridge_publication_context(_eb_strict(raw_context), binding=binding)
 need(_eb_encoded(expected) == raw_context, 'publication context bytes are not canonical')
 home = G/'native-guard-r10-r1'/label
 package = home/'package'
 with _EpochBridgeRuntime(package, binding['runtime'], check) as loaded:
  common = loaded.modules['component_common']
  late = loaded.modules['late_boundary']
  need(loaded.manifest.get('current_combination_sha256') == binding['combination']['sha256']
  and loaded.manifest.get('epoch_shared_materials') == binding['shared_materials'],
  'actual current MF does not bind the reviewed COMBO and actual17 manifest')
  lease_raw, lease_original = loaded.original(home/'LEASE.json', {'path':str(home/'LEASE.json'),
  'bytes':arguments.lease_bytes, 'sha256':arguments.lease_sha256})
  lease = _eb_strict(lease_raw)
  epoch = common.epoch_lease_protocol_value(lease)
  need(lease['label'] == label and lease['boot_id'] == BOOT
  and lease['package_sha256'] == binding['runtime']['sha256']
  and _eb_encoded(epoch['generation']) == _eb_encoded(expected['generation']),
  'actual lease label/boot/package/catalog differs')
  check()
  collected = late.load_epoch_publication_inputs(lease, budget_check=check)
  _eb_exact(collected, {'manifest','originals_by_path','verified'},
  'complete post-COMMIT collector output required')
  manifest = collected['manifest']
  original_map = collected['originals_by_path']
  verified = collected['verified']
  index = common.epoch_manifest_value(manifest, original_map, binding=common.epoch_binding_value())
  slots = verified['registry']['slots']
  need(verified['registry']['mode'] == 'published' and slots
  and slots[-1]['terminal'] is not None
  and _eb_encoded(slots[-1]['terminal']['original']) == _eb_encoded(expected['terminal'])
  and _eb_encoded(slots[-1]['claim']['value']['generation']) == _eb_encoded(expected['generation'])
  and lease_original['path'] in index['files']
  and _eb_encoded(lease_original) == _eb_encoded(index['files'][lease_original['path']]),
  'complete publication registry is not the exact actual terminal/catalog/lease frontier')
  for name in ('generation','terminal'):
   row = expected[name]
   need(row['path'] in index['files']
   and _eb_encoded(index['files'][row['path']]) == _eb_encoded(row),
   'actual publication catalog or terminal original is omitted')
  manifest_raw = common._ep_encoded(manifest)
  final_manifest = late.recheck_epoch_capture_inputs(manifest, budget_check=check)
  need(common._ep_encoded(final_manifest) == manifest_raw,
  'publication complete final manifest differs from its first collection')
  observed = {'schema':'hepta.native-guard.epoch-publication-observation.v1',
  'state':'ACTUAL_COMPLETE_PUBLISHED_REGISTRY_READ', 'epoch_id':expected['epoch_id'],
  'boot_id':BOOT, 'manifest':manifest, 'generation':expected['generation'],
  'terminal':expected['terminal'], 'initial_manifest_sha256':sha(manifest_raw),
  'final_manifest_sha256':sha(common._ep_encoded(final_manifest)),
  'file_count':len(original_map), 'retained_bytes':sum(len(v) for v in original_map.values()),
  'source_reader_binding':{'root_source_manifest':expected['root_source_manifest'],
  'bridge_source':expected['bridge_source'], 'operation':'epoch-publication-read'},
  'rechecked_files':len(manifest['files']), 'rechecked_directories':len(manifest['directories']),
  'effects':{'ui_actions':0,'phone_native_dispatches':0,'model_requests':0,'signals_sent':0,
  'source_original_writes':0,'nonces_generated':0,'leases_created':0,
  'boundaries_published':0,'component_qualified':False,'business_qualified':False}}
  observed_raw = _eb_encoded(observed)
  wire = epoch_publication_wire_from_original(observed_raw)
  loaded.recheck()
  check()
 check()
 return wire
def epoch_bridge_dispatch():
 import sys
 if len(sys.argv) < 2 or sys.argv[1] != 'epoch-publication-read':
  return main()
 parser = argparse.ArgumentParser(allow_abbrev=False)
 parser.add_argument('operation', choices=('epoch-publication-read',))
 parser.add_argument('--label', required=True)
 parser.add_argument('--lease-bytes', required=True, type=int)
 parser.add_argument('--lease-sha256', required=True)
 parser.add_argument('--observation-context-base64', required=True)
 parser.add_argument('--execute-root-bridge-once', action='store_true')
 args = parser.parse_args()
 if not args.execute_root_bridge_once:
  print(json.dumps({'state':'PREVIEW_NO_PHONE_READ_OR_WRITE'}, sort_keys=True))
  return 0
 wire = epoch_bridge_publication_read(args)
 sys.stdout.buffer.write(wire)
 sys.stdout.buffer.flush()
 return 0
def _epoch_same_callback(a,b):
 return a is b or (type(a) is types.MethodType and type(b) is types.MethodType and a.__self__ is b.__self__ and a.__func__ is b.__func__)
def epoch_bridge_operation(request, *, request_raw, code_observation, budget_check):
 import sys
 need(callable(budget_check), 'the installed loader operation budget is mandatory')
 budget_check()
 common=sys.modules.get('component_common');stage=sys.modules.get('stage_component')
 need(common is not None and stage is not None
 and common.epoch_actual_context(globals())=='phone'
 and common.epoch_actual_context(common.__dict__)=='phone'
 and common.epoch_actual_context(stage.__dict__)=='phone',
 'bridge operations require the already verified actual phone modules')
 raw=globals().get('__reviewed_package_manifest_raw__')
 bodies=globals().get('__reviewed_package_sources__')
 need(type(raw) is bytes and type(bodies) is dict
 and stage.__dict__.get('__reviewed_package_manifest_raw__')==raw
 and stage.__dict__.get('__reviewed_package_sources__') is bodies
 and _epoch_same_callback(stage.__dict__.get('__epoch_budget_check__'),budget_check)
 and _epoch_same_callback(globals().get('__epoch_budget_check__'),budget_check),
 'bridge and stage must retain the same actual source map and clock')
 binding=epoch_bridge_binding_value()
 need(common._ep_same(request.get('runtime'),binding['runtime'])
 and common._ep_bare(raw)=={key:binding['runtime'][key] for key in ('bytes','sha256')},
 'bridge operation changed the complete source-bound current runtime')
 current,modules,fixed=stage.epoch_operation_request_value(request,
 request_raw=request_raw,code_observation=code_observation,budget_check=budget_check)
 need(current is common and modules['stage_component'] is stage,
 'operation gate returned another loaded module set')
 for key in ('combination','shared_materials'):
  need(common._ep_same(binding[key],fixed[key]),'bridge source binding changed '+key)
 need(common._ep_same(binding['template'],fixed['bridge_template'])
 and common._ep_same(code_observation['bridge_template'],binding['template'])
 and common._ep_same(code_observation['root_template'],fixed['root_template']),
 'bridge or Root source template differs from the current source authority')
 for key,source_key in (('pure_verifier','pure_verifier'),('source_derivation','derivation'),
 ('generation','generation')):
  need(binding[key]['path']==fixed['source_paths'][source_key],
  'bridge changed a fixed source generation origin')
 result=stage.epoch_execute_operation(request,request_raw=request_raw,
 code_observation=code_observation,bridge_binding=binding,budget_check=budget_check)
 budget_check()
 return stage.epoch_operation_result_value(request['operation'],result,request)
def epoch_root_host_support(api, *, actual_context):
 if actual_context!='mac' or not isinstance(api,types.ModuleType) or sys.modules.get(api.__name__) is not api:
  raise ValueError('explicit actual coordinator module and Mac context required')
 if Path(api.__file__).name!='run_component_root_once.py' or Path(__file__).name!='phone_chain_bridge.py':
  raise ValueError('actual Root3 source paths required')
 class EpochRootHostRuntime:
  def __init__(self, root_plan, *, budget_check):
   api.need(callable(budget_check),'enclosing host operation budget required')
   self.plan=root_plan;self.check=budget_check;self.reader=None;self.modules={};self.old_path=None
   self.names={};self.raws={};self.physical={};self.old_meta=None;self.old_modules={};self.old_dwb=None
  def __enter__(self):
   self.check();binding=api.epoch_root_binding_value()
   self.reader=api.EpochHostSourceReadSet(self.check)
   reader=self.reader
   def original(row,maximum=16777216):
    api._epub_pin(row,maximum=maximum)
    body,actual,_=reader.read(row['path'],maximum,row)
    return body,actual
   self.runtime_raw,self.runtime_original=original(binding['runtime'],262144)
   self.runtime=api.strict(self.runtime_raw);rows=self.runtime.get('files')
   api.need(self.runtime.get('schema')=='hepta.native-guard.adapter-package.v1'
   and self.runtime.get('state')=='HOST_REVIEWED_NOT_PHONE_QUALIFIED'
   and type(rows) is list and len(rows)==32,'actual current32 package required')
   package=Path(binding['runtime']['path']).parent;total=len(self.runtime_raw)
   for row in rows:
    api.need(type(row) is dict and set(row)=={'path','bytes','sha256'},'exact current source row required')
    rel=row['path'];size=row['bytes']
    api.need(type(rel) is str and len(rel.split('/'))==2 and rel.split('/')[0] in ('source','reference')
    and rel.split('/')[1] not in ('','.','..') and '\0' not in rel and rel not in self.raws
    and type(size) is int and 0<size and ((rel.endswith('.py') and size<=131072)
    or (rel.endswith('.json') and size<=16777216)), 'source path/type/size differs')
    total+=size;api.need(total<=33554432,'complete source bytes exceed the existing pool')
    self.raws[rel],self.physical[rel]=original(dict(row,path=str(package/rel)),
    131072 if rel.endswith('.py') else 16777216)
   for relative in ('','source','reference'):
    directory=package/relative
    before=api._epub_meta(os.lstat(directory));api.need(stat.S_ISDIR(before[2]),'actual package directory required')
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
     wanted=(['MANIFEST.json','reference','source'] if not relative else
     sorted(Path(p).name for p in self.raws if p.startswith(relative+'/')))
     api.need(sorted(os.listdir(fd))==wanted and api._epub_meta(os.fstat(fd))==before
     ==api._epub_meta(os.lstat(directory)),'complete package directory closed set differs')
    finally:os.close(fd)
   self.combination_raw,_=original(binding['combination'],16777216)
   self.shared_manifest_raw,_=original(binding['shared_materials'],262144)
   shared=api.strict(self.shared_manifest_raw);shared_rows=shared.get('files')
   api.need(type(shared_rows) is list and len(shared_rows)==17
   and self.runtime.get('epoch_shared_materials')==binding['shared_materials']
   and self.runtime.get('current_combination_sha256')==binding['combination']['sha256'],
   'whole actual shared17/runtime/COMBO linkage differs')
   self.shared={};shared_root=Path(binding['shared_materials']['path']).parent
   for row in shared_rows:
    api.need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['path']) is str
    and row['path'] not in self.shared and not Path(row['path']).is_absolute()
    and '..' not in Path(row['path']).parts,'exact shared original relative row required')
    self.shared[row['path']],_=original(dict(row,path=str(shared_root/row['path'])))
   pure_raw,self.pure_original=original(binding['pure_verifier'],131072)
   pure=types.ModuleType('epoch_reviewed_root_pure_source_gate');pure.__file__=binding['pure_verifier']['path']
   self.check();exec(compile(pure_raw,pure.__file__,'exec'),pure.__dict__);self.check()
   verify=getattr(pure,'verify_epoch_runtime_increment',None)
   api.need(callable(verify),'mandatory complete current four-input source verifier is missing')
   self.source_proof=verify(self.runtime_raw,self.raws,self.combination_raw,self.shared)
   api.need(type(self.source_proof) is dict,'current source gate did not return its structured proof')
   self.check();reader.recheck()
   self.root_sources=api.epoch_root_original_sources({'source_package':self.plan['root_source_manifest']})
   for rel in self.raws:
    if rel.endswith('.py'):
     name=Path(rel).stem;api.need(name not in self.names,'ambiguous reviewed module basename')
     self.names[name]=rel
   order=('component_common','native_proc_profile','component_lifecycle','stage_component',
   'prepare_component','late_boundary','component_snapshot')
   api.need(all(name in self.names for name in order),'all fixed epoch runtime modules required')
   api.need(all(name not in sys.modules for name in self.names),'runtime was imported before whole32/shared17 gate')
   self.old_path=list(sys.path);self.old_meta=list(sys.meta_path);self.old_dwb=sys.dont_write_bytecode
   holder=self
   class Loader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
    def find_spec(self,name,path=None,target=None):
     if name in holder.names:
      return importlib.util.spec_from_loader(name,self,origin=str(package/holder.names[name]))
     return None
    def create_module(self,spec):return None
    def exec_module(self,module):
     rel=holder.names[module.__name__];body=holder.raws[rel]
     module.__dict__.update({'__file__':str(package/rel),'__actual_context__':'mac',
     '__reviewed_package_sources__':holder.raws,'__reviewed_package_manifest_raw__':holder.runtime_raw,
     '__reviewed_package_physical_observation__':holder.physical,
     '__reviewed_source_sha256__':api.sha(body),'__epoch_budget_check__':holder.check})
     holder.check();exec(compile(body,str(package/rel),'exec'),module.__dict__);holder.check()
   try:
    sys.dont_write_bytecode=True;sys.meta_path.insert(0,Loader())
    for name in order:self.modules[name]=__import__(name)
    self.check();return self
   except BaseException:
    self.__exit__(*sys.exc_info());raise
  def __exit__(self,kind,error,tb):
   try:
    if self.reader is not None:self.reader.recheck()
   finally:
    if self.old_path is not None:sys.path[:]=self.old_path
    if self.old_meta is not None:sys.meta_path[:]=self.old_meta
    if self.old_dwb is not None:sys.dont_write_bytecode=self.old_dwb
    for name in self.names:
     sys.modules.pop(name,None)
   return False
 def epoch_preflight_plan(plan_raw):
  binding=api.epoch_root_binding_value();plan=api.strict(plan_raw)
  api.need(type(plan) is dict and type(plan.get('schema')) is str
  and plan['schema'] in ('hepta.native-guard.epoch-root-code-initialize-plan.v1',
  'hepta.native-guard.epoch-root-allocation-plan.v1'), 'explicit epoch Root plan required; legacy run is unavailable')
  mapping={'runtime':'runtime','combination':'combination','shared_materials':'shared_materials',
  'pure_verifier':'pure_verifier','derivation':'source_derivation'}
  for name,key in mapping.items():
   api.need(api._epub_compact(plan.get(name))==api._epub_compact(binding[key]),'Root plan source-generation descriptor differs: '+name)
  check=api.epoch_host_deadline(90)
  with EpochRootHostRuntime(plan,budget_check=check) as current:
   stage=current.modules['stage_component'];initialize=plan['schema'].endswith('code-initialize-plan.v1')
   validator=getattr(stage,'epoch_initialize_plan_value' if initialize else 'epoch_allocation_plan_value',None)
   api.need(callable(validator),'current pure epoch plan validator is absent')
   value=validator(plan_raw)
   api.need(api._epub_compact(value)==api._epub_compact(plan),'pure current plan interpretation differs')
   source={'runtime_raw':current.runtime_raw,'runtime_sources':dict(current.raws),
   'root_sources':current.root_sources,'source_proof':current.source_proof,
   'source_observations':{p:row[0] for p,row in current.reader.records.items()}}
   for function in ('epoch_initialize','epoch_allocate','epoch_prepare_material','epoch_operation_result_value'):
    api.need(callable(getattr(stage,function,None)),'mandatory current epoch implementation is absent: '+function)
   check()
  return plan,source
 def _epoch_host_io_worker(value, deadline):
  reader=api.EpochPublicationReadSet(deadline);action=value['action'];rows=value['rows']
  api.need(action in ('write','read') and type(rows) is list and 0<len(rows)<=1024,
  'finite host original operation required')
  root=Path(value['root']);api.need(str(root).startswith('/home/alex/codex-native-guard-chain-r10-r1/')
  and re.fullmatch('[0-9a-f]{32}',root.name),'fixed actual case host root required')
  raw=api.read_stdin(value['input']['bytes'],api._EpochOperationChannel(reader,value['input']['bytes']+1))
  api.need(api.sha(raw)==value['input']['sha256'],'complete actual host input differs')
  reader.physical_bytes+=len(raw)
  api.need(reader.physical_bytes<=16777216,'actual host carrier stdin exceeds the same physical read pool')
  packet=api._epub_strict(raw);api.need(api._epub_compact(packet)==raw and type(packet) is dict,'canonical host data required')
  saved={};results={}
  if action=='write':
   api.need(set(packet)=={r['path'] for r in rows},'complete declared host input set required')
   if value['create_root']:api._eop_private_host_directory(str(root),reader,create=True)
   else:api._eop_private_host_directory(str(root),reader,create=False)
   directories={str(root)}
   for row in rows:
    relative=Path(row['path']);api.need(not relative.is_absolute() and '..' not in relative.parts
    and relative.parts and relative.parts[0] in ('material','inputs','plans','closure-inputs','CLOSURE-PLAN.json'),
    'host material escaped its fixed namespace')
    body=base64.b64decode(packet[row['path']],validate=True)
    api.need(base64.b64encode(body).decode()==packet[row['path']]
    and len(body)==row['bytes'] and api.sha(body)==row['sha256'],'complete host original differs')
    prefix=root
    for name in relative.parts[:-1]:
     prefix=prefix/name
     if str(prefix) not in directories:
      try:api._eop_private_host_directory(str(prefix),reader,create=False)
      except FileNotFoundError:api._eop_private_host_directory(str(prefix),reader,create=True)
      directories.add(str(prefix))
    target=str(root/relative)
    saved[target]=api._eop_write_host_original(target,body,reader,8388608,members_bound=1024)
   for target,pinrow in saved.items():
    body,actual,_=reader.read(target,8388608,pinrow)
    results[target]={'original':actual}
  else:
   api.need(packet=={} and value['create_root'] is False,'read operation has no hidden input or mutation')
   for row in rows:
    path=row['path'];base='/home/alex/codex-hepta-natural-'+value['label']+'-root-v150/'
    fixture='/home/alex/codex-hepta-native-guard-fixtures-r10-r1/'+root.name+'/'
    api.need(path.startswith(str(root)+'/') or path.startswith(base) or path.startswith(fixture),
    'read escaped the actual case material/sender/fixture namespace')
    if 'maximum' in row:
     api.need(set(row)=={'path','maximum'} and type(row['maximum']) is int
     and 0<row['maximum']<=8388608,'explicit first observation bound required')
     maximum=row['maximum'];expected=None
    else:
     api._epub_pin(row,full=('metadata' in row),maximum=8388608);maximum=row['bytes'];expected=row
    if value['wait_path']==path:
     while True:
      reader.check()
      try:os.lstat(path);break
      except FileNotFoundError:time.sleep(0.05)
    body,actual,_=reader.read(path,maximum,expected)
    results[row['path']]={'original':actual,'body_base64':base64.b64encode(body).decode()}
  reader.recheck()
  result={'schema':'hepta.native-guard.epoch-owned-host-originals.v1','action':action,
  'originals':results,'physical_read_bytes':reader.physical_bytes,'physical_read_count':reader.read_count,
  'physical_read_limit':16777216,'automatic_retry':False,'phone_calls':0}
  out=api._epub_compact(result);api.need(len(out)<=16*1024*1024,'complete host original transport output bound')
  api.need(api.write_channel(1,out,deadline),'host original output not drained within its original clock')
 def epoch_host_io(chain, phase, *, files=None, originals=None, create_root=False, wait_path=None):
  api.need((files is None)!=(originals is None),'one finite host input direction required')
  source=chain.sources['sources']['source/run_component_root_once.py']['raw']
  api.epoch_root_template_view(source);action='write' if files is not None else 'read'
  if files is not None:
   api.need(type(files) is dict and 0<len(files)<=1024 and sum(map(len,files.values()))<=4*1024*1024,
   'host data and its three complete physical readbacks exceed the fixed16MiB pool')
   rows=[dict(api.desc(k,v)) for k,v in sorted(files.items())]
   data={k:base64.b64encode(v).decode() for k,v in sorted(files.items())}
  else:
   api.need(type(originals) is list and 0<len(originals)<=1024
   and sum(r.get('bytes',r.get('maximum',0)) for r in originals)<=8*1024*1024,
   'two complete host reads exceed their fixed16MiB pool')
   rows=originals;data={}
  raw=api._epub_compact(data)
  if files is not None:
   api.need(len(raw)+3*sum(map(len,files.values()))+65536<=16777216,
   'stdin plus three complete owned write/readback passes exceed the same16MiB pool')
  value={'action':action,'rows':rows,'root':chain.remote_root,'label':chain.p['label'],
  'create_root':create_root,'wait_path':wait_path,
  'input':{'bytes':len(raw),'sha256':api.sha(raw)}}
  tree=ast.parse(source);lines=source.splitlines(keepends=True)
  nodes={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
  selected=('channel_flags','read_stdin','write_channel','_EpochOperationChannel',
  '_eop_private_host_directory','_eop_write_host_original')
  code=api.epoch_owned_source_sections(source)+'\nimport base64,fcntl,select\n'+api.epoch_publication_source_sections(source)
  code+='\n\n'.join(b''.join(lines[nodes[n].lineno-1:nodes[n].end_lineno]).decode() for n in selected)
  timeout=120 if wait_path is not None else 90
  code+='\n'+api.epoch_bridge_host_worker_source(chain.sources['sources']['source/phone_chain_bridge.py']['raw'],'_epoch_host_io_worker')
  code+='\nINPUTS='+repr(value)+'\nDEADLINE=time.monotonic()+'+str(timeout-5)+'\n_epoch_host_io_worker(INPUTS,DEADLINE)\n'
  argv=api.SSH[:-4]+[shlex.join(['/usr/bin/python3','-I','-B','-c',code])]
  api.need(len(argv[-1].encode())<65536,'complete SSH host-data command exceeds fixed wire limit')
  encoded=chain.execute_process(phase,argv,timeout,input_raw=raw)
  result=api.strict(encoded)
  api.need(type(result) is dict and result.get('schema')=='hepta.native-guard.epoch-owned-host-originals.v1'
  and result['action']==action and result['automatic_retry'] is False
  and type(result['phone_calls']) is int and result['phone_calls']==0,'owned host data result differs')
  wanted={str(Path(chain.remote_root)/r['path']):r for r in rows} if action=='write' else {r['path']:r for r in rows}
  api.need(set(result['originals'])==set(wanted),'host result omitted or added an original')
  retained={}
  for path,row in result['originals'].items():
   pinrow=row['original'];api._epub_pin(pinrow,full=True,maximum=8388608)
   api.need(pinrow['path']==path and all(api._epub_compact(pinrow[k])==api._epub_compact(v)
   for k,v in wanted[path].items() if k not in ('path','maximum')),'actual host original identity differs')
   if action=='read':
    body=base64.b64decode(row['body_base64'],validate=True)
    api.need(base64.b64encode(body).decode()==row['body_base64'] and len(body)==pinrow['bytes']
    and api.sha(body)==pinrow['sha256'],'actual host body differs from its original descriptor')
    retained[path]={'original':pinrow,'raw':body}
   else:retained[path]={'original':pinrow}
  return retained
 def epoch_host_entry(chain, phase, entry, arguments, seconds):
  api.need((entry=='run_root_fixture_phase' and 1<=seconds<=250)
  or (entry=='witness_bundle' and seconds==30),'only the fixed fixture/witness host entries are available')
  manifest=dict(api.epoch_root_binding_value()['runtime'],path=chain.remote_root+'/material/tree/package/MANIFEST.json')
  argv=api.epoch_entry_argv(chain.remote_root+'/material/tree/package',manifest,entry,arguments,
  actual_context='p4',seconds=seconds)
  source=chain.sources['sources']['source/run_component_root_once.py']['raw']
  tree=ast.parse(source);lines=source.splitlines(keepends=True)
  nodes={n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
  code=api.epoch_owned_source_sections(source)+'\nimport base64,fcntl,select\n'
  for name in ('channel_flags','write_channel'):
   node=nodes[name];code+=b''.join(lines[node.lineno-1:node.end_lineno]).decode()+'\n'
  code+='ROOT='+repr(chain.remote_root)+'\nPHASE='+repr(phase)+'\nARGV='+repr(argv)+'\nSECONDS='+str(seconds)+'\n'
  code+='''deadline=time.monotonic()+SECONDS+25
    runner=EpochOwnedHostPhase(ROOT)
    try:
        runner.execute_process(PHASE,ARGV,SECONDS,input_raw=None)
    except BaseException:
        runner.close_owned_host_outputs()
        raise
    d=Path(ROOT)/PHASE
    rows={name:desc(d/name,read(d/name,65536)) for name in ('INTENT.json','CHILD.json','RESULT.json','OUTPUT-CAPTURE.json','stdout.original','stderr.original')}
    out=enc({'schema':'hepta.native-guard.epoch-owned-fixture-entry.v1','phase':PHASE,'argv':ARGV,
        'inner_stdin':None,'originals':rows,'stdout_base64':base64.b64encode(read(d/'stdout.original',65536)).decode(),
        'stderr_base64':base64.b64encode(read(d/'stderr.original',65536)).decode(),'automatic_retry':False})
    need(len(out)<=262144,'bounded complete fixture output envelope')
    need(write_channel(1,out,deadline),'fixture output incomplete at the original deadline')
    '''
  remote=api.SSH[:-4]+[shlex.join(['/usr/bin/python3','-I','-B','-c',code])]
  api.need(len(remote[-1].encode())<65536,'complete fixture SSH command exceeds original wire bound')
  value=api.strict(chain.execute_process(phase,remote,seconds+30,input_raw=b''))
  api.need(value['schema']=='hepta.native-guard.epoch-owned-fixture-entry.v1' and value['phase']==phase
  and value['argv']==argv and value['inner_stdin'] is None and value['automatic_retry'] is False,
  'actual owned fixture execution differs')
  out=base64.b64decode(value['stdout_base64'],validate=True);err=base64.b64decode(value['stderr_base64'],validate=True)
  api.need(len(out)<=65536 and len(err)<=65536 and api.desc(chain.remote_root+'/'+phase+'/stdout.original',out)
  ==value['originals']['stdout.original'] and api.desc(chain.remote_root+'/'+phase+'/stderr.original',err)
  ==value['originals']['stderr.original'],'actual bounded fixture stream differs')
  return value,out,err
 def epoch_closure_authority_archive(chain, closed):
  root=closed['root_sources'];rows={};bodies={}
  def add(role,origin,raw):
   api._epub_pin(origin,maximum=16777216)
   api.need(len(raw)==origin['bytes'] and api.sha(raw)==origin['sha256'],'actual closure authority original differs')
   rows[role]=origin;bodies[role]=raw
  add('root_plan',api.filedesc(chain.out/'ROOT-PLAN.original.json'),api.read(chain.out/'ROOT-PLAN.original.json'))
  add('root_source_manifest',root['manifest']['origin'],root['manifest']['raw'])
  for role,name in (('root_coordinator_source','source/run_component_root_once.py'),
  ('root_bridge_source','source/phone_chain_bridge.py'),('root_verifier_source','reference/policy_native5_verifier.py')):
   add(role,root['sources'][name]['origin'],root['sources'][name]['raw'])
  mf=api.epoch_root_binding_value()['runtime'];add('runtime_manifest',mf,api.pin(mf))
  row=next(r for r in api.strict(bodies['runtime_manifest'])['files'] if r['path']=='source/close_component.py')
  original=dict(row,path=str(Path(mf['path']).parent/row['path']));add('closer_source',original,api.pin(original))
  for role,name in (('mac_intent','INTENT.json'),('mac_stdin','stdin.original'),('mac_child','CHILD.json'),
  ('mac_result','RESULT.json'),('mac_output_capture','OUTPUT-CAPTURE.json'),('mac_stdout','stdout.original'),('mac_stderr','stderr.original')):
   path=chain.out/'epoch-close'/name;raw=api.read(path,16777216);add(role,api.desc(path,raw),raw)
  for role,row in closed['inner'].items():
   if role!='p4_joined':add(role,row['origin'],row['raw'])
  aliases={'mac_joined':'mac_result','p4_joined':'p4_result'}
  for role,target in aliases.items():rows[role]=rows[target];bodies[role]=bodies[target]
  api.need(len(rows)==26 and len({r['path'] for r in rows.values()})==24,'complete26 actual closure roles required')
  api.need(sum(len(bodies[k]) for k in rows if k not in aliases)<=32*1024*1024,'authority bodies exceed the shared original pool')
  epoch=chain.p['epoch']
  value={'schema':'hepta.native-guard.epoch-closure-authority-inputs.v1','epoch_id':epoch['epoch_id'],
  'ordinal':epoch['ordinal'],'nonce':chain.p['nonce'],'identity':epoch['identity'],'generation':epoch['generation'],
  'inner_stdin':None,'originals':[{'role':role,'origin':rows[role],
  'member':'originals/'+aliases.get(role,role)+'.original'} for role in sorted(rows)]}
  members={'AUTHORITY-INPUTS.json':api._epub_compact(value)}
  members.update({'originals/'+role+'.original':body for role,body in bodies.items() if role not in aliases})
  stream=io.BytesIO()
  with tarfile.open(fileobj=stream,mode='w:gz',format=tarfile.PAX_FORMAT) as archive:
   for name,body in sorted(members.items()):
    entry=tarfile.TarInfo(name);entry.size=len(body);entry.mode=0o600;entry.uid=entry.gid=0
    archive.addfile(entry,io.BytesIO(body))
  raw=stream.getvalue();api.need(len(raw)<=8388608,'complete closure authority transport input bound')
  path=chain.out/'CLOSURE-AUTHORITY.tar.gz';api._epoch_local_actual(path,raw)
  return api.desc(path,raw),raw
 def _eop_actual_worker(inputs, deadline):
  reader=api.EpochPublicationReadSet(deadline)
  wanted=inputs['payload'];api.channel_flags(0);api.channel_flags(1);api.channel_flags(2)
  raw=api.read_stdin(wanted['bytes'],api._EpochOperationChannel(reader,wanted['bytes']+1))
  api._epub_need(len(raw)==wanted['bytes'] and api._epub_sha(raw)==wanted['sha256'] and len(raw)<=8388608,
  'complete actual transport stdin/EOF/SHA differs')
  reader.physical_bytes+=len(raw)
  api._epub_need(reader.physical_bytes<=16777216,'actual carrier stdin exceeded the same physical read pool')
  request=api._epub_strict(raw)
  api._epub_need(api._epub_compact(request)==raw and request['operation']==inputs['operation'],
  'complete fixed canonical operation request differs')
  api._eop_private_host_directory(inputs['root'],reader,create=inputs['create_root'])
  api._eop_private_host_directory(inputs['inputs'],reader,create=True)
  source_pin=api._eop_write_host_original(inputs['paths']['payload_original'],raw,reader,8388608)
  actor_request={'schema':'hepta.phone-local.epoch-operation-request.v1','kind':'epoch_operation','root':True,
  'timeout_seconds':120,'payload_budget_bytes':8388608,'source':source_pin,
  'source_parent':{'path':inputs['inputs'],'metadata':api._epub_meta(os.lstat(inputs['inputs']))},
  'loader_binding':{'schema':'hepta.phone-local.epoch-operation-loader-binding.v1',
  'mode':'bootstrap' if inputs['operation']=='bootstrap-runtime' else 'installed',
  'source':{k:inputs['sources']['loader'][k] for k in ('bytes','sha256')}},
  'expected_operation':{'epoch_id':request['epoch_id'],'operation':request['operation'],
  'boot_id':request['boot_id'],'runtime':request['runtime'],'request':wanted}}
  provisional=api._epub_compact(actor_request)
  api._epub_need(len(provisional)<=131072,'finite actor request size exceeds source bound')
  request_dir=inputs['request_directory']
  api._eop_private_host_directory(request_dir,reader,create=True)
  actor_request_path=inputs['paths']['actor_request']
  request_pin=api._eop_write_host_original(actor_request_path,provisional,reader,131072)
  source_originals={}
  for name,pin in inputs['sources'].items():
   _,actual,_=reader.read(pin['path'],131072,pin);source_originals[name]=actual
  runner=api.EpochOwnedHostPhase(inputs['root'])
  argv=['/usr/bin/python3','-I','-B',inputs['sources']['actor']['path'],'--epoch-operation',
  inputs['actor_label'],actor_request_path]
  api._epub_need(deadline-time.monotonic()>150,'insufficient same producer clock before sole actor start')
  try:runner.execute_process(inputs['phase'],argv,150,input_raw=None,async_start=False)
  except BaseException:
   runner.close_owned_host_outputs();raise
  rows={};bodies={}
  for role,path in inputs['paths'].items():
   if role=='p4_joined':
    rows[role]=rows['p4_result'];bodies[role]=bodies['p4_result'];continue
   maximum=(8388608 if role=='payload_original' else 131072 if role=='actor_request'
   else 70657 if role.endswith('_incoming_wire') else 65552 if role.endswith('_smart_socket') else 65536)
   expected=source_pin if role=='payload_original' else request_pin if role=='actor_request' else None
   body,actual,_=reader.read(path,maximum,expected)
   rows[role]={'origin':{k:actual[k] for k in ('path','bytes','sha256')},'metadata':actual['metadata']}
   bodies[role]=body
  final=api._epub_strict(bodies['p4_stdout']);pending=api._epub_strict(bodies['phone_wrapper'])
  api._epub_need(final.get('schema')=='hepta.phone-local.epoch-operation-summary.v1'
  and final.get('status')=='OPERATION_ORIGINALS_RETAINED_AND_OWNED_HOST_FDS_CLOSED'
  and final.get('label')==inputs['actor_label'] and final.get('run')==inputs['run']
  and bodies['p4_stderr']==b'' and api._epub_compact(final)==bodies['p4_stdout']
  and api._epub_compact(final['result'])==api._epub_compact(dict(rows['phone_wrapper']['origin'],
  metadata=rows['phone_wrapper']['metadata']))
  and pending.get('state')=='OPERATION_WIRE_ORIGINALS_VERIFIED_PENDING_ACTOR_FD_CLOSE'
  and pending.get('operation')==inputs['operation'],'actual final actor/pending operation link differs')
  for name,key in (('loader','loader_original'),('sdk','sdk_original')):
   actual=source_originals[name]
   api._epub_need(api._epub_compact(pending.get(key))==api._epub_compact(actual),
   'actual operation source body/full9 differs from its retained actor original: '+name)
  api._epub_need(api._epub_compact(pending.get('loader_postcheck'))==api._epub_compact(dict(
  source_originals['loader'],complete_second_read_and_EOF=True)),
  'actual loader final complete original differs')
  for prefix,key in (('baseline_transport','sdk_baseline_'),('transport','sdk_operation_')):
   for field,suffix in (('stdout_original','stdout'),('stderr_original','stderr'),
   ('incoming_wire_original','incoming_wire'),('smart_socket_response_original','smart_socket')):
    item=rows[key+suffix]
    api._epub_need(api._epub_compact(pending[prefix][field])==api._epub_compact(dict(item['origin'],metadata=item['metadata'])),
    'actual operation SDK full original differs')
  item=rows['operation_result'];result=api._epub_strict(bodies['operation_result'])
  api._epub_need(api._epub_compact(pending['operation_result_original'])==api._epub_compact(dict(item['origin'],metadata=item['metadata']))
  and bodies['operation_result']==bodies['sdk_operation_stdout']==api._epub_compact(result)
  and result.get('schema')=='hepta.native-guard.epoch-operation-result.v1'
  and result.get('state')=='OPERATION_RETURNED_COMPLETE_ORIGINAL_RESULT'
  and api._epub_compact(result.get('request'))==api._epub_compact(wanted)
  and result.get('operation')==inputs['operation'] and result.get('automatic_retry') is False,
  'complete canonical operation wire/request link differs')
  reader.recheck();reader.check()
  output={'schema':'hepta.native-guard.epoch-owned-operation-output.v1',
  'state':'ACTUAL_OPERATION_ACTOR_JOINED_AND_ORIGINALS_RETAINED',
  'root_plan_sha256':inputs['root_plan_sha256'],'operation':inputs['operation'],
  'phase':inputs['phase'],'actor_label':inputs['actor_label'],'payload':wanted,
  'actor_request':request_pin,'inner_stdin':None,'originals':rows,'source_originals':source_originals,
  'operation_wire':result,'operation_wire_canonical_bytes_exact':True,
  'physical_original_reads':{'bytes':reader.physical_bytes,'count':reader.read_count,
  'maximum_bytes':16777216,'all_registered_first_and_final_complete':True,
  'carrier_stdin_bytes_included':len(raw),'owned_capture_IO_counted_here':False},
  'source_or_action_authority_verified_here':False,'automatic_retry':False,
  'new_explicit_process_signal_calls':0,'component_qualified':False}
  encoded=api.enc(output);api._epub_need(len(encoded)<=65536,'finite complete operation output envelope bound')
  reader.check()
  api._epub_need(api.write_channel(1,encoded,deadline),'complete owned operation output was not drained before deadline')
 def epoch_publication_render_inputs(coordinator_raw, bridge_raw, plan_raw, lease_raw,
 terminal_original, *, binding, actor, sdk, bridge_template, base, env):
  api._epub_need(type(coordinator_raw) is bytes and type(bridge_raw) is bytes
  and len(coordinator_raw) <= 131072 and len(bridge_raw) <= 131072,
  'whole bounded actual producer and bridge source bytes required')
  plan = api._epub_strict(plan_raw); lease = api._epub_strict(lease_raw)
  pretty = (json.dumps(plan, sort_keys=True, indent=2, ensure_ascii=False,
  allow_nan=False)+'\n').encode()
  api._epub_need(type(plan) is dict and pretty == plan_raw
  and plan.get('schema') == 'hepta.native-guard.epoch-root-plan.v1'
  and type(binding) is dict and api._epub_compact(plan.get('package')) == api._epub_compact(binding['runtime'])
  and api._epub_compact(plan.get('combination')) == api._epub_compact(binding['combination'])
  and api._epub_compact(plan.get('shared_materials')) == api._epub_compact(binding['shared_materials'])
  and type(plan.get('label')) is str and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}', plan['label'])
  and type(plan.get('nonce')) is str and re.fullmatch('[0-9a-f]{32}', plan['nonce'])
  and plan.get('boot_id') == 'f8019f83-20a7-4f18-bea1-51c980621e4d'
  and plan.get('out') == str(Path(base)/'native-guard-root-chains-r10-r1'/plan['label']),
  'actual canonical Root publication plan/source/identity differs')
  epoch = plan.get('epoch')
  api._epub_need(type(epoch) is dict and set(epoch) == {'schema','epoch_id','anchor','initialization',
  'ordinal','reservation','identity','generation'}
  and epoch['schema'] == 'hepta.native-guard.epoch-lease-binding.v1'
  and epoch['epoch_id'] == 'legacy902-active01' and type(epoch['ordinal']) is int
  and 1 <= epoch['ordinal'] <= 8, 'complete actual epoch lease-binding required')
  for name in ('anchor','initialization','reservation','identity','generation'):
   api._epub_pin(epoch[name], full=True)
  api._epub_need(type(lease) is dict and api._epub_compact(lease) == lease_raw
  and lease.get('schema') == 'hepta.native-guard.epoch-lease.v1'
  and all(lease.get(name) == plan[name] for name in ('label','nonce','boot_id','case_id'))
  and api._epub_compact(lease.get('epoch')) == api._epub_compact(epoch)
  and lease.get('package_sha256') == binding['runtime']['sha256']
  and api._epub_compact({k:epoch['generation'][k] for k in ('path','bytes','sha256')})
  == api._epub_compact(binding['generation']), 'actual complete lease differs from Root plan')
  registry = '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-epoch-legacy902-r10-r1'
  slot = registry+'/slots/%02d' % epoch['ordinal']
  api._epub_pin(terminal_original, full=True)
  api._epub_need(terminal_original['path'] == slot+'/COMMIT.json'
  and epoch['identity']['path'] == slot+'/IDENTITY.json'
  and epoch['reservation']['path'] == registry+'/slots/%02d.CLAIM.json' % epoch['ordinal']
  and epoch['generation']['path'] == registry+'/generations/01.json',
  'publication must read the exact current actual COMMIT/IDENTITY/CLAIM/catalog')
  api._epub_pin(actor, maximum=131072); api._epub_pin(sdk, maximum=131072)
  api._epub_need(Path(sdk['path']).parent == Path(actor['path']).parent
  and Path(actor['path']).name == 'phone_once_stdin.py'
  and Path(sdk['path']).name == 'preserved_ui_package_phase_r7_stdin.py',
  'actual separately reviewed actor and sibling SDK namespace differs')
  package = api._epub_pin(plan['source_package'], maximum=262144)
  bridge = {'path':str(Path(package['path']).parent/'source/phone_chain_bridge.py'),
  'bytes':len(bridge_raw), 'sha256':api._epub_sha(bridge_raw)}
  tree = ast.parse(bridge_raw); assignments = [n for n in tree.body if isinstance(n, ast.Assign)
  and len(n.targets)==1 and isinstance(n.targets[0], ast.Name)
  and n.targets[0].id=='EPOCH_BRIDGE_BINDING']
  api._epub_need(len(assignments)==1, 'actual bridge has no unique binding literal')
  node = assignments[0].value; actual = ast.literal_eval(node)
  expected = {'schema':'hepta.native-guard.epoch-bridge-source-binding.v1',
  **{k:binding[k] for k in ('runtime','combination','shared_materials','pure_verifier',
  'source_derivation','generation')},
  'bridge_template_slots':['EPOCH_BRIDGE_BINDING'], 'template':bridge_template}
  api._epub_need(api._epub_compact(actual)==api._epub_compact(expected),
  'actual bridge binding must derive from the same current generation')
  lines = bridge_raw.splitlines(keepends=True)
  start=sum(map(len,lines[:node.lineno-1]))+node.col_offset
  end=sum(map(len,lines[:node.end_lineno-1]))+node.end_col_offset
  unbound=bridge_raw[:start]+b'None'+bridge_raw[end:]
  api._epub_need({'bytes':len(unbound),'sha256':api._epub_sha(unbound)} == bridge_template,
  'whole actual bridge differs outside its reviewed one literal slot')
  observation = {'epoch_id':epoch['epoch_id'], 'boot_id':plan['boot_id'],
  'generation':epoch['generation'], 'terminal':terminal_original,
  'root_source_manifest':package, 'bridge_source':bridge}
  encoded = base64.b64encode(api._epub_compact(observation)).decode('ascii')
  argv = ['phone_chain_bridge.py','epoch-publication-read','--label',plan['label'],
  '--lease-bytes',str(len(lease_raw)),'--lease-sha256',api._epub_sha(lease_raw),
  '--observation-context-base64',encoded,'--execute-root-bridge-once']
  receipt=api._epub_pin(plan.get('code_receipt'),full=True,maximum=65536)
  api._epub_need(receipt['path']==registry+'/code/01/BOOTSTRAP-CODE.json','actual installed code receipt required')
  loaders=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1
  and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='EPOCH_PUBLICATION_INSTALLED_LOADER']
  api._epub_need(len(loaders)==1,'one ordinary installed publication loader required')
  loader=ast.literal_eval(loaders[0].value)
  api._epub_need(type(loader) is str and 0<len(loader.encode())<65536,'plain fixed loader source bound')
  data={'code_receipt':receipt,'boot_id':plan['boot_id'],'runtime':binding['runtime'],
  'root_source_manifest':package,'bridge_template':bridge_template,'bridge':{'bytes':len(bridge_raw),'sha256':api._epub_sha(bridge_raw)},
  'label':plan['label'],'lease':{'bytes':len(lease_raw),'sha256':api._epub_sha(lease_raw)},'observation_context_base64':encoded}
  inline='PIN_DATA='+repr(data)+'\n'+loader
  command = env+'/usr/bin/python3 -I -B -c '+shlex.quote(inline)
  wire = ('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(command)).encode('utf-8')
  api._epub_need(len(wire) < 65536, 'complete actual publication command exceeds old shell wire bound')
  request = {'schema':'hepta.phone-local.epoch-publication-request.v1',
  'kind':'epoch_publication_read','root':True,'command':command,
  'timeout_seconds':120,'payload_budget_bytes':8388608,'expected_observation':observation}
  request_raw = api._epub_compact(request)
  api._epub_need(len(request_raw) <= 131072, 'whole publication request source bound')
  label = 'ng-'+plan['nonce']+'-epoch-publication-read'
  value = epoch_publication_paths(plan['nonce'], label)
  value.update(phase_name='epoch-publication-read', actor_label=label,
  actor=actor, sdk=sdk, request=request, request_raw=request_raw,
  request_path=value['paths']['actor_request'], expected_observation=observation,
  actor_argv=['/usr/bin/python3','-I','-B',actor['path'],label,value['paths']['actor_request']],
  inner_wait_seconds=150, host_wait_seconds=180, inner_stdin=None,
  root_plan_sha256=api._epub_sha(plan_raw), command_wire_bytes=len(wire))
  return value
 def _epoch_archive_host_worker(value, deadline):
  def check():api.need(time.monotonic()<deadline,'same archive producer deadline exhausted')
  check();root=Path(value['root']);relative=value['relative'];expected=value['input']
  api.need(re.fullmatch('/home/alex/codex-native-guard-chain-r10-r1/[0-9a-f]{32}',str(root))
  and relative in ('inputs/component-inputs.tar.gz','closure-inputs/ORIGINALS.tar.gz')
  and set(expected)=={'bytes','sha256'} and type(expected['bytes']) is int
  and 0<expected['bytes']<=67108864 and re.fullmatch('[0-9a-f]{64}',expected['sha256']),
  'only the original bounded fixed archive domain is available')
  target=root/relative;opened=[];parents=[];filefd=None;second=None;flags=None
  counts={'stdin_read':0,'destination_write':0,'held_readback':0,'reopened_readback':0}
  phase='validate';created=False;stdin_eof=False;original=None;parent_before=None;parent_after=None
  try:
   flags=api.channel_flags(0);api.channel_flags(1);api.channel_flags(2)
   fcntl.fcntl(0,fcntl.F_SETFL,flags|os.O_NONBLOCK)
   phase='existing_private_case_and_archive_parent'
   checker=types.SimpleNamespace(check=check)
   api._eop_private_host_directory(str(root),checker,create=False)
   try:api._eop_private_host_directory(str(target.parent),checker,create=False)
   except FileNotFoundError:api._eop_private_host_directory(str(target.parent),checker,create=True)
   opened,parents=api._epub_parent_chain(str(target));parent=opened[-1]
   parent_before=api._epub_meta(os.fstat(parent));names=sorted(os.listdir(parent))
   api.need(parent_before[3:5]==[os.geteuid(),os.getegid()] and stat.S_IMODE(parent_before[2])==0o700
   and target.name not in names and len(names)<=1024 and len(opened)+2<=32,
   'fixed archive target exists or private parent/FD bound differs')
   phase='exclusive_archive_create'
   filefd=os.open(target.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
   0o600,dir_fd=parent);created=True
   initial=api._epub_meta(os.fstat(filefd))
   api.need(stat.S_ISREG(initial[2]) and stat.S_IMODE(initial[2])==0o600
   and initial[3:6]==[os.geteuid(),os.getegid(),1] and initial[6]==0,
   'new archive is not the owned empty private inode')
   phase='stream_stdin_to_exclusive_archive';digest=hashlib.sha256()
   while True:
    check();left=deadline-time.monotonic()
    ready,_,_=select.select([0],[],[],max(0,min(.05,left)))
    if not ready:continue
    size=min(65536,expected['bytes']+1-counts['stdin_read'])
    api.need(size>0,'archive stdin exceeded its fixed exact size')
    try:part=os.read(0,size)
    except BlockingIOError:continue
    counts['stdin_read']+=len(part)
    if not part:stdin_eof=True;break
    api.need(counts['stdin_read']<=expected['bytes'],'archive stdin exceeded its complete declared body')
    digest.update(part);position=0
    while position<len(part):
     check();amount=os.write(filefd,part[position:])
     api.need(0<amount<=len(part)-position,'incomplete archive stream write')
     position+=amount;counts['destination_write']+=amount
   api.need(counts['stdin_read']==counts['destination_write']==expected['bytes']
   and digest.hexdigest()==expected['sha256'] and stdin_eof,
   'complete archive stdin EOF/size/wholeSHA differs; partial file retained')
   phase='fsync_and_postcreation_parent_baseline';check();os.fsync(filefd);os.fsync(parent)
   final=api._epub_meta(os.fstat(filefd));parent_after=api._epub_meta(os.fstat(parent))
   api.need(final[:6]==initial[:6] and final[6]==expected['bytes']
   and final==api._epub_meta(os.stat(target.name,dir_fd=parent,follow_symlinks=False))==api._epub_meta(os.lstat(target))
   and parent_after[:5]==parent_before[:5] and sorted(os.listdir(parent))==sorted(names+[target.name]),
   'exclusive archive changed its inode or another parent member')
   parents[-1]=(parent,parents[-1][1],parent_after);api._epub_parent_check(parents)
   def readback(fd,key):
    phase_name=key;os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256()
    api.need(api._epub_meta(os.fstat(fd))==final,'archive readback opened a different inode')
    while counts[key]<=expected['bytes']:
     check();part=os.read(fd,min(65536,expected['bytes']+1-counts[key]))
     counts[key]+=len(part)
     if not part:break
     h.update(part)
    api.need(counts[key]==expected['bytes'] and h.hexdigest()==expected['sha256']
    and api._epub_meta(os.fstat(fd))==final
    and api._epub_meta(os.stat(target.name,dir_fd=parent,follow_symlinks=False))==final
    and api._epub_meta(os.lstat(target))==final and target.resolve(strict=True)==target,
    'complete actual archive '+phase_name+' bytes/full9/EOF differs')
    api.need(sorted(os.listdir(parent))==sorted(names+[target.name]),'archive closed parent names changed')
    api._epub_parent_check(parents);check()
   phase='complete_held_readback';readback(filefd,'held_readback')
   phase='complete_second_owned_open_readback'
   second=os.open(target.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
   readback(second,'reopened_readback')
   original={'path':str(target),'bytes':expected['bytes'],'sha256':expected['sha256'],'metadata':final}
   api.need(sum(counts.values())==4*expected['bytes'] and sum(counts.values())<=4*67108864,
   'fixed archive physical copies differ from the explicit profile')
  except BaseException as error:
   failure={'schema':'hepta.native-guard.epoch-fixed-archive-transfer-failure.v1','phase':phase,
   'error_type':type(error).__name__,'detail':str(error)[:1024],'destination_path':str(target),
   'create_attempted':phase!='validate' and phase!='existing_private_case_and_archive_parent',
   'created_exclusively_with_returned_fd':created,'stdin_eof':stdin_eof,'physical_bytes':counts,
   'partial_retained':created,'automatic_retry':False,'reopened_for_write':False,'signals_sent':0}
   api.write_channel(2,api.enc(failure),deadline,failure=True);raise
  finally:
   close_errors=[]
   for fd in (second,filefd):
    if fd is not None:
     try:os.close(fd)
     except BaseException as error:close_errors.append(type(error).__name__)
   try:api._epub_close_fds(opened)
   except BaseException as error:close_errors.append(type(error).__name__)
   if flags is not None:
    try:fcntl.fcntl(0,fcntl.F_SETFL,flags)
    except BaseException as error:close_errors.append(type(error).__name__)
   api.need(not close_errors,'owned archive FD/flag finalization failed: '+repr(close_errors))
  check();out=api.enc({'schema':'hepta.native-guard.epoch-fixed-archive-transfer.v1',
  'state':'SINGLE_EXCLUSIVE_ARCHIVE_COMPLETE_EOF_FSYNC_TWO_READBACKS',
  'original':original,'source_original':value['source_original'],'stdin_eof':True,
  'created_exclusively':True,'held_and_reopened_complete_readbacks':2,
  'parent_before':{'path':str(target.parent),'metadata':parent_before,'names':names},
  'parent_after':{'path':str(target.parent),'metadata':parent_after,'names':sorted(names+[target.name])},
  'physical_bytes':counts,'physical_total':sum(counts.values()),'archive_domain_limit':67108864,
  'ordinary_file_pool_reused':False,'owned_fds_closed':True,'automatic_retry':False,'signals_sent':0})
  api.need(len(out)<=65536,'complete archive transfer receipt bound')
  api.need(api.write_channel(1,out,deadline),'archive receipt not drained within its original deadline')
 def epoch_host_archive(chain,phase,relative,raw,source_original,*,deadline):
  api.need(relative in ('inputs/component-inputs.tar.gz','closure-inputs/ORIGINALS.tar.gz')
  and type(raw) is bytes and 0<len(raw)<=67108864,
  'only the two fixed original64MiB archives may use this streaming branch')
  api._epub_pin(source_original,full=('metadata' in source_original),maximum=67108864)
  wanted_path=str(chain.material/'component-inputs.tar.gz') if relative.startswith('inputs/') else str(chain.out/'ORIGINALS.tar.gz')
  api.need(source_original['path']==wanted_path and source_original['bytes']==len(raw)
  and source_original['sha256']==api.sha(raw),'archive input is not the actual retained fixed original')
  def check():api.need(time.monotonic()<deadline,'same complete owned archive180s clock exhausted')
  def original_again():
   check();opened,parents=api._epub_parent_chain(wanted_path);fd=None
   try:
    parent=opened[-1];name=Path(wanted_path).name;before=api._epub_meta(os.stat(name,dir_fd=parent,follow_symlinks=False))
    api.need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2])==0o600 and before[3:6]==[os.geteuid(),os.getegid(),1]
    and before[6]==len(raw) and len(opened)<32,'actual archive source is not the exact private regular file')
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
    api.need(api._epub_meta(os.fstat(fd))==before,'actual archive source changed at open')
    total=0;h=hashlib.sha256()
    while total<=len(raw):
     check();part=os.read(fd,min(65536,len(raw)+1-total))
     if not part:break
     h.update(part);total+=len(part)
    api.need(total==len(raw) and h.hexdigest()==source_original['sha256']
    and api._epub_meta(os.fstat(fd))==before==api._epub_meta(os.stat(name,dir_fd=parent,follow_symlinks=False))
    ==api._epub_meta(os.lstat(wanted_path)),'actual complete archive source/full9 changed')
    api._epub_parent_check(parents);check()
    pinrow=dict(api.desc(wanted_path,raw),metadata=before)
    api.need(all(api._epub_compact(pinrow[k])==api._epub_compact(v) for k,v in source_original.items()),
    'actual archive input changed its declared original')
    observations=[{'path':path,'metadata':metadata,
    'names':sorted(os.listdir(pfd)) if path==str(chain.out) else None} for pfd,path,metadata in parents]
    return pinrow,observations
   finally:
    if fd is not None:os.close(fd)
    api._epub_close_fds(opened)
  first,parents_before=original_again();check()
  source=chain.sources['sources']['source/run_component_root_once.py']['raw']
  tree=ast.parse(source);lines=source.splitlines(keepends=True)
  selected=('need','sha','enc','strict','desc','read','put','newdir','filedesc','channel_flags','write_channel',
  '_epub_need','_epub_meta','_epub_close_fds','_epub_parent_chain','_epub_parent_check','_eop_private_host_directory')
  nodes={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
  code='import hashlib,json,os,re,stat,time,fcntl,select,types\nfrom pathlib import Path\n'
  code+='\n'.join(b''.join(lines[nodes[n].lineno-1:nodes[n].end_lineno]).decode() for n in selected)+'\n'
  code+=api.epoch_bridge_host_worker_source(chain.sources['sources']['source/phone_chain_bridge.py']['raw'],'_epoch_archive_host_worker')
  seconds=deadline-time.monotonic();api.need(10<seconds<=180,'same archive clock has insufficient owned execution time')
  value={'root':chain.remote_root,'relative':relative,'input':{'bytes':len(raw),'sha256':api.sha(raw)},'source_original':first}
  code+='INPUTS='+repr(value)+'\nDEADLINE=time.monotonic()+'+repr(seconds-5)+'\n_epoch_archive_host_worker(INPUTS,DEADLINE)\n'
  argv=api.SSH[:-4]+[shlex.join(['/usr/bin/python3','-I','-B','-c',code])]
  api.need(len(argv[-1].encode())<65536,'complete fixed archive SSH wire exceeds original limit')
  result=api.strict(chain.execute_process(phase,argv,seconds,input_raw=raw));check()
  again,parents_after=original_again();api.need(again==first and len(parents_before)==len(parents_after),
  'actual archive source/full9 changed across its sole dispatch')
  for before,after in zip(parents_before,parents_after):
   if before['path']==str(chain.out):
    api.need(before['metadata'][:5]==after['metadata'][:5] and phase not in before['names']
    and after['names']==sorted(before['names']+[phase]),'owned Root phase changed another archive ancestor member')
   else:api.need(before==after,'an archive source ancestor changed outside its owned phase directory')
  api.need(result.get('schema')=='hepta.native-guard.epoch-fixed-archive-transfer.v1'
  and result.get('state')=='SINGLE_EXCLUSIVE_ARCHIVE_COMPLETE_EOF_FSYNC_TWO_READBACKS'
  and result.get('source_original')==first and result.get('stdin_eof') is True
  and result.get('created_exclusively') is True and result.get('owned_fds_closed') is True
  and result.get('automatic_retry') is False and result.get('signals_sent')==0
  and result.get('physical_bytes')==dict.fromkeys(('stdin_read','destination_write','held_readback','reopened_readback'),len(raw))
  and result.get('physical_total')==4*len(raw) and result.get('ordinary_file_pool_reused') is False,
  'actual complete fixed archive transfer is not fully joined and retained')
  pinrow=result['original'];api._epub_pin(pinrow,full=True,maximum=67108864)
  api.need(pinrow['path']==str(Path(chain.remote_root)/relative) and pinrow['bytes']==len(raw)
  and pinrow['sha256']==api.sha(raw),'actual complete P4 archive differs')
  api._epoch_local_actual(chain.out/phase/'ARCHIVE-SOURCE-OBSERVATIONS.json',api.enc({
  'source_original':first,'parents_before':parents_before,'parents_after':parents_after,
  'source_complete_read_bytes':2*len(raw),'source_complete_read_count':2,
  'original_owned_stdin_retention':{'write_bytes':len(raw),'complete_pre_post_read_bytes':2*len(raw),
  'child_stdin_logical_bytes':len(raw),'included_in_child_physical_measurement':False},
  'p4_stream_read_write_readbacks':result['physical_bytes'],
  'single_transfer_declared_body_copy_bytes':10*len(raw),'external_source_reads_and_phone_copies_not_free':True,
  'archive_domain_limit':67108864,'ordinary_file_pool_limit_unchanged':16777216,'automatic_retry':False}))
  check();return {pinrow['path']:{'original':pinrow}}
 return types.SimpleNamespace(EpochRootHostRuntime=EpochRootHostRuntime,epoch_preflight_plan=epoch_preflight_plan,epoch_host_io=epoch_host_io,epoch_host_entry=epoch_host_entry,epoch_closure_authority_archive=epoch_closure_authority_archive,epoch_publication_render_inputs=epoch_publication_render_inputs,epoch_host_archive=epoch_host_archive)
EPOCH_PUBLICATION_INSTALLED_LOADER = r'''import argparse,fcntl,hashlib,json,os,select,stat,sys,time,types
from pathlib import Path
deadline=time.monotonic()+90.0
def need(value,text):
 if not value:raise ValueError(text)
def check():need(time.monotonic()<deadline,'same installed publication clock expired')
def meta(value):return [getattr(value,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def strict(raw):
 def pairs(rows):
  value={}
  for key,item in rows:need(key not in value,'duplicate source record key');value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
physical=0;held=[];parents=[]
def source(row,maximum):
 global physical
 path=Path(row['path']);need(path.is_absolute() and str(path)==row['path'] and '..' not in path.parts,'fixed canonical source path required')
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 chain=[(fd,'/',meta(os.fstat(fd)))]
 try:
  current=Path('/')
  for name in path.parts[1:-1]:
   check();need(len(chain)+len(held)+sum(len(c) for c in parents)<32,'owned source FD reservation')
   child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
   try:chain.append((child,str(current/name),meta(os.fstat(child))))
   except BaseException:os.close(child);raise
   current=current/name;fd=child
  before=meta(os.stat(path.name,dir_fd=fd,follow_symlinks=False))
  need(before==row['metadata'] and stat.S_ISREG(before[2]) and before[3:6]==[0,0,1]
   and stat.S_IMODE(before[2])==0o600 and before[6]==row['bytes'] and 0<row['bytes']<=maximum,
   'actual private source whole metadata differs')
  need(len(chain)+len(held)+sum(len(c) for c in parents)<32,'owned leaf FD reservation')
  leaf=os.open(path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
  try:held.append((leaf,row,chain))
  except BaseException:os.close(leaf);raise
  parents.append(chain);chain=[]
  raw=read_again(held[-1]);return raw
 finally:
  for entry in reversed(chain):os.close(entry[0])
def read_again(entry):
 global physical
 fd,row,chain=entry;check();need(meta(os.fstat(fd))==row['metadata'],'held source changed before read')
 need(physical+row['bytes']+1<=393216,'fixed receipt and bridge source read pool exhausted')
 os.lseek(fd,0,os.SEEK_SET);raw=bytearray()
 while len(raw)<=row['bytes']:
  check();part=os.read(fd,min(65536,row['bytes']+1-len(raw)));physical+=len(part)
  if not part:break
  raw.extend(part)
 body=bytes(raw)
 need(len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256']
  and meta(os.fstat(fd))==row['metadata']==meta(os.stat(Path(row['path']).name,dir_fd=chain[-1][0],follow_symlinks=False))
  ==meta(os.lstat(row['path'])) and Path(row['path']).resolve(strict=True)==Path(row['path']),
  'whole actual installed source changed')
 for parent,path,old in chain:
  need(meta(os.fstat(parent))==old==meta(os.lstat(path)) and Path(path).resolve(strict=True)==Path(path),
   'installed source parent changed')
 return body
try:
 registry='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-epoch-legacy902-r10-r1'
 code=registry+'/code/01';receipt_pin=PIN_DATA['code_receipt']
 need(receipt_pin['path']==code+'/BOOTSTRAP-CODE.json','fixed actual bootstrap receipt required')
 receipt_raw=source(receipt_pin,65536);receipt=strict(receipt_raw)
 need(encoded(receipt)==receipt_raw and receipt['schema']=='hepta.native-guard.epoch-code-bootstrap-record.v1'
  and receipt['epoch_id']=='legacy902-active01' and receipt['boot_id']==PIN_DATA['boot_id']
  and receipt['runtime_origin']==PIN_DATA['runtime']
  and receipt['root_source_manifest_origin']==PIN_DATA['root_source_manifest']
  and receipt['bridge_template']==PIN_DATA['bridge_template']
  and type(receipt['files']) is list and len(receipt['files'])==34,'actual installation source record differs')
 matches=[row for row in receipt['files'] if row['path']==code+'/phone_chain_bridge.py']
 need(len(matches)==1 and {k:matches[0][k] for k in ('bytes','sha256')}==PIN_DATA['bridge'],
  'actual installed bridge differs from the reviewed whole Root3 source')
 bridge_raw=source(matches[0],131072)
 need(sorted(os.listdir(code))==['BOOTSTRAP-CODE.json','package','phone_chain_bridge.py'],'fixed installed code closed set differs')
 module=types.ModuleType('epoch_installed_publication_bridge')
 module.__dict__.update({'__file__':code+'/phone_chain_bridge.py','__actual_context__':'phone',
  '__reviewed_source_sha256__':PIN_DATA['bridge']['sha256']})
 check();exec(compile(bridge_raw,module.__file__,'exec'),module.__dict__);check()
 args=argparse.Namespace(label=PIN_DATA['label'],lease_bytes=PIN_DATA['lease']['bytes'],
  lease_sha256=PIN_DATA['lease']['sha256'],observation_context_base64=PIN_DATA['observation_context_base64'],
  execute_root_bridge_once=True,operation='epoch-publication-read')
 wire=module.epoch_bridge_publication_read(args,budget_check=check)
 need(type(wire) is bytes and len(wire)<=49152,'complete finite publication wire required')
 for entry in held:read_again(entry)
 need(sorted(os.listdir(code))==['BOOTSTRAP-CODE.json','package','phone_chain_bridge.py'],'installed code names changed')
 check()
finally:
 for fd,_row,_chain in reversed(held):os.close(fd)
 for chain in reversed(parents):
  for entry in reversed(chain):os.close(entry[0])
mode=os.fstat(1).st_mode;need(stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode),'actual output pipe required')
flags=fcntl.fcntl(1,fcntl.F_GETFL);fcntl.fcntl(1,fcntl.F_SETFL,flags|os.O_NONBLOCK);at=0
try:
 while at<len(wire):
  check();_,ready,_=select.select([],[1],[],max(0,min(.05,deadline-time.monotonic())))
  if not ready:continue
  try:count=os.write(1,wire[at:at+65536])
  except BlockingIOError:continue
  need(count>0,'incomplete actual publication output');at+=count
finally:fcntl.fcntl(1,fcntl.F_SETFL,flags)
'''
if __name__=='__main__':raise SystemExit(epoch_bridge_dispatch())
