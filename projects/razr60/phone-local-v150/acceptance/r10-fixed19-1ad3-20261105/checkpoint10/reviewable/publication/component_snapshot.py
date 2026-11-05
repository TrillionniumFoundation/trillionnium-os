"""Capture an ended isolated component's actual originals, without executing it.

This explicit Root entry writes only a fresh private capture directory/archive.
It never connects to a provider/sidecar, sends UI input, restarts a process,
submits a task or makes a model request. A capture is evidence, not qualification.
"""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tarfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import component_common as C
import component_lifecycle as LIFE
NATIVE=Path('/var/lib/trillionnium/owner-open/turn-events.jsonl.segments')
MAX_BYTES=64*1024*1024
MAX_FILE=16*1024*1024
MAX_FILES=8192
MAX_SCAN=128*1024*1024
MAX_LINE=4*1024*1024
class Capture:
 def __init__(self,destination):
  self.destination=C.private_dir(destination,create=True)
  self.files={};self.directories={};self.originals={};self.total=0
  self.deadline=time.monotonic()+55
 def check(self):
  C.need(time.monotonic()<self.deadline,'original capture read deadline exceeded')
  C.need(len(self.files)<MAX_FILES,'original capture file count exceeded')
 def save(self,name,raw,*,origin=None):
  self.check();p=C.relative(name)
  C.need(name not in self.files and 0<=len(raw)<=MAX_FILE,'duplicate/oversized capture original')
  C.need(self.total+len(raw)<=MAX_BYTES,'capture retained byte limit')
  target=self.destination/p
  parent=self.destination
  for part in p.parts[:-1]:
   parent=parent/part
   try:C.private_dir(parent)
   except FileNotFoundError:C.private_dir(parent,create=True)
  C.put(target,raw);self.total+=len(raw)
  self.files[name]={'path':name,**C.descriptor(raw),
  'source_path':None if origin is None else origin['source_path'],
  'source_metadata':None if origin is None else origin['source_metadata'],
  'kind':'derived_read_observation' if origin is None else 'original_file_bytes'}
 def file(self,path,name,*,private=True,maximum=MAX_FILE):
  self.check();path=Path(path);before=path.lstat()
  raw=C.read(path,maximum,private=private)
  C.need(C.metadata(before)==C.metadata(path.lstat()),'original raced before capture copy')
  origin={'source_path':str(path),'source_metadata':C.metadata(before)}
  self.save(name,raw,origin=origin)
  self.originals[str(path)]={'metadata':C.metadata(before),**C.descriptor(raw)}
  return raw
 def tree(self,path,name,*,private=True,depth=0):
  self.check();C.need(depth<=12,'capture tree depth exceeded')
  path=Path(path);before=path.lstat()
  C.need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode),'capture original directory differs')
  if private:C.private_dir(path)
  names=sorted(p.name for p in path.iterdir());C.need(len(names)<=20000,'capture directory count')
  self.directories[str(path)]={'metadata':C.metadata(before),'names':names,'capture_path':name}
  for leaf in names:
   p=path/leaf;s=p.lstat()
   C.need(not stat.S_ISLNK(s.st_mode),'capture symlink is never followed')
   if stat.S_ISDIR(s.st_mode):self.tree(p,name+'/'+leaf,private=private,depth=depth+1)
   else:self.file(p,name+'/'+leaf,private=private)
  C.need(C.metadata(path.lstat())==C.metadata(before)
  and sorted(p.name for p in path.iterdir())==names,'original directory changed during capture')
 def recheck(self):
  for path,row in self.originals.items():
   self.check();p=Path(path)
   C.need(C.metadata(p.lstat())==row['metadata'],'captured original changed afterwards')
  for path,row in self.directories.items():
   self.check();p=Path(path)
   C.need(C.metadata(p.lstat())==row['metadata'] and sorted(q.name for q in p.iterdir())==row['names'],
   'captured directory changed afterwards')
def bounded_proc(path,maximum=1024*1024):
 path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  C.need(stat.S_ISREG(os.fstat(fd).st_mode),'proc observation is not a regular pseudo-file')
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(maximum+1)
  C.need(len(raw)<=maximum,'proc observation byte bound')
  return raw
 finally:os.close(fd)
def endpoint_absence():
 raw={key:bounded_proc(path) for key,path in {
 'tcp':'/proc/net/tcp','tcp6':'/proc/net/tcp6','unix':'/proc/net/unix'}.items()}
 for key in ('tcp','tcp6'):
  lines=raw[key].splitlines();C.need(lines,'proc TCP table has no header')
  for line in lines[1:]:
   cols=line.split();C.need(len(cols)>=10,'proc TCP row incomplete')
   local=cols[1].rsplit(b':',1);C.need(len(local)==2,'proc TCP address differs')
   C.need(not (int(local[1],16)==18080 and cols[3]==b'0A'),'port 18080 still listening')
 for line in raw['unix'].splitlines()[1:]:
  cols=line.split();C.need(len(cols)>=7,'proc UNIX row incomplete')
  C.need(len(cols)==7 or cols[7] != ('@'+C.SOCKET_NAME).encode(),'component abstract socket still present')
 return raw,{'port_18080_listener_absent':True,'r6_abstract_endpoint_absent':True,
 'socket_connections':0,'observed_monotonic_ns':time.monotonic_ns()}
def native_capture(capture,scope):
 C.scope(scope);before=NATIVE.lstat()
 C.need(stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode),'native segment directory differs')
 names=sorted(p.name for p in NATIVE.iterdir());C.need(len(names)<=1024,'native segment count bound')
 files=[n for n in names if n.endswith('.jsonl')]
 C.need(files,'native original segment files absent')
 selected=[];sources=[];scanned=0
 for name in files:
  capture.check();p=NATIVE/name;s=p.lstat();data=C.read(p,64*1024*1024,private=False)
  C.need(C.metadata(s)==C.metadata(p.lstat()),'native segment generation changed')
  scanned+=len(data);C.need(scanned<=MAX_SCAN,'native full scan byte bound')
  source={'source_path':str(p),'source_metadata':C.metadata(s),**C.descriptor(data)};sources.append(source)
  capture.originals[str(p)]={'metadata':C.metadata(s),**C.descriptor(data)}
  offset=0
  for index,line in enumerate(data.splitlines(keepends=True),1):
   C.need(line.endswith(b'\n') and len(line)<=MAX_LINE,'incomplete/oversized native original line')
   value=C.strict(line)
   if value.get('scope')==scope:
    C.need(len(selected)<2048,'selected native record limit')
    selected.append((value,line,{'source_path':str(p),'line_1based':index,'offset':offset,
    **C.descriptor(line),'store_seq':value.get('store_seq'),'turn_seq':value.get('turn_seq')}))
   offset+=len(line)
 C.need(C.metadata(NATIVE.lstat())==C.metadata(before)
 and sorted(p.name for p in NATIVE.iterdir())==names,'native segment set changed')
 capture.directories[str(NATIVE)]={'metadata':C.metadata(before),'names':names,'capture_path':None}
 C.need(selected and all(type(v[0].get('store_seq')) is int for v in selected),'selected native sequence absent')
 selected.sort(key=lambda x:x[0]['store_seq']);rows=[x[0] for x in selected]
 C.need(len({r['store_seq'] for r in rows})==len(rows)
 and [r.get('turn_seq') for r in rows]==list(range(len(rows)))
 and rows[0].get('kind')=='turn.accepted' and rows[-1].get('kind')=='turn.end',
 'selected native original lacks complete accepted/end sequence')
 capture.save('native/selected.jsonl',b''.join(x[1] for x in selected))
 capture.save('native/ORIGINS.json',C.encoded({'schema':'hepta.native-guard.native-original-origins.v1',
 'scope':scope,'sources':sources,'selected_lines':[x[2] for x in selected],
 'bytes_scanned':scanned,'global_chain_complete':False,
 'selection':'All five actual scope fields; original lines retained without reserialization.'}))
 return {'records':len(rows),'first_store_seq':rows[0]['store_seq'],'last_store_seq':rows[-1]['store_seq']}
def verify_role_end(home):
 ended=C.strict(C.read(home/'LIFECYCLE-ENDED.json'))
 C.need(ended.get('schema')=='hepta.native-guard.lifecycle-ended.v1'
 and ended.get('roles_joined_and_groups_absent') is True
 and ended.get('model_requests')==0 and ended.get('automatic_restart') is False,
 'independent lifecycle exit/join originals required before capture')
 supervisor=C.strict(C.read(home/'SUPERVISOR.json'))
 roles={'supervisor':supervisor['identity']}
 for name in ('provider','sidecar'):
  spawned=C.strict(C.read(home/(name+'.SPAWNED.json')))
  roles[name]=spawned['identity'];original=ended['roles'][name]
  C.need(original.get('child_wait_returned') is True and original.get('dedicated_process_group_absent') is True,
  'component owned child lacks actual join')
  C.need(original==C.strict(C.read(home/(name+'.JOINED.json')))
  and original.get('identity')==roles[name] and original.get('role')==name,
  'lifecycle join differs from original owned generation receipt')
 observations=[C.absent_groups(list(roles.values())),C.absent_groups(list(roles.values()))]
 tables,endpoint=endpoint_absence()
 return {'schema':'hepta.native-guard.after-role-observation.v1','roles':roles,
 'original_lifecycle_ended_sha256':C.sha(C.read(home/'LIFECYCLE-ENDED.json')),
 'absence_observations':observations,**endpoint,'model_requests':0,
 'native_turn_verified':False,'component_qualified':False},tables
def epoch_capture_source_rows(capture_files, capture_directories):
 """Build actual source rows from complete retained capture originals."""
 C.need(type(capture_files) is dict and type(capture_directories) is dict,
 'epoch aliases require actual capture file and directory maps')
 sources = {}
 for name, row in capture_files.items():
  C.relative(name)
  C.need(type(row) is dict, 'epoch capture original row is not an object')
  if row.get('kind') != 'original_file_bytes':
   continue
  path = row.get('source_path'); metadata = row.get('source_metadata')
  C.need(type(path) is str and Path(path).is_absolute() and str(Path(path)) == path
  and '..' not in Path(path).parts and type(metadata) is list and len(metadata) == 9
  and all(type(v) is int for v in metadata) and stat.S_ISREG(metadata[2])
  and metadata[5] == 1 and type(row.get('bytes')) is int
  and row['bytes'] == metadata[6] and 0 <= row['bytes'] <= 16*1024*1024
  and type(row.get('sha256')) is str and C.HASH.fullmatch(row['sha256']),
  'epoch alias file is not a complete retained original')
  value = {'kind': 'file', 'metadata': metadata,
  'bytes': row['bytes'], 'sha256': row['sha256']}
  C.need(path not in sources or sources[path] == value,
  'epoch alias source has inconsistent retained copies')
  sources[path] = value
 for path, row in capture_directories.items():
  C.need(type(row) is dict, 'epoch capture directory row is not an object')
  if row.get('capture_path') is None:
   continue
  C.relative(row['capture_path'])
  metadata = row.get('metadata'); names = row.get('names')
  C.need(type(path) is str and Path(path).is_absolute() and str(Path(path)) == path
  and '..' not in Path(path).parts and type(metadata) is list and len(metadata) == 9
  and all(type(v) is int for v in metadata) and stat.S_ISDIR(metadata[2])
  and type(names) is list and all(type(v) is str and v not in ('', '.', '..')
  and '/' not in v and '\0' not in v for v in names)
  and names == sorted(set(names)), 'epoch alias directory identity differs')
  value = {'kind': 'directory', 'metadata': metadata, 'names': names}
  C.need(path not in sources or sources[path] == value,
  'epoch alias original changes kind or identity')
  sources[path] = value
 return sources
def epoch_alias_roots(reservation):
 """Only both complete staged home views of this actually bound identity."""
 C.need(type(reservation) is dict and set(reservation) == {
 'ordinal', 'identity', 'inventory_roots', 'required_absence_roots'}
 and type(reservation.get('ordinal')) is int
 and 1 <= reservation['ordinal'] <= 8, 'epoch alias reservation differs')
 identity = reservation.get('identity')
 if identity is None:
  C.need(reservation['inventory_roots'] == [] and reservation['required_absence_roots'] == [],
  'pre-identity reservation cannot invent present or absent home views')
  return None
 C.need(type(identity) is dict and set(identity) == {'label', 'nonce'}
 and type(identity['label']) is str and re.fullmatch('[a-z0-9-]{1,70}', identity['label'])
 and type(identity['nonce']) is str and re.fullmatch('[0-9a-f]{32}', identity['nonce']),
 'epoch alias source identity was not allocated and bound')
 home = C.BASE/'native-guard-r10-r1'/identity['label']
 android_home = C.ANDROID/(str(C.ANDROID_BASE/'native-guard-r10-r1'/identity['label']).lstrip('/'))
 roots = reservation['inventory_roots']; absent = reservation['required_absence_roots']
 C.need(type(roots) is list and type(absent) is list
 and all(type(v) is str for v in roots + absent)
 and (str(home) in roots) == (str(android_home) in roots)
 and (str(home) in absent) == (str(android_home) in absent),
 'both complete active-home views require the same verified phase presence')
 if str(home) in absent:
  C.need(str(home) not in roots and str(android_home) not in roots,
  'absent active homes cannot also be present aliases')
  return None
 C.need(str(home) in roots and str(android_home) in roots,
 'a bound identity omitted both phase-required home views')
 return home, android_home
def epoch_alias_pairs_from_capture(spec, capture_files, capture_directories):
 """Derive every active alias from both complete actual capture views."""
 C.need(type(spec) is dict and type(spec.get('active_reservations')) is list
 and type(spec.get('alias_pairs')) is list,
 'epoch alias derivation requires the independently verified inventory spec')
 sources = epoch_capture_source_rows(capture_files, capture_directories)
 computed = set(); active_roots = []
 for reservation in spec['active_reservations']:
  roots = epoch_alias_roots(reservation)
  if roots is None:
   continue
  active_roots.extend(roots)
  views = []
  for root in roots:
   view = {str(Path(path).relative_to(root)): row for path, row in sources.items()
   if Path(path) == root or root in Path(path).parents}
   C.need(view.get('.', {}).get('kind') == 'directory',
   'one epoch complete-home alias view has not been captured')
   children_by_parent = {}
   for relative in view:
    if relative != '.':
     children_by_parent.setdefault(str(Path(relative).parent), []).append(Path(relative).name)
   for relative, row in view.items():
    if relative != '.':
     parent = str(Path(relative).parent)
     C.need(parent in view and view[parent]['kind'] == 'directory',
     'epoch alias retained view has no complete original parent')
    if row['kind'] == 'directory':
     children = sorted(children_by_parent.get(relative, []))
     C.need(children == row['names'],
     'epoch alias retained directory omitted an original member')
   views.append(view)
  C.need(set(views[0]) == set(views[1]),
  'epoch complete-home aliases have different retained member sets')
  for relative in views[0]:
   C.need(views[0][relative] == views[1][relative],
   'epoch complete-home alias bytes, kind or full identity differ')
   pair = tuple(sorted(str(root/relative) for root in roots))
   C.need(pair not in computed, 'epoch complete-home alias pair is repeated')
   computed.add(pair)
 fixed = set()
 for pair in spec['alias_pairs']:
  C.need(type(pair) is list and len(pair) == 2 and all(type(v) is str for v in pair)
  and pair == sorted(set(pair)), 'epoch alias pair shape differs')
  value = tuple(pair)
  touches_active = any(Path(path) == root or root in Path(path).parents
  for path in pair for root in active_roots)
  C.need(not touches_active or value in computed,
  'declared active alias lacks complete actual capture originals')
  C.need(value not in fixed, 'declared epoch alias pair is repeated')
  fixed.add(value)
 pairs = sorted(fixed | computed)
 paths = [path for pair in pairs for path in pair]
 C.need(len(paths) == len(set(paths)), 'epoch alias path participates in a third view')
 return [list(pair) for pair in pairs]
def epoch_active_proof_shape(value, actual_context):
 """Check the declared result shape; the mandatory original replay runs separately."""
 C.need(actual_context in ('phone', 'mac', 'p4')
 and type(value) is dict and set(value) == {
 'schema', 'semantic', 'actual_context', 'source_observation'}
 and value['schema'] == 'hepta.native-guard.epoch-active-semantic-proof.v1'
 and value['actual_context'] == actual_context,
 'explicit active semantic proof and actual context required')
 semantic = value['semantic']; source = value['source_observation']
 semantic_fields = getattr(C, 'EPOCH_ACTIVE_SEMANTIC_FIELDS', None)
 source_fields = getattr(C, 'EPOCH_ACTIVE_SOURCE_OBSERVATION_FIELDS', None)
 C.need(type(semantic_fields) is tuple and len(semantic_fields) == 29
 and type(source_fields) is tuple and len(source_fields) == 6
 and type(semantic) is dict and set(semantic) == set(semantic_fields)
 and type(source) is dict and set(source) == set(source_fields),
 'final exact active semantic and reviewed-source result contracts required')
 C.need(semantic['schema'] == 'hepta.native-guard.epoch-active-semantics.v1'
 and semantic['all_previous_native_records_verified'] is True
 and all(semantic[key] is False for key in (
 'legacy_domains_flattened', 'legacy_semantics_verified_here',
 'live_inventory_verified_here', 'role_absence_verified_here',
 'endpoints_verified_here', 'component_qualified', 'business_qualified',
 'native_boundary_created'))
 and source['schema'] == 'hepta.native-guard.epoch-active-source-binding.v1'
 and source['context'] == actual_context
 and source['physical_full9_observation_claimed'] is False,
 'active reviewed bindings cannot claim physical source observations or another domain')
 return value
def capture_epoch_inputs(capture, lease):
 """Retain the actual phone files and directory observations of both domains."""
 import late_boundary as LATE
 capture.check()
 loaded = LATE.load_epoch_capture_inputs(lease, budget_check=capture.check)
 capture.check()
 C.need(type(loaded) is dict and set(loaded) == {'manifest', 'originals_by_path', 'verified'},
 'epoch capture loader return shape differs')
 manifest = loaded['manifest']; originals = loaded['originals_by_path']
 verified = LATE.verify_epoch_capture_inputs(lease, manifest, originals)
 C.need(C.encoded(verified) == C.encoded(loaded['verified']),
 'epoch capture loader changed its independently checked result')
 C.need(type(manifest) is dict and type(manifest.get('files')) is list
 and type(manifest.get('directories')) is list and type(originals) is dict,
 'epoch capture original manifest is incomplete')
 paths = [row['path'] for row in manifest['files']]
 C.need(len(paths) == len(set(paths)) and set(paths) == set(originals),
 'epoch capture original byte set differs from the manifest')
 copied = {}
 for row in manifest['files']:
  capture.check()
  C.need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'metadata'},
  'epoch input requires the actual original path and full identity')
  path = row['path']; name = 'epoch-inputs/files/'+C.sha(path.encode('utf-8'))+'.original'
  raw = originals[path]
  C.need(type(raw) is bytes and C.descriptor(raw) == {key: row[key] for key in ('bytes', 'sha256')},
  'epoch loader did not supply the complete actual original bytes')
  capture.save(name, raw, origin={'source_path': path, 'source_metadata': row['metadata']})
  identity = {'metadata': row['metadata'], **C.descriptor(raw)}
  C.need(path not in capture.originals or capture.originals[path] == identity,
  'epoch input differs from an earlier retained actual source')
  capture.originals[path] = identity
  copied[path] = raw
 replayed = LATE.verify_epoch_capture_inputs(lease, manifest, copied)
 C.need(C.encoded(replayed) == C.encoded(verified),
 'retained epoch originals do not reproduce the actual admitted domains')
 legacy = LATE.epoch_verified_legacy_context(lease, manifest, copied, replayed,
 budget_check=capture.check)
 C.need(type(legacy) is dict and set(legacy) == {
 'schema', 'semantic', 'actual_context', 'source_observation'}
 and legacy['schema'] == 'hepta.native-guard.epoch-legacy-semantic-proof.v1'
 and legacy['actual_context'] == 'phone'
 and type(legacy['semantic']) is dict and type(legacy['source_observation']) is dict,
 'actual phone historical semantic verification is missing')
 active_gate = getattr(LATE, 'epoch_verified_active_context', None)
 phone_source_gate = getattr(LATE, 'verify_epoch_phone_active_source_observation', None)
 C.need(callable(active_gate) and callable(phone_source_gate),
 'mandatory active semantics and phone source-binding gates are not installed')
 capture.check()
 active = epoch_active_proof_shape(active_gate(
 lease, manifest, copied, replayed, budget_check=capture.check), 'phone')
 C.need(C.encoded(phone_source_gate(active['source_observation'], manifest, copied, replayed))
 == C.encoded(active['source_observation']),
 'actual phone active reviewed-source bindings do not reproduce their original authority')
 capture.check()
 capture.save('epoch-inputs/MANIFEST.json', C.encoded(manifest))
 capture.save('epoch-inputs/LEGACY-SEMANTIC.json', C.encoded(legacy))
 capture.save('epoch-inputs/ACTIVE-SEMANTIC.json', C.encoded(active))
 capture.check()
 return manifest, replayed
def capture_active_epoch_aliases(capture, spec):
 """Copy both complete existing home views under the same one Capture."""
 for reservation in spec['active_reservations']:
  roots = epoch_alias_roots(reservation)
  if roots is None:
   continue
  for name, root in zip(('gnu', 'android'), roots):
   capture.check()
   if str(root) not in capture.directories:
    capture.tree(root, 'epoch-alias/'+str(reservation['ordinal'])+'/'+name)
 return epoch_alias_pairs_from_capture(spec, capture.files, capture.directories)
def capture_epoch_inventory(capture, lease, verified):
 """One full union inventory, with a separate explicit two-domain proof."""
 import late_boundary as LATE
 capture.check()
 C.need(type(verified) is dict and set(verified) == {
 'legacy', 'active', 'registry', 'anchor', 'failure_inputs', 'retained_roots', 'control_roots'},
 'epoch input verification did not return both explicit domains')
 spec = LATE.build_epoch_inventory_spec(verified['anchor'], verified['registry'],
 verified['failure_inputs'])
 LIFE.inventory_epoch_spec_value(spec)
 spec = C.strict(C.encoded(spec))
 spec['alias_pairs'] = capture_active_epoch_aliases(capture, spec)
 planned = LIFE.inventory_epoch_spec_value(spec)
 roots = list(map(Path, planned['roots'])); fixtures = list(map(Path, planned['fixture_roots']))
 current = C.ANDROID/'data/local/tmp'/('hepta-native-guard-'+lease['nonce'])
 absent = []
 for fixture in fixtures:
  capture.check()
  try:
   fixture.lstat()
  except OSError as error:
   C.need(error.errno == 2, 'epoch fixture existence is unknown')
   absent.append(LIFE.fixture_absence(fixture))
  else:
   name = 'fixture' if fixture == current else 'prior-fixture/'+fixture.name.rsplit('-', 1)[1]
   capture.tree(fixture, name, private=False)
 capture.check()
 result = LIFE.inventory_epoch(spec)
 capture.check()
 C.need(type(result) is dict and set(result) == {'inventory', 'control_inventory', 'epoch_observation'},
 'epoch inventory omitted its separate global accounting proof')
 LIFE.verify_epoch_inventory_observation(spec, result['inventory'], result['control_inventory'],
 result['epoch_observation'])
 C.need(result['inventory']['roots'] == planned['business_inventory_roots'],
 'epoch inventory root union differs from the independently derived specification')
 for item in result['epoch_observation']['control_leaves']:
  path, row = item['path'], item['entry']
  if row['kind'] == 'absent':
   C.need(path not in capture.originals, 'absent control leaf was retained as a present original')
  else:
   C.need(row['kind'] == 'file' and path in capture.originals
   and C.encoded(capture.originals[path]) == C.encoded({
   key: row[key] for key in ('metadata', 'bytes', 'sha256')}),
   'fixed control leaf has no complete captured original with the same phone full9 and bytes')
 capture.save('after/EPOCH-INVENTORY-SPEC.json', C.encoded(spec))
 capture.save('after/EPOCH-INVENTORY-OBSERVATION.json', C.encoded(result['epoch_observation']))
 capture.save('after/CONTROL-INVENTORY.json', C.encoded(result['control_inventory']))
 capture.check()
 return result['inventory'], roots, absent
def epoch_capture_binding(capture):
 descriptors = {key: {field: capture.files[path][field] for field in ('bytes', 'sha256')}
 for key, path in (
 ('inputs_manifest', 'epoch-inputs/MANIFEST.json'),
 ('legacy_semantic', 'epoch-inputs/LEGACY-SEMANTIC.json'),
 ('active_semantic', 'epoch-inputs/ACTIVE-SEMANTIC.json'),
 ('inventory_spec', 'after/EPOCH-INVENTORY-SPEC.json'),
 ('inventory_observation', 'after/EPOCH-INVENTORY-OBSERVATION.json'),
 ('control_inventory', 'after/CONTROL-INVENTORY.json'))}
 return {'schema': 'hepta.native-guard.epoch-capture-binding.v1', **descriptors,
 'native_chain_domains_flattened': False, 'case_or_lease_authorized': False}
def make_archive(snapshot,files):
 target=io.BytesIO()
 with tarfile.open(fileobj=target,mode='w',format=tarfile.USTAR_FORMAT) as archive:
  for name in sorted(files):
   raw=C.read(snapshot/C.relative(name),MAX_FILE)
   C.need(C.descriptor(raw)=={k:files[name][k] for k in ('bytes','sha256')},'captured bytes changed before archive')
   row=tarfile.TarInfo(name);row.size=len(raw);row.uid=row.gid=0;row.mode=0o600;row.mtime=0
   archive.addfile(row,io.BytesIO(raw))
 plain=target.getvalue();C.need(len(plain)<=MAX_BYTES+8*1024*1024,'archive total bound')
 raw=gzip.compress(plain,mtime=0);C.need(len(raw)<=MAX_BYTES,'archive compressed byte bound')
 return raw
def capture_non_native_sidebranch(capture):
 """Copy the three fixed original sideproof files; never create a native scope."""
 import late_boundary as LATE
 sidebranch = LATE.non_native_sidebranch(phone_originals=True)
 binding = sidebranch['binding']
 roles = list(binding['component_role_identities'].values())
 observations = [C.absent_groups(roles)]
 prefix = 'non-native-sidebranch/'+binding['nonce']+'/'
 for key, filename in LATE.NON_NATIVE_CAPTURE_FILES.items():
  row = binding[key]
  body = capture.file(row['path'], prefix+filename)
  C.need(body == sidebranch['raw'][key]
  and capture.files[prefix+filename]['source_metadata'] == row['metadata'],
  'captured non-native sideproof differs from its fixed original')
 observations.append(C.absent_groups(roles))
 LATE.recheck_originals(sidebranch['originals'])
 capture.save('observation/NON-NATIVE-SIDEBRANCH.json', C.encoded({
 'schema': 'hepta.native-guard.non-native-sidebranch-observation.v1',
 'binding': binding, 'absence_observations': observations,
 'phone_tool_calls': 0, 'model_requests': 0, 'native_submissions': 0,
 'native_scope_assigned': False, 'native_case_count': 0, 'component_qualified': False}))
 return sidebranch
def snapshot(a):
 import late_boundary as LATE
 C.need(C.epoch_actual_context(globals()) == 'phone'
 and C.epoch_actual_context(C.__dict__) == 'phone'
 and C.epoch_actual_context(LIFE.__dict__) == 'phone'
 and C.epoch_actual_context(LATE.__dict__) == 'phone',
 'original phone snapshot requires explicit phone module contexts')
 C.need(a.execute_original_snapshot_once,'explicit new original capture required')
 os.umask(0o077);home=C.private_dir(Path(a.lease))
 lease,lease_raw=LIFE.load_lease(home,a.lease_sha256,require_live=False)
 LIFE.native_root(lease['boot_id'])
 C.need(a.package_sha256==lease['package_sha256'],'explicit snapshot adapter pin differs')
 C.verify_package(home/'package/MANIFEST.json',a.package_sha256)
 C.need(Path(__file__)==home/'package/source/component_snapshot.py','snapshot must use the staged pinned source')
 combo_raw=C.pinned(home/'inputs/COMBINATION.json',lease['combination'])
 combo,_=C.load_combination(home/'inputs',combo_raw,
 C.strict(C.read(home/'package/reference/REVIEWED-PRODUCTION-PINS.json')))
 C.verify_external(combo)
 accepted=C.strict(C.read(home/'ACCEPTED.json'));scope=C.scope(accepted['scope'])
 bound=C.strict(C.read(home/'BOUND-CONTRACT.json'))
 C.need(bound['lease_sha256']==a.lease_sha256 and C.sha(C.encoded(bound['contract']))==accepted['contract_sha256']
 and bound['contract']['owner_request_sha256']==lease['owner_request_sha256'],'accepted original contract differs')
 run=C.COMPONENT_EVIDENCE/bound['run_basename']
 C.need(re.fullmatch(r'[0-9]{8}-[0-9]{6}-'+lease['nonce'],bound['run_basename'])
 and accepted['run_dir']==str(run),'exact original component run required')
 first=C.strict(C.read(run/'provider-in-00.jsonl',C.MAX_FRAME))
 C.need(first['kind']=='turn.start' and {k:first['turn'][k] for k in C.SCOPE}==scope
 and first['turn']['user_input'].encode()==C.read(home/'owner-request.txt',16000),
 'original owner/five-scope first native frame differs')
 after,tables=verify_role_end(home)
 out=Path(a.out)
 C.need(out.parent==C.BASE/'native-guard-snapshots-r10-r1'
 and re.fullmatch(re.escape(lease['label'])+r'-capture-[0-9]{2}',out.name),
 'new explicit per-lease capture namespace required')
 try:C.private_dir(out.parent)
 except FileNotFoundError:C.private_dir(out.parent,create=True)
 C.private_dir(out,create=True)
 original_handler=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('component snapshot 75-second hard bound')))
 signal.alarm(75);cap=Capture(out/'snapshot')
 try:
  cap.tree(home,'home');cap.tree(run,'run')
  journal=C.ANDROID/lease['android_journal'].lstrip('/')
  cap.tree(journal,'executor');cap.tree(C.PRODUCTION_EVIDENCE/'action-ledger','ledger')
  for key,row in lease['retirement'].items():cap.file(row['path'],'retirement/'+key+'.original')
  if lease['prior_boundary'] is not None:cap.file(lease['prior_boundary']['path'],'retirement/prior-boundary.original.json')
  epoch_manifest,epoch_verified=capture_epoch_inputs(cap,lease)
  sidebranch=capture_non_native_sidebranch(cap)
  actions=[]
  for phase in ('capture','guard'):
   path=run/(phase+'.dispatch-intent.json')
   try:value=C.strict(C.read(path))
   except FileNotFoundError:continue
   action=value['action_id'];C.need(re.fullmatch('[0-9a-f]{32}',action),'native action id differs')
   C.need(action not in actions,'component duplicate native action id');actions.append(action)
  client=C.BASE/'client-receipts';names=sorted(p.name for p in client.iterdir())
  for action in actions:
   for name in names:
    if not name.startswith(action+'.'):continue
    p=client/name
    if stat.S_ISDIR(p.lstat().st_mode):cap.tree(p,'client/'+name)
    else:cap.file(p,'client/'+name)
  fixture=C.ANDROID/'data/local/tmp'/('hepta-native-guard-'+lease['nonce'])
  native=native_capture(cap,scope)
  full,roots,absent=capture_epoch_inventory(cap,lease,epoch_verified)
  import late_boundary as LATE
  LATE.preserve_non_native_private(full,sidebranch)
  LATE.recheck_originals(sidebranch['originals'])
  if absent:
   for row in absent:LIFE.fixture_absence(row['path'])
   cap.save('observation/FIXTURE-ABSENCE.json',C.encoded({'schema':'hepta.native-guard.fixture-absence-set.v1',
   'scope':scope,'observations':absent,'absence_does_not_qualify_component':True}))
  cap.save('after/AFTER-INVENTORY.json',C.encoded(full))
  cap.save('observation/AFTER-ROLES.json',C.encoded(after))
  for name,raw in tables.items():cap.save('observation/proc-net-'+name+'.original',raw)
  cap.recheck()
  cap.check()
  C.need(C.encoded(LATE.recheck_epoch_capture_inputs(epoch_manifest,budget_check=cap.check))==C.encoded(epoch_manifest),
  'actual epoch input or control directory changed at the final capture bookend')
  cap.check()
  C.need(all(out!=p and p not in out.parents and out not in p.parents for p in roots),'capture overlaps original inventory')
  report={'schema':'hepta.native-guard.epoch-original-capture.v1',
  'state':'ORIGINAL_BYTES_CAPTURED_FOR_INDEPENDENT_AUDIT','boot_id':lease['boot_id'],
  'scope':scope,'owner_request_sha256':lease['owner_request_sha256'],'nonce':lease['nonce'],
  'case_id':lease['case_id'],'lease_sha256':C.sha(lease_raw),'package_sha256':a.package_sha256,
  'combination_sha256':C.sha(combo_raw),'run_basename':bound['run_basename'],
  'retirement_proof_sha256':lease['retirement']['proof']['sha256'],
  'prior_boundary_sha256':None if lease['prior_boundary'] is None else lease['prior_boundary']['sha256'],
  'files':cap.files,'directories':cap.directories,'retained_bytes':cap.total,'native':native,
  'non_native_sidebranch':sidebranch['binding'],'epoch':epoch_capture_binding(cap),
  'action_ids':actions,'component_qualified':False,'business_qualified':False,'model_requests':0,
  'native_dispatches':0,'ui_actions':0,'socket_connections':0,'source_original_writes':0,
  'automatic_retry':False,'inventory_is_closure_or_retirement':False}
  report_raw=C.encoded(report);C.put(out/'CAPTURE.json',report_raw)
  archive_files={**cap.files,'CAPTURE.json':C.descriptor(report_raw)}
  C.put(cap.destination/'CAPTURE.json',report_raw)
  body=make_archive(cap.destination,archive_files);C.put(out/'ORIGINALS.tar.gz',body)
  result={'schema':'hepta.native-guard.snapshot-result.v1','state':'ORIGINAL_CAPTURE_ARCHIVED',
  'capture':C.descriptor(report_raw),'archive':C.descriptor(body),'archive_members':len(archive_files),
  'capture_path':str(out/'CAPTURE.json'),'archive_path':str(out/'ORIGINALS.tar.gz'),
  'component_qualified':False,'business_qualified':False,'model_requests':0,'automatic_retry':False}
  C.put(out/'RESULT.json',result);print(C.encoded(result).decode(),end='');return 0
 except BaseException as error:
  C.put(out/'PARTIAL-CAPTURE.json',{'state':'PARTIAL_ORIGINALS_PRESERVED_NOT_QUALIFIED',
  'error_type':type(error).__name__,'detail':str(error)[:1024],'files':cap.files,
  'component_qualified':False,'business_qualified':False,'automatic_retry':False})
  raise
 finally:signal.alarm(0);signal.signal(signal.SIGALRM,original_handler)
def main():
 p=argparse.ArgumentParser()
 for name in ('lease','lease-sha256','package-sha256','out'):p.add_argument('--'+name,required=True)
 p.add_argument('--execute-original-snapshot-once',action='store_true')
 return snapshot(p.parse_args())
import component_common as _EPS_CAPTURE_COMMON
import stat as _eps_stat
def _eps_capture_source_rows(capture_files, capture_directories):
 """Build actual source rows from complete retained capture originals."""
 _EPS_CAPTURE_COMMON.need(type(capture_files) is dict and type(capture_directories) is dict,
 'epoch aliases require actual capture file and directory maps')
 sources = {}
 for name, row in capture_files.items():
  _EPS_CAPTURE_COMMON.relative(name)
  _EPS_CAPTURE_COMMON.need(type(row) is dict, 'epoch capture original row is not an object')
  if row.get('kind') != 'original_file_bytes':
   continue
  path = row.get('source_path'); metadata = row.get('source_metadata')
  _EPS_CAPTURE_COMMON.need(type(path) is str and Path(path).is_absolute() and str(Path(path)) == path
  and '..' not in Path(path).parts and type(metadata) is list and len(metadata) == 9
  and all(type(v) is int for v in metadata) and _eps_stat.S_ISREG(metadata[2])
  and metadata[5] == 1 and type(row.get('bytes')) is int
  and row['bytes'] == metadata[6] and 0 <= row['bytes'] <= 16*1024*1024
  and type(row.get('sha256')) is str and _EPS_CAPTURE_COMMON.HASH.fullmatch(row['sha256']),
  'epoch alias file is not a complete retained original')
  value = {'kind': 'file', 'metadata': metadata,
  'bytes': row['bytes'], 'sha256': row['sha256']}
  _EPS_CAPTURE_COMMON.need(path not in sources or sources[path] == value,
  'epoch alias source has inconsistent retained copies')
  sources[path] = value
 for path, row in capture_directories.items():
  _EPS_CAPTURE_COMMON.need(type(row) is dict, 'epoch capture directory row is not an object')
  if row.get('capture_path') is None:
   continue
  _EPS_CAPTURE_COMMON.relative(row['capture_path'])
  metadata = row.get('metadata'); names = row.get('names')
  _EPS_CAPTURE_COMMON.need(type(path) is str and Path(path).is_absolute() and str(Path(path)) == path
  and '..' not in Path(path).parts and type(metadata) is list and len(metadata) == 9
  and all(type(v) is int for v in metadata) and _eps_stat.S_ISDIR(metadata[2])
  and type(names) is list and all(type(v) is str and v not in ('', '.', '..')
  and '/' not in v and '\0' not in v for v in names)
  and names == sorted(set(names)), 'epoch alias directory identity differs')
  value = {'kind': 'directory', 'metadata': metadata, 'names': names}
  _EPS_CAPTURE_COMMON.need(path not in sources or sources[path] == value,
  'epoch alias original changes kind or identity')
  sources[path] = value
 return sources
def _eps_alias_roots(reservation):
 """Only both complete staged home views of this actually bound identity."""
 _EPS_CAPTURE_COMMON.need(type(reservation) is dict and set(reservation) == {
 'ordinal', 'identity', 'inventory_roots', 'required_absence_roots'}
 and type(reservation.get('ordinal')) is int
 and 1 <= reservation['ordinal'] <= 8, 'epoch alias reservation differs')
 identity = reservation.get('identity')
 if identity is None:
  _EPS_CAPTURE_COMMON.need(reservation['inventory_roots'] == [] and reservation['required_absence_roots'] == [],
  'pre-identity reservation cannot invent present or absent home views')
  return None
 _EPS_CAPTURE_COMMON.need(type(identity) is dict and set(identity) == {'label', 'nonce'}
 and type(identity['label']) is str and re.fullmatch('[a-z0-9-]{1,70}', identity['label'])
 and type(identity['nonce']) is str and re.fullmatch('[0-9a-f]{32}', identity['nonce']),
 'epoch alias source identity was not allocated and bound')
 home = _EPS_CAPTURE_COMMON.BASE/'native-guard-r10-r1'/identity['label']
 android_home = _EPS_CAPTURE_COMMON.ANDROID/(str(_EPS_CAPTURE_COMMON.ANDROID_BASE/'native-guard-r10-r1'/identity['label']).lstrip('/'))
 roots = reservation['inventory_roots']; absent = reservation['required_absence_roots']
 _EPS_CAPTURE_COMMON.need(type(roots) is list and type(absent) is list
 and all(type(v) is str for v in roots + absent)
 and (str(home) in roots) == (str(android_home) in roots)
 and (str(home) in absent) == (str(android_home) in absent),
 'both complete active-home views require the same verified phase presence')
 if str(home) in absent:
  _EPS_CAPTURE_COMMON.need(str(home) not in roots and str(android_home) not in roots,
  'absent active homes cannot also be present aliases')
  return None
 _EPS_CAPTURE_COMMON.need(str(home) in roots and str(android_home) in roots,
 'a bound identity omitted both phase-required home views')
 return home, android_home
def _eps_alias_pairs_from_capture(spec, capture_files, capture_directories):
 """Derive every active alias from both complete actual capture views."""
 _EPS_CAPTURE_COMMON.need(type(spec) is dict and type(spec.get('active_reservations')) is list
 and type(spec.get('alias_pairs')) is list,
 'epoch alias derivation requires the independently verified inventory spec')
 sources = _eps_capture_source_rows(capture_files, capture_directories)
 computed = set(); active_roots = []
 for reservation in spec['active_reservations']:
  roots = _eps_alias_roots(reservation)
  if roots is None:
   continue
  active_roots.extend(roots)
  views = []
  for root in roots:
   view = {str(Path(path).relative_to(root)): row for path, row in sources.items()
   if Path(path) == root or root in Path(path).parents}
   _EPS_CAPTURE_COMMON.need(view.get('.', {}).get('kind') == 'directory',
   'one epoch complete-home alias view has not been captured')
   children_by_parent = {}
   for relative in view:
    if relative != '.':
     children_by_parent.setdefault(str(Path(relative).parent), []).append(Path(relative).name)
   for relative, row in view.items():
    if relative != '.':
     parent = str(Path(relative).parent)
     _EPS_CAPTURE_COMMON.need(parent in view and view[parent]['kind'] == 'directory',
     'epoch alias retained view has no complete original parent')
    if row['kind'] == 'directory':
     children = sorted(children_by_parent.get(relative, []))
     _EPS_CAPTURE_COMMON.need(children == row['names'],
     'epoch alias retained directory omitted an original member')
   views.append(view)
  _EPS_CAPTURE_COMMON.need(set(views[0]) == set(views[1]),
  'epoch complete-home aliases have different retained member sets')
  for relative in views[0]:
   _EPS_CAPTURE_COMMON.need(views[0][relative] == views[1][relative],
   'epoch complete-home alias bytes, kind or full identity differ')
   pair = tuple(sorted(str(root/relative) for root in roots))
   _EPS_CAPTURE_COMMON.need(pair not in computed, 'epoch complete-home alias pair is repeated')
   computed.add(pair)
 fixed = set()
 for pair in spec['alias_pairs']:
  _EPS_CAPTURE_COMMON.need(type(pair) is list and len(pair) == 2 and all(type(v) is str for v in pair)
  and pair == sorted(set(pair)), 'epoch alias pair shape differs')
  value = tuple(pair)
  touches_active = any(Path(path) == root or root in Path(path).parents
  for path in pair for root in active_roots)
  _EPS_CAPTURE_COMMON.need(not touches_active or value in computed,
  'declared active alias lacks complete actual capture originals')
  _EPS_CAPTURE_COMMON.need(value not in fixed, 'declared epoch alias pair is repeated')
  fixed.add(value)
 pairs = sorted(fixed | computed)
 paths = [path for pair in pairs for path in pair]
 _EPS_CAPTURE_COMMON.need(len(paths) == len(set(paths)), 'epoch alias path participates in a third view')
 return [list(pair) for pair in pairs]
def _eps_manifest_inventory_rows(manifest, inventory, control_inventory, observation):
 """Cross-link protocol originals with the one complete inventory read."""
 originals = {row['path']: {'kind': 'file', 'metadata': row['metadata'],
 'bytes': row['bytes'], 'sha256': row['sha256']}
 for row in manifest['files']}
 _EPS_CAPTURE_COMMON.need(len(originals) == len(manifest['files']), 'epoch manifest repeats an original path')
 for row in manifest['directories']:
  _EPS_CAPTURE_COMMON.need(type(row) is dict and set(row) == {'path', 'metadata', 'names'}
  and row['path'] not in originals, 'epoch manifest directory is malformed or repeated')
  originals[row['path']] = {'kind': 'directory', 'metadata': row['metadata'], 'names': row['names']}
 business = inventory['entries']
 control = {} if control_inventory is None else control_inventory['entries']
 _EPS_CAPTURE_COMMON.need(not (set(business) & set(control)), 'control inventory overlaps business originals')
 for path, row in originals.items():
  if path in business:
   _EPS_CAPTURE_COMMON.need(_EPS_CAPTURE_COMMON.encoded(business[path]) == _EPS_CAPTURE_COMMON.encoded(row),
   'epoch business input changed between protocol capture and full inventory')
  if path in control:
   _EPS_CAPTURE_COMMON.need(_EPS_CAPTURE_COMMON.encoded(control[path]) == _EPS_CAPTURE_COMMON.encoded(row),
   'epoch control original changed between protocol capture and full inventory')
 for path, row in control.items():
  _EPS_CAPTURE_COMMON.need(path in originals and _EPS_CAPTURE_COMMON.encoded(originals[path]) == _EPS_CAPTURE_COMMON.encoded(row),
  'complete control inventory contains an unretained protocol original')
 for item in observation['control_leaves']:
  path, row = item['path'], item['entry']
  _EPS_CAPTURE_COMMON.need(path not in business and path not in control,
  'flat control leaf leaked into a directory-root inventory projection')
  if row['kind'] == 'absent':
   _EPS_CAPTURE_COMMON.need(path not in originals, 'absent control leaf has a conflicting captured original')
  else:
   _EPS_CAPTURE_COMMON.need(row['kind'] == 'file' and path in originals
   and _EPS_CAPTURE_COMMON.encoded(originals[path]) == _EPS_CAPTURE_COMMON.encoded(row),
   'fixed control leaf body and original phone metadata are missing or differ')
"""Pure two-layer authority for one actual epoch host closure.

Every body is obtained from the caller's already charged original pool.  Host
origin paths and phone carrier inodes remain distinct.  This module never reads
a host archive, imports the closer, executes a Root template, or grants an
action from a state string.  Final template/renderer/layout bindings are absent
in this source-only candidate and must refuse before any authority is returned.
"""
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import stat
EPOCH_CLOSURE_AUTHORITY_LAYOUT = None
EPOCH_CLOSURE_AUTHORITY_SOURCES = None
EPOCH_CLOSURE_AUTHORITY_PRODUCER = None
_ECA_LIMIT = 32*1024*1024
_ECA_META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
'st_size','st_mtime_ns','st_ctime_ns')
_ECA_ROLES = (
'root_plan','root_source_manifest','root_coordinator_source',
'root_bridge_source','root_verifier_source','runtime_manifest','closer_source',
'mac_intent','mac_stdin','mac_child','mac_result','mac_joined',
'mac_output_capture','mac_stdout','mac_stderr',
'p4_intent','p4_child','p4_result','p4_joined',
'p4_output_capture','p4_stdout','p4_stderr',
'closure_plan','closure_result','closed_original','inventory_original')
_ECA_ALIASES = {'mac_joined':'mac_result','p4_joined':'p4_result'}
def _eca_need(value, message):
 if not value:
  raise ValueError(message)
def _eca_encoded(value, *, pretty=False):
 options={'ensure_ascii':False,'sort_keys':True,'allow_nan':False}
 options.update({'indent':2} if pretty else {'separators':(',',':')})
 return (json.dumps(value,**options)+'\n').encode('utf-8')
def _eca_same(left,right):
 return _eca_encoded(left)==_eca_encoded(right)
def _eca_strict(raw):
 _eca_need(type(raw) is bytes and len(raw)<=_ECA_LIMIT,'complete bounded original JSON required')
 def pairs(rows):
  value={}
  for key,item in rows:
   _eca_need(key not in value,'duplicate authority JSON key')
   value[key]=item
  return value
 def constant(value):
  raise ValueError('non-finite authority JSON number: '+value)
 return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=constant)
def _eca_exact(value,keys,message):
 _eca_need(type(value) is dict and set(value)==set(keys),message)
def _eca_path(value):
 _eca_need(type(value) is str and value.startswith('/') and not value.startswith('//')
 and '\0' not in value and len(value.encode('utf-8'))<=4096
 and str(PurePosixPath(value))==value and '..' not in PurePosixPath(value).parts,
 'canonical absolute authority path required')
 return value
def _eca_bare(raw):
 _eca_need(type(raw) is bytes,'actual complete bytes required')
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def _eca_pin(value, *, phone=False):
 _eca_exact(value,('path','bytes','sha256','metadata') if phone else
 ('path','bytes','sha256'),'exact origin or carrier descriptor required')
 _eca_path(value['path'])
 _eca_need(type(value['bytes']) is int and 0<=value['bytes']<=_ECA_LIMIT
 and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']) is not None,
 'authority original byte count or digest differs')
 if phone:
  m=value['metadata']
  _eca_need(type(m) is list and len(m)==9 and all(type(x) is int and x>=0 for x in m)
  and stat.S_ISREG(m[2]) and stat.S_IMODE(m[2])==0o600
  and m[3:6]==[0,0,1] and m[6]==value['bytes'],
  'actual private phone carrier full9 is required')
 return value
def _eca_number(value,message):
 _eca_need(type(value) in (int,float) and math.isfinite(value) and value>=0,message)
 return value
def _eca_metadata(value, *, size):
 _eca_exact(value,_ECA_META,'actual held output metadata fields differ')
 _eca_need(all(type(value[k]) is int and value[k]>=0 for k in _ECA_META)
 and value['st_ino']>0 and stat.S_ISREG(value['st_mode'])
 and stat.S_IMODE(value['st_mode'])==0o600 and value['st_nlink']==1
 and value['st_size']==size,'actual regular output metadata differs')
 return value
class _ECAOriginals:
 """A strict view of the existing pool; this creates no additional allowance."""
 def __init__(self,original_from,budget_check):
  _eca_need(callable(original_from) and callable(budget_check),
  'original lookup and same enclosing budget are required')
  self.original_from=original_from;self.budget_check=budget_check;self.used={}
 def get(self,pin):
  self.budget_check();_eca_pin(pin,phone=True)
  path=pin['path']
  if path in self.used:
   previous,raw=self.used[path]
   _eca_need(_eca_same(previous,pin),'one carrier path changed full original identity')
   return raw
  raw=self.original_from(pin);self.budget_check()
  _eca_need(type(raw) is bytes and _eca_same(_eca_bare(raw),
  {k:pin[k] for k in ('bytes','sha256')}),'actual carrier body differs')
  self.used[path]=(_eca_strict(_eca_encoded(pin)),raw)
  _eca_need(sum(len(pair[1]) for pair in self.used.values())<=_ECA_LIMIT,
  'authority subset exceeds the same enclosing 32MiB original pool')
  return raw
 def descriptors(self):
  return [self.used[path][0] for path in sorted(self.used)]
def _eca_final_bindings():
 _eca_need(EPOCH_CLOSURE_AUTHORITY_LAYOUT is not None
 and EPOCH_CLOSURE_AUTHORITY_SOURCES is not None
 and EPOCH_CLOSURE_AUTHORITY_PRODUCER is not None,
 'actual closure producer, reviewed templates and fixed layout are not bound')
 return EPOCH_CLOSURE_AUTHORITY_LAYOUT,EPOCH_CLOSURE_AUTHORITY_SOURCES,EPOCH_CLOSURE_AUTHORITY_PRODUCER
def _eca_packet(packet_pin,pool, *, expected, directory_from):
 raw=pool.get(packet_pin);value=_eca_strict(raw)
 _eca_exact(value,{'schema','epoch_id','ordinal','nonce','identity','generation',
 'inner_stdin','originals'},'complete finite closure-authority packet required')
 ordinal=expected['ordinal'];root=expected['registry_root']+'/slots/%02d/closure-authority'%ordinal
 _eca_need(value['schema']=='hepta.native-guard.epoch-closure-authority.v1'
 and value['epoch_id']==expected['epoch_id'] and type(value['ordinal']) is int
 and value['ordinal']==ordinal and value['nonce']==expected['nonce']
 and _eca_same(value['identity'],expected['identity'])
 and _eca_same(value['generation'],expected['generation'])
 and value['inner_stdin'] is None and raw==_eca_encoded(value)
 and packet_pin['path']==root+'/AUTHORITY.json',
 'authority packet changed its allocated ordinal, original identity or actual DEVNULL')
 _eca_need(type(value['originals']) is list and len(value['originals'])==len(_ECA_ROLES),
 'finite source, two-layer action and output originals are incomplete')
 records={};bodies={};origins={};paths=set();origin_paths=set()
 _eca_need([row.get('role') for row in value['originals']]==sorted(_ECA_ROLES),
 'authority role order or exact role set differs')
 for row in value['originals']:
  _eca_exact(row,{'role','origin','carrier'},'authority origin/carrier fields differ')
  role=row['role'];origin=_eca_pin(row['origin']);carrier=_eca_pin(row['carrier'],phone=True)
  name=_ECA_ALIASES.get(role,role)+'.original'
  _eca_need(carrier['path']==root+'/originals/'+name
  and origin['path']!=carrier['path']
  and _eca_same({k:origin[k] for k in ('bytes','sha256')},
  {k:carrier[k] for k in ('bytes','sha256')}),
  'host origin was confused with its exclusively created phone carrier')
  if role not in _ECA_ALIASES:
   _eca_need(carrier['path'] not in paths and origin['path'] not in origin_paths,
   'distinct original roles repeat a path without a reviewed alias')
   paths.add(carrier['path']);origin_paths.add(origin['path'])
  records[role]=row;origins[role]=origin;bodies[role]=pool.get(carrier)
 for alias,target in _ECA_ALIASES.items():
  _eca_need(_eca_same(records[alias]['origin'],records[target]['origin'])
  and _eca_same(records[alias]['carrier'],records[target]['carrier'])
  and bodies[alias]==bodies[target],
  'synchronous joined role is not the same original RESULT alias')
 for path,names in ((root,['AUTHORITY.json','originals']),
 (root+'/originals',sorted(PurePosixPath(p).name for p in paths))):
  pool.budget_check();observed=directory_from(path);pool.budget_check()
  _eca_exact(observed,{'path','metadata','names'},'actual authority directory observation required')
  m=observed['metadata']
  _eca_need(observed['path']==path and type(m) is list and len(m)==9
  and all(type(x) is int and x>=0 for x in m) and stat.S_ISDIR(m[2])
  and stat.S_IMODE(m[2])==0o700 and m[3:5]==[0,0] and m[5]>=1
  and _eca_same(observed['names'],sorted(names)),
  'complete private authority directory members or actual full9 differ')
 return value,origins,bodies
def _eca_runtime_sources(origins,bodies, *, runtime_raw,runtime_sources,generation):
 _eca_need(type(runtime_raw) is bytes and bodies['runtime_manifest']==runtime_raw
 and _eca_same(_eca_bare(runtime_raw),{k:generation['runtime'][k] for k in ('bytes','sha256')}),
 'actual host runtime manifest differs from the immutable source catalog')
 manifest=_eca_strict(runtime_raw);rows=manifest.get('files')
 _eca_need(type(rows) is list and len(rows)==32 and type(runtime_sources) is dict
 and len(runtime_sources)==32,'complete actual32 current runtime bytes required')
 seen=set()
 for row in rows:
  _eca_exact(row,{'path','bytes','sha256'},'runtime member row fields differ')
  path=row['path']
  _eca_need(type(path) is str and path.startswith(('source/','reference/'))
  and not path.startswith('/') and '\0' not in path and '..' not in path.split('/')
  and '' not in path.split('/') and path not in seen and path in runtime_sources
  and (path.endswith('.py') or path.endswith('.json')) and type(row['bytes']) is int
  and 0<row['bytes']<=(131072 if path.endswith('.py') else 16*1024*1024)
  and type(runtime_sources[path]) is bytes
  and _eca_same(_eca_bare(runtime_sources[path]),{k:row[k] for k in ('bytes','sha256')}),
  'source-authorized runtime map changes or omits complete original bytes')
  seen.add(path)
 _eca_need(seen==set(runtime_sources)
 and bodies['closer_source']==runtime_sources['source/close_component.py'],
 'actual host closer source differs from the reviewed complete runtime')
 return manifest
import ast
import base64
_ECA_CLOSE_RENDER_FUNCTIONS={'epoch_owned_source_sections': {'bytes': 1293, 'sha256': 'cb90fe197f45468873cce15dcf8d279f3fee5a7a85d6e3f437a8f3abc1f7a860'}, 'epoch_entry_argv': {'bytes': 1082, 'sha256': '076d5409072ef3d278a18b7de016a403403b8b32fcac24a3da171f45bb7e89a9'}, 'epoch_render_close_program': {'bytes': 5450, 'sha256': '0db5f902376686311b19507846893f235e8c100bd48609dc39f70f4e43788139'}}
def _eca_render_close_program(coordinator_raw, plan_raw, closure_plan_raw, *,
binding, base, bootstrap, budget_check):
 """Use only the already admitted current prepare member; never import one."""
 _eca_need(callable(budget_check), 'the same complete action budget is required')
 budget_check()
 module = sys.modules.get('prepare_component')
 sources = globals().get('__reviewed_package_sources__')
 manifest = globals().get('__reviewed_package_manifest_raw__')
 context = globals().get('__actual_context__')
 _eca_need(module is not None and context in ('phone', 'mac', 'p4')
 and type(sources) is dict and len(sources) == 32 and type(manifest) is bytes
 and getattr(module, '__actual_context__', None) == context
 and getattr(module, '__reviewed_package_manifest_raw__', None) == manifest
 and getattr(module, '__reviewed_package_sources__', None) is sources
 and getattr(module, '__reviewed_source_sha256__', None)
 == _eca_sha(sources['source/prepare_component.py']),
 'the exact current prepare renderer is not already admitted in this context')
 function = getattr(module, 'epoch_render_verified_close_program', None)
 _eca_need(callable(function), 'the source-bound pure close renderer is missing')
 value = function(coordinator_raw, plan_raw, closure_plan_raw, binding=binding,
 base=base, bootstrap=bootstrap, budget_check=budget_check)
 budget_check()
 return value
def _eca_sha(raw):
 return hashlib.sha256(raw).hexdigest()
def _eca_bare_pin(value):
 _eca_exact(value,{'bytes','sha256'},'reviewed whole template pin required')
 _eca_need(type(value['bytes']) is int and 0 < value['bytes']<=131072
 and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),
 'reviewed whole source template bound differs')
 return value
def _eca_source_node(raw,node):
 return b''.join(raw.splitlines(keepends=True)[node.lineno-1:node.end_lineno])
def _eca_literal(tree,name):
 nodes=[node for node in tree.body if isinstance(node,ast.Assign)
 and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
 and node.targets[0].id==name]
 _eca_need(len(nodes)==1,'one reviewed literal assignment is required: ' + name)
 return nodes[0].value
def _eca_inverse_source_slot(raw,slot,expected,template):
 """Only the source-defined single literal RHS may differ; never execute it."""
 _eca_bare_pin(template)
 _eca_need(type(raw) is bytes and 0 < len(raw)<=131072,
 'actual complete source must fit its unchanged executable member limit')
 tree=ast.parse(raw)
 node=_eca_literal(tree,slot)
 _eca_need(_eca_same(ast.literal_eval(node),expected),
 'source literal differs from independently derived actual values: ' + slot)
 lines=raw.splitlines(keepends=True)
 start=sum(map(len,lines[:node.lineno-1])) + node.col_offset
 end=sum(map(len,lines[:node.end_lineno-1])) + node.end_col_offset
 parent=raw[:start] + b'None' + raw[end:]
 _eca_need(_eca_same(_eca_bare(parent),template),
 'source changes bytes outside its one reviewed literal slot')
 return tree
def _eca_renderer_source_contract(bindings,expected):
 layout,sources,producer=bindings
 _eca_exact(layout,{'schema','epoch_id','registry_root'},'fixed authority layout binding required')
 _eca_need(layout['schema']=='hepta.native-guard.epoch-closure-authority-layout.v1'
 and layout['epoch_id']==expected['epoch_id']=='legacy902-active01'
 and _eca_path(layout['registry_root'])==expected['registry_root'],
 'authority packet is outside the source-fixed epoch registry')
 _eca_exact(sources,{'schema','root_template','bridge_template','root_reference'},
 'exact independently reviewed Root3 templates are required')
 _eca_need(sources['schema']=='hepta.native-guard.epoch-closure-source-authority.v1',
 'closure source binding schema differs')
 for name in ('root_template','bridge_template','root_reference'):
  _eca_bare_pin(sources[name])
 _eca_need(_eca_same(sources['root_reference'],{
 'bytes':126796,'sha256':'74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}),
 'actual unchanged policy verifier reference differs')
 _eca_exact(producer,{'schema','close_render_functions'},'fixed actual close renderer recipe required')
 _eca_need(producer['schema']=='hepta.native-guard.epoch-close-producer-recipe.v1'
 and _eca_same(producer['close_render_functions'],_ECA_CLOSE_RENDER_FUNCTIONS),
 'a changed producer function requires a separately reviewed renderer increment')
 return sources
def _eca_derived_root_binding(expected,runtime_raw,generation,sources):
 manifest=_eca_strict(runtime_raw)
 shared=_eca_pin(manifest.get('epoch_shared_materials'))
 for name in ('runtime','combination','pure_verifier','derivation'):
  _eca_pin(generation[name])
 _eca_need(_eca_same(_eca_bare(runtime_raw),
 {key:generation['runtime'][key] for key in ('bytes','sha256')}),
 'the independently catalogued complete runtime changed')
 return {'schema':'hepta.native-guard.epoch-root-source-binding.v1',
 'runtime':generation['runtime'],'combination':generation['combination'],
 'shared_materials':shared,'pure_verifier':generation['pure_verifier'],
 'source_derivation':generation['derivation'],
 'generation':{key:expected['generation'][key] for key in ('path','bytes','sha256')},
 'root_plan_schema':'hepta.native-guard.epoch-root-plan.v1',
 'root_template_slots':['EPOCH_ROOT_BINDING'],'template':sources['root_template']}
def _eca_root_source_constants(tree,raw):
 base=_eca_literal(tree,'B')
 _eca_need(isinstance(base,ast.Call) and isinstance(base.func,ast.Name)
 and base.func.id=='Path' and len(base.args)==1 and not base.keywords,
 'reviewed Root base must remain its one literal Path constructor')
 base=_eca_path(ast.literal_eval(base.args[0]))
 ssh=ast.literal_eval(_eca_literal(tree,'SSH'))
 bootstrap=ast.literal_eval(_eca_literal(tree,'EPOCH_ENTRY_BOOTSTRAP'))
 limit_node=_eca_literal(tree,'HOST_OUTPUT_LIMIT')
 _eca_need(ast.dump(limit_node,include_attributes=False)
 ==ast.dump(ast.parse('64*1024*1024',mode='eval').body,include_attributes=False),
 'the original fixed host-output expression changed')
 limit=64*1024*1024
 _eca_need(type(ssh) is list and ssh and all(type(v) is str and '\0' not in v for v in ssh)
 and type(bootstrap) is str and 0 < len(bootstrap.encode()) < 65536
 and type(limit) is int and limit==64*1024*1024,
 'actual Root SSH/bootstrap or original output allowance changed')
 functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
 for name,pin in _ECA_CLOSE_RENDER_FUNCTIONS.items():
  _eca_need(name in functions and _eca_same(_eca_bare(_eca_source_node(raw,functions[name])),pin),
  'whole actual producer function differs from reviewed recipe: ' + name)
 return {'base':PurePosixPath(base),'ssh':ssh,'bootstrap':bootstrap,'output_limit':limit}
def _eca_root3_originals(origins,bodies,plan,root_binding,sources):
 manifest=_eca_strict(bodies['root_source_manifest'])
 _eca_need(_eca_same(plan['source_package'],origins['root_source_manifest'])
 and manifest.get('schema')=='hepta.native-guard.root-chain-source-package.v1'
 and manifest.get('frozen_component_package_sha256')==root_binding['runtime']['sha256']
 and manifest.get('current_combination_sha256')==root_binding['combination']['sha256'],
 'actual Root manifest does not bind this runtime, combination and original plan')
 rows=manifest.get('files')
 _eca_need(type(rows) is list and len(rows)==3,'complete three-member Root source manifest required')
 names={'source/run_component_root_once.py':'root_coordinator_source',
 'source/phone_chain_bridge.py':'root_bridge_source',
 'reference/policy_native5_verifier.py':'root_verifier_source'}
 parent=str(PurePosixPath(origins['root_source_manifest']['path']).parent)
 seen=set()
 for row in rows:
  _eca_exact(row,{'path','bytes','sha256'},'complete actual Root member row required')
  _eca_need(type(row['path']) is str and row['path'] in names and row['path'] not in seen,
  'duplicate or undeclared Root source member')
  seen.add(row['path']); role=names[row['path']]
  _eca_need(_eca_same(origins[role],dict(row,path=parent + '/' + row['path']))
  and _eca_same(_eca_bare(bodies[role]),{key:row[key] for key in ('bytes','sha256')}),
  'actual Root source path or complete bytes differs from the retained manifest')
 _eca_need(seen==set(names)
 and _eca_same(_eca_bare(bodies['root_verifier_source']),sources['root_reference']),
 'actual Root3 source closure or unchanged reference differs')
 return _eca_inverse_source_slot(bodies['root_coordinator_source'],
 'EPOCH_ROOT_BINDING',root_binding,sources['root_template'])
def _eca_actual_identity_links(plan,expected,root_binding):
 identity=expected['identity_value']; epoch=expected['epoch_binding']
 _eca_exact(epoch,{'schema','epoch_id','anchor','initialization','ordinal',
 'reservation','identity','generation'},'actual epoch lease binding must be complete')
 _eca_need(type(identity) is dict and identity.get('schema')=='hepta.native-guard.epoch-identity.v1'
 and _eca_same(_eca_bare(_eca_encoded(identity)),
 {key:expected['identity'][key] for key in ('bytes','sha256')})
 and _eca_same(epoch,plan.get('epoch'))
 and epoch['schema']=='hepta.native-guard.epoch-lease-binding.v1'
 and epoch['epoch_id']==expected['epoch_id'] and type(epoch['ordinal']) is int
 and epoch['ordinal']==expected['ordinal']==identity['ordinal']
 and _eca_same(epoch['identity'],expected['identity'])
 and _eca_same(epoch['generation'],expected['generation'])
 and _eca_same(epoch['reservation'],identity['reservation'])
 and _eca_same(epoch['generation'],identity['source_generation']),
 'Root plan is not linked to the actual allocated phone IDENTITY and lease')
 for name in ('anchor','initialization','reservation','identity','generation'):
  _eca_pin(epoch[name],phone=True)
 for key in ('label','nonce','case_id','boot_id'):
  _eca_need(type(identity[key]) is str and plan.get(key)==identity[key],
  'Root plan changed an actual allocated identity field: ' + key)
 _eca_need(plan['nonce']==expected['nonce']
 and plan.get('session_id')==identity['selected_session_id']
 and plan.get('profile_id')==identity['selected_profile_id']
 and _eca_same({key:_eca_pin(plan['request'])[key] for key in ('bytes','sha256')},
 {key:identity['owner_request'][key] for key in ('bytes','sha256')})
 and _eca_same(plan['package'],root_binding['runtime'])
 and _eca_same(plan['combination'],root_binding['combination'])
 and _eca_same(plan['shared_materials'],root_binding['shared_materials']),
 'Root plan owner/source/selected scope differs from independently verified originals')
def _eca_verify_actual_epoch_bridge_source(raw,origin,root_binding,sources,*,budget_check):
 """Verify the one real bridge slot against independently derived current sources."""
 _eca_need(callable(budget_check), 'the enclosing action clock is mandatory')
 budget_check()
 _eca_pin(origin)
 _eca_need(type(raw) is bytes and _eca_same(_eca_bare(raw),
 {key:origin[key] for key in ('bytes','sha256')}),
 'the entire actual bridge original differs from its Root3 member')
 _eca_exact(root_binding, {'schema','runtime','combination','shared_materials',
 'pure_verifier','source_derivation','generation','root_plan_schema',
 'root_template_slots','template'}, 'complete independently derived Root binding required')
 _eca_need(root_binding['schema']=='hepta.native-guard.epoch-root-source-binding.v1'
 and root_binding['root_plan_schema']=='hepta.native-guard.epoch-root-plan.v1'
 and _eca_same(root_binding['root_template_slots'],['EPOCH_ROOT_BINDING']),
 'the bridge must use the current exact epoch Root protocol')
 template=_eca_bare_pin(sources['bridge_template'])
 binding={'schema':'hepta.native-guard.epoch-bridge-source-binding.v1',
 'bridge_template_slots':['EPOCH_BRIDGE_BINDING'],'template':template}
 for name in ('runtime','combination','shared_materials','pure_verifier',
 'source_derivation','generation'):
  value=_eca_pin(root_binding[name])
  _eca_need(value['bytes']>0,'an actual source or catalog cannot be empty')
  binding[name]=_eca_strict(_eca_encoded(value))
 _eca_inverse_source_slot(raw,'EPOCH_BRIDGE_BINDING',binding,template)
 budget_check()
 return {'schema':'hepta.native-guard.epoch-bridge-source-verification.v1',
 'actual_original':_eca_strict(_eca_encoded(origin)),
 'unbound_template':_eca_strict(_eca_encoded(template)),
 'only_changed_literal':'EPOCH_BRIDGE_BINDING',
 'source_binding':binding,'physical_file_authority_inferred_here':False,
 'bridge_entry_executed_here':False}
def _eca_render_actual_source_bound_actions(origins,bodies,*,expected,runtime_raw,
runtime_sources,generation,bindings,budget_check):
 budget_check()
 sources=_eca_renderer_source_contract(bindings,expected)
 binding=_eca_derived_root_binding(expected,runtime_raw,generation,sources)
 _eca_need(len(bodies['root_plan'])<=262144 and len(bodies['closure_plan'])<=262144,
 'actual Root and closer plan originals must fit their original read bounds')
 plan=_eca_strict(bodies['root_plan'])
 _eca_need(type(plan) is dict and bodies['root_plan']==_eca_encoded(plan,pretty=True)
 and plan.get('schema')==binding['root_plan_schema']
 and origins['root_plan']['path']==_eca_path(plan['out']) + '/ROOT-PLAN.original.json',
 'the complete actual Root-retained plan and original encoding are required')
 _eca_actual_identity_links(plan,expected,binding)
 tree=_eca_root3_originals(origins,bodies,plan,binding,sources)
 constants=_eca_root_source_constants(tree,bodies['root_coordinator_source'])
 _eca_verify_actual_epoch_bridge_source(bodies['root_bridge_source'],
 origins['root_bridge_source'],binding,sources,budget_check=budget_check)
 budget_check()
 rendered=_eca_render_close_program(bodies['root_coordinator_source'],bodies['root_plan'],
 bodies['closure_plan'],binding=binding,base=constants['base'],
 bootstrap=constants['bootstrap'],budget_check=budget_check)
 package=rendered['p4_root'] + '/material/tree/package'
 _eca_need(origins['runtime_manifest']['path']==package + '/MANIFEST.json'
 and origins['closer_source']['path']==package + '/source/close_component.py',
 'executed current runtime and closer must retain their actual P4 source paths')
 rows={}
 for role in ('p4_intent','p4_child','p4_result','p4_output_capture','p4_stdout',
 'p4_stderr','closure_plan','closure_result','closed_original','inventory_original'):
  _eca_need(_eca_same(_eca_bare(bodies[role]),
  {k:origins[role][k] for k in ('bytes','sha256')}),
  'the descriptor stdout cannot replace the complete separately retained original body')
  rows[role]={'origin':origins[role]}
 rows['p4_joined']=dict(rows['p4_result'])
 value={'schema':'hepta.native-guard.epoch-owned-host-closure-output.v2',
 'state':'ORIGINAL_INNER_CLOSER_JOINED_AND_OUTPUTS_RETAINED',
 'root_plan_sha256':_eca_sha(_eca_encoded(plan,pretty=True)),'inner_stdin':None,
 'originals':rows,'phone_calls':0,'signals_sent':0,'automatic_retry':False}
 outer_raw=_eca_encoded(value,pretty=True)
 _eca_need(len(outer_raw)<=65536,
 'complete descriptor-only stdout exceeds the actual producer write bound')
 budget_check()
 return {'mac':{'phase':rendered['phase'],'directory':rendered['mac_directory'],
 'argv':constants['ssh'],'stdin':rendered['code'].encode(),
 'wait_seconds':rendered['mac_wait_seconds'],
 'output_limit_bytes_per_stream':constants['output_limit']},
 'p4':{'phase':rendered['phase'],'directory':rendered['p4_directory'],
 'argv':rendered['p4_argv'],'stdin':None,'wait_seconds':rendered['p4_wait_seconds'],
 'output_limit_bytes_per_stream':rendered['p4_output_limit_bytes_per_stream']},
 'closure_plan':_eca_strict(bodies['closure_plan']),
 'closure_plan_path':rendered['closure_plan_path'],'closure_out':rendered['closure_out'],
 'mac_stdout':outer_raw,'verified_source_descriptors':[origins[key] for key in
 ('root_source_manifest','root_coordinator_source','root_bridge_source',
 'root_verifier_source','runtime_manifest','closer_source')]}
def _eca_closer_outputs(origins,bodies,rendered, *, closure_raw,inventory_raw,capture_raw):
 closed=_eca_strict(closure_raw);plan=_eca_strict(bodies['closure_plan'])
 _eca_need(_eca_same(plan,rendered['closure_plan'])
 and origins['closure_plan']['path']==rendered['closure_plan_path'],
 'actual closure plan differs from its fixed Root input renderer')
 out=_eca_path(rendered['closure_out'])
 for role,name in (('closed_original','CLOSURE.original.json'),
 ('inventory_original','AFTER-INVENTORY.original.json'),
 ('closure_result','RESULT.json')):
  _eca_need(origins[role]['path']==out+'/'+name,'actual closer output escaped its fixed directory')
 _eca_need(bodies['closed_original']==closure_raw and bodies['inventory_original']==inventory_raw
 and _eca_same(closed['capture'],_eca_bare(capture_raw))
 and _eca_same(closed['archive'],plan['archive'])
 and _eca_same(closed['root_fixture_attempts'],plan['root_fixture_attempts'])
 and closed['closure_source_sha256']==_eca_bare(bodies['closer_source'])['sha256'],
 'actual closed bytes, capture/archive/fixture inputs or executing closer source differ')
 for pin in (origins['closure_plan'],plan['archive'],plan['package'],plan['request'],
 plan['previous'],plan['preserved_draft'],plan['sender_host_result'],
 plan['sender_local_once'],plan['sender_actor']):
  _eca_pin(pin);row=closed['original_host_inputs'].get(pin['path'])
  _eca_exact(row,{'bytes','sha256','metadata'},'actual host closer omitted a mandatory original input')
  m=row['metadata']
  _eca_need(_eca_same({k:row[k] for k in ('bytes','sha256')},
  {k:pin[k] for k in ('bytes','sha256')})
  and type(m) is list and len(m)==9 and all(type(v) is int and v>=0 for v in m)
  and stat.S_ISREG(m[2]) and m[5]==1 and m[6]==pin['bytes'],
  'actual host closer input size, digest or host file identity differs')
 keys=('state','closed','component_qualified','business_qualified','native_status',
 'actual_native_calls','unknown_effects','phone_calls','boundary_published_here')
 summary={k:closed[k] for k in keys};summary['closure']=_eca_bare(closure_raw)
 serialized=_eca_encoded(summary)
 _eca_need(bodies['closure_result']==serialized and bodies['p4_stdout']==serialized
 and bodies['p4_stderr']==b'',
 'actual inner joined output is not the complete original closer RESULT and closure hash')
 _eca_need(bodies['mac_stdout']==rendered['mac_stdout']
 and bodies['mac_stderr']==b'',
 'outer actual joined output does not retain the reviewed complete inner action envelope')
 return summary
def verify_epoch_closure_authority(packet_pin, *, expected, original_from,directory_from,
runtime_raw,runtime_sources,generation,closure_raw,inventory_raw,capture_raw,budget_check):
 """Authenticate one actual deep host audit without pretending to redo it."""
 _eca_need(callable(budget_check),'the original complete-operation budget is mandatory')
 budget_check();bindings=_eca_final_bindings()
 _eca_exact(expected,{'epoch_id','ordinal','nonce','identity','generation','registry_root',
 'identity_value','epoch_binding'},
 'source-authorized allocated record identity required')
 _eca_need(type(expected['ordinal']) is int and 1<=expected['ordinal']<=8,
 'bounded actual reservation ordinal required')
 pool=_ECAOriginals(original_from,budget_check)
 packet,origins,bodies=_eca_packet(packet_pin,pool,expected=expected,directory_from=directory_from)
 _eca_runtime_sources(origins,bodies,runtime_raw=runtime_raw,
 runtime_sources=runtime_sources,generation=generation)
 rendered=_eca_render_actual_source_bound_actions(origins,bodies,expected=expected,
 runtime_raw=runtime_raw,runtime_sources=runtime_sources,generation=generation,
 bindings=bindings,budget_check=budget_check)
 _eca_exact(rendered,{'mac','p4','closure_plan','closure_plan_path','closure_out','mac_stdout',
 'verified_source_descriptors'},'complete reviewed producer rendering required')
 actions={}
 for layer in ('mac','p4'):
  budget_check();local_origins={};local_raw={}
  for short in ('intent','stdin','child','result','joined','output_capture','stdout','stderr'):
   key=layer+'_'+short
   local_origins['host_'+short]=None if key=='p4_stdin' else origins[key]
   local_raw['host_'+short]=None if key=='p4_stdin' else bodies[key]
  actions[layer]=_eca_verify_owned_capture(local_origins,local_raw,rendered[layer])
  budget_check()
 summary=_eca_closer_outputs(origins,bodies,rendered,closure_raw=closure_raw,
 inventory_raw=inventory_raw,capture_raw=capture_raw)
 budget_check()
 return {'schema':'hepta.native-guard.epoch-closure-action-verification.v1',
 'state':'SOURCE_BOUND_ORIGINAL_HOST_CLOSURE_AND_OUTPUTS_VERIFIED',
 'packet':packet_pin,'epoch_id':expected['epoch_id'],'ordinal':expected['ordinal'],
 'closure':_eca_bare(closure_raw),'inventory':_eca_bare(inventory_raw),
 'capture':_eca_bare(capture_raw),'actual_closer_summary':summary,
 'actions':actions,'used_carrier_descriptors':pool.descriptors(),
 'verified_source_descriptors':rendered['verified_source_descriptors'],
 'host_deep_closure_execution_verified':True,
 'host_archive_read_by_phone_or_consumer':False,
 'host_metadata_relabelled_as_phone_metadata':False,
 'host_pid_start_ticks_recorded':False,'remote_cleanup_inferred_from_capture':False,
 'component_qualified_here':False,'boundary_published_here':False}
def _eca_verify_owned_capture(action, raw, expected):
 """Verify the actual synchronous transport result; no phone success here."""
 _eca_exact(expected, {'phase','directory','argv','stdin','wait_seconds','output_limit_bytes_per_stream'},
 'exact reviewed owned-producer expectation required')
 _eca_need(type(expected['phase']) is str
 and re.fullmatch('[a-z0-9-]{1,55}',expected['phase']) is not None
 and type(expected['argv']) is list and expected['argv']
 and all(type(v) is str and '\0' not in v for v in expected['argv'])
 and type(expected['output_limit_bytes_per_stream']) is int
 and 0<expected['output_limit_bytes_per_stream']<=64*1024*1024
 and _eca_number(expected['wait_seconds'],'owned wait is not finite')>0,
 'reviewed actual argv, phase or existing stream limit differs')
 phase = expected['phase']; directory = _eca_path(expected['directory'])
 names = {'host_intent': 'INTENT.json', 'host_stdin': 'stdin.original', 'host_child': 'CHILD.json',
 'host_result': 'RESULT.json', 'host_joined': 'RESULT.json',
 'host_output_capture': 'OUTPUT-CAPTURE.json', 'host_stdout': 'stdout.original',
 'host_stderr': 'stderr.original'}
 _eca_exact(action,names,'complete actual owned original roles required')
 _eca_exact(raw,names,'complete owned body roles required')
 for role, name in names.items():
  if role=='host_stdin' and expected['stdin'] is None:
   _eca_need(action[role] is None and raw[role] is None,
   'source-defined DEVNULL must not manufacture a stdin original')
   continue
  _eca_pin(action[role])
  _eca_need(action[role]['path'] == directory + '/' + name
  and _eca_same(_eca_bare(raw[role]),{k:action[role][k] for k in ('bytes','sha256')}),
  'actual owned original path or whole bytes differ: '+role)
 _eca_need((expected['stdin'] is None or type(expected['stdin']) is bytes)
 and raw['host_stdin']==expected['stdin'],
 'actual retained stdin differs from the reviewed byte renderer')
 intent = _eca_strict(raw['host_intent']); child = _eca_strict(raw['host_child'])
 result = _eca_strict(raw['host_result']); capture = _eca_strict(raw['host_output_capture'])
 expected_intent = {'schema': 'hepta.native-guard.root-host-command.v1', 'phase': phase,
 'argv': expected['argv'], 'stdin_sha256': None if expected['stdin'] is None else _eca_bare(raw['host_stdin'])['sha256'],
 'maximum_starts': 1, 'maximum_wait_seconds': expected['wait_seconds'],
 'automatic_retry': False, 'signals_on_timeout': False,
 'deadline_scope': 'popen_start_through_child_join_pipe_eof_and_output_verification',
 'input_transport': 'retained_readonly_regular_fd_child_reads_within_execution_budget',
 'output_transport': 'owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence',
 'output_limit_bytes_per_stream': expected['output_limit_bytes_per_stream'],
 'hard_bound_on_filesystem_spawn_or_cleanup': False}
 _eca_need(_eca_same(intent, expected_intent) and raw['host_intent'] == _eca_encoded(intent, pretty=True),
 'actual intent is not the single fixed source/phase/stdin dispatch')
 _eca_exact(child, ('pid', 'pgid', 'sid', 'source_intent_sha256', 'maximum_starts',
 'execution_deadline_monotonic', 'deadline_validity', 'original_output_identities',
 'identity_missing_only_if_actual_child_already_joined'), 'actual owned child fields differ')
 pid = child['pid']; digest = _eca_bare(raw['host_intent'])['sha256']
 _eca_need(type(pid) is int and pid > 0 and type(child['maximum_starts']) is int
 and child['maximum_starts'] == 1 and child['source_intent_sha256'] == digest
 and child['deadline_validity'] == 'this_running_coordinator_only', 'owned child intent binding differs')
 missing = child['identity_missing_only_if_actual_child_already_joined']
 _eca_need(type(missing) is bool and ((missing is True and child['pgid'] is child['sid'] is None)
 or (missing is False and type(child['pgid']) is int and type(child['sid']) is int
 and child['pgid'] == child['sid'] == pid)), 'actual child session identity differs')
 deadline = _eca_number(child['execution_deadline_monotonic'], 'owned child deadline is not finite')
 start = deadline - expected['wait_seconds']
 _eca_need(start >= 0, 'owned child execution window differs')
 _eca_exact(result, ('state', 'phase', 'pid', 'returncode', 'stdout', 'stderr', 'automatic_retry'),
 'actual synchronous RESULT must retain its original exact seven fields')
 _eca_need(result['state'] == 'ORIGINAL_HOST_CHILD_JOINED' and result['phase'] == phase
 and type(result['pid']) is int and result['pid'] == pid
 and type(result['returncode']) is int and result['returncode'] == 0
 and result['automatic_retry'] is False, 'host child was not actually joined with return code zero')
 _eca_need(raw['host_joined'] == raw['host_result']
 and _eca_same(action['host_joined'], action['host_result']), 'joined semantic alias differs')
 fields = ('schema', 'phase', 'pid', 'source_intent_sha256', 'output_limit_bytes_per_stream',
 'worker_started', 'worker_joined', 'pipe_reader_owner', 'child_wait_returned',
 'child_returncode', 'child_join_observed_monotonic', 'execution_deadline_monotonic',
 'deadline_validity', 'stdout_eof', 'stderr_eof', 'eof_observed_monotonic',
 'prefix_only_or_unknown', 'captured', 'files', 'error', 'persist_errors',
 'pipe_close_errors', 'automatic_retry', 'signals_sent', 'remote_terminal_or_cleanup_proven')
 _eca_exact(capture, fields, 'actual OUTPUT-CAPTURE sidecar fields differ')
 _eca_need(capture['schema'] == 'hepta.native-guard.host-output-capture.v1'
 and capture['phase'] == phase and type(capture['pid']) is int and capture['pid'] == pid
 and capture['source_intent_sha256'] == digest
 and type(capture['output_limit_bytes_per_stream']) is int
 and capture['output_limit_bytes_per_stream'] == expected['output_limit_bytes_per_stream']
 and capture['deadline_validity'] == child['deadline_validity']
 and _eca_same(capture['execution_deadline_monotonic'], deadline), 'capture source or deadline differs')
 for key in ('worker_started', 'worker_joined', 'child_wait_returned', 'stdout_eof', 'stderr_eof'):
  _eca_need(capture[key] is True, 'actual child/worker/pipe completion missing: ' + key)
 _eca_need(capture['pipe_reader_owner'] == 'closed_by_worker'
 and type(capture['child_returncode']) is int and capture['child_returncode'] == 0
 and capture['prefix_only_or_unknown'] is False and capture['error'] is None
 and capture['persist_errors'] == [] and capture['pipe_close_errors'] == []
 and capture['automatic_retry'] is False and type(capture['signals_sent']) is int
 and capture['signals_sent'] == 0 and capture['remote_terminal_or_cleanup_proven'] is False,
 'capture remains partial, unjoined, errored or incorrectly claims remote cleanup')
 joined_at = _eca_number(capture['child_join_observed_monotonic'], 'actual wait-return timestamp missing')
 _eca_need(start <= joined_at <= deadline, 'child join is outside the same original deadline')
 for key in ('captured', 'files', 'eof_observed_monotonic'):
  _eca_exact(capture[key], ('stdout', 'stderr'), 'both actual output streams required')
 _eca_exact(child['original_output_identities'], ('stdout', 'stderr'), 'both original created outputs required')
 output_identities = []
 for stream in ('stdout', 'stderr'):
  observed = _eca_number(capture['eof_observed_monotonic'][stream], 'actual pipe EOF timestamp missing')
  _eca_need(start <= observed <= deadline, 'pipe EOF is outside the same original deadline')
  bare = _eca_bare(raw['host_' + stream]); descriptor = action['host_' + stream]
  _eca_need(_eca_same(result[stream], descriptor) and _eca_same(capture['captured'][stream], bare)
  and _eca_same({key: descriptor[key] for key in ('bytes', 'sha256')}, bare),
  'result/capture actual complete stream bytes differ')
  proof = capture['files'][stream]
  _eca_exact(proof, ('path', 'bytes', 'sha256', 'metadata', 'original_created_inode_bound'),
  'held original output proof differs')
  _eca_need(_eca_same({key: proof[key] for key in ('path', 'bytes', 'sha256')}, descriptor)
  and proof['original_created_inode_bound'] is True, 'output path is not bound to its created inode')
  first = _eca_metadata(child['original_output_identities'][stream], size=0)
  final = _eca_metadata(proof['metadata'], size=bare['bytes'])
  _eca_need(all(first[key] == final[key] for key in _ECA_META[:6]), 'original output inode/owner/type was replaced')
  output_identities.append((final['st_dev'], final['st_ino']))
 _eca_need(len(set(output_identities)) == 2, 'stdout and stderr share one file identity')
 _eca_need(raw['host_stderr'] == b'', 'unexpected original host stderr in fixed publication reader')
 return {'phase': phase, 'pid': pid, 'pgid': child['pgid'], 'sid': child['sid'],
 'source_intent_sha256': digest, 'original_deadline': deadline,
 'child_join_observed_monotonic': joined_at,
 'eof_observed_monotonic': capture['eof_observed_monotonic'],
 'joined_role_is_result_alias': True, 'complete_original_streams_verified': True,
 'remote_cleanup_inferred_from_host_capture': False,
 'host_pid_start_ticks_recorded': False}
"""Pure source/action verification for the explicit publication carrier v2.

All bytes come from the caller's declared, precharged original_from pool.
This module does not read files, import a target module, execute a producer,
or authorize an operation. Final source and actual-producer bindings are
intentionally absent. No public successful verification is possible yet.
"""
import ast
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import shlex
import stat
FINAL_PUBLICATION_TEMPLATES = None
FINAL_PUBLICATION_PRODUCER = None
_PA_SOURCE_ROLES = ('root_source_manifest', 'root_coordinator', 'root_bridge',
'root_reference', 'actor', 'sdk')
_PA_ACTION_ROLES = ('root_plan', 'root_source_manifest', 'host_intent', 'host_stdin',
'host_child', 'host_result', 'host_joined', 'host_output_capture',
'host_stdout', 'host_stderr', 'phone_wrapper')
_PA_ROOT_ROWS = {'root_coordinator': 'source/run_component_root_once.py',
'root_bridge': 'source/phone_chain_bridge.py',
'root_reference': 'reference/policy_native5_verifier.py'}
_PA_POOL_LIMIT = 32 * 1024 * 1024
_PA_HOST_OUTPUT_LIMIT = 64 * 1024 * 1024
def _pa_need(value, message):
 if not value:
  raise ValueError(message)
def _pa_encoded(value, *, pretty=False):
 options = {'ensure_ascii': False, 'sort_keys': True, 'allow_nan': False}
 options.update({'indent': 2} if pretty else {'separators': (',', ':')})
 return (json.dumps(value, **options) + '\n').encode('utf-8')
def _pa_same(left, right):
 return _pa_encoded(left) == _pa_encoded(right)
def _pa_strict(raw):
 _pa_need(type(raw) is bytes, 'original JSON must be complete bytes')
 def pairs(rows):
  value = {}
  for key, item in rows:
   _pa_need(key not in value, 'duplicate JSON key')
   value[key] = item
  return value
 def constant(value):
  raise ValueError('non-finite JSON number: ' + value)
 return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
def _pa_exact(value, keys, message):
 _pa_need(type(value) is dict and set(value) == set(keys), message)
def _pa_path(value):
 _pa_need(type(value) is str and value.startswith('/') and not value.startswith('//')
 and '\x00' not in value and len(value.encode('utf-8')) <= 4096
 and str(PurePosixPath(value)) == value
 and '..' not in PurePosixPath(value).parts, 'canonical absolute original path required')
 return value
def _pa_hash(value):
 _pa_need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
 'exact lowercase SHA256 required')
 return value
def _pa_bare(raw):
 _pa_need(type(raw) is bytes, 'complete original bytes required')
 return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
def _pa_pin(value, *, phone=False):
 _pa_exact(value, ('path', 'bytes', 'sha256', 'metadata') if phone else
 ('path', 'bytes', 'sha256'), 'exact original descriptor required')
 _pa_path(value['path']); _pa_hash(value['sha256'])
 _pa_need(type(value['bytes']) is int and 0 <= value['bytes'] <= _PA_POOL_LIMIT,
 'original byte count must fit the enclosing original pool')
 if phone:
  m = value['metadata']
  _pa_need(type(m) is list and len(m) == 9 and all(type(x) is int for x in m)
  and m[6] == value['bytes'], 'actual phone full9 required')
 return value
def _pa_number(value, message):
 _pa_need(type(value) in (int, float) and math.isfinite(value) and value >= 0, message)
 return value
def _pa_source_bindings(source_authority):
 """Enumerate a consumer-literal closure; this does not authenticate code."""
 _pa_need(source_authority is not None and FINAL_PUBLICATION_TEMPLATES is not None
 and FINAL_PUBLICATION_PRODUCER is not None,
 'final publication templates, producer and external source authority are not bound')
 _pa_exact(source_authority,_PA_SOURCE_ROLES,'fixed external publication source roles differ')
 templates=FINAL_PUBLICATION_TEMPLATES
 _pa_exact(templates,('schema','root_template','bridge_template','root_reference','actor','sdk'),
 'reviewed unbound templates and independent dependencies required')
 _pa_need(templates['schema']=='hepta.native-guard.epoch-publication-source-templates.v1',
 'publication source template schema differs')
 for name in ('root_template','bridge_template','root_reference','actor','sdk'):
  _eca_bare_pin(templates[name])
 _pa_need(_pa_same(templates['root_reference'],{'bytes':126796,
 'sha256':'74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}),
 'unchanged original policy reference differs')
 values=[]
 for role in _PA_SOURCE_ROLES:
  pin=_pa_pin(source_authority[role]); values.append(pin)
  _pa_need(0 < pin['bytes']<=(262144 if role=='root_source_manifest' else 131072),
  'whole source original exceeds its fixed source limit')
  if role in ('root_reference','actor','sdk'):
   _pa_need(_pa_same({k:pin[k] for k in ('bytes','sha256')},templates[role]),
   'external source authority changed an independent fixed dependency: ' + role)
 _pa_need(len({row['path'] for row in values})==6,'trusted source paths repeat')
 return _pa_strict(_pa_encoded(source_authority))
def publication_action_needed_source_descriptors(*,source_authority):
 """Pure complete enumeration only; a typed map cannot grant action authority."""
 sources=_pa_source_bindings(source_authority)
 return _pa_strict(_pa_encoded(sorted(sources.values(),key=lambda row:row['path'])))
class _PAOriginals:
 """A view of ONE enclosing pool; no filesystem or second budget exists."""
 def __init__(self, original_from, budget_check):
  _pa_need(callable(original_from) and callable(budget_check),
  'declared original lookup and enclosing budget callback required')
  self.original_from = original_from
  self.budget_check = budget_check
  self.used = {}
 def get(self, descriptor):
  self.budget_check(); _pa_pin(descriptor)
  path = descriptor['path']
  if path in self.used:
   previous, raw = self.used[path]
   _pa_need(_pa_same(previous, descriptor), 'one original path changes identity')
   return raw
  raw = self.original_from(descriptor)
  self.budget_check()
  _pa_need(type(raw) is bytes and _pa_same(_pa_bare(raw),
  {key: descriptor[key] for key in ('bytes', 'sha256')}),
  'declared original lookup returned different bytes')
  self.used[path] = (_pa_strict(_pa_encoded(descriptor)), raw)
  return raw
 def descriptors(self):
  return [self.used[path][0] for path in sorted(self.used)]
def _pa_packet_view(packet_original, parsed, originals):
 packet_raw = originals.get(packet_original); packet = _pa_strict(packet_raw)
 _pa_exact(packet, ('schema', 'epoch_id', 'boot_id', 'publication_observation',
 'manifest', 'carriers', 'source_action_originals'), 'publication packet fields differ')
 _pa_need(packet['schema'] == 'hepta.native-guard.epoch-publication-inputs.v2'
 and packet['epoch_id'] == 'legacy902-active01' and _pa_encoded(packet) == packet_raw,
 'canonical publication v2 packet required')
 _pa_exact(parsed, ('manifest', 'originals_by_path', 'publication_observation',
 'source_action_originals', 'source_action_original_bytes',
 'action_verification_required', 'source_or_action_authority_verified_here'),
 'publication parser return contract differs')
 _pa_need(parsed['action_verification_required'] is True
 and parsed['source_or_action_authority_verified_here'] is False,
 'carrier parser cannot claim source or action authority')
 action = packet['source_action_originals']
 _pa_exact(action, _PA_ACTION_ROLES, 'all eleven actual action roles required')
 for role in _PA_ACTION_ROLES: _pa_pin(action[role])
 _pa_need(_pa_same(action['host_joined'], action['host_result']),
 'joined role must alias the same actual synchronous RESULT')
 _pa_need(len({action[role]['path'] for role in _PA_ACTION_ROLES if role != 'host_joined'}) == 10,
 'the other ten action roles must have distinct paths')
 _pa_need(_pa_same(action, parsed['source_action_originals']), 'parser action descriptors differ')
 _pa_exact(parsed['source_action_original_bytes'], _PA_ACTION_ROLES, 'parser action bytes differ')
 action_raw = {}
 for role in _PA_ACTION_ROLES:
  action_raw[role] = originals.get(action[role])
  _pa_need(type(parsed['source_action_original_bytes'][role]) is bytes
  and parsed['source_action_original_bytes'][role] == action_raw[role],
  'parser action bytes do not match actual original lookup')
 manifest_raw = originals.get(packet['manifest']); manifest = _pa_strict(manifest_raw)
 _pa_exact(manifest, ('schema', 'files', 'directories'), 'complete publication manifest required')
 _pa_need(manifest['schema'] == 'hepta.native-guard.epoch-capture-inputs.v1'
 and _pa_encoded(manifest) == manifest_raw and _pa_same(manifest, parsed['manifest'])
 and type(manifest['files']) is list and 1 <= len(manifest['files']) <= 8192
 and type(manifest['directories']) is list, 'actual canonical manifest differs')
 _pa_need(type(packet['carriers']) is list and len(packet['carriers']) == len(manifest['files'])
 and type(parsed['originals_by_path']) is dict, 'complete separate original carriers required')
 phone_paths = set(); carrier_paths = set()
 for row, declared in zip(packet['carriers'], manifest['files']):
  originals.budget_check()
  _pa_exact(row, ('original', 'carrier'), 'phone original and host carrier must stay separate')
  original = _pa_pin(row['original'], phone=True); carrier = _pa_pin(row['carrier'])
  _pa_need(_pa_same(original, declared) and original['path'] not in phone_paths
  and carrier['path'] not in carrier_paths
  and _pa_same({k: carrier[k] for k in ('bytes', 'sha256')},
  {k: original[k] for k in ('bytes', 'sha256')}),
  'carrier order, identity, complete bytes or uniqueness differs')
  raw = originals.get(carrier)
  _pa_need(type(parsed['originals_by_path'].get(original['path'])) is bytes
  and parsed['originals_by_path'][original['path']] == raw,
  'parser phone body is not the separate actual host carrier')
  phone_paths.add(original['path']); carrier_paths.add(carrier['path'])
 _pa_need(set(parsed['originals_by_path']) == phone_paths, 'hidden or omitted parsed phone original')
 observed_raw = originals.get(packet['publication_observation'])
 observed = _pa_strict(observed_raw)
 _pa_need(_pa_same(observed, parsed['publication_observation']), 'parser observation differs from original')
 _pa_exact(observed, ('schema', 'state', 'epoch_id', 'boot_id', 'manifest', 'generation', 'terminal',
 'initial_manifest_sha256', 'final_manifest_sha256', 'file_count', 'retained_bytes',
 'source_reader_binding', 'rechecked_files', 'rechecked_directories', 'effects'),
 'complete actual phone publication observation required')
 expected_counts = {'file_count': len(phone_paths),
 'retained_bytes': sum(row['bytes'] for row in manifest['files']),
 'rechecked_files': len(phone_paths),
 'rechecked_directories': len(manifest['directories'])}
 _pa_need(observed['schema'] == 'hepta.native-guard.epoch-publication-observation.v1'
 and observed['state'] == 'ACTUAL_COMPLETE_PUBLISHED_REGISTRY_READ'
 and observed['epoch_id'] == packet['epoch_id'] and observed['boot_id'] == packet['boot_id']
 and _pa_same(observed['manifest'], manifest)
 and observed['initial_manifest_sha256'] == observed['final_manifest_sha256']
 == packet['manifest']['sha256'], 'phone initial/final manifest linkage differs')
 for key, value in expected_counts.items():
  _pa_need(type(observed[key]) is int and observed[key] == value,
  'phone complete observation accounting differs: ' + key)
 for key in ('generation', 'terminal'):
  _pa_pin(observed[key], phone=True)
  _pa_need(any(_pa_same(observed[key], row) for row in manifest['files']),
  'phone generation or terminal is missing from complete carriers')
 _pa_exact(observed['source_reader_binding'], ('root_source_manifest', 'bridge_source', 'operation'),
 'actual Root source reader binding required')
 _pa_need(observed['source_reader_binding']['operation'] == 'epoch-publication-read'
 and _pa_same(observed['source_reader_binding']['root_source_manifest'], action['root_source_manifest']),
 'phone operation is not bound to the same Root source manifest')
 effects = {'ui_actions': 0, 'phone_native_dispatches': 0, 'model_requests': 0,
 'signals_sent': 0, 'source_original_writes': 0, 'nonces_generated': 0,
 'leases_created': 0, 'boundaries_published': 0,
 'component_qualified': False, 'business_qualified': False}
 _pa_need(_pa_same(observed['effects'], effects), 'publication observation effects differ')
 return packet, action_raw, manifest, observed, observed_raw
def _pa_verify_host_capture(plan, action, raw, expected):
 """Use the same original 0374 decoder with the publication-specific pins.

    The source-bound publication renderer still selects the action.  This
    wrapper neither accepts a supplied argv nor changes the original deadline.
    """
 out = _pa_path(plan['out'])
 _pa_need(action['root_plan']['path'] == out + '/ROOT-PLAN.original.json',
 'actual Root-retained plan is missing')
 names = ('host_intent', 'host_stdin', 'host_child', 'host_result',
 'host_joined', 'host_output_capture', 'host_stdout', 'host_stderr')
 authority = {name: action[name] for name in names}
 bodies = {name: raw[name] for name in names}
 fixed = {'phase': expected['phase'], 'directory': out + '/' + expected['phase'],
 'argv': expected['ssh_argv'], 'stdin': expected['host_stdin'],
 'wait_seconds': expected['host_wait_seconds'],
 'output_limit_bytes_per_stream': _PA_HOST_OUTPUT_LIMIT}
 return _eca_verify_owned_capture(authority, bodies, fixed)
def _pa_pub_host_pin(value, path, maximum):
 _pa_pin(value, phone=True)  
 m = value['metadata']
 _pa_need(value['path'] == path and value['bytes'] <= maximum
 and all(x >= 0 for x in m) and m[1] > 0
 and stat.S_ISREG(m[2]) and stat.S_IMODE(m[2]) == 0o600 and m[5] == 1,
 'actual private actor original path/full9 differs')
 return {key: value[key] for key in ('path', 'bytes', 'sha256')}
def _pa_publication_sdk_originals(wrapper, run, originals):
 """Eight actual bodies, not eight descriptions treated as read bodies."""
 rows = (('stdout_original', 'stdout.original', 65536),
 ('stderr_original', 'stderr.original', 65536),
 ('incoming_wire_original', 'incoming-shell-wire.original', 70657),
 ('smart_socket_response_original', 'smart-socket-responses.original', 65552))
 bodies = {}
 declared = []
 identities = set()
 for name, prefix in (('baseline_transport', 'baseline-'), ('transport', '')):
  record = wrapper[name]
  _pa_need(type(record) is dict, 'actual complete SDK record required')
  bodies[name] = {}
  for field, leaf, maximum in rows:
   originals.budget_check()
   pin = _pa_pub_host_pin(record[field], run + '/' + prefix + leaf, maximum)
   identity = tuple(record[field]['metadata'][:2])
   _pa_need(identity not in identities, 'distinct actor originals share an inode')
   identities.add(identity)
   bodies[name][field] = originals.get(pin)
   declared.append(pin)
 _pa_need(len({row['path'] for row in declared}) == 8, 'SDK original paths repeat')
 return bodies, sorted(declared, key=lambda row: row['path'])
def _pa_publication_exchange(record, raw, command, remaining, budget_check):
 """Recompute frames and accounting; EOF is still a pinned SDK observation."""
 budget_check()
 _pa_need(type(command) is str and '\0' not in command,
 'the exact source-rendered command is required')
 route = record.get('route')
 _pa_need(type(route) is list and len(route) == 2 and type(route[0]) is int
 and 0 < route[0] < 65536 and type(route[1]) is str
 and re.fullmatch('[1-9][0-9]*', route[1]) is not None,
 'original route identity differs')
 request_bytes = len(('shell,v2,raw:' + command).encode('utf-8'))
 transport_bytes = len(('host:transport-id:' + route[1]).encode('utf-8'))
 _pa_need(request_bytes < 65536 and transport_bytes < 65536
 and type(remaining) is int and request_bytes + 65536 <= remaining <= 8388608,
 'original command and remaining single transport pool differ')
 fixed = {'schema': 'hepta.phone-local.shell-stdin-transport.v1',
 'state': 'ORIGINAL_STDIN_AND_EXIT_STREAM_COMPLETE_RECEIVER_UNASSESSED',
 'phase': 'duplex-stdin-and-response', 'command': command,
 'stdin_original': _pa_bare(b''), 'rc': 0, 'failure': None,
 'command_wire_bytes': request_bytes, 'shared_payload_limit_bytes': remaining,
 'receiver_output_reservation_bytes': 65536,
 'stdin_payload_bytes_sent_to_socket': 0, 'stdin_complete_frame_payload_bytes': 0,
 'sent_frames': 1, 'input_protocol_bytes_sent': 5,
 'incomplete_incoming_frame_bytes': 0, 'partial_outgoing_frame_bytes_sent': 0,
 'smart_socket_failure_payload_bytes_received': 0,
 'new_explicit_process_signal_calls': 0,
 'incoming_wire_prefix_limit_bytes': 70658}
 for key in ('socket_acquisition_attempted', 'socket_acquired', 'socket_close_returned',
 'shell_service_request_attempted', 'shell_service_okay', 'close_stdin_frame_sent',
 'exit_frame_received', 'socket_eof_observed', 'transport_complete',
 'received_originals_complete', 'shared_payload_limit_satisfied',
 'transport_disconnect_may_trigger_adbd_SIGHUP',
 'existing_route_gate_is_not_preempted_by_this_function',
 'one_excess_byte_may_be_retained_to_prove_wire_overflow'):
  fixed[key] = True
 for key in ('exit_received_before_input_complete', 'automatic_retry',
 'remote_cleanup_proven', 'receiver_file_authority_verified_here',
 'hard_preemptive_IO_deadline_claimed'):
  fixed[key] = False
 dynamic = ('route', 'elapsed_seconds', 'carrier_accounting', 'received_frames',
 'stdout_payload_bytes_received', 'stderr_payload_bytes_received',
 'shared_payload_bytes_charged', 'smart_socket_request_bytes_sent',
 'incoming_wire_bytes_outside_complete_stdout_stderr_payload',
 'stdout_original', 'stderr_original', 'incoming_wire_original',
 'smart_socket_response_original')
 _pa_exact(record, set(fixed) | set(dynamic), 'exact complete SDK receipt fields differ')
 _pa_need(all(_pa_same(record[key], value) for key, value in fixed.items()),
 'partial/unknown SDK receipt cannot establish EXIT, EOF or complete stdin')
 _pa_need(_pa_number(record['elapsed_seconds'], 'SDK elapsed must be finite') <= 300,
 'SDK observation exceeds its fixed maximum')
 _pa_need(raw['smart_socket_response_original'] == b'OKAYOKAY'
 and not raw['stderr_original'], 'both smart services and empty error output are required')
 wire = raw['incoming_wire_original']
 _pa_need(0 < len(wire) <= 70657, 'complete bounded shell frame wire required')
 cursor = 0; count = 0; ended = False; output = {1: [], 2: []}; size = 0
 while cursor < len(wire):
  budget_check()
  _pa_need(not ended and cursor + 5 <= len(wire), 'partial header or bytes after EXIT')
  kind = wire[cursor]; length = int.from_bytes(wire[cursor+1:cursor+5], 'little')
  cursor += 5; count += 1
  _pa_need(kind in (1, 2, 3) and count <= 1024 and length <= 65536
  and cursor + length <= len(wire), 'partial, unknown or oversized incoming frame')
  body = wire[cursor:cursor+length]; cursor += length
  if kind == 3:
   _pa_need(length == 1 and body == b'\0' and cursor == len(wire),
   'one final single-byte successful EXIT is mandatory')
   ended = True
  else:
   size += length
   _pa_need(size <= 65536, 'combined output frame payload bound exceeded')
   output[kind].append(body)
 _pa_need(ended and b''.join(output[1]) == raw['stdout_original']
 and b''.join(output[2]) == raw['stderr_original'],
 'actual stream originals do not equal complete frame payloads')
 sent = 8 + request_bytes + transport_bytes
 counters = {'received_frames': count,
 'stdout_payload_bytes_received': len(raw['stdout_original']),
 'stderr_payload_bytes_received': len(raw['stderr_original']),
 'shared_payload_bytes_charged': request_bytes + size,
 'smart_socket_request_bytes_sent': sent,
 'incoming_wire_bytes_outside_complete_stdout_stderr_payload': len(wire) - size}
 _pa_need(all(_pa_same(record[key], value) for key, value in counters.items()),
 'actual frame/payload counters differ')
 accounting = {'smart_socket_request_bytes_sent': sent,
 'smart_socket_response_bytes_received': 8,
 'shell_protocol_bytes_sent': 5, 'shell_protocol_bytes_received': len(wire),
 'all_socket_bytes_sent': sent + 5, 'all_socket_bytes_received': 8 + len(wire),
 'protocol_and_carrier_costs_are_separate_from_shared_payload': True,
 'whole_case_or_reservation_pool_qualified_here': False}
 _pa_need(_pa_same(record['carrier_accounting'], accounting),
 'actual carrier and framing costs are not the source-defined complete charge')
 charged = sent + 5 + 8 + len(wire)
 _pa_need(charged <= 267293 <= remaining and request_bytes + size <= remaining,
 'whole exchange exceeded its reserved single-operation pool')
 return charged
def _pa_publication_wire_original(wire, observed_raw):
 import base64
 import zlib
 _pa_need(type(wire) is bytes and 0 < len(wire) <= 49152
 and type(observed_raw) is bytes and 0 < len(observed_raw) <= 2097152,
 'original publication wire/decoded observation exceeds source limits')
 value = _pa_strict(wire)
 _pa_exact(value, ('schema', 'encoding', 'uncompressed', 'compressed', 'payload_base64'),
 'exact publication data wire required')
 _pa_need(_pa_encoded(value) == wire
 and value['schema'] == 'hepta.native-guard.epoch-publication-wire.v1'
 and value['encoding'] == 'zlib+base64', 'canonical publication wire differs')
 for key, maximum in (('uncompressed', 2097152), ('compressed', 49152)):
  _pa_exact(value[key], ('bytes', 'sha256'), 'exact bounded data pin required')
  _pa_hash(value[key]['sha256'])
  _pa_need(type(value[key]['bytes']) is int and 0 < value[key]['bytes'] <= maximum,
  'wire byte pin exceeds its own data bound')
 text = value['payload_base64']
 _pa_need(type(text) is str and len(text) <= 65536, 'bounded canonical base64 required')
 packed = base64.b64decode(text, validate=True)
 _pa_need(base64.b64encode(packed).decode('ascii') == text
 and _pa_same(_pa_bare(packed), value['compressed']), 'compressed original pin differs')
 decoder = zlib.decompressobj()
 body = decoder.decompress(packed, 2097153)
 _pa_need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
 and body == observed_raw and _pa_same(_pa_bare(body), value['uncompressed']),
 'wire is not the one whole bounded original observation stream')
 observation = _pa_strict(body)
 _pa_need(type(observation) is dict and _pa_encoded(observation) == body
 and observation.get('schema') == 'hepta.native-guard.epoch-publication-observation.v1',
 'decoded original observation bytes are not canonical')
def _pa_publication_pending(action, raw, expected, packet, observed_raw, originals, sources):
 """Verify pending data and eight originals; never claim actor completion."""
 originals.budget_check()
 wrapper = _pa_strict(raw['phone_wrapper'])
 _pa_need(len(raw['phone_wrapper']) <= 65536 and _pa_encoded(wrapper) == raw['phone_wrapper'],
 'one complete canonical original actor result required')
 label = expected['actor_label']
 _pa_need(type(label) is str and re.fullmatch('[A-Za-z0-9_-]{1,100}', label) is not None,
 'actual source-rendered actor label differs')
 run = '/home/alex/razr60-local-model-v150/operations/' + label
 _pa_need(action['phone_wrapper']['path'] == expected['actor_wrapper_path'] == run + '/result.json',
 'pending actor original is not the actual fixed operation file')
 req = expected['request']; request_raw = expected['request_raw']
 _pa_exact(req, ('schema', 'kind', 'root', 'command', 'timeout_seconds',
 'payload_budget_bytes', 'expected_observation'), 'exact new actor request required')
 _pa_need(req['schema'] == 'hepta.phone-local.epoch-publication-request.v1'
 and req['kind'] == 'epoch_publication_read' and req['root'] is True
 and type(req['command']) is str and '\0' not in req['command']
 and type(req['timeout_seconds']) is int and 1 <= req['timeout_seconds'] <= 300
 and type(req['payload_budget_bytes']) is int
 and 534586 <= req['payload_budget_bytes'] <= 8388608
 and type(request_raw) is bytes and len(request_raw) <= 131072
 and _pa_same(_pa_strict(request_raw), req), 'source-rendered request bytes or pool differ')
 observed = _pa_strict(observed_raw)
 expected_observation = {key: observed[key] for key in ('epoch_id', 'boot_id', 'generation', 'terminal')}
 expected_observation.update({key: observed['source_reader_binding'][key]
 for key in ('root_source_manifest', 'bridge_source')})
 _pa_need(_pa_same(req['expected_observation'], expected_observation),
 'source-rendered request and actual complete observation links differ')
 fixed = {'schema': 'hepta.phone-local.epoch-publication-result.v1', 'label': label,
 'state': 'PUBLICATION_WIRE_ORIGINALS_VERIFIED_PENDING_ACTOR_FD_CLOSE',
 'automatic_retry': False, 'automatic_replay': False,
 'new_explicit_process_signal_calls': 0, 'remote_cleanup_proven': False,
 'publication_source_authority_verified_here': False, 'model_decision': False,
 'native_task_result': False, 'component_case_passed': False,
 'transport_disconnect_may_trigger_adbd_SIGHUP': True,
 'baseline_dispatch_count': 1, 'payload_dispatch_count': 1, 'failure': None,
 'local_filesystem_IO_is_not_preemptible': True, 'legacy_route_gate_is_not_preempted': True,
 'whole_case_or_reservation_pool_qualified_here': False,
 'wire_and_declared_observation_shape_verified': True,
 'expected_observation': req['expected_observation'],
 'empty_stdin': {**_pa_bare(b''), 'host_source_file': None,
 'semantics': 'SOURCE_DEFINED_EMPTY_INPUT_AND_REAL_CLOSE_STDIN'}}
 extra = ('transport', 'baseline_transport', 'sdk_original', 'config_original',
 'publication_wire_utf8', 'publication_observation_original', 'whole_transport_pool',
 'request_postcheck', 'config_postcheck', 'elapsed_seconds')
 _pa_exact(wrapper, set(fixed) | set(extra), 'exact successful pending actor fields differ')
 _pa_need(all(_pa_same(wrapper[key], value) for key, value in fixed.items())
 and _pa_number(wrapper['elapsed_seconds'], 'pending elapsed must be finite')
 < req['timeout_seconds'], 'pending actor does not match the exact source request')
 _pa_pin(wrapper['sdk_original'], phone=True)
 _pa_need(_pa_same({k: wrapper['sdk_original'][k] for k in ('path', 'bytes', 'sha256')}, sources['sdk']),
 'actual actor loaded a different whole SDK source')
 pin = _pa_pub_host_pin(wrapper['publication_observation_original'],
 run + '/PUBLICATION-OBSERVATION.original.json', 2097152)
 _pa_need(_pa_same(pin, packet['publication_observation'])
 and originals.get(pin) == observed_raw, 'decoded observation is not the actual retained original')
 for key, path, body in (
 ('request_postcheck', expected['request_path'], request_raw),
 ('config_postcheck', '/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved-ui-package-config.json', None)):
  value = wrapper[key]
  _pa_exact(value, ('path', 'bytes', 'sha256', 'metadata', 'complete_second_read_and_EOF'),
  'actual original post-read receipt required')
  row = {k: value[k] for k in ('path', 'bytes', 'sha256', 'metadata')}
  _pa_pin(row, phone=True)
  _pa_need(value['path'] == path and value['complete_second_read_and_EOF'] is True,
  'actor post-read source identity differs')
  if body is not None:
   _pa_need(_pa_same({k: value[k] for k in ('bytes', 'sha256')}, _pa_bare(body)),
   'actual request hash differs from the fixed producer bytes')
  else:
   config = wrapper['config_original']
   _pa_pub_host_pin(config, run + '/config.original.json', 65536)
   _pa_need(_pa_same({k: config[k] for k in ('bytes', 'sha256')},
   {k: value[k] for k in ('bytes', 'sha256')}),
   'retained config and actual source post-read pins differ')
 bodies, descriptors = _pa_publication_sdk_originals(wrapper, run, originals)
 baseline_command = 'cat /proc/sys/kernel/random/boot_id; getprop ro.build.fingerprint; getprop sys.usb.config; getenforce; pidof adbd'
 baseline = _pa_publication_exchange(wrapper['baseline_transport'], bodies['baseline_transport'],
 baseline_command, req['payload_budget_bytes'], originals.budget_check)
 _pa_need(wrapper['baseline_transport']['elapsed_seconds'] <= min(15, req['timeout_seconds'])
 and wrapper['transport']['elapsed_seconds'] < req['timeout_seconds'],
 'actual SDK exchanges exceed their original actor deadline')
 _pa_need(bodies['baseline_transport']['stdout_original'].decode('utf-8', 'strict').splitlines()
 == ['f8019f83-20a7-4f18-bea1-51c980621e4d',
 'motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys',
 'adb', 'Enforcing', '3021'], 'complete actual baseline differs')
 command = '/debug_ramdisk/su -c ' + shlex.quote(req['command'])
 charged = _pa_publication_exchange(wrapper['transport'], bodies['transport'], command,
 req['payload_budget_bytes'] - baseline, originals.budget_check)
 _pa_need(_pa_same(wrapper['transport']['route'], wrapper['baseline_transport']['route']),
 'actual route changed between the two exchanges')
 _pa_need(_pa_same(wrapper['whole_transport_pool'], {
 'maximum_bytes': req['payload_budget_bytes'], 'baseline_socket_bytes': baseline,
 'publication_socket_bytes': charged, 'total_socket_bytes': baseline + charged,
 'each_exchange_pre_reserved_bytes': 267293,
 'command_stdin_stdout_stderr_smart_replies_and_shell_framing_included': True,
 'unchanged_legacy_route_observations_are_not_shell_exchange_bytes': True}),
 'actor same-operation whole wire accounting differs')
 wire = bodies['transport']['stdout_original']
 _pa_need(type(wrapper['publication_wire_utf8']) is str
 and wrapper['publication_wire_utf8'].encode('utf-8') == wire,
 'pending result changed the actual original wire')
 originals.budget_check(); _pa_publication_wire_original(wire, observed_raw); originals.budget_check()
 return {'actor_label': label, 'actual_run': run, 'dynamic_sdk_originals': descriptors,
 'transport_socket_bytes': baseline + charged, 'original_wire': _pa_bare(wire),
 'decoded_original': _pa_bare(observed_raw), 'actor_completion_verified_here': False,
 'config_body_independently_read_by_this_helper': False,
 'source_or_action_authority_from_pending_result': False}
def _pa_publication_actor_completion(stdout_raw, stderr_raw, actor_rc, expected,
wrapper_pin, wrapper_raw, *, budget_check):
 """Only actual producer-supplied complete actor streams may enter this API."""
 budget_check()
 _pa_need(type(actor_rc) is int and actor_rc == 0 and type(stderr_raw) is bytes
 and stderr_raw == b'' and type(stdout_raw) is bytes and 0 < len(stdout_raw) <= 65536,
 'actual actor return and complete streams are mandatory')
 value = _pa_strict(stdout_raw)
 fixed = {'schema': 'hepta.phone-local.epoch-publication-summary.v1',
 'label': expected['actor_label'],
 'run': '/home/alex/razr60-local-model-v150/operations/' + expected['actor_label'],
 'status': 'PUBLICATION_ORIGINALS_RETAINED_AND_OWNED_HOST_FDS_CLOSED',
 'failure': None, 'failure_retention_error': None,
 'baseline_dispatch_count': 1, 'payload_dispatch_count': 1,
 'automatic_retry': False, 'remote_cleanup_proven': False,
 'publication_source_authority_verified_here': False,
 'transport_disconnect_may_trigger_adbd_SIGHUP': True}
 _pa_exact(value, set(fixed) | {'result', 'host_owned_fd_cleanup', 'elapsed_seconds'},
 'exact final actor summary required')
 _pa_need(_pa_encoded(value) == stdout_raw
 and all(_pa_same(value[key], item) for key, item in fixed.items())
 and _pa_number(value['elapsed_seconds'], 'final actor elapsed must be finite')
 < expected['request']['timeout_seconds'], 'actor final completion differs')
 pin = _pa_pub_host_pin(value['result'], expected['actor_wrapper_path'], 65536)
 _pa_need(_pa_same(pin, wrapper_pin)
 and _pa_same(_pa_bare(wrapper_raw), {k: pin[k] for k in ('bytes', 'sha256')}),
 'final actor summary does not bind the retained pending original')
 cleanup = value['host_owned_fd_cleanup']
 fixed_cleanup = {'known_remaining': [], 'close_errors': [], 'fd_registration_incomplete': False,
 'owned_known_fds_closed': True, 'complete_ownership_claimed': True,
 'remote_cleanup_proven': False}
 fields = ('known_opened', 'known_closed', 'physical_file_bytes_read', 'physical_file_bytes_written')
 _pa_exact(cleanup, set(fixed_cleanup) | set(fields), 'actual owned FD completion fields differ')
 _pa_need(all(_pa_same(cleanup[key], item) for key, item in fixed_cleanup.items())
 and all(type(cleanup[key]) is int and cleanup[key] >= 0 for key in fields)
 and cleanup['known_opened'] == cleanup['known_closed'] > 0,
 'unknown host FD ownership cannot establish actor completion')
 budget_check()
 return {'actor_returncode': 0, 'complete_actor_stdout': _pa_bare(stdout_raw),
 'complete_actor_stderr': _pa_bare(stderr_raw), 'pending_result': wrapper_pin,
 'owned_host_fd_cleanup': cleanup, 'actual_producer_source_and_join_still_required': True}
def _pa_verify_native_wrapper(action, raw, expected, observed_raw, *, originals):
 module=_pa_publication_prepare_module()
 function=getattr(module,'epoch_verify_publication_producer_outputs',None)
 _pa_need(callable(function),'the actual publication producer envelope verifier is missing')
 return function(action,raw,expected,observed_raw,original_from=originals.get,
 budget_check=originals.budget_check)
def _pa_original_phone_json(pin,parsed):
 _pa_pin(pin,phone=True)
 rows=[row for row in parsed['manifest']['files'] if row['path']==pin['path']]
 _pa_need(len(rows)==1 and _pa_same(rows[0],pin),
 'an actual phone original is missing or has different full9')
 raw=parsed['originals_by_path'].get(pin['path'])
 _pa_need(type(raw) is bytes and _pa_same(_pa_bare(raw),
 {k:pin[k] for k in ('bytes','sha256')}),'complete original phone body differs')
 value=_pa_strict(raw)
 _pa_need(type(value) is dict and _pa_encoded(value)==raw,
 'actual canonical phone JSON original required')
 return value
def _pa_verify_source_bytes(sources,source_bytes,packet,action_raw,parsed,*,budget_check):
 """Whole source validation uses actual originals and the admitted current32."""
 budget_check()
 runtime_raw=globals().get('__reviewed_package_manifest_raw__')
 runtime_sources=globals().get('__reviewed_package_sources__')
 context=globals().get('__actual_context__')
 _pa_need(context in ('phone','mac','p4') and type(runtime_raw) is bytes
 and type(runtime_sources) is dict and len(runtime_sources)==32,
 'publication action lost the explicit actual current32 source context')
 for name in ('component_common','component_lifecycle','prepare_component',
 'late_boundary','component_snapshot'):
  module=sys.modules.get(name); body=runtime_sources.get('source/' + name + '.py')
  _pa_need(module is not None and type(body) is bytes
  and getattr(module,'__actual_context__',None)==context
  and getattr(module,'__reviewed_package_manifest_raw__',None)==runtime_raw
  and getattr(module,'__reviewed_source_sha256__',None)==_pa_bare(body)['sha256'],
  'loaded publication dependency does not retain its exact source/context: ' + name)
  other=getattr(module,'__reviewed_package_sources__',None)
  _pa_need(type(other) is dict and set(other)==set(runtime_sources)
  and all(type(other[k]) is bytes and other[k]==b for k,b in runtime_sources.items()),
  'publication dependency changed the complete admitted source map')
 _pa_need(sys.modules['component_snapshot'].__dict__ is globals(),
 'publication action must run in the admitted snapshot member')
 generation_pin=parsed['publication_observation']['generation']
 generation=_pa_original_phone_json(generation_pin,parsed)
 _pa_exact(generation,('schema','epoch_id','ordinal','runtime','combination',
 'pure_verifier','derivation','predecessor_generation','closed_failure_input'),
 'complete original source catalog required')
 _pa_need(generation['schema']=='hepta.native-guard.epoch-generation-catalog.v1'
 and generation['epoch_id']==packet['epoch_id']
 and type(generation['ordinal']) is int and generation['ordinal']==1
 and generation['predecessor_generation'] is None and generation['closed_failure_input'] is None,
 'later generations require their separately reviewed finite source increment')
 _eca_runtime_sources({},{'runtime_manifest':runtime_raw,
 'closer_source':runtime_sources['source/close_component.py']},runtime_raw=runtime_raw,
 runtime_sources=runtime_sources,generation=generation)
 common=sys.modules['component_common']
 registry=_pa_path(common.EPOCH_REGISTRY_ROOT)
 _pa_need(generation_pin['path']==registry + '/generations/01.json',
 'actual catalog is outside the current source-fixed registry')
 common.epoch_manifest_value(parsed['manifest'],parsed['originals_by_path'],
 binding=common.epoch_binding_value())
 plan_raw=action_raw['root_plan']; plan=_pa_strict(plan_raw)
 _pa_need(len(plan_raw)<=262144 and type(plan) is dict
 and plan_raw==_pa_encoded(plan,pretty=True)
 and plan.get('schema')=='hepta.native-guard.epoch-root-plan.v1'
 and _pa_same(plan.get('source_package'),sources['root_source_manifest'])
 and _pa_same(packet['source_action_originals']['root_source_manifest'],sources['root_source_manifest']),
 'actual retained epoch plan or fixed Root manifest differs')
 epoch=plan.get('epoch')
 _pa_exact(epoch,('schema','epoch_id','anchor','initialization','ordinal',
 'reservation','identity','generation'),'complete actual epoch links required')
 identity=_pa_original_phone_json(epoch['identity'],parsed)
 _pa_need(type(identity.get('ordinal')) is int and 1<=identity['ordinal']<=8
 and type(identity.get('label')) is str
 and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}',identity['label']) is not None
 and epoch['identity']['path']==registry + '/slots/%02d/IDENTITY.json' % identity['ordinal'],
 'actual allocated identity path or ordinal differs')
 lease_path=str(common.BASE / 'native-guard-r10-r1' / identity['label'] / 'LEASE.json')
 leases=[row for row in parsed['manifest']['files'] if row['path']==lease_path]
 _pa_need(len(leases)==1,'the complete actual publication identity lease is absent')
 lease=_pa_original_phone_json(leases[0],parsed)
 actual_epoch=common.epoch_lease_protocol_value(lease)
 _pa_need(_pa_same(actual_epoch,epoch) and _pa_same(epoch['generation'],generation_pin),
 'Root plan substitutes a self-reported epoch binding for the retained actual lease')
 for name in ('anchor','initialization','reservation','identity','generation'):
  _pa_original_phone_json(actual_epoch[name],parsed)
 expected={'epoch_id':packet['epoch_id'],'ordinal':identity['ordinal'],
 'nonce':identity['nonce'],'identity':actual_epoch['identity'],'generation':generation_pin,
 'registry_root':registry,'identity_value':identity,'epoch_binding':actual_epoch}
 templates=FINAL_PUBLICATION_TEMPLATES
 binding=_eca_derived_root_binding(expected,runtime_raw,generation,templates)
 _eca_actual_identity_links(plan,expected,binding)
 names={'root_source_manifest':'root_source_manifest',
 'root_coordinator_source':'root_coordinator','root_bridge_source':'root_bridge',
 'root_verifier_source':'root_reference'}
 origins={name:sources[role] for name,role in names.items()}
 bodies={name:source_bytes[role] for name,role in names.items()}
 tree=_eca_root3_originals(origins,bodies,plan,binding,templates)
 constants=_eca_root_source_constants(tree,source_bytes['root_coordinator'])
 _pa_need(plan['boot_id']==packet['boot_id']
 ==ast.literal_eval(_eca_literal(tree,'BOOT')),
 'actual Root action boot differs from its source and full phone observation')
 actor_tree=ast.parse(source_bytes['actor'])
 _pa_need(_pa_same(ast.literal_eval(_eca_literal(actor_tree,'ROOT_STDIN_SDK_PIN')),
 {k:sources['sdk'][k] for k in ('bytes','sha256')})
 and ast.literal_eval(_eca_literal(actor_tree,'ROOT_STDIN_SDK_NAME'))
 ==PurePosixPath(sources['sdk']['path']).name
 and PurePosixPath(sources['sdk']['path']).parent==PurePosixPath(sources['actor']['path']).parent,
 'actual actor must bind the exact full-byte-verified SDK at its real sibling path')
 _eca_verify_actual_epoch_bridge_source(source_bytes['root_bridge'],sources['root_bridge'],
 binding,templates,budget_check=budget_check)
 budget_check()
 return plan,_pa_strict(source_bytes['root_source_manifest']),constants
def _pa_publication_prepare_module():
 module=sys.modules.get('prepare_component')
 context=globals().get('__actual_context__')
 sources=globals().get('__reviewed_package_sources__')
 manifest=globals().get('__reviewed_package_manifest_raw__')
 _pa_need(module is not None and context in ('phone','mac','p4')
 and type(sources) is dict and len(sources)==32 and type(manifest) is bytes
 and getattr(module,'__actual_context__',None)==context
 and getattr(module,'__reviewed_package_manifest_raw__',None)==manifest
 and getattr(module,'__reviewed_package_sources__',None) is sources
 and getattr(module,'__reviewed_source_sha256__',None)
 ==_eca_sha(sources['source/prepare_component.py']),
 'the publication pure producer gate is not the already admitted current prepare member')
 return module
def _pa_render_bound_publication_action(plan, parsed, source_bytes, sources, *, budget_check):
 module=_pa_publication_prepare_module()
 function=getattr(module,'epoch_publication_expected_action',None)
 _pa_need(callable(function),'the complete actual source-bound publication renderer is unavailable')
 return function(plan,parsed,source_bytes,sources,budget_check=budget_check)
def verify_publication_action_receipts(packet_original, parsed, *, source_authority, original_from, budget_check):
 """Return exact six-key proof only after actual source and action closure.

    The constructor supplies every descriptor explicitly; the caller must
    also enforce its final all-parser/all-action used_paths==declared_paths.
    This proof is not native-business qualification or new publication
    permission. Original provenance comes from the enclosing retained-input
    acquisition chain, not from merely presenting matching JSON strings.
    """
 _pa_need(callable(budget_check), 'the original whole-operation budget is mandatory')
 budget_check()
 sources = _pa_source_bindings(source_authority)  
 originals = _PAOriginals(original_from, budget_check)
 packet, action_raw, manifest, observed, observed_raw = _pa_packet_view(packet_original, parsed, originals)
 source_bytes = {role: originals.get(sources[role]) for role in _PA_SOURCE_ROLES}
 plan, source_manifest, constants = _pa_verify_source_bytes(
 sources, source_bytes, packet, action_raw, parsed, budget_check=budget_check)
 _pa_need(_pa_same(observed['source_reader_binding']['bridge_source'], sources['root_bridge']),
 'phone reader is not the trusted actual bridge source')
 originals.budget_check()
 expected = _pa_render_bound_publication_action(plan, parsed, source_bytes, sources, budget_check=originals.budget_check)
 host = _pa_verify_host_capture(plan, packet['source_action_originals'], action_raw, expected)
 transport = _pa_publication_pending(packet['source_action_originals'], action_raw,
 expected, packet, observed_raw, originals, sources)
 phone = _pa_verify_native_wrapper(packet['source_action_originals'], action_raw, expected, observed_raw, originals=originals)
 originals.budget_check()
 proof = {'operation': 'epoch-publication-read', 'host': host, 'phone': phone, 'transport': transport,
 'complete_phone_manifest': packet['manifest'],
 'phone_original_count': len(manifest['files']),
 'root_plan': packet['source_action_originals']['root_plan'],
 'root_source_manifest': sources['root_source_manifest'],
 'literal_source_pins_and_actual_stdin_renderer_verified': True,
 'same_enclosing_pool_no_callback_bypass': True,
 'no_target_sources_executed_by_verifier': True,
 'component_qualified': False, 'business_qualified': False,
 'authorizes_new_publication_or_replay': False}
 return {'schema': 'hepta.native-guard.epoch-publication-action-verification.v1',
 'state': 'OWNED_HOST_AND_ACTUAL_PHONE_PUBLICATION_READ_VERIFIED',
 'packet_original': _pa_strict(_pa_encoded(_pa_pin(packet_original))),
 'needed_source_descriptors': publication_action_needed_source_descriptors(source_authority=source_authority),
 'used_original_descriptors': originals.descriptors(), 'proof': proof}
if __name__=='__main__':
 C.need(globals().get('__actual_context__', 'phone') == 'phone',
 'direct phone snapshot context conflicts with an injected context')
 __actual_context__ = 'phone'
 import late_boundary as LATE
 for _module in (C, LIFE, LATE):
  C.need(getattr(_module, '__actual_context__', None) in (None, 'phone'),
  'direct phone snapshot cannot overwrite another actual context')
  _module.__actual_context__ = 'phone'
 raise SystemExit(main())
