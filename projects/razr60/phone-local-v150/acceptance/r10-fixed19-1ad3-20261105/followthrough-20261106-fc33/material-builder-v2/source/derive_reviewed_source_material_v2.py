#!/usr/bin/env python3
"""Derive shared source material from reviewed replacements; never freeze a runtime or dispatch."""
import ast,copy,hashlib,json,os,re,stat,sys
from pathlib import Path
BASE=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-final-v3-getattr-a1055-r4')
PINS={
 'COMBINATION.json':(4695,'02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708'),
 'SOURCE-SEAL.json':(2341,'78c39b4cc4afd438bb149013fff20bbecc0a78241c3ed979e101320736eadcc0'),
 'shared/SHARED-MATERIALS.json':(3519,'2ea9a478b366d6a69fdb8942699b6241d72330cfa789baa4b3132fdaca169e68'),
 'shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json':(10654,'e0522c5d743fd9bdc30343d93200a894d58016f935f564284bb6b0d924ba898a'),
 'shared/local-config-r10-r1.json':(1493,'22f57380a8bf92d88f0a0d7eda700adc7c711464975d7184b0dce48b3bdd5d3e')
}
ALLOWED={'phone_observation_tools.py','phone_local_tools.py','daily_phone_local.py'}
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
BOOK={}
def need(v,why):
 if not v:raise ValueError(why)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def strict(raw):
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate JSON key');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def enc(v,pretty=True):
 kw={'sort_keys':True,'ensure_ascii':False,'allow_nan':False}
 kw.update({'indent':2}if pretty else{'separators':(',',':')})
 return(json.dumps(v,**kw)+'\n').encode()
def style(raw):
 value=strict(raw);matches=[p for p in (True,False)if enc(value,p)==raw]
 need(len(matches)==1,'exact known original JSON serializer');return value,matches[0]
def meta(s):return[getattr(s,k)for k in META]
def read(desc):
 need(type(desc)is dict and set(desc)=={'path','bytes','sha256'},'exact source descriptor')
 need(type(desc['path'])is str and type(desc['bytes'])is int and 0<desc['bytes']<=1048576
  and type(desc['sha256'])is str and re.fullmatch('[0-9a-f]{64}',desc['sha256']),'bounded typed source descriptor')
 p=Path(desc['path']);need(p.is_absolute()and p.parent.resolve(strict=True)==p.parent,'canonical source parent')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==desc['bytes'],'exact single-link source')
  chunks=[];n=0
  while n<=a.st_size:
   b=os.read(fd,min(65536,a.st_size+1-n))
   if not b:break
   n+=len(b);chunks.append(b)
  raw=b''.join(chunks)
  need(pin(raw)=={k:desc[k]for k in ('bytes','sha256')}and meta(a)==meta(os.fstat(fd))==meta(p.lstat()),'full source bytes/hash/metadata')
 finally:os.close(fd)
 row=dict(desc,metadata=meta(a));need(str(p)not in BOOK or BOOK[str(p)]==row,'stable source original')
 BOOK[str(p)]=row;return raw
def desc(path,raw):return{'path':str(path),**pin(raw)}
def parents(raw):
 t=ast.parse(raw);rows=[n.value for n in t.body if isinstance(n,ast.Assign)and any(isinstance(a,ast.Name)and a.id=='PARENTS'for a in n.targets)]
 need(len(rows)==1,'one daily dependency map');v=ast.literal_eval(rows[0])
 need(type(v)is dict and len(v)==14 and all(type(k)is str and type(x)is str for k,x in v.items()),'fourteen exact daily dependency hashes')
 return v
def publish_material(out,files):
 """Create a complete host artifact through held directory FDs; terminal JSON is last."""
 need(isinstance(out,Path)and out.is_absolute(),'absolute fresh material output')
 need(type(files)is dict and 'DERIVATION.json'in files,'complete material map with terminal record')
 directories=('', 'shared', 'shared/provider', 'shared/provider/source', 'reference')
 for name,raw in files.items():
  need(type(name)is str and name and not any(c in name for c in '\0\r\n\t'),'plain material member')
  p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent)
  need(not p.is_absolute()and str(p)==name and p.name and '..'not in p.parts
   and parent in directories and name not in directories and type(raw)is bytes,'closed relative material file')
 out.mkdir(mode=0o700);created=out.lstat();handles={};identities={};members={n:set()for n in directories};observed={}
 def close_all():
  primary=sys.exc_info()[1];errors=[]
  for fd in reversed(list(handles.values())):
   try:os.close(fd)
   except BaseException as error:errors.append(error)
  if errors:
   if primary is not None:raise primary from errors[0]
   raise errors[0]
 def verify_directory(name):
  info=os.fstat(handles[name])
  if name=='':path_info=out.lstat()
  else:
   p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent)
   path_info=os.stat(p.name,dir_fd=handles[parent],follow_symlinks=False)
  need(stat.S_ISDIR(path_info.st_mode)and stat.S_IMODE(path_info.st_mode)==0o700
   and meta(info)[:5]==meta(path_info)[:5]==identities[name],'same owned material directory identity')
  need(set(os.listdir(handles[name]))==members[name],'exact known material directory membership')
 def verify_directories():
  for name in handles:verify_directory(name)
 def owner(name):
  p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent)
  return parent,p.name
 def readback(name,expected,first=False):
  parent,base=owner(name);verify_directories()
  fd=os.open(base,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=handles[parent])
  try:
   before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode)and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1,'private single-link material output')
   with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(len(expected)+1)
   need(raw==expected and meta(before)==meta(os.fstat(fd))
    ==meta(os.stat(base,dir_fd=handles[parent],follow_symlinks=False)),'complete created material full9/byte readback')
   if first:observed[name]=meta(before)
   else:need(observed[name]==meta(before),'created material changed before terminal publication')
  finally:os.close(fd)
  verify_directories()
 def put(name,raw):
  parent,base=owner(name);verify_directories()
  fd=os.open(base,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=handles[parent])
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  members[parent].add(base);verify_directories();readback(name,raw,True)
 try:
  handles['']=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  identities['']=meta(created)[:5];verify_directory('')
  for name in directories[1:]:
   p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent);verify_directories()
   os.mkdir(p.name,mode=0o700,dir_fd=handles[parent]);members[parent].add(p.name)
   first=os.stat(p.name,dir_fd=handles[parent],follow_symlinks=False)
   handles[name]=os.open(p.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=handles[parent])
   identities[name]=meta(first)[:5];verify_directories()
  for name,raw in sorted(files.items()):
   if name!='DERIVATION.json':put(name,raw)
  for name in sorted(observed):readback(name,files[name])
  for name in reversed(directories):os.fsync(handles[name])
  verify_directories()
  put('DERIVATION.json',files['DERIVATION.json'])
  os.fsync(handles['']);verify_directories()
 finally:close_all()

def main():
 if len(sys.argv)==1:
  print(json.dumps({'state':'UNBOUND_HOST_MATERIAL_TEMPLATE','io':0,'phone_calls':0,'runtime_freeze':False,'actual_BUILD':False,'actual_READY':False}));return
 need(sys.argv[1:]==['--derive-reviewed-host-material'],'explicit host-only mode')
 raw_request=sys.stdin.buffer.read(65537);need(0<len(raw_request)<=65536,'bounded original request')
 request=strict(raw_request)
 need(type(request)is dict and set(request)=={'reviewed_builder_sha256','candidate_sources','output_dir'},'exact host material request')
 own=Path(__file__);ownraw=own.read_bytes();need(pin(ownraw)['sha256']==request['reviewed_builder_sha256'],'reviewed exact builder bytes')
 candidates=request['candidate_sources']
 need(type(candidates)is dict and {'phone_observation_tools.py','daily_phone_local.py'}<=set(candidates)<=ALLOWED,'closed reviewed source-change family')
 originals={};values={};styles={}
 for name,(size,digest)in PINS.items():
  raw=read({'path':str(BASE/name),'bytes':size,'sha256':digest})
  originals[name]=raw;values[name],styles[name]=style(raw)
 combo=values['COMBINATION.json'];seal=values['SOURCE-SEAL.json'];shared=values['shared/SHARED-MATERIALS.json']
 service=values['shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json'];config=values['shared/local-config-r10-r1.json']
 need(combo['source_seal']==pin(originals['SOURCE-SEAL.json'])
  and combo['configuration']==pin(originals['shared/local-config-r10-r1.json'])
  and combo['service_inputs']==pin(originals['shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json'])
  and config['service_manifest_sha256']==combo['service_inputs']['sha256'],'original source graph')
 old_sources={}
 for row in combo['production_files']:
  name=Path(row['path']).name
  need(row['path']=='production/'+name and name not in old_sources,'exact production member')
  old_sources[name]=read({'path':str(BASE/'shared/provider/source'/name),'bytes':row['bytes'],'sha256':row['sha256']})
 need(len(old_sources)==15 and set(candidates)<=set(old_sources),'complete original fifteen sources')
 new_sources=dict(old_sources)
 for name,row in candidates.items():new_sources[name]=read(row);ast.parse(new_sources[name])
 changed=sorted(n for n in old_sources if old_sources[n]!=new_sources[n])
 need({'phone_observation_tools.py','daily_phone_local.py'}<=set(changed)<=ALLOWED,'only explicitly reviewed source changes')
 expected_daily=old_sources['daily_phone_local.py']
 for name in sorted(ALLOWED-{'daily_phone_local.py'}):
  oldsha=pin(old_sources[name])['sha256'];newsha=pin(new_sources[name])['sha256']
  need(expected_daily.count(oldsha.encode())==1,'one original daily dependency pin')
  expected_daily=expected_daily.replace(oldsha.encode(),newsha.encode(),1)
 need(expected_daily==new_sources['daily_phone_local.py'],'daily changes only reviewed dependency hashes')
 need(parents(new_sources['daily_phone_local.py'])=={n:pin(r)['sha256']for n,r in new_sources.items()if n!='daily_phone_local.py'},'all fourteen actual candidate dependency pins')
 def update_rows(rows,prefix,names):
  need(len(rows)==len(names)and {r['path']for r in rows}=={prefix+n for n in names},'closed exact source row set')
  return[{'path':r['path'],**pin(new_sources[Path(r['path']).name])}for r in rows]
 next_service=copy.deepcopy(service)
 next_service['provider_sources']=update_rows(service['provider_sources'],'provider-r10-r1/source/',old_sources)
 next_service['parent_service_inputs_sha256']=pin(originals['shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json'])['sha256']
 service_raw=enc(next_service,styles['shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json'])
 next_config=copy.deepcopy(config);next_config['service_manifest_sha256']=pin(service_raw)['sha256']
 config_raw=enc(next_config,styles['shared/local-config-r10-r1.json'])
 next_seal=copy.deepcopy(seal)
 next_seal['configuration']=pin(config_raw);next_seal['phone_service_inputs_sha256']=pin(service_raw)['sha256']
 next_seal['production_files']=update_rows(seal['production_files'],'source/',old_sources)
 seal_raw=enc(next_seal,styles['SOURCE-SEAL.json'])
 next_combo=copy.deepcopy(combo)
 next_combo['configuration']=pin(config_raw);next_combo['service_inputs']=pin(service_raw);next_combo['source_seal']=pin(seal_raw)
 next_combo['production_files']=update_rows(combo['production_files'],'production/',old_sources)
 combo_raw=enc(next_combo,styles['COMBINATION.json'])
 source_input={'schema':'hepta.reviewed-source-material-derivation-input.v1','state':'HOST_SOURCE_ONLY_NOT_RUNTIME_ADOPTION',
  'original_component':{'path':str(BASE/'COMBINATION.json'),**pin(originals['COMBINATION.json'])},
  'builder':desc(own,ownraw),'original_request_sha256':pin(raw_request)['sha256'],
  'reviewed_replacements':candidates,'changed_sources':changed,'phone_calls':0,'actual_cleanup_closure_bound':False}
 source_input_raw=enc(source_input)
 files={'shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json':service_raw,'shared/local-config-r10-r1.json':config_raw,
  'SOURCE-SEAL.json':seal_raw,'COMBINATION.json':combo_raw,'SOURCE-INPUTS.json':source_input_raw}
 files.update({'shared/provider/source/'+n:r for n,r in new_sources.items()})
 next_shared=copy.deepcopy(shared)
 expected_members={'PHONE-SERVICE-INPUTS-v150-r10-r1.json','local-config-r10-r1.json'}|{'provider/source/'+n for n in old_sources}
 need(len(shared['files'])==17 and {r['path']for r in shared['files']}==expected_members,'seventeen original shared members')
 for row in shared['files']:
  need(row=={'path':row['path'],**pin(originals['shared/'+row['path']]if 'provider/source/'not in row['path']else old_sources[Path(row['path']).name])},'every old shared row matched')
 next_shared['files']=[{'path':r['path'],**pin(files['shared/'+r['path']])}for r in shared['files']]
 next_shared['parent_configuration_sha256']=pin(originals['shared/local-config-r10-r1.json'])['sha256']
 next_shared['parent_service_inputs_sha256']=pin(originals['shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json'])['sha256']
 next_shared['source_input_sha256']=pin(source_input_raw)['sha256']
 files['shared/SHARED-MATERIALS.json']=enc(next_shared,styles['shared/SHARED-MATERIALS.json'])
 # Exact inverse checks cover the complete objects, not just the modified fields.
 reverse=copy.deepcopy(next_service);reverse['provider_sources']=service['provider_sources'];reverse['parent_service_inputs_sha256']=service['parent_service_inputs_sha256']
 need(enc(reverse,styles['shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json'])==originals['shared/PHONE-SERVICE-INPUTS-v150-r10-r1.json'],'service exact inverse')
 reverse=copy.deepcopy(next_config);reverse['service_manifest_sha256']=config['service_manifest_sha256']
 need(enc(reverse,styles['shared/local-config-r10-r1.json'])==originals['shared/local-config-r10-r1.json'],'config exact inverse')
 for new,old,names in ((next_seal,seal,('configuration','phone_service_inputs_sha256','production_files')),
  (next_combo,combo,('configuration','service_inputs','source_seal','production_files')),
  (next_shared,shared,('files','parent_configuration_sha256','parent_service_inputs_sha256','source_input_sha256'))):
  reverse=copy.deepcopy(new)
  for k in names:reverse[k]=old[k]
  need(reverse==old,'complete material inverse')
 for row in list(BOOK.values()):read({k:row[k]for k in ('path','bytes','sha256')})
 out=Path(request['output_dir']);need(out.is_absolute()and out.parent.resolve(strict=True)==out.parent and not os.path.lexists(out),'fresh canonical host output')
 need(out!=BASE and BASE not in out.parents,'historical frozen component cannot be an output')
 source_parents=[Path(r['path']).parent for r in candidates.values()]
 need(all(out!=p and p not in out.parents for p in source_parents),'candidate input cannot be an output parent')
 files.update({'reference/'+name.replace('/','__'):raw for name,raw in originals.items()})
 result={'schema':'hepta.reviewed-source-material-derivation.v1','state':'DERIVED_SHARED_SOURCE_MATERIAL_ONLY',
  'builder':pin(ownraw),'input_originals':list(BOOK.values()),'changed_sources':changed,'source_count':15,
  'daily_dependency_count':14,'shared_member_count':17,'all_original_inputs_reread':True,
  'exact_object_inverses_verified':True,'combination':pin(combo_raw),'source_seal':pin(seal_raw),
  'configuration':pin(config_raw),'service_inputs':pin(service_raw),'shared_manifest':pin(files['shared/SHARED-MATERIALS.json']),
  'actual_cleanup_closure_bound':False,'runtime_freeze':False,'root_plan_generated':False,'native_history_rebased':False,
  'actual_BUILD':False,'actual_install':False,'actual_READY':False,'phone_calls':0,'new_nonces':0,'fixed19_credit':0,
  'remaining':'Reviewed runtime/history/preparer/builder/reader propagation and actual same-tuple component/physical evidence',
  'files':[{'path':name,**pin(raw)}for name,raw in sorted(files.items())]}
 files['DERIVATION.json']=enc(result)
 publish_material(out,files)
 print(json.dumps({'state':result['state'],'result':desc(out/'DERIVATION.json',files['DERIVATION.json']),
  'changed_sources':changed,'combination':result['combination'],'phone_calls':0,'runtime_freeze':False,'actual_BUILD':False},sort_keys=True))
if __name__=='__main__':main()
