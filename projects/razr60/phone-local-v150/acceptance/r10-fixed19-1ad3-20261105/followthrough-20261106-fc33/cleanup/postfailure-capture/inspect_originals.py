#!/usr/bin/env python3
"""Host-only exact-original analysis of an already-ended read-only capture.
No phone action, imported source execution, subprocess, network, signal or deletion.
Creates one new P4 host evidence directory; old requests/operations remain untouched.
"""
from pathlib import Path
import ast,base64,hashlib,io,json,lzma,os,shlex,stat,sys,tarfile,zlib
B=Path('/home/alex/razr60-local-model-v150')
OLD='ng-a1055-neg02-final04-owned-cleanup01'
NEW='ng-a1055-neg02-final04-postfailure-capture01'
OUT=B/'postfailure-capture01-host-analysis-fc33'
MAX_FILE=16*1024*1024
MAX_TOTAL=32*1024*1024
BOOK={}
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
PINS={
'old_request':(63196,'af2addbc79a4936f9a89becb42c017a4c177fbce7178b8eedf30b729f0288888'),
'failed_operation':(68538,'aae928ae0493966f92684f94cf56e30f409c3932ec8fd690f4ba99ff49800937'),
'fresh_request':(35404,'43d243d1ccd59e357bbcc08d1343eeb91757f159f859f6503f91217e9d934e09'),
'capture_source':(89241,'e6f1562d9e887137958eaeecb8aec647c4601ac4796c33656a7aaf58985daa34'),
'capture_binding':(42253,'3d716252466d6afe1d582047b221816394bf5740399ade9da0b9678da6002056'),
'cleanup_source':(57090,'dfa9ffbde578dbd262ac03c802fa809cb8beb8432e9c10c1dc2b485b891f6329'),
'cleanup_binding':(277171,'8362481fc74494bc99f50d2f130c19d86fce5834df63ce599d41ecb4b41a901f'),
'targets':(102119,'c8e5b1b5a928ddba858a9c2a2ede1cba16e04cf98b456eeb073e5d951617403d'),
'old_map':(119467,'be8976a2f324454c49f5b8aa4aff978c925662eb15a6900c023773c281aeab96')}
FRESH_SHA='cb5b6619d8b7e58f7520aa40d6961f3d208911493ccc6bf8d0abf7aae09f9ba2'
ENV='/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B -c '
def need(v,why):
 if not v:raise ValueError(why)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def match(raw,name):need((len(raw),hashlib.sha256(raw).hexdigest())==PINS[name],'exact original '+name)
def enc(v):return(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict(raw):
 def pairs(v):
  d={}
  for k,x in v:need(k not in d,'duplicate JSON key');d[k]=x
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def meta(s):return[getattr(s,k)for k in META]
def read(p,sha=None):
 p=Path(p);need(p.is_absolute()and p.parent.resolve(strict=True)==p.parent,'canonical P4 host original parent')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=MAX_FILE,'bounded single-link original')
  chunks=[];n=0
  while True:
   v=os.read(fd,min(65536,MAX_FILE+1-n))
   if not v:break
   chunks.append(v);n+=len(v);need(n<=MAX_FILE,'complete original read bound')
  raw=b''.join(chunks)
  need(len(raw)==s.st_size and meta(s)==meta(os.fstat(fd))==meta(p.lstat()),'complete original bytes/full9 bookends')
  if sha:need(pin(raw)['sha256']==sha,'expected original SHA256')
 finally:os.close(fd)
 row={'path':str(p),**pin(raw),'metadata':meta(s)}
 need(str(p)not in BOOK or BOOK[str(p)]==row,'stable original on reread')
 BOOK[str(p)]=row
 return raw
def b85_literal(command):
 inline=shlex.split(command)[-1]
 need(ENV+shlex.quote(inline)==command,'exact unchanged chroot environment and quoting')
 tree=ast.parse(inline)
 calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)
  and isinstance(n.func.value,ast.Name)and n.func.value.id=='base64'and n.func.attr=='b85decode']
 need(len(calls)==1 and len(calls[0].args)==1 and not calls[0].keywords,'one exact embedded base85 payload')
 value=ast.literal_eval(calls[0].args[0]);need(type(value)is str and len(value)<=100000,'bounded payload literal')
 return inline,value
def jdiff(a,b,path=''):
 if type(a)is not type(b):return[{'path':path,'kind':'type','old_type':type(a).__name__,'fresh_type':type(b).__name__,'old':a,'fresh':b}]
 if isinstance(a,dict):
  out=[]
  for k in sorted(set(a)|set(b)):
   p=path+'/'+str(k).replace('~','~0').replace('/','~1')
   if k not in a or k not in b:out.append({'path':p,'kind':'field_presence','old_present':k in a,'fresh_present':k in b,'old':a.get(k),'fresh':b.get(k)})
   else:out.extend(jdiff(a[k],b[k],p))
  return out
 if isinstance(a,list):
  if a==b:return[]
  if path.endswith('/metadata')and len(a)==len(b)==9 and all(type(x)is int for x in a+b):
   changed={META[i]:{'old_decimal':str(x),'fresh_decimal':str(y)}for i,(x,y)in enumerate(zip(a,b))if x!=y}
   return[{'path':path,'kind':'full9','old':a,'fresh':b,'changed':changed}]
  if all(type(x)is str for x in a+b):
   return[{'path':path,'kind':'names','old_count':len(a),'fresh_count':len(b),'removed':sorted(set(a)-set(b)),'added':sorted(set(b)-set(a)),'order_equal':a==b}]
  if len(a)!=len(b):return[{'path':path,'kind':'length','old':len(a),'fresh':len(b)}]
  out=[]
  for i,(x,y)in enumerate(zip(a,b)):out.extend(jdiff(x,y,path+'/'+str(i)))
  return out
 return[] if a==b else[{'path':path,'kind':'value','old':a,'fresh':b}]
def write(p,raw):
 need(type(raw)is bytes and p.parent.resolve(strict=True)==p.parent,'exact output bytes/canonical parent')
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  view=memoryview(raw)
  while view:
   n=os.write(fd,view);need(n>0,'write progress');view=view[n:]
  os.fsync(fd)
 finally:os.close(fd)
 need(read(p)==raw,'complete retained output readback')
 return{'path':str(p),**pin(raw)}
def main():
 need(not OUT.exists(),'one create-only host diagnostic namespace')
 oldreqraw=read(B/'requests'/(OLD+'.json'));match(oldreqraw,'old_request');oldreq=strict(oldreqraw)
 failedraw=read(B/'operations'/OLD/'result.json');match(failedraw,'failed_operation');failed=strict(failedraw)
 need(failed['status']=='command_exited'and failed['phone']['rc']==1 and failed['phone']['stdout']=='','actual failed phone original')
 failure=strict(failed['phone']['stderr'].encode())
 need(failure['phase']=='same_locked_original_capture_preflight'and failure['durable_intent']is None
  and failure['durable_result']is None and failure['completed_removal_count']==0
  and failure['completed_removed_paths']==[],'actual zero-recorded-effect preflight refusal')
 _oldinline,xzlit=b85_literal(oldreq['command']);xz=base64.b85decode(xzlit)
 need(pin(xz)=={'bytes':44636,'sha256':'b7fd363b41812ca1fbfad30ea3bcc05b1668e2a20a74b132badbaeeaed193b83'},'original frozen cleanup XZ')
 xd=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=16777216);xr=xd.decompress(xz,max_length=1048577)
 need(len(xr)<=1048576 and xd.eof and not xd.unused_data,'one bounded exact cleanup XZ')
 wrapper,payload=xr.split(b'\0',1)
 expected=b"import json,types\nv=json.loads(BINDING_RAW);s=v['source'].encode();r=v['binding'].encode();c=v['capture_source'].encode()\nm=types.ModuleType('owned_stage_cleanup');exec(compile(s,'<owned_stage_cleanup>','exec'),m.__dict__)\nraise SystemExit(m.main(r,s,c))\n"
 need(wrapper==expected,'exact original one-call cleanup wrapper decoded as data, never executed')
 payload=strict(payload);need(set(payload)=={'binding','source','capture_source'},'complete original three-field payload')
 cleanup_source=payload['source'].encode();boundraw=payload['binding'].encode();capsource=payload['capture_source'].encode()
 match(cleanup_source,'cleanup_source');match(boundraw,'cleanup_binding');match(capsource,'capture_source')
 bound=strict(boundraw);qraw=bound['capture_request_raw'].encode();targetsraw=bound['owned_targets_raw'].encode();oldmapraw=bound['original_map_raw'].encode()
 match(qraw,'capture_binding');match(targetsraw,'targets');match(oldmapraw,'old_map')
 targets=strict(targetsraw);oldmap=strict(oldmapraw);oldrows={r['path']:r for r in oldmap['files']}
 need(len(oldrows)==len(oldmap['files'])==192 and len(targets['files'])==77 and len(targets['directories'])==9,'exact preserved 192/77/9')
 freshreqraw=read(B/'requests'/(NEW+'.json'));match(freshreqraw,'fresh_request');req=strict(freshreqraw)
 need(req['kind']=='shell'and req['root']is True and req['timeout_seconds']==70,'unchanged readonly actor request')
 inline,zlit=b85_literal(req['command']);zd=zlib.decompressobj();zr=zd.decompress(base64.b85decode(zlit),1048577)
 need(len(zr)<=1048576 and zd.eof and not zd.unused_data and not zd.unconsumed_tail,'complete bounded original zlib payload')
 zp=strict(zr);need(set(zp)=={'source','request'}and zp['source'].encode()==capsource and zp['request'].encode()==qraw,'complete original readonly source/request byte equality')
 template="import base64,json,types,zlib;v=json.loads(zlib.decompress(base64.b85decode("+repr(zlit)+")));s=v['source'].encode();r=v['request'].encode();m=types.ModuleType('owned_stage_capture');exec(compile(s,'<owned_stage_capture>','exec'),m.__dict__);raise SystemExit(m.main(r,s))"
 need(inline==template,'fixed single capture main wrapper')
 service=('shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(req['command'])).encode()
 need(len(service)+1==35506 and len(service)+1<=65535,'complete conservative wire including NUL')
 freshraw=read(B/'operations'/NEW/'result.json',FRESH_SHA);op=strict(freshraw)
 need(op['schema']=='hepta.phone-local.operator-result.v150.1'and op['label']==NEW and op['status']=='command_exited'
  and op['phone']['rc']==0 and op['phone']['stderr']==''and op['model_decision']is False
  and op['native_task_result']is False,'actual successful read-only operation')
 need(op['phone']['command']=='/debug_ramdisk/su -c '+shlex.quote(req['command']),'actual original readonly command equality')
 intentraw=read(B/'operations'/NEW/'intent.json');baseraw=read(B/'operations'/NEW/'baseline.json')
 intent=strict(intentraw);base=strict(baseraw)
 need(intent['request']==req and intent['request_sha256']==pin(freshreqraw)['sha256']and intent['automatic_replay']is False,'actual intent matches exact request')
 need(base['rc']==0 and base['stderr']=='','successful original baseline')
 packetraw=op['phone']['stdout'].encode();need(len(packetraw)<=8*1024*1024-65536,'unchanged complete stdout bound')
 packet=strict(packetraw)
 need(packet['schema']=='hepta.owned-unstarted-stage.phone-capture-result.v2'and packet['source']==pin(capsource)
  and packet['request']==pin(qraw)and packet['phone_file_writes']==0 and packet['cleanup_performed']is False,'actual readonly packet scope/source')
 compressed=base64.b64decode(packet['archive_base64'],validate=True)
 need(len(compressed)<=MAX_FILE and pin(compressed)==packet['archive'],'complete original archive')
 dec=zlib.decompressobj(31);plain=dec.decompress(compressed,MAX_TOTAL+1)
 need(len(plain)<=MAX_TOTAL and dec.eof and not dec.unused_data and not dec.unconsumed_tail and pin(plain)==packet['archive_plain'],'single complete bounded gzip')
 files={}
 with tarfile.open(fileobj=io.BytesIO(plain),mode='r:')as tar:
  for m in tar:
   name=Path(m.name)
   allowed=m.name in {'REQUEST.original.json','SOURCE.original.py','BEFORE-CLEANUP-INVENTORY.json','OBSERVATIONS.json','ORIGINALS.json'}or(
    len(name.parts)==2 and name.parts[0]=='originals'and len(name.name)==68 and name.name.endswith('.bin')and all(c in '0123456789abcdef'for c in name.stem))
   need(allowed and m.name not in files and m.isreg()and not m.pax_headers and m.uid==m.gid==0 and m.mode==0o600 and m.mtime==0 and 0<=m.size<=MAX_FILE,'exact original regular USTAR member')
   stream=tar.extractfile(m);raw=stream.read(m.size+1);need(len(raw)==m.size,'complete member bytes');files[m.name]=raw
 need(len(files)==packet['archive_member_count']and sum(map(len,files.values()))<=MAX_TOTAL,'complete bounded original family')
 canonical=io.BytesIO()
 with tarfile.open(fileobj=canonical,mode='w',format=tarfile.USTAR_FORMAT)as tar:
  for name,raw in sorted(files.items()):
   row=tarfile.TarInfo(name);row.mode=0o600;row.uid=row.gid=0;row.mtime=0;row.size=len(raw);tar.addfile(row,io.BytesIO(raw))
 need(canonical.getvalue()==plain,'no omitted or appended USTAR bytes')
 need(files['SOURCE.original.py']==capsource and files['REQUEST.original.json']==qraw,'actual archived exact source and capture binding')
 omap=strict(files['ORIGINALS.json']);obs=strict(files['OBSERVATIONS.json']);inv=strict(files['BEFORE-CLEANUP-INVENTORY.json'])
 need(pin(files['ORIGINALS.json'])==packet['original_map']and pin(files['OBSERVATIONS.json'])==packet['observations']
  and pin(files['BEFORE-CLEANUP-INVENTORY.json'])==packet['inventory'],'all original structured member pins')
 rows={r['path']:r for r in omap['files']};need(len(rows)==len(omap['files'])==192,'192 unique actual original paths')
 original_differences=[]
 need(set(rows)==set(oldrows),'same complete 192 original path set')
 for path,row in rows.items():
  raw=files[row['retained_member']];need(pin(raw)=={k:row[k]for k in('bytes','sha256')},'complete phone original bytes '+path)
  need(row['retained_member']=='originals/'+row['sha256']+'.bin','content addressed original member')
  need(type(row['metadata'])is list and len(row['metadata'])==9 and all(type(x)is int for x in row['metadata']),'exact integer full9')
  d=jdiff(oldrows[path],row)
  if d:original_differences.append({'phone_path':path,'differences':d})
 target_differences=[]
 for row in targets['files']:
  need(oldrows[row['path']]==row,'target exactly matched preserved original')
  d=jdiff(row,rows[row['path']])
  if d:target_differences.append({'phone_path':row['path'],'differences':d})
 pairs=[('stage_directories',targets['directories'],obs['stage_before']['directories']),
  ('stage_aliases',targets['aliases'],obs['stage_before']['aliases']),
  ('transport_parents',targets['transport_parents'],obs['transport_before']['parents']),
  ('sender_xml_parent',targets['sender_xml_parent'],obs['sender_xml_before']['parent']),
  ('sender_xml_before_vs_after',obs['sender_xml_before'],obs['sender_xml_after'])]
 comparisons=[{'name':name,'equal':a==b,'differences':jdiff(a,b)}for name,a,b in pairs]
 audit_names=['root-r10-neg02-a1055-final04.CLEANUP-INTENT.json','root-r10-neg02-a1055-final04.CLEANUP-RESULT.json']
 gnu='/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1'
 parent_samples=[next(p for p in obs[k]['parents']if p['path']==gnu)for k in('transport_before','transport_after')]
 audit_absent=all(all(name not in p['names']for name in audit_names)for p in parent_samples)
 need(len(obs['locks_before'])==len(obs['locks_after'])==14 and all(r['same_open_fd_held']is True for r in obs['locks_after']),'same14 existing locks before/after')
 source_raw=read(Path(__file__))
 for row in list(BOOK.values()):
  need(read(row['path'],row['sha256'])is not None,'original bookend')
 inputs=list(BOOK.values())
 diagnostics={'schema':'hepta.neg02.postfailure-fresh-capture-differences.v1',
  'state':'READ_ONLY_DIAGNOSIS_NOT_CLEANUP','failed_original':pin(failedraw),'fresh_original':pin(freshraw),
  'scope':bound['scope'],'old_target_manifest':pin(targetsraw),'old_original_map':pin(oldmapraw),
  'actual_original_map':pin(files['ORIGINALS.json']),'original_path_count':192,
  'original_differences':original_differences,'owned_target_count':77,'target_differences':target_differences,
  'five_comparisons':comparisons,'cleanup_audit_names':audit_names,'cleanup_audit_absent_in_two_complete_parent_censuses':audit_absent,
  'cleanup_audit_parent_samples':parent_samples,'same14_existing_lock_count':14,
  'failed_cleanup_reported_removals':failure['completed_removal_count'],'failed_cleanup_reported_intent':failure['durable_intent'],
  'failed_cleanup_reported_result':failure['durable_result'],'phone_mutations_by_this_program':0,
  'old_nonce_or_lease_changed':False,'owned_targets_expanded':False,'fixed19_credit':0}
 OUT.mkdir(mode=0o700)
 for name in ('packet','packet/originals'): (OUT/name).mkdir(mode=0o700)
 outputs={}
 primary={'SOURCE.original.py':source_raw,'INPUT-ORIGINALS.json':enc(inputs),'FAILED-OPERATION.original.json':failedraw,
  'FRESH-OPERATION.original.json':freshraw,'FRESH-INTENT.original.json':intentraw,'FRESH-BASELINE.original.json':baseraw,
  'FRESH-PHONE-REQUEST.original.json':freshreqraw,'ORIGINAL-CLEANUP-PHONE-REQUEST.original.json':oldreqraw,
  'PRESERVED-TARGETS.original.json':targetsraw,'PRESERVED-ORIGINAL-MAP.original.json':oldmapraw,
  'CAPTURE-PACKET.original.json':packetraw,'CAPTURE-ARCHIVE.original.tar.gz':compressed,'DIFFERENCES.json':enc(diagnostics)}
 for name,raw in sorted(primary.items()):outputs[name]=write(OUT/name,raw)
 member_rows=[]
 for name,raw in sorted(files.items()):member_rows.append(write(OUT/'packet'/name,raw))
 outputs['PACKET-ORIGINALS.json']=write(OUT/'PACKET-ORIGINALS.json',enc(member_rows))
 summaries=[]
 for c in comparisons:
  summaries.append({'name':c['name'],'equal':c['equal'],'difference_count':len(c['differences']),'differences':c['differences']})
 result={'schema':'hepta.neg02.postfailure-host-analysis.v1','state':'COMPLETE_READ_ONLY_DIAGNOSIS',
  'output':str(OUT),'inputs':inputs,'outputs':outputs,'archive_member_count':len(files),
  'all192_originals_exactly_equal':not original_differences,'all77_owned_targets_exactly_equal':not target_differences,
  'cleanup_audit_absent_in_two_complete_parent_censuses':audit_absent,
  'new_readonly_packet_complete':True,'five_comparisons':summaries,
  'readonly_source':pin(capsource),'readonly_capture_request':pin(qraw),'readonly_phone_request':pin(freshreqraw),
  'complete_service_with_nul_bytes':len(service)+1,'unchanged_service_limit':65535,
  'whole_capture_seconds':45,'actor_seconds':70,'source':pin(source_raw),
  'old_namespace_not_replayed':True,'new_phone_calls_by_this_host_program':0,'fixed19_credit':0}
 resultdesc=write(OUT/'RESULT.json',enc(result))
 d=os.open(OUT,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:os.fsync(d)
 finally:os.close(d)
 print(json.dumps({'result':resultdesc,'all192_originals_exactly_equal':not original_differences,
  'all77_owned_targets_exactly_equal':not target_differences,'cleanup_audit_absent':audit_absent,
  'five_comparisons':summaries,'archive_member_count':len(files),'source':pin(source_raw),
  'complete_service_with_nul_bytes':len(service)+1,'new_phone_calls':0},sort_keys=True))
if __name__=='__main__':main()
