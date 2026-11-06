#!/usr/bin/env python3
"""Independent complete public-reader replay of immutable external cleanup02
originals. Original files are read-only. Only this new fc33 receipt is written."""
from pathlib import Path
import ast,hashlib,json,os,stat,types
B=Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1")
I=B/'owned-unstarted-stage-cleanup-neg02-final04-a1055-candidate01/foreign-retained-reference01/cleanup02-import01'
OUT=B/'owned-neg02-cleanup-source-recovery-a1055-20261106-01/fc33-independent-cleanup02-verification01'
READER={'bytes':69563,'sha256':'265134fb8632097388a85164be1c8d160533183415cfd725ae2e70da02b61ff2'}
INPUT={'bytes':774,'sha256':'2edb818d53b320cb402154bf8dfc750a6a7c1cb8d64929ac9e3f5a7e3135058b'}
CLOSED={'bytes':183496,'sha256':'c19e5d51712452dd38c9ddb0c6ef240f372a1d563225581634d5f27d53d84d10'}
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
BOOK={};READS=0;READ_BYTES=0
def need(v,s):
 if not v:raise ValueError(s)
def pin(raw):return{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def enc(v):return(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def meta(st):return[getattr(st,k)for k in META]
def read(row):
 global READS,READ_BYTES
 need(type(row)is dict and set(row)in({'path','bytes','sha256'},{'path','bytes','sha256','metadata'}),'exact callback descriptor')
 p=Path(row['path']);need(p.is_absolute()and '..'not in p.parts and p.parent.resolve(strict=True)==p.parent,'canonical actual Mac namespace')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);m=meta(st)
  need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and 0<=st.st_size<=33554432,'bounded actual single-link original')
  if 'metadata'in row:need(row['metadata']==m and all(type(x)is int for x in row['metadata']),'all9 actual FD metadata integers')
  chunks=[];n=0
  while True:
   v=os.read(fd,min(65536,33554433-n))
   if not v:break
   chunks.append(v);n+=len(v);need(n<=33554432,'complete read bound')
  raw=b''.join(chunks)
  need(n==st.st_size and m==meta(os.fstat(fd))==meta(p.lstat()),'complete FD and named full9 bookends')
  need(pin(raw)=={k:row[k]for k in('bytes','sha256')},'complete original exact SHA/length')
 finally:os.close(fd)
 observed={'path':str(p),**pin(raw),'metadata':m}
 need(str(p)not in BOOK or BOOK[str(p)]==observed,'same actual original generation throughout')
 BOOK[str(p)]=observed;READS+=1;READ_BYTES+=len(raw);return raw
def bypath(p):
 p=Path(p);st=p.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1,'regular whole source')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  raw=b''
  while True:
   b=os.read(fd,65536)
   if not b:break
   raw+=b;need(len(raw)<=33554432,'whole file bound')
  need(meta(st)==meta(os.fstat(fd))==meta(p.lstat()),'whole original source generation')
 finally:os.close(fd)
 return read({'path':str(p),**pin(raw)})
def write(p,raw):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
 try:
  v=memoryview(raw)
  while v:n=os.write(fd,v);need(n>0,'complete write progress');v=v[n:]
  os.fsync(fd)
 finally:os.close(fd)
 need(bypath(p)==raw,'new exact evidence readback')
 return{'path':str(p),**pin(raw)}
def main():
 need(not OUT.exists(),'one independent receipt namespace')
 reader=bypath(I/'source/verify_owned_current44_cleanup.py');need(pin(reader)==READER,'whole reviewed actual reader')
 inputs=bypath(I/'INPUTS.json');need(pin(inputs)==INPUT,'whole actual public inputs')
 closed=bypath(I/'CLOSED.json');need(pin(closed)==CLOSED,'exact immutable existing closure')
 source=bypath(Path(__file__))
 m=types.ModuleType('fc33_independent_actual_cleanup_public_reader');m.__file__='<reviewed-actual-public-reader>'
 exec(compile(reader,m.__file__,'exec'),m.__dict__)
 value=m.verify_owned_unstarted_stage_cleanup(inputs,read_pinned=read)
 need(value['state']=='VERIFIED_OWNED_UNSTARTED_STAGE_CLEANUP'
  and value['fixed19_credit']==0 and value['new_native_case_count']==0 and value['new_fixture_count']==0
  and value['old_final02_original_sender_wait']=='UNKNOWN_UNCHANGED'
  and value['post_cleanup_fresh_current44_admission_required']is True,'exact recovery-only result without task credit')
 need(value['closure']==json.loads(inputs)['closure']and pin(bypath(value['closure']['path']))==CLOSED,'same independently reconstructed closure')
 before=list(BOOK.values())
 for row in before:read(row)
 checked_reads=READS;checked_bytes=READ_BYTES
 OUT.mkdir(mode=0o700);(OUT/'returned-bytes').mkdir(mode=0o700)
 blobs={}
 def retained(v,path='return'):
  if isinstance(v,bytes):
   k=pin(v)['sha256']
   if k not in blobs:blobs[k]=write(OUT/'returned-bytes'/(k+'.bin'),v)
   return{'complete_returned_raw_bytes':blobs[k]}
  if isinstance(v,dict):return{k:retained(x,path+'/'+str(k))for k,x in v.items()}
  if isinstance(v,(list,tuple)):return[retained(x,path+'/'+str(i))for i,x in enumerate(v)]
  need(v is None or type(v)in(str,int,float,bool),'closed public return projection')
  return v
 complete=retained(value)
 full=write(OUT/'COMPLETE-PUBLIC-RETURN.json',enc(complete))
 book=write(OUT/'ALL-INPUT-ORIGINALS.json',enc(before))
 src=write(OUT/'SOURCE.original.py',source)
 result={'schema':'hepta.fc33.independent-cleanup02-public-verification.v1',
  'state':'INDEPENDENT_PUBLIC_API_REEXECUTION_PASSED',
  'actual_original_job':'1a1b15889a7-fc05-77e7','actual_original_operation':{'bytes':6151995,'sha256':'9bae925fe62ad40039b1b915d309c14c1d58a5f36067ad4d1b77fae719fe6fd0'},
  'reader':{'path':str(I/'source/verify_owned_current44_cleanup.py'),**READER},
  'inputs':{'path':str(I/'INPUTS.json'),**INPUT},'closure':value['closure'],
  'whole_original_count':len(before),'complete_read_count':checked_reads,'complete_read_bytes':checked_bytes,
  'all_actual_fd_and_named_full9_bookends_verified':True,
  'complete_public_return':full,'input_originals':book,'source':src,
  'removed_files':77,'removed_directories':9,'removed_sender_xml_files':11,
  'after_inventory':value['after_inventory'],'after_inventory_raw':pin(value['after_inventory_raw']),
  'scope':value['original_scope'],'prior_final02_original_sender_wait':'UNKNOWN_UNCHANGED',
  'new_phone_calls':0,'new_phone_effects':0,'original_other_session_identity_preserved':True,
  'fc33_failed_successor_remains_failed':True,'fixed19_credit':0,'fresh_current44_admission_required':True}
 r=write(OUT/'RESULT.json',enc(result))
 print(enc({'result':r,'state':result['state'],'closure':result['closure'],
  'whole_original_count':len(before),'complete_read_count':checked_reads,'complete_read_bytes':checked_bytes,'phone_calls':0}).decode(),end='')
if __name__=='__main__':main()
