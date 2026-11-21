#!/usr/bin/env python3
"""Private captured-history mutation gate; no device connection or side effects.

The external 23-original map stays private. The public test is parameterized and
cannot run without it. The legacy synthetic policy/client gate is genuinely run
against this source, then the v3 test uses those exact compiled classes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
sys.dont_write_bytecode = True

JSON_SHA = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
PINS = {
 'src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceRecovery.java':'9589fc95295e4a44bc5222dc56390aa1361091a78f8e3d2fd5b1285785e93f17',
 'src/org/trillionnium/hepta/local/PublicPersonalNotesRecoveryClient.java':'110a08a85c810b24169fc33ff241544f979f1d6534dff44899c1eb1c93ff9965',
 'src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceMain.java':'cb2d44b73c27bc991fc8276704867081fc7887f471987b9efdf33169c1e9cb41',
 'src/org/trillionnium/hepta/background/ProfileRecoveryProcesses.java':'9fd0453f33c93094e6ace8fdcdcbb959d47cbac480b2e5f1bbfe03a29a987dc9',
 'src/org/trillionnium/hepta/local/WorkerGenerationProof.java':'38dcc6d07d9d9dcbd49497f4974661df81f2acfc22f2e093c87fb6fed1a00e19',
 'tests/personal-notes-absence/run_host.py':'2866dad5e1619456e756a29130828d552fdf106a584754c0c2bbf990f5c16e48',
}
PARENTS = {
 'src/org/trillionnium/hepta/background/PublicPersonalNotesAbsenceRecovery.java':'ff398845fec920062049e7ba5212b7be7502b2e2470b1aff3f82969bd26d9400',
 'src/org/trillionnium/hepta/local/PublicPersonalNotesRecoveryClient.java':'4401796504d20698aa8536a5be07aa67ef33ee8c3661bf17f8a3c9c45fc8b087',
}
RECOVERY_METHODS = (
 'private void requireDrainedBootstrap(', 'private void requireDrainedModel(', 'private void requireNormalModelClose(',
 'private int notesCustody(', 'private void requireSelection(', 'private void bindBackground(', 'private void requireBroker(',
 'private void requireBootstrapPrefix(', 'public void requireFence(', 'public JSONObject recordedOwnedIdentity(',
 'public static JSONObject validate(')
CLIENT_METHODS = (
 'void persist(', 'private static void createOrRequireExact(', 'void requirePersisted(', 'void requireLease(', 'JSONObject evidence(',
 'private static void requireTaskEntries(File task,boolean postModel)', 'private static void collectDrainedOriginals(',
 'static void requireDrainedGeneration(', 'private static void recordFailedAttempt(', 'private static File existingDirectory(')
ROLES = set(('journal owner bootstrap cleanup result broker_receipt broker_output step_model step_action fixed_intent_attempt '
 'model_request_receipt model_session_receipt native_session_receipt generation_identity generation_cleanup_receipt '
 'workflow_result workflow_grant child_1_action child_2_action child_1_proof child_2_proof completion_candidate completion_identity').split())

def need(ok, message):
 if not ok: raise RuntimeError(message)
def digest(raw): return hashlib.sha256(raw).hexdigest()
def read(path):
 path=Path(path);need(path.is_absolute() and path.resolve()==path,'absolute regular path required')
 with path.open('rb') as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,'regular single-link file required')
  raw=f.read();z=os.fstat(f.fileno())
 fields=lambda q:(q.st_dev,q.st_ino,q.st_size,q.st_mtime_ns,q.st_ctime_ns,q.st_mode,q.st_nlink)
 need(fields(a)==fields(z)==fields(path.lstat()) and len(raw)==a.st_size,'input changed during read')
 return raw
def pin(path, expected=None):
 raw=read(path);value={'path':str(path),'bytes':len(raw),'sha256':digest(raw)}
 need(expected is None or value['sha256']==expected,'source pin differs: '+str(path))
 return value
def pairs(rows):
 out={}
 for key,value in rows:
  need(key not in out,'duplicate JSON key');out[key]=value
 return out
def decode(raw):
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(RuntimeError('nonfinite JSON')))
def tree(root):
 rows={}
 for path in sorted(root.rglob('*')):
  need(not path.is_symlink(),'source symlink forbidden')
  if path.is_file():rows[path.relative_to(root).as_posix()]=digest(read(path))
 encoded=json.dumps(rows,sort_keys=True,separators=(',',':')).encode()
 return {'files':len(rows),'sha256':digest(encoded)}
def method(text, marker):
 need(text.count(marker)==1,'unique actual method marker required: '+marker)
 start=text.index(marker);brace=text.index('{',start);level=0;quote=None;escaped=False;line=False;block=False;i=brace
 while i<len(text):
  c=text[i];n=text[i+1] if i+1<len(text) else ''
  if line:
   if c=='\n':line=False
  elif block:
   if c=='*' and n=='/':block=False;i+=1
  elif quote:
   if escaped:escaped=False
   elif c=='\\':escaped=True
   elif c==quote:quote=None
  elif c=='/' and n=='/':line=True;i+=1
  elif c=='/' and n=='*':block=True;i+=1
  elif c in ('"',"'"):quote=c
  elif c=='{':level+=1
  elif c=='}':
   level-=1
   if level==0:return text[start:i+1].encode()
  i+=1
 raise RuntimeError('unterminated actual method')
def protected(source,parent):
 result=[]
 for relative,markers in ((next(iter(PARENTS)),RECOVERY_METHODS),(list(PARENTS)[1],CLIENT_METHODS)):
  old=read(parent/relative).decode();new=read(source/relative).decode()
  for marker in markers:
   a,b=method(old,marker),method(new,marker);need(a==b,'protected method changed: '+marker)
   result.append({'source':relative,'method':marker,'sha256':digest(b),'bytes_unchanged':True})
 for relative in list(PINS)[2:5]:
  need(read(source/relative)==read(parent/relative),'protected full producer changed')
  result.append({'source':relative,'whole_file_unchanged':True,'sha256':PINS[relative]})
 need(len(result)==24,'complete protected producer set required');return result
def input_map(path):
 manifest=decode(read(path));rows=manifest['rows'];refs={};total=0
 for row in rows:
  role=row['role'];need(role not in refs,'duplicate map role')
  ref=pin(Path(row['host_path']),row['sha256']);need(ref['bytes']==row['bytes'],'captured bytes differ')
  refs[role]=ref
  if role!='current_control':total+=ref['bytes']
 need(set(refs)==ROLES|{'current_control'} and total<=262144,'exact bounded 23-original map required')
 return refs
def run(stage,argv,out,result,env,timeout=240):
 (out/(stage+'.command.json')).write_text(json.dumps(argv,indent=2)+'\n')
 start=time.monotonic();proc=subprocess.run(argv,capture_output=True,env=env,timeout=timeout)
 (out/(stage+'.stdout')).write_bytes(proc.stdout);(out/(stage+'.stderr')).write_bytes(proc.stderr)
 result['stages'].append({'stage':stage,'exit_code':proc.returncode,'seconds':time.monotonic()-start,
  'stdout_sha256':digest(proc.stdout),'stderr_sha256':digest(proc.stderr)})
 need(proc.returncode==0 and proc.stderr==b'','stage failed or produced stderr: '+stage)
 return proc.stdout

def main():
 parser=argparse.ArgumentParser()
 for name in ('source','parent-source','java-home','json-jar','private-input-map','output'):
  parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args();source=args.source.resolve();parent=args.parent_source.resolve();out=args.output.resolve()
 out.mkdir(parents=True,exist_ok=False)
 own=source/'tests/notes-workflow-close-recovery';env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
 jdk=args.java_home.resolve()/'bin';jars=args.json_jar.resolve()
 result={'schema':'hepta.notes-workflow-close-recovery-host-validation.v1','all_pass':False,'phone_operations':0,
  'private_actual_history_inputs':True,'authored_negative_mutations':True,'controller_and_clock_fixtures':True,
  'portable_without_private_inputs':False,'current_absence_claimed':False,'business_success_claimed':False,
  'stages':[]}
 before=tree(source);parent_refs={str(parent/p):pin(parent/p,h) for p,h in PARENTS.items()}
 refs=input_map(args.private_input_map.resolve());map_ref=pin(args.private_input_map.resolve())
 tools={str(p):pin(p) for p in (jdk/'java',jdk/'javac',jars)};need(tools[str(jars)]['sha256']==JSON_SHA,'pinned JSON required')
 source_inputs={str(source/p):pin(source/p,h)['sha256'] for p,h in PINS.items()}
 for path in (own/'NotesWorkflowCloseRecoveryHostTest.java',own/'run_host.py',own/'README.md'):
  source_inputs[str(path)]=pin(path)['sha256']
 result.update(source_inputs=source_inputs,parent_inputs=parent_refs,tool_inputs=tools,input_map=map_ref,
  private_originals=refs,protected_producers=protected(source,parent),source_tree_before=before)
 try:
  run('legacy',[sys.executable,str(source/'tests/personal-notes-absence/run_host.py'),'--source',str(source),
      '--java-home',str(args.java_home.resolve()),'--json-jar',str(jars),'--output',str(out/'legacy')],out,result,env)
  legacy_path=out/'legacy/RESULT.json';legacy=decode(read(legacy_path))
  need(legacy['all_pass'] is True and legacy['inputs_unchanged'] is True and legacy['strict_release8'] is True
   and len(legacy['stages'])==6 and all(s['exit_code']==0 for s in legacy['stages']),'genuine retained legacy gate required')
  for path,digest_value in legacy['source_inputs'].items():
   if Path(path).is_relative_to(source):
    need(pin(Path(path))['sha256']==digest_value,'legacy actual source pin differs');source_inputs[path]=digest_value
  result['retained_legacy_result']=pin(legacy_path)
  result['retained_legacy_counts']={key:{'cases':legacy[key].get('cases'),'assertions':legacy[key].get('assertions')}
    for key in ('policy','display-census','client','post-model')}
  classes=out/'legacy/client-classes';cp=str(classes)+os.pathsep+str(jars)
  run('compile',[str(jdk/'javac'),'--release','8','-Xlint:all,-options','-Werror','-encoding','UTF-8','-proc:none',
     '-cp',cp,'-d',str(classes),str(own/'NotesWorkflowCloseRecoveryHostTest.java')],out,result,env)
  raw=run('workflow',[str(jdk/'java'),'-cp',cp,'org.trillionnium.hepta.local.NotesWorkflowCloseRecoveryHostTest',
      str(args.private_input_map.resolve()),str(out/'mutation-scratch')],out,result,env)
  result['workflow']=decode(raw)
  need(result['workflow']['all_pass'] is True and result['workflow']['original_byte_preservation'] is True,'new workflow gate failed')
  result['all_pass']=True
 except Exception as error:
  result['error']=type(error).__name__+': '+str(error)
 finally:
  result['source_tree_after']=tree(source)
  result['inputs_unchanged']=before==result['source_tree_after'] and all(pin(Path(p))['sha256']==h for p,h in source_inputs.items())
  result['parent_inputs_unchanged']=all(pin(Path(p))==v for p,v in parent_refs.items())
  result['tool_inputs_unchanged']=all(pin(Path(p))==v for p,v in tools.items())
  result['original_byte_preservation']=refs==input_map(args.private_input_map.resolve()) and map_ref==pin(args.private_input_map.resolve())
  result['all_pass']=result['all_pass'] and result['inputs_unchanged'] and result['parent_inputs_unchanged'] and result['tool_inputs_unchanged'] and result['original_byte_preservation']
  (out/'RESULT.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'all_pass':result['all_pass'],'result':str(out/'RESULT.json'),'stages':result['stages'],'error':result.get('error')}))
 return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
