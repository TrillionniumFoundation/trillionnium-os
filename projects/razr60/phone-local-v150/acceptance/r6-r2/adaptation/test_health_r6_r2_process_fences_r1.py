#!/usr/bin/env python3
"""One synthetic host process fault for the new health process-terminal fences."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,types
B=Path('/operator-workspace/razr60/phone-local-v150')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def put(p,raw):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def main():
 p=argparse.ArgumentParser();p.add_argument('--source-sha256',required=True);a=p.parse_args()
 os.umask(0o077)
 path=B/'health-r6-r2-original-export-r1/export_health_r6_once.py'
 raw=path.read_bytes();assert sha(raw)==a.source_sha256
 m=types.ModuleType('synthetic_host_health_fences');m.__file__=str(path)
 exec(compile(raw,str(path),'exec'),m.__dict__)
 out=B/'acceptance-r6-r2-adaptation-r1/validation/health-nonzero-pass-01'
 out.parent.mkdir(mode=0o700,exist_ok=True);out.mkdir(mode=0o700)
 process=subprocess.run([sys.executable,'-I','-c',
  "import json,sys;print(json.dumps({'health_qualification_pass':True,'proof_complete':True,'task_classification':'health_pass'}));sys.exit(7)"],
  capture_output=True,timeout=5)
 put(out/'synthetic-child.stdout',process.stdout);put(out/'synthetic-child.stderr',process.stderr)
 assert process.returncode==7 and process.stderr==b''
 report=json.loads(process.stdout);assert report['health_qualification_pass'] is True
 checks=[]
 for label,actor_rc,phone_rc,collector_rc,expected in (
  ('positive_control',0,0,0,True),
  ('actor_nonzero_raw_pass',process.returncode,0,0,False),
  ('phone_nonzero_raw_pass',0,process.returncode,0,False),
  ('collector_nonzero_raw_pass',0,0,process.returncode,False)):
  case=out/label;case.mkdir(mode=0o700);m.E=case
  capture=enc({'scope':'synthetic_host_process_fence_only','no_actual_phone_originals':True})
  operation=enc({'actor_rc':actor_rc,'wrapper':{'phone':{'rc':phone_rc,'stdout':capture.decode()}}})
  put(case/'ACTUAL-CAPTURE-01.json',capture)
  put(case/(m.OP+'.original-operation.json'),operation)
  original_zero=type(actor_rc) is int and actor_rc==0 and type(phone_rc) is int and phone_rc==0
  terminal={'schema':'hepta.health-capture-process-terminal.v150.r6.2','operation_label':m.OP,
   'original_operation_sha256':sha(operation),'capture_sha256':sha(capture),
   'phone_process_rc':phone_rc,'actor_rc':actor_rc,'capture_process_completed_zero':original_zero}
  put(case/'CAPTURE-TERMINAL.json',enc(terminal))
  complete=m.capture_terminal_zero()
  result=m.final_health_qualification(complete,collector_rc,report)
  assert result['health_qualification_pass'] is expected and result['proof_complete'] is expected
  if not expected:assert result['task_classification'] in ('unconfirmed_collector_process','unconfirmed_original_capture')
  checks.append({'case':label,'actor_rc':actor_rc,'phone_rc':phone_rc,'collector_rc':collector_rc,
   'capture_process_zero':complete,'final':result,'expected_predicate':expected,'passed':True})
 value={'schema':'hepta.synthetic-health-process-fence-test.v1','state':'PASS',
  'source_sha256':sha(raw),'actual_synthetic_child_rc':process.returncode,
  'actual_synthetic_child_raw_pass':True,'one_actual_host_fault_scenario':True,
  'fence_positions_rejected':3,'positive_control_count':1,'checks':checks,
  'phone_calls':0,'model_calls':0,'task_nonces_generated':0,'qualification_credit':0,
  'scope':'Host-only synthetic records; proves process exit conjunction, not phone/runtime health'}
 put(out/'RESULT.json',enc(value));print(json.dumps({'result':str(out/'RESULT.json'),
  'sha256':sha((out/'RESULT.json').read_bytes()),'passed':True,'phone_calls':0,'nonce_generated':False}))
if __name__=='__main__':main()
