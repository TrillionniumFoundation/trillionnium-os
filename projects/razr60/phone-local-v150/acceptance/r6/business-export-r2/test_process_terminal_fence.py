#!/usr/bin/env python3
"""One host-only nonzero-child/raw-PASS rejection scenario; never calls a phone."""
from pathlib import Path
import ast,hashlib,importlib.util,json,os,subprocess,sys
sys.dont_write_bytecode=True
D=Path(__file__).resolve().parent
V=D/'validation'/'nonzero-pass-02'
V.mkdir(mode=0o700,parents=True,exist_ok=False)
for name in ('export_business_once.py','capture_business_originals.py','read_archive_chunk.py'):
 ast.parse((D/name).read_bytes(),filename=name)
spec=importlib.util.spec_from_file_location('new_business_export',D/'export_business_once.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
r=subprocess.run([sys.executable,'-I','-c',
 "import json,sys;print(json.dumps({'proof_complete':True,'complete_business_success':True,'task_classification':'complete_success'}));sys.exit(7)"],
 capture_output=True,timeout=5)
assert r.returncode==7 and not r.stderr
raw_report=m.strict(r.stdout)
assert raw_report=={'proof_complete':True,'complete_business_success':True,'task_classification':'complete_success'}
collector_flags=m.final_qualification(True,r.returncode,raw_report)
assert collector_flags=={'proof_complete':False,'complete_business_success':False,'task_classification':'unconfirmed_collector_process'}
bound={'nonce':'a'*32,'owner_request_sha256':hashlib.sha256(b'synthetic-host-only-owner').hexdigest()}
label='business-r6-'+bound['nonce']+'-capture'
# The synthetic raw stdout stays PASS while its actual child's nonzero exit is retained.
original={'actor_rc':0,'wrapper':{'phone':{'rc':r.returncode,'stdout':r.stdout.decode()}}}
original_raw=m.json_bytes(original)
m.put(V/(label+'.original-operation.json'),original_raw)
m.put(V/'CAPTURE-RESULT.json',r.stdout)
m.writej(V/'CAPTURE-TERMINAL.json',{'schema':'hepta.business-capture-process-terminal.v150.r6.2',
 'nonce':bound['nonce'],'owner_request_sha256':bound['owner_request_sha256'],'operation_label':label,
 'original_operation_sha256':m.sha(original_raw),'capture_result_sha256':m.sha(r.stdout),
 'phone_process_rc':r.returncode,'actor_rc':0,'capture_process_completed_zero':False})
capture_zero=m.capture_terminal_zero(V,bound)
assert capture_zero is False
capture_flags=m.final_qualification(capture_zero,0,raw_report)
assert capture_flags=={'proof_complete':False,'complete_business_success':False,'task_classification':'unconfirmed_original_capture'}
report={'schema':'hepta.business-process-terminal-fence.host-negative.v150.r6.2',
 'state':'PASS','scenario_count':1,
 'scenario':'actual nonzero host child with raw PASS must never qualify',
 'actual_synthetic_child_rc':r.returncode,'original_raw_PASS_flags_preserved':raw_report,
 'collector_nonzero_final_flags':collector_flags,'recorded_capture_nonzero_final_flags':capture_flags,
 'capture_terminal_read_from_original_wrapper':True,
 'phone_operations':0,'model_requests':0,'actual_task_nonce_generation':0,
 'old_r1_broad_checks_repeated':False,'business_qualification_credit':0,
 'source_sha256':hashlib.sha256((D/'export_business_once.py').read_bytes()).hexdigest()}
raw=m.json_bytes(report);m.put(V/'RESULT.json',raw)
print(json.dumps({'state':'PASS','scenario_count':1,'bytes':len(raw),'sha256':m.sha(raw),
 'report':str(V/'RESULT.json'),'phone_operations':0,'model_requests':0},sort_keys=True))
