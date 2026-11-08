#!/usr/bin/env python3
"""Actual-original pure R10 wiring controls; no phone or future case fixture."""
import ast,copy,hashlib,io,json,os,sys,tarfile,time,types,zlib
from pathlib import Path
sys.dont_write_bytecode=True
R=Path('/dev/shm/razr60-d39712953a2d-continuation-01')
W=Path('/workspace/scratch/d39712953a2d')
P=R/'r8-integration/r10-whole-development01'
PARENT=R/'p1-r9-preparation/r9-failure-host-export01/actual/pocket4-originals/originals/chain/material/tree/package'
R7=W/'r8-integration/development01/dependencies/retained-preaccept'
PKG=R/'r8-integration/r8-failed-retention-package02'
R9=R/'p1-r9-preparation/r9-retained-transport-package01'
def need(v,m):
 if not v:raise ValueError(m)
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def mod(b,n,p):
 m=types.ModuleType(n);m.__file__=str(p);exec(compile(b,str(p),'exec'),m.__dict__);return m
freeze=json.loads((R/'r9-actual/FREEZE-RESULT.original.json').read_bytes())
need(pin((R/'r9-actual/FREEZE-RESULT.original.json').read_bytes())=={'bytes':1460733,'sha256':'a931bdbce572b4a4a61d3ee89686fd453d99e28f9ded407bf76ceeec2beeba1d'},'actual parent freeze')
package=json.loads((P/'runtime/MANIFEST.json').read_bytes());sources={}
for row in package['files']:
 name=row['path']
 if (P/'runtime'/name).is_file():raw=(P/'runtime'/name).read_bytes()
 else:
  raw=(PARENT/name).read_bytes()
  need(pin(raw)=={k:freeze['files']['runtime/'+name][k]for k in ('bytes','sha256')},'actual unchanged source '+name)
 need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'complete selected package '+name);sources[name]=raw
C=mod(sources['source/component_common.py'],'component_common',PARENT/'source/component_common.py');sys.modules['component_common']=C
m=mod(sources['source/late_boundary.py'],'r10_actual_late_wiring',P/'runtime/source/late_boundary.py')
m.__reviewed_package_sources__=sources;m.__reviewed_source_sha256__=pin(sources['source/late_boundary.py'])['sha256']
r7m=(R7/'RETENTION-INPUTS.mac.original.json').read_bytes();r7a=(R7/'ORIGINALS.zlib').read_bytes()
r8m=(PKG/'MAC-RETENTION-INPUTS.json').read_bytes();r8a=(PKG/'ORIGINALS.zlib').read_bytes();r8r=(PKG/'verify_retained_staged_r8.py').read_bytes()
r9d=json.loads((R9/'DEPLOYMENT.json').read_bytes())
data={m.RETAINED_PREACCEPT_HOST['path']:r7m,m.RETAINED_PREACCEPT_HOST_ARCHIVE['path']:r7a,
 m.RETAINED_FAILED_STAGED_HOST['path']:r8m,m.RETAINED_FAILED_STAGED_HOST_ARCHIVE['path']:r8a,
 m.RETAINED_FAILED_STAGED_HOST_READER['path']:r8r,
 m.RETAINED_FAILED_TRANSPORT_HOST_ADAPTER['path']:(P/'dependencies/runtime/retained_transport_r9_adapter.py').read_bytes()}
for k in ('manifest_host','archive_host','reader_host'):data[r9d[k]['path']]=(R9/r9d[k]['local_file']).read_bytes()
read_calls=[];tamper_adapter=False
def supplied(row):
 need(set(row)=={'path','bytes','sha256'}and row['path']in data,'only exact local copies of actual host proof descriptors')
 raw=data[row['path']]
 if tamper_adapter and row==m.RETAINED_FAILED_TRANSPORT_HOST_ADAPTER:raw=b'!'+raw[1:]
 need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'actual input descriptor differs')
 read_calls.append(row.copy());return raw
started=time.monotonic()
r7=m.install_retained_preaccept_host_reader(supplied)
m.install_retained_failed_staged_host_reader(supplied);r8=m.retained_failed_staged()
m.install_retained_failed_transport_host_reader(supplied);r9=m.retained_failed_transport()
m.validate_current_package_manifest(package)
m.current_context(freeze['combination']['sha256'],pin((P/'runtime/MANIFEST.json').read_bytes())['sha256'])
with tarfile.open(fileobj=io.BytesIO(zlib.decompress(r7a)),mode='r:')as t:
 inv44=t.extractfile('originals/old_inventory').read()
boundary=(Path('/workspace/scratch/00f8328876d8/r2-private/r7-retained-preaccept01')/'final04-LATE-BOUNDARY.original.json').read_bytes()
need(pin(inv44)=={'bytes':1345535,'sha256':'4bd70b72d2a92a6c963912159d9e978fc681a35ddb30c03a2c741700bf47cde4'}and
 pin(boundary)=={'bytes':29342,'sha256':'39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'},'actual native final04 originals')
count=m.validate_r10_prior_selection(json.loads(boundary),json.loads(inv44),r9['inventory_value'],r9['inventory'],
 'exact_source_parent44_plus_retained_failed_r7_r8_r9_49',next_case='NEG-01')
need(count==49 and r9['native_terminal']is None and r9['first_launch_receipt_gap']is True and r9['original_start_reused']is True,'original unknown and exact current49')
positive_elapsed=time.monotonic()-started
controls=[{'name':'actual_six_sources_three_host_mappers_and_native44_to_retained49','result':'PASS','elapsed_seconds':positive_elapsed,'returned_root_count':count}]
def reject(name,action):
 try:action()
 except (ValueError,AssertionError)as error:
  controls.append({'name':name,'result':'PASS_REJECTED','error_type':type(error).__name__,'error':str(error)})
 else:raise ValueError('negative control unexpectedly accepted: '+name)
reject('old_R8_inventory_pin_cannot_replace_actual_R9_observation',lambda:m.validate_r10_prior_selection(
 json.loads(boundary),json.loads(inv44),r8['inventory_value'],r8['inventory'],
 'exact_source_parent44_plus_retained_failed_r7_r8_r9_49',next_case='NEG-01'))
missing=copy.deepcopy(package);del missing['retained_failed_transport_runtime_adapter']
reject('runtime_manifest_requires_exact_separate_adapter',lambda:m.validate_current_package_manifest(missing))
tamper_adapter=True
reject('changed_host_adapter_bytes_rejected_before_module_load',lambda:m.retained_failed_transport_adapter())
tamper_adapter=False
unique={x['path']:x for x in read_calls}
report={'schema':'hepta.r10.actual-proof-and-source-host-controls.v1','state':'FOUR_PURE_HOST_WIRING_CONTROLS_PASSED_NO_EXECUTION_QUALIFICATION',
 'controls':controls,'count':len(controls),'sources':{name:pin((P/name).read_bytes())for name in ['runtime/MANIFEST.json','runtime/source/late_boundary.py','dependencies/runtime/retained_transport_r9_adapter.py']},
 'unchanged_Common':pin(sources['source/component_common.py']),'complete_selected_runtime_members':len(sources),
 'original_native_boundary':pin(boundary),'original_native_inventory':pin(inv44),
 'retained_R9_inventory':r9['inventory'],'retained_R8_inventory':r8['inventory'],
 'actual_proof_callback_descriptors':list(unique.values()),'actual_positive_replay_elapsed_seconds':positive_elapsed,
 'elapsed_is_local_pure_replay_not_phone_current_inventory_measurement':True,
 'phone_LIFE_inventory_and_current_absence_not_executed':True,'runtime_30_second_inventory_budget_not_changed':True,
 'actual_Mac_consumer_attested':False,'actual_phone_publication_attested':False,'actual_R10_freeze':None,
 'native_case_credit':0,'phone_calls':0,'new_nonce_draws':0,'remote_actions':0}
out=R/'r8-integration/r10-whole-host-controls01';out.mkdir(mode=0o700)
raw=enc(report);p=out/'HOST-CONTROLS.json';fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
 need(os.write(fd,raw)==len(raw),'whole report write');os.fsync(fd)
finally:os.close(fd)
need(p.read_bytes()==raw,'complete saved report')
print(json.dumps({'path':str(p),**pin(raw),'controls':len(controls),'actual_positive_elapsed_seconds':positive_elapsed}))
