#!/usr/bin/env python3
"""R6: actual UI closure fix and fresh-identity finite preparation budgets only."""
from pathlib import Path
import ast,base64,copy,difflib,gzip,hashlib,json,re,sys,types
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parent;OLD=R/'R5-root';BASE=R/'R4';OUT=R/'R6-root'
REMOTE='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r6'
def need(v,s):
 if not v:raise ValueError(s)
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def put(p,b):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);need(p.read_bytes()==b,'whole output readback')
def main():
 need(not OUT.exists(),'one new local source assembly')
 runtime_raw=(OLD/'runtime/MANIFEST.json').read_bytes();root_raw=(OLD/'root-chain/SOURCE-MANIFEST.json').read_bytes()
 need(pin(runtime_raw)=={'bytes':57078,'sha256':'990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'},'exact actual R5 runtime')
 need(pin(root_raw)=={'bytes':50107,'sha256':'f9145ce2f0e5864a78ed8bece2d926187dc83e8baf15799758200bb646057282'},'exact actual R5 root source manifest')
 runtime=json.loads(runtime_raw);root=json.loads(root_raw);files={};parent={};edits={}
 for family,manifest in [('runtime',runtime),('root-chain',root)]:
  for row in manifest['files']:
   name=family+'/'+row['path'];b=(OLD/name).read_bytes();need(pin(b)=={k:row[k]for k in ('bytes','sha256')},'actual R5 complete member '+name);files[name]=b;parent[name]=b
 need(len(runtime['files'])==38 and len(root['files'])==3,'same fixed package members')
 def change(name,old,new):
  old=old.encode()if type(old)is str else old;new=new.encode()if type(new)is str else new
  need(files[name].count(old)==1 and old!=new,'one exact source segment '+name);files[name]=files[name].replace(old,new,1);edits.setdefault(name,[]).append((old,new))
 sender='runtime/source/send_new_native_guard_task_r10_r4.py'
 old_block=(R/'R6-sender-ui/candidate02/CLOSE-DETAILS.old.txt').read_bytes();new_block=(R/'R6-sender-ui/candidate02/CLOSE-DETAILS.new.txt').read_bytes()
 need(pin(new_block)=={'bytes':818,'sha256':'5c88d8b8c4c88fe2605abb55239d21c233e97037ebfdcfb9346f4c4ee2e528f5'},'reviewed final UI block')
 change(sender,old_block,new_block)
 need(pin(files[sender])=={'bytes':41647,'sha256':'546010c5ef2c8f99d2be71a9f99d608c41186bdfc9a70e7d64b286fe133e3045'},'actual8-controls UI-only candidate')
 change(sender,'pre_send_deadline_ns=time.monotonic_ns()+150_000_000_000','pre_send_deadline_ns=time.monotonic_ns()+(240_000_000_000 if component_binding is not None else 150_000_000_000)')
 change(sender,'result = subprocess.run(ssh, input=source.encode(), capture_output=True, timeout=600)','result = subprocess.run(ssh, input=source.encode(), capture_output=True, timeout=660 if component_binding is not None else 600)')
 for name in ['prepare_component.py','stage_component.py','component_lifecycle.py']:
  path='runtime/source/'+name
  change(path,'<=600000','<=900000') if name!='component_lifecycle.py' else change(path,'<= 600000','<= 900000')
  if name=='prepare_component.py':change(path,'at most 600 seconds','at most 900 seconds')
  if name=='component_lifecycle.py':change(path,'exceeds 600 seconds','exceeds 900 seconds')
 driver='root-chain/source/run_component_root_once.py';bridge='root-chain/source/phone_chain_bridge.py'
 change(driver,'The 600-second lease is','The 900-second lease is')
 change(driver,'expiry=time.time_ns()//1000000+600000','expiry=time.time_ns()//1000000+900000')
 change(driver,"self.sender=self.execute_process('sender-execute',sender+['--execute-once'],600,async_start=True)","self.sender=self.execute_process('sender-execute',sender+['--execute-once'],660,async_start=True)")
 change(driver,'never extend the original 600-second lease.','never extend the original 900-second lease.')
 change(driver,"self.frozen_phone('launch',self.prepared['root_detached_launcher_argv'],60)","self.frozen_phone('launch',self.prepared['root_detached_launcher_argv'],90)")
 change(driver,"timeout=75 if phase=='setup' else 40","timeout=135 if phase=='setup' else 40")
 change(bridge,"(60 if a.phase=='setup' else 25)","(120 if a.phase=='setup' else 25)")
 def constant(name,key,new):
  src=files[name].decode();lines=re.findall(r'^'+re.escape(key)+r'\s*=.*$',src,re.M);need(len(lines)==1,'one binding '+key);change(name,lines[0],key+' = '+new)
 constant(driver,'PKG','None');constant(bridge,'PKG','None')
 constant(driver,'SENDER',repr(pin(files[sender])['sha256']))
 constant(driver,'MATERIAL_ROOT','Path('+repr(REMOTE+'/shared')+')')
 budget={'schema':'hepta.fc33.new-identity-preparation-budget.v1','initial_lease_seconds':900,'prior_initial_lease_seconds':600,'existing_leases_modified':False,'lease_extension':False,'component_pre_send_seconds':240,'non_component_pre_send_seconds_unchanged':150,'component_sender_total_seconds':660,'non_component_sender_total_seconds_unchanged':600,'root_sender_async_seconds':660,'launch_phone_request_seconds':90,'launch_p4_actor_wait_seconds':110,'launch_root_remote_seconds':145,'setup_bridge_observation_seconds':120,'setup_phone_request_seconds':135,'setup_p4_actor_wait_seconds':155,'setup_root_remote_seconds':190,'before_after_bridge_seconds_unchanged':25,'before_after_phone_request_seconds_unchanged':40,'prelaunch_remaining_required_seconds_unchanged':510,'listener_seconds_unchanged':420,'native_turn_seconds_unchanged':300,'single_send_single_fork_unchanged':True,'timeout_is_UNKNOWN_not_no_effect_proof':True,'existing_common_unused_MAX_LEASE_SECONDS_declaration_preserved':600,'historical_retained_stage_600_unchanged':True,'current_launch_and_READY_time_not_yet_measured':True}
 runtime['revision']='r10-r1-fc33-native-bound-v3-r6'
 runtime['new_identity_preparation_budget']=budget
 runtime['sender_ui_completion']={'parent_source':pin(parent[sender]),'reviewed_UI_only_candidate':{'bytes':41647,'sha256':'546010c5ef2c8f99d2be71a9f99d608c41186bdfc9a70e7d64b286fe133e3045'},'old_block':pin(old_block),'new_block':pin(new_block),'max_recognized_dialog_closes':4,'exact_final_editor_and_request_required':True,'source_control_result':{'bytes':5402,'sha256':'7cdd420fd5f5055509b0659a109d5932bcc7a3ce27e440a4957db091fbd07348'},'actual_business_credit':False}
 runtime['preceding_unqualified_source_package']={**pin(runtime_raw),'current_case_credit':False}
 runtime['files']=[{'path':row['path'],**pin(files['runtime/'+row['path']])}for row in runtime['files']]
 sources={name[len('runtime/'):]:b for name,b in files.items() if name.startswith('runtime/')}
 saved=sys.modules.get('component_common')
 try:
  common=types.ModuleType('component_common');common.__file__=str(OUT/'runtime/source/component_common.py');sys.modules['component_common']=common;exec(compile(sources['source/component_common.py'],common.__file__,'exec'),common.__dict__)
  late=types.ModuleType('fc33_r6_late');late.__file__=str(OUT/'runtime/source/late_boundary.py');late.__reviewed_package_sources__=sources;late.__reviewed_source_sha256__=pin(sources['source/late_boundary.py'])['sha256'];exec(compile(sources['source/late_boundary.py'],late.__file__,'exec'),late.__dict__)
  late.validate_current_package_manifest(runtime)
  need((late.SOURCE_PARENT_COUNT,late.MAX_CHAIN,late.COMPONENT_ROLE_CAP,late.MAX_FIXTURE_ROOTS,late.SOURCE_PARENT_INVENTORY_ROOT_COUNT,late.MAX_CURRENT_INVENTORY_ROOTS)==(1,12,42,14,44,50),'all existing source-parent scope/caps unchanged')
 finally:
  if saved is None:sys.modules.pop('component_common',None)
  else:sys.modules['component_common']=saved
 manifest_raw=enc(runtime);package=pin(manifest_raw)
 binding=[]
 for name in [driver,bridge]:
  template=files[name];change(name,'PKG = None','PKG = '+repr(package['sha256']));binding.append({'path':name.removeprefix('root-chain/'),'template':pin(template),'bound':pin(files[name]),'exact_slot_inverse':True})
 root['revision']='r10-r1-fc33-native-bound-v3-r6';root['frozen_component_package_sha256']=package['sha256'];root['fixed_shared_material_root']=REMOTE+'/shared'
 old_launch=copy.deepcopy(root['launch_observation_budget']);new_launch=copy.deepcopy(old_launch);new_launch.pop('lease_seconds_unchanged');new_launch.update(initial_lease_seconds=900,prior_initial_lease_seconds=600,new_identity_initial_budget_only=True,request_seconds=90,p4_actor_wait_seconds=110,root_remote_seconds=145)
 root['launch_observation_budget']=new_launch;root['new_identity_preparation_budget']=budget
 root['preceding_unqualified_root_source_manifest']={**pin(root_raw),'current_case_credit':False}
 root['files']=[{'path':row['path'],**pin(files['root-chain/'+row['path']])}for row in root['files']]
 files['runtime/MANIFEST.json']=manifest_raw;files['root-chain/SOURCE-MANIFEST.json']=enc(root)
 inverse=[]
 for name,ops in edits.items():
  result=files[name]
  for a,b in reversed(ops):need(result.count(b)==1,'exact source inverse segment '+name);result=result.replace(b,a,1)
  need(result==parent[name],'whole original source inverse '+name)
  inverse.append({'path':name,'parent':pin(parent[name]),'candidate':pin(files[name]),'segment_count':len(ops),'complete_byte_inverse':True})
  patch=''.join(difflib.unified_diff(parent[name].decode().splitlines(True),files[name].decode().splitlines(True),fromfile='R5/'+name,tofile='R6/'+name))
  put(OUT/'reviewed-deltas'/(Path(name).name+'.patch'),patch.encode())
 for name,b in files.items():
  if name.endswith('.py'):ast.parse(b,filename=name)
  put(OUT/name,b)
 delta={}
 for name,b in files.items():
  prior=BASE/name
  if not prior.exists()or prior.read_bytes()!=b:delta[name]=b
 need(len(delta)==17,'unchanged17 complete R4-to-current delta members')
 proof={'schema':'hepta.fc33.runtime-r6.sender-ui-and-initial-budget-delta.v1','state':'SOURCE_CANDIDATE_NOT_PHONE_QUALIFIED','runtime_parent':pin(runtime_raw),'root_parent':pin(root_raw),'source_files_changed':inverse,'runtime_files_changed':4,'root_files_changed':2,'original_production15_and_combination_unchanged':True,'source_parent_and_all_legacy_bytes_unchanged':True,'complete_manifest_files_rehashed':True,'budgets':budget,'prior_launch_observation_metadata':old_launch,'phone_calls':0,'new_nonces':0,'case_credit':0}
 put(OUT/'R6-SOURCE-DELTA.json',enc(proof))
 assembly=json.loads((OLD/'ASSEMBLY.json').read_bytes());assembly['runtime_manifest']=package;assembly['root_manifest']=pin(files['root-chain/SOURCE-MANIFEST.json']);assembly['root_package_constant_binding']=binding;assembly['files']=[{'path':n,**pin(b)}for n,b in sorted(delta.items())];assembly['r6_source_delta']=proof;assembly['all_python_compiled']=True
 put(OUT/'ASSEMBLY.json',enc(assembly))
 bundle={'schema':'hepta.fc33.reviewed-runtime-delta-bundle.v1','assembly':assembly,'files':[{'path':n,**pin(b),'base64':base64.b64encode(b).decode()}for n,b in sorted(delta.items())]}
 packed=gzip.compress(enc(bundle),mtime=0);put(OUT/'RUNTIME-DELTA.json.gz',packed)
 print(json.dumps({'runtime':package,'root':pin(files['root-chain/SOURCE-MANIFEST.json']),'sender':pin(files[sender]),'source_delta':pin(enc(proof)),'assembly':pin(enc(assembly)),'delta_files':len(delta),'bundle':pin(packed),'phone_calls':0}))
if __name__=='__main__':main()
