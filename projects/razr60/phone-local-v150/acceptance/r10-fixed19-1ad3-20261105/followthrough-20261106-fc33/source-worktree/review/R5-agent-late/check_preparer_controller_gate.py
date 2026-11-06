#!/usr/bin/env python3
"""In-memory controller gate controls. No preparer main, nonce or phone call."""
from pathlib import Path
import ast,copy,hashlib,json,types

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'prepare_native_bound_components_r5_UNBOUND.py'
HELPER=ROOT/'formal-originals/prepare_diagnostic_root_plan_once.py'
EXPECTED={'bytes':19853,'sha256':'b3cf58988b5533a4bd9ae7a94ea54872bf1539a08bcf2e7740232fb17c272116'}

def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def enc(v):return(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def extract(raw,names):
 text=raw.decode();tree=ast.parse(text);lines=text.splitlines(keepends=True)
 selected=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names]
 assert {n.name for n in selected}==set(names)
 return ''.join(''.join(lines[n.lineno-1:n.end_lineno])+'\n\n'for n in selected)

def main():
 raw=SOURCE.read_bytes();assert pin(raw)==EXPECTED
 helper=HELPER.read_bytes();assert pin(helper)=={'bytes':35690,'sha256':'4708d037d58fd5b40e2a15210887ce58d9e7d0857ef27057855031591ee7faf9'}
 import re
 ns={'re':re,'FROZEN_INPUTS':None}
 code=extract(raw,('need','controller_value','verify_controller'));exec(compile(code,'<reviewed-controller-gate-pure-control>','exec'),ns)
 hn={'json':json};exec(compile(extract(helper,('need','strict')),'<exact-helper-json-pure-control>','exec'),hn)
 h=types.SimpleNamespace(strict=hn['strict'])
 freeze={'path':'/CONTROL-ONLY/unused/FREEZE-RESULT.json','bytes':10,'sha256':'1'*64}
 f={'source':{'path':'/CONTROL-ONLY/unused/freezer.py','sha256':'2'*64},
    'state':'FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED',
    'runtime_manifest':{'path':'/CONTROL-ONLY/unused/runtime/MANIFEST.json','bytes':10,'sha256':'3'*64},
    'root_chain_manifest':{'path':'/CONTROL-ONLY/unused/root-chain/SOURCE-MANIFEST.json','bytes':10,'sha256':'4'*64},
    'combination':{'path':'/CONTROL-ONLY/unused/COMBINATION.json','bytes':10,'sha256':'5'*64},'complete_directory_bytes':100}
 summary={k:f[k]for k in('state','runtime_manifest','root_chain_manifest','combination','complete_directory_bytes')}
 summary.update(freeze=freeze,phone_calls=0,full19_qualified=False)
 stdout=enc(summary);stderr=b'';job='CONTROL-ONLY-NOT-ACTUAL-JOB'
 request={'host':'mac','executable':'/usr/bin/python3','args':['-I','-B',f['source']['path'],'--freeze-reviewed-host-runtime',f['source']['sha256']],
          'idempotency_key':'fc33-freeze-native-bound-runtime-r5-01'}
 start={'reused':False,'job':{**request,'id':job,'launch_error':None,'launch_state':'launched'}}
 status={'job_id':job,'state':'succeeded','exit_code':0,'cancelled':False,'timed_out':False,'automatic_retry':False,
         'output_complete':True,'output_durable':True,'terminal_publication_confirmed':True,
         'log_bytes':{},'log_truncated':{},'log_synced':{},'log_errors':{}}
 read={'job_id':job}
 for name,data in(('stdout',stdout),('stderr',stderr)):
  n=len(data);read[name]={'bytes_hex':data.hex(),'offset':0,'next_offset':n,'size':n,'eof':True}
  status['log_bytes'][name]={'seen':n,'stored':n};status['log_truncated'][name]=False
  status['log_synced'][name]=True;status['log_errors'][name]=None
 base={'request':request,'start':start,'status':status,'read':read}
 def check(value):
  carrier={'schema':'hepta.fc33.actual-runtime-freeze-controller-originals.v1','request':value['request']}
  for key in('start','status','read'):
   carrier[key]={'isError':False,'content':[{'type':'text','text':json.dumps(value[key])}]}
  body=enc(carrier);row={'path':'/CONTROL-ONLY/in-memory-controller.json',**pin(body)}
  ns['FROZEN_INPUTS']={'controller':row}
  class O:
   def read(self,asked):
    assert asked==row
    return body
  return ns['verify_controller'](h,O(),f,freeze)
 positive=check(base);assert positive['all_terminal_copies_required']is True
 cases=[]
 def rejected(name,change):
  v=copy.deepcopy(base);change(v)
  try:check(v)
  except (ValueError,KeyError,TypeError)as error:cases.append({'name':name,'state':'REJECTED','reason':str(error)})
  else:raise AssertionError('unexpected acceptance: '+name)
 rejected('failed_terminal',lambda v:v['status'].update(state='failed'))
 rejected('nonzero_exit',lambda v:v['status'].update(exit_code=1))
 rejected('boolean_exit_is_not_zero_integer',lambda v:v['status'].update(exit_code=False))
 rejected('cancelled',lambda v:v['status'].update(cancelled=True))
 rejected('timed_out',lambda v:v['status'].update(timed_out=True))
 rejected('automatic_retry',lambda v:v['status'].update(automatic_retry=True))
 rejected('not_durable',lambda v:v['status'].update(output_durable=False))
 rejected('missing_terminal_publication',lambda v:v['status'].update(terminal_publication_confirmed=False))
 rejected('reused_launch',lambda v:v['start'].update(reused=True))
 rejected('different_terminal_job',lambda v:v['status'].update(job_id='OTHER-CONTROL-JOB'))
 rejected('different_read_job',lambda v:v['read'].update(job_id='OTHER-CONTROL-JOB'))
 rejected('different_source_argv',lambda v:v['request']['args'].__setitem__(2,'/CONTROL-ONLY/other.py'))
 rejected('stdout_nonzero_offset',lambda v:v['read']['stdout'].update(offset=1))
 rejected('stderr_not_eof',lambda v:v['read']['stderr'].update(eof=False))
 rejected('stdout_not_eof',lambda v:v['read']['stdout'].update(eof=False))
 rejected('uppercase_hex',lambda v:v['read']['stdout'].update(bytes_hex=v['read']['stdout']['bytes_hex'].upper()))
 rejected('stdout_truncated',lambda v:v['status']['log_truncated'].update(stdout=True))
 rejected('stderr_log_error',lambda v:v['status']['log_errors'].update(stderr='control_error'))
 rejected('stdout_unsynced',lambda v:v['status']['log_synced'].update(stdout=False))
 rejected('late_bytes_not_in_terminal',lambda v:v['status']['log_bytes']['stdout'].update(seen=len(stdout)+1))
 def nonempty_stderr(v):
  v['read']['stderr'].update(bytes_hex='78',size=1,next_offset=1)
  v['status']['log_bytes']['stderr'].update(seen=1,stored=1)
 rejected('nonempty_stderr',nonempty_stderr)
 def other_freeze(v):
  s=copy.deepcopy(summary);s['freeze']['sha256']='6'*64;b=enc(s);n=len(b)
  v['read']['stdout'].update(bytes_hex=b.hex(),size=n,next_offset=n)
  v['status']['log_bytes']['stdout'].update(seen=n,stored=n)
 rejected('stdout_binds_another_freeze',other_freeze)
 def false_phone(v):
  s=copy.deepcopy(summary);s['phone_calls']=1;b=enc(s);n=len(b)
  v['read']['stdout'].update(bytes_hex=b.hex(),size=n,next_offset=n)
  v['status']['log_bytes']['stdout'].update(seen=n,stored=n)
 rejected('stdout_reports_phone_effect',false_phone)
 result={'schema':'hepta.fc33.preparer-controller-gate-pure-controls.v1','state':'PURE_CONTROLLER_NEGATIVE_CONTROLS_PASSED',
         'preparer_source':{'path':str(SOURCE),**pin(raw)},'helper_source':{'path':str(HELPER),**pin(helper)},
         'exact_function_sources':pin(code.encode()),'positive_in_memory_fixture':True,
         'negative_controls':cases,'actual_freeze_controller_qualification':False,
         'preparer_main_called':False,'nonce_generated':False,'phone_calls':0,
         'memory_fixture_paths_read':False}
 out=Path(__file__).with_name('PREPARER-CONTROLLER-GATE-REVIEW.json');b=enc(result);out.write_bytes(b)
 print(json.dumps({'result':{'path':str(out),**pin(b)},'negative_controls':len(cases),'actual_operations':0},sort_keys=True))

if __name__=='__main__':main()
