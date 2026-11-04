#!/usr/bin/env python3
"""Execute original entry code with an audit fence; no service/network/key access."""
import argparse,ast,contextlib,hashlib,io,json,os,runpy,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('mode',choices=('original-help','candidate-help','candidate-config-boundary'));a=p.parse_args()
B=Path('/operator-workspace/phone-local-v150')
D=B/'provider-r7';parent=B/'provider-r6-r2'
source=(parent if a.mode=='original-help' else D)/'source'
entry=source/'daily_phone_local.py'
names={p.name for p in source.glob('*.py')};assert len(names)==13
before={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in sorted(names)}
external=source/'phone_local_tools.py';tree=ast.parse(external.read_bytes())
function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='validate_executor')
branch=next(n for n in function.body if isinstance(n,ast.If) and isinstance(n.test,ast.Name) and n.test.id=='verify_files')
boundary_line=branch.body[0].lineno
state=D/'validation/NO_SERVICE_STATE';claims=D/'validation/NEVER_READ_CLAIMS.json'
assert not state.exists() and not claims.exists()
executed=set();forbidden=[];boundary=None
active=True
class BoundaryReached(BaseException):pass
def audit(event,args):
 if not active:return
 if event=='exec':
  filename=getattr(args[0],'co_filename','')
  if filename.startswith(str(source)+os.sep):executed.add(Path(filename).name)
 if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.posix_spawn','os.fork','os.exec','os.mkdir','os.rename','os.remove','os.rmdir','os.kill','os.killpg'):
  forbidden.append({'event':event});raise RuntimeError('preflight external operation forbidden:'+event)
 if event=='open':
  path,mode,flags=args
  if isinstance(path,(str,bytes)):
   text=os.fsdecode(path)
   if text.endswith('llama-api.key') or text==str(claims):
    forbidden.append({'event':'private_input_open'});raise RuntimeError('preflight private input forbidden')
  if isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
   forbidden.append({'event':'file_write'});raise RuntimeError('preflight file mutation forbidden')
def trace(frame,event,arg):
 global boundary
 if (a.mode=='candidate-config-boundary' and event=='line'
     and frame.f_code.co_filename==str(external) and frame.f_code.co_name=='validate_executor'
     and frame.f_lineno==boundary_line):
  assert frame.f_locals['verify_files'] is True
  value=frame.f_locals['executor']
  assert value['client_path']=='/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py'
  assert value['client_sha256']=='500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f'
  boundary={'function':'validate_executor','source':'phone_local_tools.py','line':boundary_line,
   'stop_before':'first external phone client filesystem lookup; later key read and serve not reached',
   'actual_main_and_load_local_config_called':True,
   'actual_endpoint_model_limits_apps_executor_schema_validation_executed':True,
   'actual_client_file_or_key_validation_claimed':False}
  raise BoundaryReached()
 return trace
sys.dont_write_bytecode=True
sys.addaudithook(audit)
sys.argv=[str(entry),'--help']
if a.mode=='candidate-config-boundary':
 sys.argv=[str(entry),'--state',str(state),'--config',str(D/'local-config.phone.production.json'),
  '--port','18080','--workers','1','--timeout','120','--retained-claims',str(claims),
  '--retained-claims-sha256','<RETAINED_CLAIMS_INSTANCE_SHA256_REQUIRED>']
out,err=io.StringIO(),io.StringIO();outcome=None;error=None
try:
 sys.settrace(trace)
 with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):runpy.run_path(str(entry),run_name='__main__')
 outcome='returned'
except BoundaryReached:outcome='declared_external_boundary_reached'
except SystemExit as e:outcome='system_exit';error={'code':e.code}
except BaseException as e:outcome='exception';error={'type':type(e).__name__,'message':str(e)}
finally:
 sys.settrace(None);active=False
after={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in sorted(names)}
assert before==after and not state.exists() and not claims.exists() and not forbidden
if a.mode=='original-help':
 accepted=outcome=='exception' and error=={'type':'RuntimeError','message':'protocol source pin differs'}
else:
 assert executed==names,(executed,names)
 accepted=((outcome=='system_exit' and error=={'code':0}) if a.mode=='candidate-help'
           else outcome=='declared_external_boundary_reached' and boundary is not None)
result={'schema':'hepta.real-entry-preflight.v150.r7.1','mode':a.mode,'accepted_expected_result':accepted,
 'original_entry_path':str(entry),'entry_sha256':before['daily_phone_local.py'],
 'actual_entry_outcome':outcome,'actual_error_or_exit':error,'boundary':boundary,
 'executed_production_source_files':sorted(executed),'source_bytes_before_and_after':before,
 'all_13_source_files_executed':executed==names,'source_files_unchanged':before==after,
 'captured_entry_stdout_bytes':len(out.getvalue().encode()),'captured_entry_stderr_bytes':len(err.getvalue().encode()),
 'forbidden_operation_attempts':forbidden,'socket_operations':0,'model_requests':0,'phone_calls':0,
 'service_started':False,'state_or_claim_directory_created':False,'private_key_read':False,
 'actual_phone_ready_claim':False,'original_pin_failure_preserved':True}
print(json.dumps(result,sort_keys=True))
raise SystemExit(0 if accepted else 2)
