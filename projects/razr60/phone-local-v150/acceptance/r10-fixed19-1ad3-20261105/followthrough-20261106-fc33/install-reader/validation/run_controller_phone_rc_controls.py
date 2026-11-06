"""Focused synthetic CLI/result-code boundary; no controller or phone is invoked."""
import hashlib,json,sys,types
from pathlib import Path,PurePosixPath
root=Path(__file__).resolve().parents[1]
source=root/'source/verify_install_start_ready_UNBOUND.py'
api=types.ModuleType('selected_install_reader')
exec(compile(source.read_bytes(),str(source),'exec'),api.__dict__)
def encode(value):return(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def tool(value):return encode({'content':[{'type':'text','text':json.dumps(value)}],'isError':False,'structuredContent':None})
def exercise(code):
    dispatch={'host':'pocket4','executable':'/usr/bin/python3','args':['-I','-B','/synthetic/actor.py','HOST_SOURCE_CONTROL','/synthetic/request.json'],'cwd':'/synthetic','idempotency_key':'HOST_SOURCE_CONTROL'}
    expected={'dispatch':dispatch,'actor_operation_dir':'/synthetic/operations/HOST_SOURCE_CONTROL'}
    summary={'run':expected['actor_operation_dir'],'status':'command_exited','sha256':'0'*64,'elapsed_seconds':0.1,'http_status':None,'phone_rc':code,'error':None}
    stdout=(json.dumps(summary,ensure_ascii=False)+'\n').encode()
    status={'job_id':'HOST_SOURCE_CONTROL','state':'succeeded','exit_code':0,'at_unix_ms':2000,'output_complete':True,'output_durable':True,'terminal_publication_confirmed':True,'timed_out':False,'cancelled':False,'log_errors':{'stdout':None,'stderr':None},'log_truncated':{'stdout':False,'stderr':False},'log_synced':{'stdout':True,'stderr':True},'log_bytes':{'stdout':{'seen':len(stdout),'stored':len(stdout)},'stderr':{'seen':0,'stored':0}}}
    def stream(raw):return dict(bytes_hex=raw.hex(),eof=True,next_offset=len(raw),offset=0,size=len(raw),text=raw.decode())
    values={'dispatch':encode(dispatch),'start':tool({'job':dict(dispatch,id='HOST_SOURCE_CONTROL',created_unix_ms=1000,launch_state='launched',launch_error=None,env_keys=[]),'reused':False}),'status':tool(status),'read':tool({'job_id':'HOST_SOURCE_CONTROL','stdout':stream(stdout),'stderr':stream(b'')})}
    rows={k:dict(path='/synthetic/'+k,**api.pin(v))for k,v in values.items()}
    class Pool:
        def read(self,row,maximum):return values[PurePosixPath(row['path']).name]
    return api.verify_process(rows,expected,Pool())
cases=[]
exercise(0);cases.append({'name':'integer_phone0_with_original_actor0_shape','passed':True})
for name,code in [('integer_phone7_with_actor0_rejected',7),('boolean_false_not_phone_exit0',False)]:
    try:exercise(code)
    except ValueError as e:
        assert str(e)=='actor zero alone is insufficient: original phone must also exit zero'
        cases.append({'name':name,'passed':True,'rejection':str(e)})
    else:raise AssertionError(name)
result={'schema':'hepta.production.install-ready.focused-code-controls.v1','passed':3,'tests':cases,'fixture_family':'SYNTHETIC_PARSER_ONLY','actor_executions':0,'phone_calls':0,'actual_phase_credit':0,
        'source':dict(path=str(source),**api.pin(source.read_bytes())),
        'earlier_control_label_correction':'controls01/controller_zero_does_not_imply_phone_zero changed only text and therefore tested bytes/text disagreement; this new control tests the actual phone_rc semantic gate with internally consistent complete output bytes.'}
raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
out=root/'validation/CONTROLLER-PHONE-RC-RESULT.json'
with out.open('xb')as f:f.write(raw)
sys.stdout.buffer.write(raw)
