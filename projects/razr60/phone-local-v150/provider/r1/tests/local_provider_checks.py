#!/usr/bin/env python3
"""Fresh isolated local-provider fixtures. No phone/model/production endpoint is used."""
import base64
import contextlib
import datetime
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import sys
import threading
import time
import traceback
from types import SimpleNamespace
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE/'source'))
from daily_phone_local import DailyAdapter, file_identity, replace_json, expected_evidence_temporary, evidence_item_size
from model_health import ModelHealth
from provider_openai_compatible import PROTOCOL, ProviderError, tool_call
from provider_phone_local import load_local_config
from phone_local_http_worker import endpoint_parts
from phone_local_tools import PhoneLocalTools
from phone_observation_tools import native_streams
from task_postconditions import evaluate, terminal_fields, load_contract
from phone_task_guards import HEPTA_COMPONENT

RUN = BASE/'validation'/('isolated-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(8))
RUN.mkdir(mode=0o700)
REPORT = {'schema':'hepta.phone-local-isolated-validation.v150.1','layer':'host_isolated_fixture',
          'physical_phone_actions':0,'real_model_requests':0,'production_state_modified':False,
          'run_dir':str(RUN),'checks':[],'cases':[]}
MODEL = 'fixture-phone-model'
PCK = 'org.trillionnium.hepta.controlprobe'
APPS = {'probe_visual':{'component':PCK+'/.VisualChallengeActivity','label':'视觉验证'},
        'probe_unicode':{'component':PCK+'/.TextEntryActivity','label':'Unicode验证'}}
WINDOW = '''  Display: mDisplayId=1 (organized)
    mCurrentFocus=null
    mFocusedApp=null
    isKeyguardShowing=false
  Display: mDisplayId=0 (organized)
    mCurrentFocus=Window{3b4490 u0 org.trillionnium.owneropen/org.trillionnium.owneropen.OwnerOpenShellActivity}
    mFocusedApp=ActivityRecord{171231292 u0 org.trillionnium.owneropen/.OwnerOpenShellActivity t205}
    isKeyguardShowing=false
  mTopFocusedDisplayId=0
    topResumedActivity=ActivityRecord{171231292 u0 org.trillionnium.owneropen/.OwnerOpenShellActivity t205}'''
VIEWPORT = "mViewports=[DisplayViewport{type=INTERNAL, valid=true, isActive=true, displayId=0, uniqueId='local:4630947043778501779', orientation=0, logicalFrame=Rect(0, 0 - 1224, 2992), physicalFrame=Rect(0, 0 - 1224, 2992)}, DisplayViewport{type=INTERNAL, valid=true, isActive=false, displayId=1, uniqueId='local:cover-fixture', orientation=2, logicalFrame=Rect(0, 0 - 1080, 1272), physicalFrame=Rect(0, 0 - 1080, 1272)}]"


def check(name, condition=True):
    if not condition:
        raise AssertionError(name)
    REPORT['checks'].append(name)


def reject(name, fn, classes=(Exception,)):
    try:
        fn()
    except classes:
        check(name)
        return
    raise AssertionError(name + ': accepted invalid fixture')


def b64(value):
    return base64.b64encode(value.encode() if isinstance(value,str) else value).decode()


class ModelServer:
    def __init__(self, root, mode='complete'):
        self.root, self.mode = root, mode
        self.calls, self.active, self.disconnected = 0, False, False
        self.started = threading.Event()
        self.second_started = threading.Event()
        self.release = threading.Event()
        self.bodies = []
        outer = self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self,*args):
                pass
            def answer(self, code, body):
                raw=json.dumps(body,ensure_ascii=False,separators=(',',':')).encode()
                self.send_response(code);self.send_header('Content-Length',str(len(raw)))
                self.send_header('Connection','close');self.end_headers()
                try:self.wfile.write(raw);self.wfile.flush()
                except (BrokenPipeError,ConnectionResetError):pass
            def do_GET(self):
                if self.path != '/slots':
                    return self.answer(404,{'error':'fixture route absent'})
                return self.answer(200,[{'id':0,'id_task':77,'is_processing':outer.active}])
            def do_POST(self):
                length=int(self.headers.get('Content-Length','0'))
                body=json.loads(self.rfile.read(length))
                outer.bodies.append(body);outer.calls+=1;outer.active=True
                outer.started.set()
                if outer.calls==2:outer.second_started.set()
                scope=json.loads(body['messages'][1]['content'][0]['text'])
                hold=(outer.mode=='hold' or (outer.mode=='return_then_hold' and outer.calls==2))
                if hold:
                    while not outer.release.is_set():
                        ready=select.select([self.connection],[],[],0.01)[0]
                        if ready and self.connection.recv(1,socket.MSG_PEEK)==b'':
                            outer.active=False;outer.disconnected=True;return
                if outer.mode=='redirect':
                    outer.active=False
                    return self.answer(307,{'redirect':'never-follow'})
                decision={'kind':'turn.complete','call_id':'','tool':'none','command':'','argv':[],
                          'summary':'synthetic fixture completed; no real phone/model','task_status':'completed'}
                if outer.mode in {'return_once','return_then_hold'} and outer.calls==1:
                    decision.update(kind='tool.call',call_id=scope['allowed_call_id'],
                                    tool='phone.return_hepta',task_status='in_progress')
                if outer.mode=='unselected_shell':
                    decision.update(kind='tool.call',call_id=scope['allowed_call_id'],
                                    tool='shell.exec',command='echo prohibited',task_status='in_progress')
                response={'id':'fixture-'+secrets.token_hex(8),'model':MODEL,
                          'choices':[{'index':0,'finish_reason':'length' if outer.mode=='length' else 'stop',
                                      'message':{'role':'assistant','content':json.dumps(decision,ensure_ascii=False)}}],
                          'usage':{'prompt_tokens':17,'completion_tokens':23,'total_tokens':40},
                          'timings':{'fixture_only':True}}
                outer.active=False
                self.answer(200,response)
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.server.daemon_threads=True
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()

    @property
    def endpoint(self):
        return 'http://127.0.0.1:%d/v1/chat/completions'%self.server.server_address[1]

    def close(self):
        self.release.set();self.server.shutdown();self.server.server_close();self.thread.join(2)


class Turn:
    def __init__(self, server, name, *, evidence=None, identity=None, timeout=3):
        self.root=RUN/(name+'-'+secrets.token_hex(8));self.root.mkdir(mode=0o700)
        self.evidence=evidence or self.root/'evidence'
        self.evidence.mkdir(mode=0o700,exist_ok=True)
        (self.evidence/'claims').mkdir(mode=0o700,exist_ok=True)
        run_dir=self.evidence/('20261103-120000-'+secrets.token_hex(16));run_dir.mkdir(mode=0o700)
        contracts=self.root/'task-contracts'
        for p in [contracts,contracts/'templates',contracts/'bindings']:p.mkdir(mode=0o700)
        key=self.root/'fixture-api.key';key.write_text(secrets.token_hex(32));key.chmod(0o600)
        config={'schema':'hepta.phone-local-provider.v150.1','endpoint':server.endpoint,
                'api_key_file':str(key),'model':MODEL,'service_manifest_sha256':'f'*64,
                'max_tokens':256,'max_prompt_bytes':65536,'approved_apps':APPS,
                'inference_location':'phone','expected_parallel_slots':1,
                'executor':{'mode':'adb_legacy'}}
        conf=self.root/'config.json';conf.write_text(json.dumps(config));conf.chmod(0o600)
        verified,digest=load_local_config(conf)
        worker=BASE/'source'/'phone_local_http_worker.py'
        self.args=SimpleNamespace(local_config=verified,local_config_sha256=digest,config=conf,
                                  worker=worker,worker_stat=file_identity(worker),timeout=timeout,
                                  evidence=self.evidence,contracts=contracts,model=MODEL,
                                  model_health=ModelHealth(self.root/'health.json',MODEL,replace_json))
        left,right=socket.socketpair()
        self.client,self.server_socket=left,right
        self.reader=left.makefile('rb');self.client.settimeout(7)
        self.source,self.sink=right.makefile('rb'),right.makefile('w')
        self.shutdown=threading.Event()
        self.adapter=DailyAdapter(self.args,self.source,self.sink,run_dir,self.shutdown)
        nonce=secrets.token_hex(16)
        self.identity=identity or {'session_id':'session-'+nonce,'profile_id':'owner-open-fixture',
                                 'task_id':'task-'+nonce,'turn_id':'turn-'+nonce}
        self.turn={**self.identity,'turn_stream_id':'stream-'+secrets.token_hex(16),
                   'user_input':'isolated synthetic case '+nonce}
        self.input_seq=0
        self.frames=[]
        self.error=None
        self.thread=threading.Thread(target=self.work,daemon=True);self.thread.start()
        self.send('turn.start',turn=self.turn)

    def work(self):
        try:self.adapter.run()
        except BaseException as error:
            self.error=type(error).__name__
            if self.adapter.terminal is None:
                with contextlib.suppress(Exception):self.adapter.emit('turn.fail',error=str(error)[:1024])
        finally:
            with contextlib.suppress(Exception):self.adapter.join_child()
            self.adapter.frames.close();self.adapter.inputs.close()
            with contextlib.suppress(Exception):self.server_socket.shutdown(socket.SHUT_RDWR)
            self.source.close();self.sink.close();self.server_socket.close()

    def send(self,kind,**fields):
        frame={'protocol':PROTOCOL,'kind':kind,'seq':self.input_seq,**fields}
        self.input_seq+=1
        self.client.sendall((json.dumps(frame,ensure_ascii=False,separators=(',',':'))+'\n').encode())

    def until(self,kind=None):
        while True:
            raw=self.reader.readline()
            if not raw:return None
            frame=json.loads(raw);self.frames.append(frame)
            if kind is None or frame.get('kind')==kind:return frame

    def terminal(self):
        while True:
            frame=self.until()
            if frame is None:return None
            if frame['kind'] in {'turn.complete','turn.fail','turn.cancelled'}:return frame

    def disconnect(self):
        with contextlib.suppress(Exception):self.client.shutdown(socket.SHUT_RDWR)
        self.client.close()

    def finish(self):
        self.thread.join(7)
        check('fixture thread joined: '+self.root.name,not self.thread.is_alive())
        with contextlib.suppress(Exception):self.reader.close()
        with contextlib.suppress(Exception):self.client.close()

    def outcome(self):
        return json.loads((self.adapter.run_dir/'business-outcome.json').read_text())

    def claim_count(self):
        return len(list((self.evidence/'claims').iterdir()))


def reply_for(call,adapter):
    call_id=call['call_id']
    token=adapter.phone_tools.calls[call_id]['capture_id']
    value={'schema':'hepta.return-receipt.v149.1','operation_id':token,'launch_exit_code':0,
           'launch_b64':b64('Status: ok\nActivity: '+HEPTA_COMPONENT+'\n'),
           'page_b64':b64(WINDOW),'viewport_b64':b64(VIEWPORT)}
    raw=json.dumps(value,separators=(',',':')).encode()
    terminal={'kind':'exited','exit_code':0,'error':None,'output_truncated':False,
              'stdout_bytes':len(raw),'stderr_bytes':0}
    events=[{'kind':'accepted'},{'kind':'started','pid':999},
            {'kind':'output','stream':'stdout','encoding':'base64','byte_count':len(raw),'data':b64(raw)},
            {'kind':'terminal','terminal':terminal}]
    return {'call_id':call_id,'status':'terminal','terminal':terminal,
            'events':[{'call_id':call_id,'tool':call['tool'],'seq':i,'event':e} for i,e in enumerate(events)]}


def case(case_id, function):
    start=time.monotonic()
    count=len(REPORT['checks'])
    try:function()
    except BaseException as error:
        REPORT['cases'].append({'id':case_id,'status':'FAIL','layer':'host_isolated_fixture',
                               'error_type':type(error).__name__,'error':str(error),
                               'elapsed_seconds':time.monotonic()-start})
        raise
    else:REPORT['cases'].append({'id':case_id,'status':'PASS','layer':'host_isolated_fixture',
                                 'checks':len(REPORT['checks'])-count,
                                 'elapsed_seconds':time.monotonic()-start})


def health():
    server=ModelServer(RUN)
    try:
        turn=Turn(server,'health')
        terminal=turn.terminal();turn.finish()
        check('health fixture completed',terminal['kind']=='turn.complete')
        check('health no business claim',turn.outcome()['business_verified'] is False)
        check('single actual fixture model POST',server.calls==1)
        receipt=json.loads((turn.adapter.run_dir/'local-01.http-receipt.json').read_text())
        check('usage preserved exactly',receipt['usage']['total_tokens']==40)
        check('same selected model reported',receipt['response_model']==MODEL)
        check('worker group joined',json.loads((turn.adapter.run_dir/'local-01.joined.json').read_text())['dedicated_process_group_absent'])
        check('server slot idle independently observed',json.loads((turn.adapter.run_dir/'local-01.slot-after.json').read_text())['idle'])
        check('nested constrained schema sent',server.bodies[0]['response_format']['json_schema']['schema']['additionalProperties'] is False)
    finally:server.close()


def disconnect_before():
    server=ModelServer(RUN,'hold')
    try:
        turn=Turn(server,'disconnect-before')
        check('model fixture started before test disconnect',server.started.wait(3))
        turn.disconnect();turn.finish()
        check('no effect before disconnect',not turn.adapter.dispatched_calls)
        check('claim consumed after disconnect',turn.claim_count()==1)
        check('no business success on disconnect',turn.outcome()['business_verified'] is False)
        check('one original model request only',server.calls==1)
        again=Turn(server,'duplicate-before',evidence=turn.evidence,identity=turn.identity)
        terminal=again.terminal();again.finish()
        check('new stream cannot reuse semantic identity',terminal['kind']=='turn.fail' and server.calls==1)
    finally:server.close()


def disconnect_after():
    server=ModelServer(RUN,'return_once')
    try:
        turn=Turn(server,'disconnect-after')
        frame=turn.until('tool.call')
        counter=turn.root/'effect-counter';counter.write_text('1')
        turn.disconnect();turn.finish()
        check('one original effect after disconnect',counter.read_text()=='1' and len(turn.adapter.dispatched_calls)==1)
        check('pending result remains unknown',turn.adapter.pending_call_id==frame['call']['call_id'])
        check('disconnect cannot become business success',turn.outcome()['business_verified'] is False)
        again=Turn(server,'duplicate-after',evidence=turn.evidence,identity=turn.identity)
        terminal=again.terminal();again.finish()
        check('already-started effect never redispatched',terminal['kind']=='turn.fail' and server.calls==1 and counter.read_text()=='1')
    finally:server.close()


def model_timeout():
    server=ModelServer(RUN,'hold')
    try:
        turn=Turn(server,'model-timeout',timeout=1)
        terminal=turn.terminal();turn.finish()
        check('model timeout classified',terminal['kind']=='turn.fail' and 'model_timeout' in terminal['error'])
        check('timeout no tool dispatch',not turn.adapter.dispatched_calls)
        check('timeout no relaunch',server.calls==1)
        check('timeout claim retained',turn.claim_count()==1)
        check('timeout worker joined',json.loads((turn.adapter.run_dir/'local-01.joined.json').read_text())['dedicated_process_group_absent'])
    finally:server.close()


def executor_timeout():
    server=ModelServer(RUN,'return_once')
    try:
        turn=Turn(server,'executor-timeout')
        frame=turn.until('tool.call');counter=1
        turn.adapter.session_deadline=time.monotonic()+0.15
        terminal=turn.terminal()
        path=turn.adapter.run_dir/'terminal.json'
        before=hashlib.sha256(path.read_bytes()).hexdigest()
        with contextlib.suppress(OSError):turn.send('tool.result',**reply_for(frame['call'],turn.adapter))
        turn.finish()
        check('executor deadline fails',terminal['kind']=='turn.fail')
        check('late result cannot overwrite terminal',hashlib.sha256(path.read_bytes()).hexdigest()==before)
        check('no second effect after late result',counter==1 and len(turn.adapter.dispatched_calls)==1 and server.calls==1)
        check('late result not business success',not turn.outcome()['business_verified'])
    finally:server.close()


def cancel_before():
    server=ModelServer(RUN,'hold')
    try:
        turn=Turn(server,'cancel-before')
        check('cancel fixture starts',server.started.wait(3))
        turn.send('turn.cancel')
        terminal=turn.terminal();turn.finish()
        check('before-effect cancellation terminal',terminal['kind']=='turn.cancelled')
        check('cancel no phone effect',len(turn.adapter.dispatched_calls)==0)
        check('cancel retains original claim',turn.claim_count()==1)
        check('cancel no business success',not turn.outcome()['business_verified'])
    finally:server.close()


def cancel_after():
    server=ModelServer(RUN,'return_then_hold')
    try:
        turn=Turn(server,'cancel-after')
        frame=turn.until('tool.call');counter=1
        turn.send('tool.result',**reply_for(frame['call'],turn.adapter))
        check('post-effect second model round started',server.second_started.wait(3))
        turn.send('turn.cancel')
        terminal=turn.terminal();turn.finish()
        check('after-effect cancellation terminal',terminal['kind']=='turn.cancelled')
        check('exactly prior confirmed effect remains',counter==1 and len(turn.adapter.dispatched_calls)==1)
        check('no forced follow-up or business complete',not turn.outcome()['business_verified'])
        check('both worker groups joined',len(list(turn.adapter.run_dir.glob('local-*.joined.json')))==2)
    finally:server.close()


def budgets_and_tools():
    for bad in ['https://127.0.0.1:18087/v1/chat/completions','http://192.168.1.2:18087/v1/chat/completions',
                'http://localhost:18087/v1/chat/completions','http://127.0.0.1:18087/v1/chat/completions?x=1']:
        reject('reject non-pinned endpoint '+bad,lambda bad=bad:endpoint_parts(bad))
    for mode in ['length','unselected_shell','redirect']:
        server=ModelServer(RUN,mode)
        try:
            turn=Turn(server,mode)
            terminal=turn.terminal();turn.finish()
            check('fail closed '+mode,terminal['kind']=='turn.fail' and not turn.adapter.dispatched_calls)
            check('no retry/fallback '+mode,server.calls==1)
            if mode=='length':check('token budget explicit','model_budget_exhausted' in terminal['error'])
        finally:server.close()
    work=RUN/'mapper';work.mkdir(mode=0o700)
    atomic=lambda p,v:p.write_text(json.dumps(v))
    mapper=PhoneLocalTools(work,atomic,APPS,{'mode':'adb_legacy'})
    mapper.bind({'session_id':'s-'+secrets.token_hex(16),'profile_id':'p','task_id':'t','turn_id':'u','turn_stream_id':'v'})
    mapper.encoded_bytes_used=393216-65535
    reject('image byte budget blocks before dispatch',lambda:mapper.map({'call_id':'budget','tool':'phone.screenshot','command':'','argv':['0']}))
    mapper.visual_read_constraints=[{'package':PCK}]
    reject('visual challenge cannot be read through observe',lambda:mapper.map({'call_id':'leak','tool':'phone.observe','command':'','argv':[PCK]}))
    reject('unknown app is not executable',lambda:mapper.map({'call_id':'unknown','tool':'phone.open_app','command':'','argv':['missing-app']}))
    reject('shell is not a phone tool',lambda:mapper.map({'call_id':'shell','tool':'shell.exec','command':'echo prohibited','argv':[]}))
    mapper.latest={'call_id':'fresh','attached_round':1,'received_monotonic':time.monotonic()-121,
                   'encoded_size':[400,1000]}
    mapper.round=1
    reject('expired image cannot tap',lambda:mapper.map({'call_id':'expired','tool':'phone.tap','command':'','argv':['fresh','1','1']}))
    mapper.latest['received_monotonic']=time.monotonic()
    reject('foreign screenshot cannot tap',lambda:mapper.map({'call_id':'foreign','tool':'phone.tap','command':'','argv':['other','1','1']}))
    mapper.latest['attached_round']=0
    reject('old round image cannot tap',lambda:mapper.map({'call_id':'round','tool':'phone.tap','command':'','argv':['fresh','1','1']}))
    shell=tool_call({'type':'function','id':'shell-argv','function':{'name':'shell_exec','arguments':json.dumps({'argv':['/usr/bin/python3','/reviewed/client.py']})}},set())
    check('shell argv is real shell.exec wire',shell['tool']=='shell.exec' and 'command' not in shell)
    reject('shell command+argv ambiguity rejected',lambda:tool_call({'type':'function','id':'ambiguous','function':{'name':'shell_exec','arguments':json.dumps({'command':'x','argv':['x']})}},set()))


def native_envelope():
    call={'call_id':'native-'+secrets.token_hex(8),'tool':'shell.exec'}
    raw=b'{}'
    terminal={'kind':'exited','exit_code':0,'error':None,'output_truncated':False,'stdout_bytes':2,'stderr_bytes':0}
    events=[{'kind':'accepted'},{'kind':'started','pid':999},{'kind':'output','stream':'stdout','encoding':'base64','byte_count':2,'data':b64(raw)},
            {'kind':'terminal','terminal':terminal}]
    reply={'call_id':call['call_id'],'status':'terminal','terminal':terminal,
           'events':[{'call_id':call['call_id'],'tool':'shell.exec','seq':i,'event':e} for i,e in enumerate(events)]}
    check('exact shell.exec envelope admitted',native_streams(reply,call['call_id'],'shell.exec')==raw)
    reject('shell cannot masquerade as adb',lambda:native_streams(reply,call['call_id'],'adb.exec'))
    for label,mutate in [
      ('call',lambda r:r.update(call_id='foreign')),
      ('seq',lambda r:r['events'][2].update(seq=99)),
      ('bytes',lambda r:r['events'][2]['event'].update(byte_count=999)),
      ('exit',lambda r:r['terminal'].update(exit_code=1)),
      ('truncation',lambda r:r['terminal'].update(output_truncated=True)),
      ('base64',lambda r:r['events'][2]['event'].update(data='!')),
      ('wire',lambda r:r['events'][1].update(tool='adb.exec'))]:
        changed=json.loads(json.dumps(reply));mutate(changed)
        reject('damaged native envelope '+label,lambda changed=changed:native_streams(changed,call['call_id'],'shell.exec'))


def partial_completion():
    digest='f'*64
    contract={'contract':{'coverage':'entire_request','postconditions':[
        {'id':'input','kind':'text_readback_exact','package':PCK,'view_id':PCK+':id/unicode_input','utf8_sha256':digest},
        {'id':'public','kind':'public_text_exact','package':PCK,'view_id':PCK+':id/unicode_readback','utf8_sha256':digest},
        {'id':'return','kind':'foreground_hepta'}]},'source_sha256':'a'*64}
    facts=[{'kind':'text_readback_exact','call_id':'input','package':PCK,'view_id':PCK+':id/unicode_input','utf8_sha256':digest}]
    outcome=evaluate(contract,facts,'input','completed','turn.complete')
    kind,_=terminal_fields('turn.complete',{'summary':'claimed success'},outcome,True)
    check('input-only completed declaration fails',kind=='turn.fail' and not outcome['business_verified'])
    facts.append({'kind':'public_text_observation','call_id':'public','package':PCK,'values':[{'view_id':PCK+':id/unicode_readback','utf8_sha256':digest}]})
    outcome=evaluate(contract,facts,'public','completed','turn.complete')
    check('public receipt without return fails',terminal_fields('turn.complete',{},outcome,True)[0]=='turn.fail')
    facts.append({'kind':'foreground_hepta','call_id':'return'})
    contract['contract']['coverage']='declared_postconditions_only'
    outcome=evaluate(contract,facts,'return','completed','turn.complete')
    check('partial coverage cannot qualify whole task',terminal_fields('turn.complete',{},outcome,True)[0]=='turn.fail')


def capacity():
    evidence=RUN/'capacity';evidence.mkdir(mode=0o700)
    run=evidence/('20261103-120000-'+secrets.token_hex(16));run.mkdir(mode=0o700)
    temp=run/'local-01.request.json.new';temp.write_bytes(b'{}')
    canonical=run/'local-01.request.json'
    check('new local evidence temp grammar recognized',expected_evidence_temporary(temp,evidence))
    enumerated=list(run.iterdir());os.replace(temp,canonical)
    check('recognized rename race tolerated',evidence_item_size(enumerated[0],evidence) is None)
    check('canonical renamed evidence counted',evidence_item_size(canonical,evidence)==2)
    reject('missing canonical evidence fails',lambda:evidence_item_size(run/'local-02.request.json',evidence))
    reject('unknown missing temporary fails',lambda:evidence_item_size(run/'unrecognized.json.new',evidence))
    orphan=run/'local-03.spawn-intent.json';orphan.write_text('{}')
    check('unjoined intent remains present',orphan.exists() and not orphan.with_name('local-03.joined.json').exists())


def main():
    case('LOCAL-HEALTH-FIXTURE',health)
    case('NEG-04',disconnect_before)
    case('NEG-05',disconnect_after)
    case('NEG-06',model_timeout)
    case('NEG-07',executor_timeout)
    case('NEG-08',cancel_before)
    case('NEG-09',cancel_after)
    case('NEG-10',budgets_and_tools)
    case('NEG-11',native_envelope)
    case('NEG-12',partial_completion)
    case('NEG-14-SUBSET',capacity)


try:
    main();REPORT['status']='PASS'
except BaseException as error:
    REPORT['status']='FAIL';REPORT['error_type']=type(error).__name__;REPORT['error']=str(error)
    REPORT['traceback']=traceback.format_exc()
finally:
    REPORT['completed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    REPORT['physical_lifecycle_qualification']=False
    REPORT['neg13_contract_race_not_executed_by_this_runner']=True
    raw=json.dumps(REPORT,ensure_ascii=False,indent=2).encode()
    (RUN/'RESULT.json').write_bytes(raw)
    print(json.dumps({'status':REPORT['status'],'checks':len(REPORT['checks']),'cases':REPORT['cases'],
                      'result':str(RUN/'RESULT.json'),'sha256':hashlib.sha256(raw).hexdigest()},ensure_ascii=False))
sys.exit(0 if REPORT['status']=='PASS' else 1)
