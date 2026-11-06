#!/usr/bin/env python3
"""NEG-03 isolated original-shaped geometry receipts against actual sealed sources.
Default is a zero-I/O preview. This program has no phone or process transport.
A passing result is the protocol's fixture component case, never physical,
native-task, model, or business qualification.
"""
import argparse,base64,copy,hashlib,json,os,platform,re,resource,stat,sys,time,traceback,types
from pathlib import Path
sys.dont_write_bytecode=True
ASSETS={'png':(1191,'4318a71128144b0e7da041731c3014192fffb4f1a15495eda8864a774c831d13'),
        'jpeg':(19356,'e8e0d7d851b6079e29e86c69f176056bee2ed849540620f0505a34ddf0438521')}
NEGATIVES=(('screenshot','display'),('screenshot','rotation'),('screenshot','geometry'),
           ('return','display'),('return','rotation'),('return','geometry'))
def context(manifest_sha):
 def exact(raw):
  def pairs(rows):
   result={}
   for key,value in rows:
    if key in result:raise ValueError('duplicate JSON key')
    result[key]=value
   return result
  return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
 def md(st):return tuple(getattr(st,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 def read(path,maximum):
  if path.resolve(strict=True)!=path:raise ValueError('canonical original required')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd)
   if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or not 0<st.st_size<=maximum:raise ValueError('bounded single-link source required')
   with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(st.st_size+1)
   if len(raw)!=st.st_size or md(st)!=md(os.fstat(fd)) or md(st)!=md(path.lstat()):raise ValueError('source changed')
   return raw
  finally:os.close(fd)
 root=Path(__file__).absolute().parent.parent
 raw=read(root/'MANIFEST.json',262144)
 if not isinstance(manifest_sha,str) or hashlib.sha256(raw).hexdigest()!=manifest_sha:raise ValueError('explicit package manifest pin required')
 manifest=exact(raw)
 rows=[r for r in manifest['files'] if r['path']=='source/component_source_context.py']
 if len(rows)!=1:raise ValueError('single pinned source context required')
 row=rows[0];path=root/row['path'];source=read(path,262144)
 if len(source)!=row['bytes'] or hashlib.sha256(source).hexdigest()!=row['sha256']:raise ValueError('source context differs')
 module=types.ModuleType('fixed19_component_source_context');module.__file__=str(path)
 exec(compile(source,str(path),'exec',optimize=0),module.__dict__)
 originals=module.Originals()
 package=module.verify_source_package(originals,root,manifest_sha)
 return module,originals,package

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def b64(raw):return base64.b64encode(raw if isinstance(raw,bytes) else raw.encode()).decode()
def page(component='org.example.hepta.synthetic/.FixtureActivity'):
 return ('Display: mDisplayId=0\nmTopFocusedDisplayId=0\n'
  'mCurrentFocus=Window{synthetic u0 '+component+'}\n'
  'mFocusedApp=ActivityRecord{synthetic u0 '+component+'}\n'
  'isKeyguardShowing=false\ntopResumedActivity=ActivityRecord{synthetic u0 '+component+'}\n')
def viewport(obs):
 return "DisplayViewport{type=INTERNAL, valid=true, isActive=true, displayId=0, uniqueId='local:"+obs.PHYSICAL_DISPLAY+"', orientation=0, logicalFrame=Rect(0, 0 - 1224, 2992), physicalFrame=Rect(0, 0 - 1224, 2992)}"
def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reference_field(hasher, name, value):
    raw_name = name.encode("ascii")
    hasher.update(len(raw_name).to_bytes(8, "big"))
    hasher.update(raw_name)
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def reference_claims(call, scope):
    # Independent transcription of the reviewed Rust narrow argv preimage.
    # No production native_bound_call or digest helper is invoked here.
    value = {key: scope[key] for key in ("session_id", "profile_id", "task_id", "turn_id")}
    value.update(tool=call["tool"], argv=call["argv"], config_generation=None, mode="argv",
                 pty=False, timeout_ms=0, stream=True, protocol="trillionnium.agent.turn.v1", protocol_version=1)
    if "target" in call or "target_id" in call:
        value["target_id"] = call.get("target_id") if call.get("target_id") is not None else call.get("target")
    fingerprint = hashlib.sha256()
    for key, raw in (("schema", b"trillionnium.owner-open.binding.v1"), ("tool", call["tool"].encode()),
                     ("executable", b"/bin/sh" if call["tool"] == "shell.exec" else b"adb"),
                     ("config_generation", b"null")):
        reference_field(fingerprint, key, raw)
    return {"request_sha256": sha(canonical(value)), "binding_fingerprint": fingerprint.hexdigest()}


def reference_observation(call, reply):
    digest = hashlib.sha256()
    target = call.get("target_id") if call.get("target_id") is not None else call.get("target")
    for key, raw in (("schema", b"trillionnium.owner-open.local-observation.v1"),
                     ("call_id", call["call_id"].encode()), ("tool", call["tool"].encode()),
                     ("target_id", target.encode() if target is not None else b""),
                     ("spawn_generation", reply["generation"].to_bytes(8, "big"))):
        reference_field(digest, key, raw)
    for index, record in enumerate(reply["events"]):
        event = record["event"]
        reference_field(digest, "event_ordinal", index.to_bytes(8, "big"))
        reference_field(digest, "kind", event["kind"].encode())
        if event["kind"] == "started":
            reference_field(digest, "pid", event["pid"].to_bytes(4, "big"))
        elif event["kind"] == "output":
            reference_field(digest, "stream", event["stream"].encode())
            reference_field(digest, "bytes", base64.b64decode(event["data"], validate=True))
        elif event["kind"] == "terminal":
            terminal = event["terminal"]
            reference_field(digest, "terminal_kind", terminal["kind"].encode())
            for key in ("exit_code", "signal"):
                value = terminal[key] if terminal[key] is not None else -2147483648
                reference_field(digest, key, value.to_bytes(4, "big", signed=True))
            for key in ("stdout_bytes", "stderr_bytes"):
                reference_field(digest, key, terminal[key].to_bytes(8, "big"))
            reference_field(digest, "output_truncated", bytes([int(terminal["output_truncated"])]))
            reference_field(digest, "elapsed_ms", terminal["elapsed_ms"].to_bytes(8, "big"))
            reference_field(digest, "error", (terminal["error"] or "").encode())
    return digest.hexdigest()


def seal_native_fixture(reply, call, scope):
    claims = reference_claims(call, scope)
    reply["registry"].update(claims)
    observed = reference_observation(call, reply)
    reply["observation_sha256"] = observed
    terminal = reply["terminal"]
    exit_value = "None" if terminal["exit_code"] is None else "Some(" + str(terminal["exit_code"]) + ")"
    signal_value = "None" if terminal["signal"] is None else "Some(" + str(terminal["signal"]) + ")"
    reply["registry"]["state"] = (
        'Terminal { generation: ' + str(reply["generation"]) + ', terminal: TerminalRecord { terminal_kind: "'
        + terminal["kind"] + '", exit_code: ' + exit_value + ', signal: ' + signal_value
        + ', observation_sha256: "' + observed + '", stdout_bytes: ' + str(terminal["stdout_bytes"])
        + ', stderr_bytes: ' + str(terminal["stderr_bytes"]) + ' } }')
    return reply


def native(call_id, raw, tool, *, wire_call, scope):
    # Explicitly synthetic current-schema receipt. Real archived NEG01 goldens
    # independently verify these preimages; no physical execution is attested.
    assert wire_call["call_id"] == call_id and wire_call["tool"] == tool
    target = wire_call.get("target_id") if wire_call.get("target_id") is not None else wire_call.get("target")
    terminal = {"kind": "exited", "exit_code": 0, "signal": None, "stdout_bytes": len(raw),
                "stderr_bytes": 0, "output_truncated": False, "elapsed_ms": 7, "error": None}
    events = [{"kind": "accepted"}, {"kind": "started", "pid": 12345},
              {"kind": "output", "stream": "stdout", "encoding": "base64",
               "data": b64(raw), "byte_count": len(raw)},
              {"kind": "terminal", "terminal": copy.deepcopy(terminal)}]
    reply = {"protocol": "trillionnium.owner-open.provider-jsonl.v1", "kind": "tool.result", "seq": 1,
             "call_id": call_id, "status": "terminal", "terminal": terminal,
             "registry": {"call_id": call_id, "tool": tool, "target_id": target,
                          "cancellation_requested": False, "connection_lost": False,
                          "earliest_history_seq": 0, "next_event_seq": 4},
             "generation": 1,
             "events": [{"call_id": call_id, "target_id": target, "tool": tool,
                         "seq": i, "elapsed_ms": i * 2, "event": event}
                        for i, event in enumerate(events)]}
    return seal_native_fixture(reply, wire_call, scope)


def synthetic_reply(call,raw):
 # Only explicitly synthetic fixture scopes enter this constructor.
 assert all(isinstance(value,str) and value.startswith('synthetic-') for value in call['turn'].values())
 return native(call['call_id'],raw,call['wire_tool'],wire_call=call['wire_call'],scope=call['turn'])
def image_envelope(obs,token,jpeg,png):
 screen={'schema':'hepta.phone-screenshot.v1','status':'encoded','capture_id':token,'serial':obs.SERIAL,
  'logical_display_id':0,'physical_display_id':obs.PHYSICAL_DISPLAY,'rotation':0,
  'viewport_before':viewport(obs),'viewport_after':viewport(obs),'original_width':1224,'original_height':2992,
  'encoded_width':153,'encoded_height':374,'media_type':'image/jpeg','encoding':'base64','quality':75,
  'data_base64':b64(jpeg),'image_sha256':hashlib.sha256(jpeg).hexdigest(),
  'source_png_sha256':hashlib.sha256(png).hexdigest(),'source_png_bytes':len(png),'encoded_bytes':len(jpeg)}
 return {'schema':'hepta.capture-page-envelope.v149.1','capture_id':token,
         'page_before_b64':b64(page()),'page_after_b64':b64(page()),'screenshot':screen}
def return_envelope(obs,guards,token):
 launch='Status: ok\nActivity: '+guards.HEPTA_COMPONENT+'\n'
 return {'schema':'hepta.return-receipt.v149.1','operation_id':token,'launch_exit_code':0,
         'launch_b64':b64(launch),'page_b64':b64(page(guards.HEPTA_COMPONENT)),
         'viewport_b64':b64(viewport(obs))}
def differences(a,b,path=''):
 if type(a) is not type(b):return [path]
 if isinstance(a,dict):
  if set(a)!=set(b):return [path]
  return [r for k in sorted(a) for r in differences(a[k],b[k],path+'/'+k)]
 if isinstance(a,list):
  if len(a)!=len(b):return [path]
  return [r for i,(x,y) in enumerate(zip(a,b)) for r in differences(x,y,path+'/'+str(i))]
 return [] if a==b else [path]

class Evidence:
 def __init__(self,C,obs,guards,provider,root,fixture_id,assets):
  self.C,self.obs,self.guards,self.provider=C,obs,guards,provider
  self.root,self.fixture_id,self.assets=root,fixture_id,assets
  self.checks=[];self.rows=[];self.files=[]
 def record(self,path,value):
  row=self.C.put(path,self.C.encode(value));self.files.append(row);return row
 def check(self,name,condition):
  row={'name':name,'passed':condition is True};self.checks.append(row)
  self.C.need(condition is True,name)
 def reject(self,name,fn,expected):
  try:fn()
  except self.provider.ProviderError as error:
   self.check(name+' original rejection reason',expected in str(error))
   return {'type':type(error).__name__,'message':str(error),'rejected':True}
  raise AssertionError(name+' incorrectly passed')
 def tools(self,label):
  root=self.C.fresh_directory(self.root/label);writes=[]
  def record(path,value):
   writes.append(str(path));return self.record(path,value)
  t=self.obs.PhoneTools(root,record)
  token=self.C.sha(canonical([self.fixture_id,label]))[:32]
  identity={key:'synthetic-'+key+'-'+token for key in
            ('session_id','profile_id','task_id','turn_id','turn_stream_id')}
  self.check(label+' explicitly synthetic native scope with no actual task',
             all(value.startswith('synthetic-') for value in identity.values()))
  t.bind(identity)
  return t,root,writes
 def mapped(self,t,call_id,tool,argv):
  decision={'call_id':call_id,'tool':tool,'argv':argv,'command':''}
  wire=t.map(decision);call=t.calls[call_id]
  self.check(call_id+' mapper retained its exact wire',wire==call['wire_call']['argv'])
  return call
 def prepare(self,t,root,call,envelope,round_number,name):
  payload=canonical(envelope);reply=synthetic_reply(call,payload);raw=canonical(reply)
  self.C.put(root/(name+'.synthetic-native-reply.original.json'),raw)
  self.C.put(root/(name+'.synthetic-payload.original.json'),payload)
  message={'role':'tool','tool_call_id':call['call_id'],'content':raw.decode()}
  return t.prepare([message],[copy.deepcopy(message)],round_number)
 def baseline_screenshot(self,t,root,label):
  call=self.mapped(t,label+'-base','phone.screenshot',['0'])
  envelope=image_envelope(self.obs,call['capture_id'],self.assets['jpeg'],self.assets['png'])
  rendered,images=self.prepare(t,root,call,envelope,1,'qualified-baseline')
  self.check(label+' original-shaped qualified screenshot passes',len(images)==1 and t.latest is not None
             and t.latest['call_id']==call['call_id'] and t.latest['encoded_size']==[153,374]
             and t.latest['attached_round']==1 and t.latest['observed_page']['display_id']==0)
  return call,envelope

def run_fixtures(C,obs,guards,provider,root,fixture_id,assets):
 e=Evidence(C,obs,guards,provider,root,fixture_id,assets)
 e.check('production geometry and budgets unchanged',obs.ORIGINAL_SIZE==(1224,2992)
         and obs.PHYSICAL_DISPLAY=='4630947043778501779' and obs.MAX_IMAGE_BYTES==196608
         and obs.MAX_TURN_IMAGE_BYTES==393216)
 t,d,writes=e.tools('positive-screenshot-and-tap')
 call,_=e.baseline_screenshot(t,d,'positive')
 tap=e.mapped(t,'positive-tap','phone.tap',[call['call_id'],'0','0'])
 shell=tap['wire_call']['argv'][-1]
 e.check('qualified baseline tap only maps display0 and does not execute',
         shell.count('input -d 0 tap ')==1 and 'input -d 1 ' not in shell and tap['original_xy']==[0,0])
 t,d,writes=e.tools('positive-return')
 call=e.mapped(t,'positive-return','phone.return_hepta',[])
 envelope=return_envelope(obs,guards,call['capture_id'])
 e.prepare(t,d,call,envelope,1,'qualified-return')
 observed,vp=guards.verify_return(envelope,call['capture_id']);obs.validate_viewport(vp)
 e.check('qualified return launch focus keyguard and viewport pass',
         observed['component']==guards.HEPTA_FULL_COMPONENT and observed['keyguard_showing'] is False
         and t.verified_facts[call['call_id']]['evidence_type']=='explicit_return_launch_and_actual_focus')
 for semantic,axis in NEGATIVES:
  label=semantic+'-'+axis;t,d,writes=e.tools(label)
  e.baseline_screenshot(t,d,label)
  bad_id=label+'-negative'
  call=e.mapped(t,bad_id,'phone.screenshot' if semantic=='screenshot' else 'phone.return_hepta',
                ['0'] if semantic=='screenshot' else [])
  if semantic=='screenshot':
   qualified=image_envelope(obs,call['capture_id'],assets['jpeg'],assets['png'])
   negative=copy.deepcopy(qualified)
   key={'display':'logical_display_id','rotation':'rotation','geometry':'original_width'}[axis]
   negative['screenshot'][key]={'display':1,'rotation':1,'geometry':1225}[axis]
   expected_path='/screenshot/'+key
   reason='screenshot codec fields differ' if axis=='geometry' else 'screenshot metadata does not match the selected phone call'
  else:
   qualified=return_envelope(obs,guards,call['capture_id']);negative=copy.deepcopy(qualified)
   vp=viewport(obs)
   old,new={'display':('displayId=0','displayId=1'),'rotation':('orientation=0','orientation=1'),
            'geometry':('logicalFrame=Rect(0, 0 - 1224, 2992)','logicalFrame=Rect(0, 0 - 1225, 2992)')}[axis]
   e.check(label+' exactly one viewport substitution',vp.count(old)==1)
   badvp=vp.replace(old,new);negative['viewport_b64']=b64(badvp);expected_path='/viewport_b64'
   reason='screenshot display or rotation is not qualified'
   # This isolates the viewport qualification after a valid return receipt.
   before,v=guards.verify_return(negative,call['capture_id'])
   e.check(label+' launch and focus remain valid before viewport gate',
           before['component']==guards.HEPTA_FULL_COMPONENT and v==badvp)
  e.check(label+' only its declared geometry field differs',differences(qualified,negative)==[expected_path])
  e.record(d/'DECLARED-MUTATION.json',{'synthetic':True,'semantic':semantic,'axis':axis,
            'qualified_payload':C.pin(canonical(qualified)),'negative_payload':C.pin(canonical(negative)),
            'changed_paths':[expected_path],'physical_observation':False})
  C.put(d/'paired-qualified.synthetic-payload.json',canonical(qualified))
  error=e.reject(label,lambda:e.prepare(t,d,call,negative,2,'unqualified'),reason)
  e.check(label+' rejected result has no current valid latest or admitted fact',
          t.latest is None and bad_id not in t.images and bad_id not in t.verified_facts)
  before_calls=copy.deepcopy(t.calls);before_writes=list(writes)
  tap_error=e.reject(label+' subsequent tap',
      lambda:t.map({'call_id':label+'-tap','tool':'phone.tap','command':'','argv':[bad_id,'0','0']}),
      "current completion's latest valid screenshot")
  e.check(label+' rejected tap creates no wire or atomic record',t.calls==before_calls and writes==before_writes)
  row={'name':label,'mutation_path':expected_path,'original_parser_rejection':error,
       'subsequent_original_tap_rejection':tap_error,'current_valid_latest':False,
       'new_tap_mapping':False,'input_dispatches':0,'physical_qualified':False}
  e.rows.append(row);e.record(d/'OBSERVATION.json',row)
 e.check('all six independent single-field negative cases observed',len(e.rows)==6)
 return e

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--plan');p.add_argument('--plan-sha256');p.add_argument('--package-manifest-sha256')
 p.add_argument('--out');p.add_argument('--execute-host-fixture-once',action='store_true')
 a=p.parse_args()
 if not a.execute_host_fixture_once:
  print(json.dumps({'schema':'hepta.fixed19.neg03.fixture-preview.v1','state':'SOURCE_ONLY_NO_INPUTS_READ',
      'case_id':'NEG-03','physical_test':False,'phone_calls':0,'model_calls':0,'case_executed':False,
      'requires':['actual sealed release','explicit plan and package pins','fresh isolated host output','execute flag']},sort_keys=True))
  return 0
 if not all((a.plan,a.plan_sha256,a.package_manifest_sha256,a.out)):raise ValueError('all actual inputs and pins required')
 C,originals,package=context(a.package_manifest_sha256)
 plan_path=Path(a.plan)
 raw=C.read_plan(originals,plan_path,a.plan_sha256)
 plan=C.strict(raw)
 C.need(isinstance(plan,dict) and set(plan)=={'schema','case_id','release','fixture_id','assets','maximum_effect_dispatches','physical_test'}
        and plan['schema']=='hepta.fixed19.neg03.geometry-fixture-plan.v1' and plan['case_id']=='NEG-03'
        and isinstance(plan['fixture_id'],str) and re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',plan['fixture_id'])
        and type(plan['maximum_effect_dispatches']) is int and plan['maximum_effect_dispatches']==0
        and plan['physical_test'] is False and set(plan['assets'])==set(ASSETS),'explicit fixture plan differs')
 for key,(size,digest) in ASSETS.items():
  C.need({k:plan['assets'][key][k] for k in ('bytes','sha256')}=={'bytes':size,'sha256':digest},'frozen synthetic asset differs')
 output=Path(a.out).absolute();package_root=Path(__file__).absolute().parent.parent
 C.need(output!=package_root and package_root not in output.parents,'fixture output may not modify source package')
 C.need(output!=Path(plan['release']['path']) and Path(plan['release']['path']) not in output.parents,'fixture output may not modify release')
 started=time.monotonic_ns();usage_before=resource.getrusage(resource.RUSAGE_SELF)
 out=C.fresh_directory(output);audit=C.audit_no_effects(out);e=None
 C.put(out/'INTENT.json',C.encode({'schema':'hepta.fixed19.neg03.fixture-intent.v1','case_id':'NEG-03',
       'plan':{'path':str(plan_path),**C.pin(raw)},'source_package':package['descriptor'],
       'fixture_id':plan['fixture_id'],'maximum_starts':1,'automatic_retry':False,'maximum_effect_dispatches':0}))
 try:
  result,release_pins=C.sealed_sources(originals,plan['release'])
  protocol,case=C.protocol(originals,'NEG-03')
  assets={key:originals.descriptor(row,262144) for key,row in plan['assets'].items()}
  C.put(out/'PLAN.original.json',raw);C.put(out/'PROTOCOL.original.json',protocol)
  source_dir=C.fresh_directory(out/'production-originals')
  for name,source in sorted(result['source'].items()):C.put(source_dir/name,source)
  C.put(out/'RELEASE-BINDING.json',C.encode(release_pins))
  fixture_root=C.fresh_directory(out/'synthetic-receipts')
  with C.production_modules(result['source']) as modules:
   e=run_fixtures(C,modules['phone_observation_tools'],modules['phone_task_guards'],
                  modules['provider_openai_compatible'],fixture_root,plan['fixture_id'],assets)
  C.recheck_source_package(originals,package)
  C.need(audit['network_or_process_attempts']==0 and audit['writes_outside_output']==0,'fixture isolation was violated')
  ended=time.monotonic_ns();usage_after=resource.getrusage(resource.RUSAGE_SELF)
  report={'schema':'hepta.fixed19.neg03.geometry-fixture-result.v1','state':'NEG03_COMPONENT_FIXTURE_PASSED',
   'case_id':'NEG-03','layer':'component_direct','execution_kind':'isolated_original_shaped_synthetic_receipts',
   'fixture_id':plan['fixture_id'],'fixed19_component_case_passed':True,'physical_qualified':False,
   'native_task_qualified':False,'model_qualified':False,'business_verified':False,
   'all_receipts_synthetic':True,'actual_phone_observations':0,'no_original_native_task_identity_fabricated':True,
   'all_native_scopes_synthetic':True,'actual_native_scope_or_generation_attested':False,
   'source_package':package['descriptor'],'release_pins':release_pins,'contract':C.pin(protocol),
   'source_originals':list(originals.seen.values()),'checks':e.checks,'negative_observations':e.rows,
   'metrics':{'latency':{'host_elapsed_ns':ended-started,'start_monotonic_ns':started,'end_monotonic_ns':ended},
    'usage':{'model_requests':0,'tokens':0,'phone_calls':0,'input_dispatches':0},
    'cost':{'model_billed_usd':0,'basis':'no model call'},
    'resources':{'user_cpu_seconds':usage_after.ru_utime-usage_before.ru_utime,
                 'system_cpu_seconds':usage_after.ru_stime-usage_before.ru_stime,
                 'process_maxrss':usage_after.ru_maxrss,'maxrss_unit':'bytes' if sys.platform=='darwin' else 'KiB'},
    'evidence':{'original_protocol_retained':True,'all_fifteen_production_sources_retained':True,
                'qualified_baselines_and_single_field_mutations_retained':True},
    'restoration':{'state':'NO_DEVICE_EFFECTS_NO_DEVICE_RESTORATION_REQUIRED','physical_baseline_changed':False}},
   'isolation':audit,'automatic_retry':False,'old_six_host_suite_membership_changed':False}
  C.put(out/'RESULT.json',C.encode(report));print(json.dumps({'state':report['state'],'case_id':'NEG-03',
      'result':{'path':str(out/'RESULT.json'),**C.pin(C.encode(report))},'physical_qualified':False,
      'phone_calls':0,'model_requests':0},sort_keys=True));return 0
 except BaseException as error:
  failure={'schema':'hepta.fixed19.neg03.geometry-fixture-failure.v1','state':'FAILED_FIXTURE_ORIGINALS_PRESERVED',
    'error_type':type(error).__name__,'detail':str(error)[:1024],'checks':[] if e is None else e.checks,
    'source_originals':list(originals.seen.values()),'isolation':audit,'automatic_retry':False,
    'fixed19_component_case_passed':False,'physical_qualified':False,'phone_calls':0,'model_requests':0}
  C.put(out/'FAILURE.json',C.encode(failure));raise
if __name__=='__main__':raise SystemExit(main())
