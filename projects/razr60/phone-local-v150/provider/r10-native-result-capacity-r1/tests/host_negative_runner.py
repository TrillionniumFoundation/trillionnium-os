#!/usr/bin/env python3
"""Retained r7-r3 NEG10/11/12/13 case functions, with native-envelope regressions.

Use run_regressions.py for the separately sealed r10 candidate. The historical
namespace entry and its old seals below do not qualify this new candidate.
"""
import argparse,base64,copy,datetime,hashlib,importlib,json,os,resource,secrets,signal,stat,sys,threading,time,traceback,types
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
BASE=Path('/suite')
SOURCE=BASE/'provider/source'
SEAL=BASE/'provider/SOURCE-SEAL.json'
SEAL_SHA='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
COMBO=BASE/'combination.json'
COMBO_SHA='e42e6cb00112be91ac9414b04786ad2693b86a9af413b8f90a0e0e42543c81d1'
COMBO_CANONICAL='1cfbfcbd919bafed31af23750d448f38303a8ed86680e18b0718df5b0fb3d188'
PROTOCOL=BASE/'protocol.json'
PROTOCOL_SHA='74e8f8e6c22ba6240ba85cb610cb46ff8a0f158a39375118385f5012a47efdfb'
ORIGINAL_PROTOCOL=BASE/'original-protocol.json'
ORIGINAL_SHA='c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0'
ASSETS={'synthetic.png':(1191,'4318a71128144b0e7da041731c3014192fffb4f1a15495eda8864a774c831d13'),'synthetic.jpg':(19356,'e8e0d7d851b6079e29e86c69f176056bee2ed849540620f0505a34ddf0438521')}
IDS=('NEG-10','NEG-11','NEG-12','NEG-13')
PACKAGE='org.example.hepta.synthetic'
EDITOR=PACKAGE+':id/editor'
PUBLIC=PACKAGE+':id/receipt'
APP=PACKAGE+'/.FixtureActivity'
AUDIT=[]
OUT=None
OBS=GUARDS=CONTRACT=CODEX=OPENAI=None
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def new_json(path,value):
 raw=json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False).encode()+b'\n'
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def mkdir(path):
 path.mkdir(mode=0o700)
 return path
def read_pinned(path,expected,maximum=1024*1024):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=maximum
  with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(maximum+1)
  after=os.fstat(fd)
  assert len(raw)==st.st_size and (st.st_dev,st.st_ino,st.st_mtime_ns,st.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns)
 finally:os.close(fd)
 assert sha(raw)==expected,(str(path),'sha mismatch')
 return raw
def file_record(path):
 raw=path.read_bytes()
 return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}
def audit(event,args):
 denied=False
 if event in {'socket.__new__','socket.connect','socket.bind','subprocess.Popen','os.system','os.fork','os.posix_spawn','os.exec','pty.spawn'}:
  denied=True
 if event=='open' and len(args)>2 and isinstance(args[0],(str,bytes,os.PathLike)):
  flags=args[2]
  if isinstance(flags,int) and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
   p=os.path.abspath(os.fsdecode(args[0]));denied=not(p==str(OUT) or p.startswith(str(OUT)+os.sep))
 if event in {'os.mkdir','os.remove','os.rmdir','os.chmod','os.rename'}:
  paths=args[:2] if event=='os.rename' else args[:1]
  for p in paths:
   if isinstance(p,(str,bytes,os.PathLike)):
    p=os.path.abspath(os.fsdecode(p))
    if not(p==str(OUT) or p.startswith(str(OUT)+os.sep)):denied=True
 if denied:
  AUDIT.append({'event':event,'denied':True})
  raise PermissionError('isolated runner denied network/process/outside write: '+event)
def resources():
 fdroot=Path('/proc/self/fd') if Path('/proc/self/fd').is_dir() else Path('/dev/fd')
 r=resource.getrusage(resource.RUSAGE_SELF);c=resource.getrusage(resource.RUSAGE_CHILDREN)
 return {'monotonic':time.monotonic(),'open_fd_count':len(list(fdroot.iterdir())),
         'thread_count':threading.active_count(),'self_cpu_user_seconds':r.ru_utime,'self_cpu_system_seconds':r.ru_stime,
         'children_cpu_user_seconds':c.ru_utime,'children_cpu_system_seconds':c.ru_stime,
         'maxrss_lifetime_raw':r.ru_maxrss,'maxrss_raw_unit':'bytes' if sys.platform=='darwin' else 'KiB',
         'maxrss_is_case_peak':False}
def identity():
 return {'session_id':'synthetic-session-'+secrets.token_hex(16),'profile_id':'synthetic-host-only',
         'task_id':'synthetic-task-'+secrets.token_hex(16),'turn_id':'synthetic-turn-'+secrets.token_hex(16),
         'turn_stream_id':'synthetic-stream-'+secrets.token_hex(16)}
def b64(raw):return base64.b64encode(raw if isinstance(raw,bytes) else raw.encode()).decode()
def page(component=APP):
 return ('Display: mDisplayId=0\nmTopFocusedDisplayId=0\n'
  'mCurrentFocus=Window{synthetic u0 '+component+'}\n'
  'mFocusedApp=ActivityRecord{synthetic u0 '+component+'}\n'
  'isKeyguardShowing=false\ntopResumedActivity=ActivityRecord{synthetic u0 '+component+'}\n')
def viewport():
 return "DisplayViewport{type=INTERNAL, valid=true, isActive=true, displayId=0, uniqueId='local:"+OBS.PHYSICAL_DISPLAY+"', orientation=0, logicalFrame=Rect(0, 0 - 1224, 2992), physicalFrame=Rect(0, 0 - 1224, 2992)}"
def native(call_id,raw,tool='shell.exec'):
 terminal={'kind':'exited','exit_code':0,'error':None,'output_truncated':False,'stdout_bytes':len(raw),'stderr_bytes':0}
 ev=[{'kind':'accepted'},{'kind':'started'},{'kind':'output','stream':'stdout','encoding':'base64','data':b64(raw),'byte_count':len(raw)},{'kind':'terminal','terminal':copy.deepcopy(terminal)}]
 return {'call_id':call_id,'status':'terminal','terminal':terminal,
         'events':[{'call_id':call_id,'tool':tool,'seq':i,'event':x} for i,x in enumerate(ev)]}
def tool_input(call_id,semantic,token=None):
 row={'call_id':call_id,'semantic_tool':semantic,'wire_tool':'shell.exec','capture_id':token or secrets.token_hex(16)}
 if semantic=='phone.screenshot':row['max_image_bytes']=196608
 elif semantic=='phone.read_text':row.update(package=PACKAGE,view_ids=[PUBLIC])
 elif semantic=='phone.input_text':row.update(package=PACKAGE,view_id=EDITOR,expected_text='',requested_text='合成 Ω 🌟')
 return row
class Evidence:
 def __init__(self,path):
  self.path=mkdir(path);self.checks=[];self.observations=[]
 def check(self,label,condition):
  self.checks.append({'name':label,'passed':condition is True})
  if condition is not True:raise AssertionError(label)
 def record(self,label,value):
  return new_json(self.path/(label+'.json'),value)
 def reject(self,label,fn,contains=None):
  started=time.monotonic()
  try:value=fn()
  except OPENAI.ProviderError as e:
   item={'label':label,'exception_type':type(e).__name__,'error':str(e),'elapsed_seconds':time.monotonic()-started,'rejected':True}
   self.observations.append(item)
   self.check(label+' rejects through original ProviderError',True)
   if contains:self.check(label+' exact guard reason',contains in str(e))
   return item
  item={'label':label,'rejected':False,'returned':value,'elapsed_seconds':time.monotonic()-started}
  self.observations.append(item)
  self.check(label+' must reject',False)
 def tools(self,label):
  d=mkdir(self.path/label);writes=[]
  def record(p,v):
   writes.append(str(p))
   return new_json(p,v)
  t=OBS.PhoneTools(d,record);t.bind(identity())
  return t,writes
def snapshot(t):
 return {'calls':copy.deepcopy(t.calls),'images':copy.deepcopy(t.images),'facts':copy.deepcopy(t.verified_facts),
         'encoded_bytes_used':t.encoded_bytes_used,'latest':copy.deepcopy(t.latest),'round':t.round}
def prepare_one(t,call,reply,round_number=1):
 raw=json.dumps(reply,ensure_ascii=False,separators=(',',':'))
 message={'role':'tool','tool_call_id':call['call_id'],'content':raw}
 return t.prepare([message],[copy.deepcopy(message)],round_number)
def image_envelope(token,jpeg,png):
 screen={'schema':'hepta.phone-screenshot.v1','status':'encoded','capture_id':token,'serial':OBS.SERIAL,
  'logical_display_id':0,'physical_display_id':OBS.PHYSICAL_DISPLAY,'rotation':0,
  'viewport_before':viewport(),'viewport_after':viewport(),'original_width':1224,'original_height':2992,
  'encoded_width':153,'encoded_height':374,'media_type':'image/jpeg','encoding':'base64','quality':75,
  'data_base64':b64(jpeg),'image_sha256':sha(jpeg),'source_png_sha256':sha(png),'source_png_bytes':len(png),'encoded_bytes':len(jpeg)}
 return {'schema':'hepta.capture-page-envelope.v149.1','capture_id':token,'page_before_b64':b64(page()),'page_after_b64':b64(page()),'screenshot':screen}
def public_payload(token,text,component=APP):
 import xml.etree.ElementTree as ET
 root=ET.Element('hierarchy',rotation='0')
 ET.SubElement(root,'node',{'resource-id':PUBLIC,'package':PACKAGE,'password':'false','enabled':'true','visible-to-user':'true','bounds':'[10,20][200,100]','text':text})
 xml=ET.tostring(root,encoding='unicode')
 return {'schema':'hepta.public-text-receipt.v149.1','operation_id':token,'package':PACKAGE,
  'page_before_b64':b64(page(component)),'page_after_b64':b64(page(component)),
  'viewport_before_b64':b64(viewport()),'viewport_after_b64':b64(viewport()),'xml_b64':b64(xml)}
def return_payload(token):
 return {'schema':'hepta.return-receipt.v149.1','operation_id':token,'launch_exit_code':0,
  'launch_b64':b64('Status: ok\nActivity: '+GUARDS.HEPTA_COMPONENT+'\n'),
  'page_b64':b64(page(GUARDS.HEPTA_COMPONENT)),'viewport_b64':b64(viewport())}
def input_payload(call):
 raw=call['requested_text'].encode()
 return {'schema':'hepta.focused-unicode-input.v1','status':'set_verified','operation_id':call['call_id'],
  'display_id':0,'package':call['package'],'view_id':call['view_id'],'requested_utf8_sha256':sha(raw),
  'before_utf8_sha256':sha(call['expected_text'].encode()),'after_utf8_sha256':sha(raw),
  'own_automation_disconnected':True,'action_attempted':True,'effect_state':'observed_exact_requested_text','readback_text_b64':b64(raw)}
def neg10(e):
 e.check('single and turn image byte limits unchanged',OBS.MAX_IMAGE_BYTES==196608 and OBS.MAX_TURN_IMAGE_BYTES==393216 and OBS.MIN_IMAGE_BUDGET==65536)
 for label in ('byte_budget','expired_image','foreign_call','old_round'):
  t,writes=e.tools(label);call_id='neg10_'+secrets.token_hex(12)
  if label=='byte_budget':
   t.encoded_bytes_used=393216-65535
   d={'call_id':call_id,'tool':'phone.screenshot','command':'','argv':['0']}
   expected='byte budget exhausted'
  else:
   image_call='image_'+secrets.token_hex(12)
   t.round=2;t.latest={'call_id':image_call,'attached_round':2,'received_monotonic':time.monotonic(),'encoded_size':[153,374]}
   if label=='expired_image':t.latest['received_monotonic']-=121
   if label=='old_round':t.latest['attached_round']=1
   d={'call_id':call_id,'tool':'phone.tap','command':'','argv':[('foreign_'+secrets.token_hex(8)) if label=='foreign_call' else image_call,'0','0']}
   expected='expired' if label=='expired_image' else "current completion's latest valid screenshot"
  before=snapshot(t);e.record(label+'-input',{'synthetic':True,'decision':d,'state':before})
  error=e.reject(label,lambda:t.map(d),expected)
  after=snapshot(t);e.record(label+'-original-observation',{'error':error,'before':before,'after':after,'atomic_record_calls':writes})
  e.check(label+' no semantic mapping or fact admission',t.calls=={} and t.verified_facts=={} and writes==[] and before==after)
def mutate_native(r,label):
 if label=='call_id':r['call_id']='wrong_'+secrets.token_hex(8)
 elif label=='event_call_id':r['events'][1]['call_id']='wrong_'+secrets.token_hex(8)
 elif label=='sequence':r['events'][2]['seq']=99
 elif label=='byte_count':r['events'][2]['event']['byte_count']+=1
 elif label=='terminal_exit':r['terminal']['exit_code']=7;r['events'][-1]['event']['terminal']['exit_code']=7
 elif label=='truncation':r['terminal']['output_truncated']=True;r['events'][-1]['event']['terminal']['output_truncated']=True
 elif label=='base64':r['events'][2]['event']['data']='!'
 elif label=='wire_tool':r['events'][1]['tool']='adb.exec'
 elif label=='output_before_started':
  r['events'][1],r['events'][2]=r['events'][2],r['events'][1]
  for i,event in enumerate(r['events']):event['seq']=i
 elif label=='unknown_event':
  r['events'].insert(2,{'call_id':r['call_id'],'tool':r['events'][0]['tool'],'seq':2,'event':{'kind':'unrecognized_lifecycle'}})
  for i,event in enumerate(r['events']):event['seq']=i
 elif label in ('boolean_exit_code','floating_exit_code'):
  value=False if label=='boolean_exit_code' else 0.0
  r['terminal']['exit_code']=value;r['events'][-1]['event']['terminal']['exit_code']=value
 elif label=='nested_boolean_exit_code':r['events'][-1]['event']['terminal']['exit_code']=False
 elif label=='nested_floating_count':r['events'][-1]['event']['terminal']['stdout_bytes']=float(r['terminal']['stdout_bytes'])
 elif label=='nested_integer_truncation':r['events'][-1]['event']['terminal']['output_truncated']=0
 elif label=='nested_floating_truncation':r['events'][-1]['event']['terminal']['output_truncated']=0.0
 elif label=='missing_kind':del r['events'][1]['event']['kind']
 else:raise AssertionError('unknown native mutation '+label)
 return r
def neg11(e):
 jpeg=read_pinned(HERE/'assets/synthetic.jpg',ASSETS['synthetic.jpg'][1])
 png=read_pinned(HERE/'assets/synthetic.png',ASSETS['synthetic.png'][1])
 control_id='control_'+secrets.token_hex(12);control=native(control_id,b'new-synthetic-control')
 e.check('original native_streams accepts valid synthetic control',OBS.native_streams(control,control_id,'shell.exec')==b'new-synthetic-control')
 e.record('valid-native-control',{'synthetic':True,'input':control})
 empty=native(control_id,b'');del empty['events'][2]
 for i,event in enumerate(empty['events']):event['seq']=i
 e.check('successful native lifecycle permits no output events',OBS.native_streams(empty,control_id,'shell.exec')==b'')
 split=native(control_id,b'ab');split['events'][2]['event'].update(data=b64(b'a'),byte_count=1)
 split['events'].insert(3,{'call_id':control_id,'tool':'shell.exec','seq':3,'event':{'kind':'output','stream':'stdout','encoding':'base64','data':b64(b'b'),'byte_count':1}})
 for i,event in enumerate(split['events']):event['seq']=i
 e.check('successful native lifecycle permits multiple output events',OBS.native_streams(split,control_id,'shell.exec')==b'ab')
 mutations=('call_id','event_call_id','sequence','byte_count','terminal_exit','truncation','base64','wire_tool',
  'output_before_started','unknown_event','boolean_exit_code','floating_exit_code','nested_boolean_exit_code',
  'nested_floating_count','nested_integer_truncation','nested_floating_truncation','missing_kind')
 for label in mutations:
  call_id='neg11_'+secrets.token_hex(12);r=mutate_native(native(call_id,b'{}'),label)
  e.record(label+'-synthetic-input',r)
  error=e.reject(label,lambda r=r,c=call_id:OBS.native_streams(r,c,'shell.exec'))
  for semantic,suffix in (('phone.screenshot','image'),('phone.read_text','text'),('phone.return_hepta','return'),('phone.input_text','input')):
   t,writes=e.tools(label+'-'+suffix);call=tool_input(call_id,semantic);t.calls[call_id]=call
   if semantic=='phone.screenshot':payload=image_envelope(call['capture_id'],jpeg,png)
   elif semantic=='phone.read_text':payload=public_payload(call['capture_id'],'合成 Ω 🌟\n公开读回')
   elif semantic=='phone.return_hepta':payload=return_payload(call['capture_id'])
   else:payload=input_payload(call)
   r=mutate_native(native(call_id,canonical(payload)),label)
   e.record(label+'-'+suffix+'-synthetic-valid-payload',r)
   e.reject(label+'-'+suffix,lambda t=t,c=call,r=r:prepare_one(t,c,r),error['error'])
   e.check(label+'-'+suffix+' admits no fact or image',t.verified_facts=={} and t.images=={} and writes==[])
 for label in ('image_hash','png_hash_format','capture_identity'):
  t,writes=e.tools(label);cid='image_'+secrets.token_hex(12);call=tool_input(cid,'phone.screenshot')
  payload=image_envelope(call['capture_id'],jpeg,png)
  if label=='image_hash':payload['screenshot']['image_sha256']='0'*64
  elif label=='png_hash_format':payload['screenshot']['source_png_sha256']='invalid'
  else:payload['capture_id']='wrong_'+secrets.token_hex(8)
  r=native(cid,canonical(payload));t.calls[cid]=call;e.record(label+'-synthetic-input',r)
  e.reject(label,lambda:prepare_one(t,call,r))
  e.check(label+' no image/fact accepted',t.images=={} and t.verified_facts=={} and writes==[])
 for label in ('retained_source_hash','retained_image_hash'):
  t,writes=e.tools(label);cid='image_'+secrets.token_hex(12);call=tool_input(cid,'phone.screenshot')
  payload=image_envelope(call['capture_id'],jpeg,png);r=native(cid,canonical(payload));raw=json.dumps(r,separators=(',',':'))
  t.calls[cid]=call;accepted=t._image(r,raw,call)
  e.record(label+'-original-synthetic-control',{'raw_native':r,'source_content':raw,'accepted':accepted})
  e.check(label+' positive control accepted one synthetic image',len(t.images)==1 and accepted['image_sha256']==sha(jpeg) and not t.verified_facts)
  old_count=len(writes);original=Path(accepted['path']).read_bytes()
  if label=='retained_source_hash':
   mutated=raw+' ';e.record(label+'-mutation',{'change':'append whitespace to only this synthetic source input','original_sha256':sha(raw.encode()),'changed_sha256':sha(mutated.encode())})
  else:
   fd=os.open(accepted['path'],os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
   with os.fdopen(fd,'wb') as f:f.write(b'synthetic tampered retained JPEG');f.flush();os.fsync(f.fileno())
   mutated=raw;e.record(label+'-mutation',{'change':'overwrite only a synthetic retained fixture image; original bytes retained as pinned asset','original_sha256':sha(original),'changed_sha256':sha(Path(accepted['path']).read_bytes())})
  e.reject(label,lambda:t._image(r,mutated,call),'retained screenshot observation changed')
  e.check(label+' no new fact or image admission',len(t.images)==1 and not t.verified_facts and len(writes)==old_count)
 for semantic,labels in (('phone.read_text',('public_identity','public_invalid_utf8','public_wrong_package')),('phone.return_hepta',('return_identity','return_wrong_activity'))):
  for label in labels:
   t,writes=e.tools(label);cid='semantic_'+secrets.token_hex(12);call=tool_input(cid,semantic);t.calls[cid]=call
   p=public_payload(call['capture_id'],'合成 Ω') if semantic=='phone.read_text' else return_payload(call['capture_id'])
   if label.endswith('identity'):p['operation_id']='wrong_'+secrets.token_hex(8)
   elif label=='public_invalid_utf8':p['xml_b64']=b64(b'\xff')
   elif label=='public_wrong_package':p['package']='org.example.foreign'
   else:p['page_b64']=b64(page(APP))
   r=native(cid,canonical(p));e.record(label+'-synthetic-input',r)
   e.reject(label,lambda t=t,c=call,r=r:prepare_one(t,c,r))
   e.check(label+' admits no text/return fact',not t.verified_facts and not t.images and writes==[])
def contract_tree(path):
 mkdir(path);mkdir(path/'templates');mkdir(path/'bindings')
 return path
def template(scope,request,nonce,conditions,coverage='entire_request'):
 return {'schema':'hepta.task-template.v149.1','expected_scope':{k:scope[k] for k in ('session_id','profile_id')},
         'request_sha256':CONTRACT.request_hash(request),'nonce':nonce,'coverage':coverage,'postconditions':conditions}
def neg12(e):
 for label in ('input_only','missing_return','partial_coverage'):
  d=mkdir(e.path/label);state=mkdir(d/'state');evidence=mkdir(state/'evidence');mkdir(evidence/'claims');contracts=contract_tree(state/'task-contracts');run=mkdir(evidence/'run')
  ident=identity();nonce=secrets.token_hex(16);text='合成验收 Ω 🌟 '+nonce;request='Synthetic host-only contract: '+text
  public_text='已确认 '+text
  conditions=[{'id':'input','kind':'text_readback_exact','package':PACKAGE,'view_id':EDITOR,'utf8_sha256':sha(text.encode())},
   {'id':'public','kind':'public_text_exact','package':PACKAGE,'view_id':PUBLIC,'utf8_sha256':sha(public_text.encode())},
   {'id':'return','kind':'foreground_hepta'}]
  value=template(ident,request,nonce,conditions,'declared_postconditions_only' if label=='partial_coverage' else 'entire_request')
  CONTRACT.write_exclusive(contracts/'templates'/(CONTRACT.request_hash(request)+'.json'),value)
  frame={'protocol':OPENAI.PROTOCOL,'kind':'turn.start','seq':0,'turn':dict(ident,user_input=request)}
  e.record(label+'-synthetic-owner-and-contract',{'synthetic':True,'frame':frame,'template':value})
  rfd,wfd=os.pipe();source=os.fdopen(rfd,'rb',buffering=0);sink=open(d/'wire.jsonl','w',encoding='utf-8')
  args=types.SimpleNamespace(evidence=evidence,contracts=contracts)
  adapter=None
  try:
   raw=canonical(frame)+b'\n';assert len(raw)<4096;os.write(wfd,raw);os.close(wfd);wfd=None
   adapter=CODEX.CodexAdapter(args,source,sink,run)
   received=adapter.receive('turn.start',timeout=1)
   e.check(label+' exact original admission',received==frame and adapter.claimed and adapter.accepted_identity==ident)
   adapter.model_task_status='completed'
   round_number=0
   decisions=[{'call_id':'input_'+secrets.token_hex(12),'tool':'phone.input_text','command':text,'argv':[PACKAGE,EDITOR,'']}]
   if label!='input_only':decisions.append({'call_id':'public_'+secrets.token_hex(12),'tool':'phone.read_text','command':'','argv':[PACKAGE,PUBLIC]})
   if label=='partial_coverage':decisions.append({'call_id':'return_'+secrets.token_hex(12),'tool':'phone.return_hepta','command':'','argv':[]})
   for decision in decisions:
    adapter.phone_tools.map(decision);call=adapter.phone_tools.calls[decision['call_id']]
    if decision['tool']=='phone.input_text':payload=input_payload(call)
    elif decision['tool']=='phone.read_text':payload=public_payload(call['capture_id'],public_text)
    else:payload=return_payload(call['capture_id'])
    reply=native(call['call_id'],canonical(payload),call['wire_tool']);round_number+=1
    e.record(label+'-synthetic-receipt-'+str(round_number),{'synthetic':True,'mapped_call':call,'native_result':reply})
    prepare_one(adapter.phone_tools,call,reply,round_number)
   e.check(label+' only verified synthetic parser facts used',len(adapter.phone_tools.verified_facts)==len(decisions))
   e.check(label+' no actual native/tool frame dispatched',not adapter.dispatched_calls and adapter.tool_count==0)
   adapter.emit('turn.complete',summary='Synthetic model decision says completed; not a real model request.')
   sink.flush();os.fsync(sink.fileno())
   outcome=json.loads((run/'business-outcome.json').read_text());terminal=json.loads((run/'terminal.json').read_text())
   wire=[json.loads(x) for x in (d/'wire.jsonl').read_text().splitlines()]
   e.check(label+' actual wire downgraded to turn.fail',len(wire)==1 and wire[0]['kind']=='turn.fail' and '[business_not_verified]' in wire[0]['error'])
   e.check(label+' persisted terminal matches wire',terminal['kind']=='turn.fail' and terminal['error']==wire[0]['error'])
   e.check(label+' business remains false',outcome['business_verified'] is False and outcome['native_completed_is_business_success'] is False and outcome['emitted_protocol_terminal']=='turn.fail')
   expected={'input_only':['public','return'],'missing_return':['return'],'partial_coverage':[]}[label]
   e.check(label+' exact missing conditions',outcome['missing_postconditions']==expected)
   if label=='partial_coverage':e.check(label+' coverage-only barrier preserved',outcome['postconditions_verified'] is True and outcome['coverage']=='declared_postconditions_only')
   e.check(label+' claims and consumed binding retained',len(list((evidence/'claims').iterdir()))==1 and len(list((contracts/'bindings').iterdir()))==1)
   e.record(label+'-persisted-originals',{'files':[file_record(x) for x in (d/'wire.jsonl',run/'provider-out.jsonl',run/'terminal.json',run/'business-outcome.json')],'outcome':outcome})
  finally:
   if wfd is not None:os.close(wfd)
   if adapter is not None:adapter.frames.close();adapter.inputs.close()
   source.close();sink.close()
def neg13(e):
 d=contract_tree(e.path/'contracts');ident=identity();nonce=secrets.token_hex(16);request='New synthetic one-use request '+nonce
 value=template(ident,request,nonce,[{'id':'return','kind':'foreground_hepta'}])
 p=d/'templates'/(CONTRACT.request_hash(request)+'.json');CONTRACT.write_exclusive(p,value)
 e.record('template-original',{'synthetic':True,'template':value,'scope':ident})
 for field in ('session_id','profile_id'):
  wrong=dict(ident);wrong[field]='wrong-'+secrets.token_hex(16)
  e.record('wrong-'+field+'-input',wrong)
  e.reject('wrong-'+field,lambda wrong=wrong:CONTRACT.load_contract(d,wrong,request),'known scope differs')
  e.check('wrong '+field+' does not consume template',not list((d/'bindings').iterdir()))
 barrier=threading.Barrier(2,timeout=2);outcomes=[];lock=threading.Lock()
 def attempt():
  who=dict(ident,task_id='task-'+secrets.token_hex(16),turn_id='turn-'+secrets.token_hex(16),turn_stream_id='stream-'+secrets.token_hex(16))
  start=time.monotonic()
  try:
   barrier.wait()
   result=CONTRACT.load_contract(d,who,request)
   row={'accepted':True,'identity':who,'result':result}
  except BaseException as error:
   row={'accepted':False,'identity':who,'error_type':type(error).__name__,'error':str(error)}
  row['elapsed_seconds']=time.monotonic()-start
  with lock:outcomes.append(row)
 threads=[threading.Thread(target=attempt,name='synthetic-contract-race-'+str(i),daemon=True) for i in range(2)]
 for t in threads:t.start()
 for t in threads:t.join(3)
 e.record('race-original-results',{'synthetic':True,'threads_joined':all(not t.is_alive() for t in threads),'outcomes':outcomes})
 e.check('both original race threads joined',all(not t.is_alive() for t in threads))
 e.check('exactly one real O_EXCL binding won',len(outcomes)==2 and sum(x['accepted'] for x in outcomes)==1 and len(list((d/'bindings').iterdir()))==1)
 loser=next(x for x in outcomes if not x['accepted'])
 e.check('loser rejected by original one-use guard',loser['error_type']=='ProviderError' and 'already consumed' in loser['error'])
 binding=next((d/'bindings').iterdir());before=binding.read_bytes();template_before=p.read_bytes()
 winner=next(x['identity'] for x in outcomes if x['accepted'])
 replacements=[('new_semantic_turn',dict(ident,task_id='task-'+secrets.token_hex(16),turn_id='turn-'+secrets.token_hex(16))),
               ('replacement_stream',dict(winner,turn_stream_id='stream-'+secrets.token_hex(16)))]
 for label,who in replacements:
  e.record(label+'-input',who);e.reject(label,lambda who=who:CONTRACT.load_contract(d,who,request),'already consumed')
 e.check('original binding and template retained unchanged',binding.read_bytes()==before and p.read_bytes()==template_before and len(list((d/'bindings').iterdir()))==1)
 e.record('retained-binding-original',{'binding':json.loads(before),'binding_sha256':sha(before),'template_sha256':sha(template_before),'all_original_entries':sorted(str(x.relative_to(d)) for x in d.rglob('*'))})
def verify_inputs():
 seal=json.loads(read_pinned(SEAL,SEAL_SHA));combo=json.loads(read_pinned(COMBO,COMBO_SHA))
 assert sha(canonical(combo))==COMBO_CANONICAL and combo['provider_source_seal_sha256']==SEAL_SHA
 p=json.loads(read_pinned(PROTOCOL,PROTOCOL_SHA));old=json.loads(read_pinned(ORIGINAL_PROTOCOL,ORIGINAL_SHA))
 assert p['cases']==old['cases'] and p['limits']==old['limits'] and p['qualified_geometry']==old['qualified_geometry']
 rows=[]
 for x in seal['production_files']:
  path=SEAL.parent/x['path'];raw=read_pinned(path,x['sha256']);assert len(raw)==x['bytes'];rows.append(file_record(path))
 for name,(size,digest) in ASSETS.items():assert len(read_pinned(HERE/'assets'/name,digest))==size
 return seal,p,rows
def main():
 global OUT,OBS,GUARDS,CONTRACT,CODEX,OPENAI
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute-once',action='store_true');parser.add_argument('--attempt-label',default='attempt-01')
 a=parser.parse_args()
 if not a.execute_once:
  print(json.dumps({'mode':'review-only','cases':IDS,'phone_calls':0,'model_requests':0,'source_seal_sha256':SEAL_SHA}));return 0
 assert a.attempt_label.startswith('attempt-') and a.attempt_label.replace('-','').isalnum() and len(a.attempt_label)<64
 os.umask(0o077);OUT=Path('/work');assert OUT.is_dir() and not (OUT/'INPUT-PINS.json').exists()
 start=time.monotonic();seal,p,inputs=verify_inputs()
 new_json(OUT/'INPUT-PINS.json',{'schema':'hepta.frozen-host-test-inputs.v1','source_seal_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'combination_sha256':COMBO_CANONICAL,'protocol_sha256':PROTOCOL_SHA,'cases':[x for x in p['cases'] if x['id'] in IDS],'limits':p['limits'],'geometry':p['qualified_geometry'],'sources':inputs,'runner':file_record(Path(__file__)),'synthetic_only':True})
 sys.addaudithook(audit)
 for name in ('phone_observation_tools','phone_task_guards','task_postconditions','provider_codex_host','provider_openai_compatible'):assert name not in sys.modules
 sys.path.insert(0,str(SOURCE))
 OBS=importlib.import_module('phone_observation_tools');GUARDS=importlib.import_module('phone_task_guards');CONTRACT=importlib.import_module('task_postconditions');CODEX=importlib.import_module('provider_codex_host');OPENAI=importlib.import_module('provider_openai_compatible')
 used=[]
 for m in (OBS,GUARDS,CONTRACT,CODEX,OPENAI):
  path=Path(m.__file__).resolve();assert path.parent==SOURCE.resolve();used.append(file_record(path))
 new_json(OUT/'ACTUAL-IMPORTED-SOURCES.json',used)
 def timeout(_n,_f):raise TimeoutError('host suite absolute 50 second deadline')
 signal.signal(signal.SIGALRM,timeout);signal.alarm(50)
 cases=[]
 try:
  for case_id,fn in zip(IDS,(neg10,neg11,neg12,neg13)):
   e=Evidence(OUT/case_id);before=resources();error=None
   try:fn(e)
   except BaseException as ex:error={'type':type(ex).__name__,'error':str(ex),'traceback':traceback.format_exc()}
   after=resources()
   for label,ok in [('file descriptor baseline restored',after['open_fd_count']==before['open_fd_count']),('thread baseline restored',after['thread_count']==before['thread_count']),('no child CPU activity',after['children_cpu_user_seconds']==before['children_cpu_user_seconds'] and after['children_cpu_system_seconds']==before['children_cpu_system_seconds']),('no attempted socket/process/outside-write operation',not AUDIT)]:
    e.checks.append({'name':label,'passed':bool(ok)})
   passed=error is None and all(x['passed'] for x in e.checks)
   row={'schema':'hepta.host-negative-original-result.v150.r7-r3.1','case_id':case_id,'layer':'host_isolated','synthetic_inputs':True,'status':'PASS' if passed else 'FAIL','candidate_manifest_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'combination_sha256':COMBO_CANONICAL,'assertions':e.checks,'observations':e.observations,'error':error,'resources':{'before':before,'after':after,'elapsed_seconds':after['monotonic']-before['monotonic']},'phone_calls':0,'real_model_requests':0,'fixture_http_requests':0,'native_dispatches':0,'task_outcome_scope':'Synthetic negative guard/admission inputs only; no phone business task.','model_tokens':None,'model_token_reason':'No model inference was requested.'}
   rec=new_json(e.path/'RESULT.json',row)
   cases.append({'case_id':case_id,'attempt_id':case_id+'-'+secrets.token_hex(16),'layer':'host_isolated','candidate_manifest_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'combination_sha256':COMBO_CANONICAL,'protocol_result':row['status'],'task_outcome':'failed' if case_id!='NEG-13' and passed else 'unconfirmed','task_outcome_scope':row['task_outcome_scope'],'assertions':e.checks,'evidence':[{'path':rec['path'],'sha256':rec['sha256']}],'resources':row['resources'],'model_request_count':0,'phone_actions':0})
  _,_,after_inputs=verify_inputs();assert inputs==after_inputs
  signal.alarm(0)
  new_json(OUT/'ATTEMPTS.json',cases)
  final={'schema':'hepta.host-negative-suite.v150.r7-r3.1','status':'PASS' if all(x['protocol_result']=='PASS' for x in cases) else 'FAIL','source_seal_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'combination_sha256':COMBO_CANONICAL,'cases':[{'id':x['case_id'],'protocol_result':x['protocol_result'],'assertions':len(x['assertions'])} for x in cases],'elapsed_seconds':time.monotonic()-start,'production_sources_unchanged':True,'audit_denied_events':AUDIT,'phone_calls':0,'real_model_requests':0,'fixture_http_requests':0,'native_dispatches':0,'new_case_sample_count':4,'model_business_sample_count':0,'expected_exit_code':0 if all(x['protocol_result']=='PASS' for x in cases) else 1,'declared_scope':'Only the original four host_isolated protocol layers; no phone/model/native qualification.'}
  rec=new_json(OUT/'RESULT.json',final)
  print(json.dumps({'result':rec,'status':final['status'],'cases':final['cases'],'expected_exit_code':final['expected_exit_code'],'phone_calls':0,'model_requests':0},ensure_ascii=False))
  return final['expected_exit_code']
 finally:signal.alarm(0)
if __name__=='__main__':sys.exit(main())
