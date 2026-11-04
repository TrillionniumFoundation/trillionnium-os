#!/usr/bin/env python3
"""NEG03 using original PhoneLocalTools and original-shaped synthetic receipts only."""
import argparse,copy,hashlib,importlib,json,os,signal,sys,time,traceback,types
from pathlib import Path
sys.dont_write_bytecode=True
WORK=Path('/work');SUITE=Path('/suite');HARNESS=Path('/harness')
REFERENCE_SHA='17791d4172d08fdd9dcccc7fac324aa2550fae717491a427b237524471f5cf13'
SEAL_SHA='7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab'
COMBO_SHA='ab038c5533a7459c8bb4d94cca008ca0f61ade0d90ad6db0e8ece3ab1af99ae8'
COMBO_CANONICAL='87609ca2d6b6701071a1f175acd417e1f3036617884dc09666b9154de25e93f8'
APP='org.trillionnium.hepta.controlprobe/.VisualChallengeActivity'
PACKAGE='org.trillionnium.hepta.controlprobe'
PUBLIC=PACKAGE+':id/fixture_receipt'
def main():
 a=argparse.ArgumentParser();a.add_argument('--execute-once',action='store_true');a.add_argument('--reference-sha256',required=True);args=a.parse_args()
 if not args.execute_once:print('review-only');return 0
 assert args.reference_sha256==REFERENCE_SHA
 os.umask(0o077)
 raw=(HARNESS/'reference_host_helpers.py').read_bytes();assert hashlib.sha256(raw).hexdigest()==REFERENCE_SHA
 H=types.ModuleType('original_fixture_helpers');H.__file__=str(HARNESS/'reference_host_helpers.py')
 exec(compile(raw,H.__file__,'exec'),H.__dict__)
 H.HERE=HARNESS;H.BASE=SUITE;H.SOURCE=SUITE/'provider/source';H.SEAL=SUITE/'provider/SOURCE-SEAL.json'
 H.COMBO=SUITE/'combination.json';H.PROTOCOL=SUITE/'protocol.json';H.ORIGINAL_PROTOCOL=SUITE/'original-protocol.json';H.OUT=WORK
 H.PACKAGE=PACKAGE;H.PUBLIC=PUBLIC
 env=json.loads((WORK/'OUTER-ENV.json').read_bytes())
 namespace={'uid':os.getuid(),'netns':os.readlink('/proc/self/ns/net'),'mntns':os.readlink('/proc/self/ns/mnt'),'pidns':os.readlink('/proc/self/ns/pid')}
 assert namespace['uid']==0 and namespace['netns']!=env['host_netns'] and namespace['mntns']!=env['host_mntns']
 assert os.statvfs(SUITE).f_flag & 1
 seal,protocol,inputs=H.verify_inputs()
 H.new_json(WORK/'SUITE-INTENT.json',{'schema':'hepta.geometry-rejection-fixture.v150.r7-r1.1','case_id':'NEG-03','layer':'component_direct','synthetic_only':True,'source_seal_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'namespace':namespace,'phone_calls':0,'real_model_requests':0,'note':'Current real source against synthetic shapes; no observed physical outer-screen, landscape or fold transition.'})
 sys.addaudithook(H.audit);sys.path.insert(0,str(H.SOURCE))
 H.OBS=importlib.import_module('phone_observation_tools');H.GUARDS=importlib.import_module('phone_task_guards');H.OPENAI=importlib.import_module('provider_openai_compatible')
 LOCAL=importlib.import_module('phone_local_tools')
 used=[]
 for m in (H.OBS,H.GUARDS,H.OPENAI,LOCAL):
  p=Path(m.__file__).resolve();assert p.parent==H.SOURCE.resolve();used.append(H.file_record(p))
 H.new_json(WORK/'ACTUAL-IMPORTED-SOURCES.json',used)
 cfg=json.loads((SUITE/'production-config.json').read_bytes())
 H.new_json(WORK/'INPUT-PINS.json',{'source_seal_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'combination_sha256':COMBO_CANONICAL,'sources':inputs,'original_protocol_case':next(x for x in protocol['cases'] if x['id']=='NEG-03'),'limits':protocol['limits'],'qualified_geometry':protocol['qualified_geometry'],'reference_builder_sha256':REFERENCE_SHA,'fixture_package':PACKAGE})
 base_entry="DisplayViewport{type=INTERNAL, valid=true, isActive=true, displayId=0, uniqueId='local:"+H.OBS.PHYSICAL_DISPLAY+"', orientation=0, logicalFrame=Rect(0, 0 - 1224, 2992), physicalFrame=Rect(0, 0 - 1224, 2992)}"
 base_view='mViewports=['+base_entry+']'
 outer_entry=base_entry.replace('displayId=0','displayId=1').replace(H.OBS.PHYSICAL_DISPLAY,'4630947043778501780').replace('orientation=0','orientation=2').replace('1224, 2992','1080, 1272')
 outer_view='mViewports=['+outer_entry+']'
 landscape_view=base_view.replace('orientation=0','orientation=1').replace('1224, 2992','2992, 1224')
 def page(component=APP):
  return ('Display: mDisplayId=0\nmTopFocusedDisplayId=0\nmCurrentFocus=Window{synthetic u0 '+component+'}\nmFocusedApp=ActivityRecord{synthetic u0 '+component+'}\nisKeyguardShowing=false\ntopResumedActivity=ActivityRecord{synthetic u0 '+component+'}\n')
 H.page=page;H.viewport=lambda:base_view
 class Evidence(H.Evidence):
  def tools(self,label):
   d=H.mkdir(self.path/label);writes=[]
   def record(p,v):writes.append(str(p));return H.new_json(p,v)
   t=LOCAL.PhoneLocalTools(d,record,cfg['approved_apps'],cfg['executor']);t.bind(H.identity())
   return t,writes
 def mapped(e,label,tool,argv):
  t,writes=e.tools(label);cid='neg03_'+os.urandom(12).hex()
  d={'kind':'tool.call','call_id':cid,'tool':tool,'command':'','argv':argv,'summary':'Synthetic display guard fixture','task_status':'in_progress'}
  actual=t.map(d);call=t.calls[cid]
  e.check(label+' real phone-local mapper emits only pinned sidecar argv',actual[:3]==['/usr/bin/python3',cfg['executor']['client_path'],'execute'] and call['wire_tool']=='shell.exec')
  e.record(label+'-MAPPED-NOT-DISPATCHED',{'synthetic':True,'decision':d,'actual_map':actual,'call':call,'native_dispatch':False})
  return t,writes,call
 e=Evidence(WORK/'NEG-03');before=H.resources();error=None
 def alarm(n,f):raise TimeoutError('NEG03 isolated 20 second bound')
 signal.signal(signal.SIGALRM,alarm);signal.alarm(20)
 try:
  jpeg=H.read_pinned(HARNESS/'assets/synthetic.jpg',H.ASSETS['synthetic.jpg'][1]);png=H.read_pinned(HARNESS/'assets/synthetic.png',H.ASSETS['synthetic.png'][1])
  e.check('original viewport parser accepts exactly qualified positive control',H.OBS.validate_viewport(base_view)==H.sha(base_view.encode()))
  variants={'outer_display':outer_view,'landscape':landscape_view,'rotated_180':base_view.replace('orientation=0','orientation=2'),'changed_physical_identity':base_view.replace(H.OBS.PHYSICAL_DISPLAY,'4630947043778501780'),'two_active_displays':'mViewports=['+base_entry+','+outer_entry+']','no_active_display':base_view.replace('isActive=true','isActive=false'),'invalid_viewport':base_view.replace('valid=true','valid=false')}
  for label,vp in variants.items():
   e.record('viewport-'+label,{'synthetic':True,'original_shaped_viewport':vp})
   e.reject('viewport '+label,lambda vp=vp:H.OBS.validate_viewport(vp))
  t,writes=e.tools('reject-display1-map');d={'call_id':'neg03_'+os.urandom(12).hex(),'tool':'phone.screenshot','command':'','argv':['1']}
  e.record('reject-display1-map-INPUT',{'synthetic':True,'decision':d})
  e.reject('screenshot display1 mapping',lambda:t.map(d),'screenshot requires empty command and argv[0]')
  e.check('display1 screenshot creates no mapped call or effect',not t.calls and not writes and not t.verified_facts)
  t,writes,call=mapped(e,'qualified-screenshot-control','phone.screenshot',['0'])
  payload=H.image_envelope(call['capture_id'],jpeg,png);reply=H.native(call['call_id'],H.canonical(payload))
  e.record('qualified-screenshot-control-INPUT',{'synthetic':True,'raw_native':reply})
  projected,paths=H.prepare_one(t,call,reply)
  e.check('actual current PhoneLocalTools accepts one valid synthetic screenshot',len(paths)==1 and t.latest is not None and len(t.images)==1 and t.latest['rotation']==0 and t.latest['logical_display_id']==0)
  tap={'kind':'tool.call','call_id':'neg03_'+os.urandom(12).hex(),'tool':'phone.tap','command':'','argv':[call['call_id'],'0','0'],'summary':'synthetic mapping only','task_status':'in_progress'}
  wire=t.map(tap);tap_record=t.calls[tap['call_id']]
  e.check('valid synthetic tap mapping remains display0 and exact guard only',tap_record['exact_pixel_and_focus_guard'] is True and tap_record['original_xy']==[0,0] and wire[:3]==['/usr/bin/python3',cfg['executor']['client_path'],'execute'])
  e.record('qualified-tap-control-MAPPED-NOT-DISPATCHED',{'synthetic':True,'wire':wire,'record':tap_record,'native_dispatch':False})
  for label in ['outer_metadata','rotated_metadata','foreign_physical_metadata','landscape_dimensions','outer_viewport','landscape_viewport','changed_during_capture','outer_focus']:
   t,writes,call=mapped(e,'screenshot-'+label,'phone.screenshot',['0'])
   payload=H.image_envelope(call['capture_id'],jpeg,png);screen=payload['screenshot']
   if label=='outer_metadata':screen['logical_display_id']=1
   elif label=='rotated_metadata':screen['rotation']=1
   elif label=='foreign_physical_metadata':screen['physical_display_id']='4630947043778501780'
   elif label=='landscape_dimensions':screen['original_width'],screen['original_height']=2992,1224
   elif label=='outer_viewport':screen['viewport_before']=screen['viewport_after']=outer_view
   elif label=='landscape_viewport':screen['viewport_before']=screen['viewport_after']=landscape_view
   elif label=='changed_during_capture':screen['viewport_after']=outer_view
   elif label=='outer_focus':
    raw_page=page().replace('mDisplayId=0','mDisplayId=1').replace('mTopFocusedDisplayId=0','mTopFocusedDisplayId=1')
    payload['page_before_b64']=payload['page_after_b64']=H.b64(raw_page)
   reply=H.native(call['call_id'],H.canonical(payload));e.record('screenshot-'+label+'-INPUT',{'synthetic':True,'raw_native':reply})
   prior=len(writes);e.reject('screenshot '+label,lambda:H.prepare_one(t,call,reply))
   e.check(label+' admits no image or fact',not t.images and not t.verified_facts and t.latest is None and t.encoded_bytes_used==0 and len(writes)==prior)
   decision={'call_id':'neg03_'+os.urandom(12).hex(),'tool':'phone.tap','command':'','argv':[call['call_id'],'0','0']}
   e.reject('tap after rejected '+label,lambda:t.map(decision),"current completion's latest valid screenshot")
   e.check(label+' cannot reserve or map a tap after rejection',len(t.calls)==1 and len(writes)==prior and not t.verified_facts)
  for semantic,short in [('phone.read_text','public'),('phone.return_hepta','return')]:
   for label in ['qualified_control','outer_viewport','landscape_viewport','outer_focus']:
    argv=[PACKAGE,PUBLIC] if semantic=='phone.read_text' else []
    t,writes,call=mapped(e,short+'-'+label,semantic,argv)
    payload=(H.public_payload(call['capture_id'],'New synthetic display negative',component=APP) if short=='public' else H.return_payload(call['capture_id']))
    if label in ('outer_viewport','landscape_viewport'):
     value=outer_view if label=='outer_viewport' else landscape_view
     keys=['viewport_before_b64','viewport_after_b64'] if short=='public' else ['viewport_b64']
     for k in keys:payload[k]=H.b64(value)
    elif label=='outer_focus':
     keys=['page_before_b64','page_after_b64'] if short=='public' else ['page_b64']
     for k in keys:
      decoded=H.base64.b64decode(payload[k]).decode().replace('mDisplayId=0','mDisplayId=1').replace('mTopFocusedDisplayId=0','mTopFocusedDisplayId=1');payload[k]=H.b64(decoded)
    reply=H.native(call['call_id'],H.canonical(payload));e.record(short+'-'+label+'-INPUT',{'synthetic':True,'raw_native':reply})
    prior=len(writes)
    if label=='qualified_control':
     H.prepare_one(t,call,reply);fact=t.verified_facts[call['call_id']]
     e.check(short+' valid synthetic positive control accepted',fact['display_id']==0 and fact['kind']==('public_text_observation' if short=='public' else 'foreground_hepta'))
    else:
     e.reject(short+' '+label,lambda:H.prepare_one(t,call,reply))
     e.check(short+' '+label+' cannot admit public or HEPTA return fact',not t.verified_facts and len(writes)==prior)
 except BaseException as ex:error={'type':type(ex).__name__,'error':str(ex),'traceback':traceback.format_exc()}
 finally:signal.alarm(0)
 after=H.resources()
 for label,ok in [('file descriptor baseline restored',after['open_fd_count']==before['open_fd_count']),('thread baseline restored',after['thread_count']==before['thread_count']),('zero child process CPU activity',after['children_cpu_user_seconds']==before['children_cpu_user_seconds'] and after['children_cpu_system_seconds']==before['children_cpu_system_seconds']),('zero attempted socket subprocess or outside write',not H.AUDIT)]:
  e.checks.append({'name':label,'passed':bool(ok)})
 _,_,after_inputs=H.verify_inputs();assert after_inputs==inputs
 passed=error is None and all(x['passed'] for x in e.checks)
 row={'schema':'hepta.geometry-negative-result.v150.r7-r1.1','case_id':'NEG-03','layer':'component_direct','status':'PASS' if passed else 'FAIL','source_seal_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'combination_sha256':COMBO_CANONICAL,'assertions':e.checks,'observations':e.observations,'error':error,'resources':{'before':before,'after':after,'elapsed_seconds':after['monotonic']-before['monotonic']},'fixture_scope':'Original-shaped synthetic screenshot/public/return receipts fed to actual frozen PhoneLocalTools; mapped actions never dispatched','synthetic_only':True,'physical_display_state_verified':False,'supports_outer_or_landscape':False,'phone_calls':0,'native_dispatches':0,'real_model_requests':0,'fixture_http_requests':0,'audit_denied_events':H.AUDIT,'production_source_pins_preserved':True}
 rec=H.new_json(e.path/'RESULT.json',row)
 final={'schema':'hepta.geometry-negative-suite.v150.r7-r1.1','status':row['status'],'case':rec,'assertions':len(e.checks),'source_seal_sha256':SEAL_SHA,'combination_manifest_sha256':COMBO_SHA,'combination_sha256':COMBO_CANONICAL,'namespace':namespace,'phone_calls':0,'native_dispatches':0,'real_model_requests':0,'fixture_http_requests':0,'physical_display_state_verified':False}
 result=H.new_json(WORK/'RESULT.json',final)
 print(json.dumps({'result':result,'status':row['status'],'case':rec,'assertions':len(e.checks),'phone_calls':0,'real_model_requests':0}))
 return 0 if passed else 1
if __name__=='__main__':raise SystemExit(main())
