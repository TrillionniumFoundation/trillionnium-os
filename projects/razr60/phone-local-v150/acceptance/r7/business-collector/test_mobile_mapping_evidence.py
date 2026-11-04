#!/usr/bin/env python3
"""Narrow host-only original-model/mapping evidence tests. No phone/task nonce."""
import ast,copy,hashlib,json,os,sys
from pathlib import Path
D=Path(__file__).resolve().parent;B=D.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(D))
import collect_business_evidence as collector
import mobile_use_evidence as evidence
def write(path,raw):
 path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 with path.open('xb') as stream:stream.write(raw)
def enc(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
out=D/'validation';out.mkdir(mode=0o700)
checks=[]
def passed(name):checks.append({'check':name,'passed':True})
source=(B/'provider-r7/source/provider_phone_local.py')
seal=json.loads((B/'provider-r7/SOURCE-SEAL-v150-r7.json').read_bytes())
apiout=out/'source-read';apiout.mkdir(mode=0o700)
api=evidence.load_projection_api(collector.Snapshot(apiout,1048576),source.parent,seal)
assert sha(source.read_bytes())==evidence.PROVIDER_SHA256
passed('real_selected_source_pin_and_pure_function_extraction')
rev=json.loads((D/'SOURCE-REVISION-CHECK.json').read_bytes())
assert rev['reverse_substitution_exact_original_sha256']=='5719479507cd6f2366bb8848cb28a6f4a8d175a2ebc91332c77da2239b4fe899'
passed('all_original_collector_gates_reverse_byte_exact')
requestid='0123456789abcdef0123456789abcdef';allowed='r01_'+requestid[:16]
required=['kind','call_id','tool','command','argv','summary','task_status']
def branch(tool,argv,command=None):
 final=tool=='none'
 props={'kind':{'const':'turn.complete' if final else 'tool.call'},
  'call_id':{'const':'' if final else allowed},'tool':{'const':tool},
  'command':{'const':''} if command is None else command,'argv':argv,
  'summary':{'type':'string','maxLength':1024},
  'task_status':{'type':'string','enum':['completed','partial','failed','unknown']} if final else {'const':'in_progress'}}
 return {'type':'object','properties':props,'required':required,'additionalProperties':False}
legacy={'oneOf':[branch('none',{'const':[]}),
 branch('phone.open_app',{'type':'array','items':{'type':'string','enum':['visual_fixture']},'minItems':1,'maxItems':1}),
 branch('phone.input_text',{'type':'array','prefixItems':[{'type':'string'},{'type':'string'},{'type':'string'}],'minItems':3,'maxItems':3},{'type':'string','maxLength':4096})]}
mobile=api['mobile_use_schema'](legacy)
def fixture(name,action,expected,modify=None,with_semantic=False,reject=False):
 root=out/name;run=root/'run';run.mkdir(mode=0o700,parents=True)
 mapped=api['normalize_mobile_use'](action,legacy,allowed);assert mapped==expected
 content=json.dumps(action,ensure_ascii=False,separators=(',',':'))
 images={'request_id':requestid,'images':[]}
 projected={'allowed_call_id':allowed,'round':1,'tools_remaining':7,'transcript':[],
  'observation_status':{'current_image_present':False,'attempted_action_count':0,'verified_fact_count':0,'catalogue_and_request_are_not_screen_observations':True}}
 body={'messages':[{'role':'system','content':api['mobile_use_policy'](mobile)},
  {'role':'user','content':json.dumps(projected)}, {'role':'user','content':[{'type':'text','text':'synthetic fixture only'}]}],
  'response_format':{'type':'json_schema','json_schema':{'name':'hepta_mobile_use_action','strict':True,'schema':mobile}}}
 mapping=api['mobile_mapping_evidence'](action,mapped,legacy,allowed,content,requestid,1)
 call={'call_id':allowed,'tool':'shell.exec','argv':['synthetic_not_executed']}
 calls=[call] if with_semantic else []
 semantic={'call_id':allowed,'wire_call':call,'semantic_tool':mapped['tool'],'alias':'visual_fixture'}
 values={'action':copy.deepcopy(action),'decision':copy.deepcopy(mapped),'mapping':mapping,
         'body':body,'projected':projected,'images':images,'semantic':semantic,'raw':content}
 if modify:modify(values)
 write(run/'local-01.model-action.json',enc(values['action']))
 write(run/'local-01.mapping.json',enc(values['mapping']))
 if with_semantic:write(run/('semantic-'+sha(allowed.encode())+'.json'),enc(values['semantic']))
 new=root/'collected';new.mkdir(mode=0o700)
 snapshot=collector.Snapshot(new,1048576)
 try:
  result=evidence.verify_projection(snapshot,run,'local-01',values['body'],values['images'],
   values['projected'],values['raw'],values['decision'],1,calls,[],api)
 except (ValueError,KeyError,TypeError) as error:
  assert reject,(name,type(error).__name__,str(error))
  passed(name);return
 assert not reject,name
 assert result['named_action_projection_verified'] is True
 assert result['projection_is_execution_or_business_success'] is False
 assert result['original_model_action_file_sha256']==sha((run/'local-01.model-action.json').read_bytes())
 assert result['original_mapping_file_sha256']==sha((run/'local-01.mapping.json').read_bytes())
 assert not snapshot.final_changes()
 passed(name)
open_action={'name':'mobile_use','arguments':{'action':'open','text':'visual_fixture','summary':'Open the approved fixture.'}}
open_expected={'kind':'tool.call','call_id':allowed,'tool':'phone.open_app','command':'','argv':['visual_fixture'],'summary':'Open the approved fixture.','task_status':'in_progress'}
unicode='Synthetic 🦉\n原样 "$HOME" ; literal'
type_action={'name':'mobile_use','arguments':{'action':'type','package':'fixture.app','view_id':'fixture.app:id/editor','old_text':'','text':unicode,'summary':'Set exact text.'}}
type_expected={'kind':'tool.call','call_id':allowed,'tool':'phone.input_text','command':unicode,'argv':['fixture.app','fixture.app:id/editor',''],'summary':'Set exact text.','task_status':'in_progress'}
final_action={'name':'mobile_use','arguments':{'action':'terminate','status':'unknown','summary':'No verified outcome.'}}
final_expected={'kind':'turn.complete','call_id':'','tool':'none','command':'','argv':[],'summary':'No verified outcome.','task_status':'unknown'}
active=True;forbidden=[]
def audit(event,args):
 if active and (event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.posix_spawn','os.fork','os.exec','os.kill','os.killpg')):
  forbidden.append(event);raise AssertionError('external operation forbidden:'+event)
sys.addaudithook(audit)
fixture('valid_open_and_original_semantic_binding',open_action,open_expected,with_semantic=True)
fixture('exact_unicode_named_fields',type_action,type_expected)
fixture('honest_unknown_terminal_no_success_promotion',final_action,final_expected)
fixture('changed_original_model_object_rejected',open_action,open_expected,
 lambda v:v['action']['arguments'].__setitem__('text','another'),reject=True)
fixture('changed_legacy_decision_rejected',type_action,type_expected,
 lambda v:v['decision'].__setitem__('command','changed'),reject=True)
fixture('changed_mapping_hash_rejected',open_action,open_expected,
 lambda v:v['mapping'].__setitem__('original_model_content_sha256','0'*64),reject=True)
fixture('changed_admission_identity_rejected',open_action,open_expected,
 lambda v:v['projected'].__setitem__('allowed_call_id','r01_'+'f'*16),reject=True)
fixture('changed_system_prompt_rejected',open_action,open_expected,
 lambda v:v['body']['messages'][0].__setitem__('content','invented'),reject=True)
fixture('changed_decoder_rejected',open_action,open_expected,
 lambda v:v['body']['response_format']['json_schema'].__setitem__('strict',False),reject=True)
fixture('mismatched_original_native_alias_rejected',open_action,open_expected,
 lambda v:v['semantic'].__setitem__('alias','other'),with_semantic=True,reject=True)
active=False
assert not forbidden
report={'schema':'hepta.mobile-projection-collector-host-check.v150.1','state':'PASS',
 'checks':checks,'passed':len(checks),'total':len(checks),'forbidden_operation_attempts':forbidden,
 'model_requests':0,'phone_operations':0,'task_nonces_generated':False,'scope':'Synthetic mapping evidence only; no native task or business qualification',
 'original_collector_gates_preserved':True,'raw_originals_unchanged':True,
 'provider_sha256':evidence.PROVIDER_SHA256,'projection_is_business_success':False}
write(out/'HOST-CHECKS-01.json',enc(report))
print(json.dumps({'state':'PASS','passed':len(checks),'total':len(checks),'report_sha256':sha((out/'HOST-CHECKS-01.json').read_bytes()),'phone_operations':0,'model_requests':0},sort_keys=True))
