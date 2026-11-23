#!/usr/bin/env python3
"""Focused native model-only projection validation. No phone, model or speed claim."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path
def pin(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def main():
 p=argparse.ArgumentParser()
 for name in ('source','output','java-home','json-jar','baseline-source'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--replay-prompt',type=Path,action='append',default=[]);p.add_argument('--replay-system',type=Path)
 a=p.parse_args();s=a.source.resolve();out=a.output.resolve();j=a.java_home.resolve();jar=a.json_jar.resolve();base=a.baseline_source.resolve()
 assert not out.exists() and s not in out.parents
 assert pin(jar)['sha256']=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
 out.mkdir(parents=True);env=dict(os.environ)
 for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH'):env.pop(k,None)
 env['JAVA_HOME']=str(j);env['PATH']=str(j/'bin')+':'+env.get('PATH','');env['PYTHONDONTWRITEBYTECODE']='1'
 pkg=s/'src/org/trillionnium/hepta/local';tests=s/'tests/native-model-projection'
 sources=[pkg/'LocalTaskController.java',pkg/'VisualPromptProjection.java',*sorted(tests.glob('*'))]
 before={str(f):pin(f) for f in sources if f.is_file()}
 r={'schema':'hepta.native-model-projection-host-validation.v1','passed':False,'steps':[],'inputs_before':before,'replays':[],
    'phone_operations':0,'android_runtime':False,'model_inference':False,'exact_token_count_measured':False,'latency_measured':False}
 def run(n,argv,timeout=180):
  cmd=list(map(str,argv));start=time.monotonic();v=subprocess.run(cmd,cwd=out,env=env,capture_output=True,timeout=timeout)
  so=out/(n+'.stdout');se=out/(n+'.stderr');so.write_bytes(v.stdout);se.write_bytes(v.stderr)
  r['steps'].append({'name':n,'argv':cmd,'exit_code':v.returncode,'seconds':time.monotonic()-start,'stdout':pin(so),'stderr':pin(se)})
  if v.returncode:raise RuntimeError(n+' failed: '+v.stderr.decode('utf-8','replace')[-2500:]+v.stdout.decode('utf-8','replace')[-1000:])
  return v.stdout
 try:
  pure=out/'pure-classes';pure.mkdir()
  run('pure-compile',[j/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all','-Werror','-cp',jar,'-d',pure,
      pkg/'VisualPromptProjection.java',s/'tests/visual-prompt-projection/VisualPromptProjectionHostTest.java',tests/'NativeModelPromptProjectionHostTest.java'])
  cp=str(pure)+os.pathsep+str(jar)
  for name,cls in [('visual','VisualPromptProjectionHostTest'),('native','NativeModelPromptProjectionHostTest')]:
   result=json.loads(run(name+'-projection',[j/'bin/java','-cp',cp,'org.trillionnium.hepta.local.'+cls]));assert result['passed'] is True;r[name+'_projection']=result
  system=run('native-system',[j/'bin/java','-cp',cp,'org.trillionnium.hepta.local.NativeModelPromptProjectionHostTest','--system-text'])
  r['native_system']={'bytes':len(system),'sha256':hashlib.sha256(system).hexdigest()}

  for i,prompt in enumerate(a.replay_prompt):
   raw=prompt.read_bytes();text=raw.decode();prefix='UNTRUSTED_DATA\n';boundary='\nOWNER\n'
   assert text.startswith(prefix) and text.count(boundary)==1
   data_raw,owner=text[len(prefix):].split(boundary,1);data=json.loads(data_raw)
   replay=out/('replay-%02d-source.json'%i);replay.write_text(data_raw,encoding='utf-8')
   projected=json.loads(run('replay-%02d'%i,[j/'bin/java','-cp',cp,'org.trillionnium.hepta.local.NativeModelPromptProjectionHostTest','--project-json',replay]))
   for key in ('screen','events','last_transition','last_model_decision','apps','open_allowed_packages','blocked','format_correction'):
    if key in data:assert data[key]==projected.get(key),'real prompt fact changed: '+key
   old=data['completion']['native_app'];new=projected['completion']['native_app']
   for key in ('phase','observation_id','package','read_only_query_targets','literal_edit_values','back_allowed','result_ready','missing','booking_purchase_or_payment_allowed','web_helper_allowed','external_model_allowed'):
    assert old.get(key)==new.get(key),'native domain changed: '+key
   for key in ('allowed_done_statuses','done_success_eligible','completion_verified','missing'):
    assert data['completion'].get(key)==projected['completion'].get(key),'completion changed: '+key
   oldp=old.get('provider',{});newp=new.get('provider',{})
   for key,value in oldp.items():
    if key not in ('schema','from','to','requested_departure_date','adults'):assert newp.get(key)==value,'provider observation/budget changed: '+key
   for node,resource in old.get('resource_clicks',{}).items():
    for key in ('node_id','node_label','purpose','raw','bounds','native_tree_path','native_parent_class'):
     assert resource.get(key)==new['resource_clicks'][node].get(key),'resource fact changed: '+key
   sections=',\n'.join(json.dumps({k:projected[k]},ensure_ascii=False,separators=(',',':'))[1:-1] for k in data)
   rendered=prefix+('{\n'+sections+'\n}').replace('<','\\u003c')+boundary+owner
   dest=out/('replay-%02d-model-prompt.txt'%i);dest.write_text(rendered,encoding='utf-8')
   assert rendered.split(boundary,1)[1]==owner and len(rendered.encode())<len(raw)
   original_total=len(raw)+(a.replay_system.stat().st_size if a.replay_system else 0);new_total=len(rendered.encode())+len(system)
   r['replays'].append({'original':pin(prompt),'projected':pin(dest),'phase':old['phase'],'owner_exact':True,'screen_history_current_domain_exact':True,
      'provider_observations_and_budgets_preserved':True,'original_system_and_prompt_bytes':original_total,'new_system_and_prompt_bytes':new_total,
      'byte_reduction_fraction':1-new_total/original_total,'byte_scope':'host JSON serialization; not native tokens or latency'})
  routing=out/'routing'
  run('original-routing-gate',[os.sys.executable,s/'tests/native-app-routing/run_host.py','--source',s,'--output',routing,'--java-home',j,'--json-jar',jar])
  route=json.loads((routing/'RESULT.json').read_text());assert route['all_pass'] is True and route['inputs_unchanged'] is True
  r['routing_result']=pin(routing/'RESULT.json');r['routing_cases']=route['cases']['cases'];r['routing_assertions']=route['cases']['assertions']
  entry=routing/'entry-classes';extra=out/'extra-classes';extra.mkdir()

  extra_inputs=[tests/'NativeModelPromptWiringHostTest.java',tests/'NonNativePromptArtifactHostTest.java',
      s/'tests/notes-task-phase/NotesTaskScopeHostTest.java',s/'tests/completion/TaskCompletionGateHostTest.java',s/'tests/fixed-intent-tools/FixedIntentIntegrationHostTest.java']
  run('extra-compile',[j/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all','-Werror','-cp',entry,'-d',extra,*extra_inputs])
  candidate_cp=str(extra)+os.pathsep+str(entry)
  run('wiring',[j/'bin/java','-cp',candidate_cp,'org.trillionnium.hepta.local.NativeModelPromptWiringHostTest',out/'WIRING.json'])
  r['wiring']=json.loads((out/'WIRING.json').read_text());assert r['wiring']['passed'] is True
  baseline=out/'baseline-classes';baseline.mkdir()
  original=[base/'src/org/trillionnium/hepta/local/LocalTaskController.java',base/'src/org/trillionnium/hepta/local/VisualPromptProjection.java']
  assert [pin(f)['sha256'] for f in original]==['57fddc5bacb0b88f60a4095086a5b7cca043d80827794ade7184572b71d8354a','024c24468fe9493396030e7f4c243531d86d2074f3c2157e0776b4792d484bb8']
  run('baseline-compile',[j/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all','-Werror','-cp',entry,'-d',baseline,*original])
  baseline_cp=str(baseline)+os.pathsep+candidate_cp
  run('baseline-terminal',[j/'bin/java','-cp',baseline_cp,'org.trillionnium.hepta.local.NativeTerminalStatusHostTest',out/'baseline-terminal'])
  candidate_rows=json.loads((routing/'terminal-status/grammar-cases.json').read_text());baseline_rows=json.loads((out/'baseline-terminal/grammar-cases.json').read_text())
  assert candidate_rows==baseline_rows and len(candidate_rows)==69
  r['native_69_grammar_rows_exact']=True;r['native_terminal']=json.loads((routing/'terminal-status/GBNF-RESULT.json').read_text())
  notes=s/'tests/notes-task-phase/fixtures/v47-notes-scope-trace.json'
  for name,classpath in [('candidate',candidate_cp),('baseline',baseline_cp)]:
   run(name+'-non-native',[j/'bin/java','-cp',classpath,'org.trillionnium.hepta.local.NonNativePromptArtifactHostTest',out/(name+'-non-native'),notes])
  candidate_files={str(f.relative_to(out/'candidate-non-native')):f.read_bytes() for f in (out/'candidate-non-native').rglob('*') if f.is_file()}
  baseline_files={str(f.relative_to(out/'baseline-non-native')):f.read_bytes() for f in (out/'baseline-non-native').rglob('*') if f.is_file()}
  assert candidate_files==baseline_files and len(candidate_files)==13,'ordinary/visual/Notes actual artifacts differ'
  r['non_native_byte_identical']={'files':[{'path':n,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()} for n,b in sorted(candidate_files.items())],
      'ordinary_visual_notes_system_prompt_grammar_budget_exact':True,'visual_private_evidence_exact':True,'historical_notes_fixture':pin(notes)}
  r['inputs_unchanged']=before=={str(f):pin(f) for f in sources if f.is_file()};assert r['inputs_unchanged'];r['passed']=True
 except Exception as error:r['error']=type(error).__name__+': '+str(error)
 finally:
  (out/'RESULT.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
  print(json.dumps({'passed':r['passed'],'error':r.get('error'),'result':pin(out/'RESULT.json'),'native_checks':r.get('native_projection',{}).get('checks'),
      'wiring_checks':r.get('wiring',{}).get('checks'),'replays':[{'phase':q['phase'],'before':q['original_system_and_prompt_bytes'],'after':q['new_system_and_prompt_bytes']} for q in r['replays']]}))
 return 0 if r['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
