#!/usr/bin/env python3
"""Exact production pre-dispatch methods/control flow and complete receipt verifier."""
import argparse, ast, hashlib, importlib.util, json, subprocess, time
from pathlib import Path
def sha(data): return hashlib.sha256(data).hexdigest()
def main():
 p=argparse.ArgumentParser()
 for key in ('source','output','java-home','json-jar'):p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--baseline-source',type=Path);p.add_argument('--actual-helper',type=Path)
 a=p.parse_args();root=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 here=Path(__file__).resolve().parent
 report={'schema':'hepta.web-pre-dispatch-host.v1','passed':False,'phone_commands':0,'stages':[],
 'scope':'Exact Session methods and Controller catch/continue. Android, model and IPC effects are synthetic. Full receipt verifier uses synthetic or saved authentication inputs.'}
 try:
  assert sha(a.json_jar.read_bytes())=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
  helper=root/'tests/action-worker/run_host_tests.py';spec=importlib.util.spec_from_file_location('extractor',helper)
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  session=root/'src/org/trillionnium/hepta/local/WebFlightSession.java';controller=root/'src/org/trillionnium/hepta/local/LocalTaskController.java'
  signatures=['static final class PreDispatchPageChanged extends IllegalStateException','private void requirePreDispatchCapture(WebTaskDomain original,PhoneObservation frame,ActionDecision action,','void claimPreDispatchReobserve(PreDispatchPageChanged failure,PhoneObservation frame,ActionDecision action,','void beforeModelAction(ActionDecision action,String run,long deadline)']
  methods=[m.body(session.read_text(),s) for s in signatures];control=controller.read_text()
  anchor='                final WebFlightSession webTask=activeWebTask;';end='                long nativeDispatchStarted=activeNativeTask==null?-1:SystemClock.elapsedRealtime();'
  assert control.count(anchor)==1 and control.count(end)==1;block=control[control.index(anchor):control.index(end)]
  assert 'modelActionOutcome' not in block and 'awaitAction' not in block
  report['source_inputs']=[{'path':str(f.relative_to(root)),'sha256':sha(f.read_bytes())} for f in (session,controller,helper)]
  report['methods']=[{'signature':s,'sha256':sha(v.encode())} for s,v in zip(signatures,methods)]
  report['controller_block_sha256']=sha(block.encode())
  template=here/'WebPreDispatchHost.template';receipt=here/'WebPreDispatchReceiptHostTest.java'
  report['test_inputs']=[{'path':f.name,'sha256':sha(f.read_bytes())} for f in (Path(__file__),template,receipt)]
  def run(name,args,expected=0,reason=None):
   start=time.monotonic();r=subprocess.run(list(map(str,args)),capture_output=True,stdin=subprocess.DEVNULL,timeout=90)
   (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
   report['stages'].append({'name':name,'exit_code':r.returncode,'expected_exit_code':expected,'elapsed_s':time.monotonic()-start,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)})
   assert r.returncode==expected,(name,r.returncode,r.stderr.decode(errors='replace')[-4000:])
   if reason:assert reason in r.stderr.decode(errors='replace'),(name,'red reason differs')
  for stage in (['baseline','current'] if a.baseline_source else ['current']):
   chosen=list(methods);selected=block
   if stage=='baseline':
    bs=a.baseline_source/'src/org/trillionnium/hepta/local/WebFlightSession.java';bc=a.baseline_source/'src/org/trillionnium/hepta/local/LocalTaskController.java'
    chosen[-1]=m.body(bs.read_text(),signatures[-1]);old='                if(activeWebTask!=null)activeWebTask.beforeModelAction(action,decisionRunId,deadline);'
    assert bc.read_text().count(old)==1;selected=old+'\n'
    report['baseline']={'session_sha256':sha(bs.read_bytes()),'controller_sha256':sha(bc.read_bytes()),'active_method_sha256':sha(chosen[-1].encode()),'controller_block_sha256':sha(selected.encode()),'candidate_type_helpers_compiled_but_unreachable_from_baseline_flow':True}
   folder=out/stage;folder.mkdir();java=folder/'WebPreDispatchHost.java';classes=folder/'classes'
   java.write_text(template.read_text().replace('/* EXACT_SESSION_METHODS */','\n\n'.join(chosen)).replace('/* EXACT_CONTROLLER_BLOCK */',selected))
   run(stage+'-compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-cp',a.json_jar,'-d',classes,java])
   run(stage+'-cases',[a.java_home/'bin/java','-cp',str(classes)+':'+str(a.json_jar),'org.trillionnium.hepta.local.WebPreDispatchHost',folder/'CASES.json',stage],1 if stage=='baseline' else 0,'pre-dispatch recovery did not request a fresh model decision' if stage=='baseline' else None)
   if stage=='current':report['control_flow']=json.loads((folder/'CASES.json').read_text())
  parsed=ast.parse((root/'tests/web-flight/run_query_host_tests.py').read_text())
  paths=next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PURE_PATHS' for t in n.targets))
  inputs=[root/v for v in paths if v!='tests/web-flight/WebFlightQueryHostTest.java']
  report['receipt_verifier_inputs']=[{'path':str(v.relative_to(root)),'sha256':sha(v.read_bytes())} for v in inputs]
  # Match Android JSONObject(Map)'s explicit null entries; preserve original inputs.
  purpose=root/'src/org/trillionnium/hepta/webprotocol/WebTaskPurpose.java';raw=purpose.read_text()
  old='new JSONObject(purpose.authorization.evidence());';marker='    private static String text(JSONObject value,String key)throws Exception{'
  bridge='    private static JSONObject androidMap(java.util.Map<String,Object> input)throws Exception{\n        JSONObject out=new JSONObject(input);\n        for(java.util.Map.Entry<String,Object> row:input.entrySet())if(row.getValue()==null)out.put(row.getKey(),JSONObject.NULL);\n        return out;\n    }\n'
  assert raw.count(old)==1 and raw.count(marker)==1
  projection=out/'WebTaskPurpose.java';projection.write_text(raw.replace(old,'androidMap(purpose.authorization.evidence());').replace(marker,bridge+marker))
  report['host_json_boundary']={'class':'WebTaskPurpose','original_sha256':sha(purpose.read_bytes()),'compiled_projection_sha256':sha(projection.read_bytes()),'change':'JSONObject(Map) explicit-null entries retained as on Android','production_source_modified':False,'original_capture_callback_and_binding_bytes_modified':False}
  inputs=[projection if v==purpose else v for v in inputs]
  classes=out/'receipt-classes'
  run('receipt-compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-cp',a.json_jar,'-d',classes,*inputs,receipt])
  cmd=[a.java_home/'bin/java','-cp',str(classes)+':'+str(a.json_jar),'org.trillionnium.hepta.local.WebPreDispatchReceiptHostTest',out/'RECEIPT-CASES.json']
  if a.actual_helper:cmd.append(a.actual_helper.resolve())
  run('receipt-cases',cmd);report['receipt_verifier']=json.loads((out/'RECEIPT-CASES.json').read_text())
  for v in report['source_inputs']+report['receipt_verifier_inputs']:assert sha((root/v['path']).read_bytes())==v['sha256'],'source changed during gate'
  report['passed']=True
 except Exception as error:report['error']=str(error)
 finally:(out/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({k:report.get(k) for k in ['passed','error']},ensure_ascii=False));return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
