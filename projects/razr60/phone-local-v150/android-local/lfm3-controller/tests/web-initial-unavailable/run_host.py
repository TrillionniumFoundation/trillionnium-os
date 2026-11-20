#!/usr/bin/env python3
"""Pinned original DOM/metadata with exact Session methods; clock, IPC and native tokens are instrumented."""
import argparse,ast,hashlib,importlib.util,json,subprocess,time
from pathlib import Path
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser()
 for name in ['source','baseline-session','output','java-home','json-jar','actual-helper','actual-before']:
  p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();root=a.source.resolve();test=Path(__file__).resolve().parent;out=a.output.resolve();out.mkdir(exist_ok=False,parents=True)
 report={'schema':'hepta.initial-unavailable-host.v1','all_pass':False,'phone_operations':False,'clock_ipc_native_and_future_sequence_synthetic':True,'original_DOM_metadata_pinned':True,'full_receipt_verification_separate':True,'business_verified':False,'stages':[]}
 try:
  assert sha(a.json_jar.read_bytes())=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
  spec=importlib.util.spec_from_file_location('extractor',root/'tests/action-worker/run_host_tests.py')
  extractor=importlib.util.module_from_spec(spec);spec.loader.exec_module(extractor)
  parsed=ast.parse((root/'tests/web-flight/run_query_host_tests.py').read_text())
  paths=next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PURE_PATHS' for t in n.targets))
  inputs=[root/v for v in paths if v!='tests/web-flight/WebFlightQueryHostTest.java']
  inputs += [root/'src/org/trillionnium/hepta/local/WebObservationTiming.java',root/'src/org/trillionnium/hepta/local/TaskDisplayText.java']
  report['source_inputs']=[{'path':str(v.relative_to(root)),'sha256':sha(v.read_bytes())} for v in inputs]
  template=test/'WebInitialUnavailableHost.template';report['template_sha256']=sha(template.read_bytes())
  report['runner_sha256']=sha(Path(__file__).read_bytes())
  report['original_inputs']=[]
  for path in [a.actual_before,*sorted(a.actual_helper.glob('BINDING.json')),*sorted(a.actual_helper.glob('raw-*.json')),*sorted(a.actual_helper.glob('reply-faa30d*.json')),*sorted(a.actual_helper.glob('request-faa30d*.json'))]:
   report['original_inputs'].append({'path':str(path),'sha256':sha(path.read_bytes())})
  signatures=['PhoneObservation observe(PhoneObservation initial,Observer observer,long deadline)',
   'private boolean retryLoadingDocument(WebEvidenceReceipt first,WebEvidenceReceipt last,PhoneObservation frame,',
   'private static boolean sameFrame(PhoneObservation a,PhoneObservation b)',
   'private static String loadingKey(WebEvidenceReceipt receipt)',
   'private PhoneObservation publishWaiting(PhoneObservation frame,WebEvidenceReceipt receipt,String reason)']
  optional='private boolean retryInitialUnavailablePair(WebEvidenceReceipt first,WebEvidenceReceipt last,PhoneObservation frame,'
  def command(name,args,expected=0,contains=None):
   start=time.monotonic();r=subprocess.run(list(map(str,args)),cwd=root,capture_output=True,stdin=subprocess.DEVNULL,timeout=120)
   (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
   report['stages'].append({'name':name,'exit_code':r.returncode,'expected_exit_code':expected,'elapsed_s':time.monotonic()-start,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)})
   assert r.returncode==expected,(name,r.returncode,r.stderr.decode(errors='replace')[-3000:])
   if contains:assert contains in r.stderr.decode(errors='replace'),(name,'unexpected red reason',r.stderr.decode(errors='replace')[-2000:])
  for stage,source,pin in [
   ('baseline',a.baseline_session,'dd45a9b72319bdc52a78152b13f62a849914d97b83146afb7435581a86fa6286'),
   ('current',root/'src/org/trillionnium/hepta/local/WebFlightSession.java','789433dc2254f7661b5318ceb85b8715418335eeb291ee0ca9984a6799207445')]:
   raw=source.read_bytes();assert sha(raw)==pin,(stage,'Session source pin')
   body=raw.decode();sigs=signatures+([optional] if optional in body else [])
   methods=[extractor.body(body,sig) for sig in sigs];target=out/stage;target.mkdir()
   java=target/'WebInitialUnavailableHost.java'
   java.write_text(template.read_text().replace('/* EXACT_PRODUCTION_METHODS */','\n\n'.join(methods)))
   report[stage]={'source_sha256':sha(raw),'generated_sha256':sha(java.read_bytes()),'methods':[{'signature':s,'sha256':sha(v.encode())} for s,v in zip(sigs,methods)]}
   classes=target/'classes'
   command(stage+'-compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-cp',a.json_jar,'-d',classes,*inputs,java])
   mode='counterfactual' if stage=='baseline' else 'all'
   command(stage+'-'+mode,[a.java_home/'bin/java','-cp',str(classes)+':'+str(a.json_jar),'org.trillionnium.hepta.local.WebInitialUnavailableHost',a.actual_helper,a.actual_before,target/'CASES.json',mode],1 if stage=='baseline' else 0,'did not replace unavailable pair with a complete fresh pair' if stage=='baseline' else None)
   if stage=='current':report['current']['cases']=json.loads((target/'CASES.json').read_text())
  for row in report['original_inputs']:assert sha(Path(row['path']).read_bytes())==row['sha256']
  report['original_inputs_unchanged']=True;report['all_pass']=True
 except Exception as e:report['error']=str(e)
 finally:(out/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({k:report.get(k) for k in ['all_pass','error']}))
 return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
