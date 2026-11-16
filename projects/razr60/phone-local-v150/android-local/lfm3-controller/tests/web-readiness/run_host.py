#!/usr/bin/env python3
"""Exact observation/retry methods with explicit host IPC/native instrumentation."""
import argparse,ast,gzip,hashlib,importlib.util,json,subprocess,time
from pathlib import Path
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser()
 for name in ['output','java-home','json-jar']:p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();test=Path(__file__).resolve().parent;root=test.parents[1];out=a.output.resolve();out.mkdir(exist_ok=False,parents=True)
 report={'schema':'hepta.web-readiness-host.v1','all_pass':False,'phone_operations':False,'native_identity_and_ipc_mocked':True,'calendar_pending_detectors_mocked':True,'future_sequences_synthetic':True,'stages':[]}
 try:
  fixture=out/'originals';fixture.mkdir();old=root/'tests/shopping-observation-retry/fixtures/actual-shopping-v57-r1'
  provenance=json.loads((old/'PROVENANCE.json').read_text())
  for row in provenance['files']:
   zipped=(old/row['fixture_file']).read_bytes();raw=gzip.decompress(zipped)
   assert sha(zipped)==row['gzip_sha256'] and sha(raw)==row['sha256'] and len(raw)==row['bytes']
   (fixture/row['name']).write_bytes(raw)
  (fixture/'PROVENANCE.json').write_bytes((old/'PROVENANCE.json').read_bytes())
  assert sha(a.json_jar.read_bytes())=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
  spec=importlib.util.spec_from_file_location('extractor',root/'tests/action-worker/run_host_tests.py')
  extractor=importlib.util.module_from_spec(spec);spec.loader.exec_module(extractor)
  parsed=ast.parse((root/'tests/web-flight/run_query_host_tests.py').read_text())
  paths=next(ast.literal_eval(n.value) for n in parsed.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PURE_PATHS' for t in n.targets))
  inputs=[root/v for v in paths if v!='tests/web-flight/WebFlightQueryHostTest.java']
  inputs += [root/'src/org/trillionnium/hepta/local/WebObservationTiming.java',root/'src/org/trillionnium/hepta/local/TaskDisplayText.java']
  report['source_inputs']=[{'path':str(v.relative_to(root)),'sha256':sha(v.read_bytes())} for v in inputs]
  signatures=['PhoneObservation observe(PhoneObservation initial,Observer observer,long deadline)','private boolean retryLoadingDocument(WebEvidenceReceipt first,WebEvidenceReceipt last,PhoneObservation frame,','private static boolean sameFrame(PhoneObservation a,PhoneObservation b)','private static String loadingKey(WebEvidenceReceipt receipt)']
  template=test/'WebReadinessHost.template';report['template_sha256']=sha(template.read_bytes())
  def command(name,args,expected=0,contains=None):
   start=time.monotonic();r=subprocess.run(list(map(str,args)),cwd=root,capture_output=True,stdin=subprocess.DEVNULL,timeout=90)
   (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
   report['stages'].append({'name':name,'exit_code':r.returncode,'expected_exit_code':expected,'elapsed_s':time.monotonic()-start,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)})
   assert r.returncode==expected,(name,r.returncode,r.stderr.decode(errors='replace')[-3000:])
   if contains:assert contains in r.stderr.decode(errors='replace'),(name,'unexpected red reason')
  for stage,source in [('baseline',test/'reference-5ad/WebFlightSession.java.reference'),('current',root/'src/org/trillionnium/hepta/local/WebFlightSession.java')]:
   target=out/stage;target.mkdir();methods=[extractor.body(source.read_text(),sig) for sig in signatures]
   java=target/'WebReadinessHost.java';java.write_text(template.read_text().replace('/* EXACT_PRODUCTION_METHODS */','\n\n'.join(methods)))
   report[stage]={'source_sha256':sha(source.read_bytes()),'methods':[{'signature':s,'sha256':sha(v.encode())} for s,v in zip(signatures,methods)]}
   classes=target/'classes'
   command(stage+'-compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-cp',a.json_jar,'-d',classes,*inputs,java])
   modes=[('precommit','unexercised IPC waiting status'),('initialflight','AX/DOM bracket changed'),('nativechange','native target, ancestor')] if stage=='baseline' else [('all',None)]
   for mode,expected in modes:
    command(stage+'-'+mode,[a.java_home/'bin/java','-cp',str(classes)+':'+str(a.json_jar),'org.trillionnium.hepta.local.WebReadinessHost',fixture,target/(mode+'.json'),mode],1 if stage=='baseline' else 0,expected)
   if stage=='current':report['current']['cases']=json.loads((target/'all.json').read_text())
  report['all_pass']=True
 except Exception as e:report['error']=str(e)
 finally:(out/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({k:report.get(k) for k in ['all_pass','error']}))
 return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
