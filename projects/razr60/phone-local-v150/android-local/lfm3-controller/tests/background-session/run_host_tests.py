#!/usr/bin/env python3
"""Real client protocol/lease code with controlled Android IO; no phone or process launch."""
import argparse,hashlib,importlib.util,json,shutil,subprocess,time
from pathlib import Path

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);p.add_argument('--release8',action='store_true');a=p.parse_args()
 source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 spec=importlib.util.spec_from_file_location('background_client_fixture',Path(__file__).with_name('prepare_fixture.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 files,extraction=m.prepare(source,out/'fixture');files.append(Path(__file__).with_name('BackgroundSessionHostTest.java'));classes=out/'classes';classes.mkdir()
 before={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
 flags=['--release','8'] if a.release8 else ['-source','8','-target','8']
 compiler=[shutil.which('javac')] if shutil.which('javac') else ['java','-m','jdk.compiler/com.sun.tools.javac.Main']
 cmd=compiler+flags+['-encoding','UTF-8','-Xlint:all,-options','-Werror','-d',str(classes)]+list(map(str,files))
 stages=[]
 for name,argv in [('compile',cmd),('client-tests',['java','-cp',str(classes),'org.trillionnium.hepta.local.BackgroundSessionHostTest',str(out/'cases')])]:
  started=time.monotonic();r=subprocess.run(argv,text=True,capture_output=True,timeout=60);(out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr);stages.append({'name':name,'exit_code':r.returncode,'elapsed_seconds':time.monotonic()-started})
  if r.returncode:
   (out/'VALIDATION.json').write_text(json.dumps({'status':'failed','stages':stages},indent=2)+'\n');print(r.stdout[-3000:]);print(r.stderr[-9000:]);return r.returncode
 after={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
 if before!=after:raise RuntimeError('source changed during checks')
 result=json.loads((out/'cases/RESULT.json').read_text());proof={'schema':'hepta.background-client-host-validation.v1','status':'passed','compiler_contract':'Java8 API release' if a.release8 else 'Java8 syntax/target only; not --release8 or Android compile proof','passed':result['passed'],'failed':result['failed'],'source_inputs':before,'source_inputs_unchanged':True,'stages':stages,'phone_actions':False,'native_inference':False,'root_process_started':False,'android_runtime':False,'fixture':extraction}
 (out/'VALIDATION.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps({k:proof[k] for k in ('status','compiler_contract','passed','failed')},indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
