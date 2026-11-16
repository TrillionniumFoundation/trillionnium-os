#!/usr/bin/env python3
"""Host-only actual pure-class diagnostics; Android Service/Session are pinned, not executed."""
import argparse, ast, hashlib, json, os, subprocess, time
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2])
for n in ('output','java-home','json-jar'):p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);(a.output/'classes').mkdir()
sha=lambda b:hashlib.sha256(b).hexdigest()
PRODUCTION_PINS={'src/org/trillionnium/hepta/local/WebShoppingObservationStability.java': '613148d806b0eade9b3c893a652e5661e45f22e53476a884d3eb5be8576a6eaa', 'src/org/trillionnium/hepta/local/WebObservationTiming.java': '23cc115bf8eb378dcc1f26ee0d682df3e861df61ff22ea2cf822df84dfbd9027', 'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java': '1ca8f425f780be1130f1a81529d5abc9b3be6153459f6f0c4c9c6b3cecbbd718', 'src/org/trillionnium/hepta/local/WebFlightSession.java': 'a86f308053da7f615c05fb9da03634df73f0f131ad1576165c7a1b07bd63d471'}
m={'files':[{'path':k,'sha256':v} for k,v in PRODUCTION_PINS.items()]}
for path,digest in PRODUCTION_PINS.items():assert sha((a.source/path).read_bytes())==digest
tree=ast.parse((a.source/'tests/web-flight/run_query_host_tests.py').read_text())
paths=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id=='PURE_PATHS' for v in n.targets))
paths=[v for v in paths if not v.endswith('/WebFlightQueryHostTest.java')]
paths.append('src/org/trillionnium/hepta/local/WebObservationTiming.java')
assert len(paths)==len(set(paths))
files=[a.source/v for v in paths]
test=a.source/'tests/native-containment-diagnostic/NativeContainmentDiagnosticHostTest.java'
tracked=[*files,test,Path(__file__).resolve(),a.source/'SOURCE-MANIFEST.json',a.json_jar]
tracked.extend(a.source/f['path'] for f in m['files'])
tracked=list(dict.fromkeys(tracked));before={str(f):f.read_bytes() for f in tracked}
assert sha(a.json_jar.read_bytes())=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
report=dict(schema='hepta.native-containment-targeted-gate.v1',all_pass=False,phone_actions=0,
 synthetic_complete_native_pairs=True,historical_native_pair_replayed=False,
 full_android_service_compiled=False,full_android_session_compiled=False,
 production_files=m['files'],inputs=[dict(path=k,sha256=sha(v),bytes=len(v)) for k,v in before.items()],steps=[])
try:
 for name,cmd in [
  ('compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-cp',a.json_jar,'-d',a.output/'classes',*files,test]),
  ('run',[a.java_home/'bin/java','-Xmx512m','-cp',str(a.output/'classes')+os.pathsep+str(a.json_jar),'org.trillionnium.hepta.local.NativeContainmentDiagnosticHostTest'])]:
  start=time.monotonic();r=subprocess.run(list(map(str,cmd)),capture_output=True,timeout=150)
  (a.output/(name+'.stdout')).write_bytes(r.stdout);(a.output/(name+'.stderr')).write_bytes(r.stderr)
  report['steps'].append(dict(name=name,exit_code=r.returncode,elapsed_seconds=time.monotonic()-start,
   stdout_sha256=sha(r.stdout),stderr_sha256=sha(r.stderr)))
  if r.returncode:raise RuntimeError(name+' failed: '+r.stderr.decode(errors='replace')[-2000:])
  if name=='run':
   report['tests']=json.loads(r.stdout);assert report['tests']['all_pass'] and report['tests']['cases']==17
 report['all_pass']=True
except Exception as e:report['error']=str(e)
report['inputs_unchanged']=all(Path(k).read_bytes()==v for k,v in before.items())
report['all_pass'] &= report['inputs_unchanged']
raw=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode();(a.output/'RESULT.json').write_bytes(raw)
print(json.dumps(dict(all_pass=report['all_pass'],result_sha256=sha(raw),tests=report.get('tests'),error=report.get('error'))))
raise SystemExit(0 if report['all_pass'] else 1)
