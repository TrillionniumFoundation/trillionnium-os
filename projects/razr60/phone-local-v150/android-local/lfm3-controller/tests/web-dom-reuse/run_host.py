#!/usr/bin/env python3
"""Synthetic ownership/parity checks; no phone or network operations."""
import argparse,ast,hashlib,json,os,pathlib,subprocess,time
p=argparse.ArgumentParser()
for n in ('source','output','java-home','json-jar'):p.add_argument('--'+n,type=pathlib.Path,required=True)
a=p.parse_args();o=a.output;o.mkdir(parents=True,exist_ok=False);(o/'classes').mkdir()
t=ast.parse((a.source/'tests/web-flight/run_query_host_tests.py').read_text())
paths=next(ast.literal_eval(n.value) for n in t.body if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id=='PURE_PATHS' for v in n.targets))
paths=[x for x in paths if not x.endswith('/WebFlightQueryHostTest.java')]
paths+=['tests/web-dom-reuse/'+x for x in ('CanonicalComparisonParity.java','ProjectionParityHostTest.java','ReceiptReuseHostTest.java')]
sha=lambda b:hashlib.sha256(b).hexdigest()
original={x:(a.source/x).read_bytes() for x in paths};jar=a.json_jar.read_bytes()
r={'schema':'hepta.dom-reuse-host-validation.v1','all_pass':False,'host_only':True,'phone_actions':0,'live_native_admission_tested_here':False,
'inputs':[{'path':x,'bytes':len(b),'sha256':sha(b)} for x,b in sorted(original.items())],'json_dependency_sha256':sha(jar),'steps':[]}
def run(n,cmd):
 start=time.monotonic();v=subprocess.run(list(map(str,cmd)),capture_output=True,timeout=150)
 (o/(n+'.stdout')).write_bytes(v.stdout);(o/(n+'.stderr')).write_bytes(v.stderr)
 r['steps'].append({'name':n,'exit_code':v.returncode,'elapsed_seconds':time.monotonic()-start,'stdout_sha256':sha(v.stdout),'stderr_sha256':sha(v.stderr)})
 if v.returncode:raise RuntimeError(n+' failed: '+v.stderr.decode()[-1000:])
 return v.stdout
try:
 assert sha(jar)=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
 run('compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-cp',a.json_jar,'-d',o/'classes',*[a.source/x for x in paths]])
 for n,k in [('comparison','webprotocol.CanonicalComparisonParity'),('projection','webprotocol.ProjectionParityHostTest'),('ownership','local.ReceiptReuseHostTest')]:
  r[n]=json.loads(run(n,[a.java_home/'bin/java','-Xmx768m','-cp',str(o/'classes')+os.pathsep+str(a.json_jar),'org.trillionnium.hepta.'+k]));assert r[n]['all_pass']
 r['all_pass']=True
except Exception as e:r['error']=str(e)
r['inputs_unchanged']=all((a.source/x).read_bytes()==b for x,b in original.items()) and a.json_jar.read_bytes()==jar;r['all_pass']&=r['inputs_unchanged']
raw=(json.dumps(r,sort_keys=True,indent=2)+'\n').encode();(o/'RESULT.json').write_bytes(raw)
print(json.dumps({'all_pass':r['all_pass'],'error':r.get('error'),'result_sha256':sha(raw),'cases':{k:r[k].get('cases') for k in ('comparison','projection','ownership') if k in r}}))
raise SystemExit(0 if r['all_pass'] else 1)

