#!/usr/bin/env python3
"""Replay actual immutable DOM fixtures through exact Session observation orchestration.

The private native service, authenticated IPC client and publisher are instrumented
host boundaries. This never reconstructs a live action token or operates a phone.
"""
import argparse,ast,hashlib,importlib.util,json,subprocess,time
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--output',type=Path,required=True)
p.add_argument('--json-jar',type=Path,required=True)
a=p.parse_args()
root=Path(__file__).resolve().parents[2]
test=Path(__file__).resolve().parent
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
fixture_dir=test/'fixtures'/'actual-flight-r2'
provenance=json.loads((fixture_dir/'PROVENANCE.json').read_text())
for member in provenance['files']:
    raw=(fixture_dir/member['path']).read_bytes()
    if len(raw)!=member['bytes'] or hashlib.sha256(raw).hexdigest()!=member['sha256']:
        raise SystemExit('original fixture bytes changed: '+member['path'])
extractor=root/'tests/action-worker/run_host_tests.py'
spec=importlib.util.spec_from_file_location('original_method_extractor',extractor)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
source=root/'src/org/trillionnium/hepta/local/WebFlightSession.java'
raw=source.read_text();methods=[];identity=[]
for signature in ['PhoneObservation observe(PhoneObservation initial,Observer observer,long deadline)',
                  'private static boolean sameFrame(PhoneObservation a,PhoneObservation b)']:
    value=module.body(raw,signature);methods.append(value)
    identity.append({'signature':signature,'bytes':len(value.encode()),'sha256':hashlib.sha256(value.encode()).hexdigest()})
template=test/'FlightObservationSessionHost.template'
generated=template.read_text().replace('/* EXACT_PRODUCTION_METHODS */','\n\n'.join(methods))
java=out/'FlightObservationSessionHost.java';java.write_text(generated)
query_ast=ast.parse((root/'tests/web-flight/run_query_host_tests.py').read_text())
paths=next(ast.literal_eval(n.value) for n in query_ast.body if isinstance(n,ast.Assign)
           and any(isinstance(t,ast.Name) and t.id=='PURE_PATHS' for t in n.targets))
paths=[x for x in paths if x!='tests/web-flight/WebFlightQueryHostTest.java']
paths=list(dict.fromkeys(paths+['src/org/trillionnium/hepta/local/WebFlightNativeStability.java']))
sources=[root/x for x in paths]+[java]
jar=a.json_jar.resolve()
record={'schema':'hepta.flight-session-original-fixture-host-run.v1',
        'session_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        'template_sha256':hashlib.sha256(template.read_bytes()).hexdigest(),
        'generated_sha256':hashlib.sha256(java.read_bytes()).hexdigest(),
        'extracted_methods':identity,'actual_original_fixtures':provenance,
        'sources':[{'path':str(x),'bytes':x.stat().st_size,'sha256':hashlib.sha256(x.read_bytes()).hexdigest()} for x in sources],
        'phone_operations':0,'android_compiled':False,'live_native_token_proven':False,
        'actual_binding_authorization_replayed':False,
        'host_json_boundary':'JSON-java JSONObject(Map) drops Java-null find_query whereas original Android retains explicit null. Original fixture bytes remain unchanged; geometry uses the production checked-stability overload also called by Session. This harness does not claim binding authentication.',
        'boundary':'Exact production observe/sameFrame methods, actual captured DOMs and pure DOM/geometry predicates. Service native IO/authority, authenticated IPC and publisher use explicit host carriers; native completeness is a separate synthetic pure test and worker ownership a separate host test.',
        'compiler_contract':'Java 8 syntax and bytecode target; Android build remains required.',
        'stages':[]}
cp=str(out/'classes')+':'+str(jar)
commands=[('compile',['java','-m','jdk.compiler/com.sun.tools.javac.Main','-source','8','-target','8','-encoding','UTF-8','-Xlint:all,-options','-Werror','-cp',str(jar),'-d',str(out/'classes'),*[str(x) for x in sources]]),
          ('tests',['java','-cp',cp,'org.trillionnium.hepta.local.FlightObservationSessionHost',str(fixture_dir),str(out/'cases.json')])]
for name,cmd in commands:
    started=time.monotonic();r=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
    (out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr)
    record['stages'].append({'name':name,'exit_code':r.returncode,'elapsed_s':time.monotonic()-started,'command':cmd})
    if r.returncode:
        record['all_pass']=False;(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
        print(r.stdout);print(r.stderr);raise SystemExit(r.returncode)
record['all_pass']=True;record['cases']=json.loads((out/'cases.json').read_text())
(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'all_pass':True,'cases':record['cases'],'output':str(out)}))
