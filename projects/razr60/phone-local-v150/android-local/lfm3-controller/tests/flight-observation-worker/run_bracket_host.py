#!/usr/bin/env python3
"""Compile original pure production classes and run explicit synthetic policy/bracket cases."""
import argparse,ast,hashlib,json,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--json-jar',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[2];source=root;out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
module=ast.parse((source/'tests/web-flight/run_query_host_tests.py').read_text())
paths=next(ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PURE_PATHS' for t in n.targets))
paths=[x for x in paths if x!='tests/web-flight/WebFlightQueryHostTest.java']
paths=list(dict.fromkeys(paths+['src/org/trillionnium/hepta/local/WebFlightNativeStability.java']))
original_policy=root/'tests/web-flight/WebFlightNativeStabilityHostTest.java'
sources=[source/x for x in paths]+[original_policy,Path(__file__).with_name('reference-current57')/'WebFlightEvidenceHostTest.java',Path(__file__).with_name('FlightObservationBracketHost.java')]
jar=a.json_jar.resolve()
record={'schema':'hepta.current57-bracket-merged59-pure-host.v1','phone_operations':0,'android_compiled':False,
    'native_io_or_service_authority_proven':False,'sources':[{'path':str(x),'bytes':x.stat().st_size,'sha256':hashlib.sha256(x.read_bytes()).hexdigest()} for x in sources],
    'boundary':'Actual merged production WebFlightNativeStability and dependencies; synthetic complete DOM/native/capture fixtures. Original evidence-test factories are reused but its old main is not executed.','stages':[]}
cp=str(out/'classes')+':'+str(jar)
commands=[('compile',['java','-m','jdk.compiler/com.sun.tools.javac.Main','-source','8','-target','8','-encoding','UTF-8','-Xlint:all,-options','-Werror','-cp',str(jar),'-d',str(out/'classes'),*[str(x) for x in sources]]),
    ('policy36',['java','-cp',cp,'org.trillionnium.hepta.local.WebFlightNativeStabilityHostTest',str(out/'policy36-cases.json')]),
    ('observation-bracket',['java','-cp',cp,'org.trillionnium.hepta.local.FlightObservationBracketHost',str(out/'bracket-cases.json')])]
for name,cmd in commands:
    start=time.monotonic();r=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
    (out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr)
    record['stages'].append({'name':name,'exit_code':r.returncode,'elapsed_s':time.monotonic()-start,'command':cmd})
    if r.returncode:
        record['all_pass']=False;(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(r.stdout);print(r.stderr);raise SystemExit(r.returncode)
record['all_pass']=True;record['policy36']=json.loads((out/'policy36-cases.json').read_text());record['bracket']=json.loads((out/'bracket-cases.json').read_text())
(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'all_pass':True,'policy_cases':record['policy36']['cases'],'bracket_cases':record['bracket']['cases'],'output':str(out)}))
