#!/usr/bin/env python3
"""Execute exact candidate lifecycle methods with explicit blocked native-IO carriers."""
import argparse,hashlib,importlib.util,json,subprocess,time
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--json-jar',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[2];source=root/'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java'
extractor=root/'tests/action-worker/run_host_tests.py'
spec=importlib.util.spec_from_file_location('original_method_extractor',extractor);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
signatures={
    'NODE_COPY':'private NodeRef(NodeRef original){',
    'GRAPH_BUDGET':'private interface GraphBudget {',
    'CHECK_READ_BUDGET':'private static void checkReadBudget(GraphBudget budget){',
    'GRAPH':'private static final class Graph {',
    'SNAPSHOT':'static final class FlightObservationSnapshot implements AutoCloseable {',
    'READ':'private final class FlightObservationRead<T> implements Runnable {',
    'MAIN_HANDOFF':'private <T>T readFlightObservationOnMain(',
    'CURRENT':'private Graph requireFlightObservationCurrent(',
    'COMPLETE_GRAPH':'private static boolean completeFlightGraph(',
    'OWNS':'private synchronized boolean ownsFlightObservation(',
    'LIVE':'private void requireFlightObservationLive(',
    'AUTHORITY':'private void requireFlightObservationAuthority(',
    'COMPLETE_SNAPSHOT':'private static void requireCompleteFlightSnapshot(',
    'RETAIN':'FlightObservationSnapshot retainFlightObservation(',
    'VERIFY':'JSONObject verifyFlightObservationBracket(',
}
text=source.read_text();template=Path(__file__).with_name('FlightObservationWorkerHost.template');fixture=template.read_text();extracted=[]
for key,signature in signatures.items():
    value=module.body(text,signature);marker='/*__'+key+'__*/';assert fixture.count(marker)==1
    fixture=fixture.replace(marker,value);extracted.append({'signature':signature,'bytes':len(value.encode()),'sha256':hashlib.sha256(value.encode()).hexdigest()})
assert '/*__' not in fixture
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);java=out/'FlightObservationWorkerHost.java';java.write_text(fixture)
jar=a.json_jar.resolve()
canonical=root/'src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java'
record={'schema':'hepta.flight-observation-worker-validation.v1','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
    'template_sha256':hashlib.sha256(template.read_bytes()).hexdigest(),'generated_sha256':hashlib.sha256(java.read_bytes()).hexdigest(),
    'extracted_methods':extracted,'phone_operations':0,'android_compiled':False,'android_runtime_tested':False,
    'boundary':'Exact production token, Graph, copy, main handoff, read queue, await, task/lease predicates and verify orchestration. Android node/frame/scope/Handler/native traversal use instrumented host carriers. Pure bracket rules are separate tests.',
    'stages':[]}
commands=[('compile',['java','-m','jdk.compiler/com.sun.tools.javac.Main','-source','8','-target','8','-encoding','UTF-8','-Xlint:all,-options,-try','-Werror','-cp',str(jar),'-d',str(out/'classes'),str(canonical),str(java)]),
          ('tests',['java','-cp',str(out/'classes')+':'+str(jar),'org.trillionnium.hepta.local.FlightObservationWorkerHost'])]
for name,cmd in commands:
    start=time.monotonic();r=subprocess.run(cmd,capture_output=True,text=True,timeout=45)
    (out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr)
    record['stages'].append({'name':name,'exit_code':r.returncode,'elapsed_s':time.monotonic()-start,'command':cmd})
    if r.returncode:
        record['all_pass']=False;(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(r.stdout);print(r.stderr);raise SystemExit(r.returncode)
record['all_pass']=True;record['cases']=json.loads((out/'tests.stdout').read_text().splitlines()[-1])
(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'all_pass':True,'cases':record['cases'],'output':str(out)}))
