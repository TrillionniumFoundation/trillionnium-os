#!/usr/bin/env python3
"""Pure carousel policy/bracket regressions. Optional raw captures are read in place; no phone I/O."""
import argparse,ast,hashlib,json,subprocess,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--output',type=Path,required=True);p.add_argument('--json-jar',type=Path,required=True)
    p.add_argument('--actual-raw',type=Path,action='append',default=[])
    p.add_argument('--reject-raw',type=Path,action='append',default=[])
    a=p.parse_args();root=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
    module=ast.parse((root/'tests/web-flight/run_query_host_tests.py').read_text())
    paths=next(ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PURE_PATHS' for t in n.targets))
    paths=[x for x in paths if x!='tests/web-flight/WebFlightQueryHostTest.java']
    paths=list(dict.fromkeys(paths+['src/org/trillionnium/hepta/local/WebFlightNativeStability.java','src/org/trillionnium/hepta/local/WebNativeObservationChanged.java','tests/web-flight/WebFlightNativeStabilityHostTest.java','tests/flight-observation-worker/reference-current57/WebFlightEvidenceHostTest.java','tests/flight-observation-worker/FlightObservationBracketHost.java','tests/flight-carousel-count/FlightCarouselCountHost.java']))
    jar=a.json_jar.resolve();cp=str(out/'classes')+':'+str(jar)
    record={'schema':'hepta.carousel-seven-eight-portable-host.v1','all_pass':False,'phone_operations':0,'android_compiled':False,'android_service_authority_proven':False,'business_verified':False,'sources':[{'path':x,'sha256':sha(root/x)} for x in paths],'external_raw_inputs':[{'sha256':sha(x),'expect_admitted':True} for x in a.actual_raw]+[{'sha256':sha(x),'expect_admitted':False} for x in a.reject_raw],'stages':[]}
    commands=[('compile',['java','-m','jdk.compiler/com.sun.tools.javac.Main','-source','8','-target','8','-encoding','UTF-8','-Xlint:all,-options','-Werror','-cp',str(jar),'-d',str(out/'classes'),*[str(root/x) for x in paths]])]
    for name,cls in [('policy','WebFlightNativeStabilityHostTest'),('bracket','FlightObservationBracketHost'),('counts','FlightCarouselCountHost')]:
        cmd=['java','-cp',cp,'org.trillionnium.hepta.local.'+cls,str(out/(name+'.json'))]
        if name=='counts':cmd += [str(x) for x in a.actual_raw]+['reject:'+str(x) for x in a.reject_raw]
        commands.append((name,cmd))
    for name,cmd in commands:
        start=time.monotonic();r=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
        (out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr)
        record['stages'].append({'name':name,'exit_code':r.returncode,'elapsed_s':time.monotonic()-start})
        (out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
        if r.returncode:print(r.stdout);print(r.stderr);return r.returncode
    missing=out/'MissingDomProof.java'
    missing.write_text('package org.trillionnium.hepta.local; import org.json.*; final class MissingDomProof { void test(JSONArray a,JSONArray b)throws Exception {WebFlightNativeStability.compareNative(a,b,"0");}}\n')
    r=subprocess.run(['java','-m','jdk.compiler/com.sun.tools.javac.Main','-cp',cp,'-d',str(out/'rejected-classes'),str(missing)],capture_output=True,text=True,timeout=30)
    (out/'missing-proof-compile.stderr').write_text(r.stderr)
    if r.returncode==0 or 'compareNative' not in r.stderr:raise AssertionError('missing DOM proof must fail compilation')
    record['missing_proof_parameter_compile_rejected']=True
    source=(root/'src/org/trillionnium/hepta/local/WebFlightNativeStability.java').read_text()+(root/'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java').read_text()
    required=['compareNative(beforeNative,afterNative,targetPath,domProof);','compareNative(oldNative,newNative,permit.targetPath,permit.domEvidence());','compareNative(observedNative,liveNative,source.targetPath,proof.getJSONObject("dom"));']
    record['all_three_original_calls_bind_dom_proof']=all(x in source for x in required)
    if not record['all_three_original_calls_bind_dom_proof']:raise AssertionError('all three original call sites must retain their own DOM proof')
    record['results']={n:json.loads((out/(n+'.json')).read_text()) for n in ['policy','bracket','counts']};record['all_pass']=True
    (out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'all_pass':True,'cases':{n:v['cases'] for n,v in record['results'].items()},'phone_operations':0}));return 0

if __name__=='__main__':raise SystemExit(main())
