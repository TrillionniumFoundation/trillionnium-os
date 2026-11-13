#!/usr/bin/env python3
"""Replay the retained v61 city failure through current and old pure retry predicates.
No phone or authenticated/native action authority is reconstructed."""
import argparse,gzip,hashlib,importlib.util,json,os,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True

def pin(p):
    raw=p.read_bytes()
    return {'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def need(ok,why):
    if not ok:raise RuntimeError(why)
def main():
    ap=argparse.ArgumentParser()
    for k in ('query-output','city-output','json-jar','java-home','out'):
        ap.add_argument('--'+k,type=Path,required=True)
    a=ap.parse_args();root=Path(__file__).resolve().parents[2];out=a.out.resolve();out.mkdir(exist_ok=False)
    q=json.loads((a.query_output/'RESULT.json').read_bytes());c=json.loads((a.city_output/'RESULT.json').read_bytes())
    need(q['all_pass'] is True and q['cases']['cases']==40 and q['cases']['assertions']==187 and q['originals_unchanged'] is True,'retained query40 failed')
    need(c['all_pass'] is True and c['cases']['cases']==25 and c['cases']['assertions']==40,'city policy suite failed')
    for row in q['source_inputs']+c['source_inputs']:need(pin(Path(row['path']))==row,'prior gate input changed')
    need(pin(a.json_jar)['sha256']=='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed','host JSON differs')
    fixture=root/'tests/web-flight/fixtures/actual-city-v61-r1';provenance=json.loads((fixture/'PROVENANCE.json').read_bytes())
    originals=out/'originals';originals.mkdir();(originals/'PROVENANCE.json').write_bytes((fixture/'PROVENANCE.json').read_bytes())
    for row in provenance['files']:
        z=(fixture/row['fixture_file']).read_bytes()
        need(len(z)==row['gzip_bytes'] and hashlib.sha256(z).hexdigest()==row['gzip_sha256'],'fixture compressed bytes changed')
        raw=gzip.decompress(z);need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'original capture bytes changed')
        (originals/row['name']).write_bytes(raw)
    session=root/'src/org/trillionnium/hepta/local/WebFlightSession.java'
    legacy=root/'tests/web-flight/reference-v61/WebFlightSession.java.reference'
    need(pin(legacy)['sha256']=='8eacb92640772dc7e46a52d81c6531a093a9517ca2363cf38d3c6d4880dbe739','exact v61 reference changed')
    runner=root/'tests/web-flight/run_query_host_tests.py'
    spec=importlib.util.spec_from_file_location('exact_method_extractor',runner);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    projection=Path(c['generated_projection']['path'])
    need(pin(projection)==c['generated_projection'],'actual compiled city projection changed')
    old_method=m.java_block(legacy.read_bytes(),'private boolean retryLoadingDocument(')
    current_method=m.java_block(session.read_bytes(),'private boolean retryLoadingDocument(')
    same=m.java_block(session.read_bytes(),'private static boolean sameFrame(')
    src=projection.read_text();pos=src.rfind('}')
    src=src[:pos]+same+'\n static boolean same(PhoneObservation a,PhoneObservation b){return sameFrame(a,b);}\n'+src[pos:]
    need(src.count(current_method)==1,'one exact current retry body')
    old=src.replace(current_method,old_method).replace('WebCityObservationRetryProjection','LegacyCityObservationRetryProjection')
    call='retryLoadingDocument(first,last,frame,stable,bracket,(CityObservationRetry)token,deadline)'
    need(old.count(call)==1,'one explicit legacy wrapper adaptation')
    old=old.replace(call,'retryLoadingDocument(first,last,frame,stable,deadline)')
    current_java=out/'WebCityObservationRetryProjection.java';current_java.write_text(src)
    old_java=out/'LegacyCityObservationRetryProjection.java';old_java.write_text(old)
    test=root/'tests/web-flight/WebCityObservationFixtureHostTest.java'
    inputs=list(map(pin,[session,legacy,runner,projection,test,Path(__file__).resolve(),a.query_output/'RESULT.json',a.city_output/'RESULT.json',a.json_jar,fixture/'PROVENANCE.json']))
    report={'schema':'hepta.city-actual-fixture-host-result.v1','all_pass':False,'source_inputs':inputs,
        'actual_originals':provenance,'query40_prerequisite':pin(a.query_output/'RESULT.json'),'city25_prerequisite':pin(a.city_output/'RESULT.json'),
        'boundary':'Pure original DOM/AX metadata and actual dispatched outcome; label/receipt carriers and post-AX clock. No authenticated IPC or live native authority. No future stable frame claim.',
        'phone_operations':0,'business_verified':False,'commands':[],'generated':[pin(current_java),pin(old_java)],
        'extracted_blocks':[{'source':str(path),'signature':sig,'bytes':len(body.encode()),'sha256':hashlib.sha256(body.encode()).hexdigest()} for path,sig,body in [
            (session,'retryLoadingDocument',current_method),(legacy,'retryLoadingDocument',old_method),(session,'sameFrame',same)]]}
    def run(name,argv):
        p=subprocess.run(list(map(str,argv)),cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
        stdout=out/(name+'.stdout');stderr=out/(name+'.stderr');stdout.write_bytes(p.stdout);stderr.write_bytes(p.stderr)
        report['commands'].append({'name':name,'argv':list(map(str,argv)),'exit_code':p.returncode,'stdout':pin(stdout),'stderr':pin(stderr)})
        need(p.returncode==0,name+' failed')
    try:
        classes=out/'classes';empty=out/'empty-sourcepath';empty.mkdir()
        cp=str(a.query_output/'classes')+os.pathsep+str(a.json_jar)
        run('compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-proc:none','-implicit:none','-sourcepath',empty,'-cp',cp,'-d',classes,current_java,old_java,test])
        run('actual-fixture-cases',[a.java_home/'bin/java','-Xmx512m','-cp',str(classes)+os.pathsep+cp,'org.trillionnium.hepta.local.WebCityObservationFixtureHostTest',originals,out/'CASES.json'])
        report['cases']=json.loads((out/'CASES.json').read_bytes())
        report['all_pass']=report['cases']['all_pass'] is True
    except Exception as e:
        report['error']=type(e).__name__+': '+str(e)
    finally:
        report['inputs_unchanged']=all(pin(Path(x['path']))==x for x in inputs)
        report['all_pass']=report['all_pass'] and report['inputs_unchanged']
        result=out/'RESULT.json';result.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_pass':report['all_pass'],'error':report.get('error'),'cases':report.get('cases'),'result':pin(result)}))
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
