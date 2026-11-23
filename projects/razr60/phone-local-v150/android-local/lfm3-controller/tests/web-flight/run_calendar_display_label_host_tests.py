#!/usr/bin/env python3
"""Portable host-only calendar gates. Optional private originals are never bundled."""
import argparse,hashlib,importlib.util,json,pathlib,subprocess,time
def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,why):
    if not ok:raise RuntimeError(why)
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for key in ('source','output','java-home','json-jar'):ap.add_argument('--'+key,type=pathlib.Path,required=True)
    ap.add_argument('--baseline-source',type=pathlib.Path)
    ap.add_argument('--actual-fixtures',type=pathlib.Path,help='Private JSON index of original capture/AX paths and SHA256')
    a=ap.parse_args();need(all(p.is_absolute() for p in [a.source,a.output,a.java_home,a.json_jar]),'absolute host paths required')
    need(not a.output.exists(),'new output required');a.output.mkdir(mode=0o700,parents=True)
    runner=a.source/'tests/web-flight/run_query_host_tests.py'
    spec=importlib.util.spec_from_file_location('retained_query_factories',runner);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    test=a.source/'tests/web-flight/WebCalendarDisplayLabelHostTest.java';test_raw=test.read_bytes();jar_raw=a.json_jar.read_bytes()
    result={'schema':'hepta.calendar-display-label-host-gates.v1','all_pass':False,'phone_actions':0,'live_binding_or_dispatch_tested':False,
            'flight_results_verified':False,'test_sha256':sha(test_raw),'runner_sha256':sha(pathlib.Path(__file__).read_bytes()),
            'fixture_runner_sha256':sha(runner.read_bytes()),'json_jar_sha256':sha(jar_raw),'steps':[]}
    original={test:test_raw,runner:runner.read_bytes(),a.json_jar:jar_raw}
    if a.actual_fixtures:
        raw=a.actual_fixtures.read_bytes();original[a.actual_fixtures]=raw
        for row in json.loads(raw)['cases']:
            for kind in ('raw','ax'):
                p=pathlib.Path(row[kind+'_path']);b=p.read_bytes();need(sha(b)==row[kind+'_sha256'],'private original SHA mismatch');original[p]=b
        result['private_fixture_index_sha256']=sha(raw)
    def command(name,argv,timeout=90):
        start=time.monotonic();p=subprocess.run([str(v) for v in argv],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
        (a.output/(name+'.stdout')).write_bytes(p.stdout);(a.output/(name+'.stderr')).write_bytes(p.stderr)
        result['steps'].append({'name':name,'exit_code':p.returncode,'seconds':round(time.monotonic()-start,6),'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
        return p
    def compile_tree(label,source):
        dest=a.output/label;classes=dest/'classes';classes.mkdir(parents=True)
        paths=[p for p in m.PURE_PATHS if p!='tests/web-flight/WebFlightQueryHostTest.java'];java=[];pins=[]
        for rel in paths:
            path=source/rel;b=path.read_bytes();original[path]=b;pins.append({'path':rel,'sha256':sha(b)});java.append(path)
        for fs in m.FACTORY_SPECS:
            if fs['name'] not in ('WebTaskCompositionHostTest','WebFlightEvidenceHostTest'):continue
            path=source/fs['path'];b=path.read_bytes();original[path]=b;generated,record=m.factory_projection(b,fs)
            out=dest/fs['generated']['path'];out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(generated);java.append(out)
            pins.append({'path':fs['path'],'sha256':sha(b),'projection_sha256':sha(generated),'synthetic_fixture_adapter':True})
        java.append(test);(dest/'INPUTS.json').write_text(json.dumps(pins,indent=2)+'\n')
        p=command(label+'-compile',[a.java_home/'bin/javac','-encoding','UTF-8','-source','8','-target','8','-cp',a.json_jar,'-d',classes,*java])
        need(p.returncode==0,label+' compilation failed; see retained stderr')
        return [a.java_home/'bin/java','-Xmx768m','-cp',str(classes)+':'+str(a.json_jar),'org.trillionnium.hepta.local.WebCalendarDisplayLabelHostTest']
    try:
        if a.baseline_source:
            before=compile_tree('baseline',a.baseline_source);red=command('baseline-red',before)
            need(red.returncode!=0 and b'priced calendar target must be admitted in its explicit month' in red.stderr,'baseline must fail at exact missing composite-label assertion')
            probe=before+['--baseline-probe']
            if a.actual_fixtures:probe+=['--actual-fixtures',a.actual_fixtures]
            p=command('baseline-probe',probe);need(p.returncode==0,'baseline refusal probe failed')
            result['baseline_red_expected']=True;result['baseline_probe']=json.loads(p.stdout)
        after=compile_tree('candidate',a.source);p=command('portable',after);need(p.returncode==0,'portable calendar gate failed')
        result['portable']=json.loads(p.stdout);need(result['portable'].get('all_pass') is True,'portable verdict missing')
        if a.actual_fixtures:
            p=command('with-private-originals',after+['--actual-fixtures',a.actual_fixtures]);need(p.returncode==0,'private replay failed')
            result['with_private_originals']=json.loads(p.stdout)
        need(all(p.read_bytes()==b for p,b in original.items()),'original input changed during tests')
        result['original_inputs_unchanged']=True;result['all_pass']=True
    finally:
        (a.output/'RESULT.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_pass':result['all_pass'],'synthetic_cases':result['portable']['synthetic_cases'],
            'actual_replays':result.get('with_private_originals',{}).get('actual_replays',0),'phone_actions':0}))
if __name__=='__main__':main()
