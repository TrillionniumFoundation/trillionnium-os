#!/usr/bin/env python3
"""Actual parser regression plus unchanged original Notes gate and semantic old-source control."""
import argparse,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    a=argparse.ArgumentParser()
    for n in ('source','baseline','java-home','output'): a.add_argument('--'+n,type=Path,required=True)
    q=a.parse_args();source=q.source.resolve(strict=True);base=q.baseline.resolve(strict=True);out=q.output.resolve()
    if out==source or source in out.parents: raise ValueError('outputs must remain outside source')
    out.mkdir(parents=True,exist_ok=False)
    here=source/'tests/notes-new-body'
    if Path(__file__).resolve().parent!=here: raise ValueError('runner source identity differs')
    old_test='tests/notes-owner-intent/NotesOwnerIntentHostTest.java'
    old_runner='tests/notes-owner-intent/run_host_tests.py'
    if sha(source/old_test)!='020426a66c6b8923254509bd8b8dc387022cedf17ae03a166727ead524ad7161': raise ValueError('original cases changed')
    if sha(source/old_runner)!='e24824e723ef6a9c15cf95287beec289a3a4707a6eef728658ed71922663873f': raise ValueError('original runner changed')
    relative='src/org/trillionnium/hepta/local/NotesOwnerIntent.java'
    if sha(base/relative)!='a4706c6c89f569e2530aa7a48160d36f34ddd73236c67701424897d288c3486c': raise ValueError('baseline parser differs')
    paths=[source/relative,source/old_test,source/old_runner,here/'NotesNewBodyHostTest.java',Path(__file__),base/relative]
    pins={str(p):sha(p) for p in paths};env=dict(os.environ)
    env['PATH']=str(q.java_home/'bin')+os.pathsep+env.get('PATH','')
    env['PYTHONDONTWRITEBYTECODE']='1'
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
    report={'schema':'hepta.notes-new-body-host.v1','passed':False,'phone_operations':0,'model_requests':0,'android_execution':False,'source_inputs':pins,'stages':[]}
    def run(name,args,expected=0):
        began=time.monotonic();r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,env=env)
        (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
        report['stages'].append({'name':name,'argv':args,'exit_code':r.returncode,'seconds':time.monotonic()-began,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()})
        if r.returncode!=expected:raise RuntimeError(name+' unexpected exit '+str(r.returncode))
        return r
    try:
        run('original-notes',[sys.executable,'-B',str(source/old_runner),'--source',str(source),'--output',str(out/'original'),'--release8'])
        original=json.loads((out/'original/RESULT.json').read_text())
        if not original['passed'] or not original['source_unchanged']:raise RuntimeError('original gate not verified')
        report['original_cases']=original['cases'];report['original_assertions']=original['assertions']
        report['original_result_sha256']=sha(out/'original/RESULT.json')
        classes=out/'classes';classes.mkdir();prior=out/'original/classes'
        javac=str(q.java_home/'bin/javac');java=str(q.java_home/'bin/java')
        run('compile-new',[javac,'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(prior),'-d',str(classes),str(here/'NotesNewBodyHostTest.java')])
        cp=str(classes)+os.pathsep+str(prior)
        actual=run('new-cases',[java,'-ea','-cp',cp,'org.trillionnium.hepta.local.NotesNewBodyHostTest'])
        m=re.fullmatch(rb'NEW_NOTE_BODY_CASES=(\d+)\nNEW_NOTE_BODY_ASSERTIONS=(\d+)\nNEW_NOTE_BODY_PASSED phone_operations=0 model_requests=0\n',actual.stdout)
        if not m:raise RuntimeError('new result summary missing')
        report['new_cases']=int(m[1]);report['new_assertions']=int(m[2])
        oldclasses=out/'baseline-classes';oldclasses.mkdir()
        run('compile-baseline',[javac,'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(prior),'-d',str(oldclasses),str(base/relative)])
        rejected=run('baseline-semantic-control',[java,'-ea','-cp',str(oldclasses)+os.pathsep+cp,'org.trillionnium.hepta.local.NotesNewBodyHostTest','--positive-only'],1)
        if b'full natural new-note phrase must be recognized' not in rejected.stderr:raise RuntimeError('baseline failure was not actual parser regression')
        report['baseline_semantic_rejection']=True
        report['source_unchanged']=all(sha(Path(p))==h for p,h in pins.items())
        report['passed']=report['source_unchanged']
    except Exception as error:report['error']=repr(error)
    (out/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('passed','phone_operations','model_requests')},ensure_ascii=False))
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
