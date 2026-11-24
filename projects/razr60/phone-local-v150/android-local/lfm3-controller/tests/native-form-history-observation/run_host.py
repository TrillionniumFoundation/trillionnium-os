#!/usr/bin/env python3
"""Actual form-history AX producer with explicit host IO and replayed complete node values.
No phone observation, action, permission, SDK, model, or business completion is claimed."""
import argparse,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
PKG=Path('src/org/trillionnium/hepta/local')
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def generate(source,out,h,snap,ax):
 meta=ax.generate(source,out,h,snap);path=out/'ObserverPipelineHost.java';s=path.read_text()
 service=(source/PKG/'HeptaAccessibilityService.java').read_text()
 evidence=(source/PKG/'NativeAppEvidence.java').read_text()
 same=h.body(service,'    private static void requireSameProfileOwner(WindowOwnership original,WindowOwnership actual){')
 profile=h.body(evidence,'    static boolean sameProfileOwner(WindowOwnership a,WindowOwnership b){')
 target=h.body(evidence,'    static void requireProfileTarget(ProfileTarget expected,WindowOwnership actual){')
 s=ax.once(s,h.body(s,'    static void requireSameProfileOwner(WindowOwnership before,WindowOwnership after){'),same)
 s=ax.once(s,h.body(s,'        static void requireProfileTarget(Object expected,WindowOwnership actual){'),target+'\n'+profile)
 exception=h.body(service,'    private static final class ProfileOwnershipViolation extends IllegalStateException {')
 s=ax.once(s,'    static final class SystemClock {',exception+'\n    static final class SystemClock {')
 s=ax.once(s,'            if(profile!=null)throw new AssertionError("legacy observer cannot publish profile authority");',
  '''            // Value-only host DTO: no Android or permission is created here. Actual Phone is tested separately.
            if(profile!=null){NativeAppEvidence.requireProfileTarget(live.taskBackground.profileTarget(),profile);
                profile.requireMatches(live.taskBackground.profileTarget(),generation,live.taskBackground.displayId(),window,profile.taskId,captured);}''')
 s=ax.once(s,h.body(s,'    public static void main(String[] args)throws Exception{'),(HERE/'HistoryPipelineCases.fragment').read_text())
 path.write_text(s,encoding="utf-8") # Replace only this new output directory generated carrier.
 return {'schema':'hepta.native-form-history-extraction.v1','parent':meta,
  'actual_profile_target_and_owner_predicates':True,'full_raw_node_values_replayed_without_change':True,
  'boundary':'Synthetic host profile, clocks, Android graph/window IO, and lifecycle carriers. Verbatim actual AX producer and real canonical receipt helpers. Actual Phone/Frame/Session consumers are separately qualified, not simulated as permissions here.'}
def main():
 ap=argparse.ArgumentParser()
 for n in ['source','output','java-home','json-jar','census-input']:ap.add_argument('--'+n,type=Path,required=True)
 a=ap.parse_args();source=a.source.resolve();out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
 h=load(source/'tests/observation-diagnostics/run_host.py','history_h')
 snap=load(source/'tests/native-observation-snapshot/run_host.py','history_snap')
 ax=load(source/'tests/native-ax-observation/run_host.py','history_ax')
 java=a.java_home/'bin/java';javac=a.java_home/'bin/javac';jar=a.json_jar.resolve()
 if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('JSON pin')
 raw=a.census_input.resolve()
 if raw.stat().st_size!=562920 or h.sha(raw.read_bytes())!='ea77dee1c7f044fac8014d101922c10ab8035c0d12a2335b8d207f817328924d':raise RuntimeError('complete original A/C raw pin')
 deps_png=h.png_sources(source)
 deps=[source/PKG/n for n in snap.JAVA]+[source/PKG/n for n in ['NativeCtripFormObservation.java','NativeActionSnapshotCheck.java','ObservedTargetLabels.java']]+deps_png
 profiles=[source/'src/org/trillionnium/hepta/background'/(n+'.java') for n in ['ProfileIdentity','ProfileTarget','WindowOwnership']]
 rect=source/'tests/qualification-scope/fixtures/android/graphics/Rect.java'
 fixtures=[source/'tests/native-observation-snapshot'/n for n in ['SnapshotChecks.java','ObservationEvidenceHost.java']]+[source/'tests/native-ax-observation/ActualAxPhoneChecks.java']
 inputs=deps+[source/PKG/'NativeCtripFlightPage.java',source/PKG/'NativeAppGoal.java']+profiles+[rect,*fixtures,HERE/'run_host.py',HERE/'HistoryPipelineCases.fragment',source/'tests/native-ax-observation/run_host.py',source/'tests/native-ax-observation/AxPipelineCases.fragment',source/'tests/native-observation-snapshot/run_host.py',source/'tests/native-observation-snapshot/SnapshotPipelineCases.fragment',source/'tests/observation-pipeline/ObserverPipelineHost.template',source/'tests/observation-diagnostics/run_host.py',raw]
 tools=[java,javac,a.java_home/'lib/modules',a.java_home/'lib/ct.sym',jar]
 before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
 result={'schema':'hepta.native-form-history-host.v1','all_pass':False,'stages':[],'input_before':before,'tools_before':tool_before,
  'phone_execution':False,'android_execution':False,'sdk_loaded':False,'model_executed':False,'business_completion_verified':False,
  'host_fixture_identity_and_clock':True,'raw_actual_complete_node_values_only':True,'action_freshness_relaxed':False,'deadline_expanded':False}
 try:
  gen=out/'generated';gen.mkdir();h.save(out/'EXTRACTION.json',generate(source,gen,h,snap,ax));classes=out/'classes';classes.mkdir()
  sources=[p for p in deps if p.name not in ['HeptaAccessibilityService.java','LocalTaskController.java','NativeAppEvidence.java']]+profiles+fixtures+[rect,gen/'ObserverPipelineHost.java']
  result['stages'].append(h.stage('compile',[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources)),out))
  if result['stages'][-1]['exit_code']!=0:raise RuntimeError('actual history extraction compile failed')
  result['stages'].append(h.stage('cases',[str(java),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ObserverPipelineHost',str(out/'CASES.json'),str(raw)],out))
  if (out/'CASES.json').exists():result['cases']=json.loads((out/'CASES.json').read_text())
  if result['stages'][-1]['exit_code']!=0:raise RuntimeError('actual history producer cases failed')
  cases=result['cases']
  if cases['all_pass'] is not True or len(cases['case_names'])!=cases['cases'] or len(set(cases['case_names']))!=cases['cases']:raise RuntimeError('history case accounting')
  result['all_pass']=True
 except Exception as e:result['error']={'type':type(e).__name__,'message':str(e)}
 finally:
  result['input_after']=[h.meta(p) for p in inputs];result['tools_after']=[h.meta(p) for p in tools]
  result['inputs_unchanged']=before==result['input_after'];result['tools_unchanged']=tool_before==result['tools_after']
  result['all_pass']=result['all_pass'] and result['inputs_unchanged'] and result['tools_unchanged'];h.save(out/'RESULT.json',result)
 print(json.dumps({'all_pass':result['all_pass'],'error':result.get('error'),'cases':result.get('cases',{}).get('cases'),'result':h.meta(out/'RESULT.json')}))
 return 0 if result['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
