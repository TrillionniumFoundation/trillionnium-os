#!/usr/bin/env python3
"""Actual HA new producer/effect methods with real Session/Gate, explicit Android IO."""
import argparse,hashlib,importlib.util,json,os,subprocess,sys,time
from pathlib import Path

def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(p):
 p=Path(p).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def module(p,name):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def write(p,text):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
def main():
 ap=argparse.ArgumentParser()
 for arg in ('source','output','java-home','json-jar'):ap.add_argument('--'+arg,type=Path,required=True)
 args=ap.parse_args();source=args.source.resolve();out=args.output.resolve();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
 if out.exists() or source in out.parents:raise RuntimeError('fresh outside-source output required')
 out.mkdir(mode=0o700);sys.dont_write_bytecode=True
 test=source/'tests/native-search-producer';pkg=source/'src/org/trillionnium/hepta/local'
 query=module(source/'tests/web-flight/run_query_host_tests.py','producer_query')
 extractor=module(source/'tests/observation-diagnostics/run_host.py','producer_extract')
 body,section=extractor.body,extractor.section
 closure=module(source/'tests/native-search-planning/host_closure.py','producer_closure')
 paths,provenance=closure.prepare(source,out/'generated',[
  source/'tests/native-search-session/NativeSearchSessionHostTest.java',
  source/'tests/native-search-grammar/NativeSearchGrammarHostTest.java',
  source/'tests/native-search-planning/NativeSearchPlanningContractHostTest.java'])
 raw=(pkg/'HeptaAccessibilityService.java').read_text()
 parts={
 'outcome':body(raw,'    public static final class ActionOutcome {'),
 'graph_budget':body(raw,'    private interface GraphBudget {'),
 'stale':body(raw,'    private static final class StaleObservation extends IllegalStateException {'),
 'abandoned':body(raw,'    private static final class ObservationAbandoned extends IllegalStateException {'),
 'no_root':body(raw,'    private static final class NoActiveWindow extends IllegalStateException {'),
 'profile_violation':body(raw,'    private static final class ProfileOwnershipViolation extends IllegalStateException {'),
 'mode':body(raw,'    private static final class NativeAxMode {'),
 'node_ref':body(raw,'    private static final class NodeRef {'),
 'frozen_window':body(raw,'    private static final class FrozenObservationWindow {'),
 'close_graph':body(raw,'        void close(){for(NodeRef n:refs.values())n.node.recycle();refs.clear();}'),
 'observation':section(raw,'    /** A separate historical planning channel.','    /** Native text capture mode is bound once'),
 'action':section(raw,'    private volatile SearchActionWork activeSearchAction;','    private final class ActionWork {'),
 }
 signatures=[
 '    private synchronized boolean ownsBackground(', '    private synchronized boolean ownsAuthorization(',
 '    void requireTaskAuthorization(', '    private synchronized QualificationScopeConfig.Bound scopeFor(',
 '    private synchronized boolean ownsScope(', '    private static JSONObject callbackScopeEvidence(',
 '    private JSONObject callbackAuthorizationEvidence(', '    boolean actionWorkPending(){',
 '    boolean observationReadWorkPending(){', '    private static void checkReadBudget(',
 '    private static boolean hasAction(', '    private Map<String,Object> readNativeActionWindows(',
 '    private static void collectNativeActionNode(',
 '    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(AccessibilityNodeInfo node,String path,\n            String parentClass,PhoneObservation.Node retained,NodeRef reference){',
 '    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(AccessibilityNodeInfo node,String path,\n            String parentClass,PhoneObservation.Node retained,NodeRef reference,Graph rawOwner){',
 '    private static FrozenObservationWindow frozenObservationWindow(',
 '    private static boolean completeNativeObservationGraph(', '    private static void requireSameProfileOwner(',
 '    private static void requireSameProfileWindow(', '    private WindowOwnership readProfileWindow(',
 '    private ImeVisibility readImeVisibility(', '    private ObservedWindowMetadata readWindowMetadata(',
 '    private static String nodeSignature(', '    private static String baseNodeSignature(', '    private static String inputTextHash(',
 '    private static ObservedChildText.Result observedChildText(final AccessibilityNodeInfo root,final boolean refreshChildren,final GraphBudget budget){',
 ]
 methodparts={s:body(raw,s) for s in signatures};parts['methods']='\n'.join(methodparts.values())
 start='                        boolean currentLease=work.currentLease()&&lastActionExecution==work.state,stopped=cancel.isCancelled();'
 end='                        callback.onResult(delivered.withActionExecution(actionDiagnosticEvidence(work)));'
 if raw.count(start)!=1 or raw.count(end)!=1:raise RuntimeError('legacy callback anchors')
 parts['legacy_callback']=raw[raw.index(start):raw.index(end)+len(end)]
 parts['cases']=(test/'ProducerCases.fragment').read_text()
 template=(test/'SearchProducerHost.template').read_text()
 for key,value in parts.items():
  if template.count('{{'+key+'}}')!=1:raise RuntimeError('unique template slot '+key)
  template=template.replace('{{'+key+'}}',value)
 if '{{' in template:raise RuntimeError('remaining fixture slots')
 service=out/'generated/ports/org/trillionnium/hepta/local/HeptaAccessibilityService.java';service.write_text(template)
 config=out/'generated/ports/org/trillionnium/hepta/local/QualificationScopeConfig.java'
 c=config.read_text();q=(pkg/'QualificationScopeConfig.java').read_text()
 bound=body(q,'    static final class Bound {')
 c=c.replace('import java.util.*;','import java.util.*;import org.json.*;')
 if not c.endswith('}\n'):raise RuntimeError('config closing brace')
 c=c[:-2]+bound+'''\n    private static Object nullable(Object o){return o==null?JSONObject.NULL:o;}
    private static JSONObject pathDiagnostics(Context c,FilesRoot root){return new JSONObject();}
    private static String home(Context c){throw new AssertionError("restricted launcher IO outside this gate");}
}\n''';config.write_text(c)
 ports=out/'generated/ports'
 write(ports/'android/os/Looper.java','package android.os;public final class Looper{public static boolean main=true;private static final Looper MAIN=new Looper(),WORKER=new Looper();public static Looper myLooper(){return main?MAIN:WORKER;}public static Looper getMainLooper(){return MAIN;}}\n')
 keyguard=ports/'android/app/KeyguardManager.java';s=keyguard.read_text();s=s.replace('public boolean locked;', 'public boolean locked;public static Runnable beforeCheck;').replace('return locked;', 'if(beforeCheck!=null)beforeCheck.run();return locked;');keyguard.write_text(s)
 osp=ports/'android/system/Os.java';s=osp.read_text();s=s.replace(' public static String failFsyncPath;', ' public static String failFsyncPath;public static Runnable afterRead,beforeWrite;public static java.util.function.Consumer<String> afterFsync;')
 s=s.replace('return count<0?0:count;', 'if(afterRead!=null){Runnable hook=afterRead;afterRead=null;hook.run();}return count<0?0:count;')
 s=s.replace('OPEN.get(fd).file.write(b,p,n);return n;', 'if(beforeWrite!=null)beforeWrite.run();OPEN.get(fd).file.write(b,p,n);return n;');osp.write_text(s)
 s=s.replace('if(fd.valid())fd.sync();', 'if(fd.valid())fd.sync();if(afterFsync!=null)afterFsync.accept(path);');osp.write_text(s)
 additional=[]
 for path,text in {
  'android/util/DisplayMetrics.java':'package android.util;public final class DisplayMetrics{public int widthPixels,heightPixels;}\n',
  'android/util/Log.java':'package android.util;public final class Log{public static int i(String tag,String text){return 0;}}\n',
 }.items():
  p=ports/path;write(p,text);additional.append(p)
 paths+=additional+[pkg/'PersistentActionPolicy.java',pkg/'ObservationStabilityGate.java']
 paths=list(dict.fromkeys(paths));inputs=[meta(p) for p in paths]
 tools=[meta(p) for p in (jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar)]
 if tools[-1]['sha256']!=closure.JSON_SHA:raise RuntimeError('actual JSON jar pin')
 report={'schema':'hepta.native-search-actual-producer-host.v1','all_pass':False,'phone_operations':0,'android_execution':False,'business_verified':False,'stages':[],
 'source':str(source),'actual_service':meta(pkg/'HeptaAccessibilityService.java'),'compile_inputs_before':inputs,'tools_before':tools,
 'source_inputs':provenance['production_inputs']+[meta(p) for p in test.iterdir() if p.is_file()],
 'boundary':'Real full Session/Gate/Offer/Attempt/Role/Planning plus verbatim HA new producer, typed effect, ownership guards, raw census, original callback and actual scope Bound. Explicit synthetic Android nodes/windows/socket/clock/queues. No permissive Offer or action guard surrogate.'}
 extraction={'parts':{k:{'bytes':len(v.encode()),'sha256':sha(v.encode())} for k,v in parts.items() if k!='cases'},'actual_methods':{k:sha(v.encode()) for k,v in methodparts.items()},'actual_scope_bound_sha256':sha(bound.encode()),'shared_closure':provenance}
 write(out/'EXTRACTION.json',json.dumps(extraction,ensure_ascii=False,indent=2)+'\n')
 env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1'
 for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
 classes=out/'classes';classes.mkdir()
 def run(name,argv):
  start=time.monotonic()
  with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
   result=subprocess.run(list(map(str,argv)),stdout=stdout,stderr=stderr,env=env,cwd=out,timeout=180)
  stage={'name':name,'argv':list(map(str,argv)),'exit_code':result.returncode,'seconds':time.monotonic()-start,'stdout':meta(out/(name+'.stdout')),'stderr':meta(out/(name+'.stderr'))};report['stages'].append(stage);return result.returncode
 try:
  argsfile=out/'javac.args';argsfile.write_text('\n'.join('"'+str(p)+'"' for p in paths)+'\n')
  if run('javac',[jdk/'bin/javac','-J-Xmx768m','--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',jar,'-d',classes,'@'+str(argsfile)])==0:
   if run('producer-cases',[jdk/'bin/java','-ea','-cp',str(classes)+':'+str(jar),'org.trillionnium.hepta.local.HeptaAccessibilityService',out/'CASES.json',out/'private-fixture'])==0:
    report['case_result']=json.loads((out/'CASES.json').read_text());report['all_pass']=report['case_result']['all_pass']
 finally:
  report['compile_inputs_after']=[meta(p) for p in paths];report['tools_after']=[meta(p['path']) for p in tools]
  report['inputs_unchanged']=report['compile_inputs_before']==report['compile_inputs_after'];report['tools_unchanged']=report['tools_before']==report['tools_after']
  report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged']
  write(out/'RESULT.json',json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'all_pass':report['all_pass'],'stages':[{k:s[k] for k in ('name','exit_code','seconds')} for s in report['stages']],'result':meta(out/'RESULT.json')}))
 return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
