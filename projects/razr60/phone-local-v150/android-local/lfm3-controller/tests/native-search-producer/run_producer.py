#!/usr/bin/env python3
"""Actual HA new producer/effect methods with real Session/Gate, explicit Android IO."""
import argparse,hashlib,importlib.util,json,os,re,subprocess,sys,time
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
 ap.add_argument('--loading-original',type=Path)
 ap.add_argument('--after-target-original',type=Path,action='append',default=[])
 args=ap.parse_args();source=args.source.resolve();out=args.output.resolve();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
 if out.exists() or source in out.parents:raise RuntimeError('fresh outside-source output required')
 if len(args.after_target_original) not in (0,2):raise RuntimeError('exactly two complete after-target action originals required')
 after_target_before=[meta(p) for p in args.after_target_original]
 if after_target_before and [(x['bytes'],x['sha256']) for x in after_target_before]!=[(271012,'9bd6ffbb6b0b154fc002ea189db778bf982b673bb3835dd8d2485a318eb416bc'),(271493,'6222aa65845d2040fbf51769f3e794c811544f846572f55d8e743f4a301dc603')]:raise RuntimeError('exact archived c78b whole action bytes required')
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
 read_graph=body(raw,'    private Graph readGraph(GraphBudget budget,BackgroundSession background){')
 child_guard=[line.strip() for line in read_graph.splitlines() if line.strip().startswith('if(background!=null&&node!=root&&!node.refresh())')]
 if len(child_guard)!=1:raise RuntimeError('one actual descendant refresh failure branch required')
 cleanup='catch(RuntimeException e){graph.close();throw e;}'
 if read_graph.count(cleanup)!=1 or read_graph.count('finally{while(!queue.isEmpty())queue.removeFirst().recycle();}')!=1:
  raise RuntimeError('actual incomplete graph and queue cleanup must remain')
 parts['background_child_guard']=child_guard[0];parts['read_graph_failure_cleanup']=cleanup
 signatures=[
  '    private void clearSnapshot(', '    private synchronized BackgroundSession backgroundFor(', '    void verifyBackgroundRemote(',
  '    private synchronized boolean ownsBackground(', '    private synchronized boolean ownsAuthorization(',
 '    void requireTaskAuthorization(', '    private synchronized QualificationScopeConfig.Bound scopeFor(',
 '    private synchronized boolean ownsScope(', '    private static JSONObject callbackScopeEvidence(',
 '    private JSONObject callbackAuthorizationEvidence(', '    boolean actionWorkPending(){', '    JSONObject actionExecutionEvidence(',
 '    boolean observationReadWorkPending(){', '    void retireActionWork(', '    private static void checkReadBudget(',
 '    private static boolean hasAction(', '    private Map<String,Object> readNativeActionWindows(',
 '    private static void collectNativeActionNode(',
 '    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(AccessibilityNodeInfo node,String path,\n            String parentClass,PhoneObservation.Node retained,NodeRef reference){',
 '    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(AccessibilityNodeInfo node,String path,\n            String parentClass,PhoneObservation.Node retained,NodeRef reference,Graph rawOwner){',
 '    private static FrozenObservationWindow frozenObservationWindow(',
 '    private static boolean completeNativeObservationGraph(', '    private static void requireSameProfileOwner(',
 '    private static void requireSameProfileWindow(', '    private WindowOwnership readProfileWindow(',
 '    private ImeVisibility readImeVisibility(', '    private ObservedWindowMetadata readWindowMetadata(',
 '    static String limited(',
 '    private static String nodeSignature(', '    private static String baseNodeSignature(', '    private static String inputTextHash(',
 '    private static ObservedChildText.Result observedChildText(final AccessibilityNodeInfo root,final boolean refreshChildren,final GraphBudget budget){',
 ]
 methodparts={s:body(raw,s) for s in signatures};parts['methods']='\n'.join(methodparts.values())
 start='                        boolean currentLease=work.currentLease()&&lastActionExecution==work.state,stopped=cancel.isCancelled();'
 end='                        callback.onResult(delivered.withActionExecution(actionDiagnosticEvidence(work)));'
 if raw.count(start)!=1 or raw.count(end)!=1:raise RuntimeError('legacy callback anchors')
 parts['legacy_callback']=raw[raw.index(start):raw.index(end)+len(end)]
 parts['cases']=(test/'ProducerCases.fragment').read_text()
 if parts['cases'].count('        finalCensusRecoveryCases();')!=1:raise RuntimeError('one original producer case registration anchor')
 parts['cases']=parts['cases'].replace('        finalCensusRecoveryCases();','        finalCensusRecoveryCases();\n        modalPreludeCases();\n        incompleteCensusCases();\n        publicationReplacementCases();\n        afterTargetReplacementCases();\n        postBackClientCacheCases();',1)+(test/'ModalPreludeCases.fragment').read_text()+(test/'IncompleteCensusCases.fragment').read_text()+(test/'PublicationReplacementCases.fragment').read_text()+(test/'AfterTargetCensusCases.fragment').read_text()+(test/'PostBackClientCacheCases.fragment').read_text()
 cache_report_anchor='        report.put("after_target_census_evidence",afterTargetEvidence);'
 if parts['cases'].count(cache_report_anchor)!=1:raise RuntimeError('one original evidence report anchor')
 parts['cases']=parts['cases'].replace(cache_report_anchor,cache_report_anchor+'\n        report.put("post_back_cache_event_evidence",postBackCacheEventEvidence);',1)
 parts['loading_cases']=(test/'LoadingRetryCases.fragment').read_text()+(test/'ProgressHomeCases.fragment').read_text()
 parts['successor_cases']=(test/'NoEffectSuccessorCases.fragment').read_text()+(test/'FullPageSwapCases.fragment').read_text()+(test/'SearchIconCases.fragment').read_text()+(test/'NavigationWindowCases.fragment').read_text()
 parts['sampling_cases']=(test/'SamplingExhaustionCases.fragment').read_text()
 template=(test/'SearchProducerHost.template').read_text()
 for key,value in parts.items():
  if template.count('{{'+key+'}}')!=1:raise RuntimeError('unique template slot '+key)
  template=template.replace('{{'+key+'}}',value)
 if '{{' in template:raise RuntimeError('remaining fixture slots')
 service=out/'generated/ports/org/trillionnium/hepta/local/HeptaAccessibilityService.java';service.write_text(template)
 # The actual search producer overwrites the shared Service carrier. Restore only
 # the same unconstructible calendar types; every extracted search method is untouched.
 calendar_paths,calendar_boundary=closure.calendar_legacy_closure(source,service)
 paths+=calendar_paths
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
 clock=ports/'android/os/SystemClock.java';clock_text=clock.read_text()
 old_clock='public static long now=1000000;public static long elapsedRealtime(){return now;}'
 new_clock='public static long now=1000000;public static volatile Runnable beforeRead;public static long elapsedRealtime(){if(beforeRead!=null)beforeRead.run();return now;}'
 if clock_text.count(old_clock)!=1:raise RuntimeError('one exact original synthetic clock endpoint required')
 clock.write_text(clock_text.replace(old_clock,new_clock))

 write(ports/'android/os/Looper.java','package android.os;public final class Looper{public static boolean main=true;private static final Looper MAIN=new Looper(),WORKER=new Looper();public static Looper myLooper(){return main?MAIN:WORKER;}public static Looper getMainLooper(){return MAIN;}}\n')
 keyguard=ports/'android/app/KeyguardManager.java';s=keyguard.read_text();s=s.replace('public boolean locked;', 'public boolean locked;public static Runnable beforeCheck;').replace('return locked;', 'if(beforeCheck!=null)beforeCheck.run();return locked;');keyguard.write_text(s)
 osp=ports/'android/system/Os.java';s=osp.read_text();s=s.replace(' public static String failFsyncPath;', ' public static String failFsyncPath;public static Runnable afterRead,beforeWrite;public static java.util.function.Consumer<String> afterFsync;')
 s=s.replace('return count<0?0:count;', 'if(afterRead!=null){Runnable hook=afterRead;afterRead=null;hook.run();}return count<0?0:count;')
 s=s.replace('OPEN.get(fd).file.write(b,p,n);return n;', 'if(beforeWrite!=null)beforeWrite.run();OPEN.get(fd).file.write(b,p,n);return n;');osp.write_text(s)
 s=s.replace('if(fd.valid())fd.sync();', 'if(fd.valid())fd.sync();if(afterFsync!=null)afterFsync.accept(path);');osp.write_text(s)
 # Dedicated, normally-null IO endpoint for the actual LTC record's final chmod.
 # It does not rewrite record(), its FileOutputStream write or FD.sync.
 chmod_start=' public static void chmod(String s,int mode)throws Exception{'
 if s.count(chmod_start)!=1:raise RuntimeError('one actual host chmod endpoint required')
 s=s.replace('public final class Os {','public final class Os {\n public static volatile java.util.function.Consumer<String> beforeChmod;')
 s=s.replace(chmod_start,chmod_start+'if(beforeChmod!=null)beforeChmod.accept(s);');osp.write_text(s)
 additional=[source/'tests/qualification-scope/fixtures/android/os/Build.java']
 for path,text in {
  'android/util/DisplayMetrics.java':'package android.util;public final class DisplayMetrics{public int widthPixels,heightPixels;}\n',
  'android/util/Log.java':'package android.util;public final class Log{public static int i(String tag,String text){return 0;}}\n',
 }.items():
  p=ports/path;write(p,text);additional.append(p)
 controller_raw=(pkg/'LocalTaskController.java').read_text()
 controller_signatures=['    private static final class NativeSearchLoadingReadFailure extends IllegalStateException {',
  '    private static final class NativeSearchSamplingReadFailure extends IllegalStateException {',
  '    private static final class NativeSearchImageModalReadFailure extends IllegalStateException {',
  '    private void requireInitialSearchPlanningRead(', '    private NativeSearchPlanning awaitNativeSearchPlanning(',
  '    private NativeSearchPlanning awaitNativeSearchPlanningOnce(', '    private void checkActive(',
  '    private static final class Stopped extends Exception {','    private static void record(']
 controller_parts={key:body(controller_raw,key) for key in controller_signatures}
 controller_template=(test/'LoadingControllerHost.template').read_text()
 if controller_template.count('{{actual_controller_methods}}')!=1:raise RuntimeError('exact controller method slot')
 controller_source=ports/'org/trillionnium/hepta/local/NativeSearchLoadingControllerHost.java'
 write(controller_source,controller_template.replace('{{actual_controller_methods}}','\n'.join(controller_parts.values())))
 additional.append(controller_source)
 successor_signatures=controller_signatures+[
  '    private static final class NativeSearchChainResult {', '    private void runNativeSearchChain(',
  '    private static final class NativeSearchActionReply {',
  '    private static final class NativeSearchNoEffectReplanRequired extends IllegalStateException {',
  '    private NativeSearchPlanning awaitNativeSearchPlanningAfterNoEffect(',
  '    private PhoneObservation runNativeSearchPrelude(',
  '    private NativeSearchActionReply awaitNativeOpenSearch(', '    private static boolean retiredSearchDrain(', '    private static boolean unclaimedSearchAtDisposal(',
  '    private static final class ModelAnswer {',
  '    private static final class CleanupUnknown extends Exception {']
 successor_parts={key:body(controller_raw,key) for key in successor_signatures}
 branch_start='            if(activeNativeSearch!=null){\n                final NativeSearchSession search=activeNativeSearch;'
 branch_end='else observation=awaitInitialNativeObservation(taskId,evidence,authorization,deadline);'
 if controller_raw.count(branch_start)!=1 or controller_raw.count(branch_end)!=1:raise RuntimeError('unique actual complete search branch required')
 start_at=controller_raw.index(branch_start);end_at=controller_raw.index(branch_end,start_at)
 successor_branch=controller_raw[start_at:end_at]
 model_method=body(controller_raw,'    private ModelAnswer awaitModel(')
 model_start='        final boolean searchProtocol=';model_end='        final LocalRuntimeConfig runtime=inference.configuration();'
 if model_method.count(model_start)!=1 or model_method.count(model_end)!=1:raise RuntimeError('actual model precheck anchors')
 model_precheck=model_method[model_method.index(model_start):model_method.index(model_end)]
 constants=[]
 for name in ('NATIVE_SEARCH_SYSTEM','MODEL_TIMEOUT_MS','MAX_STEPS'):
  found=re.findall(r'    private static final [^\n]*'+name+r'.*?;\n',controller_raw,re.S)
  if len(found)!=1:raise RuntimeError('exact controller constant '+name)
  constants.append(found[0])
 successor_template=(test/'NoEffectControllerHost.template').read_text()
 for key,value in {'actual_constants':'\n'.join(constants),'actual_search_branch':successor_branch,
    'actual_model_precheck':model_precheck,'actual_controller_methods':'\n'.join(successor_parts.values())}.items():
  if successor_template.count('{{'+key+'}}')!=1:raise RuntimeError('exact successor controller slot '+key)
  successor_template=successor_template.replace('{{'+key+'}}',value)
 successor_source=ports/'org/trillionnium/hepta/local/NativeSearchNoEffectControllerHost.java'
 write(successor_source,successor_template);additional.append(successor_source)

 paths+=additional+[pkg/'PersistentActionPolicy.java',pkg/'ObservationStabilityGate.java']
 paths=list(dict.fromkeys(paths));inputs=[meta(p) for p in paths]
 tools=[meta(p) for p in (jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar)]
 if tools[-1]['sha256']!=closure.JSON_SHA:raise RuntimeError('actual JSON jar pin')
 report={'schema':'hepta.native-search-actual-producer-host.v1','all_pass':False,'phone_operations':0,'android_execution':False,'business_verified':False,'stages':[],
 'source':str(source),'actual_service':meta(pkg/'HeptaAccessibilityService.java'),'compile_inputs_before':inputs,'tools_before':tools,
 'source_inputs':provenance['production_inputs']+[meta(pkg/'LocalTaskController.java')]+[meta(p) for p in test.iterdir() if p.is_file()],
 'boundary':'Real full Session/Gate/Offer/Attempt/Role/Planning plus verbatim HA new producer, typed effect, ownership guards, raw census, original callback and actual scope Bound. Explicit synthetic Android nodes/windows/socket/clock/queues. No permissive Offer or action guard surrogate.'}
 extraction={'parts':{k:{'bytes':len(v.encode()),'sha256':sha(v.encode())} for k,v in parts.items() if k!='cases'},'actual_methods':{k:sha(v.encode()) for k,v in methodparts.items()},'actual_scope_bound_sha256':sha(bound.encode()),'read_graph_failure_source_sha256':sha(read_graph.encode()),'shared_closure':provenance}
 extraction['calendar_legacy_boundary']=calendar_boundary
 extraction['actual_controller_methods']={key:sha(value.encode()) for key,value in controller_parts.items()}
 extraction['actual_successor_controller_methods']={key:sha(value.encode()) for key,value in successor_parts.items()}
 extraction['actual_successor_controller_search_branch_sha256']=sha(successor_branch.encode())
 extraction['actual_successor_controller_model_precheck_sha256']=sha(model_precheck.encode())
 extraction['synthetic_controller_endpoints']=['model output and latency','token estimate metadata','post-effect old AX callback using real provider Frame']
 modal_fixture=source/'tests/native-search-modal/recorded-5b8-modal-censuses.json'
 report['modal_fixture_before']=meta(modal_fixture)
 original_before=meta(args.loading_original) if args.loading_original else None
 report['external_after_target_originals_before']=after_target_before
 report['external_after_target_replay_enabled']=bool(after_target_before)
 report['external_loading_original']=original_before
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
   if run('producer-cases',[jdk/'bin/java','-ea','-Dhepta.test.imageModalCensuses='+str(modal_fixture),'-Dhepta.test.fullPageCensuses='+str(test/'0b742-execution-censuses.json'),'-Dhepta.test.progressHome='+str(test/'dcc738-progress-censuses.json'),'-Dhepta.test.retiredSearch='+str(test/'99c24-retired-search.json'),'-Dhepta.test.retiredNoInput='+str(test/'92dc-retired-without-input.json')]+['-Dhepta.test.afterTargetOriginal'+str(i+1)+'='+str(p.resolve()) for i,p in enumerate(args.after_target_original)]+['-cp',str(classes)+':'+str(jar),'org.trillionnium.hepta.local.HeptaAccessibilityService',out/'CASES.json',out/'private-fixture']+([args.loading_original.resolve()] if args.loading_original else []))==0:
    report['case_result']=json.loads((out/'CASES.json').read_text());report['all_pass']=report['case_result']['all_pass']
    expected=json.loads((test/'AfterTargetExpectedCases.json').read_text())
    names=[r['name'] for r in report['case_result']['results']]
    required=expected['synthetic_actual_call_path']+(expected['archived_pair_optional_external'] if after_target_before else [])
    observed=[n for n in names if n.startswith('after_target_')]
    report['after_target_expected_cases']=required;report['after_target_observed_cases']=observed
    report['after_target_exact_cases']=len(names)==len(set(names)) and len(observed)==len(required) and set(observed)==set(required)
    report['all_pass']=report['all_pass'] and report['after_target_exact_cases']
    cache_expected=json.loads((test/'PostBackClientCacheExpectedCases.json').read_text())
    cache_observed=[n for n in names if n.startswith('post_back_cache_')]
    report['post_back_cache_expected_cases']=cache_expected
    report['post_back_cache_observed_cases']=cache_observed
    report['post_back_cache_exact_cases']=len(names)==len(set(names)) and len(cache_observed)==len(cache_expected) and set(cache_observed)==set(cache_expected)
    report['all_pass']=report['all_pass'] and report['post_back_cache_exact_cases']
 finally:
  report['compile_inputs_after']=[meta(p) for p in paths];report['tools_after']=[meta(p['path']) for p in tools]
  report['inputs_unchanged']=report['compile_inputs_before']==report['compile_inputs_after'];report['tools_unchanged']=report['tools_before']==report['tools_after']
  report['external_original_unchanged']=original_before is None or original_before==meta(args.loading_original)
  report['external_after_target_originals_after']=[meta(p) for p in args.after_target_original]
  report['external_after_target_originals_unchanged']=after_target_before==report['external_after_target_originals_after']
  report['modal_fixture_after']=meta(modal_fixture);report['modal_fixture_unchanged']=report['modal_fixture_before']==report['modal_fixture_after']
  report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged'] and report['external_original_unchanged'] and report['modal_fixture_unchanged'] and report['external_after_target_originals_unchanged']
  write(out/'RESULT.json',json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'all_pass':report['all_pass'],'stages':[{k:s[k] for k in ('name','exit_code','seconds')} for s in report['stages']],'result':meta(out/'RESULT.json')}))
 return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
