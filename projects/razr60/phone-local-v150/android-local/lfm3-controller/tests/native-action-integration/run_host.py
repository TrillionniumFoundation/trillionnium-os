#!/usr/bin/env python3
"""Actual Session and verbatim Service bridge methods with explicit host IO.

One compiler invocation, retained pure matrix, then actual integration cases.
Android APIs, traversal, clock, installed app and effects remain host endpoints;
no phone, model, business, pixel or platform-dispatch success is claimed.
"""
import argparse, hashlib, importlib.util, json, os, subprocess, sys, time
from pathlib import Path

PKG=Path('src/org/trillionnium/hepta/local')
TEST=Path('tests/native-action-integration')
JSON_SHA='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
METHODS={
 'snapshot_node':'    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(AccessibilityNodeInfo node,String path,\n            String parentClass,PhoneObservation.Node retained,NodeRef reference){',
 'snapshot_node_raw':'    private static NativeActionSnapshotCheck.Node snapshotNativeActionNode(AccessibilityNodeInfo node,String path,\n            String parentClass,PhoneObservation.Node retained,NodeRef reference,Graph rawOwner){',
 'windows':'    private Map<String,Object> readNativeActionWindows(',
 'begin_census':'    private void beginNativeActionCensus(',
 'collect_node':'    private static void collectNativeActionNode(',
 'finish_census':'    private void finishNativeActionCensus(',
 'guard':'    private void requireNativeActionGuard(',
 'snapshot':'    private static NativeActionSnapshotCheck.Snapshot nativeActionSnapshot(',
 'search_entry_guard':'    private static boolean nativeSearchEntryGuard(',
 'flight_open_guard':'    private static boolean nativeFlightOpenGuard(',
 'search_entry_defer':'    private boolean deferNativeSearchEntrySignature(',
 'background_precheck':'    private void backgroundBeforeDispatch(',
 'compare':'    private Map<String,Object> compareNativeAction(',
 'final_check':'    private void finalNativeActionCheck(',
 'live_chain':'    private void refreshNativeActionTargetChain(',
 'validate':'    private String validate(',
 'graph_for_action':'    private Graph graphForAction(',
 'background_lock':'    private boolean locked(BackgroundSession background)',
 'action_check':'    private static void actionCheck(',
 'action_phase':'    private static void actionPhase(',
 'action_cancellation':'    private Cancellation actionCancellation(',
 'profile_violation':'    private static final class ProfileOwnershipViolation extends IllegalStateException {',
 'profile_owner':'    private static void requireSameProfileOwner(',
 'profile_window':'    private static void requireSameProfileWindow(',
 'profile_historical':'    private static void requireHistoricalProfileWindow(',
 'profile_before_effect':'    private void requireLiveProfileBeforeEffect(',
 'enter_effect':'    private void enterActionEffect(',
 'effect_returned':'    private static void actionEffectReturned(',
 'refresh':'    private boolean refreshActionNode(',
 'base_signature':'    private static String baseNodeSignature(',
 'node_signature':'    private static String nodeSignature(',
 'observed_child_text':'    private static ObservedChildText.Result observedChildText(final AccessibilityNodeInfo root,final boolean refreshChildren,final GraphBudget budget){',
 'input_hash':'    private static String inputTextHash('}

EXPECTED_EQUAL_OPEN_CASES=['equal_tree_OPEN_runs_final_complete_census_and_one_claim_before_effect', 'equal_tree_OPEN_closed_guard_cannot_enter_effect', 'equal_tree_OPEN_preclaimed_guard_cannot_enter_effect', 'equal_tree_OPEN_rechecks_installed_uid_and_apk', 'equal_tree_OPEN_rejects_same_value_selection_replacement', 'equal_tree_OPEN_preserves_original_deadline_and_cancel', 'equal_tree_OPEN_rejects_missing_final_complete_census', 'equal_tree_OPEN_final_read_cannot_replace_original_live_NodeRef', 'equal_tree_OPEN_last_target_geometry_change_is_refused']

def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,why):
    if not ok:raise RuntimeError(why)
def meta(path):
    path=Path(path).absolute();raw=path.read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw),'mode':path.stat().st_mode&0o777}
def write(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    if isinstance(raw,str):raw=raw.encode('utf-8')
    with path.open('xb') as stream:stream.write(raw)
def save(path,value):write(path,json.dumps(value,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def inventory(source):
    rows={}
    for path in sorted(source.rglob('*')):
        need(not path.is_symlink(),'source symlink')
        if path.is_file() and '__pycache__' not in path.parts:
            m=meta(path);rows[str(path.relative_to(source))]={k:m[k] for k in ('bytes','sha256','mode')}
    return rows
def replace(text,marker,value):
    need(text.count(marker)==1,'nonunique marker: '+marker);return text.replace(marker,value,1)

def generate(source,out):
    extraction=load(source/'tests/observation-diagnostics/run_host.py','integration_original_extractor')
    body=extraction.body;section=extraction.section
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    controller=(source/PKG/'LocalTaskController.java').read_text()
    anchors={
      'same_window':'        boolean sameWindow(Graph other){',
      'copy_for_action':'        Graph copyForAction(String nodeId,WebRegionNativeBridge region){',
      'close_graph':'        void close(){for(NodeRef n:refs.values())n.node.recycle();refs.clear();}',
      'node_ref':'    private static final class NodeRef {',
      'action_work':'    private final class ActionWork {'}
    parts={key:body(service,value) for key,value in anchors.items()}
    parts['selected_refresh']=section(service,'            NodeRef reference=graph.refs.get(action.nodeId);','            boolean accepted;')
    parts['click_branch']=body(service,'            if("click".equals(action.action)){')
    text=(source/TEST/'NativeActionBridgeHost.template').read_text()
    for key,value in parts.items():text=replace(text,'{{'+key+'}}',value)
    methods={}
    for name,signature in METHODS.items():methods[name]=body(service,signature)
    text=replace(text,'    // ACTUAL_METHODS','\n'.join(methods.values()))
    bridge=(source/TEST/'BridgeCases.fragment').read_text()
    bridge=replace(bridge,'        signatureCases();rejectionCases();effectCases();equalOpenCases();',
        '        signatureCases();rejectionCases();effectCases();equalOpenCases();publicationActionCases();')
    bridge+='\n'+(source/TEST/'PublicationActionCases.fragment').read_text()
    text=replace(text,'{{bridge_cases}}',bridge)
    # Actual Controller handoff is connected to the actual unchanged-tree Service
    # branch. Only Android callback/clock/IO endpoints are synthetic.
    open_parts={
      'open_record':body(controller,'    private static void record(File directory,String name,JSONObject value)throws Exception{'),
      'open_cleanup_unknown':body(controller,'    private static final class CleanupUnknown extends Exception {'),
      'open_execution_projection':body(controller,'    private static java.util.Map<String,Object> nativeQueryExecution('),
      'open_await_action':body(controller,'    private HeptaAccessibilityService.ActionOutcome awaitAction('),
      'open_legacy_selected_refresh':parts['selected_refresh']}
    legacy_open=replace(parts['click_branch'],
      'if(expected.capture!=null&&expected.capture.formHistory()\n                        ||work!=null&&(work.nativeActionRevalidated||nativeSearchEntryGuard(work)||nativeFlightOpenGuard(work)))',
      'if(work!=null&&(work.nativeActionRevalidated||nativeSearchEntryGuard(work)))')
    need(sha(legacy_open.encode())=='0a8533a8c582e714df4777b5ddc1ed7acb40e1ee99007f95095b5c9f4be1c742','old 1079 OPEN branch must match retained actual bytes')
    open_parts['open_legacy_click_branch']=legacy_open
    for key,value in open_parts.items():text=replace(text,'{{'+key+'}}',value)
    methods.update(open_parts)
    need('{{' not in text,'unfilled bridge template');write(out/'NativeActionBridgeHost.java',text)
    original=(source/'tests/native-app-provider/NativeXiaomiModalSessionHostTest.java').read_text()
    main=body(original,'    public static void main(String[] args)throws Exception{')
    projection=replace(original,main,(source/TEST/'XiaomiGuardCases.fragment').read_text())
    projection=replace(projection,'class NativeXiaomiModalSessionHostTest','class XiaomiActionGuardHost')
    projection=replace(projection,'private NativeXiaomiModalSessionHostTest(){}','private XiaomiActionGuardHost(){}')
    # Exact Controller accepted-outcome barrier and complete await methods.
    pending_parts={
      'controller_pending_await':body(controller,'    private PhoneObservation awaitObservation(final String id,final File directory,final TaskAuthorization.Gate authorization,final long deadline)throws Exception{'),
      'controller_pending_await_request':body(controller,'    private PhoneObservation awaitObservation(final String id,final File directory,final TaskAuthorization.Gate authorization,final long deadline,'),
      'controller_pending_barrier':section(controller,'                staleRounds=0;checkActive(deadline);',
        '                JSONObject row=new JSONObject().put("step",steps).put("action",action.action).put("detail",outcome.detail)')}
    for name,value in pending_parts.items():projection=replace(projection,'{{'+name+'}}',value)
    projection=replace(projection,'import java.nio.charset.StandardCharsets;','import java.io.File;\nimport java.nio.charset.StandardCharsets;')
    methods.update(pending_parts)
    write(out/'XiaomiActionGuardHost.java',projection)
    write(out/'android/util/DisplayMetrics.java','package android.util; public final class DisplayMetrics { public int widthPixels,heightPixels; }\n')
    return service,controller,parts,methods,original,main

def sources(source,out):
    query=load(source/'tests/web-flight/run_query_host_tests.py','integration_query_closure')
    bg=load(source/'tests/background-session/prepare_fixture.py','integration_background_fixture')
    bgfiles,bgrecord=bg.prepare(source,out/'platform-fixture')
    # The legacy action gate compiles the actual new Session type without
    # pretending to offer the new planning/dispatch protocol. This generated
    # signature-only port is unconstructible and can never accept an effect.
    service_port=out/'platform-fixture/org/trillionnium/hepta/local/HeptaAccessibilityService.java'
    calendar_paths,calendar_boundary=calendar_legacy_closure(source,service_port)
    service_before=service_port.read_bytes();service_text=service_before.decode('utf-8')
    need(bgfiles.count(service_port)==1 and service_text.endswith('}')
         and 'class ActionOutcome' not in service_text and 'class NativeSearchReadRetryProof' not in service_text and 'class NativeSearchNoEffectReplanProof' not in service_text and 'class NativeSearchSamplingExhaustionProof' not in service_text,
         'one original Service type port required')
    outcome_port="""    public static final class ActionOutcome {
        public final boolean accepted=false,dispatched=false,stale=true;
        public final String detail=null;
        public final org.json.JSONObject taskAuthorization=null,actionExecution=null;
        private ActionOutcome(){throw new AssertionError("native search dispatch is outside the legacy action fixture");}
    }
    public static final class NativeSearchReadRetryProof {
        private NativeSearchReadRetryProof(){throw new AssertionError("native loading read retry is outside the legacy action fixture");}
    }
    public static final class NativeSearchSamplingExhaustionProof {
        private NativeSearchSamplingExhaustionProof(){throw new AssertionError("native sampling successor is outside this legacy fixture");}
        public void close(){throw new AssertionError("no sampling successor authority in this legacy fixture");}
    }
    public static final class NativeSearchNoEffectReplanProof {
        private NativeSearchNoEffectReplanProof(){throw new AssertionError("native search no-effect successor is outside this legacy fixture");}
        public void requireOriginal(NativeSearchSession session,NativeSearchSession.Attempt attempt,long now,boolean live){throw new AssertionError("no successor authority in this legacy fixture");}
        public void requireOutcome(ActionOutcome outcome){throw new AssertionError("no successor authority in this legacy fixture");}
        public void requirePublishedPlanning(NativeSearchSession session,NativeSearchPlanning planning){throw new AssertionError("no successor authority in this legacy fixture");}
        public java.util.Map<String,Object> evidence(){throw new AssertionError("no successor evidence in this legacy fixture");}
    }"""
    service_after=(service_text[:-1]+chr(10)+outcome_port+chr(10)+'}').encode('utf-8')
    need(service_after.decode('utf-8').replace(chr(10)+outcome_port+chr(10),'',1)==service_text,
         'original Service port changed outside the refusing type boundary')
    service_port.write_bytes(service_after)
    bgrecord=dict(bgrecord)
    bgrecord['native_calendar_legacy_type_boundary']=calendar_boundary
    bgrecord['native_search_legacy_type_boundary']={
        'generated_service':str(service_port),'original_service_sha256':sha(service_before),
        'compiled_service_sha256':sha(service_after),'type_block_sha256':sha(outcome_port.encode('utf-8')),
        'original_service_bytes_reversible':True,'constructor_always_throws':True,
        'accepted_and_dispatched_always_false':True,'authority_and_execution_always_null':True,
        'new_search_dispatch_tested':False,'loading_read_retry_proof_constructor_always_throws':True,
        'loading_read_retry_proof_minted':False, 'no_effect_successor_proof_constructor_and_methods_always_throw':True, 'no_effect_successor_proof_minted':False}
    bgfiles=[p for p in bgfiles if not(p.parent.name=='json' and p.parent.parent.name=='org') and 'terminal' not in p.parts]
    paths=[source/p for p in query.PURE_PATHS if p not in ('tests/web-flight/WebFlightQueryHostTest.java','tests/native-app/legacy-boundary/NativeAppSession.java')]+bgfiles
    names=['ObservationCaptureEvidence', 'PromptActionDomain','NativeAppEvidence','NativeAppDomain','NativeAppSession','NativeAppObservation',
      'NativeCtripFlightPage','NativeXiaomiProductPage','NativeActionSnapshotCheck','ActionExecutionState',
      'NativeSearchRole','NativeSearchPlanning','NativeSearchDecision','NativeSearchSession',
      'ObservationDiagnostics','ActionPolicy','PersistentActionPolicy']
    paths += [source/PKG/(name+'.java') for name in names]
    paths += [source/'tests/native-app-fixtures/NativeXmlFixture.java',
      source/'tests/native-app-provider/NativeAppProviderHostTest.java',
      source/'tests/native-app-provider/NativeResourceHomeHostTest.java',
      source/'tests/native-xiaomi-image-modal/ActualXiaomiImageModalFixture.java']
    paths += [source/TEST/(name+'.java') for name in ['IntegrationChecks','NativeActionSessionHostTest',
        'NativeActionSnapshotCheckHostTest','NativeCtripNestedBranchHostTest','NativeCarouselCurrentnessHostTest','NativeXiaomiHomeVariationHostTest','NativeXiaomiEntryObservationHostTest','NativeStableSearchIconHostTest','NativeActionIntegrationHostTest']]
    paths += sorted((out/'generated').rglob('*.java'))
    if not any(str(p).endswith('/android/util/Log.java') for p in paths):
        log=out/'generated/android/util/Log.java'
        write(log,'package android.util; public final class Log { public static int i(String tag,String text){return 0;} }\n');paths.append(log)
    actual_calendar_files={p.name for p in calendar_paths if source in p.parents}
    paths=[p for p in paths if not (p.parent==service_port.parent and (p.name in actual_calendar_files or p.name=="NativeAppSession.java"))]
    paths += calendar_paths
    paths=list(dict.fromkeys(p.resolve() for p in paths))
    for path in paths:need(path.is_file(),'missing actual compile source: '+str(path))
    return paths,bgrecord

def stage(name,argv,out,env):
    begin=time.monotonic_ns()
    with (out/(name+'.stdout')).open('xb') as stdout,(out/(name+'.stderr')).open('xb') as stderr:
        run=subprocess.run(list(map(str,argv)),cwd=out,env=env,stdout=stdout,stderr=stderr,timeout=150,check=False)
    return {'name':name,'argv':list(map(str,argv)),'exit_code':run.returncode,'elapsed_ns':time.monotonic_ns()-begin,
      'stdout':meta(out/(name+'.stdout')),'stderr':meta(out/(name+'.stderr'))}


def calendar_legacy_closure(source, service_port):
    """Actual pure calendar dependencies; opaque lifecycle/model types always refuse."""
    actual_names = (
        "NativeCalendarDateEnvelope", "NativeCalendarDateIntent", "NativeCalendarDateProtocol",
        "LocalInference", "LocalRuntimeConfig", "ModelProfile", "MobiMindContract", "MobiMindPins",
        "MobiMindPrivateFiles", "UiVenusInputContract", "UiVenusPins")
    source_paths = [source / ("src/org/trillionnium/hepta/local/" + name + ".java") for name in actual_names]
    before = service_port.read_text()
    if not before.endswith("}") or any("class " + name in before for name in (
            "CalendarFreshObservation", "CalendarActionResult", "CalendarSelectionObservation", "NativeSearchFinalCensusResampleProof")):
        raise RuntimeError("one original Service port without calendar authority required")
    input_port = '    /** Type-only old host boundary: no private action attempt can be constructed. */\n    static final class CalendarInputAttempt {\n        final String operationId=null;\n        final long queuedElapsed=-1;\n        private CalendarInputAttempt(){throw new UnsupportedOperationException("No calendar input authority in legacy fixture");}\n        void requirePermitProducer(NativeAppSession.CalendarPermit actual,boolean entered){\n            throw new UnsupportedOperationException("No calendar input authority in legacy fixture");\n        }\n        java.util.Map<String,Object> executionBeforeInput(){\n            throw new UnsupportedOperationException("No calendar input authority in legacy fixture");\n        }\n        java.util.Map<String,Object> beginBrokerCall(BackgroundSession actual,Cancellation original)throws Exception{\n            throw new UnsupportedOperationException("No calendar input authority in legacy fixture");\n        }\n        void requireBeforeSend(BackgroundSession actual,Cancellation original){\n            throw new UnsupportedOperationException("No calendar input authority in legacy fixture");\n        }\n    }\n'
    inherited_input = "class CalendarInputAttempt" in before
    if inherited_input and before.count(input_port) != 1:
        raise RuntimeError("unknown shared CalendarInputAttempt port")
    calendar_types = """
    static final class NativeSearchFinalCensusResampleProof {
        private NativeSearchFinalCensusResampleProof(){throw new AssertionError("actual final-census producer unavailable in this pure gate");}
        void consume(NativeSearchSession.Attempt attempt,NativeSearchRole role,long now){throw new AssertionError("no final-census replacement authority");}
    }
    public static final class CalendarFreshObservation {
        private CalendarFreshObservation(){throw new AssertionError("calendar publication is outside this legacy fixture");}
        void requireBound(NativeAppSession.CalendarFreshRead read)throws Exception{throw new AssertionError("no calendar publication authority");}
        NativeCalendarDateEnvelope readEnvelope(NativeAppSession.CalendarFreshRead read)throws Exception{throw new AssertionError("no calendar publication authority");}
        java.util.Map<String,Object> evidence(){throw new AssertionError("no calendar publication evidence");}
        PhoneObservation observationFor(LocalTaskController controller,NativeAppSession.CalendarFreshRead read)throws Exception{throw new AssertionError("no calendar publication authority");}
        PhoneObservation observationForAction(HeptaAccessibilityService actual,LocalTaskController controller,NativeAppSession.CalendarFreshRead read){throw new AssertionError("no calendar action authority");}
        void requireActionCurrentPure(HeptaAccessibilityService actual,LocalTaskController controller,NativeAppSession.CalendarFreshRead read){throw new AssertionError("no calendar action authority");}
        void requireActionIssuer(HeptaAccessibilityService actual,LocalTaskController controller,NativeAppSession.CalendarFreshRead read){throw new AssertionError("no calendar action authority");}
        void retireInputTracking(){throw new AssertionError("no calendar tracker in legacy fixture");}
        void requireRecordedOriginal(NativeAppSession.CalendarFreshRead read)throws Exception{throw new AssertionError("no calendar original publication");}
    }
    public static final class CalendarActionResult {
        final long confirmedElapsed=-1L;
        private CalendarActionResult(){throw new AssertionError("calendar result is outside this legacy fixture");}
        void requireSuccessfulOriginal(NativeAppSession.CalendarPermit permit,CalendarInputAttempt input){throw new AssertionError("no calendar result authority");}
        java.util.Map<String,Object> evidence()throws Exception{throw new AssertionError("no calendar result evidence");}
    }
    public static final class CalendarSelectionObservation {
        final CalendarActionResult result=null;
        final NativeAppEvidence.Frame frame=null;
        private CalendarSelectionObservation(){throw new AssertionError("calendar selection is outside this legacy fixture");}
        void requireBound(NativeAppSession.CalendarPermit permit)throws Exception{throw new AssertionError("no calendar selection authority");}
        java.util.Map<String,Object> evidence(){throw new AssertionError("no calendar selection evidence");}
    }
    void registerNativeCalendarInputTracking(NativeAppSession.CalendarFreshRead read,CalendarFreshObservation proof){throw new AssertionError("no calendar tracker in legacy fixture");}
    void retireNativeCalendarInputTracking(NativeAppSession.CalendarFreshRead read){throw new AssertionError("no calendar tracker in legacy fixture");}
"""
    extension = calendar_types + ("" if inherited_input else input_port)
    after = before[:-1] + extension + "}"
    if after.replace(extension, "", 1) != before:
        raise RuntimeError("calendar port changed the original Service body")
    service_port.write_text(after)
    model_port = """package org.trillionnium.hepta.local;
final class VlmInferenceAdapter implements LocalInference {
    private VlmInferenceAdapter(){throw new AssertionError("visual model is outside this legacy fixture");}
    public LocalRuntimeConfig configuration(){throw new AssertionError("no visual model configuration");}
    public Handle generate(String prompt,String system,java.io.File image,DecisionGrammar grammar,int tokens,long timeout,Callback callback){throw new AssertionError("no visual model execution");}
    interface AcceptedRequestCallback extends LocalInference.Callback {void onAcceptedRequest(AcceptedRequest proof);}
    public final class AcceptedRequest {
        private AcceptedRequest(){throw new AssertionError("no accepted visual request in legacy fixture");}
        public String requestId(){throw new AssertionError("no accepted visual request");}
        public String rawText(){throw new AssertionError("no accepted visual request");}
        public void requireBound(LocalInference engine,CurrentFrame frame,DecisionGrammar grammar)throws Exception{throw new AssertionError("no accepted visual request authority");}
        public java.util.Map<String,Object> evidence(){throw new AssertionError("no accepted visual request evidence");}
    }
}
"""
    runtime_port = """package org.trillionnium.hepta.local;
final class RuntimeInferenceAdapter implements LocalInference {
    private RuntimeInferenceAdapter(){throw new AssertionError("runtime router is outside this legacy fixture");}
    public LocalRuntimeConfig configuration(){throw new AssertionError("no runtime configuration authority");}
    public Handle generate(String prompt,String system,java.io.File image,DecisionGrammar grammar,int tokens,long timeout,Callback callback){throw new AssertionError("no runtime model execution");}
    final class CalendarModelBinding {
        private CalendarModelBinding(){throw new AssertionError("no runtime calendar binding in legacy fixture");}
        VlmInferenceAdapter requireCurrent(String taskId,LocalRuntimeConfig config){throw new AssertionError("no runtime calendar producer authority");}
    }
    synchronized CalendarModelBinding bindCalendarModel(String taskId,LocalRuntimeConfig config){throw new AssertionError("no runtime calendar binding authority");}
}
"""
    controller_port = """package org.trillionnium.hepta.local;
final class LocalTaskController {
    private LocalTaskController(){throw new AssertionError("calendar controller is outside this legacy fixture");}
}
"""
    generated = []
    for name, text in (("VlmInferenceAdapter.java", model_port), ("LocalTaskController.java", controller_port), ("RuntimeInferenceAdapter.java", runtime_port)):
        path = service_port.parent / name
        with path.open("x", encoding="utf-8") as f:
            f.write(text)
        generated.append(path)
    def pin(path):
        raw = path.read_bytes()
        return dict(path=str(path), bytes=len(raw), sha256=sha(raw))
    record = dict(schema="hepta.calendar-legacy-type-boundary.v1",
        original_service_sha256=sha(before.encode()), calendar_extension_service_sha256=sha(after.encode()),
        service_extension_sha256=sha(extension.encode()), original_service_bytes_reversible=True,
        inherited_shared_input_port=inherited_input, shared_input_port_sha256=sha(input_port.encode()),
        actual_pure_sources=[pin(p) for p in source_paths], refusing_ports=[pin(p) for p in generated],
        all_new_proof_constructors_private_and_throwing=True, all_new_authority_methods_throw=True,
        accepted_request_minted=False, calendar_permit_minted=False, input_attempt_minted=False,
        actual_calendar_behavior_tested=False, phone_actions=0, model_executed=False)
    return source_paths + generated, record


def main():
    parser=argparse.ArgumentParser()
    for name in ('source','output','java-home','json-jar'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args();source=args.source.resolve();out=args.output.absolute();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
    need(source.is_dir() and not out.exists() and source not in out.parents,'fresh output outside source required')
    toolpaths=[jdk/'bin/java',jdk/'bin/javac',jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    need(all(p.is_file() for p in toolpaths),'full JDK17 and JSON tools required')
    need(jar.stat().st_size==78332 and sha(jar.read_bytes())==JSON_SHA,'pinned JSON jar required')
    before=inventory(source);tools_before=[meta(p) for p in toolpaths];out.mkdir(parents=True,mode=0o700)
    env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1';sys.dont_write_bytecode=True
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH'):env.pop(key,None)
    report={'schema':'hepta.native-action-integration-host-gate.v1','all_pass':False,'stages':[],
      'inputs_before':before,'tools_before':tools_before,'phone_operations':0,'android_execution':False,
      'model_executed':False,'business_completion_verified':False,'platform_dispatch_executed':False,
      'compiler_contract':'JDK17 --release8; complete actual Session plus verbatim bridge; explicit host IO'}
    try:
        generated=out/'generated';generated.mkdir()
        service,controller,parts,methods,xiaomi,oldmain=generate(source,generated)
        paths,bgrecord=sources(source,out)
        modal=source/'tests/native-xiaomi-image-modal'
        modal_record=load(modal/'run_host.py','integration_modal_fixture').fixture(modal)
        record={'schema':'hepta.native-action-integration-extraction.v1','bodies_verbatim':True,
          'source_files':{name:meta(source/PKG/(name+'.java')) for name in ('HeptaAccessibilityService','LocalTaskController','NativeAppSession','NativeActionSnapshotCheck')},
          'methods':{name:{'bytes':len(value.encode()),'sha256':sha(value.encode())} for name,value in {**parts,**methods}.items()},
          'xiaomi_original_harness':meta(source/'tests/native-app-provider/NativeXiaomiModalSessionHostTest.java'),
          'xiaomi_only_main_and_outer_name_changed':False,'xiaomi_main_outer_name_and_File_import_only':True,'xiaomi_old_main_sha256':sha(oldmain.encode()),
          'background_fixture':bgrecord,'actual_image_fixture':modal_record,
          'open_equal_tree_actual_Service_and_Controller_handoff':True,
          'open_legacy_click_branch_sha256':'0a8533a8c582e714df4777b5ddc1ed7acb40e1ee99007f95095b5c9f4be1c742',
          'open_legacy_click_branch_exact_inverse_of_one_condition':True,
          'open_host_endpoint_manually_claims_guard':False,
          'open_actual_receipt_create_write_fsync':True,
          'boundary':'Session/authorization/provider classes and Service extracted bodies are actual. Complete census rows, Android APIs, traversal, clock, installed verifier and performAction are explicit synthetic host endpoints. No PhoneObservation screenshot is fabricated as device proof.'}
        save(out/'EXTRACTION.json',record)
        report['compile_inputs']=[meta(p) for p in paths]
        classes=out/'classes';classes.mkdir()
        commands=[('compile',[jdk/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-cp',jar,'-d',classes,*paths]),
          ('pure-cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeActionSnapshotCheckHostTest',out/'PURE-CASES.json']),
          ('nested-ctrip-cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeCtripNestedBranchHostTest',out/'NESTED-CTRIP-CASES.json']),
          ('integration-cases',[jdk/'bin/java','-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.NativeActionIntegrationHostTest',source,out/'CASES.json',out/'private'])]
        for name,command in commands:
            result=stage(name,command,out,env);report['stages'].append(result)
            need(result['exit_code']==0,'actual stage failed: '+name)
        pure=json.loads((out/'PURE-CASES.json').read_text());cases=json.loads((out/'CASES.json').read_text())
        need(pure['schema']=='hepta.native-action-snapshot-candidate-host.v1' and pure['all_pass'] is True and pure['cases']==76 and pure['assertions']==157 and len(set(pure['names']))==76,'original complete pure matrix required')
        need(cases['schema']=='hepta.native-action-integration-host.v1' and cases['all_pass'] is True and cases['cases']==len(cases['case_names'])==len(set(cases['case_names'])) and cases['assertions']>0,'actual complete unique integration cases required')
        need(all(name in cases['case_names'] for name in EXPECTED_EQUAL_OPEN_CASES),'all equal-tree OPEN pre-effect claim regressions required')
        nested=json.loads((out/'NESTED-CTRIP-CASES.json').read_text())
        need(nested['schema']=='hepta.ctrip-nested-disjoint-host.v1' and nested['all_pass'] is True
             and nested['cases']==90 and len(nested['case_names'])==len(set(nested['case_names']))==90
             and nested['assertions']>0 and nested['actual_comparator'] is True
             and nested['complete_synthetic_censuses'] is True and nested['baseline_control'] is False
             and nested['android_execution'] is False and nested['screenshot_admission_changed'] is False
             and nested['platform_dispatch_executed'] is False and nested['business_completion_verified'] is False,
             'complete nested Ctrip positive and refusal matrix required')
        report['nested_ctrip']=nested;report['nested_ctrip_file']=meta(out/'NESTED-CTRIP-CASES.json')
        pending=json.loads((out/'PENDING-BOUNDARY.json').read_text())
        need(pending['schema']=='hepta.r5.native-pending-controller-boundary.v1'
             and pending['actual_controller_barrier_completed'] is True
             and pending['next_model_waited_for_actual_session_observed'] is True
             and pending['fresh_pending_domain_refused_second_icon'] is True
             and pending['direct_session_pending_barrier_claimed'] is False,'actual Controller ordering and explicit Session API boundary')
        report['pending_boundary_file']=meta(out/'PENDING-BOUNDARY.json')
        report.update(cases=cases,pure=pure,cases_file=meta(out/'CASES.json'),pure_cases_file=meta(out/'PURE-CASES.json'),extraction_file=meta(out/'EXTRACTION.json'),
            generated_files={str(p.relative_to(generated)):meta(p) for p in sorted(generated.rglob('*.java'))},all_pass=True)
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['inputs_after']=inventory(source);report['tools_after']=[meta(p) for p in toolpaths]
        report['inputs_unchanged']=report['inputs_after']==before;report['tools_unchanged']=report['tools_after']==tools_before
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged'];save(out/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'result':meta(out/'RESULT.json'),'error':report.get('error')}))
    return 0 if report['all_pass'] else 1

if __name__=='__main__':raise SystemExit(main())

