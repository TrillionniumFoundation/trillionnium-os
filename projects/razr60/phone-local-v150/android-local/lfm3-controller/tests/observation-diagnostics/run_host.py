#!/usr/bin/env python3
"""Execute actual bounded diagnostic producers/consumer with explicit host IO.

The actual original observer methods, diagnostic factory/snapshot, observed-row
projection and action receipt helpers are preserved. The new Calendar producer
has an explicit private refusing type carrier; all three Controller awaits are
compiled with the sole enclosing-owner type name adapted to this host fixture.
Android graph, clock, callback, authorization and disk endpoints are host fakes.
No host result claims Android execution, cleanup, business success or authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

PKG = Path('src/org/trillionnium/hepta/local')
TEST = Path('tests/observation-diagnostics')
JAVA = ['ObservationCaptureEvidence.java', 'HeptaAccessibilityService.java','LocalTaskController.java','ObservationDiagnostics.java',
        'ObservationStabilityGate.java','ActionExecutionState.java','TaskCancellationQueue.java','ObservedWindowMetadata.java',
        'NativeActionSnapshotCheck.java','ObservedChildText.java','ObservedTargetLabels.java','NativeCtripFormObservation.java','NativeXiaomiSearchInputObservation.java','ObservedImeEnter.java']
OWN = ['run_host.py','DiagnosticChecks.java','ObservationDiagnosticsHostTest.java',
       'DiagnosticPipelineCases.fragment','DiagnosticGraphHost.template','DiagnosticControllerHost.template','CompactCensusDiagnosticsHostTest.java','PrivateCensusDiagnosticsHostTest.java','PrivateCensusFileHost.template','AxPublicationDiagnosticsHostTest.java']

def png_sources(source):
    # Exact production encoder plus explicit Android metadata type ports; no graph/owner authority.
    return [source/PKG/'ObservationPngEncoder.java',source/PKG/'PixelNativeCensusEvidence.java',
            source/'tests/observation-png/stubs/android/graphics/ColorSpace.java',
            source/'tests/observation-png/stubs/android/os/Build.java']

def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(path):
    path=Path(path).absolute();raw=path.read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw),'mode':path.stat().st_mode&0o777}
def write(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    if isinstance(raw,str):raw=raw.encode()
    with path.open('xb') as stream:stream.write(raw)
    os.chmod(path,0o600)
def save(path,value):write(path,json.dumps(value,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
def section(raw,start,end):
    if raw.count(start)!=1 or raw.count(end)!=1:raise RuntimeError('nonunique source anchors: '+start)
    first=raw.index(start);return raw[first:raw.index(end,first)]
def body(raw,start):
    if raw.count(start)!=1:raise RuntimeError('nonunique body anchor: '+start)
    first=raw.index(start);i=raw.index('{',first);depth=0;mode='code';escape=False
    while i<len(raw):
        c=raw[i];pair=raw[i:i+2]
        if mode=='line':
            if c=='\n':mode='code'
        elif mode=='comment':
            if pair=='*/':mode='code';i+=1
        elif mode in ('string','char'):
            if escape:escape=False
            elif c=='\\':escape=True
            elif c==('"' if mode=='string' else "'"):mode='code'
        elif pair=='//':mode='line';i+=1
        elif pair=='/*':mode='comment';i+=1
        elif c=='"':mode='string'
        elif c=="'":mode='char'
        elif c=='{':depth+=1
        elif c=='}':
            depth-=1
            if depth==0:return raw[first:i+1]
        i+=1
    raise RuntimeError('unterminated body')
def pixel_native_census_legacy_parts(service, parts):
    """No optional companion authority in the old synthetic scheduling fixtures.
    The separate pixels-native-census gate executes both complete actual members.
    Every existing worker/callback/product body remains current.
    """
    expected = {'    private boolean pixelNativeCensusEligible(': {'sha256': '5fad1f6a50491278fa723c68e5432efe95ce9e449b84e4d4379975a2ab8230bf', 'bytes': 738, 'port': '    private boolean pixelNativeCensusEligible(ObservationRequest request,ObservationProduct product){\n        if(product!=null&&(product.pixelNativeCensus!=null||product.pixelNativeCensusPath!=null))\n            throw new AssertionError("legacy observer cannot hold a pixel/native census companion");\n        return false;\n    }'}, '    private void persistPixelNativeCensus(': {'sha256': '4b602fa9a53cb86b0103452c5b08e6ba3295428a478014cd6e78b0028bdbc9b4', 'bytes': 4006, 'port': '    private void persistPixelNativeCensus(ObservationRequest request,ObservationProduct product)throws Exception{\n        if(product==null||product.pixelPng!=null||product.pixelNativeCensus!=null||product.pixelNativeCensusPath!=null)\n            throw new AssertionError("legacy observer cannot manufacture a pixel/native census companion");\n    }'}}
    compiled = dict(parts)
    rows = []
    for anchor, rule in expected.items():
        member = body(service, anchor)
        if len(member.encode()) != rule["bytes"] or sha(member.encode()) != rule["sha256"]:
            raise RuntimeError("unknown optional pixel companion producer: " + anchor)
        if compiled["observation"].count(member) != 1:
            raise RuntimeError("complete optional companion member must occur once")
        before = compiled["observation"]
        compiled["observation"] = before.replace(member, rule["port"], 1)
        if compiled["observation"].replace(rule["port"], member, 1) != before:
            raise RuntimeError("only the complete optional companion producer may be excluded")
        rows.append({"anchor": anchor, "bytes": rule["bytes"], "sha256": rule["sha256"],
                     "explicit_no_companion_port_sha256": sha(rule["port"].encode())})
    return compiled, {"schema": "hepta.pixel-census-legacy-type-boundary.v1",
                      "excluded_complete_new_members": rows,
                      "original_source_sha256": sha(parts["observation"].encode()),
                      "compiled_source_sha256": sha(compiled["observation"].encode()),
                      "pixel_census_producer_executed": False, "pixel_census_authority_available": False,
                      "new_actual_producer_gate": "tests/pixels-native-census/run_host.py"}

def ctrip_sampling_legacy_parts(service, parts, retain_ctrip_sampling=False):
    parts, pixel_boundary = pixel_native_census_legacy_parts(service, parts)
    compiled, boundary = _ctrip_sampling_legacy_parts(service, parts, retain_ctrip_sampling)
    boundary["pixel_native_census_boundary"] = pixel_boundary
    return compiled, boundary

def _ctrip_sampling_legacy_parts(service, parts, retain_ctrip_sampling=False):
    """Exact type boundary only; qualified form tests must retain the real block."""
    start = "    private boolean ctripFormSamplingOwner(ObservationRequest request,long now){"
    end = "    private void sampleObservation(final ObservationRequest request){"
    if start not in service:
        if "CtripFormSample" in parts["observation"]:
            raise RuntimeError("Unknown form sampling producer cannot enter legacy observer fixture")
        return dict(parts), {"schema": "hepta.observer-form-sampling-legacy-boundary.v1",
                             "sampling_helper_present": False, "sampling_producer_executed": False}
    actual = section(service, start, end)
    actual_sha = sha(actual.encode())
    proof = actual
    current_refusal_inverse_verified = False
    if actual_sha == '32cb9cce6e16596dc4be6f92b7ac4ea85e1f9cbcd8b827e15196a7b625bce6ed':
        for revised, prior in [('    /** Diagnostic values at the actual failed main-thread check, before clearing\n     * its sample. Bit 4 is the aggregate result of the unchanged initial check;\n     * the remaining bits describe this locked endpoint, not an inferred cause\n     * inside that earlier check. No graph, SDK object or authority is retained. */\n    private static void recordCtripSampleRefusal(ObservationRequest request,CtripFormSampleRead read,boolean initialCurrent){\n        try{\n            CtripFormSample after=read==null?null:read.after;\n            ObservationEventWatermark current=request.eventWatermark();\n            int mask=(read==null?1:0)|(after==null?2:0)|(!initialCurrent?4:0);\n            if(after!=null&&after.epoch!=request.ctripFormSampleEpoch)mask|=8;\n            if(read!=null&&request.ctripFormSample!=read.before)mask|=16;\n            if(after!=null&&!sameObservationWatermark(after.completed,current))mask|=32;\n            long at=SystemClock.elapsedRealtime();\n            Map<String,Object> out=new LinkedHashMap<String,Object>();\n            out.put("stage","sampling");out.put("reason","SAMPLE_CURRENT_REFUSED");out.put("at_ms",at);\n            out.put("failure_mask",mask);out.put("initial_current",initialCurrent);\n            out.put("epochs",java.util.Arrays.asList(after==null?-1:after.epoch,request.ctripFormSampleEpoch));\n            out.put("read_completed_ms",after==null?-1:after.readCompletedAt);\n            out.put("end_marks",ctripDiagnosticMark(after==null?null:after.completed));\n            out.put("current_marks",ctripDiagnosticMark(current));\n            request.ctripReadDiagnostic.helper(out);\n        }catch(RuntimeException unavailable){/* Optional diagnostics never alter a decision. */}\n    }\n', ''), ('        // This is an unpublished immutable value. The complete combined history is\n        // encoded and bounded once by persistCtripFormHistory before publication.\n', '        if(new JSONObject(out).toString().getBytes(StandardCharsets.UTF_8).length>786432)\n            throw new IllegalArgumentException("complete sampling history exceeds original form-history byte bound");\n')]:
            if proof.count(revised) != 1:raise RuntimeError("Unique complete current-sample helper inverse required")
            proof = proof.replace(revised, prior, 1)
        if len(proof.encode()) != 14414 or sha(proof.encode()) != "572fe702f6187416090a6d832bebf6fee02175b31a4fbcc5c48d615eab7feade":
            raise RuntimeError("Complete d4 dual-clock sampling helper block must be restored on the proof copy")
        current_refusal_inverse_verified = True
    if sha(proof.encode()) != "7552b60b680693577fc68d6f1da5a16e014dc99d55f5088ce7cb3896884ce54e":
        # Proof copy only: retain the actual dual-clock helper block for real Ctrip bridges.
        if sha(proof.encode()) != '572fe702f6187416090a6d832bebf6fee02175b31a4fbcc5c48d615eab7feade' or len(proof.encode()) != 14414:
            raise RuntimeError("Exact reviewed complete form sampling helper block required")
        for revised, prior in [('                        ||before.gateAcceptedAt<request.started||before.gateAcceptedAt>before.acceptedAt\n', ''), ('        out.put("before_gate_key_accepted_elapsed_ms",a.gateAcceptedAt);\n', '')]:
            if proof.count(revised) != 1:raise RuntimeError("Unique reviewed sampling clock helper delta required")
            proof = proof.replace(revised, prior, 1)
        if len(proof.encode()) != 14236 or sha(proof.encode()) != "7552b60b680693577fc68d6f1da5a16e014dc99d55f5088ce7cb3896884ce54e":
            raise RuntimeError("Complete original 712 helper block must be restored on the proof copy")
    if parts["observation"].count(actual) != 1:
        raise RuntimeError("Unique complete form sampling helper block required")
    port = """    /** Legacy observer fixtures have no qualified Ctrip sampling owner.
     * Dedicated form bridges retain the complete actual helper block instead. */
    private boolean ctripFormSamplingOwner(ObservationRequest request,long now){return false;}
    private static boolean sameObservationWatermark(ObservationEventWatermark a,ObservationEventWatermark b){
        return a!=null&&b!=null&&a.events==b.events&&a.unknownEvents==b.unknownEvents
                &&a.contentEvents==b.contentEvents&&a.boundaryEvents==b.boundaryEvents;
    }
    private static void recordCtripSampling(ObservationRequest request,String reason,CtripFormSample a,CtripFormSample b,Exception failure){
        throw new AssertionError("legacy observer cannot record a qualified Ctrip sample");
    }
    private CtripFormSampleRead readCtripFormSample(ObservationRequest request,Graph graph,CtripFormSample before,
            ObservationEventWatermark readStart,ObservationEventWatermark completed,long completedAt,long epoch){
        if(before!=null||request.ctripSample()!=null)
            throw new AssertionError("legacy observer cannot retain a qualified Ctrip sample");
        return null;
    }
    private boolean ctripFormSampleCurrent(ObservationRequest request,Graph graph,CtripFormSampleRead read){
        if(read!=null)throw new AssertionError("legacy observer cannot receive a qualified Ctrip pair");
        return false;
    }
    private static void recordCtripSampleRefusal(ObservationRequest request,CtripFormSampleRead read,boolean initialCurrent){
        throw new AssertionError("legacy observer cannot receive a qualified Ctrip sample refusal");
    }
    private static Map<String,Object> ctripSamplingProof(ObservationRequest request,CtripFormSampleRead read,long admittedAt){
        throw new AssertionError("legacy observer cannot construct classified sampling evidence");
    }
    private boolean ctripSamplingProofCurrent(ObservationRequest request,Map<String,Object> proof){return false;}
    private static Map<String,Object> ctripSamplingSummary(Map<String,Object> proof,File path,int bytes,String digest){
        throw new AssertionError("legacy observer cannot publish classified sampling evidence");
    }
"""
    compiled = dict(parts)
    if not retain_ctrip_sampling:
        compiled["observation"] = parts["observation"].replace(actual, port, 1)
        if compiled["observation"].replace(port, actual, 1) != parts["observation"]:
            raise RuntimeError("Actual form sampling helper block must remain fully reversible")
    elif compiled["observation"] != parts["observation"]:
        raise RuntimeError("Dedicated Ctrip bridge must retain the complete actual sampling block")
    return compiled, {
        "schema": "hepta.observer-form-sampling-legacy-boundary.v1",
        "sampling_helper_present": True,
        "actual_helper_bytes": len(actual.encode()), "actual_helper_sha256": actual_sha,
        "current_refusal_inverse_verified": current_refusal_inverse_verified,
        "current_refusal_proof_copy_only": True,
        "reviewed_712_helper_sha256": "7552b60b680693577fc68d6f1da5a16e014dc99d55f5088ce7cb3896884ce54e",
        "sampling_clock_inverse_proof_copy_only": True,
        "compiled_observation_sha256": sha(compiled["observation"].encode()),
        "full_source_observation_sha256": sha(parts["observation"].encode()),
        "retains_actual_sampling_helpers": bool(retain_ctrip_sampling),
        "legacy_sampling_ports_used": not retain_ctrip_sampling,
        "refusing_ports_sha256": None if retain_ctrip_sampling else sha(port.encode()),
        "production_worker_six_argument_accept_event_and_capture_bodies_verbatim": True,
        "legacy_qualified_sample_or_proof_available": False,
        "legacy_sampling_producer_executed": False,
        "actual_sampling_behavior_requires_dedicated_form_gate": True,
        "phone_operations": 0}


def calendar_observer_legacy_parts(service, parts, retain_ctrip_sampling=False):
    original_observation = parts["observation"]
    parts, sampling_boundary = ctrip_sampling_legacy_parts(service, parts, retain_ctrip_sampling)
    """Preserve actual observer methods; calendar-only proof types always refuse."""
    start = "    /** One typed read, using the existing observation request/PNG publication."
    end = "    public void observe(final String taskId,final File evidenceDirectory,final Cancellation cancel,"
    if start not in service:
        if "CalendarFreshObserver" in parts["observation"]:
            raise RuntimeError("Unknown calendar producer cannot enter the legacy observer fixture")
        return dict(parts), {"schema": "hepta.observer-calendar-legacy-type-boundary.v1",
                             "calendar_producer_excluded": False, "calendar_producer_executed": False,
                             "ctrip_form_sampling_boundary": sampling_boundary}
    actual = section(service, start, end)
    actual_sha = sha(actual.encode())
    if actual_sha != "d143d3bca16e6f85571c234535aee39a45b91851c77b7cf70dee06adb988fb04":
        raise RuntimeError("Exact reviewed calendar-only producer block required")
    port = """    private abstract class CalendarFreshObserver implements ObservationCallback {
        private CalendarFreshObserver(){throw new UnsupportedOperationException("Calendar producer unavailable in observer-only fixture");}
        void bind(ObservationRequest request){throw new UnsupportedOperationException("No calendar producer authority");}
        void requireAdmission(ObservationRequest request){throw new UnsupportedOperationException("No calendar producer authority");}
    }

"""
    if parts["observation"].count(actual) != 1:
        raise RuntimeError("Unique calendar producer within the observation section required")
    compiled = dict(parts)
    compiled["observation"] = parts["observation"].replace(actual, port, 1)
    if compiled["observation"].replace(port, actual, 1) != parts["observation"]:
        raise RuntimeError("Original production observation section must remain reversible")
    return compiled, {
        "schema": "hepta.observer-calendar-legacy-type-boundary.v1",
        "calendar_producer_excluded": True,
        "full_production_observation_sha256": sha(original_observation.encode()),
        "calendar_only_excluded_bytes": len(actual.encode()),
        "calendar_only_excluded_sha256": actual_sha, "refusing_port_sha256": sha(port.encode()),
        "compiled_observation_sha256": sha(compiled["observation"].encode()),
        "actual_observer_scheduling_and_both_calendar_type_hooks_unchanged": True,
        "private_constructor_and_lifecycle_methods_throw": True,
        "calendar_callback_created": False, "calendar_producer_executed": False,
        "calendar_actual_gates": ["native-calendar-date-fresh", "native-calendar-date-actions"],
        "ctrip_form_sampling_boundary": sampling_boundary}


def calendar_controller_legacy_template(template):
    """Add only opaque, unconstructible calendar types to this existing IO carrier."""
    original = template
    replacements = []
    def insert(before, after):
        nonlocal template
        if template.count(before) != 1:
            raise RuntimeError("Unique controller calendar type boundary required: " + before[:70])
        template = template.replace(before, after, 1)
        replacements.append((before, after))
    insert("    static final class BackgroundSession {",
           "    static final class BackgroundSession {long expiresElapsed=-1;")
    session_types = """
        final TaskAuthorization.Gate authorization=null;final String taskId=null;
        static final class CalendarFreshRead {
            final NativeAppSession session=null;final BackgroundSession background=null;
            final long deadlineElapsed=-1;
            private CalendarFreshRead(){throw new AssertionError("No calendar read in legacy controller fixture");}
            void requireOriginal(NativeAppSession owner,BackgroundSession actual){throw new AssertionError("No calendar read authority");}
            void close(){throw new AssertionError("No calendar read authority");}
        }
"""
    insert("    static final class NativeAppSession {",
           "    static final class NativeAppSession {" + session_types)
    service_types = """
        interface CalendarFreshCallback {
            void onDiagnostic(Callable<String> snapshot);void onPrivateCensusDiagnostic(Callable<String> snapshot);
            void onError(String detail);void onFresh(CalendarFreshObservation proof);
        }
        static final class CalendarFreshObservation {
            private CalendarFreshObservation(){throw new AssertionError("No calendar publication in legacy controller fixture");}
            PhoneObservation observationFor(Object owner,NativeAppSession.CalendarFreshRead read)throws Exception{
                throw new AssertionError("No calendar publication authority");
            }
        }
        void observeNativeCalendarFresh(Object owner,NativeAppSession.CalendarFreshRead read,File directory,
                Cancellation cancel,long deadline,CalendarFreshCallback callback){
            throw new AssertionError("No calendar observer in legacy controller fixture");
        }
"""
    insert("    static final class HeptaAccessibilityService {",
           "    static final class HeptaAccessibilityService {" + service_types)
    controller_types = """    private static final class CalendarFreshWait {
        final NativeAppSession.CalendarFreshRead read=null;
        final AtomicReference<HeptaAccessibilityService.CalendarFreshObservation> publication=null;
        private CalendarFreshWait(){throw new AssertionError("No calendar wait in legacy controller fixture");}
    }
    private void requireNativeCalendarFreshOwner(NativeAppSession.CalendarFreshRead read){
        throw new AssertionError("No calendar owner authority in legacy controller fixture");
    }
"""
    insert("{{await_observation}}", controller_types + "{{await_observation}}")
    insert("{{await_observation_request}}", "{{await_observation_request}}\n{{await_observation_calendar}}")
    inverse = template
    for before, after in reversed(replacements):
        if inverse.count(after) != 1:
            raise RuntimeError("Controller calendar type inverse is not unique")
        inverse = inverse.replace(after, before, 1)
    if inverse != original:
        raise RuntimeError("Controller calendar types changed original fixture logic")
    return template, {
        "schema": "hepta.controller-calendar-legacy-type-boundary.v1",
        "original_template_sha256": sha(original.encode()),
        "extended_template_sha256": sha(template.encode()),
        "original_template_bytes_reversible": True,
        "new_proof_constructors_private_and_throwing": True,
        "calendar_authority_endpoints_throw": True,
        "calendar_wait_created": False, "calendar_behavior_executed": False,
        "type_extensions": [{"bytes":len(after.encode())-len(before.encode()),"sha256":sha(after.encode())}
                            for before,after in replacements]}


def generate(source,output):
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    controller=(source/PKG/'LocalTaskController.java').read_text()
    parts={
      'observation_callback':section(service,'    public interface ObservationCallback','    public interface Cancellation'),
      'diagnostic':section(service,'    private String diagnosticTask;','    /** Each observation owns'),
      'acquire':section(service,'    public synchronized boolean acquireTask(','    public synchronized void releaseTask('),
      'recovery_idle':section(service,'    synchronized boolean recoveryControllerIdle(','    synchronized void retireControllerAfterAcknowledgement('),
      'action_pending':section(service,'    boolean actionWorkPending()','    void retireActionWork('),
      'cancellation_pending':section(service,'    boolean nativeCancellationWorkPending()','    boolean requestNativeCancellation('),
      'background_lock':section(service,'    private boolean locked(BackgroundSession background)','    private int rotation('),
      'observation':section(service,'    /** Each observation owns','    synchronized void bindQualificationScope(')}
    compiled_parts,calendar_boundary=calendar_observer_legacy_parts(service,parts)
    template=(source/'tests/observation-pipeline/ObserverPipelineHost.template').read_text()
    for name,value in compiled_parts.items():
        marker='{{'+name+'}}'
        if template.count(marker)!=1:raise RuntimeError('pipeline marker '+name)
        template=template.replace(marker,value,1)
    main=body(template,'    public static void main(String[] args)throws Exception{')
    template=template.replace(main,(source/TEST/'DiagnosticPipelineCases.fragment').read_text(),1)
    if '{{' in template:raise RuntimeError('unfilled pipeline fixture')
    write(output/'ObserverPipelineHost.java',template)
    methods={
        'native_stamp':body(service,'    private static ObservationDiagnostics.GraphStamp nativeDiagnosticStamp(Graph graph){'),
        'native_census':body(service,'    private static ObservationDiagnostics.CensusStamp nativeDiagnosticCensus(Graph graph){'),
        'stale_record':body(service,'    private static void recordStaleDiagnostic(ActionWork work,Graph before,Graph after,String selectedId){'),
        'action_evidence':body(service,'    private static JSONObject actionDiagnosticEvidence(ActionWork work){'),
        'take_diagnostics':body(controller,'    private JSONObject takeObservationDiagnostics(String task){'),
        'private_census_holder':body(controller,'    private static final class FailedCensusDiagnostic {'),
        'persist_private_census':body(controller,'    private JSONObject persistFailedCensusDiagnostic(String task,String status,boolean verified,File directory){'),
        'private_census_write':body(controller,'    private static void recordPrivateCensus(File directory,String name,byte[] bytes)throws Exception{'),
        'await_observation':body(controller,'    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline)throws Exception{'),
        'await_observation_request':body(controller,'    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline,\n            HeptaAccessibilityService.NativeObservationRetryProof retryProof)throws Exception{'),
        'read_retry_failure':body(controller,'    private static final class NativeObservationTransientFailure extends IllegalStateException {'),
        'initial_read_failure':body(controller,'    private static final class InitialNativeObservationFailure extends IllegalStateException {'),
        'post_effect_read_failure':body(controller,'    private static final class PostEffectNativeObservationFailure extends IllegalStateException {')}
    calendar_signature = "    private PhoneObservation awaitObservationRaw(String id,File directory,TaskAuthorization.Gate authorization,long deadline,\n            HeptaAccessibilityService.NativeObservationRetryProof retryProof,final CalendarFreshWait calendar)throws Exception{"
    if calendar_signature in controller:
        methods["await_observation_calendar"] = body(controller, calendar_signature)
    calendar_controller_boundary = None
    for fixture,names in [('DiagnosticGraphHost',['native_stamp','native_census','stale_record','action_evidence']),('DiagnosticControllerHost',['await_observation','await_observation_request','read_retry_failure','initial_read_failure','post_effect_read_failure','take_diagnostics','private_census_holder','persist_private_census']),('PrivateCensusFileHost',['private_census_write'])]:
        text=(source/TEST/(fixture+'.template')).read_text()
        compiled_methods = dict(methods)
        if fixture == "DiagnosticControllerHost" and "await_observation_calendar" in methods:
            text,calendar_controller_boundary = calendar_controller_legacy_template(text)
            names = list(names) + ["await_observation_calendar"]
            calendar_body = methods["await_observation_calendar"]
            if calendar_body.count("LocalTaskController.this") != 1:
                raise RuntimeError("Exact enclosing Controller reference required")
            compiled_methods["await_observation_calendar"] = calendar_body.replace(
                "LocalTaskController.this", "DiagnosticControllerHost.this", 1)
            calendar_controller_boundary["fixture_enclosing_owner_type_mapping"] = {
                "from": "LocalTaskController.this", "to": "DiagnosticControllerHost.this",
                "occurrences": 1, "only_calendar_callback_owner_expression": True}
            calendar_controller_boundary["actual_calendar_await_sha256"] = sha(calendar_body.encode())
            calendar_controller_boundary["compiled_calendar_await_sha256"] = sha(
                compiled_methods["await_observation_calendar"].encode())
        for name in names:
            marker='{{'+name+'}}'
            if text.count(marker)!=1:raise RuntimeError('method marker '+name)
            text=text.replace(marker,compiled_methods[name],1)
        if '{{' in text:raise RuntimeError('unfilled '+fixture)
        write(output/(fixture+'.java'),text)
    # Preserve the exact native guard and original default refusal call site.
    # This observer suite does not qualify the separate native action guard.
    branch='''}else if(!graph.digest.equals(now.digest)){
                    if(work!=null&&work.nativeGuard!=null){
                        try{compareNativeAction(taskId,expected,action,now,work);work.nativeActionRevalidated=true;}
                        catch(ProfileOwnershipViolation identityChanged){throw identityChanged;}
                        catch(Exception mismatch){recordStaleDiagnostic(work,graph,now,action.nodeId);
                            return "stale:原生目的复核失败："+message(mismatch);}
                    }else{recordStaleDiagnostic(work,graph,now,action.nodeId);return "stale:目标窗口内容已变化";}
                }'''
    # Both separately sealed planning-history kinds require the unchanged native
    # guard even when the historical whole-tree digest matches. Check the exact
    # closed kind predicates, then reverse only this reviewed condition through
    # the prior form-history condition to the complete original fallback branch.
    capture=(source/PKG/'ObservationCaptureEvidence.java').read_text()
    history_predicates='''    boolean formHistory(){return NATIVE_AX_FORM_HISTORY.equals(kind);}
    boolean inputHistory(){return NATIVE_AX_INPUT_HISTORY.equals(kind);}
    boolean planningHistory(){return formHistory()||inputHistory();}'''
    if capture.count(history_predicates)!=1:
        raise RuntimeError('exact two-kind planning-history predicate required')
    legacy_condition='}else if(!graph.digest.equals(now.digest)){'
    form_condition='}else if(expected.capture!=null&&expected.capture.formHistory()||!graph.digest.equals(now.digest)){'
    history_condition='}else if(expected.capture!=null&&expected.capture.planningHistory()||!graph.digest.equals(now.digest)){'
    if branch.count(legacy_condition)!=1:raise RuntimeError('exact legacy guard condition required')
    form_branch=branch.replace(legacy_condition,form_condition,1)
    actual_branch=form_branch.replace(form_condition,history_condition,1)
    if (actual_branch.count(history_condition)!=1
            or actual_branch.replace(history_condition,form_condition,1)!=form_branch
            or form_branch.replace(form_condition,legacy_condition,1)!=branch):
        raise RuntimeError('history call-site inverse must preserve the original native guard and fallback')
    if service.count(actual_branch)!=1:raise RuntimeError('exact separately guarded native branch and original fallback required')
    callback='callback.onResult(delivered.withActionExecution(actionDiagnosticEvidence(work)));'
    if service.count(callback)!=1:raise RuntimeError('actual action callback must consume diagnostic evidence')
    await_body=methods.get('await_observation_calendar',methods['await_observation_request']);finally_body=await_body[await_body.index('        }finally{\n            abandoned.set(true);'):]
    if any(token in finally_body for token in ('record(', 'System.err', 'System.out', '.wait(', '.sleep(')):raise RuntimeError('diagnostic finally must not perform IO or wait')
    finalization=section(controller,'        finally{\n            if(activeNativeSearch!=null)activeNativeSearch.retire();\n            service.retireActionWork(taskId,', '    private static NotesCompletionEvidence.Frame completionFrame(')
    positions=[finalization.index(token) for token in ['backgroundCleanup=background.close();','modelCleanup=inference.endTask(taskId);','terminalDecisionSealed=true;','persistFailedCensusDiagnostic(taskId,finalStatus,completionVerified,evidence)','record(evidence,"result.json"','takeObservationDiagnostics(taskId)','if(cleanup)service.releaseTask(taskId);','running=false;','selected.onFinished(result)']]
    if positions!=sorted(positions) or finalization.count('takeObservationDiagnostics(taskId)')!=1:raise RuntimeError('original cleanup then existing terminal record order required')
    if controller.count('pendingObservationDiagnostics.add(')!=1 or controller.count('pendingObservationDiagnostics.size()<96')!=1:raise RuntimeError('bounded single memory admission required')
    extraction={'schema':'hepta.observation-diagnostics-extraction.v1',
        'bodies_verbatim':not calendar_boundary['calendar_producer_excluded'] and calendar_controller_boundary is None,
        'original_observer_methods_and_hooks_verbatim':True,
        'calendar_legacy_boundary':calendar_boundary,'calendar_controller_legacy_boundary':calendar_controller_boundary,
        'sources':{'service':meta(source/PKG/'HeptaAccessibilityService.java'),'controller':meta(source/PKG/'LocalTaskController.java')},
        'methods':{name:{'bytes':len(value.encode()),'sha256':sha(value.encode())} for name,value in {**parts,**methods}.items()},
        'stale_refusal_callsite':{'bytes':len(actual_branch.encode()),'sha256':sha(actual_branch.encode())},
        'stale_refusal_legacy_inverse':{'bytes':len(branch.encode()),'sha256':sha(branch.encode()),'exact_inverse':True},
        'stale_refusal_form_history_inverse':{'bytes':len(form_branch.encode()),'sha256':sha(form_branch.encode()),'exact_inverse':True},
        'planning_history_kind_predicates':{'bytes':len(history_predicates.encode()),'sha256':sha(history_predicates.encode()),'exact_form_or_input_only':True},
        'action_callback_callsite':{'bytes':len(callback.encode()),'sha256':sha(callback.encode())},
        'legacy_pipeline_main_not_replaced_in_source':True,
        'default_whole_graph_action_refusal_retained':True,'native_action_guard_qualification_claimed':False,
        'diagnostic_finally_has_no_IO_or_wait':True,'terminal_summary_uses_only_existing_result_write':True,'private_failure_artifact_after_original_cleanup_and_terminal':True,
        'cleanup_terminal_order_source_sha256':sha(finalization.encode()),
        'boundary':'Actual Service/Controller bodies, pure tracker and stability gate. Android graph/clock, already-observed row carriers, Session carrier, callback/authorization and disk endpoints are explicit host fakes; no Android/currentness or business qualification.'}
    return extraction

def stage(name,argv,output):
    begin=time.monotonic_ns()
    with (output/(name+'.stdout')).open('xb') as stdout,(output/(name+'.stderr')).open('xb') as stderr:
        proc=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=90,check=False)
    return {'name':name,'argv':argv,'exit_code':proc.returncode,'elapsed_ns':time.monotonic_ns()-begin,
            'stdout':meta(output/(name+'.stdout')),'stderr':meta(output/(name+'.stderr'))}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--java-home',type=Path,required=True);ap.add_argument('--json-jar',type=Path,required=True);args=ap.parse_args()
    source=args.source.resolve();output=args.output.absolute();output.mkdir(parents=True,exist_ok=False)
    jdk=args.java_home.resolve();java=jdk/'bin/java';javac=jdk/'bin/javac';jar=args.json_jar.resolve()
    tools=[java,javac,jdk/'lib/modules',jdk/'lib/ct.sym',jar]
    if not all(p.is_file() for p in tools):raise RuntimeError('complete strict JDK and JSON tool closure required')
    if jar.stat().st_size!=78332 or sha(jar.read_bytes())!='3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed':raise RuntimeError('pinned JSON jar required')
    paths=[source/PKG/x for x in JAVA]+[source/TEST/x for x in OWN]+[source/'tests/observation-pipeline/ObserverPipelineHost.template']+tools
    paths += png_sources(source)
    before=[meta(x) for x in paths];tools_before=[meta(x) for x in tools]
    report={'schema':'hepta.observation-diagnostics-host-gate.v1','all_pass':False,'stages':[],
        'input_before':before,'tools_before':tools_before,'android_execution':False,'phone_execution':False,'phone_operations':0,
        'model_executed':False,'business_completion_verified':False,'sdk_loaded':False,
        'action_guard_changed':True,'native_action_guard_qualification_claimed':False,
        'compiler_contract':'JDK17 --release 8 -Xlint:all -Werror',
        'boundary':'Production observer/consumer methods execute with explicit host IO; no device or effect authority.'}
    try:
        generated=output/'generated';generated.mkdir();extraction=generate(source,generated);save(output/'EXTRACTION.json',extraction)
        classes=output/'classes';classes.mkdir()
        sources=[source/PKG/x for x in JAVA if x not in ('HeptaAccessibilityService.java','LocalTaskController.java')]
        sources += [source/TEST/'DiagnosticChecks.java',source/TEST/'ObservationDiagnosticsHostTest.java',source/TEST/'CompactCensusDiagnosticsHostTest.java',source/TEST/'PrivateCensusDiagnosticsHostTest.java',source/TEST/'AxPublicationDiagnosticsHostTest.java']+sorted(generated.glob('*.java'))
        sources += png_sources(source)
        command=[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources))
        compiled=stage('compile',command,output);report['stages'].append(compiled)
        if compiled['exit_code']!=0:raise RuntimeError('actual diagnostic wiring compilation failed')
        executed=stage('cases',[str(java),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.ObservationDiagnosticsHostTest',str(output/'CASES.json')],output);report['stages'].append(executed)
        if executed['exit_code']!=0:raise RuntimeError('actual diagnostic wiring cases failed')
        cases=json.loads((output/'CASES.json').read_text())
        if cases['all_pass'] is not True or cases['cases']!=len(cases['case_names']) or len(set(cases['case_names']))!=cases['cases']:raise RuntimeError('complete unique case identity required')
        compact=stage('compact-cases',[str(java),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.CompactCensusDiagnosticsHostTest',str(output/'COMPACT-CASES.json')],output);report['stages'].append(compact)
        if compact['exit_code']!=0:raise RuntimeError('actual compact census diagnostic cases failed')
        compact_cases=json.loads((output/'COMPACT-CASES.json').read_text())
        if compact_cases['all_pass'] is not True or compact_cases['cases']!=15 or len(compact_cases['case_names'])!=15 or len(set(compact_cases['case_names']))!=15 or compact_cases['assertions']<=0:
            raise RuntimeError('complete unique compact census case identity required')
        if compact_cases['actual_tracker_and_Service_snapshot'] is not True or compact_cases['deadline_or_sampling_changed'] is not False or compact_cases['android_execution'] is not False or compact_cases['phone_operations']!=0 or compact_cases['business_completion_verified'] is not False:
            raise RuntimeError('compact diagnostic boundary changed')
        report['compact_cases']=compact_cases;report['compact_cases_file']=meta(output/'COMPACT-CASES.json')
        ax=stage('ax-publication-cases',[str(java),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.AxPublicationDiagnosticsHostTest',str(output/'AX-PUBLICATION-CASES.json')],output);report['stages'].append(ax)
        if ax['exit_code']!=0:raise RuntimeError('actual AX publication diagnostic cases failed')
        ax_cases=json.loads((output/'AX-PUBLICATION-CASES.json').read_text())
        if ax_cases['all_pass'] is not True or ax_cases['cases']!=18 or len(ax_cases['case_names'])!=18 or len(set(ax_cases['case_names']))!=18 or ax_cases['assertions']<=0:
            raise RuntimeError('complete unique AX publication diagnostic case identity required')
        if ax_cases['actual_tracker_and_Service_serializers'] is not True or ax_cases['deadline_or_sampling_changed'] is not False or ax_cases['android_execution'] is not False or ax_cases['phone_operations']!=0 or ax_cases['business_completion_verified'] is not False:
            raise RuntimeError('AX publication diagnostic boundary changed')
        report['ax_publication_cases']=ax_cases;report['ax_publication_cases_file']=meta(output/'AX-PUBLICATION-CASES.json')
        report['cases']=cases;report['cases_file']=meta(output/'CASES.json');report['extraction_file']=meta(output/'EXTRACTION.json')
        report['generated_files']={p.name:meta(p) for p in sorted(generated.glob('*.java'))}
        report['actual_Service_observation_and_callback_compiled_verbatim']=not extraction['calendar_legacy_boundary']['calendar_producer_excluded']
        report['actual_original_Service_observer_methods_and_type_hooks_compiled_verbatim']=True
        report['actual_Controller_await_compiled_verbatim']=extraction['calendar_controller_legacy_boundary'] is None
        report['actual_Controller_await_only_enclosing_owner_type_mapped']=extraction['calendar_controller_legacy_boundary'] is not None
        report['actual_native_graph_projection_and_stale_receipt_compiled_verbatim']=True
        report['original_deadline_and_guard_calls_retained']=False
        report['original_guard_calls_retained']=True
        report['deadline_expanded']=True
        report['observation_budget']={'settle_ms':10000,'capture_margin_ms':2000,'total_ms':12000,
            'task_deadline_caps_total':True,'retry_renews_deadline':False,'legacy_explicit_ten_second_cases_retained':True}
        report['all_pass']=True
    except Exception as error:report['error']={'type':type(error).__name__,'message':str(error)}
    finally:
        report['input_after']=[meta(x) for x in paths];report['tools_after']=[meta(x) for x in tools]
        report['inputs_unchanged']=report['input_after']==before;report['tools_unchanged']=report['tools_after']==tools_before
        report['all_pass']=report['all_pass'] and report['inputs_unchanged'] and report['tools_unchanged'];save(output/'RESULT.json',report)
    print(json.dumps({'all_pass':report['all_pass'],'result':meta(output/'RESULT.json')}));return 0 if report['all_pass'] else 1

if __name__=='__main__':raise SystemExit(main())

