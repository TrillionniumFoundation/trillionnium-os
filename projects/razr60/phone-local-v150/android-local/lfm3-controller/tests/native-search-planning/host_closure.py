"""Shared host compile closure: real Session/Offer/Role, explicit Android IO ports.

No phone command is available here.  Existing profile/background host ports are
reused exactly; actual full production classes remain the compiled consumers.
"""
from pathlib import Path
import hashlib
import importlib.util

JSON_SHA = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def record(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value



def calendar_legacy_closure(source, service_port):
    """Actual pure calendar dependencies; opaque lifecycle/model types always refuse."""
    actual_names = (
        "NativeCalendarDateEnvelope", "NativeCalendarDateIntent", "NativeCalendarDateProtocol",
        "LocalInference", "LocalRuntimeConfig", "ModelProfile", "MobiMindContract", "MobiMindPins",
        "MobiMindPrivateFiles", "UiVenusInputContract", "UiVenusPins")
    source_paths = [source / ("src/org/trillionnium/hepta/local/" + name + ".java") for name in actual_names]
    before = service_port.read_text()
    ending = "}\n" if before.endswith("}\n") else "}"
    if not before.endswith(ending) or any("class " + name in before for name in (
            "CalendarFreshObservation", "CalendarActionResult", "CalendarSelectionObservation")):
        raise RuntimeError("one original Service port without calendar authority required")
    input_port = '    /** Type-only old host boundary: no private action attempt can be constructed. */\n    static final class CalendarInputAttempt {\n        final String operationId=null;\n        final long queuedElapsed=-1;\n        private CalendarInputAttempt(){throw new UnsupportedOperationException("No calendar input authority in legacy fixture");}\n        void requirePermitProducer(NativeAppSession.CalendarPermit actual,boolean entered){\n            throw new UnsupportedOperationException("No calendar input authority in legacy fixture");\n        }\n        java.util.Map<String,Object> executionBeforeInput(){\n            throw new UnsupportedOperationException("No calendar input authority in legacy fixture");\n        }\n        java.util.Map<String,Object> beginBrokerCall(BackgroundSession actual,Cancellation original)throws Exception{\n            throw new UnsupportedOperationException("No calendar input authority in legacy fixture");\n        }\n        void requireBeforeSend(BackgroundSession actual,Cancellation original){\n            throw new UnsupportedOperationException("No calendar input authority in legacy fixture");\n        }\n    }\n'
    inherited_input = "class CalendarInputAttempt" in before
    if inherited_input and before.count(input_port) != 1:
        raise RuntimeError("unknown shared CalendarInputAttempt port")
    calendar_types = """
    private static final class CalendarLegacyEvents {
        private CalendarLegacyEvents(){throw new AssertionError("calendar event tracker is outside this legacy fixture");}
        void event(int display,int window,String packageName,boolean content,boolean typed){throw new AssertionError("no calendar event tracker in legacy fixture");}
    }
    public static final class CalendarFreshObservation {
        private final CalendarLegacyEvents inputEvents=null;
        private CalendarFreshObservation(){throw new AssertionError("calendar publication is outside this legacy fixture");}
        void requireBound(NativeAppSession.CalendarFreshRead read)throws Exception{throw new AssertionError("no calendar publication authority");}
        NativeCalendarDateEnvelope readEnvelope(NativeAppSession.CalendarFreshRead read)throws Exception{throw new AssertionError("no calendar publication authority");}
        java.util.Map<String,Object> evidence(){throw new AssertionError("no calendar publication evidence");}
        org.trillionnium.hepta.local.PhoneObservation observationFor(LocalTaskController controller,NativeAppSession.CalendarFreshRead read)throws Exception{throw new AssertionError("no calendar publication authority");}
        org.trillionnium.hepta.local.PhoneObservation observationForAction(HeptaAccessibilityService actual,LocalTaskController controller,NativeAppSession.CalendarFreshRead read){throw new AssertionError("no calendar action authority");}
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
    after = before[:-len(ending)] + extension + ending
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
    for name, text in (("VlmInferenceAdapter.java", model_port), ("RuntimeInferenceAdapter.java", runtime_port), ("LocalTaskController.java", controller_port)):
        path = service_port.parent / name
        if path.exists():
            if path.read_bytes() != text.encode("utf-8"):
                raise RuntimeError("existing calendar legacy model/controller port differs")
        else:
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



def prepare(source, output, extra_tests=()):
    """Return (actual compile paths, provenance) in a fresh output directory.

    `extra_tests` are explicit Path values.  Both old complete fixture classes
    are always included, so callers can reuse their synthetic setup without
    manufacturing permission-bearing Session, Offer, or Attempt objects.
    """
    source, output = Path(source).resolve(), Path(output).resolve()
    if output.exists():
        raise RuntimeError("host closure output must be fresh")
    output.mkdir(parents=True, mode=0o700)
    query_path = source / "tests/web-flight/run_query_host_tests.py"
    background_path = source / "tests/background-session/prepare_fixture.py"
    query = module(query_path, "native_search_query_closure")
    background = module(background_path, "native_search_background_closure")
    bgfiles, extraction = background.prepare(source, output / "ports", include_terminal=False)
    # The original Android ports are retained; JSON semantics come from the
    # independently pinned actual org.json jar, not a capability-shaped stub.
    bgfiles = [p for p in bgfiles if not (p.parent.name == "json" and p.parent.parent.name == "org")]
    config_path = output / "ports/org/trillionnium/hepta/local/QualificationScopeConfig.java"
    config_source = source / "src/org/trillionnium/hepta/local/QualificationScopeConfig.java"
    actual_completion = query.java_block(config_source.read_bytes(), "static final class CompletionInstalledIdentity {")
    config = config_path.read_text()
    if not config.endswith("}\n") or "CompletionInstalledIdentity" in config:
        raise RuntimeError("nonunique original complete identity fixture")
    # Same refusing ordinary-PackageManager endpoints as run_native_host.py.
    ports = '''
    private static final class Installed {
        String packageName,apkSetSha256;int uid;long version;
        Map<String,Apk> apks;
        static Installed capture(Context c,String pkg){throw new AssertionError("ordinary PackageManager fallback forbidden in profile gate");}
        void verify(Context c){throw new AssertionError("ordinary installation verifier forbidden in profile gate");}
    }
    private static final class Apk {String sha256;}
'''
    config_path.write_text(config[:-2].replace("import java.io.File;", "import java.io.File;import java.util.*;")
                           + actual_completion + "\n" + ports + "}\n")
    calculator = output / "ports/org/trillionnium/hepta/local/CalculatorGoalContract.java"
    calculator.write_text('package org.trillionnium.hepta.local;final class CalculatorGoalContract {static final String PACKAGE="com.google.android.calculator";}\n')
    bgfiles.append(calculator)
    fixture_source = source / "tests/background-session/BackgroundSessionHostTest.java"
    signatures = ("static Object invoke(", "static JSONObject decode(", "static byte[] frame(",
                  "static JSONObject policy(", "static byte[] response(")
    fixture_methods = [query.java_block(fixture_source.read_bytes(), s) for s in signatures]
    client = output / "ports/org/trillionnium/hepta/local/ProfileClientPort.java"
    client.write_text("package org.trillionnium.hepta.local;\nimport java.io.*;import java.lang.reflect.*;"
                      "import java.nio.charset.StandardCharsets;import java.util.*;import org.json.*;"
                      "import android.os.SystemClock;\nfinal class ProfileClientPort {\n"
                      + "\n".join(fixture_methods) + "\n}\n")
    bgfiles.append(client)
    # Session.acceptOutcome consumes the entire actual production result type.
    # Only its containing Android service is absent from this pure consumer gate.
    service_source = source / "src/org/trillionnium/hepta/local/HeptaAccessibilityService.java"
    outcome = query.java_block(service_source.read_bytes(), "public static final class ActionOutcome {")
    service_path = output / "ports/org/trillionnium/hepta/local/HeptaAccessibilityService.java"
    service = service_path.read_text()
    if not service.endswith("}") or "class ActionOutcome" in service or "class NativeSearchSamplingExhaustionProof" in service:
        raise RuntimeError("nonunique original service IO port")
    no_effect_port = """
    static final class NativeSearchSamplingExhaustionProof {
        private NativeSearchSamplingExhaustionProof(){throw new AssertionError("No Android sampling successor proof in pure Session gate");}
        void close(){throw new AssertionError("No Android sampling successor authority in pure Session gate");}
    }
    static final class NativeSearchFinalCensusResampleProof {
        private NativeSearchFinalCensusResampleProof(){throw new AssertionError("actual final-census producer unavailable in this pure gate");}
        void consume(NativeSearchSession.Attempt attempt,NativeSearchRole role,long now){throw new AssertionError("no final-census replacement authority");}
    }
    static final class NativeSearchNoEffectReplanProof {
        private NativeSearchNoEffectReplanProof(){throw new AssertionError("Android no-effect successor proof is unavailable in this pure consumer gate");}
        void requireOriginal(NativeSearchSession session,NativeSearchSession.Attempt attempt,long now,boolean closed){throw new AssertionError("No Android no-effect proof in pure Session gate");}
        void requireOutcome(ActionOutcome outcome){throw new AssertionError("No Android no-effect proof in pure Session gate");}
        void requirePublishedPlanning(NativeSearchSession session,NativeSearchPlanning planning){throw new AssertionError("No Android no-effect proof in pure Session gate");}
        java.util.Map<String,Object> evidence(){throw new AssertionError("No Android no-effect proof in pure Session gate");}
    }
"""
    service_path.write_text(service[:-1].replace("package org.trillionnium.hepta.local;",
                            "package org.trillionnium.hepta.local;import org.json.JSONObject;")
                            + "\n" + outcome + "\n"
                            + "static final class NativeSearchReadRetryProof { private NativeSearchReadRetryProof(){throw new AssertionError(\"Android initial-read proof is unavailable in this pure consumer gate\");} }\n" + no_effect_port + "}\n")
    calendar_paths, calendar_boundary = calendar_legacy_closure(source, service_path)
    actual_calendar_names = {p.name for p in calendar_paths if source in p.parents}
    actual_calendar_names.add("NativeAppSession.java")
    # These generated type-only declarations are replaced by the full actual classes.
    # Every other original Android/background port remains the original file.
    bgfiles = [p for p in bgfiles if not (p.parent == service_path.parent and p.name in actual_calendar_names)]
    excluded = {"tests/web-flight/WebFlightQueryHostTest.java", "tests/native-app/legacy-boundary/NativeAppSession.java"}
    paths = [source / p for p in query.PURE_PATHS if p not in excluded] + bgfiles
    paths += [source / ("src/org/trillionnium/hepta/local/" + name + ".java") for name in (
        "ObservationCaptureEvidence", "PromptActionDomain", "NativeAppEvidence", "NativeAppDomain", "NativeAppSession",
        "NativeActionSnapshotCheck", "NativeAppObservation", "NativeCtripFlightPage", "NativeXiaomiProductPage",
        "ActionExecutionState", "NativeSearchRole", "NativeSearchPlanning", "NativeSearchDecision", "NativeSearchSession")]
    paths += [source / "tests/xiaomi-profile/NativeProfileIdentityHostTest.java",
              source / "tests/native-action-integration/NativeActionSnapshotCheckHostTest.java"]
    paths += calendar_paths
    paths += list(map(Path, extra_tests))
    paths = list(dict.fromkeys(p.resolve() for p in paths))
    originals = [p for p in paths if source in p.parents] + [
        config_source, fixture_source, service_source, query_path, background_path, Path(__file__).resolve()]
    originals = list(dict.fromkeys(p.resolve() for p in originals))
    provenance = {
        "schema": "hepta.native-search-shared-host-closure.v1",
        "source": str(source), "production_inputs": [record(p) for p in originals],
        "compile_inputs": [record(p) for p in paths], "background_fixture": extraction,
        "calendar_legacy_boundary": calendar_boundary,
        "exact_completion_installed_identity_sha256": sha(actual_completion.encode()),
        "exact_actual_action_outcome_sha256": sha(outcome.encode()),
        "android_no_effect_successor_proof_available": False,
        "android_no_effect_successor_proof_port": "Unconstructible, all four authority methods refuse; no typed producer success is claimed here.",
        "client_port_methods": [{"signature": s, "sha256": sha(v.encode())} for s, v in zip(signatures, fixture_methods)],
        "boundary": "Full actual Session, Offer, Attempt, Role, Planning, authorization, selection and provider classes. Existing Android socket/display/clock ports are synthetic; ordinary PM/root recovery ports refuse. Actual ActionOutcome is copied byte-for-byte. This is not an Android producer, phone effect or business-success proof.",
        "phone_actions": 0, "device_qualified": False, "business_verified": False}
    return paths, provenance
