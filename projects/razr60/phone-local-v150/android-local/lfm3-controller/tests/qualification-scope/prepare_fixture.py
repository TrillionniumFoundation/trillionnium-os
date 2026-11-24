"""Exact production dispatch/controller/config/UI code with explicit Android IO fakes.

No phone, model inference, Android runtime, OS permission or durable fsync claim.
The fake effect APIs count every actual production call; policy is not reimplemented.
"""
import ast
import hashlib
import json
import re
import types
from pathlib import Path


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError(f'nonunique production extraction anchor: {start}')
    i = text.index(start)
    return text[i:text.index(end, i)]


JAVA_TOKENS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\r\n]*|/\*.*?\*/|[{}]', re.S)


def java_method(text, signature):
    """Copy one complete method verbatim; adjacent UI methods are never included."""
    if text.count(signature) != 1 or not signature.endswith('{'):
        raise RuntimeError(f'nonunique complete method signature: {signature}')
    start = text.index(signature)
    opening = start + len(signature) - 1
    depth = 0
    for token in JAVA_TOKENS.finditer(text, opening):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if depth == 0:
                end = token.end()
                if text[end:end + 1] == '\n':
                    end += 1
                return text[start:end]
    raise RuntimeError(f'unclosed production method: {signature}')


def prepare(source, output):
    source, output = Path(source), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    pkg = source / 'src/org/trillionnium/hepta/local'
    s = (pkg / 'HeptaAccessibilityService.java').read_text()
    pieces = {
        'service_interfaces_outcome': section(s, '    public interface ObservationCallback', '    private static volatile HeptaAccessibilityService live;'),
        'web_binding': section(s, '    synchronized void bindWebFlightSession(', '    synchronized void bindBackgroundSession('),
        'background_binding': section(s, '    synchronized void bindBackgroundSession(', '    private void refreshApps()'),
        'app_catalogue': section(s, '    public AppCatalogueRanker.Page appCatalogue(', '    private String diagnosticTask;'),
        'lease': section(s, '    public synchronized boolean acquireTask(', '    private boolean locked()'),
        'background_lock': section(s, '    private boolean locked(BackgroundSession background)', '    private int rotation('),
        # Keep each original dispatch method verbatim. The new native bridge is
        # executed by its separate gate; this non-native fixture has throwing endpoints.
        'scope_validate_dispatch': (section(s, '    synchronized void bindQualificationScope(', '    private void requireNativeActionGuard(')
                                    + section(s, '    private String validate(', '    private void coordinateClick(')),
        'search_entry_precheck': section(s, '    private static boolean nativeSearchEntryGuard(', '    private Map<String,Object> compareNativeAction('),
        'node_graph': section(s, '    private static boolean hasAction(', '    /** Inspect window metadata only.'),
        # Preserve each legacy-tested production method byte-for-byte; the new
        # helper-only live-region implementation has a throwing type boundary below.
        'node_identity': (section(s, '    private static String nodeSignature(', '    private NativeRegionCheck requireLiveNativeRegion(')
                          + section(s, '    private static void requireSubmitWindow(', '    private static String fileSha256(')),
        'strings': section(s, '    private static String string(', '\n}'),
    }
    # The exact lease cleanup now also retires a pending post-effect read.
    # Keep both actual cleanup methods and their lock/state declarations. This
    # legacy carrier never starts an observer or constructs/registers a pending
    # retry; its private type is only the fields consumed by the real cleanup.
    post_effect_cleanup = section(s,
        '    private final Object postEffectSamplingLock=new Object();',
        '    private void notePostEffectSamplingEvent(')
    post_effect_cleanup_ports = '''    private static final class PostEffectSamplingRetry {
        final String taskId=null;
        boolean invalidated,closed;
        private PostEffectSamplingRetry(){
            throw new UnsupportedOperationException("No post-effect observer or retry authority in legacy qualification fixture");
        }
    }
'''
    # This legacy fixture executes the actual native mode admission and every
    # original dispatch method. Its observation IO has no asynchronous worker.
    # Exclude only the adjacent AX request/census/worker/publication block;
    # the separate native-ax-observation gate executes those exact methods.
    ax_observer_only = section(s,
        '    private synchronized void bindNativeAxObservationRequest(',
        '    synchronized TaskAuthorization.Gate bindTaskAuthorization(')
    ax_mode_binding = section(s,
        '    /** Native text capture mode is bound once',
        '    private synchronized void bindNativeAxObservationRequest(')
    if pieces['scope_validate_dispatch'].count(ax_observer_only) != 1:
        raise RuntimeError('one complete AX observer-only block in legacy dispatch extraction')
    pieces['scope_validate_dispatch'] = pieces['scope_validate_dispatch'].replace(ax_observer_only, '', 1)
    if pieces['scope_validate_dispatch'].count(ax_mode_binding) != 1:
        raise RuntimeError('actual native AX mode admission must remain byte-identical')
    # The new typed search observer/dispatcher has its own actual-method gate.
    # Keep every old method, actual AX admission and actual legacy-read gate exact.
    search_observer_only=section(s,
        '    /** A separate historical planning channel. It never writes current/currentGraph. */',
        '    /** Native text capture mode is bound once')
    search_dispatch_only=section(s,
        '    private volatile SearchActionWork activeSearchAction;',
        '    private final class ActionWork {')
    for block in (search_observer_only,search_dispatch_only):
        if pieces['scope_validate_dispatch'].count(block)!=1:
            raise RuntimeError('one exact typed-search-only block in old Service extraction')
        pieces['scope_validate_dispatch']=pieces['scope_validate_dispatch'].replace(block,'',1)
    search_legacy_gate=java_method(s,'    private boolean nativeSearchAllowsLegacyObservation(String taskId){')
    search_retire=java_method(s,'    private void retireNativeSearch(String taskId,String reason){')
    search_raw=(pkg/'NativeSearchSession.java').read_text()
    search_eligible=java_method(search_raw,'    static boolean eligible(NativeAppSession task){')
    search_boundaries=source/'tests/native-app/legacy-boundary/search-controller'
    for name in ('NativeSearchSession','NativeSearchPlanning'):
        raw=(search_boundaries/(name+'.template')).read_text()
        if name=='NativeSearchSession':
            if raw.count('{{actual_eligible}}')!=1:raise RuntimeError('one exact native-search eligibility port')
            raw=raw.replace('{{actual_eligible}}',search_eligible,1)
        (output/(name+'.java')).write_text(raw)
    search_io_ports='''    // Permanently absent typed workers; all constructors and effect endpoints refuse.
    private volatile NativeSearchSession nativeSearchSession;
    private volatile NativeSearchRequest activeNativeSearchObservation;
    private volatile NativeSearchRequest nativeSearchRetryPending;
    private volatile NativeSearchRequest nativeSearchModalPending;
    private final NativeSearchRequest nativeSearchSamplingTracked=null;
    private final java.util.concurrent.atomic.AtomicBoolean observationIoBusy=new java.util.concurrent.atomic.AtomicBoolean(false);
    private volatile SearchActionWork activeSearchAction;
    private final Object nativeSearchEventLock=new Object();
    private volatile SearchActionWork nativeSearchTrackedAction;
    private boolean nativeSearchPlanningAdmitted;
    private static final class NativeSearchRequest {
        final String taskId=null;
        private NativeSearchRequest(){throw new AssertionError("No typed planning request in old fixture");}
    }
    static final class NativeSearchReadRetryProof {
        private NativeSearchReadRetryProof(){throw new AssertionError("No initial planning retry capability in old fixture");}
        void requireOriginal(HeptaAccessibilityService service,Object controller,NativeSearchSession session,String task,File directory,long deadline){throw new AssertionError("No initial planning retry authority in old fixture");}
        java.util.Map<String,Object> evidence(){throw new AssertionError("No initial planning retry evidence in old fixture");}
    }
    static final class NativeSearchSamplingExhaustionProof {
        private NativeSearchSamplingExhaustionProof(){throw new AssertionError("No sampling successor proof in old fixture");}
        void requireOriginal(Object service,Object controller,NativeSearchSession session,String task,File directory,long deadline){throw new AssertionError("No sampling successor read authority in old fixture");}
        java.util.Map<String,Object> evidence(){throw new AssertionError("No sampling successor evidence in old fixture");}
        void close(){throw new AssertionError("No sampling successor authority in old fixture");}
    }
    private void closeNativeSearchSampling(NativeSearchRequest request){throw new AssertionError("No sampling history tracker in old fixture");}
    static final class NativeSearchNoEffectReplanProof {
        private NativeSearchNoEffectReplanProof(){throw new AssertionError("No no-effect successor proof in old fixture");}
        void requireOriginal(NativeSearchSession session,NativeSearchSession.Attempt attempt,long now,boolean closed){throw new AssertionError("No no-effect successor authority in old fixture");}
        void requireOutcome(ActionOutcome outcome){throw new AssertionError("No no-effect successor outcome in old fixture");}
        void requirePublishedPlanning(NativeSearchSession session,NativeSearchPlanning planning){throw new AssertionError("No no-effect successor publication in old fixture");}
        void requireReadTarget(HeptaAccessibilityService service,Object controller,NativeSearchSession session,String task,File directory,long deadline){throw new AssertionError("No no-effect successor read in old fixture");}
        java.util.Map<String,Object> evidence(){throw new AssertionError("No no-effect successor evidence in old fixture");}
    }
    private static final class SearchActionWork {
        final ActionExecutionState state=null;
        final NativeSearchSession session=null;
        private SearchActionWork(){throw new AssertionError("No typed action work in old fixture");}
    }
    synchronized void bindNativeSearchSession(NativeSearchSession session){throw new AssertionError("No typed Session binding in old fixture");}
    synchronized Map<String,Object> beginNativeSearchImageModalPrelude(Object controller,NativeSearchSession session,File directory,long deadline){throw new AssertionError("No image-modal read handoff in old fixture");}
    synchronized void prepareNativeSearchAfterImageModal(Object controller,NativeSearchSession session,ActionDecision action,String run){throw new AssertionError("No image-modal Back or home planning authority in old fixture");}
    void observeNativeSearchPlanning(String task,File directory,NativeSearchSession session,Cancellation cancel,long deadline,NativeSearchSession.ObservationCallback callback){throw new AssertionError("No typed planning IO in old fixture");}
    void observeNativeSearchPlanning(String task,File directory,NativeSearchSession session,Cancellation cancel,long deadline,NativeSearchSession.ObservationCallback callback,NativeSearchReadRetryProof retry){throw new AssertionError("No typed planning recovery IO in old fixture");}
    void observeNativeSearchPlanningAfterNoEffect(String task,File directory,NativeSearchSession session,Cancellation cancel,long deadline,NativeSearchSession.ObservationCallback callback,NativeSearchNoEffectReplanProof successor){throw new AssertionError("No typed successor planning IO in old fixture");}
    void observeNativeSearchPlanningAfterSamplingExhaustion(String task,File directory,NativeSearchSession session,Cancellation cancel,long deadline,NativeSearchSession.ObservationCallback callback,NativeSearchSamplingExhaustionProof successor){throw new AssertionError("No sampling successor planning IO in old fixture");}
    void performNativeOpenSearch(String task,NativeSearchSession.Attempt attempt,Cancellation cancel,NativeSearchSession.ActionCallback callback){throw new AssertionError("No typed effect IO in old fixture");}
    private void finishNativeSearchObservation(NativeSearchRequest request,NativeSearchPlanning planning,String error){throw new AssertionError("No typed publication in old fixture");}
'''+search_legacy_gate+search_retire
    # These newly added methods only belong to the separate real calendar gates.
    # Remove their complete bodies from the old Service carrier and supply only
    # impossible typed endpoints. Every pre-existing dispatch method stays exact.
    calendar_source_only=java_method(s,
        '    void requireNativeCalendarSourceOwnership(LocalTaskController controller,NativeAppSession nativeTask,\n'
        '            BackgroundSession background,PhoneObservation observed,long taskDeadline){')
    calendar_action_only=section(s,
        '    interface CalendarActionCallback {void onResult(CalendarActionResult result);}',
        '    public void perform(final String taskId,final PhoneObservation expected,final ActionDecision decision,\n'
        '                        final ObservedTargetLabels targets,final TaskAuthorization.Gate expectedAuthorization,final String modelRunId,\n'
        '                        final Cancellation cancel,final ActionCallback callback){')
    for excluded in (calendar_source_only,calendar_action_only):
        if sum(value.count(excluded) for value in pieces.values())!=1:
            raise RuntimeError('one exact new calendar-only block in old Service carrier')
        for name,value in list(pieces.items()):
            if excluded in value:pieces[name]=value.replace(excluded,'',1)
    calendar_io_ports='''    // This legacy fixture has no calendar pixel, model, action or selection producer.
    interface CalendarFreshCallback {
        void onFresh(CalendarFreshObservation proof);
        void onError(String detail);
        default void onDiagnostic(java.util.concurrent.Callable<String> snapshot) {}
        default void onPrivateCensusDiagnostic(java.util.concurrent.Callable<String> snapshot) {}
    }
    static final class CalendarFreshObservation {
        private CalendarFreshObservation(){throw calendarUnavailable();}
        PhoneObservation observationFor(LocalTaskController controller,NativeAppSession.CalendarFreshRead read){throw calendarUnavailable();}
    }
    interface CalendarActionCallback {void onResult(CalendarActionResult result);}
    static final class CalendarActionResult {
        final ActionOutcome outcome=null;
        private CalendarActionResult(){throw calendarUnavailable();}
        java.util.Map<String,Object> evidence(){throw calendarUnavailable();}
    }
    static final class CalendarSelectionObservation {
        private CalendarSelectionObservation(){throw calendarUnavailable();}
    }
    void requireNativeCalendarSourceOwnership(LocalTaskController controller,NativeAppSession task,
            BackgroundSession background,PhoneObservation observed,long deadline){throw calendarUnavailable();}
    void observeNativeCalendarFresh(LocalTaskController controller,NativeAppSession.CalendarFreshRead read,
            File directory,Cancellation cancel,long deadline,CalendarFreshCallback callback){throw calendarUnavailable();}
    void performNativeCalendarDate(LocalTaskController controller,NativeAppSession.CalendarPermit permit,
            Cancellation cancel,CalendarActionCallback callback){throw calendarUnavailable();}
    CalendarSelectionObservation calendarSelectionObservation(LocalTaskController controller,NativeAppSession.CalendarPermit permit,
            CalendarActionResult result,PhoneObservation observed,File directory){throw calendarUnavailable();}
    private static UnsupportedOperationException calendarUnavailable(){
        return new UnsupportedOperationException("No calendar producer or authority in legacy qualification fixture");
    }
'''
    calendar_nas_ports='''    /** Calendar ABI only. Constructors and every authority endpoint always refuse. */
    interface CalendarModelSignal {
        void onModelReady();
        void onModelFailure(String detail,boolean cleanup);
    }
    static final class CalendarOffer implements AutoCloseable {
        final NativeAppSession session=null;
        final NativeCalendarDateEnvelope source=null;
        final NativeCalendarDateProtocol protocol=null;
        final LocalInference inference=null;
        final LocalRuntimeConfig runtime=null;
        final long taskDeadlineElapsed=-1;
        final java.time.LocalDate priorObservedFormDate=null;
        private CalendarOffer(){throw unavailable();}
        DecisionGrammar grammar(){throw unavailable();}
        void claimGrammar(TaskAuthorization.Frame frame){throw unavailable();}
        VlmInferenceAdapter.AcceptedRequestCallback modelCallback(CalendarModelSignal signal){throw unavailable();}
        CalendarModelRequest registerModelReply(){throw unavailable();}
        public void close(){throw unavailable();}
    }
    static final class CalendarModelRequest {
        private CalendarModelRequest(){throw unavailable();}
        String modelRunId(){throw unavailable();}
        String rawText(){throw unavailable();}
        Map<String,Object> intentEvidence(){throw unavailable();}
        CalendarFreshRead beginFreshObservation(BackgroundSession background){throw unavailable();}
    }
    static final class CalendarFreshRead implements AutoCloseable {
        final NativeAppSession session=null;
        final BackgroundSession background=null;
        final long deadlineElapsed=-1;
        private CalendarFreshRead(){throw unavailable();}
        void requireOriginal(NativeAppSession session,BackgroundSession background){throw unavailable();}
        CalendarPermit acceptFreshObservation(HeptaAccessibilityService.CalendarFreshObservation proof){throw unavailable();}
        public void close(){throw unavailable();}
    }
    static final class CalendarPermit implements AutoCloseable {
        final long deadlineElapsed=-1;
        private CalendarPermit(){throw unavailable();}
        NativeAppSession session(){throw unavailable();}
        BackgroundSession background(){throw unavailable();}
        void requireSelectionPublication(HeptaAccessibilityService.CalendarActionResult result,long now){throw unavailable();}
        void claimSelectionRead(HeptaAccessibilityService.CalendarActionResult result){throw unavailable();}
        CalendarSelectionEvidence acceptSelection(HeptaAccessibilityService.CalendarSelectionObservation proof){throw unavailable();}
        public void close(){throw unavailable();}
    }
    static final class CalendarSelectionEvidence {
        final String recordSha256=null;
        private CalendarSelectionEvidence(){throw unavailable();}
        Map<String,Object> evidence(){throw unavailable();}
    }
    CalendarOffer offerCalendarDate(NativeCalendarDateEnvelope envelope,LocalInference inference,
            NativeCalendarDateProtocol.Clock clock,long deadline){throw unavailable();}
'''
    calendar_nas_source=source/'tests/native-app/legacy-boundary/NativeAppSession.java'
    calendar_nas_raw=calendar_nas_source.read_text()
    calendar_nas_anchor='    private static UnsupportedOperationException unavailable(){'
    if calendar_nas_raw.count(calendar_nas_anchor)!=1:
        raise RuntimeError('one original refusing native Session boundary')
    (output/'NativeAppSession.java').write_text(
        calendar_nas_raw.replace(calendar_nas_anchor,calendar_nas_ports+calendar_nas_anchor,1))
    (output/'VlmInferenceAdapter.java').write_text('''package org.trillionnium.hepta.local;
/** Callback type only; no Adapter, accepted request or model can be constructed. */
final class VlmInferenceAdapter {
    private VlmInferenceAdapter(){throw new UnsupportedOperationException("No calendar Adapter in legacy qualification fixture");}
    interface AcceptedRequestCallback extends LocalInference.Callback {}
}
''')
    fixture = (Path(__file__).parent / 'ServiceFixture.template').read_text()
    marker='{{service_interfaces_outcome}}\n'
    if fixture.count(marker)!=1:raise RuntimeError('one legacy Service interface boundary')
    fixture=fixture.replace(marker,marker+search_io_ports+calendar_io_ports+post_effect_cleanup_ports+post_effect_cleanup,1)
    for name, code in pieces.items():
        fixture = fixture.replace('{{' + name + '}}', code)
    if '{{' in fixture:
        raise RuntimeError('unfilled service fixture template')
    (output / 'HeptaAccessibilityService.java').write_text(fixture)
    snapshot_parts = {
        'stale_type': section(s, '    /** Only freshness failures before an effect', '    /** Rechecks the complete original scope'),
        'graph_limits': section(s, '    private static final int MAX_NODES=', '\n    private final Map<String,String> launchable='),
        'node_graph': pieces['node_graph'],
        'window_metadata': section(s, '    /** Read only the selected root\'s window metadata;', '    private List<AccessibilityWindowInfo> windowsForDisplay('),
        'snapshot': section(s, '    /** A background root comes only', '    private FlightNativeCheck requireLiveFlightNativeStability('),
        'node_identity': pieces['node_identity'],
        'strings': pieces['strings'],
    }
    # The legacy collector fixture has no asynchronous observer/request endpoint.
    # Exclude only the two new observer-specific helpers; all original collector,
    # root selection, census and action bodies remain exact. The snapshot gate
    # executes the pure policy and pins/checks the live Android adapter separately.
    observer_only = section(s,
        '    /** Pure copy from the original complete read; partial/action graphs cannot enter this path. */',
        '    /** Only metadata of all reported windows on the selected display. No other')
    if snapshot_parts['snapshot'].count(observer_only) != 1:
        raise RuntimeError('one observer-only helper block in collector fixture')
    snapshot_parts['snapshot'] = snapshot_parts['snapshot'].replace(observer_only, '', 1)
    fixture = (Path(__file__).parent / 'BackgroundObservationFixture.template').read_text()
    for name, code in snapshot_parts.items():fixture=fixture.replace('{{'+name+'}}',code)
    if '{{' in fixture:raise RuntimeError('unfilled background snapshot fixture')
    (output / 'BackgroundObservationFixture.java').write_text(fixture)
    # The unchanged background guard now uses the production canonical comparator.
    # Extract its actual two pure methods, not a permissive equality stub.
    web_protocol = source/'src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java'
    binding_path = source/'src/org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java'
    receipt_path = pkg/'WebEvidenceReceipt.java'
    binding_raw, receipt_raw = binding_path.read_text(), receipt_path.read_text()
    comparison_parts = {
        'binding_canonical': section(binding_raw, '    public static String canonical(', '\n}'),
        'receipt_same': section(receipt_raw, '    static boolean same(', '    static String decode('),
    }
    (output/'WebEvidenceBinding.java').write_text("package org.trillionnium.hepta.webprotocol;\nimport org.json.JSONArray;\nimport org.json.JSONObject;\nimport java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.Iterator;\n/** Exact production canonical comparison only; no binding, helper or lease construction. */\npublic final class WebEvidenceBinding {\n    private WebEvidenceBinding(){throw new AssertionError(\"comparison-only fixture\");}\n" + comparison_parts['binding_canonical'] + '\n}\n')
    (output/'WebEvidenceReceipt.java').write_text("package org.trillionnium.hepta.local;\nimport org.trillionnium.hepta.webprotocol.WebEvidenceBinding;\n/** Exact production comparison only; no receipt or helper authority. */\nfinal class WebEvidenceReceipt {\n    private WebEvidenceReceipt(){throw new AssertionError(\"comparison-only fixture\");}\n" + comparison_parts['receipt_same'] + '}\n')
    (output/'WebRegionNativeBridge.java').write_text("package org.trillionnium.hepta.local;\n/** Type-only legacy non-Web boundary. No native region evidence or role snapshot can be created. */\nfinal class WebRegionNativeBridge {\n    final PhoneObservation.Node anchor=null;\n    final String nativeWebViewId=null;\n    static final class Role {\n        final String nodeId=null;\n        private Role(){throw new AssertionError(\"legacy fixture has no native role capability\");}\n    }\n    java.util.List<Role> roles(){throw new AssertionError(\"legacy fixture cannot expose native roles\");}\n    private WebRegionNativeBridge(){throw new AssertionError(\"legacy fixture has no Web native-region capability\");}\n}\n")
    flight_stability_path=pkg/'WebFlightNativeStability.java'
    flight_stability_raw=flight_stability_path.read_text()
    flight_limit=section(flight_stability_raw, '    static final int MAX_NATIVE_NODES=', '    private WebFlightNativeStability()')
    (output/'WebFlightNativeStability.java').write_text("package org.trillionnium.hepta.local;\n/** Type-only legacy boundary: exact production collection limit, no Flight permit construction. */\nfinal class WebFlightNativeStability {\n"+flight_limit+"    static final class Permit {\n        private Permit(){throw new AssertionError(\"legacy fixture has no Flight stability permit\");}\n    }\n    private WebFlightNativeStability(){throw new AssertionError(\"legacy fixture has no Flight capability\");}\n}\n")
    shopping_stability_path=pkg/'WebShoppingObservationStability.java'
    shopping_raw=shopping_stability_path.read_text()
    shopping_limit=[line for line in shopping_raw.splitlines(keepends=True) if line.startswith('    static final int MAX_NATIVE_NODES=')]
    if len(shopping_limit)!=1:raise RuntimeError('one exact production shopping collection bound required')
    (output/'WebShoppingObservationStability.java').write_text("package org.trillionnium.hepta.local;\n/** Type-only non-Web boundary: exact collection limit, no shopping read or completion authority. */\nfinal class WebShoppingObservationStability {\n"+shopping_limit[0]+"    private WebShoppingObservationStability(){throw new AssertionError(\"legacy fixture has no shopping read capability\");}\n}\n")
    session = (pkg / 'LocalTaskSession.java').read_text()
    session_parts = {
        'schedule': section(session, '    public boolean schedule(final String owner,String source,String testNonceSha,long delayMillis)', '    /** The only caller is the positive button'),
        'persist': section(session, '    private void persist(', '\n}'),
        'parse_record': section(session, '    private static JSONObject parseSessionJson(', '    private static Map<String,Object> fieldsOf('),
        'record_exists': section(session, '    private static boolean recordExists(', '    /** Create once; never unlink'),
        'read_record': section(session, '    private static byte[] readSessionRecord(', '    private JSONArray archivePriorRecords('),
    }
    # The legacy session fixture executes the original task/terminal methods.
    # The new read-only model-settings admission is covered by its separate gate;
    # do not fabricate recovery/journal permission endpoints in this fixture.
    session_settings_only = section(session,
        '    /** Read-only settings admission. Reuses the ordinary startup/terminal policy without acknowledging it. */',
        '    private LeaseState readLeaseState(){')
    if session_parts['persist'].count(session_settings_only) != 1:
        raise RuntimeError('one model-settings-only helper block in legacy session fixture')
    session_parts['persist'] = session_parts['persist'].replace(session_settings_only, '', 1)
    fixture = (Path(__file__).parent / 'SessionFixture.template').read_text()
    for name, code in session_parts.items():fixture=fixture.replace('{{'+name+'}}',code)
    (output / 'LocalTaskSession.java').write_text(fixture)
    ui = (pkg / 'MainActivity.java').read_text()
    ui_methods = {
        signature: java_method(ui, signature) for signature in (
            '    @Override protected void onSaveInstanceState(Bundle state){',
            '    private void restoreScopeUi(Bundle state){',
            '    private void acceptScopePrefill(Intent intent,String task,String expected,boolean hasExpected,boolean autoTask){',
            '    private void handleIntent(Intent intent){',
            '    private boolean beginTask(String owner,String source,String nonceSha){',
        )
    }
    ui_parts = {
        'binding': ''.join(list(ui_methods.values())[:3]),
        'intent_start': ''.join(list(ui_methods.values())[3:]),
    }
    # Every original binding/Intent/beginTask body is copied in full. Separately
    # declared file-picker/settings UI is outside this legacy fixture's scope.
    ui_settings_only = ''.join(java_method(ui, signature) for signature in (
        '    private void chooseLocalModelFromOwnerButton(){',
        '    private void restoreLocalModelFromOwnerButton(){',
        '    @Override public void onLocalModelSettingsChanged(){',
    ))
    ui_import_only = ''.join(java_method(ui, signature) for signature in (
        '    private void chooseModelFileFromOwnerButton(){',
        '    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){',
        '    @Override public void onLocalModelImportChanged(){',
    ))
    fixture = (Path(__file__).parent / 'UiFixture.template').read_text()
    # The legacy scope fixture has no actual Activity/physical identity.
    # Null keeps its existing VD/strict path; the exact capture method has its own gate.
    fixture = fixture.replace('{{intent_start}}',
        '    private org.trillionnium.hepta.background.PublicPermissionControllerUi.Locator controllerUiFromOwnerButton(String owner){return null;}\n{{intent_start}}',1)
    for name,code in ui_parts.items():fixture=fixture.replace('{{'+name+'}}',code)
    (output / 'ScopeUiFixture.java').write_text(fixture)
    # Execute the actual saved-mode default/type check. Only SharedPreferences IO
    # is replaced by a supplied map; no selection, persistence or task authority.
    preferences_raw=(pkg/'BackgroundUiPreferences.java').read_text()
    mode_parts={
        'mode_key':section(preferences_raw, '    private static final String MODE=', '    private static final int MAX_BYTES='),
        'mode':section(preferences_raw, '    static boolean mode(Context context){', '    static void saveMode('),
    }
    (output/'BackgroundModePreferencesFixture.java').write_text(
        'package org.trillionnium.hepta.local;\nimport android.content.Context;\nimport java.util.Map;\n'
        '/** Exact production mode reader; SharedPreferences is explicit host IO. */\n'
        'final class BackgroundModePreferencesFixture {\n'
        '    static Map<String,?> saved;\n'
        '    static final class Preferences {Map<String,?> getAll(){return saved;}}\n'
        '    private static Preferences preferences(Context context){return new Preferences();}\n'
        +mode_parts['mode_key']+mode_parts['mode']+'}\n')
    pure=['NativeXiaomiSearchInputObservation', 'NativeCtripFormObservation', 'ObservationCaptureEvidence', 'BackgroundTaskTarget','NativeAppGoal','NativeAppEvidence','NativeAppDomain','NativeCtripFlightPage','NativeXiaomiProductPage','NativeAppObservation','NotesCreateWorkflow','NotesOwnerIntent','CalculatorTaskInputGuard','CalculatorGoalContract','CalculatorCompletionEvidence','NotesTaskPhaseGuard','TaskCompletionGate','NotesCompletionEvidence','FixedIntentAttemptGuard','LastModelDecisionProjection','TaskAuthorization','ActionDecision','ActionPolicy','ObservedTargetLabels','ObservedScrollActions','ObservedImeEnter','SubmitAttemptGuard','ObservationStabilityGate','RecentActionProjection',
          'PersistentActionPolicy','ImeVisibility','ObservationState','ObservedWindowMetadata','ObservedChildText',
          'RepeatActionGuard','SameStateNoEffectGuard','DecisionGrammar','ModelProfile','LocalRuntimeConfig','VlmPins','VlmResultContract',
          'ConservativeTokenBudget','AppCatalogueRanker','ObservedTextProjection','ObservedTransitionProjection',
          'CompactTaskHistory','PromptActionDomain','RecoveryQuiescence','RecoveryJournalTransaction',
          'QualificationScope','QualificationScopeConfig','MobiMindPrivateFiles','LocalTaskController','LocalInference','PhoneObservation','VisualPromptProjection','MobiMindContract','MobiMindPins',
          'ActionExecutionState','TaskCancellationQueue','SessionJournalQueue','SessionTerminalEvidence','ObservationDiagnostics','NativeActionSnapshotCheck']
    pure += ['NativeCalendarDateEnvelope','NativeCalendarDateIntent','NativeCalendarDateProtocol','UiVenusInputContract','UiVenusPins']
    if (pkg/'ObservedAppLabels.java').is_file():pure.append('ObservedAppLabels')
    files=[pkg/(name+'.java') for name in dict.fromkeys(pure)]
    files += [pkg/'NativeSearchDecision.java']
    web_fixture_source=source/'tests/web-flight/legacy-boundary/WebFlightDomain.java'
    web_fixture_raw=web_fixture_source.read_bytes()
    web_fixture_compile=output/'WebTaskDomain.java'
    web_fixture_compile.write_bytes(web_fixture_raw)
    if web_fixture_compile.read_bytes()!=web_fixture_raw or web_fixture_source.read_bytes()!=web_fixture_raw:
        raise RuntimeError('Exact Web type-boundary compiler copy required')
    web_dom_canonical=source/'src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java'
    files += [pkg/'web/WebFlightGoal.java',pkg/'web/WebShoppingGoal.java',web_protocol,web_dom_canonical,
              source/'tests/web-flight/legacy-boundary/WebShoppingQuote.java']
    files += [source/'src/org/trillionnium/hepta/background'/(name+'.java') for name in ('FixedIntentTools','FixedIntentTarget','FixedIntentDispatch','BrokerProtocol','PublicPermissionControllerUi','PublicOwnGroupPolicy','ProfileIdentity','ProfileTarget','WindowOwnership')]
    # The real immutable Selection is now part of ordinary authorization admission.
    # Replace only that former fixture class; broker/display transport stays explicit IO fake.
    background_raw=(pkg/'BackgroundSession.java').read_text()
    actual_selection=section(background_raw, '    static final class Selection ', '    static final class Cleanup ')
    actual_package_check=section(background_raw, '    private static void checkPackage(', '    private static String join(')
    background_fixture=(Path(__file__).parent/'fixtures/org/trillionnium/hepta/local/BackgroundSession.java').read_text()
    legacy_selection=section(background_fixture, '    static final class Selection ', '    static final class Cleanup ')
    background_fixture=background_fixture.replace(legacy_selection,actual_selection+actual_package_check,1)
    background_fixture=background_fixture.replace('import org.json.JSONObject;', 'import org.json.JSONObject;\nimport org.json.JSONArray;\nimport java.util.*;',1)
    cleanup_marker='static final class Cleanup {'
    if background_fixture.count(cleanup_marker)!=1:raise RuntimeError('one legacy Cleanup type required')
    background_fixture=background_fixture.replace(cleanup_marker,cleanup_marker+'final PublicProfileBusinessRecoveryClient.Receipt businessRecovery=null;',1)
    # These legacy cases never own a checker or a business receipt. Keep the
    # actual Service branches intact, with an impossible typed receipt boundary.
    (output/'PublicProfileBusinessRecoveryClient.java').write_text('''package org.trillionnium.hepta.local;
final class PublicProfileBusinessRecoveryClient {
    private PublicProfileBusinessRecoveryClient(){throw unavailable();}
    static boolean workPending(){return false;} // No checker can be constructed in this fixture.
    static final class Request {
        final String taskId=null,ownerSha256=null;
        private Request(){throw unavailable();}
        String source(){throw unavailable();}
    }
    static final class Receipt {
        final Request request=null;
        private Receipt(){throw unavailable();}
        String receiptSha256(){throw unavailable();}
        void requirePersisted(){throw unavailable();}
        void requireOriginals(boolean leasePresent){throw unavailable();}
    }
    private static UnsupportedOperationException unavailable(){return new UnsupportedOperationException("No business recovery authority in legacy qualification fixture");}
}
''')
    calendar_bg_ports='''    /** No private read-only broker receipt can be constructed by this old fixture. */
    final long expiresElapsed=-1;
    static final class CalendarWindowProbeReceipt {
        final int windowId=-1,observedTaskId=-1;
        final long receivedElapsedMs=-1;
        private CalendarWindowProbeReceipt(){throw calendarUnavailable();}
        boolean belongsTo(BackgroundSession actual){throw calendarUnavailable();}
        boolean grantsDispatch(){throw calendarUnavailable();}
        org.json.JSONObject requestEvidence(){throw calendarUnavailable();}
        org.json.JSONObject evidence(){throw calendarUnavailable();}
    }
    CalendarWindowProbeReceipt readCalendarWindowProbe(int window,int task,
            HeptaAccessibilityService.Cancellation cancel,long deadline){throw calendarUnavailable();}
    private static UnsupportedOperationException calendarUnavailable(){
        return new UnsupportedOperationException("No calendar broker receipt in legacy qualification fixture");
    }
'''
    calendar_bg_anchor='    static final class Selection '
    if background_fixture.count(calendar_bg_anchor)!=1:
        raise RuntimeError('one immutable Selection insertion point for unavailable probe types')
    background_fixture=background_fixture.replace(calendar_bg_anchor,calendar_bg_ports+calendar_bg_anchor,1)
    (output/'BackgroundSession.java').write_text(background_fixture)
    # Native entry validation is extracted verbatim; all Web IO remains throwing.
    web_entry=(pkg/'WebFlightSession.java').read_text()
    web_entry_prefix=section(web_entry, '    static void validateSelection(String owner,BackgroundSession.Selection selection){',
                            '        WebFlightGoal flight=WebFlightGoal.parse(owner);')
    web_io_fixture=(Path(__file__).parent/'fixtures/org/trillionnium/hepta/local/WebFlightSession.java').read_text()
    web_entry_marker='    static void validateSelection(String owner,BackgroundSession.Selection selection){\n'
    if web_io_fixture.count(web_entry_marker)!=1:raise RuntimeError('one legacy Web fixture entry')
    (output/'WebFlightSession.java').write_text(web_io_fixture.replace(web_entry_marker,web_entry_prefix,1))
    files += sorted(output.glob('*.java'))
    files += [p for p in sorted((Path(__file__).parent/'fixtures').rglob('*.java'))
              if p.name not in ('BackgroundSession.java','WebFlightSession.java')]
    files += [Path(__file__).parent/'QualificationScopeHostTest.java',Path(__file__).parent/'BackgroundFreshnessHostTest.java']
    record={'schema':'hepta.scope-host-extraction.v1','source_files':{n:hashlib.sha256((pkg/n).read_bytes()).hexdigest() for n in ['TaskAuthorization.java','HeptaAccessibilityService.java','LocalTaskSession.java','SessionTerminalEvidence.java','MainActivity.java','BackgroundUiPreferences.java','LocalTaskController.java','QualificationScope.java','QualificationScopeConfig.java']},
        'extracted':{n:{'bytes':len(v.encode()),'sha256':hashlib.sha256(v.encode()).hexdigest()} for n,v in {**pieces,**comparison_parts,**session_parts,**ui_parts,**{'preferences_'+n:v for n,v in mode_parts.items()},**{'background_'+n:v for n,v in snapshot_parts.items()}}.items()},
        'full_actual_classes':['TaskCompletionGate','NotesCompletionEvidence','LocalTaskController','QualificationScope','QualificationScopeConfig','MobiMindPrivateFiles','SessionTerminalEvidence'],
        'boundary':'Android IO and effect endpoints are fakes; production admission/dispatch and controller code is executed',
        'native_search_legacy_boundary':{
            'no_effect_successor_proof_constructible':False,
            'no_effect_successor_authority_methods_always_refuse':True,
            'no_effect_successor_tracker_permanently_absent':True,
            'observer_only_sha256':hashlib.sha256(search_observer_only.encode()).hexdigest(),
            'dispatcher_only_sha256':hashlib.sha256(search_dispatch_only.encode()).hexdigest(),
            'actual_eligibility_sha256':hashlib.sha256(search_eligible.encode()).hexdigest(),
            'actual_legacy_read_gate_sha256':hashlib.sha256(search_legacy_gate.encode()).hexdigest(),
            'actual_retire_sha256':hashlib.sha256(search_retire.encode()).hexdigest(),
            'typed_ports_constructible':False,'typed_operations_all_refuse':True,
            'image_modal_pending_permanently_absent':True,
            'image_modal_abi_operations_always_refuse':True,
            'legacy_dispatch_methods_modified':False,
            'covered_by':'tests/native-search-producer/run_producer.py',
            'separate_typed_gate_execution_not_claimed_here':True},
        'native_ax_observer_only_excluded_from_legacy_dispatch':{
            'bytes':len(ax_observer_only.encode()),'sha256':hashlib.sha256(ax_observer_only.encode()).hexdigest(),
            'covered_by':'tests/native-ax-observation/run_host.py',
            'actual_mode_admission_retained':True,
            'actual_mode_admission_sha256':hashlib.sha256(ax_mode_binding.encode()).hexdigest(),
            'legacy_dispatch_methods_modified':False,
            'separate_ax_gate_execution_not_claimed_here':True},
        'observer_helper_excluded_from_legacy_collector':{'bytes':len(observer_only.encode()),'sha256':hashlib.sha256(observer_only.encode()).hexdigest(),'covered_by':'tests/native-observation-snapshot/run_host.py','legacy_collector_methods_modified':False},
        'model_settings_helpers_excluded_from_legacy_fixture':{
            'covered_by':'tests/local-model-settings/run_host.py',
            'session_admission':{'bytes':len(session_settings_only.encode()),'sha256':hashlib.sha256(session_settings_only.encode()).hexdigest()},
            'owner_ui':{'bytes':len(ui_settings_only.encode()),'sha256':hashlib.sha256(ui_settings_only.encode()).hexdigest()},
            'legacy_session_and_intent_methods_modified':False,
            'separate_gate_execution_not_claimed_here':True},
        'ui_exact_methods':{signature:{'bytes':len(code.encode()),'sha256':hashlib.sha256(code.encode()).hexdigest()}
            for signature,code in ui_methods.items()},
        'model_import_helpers_excluded_from_legacy_fixture':{
            'bytes':len(ui_import_only.encode()),'sha256':hashlib.sha256(ui_import_only.encode()).hexdigest(),
            'import_transaction_gate':'tests/offline-model-import/run_host.py',
            'picker_ui_executed_here':False,'production_methods_modified':False,
            'saved_pending_asset_boundary':'nullable String field only; no URI, picker or import authority'},
        'business_recovery_legacy_boundary':{
            'receipt_and_request_constructible':False,'cleanup_receipt_always_null':True,
            'all_authority_operations_refuse':True,'checker_slot_permanently_absent':True,
            'actual_service_admission_and_acceptance_methods_modified':False,
            'recovery_success_or_phone_qualification_claimed':False},
        'personal_notes_recovery_fixture_boundary':'Eligibility is explicitly false and the receipt is always null; this legacy IO fixture cannot create or accept personal Notes recovery authority.',
        'web_fixture_boundary':'Explicit empty Web journal only; real Web OWNER/selection and every helper action/cleanup throw AssertionError; actual Web classes have their separate gate',
        'background_fixture_boundary':'Actual complete immutable Selection and package check extracted verbatim; all broker/display transport remains explicit IO fake and not Android proof',
        'native_validation_prefix_sha256':hashlib.sha256(web_entry_prefix.encode()).hexdigest(),
        'background_selection_source':{'path':'src/org/trillionnium/hepta/local/BackgroundSession.java',
            'sha256':hashlib.sha256(background_raw.encode()).hexdigest(),
            'selection_sha256':hashlib.sha256(actual_selection.encode()).hexdigest(),
            'package_check_sha256':hashlib.sha256(actual_package_check.encode()).hexdigest()},
        'comparison_source_files':{str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (binding_path,receipt_path,web_protocol)},
        'web_native_fixture_boundary':'The original complete dispatch branch is retained; WebRegionNativeBridge, NativeRegionCheck and both WebSession native-region endpoints are throwing type-only boundaries',
        'flight_native_fixture_boundary':'The complete production validate branch remains; all Flight permit/live-check endpoints throw, and the graph freezer uses the actual production WebDomCanonical with the exact production Flight node limit',
        'flight_source_files':{str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (flight_stability_path,web_dom_canonical)},
        'flight_collection_limit':{'bytes':len(flight_limit.encode()),'sha256':hashlib.sha256(flight_limit.encode()).hexdigest()},
        'shopping_collection_limit':{'source':str(shopping_stability_path.relative_to(source)),
            'source_sha256':hashlib.sha256(shopping_stability_path.read_bytes()).hexdigest(),
            'bytes':len(shopping_limit[0].encode()),'sha256':hashlib.sha256(shopping_limit[0].encode()).hexdigest()},
        'web_fixture_compiler_copy':{'source_path':str(web_fixture_source.relative_to(source)),
            'compiler_path':str(web_fixture_compile),'bytes':len(web_fixture_raw),
            'sha256':hashlib.sha256(web_fixture_raw).hexdigest(),'byte_identical':True},
        'native_app_fixture_boundary':'Real immutable NativeAppEvidence/NativeAppDomain and actual observation copying compile; NativeAppSession and the four-purpose Service bridge are all-throw type boundaries for these original non-native cases. Separate native provider gates replace the Session; the native-action gate executes the actual complete collector/bridge/final checker.',
        'permission_initialization_boundary':'Original non-profile cases retain the complete production Service and Controller call sites. The explicit empty permission-worker type cannot prepare or obtain profile authority; its absent receipt is null, like a never-started real worker. The independent permission-ui gate executes the real worker and core.',
        'native_action_bridge_excluded':{'bytes':len(section(s,'    private void requireNativeActionGuard(','    private String validate(').encode()),
            'sha256':hashlib.sha256(section(s,'    private void requireNativeActionGuard(','    private String validate(').encode()).hexdigest()},
        'phone_operations':False,'native_inference':False}
    record['calendar_legacy_boundary']={
        'complete_controller_source_unchanged':True,'shared_native_session_fixture_unchanged':True,
        'local_native_session_fixture_source':str(calendar_nas_source.relative_to(source)),
        'local_native_session_fixture_source_sha256':hashlib.sha256(calendar_nas_raw.encode()).hexdigest(),
        'added_session_ports_sha256':hashlib.sha256(calendar_nas_ports.encode()).hexdigest(),
        'added_service_ports_sha256':hashlib.sha256(calendar_io_ports.encode()).hexdigest(),
        'added_background_ports_sha256':hashlib.sha256(calendar_bg_ports.encode()).hexdigest(),
        'all_new_constructors_and_authority_endpoints_refuse':True,
        'preexisting_dispatch_methods_modified':False,
        'calendar_source_only_excluded':{'bytes':len(calendar_source_only.encode()),'sha256':hashlib.sha256(calendar_source_only.encode()).hexdigest()},
        'calendar_action_only_excluded':{'bytes':len(calendar_action_only.encode()),'sha256':hashlib.sha256(calendar_action_only.encode()).hexdigest()},
        'calendar_actual_methods_covered_by':['tests/native-calendar-date-fresh/run_host.py','tests/native-calendar-date-actions/run_host.py','tests/native-calendar-probe-diagnostic/run_host.py'],
        'separate_calendar_gate_execution_claimed_here':False,'calendar_model_or_input_qualified':False}
    record['post_effect_cleanup_legacy_boundary']={
        'actual_cleanup_and_lock_declarations':{
            'bytes':len(post_effect_cleanup.encode()),
            'sha256':hashlib.sha256(post_effect_cleanup.encode()).hexdigest()},
        'type_only_port_sha256':hashlib.sha256(post_effect_cleanup_ports.encode()).hexdigest(),
        'actual_lease_block_unchanged':True,
        'actual_discard_methods_verbatim':True,
        'pending_retry_constructible':False,'observer_worker_or_registration_present':False,
        'new_retry_or_effect_authority':False,'old_cases_or_assertions_changed':False}
    # Every caller of this legacy generator compiles the same complete manual
    # beginTask. Automatic authority stays absent; the separate auto gate uses
    # bg.prepare and the real automatic producer, not this qualification fixture.
    manual_path = source/'tests/native-auto-target/manual_boundary.py'
    manual_raw = manual_path.read_bytes()
    if hashlib.sha256(manual_raw).hexdigest() != '03b1399819b54b3032d8da2f37cca70b50ac63327e3c2fd07fa935b41fa199b9':
        raise RuntimeError('exact private refusing manual compiler boundary required')
    manual = types.ModuleType('qualification_manual_automatic_boundary')
    manual.__file__ = str(manual_path)
    exec(compile(manual_raw,str(manual_path),'exec'),manual.__dict__)
    files,manual_record = manual.prepare_ui(source,output,files,
        lambda raw,signature: java_method(raw.decode('utf-8'),'    '+signature+'{'))
    if manual_path.read_bytes() != manual_raw:
        raise RuntimeError('manual compiler boundary changed during preparation')
    manual_record['generator'] = {'path':str(manual_path),'bytes':len(manual_raw),
        'sha256':hashlib.sha256(manual_raw).hexdigest()}
    record['automatic_manual_compiler_boundary'] = manual_record
    (output/'EXTRACTION.json').write_text(json.dumps(record,indent=2)+'\n')
    return files, record
