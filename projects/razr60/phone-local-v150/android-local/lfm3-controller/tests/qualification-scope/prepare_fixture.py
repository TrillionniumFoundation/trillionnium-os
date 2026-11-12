"""Exact production dispatch/controller/config/UI code with explicit Android IO fakes.

No phone, model inference, Android runtime, OS permission or durable fsync claim.
The fake effect APIs count every actual production call; policy is not reimplemented.
"""
import ast
import hashlib
import json
from pathlib import Path


def section(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError(f'nonunique production extraction anchor: {start}')
    i = text.index(start)
    return text[i:text.index(end, i)]


def prepare(source, output):
    source, output = Path(source), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    pkg = source / 'src/org/trillionnium/hepta/local'
    s = (pkg / 'HeptaAccessibilityService.java').read_text()
    pieces = {
        'service_interfaces_outcome': section(s, '    public interface ObservationCallback', '    private static volatile HeptaAccessibilityService live;'),
        'web_binding': section(s, '    synchronized void bindWebFlightSession(', '    synchronized void bindBackgroundSession('),
        'background_binding': section(s, '    synchronized void bindBackgroundSession(', '    private void refreshApps()'),
        'app_catalogue': section(s, '    public AppCatalogueRanker.Page appCatalogue(', '    /** Each observation owns'),
        'lease': section(s, '    public synchronized boolean acquireTask(', '    private boolean locked()'),
        'scope_validate_dispatch': section(s, '    synchronized void bindQualificationScope(', '    private void coordinateClick('),
        'node_graph': section(s, '    private static boolean hasAction(', '    /** Inspect window metadata only.'),
        'node_identity': section(s, '    private static String nodeSignature(', '    private static String fileSha256('),
        'strings': section(s, '    private static String string(', '\n}'),
    }
    fixture = (Path(__file__).parent / 'ServiceFixture.template').read_text()
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
        'snapshot': section(s, '    /** A background root comes only', '    private static String nodeSignature('),
        'node_identity': pieces['node_identity'],
        'strings': pieces['strings'],
    }
    fixture = (Path(__file__).parent / 'BackgroundObservationFixture.template').read_text()
    for name, code in snapshot_parts.items():fixture=fixture.replace('{{'+name+'}}',code)
    if '{{' in fixture:raise RuntimeError('unfilled background snapshot fixture')
    (output / 'BackgroundObservationFixture.java').write_text(fixture)
    session = (pkg / 'LocalTaskSession.java').read_text()
    session_parts = {
        'schedule': section(session, '    public boolean schedule(final String owner,String source,String testNonceSha,long delayMillis)', '    /** The only caller is the positive button'),
        'persist': section(session, '    private void persist(', '\n}'),
        'parse_record': section(session, '    private static JSONObject parseSessionJson(', '    private static Map<String,Object> fieldsOf('),
        'record_exists': section(session, '    private static boolean recordExists(', '    /** Create once; never unlink'),
        'read_record': section(session, '    private static byte[] readSessionRecord(', '    private JSONArray archivePriorRecords('),
    }
    fixture = (Path(__file__).parent / 'SessionFixture.template').read_text()
    for name, code in session_parts.items():fixture=fixture.replace('{{'+name+'}}',code)
    (output / 'LocalTaskSession.java').write_text(fixture)
    ui = (pkg / 'MainActivity.java').read_text()
    ui_parts = {
        'binding': section(ui, '    @Override protected void onSaveInstanceState(', '    @Override protected void onNewIntent('),
        'intent_start': section(ui, '    private void handleIntent(', '    private void runProbe('),
    }
    fixture = (Path(__file__).parent / 'UiFixture.template').read_text()
    for name,code in ui_parts.items():fixture=fixture.replace('{{'+name+'}}',code)
    (output / 'ScopeUiFixture.java').write_text(fixture)
    pure=['BackgroundTaskTarget','NotesCreateWorkflow','NotesOwnerIntent','CalculatorTaskInputGuard','CalculatorGoalContract','CalculatorCompletionEvidence','NotesTaskPhaseGuard','TaskCompletionGate','NotesCompletionEvidence','FixedIntentAttemptGuard','LastModelDecisionProjection','TaskAuthorization','ActionDecision','ActionPolicy','ObservedTargetLabels','ObservedScrollActions','ObservedImeEnter','SubmitAttemptGuard','RecentActionProjection',
          'PersistentActionPolicy','ImeVisibility','ObservationState','ObservedWindowMetadata','ObservedChildText',
          'RepeatActionGuard','SameStateNoEffectGuard','DecisionGrammar','ModelProfile','LocalRuntimeConfig',
          'ConservativeTokenBudget','AppCatalogueRanker','ObservedTextProjection','ObservedTransitionProjection',
          'CompactTaskHistory','PromptActionDomain','RecoveryQuiescence','RecoveryJournalTransaction',
          'QualificationScope','QualificationScopeConfig','MobiMindPrivateFiles','LocalTaskController','LocalInference','PhoneObservation',
          'ActionExecutionState','TaskCancellationQueue','SessionJournalQueue']
    if (pkg/'ObservedAppLabels.java').is_file():pure.append('ObservedAppLabels')
    files=[pkg/(name+'.java') for name in dict.fromkeys(pure)]
    web_fixture_source=source/'tests/web-flight/legacy-boundary/WebFlightDomain.java'
    web_fixture_raw=web_fixture_source.read_bytes()
    web_fixture_compile=output/'WebTaskDomain.java'
    web_fixture_compile.write_bytes(web_fixture_raw)
    if web_fixture_compile.read_bytes()!=web_fixture_raw or web_fixture_source.read_bytes()!=web_fixture_raw:
        raise RuntimeError('Exact Web type-boundary compiler copy required')
    files += [pkg/'web/WebFlightGoal.java',pkg/'web/WebShoppingGoal.java']
    files += [source/'src/org/trillionnium/hepta/background'/(name+'.java') for name in ('FixedIntentTools','FixedIntentTarget','FixedIntentDispatch','BrokerProtocol')]
    files += sorted(output.glob('*.java'))
    files += sorted((Path(__file__).parent/'fixtures').rglob('*.java'))
    files += [Path(__file__).parent/'QualificationScopeHostTest.java',Path(__file__).parent/'BackgroundFreshnessHostTest.java']
    record={'schema':'hepta.scope-host-extraction.v1','source_files':{n:hashlib.sha256((pkg/n).read_bytes()).hexdigest() for n in ['TaskAuthorization.java','HeptaAccessibilityService.java','LocalTaskSession.java','MainActivity.java','LocalTaskController.java','QualificationScope.java','QualificationScopeConfig.java']},
        'extracted':{n:{'bytes':len(v.encode()),'sha256':hashlib.sha256(v.encode()).hexdigest()} for n,v in {**pieces,**session_parts,**ui_parts,**{'background_'+n:v for n,v in snapshot_parts.items()}}.items()},
        'full_actual_classes':['TaskCompletionGate','NotesCompletionEvidence','LocalTaskController','QualificationScope','QualificationScopeConfig','MobiMindPrivateFiles'],
        'boundary':'Android IO and effect endpoints are fakes; production admission/dispatch and controller code is executed',
        'web_fixture_boundary':'Explicit empty Web journal only; real Web OWNER/selection and every helper action/cleanup throw AssertionError; actual Web classes have their separate gate',
        'web_fixture_compiler_copy':{'source_path':str(web_fixture_source.relative_to(source)),
            'compiler_path':str(web_fixture_compile),'bytes':len(web_fixture_raw),
            'sha256':hashlib.sha256(web_fixture_raw).hexdigest(),'byte_identical':True},
        'phone_operations':False,'native_inference':False}
    (output/'EXTRACTION.json').write_text(json.dumps(record,indent=2)+'\n')
    return files, record
