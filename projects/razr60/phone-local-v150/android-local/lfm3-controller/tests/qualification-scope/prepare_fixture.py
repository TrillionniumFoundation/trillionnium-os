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
        'lease': section(s, '    public synchronized boolean acquireTask(', '    private boolean locked()'),
        'app_catalogue': section(s, '    /** Snapshot only installed launcher entries;', '    /** Each observation owns its samples/capture'),
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
    session = (pkg / 'LocalTaskSession.java').read_text()
    session_parts = {
        'schedule': section(session, '    public boolean schedule(final String owner,String source', '    /** The only caller is the positive button'),
        'persist': section(session, '    private boolean persist(', '\n}'),
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
    pure=['ActionDecision','ActionPolicy','ObservedTargetLabels','ObservedScrollActions','RecentActionProjection',
          'PersistentActionPolicy','ImeVisibility','ObservationState','ObservedWindowMetadata','ObservedChildText',
          'RepeatActionGuard','SameStateNoEffectGuard','DecisionGrammar','ModelProfile','LocalRuntimeConfig',
          'ConservativeTokenBudget','AppCatalogueRanker','ObservedTextProjection','ObservedTransitionProjection',
          'CompactTaskHistory','PromptActionDomain','RecoveryQuiescence','RecoveryJournalTransaction',
          'QualificationScope','QualificationScopeConfig','MobiMindPrivateFiles','LocalTaskController','LocalInference','PhoneObservation']
    if (pkg/'ObservedAppLabels.java').is_file():pure.append('ObservedAppLabels')
    files=[pkg/(name+'.java') for name in dict.fromkeys(pure)]
    files += sorted(output.glob('*.java'))
    files += sorted((Path(__file__).parent/'fixtures').rglob('*.java'))
    files += [Path(__file__).parent/'QualificationScopeHostTest.java',Path(__file__).parent/'QualificationScopePrivateRootHostTest.java',Path(__file__).parent/'QualificationScopeSplitMetadataHostTest.java',Path(__file__).parent/'ScopedCatalogueHostTest.java']
    record={'schema':'hepta.scope-host-extraction.v1','source_files':{n:hashlib.sha256((pkg/n).read_bytes()).hexdigest() for n in ['HeptaAccessibilityService.java','LocalTaskSession.java','MainActivity.java','LocalTaskController.java','QualificationScope.java','QualificationScopeConfig.java']},
        'extracted':{n:{'bytes':len(v.encode()),'sha256':hashlib.sha256(v.encode()).hexdigest()} for n,v in {**pieces,**session_parts,**ui_parts}.items()},
        'full_actual_classes':['LocalTaskController','QualificationScope','QualificationScopeConfig','MobiMindPrivateFiles'],
        'boundary':'Android IO and effect endpoints are fakes; production admission/dispatch and controller code is executed',
        'phone_operations':False,'native_inference':False}
    (output/'EXTRACTION.json').write_text(json.dumps(record,indent=2)+'\n')
    return files, record
