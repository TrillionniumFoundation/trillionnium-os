#!/usr/bin/env python3
"""Synthetic boundary audit of exact production projections and terminal IO.

No phone, adb, UI, source edits, or production task simulation. Outputs are new
host-only files; the source tree must remain byte-identical.
"""
from pathlib import Path
import argparse, ast, hashlib, json, os, runpy, subprocess, sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--component', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--java-home', type=Path, required=True)
p.add_argument('--json-jar', type=Path, required=True)
a = p.parse_args()
root, out = a.component.resolve(), a.output.resolve()
out.mkdir(mode=0o700)
here = Path(__file__).resolve().parent
src = root / 'src/org/trillionnium/hepta/local'
runner = root / 'tests/session-terminal/run_host.py'
template = here / 'CensusBudgetAudit.java'

def sha(raw): return hashlib.sha256(raw).hexdigest()
def identity(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}

assert sha(runner.read_bytes()) == 'a3dfbeea735c501a5bf0c529987b0ebaf4e805401c0859b99f325e551e066540'
assert sha(a.json_jar.read_bytes()) == '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
assert sha((src/'SessionTerminalEvidence.java').read_bytes()) == '566cbd71a364d51069de271afd7db641fcdf2b97f93682107e4f76e9405b7db0'
# Preserve the audited legacy file and admit only this reviewed successor. The
# 21 terminal method bodies below remain byte-identical to the legacy contract.
local_session_raw=(src/'LocalTaskSession.java').read_bytes()
local_session_proof=local_session_raw
# The UI-only explanation getter is not part of the terminal/budget contract.
# Reverse its exact bytes on a proof copy; the full current source is retained.
if sha(local_session_raw)=='8e482c0595c7f8dec8758fd3c831d89622023ad18523ded496c14810ce3f089b':
    ui_recovery_getter=(
        '    /** Presentation only. The existing recovery admission above remains authoritative. */\n'
        '    public String interruptionRecoveryUnavailableReason(){\n'
        '        if(recovering)return "正在核验上次会话，请等待本次核验完成。";\n'
        '        if(isRunning())return "当前任务仍在运行，请先停止任务并等待退出。";\n'
        '        if(journalQueue.pending())return "会话记录正在保存，完成后才能确认中断。";\n'
        '        if(hasBackgroundLease())return "上次后台空间尚未确认释放，请先清理后台空间。";\n'
        '        return ((LocalProbeApplication)context).controlRecoveryUnavailableReason();\n'
        '    }\n'
    ).encode('utf-8')
    assert local_session_proof.count(ui_recovery_getter)==1, 'unique reviewed UI recovery getter'
    local_session_proof=local_session_proof.replace(ui_recovery_getter,b'',1)
    assert sha(local_session_proof)=='091e0a17fd8f9399bbe50743d74a7755ac227138a2f5d817b95ed98bc1dae057', 'complete pre-UI Session required'
assert sha(local_session_proof) in {
    '1d15f40b9f6205dac8fc2436544f648038a8a48e13b404941e73a47338188ca6',
    '62ad8ddd5b022150df23b04a9f17ee563336a7b92c1728fb091782be91c97bfc',
    # Reviewed separate positive-step recovery; the original 21 method digest below remains mandatory.
    '091e0a17fd8f9399bbe50743d74a7755ac227138a2f5d817b95ed98bc1dae057'}
# Preserve the audited legacy comparators and the reviewed Xiaomi SEARCH_ICON
# and Ctrip nested-disjoint successors. The unchanged Ctrip OPEN ancestor rejection, 21
# terminal method digests and all maximum-census/projection/IO checks remain.
native_snapshot_raw=(src/'NativeActionSnapshotCheck.java').read_bytes()
native_snapshot_proof=native_snapshot_raw
# Proof-copy inverse only; compile the actual current comparator below.
partial_helper=root/'tests/native-search-carousel-edge/protected_partial_edge.py'
assert sha(partial_helper.read_bytes())=='0e9fd09f587fd7939d20d675952bb5c8b7422c14cd79111b572a930c8e174b1b', 'exact reviewed partial-edge inverse helper'
if sha(native_snapshot_proof) in ('c1df34cb7613f7b50e206b89140e1518556343f438fe43594ff27ca1c5db3346','46c6aed0dfb6279c5b56ec80095a5d2fead6c3c95335f70d5a47a98bef52e0f6'):
    native_snapshot_proof=runpy.run_path(str(partial_helper))['predecessor'](native_snapshot_proof)
if sha(native_snapshot_proof) in ('b5bbcc3e74f769c94718de560fa476431d0b726997f48b9c4ad094a997d737b2','400db829f8b5942d9ad4a43a1bbbc18d96fe2138964482146b8cd08fd63ea593'):
    native_snapshot_proof=runpy.run_path(str(root/'tests/native-xiaomi-query-stability/protected_filled_query.py'))['predecessor']('NativeActionSnapshotCheck.java',native_snapshot_proof)
if sha(native_snapshot_proof) in ('dbc72e40e410334c9db300308dc0dfec60339a8e4c3018661239c1a959438d05',
        'de5a0bcd74250ce051595bc9200802ad019a99a69babc18dd9ecc229a6e2afac',
        '5e3366ed3d59c94360663058004bcab06fa896f97a120717f90fd8d8f43e33bf'):
    native_snapshot_proof=runpy.run_path(str(root/'tests/native-search-producer/protected_snapshot.py'))['predecessor'](native_snapshot_proof)
if sha(native_snapshot_proof)=='4b44a759dd41f60c6c693c60d500a83fa8ec83962eb7f6b8d6dd5be95953ad6b':
    # The two approved complete-census Xiaomi banner checks are additive.
    # Strip their exact bytes only on the proof copy; javac still uses the full source.
    start=b'    /** Identify one ambiguous blank home banner for a new read only.'
    end=b'    private static boolean bannerVisibleCoverageEqual(Snapshot old,Snapshot fresh,Node anchor){'
    assert native_snapshot_proof.count(start)==native_snapshot_proof.count(end)==1
    lo=native_snapshot_proof.index(start);hi=native_snapshot_proof.index(end,lo)
    assert sha(native_snapshot_proof[lo:hi])=='42a35e21bfcd8e6e20412916848cf784c35cffc7b3d3b28c5077109905f83cb2'
    native_snapshot_proof=native_snapshot_proof[:lo]+native_snapshot_proof[hi:]
    assert sha(native_snapshot_proof)=='df7231303bac13507172dd83ebfe36fb17d107390f4aaa40a80ce4cf18263412'
if sha(native_snapshot_proof)=='df7231303bac13507172dd83ebfe36fb17d107390f4aaa40a80ce4cf18263412':
    # Only the two reviewed typed-history diagnostic changes are reversed in a
    # proof copy. Current source still enters javac and every original case.
    proof=native_snapshot_proof.decode('utf-8')
    inverse=[
        ('need(capture.nativeText()&&sha(capture.receiptSha256)&&originalScreen==null,',
         'need(ObservationCaptureEvidence.NATIVE_AX.equals(capture.kind)&&sha(capture.receiptSha256)&&originalScreen==null,'),
        ('out.put("original_capture_kind",capture==null?ObservationCaptureEvidence.PIXELS:capture.kind);',
         'out.put("original_capture_kind",capture==null?ObservationCaptureEvidence.PIXELS:ObservationCaptureEvidence.NATIVE_AX);')]
    for current,legacy in inverse:
        assert proof.count(current)==1, 'unique reviewed NAS history diagnostic delta'
        proof=proof.replace(current,legacy,1)
    native_snapshot_proof=proof.encode('utf-8')
    assert sha(native_snapshot_proof)=='829bbcb2b7ad39c37acfde5493fcf5195acaaa7e461327d915f656a5b90fc25c'
assert sha(native_snapshot_proof) in {
    'de64eaf86b0a1a31f48fcf3ea933d3ec821d385788a619fc19881829acf33aec',
    'ee304f12980f51c87dfe031e55c5a34d4d7466e963a5f5f6bd18b633718b4fc2',
    '39fed7241743499db4fa5f6c3c5fef71ee80eb354281bb6f8a888fc63b29b756',
    'd4736f666443118a80340c74bd940009c0e30cf1d3e817e961bd2334f233e500',
    # Reviewed typed AX rejection evidence overload; legacy comparator and all budgets remain.
    '1d2278784b70f4e57857f8a2cdc89d8e5d2471726e68f57b1d75a659f47a24c1',
    # Reviewed shared search role helpers; original comparator/projection budgets remain.
    '829bbcb2b7ad39c37acfde5493fcf5195acaaa7e461327d915f656a5b90fc25c'}

# Use the already reviewed real-file IO fixture producer through its complete
# generation stage. Do not run its unrelated fixture cases or change any source.
producer = runner.read_text(encoding='utf-8')
boundary = 'for mode in ["host_owning_stream","android_nonowning_stream"]:'
assert producer.count(boundary) == 1
prefix = producer[:producer.index(boundary)]
saved_argv = sys.argv
try:
    sys.argv = [str(runner), '--output', str(out/'terminal-fixtures'), '--java-home', str(a.java_home)]
    ns = {'__file__': str(runner), '__name__': '__census_fixture_generation__'}
    exec(compile(prefix, str(runner), 'exec'), ns)
finally:
    sys.argv = saved_argv
body = ns['body']
# This gate exercises the real terminal projection, not the unrelated model
# settings/recovery UI methods added elsewhere in LocalTaskSession. Retain an
# exact fixed digest of every original exercised method, before any case runs.
terminal_projection = ns['record']['extracted_methods']
assert len(terminal_projection) == 21
assert sha(json.dumps(terminal_projection, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':')).encode()) == '40cb05319f03a05f57d07495381e6a9ae3f8448d65b2539c0264445e9c7c849c'

controller = (src/'LocalTaskController.java').read_text(encoding='utf-8')
service = (src/'HeptaAccessibilityService.java').read_text(encoding='utf-8')
methods = [
    ('LocalTaskController.java', controller, 'private static java.util.Map<String,Object> nativeQueryExecution(JSONObject raw)throws Exception{'),
    ('LocalTaskController.java', controller, 'private static java.util.Map<String,Object> historyFields(JSONObject entry)throws Exception{'),
    ('LocalTaskController.java', controller, 'private static String promptSections(JSONObject data)throws Exception{'),
    ('HeptaAccessibilityService.java', service, 'private static JSONObject actionDiagnosticEvidence(ActionWork work){'),
    ('HeptaAccessibilityService.java', service, 'JSONObject actionExecutionEvidence(String taskId){'),
]
extracted = [body(text, signature) for _, text, signature in methods]
start = controller.index('JSONObject staleRow=new JSONObject().put("step",steps)')
end = controller.index('history.put(staleRow);', start)
stale = controller[start:end]
assert 'action_execution' not in stale and 'native_action_rejection_census' not in stale
bridge = '''package org.trillionnium.hepta.local;
import org.json.JSONObject;import java.util.*;
/** Only field-shape adapters are synthetic; all five projection bodies below
 * and the stale-history construction are copied exactly from production. */
final class CensusProjectionBridge {
 static final class Guard {Map<String,Object> evidence(){return Collections.emptyMap();}}
 static final class ProfileProofBoundary {
  private ProfileProofBoundary(){throw new AssertionError("legacy census fixture cannot create a profile proof");}
  Map<String,Object> evidence(){throw new AssertionError("legacy census fixture cannot serialize profile authority");}}
 static final class ActionWork {final ActionExecutionState state;String diagnosticFreshness,nativeActionRejection,nativeActionProof;Guard nativeGuard;ProfileProofBoundary profileDispatchProof;
  Map<String,Object> queryCensusRetry;
  ActionWork(ActionExecutionState state){this.state=state;}}
 static final class Action {String action="click",packageName="ctrip.android.view",appLabel=null;}
 static final class Before {String packageName="ctrip.android.view";}
 static final class Outcome {boolean accepted=false,dispatched=false,stale=true;String detail="原生目的复核失败: actual ancestor changed: 0";}
 ActionExecutionState lastActionExecution;
 static JSONObject diagnostic(ActionExecutionState state,String census){ActionWork w=new ActionWork(state);w.nativeActionRejection=census;return actionDiagnosticEvidence(w);}
 static Map<String,Object> project(JSONObject raw)throws Exception{return nativeQueryExecution(raw);}
 static Map<String,Object> fields(JSONObject raw)throws Exception{return historyFields(raw);}
 static String prompt(JSONObject raw)throws Exception{return promptSections(raw);}
 static JSONObject staleHistory(int steps)throws Exception{Action action=new Action();Before before=new Before();Outcome outcome=new Outcome();
'''+stale+'''return staleRow;}
'''+ '\n'.join(extracted) + '\n}\n'
generated = out/'src/org/trillionnium/hepta/local'
generated.mkdir(parents=True)
bridge_path = generated/'CensusProjectionBridge.java'
bridge_path.write_text(bridge, encoding='utf-8')
harness_path = generated/'CensusBudgetAudit.java'
harness_path.write_bytes(template.read_bytes())

inputs = [root/row['path'] for row in ns['record']['source_inputs']]
inputs += [src/name for name in ['ObservationCaptureEvidence.java','NativeCtripFormObservation.java','NativeXiaomiSearchInputObservation.java', 'LocalTaskController.java','HeptaAccessibilityService.java','NativeActionSnapshotCheck.java','ObservedChildText.java','ObservedTargetLabels.java','ObservedImeEnter.java','ActionExecutionState.java','RecentActionProjection.java']]
inputs += [Path(__file__).resolve(), template, a.json_jar.resolve(), root/'tests/native-xiaomi-query-stability/protected_filled_query.py']
inputs += [root/'tests/native-ctrip-form-observation/scope_predecessor.py',partial_helper]
before = [identity(path) for path in inputs]
# Real org.json is deliberately used: the legacy host fixture's toString(2)
# delegates to compact JSON and cannot establish pretty-file byte counts.
sources = [path for path in sorted((out/'terminal-fixtures/src').rglob('*.java'))
           if 'org/json' not in path.as_posix()]
sources += [src/name for name in ['ObservationCaptureEvidence.java','NativeCtripFormObservation.java','NativeXiaomiSearchInputObservation.java', 'SessionJournalQueue.java','SessionRecovery.java','SessionTerminalEvidence.java','NativeActionSnapshotCheck.java','ObservedChildText.java','ObservedTargetLabels.java','ObservedImeEnter.java','ActionExecutionState.java','RecentActionProjection.java']]
sources += [bridge_path, harness_path]
classes = out/'classes'
classes.mkdir()
java = a.java_home/'bin/java'
compile_command = [str(java), '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-encoding', 'UTF-8', '-source','8','-target','8','-Xlint:all,-options','-Werror','-cp',str(a.json_jar),'-d',str(classes)] + [str(path) for path in sources]
record = {'schema':'hepta.native-census-boundary-audit.v1','all_pass':False,
          'synthetic_fixture':True,'phone_operations':0,'production_source_mutations':0,
          'scope':'diagnostic contribution through actual projection methods and actual terminal IO; not a global maximum of unrelated app text or a phone task',
          'source_inputs':before,'native_snapshot_actual_sha256':sha(native_snapshot_raw),'native_snapshot_legacy_proof_sha256':sha(native_snapshot_proof),
          'local_task_session_actual_sha256':sha(local_session_raw),'local_task_session_legacy_proof_sha256':sha(local_session_proof),
          'terminal_extracted_methods':ns['record']['extracted_methods'],
          'projection_extracted_methods':[{'path':name,'signature':signature,'sha256':sha(code.encode())} for (name,_,signature),code in zip(methods,extracted)],
          'stale_history_block_sha256':sha(stale.encode()),'fixture_producer_prefix_sha256':sha(prefix.encode()),
          'compile_command':compile_command,
          'environment':{k:os.environ.get(k) for k in ['LANG','LC_ALL','JAVA_HOME','PATH','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH']}}
result = subprocess.run(compile_command, capture_output=True, timeout=90)
(out/'compiler.stdout').write_bytes(result.stdout)
(out/'compiler.stderr').write_bytes(result.stderr)
record['compiler_returncode'] = result.returncode
if result.returncode == 0:
    command = [str(java), '-Dhepta.fixture.host_uid='+str(os.getuid()), '-Dhepta.fixture.nonowning=false', '-cp',str(a.json_jar)+os.pathsep+str(classes), 'org.trillionnium.hepta.local.CensusBudgetAudit',str(out/'runtime')]
    record['run_command'] = command
    result = subprocess.run(command, capture_output=True, timeout=90)
    (out/'runtime.stdout').write_bytes(result.stdout)
    (out/'runtime.stderr').write_bytes(result.stderr)
    record['runtime_returncode'] = result.returncode
    if result.returncode == 0:
        record['runtime'] = json.loads(result.stdout)
        record['all_pass'] = record['runtime']['all_pass'] is True
record['source_inputs_unchanged'] = before == [identity(path) for path in inputs]
record['all_pass'] = record['all_pass'] and record['source_inputs_unchanged']
record['generated_sources'] = [identity(path) for path in sources if out in path.parents]
(out/'RESULT.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n', encoding='utf-8')
print(json.dumps({'all_pass':record['all_pass'],'compiler_returncode':record['compiler_returncode'],'runtime_returncode':record.get('runtime_returncode'),'result':str(out/'RESULT.json'),'result_sha256':sha((out/'RESULT.json').read_bytes()),'runtime':record.get('runtime')},ensure_ascii=False))
raise SystemExit(0 if record['all_pass'] else 1)
