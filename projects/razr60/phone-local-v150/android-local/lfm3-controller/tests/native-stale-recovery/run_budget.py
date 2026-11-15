#!/usr/bin/env python3
"""Synthetic boundary audit of exact production projections and terminal IO.

No phone, adb, UI, source edits, or production task simulation. Outputs are new
host-only files; the source tree must remain byte-identical.
"""
from pathlib import Path
import argparse, ast, hashlib, json, os, subprocess, sys

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

assert sha(runner.read_bytes()) == 'e90b2bd1ba7d727bac446a45eb310089387d72c904a62df41cffc7b6af04d34e'
assert sha(a.json_jar.read_bytes()) == '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
assert sha((src/'SessionTerminalEvidence.java').read_bytes()) == '566cbd71a364d51069de271afd7db641fcdf2b97f93682107e4f76e9405b7db0'
assert sha((src/'LocalTaskSession.java').read_bytes()) == 'ccb59c5ca91214f892b060dda829ec41a1c25e91863631e3dc8dc90d7f800e0c'
assert sha((src/'NativeActionSnapshotCheck.java').read_bytes()) == '0ac969fe789ca1183d51c86c4ce38f80b2e6199f5dc62593a27d7bc3a5cca930'

# Use the already reviewed real-file IO fixture producer through its complete
# generation stage. Do not run its 88 unrelated cases or change any source.
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
 static final class ActionWork {final ActionExecutionState state;String diagnosticFreshness,nativeActionRejection,nativeActionProof;Guard nativeGuard;
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
inputs += [src/name for name in ['LocalTaskController.java','HeptaAccessibilityService.java','NativeActionSnapshotCheck.java','ObservedChildText.java','ActionExecutionState.java','RecentActionProjection.java']]
inputs += [Path(__file__).resolve(), template, a.json_jar.resolve()]
before = [identity(path) for path in inputs]
# Real org.json is deliberately used: the legacy host fixture's toString(2)
# delegates to compact JSON and cannot establish pretty-file byte counts.
sources = [path for path in sorted((out/'terminal-fixtures/src').rglob('*.java'))
           if 'org/json' not in path.as_posix()]
sources += [src/name for name in ['SessionJournalQueue.java','SessionRecovery.java','SessionTerminalEvidence.java','NativeActionSnapshotCheck.java','ObservedChildText.java','ActionExecutionState.java','RecentActionProjection.java']]
sources += [bridge_path, harness_path]
classes = out/'classes'
classes.mkdir()
java = a.java_home/'bin/java'
compile_command = [str(java), '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-encoding', 'UTF-8', '-source','8','-target','8','-Xlint:all,-options','-Werror','-cp',str(a.json_jar),'-d',str(classes)] + [str(path) for path in sources]
record = {'schema':'hepta.native-census-boundary-audit.v1','all_pass':False,
          'synthetic_fixture':True,'phone_operations':0,'production_source_mutations':0,
          'scope':'diagnostic contribution through actual projection methods and actual terminal IO; not a global maximum of unrelated app text or a phone task',
          'source_inputs':before,'terminal_extracted_methods':ns['record']['extracted_methods'],
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
