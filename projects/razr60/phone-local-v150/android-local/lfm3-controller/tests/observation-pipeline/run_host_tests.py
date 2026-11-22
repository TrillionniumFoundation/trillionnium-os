#!/usr/bin/env python3
"""Execute production observer scheduling/ownership against explicit Android IO fakes."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--output',type=Path,required=True);p.add_argument('--release8',action='store_true');a=p.parse_args()
root=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
source=root/'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java';text=source.read_text()
def section(start,end):
    if text.count(start)!=1 or text.count(end)!=1:raise RuntimeError('ambiguous production anchor')
    i=text.index(start);return text[i:text.index(end,i)]
parts={'observation_callback':section('    public interface ObservationCallback', '    public interface Cancellation'),
       'diagnostic':section('    private String diagnosticTask;', '    /** Each observation owns'),
       'acquire':section('    public synchronized boolean acquireTask(', '    public synchronized void releaseTask('),
       'recovery_idle':section('    synchronized boolean recoveryControllerIdle(', '    synchronized void retireControllerAfterAcknowledgement('),
       'action_pending':section('    boolean actionWorkPending()', '    void retireActionWork('),
       'background_lock':section('    private boolean locked(BackgroundSession background)', '    private int rotation('),
       'cancellation_pending':section('    boolean nativeCancellationWorkPending()', '    boolean requestNativeCancellation('),
       'observation':section('    /** Each observation owns', '    synchronized void bindQualificationScope(')}
# The observer-only fixture retains the actual scheduling methods, including
# both new instanceof hooks. The private calendar producer is covered by its
# dedicated gates; its local type-only stand-in cannot be constructed or run.
calendar_start = "    /** One typed read, using the existing observation request/PNG publication."
calendar_end = "    public void observe(final String taskId,final File evidenceDirectory,final Cancellation cancel,"
calendar_actual = section(calendar_start, calendar_end)
calendar_actual_sha = hashlib.sha256(calendar_actual.encode()).hexdigest()
if calendar_actual_sha != "d143d3bca16e6f85571c234535aee39a45b91851c77b7cf70dee06adb988fb04":
    raise RuntimeError("Exact reviewed calendar-only producer block required")
calendar_port = """    private abstract class CalendarFreshObserver implements ObservationCallback {
        private CalendarFreshObserver(){throw new UnsupportedOperationException("Calendar producer unavailable in observer-only fixture");}
        void bind(ObservationRequest request){throw new UnsupportedOperationException("No calendar producer authority");}
        void requireAdmission(ObservationRequest request){throw new UnsupportedOperationException("No calendar producer authority");}
    }

"""
compiled_parts = dict(parts)
if parts["observation"].count(calendar_actual) != 1:
    raise RuntimeError("Unique calendar producer within the observation section required")
compiled_parts["observation"] = parts["observation"].replace(calendar_actual, calendar_port, 1)
if compiled_parts["observation"].replace(calendar_port, calendar_actual, 1) != parts["observation"]:
    raise RuntimeError("Original production observation section must remain reversible")
calendar_boundary = {
    "schema": "hepta.observer-calendar-legacy-type-boundary.v1",
    "full_production_observation_sha256": hashlib.sha256(parts["observation"].encode()).hexdigest(),
    "calendar_only_excluded_bytes": len(calendar_actual.encode()),
    "calendar_only_excluded_sha256": calendar_actual_sha,
    "refusing_port_sha256": hashlib.sha256(calendar_port.encode()).hexdigest(),
    "compiled_observation_sha256": hashlib.sha256(compiled_parts["observation"].encode()).hexdigest(),
    "actual_observer_scheduling_and_both_calendar_type_hooks_unchanged": True,
    "private_constructor_and_lifecycle_methods_throw": True,
    "calendar_callback_created": False, "calendar_producer_executed": False,
    "calendar_actual_gates": ["native-calendar-date-fresh", "native-calendar-date-actions"]}
template_path=Path(__file__).with_name('ObserverPipelineHost.template')
template=template_path.read_text()
for key,value in compiled_parts.items():template=template.replace('{{'+key+'}}',value)
if '{{' in template:raise RuntimeError('unfilled fixture')
fixture=out/'ObserverPipelineHost.java';fixture.write_text(template)
record={'schema':'hepta.observation-pipeline-host.v1','production_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        'template_sha256':hashlib.sha256(template_path.read_bytes()).hexdigest(),
        'generated_fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),
        'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'stability_gate_sha256':hashlib.sha256((root/'src/org/trillionnium/hepta/local/ObservationStabilityGate.java').read_bytes()).hexdigest(),
        'diagnostic_source_sha256':hashlib.sha256((root/'src/org/trillionnium/hepta/local/ObservationDiagnostics.java').read_bytes()).hexdigest(),
        'window_metadata_source_sha256':hashlib.sha256((root/'src/org/trillionnium/hepta/local/ObservedWindowMetadata.java').read_bytes()).hexdigest(),
        'json_fixture_sources':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((root/'tests/qualification-scope/fixtures/org/json').glob('*.java'))},
        'action_state_sha256':hashlib.sha256((root/'src/org/trillionnium/hepta/local/ActionExecutionState.java').read_bytes()).hexdigest(),
        'cancellation_queue_sha256':hashlib.sha256((root/'src/org/trillionnium/hepta/local/TaskCancellationQueue.java').read_bytes()).hexdigest(),
        'extracted':{key:hashlib.sha256(value.encode()).hexdigest() for key,value in parts.items()},'phone_operations':False,'android_runtime':False,'native_inference':False,'production_methods_executed':['acquireTask','recoveryControllerIdle','observe','sampleObservation','acceptSample','watchObservation','captureObservation','watchCapture','processScreenshot','acceptScreenshot','failObservation','retryObservation','copyScreenshot'],'boundary':'Android graph, screenshot, Web cleanup state and callback IO are instrumented fakes; production deadline, ownership, admission/recovery conjunctions, event fence and worker/main delivery execute unchanged.'}
record['calendar_legacy_boundary']=calendar_boundary
compiler=[shutil.which('javac')] if shutil.which('javac') else ['java','-m','jdk.compiler/com.sun.tools.javac.Main']
flags=['--release','8'] if a.release8 else ['-source','8','-target','8']
classes=out/'classes';classes.mkdir()
commands=[('compile',compiler+flags+['-encoding','UTF-8','-Xlint:all' if a.release8 else '-Xlint:all,-options','-Werror','-d',str(classes),str(root/'src/org/trillionnium/hepta/local/ObservationStabilityGate.java'),str(root/'src/org/trillionnium/hepta/local/ActionExecutionState.java'),str(root/'src/org/trillionnium/hepta/local/TaskCancellationQueue.java'),str(root/'src/org/trillionnium/hepta/local/ObservationDiagnostics.java'),str(root/'src/org/trillionnium/hepta/local/ObservedWindowMetadata.java')]+[str(p) for p in sorted((root/'tests/qualification-scope/fixtures/org/json').glob('*.java'))]+[str(fixture)]),('tests',['java','-cp',str(classes),'org.trillionnium.hepta.local.ObserverPipelineHost'])]
record['stages']=[]
for name,command in commands:
    begin=time.monotonic();result=subprocess.run(command,text=True,capture_output=True,timeout=60)
    (out/(name+'.stdout')).write_text(result.stdout);(out/(name+'.stderr')).write_text(result.stderr)
    record['stages'].append({'name':name,'exit_code':result.returncode,'elapsed_s':time.monotonic()-begin})
    if result.returncode:
        record['status']='failed';(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(result.stdout);print(result.stderr);raise SystemExit(result.returncode)
record['status']='passed';record['compiler_contract']='Java 8 API release' if a.release8 else 'Java 8 syntax/class target only; strict release gate remains pending'
record['passed_cases']=sum(line.startswith('PASS ') for line in (out/'tests.stdout').read_text().splitlines())
(out/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))

