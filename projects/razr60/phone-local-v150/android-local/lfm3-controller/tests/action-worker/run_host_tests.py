#!/usr/bin/env python3
"""Compile actual pure sources and exact Stop/cancel source bodies; no phone actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def body(source, signature):
    if source.count(signature) != 1:
        raise ValueError('method signature not unique: ' + signature)
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    mode = 'code'
    escaped = False
    i = opening
    while i < len(source):
        char = source[i]
        following = source[i:i + 2]
        if mode == 'line':
            if char == '\n':
                mode = 'code'
        elif mode == 'comment':
            if following == '*/':
                mode = 'code'
                i += 1
        elif mode in ('string', 'char'):
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == ('"' if mode == 'string' else "'"):
                mode = 'code'
        elif following == '//':
            mode = 'line'
            i += 1
        elif following == '/*':
            mode = 'comment'
            i += 1
        elif char == '"':
            mode = 'string'
        elif char == "'":
            mode = 'char'
        elif char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise ValueError('unterminated method')


def identity(path, root):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(root)), 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = root / 'src/org/trillionnium/hepta'
    controller = source / 'local/LocalTaskController.java'
    service = source / 'local/HeptaAccessibilityService.java'
    background = source / 'local/BackgroundSession.java'
    engine = source / 'local/LocalModelEngine.java'
    activity = source / 'local/MainActivity.java'
    flight_stability = source / 'local/WebFlightNativeStability.java'
    template = Path(__file__).with_name('ActionWorkerHost.template')
    replacements = {
        '/*__STOP__*/': (controller, 'public void stop(){'),
        '/*__STOP_IF_TASK__*/': (controller, 'boolean stopIfTask(String expectedTask){'),
        '/*__REQUEST_NATIVE__*/': (service, 'boolean requestNativeCancellation(TaskCancellationQueue.Ticket ticket,Runnable signal){'),
        '/*__RETIRE_ACTION__*/': (service, 'void retireActionWork(String taskId,String reason){'),
        '/*__ACQUIRE_TASK__*/': (service, 'public synchronized boolean acquireTask(String taskId,Runnable onStop) {'),
        '/*__REMAINING_TIMEOUT__*/': (background, 'private static int remainingActionTimeout(JSONObject request,int maximum,'),
        '/*__READ_RESPONSE__*/': (background, 'private static void readResponseBytes(LocalSocket socket,DataInputStream input,byte[] bytes,'),
        '/*__RUN_HANDLE__*/': (engine, 'public static final class RunHandle {'),
        '/*__CLAIM_PROCESS__*/': (engine, 'private static void claimProcess(RunHandle handle,AtomicReference<RunHandle> local){'),
        '/*__CANCEL_ACTIVE__*/': (engine, 'public void cancelActive() {'),
        '/*__ACTION_GRAPH__*/': (service, 'private static final class Graph {'),
        '/*__GRAPH_BUDGET__*/': (service, 'private interface GraphBudget {'),
        '/*__CHECK_READ_BUDGET__*/': (service, 'private static void checkReadBudget(GraphBudget budget){'),
        '/*__NODE_REFERENCE_COPY__*/': (service, 'private NodeRef(NodeRef original){'),
        '/*__REGION_CHILD__*/': (service, 'private AccessibilityNodeInfo regionChild(ActionWork work,AccessibilityNodeInfo parent,int index,List<AccessibilityNodeInfo> temporary){'),
        '/*__REGION_PARENT__*/': (service, 'private AccessibilityNodeInfo regionParent(ActionWork work,AccessibilityNodeInfo child,List<AccessibilityNodeInfo> temporary){'),
        '/*__ACTION_CHECK__*/': (service, 'private static void actionCheck(ActionWork work){'),
    }
    fixture = template.read_text()
    extracted = []
    for marker, (path, signature) in replacements.items():
        method = body(path.read_text(), signature)
        if fixture.count(marker) != 1:
            raise ValueError('fixture marker changed')
        fixture = fixture.replace(marker, method)
        extracted.append({'path': str(path.relative_to(root)), 'signature': signature,
                          'body_sha256': hashlib.sha256(method.encode()).hexdigest()})
    limit_signature = 'static final int MAX_NATIVE_NODES='
    flight_raw = flight_stability.read_text()
    if flight_raw.count(limit_signature) != 1 or fixture.count('/*__FLIGHT_NATIVE_LIMIT__*/') != 1:
        raise ValueError('exact Flight collection limit marker changed')
    limit_start = flight_raw.index(limit_signature)
    limit = flight_raw[limit_start:flight_raw.index(';', limit_start) + 1]
    fixture = fixture.replace('/*__FLIGHT_NATIVE_LIMIT__*/', limit)
    extracted.append({'path': str(flight_stability.relative_to(root)), 'signature': limit_signature,
                      'body_sha256': hashlib.sha256(limit.encode()).hexdigest()})
    button_signature = 'stopTask.setOnClickListener(v -> {'
    button = body(activity.read_text(), button_signature)
    if fixture.count('/*__STOP_BUTTON_BODY__*/') != 1:
        raise ValueError('ordinary Stop fixture marker changed')
    fixture = fixture.replace('/*__STOP_BUTTON_BODY__*/', button[button.index('{') + 1:-1])
    extracted.append({'path': str(activity.relative_to(root)), 'signature': button_signature,
                      'body_sha256': hashlib.sha256(button.encode()).hexdigest()})
    generated = output / 'ActionWorkerHost.java'
    generated.write_text(fixture)
    relative = ['local/ActionExecutionState.java', 'local/TaskCancellationQueue.java', 'local/ObservationDiagnostics.java',
                'local/FixedIntentAttemptGuard.java', 'local/ObservedImeEnter.java',
                'background/FixedIntentTarget.java', 'background/FixedIntentTools.java',
                'background/BrokerProtocol.java', 'local/OwnedWorkerCancellation.java',
                'webprotocol/WebDomCanonical.java']
    sources = [source / name for name in relative]
    sources += sorted((root / 'tests/qualification-scope/fixtures/org/json').glob('*.java'))
    java = os.environ.get('JAVA', shutil.which('java') or '')
    javac = os.environ.get('JAVAC') or shutil.which('javac')
    if not java:
        raise ValueError('Java runtime required')
    # A runtime can include jdk.compiler without shipping a javac launcher or ct.sym.
    compiler = [javac] if javac else [java, '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    compile_command = compiler + ['-source', '8', '-target', '8', '-Xlint:all,-options', '-Werror',
                                  '-d', str(output / 'classes')] + [str(p) for p in sources] + [str(generated)]
    compile_result = subprocess.run(compile_command, text=True, capture_output=True, timeout=60)
    (output / 'compile.stdout').write_text(compile_result.stdout)
    (output / 'compile.stderr').write_text(compile_result.stderr)
    inputs = [identity(p, root) for p in sources + [controller, service, background, engine, activity, flight_stability, template, Path(__file__).resolve()]]
    report = {'schema': 'hepta.action-worker-host-run.v1', 'source_inputs': inputs, 'extracted_methods': extracted,
              'compile_command': compile_command, 'compiler_returncode': compile_result.returncode,
              'java8_bytecode_target': True, 'java8_api_cross_compile': False,
              'android_compilation': False, 'phone_operations': 0, 'device_qualification': False}
    report['graph_lifetime_boundary'] = ('Exact production Graph, NodeRef copy constructor and region ownership helpers execute against '
                                        'instrumented node/geometry/bridge carriers, with the actual production WebDomCanonical and '
                                        'Flight collection limit. No Android Binder, Web ARM or native region authority is created.')
    if compile_result.returncode == 0:
        run_command = [java, '-cp', str(output / 'classes'), 'org.trillionnium.hepta.local.ActionWorkerHost']
        run_result = subprocess.run(run_command, text=True, capture_output=True, timeout=45)
        (output / 'run.stdout').write_text(run_result.stdout)
        (output / 'run.stderr').write_text(run_result.stderr)
        report.update(run_command=run_command, runtime_returncode=run_result.returncode)
        if run_result.returncode == 0:
            report['runtime'] = json.loads(run_result.stdout)
    report['all_pass'] = bool(report.get('runtime', {}).get('all_pass')) and compile_result.returncode == 0
    (output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'all_pass': report['all_pass'], 'compiler_returncode': compile_result.returncode,
                      'runtime_returncode': report.get('runtime_returncode'),
                      'cases': report.get('runtime', {}).get('cases'), 'output': str(output)}))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
