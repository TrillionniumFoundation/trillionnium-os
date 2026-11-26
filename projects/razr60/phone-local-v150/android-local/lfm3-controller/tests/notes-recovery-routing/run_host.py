#!/usr/bin/env python3
"""Actual owner-button routing through personal Client/CAS and typed Service gates.

All historical/current originals stay external and unchanged. Android framework,
PM, worker/main queues and independent checker IO are explicit host boundaries.
The ordinary owner-button and Service admission methods are copied verbatim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.dont_write_bytecode = True

PATCH = '''        // A public display group may belong to user-0 personal Notes. Only a
        // profile-target lease enters this client; the ordinary recovery path
        // still validates the entire personal journal, scope and original task.
        if(!journal.has("profile_target_wire"))return false;
'''
PARENT_CLIENT_SHA = '507c13c7e994d20acd04e3b21822e842b97d4fc2a3d790669a251fd74107ccc6'
JSON_SHA = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'

def need(value, message):
    if not value:
        raise RuntimeError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path and path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1, 'regular absolute input required')
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    need((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed during read')
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw))

def actual_ref(row):
    need(pin(Path(row['path'])) == row, 'actual reference differs')
    return Path(row['path']).read_bytes()

def external_inputs(old_map, current_map):
    rows = {str(old_map): pin(old_map), str(current_map): pin(current_map)}
    old = json.loads(old_map.read_bytes())
    for section in ('inputs', 'task_files'):
        for row in old[section].values():
            actual_ref(row)
            rows[row['path']] = row
    current = json.loads(current_map.read_bytes())
    need(current['schema'] == 'hepta.notes-recovery-routing-actual-inputs.v1', 'actual routing map kind')
    for row in current['notes'].values():
        actual_ref(row)
        rows[row['path']] = row
    for row in current['profile_original_maps'].values():
        paths = json.loads(actual_ref(row))
        rows[row['path']] = row
        for path in paths.values():
            rows[path] = pin(Path(path))
    return rows

def method(source, anchor):
    need(source.count(anchor) == 1, 'unique actual method required: ' + anchor)
    start = source.index(anchor)
    opening = source.index('{', start)
    depth, quote, escaped, line_comment, block_comment = 0, None, False, False, False
    i = opening
    while i < len(source):
        c = source[i]
        next_c = source[i + 1] if i + 1 < len(source) else ''
        if line_comment:
            line_comment = c != '\n'
        elif block_comment:
            if c == '*' and next_c == '/':
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == quote:
                quote = None
        elif c == '/' and next_c == '/':
            line_comment = True
            i += 1
        elif c == '/' and next_c == '*':
            block_comment = True
            i += 1
        elif c in ('"', "'"):
            quote = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise RuntimeError('unterminated actual method')

def replace(text, old, new):
    need(text.count(old) == 1, 'unique explicit host port required: ' + old)
    return text.replace(old, new, 1)

def run(name, argv, output, result, env):
    (output / (name + '.command.json')).write_text(json.dumps(argv, indent=2) + '\n')
    started = time.monotonic()
    p = subprocess.run(argv, env=env, capture_output=True, timeout=180)
    (output / (name + '.stdout')).write_bytes(p.stdout)
    (output / (name + '.stderr')).write_bytes(p.stderr)
    result['stages'].append(dict(stage=name, exit_code=p.returncode, seconds=time.monotonic() - started,
                                 stdout=pin(output / (name + '.stdout')), stderr=pin(output / (name + '.stderr'))))
    need(p.returncode == 0 and p.stderr == b'', name + ' failed or emitted stderr')
    return p.stdout

def success_client_predecessor(actual):
    """Proof copy only; the legacy dependency compiles the current Client."""
    need(sha(actual.encode()) == '473eeed0877e239bd2b0221f21a469b6373346c0e6f78460839d7346b658355c',
         'exact native-success Client required')
    spans = [('        private final TreeMap<File,String> successDirectoryKeys=new TreeMap<File,String>();\n        private final TreeMap<File,TreeSet<String>> successDirectoryMembers=new TreeMap<File,TreeSet<String>>();\n', ''), ('            if(Boolean.TRUE.equals(result.opt("model_reported_success"))){readNativeSuccessOriginals(result);return;}\n', ''), ('            unchanged(true);\n        }\n        /** The success-history variant archives every member of each bound normal\n         * SDK directory. Enumeration is checked before reads and again afterwards. */\n        private void readNativeSuccessOriginals(JSONObject result)throws Exception{\n            java.util.Set<String> paths=PublicProfileBusinessAbsenceRecovery.nativeSuccessModelPaths(result,bytes());\n            TreeMap<String,TreeSet<String>> directories=new TreeMap<String,TreeSet<String>>();\n            for(String path:paths){int slash=path.lastIndexOf(\'/\');String dir=path.substring(0,slash);\n                TreeSet<String> names=directories.get(dir);if(names==null){names=new TreeSet<String>();directories.put(dir,names);}\n                if(!names.add(path.substring(slash+1)))throw new IOException("duplicate native success original");}\n            for(Map.Entry<String,TreeSet<String>> e:directories.entrySet()){\n                File dir=existingDirectory(new File(root.path,e.getKey()));\n                String identity=directoryIdentity(dir);\n                if(!members(dir).equals(e.getValue()))throw new IOException("native success directory is not the complete normal SDK set");\n                successDirectoryKeys.put(dir,identity);successDirectoryMembers.put(dir,new TreeSet<String>(e.getValue()));\n            }\n            for(String path:paths)read(path,PublicProfileBusinessAbsenceRecovery.originalLimit(path));\n', ''), ('            for(Map.Entry<File,String> e:successDirectoryKeys.entrySet())\n                if(!e.getValue().equals(directoryIdentity(e.getKey()))||!successDirectoryMembers.get(e.getKey()).equals(members(e.getKey())))\n                    throw new IOException("native success original directory changed");\n', '')]
    historical = actual
    for current, previous in spans:
        need(historical.count(current) == 1, 'unique native-success Client inverse span required')
        historical = historical.replace(current, previous, 1)
    need(sha(historical.encode()) == 'ca23463b793ebbb4d6f261053bff631ecbbb0e32e145c19672994afc048468e0',
         'full f4c0 Client predecessor differs')
    return historical

def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'java-home', 'json-jar', 'private-input-map', 'current-input-map', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    a = parser.parse_args()
    source, output = a.source.resolve(), a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    local = source / 'src/org/trillionnium/hepta/local'
    own = source / 'tests/notes-recovery-routing'
    java = a.java_home.resolve() / 'bin'
    jar = a.json_jar.resolve()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', JAVA_HOME=str(a.java_home.resolve()))
    for name in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH'):
        env.pop(name, None)
    tools = {str(p): pin(p) for p in (java / 'java', java / 'javac', a.java_home.resolve() / 'lib/modules', jar)}
    need(tools[str(jar)]['sha256'] == JSON_SHA, 'pinned org.json required')
    originals = external_inputs(a.private_input_map.resolve(), a.current_input_map.resolve())
    source_inputs = {str(p): pin(p)['sha256'] for p in
                     (own / 'run_host.py', own / 'NotesRecoveryRoutingHostTest.java', local / 'PublicProfileBusinessRecoveryClient.java',
                      local / 'LocalTaskSession.java', local / 'HeptaAccessibilityService.java', local / 'MainActivity.java')}
    result = dict(schema='hepta.notes-recovery-routing-host-validation.v1', all_pass=False, stages=[], source_inputs=source_inputs,
                  tool_inputs=tools, private_inputs=originals, phone_operations=0, current_absence_claimed=False,
                  actual_current_startup_archive_inputs=True, framework_PM_queues_and_checker_IO_synthetic=True,
                  actual_android_UI_ACK_executed=False, strict_release8=True)
    try:
        run('legacy', [sys.executable, str(source / 'tests/notes-cancelled-absence/run_host.py'), '--source', str(source),
                       '--java-home', str(a.java_home.resolve()), '--json-jar', str(jar), '--private-input-map', str(a.private_input_map.resolve()),
                       '--output', str(output / 'legacy')], output, result, env)
        legacy = json.loads((output / 'legacy/RESULT.json').read_bytes())
        need(legacy['all_pass'] and legacy['inputs_unchanged'] and legacy['original_bytes_unchanged'], 'old actual cancelled Client/CAS cases required')
        source_inputs.update(legacy['source_inputs'])
        result['legacy_result'] = pin(output / 'legacy/RESULT.json')
        result['legacy_counts'] = dict(cases=legacy['cancelled']['cases'], assertions=legacy['cancelled']['assertions'])
        classes = output / 'legacy/legacy/client-classes'
        need(classes.is_dir(), 'actual personal client compilation missing')
        cp = str(classes) + os.pathsep + str(jar)
        generated = output / 'routing-fixture'
        generated.mkdir()
        actual = (local / 'PublicProfileBusinessRecoveryClient.java').read_text()
        proof_client = success_client_predecessor(actual)
        need(proof_client.count(PATCH) == 1, 'only reviewed narrow routing patch expected')
        predecessor = proof_client.replace(PATCH, '', 1)
        need(sha(predecessor.encode()) == PARENT_CLIENT_SHA, 'full e818 predecessor differs')
        old_methods = [method(predecessor, anchor) for anchor in (
            '    static boolean hasBusinessOrigin(Context context)', '    private static String originPath(JSONObject current)',
            '    private static JSONObject object(', '    private static String string(', '    private static long number(')]
        legacy_java = 'package org.trillionnium.hepta.local;\nimport android.content.Context;import java.io.*;import org.json.*;import org.trillionnium.hepta.background.*;\nfinal class LegacyRoutingProbe {static final int SUMMARY_LIMIT=65536;\n' + '\n'.join(old_methods) + '\n}\n'
        (generated / 'LegacyRoutingProbe.java').write_text(legacy_java)
        session = (local / 'LocalTaskSession.java').read_text()
        owner_button = method(session, '    public void reconcileBackgroundFromOwnerButton()')
        need((local / 'MainActivity.java').read_text().count('try{tasks.reconcileBackgroundFromOwnerButton();}') == 1, 'ordinary actual MainActivity handler differs')
        bridge = '''package org.trillionnium.hepta.local;
import android.content.Context;import android.os.Looper;import java.io.IOException;
final class RecoveryOwnerButtonBridge {
 final Context context;final HostQueue recoveryWorker=new HostQueue(true),main=new HostQueue(false);final JournalQueue journalQueue=new JournalQueue();
 LocalTaskController controller;boolean pending,recovering,blocked=true;long generation;int businessCalls;String state="";
 RecoveryOwnerButtonBridge(Context value){context=value;}
 boolean isRunning(){return controller!=null&&controller.isRunning();}
 void setState(String value){state=value;}
 void readLeaseState(){} // UI-only lease indicator port; actual Client/CAS checks all lease bytes.
 void reconcileBusinessBackgroundFromOwnerButton(){businessCalls++;throw new IllegalStateException("profile route is not Notes");}
 static final class JournalQueue {boolean pending(){return false;}}
 static final class HostQueue {
  final boolean worker;final java.util.ArrayList<Runnable> entries=new java.util.ArrayList<Runnable>();
  HostQueue(boolean worker){this.worker=worker;}void execute(Runnable r){entries.add(r);}boolean post(Runnable r){entries.add(r);return true;}int size(){return entries.size();}
  void drain(){while(!entries.isEmpty()){boolean old=Looper.worker;Looper.worker=worker;try{entries.remove(0).run();}finally{Looper.worker=old;}}}
 }
''' + owner_button + '\n}\n'
        (generated / 'RecoveryOwnerButtonBridge.java').write_text(bridge)
        service = (local / 'HeptaAccessibilityService.java').read_text()
        service_methods = [method(service, anchor) for anchor in (
            '    synchronized boolean personalNotesReconciliationIdle(LocalTaskController expected)',
            '    synchronized void acceptBackgroundReconciliation(BackgroundSession.Cleanup cleanup)',
            '    synchronized void acceptBackgroundReconciliation(JSONObject proof)')]
        ports = list((output / 'legacy').rglob('HeptaAccessibilityService.java'))
        need(len(ports) == 1, 'one explicit legacy Android service port required')
        port = ports[0].read_text()
        port = replace(port, 'static HeptaAccessibilityService connected(){return null;}', 'static HeptaAccessibilityService connected(){return live;}')
        extra = '''
 static HeptaAccessibilityService live;LocalTaskController ownedController;BackgroundSession taskBackground;WebFlightSession taskWeb;String lease;
 Object activeObservation,activeNativeSearchObservation;boolean capturePending,readPending,actionPending,cancelPending;int webAccepted;
 boolean observationReadWorkPending(){return readPending;}boolean actionWorkPending(){return actionPending;}boolean nativeCancellationWorkPending(){return cancelPending;}
 boolean prelaunchReconciliationIdle(LocalTaskController c){return false;}boolean postlaunchReconciliationIdle(LocalTaskController c){return false;}
 boolean publicProfileReconciliationIdle(LocalTaskController c){return false;}boolean publicProfileBusinessReconciliationIdle(LocalTaskController c,String t,String o){return false;}
 void acceptWebReconciliation(WebFlightSession.Cleanup c){if(c==null||!c.known)throw new IllegalStateException("synthetic web absence not accepted");webAccepted++;}
''' + '\n'.join(service_methods)
        close = port.rfind('}')
        port = port[:close] + extra + '\n' + port[close:]
        port = replace(port, 'package org.trillionnium.hepta.local;', 'package org.trillionnium.hepta.local;import org.json.JSONObject;')
        (generated / 'HeptaAccessibilityService.java').write_text(port)
        (generated / 'LocalTaskController.java').write_text('package org.trillionnium.hepta.local;final class LocalTaskController {boolean running;String task;boolean isRunning(){return running;}String currentTaskId(){return task;}}\n')
        (generated / 'WebFlightSession.java').write_text('package org.trillionnium.hepta.local;final class WebFlightSession {static final class Cleanup {final boolean known=true;}static Cleanup reconcile(android.content.Context c){return new Cleanup();}boolean released(){return true;}}\n')
        files = sorted(generated.glob('*.java')) + [own / 'NotesRecoveryRoutingHostTest.java']
        result['production_method_extraction'] = dict(owner_button_sha256=sha(owner_button.encode()), service_methods_sha256=[sha(x.encode()) for x in service_methods],
                                                    full_predecessor_client_sha256=PARENT_CLIENT_SHA, all_methods_verbatim=True,
                                                    actual_current_client_sha256=sha(actual.encode()),
                                                    f4c0_proof_client_sha256=sha(proof_client.encode()),
                                                    current_client_inverse_spans=4, proof_copy_not_compiled=True,
                                                    other_service_types_fail_closed=True, host_queues_are_not_android_runtime=True)
        result['generated_inputs'] = [pin(p) for p in files]
        run('compile', [str(java / 'javac'), '--release', '8', '-Xlint:all,-options', '-Werror', '-encoding', 'UTF-8', '-proc:none',
                        '-cp', cp, '-d', str(classes)] + [str(p) for p in files], output, result, env)
        report = run('routing', [str(java / 'java'), '-cp', cp, 'org.trillionnium.hepta.local.NotesRecoveryRoutingHostTest',
                                str(a.private_input_map.resolve()), str(a.current_input_map.resolve()), str(output / 'scratch')], output, result, env)
        result['routing'] = json.loads(report)
        need(result['routing']['all_pass'], 'actual routing gate failed')
        result['all_pass'] = True
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        result['inputs_unchanged'] = all(pin(Path(p))['sha256'] == digest for p, digest in source_inputs.items())
        result['tools_unchanged'] = all(pin(Path(p)) == row for p, row in tools.items())
        result['original_bytes_unchanged'] = originals == external_inputs(a.private_input_map.resolve(), a.current_input_map.resolve())
        result['all_pass'] = result['all_pass'] and result['inputs_unchanged'] and result['tools_unchanged'] and result['original_bytes_unchanged']
        (output / 'RESULT.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_pass=result['all_pass'], result=pin(output / 'RESULT.json'), error=result.get('error'),
                          cases=result.get('routing', {}).get('cases'), assertions=result.get('routing', {}).get('assertions'))))
    return 0 if result['all_pass'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
