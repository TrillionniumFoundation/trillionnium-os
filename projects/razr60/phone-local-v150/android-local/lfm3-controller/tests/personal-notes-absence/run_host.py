#!/usr/bin/env python3
"""Portable Notes current-absence gate. Real policy/client/lease; explicit IO fixtures.

All input task/controller values are authored synthetic values. No phone, shell,
su, Binder, installed APK, display, model, task action or administrative receipt.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import time
from pathlib import Path

JSON_SHA = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError('nonunique explicit fixture seam: ' + str(path))
    path.write_text(text.replace(old, new))


def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'java-home', 'json-jar', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--java8-syntax-only', action='store_true',
                        help='Draft-only JRE module compiler mode; canonical gate must omit.')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if sha(args.json_jar) != JSON_SHA:
        raise RuntimeError('pinned actual org.json differs')
    test = source / 'tests/personal-notes-absence'
    bg, local = (source / 'src/org/trillionnium/hepta' / leaf for leaf in ('background', 'local'))
    pure_names = ['ProfileIdentity', 'ProfileTarget', 'WindowOwnership', 'BrokerProtocol','PublicPermissionControllerUi', 'FixedIntentTools',
                  'BackgroundOwnedTaskPolicy', 'BackgroundOwnedSingleTask', 'ProfileTaskPolicy', 'ProfileOwnedTask',
                  'ProfilePermissionTransient', 'ProfileDisplayCustody', 'ProfilePrelaunchRecovery',
                  'ProfileRecoveryProcesses', 'PublicOwnGroupPolicy', 'PublicOwnGroupPhysicalFence',
                  'PublicProfileRecentHistory', 'PublicProfileAbsenceRecovery', 'PublicPersonalNotesHistory',
                  'PublicPersonalNotesAbsenceRecovery']
    shared_test = source / 'tests/public-own-group-policy/PublicPhysicalAuditHostTest.java'
    pure = [bg / (name + '.java') for name in pure_names] + [shared_test, test / 'PersonalNotesAbsenceHostTest.java', test / 'PersonalNotesPreLaunchHostTest.java']
    jdk = args.java_home.resolve() / 'bin'
    compiler = [str(jdk / 'javac')]
    if args.java8_syntax_only and not (jdk / 'javac').exists():
        compiler = [str(jdk / 'java'), '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = ['-source', '8', '-target', '8'] if args.java8_syntax_only else ['--release', '8']
    compile_args = [*compiler, *flags, '-Xlint:all,-options', '-Werror', '-encoding', 'UTF-8', '-proc:none', '-cp', str(args.json_jar.resolve())]
    pure_classes = output / 'policy-classes'
    pure_classes.mkdir()
    commands = [('policy-compile', [*compile_args, '-d', str(pure_classes), *map(str, pure)]),
                ('policy', [str(jdk / 'java'), '-cp', str(pure_classes) + os.pathsep + str(args.json_jar.resolve()),
                            'org.trillionnium.hepta.background.PersonalNotesAbsenceHostTest']),
                ('pre-launch', [str(jdk / 'java'), '-cp', str(pure_classes) + os.pathsep + str(args.json_jar.resolve()),
                                'org.trillionnium.hepta.background.PersonalNotesPreLaunchHostTest'])]
    helper = source / 'tests/background-session/prepare_fixture.py'
    spec = importlib.util.spec_from_file_location('notes_recovery_bg_fixture', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = output / 'fixture'
    files, derivation = module.prepare(source, fixture, include_terminal=False)
    files = [p for p in files if '/org/json/' not in str(p)]
    replace_once(fixture / 'android/os/Looper.java', 'public static Looper myLooper(){return L;}',
                 'public static boolean worker;public static Looper myLooper(){return worker?null:L;}')
    (fixture / 'android/os/Process.java').write_text('package android.os;public final class Process {public static int myUid(){return 12345;}public static int myPid(){return 123;}}\n')
    replace_once(fixture / 'android/content/Context.java', 'a.sourceDir=new java.io.File(files,"fake.apk").getPath();',
                 'a.sourceDir="/data/app/synthetic/base.apk";')
    os_java = fixture / 'android/system/Os.java'
    replace_once(os_java, 'r.st_uid=((Number)a.get("uid")).intValue();',
                 'r.st_uid=((Number)a.get("uid")).intValue();if(r.st_uid==' + str(os.getuid()) + ')r.st_uid=12345;')
    replace_once(os_java, 'public static String failFsyncPath;',
                 'public static String failFsyncPath;public static boolean corruptPublicArchiveOnSync;public static Runnable afterPublicCommitSync;')
    replace_once(os_java, 'if(fd.valid())fd.sync();', '''if(fd.valid())fd.sync();
        if(corruptPublicArchiveOnSync&&path.endsWith(".original-journal.bin")){corruptPublicArchiveOnSync=false;Files.write(Paths.get(path),new byte[]{1});}
        if(afterPublicCommitSync!=null&&Paths.get(path).getFileName().toString().matches("background-personal-notes-absence-[0-9a-f-]+\\\\.json")){
            Runnable callback=afterPublicCommitSync;afterPublicCommitSync=null;callback.run();}''')
    identity = fixture / 'org/trillionnium/hepta/background/RecoveryControllerIdentity.java'
    identity.write_text('''package org.trillionnium.hepta.background;
import org.json.*;
/** Explicit host PM/APK fixture, never actual installed identity. */
public final class RecoveryControllerIdentity {
 public static boolean changed;
 public static JSONObject read(android.content.Context context,int uid,long deadline)throws Exception{
  if(android.os.SystemClock.elapsedRealtime()>=deadline)throw new java.io.IOException("synthetic identity deadline");
  JSONObject result=new PersonalNotesAbsenceHostTest.Fixture().controller;
  if(changed)result.put("source_sha256",ProfileIdentity.sha("replacement synthetic APK"));
  return result;
 }
}
''')
    client = local / 'PublicPersonalNotesRecoveryClient.java'
    raw_client = client.read_text()
    seam = 'new ProcessBuilder("su","-c",command).redirectErrorStream(true).start()'
    if raw_client.count(seam) != 1:
        raise RuntimeError('Notes owned Process factory seam differs')
    projected = fixture / 'org/trillionnium/hepta/local/PublicPersonalNotesRecoveryClient.java'
    projected.write_text(raw_client.replace(seam, 'FakePersonalNotesRecoveryProcess.start(command)'))
    files += [bg / 'ProfileRecoveryProcesses.java', shared_test, test / 'FakePersonalNotesRecoveryProcess.java',
              test / 'PersonalNotesRecoveryClientHostTest.java', test / 'PersonalNotesAbsenceHostTest.java',
              test / 'PersonalNotesPostModelHostTest.java']
    service = local / 'HeptaAccessibilityService.java'
    service_text = service.read_text()
    methods = []
    for method in ('prelaunchReconciliationIdle', 'postlaunchReconciliationIdle', 'publicProfileReconciliationIdle', 'personalNotesReconciliationIdle'):
        start = service_text.index('    synchronized boolean ' + method + '(')
        end = service_text.index('\n    }', start) + len('\n    }')
        methods.append(service_text[start:end])
    idle = fixture / 'org/trillionnium/hepta/local/PersonalNotesRecoveryIdleFixture.java'
    idle.write_text('''package org.trillionnium.hepta.local;
/** Exact production service admission methods; surrounding Android state is a fixture. */
final class PersonalNotesRecoveryIdleFixture {
 static final class LocalTaskController {boolean running;boolean isRunning(){return running;}String currentTaskId(){return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";}}
 static final class Web {boolean released(){return false;}}
 PersonalNotesRecoveryIdleFixture live=this;LocalTaskController ownedController=new LocalTaskController();
 Object activeObservation;boolean capturePending,pendingObservation,pendingAction,pendingNative;
 BackgroundSession taskBackground;Web taskWeb;String lease=ownedController.currentTaskId();
 PersonalNotesRecoveryIdleFixture(BackgroundSession background){taskBackground=background;}
 boolean observationReadWorkPending(){return pendingObservation;}boolean actionWorkPending(){return pendingAction;}boolean nativeCancellationWorkPending(){return pendingNative;}
''' + '\n'.join(methods) + '\n}\n')
    files.append(idle)
    files = list(dict.fromkeys(files))
    classes = output / 'client-classes'
    classes.mkdir()
    commands += [('client-compile', [*compile_args, '-d', str(classes), *map(str, files)]),
                 ('client', [str(jdk / 'java'), '-cp', str(classes) + os.pathsep + str(args.json_jar.resolve()),
                             'org.trillionnium.hepta.local.PersonalNotesRecoveryClientHostTest']),
                 ('post-model', [str(jdk / 'java'), '-cp', str(classes) + os.pathsep + str(args.json_jar.resolve()),
                             'org.trillionnium.hepta.local.PersonalNotesPostModelHostTest'])]
    sources = list(dict.fromkeys(pure + files + [helper, client, service, local / 'LocalTaskSession.java',
                                               bg / 'PublicPersonalNotesAbsenceMain.java']))
    pins = {str(p): sha(p) for p in sources}
    result = {'schema': 'hepta.personal-notes-absence-host-validation.v1', 'all_pass': False,
              'strict_release8': not args.java8_syntax_only, 'stages': [], 'source_inputs': pins,
              'json_jar_sha256': JSON_SHA, 'phone_operations': 0, 'android_runtime': False,
              'business_success_claimed': False, 'all_task_values_synthetic': True,
              'framework_samples_synthetic': True, 'current_installation_pm_fixture_synthetic': True,
              'owned_process_factory_replacements_only': True, 'fixture_derivation': derivation,
              'actual_service_idle_methods_sha256': hashlib.sha256('\n'.join(methods).encode()).hexdigest(),
              'root_main_compiled_in_android_build_only': True}
    for name, argv in commands:
        (output / (name + '.command.json')).write_text(json.dumps(argv, indent=2) + '\n')
        start = time.monotonic()
        run = subprocess.run(argv, capture_output=True, timeout=60)
        (output / (name + '.stdout')).write_bytes(run.stdout)
        (output / (name + '.stderr')).write_bytes(run.stderr)
        result['stages'].append({'stage': name, 'exit_code': run.returncode, 'seconds': time.monotonic() - start,
                                 'stdout_sha256': hashlib.sha256(run.stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(run.stderr).hexdigest()})
        if run.returncode:
            break
        if name in ('policy', 'pre-launch', 'client', 'post-model'):
            result[name] = json.loads(run.stdout)
    result['inputs_unchanged'] = pins == {str(p): sha(p) for p in sources}
    result['all_pass'] = len(result['stages']) == len(commands) and all(x['exit_code'] == 0 for x in result['stages']) and result['inputs_unchanged']
    (output / 'RESULT.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_pass': result['all_pass'], 'strict_release8': result['strict_release8'], 'result': str(output / 'RESULT.json'), 'stages': result['stages']}))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
