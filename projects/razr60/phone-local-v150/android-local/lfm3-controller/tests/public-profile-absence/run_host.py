#!/usr/bin/env python3
"""Actual public recovery policy/client/lease; explicit Android, PM and owned-Process fixtures.

No phone connection. The fixture argument contains archived failed-task originals,
never a live Android path. Existing legacy profile cases remain unchanged.
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
        raise RuntimeError('fixture seam changed: ' + str(path))
    path.write_text(text.replace(old, new))


def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'java-home', 'json-jar', 'output', 'actual-originals'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--java8-syntax-only', action='store_true',
                        help='Explicit draft check for a JRE compiler without ct.sym; final gate must omit this flag.')
    args = parser.parse_args()
    source, output, originals = args.source.resolve(), args.output.resolve(), args.actual_originals.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if sha(args.json_jar) != JSON_SHA:
        raise RuntimeError('pinned actual org.json differs')
    test = source / 'tests/public-profile-absence'
    bg = source / 'src/org/trillionnium/hepta/background'
    local = source / 'src/org/trillionnium/hepta/local'
    pure_names = ['ProfileIdentity', 'ProfileTarget', 'WindowOwnership', 'BrokerProtocol','PublicPermissionControllerUi', 'FixedIntentTools',
                  'BackgroundOwnedTaskPolicy', 'BackgroundOwnedSingleTask', 'ProfileTaskPolicy', 'ProfileOwnedTask',
                  'ProfilePermissionTransient', 'ProfileDisplayCustody', 'ProfilePrelaunchRecovery',
                  'ProfileRecoveryProcesses', 'PublicOwnGroupPolicy', 'PublicOwnGroupPhysicalFence',
                  'PublicProfileRecentHistory', 'PublicProfileAbsenceRecovery']
    pure_sources = [bg / (name + '.java') for name in pure_names] + [test / 'PublicProfileAbsenceHostTest.java',
                    source / 'tests/profile-recovery-census/ProfileRecoveryCensusHostTest.java',
                    source / 'tests/profile-recovery/ProfileRecoveryHostTest.java']
    pure_classes = output / 'policy-classes'
    pure_classes.mkdir()
    jdk = args.java_home.resolve() / 'bin'
    flags = ['-source', '8', '-target', '8'] if args.java8_syntax_only else ['--release', '8']
    compile_args = [str(jdk / 'javac'), *flags, '-Xlint:all,-options', '-Werror', '-encoding', 'UTF-8', '-proc:none', '-cp', str(args.json_jar.resolve())]
    commands = [('policy-compile', [*compile_args, '-d', str(pure_classes), *map(str, pure_sources)]),
                ('policy', [str(jdk / 'java'), '-cp', str(pure_classes) + os.pathsep + str(args.json_jar.resolve()),
                            'org.trillionnium.hepta.background.PublicProfileAbsenceHostTest', str(originals)]),
                ('census-regression', [str(jdk / 'java'), '-cp', str(pure_classes) + os.pathsep + str(args.json_jar.resolve()),
                                       'org.trillionnium.hepta.background.ProfileRecoveryCensusHostTest'])]
    spec = importlib.util.spec_from_file_location('public_recovery_bg_fixture', source / 'tests/background-session/prepare_fixture.py')
    fixture_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture_module)
    fixture = output / 'fixture'
    files, derivation = fixture_module.prepare(source, fixture)
    # This legacy recovery fixture binds no typed search Session or Offer.
    search_helper = source/'tests/native-app/legacy-boundary/prepare_search_pure.py'
    search_spec = importlib.util.spec_from_file_location('public_absence_search_pure', search_helper)
    search_pure = importlib.util.module_from_spec(search_spec); search_spec.loader.exec_module(search_pure)
    files = search_pure.add(source, files)
    files = [p for p in files if '/org/json/' not in str(p)]
    replace_once(fixture / 'android/os/Looper.java', 'public static Looper myLooper(){return L;}',
                 'public static boolean worker;public static Looper myLooper(){return worker?null:L;}')
    (fixture / 'android/os/Process.java').write_text('package android.os;public final class Process {public static int myUid(){return 10481;}public static int myPid(){return 123;}}\n')
    replace_once(fixture / 'android/content/Context.java', 'a.sourceDir=new java.io.File(files,"fake.apk").getPath();',
                 'a.sourceDir="/data/app/host-fixture/base.apk";')
    os_java = fixture / 'android/system/Os.java'
    replace_once(os_java, 'r.st_uid=((Number)a.get("uid")).intValue();',
                 'r.st_uid=((Number)a.get("uid")).intValue();if(r.st_uid==' + str(os.getuid()) + ')r.st_uid=10481;')
    replace_once(os_java, 'public static String failFsyncPath;',
                 'public static String failFsyncPath;public static boolean corruptPublicArchiveOnSync;public static Runnable afterPublicCommitSync;')
    replace_once(os_java, 'if(fd.valid())fd.sync();', '''if(fd.valid())fd.sync();
        if(corruptPublicArchiveOnSync&&path.endsWith(".original-journal.bin")){corruptPublicArchiveOnSync=false;Files.write(Paths.get(path),new byte[]{1});}
        if(afterPublicCommitSync!=null&&Paths.get(path).getFileName().toString().matches("background-public-absence-[0-9a-f-]+\\\\.json")){
            Runnable callback=afterPublicCommitSync;afterPublicCommitSync=null;callback.run();}''')
    identity = fixture / 'org/trillionnium/hepta/background/RecoveryControllerIdentity.java'
    identity.write_text('''package org.trillionnium.hepta.background;
import org.json.*;
/** Explicit host PM/APK fixture, never claims actual installed identity. */
public final class RecoveryControllerIdentity {
 public static boolean changed;
 public static JSONObject read(android.content.Context context,int uid,long deadline)throws Exception{
  if(android.os.SystemClock.elapsedRealtime()>=deadline)throw new java.io.IOException("synthetic identity deadline");
  String hash=String.join("",java.util.Collections.nCopies(64,changed?"b":"a"));
  return new JSONObject().put("schema","hepta.recovery-controller-installation.v1").put("package",PublicProfileAbsenceRecovery.CONTROLLER)
    .put("user_id",0).put("uid",uid).put("source_path","/data/app/host-fixture/base.apk").put("source_bytes",22000000)
    .put("source_sha256",hash).put("version_code",70).put("signer_sha256",new JSONArray().put(hash));
 }
}
''')
    client = local / 'PublicProfileRecoveryClient.java'
    client_text = client.read_text()
    seam = 'new ProcessBuilder("su","-c",command).redirectErrorStream(true).start()'
    if client_text.count(seam) != 1:
        raise RuntimeError('public client owned Process seam differs')
    projected_client = fixture / 'org/trillionnium/hepta/local/PublicProfileRecoveryClient.java'
    projected_client.write_text(client_text.replace(seam, 'FakePublicRecoveryProcess.start(command)'))
    files += [test / 'FakePublicRecoveryProcess.java', test / 'PublicProfileRecoveryClientHostTest.java', test / 'PublicProfileAbsenceHostTest.java']
    files += [source / 'tests/background-session/BackgroundSessionHostTest.java', source / 'tests/background-session/ProfileSessionHostTest.java']
    files += [source / 'tests/profile-recovery/RecoveryProofFixture.java', source / 'tests/profile-recovery/ProfileRecoveryHostTest.java']
    files.append(bg / 'ProfileRecoveryProcesses.java')
    service_text = (local / 'HeptaAccessibilityService.java').read_text()
    idle_methods = []
    for method in ('prelaunchReconciliationIdle', 'postlaunchReconciliationIdle', 'publicProfileReconciliationIdle'):
        start = service_text.index('    synchronized boolean ' + method + '(')
        end = service_text.index('\n    }', start) + len('\n    }')
        idle_methods.append(service_text[start:end])
    idle = fixture / 'org/trillionnium/hepta/local/PublicRecoveryIdleFixture.java'
    idle.write_text('''package org.trillionnium.hepta.local;
/** Exact production service admission methods; only surrounding Android state is a fixture. */
final class PublicRecoveryIdleFixture {
 static final class LocalTaskController {boolean running;boolean isRunning(){return running;}String currentTaskId(){return "9579cd438a7f46b598c2c21b714f02b3";}}
 static final class Web {boolean released(){return false;}}
 PublicRecoveryIdleFixture live=this;LocalTaskController ownedController=new LocalTaskController();
 Object activeObservation;boolean capturePending,pendingObservation,pendingAction,pendingNative;
 // Explicit absent readonly port; the actual extracted idle predicates remain unchanged.
 final Object activeNativeSearchObservation=null;
 BackgroundSession taskBackground;Web taskWeb;String lease=ownedController.currentTaskId();
 PublicRecoveryIdleFixture(BackgroundSession background){taskBackground=background;}
 boolean observationReadWorkPending(){return pendingObservation;}boolean actionWorkPending(){return pendingAction;}boolean nativeCancellationWorkPending(){return pendingNative;}
''' + '\n'.join(idle_methods) + '\n}\n')
    files.append(idle)
    files = list(dict.fromkeys(files))
    classes = output / 'client-classes'
    classes.mkdir()
    cp = str(classes) + os.pathsep + str(args.json_jar.resolve())
    commands += [('client-compile', [*compile_args, '-d', str(classes), *map(str, files)]),
                 ('client', [str(jdk / 'java'), '-cp', cp, 'org.trillionnium.hepta.local.PublicProfileRecoveryClientHostTest', str(originals)]),
                 ('legacy-profile', [str(jdk / 'java'), '-cp', cp, 'org.trillionnium.hepta.local.ProfileSessionHostTest', str(output / 'legacy-profile.json')])]
    sources = list(dict.fromkeys(pure_sources + files + [search_helper, client, local / 'HeptaAccessibilityService.java', local / 'LocalTaskSession.java',
                                bg / 'PublicProfileRecoveryMain.java', bg / 'RecoveryControllerIdentity.java']))
    pins = {str(p): sha(p) for p in sources}
    actual_leaves = ['background-session.json', 'owner.json', 'background-bootstrap.json', 'background-cleanup.json', 'result.json',
                    'background-broker-2a746961-06d0-4a8e-9f53-2d34cadbaa99.json', 'background-broker-2a746961-06d0-4a8e-9f53-2d34cadbaa99.bin']
    original_pins = {name: sha(originals / name) for name in actual_leaves}
    history_pins = {name: sha(originals / name) for name in ('before-recents.txt', 'after-recents.txt')}
    if history_pins != {'before-recents.txt': 'bb1335844af98cf8a2a435ab8b10a6bf9930ccd96bc162bff38150c9a7d1ee6a',
                        'after-recents.txt': '5755f3c99126d9f093272b7b73cce47a74049d5398110a1c8d97465e1952c4f3'}:
        raise RuntimeError('actual archived recents inputs differ')
    result = {'schema': 'hepta.public-profile-absence-host-validation.v1', 'all_pass': False, 'stages': [],
              'source_inputs': pins, 'actual_original_inputs': original_pins, 'strict_release8': not args.java8_syntax_only,
              'actual_archived_recents_inputs': history_pins,
              'json_jar_sha256': JSON_SHA, 'phone_contacted': False, 'android_runtime': False,
              'owned_process_factory_replacements_only': True, 'framework_samples_synthetic': True,
              'current_installation_pm_fixture_synthetic': True, 'fixture_derivation': derivation}
    result['actual_service_idle_methods_sha256'] = hashlib.sha256('\n'.join(idle_methods).encode()).hexdigest()
    for name, argv in commands:
        started = time.monotonic()
        run = subprocess.run(argv, capture_output=True, timeout=60)
        (output / (name + '.stdout')).write_bytes(run.stdout)
        (output / (name + '.stderr')).write_bytes(run.stderr)
        result['stages'].append({'stage': name, 'exit_code': run.returncode, 'elapsed_seconds': time.monotonic() - started,
                                 'stdout_sha256': hashlib.sha256(run.stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(run.stderr).hexdigest()})
        if run.returncode:
            break
        if name in ('policy', 'census-regression', 'client'):
            result[name] = json.loads(run.stdout)
    result['inputs_unchanged'] = pins == {str(p): sha(p) for p in sources}
    result['originals_unchanged'] = original_pins == {name: sha(originals / name) for name in actual_leaves}
    result['archived_recents_unchanged'] = history_pins == {name: sha(originals / name) for name in history_pins}
    result['all_pass'] = len(result['stages']) == len(commands) and all(x['exit_code'] == 0 for x in result['stages']) and result['inputs_unchanged'] and result['originals_unchanged'] and result['archived_recents_unchanged']
    (output / 'RESULT.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_pass': result['all_pass'], 'result': str(output / 'RESULT.json'), 'strict_release8': result['strict_release8'], 'stages': result['stages']}, ensure_ascii=False))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
