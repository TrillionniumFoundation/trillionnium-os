#!/usr/bin/env python3
"""Host ownership, permission-init and physical-fence policy checks.

This runner does not execute or qualify Android Binder/A11y adapters or build an APK.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import shutil
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def public_reader_fixture(source, output):
    """Execute the exact new reader/coordinator body; only Android IO is inert.

    The original complete physical parser and actual scope/wire/policy remain
    production classes. These files are host-only outputs, never APK sources.
    """
    original = source / 'src/org/trillionnium/hepta/background/PublicOwnGroupPhysicalReader.java'
    raw = original.read_text()
    begin = '    static final class InitializationRead {'
    end = '    static Map<Integer,String> read(Object windowManager,'
    if raw.count(begin) != 1 or raw.count(end) != 1:
        raise RuntimeError('public initialization reader extraction boundary changed')
    body = raw[raw.index(begin):raw.index(end)]
    files = {
        'org/trillionnium/hepta/background/PublicOwnGroupPhysicalReader.java': '''package org.trillionnium.hepta.background;
import java.util.*;import java.io.*;import java.util.function.LongSupplier;
import android.hardware.display.DisplayManager;import android.os.SystemClock;
final class PublicOwnGroupPhysicalReader {
'''+body+'''
 static String activities,windows,recents;static int physicalReads,dumps;static long advanceAfterDump;
 static Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> firstDisplays,lastDisplays;
 private static Map<Integer,PublicOwnGroupPhysicalFence.DisplayFacts> displayFacts(DisplayManager ignored){
  return physicalReads++==0?firstDisplays:lastDisplays;
 }
 private static String dump(Object ignored,String[] arguments,LongSupplier deadline)throws IOException{
  dumps++;if(arguments.length!=2||!"-a".equals(arguments[0]))throw new IOException("unexpected fixture dump");
  if("activities".equals(arguments[1]))return activities;
  if("displays".equals(arguments[1]))return windows;
  if("recents".equals(arguments[1])){SystemClock.now+=advanceAfterDump;return recents;}
  throw new IOException("unexpected fixture dump");
 }
 static InitializationRead exercise(PublicOwnGroupPolicy.Scope scope,ProfileTarget target,
     PublicOwnGroupPolicy.Readback first,PublicOwnGroupPolicy.Readback last,long deadline)throws Exception{
  physicalReads=0;dumps=0;
  return readInitialization(new Object(),new DisplayManager(),new Object(),new PublicOwnGroupFramework(first,last),
    scope,target,first.display.displayId,first.display.name,null,()->deadline);
 }
}
final class PublicOwnGroupFramework {
 private final PublicOwnGroupPolicy.Readback first,last;int reads;
 PublicOwnGroupFramework(PublicOwnGroupPolicy.Readback first,PublicOwnGroupPolicy.Readback last){this.first=first;this.last=last;}
 PublicOwnGroupPolicy.Readback read(String request,int display,String name){return reads++==0?first:last;}
}
final class BackgroundTaskOrganizer {
 static PublicPermissionControllerUi.Task readOnlyControllerTask(Object ignored,int task,int display,LongSupplier deadline)throws IOException{
  throw new IOException("physical controller IO is covered by the original main-ui-permission gate");
 }
}
''',
        'android/hardware/display/DisplayManager.java': 'package android.hardware.display;public final class DisplayManager {}\n',
        'android/os/Build.java': 'package android.os;public final class Build {public static final class VERSION {public static int SDK_INT=36;}}\n',
        'android/os/SystemClock.java': 'package android.os;public final class SystemClock {public static long now=1000;public static long elapsedRealtime(){return now;}}\n',
        'android/app/ActivityManager.java': 'package android.app;public final class ActivityManager {public static Object getService(){return new Object();}}\n',
    }
    generated = []
    for relative, content in files.items():
        path = output/'public-initialization-reader-ports'/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        generated.append(path)
    receipt = {'source': str(original), 'source_sha256': digest(original),
               'exact_body_sha256': hashlib.sha256(body.encode()).hexdigest(),
               'whole_physical_parser_is_production': True,
               'substitutes': ['framework readback and DisplayManager IO', 'Binder dump transport',
                              'Android elapsed clock', 'unused physical-controller Binder lookup'],
               'android_runtime': False, 'phone_operations': 0}
    return generated, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    classes = output / 'classes'
    classes.mkdir()
    background = source / 'src/org/trillionnium/hepta/background'
    names = ['ProfileIdentity', 'ProfileTarget', 'WindowOwnership', 'BrokerProtocol','PublicPermissionControllerUi', 'PublicOwnGroupPolicy',
             'FixedIntentTools', 'BackgroundOwnedTaskPolicy', 'BackgroundOwnedSingleTask',
             'ProfileTaskPolicy', 'ProfileOwnedTask', 'ProfilePermissionTransient', 'ProfileDisplayCustody',
             'PermissionWindowObservation', 'PhysicalDisplayFence', 'PublicOwnGroupPhysicalFence']
    inputs = [background / (name + '.java') for name in names]
    inputs += [source / 'src/org/trillionnium/hepta/local/NativeAppGoal.java',
               source / 'src/org/trillionnium/hepta/local/ProfilePermissionInitialization.java',
               source / 'tests/profile-broker/ProfileBrokerHostTest.java',
               source / 'tests/profile-permission-transient/ProfilePermissionTransientHostTest.java',
               source / 'tests/profile-permission-transient/ProfileStateSettleHostTest.java',
               source / 'tests/profile-permission-initialization/ProfilePermissionInitializationHostTest.java',
               source / 'tests/profile-permission-initialization/PhysicalDisplayFenceHostTest.java',
               source / 'tests/public-own-group-policy/PublicPhysicalAuditHostTest.java']
    fixture = source / 'tests/profile-permission-transient/fixtures/synthetic-activities.txt'
    pair_runner = source / 'tests/profile-permission-transient/run_host.py'
    platform = background / 'ProfileTaskPlatform.java'
    tracked = inputs + [fixture, Path(__file__).resolve(), pair_runner, platform,
                        background/'PublicOwnGroupPhysicalReader.java']
    pins = {str(p): digest(p) for p in tracked}
    result = {'schema': 'hepta.permission-init-core-host.v1', 'all_pass': False,
              'base_head': 'f7dbe2f1c06e34c992b140d5d88995a8e99c03db',
              'source_head_from_ci': None,
              'candidate_android_integration_present': True, 'android_adapters_compiled': False,
              'phone_contacted': False, 'apk_built': False, 'fixtures_synthetic': True,
              'java_source_level': 8, 'java_target_level': 8, 'java_release_api_check': True,
              'compiler_contract': 'Java 8 API release; no fallback from --release 8',
              'source_inputs_sha256': pins, 'stages': []}

    def run(name, argv):
        begun = time.monotonic()
        process = subprocess.run(argv, capture_output=True, timeout=60)
        (output / (name + '.stdout')).write_bytes(process.stdout)
        (output / (name + '.stderr')).write_bytes(process.stderr)
        result['stages'].append({'name': name, 'exit_code': process.returncode,
                                 'elapsed_seconds': time.monotonic() - begun,
                                 'stdout_sha256': hashlib.sha256(process.stdout).hexdigest(),
                                 'stderr_sha256': hashlib.sha256(process.stderr).hexdigest()})
        if process.returncode:
            raise RuntimeError(name + ' failed; see original stdout/stderr')
        return process.stdout.decode('utf-8')

    try:
        original_tests = {'tests/profile-broker/ProfileBrokerHostTest.java': '5880a651260aa18566364f4dbca427c5adbba8048eee7f1b8a3d55f4a6f69e04', 'tests/profile-permission-transient/ProfilePermissionTransientHostTest.java': '7ac5d394010ca7e42e87ea7902bd96dd425530df3eaf4f485a8ce5efb529f162', 'tests/profile-permission-transient/ProfileStateSettleHostTest.java': 'e1b13341ce3db24921f78b4c378c7635253d659abb44027b3d582a0d808a2cf1'}
        for name, expected in original_tests.items():
            if digest(source/name) != expected:
                raise RuntimeError("Original ownership test changed: "+name)
        result["original_ownership_test_files_unchanged"] = True
        java=args.java_home.resolve()/"bin/java"
        javac=args.java_home.resolve()/"bin/javac"
        if not java.is_file() or not javac.is_file():
            raise RuntimeError("Existing full JDK required; no fallback")
        if digest(fixture) != '7f8adcb158486f74a1ebe342e54902b9fc7550ed7b0dd7bf11b36d1d97ab63f0':
            raise RuntimeError('synthetic fixture pin differs')
        pair_spec = importlib.util.spec_from_file_location('permission_init_pair_fixture', pair_runner)
        pair_module = importlib.util.module_from_spec(pair_spec)
        pair_spec.loader.exec_module(pair_module)
        generated, pair_receipt = pair_module.prepare_permission_pair_adapters(platform, output)
        inputs += generated
        pins.update({str(path): digest(path) for path in generated})
        result['permission_pair_adapter'] = pair_receipt
        public_generated, public_receipt = public_reader_fixture(source, output)
        inputs += public_generated
        pins.update({str(path): digest(path) for path in public_generated})
        result['public_initialization_reader'] = public_receipt
        result['compiler'] = run('compiler-version', [str(javac), '-version']).strip()
        run('compile', [str(javac), '--release', '8',
                        '-encoding', 'UTF-8', '-d', str(classes)] + [str(p) for p in inputs])
        run('original-profile-broker', [str(java), '-cp', str(classes),
                                       'org.trillionnium.hepta.background.ProfileBrokerHostTest'])
        run('original-permission-transient', [str(java), '-cp', str(classes),
                    'org.trillionnium.hepta.background.ProfilePermissionTransientHostTest', str(fixture), 'synthetic'])
        run('original-state-settle', [str(java), '-cp', str(classes),
                    'org.trillionnium.hepta.background.ProfileStateSettleHostTest', str(fixture)])
        new_output = run('permission-initialization', [str(java), '-cp', str(classes),
                    'org.trillionnium.hepta.background.ProfilePermissionInitializationHostTest', str(fixture)])
        result['new_policy_cases'] = json.loads(new_output.rstrip().splitlines()[-1])
        fence_output = run('physical-fence', [str(java), '-cp', str(classes),
                    'org.trillionnium.hepta.background.PhysicalDisplayFenceHostTest'])
        result['physical_fence_cases'] = json.loads(fence_output.rstrip().splitlines()[-1])
        for path, before in pins.items():
            if digest(Path(path)) != before:
                raise RuntimeError('input changed during execution: ' + path)
        result['source_inputs_unchanged'] = True
        result['all_pass'] = True
    except Exception as error:
        result['error']=str(error)
    finally:
        (output / 'RESULT.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_pass': result['all_pass'], 'new_policy_cases': result.get('new_policy_cases'),
                      'result': str(output / 'RESULT.json'), 'error':result.get('error')}, ensure_ascii=False))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
