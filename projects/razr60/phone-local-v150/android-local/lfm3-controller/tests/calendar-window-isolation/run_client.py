#!/usr/bin/env python3
"""Full actual BackgroundSession client with original Android IO ports; no broker or APK run."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--java-home',type=Path,required=True);p.add_argument('--header-port-classes',type=Path,required=True)
    a=p.parse_args();source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    here=Path(__file__).resolve().parent
    common=module('calendar_original_host_refs',here/'run_host.py')
    ref,put,inventory=common.ref,common.put,common.inventory
    before=inventory(source)
    result={'schema':'hepta.calendar-probe-client-build-validation.v1','all_pass':False,'source':str(source),
            'source_before':put(out/'SOURCE-BEFORE.json',before),'stages':[],
            'phone_actions':0,'broker_processes':0,'input_dispatch_calls':0,'actual_SDK_compilation':False,'actual_D8_execution':False,'apk_builds':0,
            'actual_full_BackgroundSession':True,'synthetic_authenticated_socket_response':True,
            'vendor_rom_qualification_or_dispatch_authority':False,'old_35_case_gate_reexecuted':False}
    helper=source/'tests/background-session/prepare_fixture.py'
    search=source/'tests/native-app/legacy-boundary/prepare_search_pure.py'
    tools=[Path(sys.executable).resolve(),a.java_home/'bin/java',a.java_home/'bin/javac',a.java_home/'lib/modules',a.java_home/'lib/ct.sym',
           Path(__file__).resolve(),here/'run_host.py',here/'check_build_headers.py',helper,search]
    tool_before=[ref(x) for x in tools];result['tools_before']=tool_before
    port_inputs=[ref(x) for x in sorted(a.header_port_classes.rglob('*')) if x.is_file()]
    result['header_android_port_classes_before']=port_inputs
    env=os.environ.copy();cleared=['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH']
    for key in cleared:env.pop(key,None)
    env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',JAVA_HOME=str(a.java_home),PATH=str(a.java_home/'bin')+':/usr/bin:/bin')
    result['cleared_environment']=cleared
    try:
        fixture=out/'fixture'
        files,record=module('calendar_client_fixture',helper).prepare(source,fixture,include_terminal=True)
        files=module('calendar_client_legacy_search',search).add(source,files)
        ports={
            'android/app/KeyguardManager.java':'package android.app;public final class KeyguardManager {public boolean locked,secure,deviceSecure,deviceLocked;public boolean isKeyguardLocked(){return locked;}public boolean isKeyguardSecure(){return secure;}public boolean isDeviceSecure(){return deviceSecure;}public boolean isDeviceLocked(){return deviceLocked;}}\n',
            'android/os/Looper.java':'package android.os;public final class Looper {public static boolean worker;private static final Looper MAIN=new Looper();public static Looper myLooper(){return worker?null:MAIN;}public static Looper getMainLooper(){return MAIN;}}\n',
            'android/os/Process.java':'package android.os;public final class Process {public static int myUid(){return 10123;}public static int myPid(){return 123;}}\n'}
        for name,text in ports.items():(fixture/name).write_text(text)
        os_path=fixture/'android/system/Os.java';text=os_path.read_text();old='r.st_uid=((Number)a.get("uid")).intValue();'
        if text.count(old)!=1:raise RuntimeError('nonunique original stat port')
        os_path.write_text(text.replace(old,'r.st_uid=10123;'))
        existing=[source/'tests/background-session/BackgroundSessionHostTest.java',source/'tests/background-session/ProfileSessionHostTest.java',
                  source/'tests/public-own-group-policy/PublicOwnGroupSessionHostTest.java']
        files+=existing+[here/'CalendarProbeClientHostTest.java']
        files=list(dict.fromkeys(Path(x).resolve() for x in files))
        record.update(existing_fixtures_compile_only_not_main_executed=[str(x) for x in existing],
                      IO_port_changes='Exact four explicit Android Keyguard/Looper/Process/stat ports already used by public-own-group runner',
                      BackgroundSession_complete_and_unrewritten=True,calendar_qualification_response_is_synthetic=True)
        result['extraction']=put(out/'EXTRACTION.json',record)
        pins=[ref(x) for x in files];result['compile_inputs_before']=pins
        classes=out/'classes';classes.mkdir()
        commands=[('compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-d',classes,*files]),
                  ('client-cases',[a.java_home/'bin/java','-ea','-cp',classes,'org.trillionnium.hepta.local.CalendarProbeClientHostTest',out/'CASES.json']),
                  ('compile-only-build-check',[Path(sys.executable).resolve(),'-B',here/'check_build_headers.py','--source',source,'--output',out/'build-check',
                                              '--java-home',a.java_home,'--port-classes',a.header_port_classes])]
        for name,argv in commands:
            argv=list(map(str,argv));start=time.monotonic();r=subprocess.run(argv,cwd=out,env=env,capture_output=True,timeout=90)
            (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
            result['stages'].append(dict(name=name,argv=argv,exit_code=r.returncode,elapsed_seconds=time.monotonic()-start,
                                        stdout=ref(out/(name+'.stdout')),stderr=ref(out/(name+'.stderr'))))
            if r.returncode:raise RuntimeError(name+' failed with exit '+str(r.returncode))
        case=json.loads((out/'CASES.json').read_bytes());build=json.loads((out/'build-check/RESULT.json').read_bytes())
        if not case['all_pass'] or not build['all_pass']:raise RuntimeError('case report failed')
        result.update(client_cases=case['cases'],client_assertions=case['assertions'],build_cases=build['cases'],build_assertions=build['assertions'],
                      cases=case['cases']+build['cases'],assertions=case['assertions']+build['assertions'],
                      client_case_report=ref(out/'CASES.json'),build_check_report=ref(out/'build-check/RESULT.json'))
        result['compile_inputs_after']=[ref(x) for x in files]
        if result['compile_inputs_after']!=pins:raise RuntimeError('compilation inputs changed')
        result['all_pass']=True
    except BaseException as error:
        result['error']=str(error);result['traceback']=traceback.format_exc()
    result['tools_after']=[ref(x) for x in tools];result['tools_unchanged']=tool_before==result['tools_after']
    result['header_android_port_classes_after']=[ref(x) for x in sorted(a.header_port_classes.rglob('*')) if x.is_file()]
    result['header_android_port_classes_unchanged']=port_inputs==result['header_android_port_classes_after']
    after=inventory(source);result['source_after']=put(out/'SOURCE-AFTER.json',after);result['source_inputs_unchanged']=before==after
    result['all_pass'] &= result['tools_unchanged'] and result['source_inputs_unchanged'] and result['header_android_port_classes_unchanged']
    rr=put(out/'RESULT.json',result);print(json.dumps({'all_pass':result['all_pass'],'cases':result.get('cases'),'assertions':result.get('assertions'),'result':rr}))
    return 0 if result['all_pass'] else 1


if __name__=='__main__':raise SystemExit(main())
