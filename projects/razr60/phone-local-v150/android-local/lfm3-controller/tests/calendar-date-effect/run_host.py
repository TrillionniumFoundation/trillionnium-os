#!/usr/bin/env python3
"""Exercise the complete exact broker perform entry and calendar date methods with explicit Android IO and cleanup/response ports."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback

def ref(path):
    path = Path(path)
    a = path.lstat()
    if not stat.S_ISREG(a.st_mode) or a.st_nlink != 1 or path.is_symlink():
        raise RuntimeError('non-regular input: ' + str(path))
    value = path.read_bytes()
    z = path.lstat()
    if any(getattr(a, k) != getattr(z, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_mtime_ns', 'st_ctime_ns')):
        raise RuntimeError('changed input: ' + str(path))
    return dict(path=str(path), bytes=len(value), sha256=hashlib.sha256(value).hexdigest(), mode=stat.S_IMODE(a.st_mode))


def put(path, value):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    return ref(path)


def inventory(source):
    return {p.relative_to(source).as_posix(): ref(p) for p in sorted(source.rglob('*')) if p.is_file()}



def extract_method(text, signature):
    if text.count(signature) != 1:
        raise RuntimeError('non-unique real broker method: ' + signature)
    a = text.index(signature)
    i = text.index('{', a)
    depth, quote, escaped, line, block = 0, None, False, False, False
    while i < len(text):
        c, n = text[i], text[i + 1:i + 2]
        if line:
            if c == '\n':
                line = False
        elif block:
            if c == '*' and n == '/':
                block = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == quote:
                quote = None
        elif c == '/' and n == '/':
            line = True
            i += 1
        elif c == '/' and n == '*':
            block = True
            i += 1
        elif c in ('"', "'"):
            quote = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[a:i + 1]
        i += 1
    raise RuntimeError('unclosed real method')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    p.add_argument('--json-jar', type=Path, required=True)
    p.add_argument('--reviewed-broker', type=Path, required=True)
    a = p.parse_args()
    source, out = a.source.resolve(), a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    shared = here.parent / 'calendar-window-isolation'
    result = dict(schema='hepta.calendar-date-broker-host-validation.v1', all_pass=False,
                  source=str(source), output=str(out), phone_actions=0, android_runtime=False, vendor_rom_qualified=False,
                  actual_app_attempt_or_slot_authority_tested=False, actual_handler_enabled=True, apk_builds=0,
                  boundary='Complete exact perform, dispatchCalendarDate, calendarMotion, calendarPlatformInt, guard and recheckProfile methods; '
                           'complete real parser/isolation/namespace/capture/value classes. Explicit Android input, current owner/display/PM '
                           'and native listener IO ports; cleanup invocation and response serialization ports. Unrelated perform operations throw. '
                           'Actual entry cases do not issue an App authority, execute platform cleanup, or qualify a ROM.')
    before = inventory(source)
    result['source_before'] = put(out / 'SOURCE-BEFORE.json', before)
    tools = [Path(sys.executable).resolve(), a.java_home/'bin/java', a.java_home/'bin/javac',
             a.java_home/'lib/modules', a.java_home/'lib/ct.sym', a.json_jar, Path(__file__).resolve(),
             here/'date_ports.py', shared/'host_ports.py']
    result['tools_before'] = [ref(x) for x in tools]
    env = os.environ.copy()
    cleared = ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONPATH']
    for k in cleared: env.pop(k, None)
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', JAVA_HOME=str(a.java_home),
               PATH=str(a.java_home/'bin')+':/usr/bin:/bin')
    result['cleared_environment'] = cleared
    stages = []
    result['stages'] = stages
    try:
        spec = importlib.util.spec_from_file_location('calendar_date_ports', here/'date_ports.py')
        ports = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ports)
        generated = out/'generated'
        boot_files, app_ports = [], []
        for prefix, values, rows in [('boot',ports.BOOT,boot_files),('app',ports.APP,app_ports)]:
            for relative, text in values.items():
                path = generated/prefix/relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text+'\n')
                rows.append(path)
        loader = generated/'loader/CalendarHostLoader.java'
        loader.parent.mkdir(parents=True)
        loader.write_text(ports.LOADER)
        original_loader=generated/'loader/OriginalCalendarHostLoader.java'
        original_loader.write_text(ports.LOADER.replace('CalendarHostLoader','OriginalCalendarHostLoader').replace('CalendarDateEntryHostTest','CalendarDateHostTest'))
        full = source/'src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java'
        raw = full.read_text()
        signatures = [
            '    private byte[] perform(BrokerProtocol.Request r) throws Exception {',
            '    private boolean dispatchCalendarDate(BrokerProtocol.Request r)throws Exception{',
            '    private static int calendarPlatformInt(Class<?> type,String name)throws Exception{',
            '    private MotionEvent calendarMotion(long downTime,long when,int action,double[] point,int flags,',
            '    private void guard(BrokerProtocol.Request r, boolean active) throws Exception {',
            '    private void recheckProfile(boolean ready,long deadline)throws Exception {']
        methods = [extract_method(raw, s) for s in signatures]
        template = (here/'BrokerDateHost.template').read_text()
        if template.count('// EXACT_DATE_METHODS') != 1: raise RuntimeError('date extraction marker')
        projection = generated/'app/org/trillionnium/hepta/background/BrokerDateHost.java'
        projection.write_text(template.replace('// EXACT_DATE_METHODS','\n\n'.join(methods)))
        probe = extract_method(raw,'    private void probeCalendarWindow(BrokerProtocol.Request r)throws Exception {')
        probe_template = shared/'BrokerProbeHost.template'
        probe_projection = generated/'app/org/trillionnium/hepta/background/BrokerProbeHost.java'
        probe_projection.write_text(probe_template.read_text().replace('// EXACT_PROBE_METHOD',probe))
        base_ref = ref(a.reviewed_broker)
        if base_ref['sha256'] != 'ae318adba493b8f4c196a396ca72807ecdd680c58a747f01a97f24af56bc1178':
            raise RuntimeError('reviewed baseline changed')
        back = '    private boolean backProfile(BrokerProtocol.Request r)throws Exception {'
        original_back = extract_method(a.reviewed_broker.read_text(),back)
        if extract_method(raw,back) != original_back: raise RuntimeError('legacy BACK changed')
        if raw.count('dispatchCalendarDate(') != 2 or raw.count('dispatched=dispatchCalendarDate(r);') != 1 or 'CALENDAR_DATE_EFFECT_NOT_INTEGRATED' in raw:
            raise RuntimeError('dedicated date route identity differs')
        if 'MotionEvent.ACTION_CANCEL' in raw: raise RuntimeError('unexpected CANCEL path')
        extraction = dict(actual_source=ref(full), template=ref(here/'BrokerDateHost.template'), projection=ref(projection),
            methods=[dict(signature=s, bytes=len(m.encode()),sha256=hashlib.sha256(m.encode()).hexdigest(),copied_verbatim=True) for s,m in zip(signatures,methods)],
            probe_projection=ref(probe_projection),probe_template=ref(probe_template),probe_method_sha256=hashlib.sha256(probe.encode()).hexdigest(),
            reviewed_baseline=base_ref, legacy_back_method_equal=True,legacy_back_method_sha256=hashlib.sha256(original_back.encode()).hexdigest(),
            actual_complete_perform_method=True,handler_enabled=True,private_method_has_exactly_one_production_caller=True,no_cancel_path=True,
            authentication_uses_actual_request_method=True,cleanup_and_response_are_explicit_ports=True,unrelated_operations_fail_closed=True,
            existing_android_owner_and_input_io_are_explicit_ports=True,whole_broker_compiled=False,no_method_logic_rewritten=True)
        result['extraction'] = put(out/'EXTRACTION.json',extraction)
        names=['InputChannelIsolation','WindowInfosCapture','AccessibilityWindowTokens','BrokerProtocol','ProfileIdentity',
               'ProfileTarget','PublicOwnGroupPolicy','PublicPermissionControllerUi','FixedIntentTools','WindowOwnership']
        production=[source/'src/org/trillionnium/hepta/background'/(x+'.java') for x in names]
        heads=[source/'compile-only/window-infos/android/view/InputWindowHandle.java',
               source/'compile-only/window-infos/android/window/WindowInfosListener.java']
        for name in ('boot-classes','head-classes','app-classes','loader-classes'): (out/name).mkdir()
        boot,head,app,load=[out/x for x in ('boot-classes','head-classes','app-classes','loader-classes')]
        common=[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror']
        commands=[
            ('compile-ports',common+['-d',boot,*boot_files]),
            ('compile-heads',common+['-cp',boot,'-d',head,*heads]),
            ('compile-actual',common+['-cp',os.pathsep.join(map(str,(head,boot,a.json_jar))),'-d',app,*production,*app_ports,projection,probe_projection]),
            ('compile-cases',common+['-cp',os.pathsep.join(map(str,(boot,app,a.json_jar))),'-d',app,shared/'CalendarWindowHostTest.java',here/'CalendarDateHostTest.java',here/'CalendarDateEntryHostTest.java']),
            ('compile-loader',common+['-d',load,loader,original_loader]),
            ('original-private-method-cases',[a.java_home/'bin/java','-ea','-cp',load,'OriginalCalendarHostLoader',boot,app,a.json_jar,out/'ORIGINAL-CASES.json']),
            ('actual-method-cases',[a.java_home/'bin/java','-ea','-cp',load,'CalendarHostLoader',boot,app,a.json_jar,out/'ENTRY-CASES.json'])]
        inputs=list(dict.fromkeys([*production,full,*heads,*boot_files,*app_ports,projection,probe_projection,loader,original_loader,
            shared/'CalendarWindowHostTest.java',probe_template,shared/'host_ports.py',here/'BrokerDateHost.template',
            here/'CalendarDateHostTest.java',here/'CalendarDateEntryHostTest.java',here/'date_ports.py',Path(__file__).resolve(),a.reviewed_broker]))
        pins=[ref(x) for x in inputs]
        result['compile_inputs_before']=pins
        for name,command in commands:
            command=[str(x) for x in command]
            started=time.monotonic()
            run=subprocess.run(command,cwd=out,env=env,capture_output=True,timeout=75)
            (out/(name+'.stdout')).write_bytes(run.stdout);(out/(name+'.stderr')).write_bytes(run.stderr)
            stages.append(dict(name=name,argv=command,exit_code=run.returncode,elapsed_seconds=time.monotonic()-started,
                               stdout=ref(out/(name+'.stdout')),stderr=ref(out/(name+'.stderr'))))
            if run.returncode: raise RuntimeError(name+' failed with exit '+str(run.returncode))
        leaked=[str(p.relative_to(app)) for p in app.rglob('*.class') if p.relative_to(app).parts[0]=='android']
        expected=['android/view/InputWindowHandle.class','android/window/WindowInfosListener$DisplayInfo.class','android/window/WindowInfosListener.class']
        if leaked or sorted(p.relative_to(head).as_posix() for p in head.rglob('*.class'))!=expected: raise RuntimeError('header class isolation')
        result['header_class_isolation']=dict(expected_headers=expected,application_android_classes=leaked,app_dex_or_apk_created=False)
        original_cases=json.loads((out/'ORIGINAL-CASES.json').read_bytes())
        entry_cases=json.loads((out/'ENTRY-CASES.json').read_bytes())
        if ref(here/'CalendarDateHostTest.java')['sha256']!='e598af2c3e7e217515688333d8d2b2073788a9717c331a2e08367d42932ec7f6':
            raise RuntimeError('original 28-case source changed')
        if original_cases['cases']!=28 or original_cases['assertions']!=293:
            raise RuntimeError('original private case/count identity changed')
        cases=dict(schema='hepta.calendar-date-combined-broker-host-cases.v1',
            all_pass=original_cases['all_pass'] and entry_cases['all_pass'],
            cases=original_cases['cases']+entry_cases['cases'],assertions=original_cases['assertions']+entry_cases['assertions'],
            rows=original_cases['rows']+entry_cases['rows'],
            original_private_cases=ref(out/'ORIGINAL-CASES.json'),actual_entry_cases=ref(out/'ENTRY-CASES.json'),
            original_case_source_unchanged=True,phone_actions=0,vendor_rom_qualified=False,
            actual_app_attempt_or_slot_authority_tested=False,platform_cleanup_executed=False,whole_socket_loop_executed=False)
        result['case_report']=put(out/'CASES.json',cases);result['cases']=cases['cases'];result['assertions']=cases['assertions']
        result['original_private_cases']=ref(out/'ORIGINAL-CASES.json');result['actual_entry_cases']=ref(out/'ENTRY-CASES.json')
        if not cases['all_pass']: raise RuntimeError('actual date cases refused')
        result['compile_inputs_after']=[ref(x) for x in inputs]
        if result['compile_inputs_after']!=pins: raise RuntimeError('compiled input changed')
        result['all_pass']=True
    except BaseException as e:
        result['error']=str(e);result['traceback']=traceback.format_exc()
        if (out/'CASES.json').exists():
            case=json.loads((out/'CASES.json').read_bytes())
            result['case_report']=ref(out/'CASES.json');result['cases']=case['cases'];result['assertions']=case['assertions']
    after=inventory(source);result['source_after']=put(out/'SOURCE-AFTER.json',after);result['source_inputs_unchanged']=before==after
    result['tools_after']=[ref(x) for x in tools];result['tools_unchanged']=result['tools_before']==result['tools_after']
    result['all_pass'] &= result['source_inputs_unchanged'] and result['tools_unchanged']
    rr=put(out/'RESULT.json',result)
    print(json.dumps(dict(all_pass=result['all_pass'],cases=result.get('cases'),assertions=result.get('assertions'),result=rr)))
    return 0 if result['all_pass'] else 1

if __name__=='__main__':
    raise SystemExit(main())
