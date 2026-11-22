#!/usr/bin/env python3
"""Compile actual read-only calendar helpers and exact broker method with explicit Android IO ports."""
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
        raise RuntimeError('non-unique real broker method')
    a = text.index(signature)
    p = text.index('{', a)
    depth = 0
    quote = None
    escape = False
    for i in range(p, len(text)):
        c = text[i]
        if quote:
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == quote:
                quote = None
        elif c in ('"', "'"):
            quote = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if not depth:
                return text[a:i + 1]
    raise RuntimeError('unclosed real broker method')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    p.add_argument('--json-jar', type=Path, required=True)
    a = p.parse_args()
    source, out = a.source.resolve(), a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'hepta.calendar-window-host-validation.v1', 'all_pass': False,
              'source': str(source), 'output': str(out), 'phone_actions': 0, 'input_dispatch_calls': 0,
              'android_runtime': False, 'vendor_rom_qualified': False, 'apk_builds': 0,
              'native_registration_deadline_is_not_hard_cancellation': True,
              'boundary': 'Actual pure comparison, complete WindowInfosCapture and AccessibilityWindowTokens, '
                          'complete BrokerProtocol and exact new broker method. Android Binder/clock/geometry '
                          'and existing owner/display guard IO are explicit host ports; parent loader simulates '
                          'the boot boundary. This does not qualify vendor WindowInfos or input isolation.'}
    before = inventory(source)
    result['source_before'] = put(out / 'SOURCE-BEFORE.json', before)
    here = Path(__file__).resolve().parent
    tools = [Path(sys.executable).resolve(), a.java_home / 'bin/java', a.java_home / 'bin/javac',
             a.java_home / 'lib/modules', a.java_home / 'lib/ct.sym', a.json_jar, Path(__file__).resolve(), here / 'host_ports.py']
    tool_before = [ref(x) for x in tools]
    result['tools_before'] = tool_before
    env = os.environ.copy()
    cleared = ['JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH', 'PYTHONPATH']
    for k in cleared:
        env.pop(k, None)
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', JAVA_HOME=str(a.java_home), PATH=str(a.java_home / 'bin') + ':/usr/bin:/bin')
    result['cleared_environment'] = cleared
    stages = []
    result['stages'] = stages
    try:
        spec = importlib.util.spec_from_file_location('calendar_host_ports', here / 'host_ports.py')
        ports = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ports)
        generated = out / 'generated'
        boot_files, app_ports = [], []
        for prefix, values, rows in [('boot', ports.BOOT, boot_files), ('app', ports.APP, app_ports)]:
            for relative, text in values.items():
                path = generated / prefix / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text + '\n')
                rows.append(path)
        loader = generated / 'loader/CalendarHostLoader.java'
        loader.parent.mkdir(parents=True)
        loader.write_text(ports.LOADER)
        full = source / 'src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java'
        raw = full.read_text()
        method = extract_method(raw, '    private void probeCalendarWindow(BrokerProtocol.Request r)throws Exception {')
        template = (here / 'BrokerProbeHost.template').read_text()
        if template.count('// EXACT_PROBE_METHOD') != 1:
            raise RuntimeError('nonunique extraction insertion')
        projection = generated / 'app/org/trillionnium/hepta/background/BrokerProbeHost.java'
        projection.write_text(template.replace('// EXACT_PROBE_METHOD', method))
        extraction = dict(actual_source=ref(full), method='probeCalendarWindow',
                          method_bytes=len(method.encode()), method_sha256=hashlib.sha256(method.encode()).hexdigest(),
                          method_copied_verbatim=True, template=ref(here / 'BrokerProbeHost.template'), projection=ref(projection),
                          existing_guard_and_owner_display_ports_are_explicit=True,
                          whole_broker_compiled=False, no_method_logic_rewritten=True)
        result['extraction'] = put(out / 'EXTRACTION.json', extraction)
        production_names = ['InputChannelIsolation', 'WindowInfosCapture', 'AccessibilityWindowTokens', 'BrokerProtocol',
                            'ProfileIdentity', 'ProfileTarget', 'PublicOwnGroupPolicy', 'PublicPermissionControllerUi',
                            'FixedIntentTools', 'WindowOwnership']
        production = [source / 'src/org/trillionnium/hepta/background' / (x + '.java') for x in production_names]
        heads = [source / 'compile-only/window-infos/android/view/InputWindowHandle.java',
                 source / 'compile-only/window-infos/android/window/WindowInfosListener.java']
        for name in ('boot-classes', 'head-classes', 'app-classes', 'loader-classes'):
            (out / name).mkdir()
        boot, head, app, load = [out / x for x in ('boot-classes', 'head-classes', 'app-classes', 'loader-classes')]
        common = [a.java_home / 'bin/javac', '--release', '8', '-encoding', 'UTF-8', '-proc:none', '-Xlint:all,-options', '-Werror']
        commands = [
            ('compile-ports', common + ['-d', boot, *boot_files]),
            ('compile-heads', common + ['-cp', boot, '-d', head, *heads]),
            ('compile-actual', common + ['-cp', os.pathsep.join(map(str, (head, boot, a.json_jar))), '-d', app,
                                        *production, *app_ports, projection]),
            ('compile-cases', common + ['-cp', os.pathsep.join(map(str, (boot, app, a.json_jar))), '-d', app,
                                       here / 'CalendarWindowHostTest.java']),
            ('compile-loader', common + ['-d', load, loader]),
            ('actual-method-cases', [a.java_home / 'bin/java', '-ea', '-cp', load, 'CalendarHostLoader', boot, app, a.json_jar, out / 'CASES.json']),
            ('same-loader-refusal', [a.java_home / 'bin/java', '-ea', '-cp', os.pathsep.join(map(str, (boot, app, a.json_jar))),
                                     'org.trillionnium.hepta.background.CalendarWindowHostTest', out / 'SAME-LOADER.json', 'same-loader'])]
        inputs = list(dict.fromkeys([*production, full, *heads, *boot_files, *app_ports, projection, loader,
                                   here / 'CalendarWindowHostTest.java', here / 'BrokerProbeHost.template', here / 'host_ports.py', Path(__file__).resolve()]))
        pins = [ref(x) for x in inputs]
        result['compile_inputs_before'] = pins
        for name, command in commands:
            command = [str(x) for x in command]
            started = time.monotonic()
            r = subprocess.run(command, cwd=out, env=env, capture_output=True, timeout=75)
            (out / (name + '.stdout')).write_bytes(r.stdout)
            (out / (name + '.stderr')).write_bytes(r.stderr)
            stages.append(dict(name=name, argv=command, exit_code=r.returncode, elapsed_seconds=time.monotonic() - started,
                               stdout=ref(out / (name + '.stdout')), stderr=ref(out / (name + '.stderr'))))
            if r.returncode:
                raise RuntimeError(name + ' failed with exit ' + str(r.returncode))
        leaked = [str(p.relative_to(app)) for p in app.rglob('*.class') if p.relative_to(app).parts[0] == 'android']
        expected_heads = ['android/view/InputWindowHandle.class', 'android/window/WindowInfosListener$DisplayInfo.class', 'android/window/WindowInfosListener.class']
        if leaked or sorted(p.relative_to(head).as_posix() for p in head.rglob('*.class')) != expected_heads:
            raise RuntimeError('compile-only headers leaked or shape changed')
        result['header_class_isolation'] = dict(expected_headers=expected_heads, application_android_classes=leaked,
                                                android_header_packaged=False, app_dex_or_apk_created=False)
        case = json.loads((out / 'CASES.json').read_bytes())
        same = json.loads((out / 'SAME-LOADER.json').read_bytes())
        if not case['all_pass'] or not same['all_pass']:
            raise RuntimeError('actual case refusal')
        result['cases'] = case['cases'] + same['cases']
        result['assertions'] = case['assertions'] + same['assertions']
        result['case_report'] = ref(out / 'CASES.json')
        result['same_loader_report'] = ref(out / 'SAME-LOADER.json')
        result['compile_inputs_after'] = [ref(x) for x in inputs]
        if result['compile_inputs_after'] != pins:
            raise RuntimeError('compile inputs changed')
        result['all_pass'] = True
    except BaseException as e:
        result['error'] = str(e)
        result['traceback'] = traceback.format_exc()
    after = inventory(source)
    result['source_after'] = put(out / 'SOURCE-AFTER.json', after)
    result['source_inputs_unchanged'] = before == after
    result['tools_after'] = [ref(x) for x in tools]
    result['tools_unchanged'] = tool_before == result['tools_after']
    result['all_pass'] &= result['source_inputs_unchanged'] and result['tools_unchanged']
    rr = put(out / 'RESULT.json', result)
    print(json.dumps({'all_pass': result['all_pass'], 'cases': result.get('cases'), 'assertions': result.get('assertions'), 'result': rr}))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
