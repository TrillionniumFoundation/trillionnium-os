#!/usr/bin/env python3
"""Exact archived C/D, typed refusal and partial-edge boundaries; no device operation."""
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

sys.dont_write_bytecode = True


def ref(path):
    path = Path(path).resolve()
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), mode=stat.S_IMODE(before.st_mode))


def inventory(source):
    return [dict(relative_path=p.relative_to(source).as_posix(), **ref(p)) for p in sorted(source.rglob('*')) if p.is_file()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('source', 'output', 'java-home', 'json-jar', 'actual-action'):
        parser.add_argument('--' + key, required=True, type=Path)
    args = parser.parse_args()
    source, output, jdk, jar = [getattr(args, key).resolve() for key in ('source', 'output', 'java_home', 'json_jar')]
    if output.exists() or source in output.parents:
        raise RuntimeError('fresh outside-source output required')
    output.mkdir(mode=0o700)
    test = source / 'tests/native-search-carousel-edge'
    fixture = args.actual_action.resolve()
    if (ref(fixture)['bytes'], ref(fixture)['sha256']) != (213701, 'cb97f512faccc62e826157b09181a503abc32c14c53b58fb4fca583e2fcf19ec'):
        raise RuntimeError('exact unmodified b813 action original required')
    helper = source / 'tests/native-search-planning/host_closure.py'
    report = dict(schema='hepta.xiaomi-banner-refusal-recovery-host-run.v1', all_pass=False, source=str(source),
                  source_before=inventory(source), stages=[], phone_operations=0, model_executions=0,
                  android_execution=False, business_verified=False)
    tool_paths = [jdk / 'bin/java', jdk / 'bin/javac', jdk / 'lib/modules', jdk / 'lib/ct.sym', jar]
    report['tools_before'] = [ref(p) for p in tool_paths]
    inputs = []
    try:
        spec = importlib.util.spec_from_file_location('banner_recovery_closure', helper)
        closure = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(closure)
        assert ref(jar)['sha256'] == closure.JSON_SHA
        paths, provenance = closure.prepare(source, output / 'generated', [test / 'NativeSearchBannerRecoveryHostTest.java'])
        report['closure'] = provenance
        report['compile_inputs_before'] = [ref(p) for p in paths]
        inputs = list(dict.fromkeys([Path(row['path']) for row in provenance['production_inputs']] + [Path(__file__).resolve(), fixture]))
        report['source_inputs_before'] = [ref(p) for p in inputs]
        classes = output / 'classes'
        classes.mkdir()
        env = dict(os.environ, PATH=str(jdk / 'bin') + ':/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1')
        for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH'):
            env.pop(key, None)
        commands = [
            ('compile', [jdk / 'bin/javac', '--release', '8', '-encoding', 'UTF-8', '-proc:none', '-Xlint:all,-options', '-Werror', '-cp', jar, '-d', classes, *paths]),
            ('banner-refusal-recovery', [jdk / 'bin/java', '-ea', '-cp', str(classes) + os.pathsep + str(jar), 'org.trillionnium.hepta.local.NativeSearchBannerRecoveryHostTest', fixture, output / 'CASES.json'])]
        for name, argv in commands:
            started = time.monotonic()
            with (output / (name + '.stdout')).open('xb') as stdout, (output / (name + '.stderr')).open('xb') as stderr:
                result = subprocess.run(list(map(str, argv)), cwd=output, env=env, stdout=stdout, stderr=stderr, timeout=120)
            report['stages'].append(dict(name=name, argv=list(map(str, argv)), exit_code=result.returncode,
                                         elapsed_seconds=time.monotonic() - started,
                                         stdout=ref(output / (name + '.stdout')), stderr=ref(output / (name + '.stderr'))))
            if result.returncode:
                raise RuntimeError('stage failed: ' + name)
        report['cases'] = json.loads((output / 'CASES.json').read_bytes())
        report['all_pass'] = report['cases']['all_pass']
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        if (output / 'CASES.json').exists():
            report['cases'] = json.loads((output / 'CASES.json').read_bytes())
    finally:
        report['source_after'] = inventory(source)
        report['source_unchanged'] = report['source_before'] == report['source_after']
        report['tools_after'] = [ref(p) for p in tool_paths]
        report['tools_unchanged'] = report['tools_before'] == report['tools_after']
        if inputs:
            report['source_inputs_after'] = [ref(p) for p in inputs]
            report['source_inputs_unchanged'] = report['source_inputs_before'] == report['source_inputs_after']
        if 'compile_inputs_before' in report:
            report['compile_inputs_after'] = [ref(p['path']) for p in report['compile_inputs_before']]
            report['compile_inputs_unchanged'] = report['compile_inputs_before'] == report['compile_inputs_after']
        report['all_pass'] = report['all_pass'] and all(report.get(k, False) for k in ('source_unchanged', 'tools_unchanged', 'source_inputs_unchanged', 'compile_inputs_unchanged'))
        report['generated_class_inputs'] = [ref(p) for p in sorted((output / 'classes').rglob('*.class'))] if (output / 'classes').exists() else []
        path = output / 'RESULT.json'
        with path.open('x') as out:
            json.dump(report, out, ensure_ascii=False, indent=2)
            out.write('\n')
        print(json.dumps(dict(all_pass=report['all_pass'], error=report.get('error'), result=ref(path),
                              cases=report.get('cases', {}).get('cases'), assertions=report.get('cases', {}).get('assertions'))))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
