#!/usr/bin/env python3
"""Full production BackgroundSession; explicit fake root RPC/Android/process IO only."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    a = p.parse_args()
    source, out = a.source.resolve(), a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('profile_session_fixture', Path(__file__).with_name('prepare_fixture.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files, extraction = module.prepare(source, out / 'fixture')
    files += [Path(__file__).with_name(name) for name in ('BackgroundSessionHostTest.java', 'ProfileSessionHostTest.java')]
    files = list(dict.fromkeys(files))
    def key(path):
        return ('source/' + str(path.relative_to(source))) if source in path.parents else ('fixture/' + str(path.relative_to(out)))
    pins = {key(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    classes = out / 'classes'
    classes.mkdir()
    stages = []
    commands = [
        ('compile', [a.java_home / 'bin/javac', '--release', '8', '-encoding', 'UTF-8', '-proc:none',
                     '-Xlint:all,-options', '-Werror', '-d', classes, *files]),
        ('profile-client', [a.java_home / 'bin/java', '-cp', classes,
                            'org.trillionnium.hepta.local.ProfileSessionHostTest', out / 'CASES.json'])]
    for name, argv in commands:
        start = time.monotonic()
        r = subprocess.run([str(v) for v in argv], cwd=out, capture_output=True, timeout=90)
        (out / (name + '.stdout')).write_bytes(r.stdout)
        (out / (name + '.stderr')).write_bytes(r.stderr)
        stages.append({'name': name, 'exit_code': r.returncode, 'elapsed_seconds': time.monotonic() - start})
        if r.returncode:
            (out / 'RESULT.json').write_text(json.dumps({'all_pass': False, 'stages': stages, 'source_inputs': pins}, indent=2) + '\n')
            print(r.stderr.decode('utf-8', errors='replace')[-10000:])
            return r.returncode
    assert pins == {key(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    cases = json.loads((out / 'CASES.json').read_text())
    result = {'schema': 'hepta.profile-client-host-validation.v1', 'all_pass': True, 'cases': cases,
              'stages': stages, 'source_inputs': pins, 'source_inputs_unchanged': True,
              'android_runtime': False, 'root_process_started': False, 'phone_actions': 0,
              'actual_client_class': True, 'transport_display_clock_process_are_explicit_fakes': True}
    (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'all_pass': True, 'cases': cases['cases'], 'assertions': cases['assertions']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
