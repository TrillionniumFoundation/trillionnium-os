#!/usr/bin/env python3
"""Compile the actual pure NotesOwnerIntent and fixed-payload validator, Java 8."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import time



def calendar_type_only_ports(source, out):
    """Compile-only ABI for an unrelated Calendar path; no new capability."""
    constants = source / 'src/org/trillionnium/hepta/local/NativeCalendarDateIntent.java'
    declarations = re.findall(r'^    static final String SCHEMA="[^"\n]+",ACTION="[^"\n]+";$',
                              constants.read_text(), re.MULTILINE)
    if len(declarations) != 1:
        raise RuntimeError('one actual Calendar schema/action declaration required')
    package = 'package org.trillionnium.hepta.local;\n'
    sources = {
        'NativeAppSession.java': package + """final class NativeAppSession {
    private NativeAppSession(){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
    static final class CalendarFacts {
        final String observationId=null,packageName=null;
        private CalendarFacts(){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
    }
    static final class CalendarSource {
        final CalendarFacts facts=null;
        private CalendarSource(){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
    }
    static final class CalendarProtocol {
        final String grammar=null,grammarSha256=null;
        private CalendarProtocol(){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
    }
    static final class CalendarOffer {
        final CalendarSource source=null;final CalendarProtocol protocol=null;
        private CalendarOffer(){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
        void claimGrammar(TaskAuthorization.Frame ignored){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
        void close(){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
    }
}
""",
        'NativeCalendarDateIntent.java': package + 'final class NativeCalendarDateIntent {\n' + declarations[0] + """
    private NativeCalendarDateIntent(){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
}
""",
        'MobiMindContract.java': package + """final class MobiMindContract {
    private MobiMindContract(){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
    static String sha(byte[] ignored){throw new UnsupportedOperationException("calendar outside Notes owner gate");}
}
""",
    }
    root = out / 'calendar-type-only'
    root.mkdir()
    generated = []
    for name, text in sources.items():
        path = root / name
        with path.open('x') as stream:
            stream.write(text)
        generated.append(path)
    return constants, generated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release8', action='store_true')
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    if out.is_relative_to(source):
        raise ValueError('test output must be outside immutable source')
    out.mkdir(parents=True, exist_ok=False)
    # The unchanged actual Owner grammar closure supplies the real authority compiler.
    names = ('BackgroundTaskTarget', 'NativeAppGoal', 'NotesOwnerIntent', 'TaskAuthorization', 'ActionDecision', 'DecisionGrammar',
             'ObservedTargetLabels', 'ObservedAppLabels', 'ObservedScrollActions',
             'ObservedImeEnter', 'AppCatalogueRanker')
    files = [source / 'src/org/trillionnium/hepta/local' / (name + '.java') for name in names]
    files += [source / 'src/org/trillionnium/hepta/background' / (name + '.java')
              for name in ('FixedIntentTools', 'FixedIntentTarget', 'ProfileIdentity', 'ProfileTarget')]
    files += [source / 'src/org/trillionnium/hepta/local/web' / (name + '.java')
              for name in ('WebFlightGoal', 'WebShoppingGoal')]
    files.append(source / 'tests/notes-owner-intent/NotesOwnerIntentHostTest.java')
    search_helper=source/'tests/native-app/legacy-boundary/prepare_search_pure.py'
    port_spec=importlib.util.spec_from_file_location('old_search_pure',search_helper)
    legacy_search=importlib.util.module_from_spec(port_spec);port_spec.loader.exec_module(legacy_search);files=legacy_search.add(source,files)
    pins = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    pins[str(search_helper.relative_to(source))]=hashlib.sha256(search_helper.read_bytes()).hexdigest()
    constants, calendar_files = calendar_type_only_ports(source, out)
    pins[str(constants.relative_to(source))] = hashlib.sha256(constants.read_bytes()).hexdigest()
    runner = source / 'tests/notes-owner-intent/run_host_tests.py'
    pins[str(runner.relative_to(source))] = hashlib.sha256(runner.read_bytes()).hexdigest()
    calendar_pins = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in calendar_files}
    files += calendar_files
    classes = out / 'classes'
    classes.mkdir()
    compiler = [shutil.which('javac')] if shutil.which('javac') else ['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = ['--release', '8'] if args.release8 else ['-source', '8', '-target', '8']
    lint = '-Xlint:all' if args.release8 else '-Xlint:all,-options'
    stages = [('compile', compiler + flags + ['-encoding', 'UTF-8', lint, '-Werror', '-d', str(classes), *map(str, files)]),
              ('notes-owner-intent', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.NotesOwnerIntentHostTest'])]
    report = {'schema': 'hepta.notes-owner-intent-host.v1', 'phone_operations': False,
              'android_runtime': False, 'native_inference': False, 'source_inputs': pins,
              'compiler_contract': 'Java 8 API release' if args.release8 else 'Java 8 syntax/target only',
              'stages': [], 'passed': False}
    report['calendar_type_only_boundary'] = {
        'unconstructible_all_throw_ports': ['NativeAppSession.CalendarOffer', 'NativeCalendarDateIntent', 'MobiMindContract'],
        'actual_schema_action_source': str(constants),
        'generated_inputs': calendar_pins, 'calendar_executed': False,
        'old_notes_and_authorization_cases_unchanged': True}
    outputs = {}
    for name, argv in stages:
        started = time.monotonic()
        result = subprocess.run(argv, capture_output=True, timeout=60)
        (out / (name + '.stdout')).write_bytes(result.stdout)
        (out / (name + '.stderr')).write_bytes(result.stderr)
        outputs[name] = result.stdout.decode('utf-8', 'strict')
        report['stages'].append({'name': name, 'argv': argv, 'exit_code': result.returncode,
                                 'elapsed_s': time.monotonic() - started})
        if result.returncode:
            break
    passed = len(report['stages']) == 2 and all(x['exit_code'] == 0 for x in report['stages'])
    text = outputs.get('notes-owner-intent', '')
    case = re.fullmatch(r'NOTES_OWNER_INTENT_CASES=(\d+)\nNOTES_OWNER_INTENT_ASSERTIONS=(\d+)\n'
                       r'NOTES_OWNER_INTENT_PASSED phone_tested=false android_io=false model_io=false\n', text)
    report['passed'] = passed and case is not None
    if case is not None:
        report['cases'], report['assertions'] = int(case[1]), int(case[2])
    report['source_unchanged'] = all(hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
                                     for name, digest in pins.items())
    if not report['source_unchanged']:
        report['passed'] = False
    report['calendar_type_only_inputs_unchanged'] = all(
        hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
        for path, digest in calendar_pins.items())
    if not report['calendar_type_only_inputs_unchanged']:
        report['passed'] = False
    (out / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('passed', 'source_unchanged', 'phone_operations')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
