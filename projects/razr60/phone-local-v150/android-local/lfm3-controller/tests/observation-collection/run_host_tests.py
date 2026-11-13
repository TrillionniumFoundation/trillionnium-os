#!/usr/bin/env python3
"""Exact collection code with bounded synthetic Android IO and pinned raw fixtures.

The browser XML is a later independent snapshot. XML does not contain Android
action lists or isVisibleToUser/isEditable results. Its projection is explicitly
not either model-bound frame, a new phone observation, or successful web work.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_fixtures(original):
    metadata = original / 'SOURCE.json'
    if digest(metadata) != '25bd9f521eda75e010eebc4f464746291347c5bfb59673b71af613cb2f1c0a03':
        raise RuntimeError('fixture provenance differs')
    info = json.loads(metadata.read_text())
    for row in info['files']:
        name = row['fixture']
        if Path(name).name != name or (original / name).is_symlink():
            raise RuntimeError('unsafe fixture name')
        p = original / name
        if p.stat().st_size != row['size'] or digest(p) != row['sha256']:
            raise RuntimeError('original fixture changed: ' + name)
    if len(list(ET.fromstring((original / 'final-current-browser.xml').read_bytes()).iter('node'))) != 975:
        raise RuntimeError('original terminal XML structure changed')
    model_frames = []
    for step in (2, 5):
        p = original / f'step-{step:02d}-before.json'
        frame = json.loads(p.read_text())
        rows = frame['nodes']
        units = sum(len(n.get(k, '').encode('utf-16-le')) // 2 for n in rows for k in ('text', 'description', 'child_text'))
        if len(rows) != 23 or units != 74 or frame['nodes_truncated'] is not True or frame.get('collection') is not None:
            raise RuntimeError('actual model-bound truncation facts changed')
        # Each limited own field is at most 96 UTF-16 units plus one ellipsis;
        # bounded derived child text adds at most 96. Even one more maximum-size
        # useful candidate cannot hit the old text gate on either actual frame.
        if not (len(rows) < 64 and units + 97 + 97 + 96 < 2400):
            raise RuntimeError('cannot exclude the old output caps')
        scroll = next(n for n in rows if n['id'] == 'n12')
        if not scroll['scroll_actions_observed'] or set(scroll['scroll_directions']) != {'forward', 'down'}:
            raise RuntimeError('original observed scroll directions changed')
        model_frames.append({'original_sha256': digest(p), 'observation_id': frame['observation_id'],
                             'retained_rows': len(rows), 'retained_text_utf16': units,
                             'old_node_and_text_caps_excluded': True, 'actual_visited_count_known': False,
                             'actual_pending_count_known': False, 'actual_scroll_directions': scroll['scroll_directions']})
    return {'model_bound_frames': model_frames, 'independent_xml_nodes': 975,
            'xml_is_model_bound_frame': False, 'xml_platform_actions_known': False,
            'prior_failed_task_upgraded': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release8', action='store_true')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    original = source / 'tests/observation-collection/fixtures'
    verified = verify_fixtures(original)
    helper = source / 'tests/qualification-scope/prepare_fixture.py'
    spec = importlib.util.spec_from_file_location('actual_collection_fixture', helper)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    files, extraction = fixture.prepare(source, output / 'fixture')
    actual = (output / 'fixture/BackgroundObservationFixture.java').read_text()
    start = '    private Graph readGraph(){'
    end = '    private static String nodeSignature('
    old = (original / 'v49-readGraph.txt').read_text()
    if digest(original / 'v49-readGraph.txt') != '1e71cdf254fb2613173d215a2271cbaf34bf1773b75ae9a3b832039ffbada6bb':
        raise RuntimeError('frozen original traversal differs')
    if actual.count(start) != 1 or actual.count(end) != 1:
        raise RuntimeError('actual traversal extraction ambiguous')
    i, j = actual.index(start), actual.index(end)
    legacy = actual[:i] + old + '\n' + actual[j:]
    limits = 'private static final int MAX_NODES=128, MAX_VISITED=1536, MAX_CHARACTERS=6144;'
    if legacy.count(limits) != 1 or legacy.count('final class BackgroundObservationFixture') != 1:
        raise RuntimeError('bounded collector fixture identity changed')
    legacy = legacy.replace(limits, 'private static final int MAX_NODES=64, MAX_VISITED=320, MAX_CHARACTERS=2400;')
    legacy = legacy.replace('final class BackgroundObservationFixture', 'final class LegacyObservationFixture')
    legacy_file = output / 'fixture/LegacyObservationFixture.java'
    legacy_file.write_text(legacy)
    files += [legacy_file, source / 'tests/observation-collection/ObservationCollectionHostTest.java']
    files = list(dict.fromkeys(files))
    inputs = list(dict.fromkeys(files + [helper, Path(__file__).resolve(),
        source / 'src/org/trillionnium/hepta/local/HeptaAccessibilityService.java']
        + sorted((source / 'tests/qualification-scope').glob('*.template')) + sorted(original.iterdir())))
    pins = {str(p): digest(p) for p in inputs}
    classes = output / 'classes'
    classes.mkdir()
    compiler = [shutil.which('javac')] if shutil.which('javac') else ['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main']
    flags = ['--release', '8'] if args.release8 else ['-source', '8', '-target', '8']
    commands = [
        ('compile', compiler + flags + ['-encoding', 'UTF-8', '-Xlint:all' if args.release8 else '-Xlint:all,-options',
             '-Werror', '-d', str(classes), *map(str, files)]),
        ('collection', ['java', '-cp', str(classes), 'org.trillionnium.hepta.local.ObservationCollectionHostTest',
             str(original / 'final-current-browser.xml'), str(output / 'TEST-RESULTS.json')]),
    ]
    report = {'schema': 'hepta.observation-collection-run.v1', 'source_inputs': pins, 'extraction': extraction,
              'fixture_evidence': verified, 'legacy_substitution': 'Exact frozen v49 method and 64/320 limits; other fixture IO unchanged',
              'compiler_contract': 'Java 8 API release' if args.release8 else 'Java 8 syntax/target only',
              'stages': [], 'passed': False, 'phone_tested': False, 'native_inference': False,
              'business_completion_provider_added': False, 'prior_failed_task_upgraded': False}
    for name, argv in commands:
        started = time.monotonic()
        result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
        (output / (name + '.stdout')).write_text(result.stdout)
        (output / (name + '.stderr')).write_text(result.stderr)
        report['stages'].append({'name': name, 'argv': argv, 'exit_code': result.returncode,
                                 'elapsed_s': time.monotonic() - started})
        if result.returncode:
            print(result.stdout[-2000:])
            print(result.stderr[-4000:])
            break
    report['passed'] = len(report['stages']) == len(commands) and all(x['exit_code'] == 0 for x in report['stages'])
    if any(digest(path) != sha for path, sha in pins.items()):
        raise RuntimeError('source changed while checking actual collection code')
    (output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('passed', 'compiler_contract', 'phone_tested', 'business_completion_provider_added')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
