#!/usr/bin/env python3
"""Saved Xiaomi loading frame, real Session/domain, verbatim scope catch.

No phone, ADB, model, SDK, Android dispatch or business completion is executed.
--previous-source additionally compiles exact R12 provider/service bodies to
reproduce the observed unsupported page and permanent scope refusal.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

PKG = Path('src/org/trillionnium/hepta/local')
TEST = Path('tests/native-xiaomi-home-loading')
JSON_SHA = '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed'
OLD_PROVIDER_SHA = 'c25c72d850e6e11f6b273c086b3dd363f8f87dd68604b1d47e045593f041e6ea'
OLD_SERVICE_SHA = '7662d0ed749fb700e316b0fadc2c1ac8cf603b04a403178645436537c6652275'
METHODS = {
    'stale_class': '    private static final class StaleObservation extends IllegalStateException {',
    'outer_scope': '    private void scopeBeforeDispatch(',
    'background': '    private void backgroundBeforeDispatch(',
    'node_window': '    private static void requireBackgroundNodeWindow(',
    'action_check': '    private static void actionCheck(',
    'action_phase': '    private static void actionPhase(',
    'node_refresh': '    private boolean refreshActionNode(',
}


def need(value, why):
    if not value:
        raise RuntimeError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def meta(path):
    path = Path(path).absolute()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw), mode=path.stat().st_mode & 0o777)


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(value.encode('utf-8') if isinstance(value, str) else value)


def save(path, value):
    write(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n')


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def replace(text, old, new):
    need(text.count(old) == 1, 'nonunique extraction/replacement: ' + old[:160])
    return text.replace(old, new, 1)


def source_inputs(source):
    paths = []
    for path in sorted(source.rglob('*')):
        need(not path.is_symlink(), 'source symlink')
        if path.is_file() and '__pycache__' not in path.parts:
            paths.append(path)
    return paths


def fixture(source, generated):
    root = source / TEST / 'fixtures'
    prov = json.loads((root / 'PROVENANCE.json').read_text())
    for row in prov['files']:
        actual = meta(root / row['file'])
        need(all(actual[key] == row[key] for key in ('bytes', 'sha256')), 'original fixture bytes changed')
    o = json.loads((root / 'actual-observation.json').read_text())
    page = json.loads((root / 'actual-page.json').read_text())
    m = page['frame']
    binding = json.loads((root / 'actual-binding.json').read_text())
    owner = prov['owner']
    need(m['phone_observation_record_sha256'] == meta(root / 'actual-observation.json')['sha256'], 'raw frame linkage')
    need(m['owner_sha256'] == binding['owner_sha256'] == sha(owner.encode()), 'exact original owner linkage')
    need(m['observation_id'] == o['observation_id'] == '21a9070fc21d43c9837397f63ea48a8f', 'exact failing observation')
    need(m['retained_nodes'] == len(o['nodes']) == 11, 'complete saved retained graph')
    need(page['provider']['phase'] == 'unrecognized_native_page', 'original failure phase')
    c = o['collection']
    need(c['visited_nodes'] == 14 and c['retained_nodes'] == 11 and c['retained_text_utf16'] == 24, 'original collector counters')
    need(c['pending_nodes_at_stop'] == c['child_slots_omitted_by_traversal_limit'] == c['nodes_omitted_by_node_limit'] == c['nodes_omitted_by_text_limit'] == 0, 'complete traversal')
    need(not o['nodes_truncated'] and c['truncation_reasons'] == [] and m['actual_collection_complete'], 'original collection completeness')
    q = lambda value: json.dumps(value, ensure_ascii=False)

    def boolean(value):
        need(type(value) is bool, 'observed boolean required')
        return str(value).lower()

    rows = []
    for n in o['nodes']:
        need(n['scroll_directions'] == [] and n['native_selection_state']['observed'] is True, 'exact scroll/selection fields')
        t = n['native_tree_position']
        s = n['native_selection_state']
        text, desc = n.get('text', ''), n.get('description', '')
        need(text or desc, 'this fixture has only literal text/description labels')
        label = text if text.strip() else desc
        vals = [q(n['id']), q(n['package']), q(n['class_name']), q(n.get('view_id', '')), q(text), q(desc), q(t['path']), q(t['parent_class']), q(n['node_app_tree_sha256']), q(label)]
        vals += list(map(str, n['bounds'])) + [boolean(n.get('enabled', True)), boolean(n.get('password', False)), boolean(n.get('clickable', False)), boolean(n.get('editable', False)), boolean(n.get('scrollable', False))]
        vals += ['Boolean.' + str(s[key]).upper() for key in ('selected', 'checkable', 'checked')] + ['Collections.<String>emptySet()']
        rows.append('        nodes.add(new NativeAppEvidence.Node(' + ','.join(vals) + '));')
    strings = [m[key] for key in ('task_id', 'owner_sha256', 'execution_target_sha256', 'task_authorization_sha256', 'actual_selection_sha256', 'observation_id', 'package', 'background_generation', 'app_tree_sha256', 'observation_state_sha256', 'screen_sha256', 'phone_observation_record_sha256', 'completion_frame_sha256')]
    args = ','.join(map(q, strings)) + ',' + ','.join(map(str, [m['display_id'], m['window_id'], o['rotation'], o['screen_width'], o['screen_height']] + o['window']['bounds'])) + ',' + str(m['captured_elapsed_ms']) + 'L,false,true,nodes,1,true'
    java = 'package org.trillionnium.hepta.local;\nimport java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.List;\nfinal class ActualXiaomiHomeLoadingFixture {\n'
    java += '    static final String OWNER=' + q(owner) + ';\n    static NativeAppEvidence.Frame frame(){\n        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();\n'
    java += '\n'.join(rows) + '\n        return new NativeAppEvidence.Frame(' + args + ');\n    }\n}\n'
    write(generated / 'ActualXiaomiHomeLoadingFixture.java', java)
    return dict(original_frame=meta(root / 'actual-observation.json'), original_page=meta(root / 'actual-page.json'), original_binding=meta(root / 'actual-binding.json'), all_DTO_fields_generated_from_original=True, live_android_adapter_executed=False, defaults_source='PhoneObservation.Node.json absent enabled=true; password/editable/scrollable false; text/description/view_id empty. All retained labels here are literal text or description.')


def bridge(source, generated, body, template):
    service = (source / PKG / 'HeptaAccessibilityService.java').read_text()
    methods = {name: body(service, signature) for name, signature in METHODS.items()}
    write(generated / 'LoadingWindowBridgeHost.java', replace(template, '    // ACTUAL_METHODS', '\n'.join(methods.values())))
    return {name: dict(bytes=len(value.encode()), sha256=sha(value.encode())) for name, value in methods.items()}


def stage(name, argv, out, env):
    began = time.monotonic_ns()
    with (out / (name + '.stdout')).open('xb') as stdout, (out / (name + '.stderr')).open('xb') as stderr:
        run = subprocess.run(list(map(str, argv)), cwd=out, env=env, stdout=stdout, stderr=stderr, timeout=180, check=False)
    return dict(name=name, argv=list(map(str, argv)), exit_code=run.returncode, elapsed_ns=time.monotonic_ns() - began, stdout=meta(out / (name + '.stdout')), stderr=meta(out / (name + '.stderr')))


LEGACY_PARSER = '''package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;import java.nio.file.*;import org.json.*;
final class PreviousLoadingFailureHost {
 public static void main(String[] args)throws Exception {
  NativeXiaomiProductPage.Page page=NativeXiaomiProductPage.inspect(NativeAppGoal.parse(ActualXiaomiHomeLoadingFixture.OWNER,NativeAppGoal.XIAOMI_PACKAGE),ActualXiaomiHomeLoadingFixture.frame());
  if(!"unrecognized_native_page".equals(page.phase)||!page.clickIds.isEmpty()||!page.editValues.isEmpty()||page.quote!=null)throw new AssertionError("original loading failure not reproduced");
  JSONObject out=new JSONObject().put("schema","hepta.native-home-loading-previous-host.v1").put("all_pass",true).put("cases",1).put("assertions",4).put("case_names",new JSONArray().put("legacy_exact_saved_loading_frame_was_unsupported"));
  Files.write(Paths.get(args[0]),(out.toString(2)+"\\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(out.toString());
 }
}
'''


def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'output', 'java-home', 'json-jar'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--previous-source', type=Path)
    args = parser.parse_args()
    source, out, jdk, jar = args.source.resolve(), args.output.absolute(), args.java_home.resolve(), args.json_jar.resolve()
    need(source.is_dir() and not out.exists() and source not in out.parents, 'fresh output outside source required')
    toolpaths = [jdk / 'bin/java', jdk / 'bin/javac', jdk / 'lib/modules', jdk / 'lib/ct.sym', jar]
    need(all(path.is_file() for path in toolpaths), 'full JDK17 and pinned JSON jar required')
    need(jar.stat().st_size == 78332 and sha(jar.read_bytes()) == JSON_SHA, 'JSON dependency identity')
    before_paths = source_inputs(source)
    if args.previous_source:
        old = args.previous_source.resolve()
        need(sha((old / PKG / 'NativeXiaomiProductPage.java').read_bytes()) == OLD_PROVIDER_SHA, 'exact previous R12 provider')
        need(sha((old / PKG / 'HeptaAccessibilityService.java').read_bytes()) == OLD_SERVICE_SHA, 'exact previous R12 service')
        before_paths += [old / PKG / (name + '.java') for name in ('NativeAppGoal', 'NativeAppEvidence', 'NativeXiaomiProductPage', 'HeptaAccessibilityService')]
    before_paths += toolpaths
    before = [meta(path) for path in before_paths]
    out.mkdir(parents=True, mode=0o700)
    sys.dont_write_bytecode = True
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    for key in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH'):
        env.pop(key, None)
    report = dict(schema='hepta.native-xiaomi-home-loading-host-gate.v1', all_pass=False, input_before=before, steps=[], phone_operations=0, android_execution=False, model_executed=False, business_completion_verified=False, platform_dispatch_executed=False)
    try:
        integration = load(source / 'tests/native-action-integration/run_host.py', 'loading_existing_compile_closure')
        extraction = load(source / 'tests/observation-diagnostics/run_host.py', 'loading_existing_body_extractor')
        generated = out / 'generated'
        generated.mkdir()
        integration.generate(source, generated)
        actual_fixture = fixture(source, generated)
        template = (source / TEST / 'LoadingWindowBridgeHost.template').read_text()
        methods = bridge(source, generated, extraction.body, template)
        harness_path = source / 'tests/native-app-provider/NativeXiaomiModalSessionHostTest.java'
        harness = harness_path.read_text()
        old_main = extraction.body(harness, '    public static void main(String[] args)throws Exception{')
        projected = replace(harness, old_main, (source / TEST / 'LoadingSessionCases.fragment').read_text())
        projected = replace(projected, 'class NativeXiaomiModalSessionHostTest', 'class NativeHomeLoadingSessionHost')
        projected = replace(projected, 'private NativeXiaomiModalSessionHostTest(){}', 'private NativeHomeLoadingSessionHost(){}')
        projected = replace(projected, 'private static final String OWNER=ActualXiaomiImageModalFixture.OWNER;', 'private static final String OWNER=ActualXiaomiHomeLoadingFixture.OWNER;')
        write(generated / 'NativeHomeLoadingSessionHost.java', projected)
        paths, bg_record = integration.sources(source, out)
        record = dict(schema='hepta.native-home-loading-extraction.v1', bodies_verbatim=True, methods=methods,
                      service_source=meta(source / PKG / 'HeptaAccessibilityService.java'), actual_fixture=actual_fixture,
                      original_session_harness=meta(harness_path), original_main_sha256=sha(old_main.encode()),
                      only_harness_main_outer_name_and_owner_changed=True, background_fixture=bg_record,
                      boundary='Actual production parser/Session/Domain/grammar and verbatim scope/background methods; Android endpoints, worker time, synthetic later observations and model callbacks remain host fixtures.')
        save(out / 'EXTRACTION.json', record)
        report['compile_inputs'] = [meta(path) for path in paths]
        classes = out / 'classes'
        classes.mkdir()
        cp = str(classes) + os.pathsep + str(jar)
        flags = ['--release', '8', '-encoding', 'UTF-8', '-proc:none', '-Xlint:all,-options', '-Werror', '-cp', jar]
        commands = [
            ('compile', [jdk / 'bin/javac', *flags, '-d', classes, *paths]),
            ('session-cases', [jdk / 'bin/java', '-cp', cp, 'org.trillionnium.hepta.local.NativeHomeLoadingSessionHost', source / 'tests/native-xiaomi-product/fixtures', out / 'SESSION-CASES.json']),
            ('window-cases', [jdk / 'bin/java', '-cp', cp, 'org.trillionnium.hepta.local.LoadingWindowBridgeHost', out / 'WINDOW-CASES.json']),
        ]
        for name, argv in commands:
            result = stage(name, argv, out, env)
            report['steps'].append(result)
            need(result['exit_code'] == 0, 'actual stage failed: ' + name)
        parts = [json.loads((out / leaf).read_text()) for leaf in ('SESSION-CASES.json', 'WINDOW-CASES.json')]
        names = [name for part in parts for name in part['case_names']]
        need(all(part['all_pass'] and part['cases'] == len(part['case_names']) for part in parts) and len(names) == len(set(names)), 'complete unique cases')
        cases = dict(schema='hepta.native-xiaomi-home-loading-host.v1', all_pass=True, cases=len(names), assertions=sum(part['assertions'] for part in parts), case_names=names, phone_operations=0, android_execution=False, model_executed=False, business_completion_verified=False, groups=parts)
        save(out / 'CASES.json', cases)
        if args.previous_source:
            previous = out / 'previous-generated'
            previous.mkdir()
            fixture(source, previous)
            previous_methods = bridge(old, previous, extraction.body, template)
            write(previous / 'PreviousLoadingFailureHost.java', LEGACY_PARSER)
            old_classes = out / 'previous-classes'
            old_classes.mkdir()
            old_paths = [old / PKG / (name + '.java') for name in ('NativeAppGoal', 'NativeAppEvidence', 'NativeXiaomiProductPage')] + sorted(previous.glob('*.java'))
            old_cp = str(old_classes) + os.pathsep + str(jar)
            for name, argv in [
                ('previous-compile', [jdk / 'bin/javac', *flags, '-d', old_classes, *old_paths]),
                ('previous-parser', [jdk / 'bin/java', '-cp', old_cp, 'org.trillionnium.hepta.local.PreviousLoadingFailureHost', out / 'PREVIOUS-PARSER-CASES.json']),
                ('previous-window', [jdk / 'bin/java', '-cp', old_cp, 'org.trillionnium.hepta.local.LoadingWindowBridgeHost', out / 'PREVIOUS-WINDOW-CASES.json', 'legacy']),
            ]:
                result = stage(name, argv, out, env)
                report['steps'].append(result)
                need(result['exit_code'] == 0, 'previous failure reproduction stage failed: ' + name)
            report['previous_cases'] = [json.loads((out / leaf).read_text()) for leaf in ('PREVIOUS-PARSER-CASES.json', 'PREVIOUS-WINDOW-CASES.json')]
            report['previous_extracted_methods'] = previous_methods
        report.update(cases=cases, cases_file=meta(out / 'CASES.json'), case_records={leaf: meta(out / leaf) for leaf in ('SESSION-CASES.json', 'WINDOW-CASES.json')}, extraction_file=meta(out / 'EXTRACTION.json'),
                      generated_files={str(path.relative_to(generated)): meta(path) for path in sorted(generated.rglob('*.java'))}, all_pass=True)
    except Exception as error:
        report['error'] = dict(type=type(error).__name__, message=str(error))
    finally:
        report['input_after'] = [meta(path) for path in before_paths]
        report['inputs_unchanged'] = report['input_after'] == before
        report['all_pass'] = report['all_pass'] and report['inputs_unchanged']
        save(out / 'RESULT.json', report)
    print(json.dumps(dict(all_pass=report['all_pass'], result=meta(out / 'RESULT.json'), error=report.get('error'))))
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
