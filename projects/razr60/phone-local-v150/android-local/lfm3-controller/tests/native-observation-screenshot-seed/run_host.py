#!/usr/bin/env python3
"""Execute the actual observer with independent screenshot-mismatch seed cases.

All original event cases and assertions run first, from byte-pinned original
fixture bodies. Exact fail-only form/AX ports and reviewed diagnostic test changes
are separately pinned; reversing them must restore the complete original fixture bytes. Android traversal, pixels, Session issuance and device success remain
outside this host boundary. An optional final manifest/map pair binds a frozen
reviewed source; every run records the complete source inventory before/after.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
TEST = Path('tests/native-observation-screenshot-seed')
PKG = Path('src/org/trillionnium/hepta/local')
PINNED_FIXTURES = {
    'tests/native-observation-events/run_host.py': 'f55e730baa3869ef1fe7110d658a809dfc901628141140c28a508878995dab38',
    'tests/native-observation-events/EventChecks.java': 'b8b8c1302af4a19643e6dda64702e49f887bb5613a6bb0ddc298941b00fccc0a',
    'tests/native-observation-events/EventPipelineCases.fragment': 'c6f71fab64f76e1e8285eb6c82bfd79ec05cc4d737878fad80a6f37a69f6d243',
    'tests/native-observation-events/SavedGraphSeedCases.fragment': '39f8b1060264a291e5e1575e18039cafccc63a49eba29d1af3f0c3094a01af18',
    'tests/native-observation-events/PublicationRecheckCases.fragment': 'a194335ea6ebee1bb5830190ef46645d84a2cd672b6ef0977aceb642b8a6d32b',
    'tests/observation-pipeline/ObserverPipelineHost.template': 'c13a2152891f7f7a4373421b8060f683c1d7d6dd92725bee86081cda9c660799',
    'tests/observation-diagnostics/run_host.py': '153a9edece2f275adc7276dcd40dea8bb7480db692a3f7dd622792ebb4399b74',
}


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_original_fixtures(source, before):
    template = 'tests/observation-pipeline/ObserverPipelineHost.template'
    port = b'''    /** Explicit fail-only port: legacy scheduling fixtures cannot admit scoped form pairs.
     * The dedicated form-observation gate substitutes both actual production helpers. */
    private Map<String,Object> nativeCtripFormPair(ObservationRequest request,CaptureIdentity identity,Graph after){return null;}
'''
    raw = (source / template).read_bytes()
    current_sha = '2fedec818e4fb21c0260580658e225da5cc34443ec8928988f34b80f6cbb9a01'
    need(before[template]['sha256'] == sha(raw) == current_sha,
         'reviewed fail-only fixture template differs')
    need(raw.count(port) == 1, 'exact single fail-only form port required')
    ax_ports = b'    // Legacy scheduling fakes never bind a text-native model. The AX gate substitutes\n    // the actual production mode admission, worker and publisher at these three ports.\n    private void bindNativeAxObservationRequest(ObservationRequest request){}\n    private boolean nativeTextObservationAllowed(ObservationRequest request,Graph graph){return false;}\n    private void captureNativeAxObservation(ObservationRequest request){throw new AssertionError("legacy fixture cannot enter AX capture");}\n'
    need(raw.count(ax_ports) == 1, 'exact reviewed fail-only AX ports required')
    legacy = raw.replace(ax_ports, b'', 1)
    need(sha(legacy) == '50b7d239c4e76334894082dd01ecad1a7a207eb1e776f82f9916d3ea1e62de1d', 'original form-port fixture bytes differ')
    original_sha = sha(legacy.replace(port, b'', 1))
    need(original_sha == PINNED_FIXTURES[template],
         'original complete fixture body differs after exact port removal')
    diagnostic = 'tests/observation-diagnostics/run_host.py'
    diagnostic_raw = (source / diagnostic).read_bytes()
    need(before[diagnostic]['sha256'] == sha(diagnostic_raw) == '8bc73b57369ffedd8681101c86ba096856f36b6dcba08d3a973f1cb72720209e',
         'exact reviewed diagnostic source-list and private-artifact test changes required')
    diagnostic_replacements = [(b"JAVA = ['HeptaAccessibilityService.java','LocalTaskController.java','ObservationDiagnostics.java',\n", b"JAVA = ['ObservationCaptureEvidence.java', 'HeptaAccessibilityService.java','LocalTaskController.java','ObservationDiagnostics.java',\n"), (b"       'DiagnosticPipelineCases.fragment','DiagnosticGraphHost.template','DiagnosticControllerHost.template','CompactCensusDiagnosticsHostTest.java']\n", b"       'DiagnosticPipelineCases.fragment','DiagnosticGraphHost.template','DiagnosticControllerHost.template','CompactCensusDiagnosticsHostTest.java','PrivateCensusDiagnosticsHostTest.java','PrivateCensusFileHost.template']\n"), (b'', b"        'private_census_holder':body(controller,'    private static final class FailedCensusDiagnostic {'),\n        'persist_private_census':body(controller,'    private JSONObject persistFailedCensusDiagnostic(String task,String status,boolean verified,File directory){'),\n        'private_census_write':body(controller,'    private static void recordPrivateCensus(File directory,String name,byte[] bytes)throws Exception{'),\n"), (b"    for fixture,names in [('DiagnosticGraphHost',['native_stamp','native_census','stale_record','action_evidence']),('DiagnosticControllerHost',['await_observation','await_observation_request','read_retry_failure','initial_read_failure','post_effect_read_failure','take_diagnostics'])]:\n", b"    for fixture,names in [('DiagnosticGraphHost',['native_stamp','native_census','stale_record','action_evidence']),('DiagnosticControllerHost',['await_observation','await_observation_request','read_retry_failure','initial_read_failure','post_effect_read_failure','take_diagnostics','private_census_holder','persist_private_census']),('PrivateCensusFileHost',['private_census_write'])]:\n"), (b'    positions=[finalization.index(token) for token in [\'backgroundCleanup=background.close();\',\'modelCleanup=inference.endTask(taskId);\',\'terminalDecisionSealed=true;\',\'record(evidence,"result.json"\',\'takeObservationDiagnostics(taskId)\',\'if(cleanup)service.releaseTask(taskId);\',\'running=false;\',\'selected.onFinished(result)\']]\n', b'    positions=[finalization.index(token) for token in [\'backgroundCleanup=background.close();\',\'modelCleanup=inference.endTask(taskId);\',\'terminalDecisionSealed=true;\',\'persistFailedCensusDiagnostic(taskId,finalStatus,completionVerified,evidence)\',\'record(evidence,"result.json"\',\'takeObservationDiagnostics(taskId)\',\'if(cleanup)service.releaseTask(taskId);\',\'running=false;\',\'selected.onFinished(result)\']]\n'), (b"        'diagnostic_finally_has_no_IO_or_wait':True,'terminal_diagnostic_uses_only_existing_result_write':True,\n", b"        'diagnostic_finally_has_no_IO_or_wait':True,'terminal_summary_uses_only_existing_result_write':True,'private_failure_artifact_after_original_cleanup_and_terminal':True,\n"), (b"        sources += [source/TEST/'DiagnosticChecks.java',source/TEST/'ObservationDiagnosticsHostTest.java',source/TEST/'CompactCensusDiagnosticsHostTest.java']+sorted(generated.glob('*.java'))\n", b"        sources += [source/TEST/'DiagnosticChecks.java',source/TEST/'ObservationDiagnosticsHostTest.java',source/TEST/'CompactCensusDiagnosticsHostTest.java',source/TEST/'PrivateCensusDiagnosticsHostTest.java']+sorted(generated.glob('*.java'))\n")]
    restored = diagnostic_raw
    for prior, revised in diagnostic_replacements:
        need(restored.count(revised) == 1, 'unique reversible diagnostic fixture change required')
        restored = restored.replace(revised, prior, 1)
    need(sha(restored) == PINNED_FIXTURES[diagnostic], 'original diagnostic runner bytes not restored')
    need(all(before[name]['sha256'] == digest for name, digest in PINNED_FIXTURES.items() if name not in (template, diagnostic)),
         'original reviewed fixture bytes differ')
    return {'template': template, 'current_sha256': current_sha,
            'original_sha256': original_sha, 'exact_removed_bytes': len(port) + len(ax_ports),
            'diagnostic_runner_current_sha256': sha(diagnostic_raw),
            'diagnostic_runner_original_sha256': sha(restored),
            'diagnostic_runner_reverse_original_byte_equality': True,
            'fail_only_port': True, 'reverse_original_byte_equality': True}


def packed(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')) + '\n').encode()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def inventory(source):
    result = {}
    for directory, dirs, files in os.walk(source, followlinks=False):
        for name in dirs:
            need(not Path(directory, name).is_symlink(), 'source directory symlink refused')
        for name in files:
            path = Path(directory, name)
            relative = path.relative_to(source).as_posix()
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
                before = os.fstat(stream.fileno())
                need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular single-link source required: ' + relative)
                mode = stat.S_IMODE(before.st_mode)
                need(mode in (0o644, 0o755), 'canonical reviewed source mode required: ' + relative)
                digest = hashlib.sha256()
                blob = hashlib.sha1(('blob ' + str(before.st_size) + '\0').encode())
                size = 0
                for value in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(value)
                    blob.update(value)
                    size += len(value)
                after = os.fstat(stream.fileno())
            current = path.lstat()
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')
            need(size == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(current, key) for key in fields),
                 'source changed during read: ' + relative)
            result[relative] = {'bytes': size, 'sha256': digest.hexdigest(), 'mode': mode, 'git_blob_sha1': blob.hexdigest()}
    return dict(sorted(result.items()))


def component_tree(values):
    root = {}
    for name, value in values.items():
        branch = root
        parts = name.split('/')
        for part in parts[:-1]:
            branch = branch.setdefault(part, {})
        branch[parts[-1]] = value
    def tree(branch):
        entries = []
        for name, value in branch.items():
            leaf = 'git_blob_sha1' in value
            mode = ('100755' if value['mode'] == 0o755 else '100644') if leaf else '40000'
            digest = value['git_blob_sha1'] if leaf else tree(value)
            entries.append(((name + ('' if leaf else '/')).encode(), mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)))
        raw = b''.join(value for _, value in sorted(entries))
        return hashlib.sha1(('tree ' + str(len(raw)) + '\0').encode() + raw).hexdigest()
    return tree(root)


def check_frozen(source, values, production, manifest_sha, map_sha):
    if manifest_sha is None and map_sha is None:
        return False
    need(manifest_sha is not None and map_sha is not None and all(re.fullmatch('[0-9a-f]{64}', value) for value in (manifest_sha, map_sha)),
         'both actual final manifest/map SHA256 values required')
    raw = (source / 'SOURCE-MANIFEST.json').read_bytes()
    need(sha(raw) == manifest_sha, 'final source manifest differs')
    manifest = json.loads(raw)
    need(manifest['schema'] == 'hepta.local-source.v3' and manifest['production_input_map_sha256'] == map_sha == sha(packed(production)),
         'actual compiler map differs from frozen manifest')
    declared = {row['path']: row for row in manifest['files']}
    need(len(declared) == len(manifest['files']) and set(declared) | {'SOURCE-MANIFEST.json'} == set(values), 'manifest must cover the full exact source set')
    for name, row in declared.items():
        need(row['bytes'] == values[name]['bytes'] and row['sha256'] == values[name]['sha256'], 'frozen file differs: ' + name)
    need(manifest['complete_source_files'] == len(values) and manifest['production_build_inputs_count'] == len(production)
         and manifest['main_java_sources'] == len(list((source / 'src').rglob('*.java'))), 'frozen source counts differ')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--json-jar', type=Path, required=True)
    parser.add_argument('--manifest-sha')
    parser.add_argument('--map-sha')
    args = parser.parse_args()
    source = args.source.absolute()
    output = args.output.absolute()
    need(source.resolve(strict=True) == source and source.is_dir(), 'canonical explicit source directory required')
    need(source != output and source not in output.parents and not output.exists(), 'fresh output must be outside source')
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    events = module(source / 'tests/native-observation-events/run_host.py', 'original_observer_event_runner')
    helper = events.helper(source)
    jdk = args.java_home.resolve(strict=True)
    java, javac, jar = jdk / 'bin/java', jdk / 'bin/javac', args.json_jar.resolve(strict=True)
    tools = [java, javac, jdk / 'lib/modules', jdk / 'lib/ct.sym', jar]
    result = {'schema': 'hepta.native-observation-screenshot-seed-host-gate.v1', 'all_pass': False,
              'source': str(source), 'stages': [], 'phone_actions': 0, 'android_execution': False,
              'model_executed': False, 'business_completion_verified': False,
              'new_action_authority': False, 'action_replayed': False, 'read_permit_expanded': False,
              'deadline_expanded_by_this_candidate': False,
              'compiler_contract': 'JDK17 --release 8 -Xlint:all -Werror',
              'boundary': 'Actual complete observer plus unchanged original fixture bodies and exact pinned fail-only form/AX ports; synthetic Android graph/window/clock/pixel IO and synthetic Session carrier. Device traversal, Session permit issuance, currentness and business completion are not proved.'}
    before = None
    tool_before = None
    try:
        before = inventory(source)
        helper.save(output / 'SOURCE-BEFORE.json', before)
        result['source_before'] = helper.meta(output / 'SOURCE-BEFORE.json')
        result['source_before_sha256'] = sha(packed(before))
        result['complete_source_files'] = len(before)
        result['component_git_tree_sha1'] = component_tree(before)
        result['source_manifest'] = helper.meta(source / 'SOURCE-MANIFEST.json')
        result['fixture_fail_only_port'] = verify_original_fixtures(source, before)
        result['original_fixture_pins'] = PINNED_FIXTURES
        identity = module(source / 'tools/build_identity.py', 'actual_seed_gate_build_identity')
        production = identity.source_inputs(source)
        helper.save(output / 'PRODUCTION-INPUTS.json', production)
        result['production_input_map_sha256'] = sha(packed(production))
        result['production_input_count'] = len(production)
        result['main_java_sources'] = len(list((source / 'src').rglob('*.java')))
        result['frozen_manifest_verified'] = check_frozen(source, before, production, args.manifest_sha, args.map_sha)
        need(all(path.is_file() for path in tools), 'JDK17 modules/API closure and JSON required')
        need(jar.stat().st_size == 78332 and sha(jar.read_bytes()) == '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed', 'reviewed JSON pin differs')
        tool_before = [helper.meta(path) for path in tools]
        result['tools_before'] = tool_before
        generated = output / 'generated'
        generated.mkdir()
        extraction = events.generate(source, generated, helper)
        extraction = events.add_saved_graph_seed_cases(source, generated, helper, extraction)
        path = generated / 'ObserverPipelineHost.java'
        original = path.read_text()
        fragment = (source / TEST / 'ScreenshotGraphSeedCases.fragment').read_text()
        text = events.replace(original, '    public static void main(String[] args)throws Exception{',
                              fragment + '\n    public static void main(String[] args)throws Exception{')
        marker = '        observationIo.executor.shutdown();EventChecks.finish(args[0]);'
        appended = '''        int originalCases=EventChecks.names.size(),originalAssertions=EventChecks.assertions;
        screenshotGraphSeedCases();
        org.json.JSONObject seedResult=new org.json.JSONObject().put("schema","hepta.native-observation-screenshot-seed-cases.v1")
            .put("all_pass",true).put("original_cases",originalCases).put("original_assertions",originalAssertions)
            .put("new_cases",EventChecks.names.size()-originalCases).put("new_assertions",EventChecks.assertions-originalAssertions)
            .put("new_case_names",new java.util.ArrayList<String>(EventChecks.names.subList(originalCases,EventChecks.names.size())));
        Files.write(Paths.get(args[1]),seedResult.toString(2).getBytes(StandardCharsets.UTF_8));
        observationIo.executor.shutdown();EventChecks.finish(args[0]);'''
        text = events.replace(text, marker, appended)
        need(text.replace(fragment + '\n', '', 1).replace(appended, marker, 1) == original,
             'only independent new cases and statistics may be appended to generated fixture')
        path.write_text(text, encoding='utf-8')
        extraction['independent_screenshot_seed_cases'] = {'fragment': helper.meta(source / TEST / 'ScreenshotGraphSeedCases.fragment'),
                                                          'original_generated_fixture_sha256': sha(original.encode()),
                                                          'append_only_reverse_byte_equality': True,
                                                          'original_cases_and_assertions_unchanged': True}
        helper.save(output / 'EXTRACTION.json', extraction)
        classes = output / 'classes'
        classes.mkdir()
        sources = [source / events.PKG / name for name in events.JAVA if name not in ('HeptaAccessibilityService.java', 'PhoneObservation.java')]
        sources += [source / 'tests/native-observation-events/EventChecks.java', path]
        row = helper.stage('compile', [str(javac), '--release', '8', '-encoding', 'UTF-8', '-Xlint:all', '-Werror', '-cp', str(jar), '-d', str(classes)] + list(map(str, sources)), output)
        result['stages'].append(row)
        need(row['exit_code'] == 0, 'actual observer compilation failed')
        row = helper.stage('cases', [str(java), '-cp', str(classes) + os.pathsep + str(jar), 'org.trillionnium.hepta.local.ObserverPipelineHost',
                                    str(output / 'CASES.json'), str(output / 'SEED-CASES.json')], output)
        result['stages'].append(row)
        need(row['exit_code'] == 0, 'actual observer original or independent seed cases failed')
        cases = json.loads((output / 'CASES.json').read_text())
        new = json.loads((output / 'SEED-CASES.json').read_text())
        need(cases['all_pass'] is True and len(cases['case_names']) == len(set(cases['case_names'])) == cases['cases'], 'complete unique passing event cases required')
        need(new['all_pass'] is True and new['original_cases'] == 238 and new['original_assertions'] == 3670,
             'all original 238 cases and 3670 assertions must execute unchanged')
        need(new['new_cases'] == len(new['new_case_names']) == 33 and all(name.startswith('screenshot_seed_') for name in new['new_case_names'])
             and cases['cases'] == new['original_cases'] + new['new_cases']
             and cases['assertions'] == new['original_assertions'] + new['new_assertions'], 'independent seed case accounting differs')
        result.update(all_pass=True, cases=cases['cases'], assertions=cases['assertions'], original_cases=new['original_cases'],
                      original_assertions=new['original_assertions'], new_cases=new['new_cases'], new_assertions=new['new_assertions'],
                      original_cases_and_assertions_preserved=True, cases_file=helper.meta(output / 'CASES.json'),
                      seed_cases_file=helper.meta(output / 'SEED-CASES.json'), extraction_file=helper.meta(output / 'EXTRACTION.json'),
                      generated_files={path.name: helper.meta(path) for path in generated.glob('*.java')})
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        try:
            after = inventory(source)
            helper.save(output / 'SOURCE-AFTER.json', after)
            result['source_after'] = helper.meta(output / 'SOURCE-AFTER.json')
            result['source_after_sha256'] = sha(packed(after))
            result['source_inputs_unchanged'] = before is not None and before == after
            result['component_git_tree_after_sha1'] = component_tree(after)
            result['tools_after'] = [helper.meta(path) for path in tools] if tool_before is not None else None
            result['tools_unchanged'] = tool_before is not None and tool_before == result['tools_after']
            result['all_pass'] = result['all_pass'] and result['source_inputs_unchanged'] and result['tools_unchanged']
        except Exception as error:
            result['all_pass'] = False
            result['finalization_error'] = {'type': type(error).__name__, 'message': str(error)}
        helper.save(output / 'RESULT.json', result)
    print(json.dumps({'all_pass': result['all_pass'], 'result': helper.meta(output / 'RESULT.json')}))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
