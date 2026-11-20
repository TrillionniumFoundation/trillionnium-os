#!/usr/bin/env python3
"""Run the real extracted observer plus typed-publication races and original fresh-action gate."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
NEW_NAMES = ["sealed_typed_content_during_window_read_2048_publishes_history","sealed_typed_content_during_window_read_16_publishes_history","sealed_typed_content_after_worker_before_main_2048_publishes_history","sealed_typed_content_after_worker_before_main_16_publishes_history","sealed_88_authored_content_events_keep_real_counts_and_original_times","sealed_structural_unknown_and_other_window_events_never_use_content_exception","sealed_structure_during_encoding_or_main_queue_invalidates_the_whole_seal","typed_content_in_pair_check_to_active_seal_gap_is_still_structural","typed_content_during_preseal_graph_read_preserves_original_all_event_fence","retired_or_retried_seal_does_not_classify_later_events_as_historical_content","unmirrored_legacy_raw_counter_change_cannot_fake_an_atomic_watermark","optional_diagnostics_are_not_required_for_typed_content_publication","earlier_callback_time_does_not_regress_later_worker_diagnostic_phase_clock"]
EXPECTED_TOTAL_ASSERTIONS = 341
DISPATCH_TAIL_SHA = '285a07fbe2620f59fbad72ed91d42652f92e5fa2a28f2e235d3b2e93efca68f5'
ACTION_RUNNER_SHA = 'ebee547ccbbc140380c48510a922f4b1b8f56912ff4aba37b05bad8871340869'
PKG = Path('src/org/trillionnium/hepta/local')
EMPTY_SHA = hashlib.sha256(b'').hexdigest()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('source', 'java-home', 'json-jar', 'output'):
        p.add_argument('--' + key, type=Path, required=True)
    a = p.parse_args()
    source, jdk, jar, output = a.source.resolve(), a.java_home.resolve(), a.json_jar.resolve(), a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'hepta.native-observation-content-publication-host.v1', 'all_pass': False,
              'phone_operations': 0, 'android_execution': False, 'model_executed': False,
              'business_completion_verified': False, 'dispatch_freshness_changed': False, 'stages': []}
    tracked = list(HERE.rglob('*')) + [source / PKG / n for n in
              ('HeptaAccessibilityService.java', 'ObservationDiagnostics.java', 'ObservationStabilityGate.java',
               'PhoneObservation.java', 'LocalTaskController.java', 'LocalInference.java', 'VlmInferenceAdapter.java')]
    tracked += list((source / 'tests/native-observation-snapshot').rglob('*'))
    tracked += [source / 'tests/observation-pipeline/ObserverPipelineHost.template',
                source / 'tests/observation-diagnostics/run_host.py',
                source / 'tests/native-action-integration/run_host.py']
    tracked = sorted({x for x in tracked if x.is_file()})
    before = {str(x.relative_to(source)): sha(x) for x in tracked}
    result['inputs_before'] = before
    try:
        contract = json.loads((HERE / 'CASE-CONTRACT.json').read_text())
        if (contract['expected_new_cases'] != len(NEW_NAMES)
                or contract['expected_total_assertions'] != EXPECTED_TOTAL_ASSERTIONS):
            raise RuntimeError('Fixed case contract differs')
        for name, digest in contract['fixture_sha256'].items():
            if sha(HERE / 'fixtures' / name) != digest:
                raise RuntimeError('Actual fixture pin differs: ' + name)
        provenance = json.loads((HERE / 'fixtures/PROVENANCE.json').read_text())
        action = json.loads((HERE / 'fixtures/actual-stale-action.json').read_text())
        observed = json.loads((HERE / 'fixtures/actual-failed-observation.json').read_text())
        if (action['accepted'] is not False or action['dispatched'] is not False or action['stale'] is not True
                or action['action_execution']['effect_entered'] is not False
                or observed['events']['CAPTURE_EVENT_RESET'] != 2 or observed['events']['EVENT_TARGET'] != 88
                or provenance['actual_event_types_recorded'] is not False
                or provenance['authored_88_event_case_metadata_and_distribution_synthetic'] is not True
                or provenance['candidate_phone_verified'] is not False):
            raise RuntimeError('Real failure versus authored typed-event boundary differs')
        text = (source / PKG / 'HeptaAccessibilityService.java').read_text()
        marker = '    private static final class StaleObservation extends IllegalStateException {'
        if text.count(marker) != 1 or hashlib.sha256(text[text.index(marker):].encode()).hexdigest() != DISPATCH_TAIL_SHA:
            raise RuntimeError('Original dispatch, node freshness or window/graph IO code changed')
        event_wiring = ('noteObservationEvent(android.os.Build.VERSION.SDK_INT>=33?event.getDisplayId():-1,\n'
                        '                event.getEventType(),event.getWindowId(),event.getPackageName()==null?null:event.getPackageName().toString());')
        if text.count(event_wiring) != 1:
            raise RuntimeError('Actual Android event callback does not copy the tested metadata')
        result['dispatch_and_following_android_io_sha256'] = DISPATCH_TAIL_SHA
        result['actual_event_types_available_in_old_failure'] = False
        result['authored_typed_event_metadata_is_synthetic'] = True
        snapshot = load(source / 'tests/native-observation-snapshot/run_host.py', 'actual_snapshot_runner')
        generate_original = snapshot.generate
        def generate_with_new_cases(src, out, helpers):
            extraction = generate_original(src, out, helpers)
            path = out / 'ObserverPipelineHost.java'
            generated = path.read_text()
            marker = '    public static void main(String[] args)throws Exception{'
            if generated.count(marker) != 1:
                raise RuntimeError('Original snapshot main boundary changed')
            generated = generated.replace(marker, (HERE / 'ContentPublicationCases.fragment').read_text() + '\n' + marker, 1)
            anchor = 'persistenceAndLegacyCases();ObservationEvidenceHost.run();'
            if generated.count(anchor) != 1:
                raise RuntimeError('Original snapshot cases changed')
            generated = generated.replace(anchor, anchor + 'typedPublicationCases();', 1)
            path.write_text(generated)
            extraction['additional_cases_sha256'] = sha(HERE / 'ContentPublicationCases.fragment')
            extraction['original_cases_preserved'] = True
            extraction['new_production_methods_replaced_by_tests'] = False
            return extraction
        snapshot.generate = generate_with_new_cases
        pipeline = output / 'pipeline'
        old_argv = sys.argv
        buffer = io.StringIO()
        started = time.monotonic()
        try:
            sys.argv = [str(source / 'tests/native-observation-snapshot/run_host.py'),
                        '--source', str(source), '--output', str(pipeline),
                        '--java-home', str(jdk), '--json-jar', str(jar)]
            with contextlib.redirect_stdout(buffer):
                code = snapshot.main()
        finally:
            sys.argv = old_argv
        (output / 'observer-pipeline.stdout').write_text(buffer.getvalue())
        result['stages'].append({'name': 'observer-pipeline', 'exit_code': code,
                                'elapsed_seconds': time.monotonic() - started,
                                'stdout_sha256': sha(output / 'observer-pipeline.stdout')})
        observed_result = json.loads((pipeline / 'RESULT.json').read_text())
        result['pipeline_result_sha256'] = sha(pipeline / 'RESULT.json')
        if (code != 0 or observed_result.get('all_pass') is not True
                or observed_result.get('inputs_unchanged') is not True
                or observed_result.get('tools_unchanged') is not True
                or observed_result.get('action_freshness_relaxed') is not False
                or observed_result.get('deadline_expanded') is not False):
            raise RuntimeError('Real observer pipeline failed; inspect preserved pipeline/RESULT.json')
        cases = observed_result['cases']
        expected_names = contract['original_case_names'] + NEW_NAMES
        result['cases'] = cases
        if (cases['case_names'] != expected_names or cases['cases'] != len(expected_names)
                or any(cases['case_assertions'].get(n) != v for n, v in contract['original_case_assertions'].items())):
            raise RuntimeError('Original cases/assertions or mandatory new case accounting differ')
        stdout = (pipeline / 'cases.stdout').read_text()
        pass_names = [x[5:] for x in stdout.splitlines() if x.startswith('PASS ')]
        stdout_summaries = [json.loads(x) for x in stdout.splitlines() if x.startswith('{')]
        # Seven original immutable-evidence cases intentionally print only in the
        # complete JSON summary; preserve the original 42 PASS-line protocol.
        if (pass_names != contract['original_stdout_pass_names'] + NEW_NAMES
                or stdout_summaries != [cases]
                or len(stdout.splitlines()) != len(pass_names) + 1):
            raise RuntimeError('Actual Java PASS/JSON lines do not bind exact cases')
        # Keep this independent unchanged action gate: publishing historical pixels
        # never substitutes for the real Session/Service fresh-node/ancestor checks.
        action_runner = source / 'tests/native-action-integration/run_host.py'
        if sha(action_runner) != ACTION_RUNNER_SHA:
            raise RuntimeError('Original fresh-action runner changed')
        action_output = output / 'fresh-action'
        argv = [sys.executable, '-B', str(action_runner), '--source', str(source),
                '--output', str(action_output), '--java-home', str(jdk), '--json-jar', str(jar)]
        started = time.monotonic()
        run = subprocess.run(argv, capture_output=True, timeout=180)
        (output / 'fresh-action.stdout').write_bytes(run.stdout)
        (output / 'fresh-action.stderr').write_bytes(run.stderr)
        result['stages'].append({'name': 'fresh-action-integration', 'exit_code': run.returncode,
                                 'elapsed_seconds': time.monotonic() - started,
                                 'stdout_sha256': sha(output / 'fresh-action.stdout'),
                                 'stderr_sha256': sha(output / 'fresh-action.stderr')})
        fresh = json.loads((action_output / 'RESULT.json').read_text())
        result['fresh_action_result_sha256'] = sha(action_output / 'RESULT.json')
        if (run.returncode != 0 or run.stderr or fresh.get('all_pass') is not True
                or fresh.get('inputs_unchanged') is not True or fresh.get('tools_unchanged') is not True
                or fresh['pure']['cases'] != 76 or fresh['pure']['assertions'] != 157
                or [x['name'] for x in fresh['stages']] != ['compile', 'pure-cases', 'integration-cases']
                or any(x['exit_code'] != 0 or x['stderr']['sha256'] != EMPTY_SHA for x in fresh['stages'])):
            raise RuntimeError('Unchanged real fresh-action gate failed')
        result['fresh_action_summary'] = {'pure_cases': fresh['pure']['cases'],
            'pure_assertions': fresh['pure']['assertions'], 'integration_cases': fresh['cases']['cases'],
            'integration_assertions': fresh['cases']['assertions'], 'case_names': fresh['cases']['case_names']}
        if (cases['assertions'] != EXPECTED_TOTAL_ASSERTIONS or cases['cases'] != 62
                or hashlib.sha256('\n'.join(cases['case_names']).encode()).hexdigest() != contract['case_names_sha256']):
            raise RuntimeError('Development assertion count not yet frozen or final contract differs')
        result['case_names_sha256'] = hashlib.sha256('\n'.join(cases['case_names']).encode()).hexdigest()
        result['all_pass'] = True
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    result['inputs_after'] = {str(x.relative_to(source)): sha(x) for x in tracked}
    result['inputs_unchanged'] = result['inputs_after'] == before
    result['all_pass'] = result['all_pass'] and result['inputs_unchanged']
    (output / 'RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'all_pass': result['all_pass'], 'error': result.get('error'),
                      'stages': result['stages'], 'cases': None if 'cases' not in result else
                      {k: result['cases'][k] for k in ('cases', 'assertions')},
                      'result_sha256': sha(output / 'RESULT.json')}))
    return 0 if result['all_pass'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
