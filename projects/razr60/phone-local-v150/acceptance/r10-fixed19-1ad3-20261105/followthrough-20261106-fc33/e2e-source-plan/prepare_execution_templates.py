#!/usr/bin/env python3
"""Deterministic review templates only; all actual task/release slots stay null."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / 'execution-templates01'
CASES = [('E2E-01', 'visual', '视觉挑战'), ('E2E-02', 'unicode', 'Unicode验证'),
         ('E2E-03', 'calculator', '计算器'), ('E2E-04', 'settings', 'settings_about')]
PACKAGE = 'org.trillionnium.hepta.controlprobe'
HEPTA = 'org.trillionnium.owneropen/org.trillionnium.owneropen.OwnerOpenShellActivity'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def descriptor(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def empty_descriptor():
    return {'path': None, 'bytes': None, 'sha256': None}


def slot(name):
    return {'unbound_slot': name}


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def main():
    source_report = json.loads((HERE / 'candidate01/CANDIDATE-SOURCES.json').read_bytes())
    candidate = descriptor(HERE / 'candidate01/CANDIDATE-SOURCES.json')
    fixed = {'phone_calls': 0, 'model_requests': 0, 'native_dispatches': 0, 'new_nonces': 0,
             'fixed19_credit': 0, 'automatic_retry': False, 'historical_pass_inherited': False}
    values = {}
    bind_inputs = {name: empty_descriptor() for name in (
        'candidate_manifest', 'runtime_freeze', 'runtime_manifest', 'formal_source_binding',
        'boundary_consumer', 'readiness_source', 'owned_capture_source')}
    bind_inputs['candidate_manifest'].update(bytes=candidate['bytes'], sha256=candidate['sha256'])
    bind_inputs['owned_capture_source'].update(bytes=37720,
        sha256='9d273d66adc09c670ae09aa06fae699d2d1de9e1981afd3980bec7e4eda6cb29')
    bind_inputs['output'] = None
    values['SOURCE-BINDING-INPUTS.UNBOUND.json'] = bind_inputs
    master = {
        'schema': 'hepta.fc33.e2e.execution-inputs.unbound.v1',
        'state': 'REVIEW_ONLY_BUILD_READY_CONTEXT_UNBOUND',
        'source_candidates': candidate,
        'source_controls': descriptor(HERE / 'SOURCE-CONTROLS.json'),
        'source_binding_constructor': descriptor(HERE / 'bind_e2e_sources_UNBOUND.py'),
        'source_combination': source_report['source_combination'],
        'source_combination_is_not_the_formal_release_binding': True,
        'actual_source_binding': None, 'actual_runtime_freeze': None,
        'actual_formal_source_binding': None, 'actual_BUILD': None, 'actual_READY': None,
        'actual_release_directory': None, 'actual_previous_input': None,
        'actual_preserved_draft': None, 'actual_retirement_resolution': None,
        'actual_context': None, 'actual_scope': None,
        'case_order': [x[0] for x in CASES],
        'next_case_previous_rule': 'Only the actual closed previous-input from the preceding attempt. Unknown lifecycle requires reconciliation of that same attempt before another case.',
        'dispatcher': 'root only',
        'maximum_tool_calls': 7, 'maximum_model_rounds': 8,
        'COMP-01_actual_return_case': None,
        'COMP-01_direct_operator_helper': 'historical reference only; no current qualification',
        'cases': [], **fixed,
    }
    for case, kind, alias in CASES:
        plan = {
            'schema': 'hepta.fixed19.e2e.coordinator-plan.v1', 'case_id': case,
            'coordinator_sha256': None, 'operator_manifest': empty_descriptor(),
            'capture_source': {'path': None, 'bytes': 37720,
                              'sha256': '9d273d66adc09c670ae09aa06fae699d2d1de9e1981afd3980bec7e4eda6cb29'},
            'shared_materials': {'path': None, **source_report['shared_materials']},
            'context': empty_descriptor(), 'output': None,
        }
        assert set(plan) == {'schema', 'case_id', 'coordinator_sha256', 'operator_manifest',
                             'capture_source', 'shared_materials', 'context', 'output'}
        values['COORDINATOR-PLAN.' + case + '.UNBOUND.json'] = plan
        material_argv = ['/usr/bin/python3', '-I', '-B', slot('actual_materializer.path'), kind,
                         '--release-dir', slot('actual_release_directory'),
                         '--build-result-sha256', slot('actual_BUILD.sha256'), '--out', slot('fresh_material_directory'),
                         '--session-id', slot('actual_previous_input.identity.session_id'),
                         '--profile-id', slot('actual_previous_input.identity.profile_id'), '--allowed-app', alias]
        master['cases'].append({
            'case_id': case, 'kind': kind, 'explicit_allowed_apps': [alias],
            'return_requested': case != 'E2E-04',
            'materializer_argv_template': material_argv,
            'unicode_text_file_override': None, 'fresh_material_directory': None,
            'fresh_sender_label': None, 'fresh_workflow_directory': None,
            'actual_nonce': None, 'actual_request': None, 'actual_material': None,
            'actual_context': None, 'actual_coordinator_plan': None, 'actual_native_scope': None,
            'actual_coordinator_result': None, 'actual_report': None, 'actual_closure': None,
            'actual_next_previous': None, 'current_case_pass': False,
        })
    values['EXECUTION-INPUTS.UNBOUND.json'] = master
    prepare_args = ['/usr/bin/python3', '-I', '-B', slot('bound_operator_directory/root_acceptance_r10.py'), 'prepare']
    for flag, value in [
        ('project-dir', 'B'), ('materializer', 'actual_materializer.path'),
        ('release-dir', 'actual_release_directory'), ('material', 'actual_material_directory'),
        ('previous-input', 'actual_previous_input.path'), ('ready-input', 'actual_READY.path'),
        ('preserved-draft', 'actual_preserved_draft.path'),
        ('retirement-resolution', 'actual_retirement_resolution.path'),
        ('collector-package', 'bound_collector_package_directory'), ('out', 'fresh_workflow_directory'),
        ('build-result-sha256', 'actual_BUILD.sha256'), ('previous-sha256', 'actual_previous_input.sha256'),
        ('ready-sha256', 'actual_READY.sha256'), ('preserved-draft-sha256', 'actual_preserved_draft.sha256'),
        ('retirement-resolution-sha256', 'actual_retirement_resolution.sha256'),
        ('operator-manifest-sha256', 'bound_operator_manifest.sha256'),
        ('collector-package-sha256', 'bound_collector_manifest.sha256'), ('sender-label', 'fresh_sender_label'),
    ]:
        prepare_args.extend(['--' + flag, slot(value)])
    phases = [
        {'name': 'register', 'budget_seconds': 240, 'entry': 'root_acceptance_r10.py register',
         'explicit_flag': '--execute-register-once', 'effect': 'one request-bound registration after original READY checks'},
        {'name': 'sender_preview', 'budget_seconds': 30, 'entry': 'root_acceptance_r10.py sender-preview',
         'explicit_flag': None, 'effect': 'build original actor only; no send'},
        {'name': 'sender_execute', 'budget_seconds': 650, 'entry': 'root_acceptance_r10.py sender-execute',
         'explicit_flag': '--execute-send-once', 'effect': 'fresh readiness recheck, exact preview actor, maximum one native send'},
        {'name': 'capture_export', 'budget_seconds': 500, 'entry': 'export_originals_r10.py capture',
         'explicit_flag': '--execute-read-once', 'effect': 'capture full originals and export them in this phase'},
        {'name': 'collect', 'budget_seconds': 135, 'entry': 'export_originals_r10.py collect',
         'explicit_flag': None, 'effect': 'new host-only original evidence report'},
        {'name': 'close', 'budget_seconds': 135, 'entry': 'close_original_r10.py',
         'explicit_flag': '--execute-close-once', 'effect': 'host closure against actual report SHA and original effect terminals'},
    ]
    values['ENTRYPOINTS.json'] = {
        'schema': 'hepta.fc33.e2e.reviewed-entrypoints.v1',
        'source_binding_first': 'Bind only actual frozen runtime/source/readiness inputs with the unbound source constructor.',
        'materialization_gate': 'Run original materializer only after actual BUILD validation and selected scope. It allocates one fresh nonce after a create-only intent.',
        'context_prepare_argv_template': prepare_args,
        'coordinator_argv_template': ['/usr/bin/python3', '-I', '-B', slot('bound_coordinator.path'),
                                      '--plan', slot('actual_coordinator_plan.path'), '--plan-sha256',
                                      slot('actual_coordinator_plan.sha256'), '--execute-e2e-once'],
        'coordinator_plan_output_rule': 'exact ROOT-CONTEXT.workflow_dir / owned-coordinator; absent before run',
        'phases': phases,
        'original_sender': {'name': 'send_new_native_task_r5.py', 'bytes': 40788,
                            'sha256': '5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'},
        'probe_reset': 'Existing sender --reset-probe is used for visual/unicode. It force-stops the probe before the model opens it; it does not read a challenge answer.',
        'materializer': {'bytes': 24834, 'sha256': 'b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290'},
        'export_must_not_be_repeated': True,
        'unknown_result_rule': 'Preserve E2E-FAILURE and all original phase outputs; reconcile the existing label/nonce/scope. Never rerun the coordinator or sender, allocate a replacement identity, or infer success.',
        'known_failed_business_rule': 'A closed lifecycle is eligible only as previous-input. It remains case failure and is never converted into a business pass.',
        **fixed,
    }
    common = [
        'Actual sealed BUILD, four-role READY, source/config/service/module and both boundary-input identities agree. Source-only 7969 combination is not a BUILD.',
        'Exact owner request and one-use nonce, explicit approved app subset, five native scope fields, and native-envelope digest remain separately bound.',
        'Exactly one actual send; every accepted native call maps to the actual local model action and full claim/sequence/length/terminal/hash-verified native record.',
        'Local-model request bytes include the exact fresh screenshot JPEG, if required; response and worker cleanup are real and complete. No retry, hidden fallback, old round, or fabricated image input.',
        'Capture thirteen bindings, complete originals/archive SHA and actor/phone return codes are verified. Collector actual exit is zero and issues are empty.',
        'All requested postconditions are rederived by the exact selected production parser, agree with the recorded full-task outcome, and native terminal is completed.',
        'All effects have original confirmed terminals, model workers are joined, owned resources are cleaned, and the next previous-input is the exact closure output.',
        'Coordinator E2E-RESULT.case_pass, report proof/business, closure proof/business and all six phase return codes agree. Missing conditions or unknown effects remain failure/unknown.',
    ]
    case_checks = {
        'E2E-01': {
            'contract': ['visual_receipt_matches_challenge', 'foreground_hepta'],
            'freshness': 'Force-stop then fresh app open; the challenge is observed only through the new screenshot before the selection.',
            'gates': [
                'Retain screenshot original, encoded JPEG, request body data URI and hashes; exact JPEG must be present in the actual local-model round.',
                'Exactly one native phone.tap using that current screenshot/viewport/page and source-image claim; no hierarchy or challenge-code read before the completed visual tap.',
                'Read visual_challenge_code and visual_receipt from the same current public UI; prefix 挑战码： and HEPTA_VISUAL_OK carry the same nonempty challenge code.',
                'Actual production phone.return_hepta verifies the requested return and contributes eligible COMP-01 originals.',
            ],
            'view_ids': [PACKAGE + ':id/visual_challenge_code', PACKAGE + ':id/visual_receipt'],
            'current_pass': False,
        },
        'E2E-02': {
            'contract': ['text_readback_exact', 'public_text_exact', 'public_text_exact', 'foreground_hepta'],
            'fresh_text': None,
            'text_recipe': 'Original materializer creates new Chinese + emoji text containing an actual LF and literal quotes, backslash, dollar/substitution/shell metacharacters. BEGIN/END delimiters are not input content.',
            'gates': [
                'Exactly one focused input intent with the complete original UTF-8 text; all original LF bytes are 0a and must not become spaces.',
                'Confirm using the actual visible unicode_submit once; retain semantic action/image-to-coordinate/native terminal evidence.',
                'Input confirmation readback, public unicode_readback and the requested text have the same exact bytes/SHA; no Unicode or whitespace normalization.',
                'Public unicode_receipt is exactly HEPTA_UNICODE_READBACK plus LF-separated sha256, codepoints and utf8_bytes derived independently from the request.',
                'Actual production return receipt verifies HEPTA, independently of operator draft restoration.',
            ],
            'view_ids': [PACKAGE + ':id/unicode_input', PACKAGE + ':id/unicode_submit',
                         PACKAGE + ':id/unicode_readback', PACKAGE + ':id/unicode_receipt'],
            'extra_original_audit': 'The existing aggregate collector enforces input<=1. Independently count the actual confirmation action and review its original target; do not infer it solely from a final receipt.',
            'current_pass': False,
        },
        'E2E-03': {
            'contract': ['text_readback_exact', 'public_text_exact', 'foreground_hepta'],
            'fresh_expression': None, 'independent_integer_result': None,
            'expression_recipe': 'Original materializer draws a,b,c independently in 11..29 and creates (a×b)+c. Compute a*b+c independently on the host from the actual saved integers.',
            'gates': [
                'Retain the fresh expression/expected-result original files and arithmetic inputs. Do not reuse a historical expression or inject the answer.',
                'One complete input, actual formula_or_result expression readback, one visible equals activation, and a fresh visible result from the application.',
                'Actual public result exactly matches the independently computed integer and the bound expected-result bytes.',
                'Actual production return receipt verifies HEPTA.',
            ],
            'view_id': 'com.motorola.cn.calculator:id/formula_or_result',
            'extra_original_audit': 'The existing collector enforces input<=1, but does not separately count equals. Count the actual equals action and verify its original target/ordering.',
            'current_pass': False,
        },
        'E2E-04': {
            'contract': ['public_text_anchor_exact'],
            'return_requested': False,
            'entry': 'com.android.settings/com.android.settings.Settings$MyDeviceInfoActivity',
            'result_component': 'com.android.settings/com.android.settings.SubSettings',
            'selector': {'title_view_id': 'android:id/title', 'anchor_text': 'Android 版本',
                         'value_view_id': 'android:id/summary',
                         'relation': 'same_direct_preference_text_container'},
            'gates': [
                'Navigate the actual current public UI without changing settings, permissions, network or accounts.',
                'Exactly one visible enabled title/value pair in the same direct android.widget.RelativeLayout; package and bounds are valid and password is false.',
                'Current window focus, focused-app component and top-resumed component independently agree on the expected Settings component.',
                'Read the actual UI version value. Historical route/getprop reference is only the fixed contract reference and never substitutes for a fresh observation.',
                'If the observed value differs from the fixed contract, retain failure; do not edit expected values in an already registered task.',
            ],
            'current_pass': False,
        },
        'COMP-01': {
            'source_cases': ['E2E-01', 'E2E-02', 'E2E-03'],
            'selected_actual_case': None, 'actual_return_call': None, 'actual_native_result': None,
            'receipt_schema': 'hepta.return-receipt.v149.1', 'component': HEPTA,
            'gates': [
                'The original request explicitly requires returning, and the actual model mapped phone.return_hepta to the production native call.',
                'Complete native claim/sequence/result binding matches the current source tuple, request, five-field scope and exact accepted dispatch.',
                'launch_exit_code is integer zero; am start -W has exactly one Status: ok and one normalized Activity equal to OwnerOpenShellActivity, with no Error/Exception/SecurityException.',
                'Actual currentFocus, focusedApp and single topResumedActivity all name the exact HEPTA component; qualified inner display and unlocked state are verified.',
                'The fresh typed foreground_hepta fact was derived from this original result. Operator restoration, old direct helper, or merely issued launch commands cannot supply this fact.',
            ],
            'current_pass': False,
        },
    }
    values['EVIDENCE-CLOSURE-CHECKLIST.json'] = {
        'schema': 'hepta.fc33.e2e.comp01.closure-checklist.v1', 'common_gates': common,
        'cases': case_checks, 'actual_evidence': None, **fixed,
    }
    values['SOURCE-READINESS.json'] = {
        'schema': 'hepta.fc33.e2e.source-readiness.v1',
        'completed_host_work': [
            'Actual seventeen shared materials and fifteen production source pins verified.',
            'Collector five SHA literals rebound with whole-byte inverse; other six collectors unchanged.',
            'Seven named-action projection fragments still have their original exact aggregate hash.',
            'Coordinator shared literal rebound; final operator-manifest literal remains None.',
            'Six operator sources retained; only root readiness literal is None pending actual final readiness source.',
            'Original materializer and both historical reference files retained byte-identically.',
            '23 pure source controls passed; no phone/model/native execution or nonce allocation.',
        ],
        'remaining_real_bindings': [
            'Actual frozen R5 runtime and corresponding bound consumer.',
            'Actual source-chain output/readiness descriptor; only boundary-consumer literal may differ from reviewed readiness parent.',
            'Source-only E2E binding publication, then actual formal BUILD and four-role READY.',
            'Latest actual previous lifecycle, preserved private draft and retirement resolution.',
            'Fresh case material, exact app scope, host context and coordinator plan for each case.',
        ],
        'preserved_history': [
            {'path': 'references/fixed19-e2e-final-r4-a1055-r1/FAILURE.json',
             'meaning': 'Old source/control construction failed; no current BUILD/READY/business credit.'},
            {'path': 'references/e2e-coordinator-independent-review-a1055-r1/RESULT.json',
             'meaning': '29 historical host controls on the unbound coordinator, no actual E2E credit.'},
            {'path': 'references/readiness-r9/operator/RUNTIME-COMPONENT-QUALIFICATION.json',
             'meaning': 'Historical physical calculator/settings routes; native_tasks=0 and model_requests=0.'},
        ],
        **fixed,
    }
    OUT.mkdir(mode=0o700)
    for name, value in sorted(values.items()):
        raw = enc(value)
        with (OUT / name).open('xb') as stream:
            stream.write(raw)
    manifest = {'schema': 'hepta.fc33.e2e.execution-template-package.v1',
                'source': descriptor(Path(__file__)), 'files': [descriptor(OUT / n) for n in sorted(values)],
                'actual_fields_remain_null': True, **fixed}
    with (OUT / 'MANIFEST.json').open('xb') as stream:
        stream.write(enc(manifest))
    print(json.dumps({'state': 'REVIEW_TEMPLATES_CREATED_NO_TASK',
                      'result': descriptor(OUT / 'MANIFEST.json'), **fixed}, sort_keys=True))


if __name__ == '__main__':
    main()
