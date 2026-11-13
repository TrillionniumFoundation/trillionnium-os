#!/usr/bin/env python3
"""Assemble v51-build-r2 on Pocket4 using cached runtimes and the existing key only.

This runner never invokes adb, contacts a phone, downloads dependencies, creates
a signing key, or edits source files. The original assembler may create its
empty source/keys directory; no file is permitted there. Outputs are exclusive.
"""
import sys
sys.dont_write_bytecode = True
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path('/home/alex/hepta-local-007f-20261111/v51-build-r2')
SOURCE = ROOT / 'source'
OUT = ROOT / 'out'
COMMIT = 'ed98f11db804f191a65254c378b195b1fb5f13be'
VERSION_CODE = 51
VERSION_NAME = '0.51.0-local-notes-workflow'
INVENTORY_SHA256 = 'ef4d17778acb54c10be989173041bda052daeb83325476135d71992602a6dc64'
SOURCE_FILE_COUNT = 546
ARCHIVE_BYTES = 449226
ARCHIVE_SHA256 = 'ff26029ecd70a18e9400132b9fc68453b4de4effbb2e9a805302da25258cf74c'
COMPILER_INPUT_COUNT = 185
SIGNER_PROOF = Path('/home/alex/hepta-v35-task-authorization-e59-r1/SIGNER-PROOF.json')
SIGNER_PROOF_SHA256 = '97e3aba44ec7a303a935965c1d608692ac06007a33bb859fec481486c1a239fe'
CERT = '202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5'
JDK_PROOF = Path('/home/alex/hepta-v31-nanbeige42-e59-r1/toolchains/old-jdk17-revalidation-r1/RESULT.json')
JDK_PROOF_SHA256 = '349939390c8b19e8cea03e28ce6c5bc2c1d010dd06d3a435b7f1517221f0dd1c'
MEMBERS = {'out/base.apk', 'out/dex/classes.dex', 'out/libhepta_local_runner.so',
           'out/mac-build-receipt.json', 'out/worker-appuid.c', 'out/native-sha256-disassembly.txt'}
HOST_RECORD_COUNT = 101
HOST_INPUT_COUNT = 370
POST_CAS_STAGE_SHA256 = '7dad86e4c61c0238b944d86d958e75bb8edd2ddb22c5ccac654e2229afb70e34'
POST_CAS_BINDING_SHA256 = '8da9a2156bb93aa005c936cd3ff5e6f7d062269a23f9343ecf73e2ff7e849e75'
PRE_COMMIT_HOST_RESULT_SHA256 = '452901b745fd46828fab3f9b0524a4e25a31d274cdf324e21109c6ea989c1840'
HOST_NAMES = 'java-compile ActionFreshnessHostTest AppCatalogueHostTest BudgetHostTest CompactEvidenceHostTest CompactSequenceHostTest CompactTaskHistoryHostTest DiagnosticStartupGateHostTest DispatchedActionSequenceHostTest Gemma4ProfileHostTest ImeObservationHostTest LastModelDecisionProjectionHostTest Lfm25MoeProfileHostTest Lfm3ExactTokenHostTest LocalPolicyHostTest MemoryAvailabilityHostTest MobiMindContractHostTest MobiMindSessionContractHostTest MobileAgentProfilesHostTest ModelProfileHostTest Nanbeige42ProfileHostTest ObservationStabilityHostTest ObservedAppLabelsHostTest ObservedChildTextHostTest ObservedScrollActionsHostTest ObservedTargetLabelsHostTest ObservedTextProjectionHostTest ObservedTransitionProjectionHostTest ObservedWindowMetadataHostTest PersistentActionPolicyHostTest PromptActionDomainHostTest PromptCapabilityProjectionHostTest Qwen35ProfileHostTest ReadableActionHistoryHostTest RecentActionProjectionHostTest RecoveryAcknowledgementHostTest RecoveryDispatchHostTest RecoverySlotHandoffHostTest RepeatActionGuardHostTest RepeatClickProjectionHostTest SameStateNoEffectGuardHostTest ScrollGrammarHostTest SessionRecoveryHostTest TaskAuthorizationDomainHostTest UiVenusContractHostTest UiVenusInputContractHostTest UiVenusProcessContractHostTest UiVenusRequestContractHostTest UiVenusSessionContractHostTest WarmProcessSessionHostTest ActionDecisionHostTest DecisionGrammarHostTest grammar-recognition app-label-grammar-recognition scroll-grammar-recognition completion-protocol same-state-no-effect-grammar background-client qualification-scope owner-authorization owner-grammar ime-submit fixed-intent-tools fixed-intent-integration background-permission background-permission-session background-broker python-tools mobimind-private-staging ui-venus-q4_0-provenance lfm25_profile_contract-compile lfm25_profile_contract mobile_agent_profiles_contract-compile mobile_agent_profiles_contract model_profile_contract-compile model_profile_contract nanbeige42_profile_contract-compile nanbeige42_profile_contract parent_death_contract-compile parent_death_contract phase_timing_contract-compile phase_timing_contract prompt_budget_contract-compile prompt_budget_contract publish_contract-compile publish_contract qwen35_profile_contract-compile qwen35_profile_contract sha256_probe-compile sha256_probe sha256-hashlib-differential native-adapter-syntax private-prompt-evidence task-worker-native-lifecycle profile-sampler notes-completion-evidence task-completion calculator-completion-pure observation-collection notes-owner-intent background-owned-task-policy'.split()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            value.update(chunk)
    return value.hexdigest()


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('Independent regular file required: ' + str(path))
    return info


def put(path, content):
    with path.open('xb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def write_json(path, value):
    put(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def read_json(path):
    regular(path)
    return json.loads(path.read_text())


def source_check():
    path = ROOT / 'SOURCE-INVENTORY.json'
    regular(path)
    if sha(path) != INVENTORY_SHA256:
        raise RuntimeError('Pinned complete source inventory changed')
    inventory = read_json(path)
    if len(inventory) != SOURCE_FILE_COUNT:
        raise RuntimeError('Complete source file count differs')
    actual = []
    if SOURCE.is_symlink() or not SOURCE.is_dir():
        raise RuntimeError('Source directory must be real')
    for member in sorted(SOURCE.rglob('*')):
        if member.is_symlink():
            raise RuntimeError('Linked source member: ' + str(member))
        if member.is_dir():
            continue
        info = regular(member)
        actual.append({'path': str(member.relative_to(SOURCE)), 'size': info.st_size, 'sha256': sha(member)})
    if actual != inventory:
        raise RuntimeError('Complete source file membership or content changed')
    keys = SOURCE / 'keys'
    if keys.exists() and (not keys.is_dir() or any(keys.iterdir())):
        raise RuntimeError('Assembler source/keys must remain an empty directory')
    manifest = ET.fromstring((SOURCE / 'AndroidManifest.xml').read_bytes())
    android = '{http://schemas.android.com/apk/res/android}'
    if (manifest.get('package'), manifest.get(android + 'versionCode'), manifest.get(android + 'versionName')) != (
            'org.trillionnium.hepta.local', str(VERSION_CODE), VERSION_NAME):
        raise RuntimeError('Pinned manifest identity differs')
    return inventory


def qualify_host():
    stage_path = ROOT / 'STAGE-RESULT.json'
    stage = read_json(stage_path)
    if sha(stage_path) != POST_CAS_STAGE_SHA256:
        raise RuntimeError('Actual post-CAS stage receipt changed')
    binding_path = ROOT / 'SOURCE-COMMIT-BINDING.json'
    if sha(binding_path) != POST_CAS_BINDING_SHA256:
        raise RuntimeError('Actual post-CAS source/Git binding changed')
    pre_commit_path = ROOT / 'PRE-COMMIT-HOST-RESULT.json'
    if sha(pre_commit_path) != PRE_COMMIT_HOST_RESULT_SHA256:
        raise RuntimeError('Original pre-publication host receipt changed')
    pre_commit = read_json(pre_commit_path)
    if (pre_commit.get('all_pass') is not True or pre_commit.get('exit_code') != 0
            or pre_commit.get('candidate_source_commit') is not None
            or pre_commit.get('publication_pending') is not True
            or pre_commit.get('source_file_count') != SOURCE_FILE_COUNT
            or pre_commit.get('source_inventory_sha256') != INVENTORY_SHA256
            or pre_commit.get('host_check_records') != HOST_RECORD_COUNT
            or pre_commit.get('host_input_count') != HOST_INPUT_COUNT
            or pre_commit.get('source_files_unchanged') is not True
            or stage.get('source_commit_bound_after_exact_host_run') is not True):
        raise RuntimeError('Post-CAS binding must preserve when the exact host gate ran')
    if (stage.get('schema') != 'hepta.background-host-stage.v1' or stage.get('host') != 'pocket4'
            or stage.get('source_commit') != COMMIT or stage.get('all_pass') is not True
            or stage.get('source_file_count') != SOURCE_FILE_COUNT or stage.get('host_check_records') != HOST_RECORD_COUNT
            or stage.get('java8_release_gate') is not True or stage.get('phone_contacted') is not False
            or stage.get('phone_tested') is not False or stage.get('installed_on_phone') is not False):
        raise RuntimeError('Actual v51-build-r2 Pocket4 host stage is not qualified')
    steps = stage.get('steps', [])
    if len(steps) != 1 or steps[0].get('name') != 'full-host-checks' or type(steps[0].get('exit_code')) is not int or steps[0]['exit_code'] != 0:
        raise RuntimeError('Original full host stage receipt incomplete')
    for suffix in ('stdout', 'stderr'):
        path = ROOT / ('full-host-checks.' + suffix)
        regular(path)
        if sha(path) != steps[0][suffix + '_sha256']:
            raise RuntimeError('Original stage log changed')
    full_path = ROOT / 'host-checks/HOST-CHECKS.json'
    full = read_json(full_path)
    if full.get('schema') != 'hepta.host-checks.v3' or full.get('scope') != 'host_only' or full.get('all_pass') is not True:
        raise RuntimeError('Actual complete host gate did not pass')
    checks = full.get('checks', [])
    if len(HOST_NAMES) != HOST_RECORD_COUNT or [row.get('name') for row in checks] != HOST_NAMES:
        raise RuntimeError('Complete v51 host check names/order differ')
    for row in checks:
        if type(row.get('exit_code')) is not int or row['exit_code'] != 0:
            raise RuntimeError('Nonzero or malformed host check result')
        for suffix in ('stdout', 'stderr'):
            path = ROOT / 'host-checks' / (row['name'] + '.' + suffix)
            regular(path)
            if sha(path) != row[suffix + '_sha256']:
                raise RuntimeError('Host log changed: ' + row['name'])
    required_markers = {'python-tools': ['TextOnlyClickHostTest checks=49', '"text_only_click_grammar_cases": 16']}
    for name, values in required_markers.items():
        output = (ROOT / 'host-checks' / (name + '.stdout')).read_text()
        if name not in HOST_NAMES or any(output.count(value) != 1 for value in values):
            raise RuntimeError('Actual nested v51 regression output missing or duplicate')
    nested_markers = {'task-completion/notes-task-phase.stdout': ['PASS 77 notes task phase and recorded two-state contracts'], 'task-completion/notes-task-phase-grammar.stdout': ['PASS 4 production phase grammar cases'], 'task-completion/notes-list-provenance.stdout': ['PASS 33 actual XML topology/source provenance cases'], 'task-completion/notes-recovery.stdout': ['PASS 200 notes recovery and reason feedback assertions'], 'task-completion/notes-recovery-grammar.stdout': ['PASS 4 production phase grammar cases'], 'task-completion/actual-completion.stdout': ['PASS actual_controller_external_window_detour_recovers_only_after_same_item_click'], 'task-completion/notes-task-scope.stdout': ['PASS 490 Notes task scope and current-surface assertions'], 'task-completion/notes-task-scope-grammar.stdout': ['PASS 78 production phase grammar cases'], 'task-completion/calculator-input.stdout': ['PASS 507 Calculator native-button input checks'], 'task-completion/calculator-input-grammar.stdout': ['PASS 36 production phase grammar cases'], 'task-completion/failed-action-observation.stdout': ['PASS 106 one-shot failed-action observation checks; cases=5'], 'task-completion/notes-editor-phase.stdout': ['PASS 206 Notes editor-phase assertions'], 'task-completion/notes-editor-phase-grammar.stdout': ['PASS 36 production phase grammar cases'], 'calculator-completion-pure/calculator-pure.stdout': ['CalculatorCompletionHostTest assertions=230 cases=9'], 'task-completion/completion-status.stdout': ['PASS 98 completion-status assertions; original_v49_partial=true; synthetic_positive_and_controller_io=true; phone_tested=false', 'completion_status_grammar_cases=39'], 'task-completion/completion-status-grammar.stdout': ['PASS 39 production phase grammar cases; phone_tested=false'], 'observation-collection/collection.stdout': ['PASS 4124 actual collection assertions; XML is a separate snapshot; phone_tested=false'], 'task-completion/notes-create-workflow.stdout': ['NotesCreateWorkflowHostTest checks=619'], 'task-completion/notes-workflow-controller.stdout': ['PASS 525 actual workflow controller assertions; cases=12; phone_tested=false; native_io_is_fake=true']}
    nested_checks = {}
    for relative, values in nested_markers.items():
        path = ROOT / 'host-checks' / relative
        regular(path)
        output = path.read_text()
        if any(output.count(value) != 1 for value in values):
            raise RuntimeError('Actual v51 phase/provenance regression output missing or duplicate')
        nested_checks[relative] = {'sha256': sha(path), 'required_markers': values}
    nested_path = ROOT / 'host-checks/task-completion/RESULT.json'
    nested = read_json(nested_path)
    if nested.get('passed') is not True or nested.get('compiler_contract') != 'Java 8 API release':
        raise RuntimeError('Actual v51 nested release8 receipt not passed')
    if [row.get('name') for row in nested.get('stages', [])] != ['compile', 'actual-completion', 'notes-task-phase', 'notes-task-phase-grammar', 'notes-list-provenance', 'notes-recovery', 'notes-recovery-grammar', 'notes-task-scope', 'notes-task-scope-grammar', 'calculator-input', 'calculator-input-grammar', 'failed-action-observation', 'notes-editor-phase', 'notes-editor-phase-grammar', 'completion-status', 'completion-status-grammar', 'notes-create-workflow', 'notes-workflow-controller']:
        raise RuntimeError('Actual v51 nested phase/provenance checks omitted')
    if any(type(row.get('exit_code')) is not int or row['exit_code'] != 0 for row in nested['stages']):
        raise RuntimeError('Actual v51 nested phase/provenance check failed')
    completion_cases_path = ROOT / 'host-checks/task-completion/cases/TEST-RESULTS.json'
    completion_cases = read_json(completion_cases_path)
    if completion_cases.get('all_pass') is not True or completion_cases.get('checks') != 20 or completion_cases.get('cases') != ['owner_literal_contract_and_no_model_chosen_goal', 'launch_is_not_save_and_two_claims_stop', 'ordered_real_list_same_item_reopen', 'any_list_click_cannot_prove_same_item', 'editor_or_reopen_without_list_never_completes', 'preexisting_body_cannot_be_new_entry', 'actual_fixed_receipt_identity_required', 'cross_display_generation_cannot_complete', 'final_window_change_is_recoverable_missing_evidence', 'unknown_readonly_goal_requires_no_write', 'web_prompt_contains_only_its_relevant_method_stage', 'bridge_clears_whitespace_masked_truncated_child', 'actual_controller_first_done_recovers_and_real_note_chain_completes', 'actual_controller_external_window_detour_recovers_only_after_same_item_click', 'actual_controller_draft_only_done_remains_partial_once', 'actual_controller_web_effect_without_results_is_partial', 'actual_controller_unknown_readonly_two_claims_zero_effects', 'actual_controller_cancel_after_rejection_stops_without_effect', 'actual_controller_installed_identity_rechecked_after_close', 'actual_controller_bad_native_close_receipt_cannot_complete']:
        raise RuntimeError('Actual final 20 completion/controller cases missing or changed')
    workflow_path = ROOT / 'host-checks/task-completion/notes-create-workflow/RESULT.json'
    workflow = read_json(workflow_path)
    workflow_cases = ['real_v50_create_body_trigger_does_not_promote_partial',
                      'synthetic_one_back_current_item_stable_foreground',
                      'synthetic_two_back_current_item_stable_owned_display',
                      'synthetic_fresh_unique_list_without_guessed_back',
                      'parent_native_action_authority_and_single_grant',
                      'child_noack_stale_callback_and_service_identity',
                      'current_domain_unique_list_navigation_bound_and_stability',
                      'cancellation_grant_reuse_visible_collision_and_installed_change']
    workflow_fixture = SOURCE / 'tests/notes-create-workflow/fixtures/v50-background-parent-create-partial.json'
    if (workflow.get('all_pass') is not True or type(workflow.get('checks')) is not int
            or workflow['checks'] != 619 or workflow.get('cases') != workflow_cases
            or workflow.get('actual_parent_fixture_sha256') != '6ed45e19b8a6f62746c9b7feb79eeba1293f468d17fdc57d46c9b92259da57b6'
            or sha(workflow_fixture) != workflow['actual_parent_fixture_sha256']
            or workflow.get('all_child_positive_io_synthetic') is not True
            or workflow.get('real_parent_terminal_unchanged') != 'partial'
            or workflow.get('native_runtime_reverified') is not False
            or workflow.get('phone_tested') is not False):
        raise RuntimeError('Actual typed Notes workflow cases, identity or scope differ')
    workflow_stdout = (ROOT / 'host-checks/task-completion/notes-create-workflow.stdout').read_text()
    expected_workflow_stdout = ''.join('PASS ' + name + '\n' for name in workflow_cases) + 'NotesCreateWorkflowHostTest checks=619\n'
    if workflow_stdout != expected_workflow_stdout:
        raise RuntimeError('Actual eight workflow cases and 619 checks differ from receipt')
    controller_path = ROOT / 'host-checks/task-completion/notes-workflow-controller/TEST-RESULTS.json'
    controller = read_json(controller_path)
    controller_cases = ['complete_literal', 'complete_natural', 'no_worker_literal',
                        'bad_receipt_literal', 'foreign_session_task_literal',
                        'missing_session_hash_literal', 'nonzero_exit_literal',
                        'close_identity_changed_literal', 'close_owner_retired_literal',
                        'close_cancel_literal', 'cleanup_unknown_literal',
                        'observation_fails_after_back_literal']
    if (controller.get('schema') != 'hepta.notes-workflow-controller-host.v1'
            or controller.get('passed') is not True or controller.get('cases') != controller_cases
            or type(controller.get('assertions')) is not int or controller['assertions'] != 525
            or controller.get('actual_controller_and_service_code') is not True
            or controller.get('android_and_native_io_are_synthetic') is not True
            or controller.get('phone_tested') is not False
            or controller.get('native_inference') is not False):
        raise RuntimeError('Actual controller workflow 12 cases or scope differ')
    controller_stdout = (ROOT / 'host-checks/task-completion/notes-workflow-controller.stdout').read_text()
    if controller_stdout != 'PASS 525 actual workflow controller assertions; cases=12; phone_tested=false; native_io_is_fake=true\n':
        raise RuntimeError('Actual controller workflow stdout differs from its receipt')
    owner_path = ROOT / 'host-checks/notes-owner-intent/RESULT.json'
    owner = read_json(owner_path)
    if (owner.get('schema') != 'hepta.notes-owner-intent-host.v1' or owner.get('passed') is not True
            or owner.get('compiler_contract') != 'Java 8 API release'
            or owner.get('source_unchanged') is not True
            or type(owner.get('cases')) is not int or owner['cases'] != 56
            or type(owner.get('assertions')) is not int or owner['assertions'] != 746
            or any(owner.get(key) is not False for key in ('phone_operations', 'android_runtime', 'native_inference'))):
        raise RuntimeError('Actual natural OWNER contract gate or scope differs')
    if ([row.get('name') for row in owner.get('stages', [])] != ['compile', 'notes-owner-intent']
            or any(type(row.get('exit_code')) is not int or row['exit_code'] != 0 for row in owner['stages'])):
        raise RuntimeError('Actual natural OWNER release8 stages omitted or failed')
    expected_owner_inputs = {'src/org/trillionnium/hepta/local/NotesOwnerIntent.java',
                             'src/org/trillionnium/hepta/background/FixedIntentTools.java',
                             'tests/notes-owner-intent/NotesOwnerIntentHostTest.java'}
    if not isinstance(owner.get('source_inputs'), dict) or set(owner['source_inputs']) != expected_owner_inputs:
        raise RuntimeError('Actual natural OWNER compiler inputs incomplete')
    for name, pin in owner['source_inputs'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise RuntimeError('Actual natural OWNER source path is not relative')
        path = SOURCE / relative
        regular(path)
        if SOURCE not in path.parents or sha(path) != pin:
            raise RuntimeError('Actual natural OWNER source input changed')
    owner_stdout = (ROOT / 'host-checks/notes-owner-intent/notes-owner-intent.stdout').read_text()
    if owner_stdout != 'NOTES_OWNER_INTENT_CASES=56\nNOTES_OWNER_INTENT_ASSERTIONS=746\nNOTES_OWNER_INTENT_PASSED phone_tested=false android_io=false model_io=false\n':
        raise RuntimeError('Actual natural OWNER stdout disagrees with its receipt')
    owned_policy_stdout = ROOT / 'host-checks/background-owned-task-policy.stdout'
    if owned_policy_stdout.read_text() != 'BackgroundOwnedTaskPolicyHostTest checks=134\n':
        raise RuntimeError('Actual owned-task policy host checks differ')
    pure_path = ROOT / 'host-checks/calculator-completion-pure/RESULT.json'
    pure = read_json(pure_path)
    if pure.get('passed') is not True or pure.get('compiler_contract') != 'Java 8 API release' or pure.get('controller_integrated') is not False or pure.get('causal_gate_implemented') is not False or pure.get('phone_tested') is not False or pure.get('native_inference') is not False:
        raise RuntimeError('Actual Calculator pure release8 evidence or scope differs')
    if [row.get('name') for row in pure.get('stages', [])] != ['compile', 'calculator-pure'] or any(type(row.get('exit_code')) is not int or row['exit_code'] != 0 for row in pure['stages']):
        raise RuntimeError('Actual Calculator pure stages omitted or failed')
    pure_cases_path = ROOT / 'host-checks/calculator-completion-pure/TEST-RESULTS.json'
    pure_cases = read_json(pure_cases_path)
    if pure_cases.get('all_pass') is not True or pure_cases.get('assertions') != 230 or pure_cases.get('passed_cases') != ['owner_arbitrary_integer_ast_and_exact_big_integer', 'owner_complete_consumption_and_authorization', 'bounded_grammar_rejects_unsupported_or_ambiguous_input', 'synthetic_current_pair_observed_without_claiming_calculation', 'history_answer_only_wrong_formula_and_ambiguous_fields_rejected', 'complete_actual_field_identity_required', 'task_owner_display_generation_and_installation_do_not_leak', 'incomplete_wrong_window_and_unobserved_metadata_fail', 'real_archived_current_vs_history_roles_preserved_without_fabricated_hashes'] or pure_cases.get('positive_observations_are_synthetic_host_io') is not True or pure_cases.get('causal_gate_implemented') is not False or pure_cases.get('controller_integrated') is not False or pure_cases.get('phone_tested') is not False or pure_cases.get('native_inference') is not False:
        raise RuntimeError('Actual Calculator contract and current-result cases differ')
    for name, pin in pure['source_inputs'].items():
        path = Path(name)
        regular(path)
        if not path.is_absolute() or ROOT not in path.parents or sha(path) != pin:
            raise RuntimeError('Actual Calculator compiler/fixture input changed')
    for name, pin in nested['source_inputs'].items():
        path = Path(name)
        regular(path)
        if not path.is_absolute() or ROOT not in path.parents or sha(path) != pin:
            raise RuntimeError('Actual v51 nested compiler/fixture input changed')
    collection_path = ROOT / 'host-checks/observation-collection/RESULT.json'
    collection = read_json(collection_path)
    if collection.get('schema') != 'hepta.observation-collection-run.v1' or collection.get('passed') is not True or collection.get('compiler_contract') != 'Java 8 API release':
        raise RuntimeError('Actual bounded collection release8 receipt differs')
    if any(collection.get(key) is not False for key in ('phone_tested', 'native_inference', 'business_completion_provider_added', 'prior_failed_task_upgraded')):
        raise RuntimeError('Collection host evidence misstates its scope')
    if [row.get('name') for row in collection.get('stages', [])] != ['compile', 'collection'] or any(type(row.get('exit_code')) is not int or row['exit_code'] != 0 for row in collection['stages']):
        raise RuntimeError('Actual bounded collection stages omitted or failed')
    expected_fixture_evidence = {'model_bound_frames': [{'original_sha256': 'eaa8c759ee468336814c60859ec2455d63ee7ea14fc916b0ae9bda2155e6b31a', 'observation_id': '01f3295217bb4672b7723ccc9893d324', 'retained_rows': 23, 'retained_text_utf16': 74, 'old_node_and_text_caps_excluded': True, 'actual_visited_count_known': False, 'actual_pending_count_known': False, 'actual_scroll_directions': ['forward', 'down']}, {'original_sha256': '6d7c4c01baa90ac73036aa9736b2d1b5c26529a38dfb3cf6f4502cfd9727fab6', 'observation_id': 'e94e6f6826d2478b8c458a879a3faca4', 'retained_rows': 23, 'retained_text_utf16': 74, 'old_node_and_text_caps_excluded': True, 'actual_visited_count_known': False, 'actual_pending_count_known': False, 'actual_scroll_directions': ['forward', 'down']}], 'independent_xml_nodes': 975, 'xml_is_model_bound_frame': False, 'xml_platform_actions_known': False, 'prior_failed_task_upgraded': False}
    if collection.get('fixture_evidence') != expected_fixture_evidence:
        raise RuntimeError('Actual separate XML and model-bound fixture provenance differs')
    for name, pin in collection['source_inputs'].items():
        path = Path(name)
        regular(path)
        if not path.is_absolute() or ROOT not in path.parents or sha(path) != pin:
            raise RuntimeError('Actual collection compiler/fixture input changed')
    extraction = collection.get('extraction', {})
    if extraction.get('schema') != 'hepta.scope-host-extraction.v1' or extraction.get('phone_operations') is not False or extraction.get('native_inference') is not False:
        raise RuntimeError('Collection exact production extraction scope differs')
    expected_extracted_sources = ['TaskAuthorization.java', 'HeptaAccessibilityService.java', 'LocalTaskSession.java', 'MainActivity.java', 'LocalTaskController.java', 'QualificationScope.java', 'QualificationScopeConfig.java']
    if set(extraction.get('source_files', {})) != set(expected_extracted_sources):
        raise RuntimeError('Collection original production extraction input omitted')
    for name, pin in extraction['source_files'].items():
        path = SOURCE / 'src/org/trillionnium/hepta/local' / name
        regular(path)
        if sha(path) != pin:
            raise RuntimeError('Collection production extraction source differs')
    collection_cases_path = ROOT / 'host-checks/observation-collection/TEST-RESULTS.json'
    collection_cases = read_json(collection_cases_path)
    if collection_cases.get('schema') != 'hepta.observation-collection-host.v1' or collection_cases.get('passed') is not True or collection_cases.get('checks') != 4124 or any(collection_cases.get(key) is not False for key in ('phone_tested', 'native_inference', 'business_goal_verified')):
        raise RuntimeError('Actual bounded collection cases or scope differs')
    projection = collection_cases.get('xml_projection', {})
    if projection.get('old_rows') != 62 or projection.get('new_rows') != 99 or projection.get('same_time_as_model_bound_frames') is not False or projection.get('android_queries_are_fakes') is not True or projection.get('action_lists_observed') is not False:
        raise RuntimeError('Independent XML projection results or scope differs')
    counters = dict(projection.get('new_collection', {}))
    elapsed = counters.pop('elapsed_ms', None)
    if type(elapsed) is not int or elapsed < 0 or counters != {'schema': 'hepta.observation-collection.v1', 'source': 'same_observed_accessibility_traversal', 'visit_limit': 1536, 'node_limit': 128, 'text_utf16_exclusive_limit': 6144, 'visited_nodes': 975, 'retained_nodes': 99, 'retained_text_utf16': 449, 'pending_nodes_at_stop': 0, 'child_slots_omitted_by_traversal_limit': 0, 'nodes_omitted_by_node_limit': 0, 'nodes_omitted_by_text_limit': 0, 'truncation_reasons': [], 'unvisited_descendant_count_known': False, 'grants_action_capability': False}:
        raise RuntimeError('Actual bounded collection counters differ')
    status_cases_path = ROOT / 'host-checks/task-completion/completion-status/grammar-cases.json'
    status_cases = read_json(status_cases_path)
    if not isinstance(status_cases, list) or len(status_cases) != 39:
        raise RuntimeError('Actual current-evidence completion status grammar cases omitted')
    paths = set(SOURCE.glob('*.py'))
    for directory, extensions in (('src', ('*.java',)), ('tests', ('*.java', '*.py')),
                                  ('native', ('*.c', '*.h', '*.inc', '*.py')), ('tools', ('*.py',))):
        for extension in extensions:
            paths.update((SOURCE / directory).rglob(extension))
    paths.update(path for path in (SOURCE / 'tests/completion/fixtures').rglob('*') if path.is_file())
    paths.update(path for path in (SOURCE / 'tests/text-only-click/fixtures').rglob('*') if path.is_file())
    paths.update(path for path in (SOURCE / 'tests/notes-task-phase/fixtures').rglob('*') if path.is_file())
    paths.update(path for path in (SOURCE / 'tests/calculator-completion/fixtures').rglob('*') if path.is_file())
    paths.update(path for path in (SOURCE / 'tests/calculator-input/fixtures').rglob('*') if path.is_file())
    paths.update(path for path in (SOURCE / 'tests/notes-editor-phase/fixtures').rglob('*') if path.is_file())
    paths.update(path for path in (SOURCE / 'tests/completion-status/fixtures').rglob('*') if path.is_file())
    paths.update(path for path in (SOURCE / 'tests/observation-collection/fixtures').rglob('*') if path.is_file())
    paths.update(path for path in (SOURCE / 'tests/notes-create-workflow/fixtures').rglob('*') if path.is_file())
    inputs = [{'path': str(path.relative_to(SOURCE)), 'sha256': sha(path)} for path in sorted(paths)]
    if len(inputs) != HOST_INPUT_COUNT or full.get('source_inputs') != inputs:
        raise RuntimeError('Host gate inputs differ from exact current source')
    return {'stage_result_sha256': sha(stage_path), 'host_checks_sha256': sha(full_path),
            'host_check_records': len(checks), 'host_input_count': len(inputs),
            'java_home': stage['java_home'], 'required_host_stdout_markers': required_markers,
            'pre_commit_host_receipt_sha256': sha(pre_commit_path),
            'source_commit_binding_sha256': sha(binding_path),
            'source_commit_bound_after_exact_host_run': True,
            'notes_create_workflow_receipt_sha256': sha(workflow_path),
            'notes_workflow_controller_receipt_sha256': sha(controller_path),
            'notes_owner_intent_receipt_sha256': sha(owner_path),
            'background_owned_task_policy_stdout_sha256': sha(owned_policy_stdout),
            'nested_phase_source_checks': nested_checks,
            'nested_phase_source_receipt_sha256': sha(nested_path), 'calculator_pure_receipt_sha256': sha(pure_path), 'calculator_pure_cases_sha256': sha(pure_cases_path), 'observation_collection_receipt_sha256': sha(collection_path), 'observation_collection_cases_sha256': sha(collection_cases_path), 'completion_status_grammar_cases_sha256': sha(status_cases_path)}


def existing_signer_and_jdk():
    if sha(SIGNER_PROOF) != SIGNER_PROOF_SHA256:
        raise RuntimeError('Existing public signer proof changed')
    signer = read_json(SIGNER_PROOF)
    if signer.get('public_certificate_sha256') != CERT or signer.get('new_key_created') is not False:
        raise RuntimeError('Existing signer identity differs')
    key = Path(signer['key_path'])
    if not key.is_absolute():
        raise RuntimeError('Existing signing key path must be absolute')
    def key_metadata():
        for path in (key, *key.parents):
            if path.is_symlink():
                raise RuntimeError('Existing signer path is linked')
        info = regular(key)
        return dict(bytes=info.st_size, device=info.st_dev, inode=info.st_ino,
                    mode=oct(stat.S_IMODE(info.st_mode)), mtime_ns=info.st_mtime_ns, uid=info.st_uid)
    if key_metadata() != signer['key_metadata']:
        raise RuntimeError('Existing signer metadata changed')
    if sha(JDK_PROOF) != JDK_PROOF_SHA256:
        raise RuntimeError('Qualified complete JDK receipt changed')
    jdk = read_json(JDK_PROOF)
    home = Path(jdk['java_home'])
    if jdk['status'] != 'ready' or jdk['release8_positive_exit'] != 0 or jdk['release8_negative_exit'] == 0:
        raise RuntimeError('Qualified JDK release 8 evidence missing')
    for name, pin in jdk['member_pins'].items():
        path = home / name
        if path.is_symlink() or path.stat().st_size != pin['bytes'] or sha(path) != pin['sha256']:
            raise RuntimeError('Qualified JDK member changed: ' + name)
    return key, key_metadata, signer['key_metadata'], home


def load_identity():
    spec = importlib.util.spec_from_file_location('actual_v51_build_identity', SOURCE / 'tools/build_identity.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract(identity, report_dir):
    archive = ROOT / 'mac-artifacts.tar.gz'
    info = regular(archive)
    if info.st_size != ARCHIVE_BYTES or sha(archive) != ARCHIVE_SHA256:
        raise RuntimeError('Actual Mac transfer archive differs')
    if OUT.exists() or OUT.is_symlink():
        raise RuntimeError('Fresh absent output directory required')
    blobs = {}
    with tarfile.open(archive, 'r:gz') as packed:
        for member in packed.getmembers():
            name = PurePosixPath(member.name)
            if (member.name not in MEMBERS or member.name in blobs or not member.isfile()
                    or member.size < 0 or member.size > 16 * 1024**2 or name.is_absolute() or '..' in name.parts):
                raise RuntimeError('Unsafe or duplicate compiled archive member')
            stream = packed.extractfile(member)
            if stream is None:
                raise RuntimeError('Compiled archive member has no payload')
            with stream:
                payload = stream.read(member.size + 1)
            if len(payload) != member.size:
                raise RuntimeError('Truncated compiled archive member')
            blobs[member.name] = payload
    if set(blobs) != MEMBERS:
        raise RuntimeError('Exactly six compiled archive members required')
    build = json.loads(blobs['out/mac-build-receipt.json'])
    actual_inputs = identity.source_inputs(SOURCE)
    if (build.get('schema') != 'hepta.local-model.mac-build.v2' or build.get('source_head_from_ci') != COMMIT
            or build.get('source_inputs') != actual_inputs or len(actual_inputs) != COMPILER_INPUT_COUNT
            or build.get('runtime') != 'llama_cpp'):
        raise RuntimeError('Complete compiler input receipt does not bind current source')
    outputs = {'base.apk': 'out/base.apk', 'classes.dex': 'out/dex/classes.dex',
               'libhepta_local_runner.so': 'out/libhepta_local_runner.so'}
    seen = set()
    for row in build['artifacts']:
        name = Path(row['path']).name
        if (name not in outputs or name in seen or row['bytes'] != len(blobs[outputs[name]])
                or row['sha256'] != digest(blobs[outputs[name]])):
            raise RuntimeError('Actual compiled artifact binding differs')
        seen.add(name)
    if seen != set(outputs) or digest(blobs['out/worker-appuid.c']) != build['worker_adapter']['adapted_sha256']:
        raise RuntimeError('Actual generated worker binding differs')
    if digest(blobs['out/native-sha256-disassembly.txt']) != build['sha256_instruction_gate']['disassembly_sha256']:
        raise RuntimeError('Actual disassembly binding differs')
    OUT.mkdir(mode=0o700, exist_ok=False)
    (OUT / 'dex').mkdir(mode=0o700)
    for name, payload in blobs.items():
        put(ROOT / name, payload)
    proof = dict(schema='hepta.mac-artifact-transfer.v1', all_pass=True, source_commit=COMMIT,
                 compiled_source_inputs=len(actual_inputs), archive_bytes=ARCHIVE_BYTES,
                 archive_sha256=ARCHIVE_SHA256, receipt_sha256=digest(blobs['out/mac-build-receipt.json']),
                 phone_contacted=False, signed=False, installed=False,
                 files={name: dict(bytes=len(raw), sha256=digest(raw)) for name, raw in blobs.items()})
    write_json(report_dir / 'MAC-ARTIFACT-TRANSFER.json', proof)
    return build, proof


def compiled_visibility(text):
    stack, tree, namespace = [], None, {}
    uri = 'http://schemas.android.com/apk/res/android'
    for line in text.splitlines():
        match = re.match(r'^\s*N: ([A-Za-z_][A-Za-z0-9_.-]*)=([^\s]+)(?:\s|$)', line)
        if match:
            prefix, value = match.groups()
            if prefix in namespace and namespace[prefix] != value:
                raise RuntimeError('Conflicting compiled namespace')
            namespace[prefix] = value
            continue
        match = re.match(r'^(\s*)E: ([^\s(]+)', line)
        if match:
            indent = len(match.group(1))
            node = {'tag': match.group(2), 'attributes': {}, 'children': []}
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                stack[-1][1]['children'].append(node)
            elif tree is None:
                tree = node
            else:
                raise RuntimeError('Multiple compiled manifest roots')
            stack.append((indent, node))
            continue
        match = re.match(r'^\s*A: ([^\s=()]+)(?:\([^)]*\))?="([^"]*)"(?:\s|$)', line)
        if match and stack:
            name, value = match.groups()
            if name.startswith(uri + ':'):
                name = 'android:' + name[len(uri) + 1:]
            elif name.startswith('android:') and namespace.get('android') != uri:
                raise RuntimeError('Unbound compiled Android namespace')
            if name in stack[-1][1]['attributes']:
                raise RuntimeError('Duplicate compiled manifest attribute')
            stack[-1][1]['attributes'][name] = value
    if tree is None or tree['tag'] != 'manifest':
        raise RuntimeError('Compiled manifest root missing')
    queries = [node for node in tree['children'] if node['tag'] == 'queries']
    if len(queries) != 1:
        raise RuntimeError('Compiled visibility queries missing or duplicate')
    packages, intents = [], []
    for node in queries[0]['children']:
        if node['tag'] == 'package':
            name = node['attributes'].get('android:name')
            if not isinstance(name, str) or not name or node['children']:
                raise RuntimeError('Malformed compiled visibility package')
            packages.append(name)
        elif node['tag'] == 'intent':
            entries = []
            for child in node['children']:
                name = child['attributes'].get('android:name')
                if child['tag'] not in ('action', 'category') or not isinstance(name, str) or not name or child['children']:
                    raise RuntimeError('Malformed compiled visibility intent')
                entries.append((child['tag'], name))
            if not entries or len(entries) != len(set(entries)):
                raise RuntimeError('Empty or duplicate compiled visibility intent')
            intents.append(sorted(entries))
        else:
            raise RuntimeError('Unexpected compiled visibility query')
    if not packages or len(packages) != len(set(packages)) or len(intents) != len({tuple(row) for row in intents}):
        raise RuntimeError('Missing or duplicate compiled visibility entries')
    return {'packages': sorted(packages), 'intents': sorted(intents)}


def require_build_parameters():
    if (not isinstance(COMMIT, str) or re.fullmatch(r'[0-9a-f]{40}', COMMIT) is None
            or COMMIT in ('180a7ab55f5a479c14c202fdbe33a1a4734cecfd', 'c76be7243b70e2142c6c87733c292c6df0d88652', '60cfbd525875cd8e948a97187c836fd965694afc', '45b45a7eb3312ca58e798cbd3b1a8c7b3ea5c0d4', '5a68ef538ca8a9d76591dd6adb089b90b0ad97d4', 'd59542de6e7d67c81a60275571f008c21d17b3dd', 'ebd495d93660f24a3229fe91fec25508c546fad4', '3c4894ad4c7958c94741b0e7e6709380d6ac8ff7')
            or COMMIT == '9ecf87f313ef08cfd2f963671a19eb2358cebbfe'
            or type(ARCHIVE_BYTES) is not int or ARCHIVE_BYTES <= 0
            or not isinstance(ARCHIVE_SHA256, str) or re.fullmatch(r'[0-9a-f]{64}', ARCHIVE_SHA256) is None
            or type(COMPILER_INPUT_COUNT) is not int or COMPILER_INPUT_COUNT <= 0):
        raise RuntimeError('Fill actual v51 COMMIT, Mac ARCHIVE_BYTES, Mac ARCHIVE_SHA256 and COMPILER_INPUT_COUNT before assembly')


def main():
    require_build_parameters()
    report_dir = ROOT / 'assembly-r1'
    report_dir.mkdir(mode=0o700, exist_ok=False)
    result = dict(schema='hepta.isolated-v51-assembly.v1', all_pass=False, source_commit=COMMIT,
                  source_file_count=SOURCE_FILE_COUNT, source_inventory_sha256=INVENTORY_SHA256,
                  mac_archive_sha256=ARCHIVE_SHA256, mac_archive_bytes=ARCHIVE_BYTES,
                  actual_compiler_source_inputs=COMPILER_INPUT_COUNT, phone_contacted=False,
                  installed_on_phone=False, dependencies_downloaded=False, new_key_created=False,
                  started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    key_metadata = None
    expected_key_metadata = None
    before = None
    try:
        script = globals().get('__runner_source__')
        script_bytes = script.encode() if isinstance(script, str) else Path(__file__).read_bytes()
        put(report_dir / 'runner.py', script_bytes)
        result['runner_sha256'] = digest(script_bytes)
        before = source_check()
        write_json(report_dir / 'SOURCE-BEFORE.json', before)
        result.update(qualify_host())
        key, key_metadata, expected_key_metadata, java_home = existing_signer_and_jdk()
        if result['java_home'] != str(java_home):
            raise RuntimeError('Assembly JDK differs from actual qualified host gate')
        result.update(signer_proof_path=str(SIGNER_PROOF), signer_proof_sha256=SIGNER_PROOF_SHA256,
                      complete_jdk_receipt_sha256=JDK_PROOF_SHA256)
        identity = load_identity()
        build, transfer = extract(identity, report_dir)
        result['mac_build_receipt_sha256'] = transfer['receipt_sha256']
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', SOURCE_HEAD_SHA=COMMIT,
                   JAVA_HOME=str(java_home), PATH=str(java_home / 'bin') + ':' + os.environ.get('PATH', ''),
                   HEPTA_BUILD_OUT=str(OUT), HEPTA_SIGNING_KEY_PATH=str(key), HEPTA_REQUIRE_EXISTING_KEY='1',
                   GENIEX_ANDROID_LIB_DIR='/home/alex/razr60-local-model-v150/offline-gpu-integration-20261108/geniex-npu-v0.10.0/package/geniex-bench-android-arm64-v0.10.0/lib',
                   GENIEX_ANDROID_ARCHIVE='/home/alex/razr60-local-model-v150/offline-gpu-integration-20261108/geniex-npu-v0.10.0/geniex-bench-android-arm64-v0.10.0.tar.gz',
                   MOBIMIND_ANDROID_RUNTIME_DIR='/home/alex/razr-local-ai-20261108-dda84ccf/mobiinfer-opencl-build-r4/runtime',
                   UI_VENUS_ANDROID_RUNTIME_DIR='/home/alex/razr-local-ai-20261108-dda84ccf/ui-venus-q4_0-app-native-build-r1/build',
                   APKSIGNER='/usr/bin/apksigner', AAPT2='/usr/bin/aapt2', READELF='/usr/bin/readelf')
        with (report_dir / 'stdout').open('xb') as stdout, (report_dir / 'stderr').open('xb') as stderr:
            completed = subprocess.run([sys.executable, '-B', str(SOURCE / 'assemble_pocket4.py')],
                                       cwd=SOURCE, env=env, stdout=stdout, stderr=stderr, timeout=600)
        result['exit_code'] = completed.returncode
        if completed.returncode:
            raise RuntimeError('Original v51-build-r2 assembler failed; original logs retained')
        source_check()
        static_dir = OUT / 'control-v51-static'
        static_path = static_dir / 'STATIC-ACCEPTANCE.json'
        static = read_json(static_path)
        apk = OUT / 'hepta-local-0.51.0.apk'
        regular(apk)
        signatures = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$',
                                (static_dir / 'apk-signature.txt').read_text(), re.M)
        if [value.lower() for value in signatures] != [CERT]:
            raise RuntimeError('Signed APK certificate differs from original installed signer proof')
        if (static.get('schema') != 'hepta.local-model.static-acceptance.v3'
                or static.get('package') != 'org.trillionnium.hepta.local' or static.get('apk') != str(apk)
                or static.get('apk_sha256') != sha(apk) or static.get('apk_bytes') != apk.stat().st_size
                or static.get('version_code') != VERSION_CODE or static.get('version_name') != VERSION_NAME
                or static.get('permissions') != [] or static.get('new_development_signing_key_created') is not False
                or static.get('installed_on_phone') is not False or static.get('ordinary_app_uid_accelerator_qualified') is not False
                or static.get('abi') != ['arm64-v8a'] or static.get('dsp_arch') != 'v79'
                or static.get('all_packaged_runtime_libraries_bound_to_independent_pins') is not True):
            raise RuntimeError('Signed APK static identity or scope claims differ')
        asset = identity.actual_build_identity(SOURCE, build)
        with zipfile.ZipFile(apk) as packed:
            if len(packed.namelist()) != len(set(packed.namelist())):
                raise RuntimeError('Duplicate signed APK member')
            dex_sha = next(row['sha256'] for row in build['artifacts'] if Path(row['path']).name == 'classes.dex')
            if digest(packed.read('classes.dex')) != dex_sha or packed.read('assets/hepta-build-identity.json') != asset:
                raise RuntimeError('Signed DEX or embedded exact compiler identity differs')
        if static.get('actual_build_identity_sha256') != digest(asset):
            raise RuntimeError('Static embedded build identity hash differs')
        manifest = ET.fromstring((SOURCE / 'AndroidManifest.xml').read_bytes())
        name = '{http://schemas.android.com/apk/res/android}name'
        queries = manifest.find('queries')
        wanted = dict(packages=sorted(row.get(name) for row in queries.findall('package')),
                      intents=sorted(sorted((row.tag, row.get(name)) for row in entry) for entry in queries.findall('intent')))
        actual = compiled_visibility((static_dir / 'apk-manifest.txt').read_text())
        if actual != wanted:
            raise RuntimeError('Signed package visibility differs from exact source manifest')
        put(report_dir / 'ACTUAL-BUILD-IDENTITY-ASSET.json', asset)
        result.update(all_pass=True, apk=str(apk), apk_bytes=apk.stat().st_size, apk_sha256=sha(apk),
                      version_code=VERSION_CODE, version_name=VERSION_NAME, permissions=[], abi=['arm64-v8a'],
                      signer_certificate_sha256=CERT, matches_previously_recorded_signer=True,
                      fresh_phone_signer_inspected=False, static_acceptance_sha256=sha(static_path),
                      actual_build_identity_sha256=digest(asset), actual_compiler_inputs_bound_to_signed_asset=True,
                      manifest_explicit_queries=actual, packaged_library_count=len(static['libraries']),
                      library_pins={row['name']: row['sha256'] for row in static['libraries']},
                      ordinary_app_uid_accelerator_qualified=False, android_runtime_tested=False)
    except Exception as error:
        result.update(all_pass=False, error_type=type(error).__name__, error=str(error))
    finally:
        for name in ('stdout', 'stderr'):
            path = report_dir / name
            if path.exists():
                result[name + '_sha256'] = sha(path)
        try:
            if before is not None:
                after = source_check()
                write_json(report_dir / 'SOURCE-AFTER.json', after)
                if after != before:
                    raise RuntimeError('Complete source inventory changed during assembly')
                result['source_files_unchanged'] = True
                result['empty_source_keys_directory_present'] = (SOURCE / 'keys').is_dir()
            if key_metadata is not None:
                if key_metadata() != expected_key_metadata:
                    raise RuntimeError('Signing changed original key metadata')
                result['existing_key_metadata_unchanged'] = True
        except Exception as error:
            result.update(all_pass=False, final_integrity_error_type=type(error).__name__, final_integrity_error=str(error))
        result['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        write_json(report_dir / 'RESULT.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
