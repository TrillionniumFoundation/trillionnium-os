"""Retained R2 probe counterexamples, adapted only to v32 requested F32 sampler."""
from helpers import *
ROOT='/data/user/0/'+m.PACKAGE

def probe_fixture(axis='npu'):
    rid = 'a' * 32
    parent = dict(pid=11001, uid=m.UID)
    raw = '计算器用于进行日常数学运算。'.encode()
    formatted = b'SYNTHETIC_RENDERED_PROMPT_ONLY'
    ids = b''.join(struct.pack('<I', i) for i in (1, 22, 333, 4444))
    inputs = dict(prompt=m.sha(m.PROMPT.encode()), system=m.sha(m.SYSTEM.encode()), grammar=None, image=None)
    budget = dict(method='llama_tokenize_exact_same_input_ids', formatted_utf8_bytes=len(formatted),
                  model_contract_sha256=m.MODEL_SHA, tokenizer_source_commit=m.LLAMA, checked=True, admitted=True,
                  is_exact_token_count=True, add_special=True, parse_special=True, input_ids_passed_directly=True,
                  prompt_tokens_exact=4, input_ids_count=4, input_ids_sha256=m.sha(ids), context_tokens=8192,
                  generation_tokens=64, reserved_tokens=256, total_context_tokens=324)
    app = dict(schema='hepta.local-model.receipt.v2', run_id=rid, package_name=m.PACKAGE, app_uid=m.UID,
               app_pid=parent['pid'], expected_parent_pid=parent['pid'], model_profile=m.PROFILE,
               compute_requested=axis, context_tokens=8192, runtime='llama_cpp', mode='llm',
               model_sha256_verified=m.MODEL_SHA, model_path=ROOT + '/files/model/' + m.MODEL_FILE,
               exit_code=0)
    for key in ('parent_death_guard_requested', 'process_started', 'process_exit_observed', 'inference_completed',
                'native_result_binding_valid', 'runtime_device_selection_valid', 'native_context_budget_valid', 'grammar_binding_valid'):
        app[key] = True
    for key in ('timeout_observed', 'fallback_allowed', 'image_sent_to_model', 'grammar_constraint_enabled', 'automatic_retry'):
        app[key] = False
    native = dict(schema='hepta.geniex-once.result.v1', request_id=rid, runtime='llama_cpp', mode='llm',
                  compute_requested=axis, device_resolved='HTP0' if axis == 'npu' else 'GPUOpenCL', device_warning=None,
                  n_ctx_create=8192, max_tokens=64, n_gpu_layers_create=999, sdk_source_commit=m.SDK, sdk_version='0.10.0',
                  automatic_retry=False, generate_attempt_count=1, model_profile=m.PROFILE,
                  model_sha256_verified=m.MODEL_SHA, model_architecture='qwen35', model_bytes_verified=m.MODEL_BYTES,
                  model_metadata_unchanged=True, chat_template_enable_thinking=False, automatic_cpu_fallback=False,
                  model_path=app['model_path'], generation_complete=True, raw_text_present=True,
                  raw_text_truncated=False, raw_text_utf8=True, raw_text_bytes=len(raw), raw_text_sha256=m.sha(raw),
                  input_metadata_unchanged=True, worker_exit_status_planned=0, error=None, stop_reason='eos',
                  input_sha256=inputs, formatted_prompt_sha256=m.sha(formatted), prompt_budget=budget,
                  profile=dict(prompt_tokens=4, generated_tokens=12, ttft_us=1000000, decode_tokens_per_second=10),
                  pid=11002, sampler_requested=qs.expected_sampler(),
                  sdk_rc=dict(resolve=0, set_log_level=0, init=0, create=0, template=0, generate=0, destroy=0, deinit=0),
                  prompt_evidence=dict(schema='hepta.private-prompt-evidence.v1', complete=True,
                       formatted_file=ROOT + '/files/runs/' + rid + '/formatted-prompt.txt',
                       input_ids_file=ROOT + '/files/runs/' + rid + '/formatted-input-ids.le32',
                       metadata_file=ROOT + '/files/runs/' + rid + '/prompt-evidence.json'))
    evidence = dict(schema='hepta.private-prompt-evidence.v1', request_id=rid, model_profile=m.PROFILE,
                    model_sha256=m.MODEL_SHA, sdk_source_commit=m.SDK, llama_source_commit=m.LLAMA,
                    formatted_prompt_sha256=m.sha(formatted), formatted_prompt_bytes=len(formatted),
                    input_ids_count=4, input_ids_bytes=len(ids), input_ids_encoding='uint32-little-endian',
                    input_ids_sha256=m.sha(ids), source_input_sha256=inputs)
    for key in ('input_ids_will_be_passed_directly', 'add_special', 'parse_special', 'use_jinja', 'add_generation_prompt'):
        evidence[key] = True
    for key in ('chat_template_override', 'enable_thinking', 'native_tools_argument', 'action_authorized'):
        evidence[key] = False
    # Deliberately 7/99, not 33/33: positive offload is never full coverage proof.
    log = ('HEPTA_APPUID_BOOTSTRAP uid=10481 euid=10481 pid=11002 plugin=llama_cpp register_rc=0 runtime=/data/app/SYNTHETIC/lib/arm64\n'
           'HEPTA_PARENT_GUARD armed expected=11001 observed=11001 signal=SIGKILL\n'
           'load_tensors: offloaded 7/99 layers to GPU\n'
           'load_tensors: ' + ('HTP0' if axis == 'npu' else 'OpenCL') + ' model buffer size = 100.0 MiB\n')
    app.update(status='completed', error=None, cancel_requested=False,
               raw_text_sha256_read=m.sha(raw), raw_text_file=ROOT + '/files/runs/' + rid + '/raw-text.txt',
               native_receipt=copy.deepcopy(native))
    files = {'app-receipt.json': m.encoded(app), 'native-result.json': m.encoded(native),
             'prompt.txt': m.PROMPT.encode(), 'system.txt': m.SYSTEM.encode(), 'formatted-prompt.txt': formatted,
             'formatted-input-ids.le32': ids, 'prompt-evidence.json': m.encoded(evidence),
             'raw-text.txt': raw, 'stdout.log': b'', 'stderr.log': log.encode()}
    return files, rid, parent

class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        m.UID=10481;m.Q=basic_context();m.CONFIG_SHAS={'npu':m.Q['runtime_config_sha256']}
    def test_probe_rejects_contradictory_original_sdk_lifecycle_with_matching_app(self):
        for field in ('resolve', 'set_log_level', 'init', 'create', 'template', 'generate', 'destroy', 'deinit'):
            for wrong in (1, -1, None, False, '0'):
                files, rid, parent = probe_fixture()
                native = m.strict(files['native-result.json']); native['sdk_rc'][field] = wrong
                app = m.strict(files['app-receipt.json']); app['native_receipt'] = copy.deepcopy(native)
                files['native-result.json'] = m.encoded(native); files['app-receipt.json'] = m.encoded(app)
                with self.subTest(field=field, wrong=wrong), self.assertRaisesRegex(RuntimeError, 'SDK lifecycle'):
                    m.validate_probe_bytes(files, 'npu', rid, parent, ac)
        for missing in (True, False):
            files, rid, parent = probe_fixture()
            native = m.strict(files['native-result.json'])
            if missing: del native['sdk_rc']
            else: native['sdk_rc']['unknown_call'] = 0
            app = m.strict(files['app-receipt.json']); app['native_receipt'] = copy.deepcopy(native)
            files['native-result.json'] = m.encoded(native); files['app-receipt.json'] = m.encoded(app)
            with self.subTest(missing=missing), self.assertRaisesRegex(RuntimeError, 'SDK lifecycle'):
                m.validate_probe_bytes(files, 'npu', rid, parent, ac)
    def test_probe_positive_npu_and_gpu_use_actual_acceptance(self):
            for axis in ('npu', 'gpu'):
                with self.subTest(axis=axis):
                    files, rid, parent = probe_fixture(axis)
                    result = m.validate_probe_bytes(files, axis, rid, parent, ac)
                    self.assertTrue(result['native_qualified'])
                    self.assertFalse(result['full_operator_coverage_proven'])
                    self.assertEqual(result['accelerator_evidence']['offloaded_layers_observed'], 7)
                    self.assertEqual(result['ground_truth'], 'not_assessed')
                    self.assertFalse(result['controller_grammar_exercised'])

    def test_probe_rejects_wrong_app_lifetime_and_controller_claim(self):
            for key, wrong in (('app_uid', 2000), ('app_pid', 11003), ('expected_parent_pid', 11003),
                               ('process_exit_observed', False), ('exit_code', 1), ('inference_completed', False),
                               ('context_tokens', 4096), ('compute_requested', 'gpu'), ('grammar_constraint_enabled', True),
                               ('native_context_budget_valid', False), ('model_sha256_verified', '0' * 64)):
                with self.subTest(key=key):
                    files, rid, parent = probe_fixture()
                    value = m.strict(files['app-receipt.json']); value[key] = wrong
                    files['app-receipt.json'] = m.encoded(value)
                    with self.assertRaises(RuntimeError):
                        m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_probe_requires_real_app_completed_uncancelled_error_null(self):
            for field, value in (('status', 'native_failed'), ('cancel_requested', True),
                                 ('cancel_requested', 0), ('error', 'fixture_error')):
                files, rid, parent = probe_fixture()
                app = m.strict(files['app-receipt.json']); app[field] = value
                files['app-receipt.json'] = m.encoded(app)
                with self.subTest(field=field, value=value), self.assertRaisesRegex(RuntimeError, 'App completion'):
                    m.validate_probe_bytes(files, 'npu', rid, parent, ac)
            for field in ('status', 'error', 'cancel_requested'):
                files, rid, parent = probe_fixture()
                app = m.strict(files['app-receipt.json']); del app[field]
                files['app-receipt.json'] = m.encoded(app)
                with self.subTest(missing=field), self.assertRaisesRegex(RuntimeError, 'App completion'):
                    m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_probe_app_raw_identity_is_same_run_and_same_bytes(self):
            for field, value in (('raw_text_sha256_read', '0' * 64),
                                 ('raw_text_file', ROOT + '/files/runs/' + 'b' * 32 + '/raw-text.txt'),
                                 ('raw_text_file', ROOT + '/files/runs/' + 'a' * 32 + '/../raw-text.txt')):
                files, rid, parent = probe_fixture()
                app = m.strict(files['app-receipt.json']); app[field] = value
                files['app-receipt.json'] = m.encoded(app)
                with self.subTest(field=field, value=value), self.assertRaisesRegex(RuntimeError, 'App raw text identity'):
                    m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_probe_embedded_native_cannot_disagree_with_original(self):
            for field, value in (('request_id', 'b' * 32), ('generate_attempt_count', True),
                                 ('error', 'embedded_error'), ('generation_complete', False)):
                files, rid, parent = probe_fixture()
                app = m.strict(files['app-receipt.json']); app['native_receipt'][field] = value
                files['app-receipt.json'] = m.encoded(app)
                with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'embedded native receipt'):
                    m.validate_probe_bytes(files, 'npu', rid, parent, ac)
            files, rid, parent = probe_fixture()
            app = m.strict(files['app-receipt.json']); del app['native_receipt']
            files['app-receipt.json'] = m.encoded(app)
            with self.assertRaisesRegex(RuntimeError, 'embedded native receipt'):
                m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_android_numeric_reencoding_allows_one_float_without_bool_coercion(self):
            files, rid, parent = probe_fixture()
            app = m.strict(files['app-receipt.json'])
            app['native_receipt']['generate_attempt_count'] = 1.0
            app['native_receipt']['sampler_requested']['top_k'] = 40.0
            files['app-receipt.json'] = m.encoded(app)
            self.assertTrue(m.validate_probe_bytes(files, 'npu', rid, parent, ac)['native_qualified'])
            self.assertFalse(m.same_json({'x': [1]}, {'x': [True]}))
            self.assertFalse(m.same_json({'x': None}, {}))
            self.assertFalse(m.same_json([1], [1, 2]))
            self.assertFalse(m.same_json({'x': 1}, {'x': '1'}))

    def test_exact_sdk_version_spellings_require_same_pinned_commit(self):
            for version, valid in (('0.10.0', True), ('v0.10.0', True), ('0.10', False),
                                   ('v0.10.0-custom', False), ('0.11.0', False)):
                files, rid, parent = probe_fixture()
                native = m.strict(files['native-result.json']); native['sdk_version'] = version
                app = m.strict(files['app-receipt.json']); app['native_receipt'] = copy.deepcopy(native)
                files['native-result.json'] = m.encoded(native); files['app-receipt.json'] = m.encoded(app)
                with self.subTest(version=version):
                    if valid:
                        self.assertTrue(m.validate_probe_bytes(files, 'npu', rid, parent, ac)['native_qualified'])
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'native request/backend/config'):
                            m.validate_probe_bytes(files, 'npu', rid, parent, ac)
            files, rid, parent = probe_fixture()
            native = m.strict(files['native-result.json']); native['sdk_source_commit'] = '0' * 40
            files['native-result.json'] = m.encoded(native)
            with self.assertRaisesRegex(RuntimeError, 'native request/backend/config'):
                m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_checked_probe_recomputes_cached_app_from_retained_original(self):
            files, rid, parent = probe_fixture()
            args = SimpleNamespace(axis='npu', package_sha256='b' * 64, prepared_result_sha256='c' * 64)
            path = self.root / 'RESULT.json'
            (self.root / 'run').mkdir()
            for name, raw in files.items():
                (self.root / 'run' / name).write_bytes(raw)
            value = m.stage_result(args, 'probe', status='complete',
                prepared_result_sha256=args.prepared_result_sha256, cleanup_known=True,
                external_state_unchanged=True, native_qualified=True, run_id=rid, parent=parent,
                app_receipt=m.strict(files['app-receipt.json']), raw_text_sha256=m.sha(files['raw-text.txt']),
                artifacts={name: dict(bytes=len(raw), sha256=m.sha(raw)) for name, raw in files.items()})
            path.write_bytes(m.encoded(value))
            with patch.object(m, 'prepared', return_value=(None, None, (None, None, None, None, ac, None, None))):
                self.assertTrue(m.checked_probe(args, path, m.sha(path.read_bytes()))[1]['native_qualified'])
                value['app_receipt']['cancel_requested'] = True
                path.write_bytes(m.encoded(value))
                with self.assertRaisesRegex(RuntimeError, 'cached App receipt'):
                    m.checked_probe(args, path, m.sha(path.read_bytes()))

    def test_probe_rejects_native_backend_budget_completion_and_raw_mismatch(self):
            for key, wrong in (('device_resolved', 'CPU'), ('device_warning', 'fallback'), ('n_gpu_layers_create', 0),
                               ('n_ctx_create', 4096), ('automatic_cpu_fallback', True), ('generate_attempt_count', 0),
                               ('generation_complete', False), ('raw_text_truncated', True), ('raw_text_sha256', '0' * 64),
                               ('model_architecture', 'lfm2moe'), ('max_tokens', 256), ('error', 'native load failed'),
                               ('stop_reason', 'length'), ('input_metadata_unchanged', False)):
                with self.subTest(key=key):
                    files, rid, parent = probe_fixture()
                    value = m.strict(files['native-result.json']); value[key] = wrong
                    files['native-result.json'] = m.encoded(value)
                    with self.assertRaises(RuntimeError):
                        m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_probe_actual_ids_and_rendered_bytes_not_cached_count(self):
            for name in ('formatted-prompt.txt', 'formatted-input-ids.le32', 'prompt.txt', 'system.txt', 'raw-text.txt'):
                with self.subTest(name=name):
                    files, rid, parent = probe_fixture(); files[name] += b'X'
                    with self.assertRaises(RuntimeError):
                        m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_probe_exact_overflow_and_sdk_count_mismatch_fail_actual_native_verifier(self):
            for mutation in ('overflow', 'sdk-count', 'admitted-false', 'ids-not-direct'):
                files, rid, parent = probe_fixture(); value = m.strict(files['native-result.json'])
                if mutation == 'overflow':
                    value['prompt_budget'].update(prompt_tokens_exact=8000, input_ids_count=8000, total_context_tokens=8320)
                    value['profile']['prompt_tokens'] = 8000
                elif mutation == 'sdk-count':
                    value['profile']['prompt_tokens'] = 3
                elif mutation == 'admitted-false':
                    value['prompt_budget']['admitted'] = False
                else:
                    value['prompt_budget']['input_ids_passed_directly'] = False
                files['native-result.json'] = m.encoded(value)
                with self.subTest(mutation=mutation), self.assertRaisesRegex(RuntimeError, 'exact admission'):
                    m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_probe_parent_uid_log_and_positive_tensor_evidence_required(self):
            for old, new in ((b'uid=10481', b'uid=2000'), (b'observed=11001', b'observed=11003'),
                             (b'7/99', b'0/99'), (b'100.0 MiB', b'0.0 MiB'),
                             (b'load_tensors: offloaded', b'quoted diagnostic: offloaded')):
                files, rid, parent = probe_fixture(); files['stderr.log'] = files['stderr.log'].replace(old, new)
                with self.subTest(old=old), self.assertRaises(RuntimeError):
                    m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_probe_source_evidence_grammar_and_request_must_match(self):
            for key, wrong in (('request_id', 'b' * 32), ('input_ids_will_be_passed_directly', False),
                               ('input_ids_sha256', '0' * 64), ('enable_thinking', True), ('model_profile', 'bonsai2-9b-q2_0')):
                files, rid, parent = probe_fixture(); evidence = m.strict(files['prompt-evidence.json']); evidence[key] = wrong
                files['prompt-evidence.json'] = m.encoded(evidence)
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    m.validate_probe_bytes(files, 'npu', rid, parent, ac)

    def test_readable_and_ground_truth_are_separate(self):
            args = SimpleNamespace(axis='npu', package_sha256='b' * 64, prepared_result_sha256='c' * 64,
                                   probe_result=Path('/synthetic/probe/RESULT.json'), probe_result_sha256='d' * 64,
                                   raw_text_sha256='e' * 64, text_integrity='readable', ground_truth='fail', output=self.root / 'review')
            with patch.object(m, 'checked_probe', return_value=({}, {'raw_text_sha256': 'e' * 64})):
                self.assertEqual(m.do_probe_review(args), 0)
            v = json.loads((args.output / 'RESULT.json').read_bytes())
            self.assertEqual(v['ground_truth'], 'fail')
            self.assertFalse(v['controller_grammar_exercised'])
            args.text_integrity = 'garbled'; args.output = self.root / 'garbled'
            with patch.object(m, 'checked_probe', return_value=({}, {'raw_text_sha256': 'e' * 64})):
                self.assertEqual(m.do_probe_review(args), 3)
            self.assertEqual(json.loads((args.output / 'RESULT.json').read_bytes())['status'], 'blocked')
