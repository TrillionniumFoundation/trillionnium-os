"""Actual host evidence gates; the retained positive came from production Java.

No device or model is contacted.  Synthetic mutations must only revoke trust.
"""
from helpers import *


class ScopeContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_strict_json_and_numeric_types(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":"\\u0000"}', b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                qs.strict(raw)
        self.assertTrue(qs.equal({"x": [1, 0.0]}, {"x": [1.0, 0]}))
        self.assertFalse(qs.equal({"x": [1]}, {"x": [True]}))

    def test_f32_policy_both_axes_and_no_greedy_or_rounded_substitution(self):
        for axis in ('npu', 'gpu'):
            q = binding_fixture(self.root / axis, axis)
            self.assertEqual(q['candidate']['compute'], axis)
            self.assertTrue(qs.sampler_valid(q['sampler_requested']))
        for key, wrong in (('temperature', .7), ('top_p', .8), ('min_p', .05), ('top_k', True), ('temperature', 0)):
            values = qs.expected_sampler(); values[key] = wrong
            with self.subTest(key=key): self.assertFalse(qs.sampler_valid(values))
        values = qs.expected_sampler(); del values['min_p']; self.assertFalse(qs.sampler_valid(values))

    def test_role_apk_set_is_sorted_paired_split_mapping(self):
        rows = [dict(key='split:z', sha256='a' * 64), dict(key='base', sha256='b' * 64)]
        expected = hashlib.sha256(('base\t' + 'b' * 64 + '\nsplit:z\t' + 'a' * 64 + '\n').encode()).hexdigest()
        self.assertEqual(qs.apk_set_sha(rows), expected)
        self.assertEqual(qs.apk_set_sha(rows[::-1]), expected)
        for bad in ([rows[0]], [rows[1], rows[1]], [dict(key='../base', sha256='b' * 64)]):
            with self.subTest(bad=bad), self.assertRaises(ValueError): qs.apk_set_sha(bad)

    def test_scope_closed_roles_and_explicit_home(self):
        q = binding_fixture(self.root / 'binding'); scope = q['scope']
        self.assertEqual(qs.validate_scope(q['raw_files']['qualification-scope.json']), scope)
        for key, value in (('enabled', False), ('extra', 1), ('settings_uid', True),
                           ('search_package', 'com.motorola.cn.searchintelligence'),
                           ('launcher_component', 'com.motorola.launcher3/.Main')):
            mutated = copy.deepcopy(scope); mutated[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): qs.validate_scope(qs.encoded(mutated))

    def test_raw_binding_files_and_identity_tamper_fail_closed(self):
        for name in ('qualification-scope.json', 'build-identity.json', 'runtime-config.json',
                     'mac-build-receipt.json', 'static-acceptance.json', 'role-identities.json',
                     'source-integration-manifest.json', 'observations/search.json'):
            q = binding_fixture(self.root / str(len(list(self.root.iterdir()))))
            path = Path(q['binding_path']); (path.parent / name).write_bytes(q['raw_files'][name] + b' ')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'binding file changed'):
                qs.load_binding(path, q['binding_sha256'])

    def test_observation_package_metadata_and_window_must_be_known(self):
        good = observation(qs.ROLES['settings'])
        self.assertEqual(qs.validate_original_observation(qs.encoded(good), good['package'])['window_id'], 7)
        changes = [('package', 'com.android.contacts'), ('window_id', 8)]
        for key, value in changes:
            item = copy.deepcopy(good); item[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                qs.validate_original_observation(qs.encoded(item), qs.ROLES['settings'])
        for key, value in (('metadata_status', 'unknown'), ('type', 2), ('display_id', True), ('window_id', -1)):
            item = copy.deepcopy(good); item['window'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                qs.validate_original_observation(qs.encoded(item), qs.ROLES['settings'])

    def test_production_java_positive_accepts_initial_empty_dispatch_proof(self):
        q, task_id, instruction = production_scope_fixture(self.root)
        before = qs.strict(qs.read(self.root / 'task/scope-binding.json'))
        self.assertEqual(before['last_check'], {})
        review = qs.task_evidence(self.root, q, task_id, instruction)
        self.assertTrue(review['verified']); self.assertFalse(review['semantic_pass_granted'])
        self.assertIn('step-01-action.json', review['file_sha256'])

    def test_production_scope_chain_rejects_changed_ownership_and_terminal(self):
        cases = [('owner.json', 'instruction_utf8_sha256', '0' * 64),
                 ('owner.json', 'expected_scope_sha256', None),
                 ('result.json', 'actual_scope_sha256', None),
                 ('result.json', 'task_id', '1' * 32),
                 ('result.json', 'final_observation_id', '2' * 32)]
        for index, (name, field, value) in enumerate(cases):
            at = self.root / str(index); q, task_id, instruction = production_scope_fixture(at)
            path = at / 'task' / name; obj = qs.strict(path.read_bytes()); obj[field] = value; path.write_bytes(qs.encoded(obj))
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                qs.task_evidence(at, q, task_id, instruction)

    def test_dispatch_rejects_retired_scope_foreign_node_unknown_root_and_target(self):
        cases = [('callback_lease_current', False), ('callback_cancelled', True), ('scope_refused', True)]
        for index, (field, value) in enumerate(cases):
            at = self.root / ('callback' + str(index)); q, task_id, instruction = production_scope_fixture(at)
            path = at / 'task/step-01-action.json'; obj = qs.strict(path.read_bytes()); obj['qualification_scope'][field] = value
            path.write_bytes(qs.encoded(obj))
            with self.subTest(field=field), self.assertRaises(ValueError): qs.task_evidence(at, q, task_id, instruction)
        for index, (field, value) in enumerate((('fresh_root_package', 'com.android.contacts'),
                ('fresh_root_active', False), ('fresh_root_visible', False), ('fresh_root_display_id', 1),
                ('fresh_root_window_id', None), ('allowed', False), ('target_package', 'com.android.dialer'))):
            at = self.root / ('root' + str(index)); q, task_id, instruction = production_scope_fixture(at)
            path = at / 'task/step-01-action.json'; obj = qs.strict(path.read_bytes())
            obj['qualification_scope']['last_check'][field] = value; path.write_bytes(qs.encoded(obj))
            with self.subTest(field=field), self.assertRaises(ValueError): qs.task_evidence(at, q, task_id, instruction)
        at = self.root / 'node'; q, task_id, instruction = production_scope_fixture(at)
        path = at / 'task/step-01-action.json'; obj = qs.strict(path.read_bytes())
        obj['action']['action'] = 'click'
        check = obj['qualification_scope']['last_check']; check['action'] = 'click'; check['node_required'] = True
        check['fresh_node_package'] = 'com.android.mms'; check['fresh_node_window_id'] = check['fresh_root_window_id']
        path.write_bytes(qs.encoded(obj))
        with self.assertRaisesRegex(ValueError, 'fresh node'): qs.task_evidence(at, q, task_id, instruction)

    def test_exact_observation_not_cached_scope_summary(self):
        q, task_id, instruction = production_scope_fixture(self.root)
        path = self.root / 'task/step-01-after.json'; obj = qs.strict(path.read_bytes()); obj['package'] = 'com.android.contacts'
        path.write_bytes(qs.encoded(obj))
        with self.assertRaisesRegex(ValueError, 'exact recorded frame'): qs.task_evidence(self.root, q, task_id, instruction)
        scope_path = self.root / ('task/scope-observation-' + obj['observation_id'] + '.json')
        bound = qs.strict(scope_path.read_bytes()); bound['observation'] = obj; scope_path.write_bytes(qs.encoded(bound))
        with self.assertRaisesRegex(ValueError, 'outside scope'): qs.task_evidence(self.root, q, task_id, instruction)

    def test_stale_no_dispatch_can_retain_prior_scope_check_without_inventing_action(self):
        q, task_id, instruction = production_scope_fixture(self.root)
        path = self.root / 'task/step-01-action.json'; obj = qs.strict(path.read_bytes())
        obj.update(stale=True, accepted=False, dispatched=False)
        obj['qualification_scope']['last_check'] = {}; path.write_bytes(qs.encoded(obj))
        self.assertTrue(qs.task_evidence(self.root, q, task_id, instruction)['verified'])
        # Only the supplemental scope gate passed. Existing native/done/goal gates
        # remain required; this fabricated stale terminal is never a task PASS.

    def test_final_scope_session_cannot_use_pending_null_or_old_intent(self):
        q = basic_context(); pending = dict(expected_scope_sha256=q['scope_sha256'], actual_scope_sha256=None, status='running', running=True)
        qs.session_binding(pending, q, allow_pending=True)
        with self.assertRaises(ValueError): qs.session_binding(pending, q)
        with self.assertRaises(ValueError): qs.session_binding({**pending, 'expected_scope_sha256': '1' * 64}, q, True)
        qs.session_binding({**pending, 'actual_scope_sha256': q['scope_sha256']}, q)

    def test_sampler_checks_original_native_files_and_cannot_upgrade_goal(self):
        run_id = 'a' * 32; target = self.root / 'runs' / run_id; target.mkdir(parents=True)
        path = target / 'native-result.json'; path.write_bytes(qs.encoded(dict(sampler_requested=qs.expected_sampler())))
        collection = dict(associated_runs=[dict(run_id=run_id)])
        evidence = qs.sampled_native(self.root, collection); self.assertEqual(evidence[0]['native_result_sha256'], qs.sha(path.read_bytes()))
        path.write_bytes(qs.encoded(dict(sampler_requested=dict(temperature=0))))
        with self.assertRaises(ValueError): qs.sampled_native(self.root, collection)
        for verdict in ('fail', 'unknown', 'unverified', 'not_run'):
            self.assertEqual(qs.downgrade(verdict, True), verdict)
        self.assertEqual(qs.downgrade('pass', False), 'unverified')

    def test_scope_transport_has_single_explicit_sha_and_no_auto_on_ordinary(self):
        q = basic_context(); nonce = 'a' * 64
        argv = qs.debug_intent(nonce, q)
        self.assertEqual(argv.count('expected_scope_sha256'), 1); self.assertEqual(argv.count(nonce), 1)
        ordinary = qs.ordinary_intent(qs.ORDINARY_INSTRUCTION, q)
        self.assertEqual(ordinary[ordinary.index('expected_scope_sha256') + 1], q['scope_sha256'])
        for forbidden in ('auto_task', 'auto_run', 'test_nonce'): self.assertNotIn(forbidden, ordinary)
        with self.assertRaises(ValueError): qs.ordinary_intent('改成别的任务', q)


if __name__ == '__main__': unittest.main()
