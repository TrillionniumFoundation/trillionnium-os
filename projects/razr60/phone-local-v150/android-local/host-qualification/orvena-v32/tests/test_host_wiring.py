"""Actual host prepare/freeze/validate and pin failure paths; no phone I/O."""
from helpers import *

sys.path.insert(0, str(CANDIDATE / 'core'))
core = module(CANDIDATE / 'core/core_phone_suite.py', 'scoped_core_tested')
sys.path.insert(0, str(CANDIDATE / 'offline'))
offline = module(CANDIDATE / 'offline/phone_offline_suite.py', 'scoped_offline_tested')


class HostWiringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.q = binding_fixture(self.root / 'binding')

    def test_exact_original_nine_goals_540_seconds_and_oracle_bytes(self):
        reference = qs.strict(qs.read(CANDIDATE / 'reference/core-cases.json'))
        if isinstance(reference, dict): reference = reference['cases']
        self.assertEqual(core.templates(), reference); self.assertEqual(len(reference), 9)
        self.assertTrue(all(c['timeout_seconds'] == 540 for c in reference))
        expected = '49f1ce7e51815ddab990bbdaf49dad7a2497cb2bb539a49690f6be75e60df24a'
        self.assertEqual(qs.sha(qs.read(CANDIDATE / 'core/core_assertions.py')), expected)
        self.assertEqual(qs.sha(qs.read(CANDIDATE / 'ordinary/core_assertions.py')), expected)
        changed = copy.deepcopy(reference[0]); changed['instruction'] += '放松条件'
        plan = self.freeze(); plan['cases'][0] = changed
        with self.assertRaisesRegex(ValueError, 'case differs'): core.validate_plan(plan, ps, True)

    def freeze(self):
        candidate = self.root / 'candidate.json'; candidate.write_bytes(qs.encoded(self.q['candidate']))
        target = self.root / 'plan.json'
        result = subprocess.run([sys.executable, '-B', str(CANDIDATE / 'core/core_phone_suite.py'), 'freeze',
            '--drivers', str(CANDIDATE / 'drivers'), '--candidate', str(candidate), '--suite-id', 'synthetic-nine',
            '--output', str(target)], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertIn(b'"phone_contacted": false', result.stdout)
        return qs.strict(target.read_bytes())

    def test_real_core_freeze_validate_and_scope_pair_required(self):
        plan = self.freeze()
        words = [sys.executable, '-B', str(CANDIDATE / 'core/core_phone_suite.py'), 'validate', str(self.root / 'plan.json')]
        result = subprocess.run(words + ['--qualification-binding', self.q['binding_path'],
            '--qualification-binding-sha256', self.q['binding_sha256']], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertIn(b'"planned_attempts": 9', result.stdout)
        missing = subprocess.run(words, capture_output=True, timeout=20)
        self.assertNotEqual(missing.returncode, 0); self.assertIn(b'qualification-binding', missing.stderr)
        self.assertEqual(len(plan['drivers']['files']), 6)

    def test_offline_exact_new_driver_pin_and_rejection_before_network(self):
        self.freeze(); out = self.root / 'offline'; out.mkdir()
        args = SimpleNamespace(plan=self.root / 'plan.json', expected_plan_sha256=qs.sha((self.root / 'plan.json').read_bytes()),
            serial=self.q['device_target']['serial'],
            core=CANDIDATE / 'core/core_phone_suite.py', qualification_binding=Path(self.q['binding_path']),
            qualification_binding_sha256=self.q['binding_sha256'], suite_deadline_seconds=6000)
        self.assertEqual(offline.CORE_SHA, qs.sha(args.core.read_bytes()))
        with patch.object(socket, 'create_connection', side_effect=AssertionError('offline validation must not connect')):
            runner, plan = offline.frozen_suite(args, out)
            self.assertEqual(len(plan['cases']), 9); self.assertTrue(runner.is_file())
            bad = self.root / 'changed-core'; bad.mkdir()
            (bad / 'core_phone_suite.py').write_bytes(args.core.read_bytes() + b'\n')
            shutil.copyfile(args.core.with_name('core_assertions.py'), bad / 'core_assertions.py')
            args.core = bad / 'core_phone_suite.py'
            out2 = self.root / 'offline-rejected'; out2.mkdir()
            with patch.object(offline.subprocess, 'run', side_effect=AssertionError('changed driver must fail before even validation subprocess')):
                with self.assertRaisesRegex(offline.guard.UnknownState, 'qualified fixed revision'):
                    offline.frozen_suite(args, out2)
        self.assertFalse((out2 / 'runner').exists())

    def test_new_selector_extended_candidate_is_verified_then_projected(self):
        o.configure(self.q, package_manifest())
        upgrade = synthetic_upgrade_receipt(self.q)
        o.upgrade_proof(qs.encoded(upgrade), observer, '7' * 64, '8' * 64)
        receipt, candidate = synthetic_selection_receipt(self.q)
        actual = o.validate_selection(qs.encoded(receipt), candidate, self.q['raw_files']['runtime-config.json'], '8' * 64)
        self.assertEqual(actual['status'], 'configuration_verified')
        for key, wrong in (('uid', 2000), ('config_sha256', '0' * 64), ('actual_build_identity_sha256', '0' * 64)):
            changed = copy.deepcopy(candidate); changed[key] = wrong
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                o.validate_selection(qs.encoded(receipt), changed, self.q['raw_files']['runtime-config.json'], '8' * 64)
        with self.assertRaises(RuntimeError):
            o.validate_selection(qs.encoded(receipt), self.q['candidate'], self.q['raw_files']['runtime-config.json'], '8' * 64)
        for key, wrong in (('build_receipt_sha256', '0' * 64), ('source_tree', '0' * 40), ('status', 'planned')):
            changed = copy.deepcopy(upgrade); changed[key] = wrong
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                o.upgrade_proof(qs.encoded(changed), observer, '7' * 64, '8' * 64)

    def test_observer_prepare_uses_actual_compiled_inputs_and_separate_host_driver_pins(self):
        inputs = dict(candidate=self.q['candidate'], config=self.q['runtime_config'], permission=synthetic_upgrade_receipt(self.q))
        for name, value in inputs.items(): (self.root / (name + '.json')).write_bytes(qs.encoded(value))
        (self.root / 'instruction.txt').write_bytes(qs.ORDINARY_INSTRUCTION.encode())
        output = self.root / 'bundle'
        result = subprocess.run([sys.executable, '-B', str(CANDIDATE / 'ordinary/ordinary_start_observer.py'), 'prepare',
            '--source-dir', str(TEST_SOURCE), '--driver-dir', str(CANDIDATE / 'drivers'),
            '--candidate', str(self.root / 'candidate.json'), '--runtime-config', str(self.root / 'config.json'),
            '--instruction-file', str(self.root / 'instruction.txt'), '--apk-permission-proof', str(self.root / 'permission.json'),
            '--qualification-binding', self.q['binding_path'], '--qualification-binding-sha256', self.q['binding_sha256'],
            '--output', str(output)], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        plan = qs.strict((output / 'PLAN.json').read_bytes())
        self.assertFalse(plan['phone_contacted']); self.assertEqual(plan['observer_phone_writes'], 0)
        self.assertEqual(plan['expected_scope_sha256'], self.q['scope_sha256'])
        self.assertIn('qualification_scope.py', plan['host_driver_files'])
        self.assertIn('src/org/trillionnium/hepta/local/MainActivity.java', plan['source_files'])
        self.assertNotIn('qualification_scope.py', plan['source_files'])
        self.assertFalse((output / 'SOURCE-MANIFEST.json').exists())

    def test_actual_issuer_refuses_review_subset_as_complete_build(self):
        subset = self.root / 'deliberately-incomplete-source'; subset.mkdir()
        shutil.copyfile(TEST_SOURCE / 'AndroidManifest.xml', subset / 'AndroidManifest.xml')
        with self.assertRaises((OSError, ValueError)):
            issuer.full_source_inventory(subset, self.q['raw_files']['source-integration-manifest.json'])
        # This is deliberately not a positive build claim: the fixture source is
        # the review subset, and the actual issuer will never issue it a binding.

    def test_runtime_config_switch_requires_a_new_axis_binding(self):
        wrong = copy.deepcopy(self.q['candidate']); wrong['compute'] = 'gpu'
        args = SimpleNamespace(expected_compute='gpu', expected_context=8192, expected_model_profile=qs.PROFILE,
            qualification_binding=Path(self.q['binding_path']), qualification_binding_sha256=self.q['binding_sha256'])
        with patch.object(ac, 'Adb', side_effect=AssertionError('wrong axis must fail before ADB')):
            with self.assertRaises(ValueError): ac.run_task(args)
        self.assertNotEqual(basic_context('gpu')['runtime_config_sha256'], basic_context('npu')['runtime_config_sha256'])


if __name__ == '__main__': unittest.main()
