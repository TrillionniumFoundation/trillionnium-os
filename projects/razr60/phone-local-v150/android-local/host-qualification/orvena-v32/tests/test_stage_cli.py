"""Real host CLI preparation/plans in a copied reviewed package; no ADB."""
from helpers import *


class StageCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.q = binding_fixture(self.root / 'binding')
        self.package = self.root / 'package'; shutil.copytree(CANDIDATE, self.package,
            ignore=shutil.ignore_patterns('__pycache__', 'PACKAGE-MANIFEST.json'))
        manifest = package_manifest(); raw = qs.encoded(manifest)
        (self.package / 'PACKAGE-MANIFEST.json').write_bytes(raw); self.package_sha = qs.sha(raw)
        self.words = [sys.executable, '-B', str(self.package / 'orvena_qualification.py'), '--package-sha256', self.package_sha,
            '--qualification-binding', self.q['binding_path'], '--qualification-binding-sha256', self.q['binding_sha256'], '--axis', 'npu']

    def test_default_plan_has_no_phone_sequence_and_explicit_f32_axis(self):
        result = subprocess.run(self.words + ['plan'], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode()); value = qs.strict(result.stdout)
        self.assertFalse(value['phone_contacted']); self.assertFalse(value['automatic_sequence']); self.assertFalse(value['automatic_fallback'])
        self.assertTrue(qs.sampler_valid(value['sampler_requested']))
        self.assertTrue(value['same_instruction_gpu_rerun_is_not_same_prompt_numerical_equivalence'])

    def test_missing_execute_only_plans_and_execute_without_idle_window_rejects(self):
        args = ['probe', '--prepared-result', str(self.root / 'nonexistent.json'), '--prepared-result-sha256', '0' * 64,
                '--scope-activation', str(self.root / 'no-activation.json'), '--scope-activation-sha256', '0' * 64,
                '--output', str(self.root / 'must-not-exist')]
        result = subprocess.run(self.words + args, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertFalse(qs.strict(result.stdout)['phone_contacted'])
        self.assertFalse((self.root / 'must-not-exist').exists())
        blocked = subprocess.run(self.words + ['--execute'] + args, capture_output=True, timeout=15)
        self.assertEqual(blocked.returncode, 3); self.assertIn(b'exclusive-idle-window', blocked.stderr)
        self.assertFalse((self.root / 'must-not-exist').exists())

    def test_package_membership_bytes_and_axis_pin_reject_before_phone(self):
        changed = self.package / 'drivers/qualification_scope.py'; changed.write_bytes(changed.read_bytes() + b'\n')
        result = subprocess.run(self.words + ['plan'], capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0); self.assertIn(b'host helper member changed', result.stderr)
        changed.write_bytes((CANDIDATE / 'drivers/qualification_scope.py').read_bytes())
        (self.package / 'unreviewed.py').write_text('# unexpected helper\n')
        result = subprocess.run(self.words + ['plan'], capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0); self.assertIn(b'closure membership', result.stderr)
        (self.package / 'unreviewed.py').unlink()
        args = self.words.copy(); args[-1] = 'gpu'
        result = subprocess.run(args + ['plan'], capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0); self.assertIn(b'another axis needs', result.stderr)

    def test_real_ordinary_host_prepare_retains_full_selected_candidate_and_separate_projection(self):
        # Both receipts are explicit synthetic protocol inputs. The actual
        # issuer rejects the partial review source as a real full build.
        selection = self.root / 'selection'; selection.mkdir()
        helper_root = ROOT / 'tests/fixtures/upgrade-select-helpers'
        upgrade_helper = helper_root / 'upgrade_v32_once_r1.py'
        selector_helper = helper_root / 'select_runtime_once_v32_r1.py'
        upgrade = synthetic_upgrade_receipt(self.q, qs.sha(upgrade_helper.read_bytes()), qs.sha(selector_helper.read_bytes()))
        upgrade_path = self.root / 'upgrade.json'; upgrade_path.write_bytes(qs.encoded(upgrade))
        receipt, candidate = synthetic_selection_receipt(self.q, qs.sha(selector_helper.read_bytes()))
        for name, value in (('RESULT.json', receipt), ('candidate.json', candidate)):
            (selection / name).write_bytes(qs.encoded(value))
        (selection / 'runtime-config.json').write_bytes(self.q['raw_files']['runtime-config.json'])
        output = self.root / 'prepared'
        words = [sys.executable, '-B', str(self.package / 'ordinary/ordinary_launcher.py'),
            '--package-sha256', self.package_sha, '--qualification-binding', self.q['binding_path'],
            '--qualification-binding-sha256', self.q['binding_sha256']]
        result = subprocess.run(words + ['prepare', '--selection', str(selection),
            '--selection-result-sha256', qs.sha((selection / 'RESULT.json').read_bytes()), '--upgrade-proof', str(upgrade_path),
            '--upgrade-proof-sha256', qs.sha(upgrade_path.read_bytes()), '--upgrade-helper', str(upgrade_helper),
            '--selector-helper', str(selector_helper), '--output', str(output)], capture_output=True, timeout=45)
        if result.returncode:
            details = '\n'.join(p.read_text(errors='replace') for p in output.rglob('*.stderr')) if output.exists() else ''
            self.fail(result.stderr.decode() + '\n' + details)
        actual = qs.strict((output / 'PREPARED.json').read_bytes())
        self.assertFalse(actual['phone_contacted'])
        self.assertIsNone(actual['model_load_qualified']); self.assertIsNone(actual['task_goal_verified'])
        self.assertEqual((output / 'selection-candidate.json').read_bytes(), (selection / 'candidate.json').read_bytes())
        self.assertEqual(qs.strict((output / 'candidate.json').read_bytes()), self.q['candidate'])
        plan = qs.strict((output / 'bundle/PLAN.json').read_bytes())
        self.assertEqual(plan['instruction'], qs.ORDINARY_INSTRUCTION); self.assertEqual(plan['app_task_origin_required'], 'user_button')


if __name__ == '__main__': unittest.main()
