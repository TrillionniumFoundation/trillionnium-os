"""Invoke the real modified acceptance function with trapped device I/O.

Only transport/fail-closed behavior is simulated. No synthetic run is graded
as a genuine native/model/phone success.
"""
from helpers import *


class DeviceIoDouble:
    def __init__(self, q, instruction, mutation=None):
        self.q = q; self.instruction = instruction; self.mutation = mutation
        self.words = []; self.private = {'files/qualification-scope.json': q['raw_files']['qualification-scope.json'],
            'files/model/runtime-config.json': q['raw_files']['runtime-config.json']}
        self.task_id = 'a' * 32; self.request = None

    def command(self, words, label=None, input_data=None, **kwargs):
        self.words.append((label, list(words)))
        if label == 'app-uid': return 0, str(self.q['app_uid']).encode()
        if label == 'phone-clock': return 0, b'1794000000\n'
        if label == 'write-one-private-request':
            self.private['files/debug-task.json'] = input_data; self.request = qs.strict(input_data)
            if self.mutation == 'after-private-write': self.private['files/qualification-scope.json'] = b'{}'
            return 0, b''
        if label == 'launch-once': return 0, b'Status: ok\n'
        if label == 'setup-home': return 0, b''
        raise AssertionError('unexpected device command: ' + str((label, words)))

    def app_bytes(self, name, **kwargs): return self.private.get(name)
    def list_children(self, *args, **kwargs): return []
    def session(self):
        return dict(task_id=self.task_id, debug_nonce_sha256=qs.sha(self.request['nonce'].encode()),
                    status='model_reported_done', pending=False, running=False, cleanup_known=True,
                    expected_scope_sha256=self.q['scope_sha256'], actual_scope_sha256=self.q['scope_sha256'])
    def status(self, *args, **kwargs):
        if not self.request: return dict(session=dict(pending=False, running=False, cleanup_known=True), trigger=None)
        return dict(session=self.session(), trigger=dict(nonce_sha256=qs.sha(self.request['nonce'].encode()),
                    accepted=True, private_request_consumed=True))
    def app_json(self, name, **kwargs):
        if name.endswith('/owner.json'):
            return dict(task_id=self.task_id, instruction=self.instruction, instruction_utf8_sha256=qs.sha(self.instruction.encode()))
        if name.endswith('/result.json'):
            return dict(task_id=self.task_id, status='model_reported_done', cleanup_known=True, external_model=False)
        raise AssertionError('unexpected JSON read: ' + name)


class AcceptanceTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.q = binding_fixture(self.root / 'binding')
        self.args = SimpleNamespace(case_id='scoped-host-transport', instruction=qs.ORDINARY_INSTRUCTION,
            evidence_root=self.root / 'evidence', adb='NO_REAL_ADB', adb_host='NO_NETWORK', adb_port=1, serial='SYNTHETIC',
            expected_compute='npu', expected_context=8192, expected_model_profile=qs.PROFILE,
            setup_home=True, timeout=2, poll=.01, stop_grace=.01, command_timeout=1,
            expected_package=qs.ROLES['settings'], expected_visible_text=[], text_match='exact', include_screenshots=False,
            qualification_binding=Path(self.q['binding_path']), qualification_binding_sha256=self.q['binding_sha256'])

    def run_acceptance(self, mutation=None):
        device = DeviceIoDouble(self.q, self.args.instruction, mutation)
        if mutation == 'before-nonce': device.private['files/qualification-scope.json'] = None
        with patch.object(ac, 'Adb', return_value=device), patch.object(ac, 'current_status', side_effect=device.status), \
             patch.object(ac, 'wait_terminal_quiescence', side_effect=lambda *a, **k: device.session()), \
             patch.object(ac, 'capture_ui', return_value={}), \
             patch.object(ac, 'ui_predicates', return_value=dict(expectations_supplied=False, all_passed=False)), \
             patch.object(ac, 'collect_evidence', return_value=dict(errors=[], associated_runs=[])), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('no real subprocess in device seam')), \
             patch.object(socket, 'create_connection', side_effect=AssertionError('no network')), contextlib.redirect_stdout(io.StringIO()):
            rc = ac.run_task(self.args)
        report = qs.strict((self.args.evidence_root / self.args.case_id / 'acceptance.json').read_bytes())
        return device, rc, report

    def test_actual_run_task_emits_once_nonce_and_scope_and_preserves_request_schema(self):
        device, rc, report = self.run_acceptance()
        launches = [words for label, words in device.words if label == 'launch-once']
        self.assertEqual(len(launches), 1)
        self.assertEqual(set(device.request), {'schema', 'nonce', 'instruction', 'created_wall_ms', 'expires_wall_ms'})
        self.assertEqual(device.request['instruction'], self.args.instruction)
        self.assertEqual(launches[0], qs.debug_intent(device.request['nonce'], self.q))
        self.assertEqual(report['expected_scope_sha256'], self.q['scope_sha256'])
        self.assertEqual(report['qualification_binding_sha256'], self.q['binding_sha256'])
        self.assertEqual(report['launch_attempt_count'], 1)
        self.assertEqual(rc, 3); self.assertEqual(report['verdict'], 'unverified')
        self.assertFalse(report['native_receipts_verified']); self.assertFalse(report['qualification_scope_review']['verified'])
        self.assertTrue((self.args.evidence_root / self.args.case_id / 'qualification-binding/BINDING.json').is_file())

    def test_missing_scope_prevents_even_nonce_write(self):
        device, rc, report = self.run_acceptance('before-nonce')
        self.assertFalse(any(label in ('write-one-private-request', 'launch-once', 'setup-home') for label, _ in device.words))
        self.assertEqual(report['launch_attempt_count'], 0); self.assertEqual(rc, 2)
        self.assertFalse(report['cleanup_unknown'])

    def test_changed_scope_after_private_request_prevents_intent(self):
        device, rc, report = self.run_acceptance('after-private-write')
        self.assertEqual(sum(label == 'write-one-private-request' for label, _ in device.words), 1)
        self.assertFalse(any(label == 'launch-once' for label, _ in device.words))
        self.assertEqual(report['launch_attempt_count'], 0); self.assertEqual(rc, 2)
        self.assertIn('fresh private file differs', ' '.join(report['errors']))

    def test_wrong_binding_axis_or_raw_hash_fails_before_constructing_adb(self):
        for field, wrong in (('expected_compute', 'gpu'), ('qualification_binding_sha256', '0' * 64)):
            args = copy.copy(self.args); setattr(args, field, wrong)
            with self.subTest(field=field), patch.object(ac, 'Adb', side_effect=AssertionError('ADB must not be constructed')):
                with self.assertRaises(ValueError): ac.run_task(args)

    def test_case_projection_keeps_binding_and_original_timeout_and_goal(self):
        case = qs.strict(qs.read(CANDIDATE / 'reference/core-cases.json'))
        if isinstance(case, dict): case = case['cases']
        case = case[0]
        self.args.qualification_binding_sha256 = self.q['binding_sha256']
        actual = ps.case_args(self.args, case, self.q['candidate'], self.root)
        self.assertEqual(actual.qualification_binding, self.args.qualification_binding)
        self.assertEqual(actual.qualification_binding_sha256, self.q['binding_sha256'])
        self.assertEqual(actual.instruction, case['instruction']); self.assertEqual(actual.timeout, 540)
        self.assertEqual(actual.expected_visible_text, case['expected_visible_text'])


if __name__ == '__main__': unittest.main()
