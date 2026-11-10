"""Private host target binding: every tested rejection precedes real transport."""
from helpers import *


class PrivateDeviceTargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.q = binding_fixture(self.root / 'binding')

    def args(self, **overrides):
        values = dict(qualification_binding=Path(self.q['binding_path']),
            qualification_binding_sha256=self.q['binding_sha256'], **self.q['device_target'],
            adb=sys.executable, adb_host='127.0.0.1', adb_port=5037, execute=True, exclusive_idle_window=True)
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_new_binding_requires_serial_and_rejects_old_schema(self):
        path=Path(self.q['binding_path']); original=qs.strict(path.read_bytes())
        for kind in ('missing-target','missing-serial','old-schema'):
            with self.subTest(kind=kind):
                value=copy.deepcopy(original)
                if kind=='missing-target': value.pop('device_target')
                elif kind=='missing-serial': value['device_target'].pop('serial')
                else: value['schema']='hepta.orvena-scoped-host-binding.v1'
                raw=qs.encoded(value); path.write_bytes(raw)
                with self.assertRaises(ValueError): qs.load_binding(path,qs.sha(raw))

    def test_serial_tampering_invalidates_original_binding_sha(self):
        path=Path(self.q['binding_path']); value=qs.strict(path.read_bytes())
        value['device_target']['serial']='ANOTHER_SYNTHETIC'
        path.write_bytes(qs.encoded(value))
        with self.assertRaisesRegex(ValueError,'binding manifest SHA differs'):
            qs.load_binding(path,self.q['binding_sha256'])

    def test_serial_and_display_validation_rejects_missing_or_invalid_values(self):
        for value in (None,'','with space','\n',False,'-option','x'*129):
            with self.subTest(serial=value), self.assertRaises(ValueError):
                target=dict(self.q['device_target'],serial=value); qs.validate_device_target(target)
        with self.assertRaisesRegex(ValueError,'display'):
            qs.require_device_target(self.args(input_width=100),self.q,display=True)

    def test_stage_args_require_exact_bound_serial_without_override(self):
        with patch.object(m,'Q',self.q):
            with self.assertRaisesRegex(ValueError,'selected serial differs'):
                m.phone_args(self.args(serial='ANOTHER_SYNTHETIC'))
            selected=m.phone_args(self.args())
        self.assertEqual(selected.serial,self.q['device_target']['serial'])
        self.assertEqual(selected.qualification_binding_sha256,self.q['binding_sha256'])

    def test_acceptance_and_observer_adb_reject_mismatched_serial_before_transport(self):
        import phone_inventory
        args=self.args(serial='ANOTHER_SYNTHETIC')
        with patch.object(socket,'create_connection',side_effect=AssertionError('no network')), \
             patch.object(subprocess,'Popen',side_effect=AssertionError('no process')):
            with self.assertRaisesRegex(ValueError,'selected serial differs'):
                ac.Adb(args,self.root/'adb')
            with self.assertRaisesRegex(ValueError,'selected serial differs'):
                observer.ObserverAdb(args,self.root/'observer',None)
            with self.assertRaisesRegex(ValueError,'selected serial differs'):
                phone_inventory.ReadOnlyAdb(args,self.root/'inventory')
            with self.assertRaisesRegex(ValueError,'selected serial differs'):
                phone_inventory.run_inventory(args)

    def test_ordinary_live_rejects_mismatched_serial_before_adb_or_server(self):
        o.configure(self.q,package_manifest())
        fake_inventory=SimpleNamespace(require_existing_adb_server=lambda *a: self.fail('server must not be contacted'))
        plan=dict(_qualification=self.q,_scope_module=qs)
        with self.assertRaisesRegex(ValueError,'selected serial differs'):
            o.live(self.args(serial='ANOTHER_SYNTHETIC'),self.root,None,plan,None,fake_inventory,require_scope=False)

    def test_offline_preflight_rejects_wrong_serial_before_radio_or_subprocess(self):
        offline=module(CANDIDATE/'offline/phone_offline_suite.py','serial_bound_offline')
        with patch.object(socket,'create_connection',side_effect=AssertionError('no network')), \
             patch.object(subprocess,'run',side_effect=AssertionError('no subprocess')):
            with self.assertRaisesRegex(ValueError,'selected serial differs'):
                offline.frozen_suite(self.args(serial='ANOTHER_SYNTHETIC'),self.root)

    def test_binding_issuer_requires_all_target_arguments(self):
        parser=issuer.parser()
        required={a.dest for a in parser._actions if a.required}
        self.assertTrue({'serial','logical_display_id','physical_display_id','input_width','input_height'} <= required)
        self.assertEqual(qs.SCHEMA,'hepta.orvena-scoped-host-binding.v2')
        self.assertEqual(self.q['scope']['schema'],'hepta.qualification-scope.v1')


if __name__=='__main__': unittest.main()
