#!/usr/bin/env python3
"""Offline rejection contracts for the actual transfer verifier; no compiler or phone."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ui_venus_ci', HERE / 'rebuild_and_verify.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
APP = Path(os.environ.get('HEPTA_TEST_APP_SOURCE', HERE.parents[1] / 'lfm3-controller'))


class TransferContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = json.loads((APP / 'provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json').read_text())
        cls.pins = json.loads((APP / 'native/ui-venus-runtime-pins.json').read_text())

    def test_exact_original_contract_with_new_host_observations(self):
        report = json.loads(json.dumps(self.original).replace('/Users/qianqi', '/ci'))
        report['elapsed_seconds'] = 12.5
        api.check_new_report(report, self.original, self.pins)

    def test_each_fixed_report_field_rejects_a_changed_value(self):
        variable = {'compile_command', 'ndk_directory', 'compiler_version', 'sdk_libraries', 'elapsed_seconds'}
        for key in set(self.original) - variable:
            with self.subTest(key=key):
                report = copy.deepcopy(self.original)
                report[key] = None
                with self.assertRaises(ValueError):
                    api.check_new_report(report, self.original, self.pins)

    def test_missing_and_added_report_fields_reject(self):
        report = copy.deepcopy(self.original)
        del report['worker']
        with self.assertRaises(ValueError):
            api.check_new_report(report, self.original, self.pins)
        report = copy.deepcopy(self.original)
        report['unreviewed_claim'] = True
        with self.assertRaises(ValueError):
            api.check_new_report(report, self.original, self.pins)

    def test_sdk_membership_order_and_bytes_remain_exact(self):
        for edit in ('hash', 'missing', 'reordered', 'path'):
            with self.subTest(edit=edit):
                report = copy.deepcopy(self.original)
                if edit == 'hash':
                    report['sdk_libraries'][0]['sha256'] = '0' * 64
                elif edit == 'missing':
                    report['sdk_libraries'].pop()
                elif edit == 'reordered':
                    report['sdk_libraries'].reverse()
                else:
                    report['sdk_libraries'][0]['source_path'] = 'relative'
                with self.assertRaises(ValueError):
                    api.check_new_report(report, self.original, self.pins)

    def test_boolean_duration_and_wrong_compiler_are_not_qualified(self):
        for key, value in (('elapsed_seconds', True), ('elapsed_seconds', -1),
                           ('compiler_version', 'unverified compiler'),
                           ('ndk_directory', 'relative'), ('compile_command', [])):
            with self.subTest(key=key, value=value):
                report = copy.deepcopy(self.original)
                report[key] = value
                with self.assertRaises(ValueError):
                    api.check_new_report(report, self.original, self.pins)

    def test_actual_compiler_flags_and_output_cannot_drift(self):
        for edit in ('remove_werror', 'optimization', 'extra_define', 'relative_output'):
            with self.subTest(edit=edit):
                report = copy.deepcopy(self.original)
                command = report['compile_command']
                if edit == 'remove_werror':
                    command.remove('-Werror')
                elif edit == 'optimization':
                    command[command.index('-O2')] = '-O0'
                elif edit == 'extra_define':
                    command.insert(1, '-DUNREVIEWED_BUILD=1')
                else:
                    command[-1] = 'libhepta_ui_venus_runner.so'
                with self.assertRaises(ValueError):
                    api.check_new_report(report, self.original, self.pins)

    def test_complete_public_source_closure_qualifies_without_inference(self):
        root, unused_api, pins, native, original = api.frozen_app(APP)
        self.assertEqual(root, APP.resolve())
        self.assertEqual(api.digest(original), api.ORIGINAL_RECEIPT_SHA)
        self.assertEqual(pins['worker']['sha256'], api.WORKER_SHA)
        self.assertTrue((native / 'tools/build_android.py').is_file())

    def test_ci_head_run_and_attempt_are_exact_nonempty_identities(self):
        self.assertEqual(api.source_identity('a' * 40, '19', '2'),
                         {'source_head_sha': 'a' * 40, 'github_run_id': '19', 'github_run_attempt': '2'})
        for head, run, attempt in (('a' * 39, '1', '1'), ('A' * 40, '1', '1'),
                                   ('a' * 40, '0', '1'), ('a' * 40, '1', '0'),
                                   ('a' * 40, '01', '1'), ('a' * 40, '1', '1\n')):
            with self.assertRaises(ValueError):
                api.source_identity(head, run, attempt)

    def test_metadata_reader_rejects_links_empty_oversized_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'record'
            path.write_bytes(b'one')
            self.assertEqual(api.read(path, 3), b'one')
            with self.assertRaises(ValueError):
                api.read(path, 2)
            (root / 'alias').symlink_to(path)
            with self.assertRaises(OSError):
                api.read(root / 'alias')
            os.link(path, root / 'hardlink')
            with self.assertRaises(ValueError):
                api.read(path)
            (root / 'empty').touch()
            with self.assertRaises(ValueError):
                api.read(root / 'empty')

    def test_duplicate_and_nonfinite_json_cannot_replace_evidence(self):
        for text in ('{"same":1,"same":2}', '{"value":NaN}', '{"value":Infinity}'):
            with self.assertRaises(ValueError):
                api.obj(text)

    def test_binding_changes_for_every_source_attempt_and_evidence_input(self):
        expected = api.source_identity('a' * 40, '19', '2')
        compiler = json.dumps({'macho': {'sha256': 'b' * 64}}).encode()
        original = api.expected_binding(expected, b'actual build report', compiler, b'actual qualifier')
        mutations = [api.expected_binding(api.source_identity('c' * 40, '19', '2'), b'actual build report', compiler, b'actual qualifier'),
                     api.expected_binding(api.source_identity('a' * 40, '20', '2'), b'actual build report', compiler, b'actual qualifier'),
                     api.expected_binding(api.source_identity('a' * 40, '19', '3'), b'actual build report', compiler, b'actual qualifier'),
                     api.expected_binding(expected, b'different report', compiler, b'actual qualifier'),
                     api.expected_binding(expected, b'actual build report', json.dumps({'macho': {'sha256': 'd' * 64}}).encode(), b'actual qualifier'),
                     api.expected_binding(expected, b'actual build report', compiler, b'different qualifier')]
        self.assertTrue(all(value != original for value in mutations))
        self.assertFalse(original['original_receipt_is_new_build_receipt'])
        self.assertFalse(original['phone_contacted'])


if __name__ == '__main__':
    unittest.main()
