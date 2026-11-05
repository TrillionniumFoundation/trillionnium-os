#!/usr/bin/env python3
"""Exercise the complete auditor's OwnedOutput in private synthetic directories.

The production main entry, old audit output, historical verifier and phone are
never called. The only fixture binding is module.OUT; original source constants
and entry checks remain in the sealed file. Real filesystem negatives accompany
one explicitly labelled projection of the separately observed Mac nlink rule.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import traceback
import types
from unittest import mock

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE/'source/audit_policy_history_once.py'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def descriptors():
    return len(os.listdir('/proc/self/fd' if Path('/proc/self/fd').is_dir() else '/dev/fd'))


def load():
    seal = json.loads((BASE/'SOURCE-SEAL.json').read_text())
    assert digest(SOURCE) == seal['candidate']['sha256']
    assert SOURCE.stat().st_size == seal['candidate']['bytes']
    probe_path = BASE/seal['mac_probe_stdout']['path']
    assert digest(probe_path) == seal['mac_probe_stdout']['sha256']
    probe = json.loads(probe_path.read_bytes())
    assert probe['before']['held'] == probe['before']['named']
    assert probe['after']['held'] == probe['after']['named']
    assert probe['before']['held'][:5] == probe['after']['held'][:5]
    assert probe['before']['held'][5] == 2 and probe['after']['held'][5] == 3
    assert probe['intent']['held'] == probe['intent']['named'] and probe['intent']['held'][5] == 1
    assert probe['original_prefix6_predicate'] is False and probe['stable_prefix5_predicate'] is True
    spec = importlib.util.spec_from_file_location('sealed_complete_policy_auditor', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, seal, probe


@contextlib.contextmanager
def fixture(module):
    original_out = module.OUT
    before = descriptors()
    with tempfile.TemporaryDirectory(prefix='hepta-owned-output-guard-') as temporary:
        root = Path(temporary).resolve()
        external = root/'external'
        external.mkdir(mode=0o700)
        module.OUT = root/'owned'
        output = None
        try:
            output = module.OwnedOutput(module.Budget())
            yield output, root, external
        finally:
            if output is not None:
                output.close()
                assert output.budget.owned_output_fds == 0
            module.OUT = original_out
    assert descriptors() == before, 'owned directory/file descriptors leaked'


def expect_rejection(fn, contains=None):
    try:
        fn()
    except (ValueError, OSError) as error:
        if contains is not None:
            assert contains in str(error), (contains, str(error))
        return {'type': type(error).__name__, 'message': str(error)}
    raise AssertionError('changed identity or evidence was accepted')


def cases(module, probe):
    def ordinary_create_write_readback():
        with fixture(module) as (output, _root, _external):
            first = output.put('INTENT.json', b'{"synthetic":true}\n', 32768)
            second = output.put('READSET.json', b'{"synthetic":"second"}\n', 32768)
            output.check(verify_bodies=True)
            assert sorted(output.members) == ['INTENT.json', 'READSET.json']
            assert first['metadata'][5] == second['metadata'][5] == 1
            assert output.readback('INTENT.json', first) == b'{"synthetic":true}\n'
            return {'actual_files_created': 2, 'actual_complete_readback': True,
                    'physical_read_bytes': output.budget.physical_read_bytes}

    def recorded_mac_counter_projection():
        with fixture(module) as (output, _root, _external):
            original_metadata = module.metadata
            identity = output.identity[:2]
            initial_links = output.identity[5]
            delta = probe['after']['held'][5]-probe['before']['held'][5]
            observed = []
            def projected_metadata(value):
                result = original_metadata(value)
                if result[:2] == identity:
                    # Derive changes from the real directory contents, not the
                    # implementation's member dictionary. Only this counter is
                    # projected; actual inode/owner/mode/time and leaf stats run.
                    names = os.listdir(output.fd)
                    result[5] = initial_links + delta*len(names)
                    observed.append({'physical_members': sorted(names), 'projected_nlink': result[5]})
                return result
            with mock.patch.object(module, 'metadata', projected_metadata):
                first = output.put('INTENT.json', b'synthetic one\n', 32768)
                second = output.put('READSET.json', b'synthetic two\n', 32768)
                output.check(verify_bodies=True)
                assert output.readback('INTENT.json', first) == b'synthetic one\n'
                assert output.readback('READSET.json', second) == b'synthetic two\n'
            assert any(row['projected_nlink'] == initial_links+1 for row in observed)
            assert any(row['projected_nlink'] == initial_links+2 for row in observed)
            return {'scope': 'actual class and filesystem writes with recorded-platform counter projection',
                    'actual_mac_candidate_execution': False, 'mac_probe_key': probe['probe_key'],
                    'actual_files_created': 2, 'observations': observed}

    def directory_replaced():
        with fixture(module) as (output, root, _external):
            output.put('INTENT.json', b'synthetic\n', 32768)
            os.rename(module.OUT, root/'original-directory')
            module.OUT.mkdir(mode=0o700)
            return expect_rejection(output.check, 'owned output directory changed')

    def directory_symlink():
        with fixture(module) as (output, root, _external):
            os.rename(module.OUT, root/'original-directory')
            module.OUT.symlink_to(root/'original-directory', target_is_directory=True)
            return expect_rejection(output.check, 'owned output directory changed')

    def directory_permissions():
        with fixture(module) as (output, _root, _external):
            os.chmod(module.OUT, 0o750)
            return expect_rejection(output.check, 'owned output directory changed')

    def unexpected_member():
        with fixture(module) as (output, _root, _external):
            (module.OUT/'UNEXPECTED.json').write_bytes(b'synthetic\n')
            return expect_rejection(output.check, 'owned output directory changed')

    def missing_member():
        with fixture(module) as (output, _root, _external):
            output.put('INTENT.json', b'synthetic\n', 32768)
            (module.OUT/'INTENT.json').unlink()
            return expect_rejection(output.check, 'owned output directory changed')

    def leaf_hardlink():
        with fixture(module) as (output, _root, external):
            output.put('INTENT.json', b'synthetic\n', 32768)
            os.link(module.OUT/'INTENT.json', external/'alias')
            assert sorted(os.listdir(output.fd)) == ['INTENT.json']
            assert (module.OUT/'INTENT.json').stat().st_nlink == 2
            return expect_rejection(output.check, 'already written output member changed identity')

    def leaf_replaced():
        with fixture(module) as (output, _root, external):
            output.put('INTENT.json', b'synthetic\n', 32768)
            replacement = external/'replacement'
            replacement.write_bytes(b'synthetic\n')
            os.replace(replacement, module.OUT/'INTENT.json')
            return expect_rejection(output.check, 'already written output member changed identity')

    def leaf_symlink():
        with fixture(module) as (output, _root, external):
            output.put('INTENT.json', b'synthetic\n', 32768)
            target = external/'target'
            target.write_bytes(b'synthetic\n')
            (module.OUT/'INTENT.json').unlink()
            (module.OUT/'INTENT.json').symlink_to(target)
            return expect_rejection(output.check, 'already written output member changed identity')

    def parent_changed():
        with fixture(module) as (output, root, _external):
            (root/'new-sibling').mkdir(mode=0o700)
            return expect_rejection(output.check, 'owned output canonical path differs')

    def held_named_full9_mismatch():
        with fixture(module) as (output, _root, _external):
            original_stat = os.stat
            def changed_named(path, *args, **kwargs):
                result = original_stat(path, *args, **kwargs)
                if path == module.OUT.name and kwargs.get('dir_fd') == output.parent_fds[-1]:
                    fields = {name: getattr(result, name) for name in (
                        'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                    fields['st_mtime_ns'] += 1
                    return types.SimpleNamespace(**fields)
                return result
            with mock.patch.object(module.os, 'stat', changed_named):
                return expect_rejection(output.check, 'owned output directory changed')

    result = [('actual_create_write_readback', ordinary_create_write_readback),
              ('recorded_mac_counter_actual_class', recorded_mac_counter_projection),
              ('directory_replacement', directory_replaced), ('directory_symlink', directory_symlink),
              ('directory_permissions', directory_permissions), ('unexpected_member', unexpected_member),
              ('missing_member', missing_member), ('leaf_hardlink', leaf_hardlink),
              ('leaf_same_bytes_replacement', leaf_replaced), ('leaf_symlink', leaf_symlink),
              ('parent_full9_change', parent_changed), ('held_named_full9_mismatch', held_named_full9_mismatch)]
    for index, field in enumerate(('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')):
        def changed_fixed_field(index=index):
            with fixture(module) as (output, _root, _external):
                original_metadata = module.metadata
                identity = output.identity[:2]
                def projection(value):
                    result = original_metadata(value)
                    if result[:2] == identity:
                        result[index] += 1
                    return result
                with mock.patch.object(module, 'metadata', projection):
                    rejection = expect_rejection(output.check, 'owned output directory changed')
                return {'scope': 'synthetic fixed-field fault over actual class/held directory', **rejection}
        result.append(('fixed_field_'+field, changed_fixed_field))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    module, seal, probe = load()
    original_bindings = {name: getattr(module, name) for name in ('BASE','SOURCE','OUT','ADOPTION','VERIFIER','BOOT','LIMITS','EXPECTED_SUMMARY')}
    started = time.monotonic()
    results = []
    for name, fn in cases(module, probe):
        try:
            observation = fn()
            results.append({'name': name, 'passed': True, 'observation': observation})
        except BaseException as error:
            results.append({'name': name, 'passed': False, 'error_type': type(error).__name__,
                            'error': str(error), 'traceback': traceback.format_exc()})
    assert all(getattr(module, name) == value for name, value in original_bindings.items())
    assert digest(SOURCE) == seal['candidate']['sha256']
    report = {'schema': 'hepta.owned-output-directory.guard-regression.v1',
              'status': 'PASS' if all(row['passed'] for row in results) else 'FAIL',
              'passed': sum(row['passed'] for row in results), 'failed': sum(not row['passed'] for row in results),
              'cases': results, 'source_sha256': seal['candidate']['sha256'], 'source_unchanged': True,
              'complete_auditor_imported': True, 'real_class_constructor_write_check_readback_exercised': True,
              'fixture_binding': 'module.OUT temporarily points at a new synthetic private directory; restored after each case',
              'production_main_called': False, 'historical_verifier_called': False,
              'historical_output_modified': False, 'phone_calls': 0, 'actual_mac_candidate_execution': False,
              'separate_actual_mac_probe_key': probe['probe_key'], 'elapsed_seconds': time.monotonic()-started}
    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)+'\n'
    if args.output:
        args.output.write_text(raw)
    print(raw, end='')
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
