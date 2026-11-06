#!/usr/bin/env python3
"""Exercise the complete pinned stager on isolated local filesystem fixtures."""
import argparse
import contextlib
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import traceback
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def descriptors():
    return len(os.listdir('/proc/self/fd' if Path('/proc/self/fd').is_dir() else '/dev/fd'))


def load():
    spec = importlib.util.spec_from_file_location('complete_create_only_stager', ROOT/'stage_sources_once.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = (ROOT/'SOURCE-PAYLOAD.json').read_bytes()
    bodies = module.decode_payload(payload)
    return module, payload, bodies


@contextlib.contextmanager
def fixture(module, bodies, names=()):
    saved = {key: getattr(module, key) for key in ('BASE', 'DEST', 'AUDIT_OUT', 'CALLER_OUT', 'OWNER_UID')}
    fd_before = descriptors()
    old_umask = os.umask(0o077)
    # A shared /tmp parent is concurrently mutated by other local agents. Keep
    # these disposable fixtures under this exclusive test directory so the
    # production full9 ancestor guard remains exercised without that unrelated
    # shared-parent race. The context removes only its own synthetic tree.
    with tempfile.TemporaryDirectory(prefix='hepta-source-stage-', dir=ROOT/'tests') as temporary:
        root = Path(temporary).resolve()
        base = root/'base'
        base.mkdir(mode=0o700)
        external = root/'external'
        external.mkdir(mode=0o700)
        for name in names:
            (base/name).write_bytes(b'')
        module.BASE = base
        for name in ('DEST', 'AUDIT_OUT', 'CALLER_OUT'):
            setattr(module, name, base/saved[name].name)
        module.OWNER_UID = os.geteuid()
        stager = module.Stager(bodies, module.Budget())
        try:
            yield stager, root, external
        finally:
            stager.close()
            for key, value in saved.items():
                setattr(module, key, value)
            os.umask(old_umask)
    assert descriptors() == fd_before, 'stager leaked a local descriptor'


def rejected(stager, contains=None):
    try:
        stager.run()
    except (ValueError, OSError) as error:
        if contains:
            assert contains in str(error), (contains, str(error))
        receipt = stager.failure(error)
        assert receipt['partial_outputs_removed'] is False
        assert receipt['retry_or_alternate_suffix'] is False
        assert not stager.fds
        assert receipt['owned_fds_closed'] is (not receipt['cleanup_errors']
                                             and not receipt['descriptor_operations_unresolved'])
        assert receipt['staged_source_execution'] is False and receipt['phone_calls'] == 0
        return receipt
    raise AssertionError('changed input, namespace, identity or budget was accepted')


def cases(module, payload, bodies):
    def normal():
        names = ['prefix-a', 'prefix-b', '中文😀\nname']
        with fixture(module, bodies, names) as (stager, _root, _external):
            report = stager.run()
            assert report['state'] == 'FIXED_THREE_SOURCES_CREATED_AND_FULLY_READ_TWICE'
            assert report['owned_fds_closed'] is True
            assert report['physical_source_read_bytes'] == 2*sum(map(len, bodies.values())) == 171298
            assert report['source_write_bytes'] == sum(map(len, bodies.values())) == 85649
            assert module.parent_names_decode(report['parent_names_before']) == sorted(names)
            assert module.parent_names_decode(report['parent_names_after']) == sorted(names+[module.DEST.name])
            assert sorted(p.name for p in module.DEST.iterdir()) == sorted(bodies)
            for name, body in bodies.items():
                assert (module.DEST/name).read_bytes() == body
                info = (module.DEST/name).stat()
                assert info.st_nlink == 1 and (info.st_mode & 0o7777) == 0o600
            assert (module.DEST.stat().st_mode & 0o7777) == 0o700
            assert not module.AUDIT_OUT.exists() and not module.CALLER_OUT.exists()
            return {'actual_files': 3, 'actual_complete_reads': 6, 'read_bytes': 171298,
                    'write_bytes': 85649, 'unicode_emoji_newline_names_exact': True,
                    'receipt_bytes': len(module.wire(report)), 'peak_owned_fds': report['peak_owned_fds']}

    def retained_name_domain():
        data = json.loads((ROOT/'evidence/CP09-PARENT-NAMES-BEFORE.json').read_bytes())
        names = module.parent_names_decode(data)
        assert len(names) == 1577
        names += ['local-regression-padding-'+str(i).zfill(3) for i in range(40)]
        with fixture(module, bodies, names) as (stager, _root, _external):
            report = stager.run()
            assert module.parent_names_decode(report['parent_names_before']) == sorted(names)
            assert module.parent_names_decode(report['parent_names_after']) == sorted(names+[module.DEST.name])
            raw = module.wire(report)
            charged = len(raw)+report['parent_names_decoded_bytes']+report['parent_names_encoded_bytes']
            assert charged <= module.LIMITS['names_and_receipt_bytes']
            return {'scope': 'synthetic local tree using retained complete cp09 names plus 40 synthetic names',
                    'before_name_count': len(names), 'after_name_count': len(names)+1,
                    'actual_read_bytes': report['physical_source_read_bytes'], 'receipt_bytes': len(raw),
                    'decoded_name_bytes': report['parent_names_decoded_bytes'],
                    'encoded_name_bytes': report['parent_names_encoded_bytes'], 'total_charged_bytes': charged}

    result = [('actual_create_fsync_two_readbacks', normal), ('retained_complete_name_domain', retained_name_domain)]
    for target in ('DEST', 'AUDIT_OUT', 'CALLER_OUT'):
        def existing(target=target):
            with fixture(module, bodies) as (stager, _root, _external):
                path = getattr(module, target)
                path.mkdir(mode=0o700)
                info = path.stat()
                report = rejected(stager, 'fixed target already exists')
                assert not stager.created and report['created_files'] == []
                assert path.stat().st_ino == info.st_ino
                if target != 'DEST':
                    assert not module.DEST.exists()
                return {'rejected_target': target, 'before_mutation': True, 'existing_target_retained': True}
        result.append(('existing_'+target.lower(), existing))

    def existing_symlink():
        with fixture(module, bodies) as (stager, _root, external):
            module.CALLER_OUT.symlink_to(external/'absent')
            rejected(stager, 'fixed target already exists')
            assert not stager.created and module.CALLER_OUT.is_symlink() and not module.DEST.exists()
            return {'dangling_target_symlink_rejected_before_mkdir': True}

    def corrupt_payload():
        for raw in (payload[:-1], payload+b'x', b'x'*(module.LIMITS['stdin_bytes']+1)):
            try:
                module.decode_payload(raw)
            except ValueError:
                continue
            raise AssertionError('changed or oversized transport accepted')
        return {'full_transport_pin_and_size_rejections': 3, 'filesystem_called': False}

    def after_first(stager, callback):
        original = stager.write_file
        def wrapped(name, body):
            original(name, body)
            if len(stager.created_files) == 1:
                callback(name, body)
        return mock.patch.object(stager, 'write_file', wrapped)

    def extra_base_member():
        with fixture(module, bodies) as (stager, _root, _external):
            with after_first(stager, lambda _n, _b: (module.BASE/'unexpected-base-member').write_bytes(b'x')):
                report = rejected(stager, 'BASE complete names changed beyond sole source addition')
            assert len(stager.created_files) == 3 and (module.BASE/'unexpected-base-member').exists()
            names = module.parent_names_decode(report['parent_names_after'])
            assert 'unexpected-base-member' in names and module.DEST.name in names
            assert all((module.DEST/name).read_bytes() == body for name, body in bodies.items())
            return {'complete_after_names_retained': True, 'three_created_sources_retained': True}

    def ancestor_changed():
        with fixture(module, bodies) as (stager, root, _external):
            with after_first(stager, lambda _n, _b: (root/'new-parent-member').write_bytes(b'x')):
                rejected(stager, 'ordinary parent full9 changed')
            assert len(stager.created_files) == 1 and module.DEST.is_dir()
            return {'ancestor_full9_change_rejected': True, 'partial_files_retained': 1}

    def source_extra_member():
        with fixture(module, bodies) as (stager, _root, _external):
            with after_first(stager, lambda _n, _b: (module.DEST/'unexpected').write_bytes(b'x')):
                rejected(stager, 'owned source directory member closure differs')
            assert (module.DEST/'unexpected').exists() and len(stager.created_files) == 1
            return {'exact_source_members_enforced': True, 'partial_state_retained': True}

    def source_permissions():
        with fixture(module, bodies) as (stager, _root, _external):
            with after_first(stager, lambda _n, _b: os.chmod(module.DEST, 0o750)):
                rejected(stager, 'owned source directory identity changed')
            assert len(stager.created_files) == 1
            return {'actual_directory_mode_change_rejected': True}

    def source_replacement():
        with fixture(module, bodies) as (stager, _root, external):
            def change(_name, _body):
                os.rename(module.DEST, external/'moved-source')
                module.DEST.mkdir(mode=0o700)
            with after_first(stager, change):
                rejected(stager, 'owned source directory identity changed')
            assert (external/'moved-source').is_dir() and module.DEST.is_dir()
            return {'held_source_vs_replacement_rejected': True, 'both_directories_retained': True}

    def leaf_hardlink():
        with fixture(module, bodies) as (stager, _root, external):
            def change(name, _body):
                os.link(module.DEST/name, external/'alias')
            with after_first(stager, change):
                rejected(stager, 'completed source file full9 changed')
            assert (external/'alias').stat().st_nlink == 2
            return {'single_link_leaf_enforced': True, 'partial_state_retained': True}

    def leaf_replacement_before_first_read():
        with fixture(module, bodies) as (stager, _root, external):
            original = stager.read_file
            def replaced(directory_fd, name, expected_metadata):
                replacement = external/'same-byte-replacement'
                replacement.write_bytes(bodies[name])
                os.chmod(replacement, 0o600)
                os.replace(replacement, module.DEST/name)
                return original(directory_fd, name, expected_metadata)
            with mock.patch.object(stager, 'read_file', replaced):
                rejected(stager, 'staged source regular single-link full9 differs')
            assert len(stager.created_files) == 1 and not stager.files
            assert (module.DEST/stager.created_files[0]).read_bytes() == bodies[stager.created_files[0]]
            return {'write_fd_identity_preserved_into_first_reopen': True, 'same_bytes_substitution_rejected': True}

    def partial_write():
        with fixture(module, bodies) as (stager, _root, _external):
            original_write = os.write
            count = 0
            def failing_write(fd, data):
                nonlocal count
                count += 1
                if count == 1:
                    return original_write(fd, data[:7])
                raise OSError(errno.EIO, 'synthetic owned partial write failure')
            with mock.patch.object(module.os, 'write', failing_write):
                report = rejected(stager, 'synthetic owned partial write failure')
            assert report['source_write_bytes'] == 7 and len(stager.created_files) == 1
            assert (module.DEST/stager.created_files[0]).stat().st_size == 7
            assert sorted(path.name for path in module.DEST.iterdir()) == stager.created_files
            return {'actual_partial_file_retained_bytes': 7, 'no_retry_or_suffix': True, 'fds_closed': True}

    def count_budget():
        with fixture(module, bodies, ['n'+str(i) for i in range(8)]) as (stager, _root, _external):
            with mock.patch.dict(module.LIMITS, {'base_names_per_snapshot': 8}):
                rejected(stager, 'new source would exceed complete name count bound')
            assert not stager.created and not module.DEST.exists()
            return {'forecast_reserves_source_name_before_mutation': True}

    def entry_budget():
        with fixture(module, bodies, ['a', 'b', 'c']) as (stager, _root, _external):
            with mock.patch.dict(module.LIMITS, {'directory_entries_observed': 2}):
                rejected(stager, 'directory enumeration entry bound exceeded')
            assert not stager.created and not module.DEST.exists()
            return {'global_scandir_entry_budget_rejected_before_mkdir': True}

    def name_byte_budget():
        with fixture(module, bodies, ['large-name-'+'x'*100]) as (stager, _root, _external):
            with mock.patch.dict(module.LIMITS, {'names_and_receipt_bytes': module.LIMITS['stdout_bytes']+40}):
                rejected(stager, 'directory name bytes exceed remaining bounded pool')
            assert not stager.created and not module.DEST.exists()
            return {'per_entry_byte_charge_rejected_before_mkdir': True}

    def fd_budget():
        with fixture(module, bodies) as (stager, _root, _external):
            with mock.patch.dict(module.LIMITS, {'owned_fds': 2}):
                rejected(stager, 'owned source-stage FD bound exceeded')
            assert not stager.created and not module.DEST.exists()
            return {'partial_parent_open_fds_closed': True}

    def deadline_budget():
        with fixture(module, bodies) as (stager, _root, _external):
            stager.budget.started -= module.LIMITS['seconds']+1
            rejected(stager, 'single source staging deadline exceeded')
            assert not stager.created and not module.DEST.exists()
            assert not issubclass(module.StageAlarm, OSError)
            return {'expired_operation_rejected_before_open': True, 'alarm_not_swallowed_by_oserror_cleanup': True}

    def real_nonmac_entry_rejects():
        assert sys.platform != 'darwin', 'this host regression specifically checks the non-Mac production gate'
        with tempfile.TemporaryDirectory(prefix='hepta-stage-entry-') as temporary:
            process = subprocess.run([sys.executable, '-I', '-B', '-c', (ROOT/'stage_sources_once.py').read_text()],
                input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=temporary, timeout=5)
            assert process.returncode == 1 and not process.stderr
            report = json.loads(process.stdout)
            assert report['state'] == 'REJECTED_BEFORE_STAGE' and report['created'] is False
            assert list(Path(temporary).iterdir()) == []
            return {'actual_production_entry_rejected_nonmac': True, 'stager_subprocesses_started': 0,
                    'local_test_harness_subprocesses': 1, 'mac_jobs_started': 0}

    def interrupted_close(use_bulk):
        with fixture(module, bodies) as (stager, _root, _external):
            fd = stager.open('/dev/null', os.O_RDONLY|os.O_CLOEXEC)
            actual_close = os.close
            def alarm_before_close(target):
                assert target == fd
                raise module.StageAlarm('synthetic alarm before close syscall completion')
            try:
                with mock.patch.object(module.os, 'close', alarm_before_close):
                    try:
                        stager.close() if use_bulk else stager.close_fd(fd)
                    except module.StageAlarm as error:
                        report = stager.failure(error)
                    else:
                        raise AssertionError('terminal alarm was swallowed')
                os.fstat(fd)  # The descriptor really remains open in this counterexample.
                assert not stager.fds and report['owned_fds_closed'] is False
                assert report['cleanup_errors'] and report['descriptor_operations_unresolved']
                assert report['descriptor_operations_unresolved'][0]['operation'] == 'remove-and-close'
                return {'real_fd_still_open_at_rejection': True, 'owned_fds_closed_claim': False,
                        'terminal_alarm_propagated': True, 'unknown_fd_not_retried': True}
            finally:
                actual_close(fd)  # Test harness owns this known synthetic descriptor.

    def interrupted_open():
        with fixture(module, bodies) as (stager, _root, _external):
            actual_open = os.open
            opened = []
            def acquire_then_alarm(*args, **kwargs):
                opened.append(actual_open(*args, **kwargs))
                raise module.StageAlarm('synthetic alarm after acquisition before registration')
            try:
                with mock.patch.object(module.os, 'open', acquire_then_alarm):
                    try:
                        stager.open('/dev/null', os.O_RDONLY|os.O_CLOEXEC)
                    except module.StageAlarm as error:
                        report = stager.failure(error)
                    else:
                        raise AssertionError('terminal acquisition alarm was swallowed')
                assert len(opened) == 1
                os.fstat(opened[0])
                assert not stager.fds and report['owned_fds_closed'] is False
                assert report['descriptor_operations_unresolved'][0]['operation'] == 'open-and-register'
                return {'real_unregistered_fd_at_rejection': True, 'owned_fds_closed_claim': False,
                        'terminal_alarm_propagated': True, 'unknown_fd_not_retried': True}
            finally:
                for fd in opened:
                    os.close(fd)  # The test, not the stager, retained these actual numbers.

    def interrupted_scandir():
        with fixture(module, bodies) as (stager, _root, _external):
            fd = stager.open(module.BASE, os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            original_scandir = os.scandir
            acquired = []
            def context_then_alarm(target):
                acquired.append(original_scandir(target))
                raise module.StageAlarm('synthetic alarm before scandir context registration')
            try:
                with mock.patch.object(module.os, 'scandir', context_then_alarm):
                    try:
                        stager.bounded_names(fd, maximum=4096, base_snapshot=True)
                    except module.StageAlarm as error:
                        stager.close()
                        report = stager.failure(error)
                    else:
                        raise AssertionError('terminal scandir alarm was swallowed')
                assert report['owned_fds_closed'] is False and not stager.fds
                assert report['descriptor_operations_unresolved'][0]['operation'] == 'scandir-context-acquire-use-close'
                return {'scandir_acquisition_uncertainty_retained': True, 'owned_fds_closed_claim': False,
                        'terminal_alarm_propagated': True}
            finally:
                for iterator in acquired:
                    iterator.close()

    result.extend([('existing_dangling_target_symlink', existing_symlink), ('changed_transport_rejected', corrupt_payload),
        ('unexpected_base_member_retained', extra_base_member), ('ancestor_full9_change', ancestor_changed),
        ('unexpected_source_member', source_extra_member), ('source_permission_change', source_permissions),
        ('source_directory_replacement', source_replacement), ('source_leaf_hardlink', leaf_hardlink),
        ('same_bytes_leaf_replacement_before_read', leaf_replacement_before_first_read),
        ('actual_partial_write_preserved', partial_write), ('complete_name_count_forecast', count_budget),
        ('global_enumeration_budget', entry_budget), ('name_bytes_charged_during_enumeration', name_byte_budget),
        ('owned_fd_budget_cleanup', fd_budget), ('operation_deadline', deadline_budget),
        ('production_nonmac_entry_guard', real_nonmac_entry_rejects),
        ('alarm_close_fd_truthful_unknown', lambda: interrupted_close(False)),
        ('alarm_bulk_close_truthful_unknown', lambda: interrupted_close(True)),
        ('alarm_open_before_registration_truthful_unknown', interrupted_open),
        ('alarm_scandir_acquisition_truthful_unknown', interrupted_scandir)])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    module, payload, bodies = load()
    source_before = (ROOT/'stage_sources_once.py').read_bytes()
    bindings = {key: getattr(module, key) for key in ('BASE', 'DEST', 'AUDIT_OUT', 'CALLER_OUT', 'OWNER_UID')}
    limits = dict(module.LIMITS)
    started = time.monotonic()
    results = []
    for name, fn in cases(module, payload, bodies):
        try:
            observation = fn()
            results.append({'name': name, 'passed': True, 'observation': observation})
        except BaseException as error:
            results.append({'name': name, 'passed': False, 'error_type': type(error).__name__,
                'error': str(error), 'traceback': traceback.format_exc()})
    assert source_before == (ROOT/'stage_sources_once.py').read_bytes()
    assert bindings == {key: getattr(module, key) for key in bindings} and limits == module.LIMITS
    report = {'schema': 'hepta.create-only-source-stager.local-regressions.v1',
        'status': 'PASS' if all(row['passed'] for row in results) else 'FAIL',
        'passed': sum(row['passed'] for row in results), 'failed': sum(not row['passed'] for row in results),
        'cases': results, 'source_sha256': sha(source_before), 'payload_sha256': sha(payload),
        'complete_source_imported': True, 'actual_pinned_payload_verified': True,
        'fixture_bindings': 'BASE/three fixed child paths and owner uid rebound only to private local fixtures; restored',
        'production_mac_main_called': False, 'mac_jobs_started': 0, 'phone_calls': 0,
        'remote_staging_performed': False, 'source_unchanged': True,
        'elapsed_seconds': time.monotonic()-started}
    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)+'\n'
    if args.output:
        args.output.write_text(raw)
    print(raw, end='')
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
