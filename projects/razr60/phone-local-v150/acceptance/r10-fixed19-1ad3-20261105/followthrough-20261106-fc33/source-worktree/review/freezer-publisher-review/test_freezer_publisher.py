#!/usr/bin/env python3
"""Narrow host controls for the exact reviewed R5 publisher transformation.

All file payloads are synthetic.  This calls publisher(), never freezer.main().
The one injected EIO is a host fault callback, not a physical or controller run.
Failed publication artifacts remain in the fresh output for inspection.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys
import threading
import types

EXPECTED_FREEZER = (21026, '7f1664543e61fcea20124173e5d9ff6745c41ffec8fd00c97df61a3e05d108be')
EXPECTED_PARENT = (16399, '842f893107dfff481e516419da3fd9b1e2c2445378903012658530d83429ac82')
KEYS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')


def check(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def full9(path):
    value = path.lstat()
    return [getattr(value, key) for key in KEYS]


def snapshot(root):
    result = {}
    for path in sorted([root, *root.rglob('*')]):
        name = '.' if path == root else str(path.relative_to(root))
        value = {'full9': full9(path)}
        if path.is_file():
            value.update(pin(path.read_bytes()))
        result[name] = value
    return result


def resources():
    fd_root = '/proc/self/fd' if Path('/proc/self/fd').is_dir() else '/dev/fd'
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'fd_count': len(os.listdir(fd_root)),
            'thread_ids': sorted(thread.ident for thread in threading.enumerate()),
            'child_user_cpu': usage.ru_utime, 'child_system_cpu': usage.ru_stime}


def deny_external_effect(event, args):
    if event.startswith(('subprocess.', 'socket.')) or event in {
            'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn',
            'os.exec', 'os.kill', 'os.killpg'}:
        raise AssertionError('host control attempted an excluded effect: ' + event)


class ObservedOS:
    """Forward the actual os calls; optional fault is before terminal creation."""
    def __init__(self, fault=None):
        self.fault = fault
        self.write_order = []
        self.opened = []
        self.closed = []
        self.fault_count = 0

    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, path, flags, *args, **kwargs):
        if flags & os.O_WRONLY:
            self.write_order.append(str(path))
            if str(path) == 'DERIVATION.json' and self.fault is not None:
                self.fault_count += 1
                raise self.fault
        fd = os.open(path, flags, *args, **kwargs)
        self.opened.append(fd)
        return fd

    def close(self, fd):
        self.closed.append(fd)
        return os.close(fd)


def main():
    check(len(sys.argv) == 4, 'usage: test_freezer_publisher.py FREEZER PUBLISHER FRESH_OUTPUT')
    freezer_path, parent_path, output = map(Path, sys.argv[1:])
    check(all(path.is_absolute() for path in (freezer_path, parent_path, output)), 'absolute paths')
    freezer_raw = freezer_path.read_bytes()
    parent_raw = parent_path.read_bytes()
    check((len(freezer_raw), pin(freezer_raw)['sha256']) == EXPECTED_FREEZER, 'exact reviewed freezer')
    check((len(parent_raw), pin(parent_raw)['sha256']) == EXPECTED_PARENT, 'exact reviewed publisher parent')
    source_before = {str(p): {'full9': full9(p), **pin(p.read_bytes())}
                     for p in (freezer_path, parent_path)}
    check(not os.path.lexists(output), 'fresh isolated host output')
    output.mkdir(mode=0o700)
    baseline = resources()
    previous_bytecode = sys.dont_write_bytecode
    sys.addaudithook(deny_external_effect)
    module = types.ModuleType('review_freezer_without_main')
    module.__file__ = str(freezer_path)
    exec(compile(freezer_raw, str(freezer_path), 'exec'), module.__dict__)
    publish, derivation, body = module.publisher(parent_raw)
    check(derivation['exact_whole_function_inverse'] is True, 'whole-function inverse')
    check(derivation['only_directory_inventory_and_bounds_changed'] is True, 'closed publisher delta')
    check(module.REVIEWED_INPUTS is None, 'source remains unbound')
    check(module._PUBLICATION is False, 'freezer main/publication phase not entered')
    cases = []

    def passed(name, **details):
        cases.append({'name': name, 'passed': True, **details})

    terminal = encode({'state': 'SYNTHETIC_HOST_PUBLISHER_CONTROL',
                       'all_output_files_read_back': True, 'full19_qualified': False})
    files = {
        'z-history/a/b/c/original.bin': b'\x00\x01 synthetic retained original\n',
        'runtime/source/deep/consumer.py': b'# synthetic, never imported\n',
        'shared/provider/source/x.py': b'# synthetic source\n',
        'FREEZE-RESULT.json': terminal,
        'DERIVATION.json': terminal,
        'A.txt': '中文 / 😀\nHEPTA\n'.encode(),
    }
    good_os = ObservedOS()
    publish.__globals__['os'] = good_os
    good = output / 'nested-success'
    publish(good, files)
    expected_dirs = {str(parent) for name in files for parent in Path(name).parents
                     if str(parent) != '.'}
    actual_files = {str(path.relative_to(good)): path.read_bytes()
                    for path in good.rglob('*') if path.is_file()}
    actual_dirs = {str(path.relative_to(good)) for path in good.rglob('*') if path.is_dir()}
    check(actual_files == files and actual_dirs == expected_dirs, 'complete nested tree and bytes')
    check(all(stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
              for path in (good, *good.rglob('*'))), 'private output modes')
    check(good_os.write_order[-1] == 'DERIVATION.json'
          and good_os.write_order.count('DERIVATION.json') == 1, 'one terminal-last creation')
    check(resources() == baseline, 'successful publisher resources returned')
    passed('nested_complete_tree_terminal_last', files=len(files), directories=1 + len(expected_dirs),
           write_order=good_os.write_order, whole_bytes_read_back=True)

    invalid = [
        ('absolute_member', {str(output / 'escape.bin'): b'x'}),
        ('parent_traversal', {'../escape.bin': b'x'}),
        ('noncanonical_double_slash', {'nested//x.bin': b'x'}),
        ('file_directory_collision', {'nested': b'x', 'nested/x.bin': b'y'}),
        ('directory_budget', {'/'.join(['p'] * 129) + '/x.bin': b'x'}),
        ('file_count_budget', {f'f{n:03d}.bin': b'x' for n in range(256)}),
    ]
    for name, extra in invalid:
        target = output / ('rejected-' + name)
        try:
            publish(target, {'DERIVATION.json': terminal, **extra})
        except ValueError as error:
            message = str(error)
        else:
            raise AssertionError('invalid map accepted: ' + name)
        check(not os.path.lexists(target), 'refusal before output mkdir: ' + name)
        check(not (output / 'escape.bin').exists(), 'escaped file absent')
        check(resources() == baseline, 'refusal resources returned: ' + name)
        passed(name, rejected_before_output_mkdir=True, error=message)

    fault = OSError(5, 'synthetic host fault before terminal creation')
    fail_os = ObservedOS(fault)
    publish.__globals__['os'] = fail_os
    failed = output / 'retained-terminal-failure'
    try:
        publish(failed, files)
    except OSError as error:
        check(error is fault, 'original injected exception object propagated')
    else:
        raise AssertionError('terminal creation fault accepted')
    check(fail_os.fault_count == 1, 'one fault with no internal retry')
    check((failed / 'FREEZE-RESULT.json').read_bytes() == terminal, 'early FREEZE retained')
    check(not (failed / 'DERIVATION.json').exists(), 'terminal absent after failed creation')
    check({str(path.relative_to(failed)): path.read_bytes()
           for path in failed.rglob('*') if path.is_file()}
          == {name: raw for name, raw in files.items() if name != 'DERIVATION.json'},
          'all ordinary payloads retained, none removed or rewritten')
    check(resources() == baseline, 'failure closes all descriptors')
    before_retry = snapshot(failed)
    passed('terminal_creation_eio_retains_incomplete_tree',
           synthetic_fault_callback=True, exact_exception_propagated=True,
           early_FREEZE_present=True, DERIVATION_present=False,
           fault_count=fail_os.fault_count, no_automatic_cleanup=True,
           write_order=fail_os.write_order)

    publish.__globals__['os'] = ObservedOS()
    try:
        publish(failed, files)
    except FileExistsError as error:
        retry_error = str(error)
    else:
        raise AssertionError('existing incomplete output admitted')
    check(snapshot(failed) == before_retry, 'retry refusal preserves every full9 and byte')
    check(resources() == baseline, 'retry refusal resources returned')
    passed('existing_incomplete_output_refuses_restart', error=retry_error,
           full9_and_bytes_unchanged=True)

    source_after = {str(p): {'full9': full9(p), **pin(p.read_bytes())}
                    for p in (freezer_path, parent_path)}
    check(source_before == source_after, 'exact source full9 and bytes preserved')
    sys.dont_write_bytecode = previous_bytecode
    final_resources = resources()
    check(final_resources == baseline, 'final resource baseline')
    passed('source_originals_and_resources_unchanged', source_full9_and_bytes_unchanged=True,
           before=baseline, after=final_resources)
    result = {
        'schema': 'fc33.r5.publisher.narrow-host-review.v1',
        'status': 'PASS', 'passed': len(cases), 'total': len(cases), 'cases': cases,
        'script': {'path': str(Path(__file__).resolve()), **pin(Path(__file__).read_bytes())},
        'freezer': {'path': str(freezer_path), **pin(freezer_raw)},
        'parent_publisher': {'path': str(parent_path), **pin(parent_raw)},
        'publisher_derivation': derivation, 'derived_publisher_body': pin(body),
        'source_originals': source_before,
        'retained_outputs': {'success': snapshot(good), 'failed': snapshot(failed)},
        'limits': [
            'All payloads are synthetic; the EIO is an explicitly injected host callback.',
            'No freezer main, actual runtime publication, controller admission, nonce, device, model or native dispatch ran.',
            'Only nested directory derivation, added bounds, retained failure and descriptor cleanup were exercised.',
            'FREEZE-RESULT alone is not success: a failed publisher can leave it and its optimistic flags intact.',
            'Consumption requires independently successful actual controller evidence, both identical terminal copies and complete file readback.',
            'These controls do not qualify any physical acceptance case or replace the preparer consumer gates.',
        ],
    }
    raw = encode(result)
    with (output / 'RESULT.json').open('xb') as handle:
        handle.write(raw)
    print(json.dumps({'status': result['status'], 'passed': len(cases),
                      'result': {'path': str(output / 'RESULT.json'), **pin(raw)},
                      'phone_calls': 0, 'native_dispatches': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
