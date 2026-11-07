#!/usr/bin/env python3
"""Source-only controls for the exact successor; no ADB, SSH, phone or model I/O."""
from pathlib import Path
import argparse
import ast
import builtins
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

PACKAGE = Path(__file__).resolve().parent
REPO_ROOT = None
PREFIX = 'projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/'
SOCKET_SHA = '06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0'
CONFIG_SHA = '310dd82101f2ab309cd790d03f0c01e40cbdfef7064510ea4120327aaac72fef'
CONFIG_BYTES = 2416
CONFIG_PATH = '/home/alex/codex-preserved-ui-root12-materials-20261101-01/preserved-ui-package-config.json'
HELPER_DIR = '/home/alex/codex-razr60-r6-followthrough-20261107/deadline/candidate'
PRIVATE_PREFIX_RESULT = None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source_text(name):
    return (PACKAGE / 'candidate' / name).read_text()


def guard_namespace():
    source = source_text('control_send_once.py')
    tree = ast.parse(source)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name in ('_transport_config_identity', '_read_pinned_transport_config')]
    if len(functions) != 2:
        raise AssertionError('exact production config guard definitions not found')
    namespace = {'os': os, 'stat': stat, 'hashlib': hashlib}
    builtins.exec(compile(ast.Module(body=functions, type_ignores=[]), '<actual-config-guard>', 'exec'), namespace)
    return namespace


class RouteReached(Exception):
    pass


def observe_first_route(raw, *, synthetic_pin=False, symlink=False, hardlink=False,
                        replace_during_read=False, change_after_close=False):
    """Execute the actual actor prefix; stop at its first route call.

    Path redirection is only a fixture transport. The production prefix bytes are
    unchanged for real-config and mismatch controls. A synthetic positive changes
    only its expected config digest/length literals, and declares that distinction.
    The complete, pinned socket helper executes only its inert definitions; route
    is replaced immediately by a stop sentinel. Any socket/subprocess call fails.
    """
    import pathlib
    real_path = pathlib.Path
    source = source_text('control_send_once.py')
    prefix = source[:source.index('expected=')]
    actual_prefix_sha = digest(prefix.encode())
    if synthetic_pin:
        old = ',' + str(CONFIG_BYTES) + ',' + repr(CONFIG_SHA) + ')'
        new = ',' + str(len(raw)) + ',' + repr(digest(raw)) + ')'
        if prefix.count(old) != 1:
            raise AssertionError('one declared fixture pin substitution required')
        prefix = prefix.replace(old, new, 1)
    socket_bytes = (PACKAGE / 'candidate/preserved_ui_package_phase_r7.py').read_bytes()
    if digest(socket_bytes) != SOCKET_SHA:
        raise AssertionError('socket helper candidate changed')
    events = {'route_calls': 0, 'socket_calls': 0, 'subprocess_calls': 0,
              'module_execs': 0, 'config_parse_count': 0, 'config_opens': 0,
              'config_reads': 0, 'config_requested_bytes': 0}
    exception = None
    parsed_sha = None
    parsed_bytes_are_verified_object = False
    routed_value = None
    with tempfile.TemporaryDirectory(prefix='deadline-prefix-') as directory:
        temp = real_path(directory)
        helper = temp / 'helper'
        helper.mkdir()
        (helper / 'preserved_ui_package_phase_r7.py').write_bytes(socket_bytes)
        config = temp / 'config.json'
        config.write_bytes(raw)
        config.chmod(0o600)
        if symlink:
            target = temp / 'actual.json'
            config.rename(target)
            config.symlink_to(target)
        if hardlink:
            os.link(config, temp / 'config-alias.json')
        original_exec = builtins.exec
        original_loads = json.loads
        original_open = os.open
        original_read = os.read
        original_close = os.close
        descriptor = None
        replaced = False
        closed_replacement = False
        namespace = {'__name__': 'exact_actor_prefix_probe'}

        def redirected_path(value, *args, **kwargs):
            if str(value) == HELPER_DIR:
                return helper
            if str(value) == CONFIG_PATH:
                return config
            return real_path(value, *args, **kwargs)

        def route_stop(configuration):
            nonlocal routed_value
            events['route_calls'] += 1
            routed_value = configuration
            raise RouteReached()

        def definition_exec(code, globals_arg, locals_arg=None):
            original_exec(code, globals_arg, locals_arg)
            if globals_arg.get('__name__') != 'actual_app_fixed_turn':
                raise AssertionError('unexpected embedded module')
            events['module_execs'] += 1
            globals_arg['route'] = route_stop

        def forbidden_socket(*args, **kwargs):
            events['socket_calls'] += 1
            raise AssertionError('fixture attempted a real socket')

        def forbidden_process(*args, **kwargs):
            events['subprocess_calls'] += 1
            raise AssertionError('fixture attempted a real subprocess')

        def config_open(path, flags, *args, **kwargs):
            nonlocal descriptor
            if str(path) != str(config):
                raise AssertionError('unexpected descriptor read')
            events['config_opens'] += 1
            if not flags & os.O_NOFOLLOW:
                raise AssertionError('no-follow flag absent')
            descriptor = original_open(path, flags, *args, **kwargs)
            return descriptor

        def config_read(fd, count):
            nonlocal replaced
            if fd != descriptor:
                raise AssertionError('unexpected file descriptor')
            events['config_reads'] += 1
            events['config_requested_bytes'] += count
            data = original_read(fd, count)
            if replace_during_read and not replaced:
                replacement = temp / 'replacement.json'
                replacement.write_bytes(raw)
                os.replace(replacement, config)
                replaced = True
            return data

        def config_close(fd):
            nonlocal closed_replacement
            original_close(fd)
            if change_after_close and fd == descriptor and not closed_replacement:
                # A later pathname read would now consume the wrong body.
                with builtins.open(config, 'wb') as stream:
                    stream.write(b'x' * len(raw))
                closed_replacement = True

        def parse_verified(data, *args, **kwargs):
            nonlocal parsed_sha, parsed_bytes_are_verified_object
            events['config_parse_count'] += 1
            if not isinstance(data, bytes):
                raise AssertionError('configuration parser did not consume bytes')
            parsed_bytes_are_verified_object = data is namespace.get('_transport_config_raw')
            parsed_sha = digest(data)
            return original_loads(data, *args, **kwargs)

        namespace['exec'] = definition_exec
        try:
            with mock.patch.object(pathlib, 'Path', redirected_path), \
                 mock.patch.object(socket, 'create_connection', forbidden_socket), \
                 mock.patch.object(subprocess, 'run', forbidden_process), \
                 mock.patch.object(os, 'open', config_open), \
                 mock.patch.object(os, 'read', config_read), \
                 mock.patch.object(os, 'close', config_close), \
                 mock.patch.object(json, 'loads', parse_verified):
                original_exec(compile(prefix, '<exact-actor-prefix>', 'exec'), namespace)
        except RouteReached:
            pass
        except Exception as error:
            exception = type(error).__name__ + ': ' + str(error)
    return {
        'actual_prefix_sha256': actual_prefix_sha,
        'synthetic_config_pin_substitution': synthetic_pin,
        'events': events,
        'exception': exception,
        'parsed_config_sha256': parsed_sha,
        'parser_received_same_verified_bytes_object': parsed_bytes_are_verified_object,
        'routed_configuration_equals_verified_json': routed_value == json.loads(raw) if events['route_calls'] else False,
        'filesystem_identity_is_local_fixture': True,
        'actual_remote_file_descriptor_read': False,
        'phone_calls': 0,
    }


class DeadlineSuccessorTests(unittest.TestCase):
    def test_complete_source_derivation_and_unmodified_actor_logic(self):
        derivation = json.loads((PACKAGE / 'DERIVATION.json').read_bytes())
        self.assertIsNotNone(REPO_ROOT, 'tests require an exact reference checkout')
        originals = {}
        for row in derivation['originals']:
            raw = (Path(REPO_ROOT) / row['repository_path']).read_bytes()
            self.assertEqual(len(raw), row['bytes'])
            self.assertEqual(digest(raw), row['sha256'])
            originals[row['candidate_path']] = raw.decode()
        for row in derivation['candidate_sources']:
            raw = (PACKAGE / row['path']).read_bytes()
            self.assertEqual(len(raw), row['bytes'])
            self.assertEqual(digest(raw), row['sha256'])
        original_ui = originals['candidate/control_send_once.py']
        candidate_ui = source_text('control_send_once.py')
        self.assertEqual(original_ui[original_ui.index('expected='):],
                         candidate_ui[candidate_ui.index('expected='):])
        original_runtime = ast.parse(originals['candidate/send_new_native_guard_task_r10_r4.py'])
        candidate_runtime = ast.parse(source_text('send_new_native_guard_task_r10_r4.py'))

        def actor_program(tree):
            return [ast.dump(n, include_attributes=False) for n in tree.body
                    if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == 'source']

        self.assertEqual(actor_program(original_runtime), actor_program(candidate_runtime))
        for name in ('READ_ONLY_PROBE', 'LATENCY_OBSERVER'):
            def assigned(tree):
                return [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
            self.assertEqual(assigned(original_runtime), assigned(candidate_runtime))
        self.assertEqual(derivation['unchanged_external_pins']['sender_native_guard_ready_r10_r4.py'],
                         '97b28afd910280bbdb7a1061218f4d72fc4b9024669b1aba10b0bfdb6caf13b2')

    def test_direct_pin_cascade_and_config_pin_before_first_route(self):
        ui = source_text('control_send_once.py')
        runtime = source_text('send_new_native_guard_task_r10_r4.py')
        ui_sha = digest(ui.encode())
        self.assertEqual(runtime.count("assert hashlib.sha256(old.encode()).hexdigest()=='" + ui_sha + "'"), 1)
        self.assertNotIn('ca200ab35d39ec42232e853c785ab298958858cb4f03e2092231d1ccc638fc70', runtime)
        self.assertIn('stock16-hepta-control-deadline-Root-20261107-r1/control_send_once.py', runtime)
        self.assertEqual(ui.count(CONFIG_SHA), 1)
        self.assertEqual(ui.count(SOCKET_SHA), 1)
        self.assertLess(ui.index('_transport_config_raw=_read_pinned_transport_config('), ui.index('t=f.route(c)'))
        self.assertLess(ui.index('c=json.loads(_transport_config_raw)'), ui.index("exec(compile(b,str(p),'exec')"))
        self.assertLess(runtime.index('SOURCE_ONLY_SUCCESSOR_EXECUTION_LOCKED'), runtime.index('args.request_file.read_bytes()'))

    def test_actual_sender_ssh_budgets_preserve_both_component_and_production(self):
        derivation = json.loads((PACKAGE / 'DERIVATION.json').read_bytes())
        row = next(r for r in derivation['originals']
                   if r['candidate_path'] == 'candidate/send_new_native_guard_task_r10_r4.py')
        old = ast.parse((Path(REPO_ROOT) / row['repository_path']).read_bytes())
        new = ast.parse(source_text('send_new_native_guard_task_r10_r4.py'))

        def timeout_expression(tree):
            calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Attribute) and n.func.attr == 'run'
                     and isinstance(n.func.value, ast.Name) and n.func.value.id == 'subprocess'
                     and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id == 'ssh']
            self.assertEqual(len(calls), 1)
            values = [keyword.value for keyword in calls[0].keywords if keyword.arg == 'timeout']
            self.assertEqual(len(values), 1)
            return values[0]

        original_timeout = timeout_expression(old)
        candidate_timeout = timeout_expression(new)
        self.assertEqual(ast.dump(original_timeout), ast.dump(candidate_timeout))
        self.assertIsInstance(candidate_timeout, ast.IfExp)
        self.assertEqual(ast.literal_eval(candidate_timeout.body), 660)
        self.assertEqual(ast.literal_eval(candidate_timeout.orelse), 600)
        self.assertEqual(derivation['budgets_unchanged']['sender_ssh_component_seconds'], 660)
        self.assertEqual(derivation['budgets_unchanged']['sender_ssh_production_seconds'], 600)

    def test_mismatched_original_config_pin_rejects_before_module_or_route(self):
        raw = b'{' + b' ' * (CONFIG_BYTES - 2) + b'}'
        report = observe_first_route(raw)
        self.assertIn('transport_config_byte_pin_mismatch_before_route', report['exception'])
        self.assertEqual(report['events']['route_calls'], 0)
        self.assertEqual(report['events']['module_execs'], 0)
        self.assertEqual(report['events']['config_parse_count'], 0)
        self.assertEqual(report['events']['socket_calls'], 0)
        self.assertEqual(report['events']['subprocess_calls'], 0)

    def test_wrong_config_size_rejects_before_read_or_route(self):
        report = observe_first_route(b'{}')
        self.assertIn('identity_or_size_mismatch', report['exception'])
        self.assertEqual(report['events']['config_reads'], 0)
        self.assertEqual(report['events']['route_calls'], 0)

    def test_symlink_config_rejected_before_route(self):
        report = observe_first_route(b'{}', synthetic_pin=True, symlink=True)
        self.assertIsNotNone(report['exception'])
        self.assertEqual(report['events']['route_calls'], 0)
        self.assertEqual(report['events']['config_reads'], 0)

    def test_hardlinked_config_rejected_before_route(self):
        report = observe_first_route(b'{}', synthetic_pin=True, hardlink=True)
        self.assertIn('identity_or_size_mismatch', report['exception'])
        self.assertEqual(report['events']['route_calls'], 0)

    def test_named_file_replacement_rejected_before_route(self):
        report = observe_first_route(b'{"route":"fixture"}', synthetic_pin=True, replace_during_read=True)
        self.assertIn('changed_during_read', report['exception'])
        self.assertEqual(report['events']['route_calls'], 0)
        self.assertEqual(report['events']['config_parse_count'], 0)

    def test_positive_synthetic_config_reaches_only_first_route(self):
        report = observe_first_route(b'{"route":"fixture"}', synthetic_pin=True)
        self.assertIsNone(report['exception'])
        self.assertEqual(report['events']['route_calls'], 1)
        self.assertEqual(report['events']['module_execs'], 1)
        self.assertEqual(report['events']['config_parse_count'], 1)
        self.assertEqual(report['events']['config_opens'], 1)
        self.assertTrue(report['parser_received_same_verified_bytes_object'])
        self.assertTrue(report['routed_configuration_equals_verified_json'])
        self.assertEqual(report['events']['socket_calls'], 0)
        self.assertEqual(report['events']['subprocess_calls'], 0)

    def test_late_path_content_change_does_not_change_parsed_verified_bytes(self):
        raw = b'{"route":"verified-before-close"}'
        report = observe_first_route(raw, synthetic_pin=True, change_after_close=True)
        self.assertIsNone(report['exception'])
        self.assertEqual(report['events']['route_calls'], 1)
        self.assertEqual(report['events']['config_opens'], 1)
        self.assertEqual(report['parsed_config_sha256'], digest(raw))
        self.assertTrue(report['parser_received_same_verified_bytes_object'])
        self.assertTrue(report['routed_configuration_equals_verified_json'])

    def test_descriptor_metadata_change_rejected(self):
        function = guard_namespace()['_read_pinned_transport_config']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            raw = b'{}'
            path.write_bytes(raw)
            real_fstat = os.fstat
            calls = []

            def changed(fd):
                info = real_fstat(fd)
                calls.append(fd)
                if len(calls) == 2:
                    fields = {key: getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                                                                  'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                    fields['st_mtime_ns'] += 1
                    return types.SimpleNamespace(**fields)
                return info

            with mock.patch.object(os, 'fstat', changed):
                with self.assertRaisesRegex(RuntimeError, 'changed_during_read'):
                    function(path, len(raw), digest(raw))

    def test_non_regular_config_rejected_without_content_read(self):
        function = guard_namespace()['_read_pinned_transport_config']
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(os, 'read', side_effect=AssertionError('directory content read')):
                with self.assertRaisesRegex(RuntimeError, 'identity_or_size_mismatch'):
                    function(Path(directory), 2, digest(b'{}'))

    def test_mismatched_file_owner_rejected_without_content_read(self):
        function = guard_namespace()['_read_pinned_transport_config']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_bytes(b'{}')
            wrong_owner = os.getuid() + 1
            with mock.patch.object(os, 'getuid', return_value=wrong_owner), \
                 mock.patch.object(os, 'read', side_effect=AssertionError('unowned content read')):
                with self.assertRaisesRegex(RuntimeError, 'identity_or_size_mismatch'):
                    function(path, 2, digest(b'{}'))

    def test_execute_flag_refused_before_runtime_input_read(self):
        with tempfile.TemporaryDirectory() as directory:
            absent = str(Path(directory) / 'intentionally-absent')
            command = [sys.executable, '-I', '-B', str(PACKAGE / 'candidate/send_new_native_guard_task_r10_r4.py'),
                       'fixture-source-only-lock', absent, absent, '--preserved-draft', absent,
                       '--retirement-resolution', absent, '--component-contract', absent,
                       '--component-package', absent, '--component-package-sha256', '0' * 64, '--execute-once']
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'SOURCE_ONLY_SUCCESSOR_EXECUTION_LOCKED', result.stderr)
            self.assertNotIn(b'FileNotFoundError', result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_exact_socket_and_full_route_controls(self):
        navigation = Path(REPO_ROOT) / PREFIX / 'verification-20261107/navigation'
        with tempfile.TemporaryDirectory() as directory:
            timeout_result = Path(directory) / 'timeout.json'
            route_result = Path(directory) / 'route.json'
            command = [sys.executable, '-I', '-B', str(navigation / 'reproduce_sender_timeout.py'),
                       '--original', str(navigation / 'dependencies/preserved_ui_package_phase_r7.py'),
                       '--candidate', str(PACKAGE / 'candidate/preserved_ui_package_phase_r7.py'),
                       '--candidate-sha256', SOCKET_SHA, '--out', str(timeout_result)]
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            timeout = json.loads(timeout_result.read_bytes())
            self.assertEqual(timeout['candidate_controls_passed'], 5)
            self.assertEqual(timeout['phone_calls'], 0)
            command = [sys.executable, '-I', '-B', str(navigation / 'check_route_deadline.py'),
                       '--candidate', str(PACKAGE / 'candidate/preserved_ui_package_phase_r7.py'),
                       '--out', str(route_result)]
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            route = json.loads(route_result.read_bytes())
            self.assertEqual(route['passed'], 2)
            self.assertEqual(route['controls'][1]['effect_service_requests'], 0)


def find_private_config_bytes(envelope):
    matches = []

    def walk(value, depth=0):
        if depth > 12:
            return
        if isinstance(value, dict):
            for child in value.values():
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                walk(child, depth + 1)
        elif isinstance(value, str):
            raw = value.encode()
            if len(raw) == CONFIG_BYTES and digest(raw) == CONFIG_SHA:
                matches.append(raw)
            elif value[:1] in ('{', '['):
                try:
                    parsed = json.loads(value)
                except ValueError:
                    return
                walk(parsed, depth + 1)

    walk(envelope)
    if not matches or any(raw != matches[0] for raw in matches):
        raise RuntimeError('private config envelope did not contain the exact pinned original')
    return matches[0]


def load_suite(repo_root):
    """Use the ordinary unittest suite from an explicit exact reference checkout."""
    global REPO_ROOT
    REPO_ROOT = Path(repo_root).resolve()
    return unittest.defaultTestLoader.loadTestsFromTestCase(DeadlineSuccessorTests)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', required=True, type=Path)
    parser.add_argument('--private-config-mcp', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        raise RuntimeError('output exists; do not overwrite an earlier control result')
    suite = load_suite(args.repo_root)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {'schema': 'razr60.deadline-successor-focused-controls.v1', 'tests_run': result.testsRun,
              'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
              'passed': result.wasSuccessful(), 'socket_controls': 5, 'route_controls': 2,
              'private_original_config_prefix_control': None,
              'phone_calls': 0, 'native_dispatches': 0, 'installation_performed': False, 'fixed19_credit': 0}
    if args.private_config_mcp:
        raw = find_private_config_bytes(json.loads(args.private_config_mcp.read_bytes()))
        private_report = observe_first_route(raw)
        if (private_report['exception'] is not None or private_report['events']['route_calls'] != 1
                or private_report['events']['socket_calls'] != 0 or private_report['events']['subprocess_calls'] != 0
                or not private_report['parser_received_same_verified_bytes_object']
                or private_report['parsed_config_sha256'] != CONFIG_SHA):
            raise AssertionError('actual pinned configuration did not reach exactly the guarded first route')
        report['private_original_config_prefix_control'] = private_report
    with args.out.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(report))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
