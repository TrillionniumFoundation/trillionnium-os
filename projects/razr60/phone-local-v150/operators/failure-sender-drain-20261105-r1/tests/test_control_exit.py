#!/usr/bin/env python3
"""Exercise failure cleanup control exits with real local sender children.

The supplied source is hash-pinned before import. Only fixture admission,
construction and the would-be remote run body are substituted. Its real main
failure handler and all capture/cleanup methods execute. Control exceptions
are injected into the original child's wait method only after the exact join
method has been entered; no operating-system signal is sent.

Raw test records must be written outside this script's package directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import types

sys.dont_write_bytecode = True


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_row(path):
    raw = Path(path).read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def put_json(path, value):
    with Path(path).open('x') as out:
        json.dump(value, out, ensure_ascii=False, sort_keys=True, indent=2)
        out.write('\n')


def test(args):
    source = args.source.resolve(strict=True)
    raw = source.read_bytes()
    assert sha(raw) == args.source_sha256
    out = args.out.absolute()
    package = Path(__file__).resolve().parent
    if package.name == 'tests':
        package = package.parent
    assert not out.is_relative_to(package), 'raw records must remain outside the public package'
    assert out.parent.resolve(strict=True) == out.parent
    out.mkdir(mode=0o700)
    fixture = out / 'local_sender.py'
    fixture_raw = b'''import os,sys,time
from pathlib import Path
ready,done=sys.argv[1:]
def write(fd,data):
    try:os.write(fd,data)
    except BrokenPipeError:pass
write(1,b"sender prefix out\\n");write(2,b"sender prefix err\\n")
Path(ready).write_text("ready\\n")
time.sleep(.30)
write(1,b"sender terminal out\\n");write(2,b"sender terminal err\\n")
Path(done).write_text("completed naturally\\n")
'''
    fixture.write_bytes(fixture_raw)
    allowed = []
    audit_rows = {'subprocess_starts': [], 'prohibited_events': []}

    def audit(event, values):
        if event.startswith('socket.') or event in (
                'os.kill', 'os.killpg', 'os.fork', 'os.forkpty', 'os.system',
                'os.exec', 'os.posix_spawn', 'os.posix_spawnp', 'signal.pidfd_send_signal'):
            audit_rows['prohibited_events'].append(event)
            raise AssertionError('prohibited fixture event: ' + event)
        if event == 'subprocess.Popen':
            executable, argv, cwd, env = values
            assert allowed and list(argv) == allowed.pop(0)
            assert executable == sys.executable and cwd is None and env is None
            assert fixture.read_bytes() == fixture_raw
            audit_rows['subprocess_starts'].append(list(argv))
        if event == 'open' and isinstance(values[0], (str, bytes, os.PathLike)):
            flags = values[2]
            if isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
                path = Path(os.fsdecode(values[0])).absolute()
                assert path == Path('/dev/null') or path.is_relative_to(out)
        if event == 'os.mkdir':
            assert Path(os.fsdecode(values[0])).absolute().is_relative_to(out)

    sys.addaudithook(audit)

    def wait_file(path):
        until = time.monotonic() + 3
        while not path.is_file():
            assert time.monotonic() < until
            time.sleep(.005)

    def case(name, injection, when):
        mod = types.ModuleType('local_control_fixture_' + name.replace('-', '_'))
        mod.__file__ = str(source)
        exec(compile(raw, str(source), 'exec'), mod.__dict__)
        real_chain = mod.Chain
        root = out / name
        root.mkdir(mode=0o700)
        ready, done = root / 'ready', root / 'done'
        argv = [sys.executable, '-I', '-B', str(fixture), str(ready), str(done)]
        allowed.append(argv)
        seen = {'join_entries': 0, 'injection_count': 0}

        def deny(*unused, **ignored):
            raise AssertionError('no remote method may run in a local fixture')

        for method in ('remote', 'phone', 'bridge_call', 'remote_files',
                       'remote_read', 'remote_program', 'push_copy', 'frozen_phone'):
            setattr(real_chain, method, deny)

        class LocalFailure(real_chain):
            def __init__(self, plan, plan_raw):
                self.p, self.out = plan, Path(plan['out'])
                mod.newdir(self.out)
                mod.put(self.out / 'ROOT-PLAN.original.json', plan_raw)
                self.steps, self.root_attempts, self.sender = [], [], None
                seen['chain'] = self

            def join_host_capture(self, phase, child, maximum_wait=None):
                assert phase == 'sender-execute' and child is seen['child']
                seen['join_entries'] += 1
                return real_chain.join_host_capture(self, phase, child, maximum_wait=maximum_wait)

            def run(self):
                self.sender = self.execute_process('sender-execute', argv, 2.0, async_start=True)
                child = self.sender[0]
                seen['child'] = child
                seen['deadline'] = self._owned_host_deadlines['sender-execute']
                wait_file(ready)
                if when == 'during-drain':
                    original_wait = child.wait

                    def interrupt_wait(timeout=None):
                        assert seen['join_entries'] == 1
                        assert self._owned_host_children['sender-execute'] is child
                        child.wait = original_wait
                        seen['injection_count'] += 1
                        raise injection

                    child.wait = interrupt_wait
                phase_error = (injection if when == 'initial-control' else
                    ValueError('fixture original phase rejection'))
                seen['phase_error'] = phase_error
                seen['failure_started'] = time.monotonic()
                raise phase_error

        mod.Chain = LocalFailure
        plan = {'out': str(root / 'root-output'), 'local_fixture_only': True}
        plan_raw = json.dumps(plan, sort_keys=True).encode()
        plan_path = root / 'FIXTURE-PLAN.json'
        plan_path.write_bytes(plan_raw)
        mod.validate_plan = lambda value: (plan, {}) if value == plan_raw else deny()
        old_argv = sys.argv
        sys.argv = [str(source), '--plan', str(plan_path), '--plan-sha256', sha(plan_raw),
                    '--execute-root-chain-once']
        caught = None
        try:
            mod.main()
        except BaseException as error:
            caught = error
        finally:
            sys.argv = old_argv
        elapsed = time.monotonic() - seen['failure_started']
        assert elapsed < 1.0
        phase_error = seen['phase_error']
        is_drain_control = when == 'during-drain' and not isinstance(injection, Exception)
        expected = injection if is_drain_control else phase_error
        assert caught is expected, 'the original exception object must be propagated'
        if is_drain_control:
            assert caught.__cause__ is phase_error
        if isinstance(expected, SystemExit):
            assert caught.code == expected.code
        fail_path = root / 'root-output' / 'ROOT-FAILURE.json'
        failure = json.loads(fail_path.read_bytes())
        assert failure['error_type'] == type(phase_error).__name__
        assert failure['detail'] == str(phase_error)
        assert failure['component_qualified'] is False and failure['business_qualified'] is False
        assert failure['automatic_retry'] is False and failure['send_again'] is False
        assert failure['signals_sent_by_coordinator'] == 0
        cleanup = failure['host_cleanup']
        assert not cleanup['stream_cleanup_errors']
        capture = cleanup['host_children'][0]['output_capture']
        drain = cleanup['sender_failure_drain']
        assert capture['worker_joined'] is True and capture['pipe_reader_owner'] == 'closed_by_worker'
        assert capture['remote_terminal_or_cleanup_proven'] is False
        assert seen['chain']._owned_host_deadlines['sender-execute'] == seen['deadline']
        assert capture['execution_deadline_monotonic'] == seen['deadline']
        assert not (root / 'root-output' / 'ROOT-RESULT.json').exists()
        assert not (root / 'root-output' / 'sender-execute' / 'RESULT.json').exists()
        if when == 'no-injection':
            assert seen['join_entries'] == 1 and seen['injection_count'] == 0
            assert capture['child_wait_returned'] is True and capture['child_returncode'] == 0
            assert capture['stdout_eof'] is True and capture['stderr_eof'] is True
            assert capture['prefix_only_or_unknown'] is False
            assert drain['state'] == 'ORIGINAL_SENDER_JOINED_OUTPUT_COMPLETE_ROOT_STILL_FAILED'
        else:
            assert capture['child_wait_returned'] is False and capture['child_returncode'] is None
            assert capture['prefix_only_or_unknown'] is True
            assert not (capture['stdout_eof'] and capture['stderr_eof'])
            if when == 'during-drain':
                assert seen['join_entries'] == seen['injection_count'] == 1
                assert drain['error_type'] == type(injection).__name__
            else:
                assert seen['join_entries'] == seen['injection_count'] == 0
                assert drain['state'] == 'NOT_REQUESTED'
        if is_drain_control:
            assert drain['control_exit_pending'] is True
            assert failure['control_exit_after_cleanup']['error_type'] == type(injection).__name__
            assert failure['control_exit_after_cleanup']['original_phase_failure_preserved'] is True
        else:
            assert 'control_exit_after_cleanup' not in failure
            assert getattr(seen['chain'], '_failure_drain_control_exit', None) is None
        for stream in ('stdout', 'stderr'):
            desc = capture['files'][stream]
            assert {key: desc[key] for key in ('path', 'bytes', 'sha256')} == file_row(desc['path'])
        failure_raw = fail_path.read_bytes()
        actual_rc = seen['child'].wait(timeout=3.0)
        assert actual_rc == 0
        wait_file(done)
        assert fail_path.read_bytes() == failure_raw
        assert not any(t.name.startswith('hepta-host-capture-') for t in threading.enumerate())
        row = {'name': name, 'state': 'PASS', 'elapsed_seconds': elapsed,
            'source_sha256': args.source_sha256,
            'original_exception_object_preserved': True,
            'original_phase_failure_recorded': True,
            'phase_failure_is_explicit_cause': is_drain_control,
            'control_exit_type': type(expected).__name__,
            'system_exit_code': expected.code if isinstance(expected, SystemExit) else None,
            'join_entries': seen['join_entries'], 'control_injections': seen['injection_count'],
            'original_deadline_unchanged': True, 'reader_worker_joined_before_propagation': True,
            'root_failure': file_row(fail_path),
            'output_capture': file_row(root / 'root-output' / 'sender-execute' / 'OUTPUT-CAPTURE.json'),
            'historical_handler_child_wait': capture['child_wait_returned'],
            'both_eof': capture['stdout_eof'] and capture['stderr_eof'],
            'later_harness_natural_wait_rc': actual_rc,
            'later_harness_wait_not_substituted_for_handler_wait': True,
            'signals_sent': 0, 'phone_terminal_inferred': False}
        put_json(root / 'TEST-RESULT.json', row)
        print(json.dumps({'case': name, 'state': 'PASS', 'elapsed_seconds': elapsed}), flush=True)
        return row

    cases = [
        case('keyboard-interrupt-during-drain', KeyboardInterrupt('fixture drain control'), 'during-drain'),
        case('system-exit-during-drain', SystemExit(23), 'during-drain'),
        case('ordinary-drain-error-keeps-phase-failure', OSError('fixture wait error'), 'during-drain'),
        case('initial-keyboard-interrupt-skips-drain', KeyboardInterrupt('fixture initial control'), 'initial-control'),
        case('initial-system-exit-skips-drain', SystemExit(19), 'initial-control'),
        case('ordinary-phase-failure-with-complete-sender', None, 'no-injection'),
    ]
    assert source.read_bytes() == raw and not allowed
    assert len(audit_rows['subprocess_starts']) == len(cases) and not audit_rows['prohibited_events']
    report = {'schema': 'hepta.failure-sender-drain.control-regression.v1',
        'state': 'PASS_WITH_SCOPE_LIMITS', 'source': file_row(source),
        'cases_passed': len(cases), 'cases': cases,
        'scope': 'Real local children and exact main/capture cleanup code with fixture-only admission and run; deterministic exceptions after entering original join; no physical signal or remote qualification.',
        'network_calls': 0, 'remote_calls': 0, 'phone_calls': 0, 'signals_sent': 0,
        'capture_threads_remaining': 0, 'original_source_unchanged': True,
        'deadline_logic_modified': False, 'long_30_second_case_repeated': False,
        'audit': audit_rows, 'component_qualified': False, 'business_qualified': False}
    put_json(out / 'RESULT.json', report)
    print(json.dumps({'state': report['state'], 'cases_passed': len(cases),
        'source_sha256': args.source_sha256}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    test(parser.parse_args())


if __name__ == '__main__':
    main()
