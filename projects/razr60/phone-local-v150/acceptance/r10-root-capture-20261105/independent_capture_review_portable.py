#!/usr/bin/env python3
"""Real local process checks for the exact Root transport source under review.

No phone, network, signals, copied runtime implementation, or effect replay.
All fixture processes have a short natural lifetime; failed transport ownership
is inspected before the harness joins only its own fixed fixture child.
"""
import argparse
import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import types


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def fds():
    root = Path('/proc/self/fd') if Path('/proc/self/fd').is_dir() else Path('/dev/fd')
    result = set()
    for name in os.listdir(root):
        if not name.isdecimal():
            continue
        try:
            os.fstat(int(name))
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            result.add(int(name))
    return result


def threads():
    return {t.ident for t in threading.enumerate() if t.is_alive()}


def load_source(source):
    raw = source.read_bytes()
    module = types.ModuleType('independent_exact_root_transport_review')
    module.__file__ = str(source)
    exec(compile(raw, str(source), 'exec'), module.__dict__)
    tree = ast.parse(raw)
    chain = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Chain')
    run = next(n for n in chain.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
    def sender_tuple(node):
        return (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Tuple)
                and all(isinstance(part, ast.Name) for part in node.targets[0].elts)
                and [part.id for part in node.targets[0].elts] == ['child','d','so','se']
                and isinstance(node.value, ast.Attribute) and node.value.attr == 'sender'
                and isinstance(node.value.value, ast.Name) and node.value.value.id == 'self')
    def following_sender_read(node):
        return (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'sent'
                and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                and node.value.func.id == 'strict' and len(node.value.args) == 1
                and isinstance(node.value.args[0], ast.Call)
                and isinstance(node.value.args[0].func, ast.Name)
                and node.value.args[0].func.id == 'read')
    starts = [i for i, node in enumerate(run.body) if sender_tuple(node)]
    ends = [i for i, node in enumerate(run.body) if following_sender_read(node)]
    assert len(starts) == len(ends) == 1 and starts[0] < ends[0]
    start, end = starts[0], ends[0]
    fragment = ast.FunctionDef(
        name='actual_sender_join_only',
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg='self')], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=run.body[start:end] + [ast.Return(value=ast.Name(id='rc', ctx=ast.Load()))],
        decorator_list=[],
    )
    subset = ast.fix_missing_locations(ast.Module(body=[fragment], type_ignores=[]))
    exec(compile(subset, str(source), 'exec'), module.__dict__)
    return module, raw, sha(ast.dump(subset, include_attributes=False).encode())


def wait_fixture_file(path, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return True
        time.sleep(.005)
    return path.is_file()


def run_case(source, evidence, name, script, budget, expected_stdout=None,
             expected_stderr=None, asynchronous=False, prejoin_marker=None,
             expects_error=False, minimum_seconds=0, max_seconds=None,
             descendant_done=None, payload=None):
    m, raw, join_ast_sha = load_source(source)
    out = evidence/name
    out.mkdir(mode=0o700)
    obj = m.Chain.__new__(m.Chain)
    obj.out = out
    obj.steps = []
    children = []
    held = []
    original_stream = m.original_stream

    def guarded_popen(argv, **kwargs):
        assert argv[0] == sys.executable and argv[1:4] == ['-I', '-B', '-c'], argv
        assert kwargs.get('start_new_session') is True and kwargs.get('close_fds') is True
        assert len(children) == 0, 'one fixture launch only'
        child = subprocess.Popen(argv, **kwargs)
        children.append(child)
        return child

    def tracked_stream(path):
        stream = original_stream(path)
        held.append(stream)
        return stream

    m.original_stream = tracked_stream
    m.subprocess = types.SimpleNamespace(
        Popen=guarded_popen, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE,
        TimeoutExpired=subprocess.TimeoutExpired,
    )
    before_fds, before_threads = fds(), threads()
    phase = 'sender-execute' if asynchronous else 'phase'
    directory = out/phase
    argv = [sys.executable, '-I', '-B', '-c', script]
    start = time.monotonic()
    error = None
    value = None
    execute_seconds = None
    ready_before_join = None
    cleanup = None
    checks = []
    try:
        try:
            value = obj.execute_process(phase, argv, budget, payload, async_start=asynchronous)
            execute_seconds = time.monotonic() - start
            if asynchronous:
                assert len(value) == 4 and value[0] is children[0], 'raw async ABI changed'
                assert (directory/'CHILD.json').is_file(), 'identity not persisted at async return'
                if prejoin_marker is not None:
                    ready_before_join = wait_fixture_file(prejoin_marker, .8)
                    checks.append(('async_output_drained_before_join', ready_before_join))
                obj.sender = value
                value = m.actual_sender_join_only(obj)
        except BaseException as exc:
            error = exc
        elapsed = time.monotonic() - start
        at_return = {
            'error_type': None if error is None else type(error).__name__,
            'error': None if error is None else str(error),
            'child_returncodes': [child.returncode for child in children],
            'parent_original_streams_closed': all(stream.closed for stream in held),
            'child_identity_written': (directory/'CHILD.json').is_file(),
            'success_result_written': (directory/'RESULT.json').is_file(),
            'sender_joined_written': (directory/'JOINED.json').is_file(),
            'failure_written': (directory/'OWNED-CHILD-FAILURE.json').is_file(),
            'parent_fds': sorted(fds()),
            'additional_live_thread_ids': sorted(threads() - before_threads),
        }
        checks += [('one_child', len(children) == 1),
                   ('child_identity_persisted', at_return['child_identity_written']),
                   ('outcome_matches', (error is not None) == expects_error),
                   ('minimum_elapsed', elapsed >= minimum_seconds),
                   ('no_capture_thread_at_return', not at_return['additional_live_thread_ids']),
                   ('parent_original_streams_closed_at_return', at_return['parent_original_streams_closed']),
                   ('no_parent_fd_leak_at_return', set(at_return['parent_fds']) == before_fds)]
        if max_seconds is not None:
            checks.append(('bounded_return', elapsed < max_seconds))
        if expects_error:
            checks.append(('no_success_receipt', not at_return['success_result_written'] and not at_return['sender_joined_written']))
        else:
            checks.append(('all_parent_original_streams_closed', at_return['parent_original_streams_closed']))
            for label, expected in (('stdout', expected_stdout), ('stderr', expected_stderr)):
                if expected is not None:
                    actual = (directory/(label+'.original')).read_bytes()
                    checks.append((label+'_exact', actual == expected))
            if not asynchronous and at_return['success_result_written']:
                receipt = json.loads((directory/'RESULT.json').read_bytes())
                keys = {'state','phase','pid','returncode','stdout','stderr','automatic_retry'}
                checks.append(('success_schema', set(receipt) == keys and receipt['state']=='ORIGINAL_HOST_CHILD_JOINED'
                               and receipt['returncode']==0 and receipt['automatic_retry'] is False))
                for label in ('stdout', 'stderr'):
                    actual = (directory/(label+'.original')).read_bytes()
                    checks.append((label+'_receipt_exact', receipt[label]['bytes']==len(actual) and receipt[label]['sha256']==sha(actual)))
        cleanup = obj.close_owned_host_outputs()
    finally:
        # These are only the harness-created, fixed-lifetime processes. Waiting
        # here establishes fixture teardown, not the transport's deadline result.
        for child in children:
            child.wait(timeout=3)
        if descendant_done is not None:
            checks.append(('descendant_naturally_ended', wait_fixture_file(descendant_done, 3)))
        for stream in held:
            if not stream.closed:
                stream.close()
    after_fds, after_threads = fds(), threads()
    checks += [('no_parent_fd_leak', before_fds == after_fds),
               ('no_capture_thread_left', before_threads == after_threads)]
    result = {
        'case': name, 'passed': all(value for _, value in checks),
        'checks': [{'name': key, 'passed': value} for key, value in checks],
        'source_sha256': sha(raw), 'actual_sender_join_ast_sha256': join_ast_sha,
        'budget_seconds': budget, 'async_start': asynchronous,
        'execute_return_seconds': execute_seconds, 'final_return_seconds': elapsed,
        'ready_before_join': ready_before_join, 'at_return': at_return,
        'outer_cleanup': cleanup, 'signals_sent': 0, 'automatic_replay': False,
        'all_fixture_direct_children_naturally_joined': True,
        'fds_before': sorted(before_fds), 'fds_after': sorted(after_fds),
        'thread_ids_before': sorted(before_threads), 'thread_ids_after': sorted(after_threads),
        'steps': obj.steps,
    }
    (out/'INDEPENDENT-RESULT.json').write_bytes(enc(result))
    return result


def fork_writer(done, delay):
    return (
        'import os,time\nfrom pathlib import Path\n'
        'pid=os.fork()\n'
        'if pid:\n os.write(1,b"DIRECT\\n");os._exit(0)\n'
        f'time.sleep({delay!r})\n'
        'try:\n os.write(1,b"TAIL\\n");os.write(2,b"ERRTAIL\\n")\n'
        'except BrokenPipeError:\n pass\n'
        f'finally:\n Path({str(done)!r}).write_bytes(b"done")\n'
        'os._exit(0)\n'
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    source, evidence = a.source.resolve(strict=True), a.out.absolute()
    evidence.mkdir(mode=0o700)
    cases = []
    done = evidence/'tail-within-budget.done'
    cases.append(run_case(source,evidence,'tail-within-budget',fork_writer(done,.25),2,
                          b'DIRECT\nTAIL\n',b'ERRTAIL\n',minimum_seconds=.20,descendant_done=done))
    done = evidence/'tail-after-deadline.done'
    cases.append(run_case(source,evidence,'tail-after-deadline',fork_writer(done,.7),.15,
                          expects_error=True,max_seconds=.50,descendant_done=done))
    target = evidence/'path-replacement/phase/stdout.original'
    script = (f'import os\nfrom pathlib import Path\np=Path({str(target)!r})\n'
              'os.rename(p,str(p)+".moved")\np.write_bytes(b"FORGED\\n")\nos.write(1,b"ACTUAL\\n")\n')
    cases.append(run_case(source,evidence,'path-replacement',script,2,expects_error=True))
    each = 2*1024*1024
    script = ('import os\nfor _ in range(32):\n os.write(1,b"O"*65536)\n os.write(2,b"E"*65536)\n')
    cases.append(run_case(source,evidence,'both-pipes-full',script,3,b'O'*each,b'E'*each))
    marker = evidence/'async-before-join.ready'
    script += f'from pathlib import Path\nPath({str(marker)!r}).write_bytes(b"ready")\n'
    cases.append(run_case(source,evidence,'async-drain-before-join',script,3,b'O'*each,b'E'*each,
                          asynchronous=True,prejoin_marker=marker,max_seconds=2))
    payload = ('中文🙂\nexact $literal `literal`\0'.encode())*8192
    script = 'import sys,hashlib; b=sys.stdin.buffer.read(); sys.stdout.write(hashlib.sha256(b).hexdigest()+"\\n")'
    cases.append(run_case(source,evidence,'utf8-binary-input',script,2,(sha(payload)+'\n').encode(),b'',payload=payload))
    cases.append(run_case(source,evidence,'async-original-deadline','import time; time.sleep(.7)',.15,
                          asynchronous=True,expects_error=True,max_seconds=.50))
    report = {
        'schema':'hepta.root.transport-log-independent-review.v1',
        'source':{'path':str(source),'bytes':source.stat().st_size,'sha256':sha(source.read_bytes())},
        'reviewer_source':{'path':str(Path(__file__).resolve()),'bytes':Path(__file__).stat().st_size,
                           'sha256':sha(Path(__file__).read_bytes())},
        'passed':sum(case['passed'] for case in cases),'failed':sum(not case['passed'] for case in cases),
        'cases':cases,'phone_calls':0,'network_calls':0,'signals_sent':0,
        'fixed19_qualification':False,'host_os':sys.platform,
    }
    (evidence/'INDEPENDENT-RESULT.json').write_bytes(enc(report))
    print(json.dumps({'passed':report['passed'],'failed':report['failed'],'source':report['source'],
                      'evidence':str(evidence/'INDEPENDENT-RESULT.json')},indent=2))
    return 0 if report['failed']==0 else 1


if __name__=='__main__':
    raise SystemExit(main())
