#!/usr/bin/env python3
"""Real loopback regressions for exact public source definitions; no device calls."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
REFUSAL = 'PUBLIC_SOURCE_PROJECTION_REVIEW_ONLY_NOT_INSTALLABLE'


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def fd_count():
    directory = '/proc/self/fd' if os.path.isdir('/proc/self/fd') else '/dev/fd'
    require(os.path.isdir(directory), 'Host lacks a descriptor inventory')
    count = 0
    for name in os.listdir(directory):
        try:
            os.fstat(int(name))
            count += 1
        except (OSError, ValueError):
            pass
    return count


def load_projection(kind, candidate):
    relative = ('source/' + kind + '.CANDIDATE.PUBLIC.py' if candidate
                else 'reference/' + kind + '.BASELINE.PUBLIC.py')
    namespace = {'__name__': 'public_fixture_dependencies'}
    support = ROOT / 'tests/fixture_support.py'
    exec(compile(support.read_bytes(), str(support), 'exec'), namespace)
    namespace['__name__'] = 'public_selected_definitions'
    path = ROOT / relative
    exec(compile(path.read_bytes(), str(path), 'exec'), namespace)
    return namespace


class Fixture:
    def __init__(self, scenario, body, method):
        self.scenario, self.body, self.method = scenario, body, method
        self.state = {'requests': 0, 'server_errors': [], 'request_method': None,
                      'client_closed_early': False}
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(6)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        try:
            connection, _ = self.listener.accept()
            with connection:
                connection.settimeout(6)
                request = b''
                while b'\r\n\r\n' not in request:
                    part = connection.recv(4096)
                    require(bool(part), 'Fixture client closed before headers')
                    request += part
                    require(len(request) <= 16384, 'Fixture request exceeded header bound')
                header, payload = request.split(b'\r\n\r\n', 1)
                first = header.split(b'\r\n', 1)[0]
                expected = (b'GET /slots HTTP/1.1' if self.method == 'GET'
                            else b'POST /v1/chat/completions HTTP/1.1')
                require(first == expected, 'Unexpected fixture request route')
                content_length = 0
                for line in header.split(b'\r\n')[1:]:
                    key, _, value = line.partition(b':')
                    if key.lower() == b'content-length':
                        content_length = int(value.strip())
                require(0 <= content_length <= 16384, 'Fixture request body exceeds bound')
                while len(payload) < content_length:
                    part = connection.recv(min(4096, content_length - len(payload)))
                    require(bool(part), 'Fixture client closed before body')
                    payload += part
                self.state['requests'] += 1
                self.state['request_method'] = self.method
                if self.scenario == 'slow_headers':
                    connection.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                    for _ in range(24):
                        connection.sendall(b'x')
                        time.sleep(0.15)
                    connection.sendall(b'\r\n')
                else:
                    connection.sendall(b'HTTP/1.1 200 OK\r\n')
                declared = len(self.body) + (7 if self.scenario == 'truncated_length' else 0)
                connection.sendall(b'Content-Type: application/json\r\nContent-Length: '
                                   + str(declared).encode() + b'\r\nConnection: close\r\n\r\n')
                if self.scenario == 'slow_body':
                    for byte in self.body:
                        connection.sendall(bytes([byte]))
                        time.sleep(0.15)
                else:
                    connection.sendall(self.body)
        except (BrokenPipeError, ConnectionResetError):
            self.state['client_closed_early'] = True
        except Exception as error:
            self.state['server_errors'].append(type(error).__name__)
        finally:
            self.listener.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.thread.join(7)
        require(not self.thread.is_alive(), 'Finite fixture server did not join')
        require(self.state['requests'] == 1, 'Fixture must observe exactly one request')
        require(not self.state['server_errors'], 'Fixture server failed')


def write_fixture_key(directory):
    key = directory / 'fixture-key'
    key.write_bytes(b'fixture_only_not_a_credential_1234')
    key.chmod(0o600)
    return key


def slot_case(candidate, scenario, busy=False):
    namespace = load_projection('slot_observation', candidate)
    body = b'[{"is_processing":true}]' if busy else b'[{"is_processing":false}]'
    before = fd_count()
    with tempfile.TemporaryDirectory(prefix='slot-deadline-fixture-') as temporary:
        directory = Path(temporary).resolve()
        key = write_fixture_key(directory)
        with Fixture(scenario, body, 'GET') as fixture:
            started = time.monotonic()
            result = namespace['inspect_single_slot']({
                'endpoint': f'http://127.0.0.1:{fixture.port}/v1/chat/completions',
                'api_key_file': str(key)})
            elapsed = time.monotonic() - started
    require(fd_count() == before, 'Slot observation leaked a descriptor')
    slow = scenario in ('slow_headers', 'slow_body')
    rejected = candidate and (slow or scenario == 'truncated_length')
    require(result['observed'] is (not rejected), 'Slot observation classification differs')
    require(result['idle'] is (not rejected and not busy), 'Slot idle classification differs')
    require(result.get('automatic_retry') is False, 'Slot retry boundary changed')
    if rejected:
        require(result.get('inference_cleanup') == 'unknown', 'Rejected slot cleanup must stay unknown')
    if slow:
        if candidate:
            require(result.get('error_type') in {'TimeoutError', socket.timeout.__name__},
                    'Slow response did not expire at its deadline')
            require(1.8 <= elapsed < 2.5, 'Candidate exceeded two-second deadline plus fixture scheduling margin')
        else:
            require(elapsed > 2.7, 'Original slow-response defect was not reproduced')
    return {'case': ('candidate-' if candidate else 'original-') + scenario + ('-busy' if busy else ''),
            'kind': 'slot_observation', 'passed': True,
            'classification': 'original_defect_reproduced' if not candidate and (slow or scenario == 'truncated_length')
                              else 'candidate_regression',
            'configured_socket_seconds': 2, 'elapsed_seconds': round(elapsed, 6),
            'fixture_deadline_margin_seconds': 0.5 if candidate and slow else None,
            'observed': result['observed'], 'idle': result['idle'],
            'error_type': result.get('error_type'), 'request_count': fixture.state['requests'],
            'server_joined': True, 'fd_baseline_restored': True, 'automatic_retry': False}


def worker_case(candidate, truncated):
    namespace = load_projection('http_worker', candidate)
    body = json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': 'fixture'}}]},
                      separators=(',', ':')).encode()
    before = fd_count()
    with tempfile.TemporaryDirectory(prefix='worker-framing-fixture-') as temporary:
        directory = Path(temporary).resolve()
        key = write_fixture_key(directory)
        scenario = 'truncated_length' if truncated else 'fast'
        with Fixture(scenario, body, 'POST') as fixture:
            value = {'schema': 'hepta.phone-local-http-request.v150.1', 'request_id': 'a' * 32,
                     'endpoint': f'http://127.0.0.1:{fixture.port}/v1/chat/completions',
                     'api_key_file': str(key), 'timeout_seconds': 2,
                     'body': {'model': 'synthetic-fixture', 'stream': False,
                              'messages': [{'role': 'user', 'content': 'synthetic fixture'}]},
                     'response_path': str(directory / 'response.json'),
                     'receipt_path': str(directory / 'receipt.json'),
                     'service_manifest_sha256': 'a' * 64}
            checked = namespace['load_input'](json.dumps(value).encode())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = namespace['once'](checked)
            receipt = json.loads((directory / 'receipt.json').read_text())
            raw = (directory / 'response.json').read_bytes()
            message = json.loads(output.getvalue())
    require(fd_count() == before, 'Worker leaked a descriptor')
    require(raw == body, 'Worker did not preserve exact received bytes')
    reject = candidate and truncated
    require(code == (1 if reject else 0), 'Worker exit classification differs')
    expected = 'transport_error_result_unknown' if reject else 'complete_http_response'
    require(receipt['transport_terminal'] == message['transport_terminal'] == expected,
            'Worker transport terminal differs')
    require(receipt['inference_terminal'] == ('unknown' if reject else 'stop'),
            'Worker inference terminal differs')
    if reject:
        require(receipt.get('error_type') == 'IncompleteRead', 'Truncated worker reply was not rejected')
    require(receipt['attempt_count'] == 1 and receipt['automatic_retry'] is False,
            'Worker single-attempt boundary changed')
    return {'case': ('candidate-' if candidate else 'original-') + ('worker-truncated' if truncated else 'worker-complete'),
            'kind': 'http_worker', 'passed': True,
            'classification': 'original_defect_reproduced' if not candidate and truncated else 'candidate_or_fixture_regression',
            'request_count': fixture.state['requests'], 'exit_code': code,
            'transport_terminal': receipt['transport_terminal'],
            'inference_terminal': receipt['inference_terminal'], 'error_type': receipt.get('error_type'),
            'received_bytes': len(raw), 'declared_bytes': len(raw) + (7 if truncated else 0),
            'exact_response_bytes_preserved': True, 'server_joined': True,
            'fd_baseline_restored': True, 'automatic_retry': False}


def run():
    manifest = json.loads((ROOT / 'PROJECTION.json').read_text())
    for item in manifest['files']:
        raw = (ROOT / item['path']).read_bytes()
        require(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'],
                'Public package file identity changed')
    cases = [{'case': 'public-package-file-identities', 'passed': True}]
    for scenario in ('slow_headers', 'slow_body', 'truncated_length'):
        cases.append(slot_case(False, scenario))
        cases.append(slot_case(True, scenario))
    cases.append(slot_case(True, 'fast'))
    cases.append(slot_case(True, 'fast', busy=True))
    for candidate in (False, True):
        for truncated in (False, True):
            cases.append(worker_case(candidate, truncated))
    for kind, patchname in (('slot_observation', 'slot-observation'), ('http_worker', 'http-worker')):
        with tempfile.TemporaryDirectory(prefix='public-source-delta-') as temporary:
            path = Path(temporary) / (kind + '.py')
            path.write_bytes((ROOT / ('reference/' + kind + '.BASELINE.PUBLIC.py')).read_bytes())
            patch = ROOT / ('changes/' + patchname + '.PUBLIC.patch')
            subprocess.run(['git', 'apply', '--check', str(patch)], cwd=temporary,
                           check=True, capture_output=True, timeout=5)
            subprocess.run(['git', 'apply', str(patch)], cwd=temporary,
                           check=True, capture_output=True, timeout=5)
            require(path.read_bytes() == (ROOT / ('source/' + kind + '.CANDIDATE.PUBLIC.py')).read_bytes(),
                    'Public patch did not reconstruct exact candidate bytes')
        cases.append({'case': kind + '-public-patch-roundtrip', 'passed': True})
    entry_paths = [
        'reference/slot_observation.BASELINE.PUBLIC.py', 'source/slot_observation.CANDIDATE.PUBLIC.py',
        'reference/http_worker.BASELINE.PUBLIC.py', 'source/http_worker.CANDIDATE.PUBLIC.py',
        'tests/fixture_support.py',
    ]
    for relative in entry_paths:
        child = subprocess.run([sys.executable, '-I', '-B', str(ROOT / relative)],
                               capture_output=True, text=True, timeout=5)
        require(child.returncode != 0 and child.stderr.strip() == REFUSAL,
                'Public selected source did not refuse direct entry')
        cases.append({'case': 'direct-entry-refusal-' + relative, 'passed': True})
    return {'schema': 'hepta.slot-deadline.public-loopback-fixtures.v1',
            'scope': 'Synthetic numeric-loopback fixture and public selected source definitions only',
            'passed': len(cases), 'failed': 0, 'cases': cases,
            'all_finite_fixture_servers_joined': True, 'automatic_retries': 0,
            'phone_requests': 0, 'model_requests': 0, 'policy_operations': 0,
            'full_private_source_imported': False, 'fixed19_credits_added': 0,
            'phone_or_business_qualification': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional new synthetic-only result file')
    arguments = parser.parse_args()
    result = run()
    raw = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if arguments.output is not None:
        with arguments.output.open('x') as stream:
            stream.write(raw)
    print(raw, end='')
