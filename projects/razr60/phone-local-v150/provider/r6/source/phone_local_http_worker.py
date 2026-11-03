#!/usr/bin/env python3
"""One bounded, non-retrying HTTP request to an operator-pinned phone-local VLM.

This child cannot execute phone tools. Its parent owns cancellation, admission,
and all action guards. A closed client is not proof that an inference server has
finished cancelling; the original request receipt remains the source of truth.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
import urllib.parse

MAX_INPUT = 2 * 1024 * 1024
MAX_RESPONSE = 1024 * 1024


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _x: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def endpoint_parts(endpoint):
    value = urllib.parse.urlsplit(endpoint)
    if (value.scheme != 'http' or value.hostname not in {'127.0.0.1', '::1'}
            or value.username is not None or value.password is not None
            or value.query or value.fragment or value.path != '/v1/chat/completions'
            or value.port is None or not 1024 <= value.port <= 65535):
        raise ValueError('phone-local endpoint must be an exact numeric-loopback chat-completions URL')
    return value.hostname, value.port, value.path


def private_api_key(path):
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise ValueError('absolute private API-key file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600
                or not 16 <= before.st_size <= 4096):
            raise ValueError('private API-key file ownership/mode differs')
        raw = os.read(fd, 4097)
        after, named = os.fstat(fd), os.lstat(path)
        attrs = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        if len(raw) != before.st_size or any(getattr(before, x) != getattr(after, x)
                or getattr(before, x) != getattr(named, x) for x in attrs):
            raise ValueError('private API-key file changed while read')
    finally:
        os.close(fd)
    value = raw.decode('ascii').strip()
    if not re.fullmatch(r'[A-Za-z0-9_./+=-]{16,4096}', value):
        raise ValueError('private API-key value has invalid framing')
    return value


def exclusive_bytes(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def load_input(raw):
    value = strict_json(raw)
    required = {'schema', 'request_id', 'endpoint', 'timeout_seconds', 'body',
                'response_path', 'receipt_path', 'service_manifest_sha256', 'api_key_file'}
    if (not isinstance(value, dict) or set(value) != required
            or value['schema'] != 'hepta.phone-local-http-request.v150.1'
            or not isinstance(value['request_id'], str)
            or not re.fullmatch(r'[a-f0-9]{32}', value['request_id'])
            or not isinstance(value['service_manifest_sha256'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', value['service_manifest_sha256'])
            or type(value['timeout_seconds']) not in {int, float}
            or not 0.1 <= value['timeout_seconds'] <= 300
            or not isinstance(value['body'], dict)
            or value['body'].get('stream') is not False):
        raise ValueError('bounded local request envelope differs')
    endpoint_parts(value['endpoint'])
    paths = [Path(value[name]) for name in ('response_path', 'receipt_path')]
    if paths[0] == paths[1] or paths[0].parent != paths[1].parent:
        raise ValueError('response and receipt must be distinct siblings')
    for path in paths:
        if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
            raise ValueError('local worker evidence path must be canonical and absolute')
        info = path.parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or path.exists() or path.is_symlink()):
            raise ValueError('local worker evidence ownership/exclusivity differs')
    return value


def once(value):
    hostname, port, path = endpoint_parts(value['endpoint'])
    api_key = private_api_key(value['api_key_file'])
    body = json.dumps(value['body'], ensure_ascii=False, separators=(',', ':'),
                      allow_nan=False).encode()
    if len(body) > MAX_INPUT:
        raise ValueError('local request body exceeds byte bound')
    receipt = {'schema': 'hepta.phone-local-http-receipt.v150.1',
               'request_id': value['request_id'],
               'request_sha256': hashlib.sha256(body).hexdigest(),
               'request_bytes': len(body), 'attempt_count': 1,
               'automatic_retry': False, 'redirect_followed': False,
               'fallback_model': False, 'phone_effects_executed_by_worker': 0,
               'endpoint': value['endpoint'],
               'service_manifest_sha256': value['service_manifest_sha256'],
               'http_status': None, 'response_bytes': None, 'response_sha256': None,
               'elapsed_monotonic_seconds': None, 'transport_terminal': 'not_started',
               'inference_terminal': 'unknown', 'error_category': None,
               'usage': None, 'timings': None, 'response_model': None}
    started = time.monotonic()
    connection = http.client.HTTPConnection(hostname, port,
                                            timeout=value['timeout_seconds'])
    raw = b''
    try:
        # http.client does not inspect proxy variables, follow redirects or retry.
        # The only permitted destination is numeric loopback, whose device-bound
        # forwarding or on-phone ownership must be independently attested.
        receipt['transport_terminal'] = 'request_attempted_result_unknown'
        connection.request('POST', path, body=body,
                           headers={'Content-Type': 'application/json',
                                    'Authorization': 'Bearer ' + api_key,
                                    'X-HEPTA-Request-ID': value['request_id'],
                                    'Connection': 'close'})
        response = connection.getresponse()
        receipt['http_status'] = response.status
        raw = response.read(MAX_RESPONSE + 1)
        receipt['response_bytes'] = len(raw)
        receipt['response_sha256'] = hashlib.sha256(raw).hexdigest()
        exclusive_bytes(value['response_path'], raw)
        if len(raw) > MAX_RESPONSE:
            receipt.update(transport_terminal='response_size_bound', error_category='request_rejected')
        elif response.status != 200:
            category = ('authentication_failed' if response.status in {401, 403}
                        else 'rate_limit_exceeded' if response.status == 429
                        else 'request_rejected' if 400 <= response.status < 500
                        else 'transport_unavailable')
            receipt.update(transport_terminal='http_error', error_category=category)
        else:
            result = strict_json(raw)
            if not isinstance(result, dict):
                raise ValueError('HTTP model response must be an object')
            receipt.update(transport_terminal='complete_http_response',
                           usage=result.get('usage'), timings=result.get('timings'),
                           response_model=result.get('model'))
            choices = result.get('choices')
            if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
                raise ValueError('HTTP model choices are absent or ambiguous')
            reason = choices[0].get('finish_reason')
            receipt['inference_terminal'] = reason if isinstance(reason, str) else 'unknown'
            if reason not in {'stop', 'tool_calls'}:
                receipt['error_category'] = 'model_budget_exhausted' if reason == 'length' else 'unknown_model_failure'
    except (TimeoutError, socket.timeout):
        receipt.update(transport_terminal='timeout_result_unknown', error_category='model_timeout')
    except (ConnectionError, OSError, http.client.HTTPException) as error:
        receipt.update(transport_terminal='transport_error_result_unknown',
                       error_category='transport_unavailable', error_type=type(error).__name__)
    except (ValueError, UnicodeError) as error:
        receipt.update(transport_terminal='malformed_response',
                       error_category='unknown_model_failure', error_type=type(error).__name__)
    finally:
        connection.close()
        receipt['elapsed_monotonic_seconds'] = time.monotonic() - started
        exclusive_bytes(value['receipt_path'], json.dumps(receipt, ensure_ascii=False,
                           separators=(',', ':'), allow_nan=False).encode())
    print(json.dumps({'schema': 'hepta.phone-local-http-child.v150.1',
                      'request_id': value['request_id'],
                      'transport_terminal': receipt['transport_terminal'],
                      'inference_terminal': receipt['inference_terminal'],
                      'error_category': receipt['error_category']}, separators=(',', ':')), flush=True)
    return 0 if receipt['error_category'] is None else 1


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    os.umask(0o077)
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if not raw or len(raw) > MAX_INPUT:
        raise ValueError('local request envelope is missing or oversized')
    return once(load_input(raw))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({'schema': 'hepta.phone-local-http-child.v150.1',
                          'error_type': type(error).__name__,
                          'error': 'local worker could not establish a valid terminal'}), flush=True)
        sys.exit(2)
