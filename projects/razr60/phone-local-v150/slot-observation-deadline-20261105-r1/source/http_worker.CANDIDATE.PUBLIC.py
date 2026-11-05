"""Selected source definitions for local review and synthetic tests only.
This is not a full provider, private source manifest, or deployment package.
The test harness supplies separately retained public dependency definitions.
"""
import hashlib
import http.client
import json
import socket
import time

if __name__ == "__main__":
    raise SystemExit("PUBLIC_SOURCE_PROJECTION_REVIEW_ONLY_NOT_INSTALLABLE")


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
    response = None
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
        elif response.length not in (None, 0):
            # read(amt) may return a short body without raising IncompleteRead.
            # Preserve those bytes, but never treat valid JSON as a complete
            # response when the server's declared body is still missing bytes.
            raise http.client.IncompleteRead(raw, response.length)
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
        if response is not None:
            response.close()
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
