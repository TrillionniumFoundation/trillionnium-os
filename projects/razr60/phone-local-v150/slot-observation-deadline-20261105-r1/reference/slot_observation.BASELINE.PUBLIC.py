"""Selected source definitions for local review and synthetic tests only.
This is not a full provider, private source manifest, or deployment package.
The test harness supplies separately retained public dependency definitions.
"""
import hashlib
import http.client
import time

if __name__ == "__main__":
    raise SystemExit("PUBLIC_SOURCE_PROJECTION_REVIEW_ONLY_NOT_INSTALLABLE")


def inspect_single_slot(config):
    """One read-only bounded observation; never asks the model to regenerate."""
    host, port, _path = endpoint_parts(config['endpoint'])
    connection = http.client.HTTPConnection(host, port, timeout=2)
    try:
        connection.request('GET', '/slots',
                           headers={'Authorization': 'Bearer ' + private_api_key(config['api_key_file']),
                                    'Connection': 'close'})
        response = connection.getresponse()
        raw = response.read(65537)
        require(response.status == 200 and len(raw) <= 65536, 'single-slot observation unavailable')
        slots = strict_json(raw)
        require(isinstance(slots, list) and len(slots) == 1 and isinstance(slots[0], dict)
                and type(slots[0].get('is_processing')) is bool,
                'server is not the qualified single-slot interface')
        return {'observed': True, 'idle': not slots[0]['is_processing'],
                'response_sha256': hashlib.sha256(raw).hexdigest(),
                'slot': slots[0], 'automatic_retry': False}
    except Exception as error:
        return {'observed': False, 'idle': False, 'error_type': type(error).__name__,
                'inference_cleanup': 'unknown', 'automatic_retry': False}
    finally:
        connection.close()
