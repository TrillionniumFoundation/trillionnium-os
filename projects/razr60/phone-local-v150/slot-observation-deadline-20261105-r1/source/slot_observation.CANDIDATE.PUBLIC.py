"""Selected source definitions for local review and synthetic tests only.
This is not a full provider, private source manifest, or deployment package.
The test harness supplies separately retained public dependency definitions.
"""
import hashlib
import http.client
import io
import time

if __name__ == "__main__":
    raise SystemExit("PUBLIC_SOURCE_PROJECTION_REVIEW_ONLY_NOT_INSTALLABLE")


def _remaining_http_seconds(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('single-slot observation deadline exceeded')
    return remaining


class _DeadlineRead(io.RawIOBase):
    """Refresh the remaining total budget before each underlying socket read.

    HTTPResponse reads headers through readline and bodies through read. Both
    can perform many socket reads, so setting a timeout once on the connection
    only bounds an idle gap and permits an indefinitely slow response.
    """
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline
        self.raw = sock.makefile('rb', buffering=0)

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(_remaining_http_seconds(self.deadline))
        return self.raw.readinto(buffer)

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()


class _DeadlineSocket:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def sendall(self, data):
        self.sock.settimeout(_remaining_http_seconds(self.deadline))
        return self.sock.sendall(data)

    def makefile(self, mode):
        if mode != 'rb':
            raise ValueError('single-slot HTTP response requires binary input')
        return io.BufferedReader(_DeadlineRead(self.sock, self.deadline))

    def __getattr__(self, name):
        return getattr(self.sock, name)


class _DeadlineHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self.deadline = time.monotonic() + timeout

    def connect(self):
        self.timeout = _remaining_http_seconds(self.deadline)
        super().connect()
        self.sock = _DeadlineSocket(self.sock, self.deadline)


def inspect_single_slot(config):
    """One read-only bounded observation; never asks the model to regenerate."""
    host, port, _path = endpoint_parts(config['endpoint'])
    connection = _DeadlineHTTPConnection(host, port, timeout=2)
    response = None
    try:
        connection.request('GET', '/slots',
                           headers={'Authorization': 'Bearer ' + private_api_key(config['api_key_file']),
                                    'Connection': 'close'})
        response = connection.getresponse()
        raw = response.read(65537)
        _remaining_http_seconds(connection.deadline)
        require(response.length in (None, 0), 'single-slot observation body is incomplete')
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
        if response is not None:
            response.close()
        connection.close()
