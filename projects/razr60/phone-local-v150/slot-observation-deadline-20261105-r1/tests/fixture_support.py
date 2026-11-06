"""Exact public dependency definitions, used only with synthetic fixture input."""
import json
import os
from pathlib import Path
import re
import stat
import urllib.parse

if __name__ == "__main__":
    raise SystemExit("PUBLIC_SOURCE_PROJECTION_REVIEW_ONLY_NOT_INSTALLABLE")


MAX_INPUT = 2 * 1024 * 1024
MAX_RESPONSE = 1024 * 1024


class ProviderError(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise ProviderError('[phone_local] ' + message)


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
