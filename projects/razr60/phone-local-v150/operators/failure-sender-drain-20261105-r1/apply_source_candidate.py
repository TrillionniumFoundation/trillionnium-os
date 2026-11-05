#!/usr/bin/env python3
"""Apply the reviewed host cleanup edit to one exact private full source.

This does not execute, install, freeze, or qualify a launcher. Public fragments
are test fixtures, not accepted production inputs. The output is create-only,
private, and must be outside this public package.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat

FULL_BASELINE_BYTES = 72674
FULL_BASELINE_SHA256 = 'dcb380efb71ddf76db046eeac34be745928c773b2071da82776a39956bce215b'
FULL_CANDIDATE_BYTES = 76328
FULL_CANDIDATE_SHA256 = '37742ec5b5bec83d6060743560bc1b732b5ce8d30a74bc15184f4220534a98d4'
PUBLIC_REFERENCE_SHA256 = 'f37c5b11a0d29bfac82665f4297facf968c887ec285efe061a5f0db299f428fd'
PUBLIC_CANDIDATE_SHA256 = 'b4940660de4ef6639cd4fdbf947ea46dd5d21daa2817c498adb2d1a19ae6610e'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_original(path, limit=131072):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, 'input path must be canonical')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 <= before.st_size <= limit, 'bounded regular input required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        current = path.lstat()
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(raw) == before.st_size and all(
            getattr(before, key) == getattr(after, key) == getattr(current, key) for key in keys),
            'input changed while reading')
        return raw
    finally:
        os.close(fd)


def selected_definitions(raw):
    tree = ast.parse(raw)
    lines = raw.splitlines(keepends=True)
    selected = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == 'main':
            selected['main'] = b''.join(lines[node.lineno - 1:node.end_lineno])
        if isinstance(node, ast.ClassDef) and node.name == 'Chain':
            for method in node.body:
                if isinstance(method, ast.FunctionDef) and method.name == 'close_owned_host_outputs':
                    selected['Chain.close_owned_host_outputs'] = b''.join(
                        lines[method.lineno - 1:method.end_lineno])
    require(set(selected) == {'main', 'Chain.close_owned_host_outputs'}, 'expected definitions missing')
    return selected


def build(source, package):
    require(len(source) == FULL_BASELINE_BYTES and sha(source) == FULL_BASELINE_SHA256,
            'only the exact reviewed full baseline is accepted; old public or superseded candidates are rejected')
    reference = read_original(package / 'reference' / 'host_transport.py')
    candidate = read_original(package / 'source' / 'host_transport.py')
    require(sha(reference) == PUBLIC_REFERENCE_SHA256 and sha(candidate) == PUBLIC_CANDIDATE_SHA256,
            'public extraction bytes changed')
    full_nodes = selected_definitions(source)
    old_nodes = selected_definitions(reference)
    new_nodes = selected_definitions(candidate)
    require(full_nodes == old_nodes, 'public reference is not the exact current full-source definitions')
    result = source
    for name in ('Chain.close_owned_host_outputs', 'main'):
        require(result.count(old_nodes[name]) == 1, 'definition is not unique')
        result = result.replace(old_nodes[name], new_nodes[name], 1)
    anchor = b'HOST_CAPTURE_STOP_WAIT=1.0\n'
    addition = (b'# Failure cleanup may only consume, never extend, the sender execution budget.\n'
                b'HOST_FAILURE_SENDER_DRAIN_WAIT=30.0\n')
    require(result.count(anchor) == 1 and addition not in result, 'constant insertion boundary differs')
    result = result.replace(anchor, anchor + addition, 1)
    require(len(result) == FULL_CANDIDATE_BYTES and sha(result) == FULL_CANDIDATE_SHA256,
            'full candidate bytes differ from the reviewed output')
    ast.parse(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    package = Path(__file__).resolve().parent
    source_path = args.source.absolute()
    output = args.out.absolute()
    require(output.parent.resolve(strict=True) == output.parent, 'output parent must already be canonical')
    require(not output.is_relative_to(package), 'private full output must be outside the public package')
    raw = read_original(source_path)
    result = build(raw, package)
    require(read_original(source_path) == raw, 'full baseline changed before publication')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(result)
        stream.flush()
        os.fsync(stream.fileno())
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    require(read_original(output) == result, 'created output differs from reviewed bytes')
    print(json.dumps({'state': 'PRIVATE_CANDIDATE_CREATED_NOT_EXECUTED_OR_ADOPTED',
        'baseline_sha256': FULL_BASELINE_SHA256, 'candidate_sha256': FULL_CANDIDATE_SHA256,
        'candidate_bytes': FULL_CANDIDATE_BYTES, 'create_only': True,
        'phone_calls': 0, 'source_executed': False, 'release_adopted': False}, sort_keys=True))


if __name__ == '__main__':
    main()
