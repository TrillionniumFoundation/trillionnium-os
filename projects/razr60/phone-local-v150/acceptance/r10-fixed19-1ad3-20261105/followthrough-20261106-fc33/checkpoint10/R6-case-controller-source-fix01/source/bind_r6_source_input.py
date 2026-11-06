#!/usr/bin/env python3
"""Bind one actual input literal and emit one host-source publication request.

This helper never dispatches the request. Actual unknown input fields are refused.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import types

B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
PACKAGE = B + '/followthrough-fc33-r6-source-rebind01'
SOURCE = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-r6-source-rebind-casefix01/source/derive_r6_source_rebindings_UNBOUND.py', 'bytes': 45121, 'sha256': '27db832a529f59d46e25b02eaecf2b9ac5c8ac9675c5bb91387a6fed4a8ee9b9'}
STAGE = {'path': B + '/followthrough-fc33-install-build-controller01/source/derive_release_install_stages_UNBOUND.py',
    'bytes': 64682, 'sha256': '60c6d2e84216798037133199882c5d34101808eb9035a741c64f22d6aa3fbece'}
HELPER = {'path': B + '/followthrough-fc33-install-build-controller01/source/derive_component_build_inputs_UNBOUND.py',
    'bytes': 34048, 'sha256': '766f6b933b4982088925669f327e0c7c2d03855b8c3f140052d7fbfd088d1b5f'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def bootstrap_source():
    """Read only the exact already-published rebinder; no main entry is executed."""
    import stat
    p = Path(SOURCE['path'])
    need(p.resolve(strict=True) == p, 'canonical published rebinder source')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        meta = lambda s: [getattr(s, n) for n in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                                                'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == SOURCE['bytes'],
             'actual complete source file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(SOURCE['bytes'] + 1)
        need(meta(first) == meta(os.fstat(fd)) == meta(p.lstat())
             and pin(raw) == {k: SOURCE[k] for k in ('bytes', 'sha256')}, 'exact whole source/full9')
    finally:
        os.close(fd)
    M = types.ModuleType('reviewed_unbound_r6_rebinder'); M.__file__ = SOURCE['path']
    exec(compile(raw, M.__file__, 'exec'), M.__dict__)
    need(M.FROZEN_INPUTS is None, 'the published source remains explicitly unbound')
    return M, raw


def prepare(M, parent, input_raw, input_row, out, key, timeout, *, read_pinned):
    input_row = M.descriptor(input_row)
    need(M.same(pin(input_raw), {k: input_row[k] for k in ('bytes', 'sha256')}), 'one exact input original')
    value = M.strict(input_raw)
    M.no_unknown(value)
    M.exact(value, ('schema', 'stage', 'output_root', 'actual'), 'closed source construction input')
    need(value['schema'] == M.SCHEMA and value['stage'] in M.STAGES, 'one source-only stage')
    M.output_root(value['output_root'])
    out = M.output_root(out)
    need(str(out) != value['output_root'] and type(key) is str
         and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{5,127}', key)
         and type(timeout) is int and 1 <= timeout <= 300, 'separate binding root and one finite operation key')
    pool = M.Pool(read_pinned)
    need(pool.read(SOURCE) == parent and pool.read(input_row) == input_raw, 'complete actual source/input originals')
    S = M.module(pool.read(STAGE), STAGE, 'reviewed_none_binding_implementation')
    H = M.module(pool.read(HELPER), HELPER, 'reviewed_source_binding_publisher')
    bound, proof = S.bind_none(parent, {'FROZEN_INPUTS': input_row})
    source = M.located(out / 'source/derive_r6_source_rebindings_BOUND.py', bound)
    request = dict(host='mac', executable='/usr/bin/python3',
        args=['-I', '-B', source['path'], '--publish-host-sources-once'],
        timeout_seconds=timeout, idempotency_key=key)
    files = {'source/derive_r6_source_rebindings_BOUND.py': bound,
        'reference/UNBOUND-SOURCE.original.py': parent,
        'reference/ACTUAL-INPUTS.original.json': input_raw,
        'SOURCE-INVERSE.json': M.enc(proof), 'requests/PUBLISH-SOURCES.json': M.enc(request)}
    report = dict(schema='hepta.fc33.r6.actual-source-input-binding.v1',
        state='ONE_NONE_LITERAL_BOUND_SOURCE_PUBLICATION_REQUEST_NOT_DISPATCHED', stage=value['stage'],
        source=SOURCE, actual_inputs=input_row, bound_source=source,
        request=M.located(out / 'requests/PUBLISH-SOURCES.json', files['requests/PUBLISH-SOURCES.json']),
        full_source_inverse=proof, phone_calls=0, BUILD_executed=False, actual_install=None, actual_READY=None,
        files=[M.located(out / n, b) for n, b in sorted(files.items())])
    files['DERIVATION.json'] = M.enc(report)
    pool.recheck()
    return dict(output_root=str(out), files=files, publisher=H.publish_material, report=report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--input-bytes', type=int, required=True)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--operation-key', required=True)
    parser.add_argument('--timeout-seconds', type=int, required=True)
    args = parser.parse_args()
    M, parent = bootstrap_source(); reader = M.HostReader()
    row = dict(path=args.input, bytes=args.input_bytes, sha256=args.input_sha256)
    result = prepare(M, parent, reader(row), row, args.output, args.operation_key, args.timeout_seconds,
                     read_pinned=reader)
    out = Path(result['output_root'])
    need(out.parent.resolve(strict=True) == out.parent and not os.path.lexists(out), 'fresh source binding output')
    result['publisher'](out, result['files'])
    for name, body in result['files'].items():
        need(reader(M.located(out / name, body)) == body, 'whole bound source publication readback')
    print(json.dumps(dict(state=result['report']['state'], stage=result['report']['stage'],
        derivation=M.located(out / 'DERIVATION.json', result['files']['DERIVATION.json']),
        request=result['report']['request'], phone_calls=0), sort_keys=True))


if __name__ == '__main__':
    main()
