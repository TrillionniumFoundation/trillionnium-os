#!/usr/bin/env python3
"""Reuse the already-published host-only package publisher with exact successor bytes."""
import base64
import hashlib
import json
from pathlib import Path
import types
import zlib

HERE = Path(__file__).resolve().parent
REVIEW = HERE.parent
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
OUTPUT = B + '/followthrough-fc33-r6-source-rebind-casefix01'


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def main():
    original = REVIEW / 'R6-source-rebind/actual-readback/actual/build_source_publication.py'
    parent = original.read_bytes()
    T = types.ModuleType('already_published_host_package_builder'); T.__file__ = str(original)
    exec(compile(parent, str(original), 'exec'), T.__dict__)
    files = {}
    for folder in ('source', 'reference'):
        for p in sorted((HERE / folder).iterdir()):
            if p.is_file():
                files[str(p.relative_to(HERE))] = p.read_bytes()
    for name in ('README.md', 'reproduce_and_derive.py', 'SOURCE.patch', 'ACTUAL-BINDER-MISMATCH.patch',
                 'SOURCE-INVERSE.json', 'RESULT.json', 'build_publication.py'):
        files[name] = (HERE / name).read_bytes()
    for name in ('ACTUAL-BINDER-READ.original.mcp.json', 'ABSENCE-CONTROLLER.original.json',
                 'ABSENCE-STDOUT.original.json', 'ROOT-PRIOR-CASE-DERIVE-FAILURE.original.json'):
        files['reference/' + name] = (HERE / 'evidence' / name).read_bytes()
    actual_input = (REVIEW / 'R6-source-rebind/actual-stages/04-case-controller.ACTUAL.json').read_bytes()
    assert pin(actual_input) == dict(bytes=921, sha256='31bf47df14325d24de5ab1814d938550e543907a615761234f753e738ee144e8')
    files['inputs/04-case-controller.ACTUAL.json'] = actual_input
    package = dict(schema='hepta.fc33.r6.case-controller-source-fix-package.v1',
        state='SOURCE_SUCCESSOR_CANDIDATE_NO_EXECUTION', output=OUTPUT,
        prior_failed_job='1a1b2a31057-fc05-7f16', parent_publisher_template=pin(parent),
        candidate_source=pin(files['source/derive_r6_source_rebindings_UNBOUND.py']),
        source_controls=pin(files['RESULT.json']), control_count=5,
        existing_release_controllers_E2E_sources_changed=False, actual_case_controller=None,
        phone_calls=0, actual_BUILD=None, actual_READY=None, new_nonces=0,
        files=[dict(path=name, **pin(body)) for name, body in sorted(files.items())])
    files['SOURCE-PACKAGE.json'] = enc(package)
    payload = enc(dict(files={n: base64.b64encode(b).decode() for n, b in sorted(files.items())}))
    program = T.TEMPLATE.replace('__OUTPUT__', repr(OUTPUT)).replace('__PAYLOAD_BYTES__', str(len(payload)))
    program = program.replace('__PAYLOAD_SHA__', repr(pin(payload)['sha256']))
    program = program.replace('__PAYLOAD_BASE64__', repr(base64.b64encode(zlib.compress(payload, 9)).decode()))
    source = program.encode(); compile(source, '<source-only-successor-publisher>', 'exec')
    request = dict(host='mac', executable='/usr/bin/python3', args=['-I', '-B', '-'],
        stdin='import sys\nsys.argv=["publish_successor_source_package.py","--publish-source-package-once"]\n' + program,
        timeout_seconds=120, idempotency_key='fc33-r6-source-rebind-casefix-package01')
    bind = dict(host='mac', executable='/usr/bin/python3',
        args=['-I', '-B', OUTPUT + '/source/bind_r6_source_input.py',
            '--input', B + '/followthrough-fc33-r6-case-controller-ACTUAL01.json',
            '--input-bytes', str(len(actual_input)), '--input-sha256', pin(actual_input)['sha256'],
            '--output', B + '/followthrough-fc33-r6-case-controller-input-binding-fix01',
            '--operation-key', 'fc33-r6-case-controller-source-derive-fix01', '--timeout-seconds', '300'],
        timeout_seconds=120, idempotency_key='fc33-r6-case-controller-source-input-binding-fix01')
    out = HERE / 'publication'; out.mkdir(mode=0o700)
    def put(name, body):
        with (out / name).open('xb') as stream:
            stream.write(body)
    put('publish_successor_source_package.py', source)
    put('PUBLISH-SUCCESSOR-REQUEST.UNEXECUTED.json', enc(request))
    put('BIND-CASE-INPUT-REQUEST.UNEXECUTED.json', enc(bind))
    put('SOURCE-PACKAGE.json', files['SOURCE-PACKAGE.json'])
    put('PAYLOAD.json', payload)
    report = dict(schema='hepta.fc33.r6.case-controller-source-fix-publication-preparation.v1',
        state='SOURCE_SUCCESSOR_AND_NEW_REQUESTS_PREPARED_NOT_DISPATCHED', output=OUTPUT,
        publisher_template_parent=pin(parent), publisher=pin(source), payload=pin(payload),
        source_package=pin(files['SOURCE-PACKAGE.json']), package_file_count=len(files) + 1,
        publication_request=pin(enc(request)), case_binding_request=pin(enc(bind)),
        same_actual_case_source_input=pin(actual_input), actual_successor_publication=None,
        actual_case_controller=None, phone_calls=0, BUILD_executed=False, new_nonces=0)
    put('PREPARATION.json', enc(report))
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
