#!/usr/bin/env python3
"""Reproduce source derivation from retained parent bytes; do not publish on Mac."""
import hashlib
import json
from pathlib import Path
import types

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / 'R5-actual-e2e-bound-source/actual'


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()


def put(path, raw):
    path.parent.mkdir(exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)


def main():
    source = HERE/'publish_compat_source.py'; raw = source.read_bytes()
    P = types.ModuleType('source_preview_only_publisher'); P.__file__ = str(source)
    exec(compile(raw,str(source),'exec'), P.__dict__)
    helper = HERE.parent/'install-build-controller/derive_component_build_inputs_UNBOUND.py'
    mapping = {P.HELPER['path']: helper, P.PARENT_BINDING['path']: OLD/'BINDING.json'}
    binding = json.loads((OLD/'BINDING.json').read_bytes())
    for row in binding['files']:
        mapping[row['path']] = OLD/row['path'][len(P.PARENT)+1:]
    read_counts = {}
    def read(row):
        p = mapping[row['path']]; before = p.stat(); body = p.read_bytes(); after = p.stat()
        fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        assert all(getattr(before,k)==getattr(after,k) for k in fields)
        assert pin(body) == {k:row[k] for k in ('bytes','sha256')}
        read_counts[row['path']] = read_counts.get(row['path'],0)+1
        return body
    H, files, report = P.derive(read)
    assert files['source/run_fixed19_e2e_root_once.py'] == (HERE/'control01/run_fixed19_e2e_root_once.py').read_bytes()
    assert len(files) == 8 and report['file_count'] == 8
    assert len(read_counts) == 50 and all(n>=2 for n in read_counts.values())
    controls = [{'name':'all50_exact_retained_parent_files_bookended', 'passed':True},
                {'name':'source_candidate_matches_real_owned_capture_probe_candidate', 'passed':True}]
    for label, target in [('empty_helper', P.HELPER['path']), ('empty_parent_binding', P.PARENT_BINDING['path']),
                          ('empty_parent_coordinator', P.PARENT+'/source/run_fixed19_e2e_root_once.py')]:
        def broken(row, target=target):
            return b'' if row['path']==target else read(row)
        try:
            P.derive(broken)
        except (ValueError, AssertionError):
            controls.append(dict(name=label+'_refused',passed=True))
        else:
            raise AssertionError(label+' unexpectedly accepted')
    out = HERE/'publication-preview'; out.mkdir(mode=0o700)
    for name, body in files.items():
        p=out/name;p.parent.mkdir(exist_ok=True)
        with p.open('xb') as stream:stream.write(body)
    request = dict(host='mac', executable='/usr/bin/python3', args=['-I','-B','-'], stdin=raw.decode(),
        timeout_seconds=120, idempotency_key='fc33-e2e-coordinator-phase-compat-source01')
    result = dict(schema='hepta.fc33.e2e.compat-publisher.source-control.v1',
        state='LOCAL_PURE_DERIVATION_ONLY_MAC_REQUEST_NOT_RUN', publisher=pin(raw), controls=controls,
        source_compat=pin(files['SOURCE-COMPAT.json']), expected_terminal=pin(files['DERIVATION.json']),
        actual_parent_mirror_files=50, actual_Mac_publication=False, file_count=len(files),
        phone_calls=0, registrations=0, native_sends=0, model_requests=0, new_nonces=0, fixed19_credit=0)
    put(HERE/'PUBLICATION-CONTROLS.json',enc(result))
    put(HERE/'REQUEST.json',enc(request))
    print(json.dumps(dict(publisher=pin(raw), request=pin(enc(request)), controls=len(controls),
        source_compat=pin(files['SOURCE-COMPAT.json']), expected_terminal=pin(files['DERIVATION.json']),
        Mac_publication=False, phone_calls=0),sort_keys=True))


if __name__=='__main__':
    main()
