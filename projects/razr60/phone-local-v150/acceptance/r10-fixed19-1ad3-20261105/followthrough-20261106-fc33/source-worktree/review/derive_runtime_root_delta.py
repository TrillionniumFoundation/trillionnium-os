#!/usr/bin/env python3
"""Derive only reviewed runtime source changes; no phone or process dispatch."""
from pathlib import Path
import ast, difflib, hashlib, json

BASE = Path(__file__).resolve().parent
PARENT = BASE / 'R4'
OUT = BASE / 'R5-root'

def pin(b):
    return {'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}

changes = {
 'runtime/source/native_guard_session_r2.py': [(
  "        if trace:\n            call['argv'][6] = base64.b64encode(b'set -x; ' + command).decode()\n",
  "        if trace:\n            call['argv'][6] = base64.b64encode(b'set -x; ' + command).decode()\n            call = self.phone.native_bound_call(\n                {key: value for key, value in call.items()\n                 if key not in {'config_generation', 'request_sha256', 'binding_fingerprint'}},\n                self.scope)\n")],
 'runtime/source/close_component.py': [(
  "len(names) == 37, 'adapter package inventory differs'",
  "len(names) == 38, 'adapter package inventory differs'"), (
  "C.need(count < 10, 'prior original boundary chain exceeds bound')",
  "C.need(count < LATE.MAX_CHAIN - 1, 'prior original boundary chain exceeds bound')"), (
  "    expected = r6_wire(decision['call_id'], derived['capture_id'], command, cfg)\n",
  "    phone = sys.modules['phone_observation_tools']\n    expected = phone.native_bound_call(\n        r6_wire(decision['call_id'], derived['capture_id'], command, cfg), scope)\n"), (
  "    actual = copy.deepcopy(expected); actual['argv'][6] = base64.b64encode(trace+command).decode()\n",
  "    actual = copy.deepcopy(expected); actual['argv'][6] = base64.b64encode(trace+command).decode()\n    actual = phone.native_bound_call(\n        {key: value for key, value in actual.items()\n         if key not in {'config_generation', 'request_sha256', 'binding_fingerprint'}}, scope)\n")],
 'runtime/source/component_snapshot.py': [(
  "capture.check();C.need(len(seen_nonce)<10,'closed component boundary chain count bound')",
  "capture.check();C.need(len(seen_nonce)<LATE.MAX_CHAIN-1,'closed component boundary chain count bound')")],
 'runtime/source/root_fixture_originals.py': [("len(rows) == len(package['files']) == 37", "len(rows) == len(package['files']) == 38")],
 'runtime/source/prepare_component.py': [("len(rows)==37", "len(rows)==38")],
 'runtime/source/stage_component.py': [("len(rows)==37", "len(rows)==38")],
 'runtime/source/root_fixture_once.py': [("len(rows)==37", "len(rows)==38")],
 'runtime/source/sender_native_guard_ready_r10_r4.py': [("len(names) == 37", "len(names) == 38")],
 'runtime/source/component_lifecycle.py': [("len(fixture_roots)<=13", "len(fixture_roots)<=14")],
}

def main():
    results = []
    manifest = json.loads((PARENT/'runtime/MANIFEST.json').read_bytes())
    parents = {'runtime/'+r['path']: {k:r[k] for k in ('bytes','sha256')} for r in manifest['files']}
    helper_name = 'runtime/source/sender_native_guard_ready_r10_r4.py'
    helper = (PARENT/helper_name).read_text()
    for old, new in changes[helper_name]:
        assert helper.count(old) == 1
        helper = helper.replace(old, new, 1)
    changes['runtime/source/send_new_native_guard_task_r10_r4.py'] = [(
        parents[helper_name]['sha256'], pin(helper.encode())['sha256'])]
    patchdir = OUT / 'reviewed-deltas'
    patchdir.mkdir(parents=True, exist_ok=True)
    for name, edits in changes.items():
        parent = (PARENT / name).read_bytes()
        assert pin(parent) == parents[name], (name, 'exact frozen parent source')
        source = parent.decode('utf-8')
        for old, new in edits:
            assert source.count(old) == 1, (name, 'parent match count', old)
            source = source.replace(old, new, 1)
        restored = source
        for old, new in reversed(edits):
            assert restored.count(new) == 1, (name, 'inverse match count')
            restored = restored.replace(new, old, 1)
        assert restored.encode('utf-8') == parent, (name, 'whole byte inverse')
        ast.parse(source, filename=name)
        raw = source.encode('utf-8')
        target = OUT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        assert target.read_bytes() == raw
        patch = ''.join(difflib.unified_diff(parent.decode().splitlines(keepends=True),
            source.splitlines(keepends=True), fromfile='R4/'+name, tofile='R5/'+name))
        (patchdir/(Path(name).name+'.patch')).write_text(patch)
        results.append({'path': name, 'parent': pin(parent), 'candidate': pin(raw),
                        'exact_whole_byte_inverse': True, 'replacement_count': len(edits)})
    result = {'schema': 'hepta.fc33.runtime-root-source-delta.v1',
        'state': 'SOURCE_CANDIDATE_WITH_HISTORY_AND_PACKAGE_BINDING_PENDING',
        'phone_calls': 0, 'qualification_credit': 0, 'files': results,
        'unmodified_component_common': pin((PARENT/'runtime/source/component_common.py').read_bytes()),
        'late_boundary_owned_by_separate_review': True,
        'root_driver_and_fixture_cap_binding_pending': True}
    raw = (json.dumps(result, sort_keys=True, indent=2)+'\n').encode()
    (OUT/'RUNTIME-ROOT-DELTA.json').write_bytes(raw)
    print(json.dumps({'result': pin(raw), 'changed_sources': len(results),
                      'phone_calls': 0, 'all_inverses_exact': True}))

if __name__ == '__main__':
    main()
