#!/usr/bin/env python3
"""Create a new host coordinator source; never run a task or edit its parent."""
import base64
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat
import types

B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
PARENT = B + '/followthrough-fc33-e2e-bound-source-r5-01'
OUTPUT = B + '/followthrough-fc33-e2e-coordinator-compat01'
PARENT_BINDING = {'path': PARENT + '/BINDING.json', 'bytes': 60062,
    'sha256': '00a6cc4850c40cc710d348480f0d6b2871a145c89ee6801bd195432659a8da15'}
HELPER = {'path': B + '/followthrough-fc33-install-build-controller01/source/derive_component_build_inputs_UNBOUND.py',
    'bytes': 34048, 'sha256': '766f6b933b4982088925669f327e0c7c2d03855b8c3f140052d7fbfd088d1b5f'}
OLD_PIN = {'bytes': 20208, 'sha256': 'd1959bfc46c0dc0e347a1a438062f6f6259d85bd6f17cf0b4aae967f1e488b53'}
NEW_PIN = {'bytes': 20206, 'sha256': '54f7a6c1fd7e9ff1b82e82f4947639bca1745d334f7512bbf92d796bb32987fa'}
BEFORE = b'   receipts.append(dict(phase=phase,**result))\n'
AFTER = b"   receipts.append({**result,'phase':phase})\n"
CONTROL_PIN = {'bytes': 2463, 'sha256': '9af639a431ef44c3a9d5b9efc5aac095b145514cca3cb006413b6f767464c582'}
CONTROL_BASE64 = 'ewogICJhY3R1YWxfRTJFIjogZmFsc2UsCiAgImFjdHVhbF9ob3N0X3Byb2JlX2NvdW50IjogMSwKICAiYWN0dWFsX2hvc3RfcHJvYmVfcmVzdWx0IjogewogICAgImF1dG9tYXRpY19yZXRyeSI6IGZhbHNlLAogICAgInBoYXNlIjogIjAxLXJlZ2lzdGVyIiwKICAgICJwaWQiOiA1LAogICAgInJldHVybmNvZGUiOiAwLAogICAgInN0YXRlIjogIk9SSUdJTkFMX0hPU1RfQ0hJTERfSk9JTkVEIiwKICAgICJzdGRlcnIiOiB7CiAgICAgICJieXRlcyI6IDAsCiAgICAgICJwYXRoIjogIi93b3Jrc3BhY2Uvc2NyYXRjaC9mYzMzZWFjOTA5YWIvcmV2aWV3L2UyZS1jb29yZGluYXRvci1waGFzZS1jb21wYXQvY29udHJvbDAxL293bmVkLXByb2JlLzAxLXJlZ2lzdGVyL3N0ZGVyci5vcmlnaW5hbCIsCiAgICAgICJzaGEyNTYiOiAiZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NSIKICAgIH0sCiAgICAic3Rkb3V0IjogewogICAgICAiYnl0ZXMiOiA0MCwKICAgICAgInBhdGgiOiAiL3dvcmtzcGFjZS9zY3JhdGNoL2ZjMzNlYWM5MDlhYi9yZXZpZXcvZTJlLWNvb3JkaW5hdG9yLXBoYXNlLWNvbXBhdC9jb250cm9sMDEvb3duZWQtcHJvYmUvMDEtcmVnaXN0ZXIvc3Rkb3V0Lm9yaWdpbmFsIiwKICAgICAgInNoYTI1NiI6ICIzZjA4YjNhNGIwOGQxNDA1MTUwY2Y5NjIxMjU3MTM0YzQ2YWJhYWM3NGQ0NTQyNDcyNjQxN2M0M2FlNGM4YjFiIgogICAgfQogIH0sCiAgImNhbmRpZGF0ZSI6IHsKICAgICJieXRlcyI6IDIwMjA2LAogICAgInNoYTI1NiI6ICI1NGY3YTZjMWZkN2U5ZmYxYjgyZTgyZjQ5NDc2MzliY2ExNzQ1ZDMzNGY3NTEyYmJmOTJkNzk2YmIzMjk4N2ZhIgogIH0sCiAgImNhcHR1cmUiOiB7CiAgICAiYnl0ZXMiOiAzNzcyMCwKICAgICJzaGEyNTYiOiAiOWQyNzNkNjZhZGMwOWM2NzBhZTA5YWEwNmZhZTY5OWQyZDFkZTllMTk4MWFmZDM5ODBiZWM3ZTRlZGE2Y2IyOSIKICB9LAogICJjb250cm9sX2NvdW50IjogMTAsCiAgImNvbnRyb2xzIjogWwogICAgewogICAgICAibmFtZSI6ICJleGFjdF90d29fZnJvemVuX3NvdXJjZXMiLAogICAgICAicGFzc2VkIjogdHJ1ZQogICAgfSwKICAgIHsKICAgICAgIm5hbWUiOiAib25lX2xpbmVfZnVsbF9ieXRlX2ludmVyc2UiLAogICAgICAicGFzc2VkIjogdHJ1ZQogICAgfSwKICAgIHsKICAgICAgIm5hbWUiOiAiY2FuZGlkYXRlX2NvbXBpbGVzIiwKICAgICAgInBhc3NlZCI6IHRydWUKICAgIH0sCiAgICB7CiAgICAgICJuYW1lIjogImFjdHVhbF9vd25lZF9jaGlsZF9jb21wbGV0ZWRfd2l0aF90d29fZnVsbF9zdHJlYW1zIiwKICAgICAgInBhc3NlZCI6IHRydWUKICAgIH0sCiAgICB7CiAgICAgICJuYW1lIjogImFjdHVhbF9jaGlsZF9yZXN1bHRfaW5jbHVkZXNfcGhhc2UiLAogICAgICAicGFzc2VkIjogdHJ1ZQogICAgfSwKICAgIHsKICAgICAgIm5hbWUiOiAib3JpZ2luYWxfbGluZV9yZXByb2R1Y2VzX2R1cGxpY2F0ZV9rZXl3b3JkX1R5cGVFcnJvciIsCiAgICAgICJwYXNzZWQiOiB0cnVlCiAgICB9LAogICAgewogICAgICAibmFtZSI6ICJyZXBsYWNlbWVudF9hY2NlcHRzX2FjdHVhbF9vcmlnaW5hbF9yZXN1bHQiLAogICAgICAicGFzc2VkIjogdHJ1ZQogICAgfSwKICAgIHsKICAgICAgIm5hbWUiOiAib25seV9sb2dpY2FsX3BoYXNlX2NoYW5nZXNfaW5fcmVjZWlwdCIsCiAgICAgICJwYXNzZWQiOiB0cnVlCiAgICB9LAogICAgewogICAgICAibmFtZSI6ICJvcmlnaW5hbF9jaGlsZF9yZXN1bHRfbm90X211dGF0ZWQiLAogICAgICAicGFzc2VkIjogdHJ1ZQogICAgfSwKICAgIHsKICAgICAgIm5hbWUiOiAib3duZWRfcmVzb3VyY2VzX3JlbGVhc2VkIiwKICAgICAgInBhc3NlZCI6IHRydWUKICAgIH0KICBdLAogICJmaXhlZDE5X2NyZWRpdCI6IDAsCiAgIm1vZGVsX3JlcXVlc3RzIjogMCwKICAibmF0aXZlX3NlbmRzIjogMCwKICAibmV3X25vbmNlcyI6IDAsCiAgIm9yaWdpbmFsIjogewogICAgImJ5dGVzIjogMjAyMDgsCiAgICAic2hhMjU2IjogImQxOTU5YmZjNDZjMGRjMGUzNDdhMWE0MzgwNjJmNmY2MjU5ZDg1YmQ2ZjE3Y2YwYjRhYWU5NjdmMWU0ODhiNTMiCiAgfSwKICAib3JpZ2luYWxfZmFpbHVyZSI6IHsKICAgICJtZXNzYWdlIjogImRpY3QoKSBnb3QgbXVsdGlwbGUgdmFsdWVzIGZvciBrZXl3b3JkIGFyZ3VtZW50ICdwaGFzZSciLAogICAgIm9yaWdpbmFsX3JlY2VpcHRzIjogW10sCiAgICAidHlwZSI6ICJUeXBlRXJyb3IiCiAgfSwKICAicGhvbmVfY2FsbHMiOiAwLAogICJyZWdpc3RyYXRpb25zIjogMCwKICAic2NoZW1hIjogImhlcHRhLmZjMzMuZTJlLmNvb3JkaW5hdG9yLXBoYXNlLWNvbXBhdGliaWxpdHkuc291cmNlLWNvbnRyb2wudjEiLAogICJzdGF0ZSI6ICJTT1VSQ0VfSU5URVJGQUNFX0RFRkVDVF9SRVBST0RVQ0VEX0FORF9PTkVfTElORV9DQU5ESURBVEVfVkVSSUZJRUQiCn0K'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def bootstrap(row):
    path = Path(row['path'])
    need(path.resolve(strict=True) == path, 'canonical actual source path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        names = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        meta = lambda st: [getattr(st, name) for name in names]
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == row['bytes'], 'original helper shape')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(row['bytes'] + 1)
        need(meta(first) == meta(os.fstat(fd)) == meta(path.lstat())
             and pin(raw) == {k: row[k] for k in ('bytes','sha256')}, 'actual full helper bytes and metadata')
        return raw
    finally:
        os.close(fd)


def derive(read_pinned):
    helper_raw = read_pinned(HELPER)
    need(pin(helper_raw) == {k: HELPER[k] for k in ('bytes','sha256')}, 'exact reviewed dirfd publisher')
    H = types.ModuleType('reviewed_e2e_compat_host_publisher'); H.__file__ = HELPER['path']
    exec(compile(helper_raw, H.__file__, 'exec'), H.__dict__)
    pool = H.Pool(read_pinned); pool.read(HELPER)
    binding_raw = pool.read(PARENT_BINDING, 131072); binding = H.strict(binding_raw)
    need(binding['state'] == 'SOURCE_BOUND_TASK_EXECUTION_UNBOUND'
         and binding['source_combination_sha256'] == '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411',
         'same actual complete source-only parent')
    rows = binding['files']
    need(type(rows) is list and len(rows) == 48 and len({r['path'] for r in rows}) == 48,
         'complete actual parent source inventory')
    selected, bodies = {}, {}
    for row in rows:
        relative = str(H.path(row['path']).relative_to(PARENT))
        selected[relative], bodies[relative] = row, pool.read(row, 4 * 1024 * 1024)
    old = bodies['source/run_fixed19_e2e_root_once.py']
    need(pin(old) == OLD_PIN and old.count(BEFORE) == 1 and old.count(AFTER) == 0, 'exact one frozen erroneous append line')
    new = old.replace(BEFORE, AFTER)
    need(pin(new) == NEW_PIN and new.count(AFTER) == 1 and new.replace(AFTER, BEFORE) == old,
         'one changed source line with complete original byte inverse')
    compile(new, OUTPUT + '/source/run_fixed19_e2e_root_once.py', 'exec')
    patch = ''.join(difflib.unified_diff(old.decode().splitlines(True), new.decode().splitlines(True),
        fromfile='actual49/source/run_fixed19_e2e_root_once.py', tofile='candidate/source/run_fixed19_e2e_root_once.py')).encode()
    inverse = dict(original=OLD_PIN, candidate=NEW_PIN, replaced_line=209,
        before=BEFORE.decode(), after=AFTER.decode(), complete_byte_inverse=True,
        production_source_changes=0, operator_manifest_changes=0, child_phase_program_changes=0)
    control = base64.b64decode(CONTROL_BASE64, validate=True)
    need(pin(control) == CONTROL_PIN, 'preserved actual isolated host source-control result')
    files = {'source/run_fixed19_e2e_root_once.py': new, 'SOURCE.patch': patch,
        'SOURCE-INVERSE.json': enc(inverse), 'SOURCE-CONTROL-RESULT.json': control,
        'reference/PARENT-BINDING.original.json': binding_raw,
        'reference/PARENT-COORDINATOR.original.py': old}
    def located(name):
        return dict(path=OUTPUT + '/' + name, **pin(files[name]))
    source_binding = dict(schema='hepta.fc33.e2e.coordinator-compat-source.v1',
        state='ONE_LINE_HOST_COORDINATOR_COMPATIBILITY_SOURCE_ONLY',
        parent_binding=PARENT_BINDING, parent_coordinator=selected['source/run_fixed19_e2e_root_once.py'],
        coordinator=located('source/run_fixed19_e2e_root_once.py'),
        source_inverse=located('SOURCE-INVERSE.json'), patch=located('SOURCE.patch'),
        source_control_result=located('SOURCE-CONTROL-RESULT.json'),
        operator_manifest=selected['operator-chain/SOURCE-MANIFEST.json'],
        capture_source=selected['reference/owned_capture.source.original.py'],
        collector_manifest=selected['collector-package/MANIFEST.json'],
        materializer=selected['operator/materialize_case_r10.py'],
        shared_materials=selected['shared/SHARED-MATERIALS.json'],
        production_source_changes=0, unchanged_parent_member_count=47, new_coordinator_only=True,
        child_phase_program_changed=False, maximum_new_sends_unchanged=1,
        actual_BUILD=None, actual_READY=None, actual_material=None, actual_context=None,
        actual_native_scope=None, actual_E2E=None, COMP01=None,
        phone_calls=0, model_requests=0, registrations=0, native_sends=0, new_nonces=0,
        fixed19_credit=0, automatic_retry=False, historical_pass_inherited=False)
    files['SOURCE-COMPAT.json'] = enc(source_binding)
    pool.recheck()
    terminal = dict(schema='hepta.fc33.e2e.coordinator-compat-publication.v1',
        state='HOST_SOURCE_COMPATIBILITY_PUBLISHED_NO_CASE_EXECUTION', output=OUTPUT,
        source_binding=located('SOURCE-COMPAT.json'), parent_binding=PARENT_BINDING,
        original_source=OLD_PIN, new_source=NEW_PIN, full_byte_inverse=True,
        actual_parent_members_completely_read=len(rows), actual_parent_files_bookended=len(pool.rows),
        actual_parent_bytes=pool.total, old_parent_unchanged=True,
        files=[located(name) for name in sorted(files)], file_count=len(files)+1,
        actual_BUILD=None, actual_READY=None, actual_E2E=None, phone_calls=0,
        registrations=0, native_sends=0, model_requests=0, new_nonces=0, fixed19_credit=0)
    files['DERIVATION.json'] = enc(terminal)
    return H, files, terminal


def main():
    Hraw = bootstrap(HELPER)
    H = types.ModuleType('reviewed_e2e_compat_bootstrap'); H.__file__ = HELPER['path']
    exec(compile(Hraw, H.__file__, 'exec'), H.__dict__)
    reader = H.HostReader(); module, files, terminal = derive(reader)
    module.publish_material(Path(OUTPUT), files)
    row = dict(path=OUTPUT + '/DERIVATION.json', **pin(files['DERIVATION.json']))
    need(reader(row) == files['DERIVATION.json'], 'actual full source-only publication terminal readback')
    print(json.dumps(dict(state=terminal['state'], source_binding=terminal['source_binding'],
        derivation=row, file_count=terminal['file_count'], phone_calls=0,
        registrations=0, native_sends=0, model_requests=0, new_nonces=0), sort_keys=True))


if __name__ == '__main__':
    main()
