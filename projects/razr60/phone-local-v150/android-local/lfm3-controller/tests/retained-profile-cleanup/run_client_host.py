#!/usr/bin/env python3
"""Reuse the actual business-client fixture with explicit socket/service ports.

The existing fixture and its cases are not rewritten. Its compilation stage adds
one new test, and its run stage selects that test. Full production Prepared,
client, private files, worker proof, Request, receipt and lease CAS remain actual.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def ref(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), mode=path.stat().st_mode & 0o777)


def pins(path_map):
    value = json.loads(path_map.read_bytes())
    return dict(path_map=ref(path_map), files={key: ref(path) for key, path in value.items()})


def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'output', 'java-home', 'json-jar', 'original-paths', 'normal-original-paths'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--model-done-cleanup', action='store_true', help='Use the actual model-done cleanup-failure Client/CAS regression')
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    original_runner = source / 'tests/public-profile-business-client/run_host.py'
    test = source / ('tests/public-profile-business-client/PublicProfileModelDoneClientHostTest.java' if args.model_done_cleanup else 'tests/retained-profile-cleanup/RetainedProfileCleanupClientHostTest.java')
    spec = importlib.util.spec_from_file_location('actual_business_client_runner', original_runner)
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    extra_before = [ref(Path(__file__)), ref(test), ref(original_runner)]
    normal_before = pins(args.normal_original_paths)
    extra_projections = []
    old_load, old_stage = base.load, base.stage

    def load(name, path):
        module = old_load(name, path)
        if name != 'business_client_bg_fixture':
            return module
        actual_prepare = module.prepare

        def prepare(src, fixture, include_terminal=False):
            files, derivation = actual_prepare(src, fixture, include_terminal=include_terminal)
            # Explicit authenticated socket endpoint identity for this port only.
            credentials = fixture / 'android/net/Credentials.java'
            before = ref(credentials)
            base.replace(credentials, 'public int getPid(){return -1;}', 'public int getPid(){return 4321;}')
            extra_projections.append(dict(boundary='synthetic socket peer pid; no Android socket', before=before, after=ref(credentials)))
            service = fixture / 'org/trillionnium/hepta/local/HeptaAccessibilityService.java'
            before = ref(service)
            raw = service.read_text()
            old_connected = 'static HeptaAccessibilityService connected(){return null;}'
            new_connected = ('static BackgroundSession cleanupBackground;'
                             'static HeptaAccessibilityService connected(){return new HeptaAccessibilityService();}')
            if raw.count(old_connected) != 1:
                raise RuntimeError('shared refusing service connection boundary changed')
            raw = raw.replace(old_connected, new_connected)
            start = '    BackgroundSession retiredBusinessBackgroundForCleanup(String task,String generation,String owner)throws java.io.IOException{'
            if raw.count(start) != 1:
                raise RuntimeError('shared refusing original-instance getter boundary changed')
            at = raw.index(start)
            end = raw.index('\n    }', at) + len('\n    }')
            original = raw[at:end]
            if 'throw new java.io.IOException' not in original or 'return' in original:
                raise RuntimeError('original-instance getter is no longer the refusing port')
            replacement = start + '\n        return cleanupBackground;\n    }'
            raw = raw[:at] + replacement + raw[end:]
            service.write_text(raw)
            extra_projections.append(dict(boundary='explicit connected service/queue and original background port; actual Android service not executed',
                                          before=before, after=ref(service), original_getter=original, replacement_getter=replacement))
            return files, derivation
        module.prepare = prepare
        return module

    def stage(name, argv, out, cwd):
        argv = list(argv)
        if name == 'compile':
            if str(test) in argv:
                raise RuntimeError('new client test already in base closure')
            argv.append(str(test))
        elif name == 'client':
            old_main = 'org.trillionnium.hepta.local.PublicProfileBusinessClientHostTest'
            if argv.count(old_main) != 1:
                raise RuntimeError('base actual-client main selection changed')
            index = argv.index(old_main)
            if len(argv) != index + 3:
                raise RuntimeError('base main arguments changed')
            argv[index] = ('org.trillionnium.hepta.local.PublicProfileModelDoneClientHostTest' if args.model_done_cleanup else 'org.trillionnium.hepta.local.RetainedProfileCleanupClientHostTest')
            if not args.model_done_cleanup:
                argv.append(str(args.normal_original_paths.resolve(strict=True)))
        return old_stage(name, argv, out, cwd)

    base.load, base.stage = load, stage
    original_argv = sys.argv
    sys.argv = [str(original_runner)]
    for name in ('source', 'output', 'java_home', 'json_jar', 'original_paths'):
        sys.argv += ['--' + name.replace('_', '-'), str(getattr(args, name))]
    try:
        code = base.main()
    finally:
        sys.argv = original_argv
    base_path = output / 'RESULT.json'
    base_result = json.loads(base_path.read_bytes())
    preserved = output / 'BASE-RESULT.json'
    if preserved.exists():
        raise RuntimeError('new-only original fixture report collision')
    base_path.rename(preserved)
    extra_after = [ref(Path(__file__)), ref(test), ref(original_runner)]
    normal_after = pins(args.normal_original_paths)
    result = dict(schema='hepta.retained-profile-cleanup-client-host.v1',
                  all_pass=code == 0 and base_result['all_pass'] and extra_before == extra_after and normal_before == normal_after,
                  counts=base_result['counts'], original_fixture_report=ref(preserved),
                  source_unchanged=base_result['source_unchanged'], tools_unchanged=base_result['tools_unchanged'],
                  actual_originals_unchanged=base_result['external_originals_unchanged'],
                  additional_inputs_before=extra_before, additional_inputs_after=extra_after,
                  normal_originals_before=normal_before, normal_originals_after=normal_after,
                  normal_originals_unchanged=normal_before == normal_after, explicit_generated_ports=extra_projections,
                  actual_prepared_cleanup_client_private_io_modelproof_absence_receipt_and_lease_cas=True,
                  independent_absence_process_and_socket_are_synthetic=True,
                  process_exit_wait_uses_real_owned_host_children=not args.model_done_cleanup,
                  model_done_cleanup_profile=args.model_done_cleanup,
                  root_effects_executed=False, android_runtime_tested=False, phone_operations=0)
    base.write(base_path, result)
    print(json.dumps(dict(all_pass=result['all_pass'], counts=result['counts'], result=ref(base_path))))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
