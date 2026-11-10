#!/usr/bin/env python3
"""Record the necessary host regression suite; never run a phone command."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs); self.methods = []; self.subtest_count = 0
    def startTest(self, test):
        self.methods.append(test.id()); super().startTest(test)
    def addSubTest(self, test, subtest, err):
        self.subtest_count += 1; super().addSubTest(test, subtest, err)


def main():
    p = argparse.ArgumentParser(); p.add_argument('--output', type=Path, required=True); args = p.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path.insert(0, str(ROOT / 'tests'))
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_*.py')
    started = time.time()
    with (args.output / 'host-tests.stderr').open('x') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=RecordedResult).run(suite)
    files = {}
    for folder in ('candidate', 'tests'):
        for path in sorted((ROOT / folder).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts:
                raw = path.read_bytes(); files[str(path.relative_to(ROOT))] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    value = dict(schema='hepta.orvena-v32-helper-host-validation.v1', passed=result.wasSuccessful(),
        tests_run=result.testsRun, subtests_observed=result.subtest_count, methods=result.methods,
        failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
        started_wall_seconds=started, elapsed_seconds=time.time()-started,
        phone_contacted=False, phone_upgrade_run=False, phone_probe_run=False,
        ordinary_phone_task_run=False, core9_phone_run=False, actual_signed_v32_apk_sha256=None,
        actual_packaged_build_asset_sha256=None, synthetic_fixtures_are_phone_evidence=False,
        test_scope='Actual host consumer/control paths with synthetic producer fixtures and trapped phone I/O; no full real binding issuance.',
        source_commit='e07c6624b7309b0acf3fe10e31b0605a29e3e72d', files=files)
    cache_tests = sys.modules.get('test_source_cache')
    value['source_cache_counterexamples'] = [] if cache_tests is None else cache_tests.COUNTEREXAMPLES
    (args.output / 'HOST-RESULT.json').write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({key:value[key] for key in ('passed','tests_run','subtests_observed','phone_contacted')}, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__': raise SystemExit(main())
