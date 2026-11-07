#!/usr/bin/env python3
"""Check exact source application and refusals; full outputs stay temporary."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NAMES = ('provider_phone_local.py', 'daily_phone_local.py', 'phone_local_http_worker.py')


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def run(public, private=None):
    manifest = json.loads((ROOT / 'PROJECTION.json').read_text())
    cases = []
    input_identity = {}
    for directory in (public, private):
        if directory is not None:
            for name in NAMES:
                path = directory / name
                input_identity[path] = hashlib.sha256(path.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='slot-source-application-') as temporary:
        work = Path(temporary).resolve()

        def invoke(directory, output, *, script=None, provider=None, daily=None, worker=None):
            command = [sys.executable, '-I', '-B', str(script or ROOT / 'apply_source_candidate.py'),
                       '--provider', str(provider or directory / NAMES[0]),
                       '--daily', str(daily or directory / NAMES[1]),
                       '--worker', str(worker or directory / NAMES[2]), '--output', str(output)]
            return subprocess.run(command, capture_output=True, timeout=10)

        def success(label, directory):
            output = work / label
            result = invoke(directory, output)
            require(result.returncode == 0, 'Accepted source application failed')
            pair = manifest['source_pairs'][label]
            for filename, field in zip(NAMES, ('provider_after_sha256', 'daily_after_sha256', 'worker_after_sha256')):
                require(hashlib.sha256((output / filename).read_bytes()).hexdigest() == pair[field],
                        'Generated full source differs from declared output')
            require(sorted(p.name for p in output.iterdir()) == sorted(NAMES + ('SOURCE-APPLICATION.json',)),
                    'Source application emitted unexpected files')
            cases.append({'case': label + '-exact-output', 'passed': True})
            return output

        public_output = success('public_r7', public)
        if private is not None:
            success('private_current', private)

        def refusal(label, directory, **kwargs):
            output = work / ('refused-' + label)
            result = invoke(directory, output, **kwargs)
            require(result.returncode != 0 and not output.exists(),
                    'Invalid source application was not rejected before output')
            cases.append({'case': label, 'passed': True})

        wrong_provider = work / 'wrong-provider.py'
        wrong_provider.write_bytes((public / NAMES[0]).read_bytes() + b'\n')
        refusal('unknown-provider-hash', public, provider=wrong_provider)
        wrong_worker = work / 'wrong-worker.py'
        wrong_worker.write_bytes((public / NAMES[2]).read_bytes() + b'\n')
        refusal('unknown-worker-hash', public, worker=wrong_worker)
        wrong_daily = work / 'wrong-daily.py'
        wrong_daily.write_bytes((public / NAMES[1]).read_bytes() + b'\n')
        refusal('unknown-daily-hash', public, daily=wrong_daily)
        if private is not None:
            refusal('mixed-public-private-source-set', public, daily=private / NAMES[1])
        symlink = work / 'provider-symlink.py'
        symlink.symlink_to(public / NAMES[0])
        refusal('symlink-input', public, provider=symlink)
        before = {p.name: p.read_bytes() for p in public_output.iterdir()}
        duplicate = invoke(public, public_output)
        require(duplicate.returncode != 0 and before == {p.name: p.read_bytes() for p in public_output.iterdir()},
                'An existing output was overwritten')
        cases.append({'case': 'existing-output-refusal', 'passed': True})
        copied = work / 'copied-public-package'
        shutil.copytree(ROOT, copied)
        bad_fragment = copied / 'source/slot_observation.CANDIDATE.PUBLIC.py'
        bad_fragment.write_bytes(bad_fragment.read_bytes() + b'\n')
        refusal('tampered-projection', public, script=copied / 'apply_source_candidate.py')
        inside = copied / 'forbidden-full-source-output'
        failed = invoke(public, inside, script=copied / 'apply_source_candidate.py')
        require(failed.returncode != 0 and not inside.exists(), 'Complete output entered the public package')
        cases.append({'case': 'public-package-output-refusal', 'passed': True})
    require(all(hashlib.sha256(path.read_bytes()).hexdigest() == digest
                for path, digest in input_identity.items()), 'Input source was modified')
    cases.append({'case': 'all-input-bytes-unchanged', 'passed': True})
    return {'schema': 'hepta.slot-deadline.source-application-checks.v1',
            'scope': 'Local source transformation only; no provider or worker imports, deployment or device calls',
            'passed': len(cases), 'failed': 0, 'cases': cases,
            'public_source_set_checked': True, 'private_source_set_checked': private is not None,
            'private_source_bytes_published': False, 'full_outputs_retained': False,
            'phone_requests': 0, 'model_requests': 0, 'qualification_credits_added': 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-source-dir', type=Path, default=ROOT.parent / 'provider/r7/source')
    parser.add_argument('--private-source-dir', type=Path,
                        help='Optional exact retained source set; bytes and paths never enter the result')
    parser.add_argument('--output', type=Path, help='Optional new synthetic-only summary file')
    arguments = parser.parse_args()
    result = run(arguments.public_source_dir.resolve(),
                 arguments.private_source_dir.resolve() if arguments.private_source_dir else None)
    raw = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if arguments.output is not None:
        with arguments.output.open('x') as stream:
            stream.write(raw)
    print(raw, end='')
