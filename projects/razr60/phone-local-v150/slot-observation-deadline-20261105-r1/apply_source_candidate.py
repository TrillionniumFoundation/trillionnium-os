#!/usr/bin/env python3
"""Write a separate, exact-hash source candidate; never deploy or execute it.

Generated complete sources can retain private bindings from the supplied input.
Keep the output outside this publication package and do not publish it.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat

SETTINGS = {'pairs': {'public_r7': {'provider_before_sha256': '8f57e86ec66e4588e2e6f43ea761f17e9ae02361791995ff2f5831a16e46dbe6', 'provider_before_bytes': 55325, 'daily_before_sha256': '92122fcc8bf01511971075fce2ad94b628dadf2c0c342f0fb940e8b00c636ec3', 'daily_before_bytes': 19981, 'provider_after_sha256': '283a9cc357b838cdc5090c9c88aa0734b7c9bbc3b0f052130498387b4b5e2388', 'provider_after_bytes': 57473, 'daily_after_sha256': '83b279c8b0eb515aa75af61c4a42a399d29fa41b4adb1a0b7389523f705e8a65', 'daily_after_bytes': 19981, 'worker_before_sha256': 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d', 'worker_before_bytes': 10453, 'worker_after_sha256': 'c99ad016803182e7b697e03f015ddc73d7115e79e27eb7584a326e28d9ea6795', 'worker_after_bytes': 10885, 'daily_change': 'Only PARENTS provider/worker entries and WORKER_SHA change.'}, 'private_current': {'provider_before_sha256': '082b02a473dc4d75d46a895895b64b96cf25ae24fc61795cb292fc70fd8d9ad6', 'provider_before_bytes': 70237, 'daily_before_sha256': '07cd44148050e48b972a992a47c8422da81b334298fc684be9909795a1ece812', 'daily_before_bytes': 22059, 'provider_after_sha256': '8959793db36e4c0174651195fc44124fc7ccc4f6b7d7ed841c2ac86686508f03', 'provider_after_bytes': 72385, 'daily_after_sha256': 'd07e9231f7c8ae7275405e0f308a4ebe7f770e56dc163bebd2bb1671d861ca84', 'daily_after_bytes': 22059, 'worker_before_sha256': 'a1f1c94f2e78ced93cbde2113f508d756507249133f71c6dbe9a82a58a232d4d', 'worker_before_bytes': 10453, 'worker_after_sha256': 'c99ad016803182e7b697e03f015ddc73d7115e79e27eb7584a326e28d9ea6795', 'worker_after_bytes': 10885, 'daily_change': 'Only PARENTS provider/worker entries and WORKER_SHA change.'}}, 'baseline_projection_sha256': '1c320fc358e4a616b0aba48b6c2dc84f0cbe7d45283c932c1ed0ee6c06762893', 'candidate_projection_sha256': 'd898434fd99c482ba1b6db558817e0289d5332e5ecf5f325c479ce0a9b928c5b', 'baseline_definition_sha256': '3a7097b62168eaf3163631748c881d292c67a3814c9e5212aa7373eda06125d7', 'candidate_definition_block_sha256': '9779ba9b60c5584faaf77e8ecae5eb1e43bef7bfbc27315c6a0a724ee5bd90fc', 'worker_baseline_projection_sha256': 'b7a8ddddb27c480450847cd15ac07a76d4a1aaef4cfca9b66596b905923dcba2', 'worker_candidate_projection_sha256': '51247ea72cb0e3444941185c6189eb8faea877e475706941de4831ff565be81a', 'worker_baseline_definition_sha256': 'b2e98a2fc0c303b5823b250dd09ff1e1457d275da32119d631a8bbc26f9a05a4', 'worker_candidate_definition_sha256': '20cd75e9d6159dde5a9170b1ea13e7fa77521bf96efa7cfcbb06004df275ced1'}
DEFINITIONS = ('_remaining_http_seconds', '_DeadlineRead', '_DeadlineSocket', '_DeadlineHTTPConnection', 'inspect_single_slot')
ROOT = Path(__file__).resolve().parent
MAX_SOURCE_BYTES = 1024 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def regular_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_SOURCE_BYTES,
                'Input is not a bounded regular source file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size <= MAX_SOURCE_BYTES,
                'Input source size changed while read')
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, f) == getattr(after, f) for f in fields),
                'Input source identity changed while read')
        return raw
    finally:
        os.close(fd)


def definition_block(text, names):
    wanted = []
    for name in names:
        matches = [n for n in ast.parse(text).body
                   if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name]
        require(len(matches) == 1, 'Selected source definition missing or duplicated')
        wanted.append(matches[0])
    require([n.lineno for n in wanted] == sorted(n.lineno for n in wanted),
            'Selected source definitions are out of order')
    return ''.join(text.splitlines(keepends=True)[wanted[0].lineno - 1:wanted[-1].end_lineno])


def parent_map(text):
    matches = [n for n in ast.parse(text).body if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == 'PARENTS' for t in n.targets)]
    require(len(matches) == 1, 'Daily source PARENTS must have exactly one definition')
    value = ast.literal_eval(matches[0].value)
    require(isinstance(value, dict), 'Daily source PARENTS is not a literal mapping')
    return value


def worker_pin(text):
    matches = [n for n in ast.parse(text).body if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == 'WORKER_SHA' for t in n.targets)]
    require(len(matches) == 1, 'Daily source WORKER_SHA must have exactly one definition')
    value = ast.literal_eval(matches[0].value)
    require(isinstance(value, str), 'Daily source WORKER_SHA is not a literal string')
    return value


def generate(provider_raw, daily_raw, worker_raw):
    source_sha = digest(provider_raw)
    matches = [(name, pair) for name, pair in SETTINGS['pairs'].items()
               if pair['provider_before_sha256'] == source_sha]
    require(len(matches) == 1, 'Provider source hash is not one of the two accepted originals')
    name, pair = matches[0]
    require(digest(daily_raw) == pair['daily_before_sha256'],
            'Daily source does not match the accepted provider/daily pair')
    require(digest(worker_raw) == pair['worker_before_sha256'],
            'Worker source does not match the accepted source set')
    require(len(provider_raw) == pair['provider_before_bytes']
            and len(daily_raw) == pair['daily_before_bytes']
            and len(worker_raw) == pair['worker_before_bytes'], 'Accepted source size differs')
    reference_raw = regular_bytes(ROOT / 'reference/slot_observation.BASELINE.PUBLIC.py')
    repaired_raw = regular_bytes(ROOT / 'source/slot_observation.CANDIDATE.PUBLIC.py')
    require(digest(reference_raw) == SETTINGS['baseline_projection_sha256'],
            'Published baseline projection changed')
    require(digest(repaired_raw) == SETTINGS['candidate_projection_sha256'],
            'Published candidate projection changed')
    old = definition_block(reference_raw.decode('utf-8'), ('inspect_single_slot',))
    new = definition_block(repaired_raw.decode('utf-8'), DEFINITIONS)
    require(digest(old.encode()) == SETTINGS['baseline_definition_sha256']
            and digest(new.encode()) == SETTINGS['candidate_definition_block_sha256'],
            'Published selected definitions changed')
    provider = provider_raw.decode('utf-8')
    daily = daily_raw.decode('utf-8')
    worker = worker_raw.decode('utf-8')
    require(definition_block(provider, ('inspect_single_slot',)) == old,
            'Input slot definition differs from accepted original')
    require(provider.count(old) == 1 and provider.count('import http.client\n') == 1,
            'Source replacement anchors missing or duplicated')
    require('\nimport io\n' not in provider, 'Source already contains the candidate import')
    result = provider.replace('import http.client\n', 'import http.client\nimport io\n', 1)
    result = result.replace(old, new, 1).encode()
    require(digest(result) == pair['provider_after_sha256']
            and len(result) == pair['provider_after_bytes'], 'Generated provider identity differs')
    worker_baseline_raw = regular_bytes(ROOT / 'reference/http_worker.BASELINE.PUBLIC.py')
    worker_candidate_raw = regular_bytes(ROOT / 'source/http_worker.CANDIDATE.PUBLIC.py')
    require(digest(worker_baseline_raw) == SETTINGS['worker_baseline_projection_sha256']
            and digest(worker_candidate_raw) == SETTINGS['worker_candidate_projection_sha256'],
            'Published worker projection changed')
    worker_old = definition_block(worker_baseline_raw.decode('utf-8'), ('once',))
    worker_new = definition_block(worker_candidate_raw.decode('utf-8'), ('once',))
    require(digest(worker_old.encode()) == SETTINGS['worker_baseline_definition_sha256']
            and digest(worker_new.encode()) == SETTINGS['worker_candidate_definition_sha256'],
            'Published worker definition changed')
    require(definition_block(worker, ('once',)) == worker_old and worker.count(worker_old) == 1,
            'Input worker definition differs from accepted original')
    worker_result = worker.replace(worker_old, worker_new, 1).encode()
    require(digest(worker_result) == pair['worker_after_sha256']
            and len(worker_result) == pair['worker_after_bytes'], 'Generated worker identity differs')
    before_parents = parent_map(daily)
    require(before_parents.get('provider_phone_local.py') == source_sha,
            'Original daily provider pin differs')
    old_pin = "'provider_phone_local.py': '" + source_sha + "'"
    new_pin = "'provider_phone_local.py': '" + pair['provider_after_sha256'] + "'"
    require(daily.count(old_pin) == 1, 'Daily provider pin anchor missing or duplicated')
    daily_result = daily.replace(old_pin, new_pin, 1)
    require(before_parents.get('phone_local_http_worker.py') == pair['worker_before_sha256']
            and worker_pin(daily) == pair['worker_before_sha256'], 'Original daily worker pins differ')
    old_worker_parent = "'phone_local_http_worker.py': '" + pair['worker_before_sha256'] + "'"
    old_worker_global = "WORKER_SHA = '" + pair['worker_before_sha256'] + "'"
    require(daily_result.count(old_worker_parent) == daily_result.count(old_worker_global) == 1,
            'Daily worker pin anchor missing or duplicated')
    daily_result = daily_result.replace(old_worker_parent,
        "'phone_local_http_worker.py': '" + pair['worker_after_sha256'] + "'", 1)
    daily_result = daily_result.replace(old_worker_global,
        "WORKER_SHA = '" + pair['worker_after_sha256'] + "'", 1)
    after_parents = parent_map(daily_result)
    expected_parents = dict(before_parents, **{'provider_phone_local.py': pair['provider_after_sha256'],
                                              'phone_local_http_worker.py': pair['worker_after_sha256']})
    require(after_parents == expected_parents and worker_pin(daily_result) == pair['worker_after_sha256'],
            'Daily change extended beyond the provider and worker pins')
    daily_result = daily_result.encode()
    require(digest(daily_result) == pair['daily_after_sha256']
            and len(daily_result) == pair['daily_after_bytes'], 'Generated daily identity differs')
    ast.parse(result)
    ast.parse(daily_result)
    ast.parse(worker_result)
    return name, pair, result, daily_result, worker_result


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', type=Path, required=True)
    parser.add_argument('--daily', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='New directory outside this publication package; never reused')
    args = parser.parse_args()
    output = args.output.absolute()
    parent = output.parent.resolve(strict=True)
    resolved_output = parent / output.name
    require(ROOT != resolved_output and ROOT not in resolved_output.parents,
            'Complete source output inside the public package is forbidden')
    require(not output.exists() and not output.is_symlink(), 'Output directory must be new')
    name, pair, provider_result, daily_result, worker_result = generate(
        regular_bytes(args.provider), regular_bytes(args.daily), regular_bytes(args.worker))
    # Validate every input and replacement before creating any output.
    resolved_output.mkdir(mode=0o700, exist_ok=False)
    write_new(resolved_output / 'provider_phone_local.py', provider_result)
    write_new(resolved_output / 'daily_phone_local.py', daily_result)
    write_new(resolved_output / 'phone_local_http_worker.py', worker_result)
    receipt = {'schema': 'hepta.slot-deadline.local-source-application.v1',
               'source_variant': name, 'source_pair': pair,
               'input_files_modified': False, 'other_production_files_copied': False,
               'private_bindings_may_remain_in_local_output': True,
               'local_full_source_output_must_not_be_published': True,
               'deployment_performed': False, 'phone_requests': 0, 'model_requests': 0,
               'complete_combination_qualified': False}
    write_new(resolved_output / 'SOURCE-APPLICATION.json',
              (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode())
    print(json.dumps({'source_variant': name, 'output_created': True,
                      'provider_sha256': pair['provider_after_sha256'],
                      'daily_sha256': pair['daily_after_sha256'],
                      'worker_sha256': pair['worker_after_sha256'],
                      'deployment_performed': False, 'keep_full_outputs_private': True}))


if __name__ == '__main__':
    main()
