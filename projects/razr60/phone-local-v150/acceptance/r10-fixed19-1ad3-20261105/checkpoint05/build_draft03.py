#!/usr/bin/env python3
"""Local immutable checkpoint index; never calls Git, a host, or target code."""
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import re
import tarfile
from pathlib import Path, PurePosixPath

BASE = Path('/workspace/scratch/1ad3d6f55439')
spec = importlib.util.spec_from_file_location('checkpoint_snapshot', BASE/'git_checkpoint05_delivery/build_draft01.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
ARCHIVES = []
OBSERVATIONS = []
OUT = S.OUT/'draft03-material'


def safe(name):
    p = PurePosixPath(name)
    assert isinstance(name, str) and name and not p.is_absolute()
    assert p.as_posix() == name and all(x not in ('', '.', '..') for x in p.parts)
    assert not any(ord(c) < 32 or ord(c) == 127 for c in name)
    return name


def write(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        assert S.read(path) == raw, 'immutable draft artifact differs: ' + str(path)
        return
    with path.open('xb') as stream:
        stream.write(raw)
    assert S.read(path) == raw


def rows(root):
    return [p for p in sorted(root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts]


def tar_members(path):
    raw = S.read(path)
    if path.name.endswith('.xz'):
        plain = lzma.decompress(raw)
    elif path.name.endswith('.gz'):
        plain = gzip.decompress(raw)
    else:
        plain = raw
    result = {}
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as archive:
        for entry in archive:
            safe(entry.name)
            assert entry.isfile() and not entry.issym() and not entry.islnk()
            assert entry.name not in result and entry.size <= 16 * 1024 * 1024
            stream = archive.extractfile(entry)
            value = stream.read(entry.size + 1)
            assert len(value) == entry.size
            result[entry.name] = value
    return raw, plain, result


def verify_archive_tree(path, root, expected=None):
    raw, plain, members = tar_members(path)
    if expected is not None:
        assert set(members) == set(expected)
    for name, body in members.items():
        assert S.read(root/name) == body, 'archive/member byte mismatch: ' + name
    ARCHIVES.append({'archive': S.desc(path, raw), 'plain_tar': {'bytes': len(plain), 'sha256': S.sha(plain)},
        'regular_members': len(members), 'member_bytes': sum(map(len, members.values())),
        'all_members_safe_regular_unique': True, 'all_members_match_local_original_bytes': True,
        'complete_expected_member_set': expected is not None})
    return members


def bundle(name, root, selected=None, note=None):
    selected = rows(root) if selected is None else sorted(selected)
    values = {safe(p.relative_to(root).as_posix()): S.read(p) for p in selected}
    assert values and len(values) == len(selected)
    records = [{'path': n, 'bytes': len(b), 'sha256': S.sha(b),
        'git_blob_sha': hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest(),
        'source': str(root/n)} for n, b in sorted(values.items())]
    manifest = {'schema': 'hepta.fixed19.checkpoint05.lossless-local-snapshot.v1',
        'source_root': str(root), 'snapshot_scope': note or 'Enumerated existing local files; exact original bytes.',
        'files': records, 'file_count': len(records), 'file_bytes': sum(r['bytes'] for r in records),
        'target_code_executed': False, 'originals_modified': False, 'qualification_claimed': False,
        'tar_metadata': 'Archive headers normalized locally; source file contents are unchanged.'}
    mfraw = S.enc(manifest)
    manifest_path = OUT/'archives'/(name+'.MEMBERS.json')
    archive_path = OUT/'archives'/(name+'.tar.xz')
    write(manifest_path, mfraw)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for n, b in sorted(values.items()):
            info = tarfile.TarInfo(n)
            info.size, info.mode, info.mtime, info.uid, info.gid = len(b), 0o600, 0, 0, 0
            archive.addfile(info, io.BytesIO(b))
    encoded = lzma.compress(buf.getvalue(), preset=6)
    write(archive_path, encoded)
    _, plain, check = tar_members(archive_path)
    assert check == values and plain == buf.getvalue()
    for n, b in values.items():
        assert S.read(root/n) == b
    for path in (archive_path, manifest_path):
        S.add(str(path.relative_to(BASE)), 'checkpoint05-evidence/'+path.name, name)
    ARCHIVES.append({'archive': S.desc(archive_path, encoded), 'manifest': S.desc(manifest_path, mfraw),
        'regular_members': len(values), 'member_bytes': sum(map(len, values.values())),
        'all_members_safe_regular_unique': True, 'all_members_match_local_original_bytes': True,
        'local_lossless_snapshot': True, 'scope': manifest['snapshot_scope']})
    return manifest


def observed_group(source, target, state, source_sha):
    root = BASE/source
    archive_path = root/'FULL-ORIGINALS.tar.xz'
    manifest = json.loads(S.read(root/'ARCHIVE-MANIFEST.original.json'))
    originals = {r['path']: r for r in manifest['files']}
    values = verify_archive_tree(archive_path, root/'originals', originals)
    assert len(values) == 12
    for name, value in values.items():
        assert len(value) == originals[name]['bytes'] and S.sha(value) == originals[name]['sha256']
    assert S.sha(values['PROBE-SOURCE.original.py']) == source_sha
    observation = json.loads(values['PHONE-STDOUT.original'])
    assert observation['state'] == state
    # The controller/phone wrapper originals are preserved; this collection is not an independent case verifier.
    support = [p for p in rows(root) if p.relative_to(root).parts[0] not in ('originals', 'chunks')
               and p != archive_path]
    bundle(target+'-host-receipts', root, support,
        'All existing top-level source/controller/verification records. Expanded 12 originals and redundant download .bin chunks are represented by the separately verified exact FULL-ORIGINALS archive.')
    S.add(str(archive_path.relative_to(BASE)), target+'/FULL-ORIGINALS.tar.xz', 'actual_readonly_observations')
    S.add(str((root/'ARCHIVE-MANIFEST.original.json').relative_to(BASE)), target+'/ARCHIVE-MANIFEST.original.json', 'actual_readonly_observations')
    OBSERVATIONS.append({'group': target, 'state': state, 'source_sha256': source_sha,
        'archive': S.desc(archive_path, S.read(archive_path)), 'regular_originals': 12,
        'phone_stdout': {'bytes': len(values['PHONE-STDOUT.original']), 'sha256': S.sha(values['PHONE-STDOUT.original'])},
        'case_pass_claimed': False, 'failed_prelaunch_formal_closure_claimed': False})


def main():
    previous_raw = S.read(S.OUT/'PUBLISH-INDEX.draft02.json')
    assert len(previous_raw) == 159940 and S.sha(previous_raw) == 'd42aa8c7d46115b02716a3d9b45c8deae066f9d49852199fdc59e02942598a74'
    previous = json.loads(previous_raw)
    assert len(previous) == 329
    S.INDEX.update({r['path'][len(S.PREFIX):]: r for r in previous})
    S.PROVENANCE.update(json.loads(S.read(S.OUT/'CHECKPOINT05-PROVENANCE-MAP.draft02.json')))
    coverage = json.loads(S.read(S.OUT/'CHECKPOINT05-MANIFEST-COVERAGE.draft02.json'))
    S.GROUPS.extend(coverage['groups'])

    for source, target, group in (
        ('runtime_prefix_successor_candidate01/delivery-final01/package', 'runtime-inventory-prefix-final01/package', 'runtime_root_prefix_source'),
        ('consumer_prefix_successor_candidate01/delivery-final01/package', 'consumer-inventory-prefix-final01/package', 'consumer_prefix_source'),
        ('prelaunch_pure_history_candidate01/delivery-final01/source-package', 'inventory-prefix-diagnostic-final01/source-package', 'inventory_expression_source'),
        ('explicit_inventory_reader_diagnostic_candidate01/delivery-final01/package', 'explicit-inventory-reader-diagnostic-final01/package', 'explicit_reader_diagnostic_source'),
    ):
        S.source_package(source, target, group)

    for source, target, archives in (
        ('runtime_prefix_successor_candidate01/delivery-final01', 'runtime-inventory-prefix-final01', ['runtime-root-inventory-prefix-source-final01.tar.gz']),
        ('consumer_prefix_successor_candidate01/delivery-final01', 'consumer-inventory-prefix-final01', ['inventory-prefix-consumer-source-stage-final01.tar.gz', 'inventory-prefix-consumer-full-evidence-final01.tar.gz']),
        ('prelaunch_pure_history_candidate01/delivery-final01', 'inventory-prefix-diagnostic-final01', ['inventory-prefix-source-stage-final01.tar.gz', 'inventory-prefix-full-evidence-final01.tar.gz']),
        ('explicit_inventory_reader_diagnostic_candidate01/delivery-final01', 'explicit-inventory-reader-diagnostic-final01', ['explicit-inventory-reader-diagnostic-source-final01.tar.gz']),
    ):
        root = BASE/source
        for name in archives:
            path = root/name
            raw, plain, members = tar_members(path)
            # Minimal stage archives are flat. Complete evidence archives preserve their declared roots.
            candidate = root/'source-package' if source.startswith('prelaunch_') and 'source-stage' in name else root/'package'
            member_root = root if all((root/n).is_file() for n in members) else candidate
            assert all((member_root/n).is_file() for n in members)
            if 'full-evidence' in name:
                selected_roots = ('evidence', 'source-package') if source.startswith('prelaunch_') else ('evidence', 'package')
                expected = {p.relative_to(root).as_posix() for part in selected_roots for p in rows(root/part)}
                if source.startswith('consumer_'):
                    expected |= {'DELIVERY-EVIDENCE-MANIFEST.json', 'inventory-prefix-consumer-source-stage-final01.tar.gz'}
            else:
                expected = {p.relative_to(member_root).as_posix() for p in rows(member_root)}
            verify_archive_tree(path, member_root, expected)
            S.add(str(path.relative_to(BASE)), target+'/'+name, 'reviewed_source_archives')
        for name in ('DELIVERY.json', 'DELIVERY-EVIDENCE-MANIFEST.json', 'STAGE-DELIVERY.json'):
            if (root/name).is_file():
                S.add(str((root/name).relative_to(BASE)), target+'/'+name, 'reviewed_source_delivery')

    for source, target in (
        ('runtime_prefix_successor_candidate01/actual-stage13', 'stage13-runtime-root-prefix'),
        ('consumer_prefix_successor_candidate01/actual-stage14', 'stage14-consumer-prefix'),
    ):
        root = BASE/source
        bundle(target+'-complete-host-records', root,
            note='Complete existing source-stage host records, including exact stdin source, request, controller terminal/read, file readback and verification. No staged entrypoint was executed.')
        for name in ('RESULT.original.json', 'STAGED-FILES.original.json', 'SOURCE-MANIFEST.original.json', 'STAGE-VERIFICATION.json'):
            S.add(str((root/name).relative_to(BASE)), 'source-stages/'+target+'/'+name, 'actual_source_stages')

    observed_group('actual_neg01_1ad3_01/reconciliation/profile-read01', 'actual-neg01/readonly-profile-partial-d3f',
        'READONLY_VERIFICATION_FAILED_OR_PARTIAL_RETAIN_ORIGINALS', 'd3f599e7adbb7b249e7da0550d48964d42713e6ac3989e16b0d3b0ca9d13e1f4')
    observed_group('actual_neg01_1ad3_01/reconciliation/retired-read02', 'actual-neg01/readonly-global-118d',
        'ACTUAL08_ORIGINAL_GLOBAL_VERIFICATION_RETURNED_AND_LOCK_RELEASED', '118d821b2007c41b6cea23ced070452c7376aa31b2829c7c4fb91e6724c0c5ba')
    observed_group('actual_neg01_1ad3_01/reconciliation/current-publication-read01', 'actual-neg01/readonly-publication-1956',
        'TWO_FAILED_NONCES_UNPUBLISHED_SELECTED_ORIGINAL_UNCHANGED', '1956c026152ff82a9c3065388139c8782c55c5788afa9cfeacfef054651f18ed')
    observed_group('actual_external_r8_cascade_and_09/phone-stage-read01', 'external-neg01-09/readonly-stage-a460',
        'EXACT_STAGED_TREE_RETAINED_NO_LAUNCH_ARTIFACTS_OBSERVED', 'a460562d2217bcbbd167ac6a4ae2e38d4713da05dee8b57337ff4ce3eceb37be')
    observed_group('actual_neg01_1ad3_01/reconciliation/explicit-prefix-diagnostic01', 'actual-neg01/explicit-prefix-diagnostic-65aa',
        'EXPLICIT_147CF_READONLY_DIAGNOSTIC_RETURNED_AND_LOCK_RELEASED', '65aa1db1beb25aad324a1e7a027eb235f65392083a7fbdb0cae3362db7d44479')

    own = BASE/'actual_neg01_1ad3_01/reconciliation'
    own_skip = {'profile-read01', 'retired-read02', 'current-publication-read01', 'explicit-prefix-diagnostic01'}
    own_archives = {'SENDER-ORIGINALS.tar.xz', 'component-inputs.original.tar.gz'}
    own_records = [p for p in rows(own) if p.relative_to(own).parts[0] not in own_skip and p.name not in own_archives
                   and not (p.parent.name == 'component-inputs-read01' and p.suffix == '.bin')]
    bundle('our-failed-prelaunch-reconciliation-host-records', own, own_records,
        'Existing failure reconciliation sources, controller receipts, stage-only observations, restoration and later process-absence records. Two exact payload archives and four later observation groups are separate. Redundant verified component .bin chunks are excluded; interrupted sender download 00.bin and its error are retained.')
    for name in own_archives:
        S.add(str((own/name).relative_to(BASE)), 'actual-neg01/reconciliation-archives/'+name, 'our_failed_prelaunch_original_archives')
    raw, plain, own_sender = tar_members(own/'SENDER-ORIGINALS.tar.xz')
    sender_mf = json.loads(S.read(own/'SENDER-ORIGINALS-MANIFEST.original.json'))
    assert len(own_sender) == 171 and sender_mf['source_file_count'] == 170
    for row in sender_mf['files']:
        name = 'sender-originals/'+row['relative_path']
        body = own_sender[name]
        assert len(body) == row['bytes'] and S.sha(body) == row['sha256']
    ARCHIVES.append({'archive': S.desc(own/'SENDER-ORIGINALS.tar.xz', raw), 'regular_members': 171,
        'original_sender_members': 170, 'all_sender_member_pins_verified': True,
        'scope': 'Lossless XZ mirror of original sender tar; does not retrofit the original parent join/EOF.'})
    for p in sorted((own/'component-inputs-read01').glob('*.bin')):
        body = S.read(own/'component-inputs.original.tar.gz')
        i = int(p.stem)
        assert S.read(p) == body[i*65536:(i+1)*65536]

    external = BASE/'actual_external_r8_cascade_and_09'
    rec = external/'reconciliation-1ad3-readonly01'
    ext_maps = [('SENDER-ORIGINALS.tar.xz', 'p4-originals'), ('MAC-ORIGINALS-AND-OBSERVATIONS.tar.xz', 'mac-originals'),
                ('component-inputs.original.tar.xz', 'component-originals')]
    excluded = {x[0] for x in ext_maps} | {x[1] for x in ext_maps}
    for archive, extracted in ext_maps:
        expected = {p.relative_to(rec/extracted).as_posix() for p in rows(rec/extracted)}
        verify_archive_tree(rec/archive, rec/extracted, expected)
        S.add(str((rec/archive).relative_to(BASE)), 'external-neg01-09/reconciliation-archives/'+archive, 'external09_original_archives')
    bundle('external09-reconciliation-host-records', rec,
        [p for p in rows(rec) if p.relative_to(rec).parts[0] not in excluded],
        'Collectors, exact raw controller/binary-read receipts, archive manifests and byte verification reports. Expanded sender/component/Mac members are omitted only because all are byte-checked against the three published exact XZ archives. Component XZ preserves tar plaintext, not the original gzip encoding.')
    bundle('external09-root-and-canonical-cascade-snapshot', external,
        [p for p in rows(external) if p.relative_to(external).parts[0] not in ('reconciliation-1ad3-readonly01', 'phone-stage-read01')],
        'Selected actual external Root plan/material/chain/failure/send-result, source and fixed canonical cascade descriptors currently downloaded. This is not a claim that all external Root-chain prefixes are locally complete.')
    for name in ('COLLECTION-DELIVERY.json', 'COLLECTOR-SOURCE-REVIEW.json', 'P4-SENDER-ARCHIVE-MANIFEST.original.json'):
        S.add(str((rec/name).relative_to(BASE)), 'external-neg01-09/reconciliation-archives/'+name, 'external09_collection_verification')

    timing = BASE/'neg01_prelaunch_timing_review'
    bundle('failed-prelaunch-timing-complete-local-records', timing,
        note='Complete existing timing review, exact 25 retained stage originals, raw read receipts, derived timing and partial-profile attribution. Local analysis only; not a new case.')
    for name in ('DIAGNOSTIC-REVIEW.json', 'DIAGNOSTIC-REVIEW.md', 'TIMING-ANALYSIS.json'):
        S.add(str((timing/name).relative_to(BASE)), 'prelaunch-timing/'+name, 'prelaunch_timing')
    reviews = [
        ('transport_fix/failed-prelaunch-publication-independent01/REVIEW.json', 'FAILED-PRELAUNCH-PUBLICATION-INDEPENDENT.json'),
        ('transport_fix/runtime-prefix-helper-independent02/REVIEW.json', 'RUNTIME-PREFIX-HELPER-INDEPENDENT.json'),
        ('transport_fix/runtime-prefix-cascade-normalization-review01/REVIEW.json', 'RUNTIME-PREFIX-CASCADE-NORMALIZATION-INDEPENDENT.json'),
        ('transport_fix/inventory-prefix-independent01/REVIEW.json', 'INVENTORY-PREFIX-INDEPENDENT.json'),
        ('transport_fix/neg01-stage-probe-independent01/REVIEW.json', 'NEG01-STAGE-READONLY-PROBE-INDEPENDENT.json'),
        ('transport_fix/neg01-readonly-profile-independent01/REVIEW.json', 'NEG01-PROFILE-INDEPENDENT.json'),
        ('transport_fix/neg01-noinstrumentation-independent02/REVIEW.json', 'NEG01-UNINSTRUMENTED-ORIGINAL-VERIFICATION-INDEPENDENT.json'),
        ('explicit_inventory_reader_diagnostic_candidate01/root-review01/REVIEW.json', 'EXPLICIT-READER-DIAGNOSTIC-ROOT-REVIEW.json'),
    ]
    for source, name in reviews:
        S.add(source, 'checkpoint05-reviews/'+name, 'independent_source_reviews')

    coverage.update({'groups': S.GROUPS, 'complete_source_groups': len(S.GROUPS),
        'draft03_archives': ARCHIVES, 'draft03_observations': OBSERVATIONS,
        'draft02_329_entries_preserved_verbatim': True,
        'scope_note': 'Byte preservation and source/record coverage only. Formal two-failed-prelaunch admission assembler is pending. The original failed parents remain unjoined/unknown in their original records.'})
    cov_path = OUT/'CHECKPOINT05-MANIFEST-COVERAGE.draft03.json'
    write(cov_path, S.enc(coverage))
    S.add(str(cov_path.relative_to(BASE)), 'checkpoint05/CHECKPOINT05-MANIFEST-COVERAGE.draft03.json', 'checkpoint_status')
    status = {'schema': 'hepta.fixed19.checkpoint05.status.v1',
        'state': 'LOCAL_DRAFT03_FAILED_PRELAUNCH_OBSERVATIONS_RETAINED_FORMAL_ADMISSION_PENDING',
        'whole_case_qualified': 0, 'whole_case_total': 19,
        'host_isolated_lifecycle_layer': {'passed': 5, 'total': 5, 'scope': 'Previously published checkpoint03 host originals; not five complete physical-case qualifications.'},
        'actual_policy_comparison_layer': {'passed': 16, 'total': 16, 'elapsed_seconds': 339.780211539, 'returncode': 0,
            'actual_policy_sha256_prefix': 'f8219f9c', 'scope': 'Previously published actual independent post report; separate from whole-case acceptance.'},
        'failed_attempts': [
            {'label': 'root-r10-neg01-20261105-09', 'nonce': '7c79195945d64e569a191166ac122a08', 'zero_send_observed': True, 'draft_restore_observed': True},
            {'label': 'root-r10-neg01-1ad3-01', 'nonce': '7c74b84aefb177d15f746fa7eae29d54', 'zero_send_observed': True, 'draft_restore_observed': True}],
        'formal_failed_prelaunch_admission_complete': False, 'new_case_nonce_generated': False,
        'original_failed_parent_join_or_eof_retrofitted': False,
        'last_real_native_boundary_sha256': 'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10',
        'readonly_original_global_118d_completed': True, 'readonly_publication_1956_completed': True,
        'readonly_external09_stage_a460_completed': True, 'instrumented_d3f_profile_partial_preserved': True,
        'explicit_derived_reader_diagnostic': {'wall_seconds': 43.907661, 'original_reader_wall_seconds': 45.949364,
            'difference_seconds': 2.041703, 'original_global_clearance_claimed': False, 'new_runtime_phone_stage_claimed': False,
            'production_deadline_fit_guaranteed': False, 'case_qualification_claimed': False},
        'source_stage13': 'runtime and Root successor only', 'source_stage14': 'consumer successor only',
        'source_stage13_or_14_entrypoint_executions': 0,
        'actual_retention_provenance': {'executed': 'd960 with original860a transport', 'ours6193_0374_executed': False},
        'prior_published_commit': '6a16a332baa4a09a6a8495673949db897821574b',
        'git_writes': 0, 'remote_calls_by_this_builder': 0, 'phone_calls_by_this_builder': 0,
        'pending': ['Formal assembler re-read of both failed attempts and publication/global evidence.',
                    'Any missing actual prefix/GZIP original bytes remain explicitly outside this snapshot until supplied.',
                    'No new case may be inferred from source staging or this index; Root reviews publication separately.']}
    status_path = OUT/'STATUS.checkpoint05.draft03.json'
    write(status_path, S.enc(status))
    S.add(str(status_path.relative_to(BASE)), 'checkpoint05/STATUS.checkpoint05.draft03.json', 'checkpoint_status')
    readme = '''# Checkpoint05 — draft03, local review only

## Acceptance status

The 19 whole acceptance cases remain **0/19 qualified**. The host-isolated lifecycle layer is **5/5** and the actual policy comparison is **16/16**, return code 0, 339.780211539 seconds. Those two layers are separate evidence and do not qualify the physical end-to-end cases. Their original records were published in earlier checkpoints.

Both failed NEG01 attempts are retained: external `root-r10-neg01-20261105-09` and our `root-r10-neg01-1ad3-01`. Both have observed zero Send and original-draft restoration; later process-absence observations and current publication checks are retained. Neither failure is turned into PASS. Their original parent join/EOF failures remain unchanged. The formal two-attempt admission assembler is still pending, and no next-case nonce has been generated.

## What this revision adds

This revision preserves all 329 draft02 entries byte-for-byte and adds complete frozen runtime/Root/consumer source packages, the one-expression inventory-prefix change, source-stage13/14 records, full timing evidence, both sender/component original archives, and read-only observation originals. The original instrumented d3f profile remains a partial failure. The uninstrumented 118d original-global verifier returned and released its lock; current1956 showed both failed nonces unpublished with selected content unchanged; the external09 a460 stage probe retained the exact staged tree without launch artifacts. Each observation retains its actual source, wrapper/controller terminal and complete 12-file archive.

The explicit derived-reader 65aa diagnostic completed in 43.907661 seconds versus 45.949364 seconds for the original-reader measurement, about 2.041703 seconds shorter. Its comparison preserves the nine observed differences (fresh clocks and process census 950→951). This is a derived-reader diagnostic, not original-global clearance or a case result. It does not establish that the new runtime has been staged on the phone or guarantee the production prelaunch budget.

Stage13 and stage14 created only reviewed source packages in independent Mac namespaces. No staged entrypoint, case, plan, phone operation or runtime freeze was executed by those two stage jobs. The new native plan helper retains a required, unfilled failed-prelaunch verifier binding until formal evidence is available.

## Original bytes and archive scope

All declared members of the new source manifests are verified. Source manifests are preserved verbatim. Full XZ/tar archives retain large closed sets; their member inventories and byte comparisons are listed in `CHECKPOINT05-MANIFEST-COVERAGE.draft03.json`. New local `checkpoint05-evidence/*.tar.xz` files are storage containers, never substituted for a remote original. Their adjacent MEMBERS files record every source path, byte count, SHA256 and Git blob SHA.

The external09 component XZ preserves the original **tar plaintext**, not the gzip compressed byte stream. Its original gzip is 469839 bytes / 79106cab8e032e60958419e26506d80e78f7127a22300e9668949d573c0ff07c on Mac. Until the separately authorized exact gzip download is included, that compressed file is descriptor-only in this revision. Selected external Root prefixes and canonical cascade descriptors are preserved with their stated scope; no missing source or prefix is described as complete.

The actual policy export remains f8219f9c…. Actual retention was performed by d960 with the original860a transport. Our f6d8 template /6193 bound0374 collector was staged but not executed; this checkpoint does not misattribute the completed retention to that candidate. The 43 MB full post archive remains on P4 with its previously published descriptor.

## Publication

This is a local draft. It performs no Git writes, branch changes, remote calls or phone operations. Root reviews the exact publish index and uses a fresh compare-and-swap before publication. Failed histories and earlier draft entries are retained. The eventual formal admission result belongs in a later immutable revision.
'''
    readme_path = OUT/'README.checkpoint05.draft03.md'
    write(readme_path, readme.encode())
    S.add(str(readme_path.relative_to(BASE)), 'checkpoint05/README.checkpoint05.draft03.md', 'checkpoint_status')
    S.add('git_checkpoint05_delivery/build_draft03.py', 'checkpoint05/build_draft03.py', 'checkpoint_builder')

    index = sorted(S.INDEX.values(), key=lambda r: r['path'])
    lookup = {r['path']: r for r in index}
    assert len(lookup) == len(index)
    assert all(lookup[r['path']] == r for r in previous)
    existing = {r['path'] for n in ('git_host5_checkpoint03/PUBLISH-INDEX.json', 'git_checkpoint04_delivery/PUBLISH-INDEX.json')
                for r in json.loads(S.read(BASE/n))}
    assert not existing.intersection(lookup)
    for r in index:
        assert r['path'].startswith(S.PREFIX)
        safe(r['path'][len(S.PREFIX):])
        raw = S.read(BASE/r['local'])
        assert len(raw) == r['bytes'] and S.sha(raw) == r['sha256']
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == r['git_blob_sha']
        if r['encoding'] == 'utf-8': raw.decode('utf-8', 'strict')
        else: assert r['encoding'] == 'base64'
    index_path = S.OUT/'PUBLISH-INDEX.draft03.json'
    write(index_path, S.enc(index))
    write(S.OUT/'CHECKPOINT05-PROVENANCE-MAP.draft03.json', S.enc(S.PROVENANCE))
    write(S.OUT/'CHECKPOINT05-MANIFEST-COVERAGE.draft03.json', S.enc(coverage))
    write(S.OUT/'README.checkpoint05.draft03.md', readme.encode())
    final = {'schema': 'hepta.fixed19.checkpoint05.local-draft.v1', 'state': status['state'],
        'index': S.desc(index_path, S.read(index_path)), 'files': len(index),
        'text_files': sum(r['encoding'] == 'utf-8' for r in index), 'binary_files': sum(r['encoding'] == 'base64' for r in index),
        'total_bytes': sum(r['bytes'] for r in index), 'retained_draft02_entries': 329,
        'new_entries': len(index)-329, 'whole_cases': '0/19', 'formal_assembler_complete': False,
        'git_writes': 0, 'phone_calls': 0, 'all_sha256_and_git_blob_sha_verified': True}
    write(S.OUT/'DRAFT03-STATE.json', S.enc(final))
    print(json.dumps(final, sort_keys=True))


if __name__ == '__main__':
    main()
