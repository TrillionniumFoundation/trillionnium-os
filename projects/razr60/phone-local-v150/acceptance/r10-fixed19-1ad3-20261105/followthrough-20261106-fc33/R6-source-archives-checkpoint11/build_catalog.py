#!/usr/bin/env python3
"""Create a public source-original allowlist; does not contact GitHub or a phone."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REVIEW = HERE.parent
PREFIX = 'projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/'

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()

def put(name, data):
    with (HERE / name).open('xb') as stream:
        stream.write(data)

def main():
    selected = set()
    roots = [REVIEW / 'R6-source-rebind/actual-readback', REVIEW / 'R6-actual-source-graph01',
             REVIEW / 'R6-case-controller-source-fix01/actual-readback', REVIEW / 'R6-component-successor02']
    for root in roots:
        for path in root.rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                selected.add(path)
    selected.add(REVIEW / 'R6-source-rebind/observe_actual_package.py')
    for root in (REVIEW / 'R6-source-rebind/publication', REVIEW / 'R6-source-rebind/actual-stages',
                 REVIEW / 'R6-case-controller-source-fix01/publication'):
        selected.update(root.glob('ROOT-*.json'))
    selected.add(HERE / 'build_catalog.py')
    cache = {}
    def add_receipt(row, response, manifest):
        if not isinstance(response, dict) or response.get('isError') is not False:
            return
        sha = response.get('structuredContent', {}).get('sha')
        expected = row.get('git_blob_sha', row.get('blob_sha', row.get('actual_blob_sha')))
        if sha != expected or not isinstance(sha, str) or len(sha) != 40:
            return
        if type(row.get('bytes')) is not int or type(row.get('sha256')) is not str:
            return
        cache[(row['bytes'], row['sha256'], sha)] = {
            'actual_create_blob_response': response,
            'prior_publication_manifest': {'path': str(manifest), **pin(manifest.read_bytes())}
        }
    for path in sorted(REVIEW.rglob('ACTUAL-GITHUB-PUBLICATION.json')):
        document = json.loads(path.read_bytes())
        for row in document.get('files', []):
            add_receipt(row, row.get('actual_create_blob_response', row.get('api_response')), path)
    for path in sorted(REVIEW.rglob('GIT-BLOB-MAP.json')):
        document = json.loads(path.read_bytes()); receipts = document.get('actual_tool_receipts', {})
        if isinstance(receipts, dict):
            for row in document.get('files', []):
                sha = row.get('git_blob_sha', row.get('blob_sha'))
                add_receipt(row, receipts.get(sha, {}).get('response'), path)
    rows = []
    for path in sorted(selected):
        relative = str(path.relative_to(REVIEW))
        raw = path.read_bytes(); raw.decode('utf-8', errors='strict')
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        row = {'local_path': str(path), 'relative_path': relative, 'git_path': PREFIX + relative,
               **pin(raw), 'expected_git_blob_sha1': blob, 'encoding': 'utf-8'}
        prior = cache.get((len(raw), row['sha256'], blob))
        if prior is not None:
            row['verified_prior_publication'] = prior
        rows.append(row)
    groups = {}
    for row in rows:
        groups.setdefault(row['relative_path'].split('/')[0], 0)
        groups[row['relative_path'].split('/')[0]] += 1
    catalog = {'schema': 'hepta.fc33.r6.public-source-original-upload-catalog.v1',
               'repository_full_name': 'TrillionniumFoundation/trillionnium-os', 'remote_prefix': PREFIX,
               'file_count': len(rows), 'total_bytes': sum(row['bytes'] for row in rows), 'groups': groups,
               'files': rows, 'phone_calls': 0, 'tree_created': False, 'commit_created': False, 'ref_changed': False,
               'private_phone_capture_or_preserved_draft_bytes_selected': False,
               'scope': 'Only complete actual host source directories, public source/controller originals, and their independent readback evidence. No task or installation qualification.'}
    put('UPLOAD-CATALOG.json', enc(catalog))
    unique = {row['expected_git_blob_sha1']: row for row in rows}
    reusable = {row['expected_git_blob_sha1'] for row in rows if 'verified_prior_publication' in row}
    print(json.dumps({'files': len(rows), 'bytes': catalog['total_bytes'], 'unique_blobs': len(unique),
                      'reusable_actual_blobs': len(reusable), 'groups': groups,
                      'catalog': pin(enc(catalog)), 'largest': sorted([(r['bytes'], r['relative_path']) for r in unique.values()], reverse=True)[:6]}, sort_keys=True))

if __name__ == '__main__':
    main()
