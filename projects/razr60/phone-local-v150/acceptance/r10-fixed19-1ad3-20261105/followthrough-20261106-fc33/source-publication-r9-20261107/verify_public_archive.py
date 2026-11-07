#!/usr/bin/env python3
"""Verify the public R9 review archive without private inputs or source execution."""
from __future__ import annotations
import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import zlib
import sys


AST_NORMALIZER = 'python312-compatible-ast-dump.v1'


def canonical_ast_dump(tree):
    """Keep all semantic fields and empty lists in the pinned Python 3.12 format."""
    require(sys.version_info >= (3, 12), 'Python 3.12 or newer is required for AST proofs')
    if sys.version_info[:2] == (3, 12):
        return ast.dump(tree, include_attributes=False).encode()
    return ast.dump(tree, include_attributes=False, show_empty=True).encode()


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def member(root, name):
    path = PurePosixPath(name)
    require(name == path.as_posix() and path.parts and not path.is_absolute()
            and '..' not in path.parts, 'unsafe archive path')
    current = root
    for part in path.parts:
        current = current / part
        require(not current.is_symlink(), 'archive symlink refused')
    require(current.is_file() and current.resolve().is_relative_to(root), 'missing archive member')
    return current


def verify_ast(data, proof):
    require(proof['normalizer'] == AST_NORMALIZER, 'unknown AST proof normalizer')
    tree = ast.parse(data.decode())
    declared = set(proof['changed_literal_ast_paths'])
    require(len(declared) == len(proof['changed_literal_ast_paths']), 'duplicate AST path')
    visited = set()

    def visit(value, path):
        if path in declared:
            require(isinstance(value, ast.Constant) and isinstance(value.value, str),
                    'declared change is not a string constant')
            value.value = 'PUBLICATION_PRIVATE_LITERAL'
            visited.add(path)
        if isinstance(value, ast.AST):
            for field in value._fields:
                visit(getattr(value, field), path + '.' + field)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + '[' + str(index) + ']')

    visit(tree, 'Module')
    require(visited == declared, 'declared AST path missing')
    require(sha(canonical_ast_dump(tree)) == proof['normalized_ast_sha256'],
            'normalized public predicate identity mismatch')


def decoded_payload_hashes(data):
    hashes = set()
    for node in ast.walk(ast.parse(data.decode())):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str) or len(node.value) < 256:
            continue
        try:
            decoded = base64.b64decode(node.value, validate=True)
        except ValueError:
            continue
        try:
            decoded = zlib.decompress(decoded)
        except zlib.error:
            pass
        hashes.add(sha(decoded))
    return hashes


def verify(manifest_path, expected):
    require(not manifest_path.is_symlink(), 'manifest symlink refused')
    raw = manifest_path.read_bytes()
    require(len(expected) == 64 and sha(raw) == expected, 'manifest identity mismatch')
    manifest = json.loads(raw)
    require(manifest['schema'] == 'razr60.r9.rebuildable-source-publication.v1', 'schema mismatch')
    root = manifest_path.parent.resolve()
    files = manifest['files']
    require(len(files) == manifest['original_source_file_count'] == 14, 'source set mismatch')
    require(not (root / manifest['private_binding']['file_name']).exists(), 'private binding in public archive')
    expected_paths = set()
    embedded = set()
    redactions = 0
    for item in files:
        name = item['public_path']
        require(name == 'sources/' + item['logical_path'] + '.txt', 'source review suffix mismatch')
        require(name not in expected_paths, 'duplicate source path')
        expected_paths.add(name)
        data = member(root, name).read_bytes()
        require(len(data) == item['public_bytes'] and sha(data) == item['public_sha256'], 'public member mismatch')
        verify_ast(data, item['predicate_invariant'])
        embedded.update(decoded_payload_hashes(data))
        cursor = 0
        for index, redaction in enumerate(item['redactions']):
            start, end = redaction['public_start'], redaction['public_end']
            require(redaction['index'] == index and cursor <= start < end <= len(data), 'invalid redaction span')
            require(sha(data[start:end]) == redaction['public_span_sha256'], 'redaction bytes mismatch')
            cursor = end
            redactions += 1
    for item in manifest['expanded_review_sources']:
        data = member(root, item['path']).read_bytes()
        expected_paths.add(item['path'])
        require(len(data) == item['public_bytes'] and sha(data) == item['public_sha256'], 'expanded member mismatch')
        if item['kind'] == 'python':
            verify_ast(data, item['predicate_invariant'])
            embedded.update(decoded_payload_hashes(data))
        else:
            require(item['kind'] == 'json', 'unexpected expanded kind')
            json.loads(data)
    for item in manifest['expanded_review_sources']:
        require(item['public_sha256'] in embedded, 'expanded member not linked to an embedded payload')
    actual = {str(p.relative_to(root)) for folder in ('sources', 'expanded')
              for p in (root / folder).rglob('*') if p.is_file()}
    require(actual == expected_paths, 'source archive member set mismatch')
    return {'schema': 'razr60.r9.public-archive-verification.v1',
            'source_manifest_sha256': expected, 'source_file_count': len(files),
            'expanded_review_sources': len(manifest['expanded_review_sources']),
            'redaction_count': redactions, 'public_member_hashes_verified': True,
            'public_ast_identities_verified': True, 'embedded_payload_links_verified': True,
            'private_binding_included': False, 'source_execution_count': 0,
            'runtime_adopted': False, 'fixed19_credit': 0}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', type=Path, default=Path(__file__).with_name('SOURCE-MANIFEST.json'))
    ap.add_argument('--expected-manifest-sha256', required=True)
    args = ap.parse_args()
    print(json.dumps(verify(args.manifest, args.expected_manifest_sha256), sort_keys=True))


if __name__ == '__main__':
    main()
