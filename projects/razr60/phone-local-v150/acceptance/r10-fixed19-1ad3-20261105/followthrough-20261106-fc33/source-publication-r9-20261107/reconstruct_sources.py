#!/usr/bin/env python3
"""Restore exact reviewed R9 source bytes from a private binding, without running them."""
from __future__ import annotations
import argparse
import ast
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys


AST_NORMALIZER = 'python312-compatible-ast-dump.v1'


def canonical_ast_dump(tree: ast.AST) -> bytes:
    """Keep all semantic fields and empty lists in the pinned Python 3.12 format."""
    require(sys.version_info >= (3, 12), 'Python 3.12 or newer is required for AST proofs')
    if sys.version_info[:2] == (3, 12):
        return ast.dump(tree, include_attributes=False).encode()
    return ast.dump(tree, include_attributes=False, show_empty=True).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def relative(value: str) -> PurePosixPath:
    p = PurePosixPath(value)
    require(isinstance(value, str) and value == p.as_posix(), 'noncanonical relative path')
    require(not p.is_absolute() and all(x not in ('', '.', '..') for x in p.parts), 'unsafe path')
    require(bool(p.parts), 'empty path')
    return p


def read_regular(path: Path, limit: int) -> bytes:
    require(not path.is_symlink(), 'source symlink refused')
    with path.open('rb') as handle:
        st = os.fstat(handle.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_size <= limit, 'invalid source size/type')
        data = handle.read(limit + 1)
        require(len(data) == st.st_size and len(data) <= limit, 'source changed during read')
    return data


def verify_literal_structure(original: bytes, public: bytes, proof: dict) -> None:
    """Parse source as data; only declared string constants may differ."""
    require(proof['normalizer'] == AST_NORMALIZER, 'unknown AST proof normalizer')
    left, right = ast.parse(original.decode()), ast.parse(public.decode())
    changed = []

    def compare(a, b, path):
        require(type(a) is type(b), 'AST type changed: ' + path)
        if isinstance(a, ast.Constant):
            require(a.kind == b.kind, 'literal kind changed: ' + path)
            if a.value != b.value:
                require(isinstance(a.value, str) and isinstance(b.value, str),
                        'non-string literal changed: ' + path)
                changed.append(path)
                a.value = b.value = 'PUBLICATION_PRIVATE_LITERAL'
        elif isinstance(a, ast.AST):
            require(a._fields == b._fields, 'AST fields changed: ' + path)
            for field in a._fields:
                compare(getattr(a, field), getattr(b, field), path + '.' + field)
        elif isinstance(a, list):
            require(len(a) == len(b), 'AST list changed: ' + path)
            for index, (x, y) in enumerate(zip(a, b)):
                compare(x, y, path + '[' + str(index) + ']')
        else:
            require(a == b, 'non-literal predicate changed: ' + path)

    compare(left, right, 'Module')
    normalized = canonical_ast_dump(left)
    require(normalized == canonical_ast_dump(right),
            'normalized AST mismatch')
    require(changed == proof['changed_literal_ast_paths'], 'literal change inventory mismatch')
    require(sha(normalized) == proof['normalized_ast_sha256'], 'predicate proof identity mismatch')


def reconstruct(manifest_path: Path, expected_manifest_sha256: str,
                binding_path: Path, output: Path) -> dict:
    require(len(expected_manifest_sha256) == 64, 'complete manifest SHA-256 required')
    manifest_bytes = read_regular(manifest_path, 8 * 1024 * 1024)
    require(sha(manifest_bytes) == expected_manifest_sha256, 'manifest identity mismatch')
    manifest = json.loads(manifest_bytes)
    require(manifest['schema'] == 'razr60.r9.rebuildable-source-publication.v1', 'schema mismatch')
    private_bytes = read_regular(binding_path, 8 * 1024 * 1024)
    pin = manifest['private_binding']
    require(len(private_bytes) == pin['bytes'] and sha(private_bytes) == pin['sha256'],
            'private binding identity mismatch')
    binding = json.loads(private_bytes)
    require(binding['schema'] == 'razr60.r9.private-source-literal-binding.v1', 'binding schema mismatch')
    salt = base64.b64decode(binding['commitment_salt_base64'], validate=True)
    require(len(salt) == 32, 'invalid private commitment salt')
    files = manifest['files']
    require(len(files) == manifest['original_source_file_count'] == 14, 'source set changed')
    names = [f['logical_path'] for f in files]
    require(len(names) == len(set(names)) and set(names) == set(binding['files']), 'binding source set changed')
    root = manifest_path.parent.resolve(strict=True)
    restored = []
    for item in files:
        logical = relative(item['logical_path'])
        public_rel = relative(item['public_path'])
        public_path = root.joinpath(*public_rel.parts)
        require(public_path.resolve(strict=True).is_relative_to(root), 'public source escaped archive')
        current = root
        for part in public_rel.parts:
            current = current / part
            require(not current.is_symlink(), 'public source symlink refused')
        data = read_regular(public_path, 2 * 1024 * 1024)
        require(len(data) == item['public_bytes'] and sha(data) == item['public_sha256'],
                'public source identity mismatch: ' + str(logical))
        originals = binding['files'][str(logical)]
        replacements = item['redactions']
        require(len(originals) == len(replacements), 'redaction count mismatch')
        chunks, cursor = [], 0
        for index, (public, private) in enumerate(zip(replacements, originals)):
            require(public['index'] == private['index'] == index, 'redaction identity mismatch')
            start, end = public['public_start'], public['public_end']
            require(type(start) is int and type(end) is int and cursor <= start <= end <= len(data),
                    'overlapping/out-of-range redaction')
            require(sha(data[start:end]) == public['public_span_sha256'], 'public redaction bytes changed')
            original = base64.b64decode(private['original_base64'], validate=True)
            require(len(original) == public['original_bytes'], 'private literal length mismatch')
            require(hmac.new(salt, original, hashlib.sha256).hexdigest() == public['original_span_commitment'],
                    'private literal commitment mismatch')
            chunks.extend([data[cursor:start], original])
            cursor = end
        chunks.append(data[cursor:])
        original = b''.join(chunks)
        require(len(original) == item['original_bytes'] and sha(original) == item['original_sha256'],
                'restored original identity mismatch: ' + str(logical))
        verify_literal_structure(original, data, item['predicate_invariant'])
        restored.append((logical, original))
    require(not output.exists() and not output.is_symlink(), 'create-only output already exists')
    # All 14 outputs are fully authenticated in memory before publication starts.
    # The root is created exclusively. Nothing is imported, evaled, or executed.
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    result_files = []
    for logical, data in restored:
        dest = output.joinpath(*logical.parts)
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        cursor = output
        for part in logical.parts[:-1]:
            cursor = cursor / part
            require(not cursor.is_symlink(), 'output directory symlink refused')
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        result_files.append({'logical_path': str(logical), 'bytes': len(data), 'sha256': sha(data)})
    result = {'schema': 'razr60.r9.exact-source-restoration.v1',
              'manifest_sha256': expected_manifest_sha256,
              'private_binding_sha256': pin['sha256'], 'files': result_files,
              'source_file_count': 14, 'all_original_bytes_restored': True,
              'source_execution_count': 0, 'phone_calls': 0,
              'runtime_adopted': False, 'fixed19_credit': 0}
    with (output / 'RESTORE-RESULT.json').open('x') as handle:
        json.dump(result, handle, sort_keys=True, indent=2)
        handle.write('\n')
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', required=True, type=Path)
    ap.add_argument('--expected-manifest-sha256', required=True)
    ap.add_argument('--private-binding', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    result = reconstruct(args.manifest, args.expected_manifest_sha256, args.private_binding, args.output)
    print(json.dumps({k: v for k, v in result.items() if k != 'files'}, sort_keys=True))


if __name__ == '__main__':
    main()
