#!/usr/bin/env python3
"""Rebuild the owner phone chain from the frozen, unchanged ordinary phone files.

This is a source selection check. Actual generated product packages and compiled
artifacts remain separate build requirements.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time

PREFIX = 'android-integration/working-tree/vendor/trillionnium/config/'
RULES = (
    ('common_mobile.mk', 'common_owner_open_mobile.mk', 'common.mk', 'common_owner_open.mk',
     1949, 'edfb5cffbef72a74c813e43cb71f17407cc9251c5c10f3fb20d819682b5e7226',
     '34abf9b19e31b32469edcb5449e50006d9162950'),
    ('common_mobile_full.mk', 'common_owner_open_mobile_full.mk', 'common_mobile.mk', 'common_owner_open_mobile.mk',
     864, '69a6dcd1f46c0c9011655962facdeb947bdb1919c7888ac87075b02221ccd6d9',
     '8e8adff898714deef0e40b2d76cf163e724338c7'),
    ('common_full_phone.mk', 'common_owner_open_full_phone.mk', 'common_mobile_full.mk', 'common_owner_open_mobile_full.mk',
     294, '4832c01e08517f2bb697bb527090a0e5fdbfecae43d47d926c23fdaf8cf9d6f9',
     'a6ea62b97a761cc11d911d5d9fb9982c232cfc52'),
)
SCHEMA = 'org.trillionnium.android.owner-open-phone-chain-source-rules.v1'
FOGOS_BEFORE_SHA = 'f074b015970624d0fe046bf1e7e4cadd0a2594b4ab75f791a9bca3130e04bb5a'
FOGOS_AFTER_SHA = 'bd43e0a253130b1a95b023f82270a4e3a3cbbae0b48fbaa9bef602b5e1a32dbf'
FOGOS_REMOVED_SUFFIX = (b'\n# Private exact-candidate Owner-Open integration selection.\n'
                        b'$(call inherit-product, vendor/trillionnium/owner-open/product.mk)\n')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def budget(deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError('whole owner phone chain deadline')


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def parent_fd(path, deadline):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'canonical absolute path required')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            budget(deadline)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        return parent
    except BaseException:
        os.close(parent)
        raise


def read_source(path, deadline, maximum=128 * 1024):
    path = Path(path)
    parent = parent_fd(path, deadline)
    fd = None
    try:
        budget(deadline)
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_size <= maximum, 'bounded single-link ordinary source required')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        need(identity(os.fstat(fd)) == identity(before), 'source descriptor differs')
        chunks = []
        count = 0
        while True:
            budget(deadline)
            block = os.read(fd, min(65536, maximum - count + 1))
            if not block:
                break
            count += len(block)
            need(count <= maximum and count <= before.st_size, 'actual source read byte bound')
            chunks.append(block)
        need(count == before.st_size and identity(os.fstat(fd)) == identity(before) ==
             identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'source changed during read')
        budget(deadline)
        return b''.join(chunks)
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            os.close(parent)


def unique_json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            need(name not in result, 'duplicate source rule member')
            result[name] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def inherit(name):
    return '$(call inherit-product, vendor/trillionnium/config/' + name + ')'


def rewrite_fogos_private_product(body):
    """Apply the closed correction to the previously declared private product."""
    need(type(body) is bytes and len(body) == 1224 and
         hashlib.sha256(body).hexdigest() == FOGOS_BEFORE_SHA,
         'exact previous private Fogos source required')
    anchor = inherit('common_full_phone.mk').encode()
    replacement = inherit('common_owner_open_full_phone.mk').encode()
    need(body.count(anchor) == 1 and body.count(FOGOS_REMOVED_SUFFIX) == 1 and
         body.endswith(FOGOS_REMOVED_SUFFIX), 'exact previous Fogos inherit/suffix required')
    changed = body.replace(anchor, replacement)[:-len(FOGOS_REMOVED_SUFFIX)]
    need(len(changed) == 1107 and hashlib.sha256(changed).hexdigest() == FOGOS_AFTER_SHA,
         'closed Fogos afterimage differs')
    return changed


def expected_outputs(root, deadline):
    root = Path(root).absolute()
    metadata_path = root / 'tools/owner-open-phone-chain.v1.json'
    metadata_raw = read_source(metadata_path, deadline, 16 * 1024)
    metadata = unique_json(metadata_raw)
    need(metadata.get('schema') == SCHEMA and
         metadata.get('original_project_name') == 'TrillionniumFoundation/android-vendor-trillionnium' and
         metadata.get('original_project_path') == 'vendor/trillionnium' and
         metadata.get('original_project_head') == 'f4d6c69727908d906d4854671140df6f533ec231' and
         metadata.get('original_project_tree') == '8b70d4c83afeac95d51069c3bc67dfebf02cbd77' and
         metadata.get('source_bom_qualified') is False and
         metadata.get('independent_approval_asserted') is False,
         'frozen baseline provenance required; no source authority qualification')
    need(type(metadata.get('rules')) is list and len(metadata['rules']) == len(RULES),
         'exact three source rewrite rules required')
    fogos = metadata.get('private_fogos_entrypoint_patch')
    need(type(fogos) is dict and all(fogos.get(key) == value for key, value in {
        'project': 'device/motorola/fogos',
        'private_head': '5ee0dd2925b701f62d56eaa12204fa1ee7ba28ed',
        'private_tree': '33959e5d40321ecf171f68844ea151a06f3b9aae',
        'git_blob': '3b9cd86f2cce017c2f47e6fc0fd030b612268df1',
        'relative': 'trillionnium_fogos.mk', 'before_bytes': 1224,
        'before_sha256': FOGOS_BEFORE_SHA, 'after_bytes': 1107,
        'after_sha256': FOGOS_AFTER_SHA,
        'from_inherit': inherit('common_full_phone.mk'),
        'to_inherit': inherit('common_owner_open_full_phone.mk'),
        'removed_suffix': FOGOS_REMOVED_SUFFIX.decode(),
    }.items()), 'exact previous private Fogos source and closed rewrite required')
    snapshots = {metadata_path: metadata_raw}
    outputs = {}
    for rule, declared in zip(RULES, metadata['rules']):
        baseline, owner, old, new, size, sha, blob = rule
        path = root / (PREFIX + baseline)
        body = read_source(path, deadline)
        actual_blob = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
        need(len(body) == size and hashlib.sha256(body).hexdigest() == sha and actual_blob == blob,
             'sealed original source bytes differ: ' + baseline)
        old_anchor, new_anchor = inherit(old).encode(), inherit(new).encode()
        need(body.count(old_anchor) == 1, 'exact single baseline inherit anchor required')
        generated = body.replace(old_anchor, new_anchor)
        expected = dict(baseline=PREFIX + baseline, owner_output=PREFIX + owner,
                        baseline_bytes=size, baseline_sha256=sha, baseline_git_blob=blob,
                        from_inherit=old_anchor.decode(), to_inherit=new_anchor.decode(),
                        owner_bytes=len(generated), owner_sha256=hashlib.sha256(generated).hexdigest())
        need(type(declared) is dict and declared == expected and
             type(declared.get('baseline_bytes')) is int and type(declared.get('owner_bytes')) is int,
             'closed source rule metadata differs')
        snapshots[path] = body
        outputs[root / (PREFIX + owner)] = generated
    budget(deadline)
    return outputs, snapshots


def write_generated(path, body, deadline):
    parent = parent_fd(path, deadline)
    fd = None
    temp_name = '.' + path.name + '.owner-open-' + str(os.getpid()) + '.tmp'
    published = False
    owned_identity = None
    try:
        try:
            before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            before = None
        need(before is None or (stat.S_ISREG(before.st_mode) and before.st_nlink == 1),
             'ordinary generated output entry required')
        budget(deadline)
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o644, dir_fd=parent)
        created = os.fstat(fd)
        owned_identity = (created.st_dev, created.st_ino)
        os.fchmod(fd, 0o644)
        offset = 0
        while offset < len(body):
            budget(deadline)
            written = os.write(fd, body[offset:])
            need(written > 0, 'generated output write made no progress')
            offset += written
        os.fsync(fd)
        owned = fd
        fd = None
        os.close(owned)
        budget(deadline)
        try:
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        need((before is None and current is None) or
             (before is not None and current is not None and identity(before) == identity(current)),
             'generated destination changed before publication')
        os.rename(temp_name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        published = True
        budget(deadline)
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            try:
                if not published and owned_identity is not None:
                    try:
                        current = os.stat(temp_name, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        if (current.st_dev, current.st_ino) == owned_identity:
                            os.unlink(temp_name, dir_fd=parent)
            finally:
                os.close(parent)


def check(root, write=False, seconds=15):
    deadline = time.monotonic() + seconds
    outputs, snapshots = expected_outputs(root, deadline)
    if write:
        for path, body in outputs.items():
            write_generated(path, body, deadline)
    for path, body in outputs.items():
        need(read_source(path, deadline) == body, 'owner phone config differs from exact source rewrite')
    for path, body in snapshots.items():
        need(read_source(path, deadline) == body, 'sealed source or rules changed during check')
    budget(deadline)
    return dict(ok=True, sealed_baselines=3, owner_outputs=3,
                ordinary_configuration_preserved_except_inherit_edges=True,
                actual_product_graph_qualified=False, actual_compiled_artifacts_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).absolute().parents[1])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--write', action='store_true')
    args = parser.parse_args()
    result = check(args.root, write=args.write)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
