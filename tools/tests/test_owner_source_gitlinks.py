"""Real local Gitlink references; no child content, Android or BOM qualification.

Each fixture makes two local repositories and commits a real child HEAD into
the parent's index. No submodule update, checkout, download or Git filter runs.
The indexed-store test uses a namespace-only 1170-project mechanism index;
only the one measured local project's descriptors are read.
"""
import base64
import copy
import os
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]


def source_module(name):
    path = TOOLS / (name + '.py')
    module = types.ModuleType('_gitlink_test_' + name)
    module.__file__ = str(path)
    # Execute the bytes under test, including when an ambient timestamp cache
    # exists. The production loader has its separate pinned-source contract.
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


m = source_module('owner_source_provenance')
surface = source_module('owner_source_surface')


class ActualGitlinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'parent'
        self.child = self.base / 'child'
        self.root.mkdir()
        self.child.mkdir()
        self.env = {
            'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_ATTR_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GIT_ALLOW_PROTOCOL': '', 'GIT_OPTIONAL_LOCKS': '0',
            'GIT_AUTHOR_NAME': 'Local Gitlink Fixture',
            'GIT_AUTHOR_EMAIL': 'fixture@local.invalid',
            'GIT_COMMITTER_NAME': 'Local Gitlink Fixture',
            'GIT_COMMITTER_EMAIL': 'fixture@local.invalid',
        }
        self.git(self.child, 'init', '-q')
        (self.child / 'ordinary.txt').write_bytes(b'unmeasured child content\n')
        self.git(self.child, 'add', 'ordinary.txt')
        self.git(self.child, 'commit', '-qm', 'real local child')
        self.child_head = self.git(self.child, 'rev-parse', 'HEAD').decode().strip()
        self.git(self.root, 'init', '-q')
        (self.root / 'ordinary.txt').write_bytes(b'measured parent source\n')
        (self.root / '.gitmodules').write_text(
            '[submodule "sdk"]\n\tpath = deps/sdk\n\turl = ./local-child\n')
        self.git(self.root, 'add', 'ordinary.txt', '.gitmodules')
        self.git(self.root, 'update-index', '--add', '--cacheinfo',
                 '160000,' + self.child_head + ',deps/sdk')
        self.commit_parent()

    def tearDown(self):
        self.temp.cleanup()

    def git(self, root, *args):
        result = subprocess.run(
            ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
             '-c', 'core.fsmonitor=false', '-c', 'commit.gpgsign=false',
             '-C', str(root), *args], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        return result.stdout

    def commit_parent(self):
        self.git(self.root, 'commit', '-qm', 'real local parent reference')
        self.head = self.git(self.root, 'rev-parse', 'HEAD').decode().strip()
        self.tree = self.git(self.root, 'rev-parse', 'HEAD^{tree}').decode().strip()

    def collect(self):
        return m.collect_git_checkout(
            self.root, self.head, self.tree, time.monotonic() + 10,
            'actual/local-parent')

    def empty_gitlink(self):
        (self.root / 'deps/sdk').mkdir(parents=True)

    def test_missing_parent_gitlink_retains_real_commit_not_blob(self):
        value = self.collect()
        self.assertEqual(value['schema'], 'org.trillionnium.owner-git-content-inventory.v3')
        self.assertEqual(len(value['gitlinks']), 1)
        ref = value['gitlinks'][0]
        self.assertEqual(ref['path'], 'deps/sdk')
        self.assertEqual(ref['git_commit'], self.child_head)
        self.assertEqual(ref['git_mode'], '160000')
        self.assertIs(ref['submodule_content_measured'], False)
        self.assertEqual(set(ref), {'path', 'git_mode', 'git_commit',
                                   'worktree_before', 'worktree_after',
                                   'submodule_content_measured'})
        state = ref['worktree_before']
        self.assertEqual(state, ref['worktree_after'])
        self.assertEqual((state['state'], state['absent_path']), ('missing', 'deps'))
        self.assertIsNone(state['entry_identity'])
        self.assertEqual([r['path'] for r in state['parent_entries']], [''])
        self.assertEqual(state['entries'], [])
        self.assertEqual({r['path'] for r in value['source_files']},
                         {'.gitmodules', 'ordinary.txt'})
        self.assertEqual(value['source_bytes'],
                         sum((self.root / path).stat().st_size
                             for path in ('.gitmodules', 'ordinary.txt')))
        raw = base64.b64decode(value['raw_ls_tree_base64'])
        parsed = m.parse_ls_tree(raw)
        self.assertEqual(m.tree_oid(parsed), self.tree)
        self.assertEqual(m.tree_oid(value['source_files'] + value['gitlinks']), self.tree)
        self.assertNotEqual(m.tree_oid(value['source_files']), self.tree)
        self.assertFalse(value['source_bom_qualified'])
        self.assertFalse(value['independent_approval_asserted'])

    def test_missing_leaf_binds_existing_parent_chain(self):
        (self.root / 'deps').mkdir()
        value = self.collect()
        state = value['gitlinks'][0]['worktree_before']
        self.assertEqual((state['state'], state['absent_path']), ('missing', 'deps/sdk'))
        self.assertEqual([r['path'] for r in state['parent_entries']], ['', 'deps'])
        self.assertEqual(state, value['gitlinks'][0]['worktree_after'])

    def test_empty_real_directory_two_observations_and_tree_reference(self):
        self.empty_gitlink()
        value = self.collect()
        state = value['gitlinks'][0]['worktree_before']
        self.assertEqual(state['state'], 'empty')
        self.assertIsNone(state['absent_path'])
        self.assertEqual(len(state['entry_identity']), 9)
        self.assertEqual([r['path'] for r in state['parent_entries']], ['', 'deps'])
        self.assertEqual(state, value['gitlinks'][0]['worktree_after'])
        self.assertEqual(state, m.observe_unmaterialized_gitlink(
            self.root, 'deps/sdk', time.monotonic() + 2))
        self.assertEqual(m.validate_inventory(value), value)

    def test_nonempty_child_payload_is_held_without_measuring_contents(self):
        self.empty_gitlink()
        (self.root / 'deps/sdk/ordinary.txt').write_bytes(
            (self.child / 'ordinary.txt').read_bytes())
        with self.assertRaisesRegex(m.SourceError, 'materialized gitlink'):
            m.observe_unmaterialized_gitlink(self.root, 'deps/sdk', time.monotonic() + 2)
        self.assertRaises(m.SourceError, self.collect)

    def test_symlink_regular_and_fifo_gitlink_entries_are_held(self):
        (self.root / 'deps').mkdir()
        leaf = self.root / 'deps/sdk'
        for kind in ('symlink', 'regular', 'fifo'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    leaf.symlink_to(self.child, target_is_directory=True)
                elif kind == 'regular':
                    leaf.write_bytes(b'not a child repository')
                else:
                    os.mkfifo(leaf)
                try:
                    self.assertRaises(m.SourceError, m.observe_unmaterialized_gitlink,
                                      self.root, 'deps/sdk', time.monotonic() + 2)
                finally:
                    leaf.unlink()

    def test_parent_symlink_is_held_before_following_child(self):
        (self.root / 'deps').symlink_to(self.child, target_is_directory=True)
        self.assertRaises(m.SourceError, m.observe_unmaterialized_gitlink,
                          self.root, 'deps/sdk', time.monotonic() + 2)

    def test_real_empty_leaf_replacement_rejected_while_original_fd_is_held(self):
        self.empty_gitlink()
        leaf = self.root / 'deps/sdk'
        replacement = self.base / 'replacement'
        replacement.mkdir()
        original_inode = leaf.stat().st_ino
        replacement_inode = replacement.stat().st_ino
        original_scan = m.os.scandir
        observations = []

        def exchange(fd):
            # The production routine has opened the original leaf by this
            # boundary. Rename real directories; return the real old-FD scan.
            if os.fstat(fd).st_ino == original_inode and not observations:
                leaf.rename(self.root / 'deps/original-held-sdk')
                replacement.rename(leaf)
                observations.append((os.fstat(fd).st_ino, leaf.stat().st_ino))
            return original_scan(fd)

        with mock.patch.object(m.os, 'scandir', side_effect=exchange):
            with self.assertRaisesRegex(m.SourceError, 'parent or entry changed'):
                m.observe_unmaterialized_gitlink(self.root, 'deps/sdk', time.monotonic() + 2)
        self.assertEqual(observations, [(original_inode, replacement_inode)])
        self.assertNotEqual(original_inode, replacement_inode)
        self.assertEqual(list(leaf.iterdir()), [])
        self.assertEqual(list((self.root / 'deps/original-held-sdk').iterdir()), [])

    def test_gitlink_missing_status_allowance_never_waives_other_deletions(self):
        self.empty_gitlink()
        value = self.collect()
        for label, raw, refs in (
                ('ordinary_blob_deleted', b' D ordinary.txt\0', value['gitlinks']),
                ('unbound_gitlink_deleted', b' D deps/sdk\0', []),
                ('empty_gitlink_claimed_deleted', b' D deps/sdk\0', value['gitlinks'])):
            with self.subTest(case=label):
                altered = copy.deepcopy(value)
                altered['gitlinks'] = copy.deepcopy(refs)
                altered['raw_status_before_base64'] = base64.b64encode(raw).decode()
                altered['raw_status_after_base64'] = base64.b64encode(raw).decode()
                self.assertRaises(m.SourceError, m.validate_inventory, altered)

    def test_changed_real_index_commit_cannot_substitute_for_committed_ref(self):
        (self.child / 'ordinary.txt').write_bytes(b'new real child generation\n')
        self.git(self.child, 'add', 'ordinary.txt')
        self.git(self.child, 'commit', '-qm', 'new local generation')
        new_head = self.git(self.child, 'rev-parse', 'HEAD').decode().strip()
        self.assertNotEqual(new_head, self.child_head)
        self.git(self.root, 'update-index', '--cacheinfo',
                 '160000,' + new_head + ',deps/sdk')
        with self.assertRaisesRegex(m.SourceError, 'index differs from committed raw tree'):
            self.collect()

    def test_ref_and_physical_state_splices_rejected_by_retained_raw_tree(self):
        value = self.collect()
        def extra_blob(v):
            v['gitlinks'][0]['git_blob'] = self.child_head
        def changed_state(v):
            v['gitlinks'][0]['worktree_after']['absent_path'] = 'other'
        def parent_shape(v):
            for name in ('worktree_before', 'worktree_after'):
                v['gitlinks'][0][name]['parent_entries'][0]['path'] = 'deps'
        mutations = {
            'missing_refs': lambda v: v.pop('gitlinks'),
            'omitted_ref': lambda v: v.update(gitlinks=[]),
            'duplicate_ref': lambda v: v['gitlinks'].append(copy.deepcopy(v['gitlinks'][0])),
            'wrong_commit': lambda v: v['gitlinks'][0].update(git_commit='0' * 40),
            'wrong_mode': lambda v: v['gitlinks'][0].update(git_mode='100644'),
            'false_measured_flag': lambda v: v['gitlinks'][0].update(submodule_content_measured=True),
            'invented_blob': extra_blob,
            'before_after_splice': changed_state,
            'physical_parent_splice': parent_shape,
            'old_schema': lambda v: v.update(schema='org.trillionnium.owner-git-content-inventory.v2'),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                altered = copy.deepcopy(value)
                mutate(altered)
                self.assertRaises(m.SourceError, m.validate_inventory, altered)

    def test_mode_and_object_type_pairing_and_truncated_raw_tree_rejected(self):
        oid = self.child_head.encode()
        for raw in (b'160000 blob ' + oid + b'\tdeps/sdk\0',
                    b'100644 commit ' + oid + b'\tdeps/sdk\0',
                    b'160000 commit ' + oid + b'\tdeps/sdk'):
            with self.subTest(raw=raw):
                self.assertRaises(m.SourceError, m.parse_ls_tree, raw)

    def test_real_publish_and_inventory_store_retain_gitlinks_and_raw_descriptor(self):
        self.empty_gitlink()
        value = self.collect()
        directory = self.base / 'shards'
        directory.mkdir(mode=0o700)
        project = 'actual/local-parent'
        record = m.publish_sharded_inventory(project, value, directory, time.monotonic() + 5)
        candidate = dict(commit=self.head, tree=self.tree, archive_sha256=m.sha(b'namespace fixture'),
                         control_regular_files=2)
        names = ['trillionnium-os', project] + ['unread-p' + str(n) for n in range(1168)]
        manifest = ('<manifest>' + ''.join(
            '<project name="fixture/' + name + '" path="' + name + '" revision="' + self.head + '"/>'
            for name in names) + '</manifest>').encode()
        entries = [dict(project=name, record=record if name == project else
                        dict(path='/never-read/' + name, bytes=1, sha256='a' * 64))
                   for name in names]
        index = dict(schema='org.trillionnium.owner-git-content-index.v1', profile_id=m.PROFILE,
                     candidate=candidate, resolved_manifest_sha256=m.sha(manifest), projects=entries)
        store = m.InventoryStore(index, candidate, manifest, [], time.monotonic() + 5)
        loaded = store[project]
        self.assertEqual(loaded, value)
        self.assertEqual(store[project], value)
        self.assertEqual(store.file_count, len(value['source_files']))
        self.assertEqual(store.source_bytes, value['source_bytes'])
        self.assertEqual(len(store.proofs), 1)
        self.assertEqual(store.cache, {})
        indexed = m.parse(m.read_descriptor(record, time.monotonic() + 2))
        self.assertEqual(indexed['metadata']['gitlinks'], value['gitlinks'])
        raw_descriptor = indexed['raw_ls_tree']
        self.assertEqual(m.read_descriptor(raw_descriptor, time.monotonic() + 2),
                         base64.b64decode(value['raw_ls_tree_base64']))
        self.assertIn(raw_descriptor['path'], store.fixed)
        store.reverify()

    def test_physical_surface_accepts_missing_and_empty_without_claiming_child_content(self):
        for kind in ('missing', 'empty'):
            with self.subTest(kind=kind):
                if kind == 'empty':
                    self.empty_gitlink()
                value = self.collect()
                measured = surface.project_surface(m, self.root, value, time.monotonic() + 5)
                self.assertTrue(measured['accepted'])
                self.assertEqual(measured['unknown_entries'], [])
                ref = measured['gitlink_references'][0]
                self.assertEqual(ref['actual_view_worktree']['state'], kind)
                self.assertFalse(ref['submodule_content_measured'])
                self.assertFalse(measured['source_bom_qualified'])
                self.assertEqual(measured['tracked_files'], 2)

    def test_materialization_after_collection_is_held_by_surface(self):
        self.empty_gitlink()
        value = self.collect()
        (self.root / 'deps/sdk/new.bp').write_bytes(b'new source input\n')
        self.assertRaises(m.SourceError, surface.project_surface,
                          m, self.root, value, time.monotonic() + 5)

    def test_gitlink_is_not_available_source_link_or_projection_contents(self):
        self.empty_gitlink()
        (self.root / 'alias').symlink_to('deps/sdk')
        self.git(self.root, 'add', 'alias')
        self.commit_parent()
        value = self.collect()
        with self.assertRaisesRegex(m.SourceError, 'not an available source link target'):
            m.source_link_closure({'actual/local-parent': value})
        for name in ('deps/sdk', 'deps/sdk/ordinary.txt', 'deps'):
            with self.subTest(projection_source=name):
                declaration = dict(project='actual/local-parent', kind='linkfile',
                                   source=name, destination='projected-sdk')
                with self.assertRaisesRegex(m.SourceError, 'gitlink cannot supply projection contents'):
                    m.projected_source_rows(declaration, {'actual/local-parent': value})


if __name__ == '__main__':
    unittest.main()
