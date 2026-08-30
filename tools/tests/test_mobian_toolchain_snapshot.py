#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/mobian_toolchain_snapshot.py"
SPEC = importlib.util.spec_from_file_location("mobian_toolchain_snapshot", TOOL)
assert SPEC and SPEC.loader
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)

EPOCH = 1_784_185_077


class MobianToolchainSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        # The snapshotter intentionally rejects /tmp's world-writable ancestry.
        trusted_temp_parent = Path.home().resolve(strict=True)
        self.base_tmp = tempfile.TemporaryDirectory(
            prefix="mobian-snapshot-tests-", dir=trusted_temp_parent
        )
        self.source_tmp = tempfile.TemporaryDirectory(
            prefix="mobian-snapshot-source-", dir=trusted_temp_parent
        )
        self.base = Path(self.base_tmp.name)
        self.source_container = Path(self.source_tmp.name)
        self.source = self.source_container / "source"
        self.source.mkdir(mode=0o700)
        os.chmod(self.base, 0o700)
        self.snapshot_path = self.base / "snapshot"
        self.manifest = self.base / "manifest.json"
        self._write_source()

    def tearDown(self) -> None:
        for root in (self.snapshot_path,):
            if root.exists() and not root.is_symlink():
                snapshot.make_tree_removable(root)
        self.base_tmp.cleanup()
        self.source_tmp.cleanup()

    def _write_source(self) -> None:
        for relative in (
            "cargo/bin",
            "cargo/registry/cache",
            "cargo/registry/src/index.crates.io-test/crate-1.0.0",
            "rustup/toolchains/test/bin",
            "sysroot/lib",
            "sysroot/usr/lib",
        ):
            (self.source / relative).mkdir(parents=True, exist_ok=True)
        for path in self.source.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
        external = self.source / "external-rustup"
        external.write_bytes(b"#!/bin/sh\nexit 0\n")
        external.chmod(0o755)
        os.symlink(str(external), self.source / "cargo/bin/rustup")
        os.symlink("rustup", self.source / "cargo/bin/cargo")
        crate = self.source / "cargo/registry/cache/crate.crate"
        crate.write_bytes(b"crate")
        crate.chmod(0o644)
        library = self.source / "sysroot/usr/lib/libx.so"
        library.write_bytes(b"library")
        library.chmod(0o644)
        os.symlink("/usr/lib/libx.so", self.source / "sysroot/lib/libx.so")
        os.symlink("missing-contained", self.source / "sysroot/lib/broken")

    def _create(self, **kwargs: object) -> dict[str, object]:
        return snapshot.create(
            self.source,
            self.snapshot_path,
            self.manifest,
            EPOCH,
            **kwargs,
        )

    def test_create_verify_closed_world_and_modes(self) -> None:
        created = self._create()
        verified = snapshot.verify(self.snapshot_path, self.manifest)
        self.assertEqual(created, verified)
        self.assertEqual(created["decision"], snapshot.PASS)
        self.assertEqual(stat.S_IMODE(self.snapshot_path.stat().st_mode), 0o500)
        self.assertEqual(self.manifest.stat().st_nlink, 1)
        self.assertEqual(
            stat.S_IMODE((self.snapshot_path / "cargo/bin/rustup").stat().st_mode),
            0o555,
        )
        self.assertFalse((self.snapshot_path / "cargo/bin/rustup").is_symlink())
        self.assertTrue((self.snapshot_path / "cargo/bin/cargo").is_symlink())
        self.assertEqual(
            os.readlink(self.snapshot_path / "cargo/bin/cargo"),
            "rustup",
        )
        self.assertEqual(
            os.readlink(self.snapshot_path / "sysroot/lib/libx.so"),
            "../usr/lib/libx.so",
        )
        broken = next(
            item
            for item in snapshot.read_manifest(self.manifest)[0]["entries"]
            if item["path"] == "sysroot/lib/broken"
        )
        self.assertIs(broken["resolved"], False)

    def test_unknown_absolute_link_fails_closed(self) -> None:
        os.symlink("/bin/false", self.source / "cargo/unknown")
        with self.assertRaisesRegex(snapshot.SnapshotError, "not allowlisted"):
            self._create()
        self.assertFalse(self.snapshot_path.exists())
        self.assertFalse(self.manifest.exists())

    def test_relative_escape_and_cycle_fail_closed(self) -> None:
        os.symlink("../../../../outside", self.source / "cargo/bin/escape")
        with self.assertRaisesRegex(snapshot.SnapshotError, "escaping or cyclic"):
            self._create()
        (self.source / "cargo/bin/escape").unlink()
        os.symlink("cycle-b", self.source / "cargo/bin/cycle-a")
        os.symlink("cycle-a", self.source / "cargo/bin/cycle-b")
        with self.assertRaisesRegex(snapshot.SnapshotError, "escaping or cyclic"):
            self._create()

    def test_tamper_extra_mode_content_and_xattr_fail(self) -> None:
        self._create()
        snapshot.make_tree_removable(self.snapshot_path)
        extra = self.snapshot_path / "extra"
        extra.write_bytes(b"extra")
        extra.chmod(0o444)
        os.utime(extra, ns=(EPOCH * 1_000_000_000,) * 2)
        snapshot.normalize_snapshot(self.snapshot_path, EPOCH)
        with self.assertRaisesRegex(snapshot.SnapshotError, "does not match"):
            snapshot.verify(self.snapshot_path, self.manifest)
        snapshot.make_tree_removable(self.snapshot_path)
        extra.unlink()
        snapshot.normalize_snapshot(self.snapshot_path, EPOCH)
        target = self.snapshot_path / "cargo/registry/cache/crate.crate"
        os.chmod(target, 0o644)
        with self.assertRaisesRegex(snapshot.SnapshotError, "0444/0555"):
            snapshot.verify(self.snapshot_path, self.manifest)
        os.chmod(target, 0o444)
        os.chmod(target, 0o644)
        os.setxattr(target, "user.trillionnium-test", b"1")
        os.chmod(target, 0o444)
        with self.assertRaisesRegex(snapshot.SnapshotError, "xattrs/ACL"):
            snapshot.verify(self.snapshot_path, self.manifest)
        os.chmod(target, 0o644)
        os.removexattr(target, "user.trillionnium-test")

    def test_source_change_during_copy_fails(self) -> None:
        original = snapshot.copy_regular_from_fd
        target = self.source / "cargo/registry/cache/crate.crate"
        mutated = False

        def mutate(
            source_fd: int,
            expected: os.stat_result,
            destination_fd: int,
            name: str,
            relative: str,
        ) -> str:
            nonlocal mutated
            if relative == "cargo/registry/cache/crate.crate" and not mutated:
                mutated = True
                target.write_bytes(b"changed")
            return original(source_fd, expected, destination_fd, name, relative)

        with mock.patch.object(snapshot, "copy_regular_from_fd", side_effect=mutate):
            with self.assertRaisesRegex(snapshot.SnapshotError, "changed while copying"):
                self._create()

    def test_source_entry_rename_inode_swap_fails(self) -> None:
        target = self.source / "cargo/registry/cache/crate.crate"
        backup = target.with_name("crate.crate.original")
        original = snapshot.open_source_child
        swapped = False

        def swap_before_open(
            directory_fd: int,
            name: str,
            flags: int,
            expected: os.stat_result,
            relative: str,
        ) -> tuple[int, os.stat_result]:
            nonlocal swapped
            if relative == "cargo/registry/cache/crate.crate" and not swapped:
                swapped = True
                target.rename(backup)
                target.write_bytes(b"crate")
            return original(directory_fd, name, flags, expected, relative)

        try:
            with mock.patch.object(
                snapshot, "open_source_child", side_effect=swap_before_open
            ):
                with self.assertRaisesRegex(
                    snapshot.SnapshotError, "changed before open"
                ):
                    self._create()
        finally:
            if backup.exists():
                target.unlink(missing_ok=True)
                backup.rename(target)

    def test_source_root_rename_inode_swap_fails(self) -> None:
        displaced = self.source_container / "source.displaced"
        original = snapshot.revalidate_source_root_path

        def swap_before_revalidation(
            source: Path, pinned_fd: int, initial: os.stat_result
        ) -> None:
            source.rename(displaced)
            shutil.copytree(displaced, source, symlinks=True)
            original(source, pinned_fd, initial)

        try:
            with mock.patch.object(
                snapshot,
                "revalidate_source_root_path",
                side_effect=swap_before_revalidation,
            ):
                with self.assertRaisesRegex(
                    snapshot.SnapshotError, "source root.*changed"
                ):
                    self._create()
        finally:
            if displaced.exists():
                if self.source.exists():
                    shutil.rmtree(self.source)
                displaced.rename(self.source)

    def test_manifest_publication_failure_cleans_snapshot(self) -> None:
        with mock.patch.object(
            snapshot, "write_new_file", side_effect=snapshot.SnapshotError("fault")
        ):
            with self.assertRaisesRegex(snapshot.SnapshotError, "fault"):
                self._create()
        self.assertFalse(self.snapshot_path.exists())
        self.assertFalse(self.manifest.exists())

    def test_competing_manifest_inode_is_not_deleted_during_cleanup(self) -> None:
        original = snapshot.write_new_file
        displaced = self.base / "manifest.published-by-this-invocation"
        competitor = b'{"competitor":true}\n'

        def replace_after_publish(
            path: Path, payload: bytes, mode: int, epoch: int
        ) -> tuple[int, int]:
            token = original(path, payload, mode, epoch)
            path.rename(displaced)
            path.write_bytes(competitor)
            path.chmod(0o444)
            os.utime(path, ns=(epoch * 1_000_000_000,) * 2)
            return token

        with mock.patch.object(
            snapshot, "write_new_file", side_effect=replace_after_publish
        ):
            with self.assertRaises(snapshot.SnapshotError):
                self._create()
        self.assertFalse(self.snapshot_path.exists())
        self.assertEqual(self.manifest.read_bytes(), competitor)
        self.assertTrue(displaced.exists())

    def test_explicit_recovery_reclaims_only_valid_incomplete_tree(self) -> None:
        self._create()
        self.manifest.unlink()
        recreated = self._create(recover_incomplete=True)
        self.assertTrue(recreated["passed"])
        self.manifest.unlink()
        snapshot.make_tree_removable(self.snapshot_path)
        (self.snapshot_path / "unmanifested").write_bytes(b"x")
        with self.assertRaises(snapshot.SnapshotError):
            self._create(recover_incomplete=True)

    def test_disjoint_and_noreplace_guards(self) -> None:
        nested_parent = self.source / "output"
        nested_parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(snapshot.SnapshotError, "ancestors or descendants"):
            snapshot.create(
                self.source,
                nested_parent / "snapshot",
                nested_parent / "manifest.json",
                EPOCH,
            )
        source = self.base / "rename-source"
        target = self.base / "rename-target"
        source.mkdir()
        target.mkdir()
        with self.assertRaisesRegex(snapshot.SnapshotError, "appeared"):
            snapshot.rename_noreplace(source, target)

    def test_symlink_components_and_insecure_parent_are_rejected(self) -> None:
        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        # mkdir(mode=...) is filtered by the process umask.  The suite is
        # intentionally run with a restrictive umask, so make the insecure
        # fixture explicit before asserting that the snapshotter rejects it.
        insecure.chmod(0o755)
        with self.assertRaisesRegex(snapshot.SnapshotError, "mode 0700"):
            snapshot.create(
                self.source,
                insecure / "snapshot",
                insecure / "manifest.json",
                EPOCH,
            )
        secure = self.base / "secure"
        secure.mkdir(mode=0o700)
        linked = self.base / "linked"
        os.symlink(secure, linked)
        with self.assertRaisesRegex(snapshot.SnapshotError, "symlink component"):
            snapshot.create(
                self.source,
                linked / "snapshot",
                linked / "manifest.json",
                EPOCH,
            )
        source_link = self.base / "source-link"
        os.symlink(self.source, source_link)
        with self.assertRaisesRegex(snapshot.SnapshotError, "symlink component"):
            snapshot.create(
                source_link,
                secure / "snapshot",
                secure / "manifest.json",
                EPOCH,
            )

    def test_writable_and_wrong_owner_source_ancestor_are_rejected(self) -> None:
        original_mode = stat.S_IMODE(self.source_container.stat().st_mode)
        try:
            self.source_container.chmod(0o770)
            with self.assertRaisesRegex(
                snapshot.SnapshotError, "source ancestor is group/world writable"
            ):
                self._create()
        finally:
            self.source_container.chmod(original_mode)

        actual_uid = os.getuid()
        with mock.patch.object(snapshot.os, "getuid", return_value=actual_uid + 1):
            with self.assertRaisesRegex(
                snapshot.SnapshotError, "wrong owner|current-user-owned"
            ):
                self._create()

    def test_forged_derivation_and_materialized_rustup_tamper_fail(self) -> None:
        self._create()
        value = snapshot.read_manifest(self.manifest)[0]
        value["derivation"] = {"forged": True}
        self.manifest.chmod(0o644)
        self.manifest.write_text(json.dumps(value, sort_keys=True) + "\n")
        self.manifest.chmod(0o444)
        os.utime(self.manifest, ns=(EPOCH * 1_000_000_000,) * 2)
        with self.assertRaisesRegex(snapshot.SnapshotError, "top-level keyset"):
            snapshot.verify(self.snapshot_path, self.manifest)
        self.manifest.chmod(0o600)
        self.manifest.unlink()
        snapshot.make_tree_removable(self.snapshot_path)
        shutil.rmtree(self.snapshot_path)
        self._create()
        snapshot.make_tree_removable(self.snapshot_path)
        rustup = self.snapshot_path / "cargo/bin/rustup"
        rustup.chmod(0o644)
        rustup.write_bytes(b"#!/bin/sh\nexit 99\n")
        snapshot.normalize_snapshot(self.snapshot_path, EPOCH)
        with self.assertRaisesRegex(snapshot.SnapshotError, "does not match"):
            snapshot.verify(self.snapshot_path, self.manifest)

    def test_acl_and_fsync_faults_fail_and_cleanup(self) -> None:
        self._create()
        snapshot.make_tree_removable(self.snapshot_path)
        target = self.snapshot_path / "cargo/registry/cache/crate.crate"
        target.chmod(0o644)
        subprocess.run(["setfacl", "-m", "u:nobody:r", str(target)], check=True)
        snapshot.normalize_snapshot(self.snapshot_path, EPOCH)
        with self.assertRaisesRegex(snapshot.SnapshotError, "xattrs/ACL"):
            snapshot.verify(self.snapshot_path, self.manifest)
        self.manifest.chmod(0o600)
        self.manifest.unlink()
        snapshot.make_tree_removable(self.snapshot_path)
        shutil.rmtree(self.snapshot_path)
        with mock.patch.object(
            snapshot, "fsync_tree", side_effect=snapshot.SnapshotError("fsync fault")
        ):
            with self.assertRaisesRegex(snapshot.SnapshotError, "fsync fault"):
                self._create()
        self.assertFalse(self.snapshot_path.exists())
        self.assertFalse(self.manifest.exists())

    def test_precopy_entry_path_file_and_aggregate_limits_fail_closed(self) -> None:
        cases = (
            ("MAX_ENTRY_COUNT", 2, "entry count"),
            ("MAX_PATH_BYTES", 3, "path"),
            ("MAX_REGULAR_FILE_BYTES", 3, "size limit|regular file"),
            ("MAX_REGULAR_BYTES", 4, "regular-file bytes"),
        )
        for constant, value, message in cases:
            with self.subTest(constant=constant), mock.patch.object(snapshot, constant, value):
                with self.assertRaisesRegex(snapshot.SnapshotError, message):
                    self._create()
                self.assertFalse(self.snapshot_path.exists())
                self.assertFalse(self.manifest.exists())

    def test_postcopy_verify_resource_limits_fail_closed(self) -> None:
        self._create()
        with mock.patch.object(snapshot, "MAX_ENTRY_COUNT", 2):
            with self.assertRaisesRegex(snapshot.SnapshotError, "entry count"):
                snapshot.verify(self.snapshot_path, self.manifest)
        with mock.patch.object(snapshot, "MAX_REGULAR_BYTES", 4):
            with self.assertRaisesRegex(snapshot.SnapshotError, "regular-file bytes"):
                snapshot.verify(self.snapshot_path, self.manifest)

    def test_oversized_manifest_is_rejected_before_json_decode(self) -> None:
        self._create()
        with mock.patch.object(snapshot, "MAX_MANIFEST_BYTES", 1):
            with self.assertRaisesRegex(snapshot.SnapshotError, "manifest.*limit"):
                snapshot.verify(self.snapshot_path, self.manifest)

    def test_manifest_duplicate_keys_and_nonfinite_numbers_are_rejected(self) -> None:
        self._create()

        def replace_manifest(payload: bytes) -> None:
            self.manifest.chmod(0o600)
            self.manifest.write_bytes(payload)
            self.manifest.chmod(0o444)
            os.utime(self.manifest, ns=(EPOCH * 1_000_000_000,) * 2)

        original = self.manifest.read_bytes()
        duplicate = original.replace(
            b'{\n  "entries":',
            b'{\n  "schema": "duplicate",\n  "entries":',
            1,
        )
        replace_manifest(duplicate)
        with self.assertRaisesRegex(snapshot.SnapshotError, "duplicate object key"):
            snapshot.verify(self.snapshot_path, self.manifest)

        nonfinite = original.replace(
            b'"source_date_epoch": ', b'"nonfinite": NaN,\n  "source_date_epoch": ', 1
        )
        replace_manifest(nonfinite)
        with self.assertRaisesRegex(snapshot.SnapshotError, "non-finite"):
            snapshot.verify(self.snapshot_path, self.manifest)


if __name__ == "__main__":
    unittest.main()
