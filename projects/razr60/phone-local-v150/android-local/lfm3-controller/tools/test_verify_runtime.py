#!/usr/bin/env python3
"""Host-only runtime identity regressions using explicitly synthetic release pins.

No real release download, model, APK, device, or installed toolchain is used. Patching
the verifier's test pins is scoped to one call; production constants stay unchanged.
The fake payloads test byte provenance, not ELF execution or model qualification.
"""
import gzip
import hashlib
import io
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

import fetch_pinned_runtime as release
import verify_runtime as m

TEST_PREFIX = "explicit-synthetic-release/lib/"
PAYLOADS = {
    "libgeniex.so": b"fixture-core-release-A\0" * 5,
    "llama_cpp/libgeniex_plugin.so": b"fixture-plugin-release-A\0" * 4,
    "llama_cpp/libggml.so": b"fixture-ggml-release-A\0" * 6,
    "llama_cpp/libggml-cpu.so": b"fixture-cpu-release-A\0" * 7,
    "llama_cpp/libggml-htp-v79.so": b"fixture-htp79-release-A\0" * 3,
    "llama_cpp/libomp.so": b"fixture-openmp-release-A\0" * 4,
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def synthetic_archive(entries=None, prefix=TEST_PREFIX):
    """entries: (relative name, bytes, tar type); no filesystem extraction."""
    if entries is None:
        entries = [(name, data, tarfile.REGTYPE) for name, data in PAYLOADS.items()]
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as bundle:
        for name, data, kind in entries:
            member = tarfile.TarInfo(prefix + name)
            member.type, member.mtime, member.mode = kind, 0, 0o755
            if kind == tarfile.REGTYPE:
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))
            else:
                member.size = 0
                member.linkname = prefix + "libgeniex.so"
                bundle.addfile(member)
    return gzip.compress(raw.getvalue(), mtime=0)


class RuntimeArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / "lib"
        self.cache.mkdir()
        for name, data in PAYLOADS.items():
            target = self.cache / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.archive = self.root / "explicit-synthetic.tar.gz"
        self.pinned_bytes = synthetic_archive()
        self.archive.write_bytes(self.pinned_bytes)
        self.original_verifier_pins = (m.BYTES, m.SHA256, m.PREFIX)
        self.original_release_pins = (release.BYTES, release.SHA256, release.PREFIX)
        for target in ((socket, "create_connection"), (urllib.request, "urlopen"), (subprocess, "Popen")):
            blocker = patch.object(*target, side_effect=AssertionError("network/process execution is forbidden in runtime identity unit tests"))
            blocker.start()
            self.addCleanup(blocker.stop)

    def tearDown(self):
        self.assertEqual((m.BYTES, m.SHA256, m.PREFIX), self.original_verifier_pins)
        self.assertEqual((release.BYTES, release.SHA256, release.PREFIX), self.original_release_pins)

    def verify(self, selected=None, archive=None, pin_bytes=None):
        selected = list(PAYLOADS) if selected is None else selected
        reference = self.pinned_bytes if pin_bytes is None else pin_bytes
        with patch.multiple(m, BYTES=len(reference), SHA256=sha(reference), PREFIX=TEST_PREFIX):
            return m.verify_runtime_archive(archive or self.archive, self.cache, selected)

    def test_exact_match_binds_every_selected_library_and_changes_no_files(self):
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        result = self.verify()
        self.assertEqual(set(result), set(PAYLOADS))
        for name, payload in PAYLOADS.items():
            self.assertEqual(result[name], {"bytes": len(payload), "sha256": sha(payload)})
        after = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_core_match_does_not_hide_a_mixed_same_size_dependency(self):
        for i, dependency in enumerate(("llama_cpp/libggml-cpu.so", "llama_cpp/libomp.so", "llama_cpp/libgeniex_plugin.so")):
            with self.subTest(dependency=dependency):
                path = self.cache / dependency
                original = PAYLOADS[dependency]
                mixed = bytearray(original)
                mixed[-1] ^= i + 1
                self.assertEqual(len(mixed), len(original))
                path.write_bytes(mixed)
                with self.assertRaisesRegex(RuntimeError, "Cached runtime library differs"):
                    self.verify()
                path.write_bytes(original)
        self.assertEqual((self.cache / "libgeniex.so").read_bytes(), PAYLOADS["libgeniex.so"])

    def test_unknown_selected_member_is_rejected_even_when_a_cache_file_exists(self):
        unknown = "llama_cpp/libnot-in-the-release.so"
        (self.cache / unknown).write_bytes(b"a cached ELF name is not provenance")
        with self.assertRaisesRegex(RuntimeError, "absent from the pinned release"):
            self.verify(list(PAYLOADS) + [unknown])

    def test_duplicate_tar_member_is_rejected_even_for_identical_payloads(self):
        records = [(name, data, tarfile.REGTYPE) for name, data in PAYLOADS.items()]
        records.append(("llama_cpp/libggml.so", PAYLOADS["llama_cpp/libggml.so"], tarfile.REGTYPE))
        duplicated = synthetic_archive(records)
        self.archive.write_bytes(duplicated)
        with self.assertRaisesRegex(RuntimeError, "duplicate pinned runtime member"):
            self.verify(pin_bytes=duplicated)

    def test_same_size_corrupt_compressed_archive_rejected_before_tar_parse(self):
        corrupt = bytearray(self.pinned_bytes)
        corrupt[len(corrupt) // 2] ^= 0x40
        self.archive.write_bytes(corrupt)
        with patch.object(m.tarfile, "open", side_effect=AssertionError("unpinned bytes must not be parsed")):
            with self.assertRaisesRegex(RuntimeError, "size/SHA256"):
                self.verify()

    def test_archive_size_pin_rejects_truncation_and_appended_data(self):
        for changed in (self.pinned_bytes[:-1], self.pinned_bytes + b"trailing-unpinned-data"):
            with self.subTest(length=len(changed)):
                self.archive.write_bytes(changed)
                with self.assertRaisesRegex(RuntimeError, "size/SHA256"):
                    self.verify()

    def test_member_hashes_do_not_substitute_for_full_archive_identity(self):
        # Changing only gzip's timestamp retains all decompressed tar/library bytes.
        repacked = bytearray(self.pinned_bytes)
        repacked[4] ^= 1
        self.assertEqual(gzip.decompress(repacked), gzip.decompress(self.pinned_bytes))
        self.archive.write_bytes(repacked)
        with self.assertRaisesRegex(RuntimeError, "size/SHA256"):
            self.verify()

    def test_tar_link_cannot_supply_a_selected_regular_library(self):
        records = [(name, data, tarfile.REGTYPE) for name, data in PAYLOADS.items() if name != "llama_cpp/libggml.so"]
        records.append(("llama_cpp/libggml.so", b"", tarfile.SYMTYPE))
        linked = synthetic_archive(records)
        self.archive.write_bytes(linked)
        with self.assertRaisesRegex(RuntimeError, "Invalid or duplicate pinned runtime member"):
            self.verify(pin_bytes=linked)

    def test_missing_or_symlinked_cache_library_is_rejected(self):
        path = self.cache / "llama_cpp/libggml.so"
        path.unlink()
        with self.assertRaisesRegex(RuntimeError, "Cached runtime library differs"):
            self.verify()
        other = self.root / "same-verified-bytes.so"
        other.write_bytes(PAYLOADS["llama_cpp/libggml.so"])
        path.symlink_to(other)
        with self.assertRaisesRegex(RuntimeError, "Cached runtime library differs"):
            self.verify()

    def test_archive_symlink_and_unsafe_selected_paths_are_rejected(self):
        link = self.root / "alias.tar.gz"
        link.symlink_to(self.archive)
        with self.assertRaises(RuntimeError):
            self.verify(archive=link)
        for selected in ([], ["/absolute/lib.so"], ["../outside.so"], ["llama_cpp/../../outside.so"]):
            with self.subTest(selected=selected), self.assertRaisesRegex(RuntimeError, "Invalid cached runtime membership"):
                self.verify(selected=selected)

    def test_prefix_and_relative_member_identity_must_match_exactly(self):
        other_prefix = synthetic_archive(prefix="another-synthetic-release/lib/")
        self.archive.write_bytes(other_prefix)
        with self.assertRaisesRegex(RuntimeError, "absent from the pinned release"):
            self.verify(pin_bytes=other_prefix)

    def test_empty_member_is_not_a_qualified_runtime_library(self):
        records = [(name, b"" if name == "llama_cpp/libggml.so" else data, tarfile.REGTYPE)
                   for name, data in PAYLOADS.items()]
        empty = synthetic_archive(records)
        self.archive.write_bytes(empty)
        (self.cache / "llama_cpp/libggml.so").write_bytes(b"")
        with self.assertRaisesRegex(RuntimeError, "Invalid or duplicate pinned runtime member"):
            self.verify(pin_bytes=empty)

    def test_archive_replacement_at_parse_time_cannot_create_unpinned_expectations(self):
        changed_name = "llama_cpp/libggml-cpu.so"
        changed_payload = PAYLOADS[changed_name].replace(b"release-A", b"release-B")
        changed_records = [(name, changed_payload if name == changed_name else data, tarfile.REGTYPE)
                           for name, data in PAYLOADS.items()]
        replacement = synthetic_archive(changed_records)
        real_tar_open = tarfile.open
        replacements = []

        def replace_then_open(*args, **kwargs):
            # This models replacement after the initial digest check, before parse.
            # Immutable-snapshot parsing must either reject the now-mixed cache or
            # return only the OLD, pinned expectation; never trust release-B bytes.
            replacements.append(True)
            self.archive.write_bytes(replacement)
            (self.cache / changed_name).write_bytes(changed_payload)
            return real_tar_open(*args, **kwargs)

        with patch.object(m.tarfile, "open", side_effect=replace_then_open):
            try:
                result = self.verify()
            except RuntimeError as error:
                self.assertIn("Cached runtime library differs", str(error))
            else:
                self.assertEqual(result[changed_name]["sha256"], sha(PAYLOADS[changed_name]),
                                 "untrusted replacement archive supplied an expected library hash")
        self.assertEqual(len(replacements), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
