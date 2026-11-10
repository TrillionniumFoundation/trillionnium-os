"""Real verify_zip regressions with synthetic ZIP/compiler bytes; no phone I/O.

Importing the existing fixture also installs its transport/child-process denial
audit hook. The production verifier, ZIP reader, hashes and library-set checks
are exercised directly; no verifier guard is mocked or replaced.
"""
import copy
import io
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

from test_v32_upgrade_select import Fixture, identity, zip_bytes


class RuntimeLibraryNames(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-v32-libcxx-")
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name))
        self.libcxx = b"synthetic libc++ shared library, never executed\n"
        self.f.apk_members["lib/arm64-v8a/libc++_shared.so"] = self.libcxx
        self.f.static["libraries"].append({
            "name": "libc++_shared.so", "bytes": len(self.libcxx),
            "sha256": identity.sha(self.libcxx),
        })

    def verify(self, raw=None):
        return identity.verify_zip(
            zip_bytes(self.f.apk_members) if raw is None else raw,
            self.f.asset, self.f.build, self.f.static, self.f.out,
        )

    def test_libcxx_standard_basename_passes_actual_zip_verifier(self):
        artifacts = self.verify()
        self.assertEqual(set(artifacts), {"classes.dex", "base.apk", "libhepta_local_runner.so"})
        self.assertEqual(artifacts["libhepta_local_runner.so"],
                         identity.sha(self.f.artifacts["libhepta_local_runner.so"]))

    def test_illegal_names_and_path_traversal_remain_rejected(self):
        for name in ("../libc++_shared.so", "sub/libc++_shared.so", "/libc++_shared.so",
                     "..\\libc++_shared.so", "libc++_shared.so/extra", "libc++_shared.so\n",
                     "libc++_shared.so\0", "lib c++_shared.so", "libc++_shared.so;id",
                     "libc++_shared.dylib", "libc＋＋_shared.so", "", None, 1):
            with self.subTest(name=name):
                self.f.static["libraries"][-1]["name"] = name
                with self.assertRaisesRegex(RuntimeError, "unexpected runtime library"):
                    self.verify()

    def test_duplicate_static_library_remains_rejected(self):
        self.f.static["libraries"].append(copy.deepcopy(self.f.static["libraries"][-1]))
        with self.assertRaisesRegex(RuntimeError, "unexpected runtime library"):
            self.verify()

    def test_duplicate_apk_zip_member_remains_rejected(self):
        output = io.BytesIO(zip_bytes(self.f.apk_members))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(output, "a") as archive:
                archive.writestr("lib/arm64-v8a/libc++_shared.so", self.libcxx)
        with self.assertRaisesRegex(RuntimeError, "duplicate APK ZIP entry"):
            self.verify(output.getvalue())

    def test_wrong_library_hash_or_payload_remains_rejected(self):
        for kind in ("receipt_hash", "payload_bytes"):
            with self.subTest(kind=kind):
                self.f.static["libraries"][-1]["sha256"] = (
                    "0" * 64 if kind == "receipt_hash" else identity.sha(self.libcxx))
                self.f.apk_members["lib/arm64-v8a/libc++_shared.so"] = (
                    self.libcxx if kind == "receipt_hash" else b"X" + self.libcxx[1:])
                with self.assertRaisesRegex(RuntimeError, "packaged runtime library differs"):
                    self.verify()

    def test_complete_runtime_library_set_is_still_required(self):
        original = copy.deepcopy(self.f.static["libraries"])
        for kind in ("unlisted_payload", "omitted_static_entry"):
            with self.subTest(kind=kind):
                self.f.static["libraries"] = copy.deepcopy(original)
                self.f.apk_members.pop("lib/arm64-v8a/libunlisted.so", None)
                if kind == "unlisted_payload":
                    self.f.apk_members["lib/arm64-v8a/libunlisted.so"] = b"unlisted runtime"
                else:
                    self.f.static["libraries"].pop()
                with self.assertRaisesRegex(RuntimeError, "packaged runtime library set differs"):
                    self.verify()


if __name__ == "__main__":
    unittest.main(verbosity=2)
