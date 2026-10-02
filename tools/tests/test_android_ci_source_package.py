"""Tests for the exact source-package producer/consumer contract."""
from __future__ import annotations

import importlib.util
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "android_ci_source_package.py"
SPEC = importlib.util.spec_from_file_location("android_ci_source_package", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


class SourcePackageTests(unittest.TestCase):
    def _raw_archive(self, path: Path, headers: list[bytes]) -> None:
        with gzip.open(path, "wb", compresslevel=1) as stream:
            for header in headers:
                stream.write(header)
            stream.write(b"\0" * 1024)

    @unittest.skipUnless(sys.platform == "linux", "requires a real address-space limit")
    def test_oversized_pax_refused_before_payload_allocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "large-pax.tar.gz"
            size = 128 * 1024 * 1024
            header = tarfile.TarInfo("pax")
            header.type = tarfile.XHDTYPE
            header.size = size
            prefix = (str(size) + " path=").encode()
            remaining = size - len(prefix) - 1
            with gzip.open(archive, "wb", compresslevel=1) as stream:
                stream.write(header.tobuf(format=tarfile.USTAR_FORMAT))
                stream.write(prefix)
                block = b"a" * (1024 * 1024)
                while remaining:
                    count = min(remaining, len(block))
                    stream.write(block[:count])
                    remaining -= count
                stream.write(b"\n" + tarfile.TarInfo("file").tobuf() + b"\0" * 1024)
            self.assertLess(archive.stat().st_size, tool.MAX_ARCHIVE_BYTES)
            script = (
                "import json,resource,sys\nfrom pathlib import Path\n"
                "namespace={'__name__':'bounded_archive_fixture'}\n"
                "exec(compile(sys.stdin.buffer.read(),sys.argv[1],'exec'),namespace)\n"
                "resource.setrlimit(resource.RLIMIT_AS,(64*1024*1024,64*1024*1024))\n"
                "try: namespace['_inspect_archive'](Path(sys.argv[2]))\n"
                "except BaseException as error: print(json.dumps({'type':type(error).__name__,'error':str(error)}))\n"
                "else: raise SystemExit('oversized metadata accepted')\n"
            )
            result = subprocess.run([sys.executable, "-I", "-c", script, str(SCRIPT), str(archive)],
                                    input=SCRIPT.read_bytes(), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            outcome = json.loads(result.stdout)
            self.assertEqual(outcome["type"], "PackageError")
            self.assertIn("extended header exceeds", outcome["error"])

    def test_gnu_long_name_and_nested_headers_have_preparse_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "headers.tar.gz"
            huge = tarfile.TarInfo("long")
            huge.type = tarfile.GNUTYPE_LONGNAME
            huge.size = 128 * 1024 * 1024
            self._raw_archive(archive, [huge.tobuf(format=tarfile.GNU_FORMAT)])
            with self.assertRaisesRegex(tool.PackageError, "extended header exceeds"):
                tool._inspect_archive(archive)
            nested = tarfile.TarInfo("pax")
            nested.type = tarfile.XHDTYPE
            self._raw_archive(archive, [nested.tobuf()] * 1000 + [tarfile.TarInfo("file").tobuf()])
            with self.assertRaisesRegex(tool.PackageError, "nesting ceiling"):
                tool._inspect_archive(archive)

    def test_member_limit_precedes_later_invalid_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "many.tar.gz"
            with gzip.open(archive, "wb", compresslevel=1) as stream:
                for index in range(tool.MAX_ARCHIVE_MEMBERS + 1):
                    stream.write(tarfile.TarInfo(f"file-{index}").tobuf())
                huge = tarfile.TarInfo("pax")
                huge.type = tarfile.XHDTYPE
                huge.size = 128 * 1024 * 1024
                stream.write(huge.tobuf() + b"\0" * 1024)
            with self.assertRaisesRegex(tool.PackageError, "too many members"):
                tool._inspect_archive(archive)

    def test_cumulative_metadata_bound_with_individually_valid_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "metadata.tar.gz"
            with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as stream:
                for index in range(1100):
                    member = tarfile.TarInfo(f"file-{index}")
                    member.pax_headers = {"comment": "x" * 62000}
                    stream.addfile(member)
            with self.assertRaisesRegex(tool.PackageError, "metadata exceeds"):
                tool._inspect_archive(archive)

    def test_sparse_records_are_refused_before_sparse_map_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "sparse.tar.gz"
            sparse = tarfile.TarInfo("sparse")
            sparse.type = tarfile.GNUTYPE_SPARSE
            self._raw_archive(archive, [sparse.tobuf(format=tarfile.GNU_FORMAT)])
            with self.assertRaisesRegex(tool.PackageError, "not an ordinary"):
                tool._inspect_archive(archive)
            for headers in ({"GNU.sparse.map": "0,1"}, {"GNU.sparse.size": "1"},
                            {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"},
                            {"GNU.sparse.realsize": "123"}, {"GNU.sparse.major": "unknown"}):
                with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as stream:
                    member = tarfile.TarInfo("file")
                    member.pax_headers = headers
                    stream.addfile(member)
                with self.assertRaisesRegex(tool.PackageError, "sparse metadata"):
                    tool._inspect_archive(archive)

    def test_global_size_cannot_hide_physical_content_extent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "global-size.tar.gz"
            with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT,
                              pax_headers={"size": "0"}) as stream:
                member = tarfile.TarInfo("file")
                member.size = 2048
                stream.addfile(member, io.BytesIO(b"x" * member.size))
            with self.assertRaisesRegex(tool.PackageError, "global size overrides"):
                tool._inspect_archive(archive)

    def test_global_pax_state_cannot_accumulate_unbounded_fields_or_text(self) -> None:
        def record(key: str, value: str) -> bytes:
            body = f" {key}={value}\n".encode()
            size = len(body) + 1
            while len(str(size)) + len(body) != size:
                size = len(str(size)) + len(body)
            return str(size).encode() + body

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "global-pax.tar.gz"
            for dense in (True, False):
                with self.subTest(dense=dense):
                    with gzip.open(archive, "wb", compresslevel=1) as stream:
                        for group in range(20):
                            payload = (b"".join(record(f"key-{group}-{i}", "x") for i in range(500))
                                       if dense else record(f"key-{group}", "x" * 40000))
                            header = tarfile.TarInfo("pax-global")
                            header.type = tarfile.XGLTYPE
                            header.size = len(payload)
                            stream.write(header.tobuf())
                            stream.write(payload + b"\0" * (-len(payload) % 512))
                            stream.write(tarfile.TarInfo(f"file-{group}").tobuf())
                        stream.write(b"\0" * 1024)
                    with self.assertRaisesRegex(tool.PackageError, "PAX (field count|text) exceeds"):
                        tool._inspect_archive(archive)

    def test_bounded_long_names_and_content_remain_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "valid.tar.gz"
            for format in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
                with self.subTest(format=format):
                    with tarfile.open(archive, "w:gz", format=format) as stream:
                        member = tarfile.TarInfo("nested/" + "a" * 200)
                        member.size = 1024 * 1024
                        stream.addfile(member, io.BytesIO(b"x" * member.size))
                    self.assertEqual(tool._inspect_archive(archive), 1)

    def test_gzip_footer_and_trailing_archive_are_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "footer.tar.gz"
            raw = tarfile.TarInfo("file").tobuf() + b"\0" * 1024
            archive.write_bytes(gzip.compress(raw)[:-8])
            with self.assertRaisesRegex(tool.PackageError, "cannot inspect"):
                tool._inspect_archive(archive)
            archive.write_bytes(gzip.compress(raw + tarfile.TarInfo("hidden").tobuf()))
            with self.assertRaisesRegex(tool.PackageError, "trailing content"):
                tool._inspect_archive(archive)

    def _git(self, root: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE)

    def _repo(self, root: Path) -> str:
        self._git(root, "init", "-q")
        self._git(root, "config", "user.name", "android-ci-test")
        self._git(root, "config", "user.email", "android-ci-test@example.invalid")
        (root / "README.md").write_text("fixture\n", encoding="utf-8")
        (root / "nested").mkdir()
        (root / "nested" / "input.txt").write_text("input\n", encoding="utf-8")
        self._git(root, "add", "README.md", "nested/input.txt")
        self._git(root, "commit", "-qm", "fixture")
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()

    def test_create_and_verify_binds_exact_commit_and_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            commit = self._repo(root)
            output = Path(directory) / "out"
            self.assertEqual(
                tool.main(
                    [
                        "create",
                        "--repo-root",
                        str(root),
                        "--output-dir",
                        str(output),
                        "--repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                0,
            )
            manifest_path = output / "trillionnium-os-source.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["source_commit"], commit)
            self.assertEqual(manifest["archive"]["member_count"], 2)
            self.assertEqual(
                tool.main(
                    [
                        "verify",
                        "--manifest",
                        str(manifest_path),
                        "--expected-repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                0,
            )

    def test_dirty_checkout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            commit = self._repo(root)
            (root / "README.md").write_text("changed\n", encoding="utf-8")
            self.assertEqual(
                tool.main(
                    [
                        "create",
                        "--repo-root",
                        str(root),
                        "--output-dir",
                        str(Path(directory) / "out"),
                        "--repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                2,
            )

    def test_archive_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            commit = self._repo(root)
            output = Path(directory) / "out"
            self.assertEqual(
                tool.main(
                    [
                        "create",
                        "--repo-root",
                        str(root),
                        "--output-dir",
                        str(output),
                        "--repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                0,
            )
            archive = output / "trillionnium-os-source.tar.gz"
            archive.write_bytes(archive.read_bytes() + b"tamper")
            self.assertEqual(
                tool.main(["verify", "--manifest", str(output / "trillionnium-os-source.json")]),
                2,
            )

    def test_sidecar_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            commit = self._repo(root)
            output = Path(directory) / "out"
            self.assertEqual(
                tool.main(
                    [
                        "create",
                        "--repo-root",
                        str(root),
                        "--output-dir",
                        str(output),
                        "--repository",
                        "Example/fixture",
                        "--expected-commit",
                        commit,
                    ]
                ),
                0,
            )
            sidecar = output / "trillionnium-os-source.tar.gz.sha256"
            sidecar.write_text("0" * 64 + "  trillionnium-os-source.tar.gz\n", encoding="ascii")
            self.assertEqual(
                tool.main(["verify", "--manifest", str(output / "trillionnium-os-source.json")]),
                2,
            )


if __name__ == "__main__":
    unittest.main()
