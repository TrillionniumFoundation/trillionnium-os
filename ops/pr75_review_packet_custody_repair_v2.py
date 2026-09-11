#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path

GENERATOR = Path("tools/contracts/generate_module_contracts.py")
CHECKER = Path("tools/contracts/check_module_contract_compatibility.py")
TESTS = Path("tools/tests/test_module_contracts.py")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one replacement anchor, found {count}")
    return text.replace(old, new, 1)


def replace_between(
    text: str,
    start_marker: str,
    end_marker: str,
    replacement: str,
    label: str,
) -> str:
    if text.count(start_marker) != 1 or text.count(end_marker) != 1:
        raise SystemExit(f"{label}: acquisition block anchors are not unique")
    start = text.find(start_marker)
    end = text.find(end_marker, start)
    if start < 0 or end < 0:
        raise SystemExit(f"{label}: acquisition block anchors are missing")
    return text[:start] + replacement + text[end:]


checker = CHECKER.read_text(encoding="utf-8")
checker_acquisition = '''    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required_flags) or not hasattr(os, "pread"):
        raise ValueError(f"{label}: review packet safe acquisition is unavailable")
    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise ValueError(f"{label}: descriptor-relative review packet acquisition is unavailable")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory_descriptors: list[int] = []
    descriptor: int | None = None
    try:
        directory_descriptors.append(os.open(root, directory_flags))
        for part in pure.parts[:-1]:
            directory_descriptors.append(
                os.open(part, directory_flags, dir_fd=directory_descriptors[-1])
            )
        parent_descriptor = directory_descriptors[-1]
        leaf = pure.parts[-1]
        descriptor = os.open(leaf, file_flags, dir_fd=parent_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > REVIEW_PACKET_MAX_BYTES
        ):
            raise ValueError(f"{label}: review packet is not one bounded regular file")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                descriptor,
                min(65536, before.st_size - offset),
                offset,
            )
            if not chunk:
                raise ValueError(f"{label}: review packet short read")
            chunks.append(chunk)
            offset += len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
    except ValueError:
        raise
    except OSError as error:
        raise ValueError(f"{label}: review packet descriptor acquisition failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)

    if (
        len(raw) != before.st_size
        or len(raw) > REVIEW_PACKET_MAX_BYTES
        or stable_file_identity(after) != stable_file_identity(before)
        or stable_file_identity(current) != stable_file_identity(before)
    ):
        raise ValueError(f"{label}: review packet changed while being read")
'''
checker = replace_between(
    checker,
    "    candidate = root\n",
    "    if sha256_bytes(raw) != expected_sha256:\n",
    checker_acquisition,
    "checker",
)
CHECKER.write_text(checker, encoding="utf-8")


generator = GENERATOR.read_text(encoding="utf-8")
generator_acquisition = '''    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    require(
        all(hasattr(os, name) for name in required_flags) and hasattr(os, "pread"),
        "review packet safe acquisition is unavailable",
    )
    require(
        os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks,
        "descriptor-relative review packet acquisition is unavailable",
    )

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory_descriptors: list[int] = []
    descriptor: int | None = None
    try:
        directory_descriptors.append(os.open(root, directory_flags))
        for part in pure.parts[:-1]:
            directory_descriptors.append(
                os.open(part, directory_flags, dir_fd=directory_descriptors[-1])
            )
        parent_descriptor = directory_descriptors[-1]
        leaf = pure.parts[-1]
        descriptor = os.open(leaf, file_flags, dir_fd=parent_descriptor)
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= REVIEW_PACKET_MAX_BYTES,
            "review packet is not one bounded regular file",
        )
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                descriptor,
                min(65536, before.st_size - offset),
                offset,
            )
            require(bool(chunk), "review packet short read")
            chunks.append(chunk)
            offset += len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
    except ContractError:
        raise
    except OSError as error:
        raise ContractError("review packet descriptor acquisition failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)

    require(
        len(raw) == before.st_size
        and len(raw) <= REVIEW_PACKET_MAX_BYTES
        and stable_file_identity(after) == stable_file_identity(before)
        and stable_file_identity(current) == stable_file_identity(before),
        "review packet changed while being read",
    )
'''
generator = replace_between(
    generator,
    "    candidate = root\n",
    "    require(sha(raw) == expected_sha256, \"review packet digest differs from path\")\n",
    generator_acquisition,
    "generator",
)
GENERATOR.write_text(generator, encoding="utf-8")


tests = TESTS.read_text(encoding="utf-8")
tests = replace_once(
    tests,
    "import json\nfrom pathlib import Path\nimport subprocess\n",
    "import json\nimport os\nfrom pathlib import Path\nimport subprocess\nimport sys\n",
    "test imports",
)

anchor = "\n\n    def test_change_review_state_machine_is_closed_and_one_shot(self) -> None:\n"
method = r'''

    @unittest.skipUnless(
        hasattr(os, "mkfifo")
        and hasattr(os, "O_NONBLOCK")
        and hasattr(os, "pread")
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks,
        "descriptor-relative nonblocking file acquisition is unavailable",
    )
    def test_review_packet_acquisition_is_nonblocking_and_descriptor_relative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packet_directory = root / "docs/reviews/module-contracts"
            packet_directory.mkdir(parents=True)
            fifo_digest = "0" * 64
            fifo_relative = (
                f"docs/reviews/module-contracts/{fifo_digest}.json"
            )
            fifo = root / fifo_relative
            os.mkfifo(fifo)
            probe = r"""
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("_packet_probe", sys.argv[1])
if spec is None or spec.loader is None:
    raise SystemExit(4)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    if sys.argv[2] == "checker":
        module.read_review_packet(
            Path(sys.argv[3]), sys.argv[4], sys.argv[5], "MOD-FIXTURE"
        )
    else:
        module.read_review_packet(Path(sys.argv[3]), sys.argv[4])
except ValueError as error:
    print(error, file=sys.stderr)
    raise SystemExit(0 if "not one bounded regular file" in str(error) else 5)
raise SystemExit(6)
"""
            for kind, source in (("checker", CHECKER), ("generator", GENERATOR)):
                with self.subTest(kind=kind):
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            probe,
                            str(source),
                            kind,
                            str(root),
                            fifo_relative,
                            fifo_digest,
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=3,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("not one bounded regular file", result.stderr)

            fifo.unlink()
            regular_raw = self.checker.canonical_packet({"fixture": True})
            regular_digest = self.checker.sha256_bytes(regular_raw)
            regular_relative = (
                f"docs/reviews/module-contracts/{regular_digest}.json"
            )
            (root / regular_relative).write_bytes(regular_raw)
            self.assertEqual(
                self.checker.read_review_packet(
                    root,
                    regular_relative,
                    regular_digest,
                    "MOD-FIXTURE",
                ),
                regular_raw,
            )
            self.assertEqual(
                self.contracts.read_review_packet(root, regular_relative),
                (regular_raw, regular_digest),
            )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            packet_directory = outside / "reviews/module-contracts"
            packet_directory.mkdir(parents=True)
            raw = self.checker.canonical_packet({"fixture": "outside"})
            digest = self.checker.sha256_bytes(raw)
            relative = f"docs/reviews/module-contracts/{digest}.json"
            (packet_directory / f"{digest}.json").write_bytes(raw)
            (root / "docs").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "descriptor acquisition failed"):
                self.checker.read_review_packet(
                    root,
                    relative,
                    digest,
                    "MOD-FIXTURE",
                )
            with self.assertRaisesRegex(ValueError, "descriptor acquisition failed"):
                self.contracts.read_review_packet(root, relative)

    def test_change_review_state_machine_is_closed_and_one_shot(self) -> None:
'''
tests = replace_once(tests, anchor, method, "review packet test insertion")
TESTS.write_text(tests, encoding="utf-8")

for path in (GENERATOR, CHECKER, TESTS):
    raw = path.read_bytes()
    print(f"{path}: bytes={len(raw)} sha256={hashlib.sha256(raw).hexdigest()}")
