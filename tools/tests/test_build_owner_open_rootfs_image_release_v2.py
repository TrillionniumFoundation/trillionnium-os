from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "owner-open"
STAGER = TOOLS / "stage_owner_open_rootfs_payload_release.py"
BUILDER = TOOLS / "build_owner_open_rootfs_image_release_v2.py"
HELP = "-noappend -all-root -no-xattrs -no-exports -no-progress -comp -b -mkfs-time -all-time -sort"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def aarch64_elf() -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 16, 2)
    struct.pack_into("<H", header, 18, 183)
    return bytes(header) + b"host-fixture"


def deterministic_tool(help_text: str = HELP) -> str:
    return f'''#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import stat
import sys
if sys.argv[1:] == ["-help"]:
    print({help_text!r})
    raise SystemExit(0)
source = Path(sys.argv[1])
output = Path(sys.argv[2])
digest = hashlib.sha256()
for path in sorted(source.rglob("*")):
    relative = path.relative_to(source).as_posix().encode()
    metadata = path.lstat()
    if path.is_dir():
        continue
    digest.update(len(relative).to_bytes(4, "little"))
    digest.update(relative)
    digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "little"))
    raw = path.read_bytes()
    digest.update(len(raw).to_bytes(8, "little"))
    digest.update(raw)
output.write_bytes(b"FAKE-SQUASHFS\\0" + digest.digest())
output.chmod(0o644)
raise SystemExit(0)
'''


def nondeterministic_tool(counter: Path) -> str:
    return f'''#!/usr/bin/env python3
from pathlib import Path
import sys
if sys.argv[1:] == ["-help"]:
    print({HELP!r})
    raise SystemExit(0)
counter = Path({str(counter)!r})
value = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(value))
Path(sys.argv[2]).write_bytes(b"NONDETERMINISTIC" + value.to_bytes(8, "little"))
raise SystemExit(0)
'''


class BuildOwnerOpenRootfsImageReleaseV2Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.inputs = self.root / "inputs"
        self.staging_parent = self.root / "staging"
        self.output_parent = self.root / "images"
        for path in (self.inputs, self.staging_parent, self.output_parent):
            path.mkdir(mode=0o700)
        self.host = self.inputs / "host"
        self.config = self.inputs / "config.json"
        self.host.write_bytes(aarch64_elf())
        self.config.write_text('{"fixture":true}\n', encoding="utf-8")
        self.host.chmod(0o700)
        self.config.chmod(0o600)
        self.staging = self.staging_parent / "payload"
        self.stage_payload()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def stage_payload(self) -> None:
        plan = self.root / "plan.json"
        plan.write_text(
            json.dumps(
                {
                    "schema": "org.trillionnium.owner-open.rootfs-payload-plan.v1",
                    "payload_id": "image-fixture",
                    "architecture": "aarch64",
                    "libc": "glibc",
                    "entries": [
                        {
                            "role": "host",
                            "source": str(self.host),
                            "destination": "/usr/libexec/trillionnium/host",
                            "mode": "0555",
                            "uid": 0,
                            "gid": 0,
                            "expected_sha256": digest(self.host),
                            "require_aarch64_elf": True,
                        },
                        {
                            "role": "config",
                            "source": str(self.config),
                            "destination": "/etc/trillionnium/owner-open/config.json",
                            "mode": "0444",
                            "uid": 0,
                            "gid": 0,
                            "expected_sha256": digest(self.config),
                        },
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        plan.chmod(0o600)
        completed = subprocess.run(
            [
                str(Path(sys.executable).resolve()),
                str(STAGER),
                "--execute",
                "--plan",
                str(plan),
                "--output",
                str(self.staging),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )

    def tool(self, source: str, name: str = "mksquashfs") -> Path:
        path = self.root / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o700)
        return path

    def command(
        self,
        tool: Path,
        output: Path,
        *,
        expected: str | None = None,
        timeout: str = "10",
    ) -> list[str]:
        return [
            str(Path(sys.executable).resolve()),
            str(BUILDER),
            "--execute",
            "--staging",
            str(self.staging),
            "--mksquashfs",
            str(tool),
            "--expected-mksquashfs-sha256",
            expected or digest(tool),
            "--output",
            str(output),
            "--runs",
            "2",
            "--probe-timeout",
            "3",
            "--build-timeout",
            timeout,
            "--json",
        ]

    def run_command(
        self, command: list[str], timeout: float = 30
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )

    def test_two_independent_builds_are_byte_identical(self) -> None:
        tool = self.tool(deterministic_tool())
        output = self.output_parent / "pass"
        completed = self.run_command(self.command(tool, output))
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        result = json.loads(completed.stdout)
        self.assertTrue(result["reproducible"])
        self.assertEqual(result["reproducibility_runs"], 2)
        self.assertEqual(len({item["image_sha256"] for item in result["build_runs"]}), 1)
        self.assertFalse(result["claims"]["image_included"])
        image = output / "owner-open-rootfs.squashfs"
        manifest = output / "owner-open-rootfs.image-manifest.json"
        self.assertTrue(image.exists())
        self.assertTrue(manifest.exists())
        self.assertEqual(stat.S_IMODE(image.lstat().st_mode), 0o444)
        self.assertEqual(json.loads(manifest.read_text())["image_sha256"], digest(image))
        self.assertFalse(any(path.name.startswith("run-") for path in output.iterdir()))

    def test_staging_tamper_is_rejected_before_output_creation(self) -> None:
        target = self.staging / "root/etc/trillionnium/owner-open/config.json"
        target.chmod(0o644)
        target.write_text("tampered\n", encoding="utf-8")
        target.chmod(0o444)
        tool = self.tool(deterministic_tool())
        output = self.output_parent / "tampered"
        completed = self.run_command(self.command(tool, output))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"digest or byte count drifted", completed.stderr)
        self.assertFalse(output.exists())

    def test_tool_digest_and_help_options_are_bound(self) -> None:
        tool = self.tool(deterministic_tool())
        output = self.output_parent / "wrong-tool"
        completed = self.run_command(self.command(tool, output, expected="0" * 64))
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(output.exists())

        missing = self.tool(deterministic_tool("-noappend -all-root"), "mksquashfs-missing")
        output = self.output_parent / "missing-options"
        completed = self.run_command(self.command(missing, output))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"lacks required deterministic options", completed.stderr)
        self.assertFalse(output.exists())

    def test_nondeterministic_image_tool_is_rejected_and_cleaned(self) -> None:
        tool = self.tool(
            nondeterministic_tool(self.root / "counter"),
            "mksquashfs-nondeterministic",
        )
        output = self.output_parent / "nondeterministic"
        completed = self.run_command(self.command(tool, output))
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"not byte-identical", completed.stderr)
        self.assertFalse(output.exists())

    def test_timed_out_image_tool_is_reaped_and_output_is_removed(self) -> None:
        tool = self.tool(
            f'''#!/usr/bin/env python3
import sys
import time
if sys.argv[1:] == ["-help"]:
    print({HELP!r})
    raise SystemExit(0)
time.sleep(60)
''',
            "mksquashfs-hang",
        )
        output = self.output_parent / "timeout"
        started = time.monotonic()
        completed = self.run_command(self.command(tool, output, timeout="1"), timeout=10)
        self.assertLess(time.monotonic() - started, 8)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"timed out and was reaped", completed.stderr)
        self.assertFalse(output.exists())

    def test_execute_flag_is_required(self) -> None:
        tool = self.tool(deterministic_tool())
        output = self.output_parent / "not-executed"
        command = self.command(tool, output)
        command.remove("--execute")
        completed = self.run_command(command, timeout=5)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"--execute is required", completed.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
