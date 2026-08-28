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
import unittest

STAGER = (
    Path(__file__).resolve().parents[1]
    / "owner-open"
    / "stage_owner_open_rootfs_payload_release.py"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def aarch64_elf(payload: bytes = b"fixture") -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 16, 2)
    struct.pack_into("<H", header, 18, 183)
    return bytes(header) + payload


def x86_64_elf() -> bytes:
    raw = bytearray(aarch64_elf())
    struct.pack_into("<H", raw, 18, 62)
    return bytes(raw)


class StageOwnerOpenRootfsPayloadReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.inputs = self.root / "inputs"
        self.outputs = self.root / "outputs"
        self.inputs.mkdir(mode=0o700)
        self.outputs.mkdir(mode=0o700)
        self.host = self.inputs / "host"
        self.config = self.inputs / "profile.json"
        self.host.write_bytes(aarch64_elf())
        self.config.write_text('{"owner_open":true}\n', encoding="utf-8")
        self.host.chmod(0o700)
        self.config.chmod(0o600)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def plan_value(self) -> dict:
        return {
            "schema": "org.trillionnium.owner-open.rootfs-payload-plan.v1",
            "payload_id": "fixture-payload",
            "architecture": "aarch64",
            "libc": "glibc",
            "entries": [
                {
                    "role": "owner_open_host",
                    "source": str(self.host),
                    "destination": "/usr/libexec/trillionnium/host",
                    "mode": "0555",
                    "uid": 0,
                    "gid": 0,
                    "expected_sha256": digest(self.host),
                    "require_aarch64_elf": True,
                },
                {
                    "role": "profile",
                    "source": str(self.config),
                    "destination": "/etc/trillionnium/owner-open/profile.json",
                    "mode": "0444",
                    "uid": 0,
                    "gid": 0,
                    "expected_sha256": digest(self.config),
                    "require_aarch64_elf": False,
                },
            ],
        }

    def write_plan(self, value: dict, name: str = "plan.json") -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def command(self, plan: Path, output: Path) -> list[str]:
        return [
            str(Path(sys.executable).resolve()),
            str(STAGER),
            "--execute",
            "--plan",
            str(plan),
            "--output",
            str(output),
            "--json",
        ]

    def run(self, plan: Path, output: Path) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            self.command(plan, output),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )

    def test_exact_payload_tree_and_manifest_are_staged_without_image_claim(self) -> None:
        plan = self.write_plan(self.plan_value())
        output = self.outputs / "payload"
        parent_mode = stat.S_IMODE(self.outputs.lstat().st_mode)
        completed = self.run(plan, output)
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["entry_count"], 2)
        self.assertEqual(result["claim_ceiling"], "ROOTFS_PAYLOAD_STAGED_NOT_IMAGE")
        self.assertFalse(result["claims"]["rootfs_image_built"])
        staged_host = output / "root/usr/libexec/trillionnium/host"
        staged_config = output / "root/etc/trillionnium/owner-open/profile.json"
        self.assertEqual(staged_host.read_bytes(), self.host.read_bytes())
        self.assertEqual(staged_config.read_bytes(), self.config.read_bytes())
        self.assertEqual(stat.S_IMODE(staged_host.lstat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(staged_config.lstat().st_mode), 0o444)
        external = output / "owner-open-rootfs.manifest.json"
        embedded = output / "root/etc/trillionnium/owner-open/rootfs.manifest.json"
        self.assertEqual(external.read_bytes(), embedded.read_bytes())
        manifest = json.loads(external.read_text())
        host_entry = next(item for item in manifest["entries"] if item["role"] == "owner_open_host")
        self.assertEqual(host_entry["elf"]["machine"], "AArch64")
        self.assertEqual(stat.S_IMODE(self.outputs.lstat().st_mode), parent_mode)

    def test_digest_mismatch_fails_before_output_creation(self) -> None:
        value = self.plan_value()
        value["entries"][0]["expected_sha256"] = "0" * 64
        plan = self.write_plan(value)
        output = self.outputs / "bad-digest"
        completed = self.run(plan, output)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"digest does not match", completed.stderr)
        self.assertFalse(output.exists())

    def test_x86_elf_is_rejected_before_output_creation(self) -> None:
        self.host.write_bytes(x86_64_elf())
        self.host.chmod(0o700)
        value = self.plan_value()
        value["entries"][0]["expected_sha256"] = digest(self.host)
        plan = self.write_plan(value)
        output = self.outputs / "wrong-arch"
        completed = self.run(plan, output)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"must target AArch64", completed.stderr)
        self.assertFalse(output.exists())

    def test_credential_and_path_escape_destinations_are_rejected(self) -> None:
        for index, destination in enumerate(
            (
                "/etc/trillionnium/owner-open/auth.json",
                "/usr/libexec/trillionnium/../escape",
                "/data/trillionnium/owner-open/file",
            )
        ):
            value = self.plan_value()
            value["entries"][1]["destination"] = destination
            plan = self.write_plan(value, f"plan-{index}.json")
            output = self.outputs / f"bad-path-{index}"
            completed = self.run(plan, output)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(output.exists())

    def test_hardlinked_or_group_writable_source_is_rejected(self) -> None:
        link = self.inputs / "host-link"
        os.link(self.host, link)
        plan = self.write_plan(self.plan_value(), "hardlink-plan.json")
        output = self.outputs / "hardlink"
        completed = self.run(plan, output)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"stable bounded private file", completed.stderr)
        self.assertFalse(output.exists())
        link.unlink()

        self.host.chmod(0o720)
        value = self.plan_value()
        value["entries"][0]["expected_sha256"] = digest(self.host)
        plan = self.write_plan(value, "writable-plan.json")
        output = self.outputs / "writable"
        completed = self.run(plan, output)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(output.exists())

    def test_duplicate_role_or_destination_is_rejected(self) -> None:
        for field in ("role", "destination"):
            value = self.plan_value()
            value["entries"][1][field] = value["entries"][0][field]
            plan = self.write_plan(value, f"duplicate-{field}.json")
            output = self.outputs / f"duplicate-{field}"
            completed = self.run(plan, output)
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(output.exists())

    def test_execute_flag_is_required(self) -> None:
        plan = self.write_plan(self.plan_value())
        output = self.outputs / "not-executed"
        command = self.command(plan, output)
        command.remove("--execute")
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"--execute is required", completed.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
