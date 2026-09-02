"""Unit tests for the fail-closed desktop Android CI helper."""

from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "android_ci_desktop_build.py"
SPEC = importlib.util.spec_from_file_location("android_ci_desktop_build", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


class DesktopBuildTests(unittest.TestCase):
    def _control_fixture(self, root: Path) -> tuple[Path, Path, str]:
        control = root / "control"
        overlay = control / tool.OVERLAY_ROOT_REL / "demo/project"
        overlay.mkdir(parents=True)
        payload = b"overlay bytes\n"
        source = overlay / "file.txt"
        source.write_bytes(payload)
        digest = tool.hashlib.sha256(payload).hexdigest()
        capture = control / tool.CAPTURE_REL
        capture.parent.mkdir(parents=True)
        manifest = b"<manifest></manifest>\n"
        frozen = control / tool.CONTROL_MANIFEST_REL
        frozen.parent.mkdir(parents=True)
        frozen.write_bytes(manifest)
        capture.write_text(
            "\n".join(
                (
                    "checkout_root\t/data/example",
                    "manifest_file\t.repo/manifests/trillionnium-fogos.xml",
                    f"manifest_sha256\t{tool.hashlib.sha256(manifest).hexdigest()}",
                    "project_count\t1172",
                    "captured_at\t2026-09-02T00:00:00Z",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        status = control / tool.STATUS_REL
        status.parent.mkdir(parents=True, exist_ok=True)
        with status.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=["project", "project_head", "status", "path", "sha256"],
                delimiter="\t",
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerow(
                {
                    "project": "demo/project",
                    "project_head": "a" * 40,
                    "status": " M",
                    "path": "file.txt",
                    "sha256": digest,
                }
            )
        return control, source, digest

    def test_overlay_fixture_is_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            control, source, digest = self._control_fixture(Path(directory))
            capture = tool._read_capture(control)
            entries, heads = tool._load_overlay(control)
            self.assertEqual(capture["project_count"], "1172")
            self.assertEqual(heads["demo/project"], "a" * 40)
            tool._verify_overlay_sources(control, entries)
            self.assertEqual(entries[0].sha256, digest)
            source.write_bytes(b"tampered\n")
            with self.assertRaises(tool.CiError):
                tool._verify_overlay_sources(control, entries)

    def test_zip_directory_entries_are_allowed_but_symlinks_are_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target-files.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("META/", b"")
                archive.writestr("META/misc_info.txt", b"a")
                archive.writestr("META/apkcerts.txt", b"a")
                archive.writestr(
                    "SYSTEM_EXT/app/TrillionniumAiShell/TrillionniumAiShell.apk",
                    b"apk",
                )
            infos = tool._verify_target_files_zip(path)
            self.assertGreaterEqual(len(infos), 4)

            symlink_path = Path(directory) / "symlink.zip"
            with zipfile.ZipFile(symlink_path, "w") as archive:
                info = zipfile.ZipInfo("META/misc_info.txt")
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, b"bad")
                archive.writestr("META/apkcerts.txt", b"a")
            with self.assertRaisesRegex(tool.CiError, "symlink"):
                tool._verify_target_files_zip(symlink_path)

    def test_device_preflight_uses_only_fixed_serial(self) -> None:
        fake = Path("/usr/bin/adb")
        observations = []

        def observation(adb: Path, serial: str, arguments: list[str], **_: object) -> dict[str, object]:
            observations.append((serial, tuple(arguments)))
            output = ""
            if arguments == ["version"]:
                output = "Android Debug Bridge version 1.0.41\n"
            elif arguments == ["get-state"]:
                output = "device\n"
            elif arguments[:2] == ["shell", "getprop"]:
                values = {
                    "ro.product.device": "fogos",
                    "ro.build.type": "userdebug",
                    "ro.build.version.sdk": "36",
                    "ro.build.fingerprint": "fixture/fogos:16/test:userdebug/test-keys",
                    "ro.boot.slot_suffix": "_a",
                    "ro.boot.verifiedbootstate": "orange",
                    "sys.boot_completed": "1",
                    "ro.bootmode": "",
                }
                output = values[arguments[2]] + "\n"
            elif arguments == ["shell", "getenforce"]:
                output = "Enforcing\n"
            elif arguments == ["shell", "id", "-u"]:
                output = "2000\n"
            elif arguments == ["shell", "dumpsys", "battery"]:
                output = "AC powered: true\n"
            elif arguments == ["shell", "df", "-k", "/data"]:
                output = "/data 100 50 50 50% /data\n"
            elif arguments[:4] == ["shell", "logcat", "-d", "-t"]:
                output = "log\n"
            return {
                "argv": [str(adb), "-s", serial, *arguments],
                "returncode": 0,
                "stdout": output,
                "stderr": "",
                "timed_out": False,
            }

        with mock.patch.object(tool, "_run_adb", side_effect=observation):
            result, properties = tool._device_preflight(fake, tool.ALLOWED_SERIAL)
        self.assertEqual(properties["ro.product.device"], "fogos")
        self.assertTrue(result)
        self.assertTrue(all(serial == tool.ALLOWED_SERIAL for serial, _ in observations))
        with self.assertRaisesRegex(tool.CiError, "fixed repository allowlist"):
            tool._device_preflight(fake, "OTHER")

    def test_external_root_gate_rejects_main_disk_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "external"
            android = external / "android"
            control = external / "control"
            run = external / "run"
            for path in (android, control, run):
                path.mkdir(parents=True)
            with self.assertRaisesRegex(tool.CiError, "escapes"):
                tool._validate_roots(
                    external,
                    root / "not-external",
                    control,
                    run,
                    skip_mount_check=True,
                    min_free_gib=0,
                )

    def test_copy_regular_refuses_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"source")
            destination = root / "destination"
            target = root / "target"
            target.write_bytes(b"target")
            destination.symlink_to(target)
            with self.assertRaises(tool.CiError):
                tool._copy_regular(source, destination, "fixture")

    def test_run_mount_failure_creates_no_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "external"
            android = external / "android"
            control = external / "control"
            run = external / "run"
            android.mkdir(parents=True)
            control.mkdir()
            with mock.patch.object(
                tool,
                "_mounted_uuid",
                side_effect=tool.CiError("external mount unavailable"),
            ):
                result = tool.main(
                    [
                        "run",
                        "--external-root",
                        str(external),
                        "--android-root",
                        str(android),
                        "--control-root",
                        str(control),
                        "--run-root",
                        str(run),
                        "--source-commit",
                        "a" * 40,
                    ]
                )
            self.assertEqual(result, 2)
            self.assertFalse(run.exists())


if __name__ == "__main__":
    unittest.main()
