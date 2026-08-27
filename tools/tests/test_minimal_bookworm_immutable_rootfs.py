#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1]


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load_module("minimal_bookworm_rootfs", "build_minimal_bookworm_rootfs.py")
EROFS = load_module("immutable_rootfs_erofs", "build_immutable_rootfs_erofs.py")


def contract() -> dict[str, object]:
    return {
        "schema": "org.trillionnium.root-linux.minimal-bookworm-build.v1",
        "suite": "bookworm",
        "architecture": "arm64",
        "snapshot": {
            "timestamp": "20260727T000000Z",
            "debian_source": (
                "deb [check-valid-until=no] "
                "https://snapshot.debian.org/archive/debian/20260727T000000Z "
                "bookworm main"
            ),
            "security_source": (
                "deb [check-valid-until=no] "
                "https://snapshot.debian.org/archive/debian-security/"
                "20260727T000000Z bookworm-security main"
            ),
            "keyring_version": "2025.1",
            "keyring_deb_bytes": 180000,
            "keyring_deb_sha256": "1" * 64,
            "keyring_payload_sha256": "2" * 64,
            "debian_inrelease_url": (
                "https://snapshot.debian.org/archive/debian/"
                "20260727T000000Z/dists/bookworm/InRelease"
            ),
            "debian_inrelease_bytes": 151075,
            "debian_inrelease_sha256": "3" * 64,
            "security_inrelease_url": (
                "https://snapshot.debian.org/archive/debian-security/"
                "20260727T000000Z/dists/bookworm-security/InRelease"
            ),
            "security_inrelease_bytes": 34770,
            "security_inrelease_sha256": "4" * 64,
            "archive_signatures_required": True,
            "keyring_origin_independently_approved": False,
        },
        "source_date_epoch": 1785110400,
        "requested_packages": ["base-files"],
        "resolved_packages": [
            {"name": "base-files", "version": "12.4", "architecture": "arm64"}
        ],
        "forbidden_package_names": ["systemd"],
        "forbidden_package_prefixes": ["gnome-", "phosh"],
        "normalization": {
            "all_uid": 0,
            "all_gid": 0,
            "directory_mode": "0555",
            "regular_mode": "0444",
            "executable_mode": "0555",
            "absolute_symlink_rewrite": "root_absolute_to_relative_v1",
            "special_files_allowed": False,
            "filesystem_write_bits_allowed": False,
        },
        "compression": {"algorithm": "zstd", "level": 19, "threads": 1},
        "tools": {
            "mmdebstrap": {"sha256": "5" * 64},
            "dpkg_deb": {"sha256": "6" * 64},
            "dpkg_query": {"sha256": "7" * 64},
            "gpgv": {"sha256": "8" * 64},
            "zstd": {"sha256": "9" * 64},
        },
        "production": {
            "contract_confers_effect_authority": False,
            "product_pin_refresh_authorized": False,
            "device_write_authorized": False,
            "ota_signing_authorized": False,
            "release_promotion_authorized": False,
        },
    }


class ContractTests(unittest.TestCase):
    def test_reviewed_contract_is_accepted(self) -> None:
        value = BASE.validate_contract(contract())
        self.assertEqual(value["suite"], "bookworm")
        self.assertEqual(value["resolved_packages"][0]["name"], "base-files")

    def test_production_authority_is_rejected(self) -> None:
        value = contract()
        value["production"]["product_pin_refresh_authorized"] = True
        with self.assertRaisesRegex(BASE.BuildError, "must not authorize"):
            BASE.validate_contract(value)

    def test_floating_or_non_https_snapshot_is_rejected(self) -> None:
        value = contract()
        value["snapshot"]["debian_source"] = "deb https://deb.debian.org bookworm main"
        with self.assertRaisesRegex(BASE.BuildError, "not the exact reviewed source"):
            BASE.validate_contract(value)

    def test_different_snapshot_source_and_inrelease_are_rejected(self) -> None:
        value = contract()
        value["snapshot"]["debian_source"] = value["snapshot"]["debian_source"].replace(
            "20260727T000000Z", "20260726T000000Z"
        )
        with self.assertRaisesRegex(BASE.BuildError, "not the exact reviewed source"):
            BASE.validate_contract(value)

        value = contract()
        value["snapshot"]["security_inrelease_url"] = value["snapshot"][
            "security_inrelease_url"
        ].replace("20260727T000000Z", "20260726T000000Z")
        with self.assertRaisesRegex(BASE.BuildError, "not the exact reviewed URL"):
            BASE.validate_contract(value)

    def test_snapshot_epoch_and_keyring_version_are_exact(self) -> None:
        value = contract()
        value["source_date_epoch"] = 1_785_110_401
        with self.assertRaisesRegex(BASE.BuildError, "not the reviewed snapshot epoch"):
            BASE.validate_contract(value)

        value = contract()
        value["snapshot"]["keyring_version"] = "2025.2"
        with self.assertRaisesRegex(BASE.BuildError, "not the reviewed version"):
            BASE.validate_contract(value)

    def test_package_inventory_is_exact_not_subset(self) -> None:
        value = BASE.validate_contract(contract())
        with self.assertRaisesRegex(BASE.BuildError, "extra=.*libc6"):
            BASE.validate_inventory(
                [
                    {"name": "base-files", "version": "12.4", "architecture": "arm64"},
                    {"name": "libc6:arm64", "version": "2.36", "architecture": "arm64"},
                ],
                value,
            )

    def test_requested_package_must_be_in_resolved_allowlist(self) -> None:
        value = contract()
        value["requested_packages"] = ["base-files", "ca-certificates"]
        with self.assertRaisesRegex(BASE.BuildError, "absent from resolved allowlist"):
            BASE.validate_contract(value)

    def test_mmdebstrap_installs_exact_resolved_versions(self) -> None:
        value = BASE.validate_contract(contract())
        command = BASE.mmdebstrap_command(
            value,
            Path("/usr/bin/mmdebstrap"),
            Path("/run/keyring.pgp"),
            Path("/run/rootfs"),
        )
        include = next(item for item in command if item.startswith("--include="))
        self.assertEqual(include, "--include=base-files=12.4")

    def test_forbidden_package_is_rejected_even_if_allowlisted(self) -> None:
        value = contract()
        value["requested_packages"] = ["systemd"]
        value["resolved_packages"] = [
            {"name": "systemd", "version": "252", "architecture": "arm64"}
        ]
        reviewed = BASE.validate_contract(value)
        with self.assertRaisesRegex(BASE.BuildError, "forbidden package"):
            BASE.validate_inventory(reviewed["resolved_packages"], reviewed)


class NormalizedArchiveTests(unittest.TestCase):
    def test_host_bound_network_and_identity_files_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            for relative in BASE.VOLATILE_CHILDREN:
                (root / relative).mkdir(parents=True, exist_ok=True)
            (root / "etc").mkdir(exist_ok=True)
            (root / "var/lib/dbus").mkdir(parents=True, exist_ok=True)
            (root / "etc/hostname").write_text("builder-host\n", encoding="utf-8")
            (root / "etc/hosts").write_text("127.0.0.1 host\n", encoding="utf-8")
            (root / "etc/resolv.conf").symlink_to("/run/host-resolv.conf")
            (root / "etc/machine-id").write_text("machine\n", encoding="utf-8")
            (root / "root/.bashrc").write_text("interactive\n", encoding="utf-8")
            (root / "home/user").mkdir()
            (root / "home/user/.profile").write_text(
                "interactive\n", encoding="utf-8"
            )
            (root / "var/lib/dbus/machine-id").write_text(
                "machine\n", encoding="utf-8"
            )
            BASE.normalize_volatile_tree(root)
            for relative in BASE.HOST_BOUND_FILES:
                self.assertFalse((root / relative).exists())
                self.assertFalse((root / relative).is_symlink())
            self.assertEqual(list((root / "root").iterdir()), [])
            self.assertEqual(list((root / "home").iterdir()), [])

    def test_tree_is_normalized_and_accepted_by_erofs_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            (root / "usr/bin").mkdir(parents=True)
            (root / "etc").mkdir()
            executable = root / "usr/bin/tool"
            executable.write_bytes(b"tool\n")
            executable.chmod(0o755)
            os.link(executable, root / "usr/bin/tool-hardlink")
            (root / "etc/tool").symlink_to("../usr/bin/tool")
            archive = Path(temporary) / "rootfs.tar"
            result = BASE.build_normalized_tar(root, archive, 1785110400)
            self.assertEqual(result["regular_bytes"], 5)
            inspected = EROFS.inspect_normalized_tar(archive, 1785110400)
            self.assertEqual(inspected["members"], 7)
            with tarfile.open(archive, "r:") as source:
                by_name = {member.name: member for member in source}
            self.assertEqual(by_name["usr/bin/tool"].mode, 0o555)
            self.assertTrue(by_name["usr/bin/tool-hardlink"].islnk())
            self.assertEqual(by_name["etc/tool"].linkname, "../usr/bin/tool")

    def test_absolute_symlink_is_rewritten_inside_root(self) -> None:
        self.assertEqual(
            BASE.normalized_link("etc/mtab", "/proc/mounts"),
            "../proc/mounts",
        )

    def test_escaping_symlink_is_rejected(self) -> None:
        with self.assertRaisesRegex(BASE.BuildError, "escapes rootfs"):
            BASE.normalized_link("link", "../../outside")

    def test_writeable_tar_member_is_rejected_by_image_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "bad.tar"
            with tarfile.open(archive_path, "w:", format=tarfile.GNU_FORMAT) as archive:
                root = tarfile.TarInfo(".")
                root.type = tarfile.DIRTYPE
                root.mode = 0o755
                root.uid = 0
                root.gid = 0
                root.mtime = 1785110400
                archive.addfile(root)
            with self.assertRaisesRegex(EROFS.ImageError, "not normalized 0555"):
                EROFS.inspect_normalized_tar(archive_path, 1785110400)

    def test_forward_or_missing_hardlink_is_rejected_by_image_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "bad-hardlink.tar"
            with tarfile.open(archive_path, "w:", format=tarfile.GNU_FORMAT) as archive:
                root = tarfile.TarInfo(".")
                root.type = tarfile.DIRTYPE
                root.mode = 0o555
                root.uid = 0
                root.gid = 0
                root.mtime = 1785110400
                archive.addfile(root)
                link = tarfile.TarInfo("hardlink")
                link.type = tarfile.LNKTYPE
                link.mode = 0o444
                link.uid = 0
                link.gid = 0
                link.mtime = 1785110400
                link.linkname = "missing"
                archive.addfile(link)
            with self.assertRaisesRegex(EROFS.ImageError, "earlier regular member"):
                EROFS.inspect_normalized_tar(archive_path, 1785110400)

    def test_noncanonical_member_order_is_rejected_by_image_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "bad-order.tar"
            with tarfile.open(archive_path, "w:", format=tarfile.GNU_FORMAT) as archive:
                for name in (".", "z", "a"):
                    member = tarfile.TarInfo(name)
                    member.uid = 0
                    member.gid = 0
                    member.mtime = 1785110400
                    if name == ".":
                        member.type = tarfile.DIRTYPE
                        member.mode = 0o555
                    else:
                        member.type = tarfile.REGTYPE
                        member.mode = 0o444
                    archive.addfile(member)
            with self.assertRaisesRegex(EROFS.ImageError, "order is not canonical"):
                EROFS.inspect_normalized_tar(archive_path, 1785110400)

    def test_spdx_output_is_deterministic(self) -> None:
        packages = [
            {"name": "base-files", "version": "12.4", "architecture": "arm64"}
        ]
        first = json.dumps(BASE.spdx_sbom(packages, "a" * 64, "b" * 64), sort_keys=True)
        second = json.dumps(BASE.spdx_sbom(packages, "a" * 64, "b" * 64), sort_keys=True)
        self.assertEqual(first, second)

    def test_fifo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            fifo = root / "fifo"
            os.mkfifo(fifo, stat.S_IRUSR | stat.S_IWUSR)
            with self.assertRaisesRegex(BASE.BuildError, "special rootfs entry"):
                BASE.build_normalized_tar(
                    root, Path(temporary) / "rootfs.tar", 1785110400
                )


if __name__ == "__main__":
    unittest.main()
