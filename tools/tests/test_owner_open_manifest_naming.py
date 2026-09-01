from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
INSTALL_MANIFEST = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.image-manifest.json"
STALE_INSTALL_MANIFEST = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.manifest.json"


class OwnerOpenManifestNamingTest(unittest.TestCase):
    def test_android_install_name_is_distinct_from_staging_name(self) -> None:
        profile = json.loads(
            (ROOT / "android-integration/owner-open-profile/profile-v2.json")
            .read_text(encoding="utf-8")
        )
        runtime = json.loads(
            (
                ROOT
                / "android-integration/working-tree/vendor/trillionnium/owner-open/config/profile-v3.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            profile["rootlinux_payload"]["manifest_install_path"], INSTALL_MANIFEST
        )
        self.assertEqual(runtime["rootlinux_payload"]["image_manifest"], INSTALL_MANIFEST)
        for document in (profile, runtime):
            encoded = json.dumps(document, sort_keys=True)
            self.assertNotIn(STALE_INSTALL_MANIFEST, encoded)

        # Staging tools intentionally use a private, pre-image name.  The
        # Android product graph uses the distinct image-manifest name above.
        for relative in (
            "tools/owner-open/stage_owner_open_rootfs_payload.py",
            "tools/owner-open/stage_owner_open_rootfs_payload_release.py",
        ):
            staging = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("owner-open-rootfs.manifest.json", staging)
            self.assertNotIn("owner-open-rootfs.image-manifest.json", staging)

    def test_source_install_contracts_use_image_manifest_name(self) -> None:
        profile = json.loads(
            (
                ROOT / "android-integration/owner-open-profile/profile-v2.json"
            ).read_text(encoding="utf-8")
        )
        runtime = json.loads(
            (
                ROOT
                / "android-integration/working-tree/vendor/trillionnium/owner-open/config/profile-v3.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(profile["rootlinux_payload"]["manifest_install_path"], INSTALL_MANIFEST)
        self.assertEqual(runtime["rootlinux_payload"]["image_manifest"], INSTALL_MANIFEST)
        android_bp = (
            ROOT
            / "android-integration/working-tree/vendor/trillionnium/owner-open/Android.bp"
        ).read_text(encoding="utf-8")
        materialized = (
            ROOT
            / "android-integration/working-tree/vendor/trillionnium/owner-open/tools/verify_owner_open_materialized_payload.py"
        ).read_text(encoding="utf-8")
        self.assertIn("owner-open-rootfs.image-manifest.json", android_bp)
        self.assertIn("owner-open-rootfs.image-manifest.json", materialized)


if __name__ == "__main__":
    unittest.main()
