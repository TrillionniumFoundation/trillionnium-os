from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/native/owner_open_bootstrap.cpp"
)
ANDROID_BP = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/Android.bp"
)
BUILDER = ROOT / "tools/owner-open/build_owner_open_rootfs_image_release.py"
MATERIALIZER = ROOT / "tools/owner-open/verify_owner_open_materialized_payload.py"
ANDROID_MATERIALIZER = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/tools/verify_owner_open_materialized_payload.py"
)
PROFILE = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/config/profile-v3.json"
TYPES = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/sepolicy/private/types.te"
DOMAINS = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/sepolicy/private/domains.te"


class OwnerOpenBootstrapManifestContractTest(unittest.TestCase):
    def read(self, path: Path) -> str:
        self.assertTrue(path.is_file(), path)
        return path.read_text(encoding="utf-8")

    def test_native_boundary_parses_and_binds_manifest_before_supervisor(self) -> None:
        source = self.read(BOOTSTRAP)
        for marker in (
            '#include <json/json.h>',
            'constexpr const char* kManifest = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.image-manifest.json";',
            'constexpr const char* kProfile = "/system_ext/etc/trillionnium/owner-open/profile-v3.json";',
            'constexpr const char* kRuntimeProfileRevision = "2026-08-29-r5-android-source-closure";',
            'constexpr const char* kRuntimeProfileId = "owner-open-dogfood-v3";',
            "Json::CharReaderBuilder::strictMode",
            'builder["skipBom"] = false',
            'builder["rejectDupKeys"] = true',
            "ReadImageManifest",
            "ValidateRuntimeProfile",
            "StagingEntriesMatch",
            'root["enabled_property"] != "ro.trillionnium.owner_open.enabled"',
            'claims["source_modules_authored"] != true',
            'claims.size() != 9',
            'claims.size() != 7',
            'claims.size() == 8',
            'claims["expected_source_digests_verified"] == true',
            'root["claim_ceiling"] != "ANDROID_OWNER_OPEN_SOURCE_IMPLEMENTED_NOT_BUILT"',
            'ingress["automatic_redispatch"] != false',
            'JsonUnsigned(run, "image_bytes"',
            'JsonUnsigned(staging, "entry_count"',
            'const Json::Value& claims = staging["claims"]',
            'claims.isObject()',
            "!SameStableMetadata(before, after)",
            "image digest file disagrees with image manifest",
            "RequiredPayloadEntriesExist(manifest)",
            'SetReady("0");',
        ):
            self.assertIn(marker, source)
        self.assertLess(
            source.index("ValidateRuntimeProfile()"),
            source.index("const pid_t child = fork()"),
        )
        self.assertLess(
            source.index("ReadImageManifest(&manifest)"),
            source.index("const pid_t child = fork()"),
        )
        self.assertLess(
            source.index('SetReady("0");', source.index("int main()")),
            source.index("if (!ValidateRuntimeProfile())"),
        )

    def test_android_module_declares_json_parser_dependency(self) -> None:
        bp = self.read(ANDROID_BP)
        self.assertIn('shared_libs: ["libcrypto", "libjsoncpp"]', bp)
        self.assertIn("owner-open-rootfs-manifest-verified", bp)

    def test_image_manifest_carries_complete_entry_inventory(self) -> None:
        builder = self.read(BUILDER)
        materializer = self.read(MATERIALIZER)
        android_materializer = self.read(ANDROID_MATERIALIZER)
        self.assertIn('"entries": manifest.get("entries")', builder)
        self.assertIn("def validate_entries", materializer)
        self.assertIn("validate_entries(manifest)", materializer)
        self.assertIn("os.fchmod(descriptor, 0o644)", materializer)
        self.assertIn("os.fchmod(descriptor, 0o644)", android_materializer)

    def test_checked_in_runtime_profile_matches_native_pins(self) -> None:
        import json

        profile = json.loads(self.read(PROFILE))
        self.assertEqual(profile["revision"], "2026-08-29-r5-android-source-closure")
        self.assertEqual(profile["profile_id"], "owner-open-dogfood-v3")
        self.assertEqual(profile["enabled_property"], "ro.trillionnium.owner_open.enabled")
        self.assertEqual(profile["ready_property"], "trillionnium.owner_open.ready")
        self.assertEqual(profile["emergency_stop_property"], "sys.trillionnium.owner_open.stop")
        self.assertEqual(profile["android_ingress"]["automatic_redispatch"], False)
        self.assertNotIn("automatic_effect_redispatch", profile["android_ingress"])
        self.assertEqual(profile["claim_ceiling"], "ANDROID_OWNER_OPEN_SOURCE_IMPLEMENTED_NOT_BUILT")
        self.assertTrue(profile["claims"]["source_modules_authored"])
        self.assertFalse(any(profile["claims"][name] for name in (
            "soong_compiled",
            "selinux_compiled",
            "target_files_built",
            "image_included",
            "physical_device_observed",
            "public_release",
        )))

    def test_payload_label_and_directory_traversal_are_declared(self) -> None:
        types = self.read(TYPES)
        domains = self.read(DOMAINS)
        self.assertIn(
            "type trillionnium_owner_open_payload_file, file_type, system_file_type, contextmount_type;",
            types,
        )
        self.assertIn("trillionnium_owner_open_payload_file:dir", domains)
        for permission in ("getattr", "open", "read", "search"):
            self.assertIn(permission, domains)
        self.assertIn(
            "allow trillionnium_owner_open_bootstrap labeledfs:filesystem",
            domains,
        )
        self.assertIn(
            "allow trillionnium_owner_open_bootstrap contextmount_type:filesystem relabelto;",
            domains,
        )
        self.assertIn(
            "allowxperm trillionnium_owner_open_bootstrap loop_device:blk_file ioctl",
            domains,
        )
        self.assertIn(
            "allow trillionnium_owner_open_bootstrap trillionnium_owner_open_payload_file:dir mounton;",
            domains,
        )


if __name__ == "__main__":
    unittest.main()
