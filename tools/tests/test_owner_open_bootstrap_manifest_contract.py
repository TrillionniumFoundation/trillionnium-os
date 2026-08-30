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
SEAPP_CONTEXTS = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/sepolicy/private/seapp_contexts"
)


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

    def test_client_certificate_and_seapp_identity_are_platform_bound(self) -> None:
        bp = self.read(ANDROID_BP)
        app_start = bp.index('name: "TrillionniumOwnerOpenShell"')
        app_end = bp.index("\n}", app_start)
        app_module = bp[app_start:app_end]
        self.assertIn('certificate: "platform"', app_module)
        self.assertNotIn('certificate: "shared"', app_module)

        seapp = self.read(SEAPP_CONTEXTS)
        self.assertIn(
            "user=_app isPrivApp=false seinfo=platform "
            "name=org.trillionnium.owneropen domain=trillionnium_owner_open_client",
            seapp,
        )

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
            "type trillionnium_owner_open_payload_file, file_type, contextmount_type;",
            types,
        )
        self.assertNotIn(
            "type trillionnium_owner_open_payload_file, file_type, system_file_type",
            types,
        )
        self.assertIn("trillionnium_owner_open_payload_file:dir", domains)
        for permission in ("getattr", "open", "read", "search"):
            self.assertIn(permission, domains)
        capability_block_start = domains.index(
            "allow trillionnium_owner_open_bootstrap self:capability {"
        )
        capability_block_end = domains.index("};", capability_block_start)
        capability_block = domains[capability_block_start:capability_block_end]
        self.assertEqual(
            {
                line.strip()
                for line in capability_block.splitlines()[1:]
                if line.strip()
            },
            {"kill", "sys_admin", "sys_chroot"},
        )
        for capability in ("chown", "dac_override", "fowner", "setgid", "setuid"):
            self.assertNotIn(f"\n    {capability}\n", capability_block)
        self.assertIn("execute_no_trans", domains)
        self.assertNotIn("\n    entrypoint\n", domains)
        self.assertNotIn("\n    execute\n", domains)
        self.assertNotIn(
            "allow trillionnium_owner_open_bootstrap labeledfs:filesystem",
            domains,
        )
        self.assertNotIn(
            "allow trillionnium_owner_open_bootstrap contextmount_type:filesystem relabelto;",
            domains,
        )
        self.assertIn(
            "allowxperm trillionnium_owner_open_bootstrap loop_device:blk_file ioctl",
            domains,
        )
        self.assertNotIn(
            "allow trillionnium_owner_open_bootstrap trillionnium_owner_open_payload_file:dir mounton;",
            domains,
        )
        self.assertIn("PLATFORM_POLICY_HOLD", domains)

    def test_platform_policy_hold_is_explicit_and_fail_closed(self) -> None:
        domains = self.read(DOMAINS)
        hold = domains[domains.index("PLATFORM_POLICY_HOLD") :]
        self.assertIn("neverallows", hold)
        self.assertIn("mounting, remounting", hold)
        self.assertIn("source-only", hold)
        self.assertIn(
            "allow trillionnium_owner_open_bootstrap trillionnium_owner_open_state_file:dir mounton;",
            domains,
        )
        emergency_start = domains.index(
            "allow trillionnium_owner_open_emergency_stop self:capability {"
        )
        emergency_end = domains.index("};", emergency_start)
        emergency_block = domains[emergency_start:emergency_end]
        self.assertIn("kill", emergency_block)
        self.assertNotIn("dac_override", emergency_block)


if __name__ == "__main__":
    unittest.main()
