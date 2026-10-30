from __future__ import annotations

from pathlib import Path
import unittest
import re


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
PROFILE = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/config/profile-codex-host-relay-v1.json"
TYPES = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/sepolicy/private/types.te"
DOMAINS = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/sepolicy/private/domains.te"
SEAPP_CONTEXTS = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/sepolicy/private/seapp_contexts"
)


INIT_RC = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/init/trillionnium-owner-open.rc"


class OwnerOpenBootstrapManifestContractTest(unittest.TestCase):
    def read(self, path: Path) -> str:
        self.assertTrue(path.is_file(), path)
        return path.read_text(encoding="utf-8")

    def test_native_boundary_parses_and_binds_manifest_before_supervisor(self) -> None:
        source = self.read(BOOTSTRAP)
        for marker in (
            '#include <json/json.h>',
            'constexpr const char* kManifest = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.image-manifest.json";',
            'constexpr const char* kProfile = "/system_ext/etc/trillionnium/owner-open/profile-codex-host-relay-v1.json";',
            'constexpr const char* kRuntimeProfileRevision = "2026-10-09-leap-api37-owner-client-emergency";',
            'constexpr const char* kRuntimeProfileId = "leap-codex-host-relay-v1";',
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
            'root["claim_ceiling"] != "LEAP_API37_SOURCE_CANDIDATE_NOT_DEVICE_QUALIFIED"',
            'ingress["automatic_redispatch"] != false',
            'JsonUnsigned(run, "image_bytes"',
            'JsonUnsigned(staging, "entry_count"',
            'const Json::Value& claims = staging["claims"]',
            'claims.isObject()',
            "!SameStableMetadata(before, after)",
            "return Fail(BootstrapFailure::DigestAgreement);",
            "RequiredPayloadEntriesExist(manifest)",
            'SetProperty("trillionnium.owner_open.ready", "0");',
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
            source.index('SetProperty("trillionnium.owner_open.ready", "0");', source.index("int main(")),
            source.index("if (!ValidateRuntimeProfile())"),
        )

    def test_android_module_declares_json_parser_dependency(self) -> None:
        bp = self.read(ANDROID_BP)
        self.assertIn('shared_libs: ["libcrypto", "libjsoncpp", "liblog"]', bp)
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
        self.assertEqual(profile["schema"], "org.trillionnium.owner-open.android-runtime-profile.v4")
        self.assertIn('src: "config/profile-codex-host-relay-v1.json"', self.read(ANDROID_BP))
        self.assertEqual(profile["mount_handoff"]["owner"], "android_init")
        self.assertFalse(profile["mount_handoff"]["bootstrap_mount_operations"])
        self.assertEqual(profile["provider"]["role"], "host_codex")
        self.assertFalse(profile["provider"]["automatic_reconnect"])
        self.assertFalse(profile["provider"]["automatic_redispatch"])
        self.assertFalse(profile["provider"]["long_lived_credentials_on_phone"])
        self.assertEqual(profile["revision"], "2026-10-09-leap-api37-owner-client-emergency")
        self.assertEqual(profile["profile_id"], "leap-codex-host-relay-v1")
        self.assertEqual(profile["enabled_property"], "ro.trillionnium.owner_open.enabled")
        self.assertEqual(profile["ready_property"], "trillionnium.owner_open.ready")
        self.assertEqual(profile["emergency_stop_property"], "sys.trillionnium.owner_open.stop")
        self.assertEqual(profile["android_ingress"]["automatic_redispatch"], False)
        self.assertNotIn("automatic_effect_redispatch", profile["android_ingress"])
        self.assertEqual(profile["claim_ceiling"], "LEAP_API37_SOURCE_CANDIDATE_NOT_DEVICE_QUALIFIED")
        self.assertTrue(profile["claims"]["source_modules_authored"])
        self.assertFalse(any(profile["claims"][name] for name in (
            "soong_compiled",
            "selinux_compiled",
            "target_files_built",
            "image_included",
            "physical_device_observed",
            "public_release",
        )))

    def test_init_owns_mounts_and_bootstrap_has_only_execution_capabilities(self) -> None:
        types = self.read(TYPES)
        domains = self.read(DOMAINS)
        self.assertIn(
            "type trillionnium_owner_open_payload_file, file_type, system_file_type;",
            types,
        )
        self.assertIn(
            "type trillionnium_owner_open_payload_exec, file_type, system_file_type, exec_type;",
            types,
        )
        self.assertNotIn("contextmount_type", types)
        self.assertIn("trillionnium_owner_open_payload_file:dir", domains)
        for permission in ("getattr", "open", "read", "search"):
            self.assertIn(permission, domains)
        capability_block_start = domains.index(
            "allow trillionnium_owner_open_bootstrap self:capability {"
        )
        capability_block_end = domains.index("};", capability_block_start)
        capability_block = domains[capability_block_start:capability_block_end]
        self.assertEqual(
            {line.strip() for line in capability_block.splitlines()[1:] if line.strip()},
            {"kill", "sys_chroot"},
        )
        for capability in ("sys_admin", "chown", "dac_override", "fowner", "setgid", "setuid"):
            self.assertNotIn(f"\n    {capability}\n", capability_block)
        self.assertIn("execute_no_trans", domains)
        self.assertIn("allow init trillionnium_owner_open_state_file:dir mounton;", domains)
        self.assertIn("allow init trillionnium_owner_open_payload_file:dir mounton;", domains)
        for forbidden in (
            "allow trillionnium_owner_open_bootstrap labeledfs:filesystem",
            "allow trillionnium_owner_open_bootstrap contextmount_type:filesystem relabelto;",
            "allowxperm trillionnium_owner_open_bootstrap loop_device:blk_file ioctl",
            "allow trillionnium_owner_open_bootstrap trillionnium_owner_open_payload_file:dir mounton;",
            "allow trillionnium_owner_open_bootstrap trillionnium_owner_open_state_file:dir mounton;",
        ):
            self.assertNotIn(forbidden, domains)

    def test_verified_init_handoff_and_emergency_stop_are_fail_closed(self) -> None:
        source = self.read(BOOTSTRAP)
        domains = self.read(DOMAINS)
        rc = self.read(INIT_RC)
        main = source[source.index("int main(") :]
        self.assertLess(main.index('SetProperty("trillionnium.owner_open.ready", "0")'), main.index("ValidateRuntimeProfile()"))
        self.assertLess(main.index("ClearComponentMeasurement()"), main.index("ValidateRuntimeProfile()"))
        self.assertLess(main.index("ValidateInitMountedRoot()"), main.index("const pid_t child = fork()"))
        self.assertLess(main.index("WaitForSupervisorReady(child, &readiness)"), main.index('SetProperty("trillionnium.owner_open.ready", "1")'))
        self.assertIn("if (!verify_only && !run_mounted)", main)
        self.assertIn("return Fail(BootstrapFailure::ExpectedMode);", main)
        self.assertIn('on property:trillionnium.owner_open.verified=1 && property:trillionnium.owner_open.data_ready=1', rc)
        handoff = rc[rc.index('on property:trillionnium.owner_open.verified=1'):rc.index('on property:init.svc.trillionnium_owner_open_bootstrap=stopped')]
        self.assertLess(handoff.index("mount erofs loop@"), handoff.index("start trillionnium_owner_open_bootstrap"))
        self.assertLess(handoff.index("setprop trillionnium.owner_open.mount_ready 1"), handoff.index("start trillionnium_owner_open_bootstrap"))
        self.assertIn("ro nosuid nodev", handoff)
        self.assertIn("bind remount nosuid nodev noexec", handoff)
        self.assertIn("private rec", handoff)
        bootstrap_service = rc[rc.index("service trillionnium_owner_open_bootstrap "):rc.index("service trillionnium_owner_open_ingress ")]
        self.assertIn("--run-mounted", bootstrap_service)
        self.assertIn("namespace mnt", bootstrap_service)
        self.assertEqual(re.findall(r"^    capabilities(.*)$", bootstrap_service, re.M), [" SYS_CHROOT KILL"])
        emergency_service = rc[rc.index("service trillionnium_owner_open_emergency_stop "):]
        self.assertEqual(re.findall(r"^    capabilities(.*)$", emergency_service, re.M), [""])
        emergency_action = rc[rc.index("on property:sys.trillionnium.owner_open.stop=1"):rc.index("service trillionnium_owner_open_verify ")]
        self.assertNotIn("stop trillionnium_owner_open_ingress", rc)
        self.assertIn("start trillionnium_owner_open_ingress\n    exec_start trillionnium_owner_open_verify", rc)
        self.assertLess(emergency_action.index("setprop trillionnium.owner_open.ready 0"), emergency_action.index("stop trillionnium_owner_open_bootstrap"))
        self.assertLess(emergency_action.index("stop trillionnium_owner_open_bootstrap"), emergency_action.index("exec_start trillionnium_owner_open_emergency_stop"))
        self.assertNotIn("allow trillionnium_owner_open_emergency_stop self:capability", domains)
        self.assertNotIn("set_prop(shell, trillionnium_owner_open_prop)", domains)


if __name__ == "__main__":
    unittest.main()
