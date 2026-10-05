"""Owner signing integration controls using real tiny ZIPs and synthetic BOMs.

No Android image, private release key, installed device or full source graph
is qualified by these fixtures. Only the mandatory host provenance path runs.
"""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
import zipfile

import test_android_release_ota as legacy

RELEASE = legacy.RELEASE


def bom_fixture():
    candidate = dict(commit="1" * 40, tree="2" * 40, archive_sha256="3" * 64,
                     control_regular_files=1600)
    from test_owner_source_provenance import m as provenance
    private = sorted(provenance.PRIVATE_PROJECT_PATHS)
    paths = ['trillionnium-os', *private, *('p%04d' % n for n in range(provenance.ORIGINAL_COUNT))]
    bom = dict(schema=RELEASE.OWNER_BOM_SCHEMA, profile_id=RELEASE.OWNER_PROFILE,
               decision="PASS_MEASURED_OWNER_GRAPH", candidate=candidate,
               manifest_sha256="4" * 64, manifest_project_count=1170,
               private_project_paths=private, control_regular_files=1600,
               git_content_inventory_sha256={p: "5" * 64 for p in paths},
               canonical_custody_sha256="6" * 64,
               manifest_repository_inventory_sha256="7" * 64,
               motorola_tree_inventory_sha256={p: "8" * 64 for p in (
                   "vendor/motorola/fogos", "vendor/motorola/sm6375-common")},
               generated_source_delta_sha256="9" * 64, owner_source_selection_sha256="a" * 64,
               manifest_projection_observations_sha256="b" * 64, private_composition_sha256="c" * 64,
               authority=RELEASE.OWNER_AUTHORITY, observations_sequential_not_globally_atomic=True,
               clean_public_source_claim=False, canonical_source_authority_modified=False,
               bom_migration_approval_asserted=False, independent_human_approval_asserted=False,
               installed=False, production_ready=False, input_packet_sha256="d" * 64,
               whole_measured_tracked_files=2000, whole_source_metadata_bytes=1170,
               raw_project_evidence_descriptors=[dict(path="/synthetic-not-executed/project%04d" % n,
                   bytes=1, sha256="e" * 64) for n in range(1170)])
    names = ("resolved_manifest", "control_archive", "inventory_index", "canonical_custody",
             "original_before", "original_after", "manifest_repository_inventory", "motorola_blob_trees",
             "generated_source_delta", "owner_source_selection", "manifest_projections", "private_composition")
    bom["input_descriptors"] = {name: dict(path="/synthetic-not-executed/" + name, bytes=1,
                                           sha256="f" * 64) for name in names}
    for name, digest in (("resolved_manifest", bom["manifest_sha256"]),
                         ("control_archive", candidate["archive_sha256"]),
                         ("canonical_custody", bom["canonical_custody_sha256"]),
                         ("manifest_projections", bom["manifest_projection_observations_sha256"]),
                         ("private_composition", bom["private_composition_sha256"])):
        bom["input_descriptors"][name]["sha256"] = digest
    bom["receipt_id"] = "sha256:" + RELEASE.sha256_bytes(RELEASE.canonical_json_bytes(bom))
    raw = RELEASE.canonical_json_bytes(bom)
    build = dict(schema="org.trillionnium.owner-android-build-source-inputs.v1", candidate=candidate,
                 resolved_manifest_sha256=bom["manifest_sha256"],
                 owner_source_bom_sha256=RELEASE.sha256_bytes(raw), stage_id="mechanism-only")
    return bom, raw, build


class OwnerReleaseIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fx = legacy.AndroidReleaseOtaTests()
        self.fx.setUp()
        self.bom, self.raw, self.build = bom_fixture()
        self.bom_path = self.fx.root / "owner-source-bom.json"
        self.bom_path.write_bytes(self.raw)
        self.build_path = self.fx.root / "owner-build-inputs.json"
        self.build_path.write_bytes(RELEASE.canonical_json_bytes(self.build))

    def tearDown(self):
        self.fx.tearDown()

    def arguments(self):
        return ["--require-owner-source-bom-binding", "--owner-source-bom", str(self.bom_path),
                "--owner-build-source-inputs", str(self.build_path)]

    def context(self):
        return RELEASE.load_owner_source_context(self.bom_path, self.build_path, 5)

    def write_owner_member(self, *, member=None, transform=None):
        context = self.context()
        binding = copy.deepcopy(context["expected"])
        if transform:
            transform(binding)
        with zipfile.ZipFile(self.fx.target, "a") as target:
            target.writestr(member or RELEASE.OWNER_BINDING_MEMBER,
                            RELEASE.canonical_json_bytes(binding))
        return context

    def test_inputs_and_mode_are_mandatory(self):
        for args in (("--require-owner-source-bom-binding",),
                     ("--owner-source-bom", str(self.bom_path)),
                     ("--owner-source-observer-seconds", "2")):
            with self.subTest(args=args), self.assertRaises(RELEASE.ReleaseError):
                self.fx.run_dry(*args)

    def test_profiles_cannot_be_mixed(self):
        with self.assertRaisesRegex(RELEASE.ReleaseError, "mutually exclusive"):
            self.fx.run_dry(*self.arguments(), "--require-source-bom-binding")

    def test_nonfinite_or_unbounded_budget_rejected(self):
        for seconds in ("nan", "inf", "0", "-1", "7201"):
            with self.subTest(seconds=seconds), self.assertRaisesRegex(RELEASE.ReleaseError, "finite"):
                self.fx.run_dry(*self.arguments(), "--owner-source-observer-seconds", seconds)

    def test_missing_owner_member_rejected_before_material_validation(self):
        with mock.patch.object(RELEASE, "validate_material") as material:
            with self.assertRaisesRegex(RELEASE.ReleaseError, "required unique owner META"):
                self.fx.run_dry(*self.arguments(), "--validate-key-material")
            material.assert_not_called()

    def test_legacy_member_cannot_substitute(self):
        self.write_owner_member(member="META/trillionnium-source-bom-binding.json")
        with self.assertRaisesRegex(RELEASE.ReleaseError, "required unique owner META"):
            self.fx.run_dry(*self.arguments())

    def test_owner_dry_run_is_complete_provenance_and_non_authorizing(self):
        self.write_owner_member()
        rc, receipt = self.fx.run_dry(*self.arguments())
        self.assertEqual(rc, 0)
        projection = receipt["plan"]["owner_source_bom_binding"]
        self.assertEqual(projection["candidate"], self.bom["candidate"])
        self.assertEqual(projection["member"], RELEASE.OWNER_BINDING_MEMBER)
        self.assertTrue(projection["whole_zip_custody_verified"])
        self.assertFalse(projection["release_signature_verified"])
        self.assertFalse(receipt["private_material_read"])
        self.assertFalse(receipt["release_boundaries"]["release_ready"])
        self.assertIs(RELEASE.validate_receipt(receipt), receipt)

    def test_meta_stage_splice_rejected(self):
        self.write_owner_member(transform=lambda b: b.update(build_stage_id="other"))
        with self.assertRaisesRegex(RELEASE.ReleaseError, "binding differs"):
            self.fx.run_dry(*self.arguments())

    def test_ambient_provenance_module_is_not_loaded_or_left_overwritten(self):
        ambient = types.ModuleType("owner_source_provenance")
        ambient.PROFILE = "malicious ambient module"
        with mock.patch.dict(sys.modules, {"owner_source_provenance": ambient}):
            context = self.context()
            self.assertEqual(context["checker"].p.PROFILE, RELEASE.OWNER_PROFILE)
            self.assertIs(sys.modules["owner_source_provenance"], ambient)

    def test_source_input_movement_rejected_after_loading(self):
        context = self.context()
        self.bom_path.write_bytes(self.raw + b" ")
        with self.assertRaisesRegex(RELEASE.ReleaseError, "changed after"):
            RELEASE.assert_owner_source_context(context)

    def test_parent_alias_rejected(self):
        alias = self.fx.root / "alias"
        alias.symlink_to(self.fx.root, target_is_directory=True)
        with self.assertRaisesRegex(RELEASE.ReleaseError, "symlink"):
            RELEASE.load_owner_source_context(alias / self.bom_path.name, self.build_path, 5)

    def test_projection_digest_type_scope_and_zip_mutations_rejected(self):
        self.write_owner_member()
        _, receipt = self.fx.run_dry(*self.arguments())
        mutations = [lambda p: p.update(installed=True), lambda p: p.update(member="META/other"),
                     lambda p: p["source_bom"].update(sha256="0" * 64),
                     lambda p: p["candidate"].update(control_regular_files=True),
                     lambda p: p["target_files"].update(sha256="0" * 64),
                     lambda p: p.update(extra="unknown")]
        for mutation in mutations:
            changed = copy.deepcopy(receipt)
            mutation(changed["plan"]["owner_source_bom_binding"])
            with self.subTest(mutation=mutation), self.assertRaises(RELEASE.ReleaseError):
                RELEASE.validate_receipt(changed)

    def test_signed_projection_needs_actual_execution_artifact(self):
        self.write_owner_member()
        _, receipt = self.fx.run_dry(*self.arguments())
        receipt["plan"]["signed_owner_source_bom_binding"] = copy.deepcopy(receipt["plan"]["owner_source_bom_binding"])
        with self.assertRaisesRegex(RELEASE.ReleaseError, "actual signed target"):
            RELEASE.validate_receipt(receipt)

    def execute_fixture(self, *, drop_member=False, move_after_validation=False, move_during_publication=False,
                        move_at_later_publication=False, move_publication_input=None,
                        input_publication_name="fixture-signed-target_files.zip", move_after_set_scan=False):
        self.write_owner_member()
        key_dir, apex_dir = self.fx.material_directories()
        output_dir = self.fx.root / "output"
        scratch_dir = self.fx.root / "scratch"
        output_dir.mkdir(mode=0o700)
        scratch_dir.mkdir(mode=0o700)
        commands = []

        def host_fixture(command, **kwargs):
            name = Path(command[0]).name
            commands.append(name)
            kwargs["output_log"].write_text("synthetic host tool only\n")
            if name == "sign_target_files_apks":
                with zipfile.ZipFile(self.fx.target) as source, zipfile.ZipFile(command[-1], "w") as signed:
                    for info in source.infolist():
                        if drop_member and info.filename == RELEASE.OWNER_BINDING_MEMBER:
                            continue
                        raw = source.read(info)
                        if info.filename == "SYSTEM/build.prop":
                            raw = raw.replace(b"test-keys", b"release-keys")
                        signed.writestr(info, raw)
            if name == "ota_from_target_files":
                Path(command[-1]).write_bytes(b"synthetic OTA, no actual signature\n")
                Path(command[command.index("--output_metadata_path") + 1]).write_text("fixture\n")
            return 0, 0.001

        def payload_fixture(path, *args):
            if move_after_validation:
                with zipfile.ZipFile(path, "a") as target:
                    target.writestr("SYSTEM/changed-after-owner-verification", b"changed")
            return {}

        def ota_fixture(path, *args):
            value = RELEASE.measure_file(path, "synthetic OTA")
            return dict(bytes=value["bytes"], sha256=value["sha256"], build_type="userdebug",
                        post_build="trillionnium/trillionnium_fogos/fogos:16/BUILD/1:userdebug/release-keys")

        capture = io.StringIO()
        original_replace = RELEASE.os.replace

        def publish_fixture(source, destination):
            if move_during_publication and Path(destination).name == "fixture-signed-target_files.zip":
                with zipfile.ZipFile(source, "a") as target:
                    target.writestr("SYSTEM/changed-during-publication", b"changed")
            if move_at_later_publication and Path(destination).name == "fixture-full-ota.zip":
                with zipfile.ZipFile(output_dir / "fixture-signed-target_files.zip", "a") as target:
                    target.writestr("SYSTEM/changed-during-later-publication", b"changed")
            result = original_replace(source, destination)
            if move_publication_input and Path(destination).name == input_publication_name:
                mutation_path = {
                    "bom": self.bom_path,
                    "build": self.build_path,
                    "target": self.fx.target,
                    **{name: self.fx.android / "out/host/linux-x86/bin" / name for name in (
                        "sign_target_files_apks", "ota_from_target_files", "check_ota_package_signature")},
                }[move_publication_input]
                mutation_path.write_bytes(mutation_path.read_bytes() + b"\n")
            return result

        original_measure = RELEASE.measure_file

        def measure_fixture(path, label, *args, **kwargs):
            result = original_measure(path, label, *args, **kwargs)
            if move_after_set_scan and label == "published output set metadata":
                self.bom_path.write_bytes(self.raw + b"\n")
            return result

        with mock.patch.object(RELEASE, "measure_file", side_effect=measure_fixture), \
             mock.patch.object(RELEASE, "run_sanitized", side_effect=host_fixture), \
             mock.patch.object(RELEASE, "verify_signed_payload_keys", side_effect=payload_fixture) as crypto, \
             mock.patch.object(RELEASE, "verify_signed_ota", side_effect=ota_fixture), \
             mock.patch.object(RELEASE.os, "replace", side_effect=publish_fixture), \
             redirect_stdout(capture):
            rc = RELEASE.main(["--android-root", str(self.fx.android), "--target-files", str(self.fx.target),
                               "--config", str(self.fx.config), "--output-dir", str(output_dir),
                               "--scratch-dir", str(scratch_dir), "--artifact-prefix", "fixture",
                               "--key-dir", str(key_dir), "--apex-key-dir", str(apex_dir), *self.arguments()])
            crypto_calls = crypto.call_count
        receipt = json.loads((output_dir / "fixture-signing-receipt.json").read_bytes())
        return rc, receipt, commands, crypto_calls, output_dir

    def test_signer_dropping_meta_denies_before_ota_and_quarantines_output(self):
        rc, receipt, commands, crypto_calls, output_dir = self.execute_fixture(drop_member=True)
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["decision"], RELEASE.EXECUTION_DENY)
        self.assertIn("required unique owner META", receipt["error"])
        self.assertEqual(commands, ["sign_target_files_apks"])
        self.assertEqual(crypto_calls, 0)
        self.assertTrue(receipt["quarantined_partial_outputs"])
        self.assertFalse((output_dir / "fixture-signed-target_files.zip").exists())

    def test_signed_zip_movement_denied_before_ota(self):
        rc, receipt, commands, _, output_dir = self.execute_fixture(move_after_validation=True)
        self.assertEqual(rc, 1)
        self.assertIn("changed after initial measurement", receipt["error"])
        self.assertEqual(commands, ["sign_target_files_apks"])
        self.assertFalse((output_dir / "fixture-signed-target_files.zip").exists())

    def test_same_owner_binding_preserved_across_signing_without_release_authority(self):
        rc, receipt, commands, _, _ = self.execute_fixture()
        self.assertEqual(rc, 0)
        before = receipt["plan"]["owner_source_bom_binding"]
        after = receipt["plan"]["signed_owner_source_bom_binding"]
        self.assertEqual(before["binding_id"], after["binding_id"])
        self.assertNotEqual(before["target_files"]["sha256"], after["target_files"]["sha256"])
        self.assertEqual(commands, ["sign_target_files_apks", "ota_from_target_files", "check_ota_package_signature"])
        self.assertFalse(receipt["release_boundaries"]["release_ready"])
        self.assertIs(RELEASE.validate_receipt(receipt), receipt)
        del receipt["plan"]["signed_owner_source_bom_binding"]
        with self.assertRaisesRegex(RELEASE.ReleaseError, "lacks signed META verification"):
            RELEASE.validate_receipt(receipt)

    def test_signed_zip_replacement_during_publication_is_denied(self):
        rc, receipt, _, _, output_dir = self.execute_fixture(move_during_publication=True)
        final = output_dir / "fixture-signed-target_files.zip"
        if rc == 0:
            facts = dict(scope="actual_tiny_zip_fixture_not_Android_or_release", returned_rc=rc,
                         receipt_signed_sha256=receipt["signed_target_files"]["sha256"],
                         actual_published_sha256=RELEASE.sha256_file(final),
                         actual_published_bytes=final.stat().st_size)
            print(json.dumps(facts, sort_keys=True))
        self.assertEqual(rc, 1)
        self.assertFalse(final.exists())

    def test_later_publication_moving_earlier_member_denies_and_retracts_entire_set(self):
        rc, receipt, _, _, output_dir = self.execute_fixture(move_at_later_publication=True)
        self.assertEqual(rc, 1)
        self.assertIn("failed to publish", receipt["error"])
        for name in ("fixture-signed-target_files.zip", "fixture-full-ota.zip", "fixture-ota-metadata.txt"):
            self.assertFalse((output_dir / name).exists())
            self.assertTrue((output_dir / (name + ".partial")).exists())
        self.assertEqual(len(receipt["quarantined_partial_outputs"]), 3)

    def assert_publication_denied_and_all_outputs_quarantined(self, result):
        rc, receipt, _, _, output_dir = result
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["decision"], RELEASE.EXECUTION_DENY)
        self.assertIn("failed to publish", receipt["error"])
        for name in ("fixture-signed-target_files.zip", "fixture-full-ota.zip", "fixture-ota-metadata.txt"):
            self.assertFalse((output_dir / name).exists())
            self.assertTrue((output_dir / (name + ".partial")).exists())
        self.assertEqual(len(receipt["quarantined_partial_outputs"]), 3)
        self.assertIs(RELEASE.validate_receipt(receipt), receipt)

    def test_source_bom_changed_after_first_publication_denies_and_retracts(self):
        self.assert_publication_denied_and_all_outputs_quarantined(
            self.execute_fixture(move_publication_input="bom"))

    def test_source_build_inputs_changed_after_second_publication_denies_and_retracts(self):
        self.assert_publication_denied_and_all_outputs_quarantined(
            self.execute_fixture(move_publication_input="build", input_publication_name="fixture-full-ota.zip"))

    def test_original_target_changed_after_last_publication_denies_and_retracts(self):
        self.assert_publication_denied_and_all_outputs_quarantined(
            self.execute_fixture(move_publication_input="target", input_publication_name="fixture-ota-metadata.txt"))

    def test_host_tools_changed_during_publication_denies_and_retracts(self):
        for name in ("sign_target_files_apks", "ota_from_target_files", "check_ota_package_signature"):
            # Each execution needs its own real output directory and baseline.
            with self.subTest(tool=name):
                fixture = OwnerReleaseIntegrationTests()
                fixture.setUp()
                try:
                    self.assert_publication_denied_and_all_outputs_quarantined(
                        fixture.execute_fixture(move_publication_input=name))
                finally:
                    fixture.tearDown()

    def test_source_changed_after_final_output_scan_still_denies_and_retracts(self):
        self.assert_publication_denied_and_all_outputs_quarantined(
            self.execute_fixture(move_after_set_scan=True))


if __name__ == "__main__":
    unittest.main()
