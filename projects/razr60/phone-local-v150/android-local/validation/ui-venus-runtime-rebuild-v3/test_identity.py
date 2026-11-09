"""Focused source/receipt identity boundaries; no compiler, network or phone."""
import copy, importlib.util, json, os, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("uiv_rebuild_under_test",HERE/"rebuild_exact_runtime.py")
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
APP=Path(os.environ["HEPTA_PUBLIC_SOURCE"])

class IdentityGates(unittest.TestCase):
    def test_exact_public_manifest_is_the_admitted_source(self):
        self.assertEqual(helper.verify_frozen_source(APP),APP.resolve())
        self.assertEqual(helper.sha(APP/"SOURCE-MANIFEST.json"),helper.APP_SHA)
    def test_historical_native_receipt_is_not_a_fresh_build_receipt(self):
        historical=json.loads((APP/"provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json").read_bytes())
        with self.assertRaises(ValueError):
            helper.check_report(historical,APP)
    def test_incomplete_new_compile_never_authorizes_assembler(self):
        incomplete={"source_build_completed":True,"worker_rebuilt":True,
                    "original_runtime_byte_identity":False,"original_assembler_allowed":False}
        with self.assertRaises(ValueError):
            helper.check_report(incomplete,APP)
    def test_source_run_binding_requires_exact_head_and_positive_attempt(self):
        _,shared=helper.dependencies()
        for head,run,attempt in (("unknown","1","1"),("a"*40,"0","1"),("a"*40,"1","0")):
            with self.assertRaises(ValueError):
                shared.source_identity(head,run,attempt)
    def test_q4_0_native_receipt_requires_exact_model_only_boundary(self):
        # This is native-receipt contract data, not a newly executed build.
        retained=json.loads((APP/"provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json").read_bytes())
        pins=helper.runtime_api(APP).load_pins(APP)
        helper.check_native_receipt(retained,APP,pins)
        mutations=(
            (("original_core_byte_unchanged",),True),
            (("only_model_identity_literals_changed",),False),
            (("source_boundary","original_files_unchanged"),17),
            (("source_boundary","changed_literal_count"),3),
            (("source_boundary","original_files_changed"),["native/probe-worker.c"]),
            (("source_boundary","files",0,"sha256"),"0"*64),
            (("worker","sha256"),"0e89b471555aba001ad762accc2a1a2016c3bc3f48b39dadfdab427fcf309285"),
            (("mmproj","sha256"),"0"*64),
            (("full_multimodal_token_admission_proven",),True),
            (("no_context_shift_proven",),True),
        )
        for keys,value in mutations:
            with self.subTest(keys=keys):
                changed=copy.deepcopy(retained);target=changed
                for key in keys[:-1]:target=target[key]
                target[keys[-1]]=value
                with self.assertRaises(ValueError):helper.check_native_receipt(changed,APP,pins)
    def test_mnn_old_manifest_or_helper_cannot_qualify_current_source(self):
        _,shared=helper.dependencies()
        # Synthetic unit input exercises identity rejection, never build success.
        sample={"source_build_completed":True,"original_runtime_byte_identity":True,
                "original_assembler_allowed":True,"mnn_library_rebuilt":True,"worker_rebuilt":True,
                "original_receipt_copied_unchanged":True,"phone_contacted":False,"pins_modified":False,
                "elf_rewritten":False,"app_source_modified":False,"state":"exact_original_runtime_rebuilt",
                "process_exit_code":0,"app_manifest_sha256":shared.APP_SHA,"helper_sha256":shared.HELPER_SHA,
                "ndk_revision_observed":"28.1.13356709",
                "toolchain":{"host_tag":"darwin-x86_64","clang_sha256":sorted(shared.MAC_CLANG_SHAS)[0]}}
        for key,old in (("app_manifest_sha256","9817f2af3937a402b52176565233c763869495d203080deffd7e279f9f621b69"),
                        ("helper_sha256","b585c1654ce91888bc4906b32fbe8ac1ace22987f445d1af25994d084f19dc78")):
            with self.subTest(key=key):
                changed=copy.deepcopy(sample);changed[key]=old
                with self.assertRaises(ValueError):shared.check_report(changed)

# The inputs below are source/receipt contract fixtures. No build is executed,
# and accepting a synthetic metadata fixture does not qualify runtime payloads.
import hashlib, tempfile

EXPECTED_APP_SHA = "1e5041491e3d2b9472b66db28d1cf2c602b45df8c3d0e8c9ee717e91cfd881ca"
OLD_PUBLIC_SHA = "1873ca6ecf998b7f3d3e447de2c9af5004c53c870042e2faef28be94265b40f4"
OLD_MNN_SHA = "961594375f7a8c6967426695b38f478106c09fa02e8c60b52eda3061f816d65d"
OLD_TRANSFER_SHA = "75c75071b23a5987fdc9d30c0da8e75d7c857d8a59eb1315b0d673d616e9461b"
OLD_UI_SHA = "2832f6db1133e5e462819e055e65fd88c6f5943df8570623b4c4021b71fbfd28"

class ClickPolicySourceIdentity(unittest.TestCase):
    def test_new_manifest_has_an_explicit_unqualified_derivative_boundary(self):
        manifest=json.loads((APP/"SOURCE-MANIFEST.json").read_bytes())
        self.assertEqual(helper.APP_SHA,EXPECTED_APP_SHA)
        self.assertFalse(manifest["phone_qualified"])
        self.assertFalse(manifest["current_candidate_installed"])
        derivative=manifest["public_source_derivative"]
        self.assertFalse(derivative["android_compile_inputs_byte_identical"])
        self.assertTrue(derivative["fresh_public_ci_build_required"])
        self.assertTrue(derivative["fresh_phone_acceptance_required"])
        self.assertEqual(derivative["parent_public_source_manifest_sha256"],OLD_PUBLIC_SHA)
        self.assertEqual(derivative["historical_full9_result"],
                         {"passed":3,"failed":6,"qualifies_this_derivative":False})

    def test_baseline_public_manifest_is_rejected_by_both_rebuilders(self):
        old=(APP/"provenance/source-manifests/code20-public-before-click-policy.json").read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(),OLD_PUBLIC_SHA)
        mnn,_=helper.dependencies()
        with tempfile.TemporaryDirectory(prefix="hepta-ci-old-source-") as temp:
            root=Path(temp);(root/"SOURCE-MANIFEST.json").write_bytes(old)
            for check in (mnn.verify_frozen_source,helper.verify_frozen_source):
                with self.subTest(check=check.__module__):
                    with self.assertRaisesRegex(ValueError,"click-policy derivative"):
                        check(root)

    def test_changed_manifest_bytes_are_rejected_before_member_admission(self):
        mnn,_=helper.dependencies()
        raw=(APP/"SOURCE-MANIFEST.json").read_bytes()+b"\n"
        with tempfile.TemporaryDirectory(prefix="hepta-ci-mutated-source-") as temp:
            root=Path(temp);(root/"SOURCE-MANIFEST.json").write_bytes(raw)
            for check in (mnn.verify_frozen_source,helper.verify_frozen_source):
                with self.subTest(check=check.__module__):
                    with self.assertRaisesRegex(ValueError,"click-policy derivative"):
                        check(root)

    def test_v8_mnn_source_and_rebuild_helper_cannot_transfer_as_current(self):
        _,shared=helper.dependencies()
        fixture={"source_build_completed":True,"original_runtime_byte_identity":True,
                 "original_assembler_allowed":True,"mnn_library_rebuilt":True,"worker_rebuilt":True,
                 "original_receipt_copied_unchanged":True,"phone_contacted":False,"pins_modified":False,
                 "elf_rewritten":False,"app_source_modified":False,"state":"exact_original_runtime_rebuilt",
                 "process_exit_code":0,"app_manifest_sha256":shared.APP_SHA,"helper_sha256":shared.HELPER_SHA,
                 "ndk_revision_observed":"28.1.13356709",
                 "toolchain":{"host_tag":"darwin-x86_64","clang_sha256":sorted(shared.MAC_CLANG_SHAS)[0]}}
        shared.check_report(fixture)  # Metadata-only fixture, never a runtime-build claim.
        for key,value in (("app_manifest_sha256",OLD_PUBLIC_SHA),("helper_sha256",OLD_MNN_SHA)):
            with self.subTest(key=key):
                old=copy.deepcopy(fixture);old[key]=value
                with self.assertRaisesRegex(ValueError,"source/helper differs"):
                    shared.check_report(old)

    def test_v2_ui_source_and_rebuild_helper_cannot_transfer_as_current(self):
        native=json.loads((APP/"provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json").read_bytes())
        fixture={"source_build_completed":True,"original_runtime_byte_identity":True,
                 "original_assembler_allowed":True,"worker_rebuilt":True,
                 "original_receipt_copied_unchanged":True,"phone_contacted":False,"pins_modified":False,
                 "elf_rewritten":False,"app_source_modified":False,"android_execution_performed":False,
                 "model_inference_performed":False,"apk_assembled":False,
                 "state":"exact_original_ui_venus_worker_rebuilt","process_exit_code":0,
                 "app_manifest_sha256":helper.APP_SHA,"helper_sha256":helper.sha(HERE/"rebuild_exact_runtime.py"),
                 "native_source_manifest_sha256":helper.NATIVE_MANIFEST_SHA,
                 "frozen_native_builder_sha256":helper.NATIVE_BUILDER_SHA,
                 "retained_original_build_receipt_sha256":helper.ORIGINAL_RECEIPT_SHA,
                 "toolchain":{"host_tag":"darwin-x86_64"},"native_builder_exit_code":0,
                 "native_build_receipt":native,
                 "native_build_receipt_sha256":hashlib.sha256((json.dumps(native,indent=2)+"\n").encode()).hexdigest()}
        helper.check_report(fixture,APP)  # Metadata-only fixture; no payload or execution qualification.
        for key,value in (("app_manifest_sha256",OLD_PUBLIC_SHA),("helper_sha256",OLD_UI_SHA)):
            with self.subTest(key=key):
                old=copy.deepcopy(fixture);old[key]=value
                with self.assertRaisesRegex(ValueError,"source/helper differs"):
                    helper.check_report(old,APP)

    def test_compiler_qualifier_remains_byte_identical(self):
        old=HERE.parent/"mobimind-ci-host-split-v8/qualify_macos_compiler.py"
        new=HERE.parent/"mobimind-ci-host-split-v9/qualify_macos_compiler.py"
        self.assertEqual(old.read_bytes(),new.read_bytes())
        self.assertEqual(helper.sha(new),helper.COMPILER_QUALIFIER_SHA)

    def test_every_rebuild_and_transfer_gate_is_preserved(self):
        mnn,shared=helper.dependencies()
        rows=(
            ("mobimind-runtime-rebuild-v8/rebuild_exact_runtime.py",
             "mobimind-runtime-rebuild-v9/rebuild_exact_runtime.py",
             ((OLD_PUBLIC_SHA,EXPECTED_APP_SHA),
              ("r8-code20-public-source","r9-code20-click-policy-public-source"),
              ("only the unmodified frozen public Code20 source is admitted",
               "only the unmodified frozen public Code20 click-policy derivative is admitted"))),
            ("mobimind-ci-host-split-v8/verify_ci_runtime_bundle.py",
             "mobimind-ci-host-split-v9/verify_ci_runtime_bundle.py",
             ((OLD_PUBLIC_SHA,EXPECTED_APP_SHA),(OLD_MNN_SHA,shared.HELPER_SHA))),
            ("ui-venus-runtime-rebuild-v2/rebuild_exact_runtime.py",
             "ui-venus-runtime-rebuild-v3/rebuild_exact_runtime.py",
             ((OLD_PUBLIC_SHA,EXPECTED_APP_SHA),(OLD_MNN_SHA,helper.MNN_REBUILD_SHA),
              (OLD_TRANSFER_SHA,helper.MNN_TRANSFER_SHA),
              ("mobimind-runtime-rebuild-v8","mobimind-runtime-rebuild-v9"),
              ("mobimind-ci-host-split-v8","mobimind-ci-host-split-v9"),
              ("r2-code20-public-source","r3-code20-click-policy-public-source"))),
            ("ui-venus-runtime-rebuild-v2/verify_ci_runtime_bundle.py",
             "ui-venus-runtime-rebuild-v3/verify_ci_runtime_bundle.py",
             ((OLD_PUBLIC_SHA,EXPECTED_APP_SHA),(OLD_UI_SHA,helper.sha(HERE/"rebuild_exact_runtime.py")))),
        )
        for old,new,replacements in rows:
            with self.subTest(new=new):
                expected=(HERE.parent/old).read_text()
                for before,after in replacements:expected=expected.replace(before,after)
                self.assertEqual(expected.encode(),(HERE.parent/new).read_bytes())
        self.assertEqual(mnn.MNN_COMMIT,"bce7456ce60b5e51b4d3b357f303515860353d8c")

    def test_ui_transfer_is_bound_to_the_new_helper_and_source(self):
        transfer=helper.module(HERE/"verify_ci_runtime_bundle.py","click_policy_ui_transfer")
        self.assertEqual(transfer.APP_SHA,EXPECTED_APP_SHA)
        self.assertEqual(transfer.HELPER_SHA,helper.sha(HERE/"rebuild_exact_runtime.py"))
        self.assertNotEqual(transfer.HELPER_SHA,OLD_UI_SHA)

if __name__=="__main__":unittest.main()
