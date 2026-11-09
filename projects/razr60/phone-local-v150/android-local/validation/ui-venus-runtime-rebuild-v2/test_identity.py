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
if __name__=="__main__":unittest.main()
