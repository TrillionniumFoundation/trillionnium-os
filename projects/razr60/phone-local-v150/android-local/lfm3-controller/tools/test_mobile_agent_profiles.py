"""Closed identities and exact receipt admission; no phone/model access."""
import copy
from pathlib import Path
import unittest
import model_profiles as profiles
import phone_acceptance as acceptance
import test_model_profiles as base_tests
EXPECTED = {'bonsai2-9b-q2_0': {'file': 'Ternary-Bonsai-2-9B-Q2_0.gguf', 'bytes': 2556640128, 'sha256': '1f884aa56aacd2bbbb2e4b7abaead2b1102b74a9c75a23fc33dab916813a384d', 'architecture': 'qwen35', 'exact': True}, 'orvena-4b-q4_k_m': {'file': 'Orvena-4B.Q4_K_M.gguf', 'bytes': 2783447904, 'sha256': 'c5d6df6e9a0828fa3068dfc6f6ca2ff6c4d950adc7e60e4b7202ece61595aa57', 'architecture': 'qwen35', 'exact': True}}
class MobileAgentProfiles(unittest.TestCase):
    def test_exact_artifacts_across_host_java_native(self):
        root=Path(__file__).resolve().parents[1]
        java=(root/"src/org/trillionnium/hepta/local/ModelProfile.java").read_text()
        native=(root/"native/model-profile.h").read_text()
        for name,p in EXPECTED.items():
            with self.subTest(profile=name):
                self.assertEqual(profiles.profile(name),p)
                self.assertGreater(p["bytes"],2**31-1)
                for value in (name,p["file"],str(p["bytes"]),p["sha256"]):
                    self.assertIn(value,java);self.assertIn(value,native)
                snapshot=profiles.profile(name);snapshot["sha256"]="0"*64
                self.assertEqual(profiles.profile(name),p)
    def test_same_architecture_receipts_do_not_cross_authorize(self):
        for name,p in EXPECTED.items():
            with self.subTest(profile=name):
                value=base_tests.ProfileTests().native()
                value.update(model_profile=name,model_sha256_verified=p["sha256"],model_architecture=p["architecture"],model_bytes_verified=p["bytes"])
                value["prompt_budget"]["model_contract_sha256"]=p["sha256"]
                self.assertTrue(acceptance.native_budget_valid(value,4096,name))
                for other in ("qwen3.5-4b-q4_0","qwen3.5-9b-q4_0",*EXPECTED):
                    if other!=name:self.assertFalse(acceptance.native_budget_valid(value,4096,other))
                for field in ("input_ids_sha256","input_ids_passed_directly","tokenizer_source_commit"):
                    bad=copy.deepcopy(value);bad["prompt_budget"].pop(field)
                    self.assertFalse(acceptance.native_budget_valid(bad,4096,name))
    def test_no_family_alias_or_path_selection(self):
        for name in ("bonsai2","Bonsai2-9B","orvena","Orvena-4B","../Ternary-Bonsai-2-9B-Q2_0.gguf",None,28):
            with self.subTest(name=name),self.assertRaises(ValueError):profiles.profile(name)
    def test_legacy_order_and_default_retained(self):
        self.assertEqual(profiles.DEFAULT_PROFILE,"lfm3-1.7b-qad-q4_0")
        self.assertEqual(list(profiles.PROFILES)[7:9],["qwen3.5-4b-q4_0","qwen3.5-9b-q4_0"])
        self.assertEqual(list(profiles.PROFILES)[9:11],list(EXPECTED))
if __name__=="__main__":unittest.main()
