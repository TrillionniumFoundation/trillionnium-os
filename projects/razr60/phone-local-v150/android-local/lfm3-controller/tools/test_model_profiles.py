"""Profile and exact-token evidence tests. No device, model, or network access."""
import copy
from pathlib import Path
import unittest
import model_profiles as profiles
import phone_acceptance as acceptance
import phone_suite as suite

class ProfileTests(unittest.TestCase):
    def native(self, name="minicpm5-2b-q4_k_m"):
        p=profiles.profile(name)
        return {"model_profile":name,"model_sha256_verified":p["sha256"],"model_architecture":p["architecture"],
            "model_bytes_verified":p["bytes"],"model_metadata_unchanged":True,"chat_template_enable_thinking":False,
            "automatic_cpu_fallback":False,"max_tokens":256,"profile":{"prompt_tokens":3584},
            "prompt_budget":{"method":"llama_tokenize_exact_same_input_ids","model_contract_sha256":p["sha256"],
                "tokenizer_source_commit":profiles.LLAMA_COMMIT,"formatted_utf8_bytes":12000,"checked":True,"admitted":True,
                "is_exact_token_count":True,"add_special":True,"parse_special":True,"input_ids_passed_directly":True,
                "prompt_tokens_exact":3584,"input_ids_count":3584,"input_ids_sha256":"a"*64,"context_tokens":4096,
                "generation_tokens":256,"reserved_tokens":256,"total_context_tokens":4096}}
    def test_exact_boundary_and_consumed_ids(self):
        value=self.native(); self.assertTrue(acceptance.native_budget_valid(value,4096,value["model_profile"]))
        for field,bad in (("input_ids_count",3583),("prompt_tokens_exact",3585),("prompt_tokens_exact",True),
                ("method","lfm3_rendered_utf8_bytes_upper_bound"),("model_contract_sha256",acceptance.MODEL_SHA256),
                ("input_ids_passed_directly",False),("input_ids_sha256","not-a-hash"),("is_exact_token_count",False)):
            broken=copy.deepcopy(value);broken["prompt_budget"][field]=bad
            self.assertFalse(acceptance.native_budget_valid(broken,4096,value["model_profile"]),field)
        broken=copy.deepcopy(value);broken["profile"]["prompt_tokens"]=3583
        self.assertFalse(acceptance.native_budget_valid(broken,4096,value["model_profile"]))
    def test_profile_cannot_cross_bind(self):
        value=self.native()
        self.assertFalse(acceptance.native_budget_valid(value,4096))
        self.assertFalse(acceptance.native_budget_valid(value,4096,"spark-x2.6-4b-q4_k_m"))
        for field in ("model_profile","model_sha256_verified","model_architecture","model_metadata_unchanged","chat_template_enable_thinking"):
            broken=copy.deepcopy(value);broken.pop(field)
            self.assertFalse(acceptance.native_budget_valid(broken,4096,value["model_profile"]),field)
    def test_java_native_allowlist_pins_agree(self):
        root=Path(__file__).resolve().parents[1]
        java=(root/"src/org/trillionnium/hepta/local/ModelProfile.java").read_text()
        native=(root/"native/model-profile.h").read_text()
        for name,p in profiles.PROFILES.items():
            for value in (name,p["file"],p["sha256"],p["architecture"],str(p["bytes"])):
                self.assertIn(value,java);self.assertIn(value,native)
        self.assertEqual(profiles.profile()["sha256"],acceptance.MODEL_SHA256)
        with self.assertRaises(ValueError):profiles.profile("../model.gguf")

    def test_default_lfm3_requires_exact_proof_for_legacy_and_explicit_selection(self):
        value=self.native(profiles.DEFAULT_PROFILE)
        self.assertTrue(profiles.profile()["exact"])
        self.assertTrue(acceptance.native_budget_valid(value,4096))
        self.assertTrue(acceptance.native_budget_valid(value,4096,profiles.DEFAULT_PROFILE))
        for field in ("input_ids_sha256","input_ids_passed_directly","tokenizer_source_commit","input_ids_count"):
            broken=copy.deepcopy(value);broken["prompt_budget"].pop(field)
            self.assertFalse(acceptance.native_budget_valid(broken,4096),field)
        for consumed in (3583,3585,True):
            broken=copy.deepcopy(value);broken["profile"]["prompt_tokens"]=consumed
            self.assertFalse(acceptance.native_budget_valid(broken,4096))
        overflow=copy.deepcopy(value)
        overflow["prompt_budget"].update(prompt_tokens_exact=3585,input_ids_count=3585,total_context_tokens=4097)
        overflow["profile"]["prompt_tokens"]=3585
        self.assertFalse(acceptance.native_budget_valid(overflow,4096))
        old=copy.deepcopy(value)
        old["prompt_budget"]={"method":"lfm3_rendered_utf8_bytes_upper_bound","model_contract_sha256":acceptance.MODEL_SHA256,
            "checked":True,"admitted":True,"is_exact_token_count":False,"formatted_utf8_bytes":500,
            "bos_eos_upper":2,"generation_tokens":256,"reserved_tokens":256,"total_context_upper":1014,"context_tokens":4096}
        self.assertFalse(acceptance.native_budget_valid(old,4096))
        for size in (0,262145,True):
            oversized=copy.deepcopy(value);oversized["prompt_budget"]["formatted_utf8_bytes"]=size
            self.assertFalse(acceptance.native_budget_valid(oversized,4096))
        self.assertFalse(acceptance.native_budget_valid(value,True))
        self.assertFalse(acceptance.native_budget_valid(value,32768))

    def test_all_three_registries_require_exact_lfm3_without_changing_artifact(self):
        root=Path(__file__).resolve().parents[1]
        p=profiles.profile()
        self.assertEqual(p["bytes"],1049615680)
        self.assertEqual(p["sha256"],"43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452")
        self.assertIn('"'+p["sha256"]+'","lfm3",true,3L<<30)',
                      (root/"src/org/trillionnium/hepta/local/ModelProfile.java").read_text())
        self.assertIn('"'+p["sha256"]+'","lfm3",1049615680u,true}',
                      (root/"native/model-profile.h").read_text())

if __name__=="__main__":unittest.main()
