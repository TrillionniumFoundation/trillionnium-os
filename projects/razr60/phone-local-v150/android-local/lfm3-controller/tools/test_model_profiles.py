"""Profile and exact-token evidence tests. No device, model, or network access."""
import copy
from pathlib import Path
import unittest
import model_profiles as profiles
import phone_acceptance as acceptance
import phone_suite as suite

class ProfileTests(unittest.TestCase):
    def native(self):
        name="minicpm5-2b-q4_k_m"; p=profiles.profile(name)
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
    def test_lfm3_requires_exact_ids_without_changing_artifact_or_context(self):
        name=profiles.DEFAULT_PROFILE; p=profiles.profile(name)
        self.assertTrue(p["exact"])
        self.assertEqual(p["bytes"],1049615680)
        self.assertEqual(p["sha256"],"43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452")
        for context in (4096,8192):
            count=context-512; value=self.native()
            value.update(model_profile=name,model_sha256_verified=p["sha256"],model_architecture=p["architecture"],model_bytes_verified=p["bytes"])
            value["profile"]["prompt_tokens"]=count
            value["prompt_budget"].update(model_contract_sha256=p["sha256"],context_tokens=context,
                prompt_tokens_exact=count,input_ids_count=count,total_context_tokens=context)
            self.assertTrue(acceptance.native_budget_valid(value,context,name))
            for field,bad in (("input_ids_count",count-1),("input_ids_sha256",""),
                    ("input_ids_passed_directly",False),("admitted",False),
                    ("method","lfm3_rendered_utf8_bytes_upper_bound"),("is_exact_token_count",False)):
                broken=copy.deepcopy(value);broken["prompt_budget"][field]=bad
                self.assertFalse(acceptance.native_budget_valid(broken,context,name),field)
            overflow=copy.deepcopy(value);overflow["prompt_budget"].update(prompt_tokens_exact=count+1,input_ids_count=count+1,total_context_tokens=context+1)
            overflow["profile"]["prompt_tokens"]=count+1
            self.assertFalse(acceptance.native_budget_valid(overflow,context,name))
            mismatch=copy.deepcopy(value);mismatch["profile"]["prompt_tokens"]=count-1
            self.assertFalse(acceptance.native_budget_valid(mismatch,context,name))
            legacy=copy.deepcopy(value)
            legacy["prompt_budget"].update(method="lfm3_rendered_utf8_bytes_upper_bound",is_exact_token_count=False,
                formatted_utf8_bytes=100,bos_eos_upper=2,total_context_upper=614)
            self.assertFalse(acceptance.native_budget_valid(legacy,context,name))
    def test_java_native_allowlist_pins_agree(self):
        root=Path(__file__).resolve().parents[1]
        java=(root/"src/org/trillionnium/hepta/local/ModelProfile.java").read_text()
        native=(root/"native/model-profile.h").read_text()
        for name,p in profiles.PROFILES.items():
            for value in (name,p["file"],p["sha256"],p["architecture"],str(p["bytes"])):
                self.assertIn(value,java);self.assertIn(value,native)
        self.assertEqual(profiles.profile()["sha256"],acceptance.MODEL_SHA256)
        with self.assertRaises(ValueError):profiles.profile("../model.gguf")

if __name__=="__main__":unittest.main()
