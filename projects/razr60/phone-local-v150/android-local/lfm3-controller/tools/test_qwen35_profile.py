"""Actual host registry selection; no model, device or network access."""
import unittest
from model_profiles import DEFAULT_PROFILE, PROFILES, profile

ID="qwen3.5-4b-q4_0"
EXPECTED={"file":"Qwen3.5-4B-Q4_0.gguf","bytes":2583221408,
          "sha256":"298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb",
          "architecture":"qwen35","exact":True}

class Qwen35ClosedProfile(unittest.TestCase):
    def test_exact_identity_and_independent_snapshot(self):
        self.assertEqual(profile(ID),EXPECTED)
        self.assertGreater(profile(ID)["bytes"],2**31-1)
        snapshot=profile(ID);snapshot["exact"]=False;snapshot["sha256"]="0"*64
        self.assertEqual(profile(ID),EXPECTED)
    def test_no_family_path_other_size_or_nonstring_selection(self):
        for name in ("qwen35","Qwen3.5-4B","qwen3.5-14b-q4_0","../"+EXPECTED["file"],None,8):
            with self.subTest(name=name),self.assertRaises(ValueError):profile(name)
    def test_nine_b_is_independent_and_larger_than_uint32(self):
        large=profile("qwen3.5-9b-q4_0")
        self.assertEqual(large,{"file":"Qwen3.5-9B-Q4_0.gguf","bytes":5379417312,
            "sha256":"17670346b4260ddcb0173965145155885024f3c9a4a24389a3370751edbcde24","architecture":"qwen35","exact":True})
        self.assertGreater(large["bytes"],2**32-1)
        self.assertNotEqual(large["sha256"],profile(ID)["sha256"])
        large["sha256"]=profile(ID)["sha256"]
        self.assertNotEqual(large,profile("qwen3.5-9b-q4_0"))
    def test_existing_default_is_unchanged(self):
        self.assertEqual(DEFAULT_PROFILE,"lfm3-1.7b-qad-q4_0")
        self.assertEqual(profile(),PROFILES[DEFAULT_PROFILE])
        self.assertEqual(list(PROFILES)[-2],ID)
        self.assertEqual(list(PROFILES)[-1],"qwen3.5-9b-q4_0")

if __name__=="__main__":unittest.main()
