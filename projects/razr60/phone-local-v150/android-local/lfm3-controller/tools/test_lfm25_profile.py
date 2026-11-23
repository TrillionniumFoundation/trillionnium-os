"""Closed Java/C/host-registry agreement; no device, download or model execution."""
import re
import unittest
from pathlib import Path
from model_profiles import DEFAULT_PROFILE, PROFILES, profile

ROOT=Path(__file__).resolve().parents[1]
ID="lfm2.5-8b-a1b-q4_0"
SHA="48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715"
EXPECTED={"file":"LFM2.5-8B-A1B-Q4_0.gguf","bytes":4844678368,
          "sha256":SHA,"architecture":"lfm2moe","exact":True}

class Lfm25ClosedProfile(unittest.TestCase):
    def test_registry_identity_and_snapshot(self):
        self.assertEqual(profile(ID),EXPECTED)
        changed=profile(ID);changed["bytes"]=1
        self.assertEqual(profile(ID),EXPECTED)
        self.assertGreater(EXPECTED["bytes"],2**32-1)
    def test_native_registry_matches_host(self):
        text=(ROOT/"native/model-profile.h").read_text()
        entries=re.findall(r'\{"([^"]+)","([^"]+)","([a-f0-9]{64})","([^"]+)",(?:UINT64_C\((\d+)\)|(\d+)u),(true|false)\}',text)
        parsed={i:{"file":f,"sha256":s,"architecture":a,"bytes":int(n or u),"exact":e=="true"} for i,f,s,a,n,u,e in entries}
        self.assertEqual(len(entries),len(parsed))
        self.assertEqual(parsed,PROFILES)
    def test_java_artifact_and_revision_match(self):
        text=(ROOT/"src/org/trillionnium/hepta/local/ModelProfile.java").read_text()
        found=re.search(r'public static final ModelProfile LFM25_8B_A1B=new ModelProfile\("([^"]+)","[^"]+",\s*"([^"]+)","([^"]+)","([^"]+)",(\d+)L,\s*"([^"]+)","([^"]+)",(true|false),7L<<30\);',text)
        self.assertIsNotNone(found)
        i,repo,rev,f,n,s,a,exact=found.groups()
        self.assertEqual(i,ID)
        self.assertEqual(repo,"LiquidAI/LFM2.5-8B-A1B-GGUF")
        self.assertEqual(rev,"49c14831707011e64d70b2ebd8462ba08d608434")
        self.assertEqual({"file":f,"bytes":int(n),"sha256":s,"architecture":a,"exact":exact=="true"},EXPECTED)
    def test_no_alias_or_path_admission(self):
        for name in ("lfm2moe","LFM2.5-8B-A1B","../"+EXPECTED["file"],None,8):
            with self.subTest(name=name),self.assertRaises(ValueError):profile(name)
    def test_default_is_not_changed(self):
        self.assertEqual(DEFAULT_PROFILE,"lfm3-1.7b-qad-q4_0")
        self.assertEqual(profile(),PROFILES[DEFAULT_PROFILE])

if __name__=="__main__":unittest.main()
