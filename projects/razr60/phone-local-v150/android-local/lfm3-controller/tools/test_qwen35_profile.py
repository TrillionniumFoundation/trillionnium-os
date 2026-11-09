"""Exact Code22-preserving experimental registration; no device/model execution."""
import hashlib
from pathlib import Path
import re
import unittest
from model_profiles import DEFAULT_PROFILE, LLAMA_COMMIT, PROFILES, profile

ROOT=Path(__file__).resolve().parents[1]
ID='qwen35-4b-q4_0'
EXPECTED={'file':'Qwen3.5-4B-Q4_0.gguf','bytes':2583221408,
          'sha256':'298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb',
          'architecture':'qwen35','exact':True}
BASE_PINS={
    'src/org/trillionnium/hepta/local/ModelProfile.java':'b0083806960be86026def1efb749d8dd2ede9468578b27f73e71f4de2febc7e8',
    'native/model-profile.h':'76f24013af935b1aa6088cf0d80a6386ee3a4f90aad3c4277da096d8ea28d36d',
    'tools/model_profiles.py':'c3930bb183a7462b8b752732100e5557319cb41105e4c15f24139648c96e4669',
}

class Qwen35ClosedProfile(unittest.TestCase):
    def test_identity_and_copy(self):
        self.assertEqual(profile(ID),EXPECTED)
        changed=profile(ID);changed['bytes']=1
        self.assertEqual(profile(ID),EXPECTED)

    def test_three_registries_agree_for_all_eight_profiles(self):
        native=(ROOT/'native/model-profile.h').read_text()
        entries=re.findall(r'\{"([^"]+)","([^"]+)","([a-f0-9]{64})","([^"]+)",(?:UINT64_C\((\d+)\)|(\d+)u),(true|false)\}',native)
        parsed={i:{'file':f,'sha256':s,'architecture':a,'bytes':int(n or u),'exact':e=='true'} for i,f,s,a,n,u,e in entries}
        self.assertEqual(len(entries),8);self.assertEqual(parsed,PROFILES)
        java=(ROOT/'src/org/trillionnium/hepta/local/ModelProfile.java').read_text()
        entries=re.findall(r'new ModelProfile\("([^"]+)","[^"]+",\s*"([^"]+)","([^"]*)",\s*"([^"]+)",(\d+)L,\s*"([^"]+)","([^"]+)",(true|false),(\d+)L<<30\)',java)
        parsed={i:{'file':f,'sha256':s,'architecture':a,'bytes':int(n),'exact':e=='true'} for i,r,v,f,n,s,a,e,m in entries}
        self.assertEqual(len(entries),8);self.assertEqual(parsed,PROFILES)
        row=[x for x in entries if x[0]==ID]
        self.assertEqual(len(row),1)
        self.assertEqual((row[0][1],row[0][2],row[0][-1]),('unsloth/Qwen3.5-4B-GGUF','1a02dbed1cdfe73efc3fa519c54126befb4faf68','6'))

    def test_removing_only_qwen_recovers_exact_code22_registries(self):
        for relative,digest in BASE_PINS.items():
            text=(ROOT/relative).read_text()
            if relative.endswith('.java'):
                start=text.index('    // Experimental Unsloth conversion')
                end=text.index('    public final String id,displayName',start)
                text=text[:start]+text[end:]
                line='        if(QWEN35_4B.id.equals(id))return QWEN35_4B;\n'
                self.assertEqual(text.count(line),1);text=text.replace(line,'',1)
            elif relative.endswith('.h'):
                text,count=re.subn(r',\n    \{"qwen35-4b-q4_0",[^\n]+\}\n};','\n};',text)
                self.assertEqual(count,1)
            else:
                text,count=re.subn(r'    "qwen35-4b-q4_0": \{[^\n]+\n        [^\n]+\},\n','',text)
                self.assertEqual(count,1)
            self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),digest,relative)

    def test_unknown_and_old_parallel_alias_are_rejected(self):
        for name in ('qwen35','Qwen3.5-4B','../'+EXPECTED['file'],ID+' ','lfm25-8b-a1b-q4_0',None,8):
            with self.subTest(name=name),self.assertRaises(ValueError):profile(name)

    def test_default_llama_and_existing_lfm_are_preserved(self):
        self.assertEqual(DEFAULT_PROFILE,'lfm3-1.7b-qad-q4_0')
        self.assertEqual(LLAMA_COMMIT,'19cce6919992fdffd92e0ac152caaf1e2b8f254e')
        self.assertEqual(profile(),PROFILES[DEFAULT_PROFILE])
        self.assertEqual(profile('lfm2.5-8b-a1b-q4_0')['sha256'],'48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715')

if __name__=='__main__':unittest.main()
