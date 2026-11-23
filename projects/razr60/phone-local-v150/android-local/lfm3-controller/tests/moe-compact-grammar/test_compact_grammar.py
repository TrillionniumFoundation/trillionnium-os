"""Consume actual generated GBNF with the unchanged independent recognizer.
No JSON schema emulation, token-count prediction, model inference or phone success.
The completed archived prefix below is explicitly synthetic and only a negative
format regression. The original failed partial bytes remain a strict rejection.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

parser=argparse.ArgumentParser()
parser.add_argument("--source",type=Path,required=True)
parser.add_argument("--generated",type=Path,required=True)
parser.add_argument("--baseline",type=Path)
parser.add_argument("--raw",type=Path,required=True)
args,remaining=parser.parse_known_args()
sys.argv=[sys.argv[0],*remaining]
spec=importlib.util.spec_from_file_location("unchanged_gbnf_consumer",args.source/"tests/action-grammar/gbnf_recognizer.py")
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
Recognizer=module.Recognizer
OBS="725c93491dec409a9caa086b1448c86f"
PKG="com.motorola.stylus"
PARTIAL_SHA="56b791ee9a83b504619ef465f2ffbf21e53c108e32c332749e99a2f24e8a2ed1"

class CompactConsumerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report=json.loads((args.generated/"JAVA-RESULT.json").read_text())
        cls.body=cls.report["body"]
        cls.partial=args.raw.read_bytes()
        if len(cls.partial)!=565 or hashlib.sha256(cls.partial).hexdigest()!=PARTIAL_SHA:
            raise AssertionError("exact archived failed request raw required")
        cls.old={row["name"]:Recognizer((args.generated/(row["name"]+"-original.gbnf")).read_bytes()) for row in cls.report["grammars"]}
        cls.new={row["name"]:Recognizer((args.generated/(row["name"]+"-compact.gbnf")).read_bytes()) for row in cls.report["grammars"]}
    def raw(self,action="notes.create",reason="新建用户指定笔记",**extra):
        value=dict(reason=reason,action=action,observation_id=OBS)
        if action=="notes.create":
            value.update(app_label="Moto 笔记",package=PKG,text=self.body)
        else:value.update(package=PKG)
        value.update(extra)
        return json.dumps(value,ensure_ascii=False,separators=(",",":"))
    def test_01_actual_partial_is_rejected_on_both_sides(self):
        self.assertFalse(self.old["v6"].accepts(self.partial))
        self.assertFalse(self.new["v6"].accepts(self.partial))
        with self.assertRaises(json.JSONDecodeError):json.loads(self.partial)
    def test_02_synthetic_completion_exposes_only_old_waste_shape(self):
        synthetic=self.partial.decode()+json.dumps(self.body,ensure_ascii=False)[1:]+"}"
        data=json.loads(synthetic)
        self.assertEqual(len(data["reason"]),96)
        self.assertEqual(data["text"],self.body)
        self.assertTrue(self.old["v6"].accepts(synthetic))
        self.assertFalse(self.new["v6"].accepts(synthetic))
        self.assertFalse(self.report["synthetic_complete_examples_are_phone_results"])
    def test_03_compact_complete_fixed_tool_and_owner_body(self):
        sample=self.raw()
        self.assertTrue(self.old["v6"].accepts(sample))
        self.assertTrue(self.new["v6"].accepts(sample))
        self.assertEqual(json.loads(sample)["text"],self.body)
        for payload in [self.body[:-1],self.body+"x",self.body.replace(" ",""),"new body","",None]:
            with self.subTest(payload=payload):self.assertFalse(self.new["v6"].accepts(self.raw(text=payload)))
    def test_04_reason_unicode_character_bound(self):
        for reason in ["x","字"*24,"😀"*24,'引号"与斜线\\',"a b\nc\t"]:
            with self.subTest(reason=reason):
                self.assertTrue(self.new["v6"].accepts(self.raw(reason=reason)))
        for reason in ["","字"*25,"😀"*25,"x"*96]:
            with self.subTest(reason=reason):
                self.assertFalse(self.new["v6"].accepts(self.raw(reason=reason)))
                if reason:self.assertTrue(self.old["v6"].accepts(self.raw(reason=reason)))
    def test_05_structural_whitespace_is_exactly_empty(self):
        plain=self.raw()
        variants=[" "+plain,plain+"\n","{\n"+plain[1:],plain.replace('":','" :',1),
                  plain.replace('":','": ',1),plain.replace('","action"','",\t"action"',1),
                  plain[:-1]+"\r}"]
        for sample in variants:
            with self.subTest(sample=sample):
                self.assertTrue(self.old["v6"].accepts(sample))
                self.assertFalse(self.new["v6"].accepts(sample))
    def test_06_strings_retain_whitespace_escapes_and_rule_lookalikes(self):
        payload=self.report["synthetic_whitespace_payload"]
        sample=self.raw(text=payload)
        self.assertIn('reason-string ::= " json-char{1,96} "',payload)
        self.assertIn("ws ::= [ \\t\\n\\r]{0,8}",payload)
        self.assertTrue(self.new["v6-payload"].accepts(sample))
        self.assertTrue(self.old["v6-payload"].accepts(sample))
        for replacement in [payload.replace("  "," "),payload.replace("\n",""),payload.replace("{1,96}","{1,24}"),payload+" "]:
            self.assertFalse(self.new["v6-payload"].accepts(self.raw(text=replacement)))
    def test_07_observation_app_pair_and_protocol_stay_closed(self):
        sample=self.raw()
        for changed in [sample.replace(OBS,"0"*32),sample.replace(PKG,"org.example.other"),
                        sample.replace("Moto 笔记","未知笔记"),sample[:-1]+',"node_id":"n1"}',
                        sample[:-1]+',"shell":"id"}',sample[:-1]+',"reason":"duplicate"}',sample+sample]:
            with self.subTest(changed=changed):
                self.assertFalse(self.old["v6"].accepts(changed))
                self.assertFalse(self.new["v6"].accepts(changed))
    def test_08_owner_task_mask_and_background_home_never_expand(self):
        self.assertFalse(self.old["restricted"].accepts(self.raw()))
        self.assertFalse(self.new["restricted"].accepts(self.raw()))
        for grammar in [self.old["restricted"],self.new["restricted"]]:
            self.assertFalse(grammar.accepts(self.raw("home")))
            self.assertFalse(grammar.accepts(self.raw("click",node_label="保存",node_id="n1")))
            self.assertTrue(grammar.accepts(self.raw("wait",duration_ms=100)))
    def test_09_current_node_label_id_and_action_capabilities(self):
        click=self.raw("click",node_label="保存",node_id="n1")
        edit=self.raw("type",node_label="查询",node_id="n2",text='保留  空格\n"引号"\\😀')
        for grammar in [self.old["v3"],self.new["v3"]]:
            self.assertTrue(grammar.accepts(click));self.assertTrue(grammar.accepts(edit))
            self.assertFalse(grammar.accepts(click.replace('"n1"','"n2"')))
            self.assertFalse(grammar.accepts(click.replace("保存","其他")))
            self.assertFalse(grammar.accepts(edit.replace('"n2"','"n1"')))
            self.assertFalse(grammar.accepts(self.raw("submit",node_label="查询",node_id="n2")))
    def test_10_completion_status_does_not_gain_authority(self):
        for grammar in [self.old["v6"],self.new["v6"]]:
            self.assertTrue(grammar.accepts(self.raw("done",status="partial",summary="缺少保存证据")))
            self.assertFalse(grammar.accepts(self.raw("done",status="success",summary="没有证据也宣称成功")))
            self.assertFalse(grammar.accepts(self.raw("done",status="partial")))
        for grammar in [self.old["wait-only"],self.new["wait-only"]]:
            self.assertTrue(grammar.accepts(self.raw("wait",duration_ms=100)))
            self.assertFalse(grammar.accepts(self.raw("done",status="partial",summary="无终态分支")))
    def test_11_schema_is_preserved_and_only_format_rules_change(self):
        for row in self.report["grammars"]:
            name=row["name"];before=(args.generated/(name+"-original.gbnf")).read_text().splitlines()
            after=(args.generated/(name+"-compact.gbnf")).read_text().splitlines()
            self.assertEqual(len(before),len(after))
            changed=[(a,b) for a,b in zip(before,after) if a!=b]
            self.assertEqual(len(changed),2)
            self.assertTrue(changed[0][0].startswith("reason-string ::= "))
            self.assertTrue(changed[1][0].startswith("ws ::= "))
    def test_12_actual_full_prompt_selected_grammar_is_consumed(self):
        for row in self.report["profile_rows"]:
            if row["profile"]!="lfm2.5-8b-a1b-q4_0":continue
            path=args.generated/(row["profile"]+"-"+row["compute"]+".gbnf")
            grammar=Recognizer(path.read_bytes())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),row["grammar_sha256"])
            self.assertTrue(grammar.accepts(self.raw()))
            self.assertFalse(grammar.accepts(self.partial))
            self.assertFalse(grammar.accepts(self.raw(reason="字"*25)))
            self.assertFalse(grammar.accepts(" "+self.raw()))
            self.assertEqual(row["generation_tokens"],256)
    def test_13_frozen_original_producer_control(self):
        if args.baseline is None:
            self.skipTest("optional independently compiled frozen source is not embedded in repository")
        previous=json.loads((args.baseline/"JAVA-RESULT.json").read_text())
        self.assertEqual(self.report["profiles"],previous["profiles"])
        for row in self.report["grammars"]:
            filename=row["name"]+"-original.gbnf"
            self.assertEqual((args.generated/filename).read_bytes(),(args.baseline/filename).read_bytes())
        for row in self.report["profile_rows"]:
            stem=row["profile"]+"-"+row["compute"]
            self.assertEqual((args.generated/(stem+".prompt.txt")).read_bytes(),(args.baseline/(stem+".prompt.txt")).read_bytes())
            if row["profile"]=="lfm2.5-8b-a1b-q4_0":
                for suffix in [".system.txt",".native-system.txt"]:
                    self.assertTrue((args.generated/(stem+suffix)).read_bytes().startswith((args.baseline/(stem+suffix)).read_bytes()))
                continue
            for suffix in [".gbnf",".system.txt",".native-system.txt"]:
                self.assertEqual((args.generated/(stem+suffix)).read_bytes(),(args.baseline/(stem+suffix)).read_bytes())
    def test_14_fixture_never_claims_business_or_model_success(self):
        self.assertFalse(self.report["phone_operations"])
        self.assertFalse(self.report["model_inference"])
        self.assertFalse(self.report["baseline_export_only"])
        self.assertEqual(len(self.report["cases"]),len(set(self.report["cases"])))
        self.assertGreaterEqual(len(self.report["cases"]),24)

if __name__=="__main__":unittest.main(verbosity=2)
