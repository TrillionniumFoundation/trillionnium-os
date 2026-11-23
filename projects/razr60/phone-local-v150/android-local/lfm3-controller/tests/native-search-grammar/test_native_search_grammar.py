#!/usr/bin/env python3
"""Recognize actual Java-produced native-search GBNF. No phone or model engine."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
sys.dont_write_bytecode=True

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures",required=True,type=Path)
    parser.add_argument("--recognizer",required=True,type=Path)
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args()
    fixtures=args.fixtures.resolve();recognizer_path=args.recognizer.resolve();out=args.out.resolve()
    out.mkdir(parents=True,exist_ok=False)
    paths=[fixtures/name for name in ("JAVA-RESULT.json","native-search.gbnf","native-search-compact.gbnf","legacy.gbnf")]
    paths += [recognizer_path,Path(__file__).resolve()]
    def inputs():
        rows=[]
        for p in paths:
            if p.is_symlink() or not p.is_file():
                raise RuntimeError("actual regular fixture/recognizer file required: "+str(p))
            raw=p.read_bytes();rows.append({"path":str(p),"bytes":len(raw),"sha256":sha(raw)})
        return rows
    before=inputs()
    report={"schema":"hepta.native-search-gbnf-host.v1","scope":"host_only","all_pass":False,
            "phone_tested":False,"native_grammar_engine_tested":False,"model_inference_tested":False,
            "started_host_wall_ms":int(time.time()*1000),"inputs_before":before,"checks":[]}
    try:
        meta=json.loads((fixtures/"JAVA-RESULT.json").read_text())
        if not(meta["all_pass"] is True and meta["actual_offer_factory_called"] is True
               and meta["offer_created_by_this_helper"] is False and meta["protocol_schema"]=="hepta.native-search-intent.v1"):
            raise RuntimeError("actual successful Offer-to-grammar fixture required")
        grammar={}
        for name,file,key in (("normal","native-search.gbnf","normal_sha256"),
                              ("compact","native-search-compact.gbnf","compact_sha256"),
                              ("legacy","legacy.gbnf","legacy_sha256")):
            raw=(fixtures/file).read_bytes()
            if sha(raw)!=meta[key]:
                raise RuntimeError("actual emitted grammar hash differs: "+name)
            grammar[name]=raw.decode("utf-8","strict")
        spec=importlib.util.spec_from_file_location("actual_native_search_independent_gbnf",recognizer_path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        recognizers={k:module.Recognizer(v) for k,v in grammar.items()}
        obs,pkg,role=meta["observation_id"],meta["package"],meta["role_id"]
        if pkg!="com.xiaomi.shop":
            raise RuntimeError("fixture is not the explicit Xiaomi planning offer")
        def raw(reason="打开当前搜索输入框",**overrides):
            e={"reason":reason,"action":"native.open_search","observation_id":obs,"package":pkg,"role_id":role}
            e.update(overrides)
            return json.dumps(e,ensure_ascii=False,separators=(",",":"))
        def check(name,text,expected,kind="normal"):
            if any(r["name"]==name for r in report["checks"]):
                raise RuntimeError("duplicate meaningful vector name")
            actual=recognizers[kind].accepts(text)
            report["checks"].append({"name":name,"grammar":kind,"expected":expected,"actual":actual,
                                     "sample_utf8_bytes":len(text.encode("utf-8"))})
            if actual!=expected:
                raise AssertionError(name+": emitted grammar accepted="+str(actual)+", expected="+str(expected))
        good=raw()
        for name,value in (("one_ascii","x"),("96_ascii","x"*96),("96_astral","😀"*96),("96_han","搜"*96),
                           ("escaped_json_chars",'引号"反斜线\\换行\n制表\t回车\r'),
                           ("reason_does_not_select_another_role","点击旧 n16 或另一个 App 不改变固定 role_id")):
            check("reason_"+name,raw(value),True)
        for name,value in (("empty",""),("97_ascii","x"*97),("97_astral","😀"*97),
                           ("null",None),("boolean",True),("number",1),("array",[]),("object",{})):
            check("reason_reject_"+name,raw(value),False)
        for field in ("reason","action","observation_id","package","role_id"):
            e=json.loads(good);del e[field]
            check("missing_"+field,json.dumps(e,ensure_ascii=False,separators=(",",":")),False)
            value=json.dumps(json.loads(good)[field],ensure_ascii=False,separators=(",",":"))
            check("duplicate_"+field,good[:-1]+","+json.dumps(field)+":"+value+"}",False)
            if field!="reason":
                for type_name,v in (("null",None),("bool",False),("number",12),("array",[]),("object",{})):
                    check("non_string_"+field+"_"+type_name,raw(**{field:v}),False)
        for action in ("click","type","submit","scroll","back","home","wait","done","open","find_app",
                       "notes.create","web.search","native.open_search.extra"):
            check("legacy_or_unknown_action_"+action,raw(action=action),False)
        for field,value in (("text","AX3000T"),("query","AX3000T"),("node_id","n16"),("node_label","搜索"),
                            ("x",50),("y",100),("direction","down"),("duration_ms",100),
                            ("status","success"),("summary","完成"),("app_label","小米商城"),
                            ("shell","id"),("schema","hepta.observed-action-gbnf.v3-label-first")):
            check("forbidden_extra_"+field,raw(**{field:value}),False)
        for field,values in (("observation_id",("0"*32 if obs!="0"*32 else "1"*32,"missing","")),
                             ("package",("ctrip.android.view","com.example.other","android")),
                             ("role_id",("0"*64 if role!="0"*64 else "1"*64,"n16",role.upper(),""))):
            for i,value in enumerate(values):
                check("bound_"+field+"_"+str(i),raw(**{field:value}),False)
        check("role_embedded_grammar_syntax",raw(role_id=role+'" | root'),False)
        check("array_root","["+good+"]",False)
        check("fenced_output",chr(96)*3+"json\n"+good+"\n"+chr(96)*3,False)
        check("second_json",good+good,False)
        check("trailing_prose",good+"\n完成",False)
        check("trailing_null",good+"\x00",False)
        check("json_comment",good+"/* comment */",False)
        e=json.loads(good);e={k:e[k] for k in ("action","reason","observation_id","package","role_id")}
        check("format_subset_order_is_fixed",json.dumps(e,ensure_ascii=False,separators=(",",":")),False)
        check("raw_control_in_reason",raw("x").replace('"x"','"a\nb"'),False)
        check("escaped_lone_surrogate",raw("x").replace('"x"','"\\uD800"'),False)
        check("escaped_control_outside_generated_subset",raw("x").replace('"x"','"\\u0000"'),False)
        check("normal_outer_whitespace_8"," "*8+good+"\t"*8,True)
        check("normal_outer_whitespace_9"," "*9+good,False)
        check("normal_pretty_whitespace",json.dumps(json.loads(good),ensure_ascii=False,indent=2),True)
        for name,value in (("compact_valid","搜"*24),("compact_astral","😀"*24),("compact_one","x")):
            check(name,raw(value),True,"compact")
        check("compact_reason_25",raw("搜"*25),False,"compact")
        check("compact_no_outer_ws"," "+raw("x"),False,"compact")
        check("compact_no_separator_ws",raw("x").replace('":','": ',1),False,"compact")
        check("compact_reject_legacy_action",raw("x",action="click"),False,"compact")
        check("compact_reject_extra_query",raw("x",query="AX3000T"),False,"compact")
        check("compact_reject_changed_role",raw("x",role_id="0"*64 if role!="0"*64 else "1"*64),False,"compact")
        legacy_click=json.dumps({"reason":"legacy click","action":"click","observation_id":obs,"package":pkg,
                                 "node_label":"","node_id":"n1"},ensure_ascii=False,separators=(",",":"))
        legacy_done=json.dumps({"reason":"legacy completion","action":"done","observation_id":obs,"package":pkg,
                                "status":"partial","summary":"host fixture"},ensure_ascii=False,separators=(",",":"))
        check("legacy_click_positive_control",legacy_click,True,"legacy")
        check("legacy_done_positive_control",legacy_done,True,"legacy")
        check("legacy_grammar_rejects_native_intent",good,False,"legacy")
        check("native_grammar_rejects_legacy_click",legacy_click,False)
        check("native_grammar_rejects_legacy_done",legacy_done,False)
        report["java_fixture"]={"cases":meta["cases"],"assertions":meta["assertions"],"case_names":meta["case_names"]}
        report["inputs_after"]=inputs()
        if before!=report["inputs_after"]:
            raise RuntimeError("fixture/tool changed during independent recognition")
        report["input_bytes_unchanged"]=True
        report["vectors"]=len(report["checks"]);report["all_pass"]=True
    except Exception as e:
        report["error"]=type(e).__name__+": "+str(e)
    report["finished_host_wall_ms"]=int(time.time()*1000)
    with (out/"RESULT.json").open("x") as f:
        json.dump(report,f,ensure_ascii=False,indent=2);f.write("\n")
    print(json.dumps({"all_pass":report["all_pass"],"vectors":len(report["checks"]),
                      "error":report.get("error"),"result":str(out/"RESULT.json")},ensure_ascii=False))
    return 0 if report["all_pass"] else 1

if __name__=="__main__":
    raise SystemExit(main())
