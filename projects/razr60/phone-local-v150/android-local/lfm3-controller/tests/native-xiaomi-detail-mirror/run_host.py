#!/usr/bin/env python3
"""Compile the full current parser/capture classes, replay the closed detail layout,
and reject structural counterfactuals. Private original inputs are read only.
This gate never runs Android, an App, a model, dispatch, installation, or cleanup."""
from pathlib import Path
import argparse,hashlib,json,os,re,runpy,stat,subprocess,time,traceback
SCHEMA="hepta.native-xiaomi-detail-mirror-host-gate.v1"
PRODUCTION_FILES=['src/org/trillionnium/hepta/local/NativeAppGoal.java', 'src/org/trillionnium/hepta/local/NativeAppEvidence.java', 'src/org/trillionnium/hepta/background/ProfileIdentity.java', 'src/org/trillionnium/hepta/background/ProfileTarget.java', 'src/org/trillionnium/hepta/background/WindowOwnership.java', 'src/org/trillionnium/hepta/local/ObservedChildText.java', 'src/org/trillionnium/hepta/local/ObservedTargetLabels.java', 'src/org/trillionnium/hepta/local/ObservationCaptureEvidence.java', 'src/org/trillionnium/hepta/local/NativeCtripFormObservation.java', 'src/org/trillionnium/hepta/local/NativeActionSnapshotCheck.java', 'src/org/trillionnium/hepta/local/ObservedScrollActions.java', 'src/org/trillionnium/hepta/local/ObservedImeEnter.java', 'src/org/trillionnium/hepta/local/NativeXiaomiSearchInputObservation.java', 'src/org/trillionnium/hepta/local/NativeXiaomiProductPage.java']
EXPECTED_CASES=['benefits_outside_group', 'capture_remains_deeply_immutable_and_same_clock', 'different_complete_window_set', 'different_parent_child_comparison', 'different_parent_child_primary', 'different_product_feature_group', 'editable_price', 'equal_prices_at_unrelated_sibling', 'extra_exact_model', 'extra_price_child_slot', 'extra_scroll_direct_child_claim', 'first_census_incomplete', 'first_second_literal_difference', 'focused_price', 'footer_duplicate_title', 'footer_outside_frame', 'footer_wrong_child_count', 'government_subsidy_role_changed', 'hidden_address_and_sku_never_supply_quote', 'hidden_competing_currency_text', 'hidden_competing_price_description', 'hidden_equal_price_description', 'hidden_exact_model_outside_selected_role', 'hidden_other_model', 'ime_unknown', 'ime_visible', 'intervening_gap_has_hidden_child', 'intervening_other_product_card', 'merged_1590_rich_text_is_not_the_price', 'mirror_clickable', 'mirror_hidden', 'mirror_outside_parent', 'mirror_scrollable', 'mirror_wrong_class', 'missing_hidden_selected_heading_before_use', 'missing_price_leaf', 'missing_subsidy_child', 'missing_text_budget_counter', 'omitted_child_slot_counter', 'ordinary_receipt_cannot_claim_history', 'paired_price_values_are_not_hardcoded', 'parent_child_two_facts_not_string_deduplication', 'pending_nodes_counter', 'pixel_frame_without_sealed_census_refused', 'price_hidden', 'price_outside_product_scroll', 'private_original_receipt_and_after_exact_replay', 'public_complete_104_node_60_projection_detail', 'raw_foreign_package_hidden', 'raw_foreign_window_hidden', 'raw_full_reference_mismatch', 'raw_missing_price_reference', 'retained_projection_membership_missing', 'retained_projection_text_mismatch', 'rich_outside_mirror', 'rich_text_changed_renderer', 'rich_text_conflicting_price', 'root_missing_slot', 'scroll_not_actual_scrollview', 'scroll_not_scrollable', 'second_census_truncated', 'selected_price', 'selected_role_visible_is_not_exception', 'selected_sku_other_model', 'subsidy_changed_to_plain_price', 'subsidy_overlaps_rich_text', 'third_competing_price_description', 'third_equal_price_description', 'title_above_price', 'title_clickable', 'title_from_another_product', 'title_moved_to_other_group', 'title_outside_product_scroll', 'title_wrong_parent_class', 'underreported_mirror_children', 'unknown_boundary_event', 'unknown_child_count', 'unknown_click_capability', 'unrecognized_price_description', 'visible_alternate_yuan_price', 'visible_competing_currency_text', 'visible_conditions_preserved_without_deduction', 'wrong_root_class']
EXPECTED_BASELINE=["baseline_private_actual_refusal","baseline_rejects_recorded_mirrored_layout"]
PARSER="src/org/trillionnium/hepta/local/NativeXiaomiProductPage.java"
TEST="tests/native-xiaomi-detail-mirror/DetailMirrorHostTest.java"
FIXTURE="tests/native-xiaomi-detail-mirror/detail-shape.json"
HELPER="tests/native-xiaomi-detail-mirror/protected_detail_mirror.py"
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
def need(v,why):
    if not v:raise RuntimeError(why)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,ensure_ascii=False,indent=2,sort_keys=True)+"\n").encode()
def stable(p):
    a=p.lstat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,"regular single-link input: "+str(p))
    b=p.read_bytes();z=p.lstat()
    need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns),"input changed: "+str(p))
    return b,{"path":str(p),"bytes":len(b),"sha256":sha(b),"mode":stat.S_IMODE(a.st_mode)}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home","json-jar"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--actual-task",type=Path)
    a=p.parse_args()
    need(all(q.is_absolute() for q in (a.source,a.output,a.java_home,a.json_jar)),"absolute host paths")
    need(a.source.is_dir() and not a.output.exists() and a.source not in a.output.parents,"fresh external output")
    tracked={}
    def read(path):
        raw,pin=stable(path);tracked[str(path)]=pin;return raw
    own=Path(__file__).resolve();read(own)
    for rel in PRODUCTION_FILES+[TEST,FIXTURE,HELPER,"tests/native-xiaomi-product/NativeXiaomiProductPageHostTest.java","tests/native-app-fixtures/NativeXmlFixture.java"]:
        read(a.source/rel)
    original_detail=runpy.run_path(str(a.source/HELPER))["predecessor"]
    semantic_path=a.source/"tests/native-xiaomi-detail-semantics/protected_price_semantics.py"
    read(semantic_path);semantic=runpy.run_path(str(semantic_path))
    def original(raw):
        if isinstance(raw,bytes) and sha(raw)==semantic["CURRENT_SHA"]:
            raw=semantic["predecessor"](raw)
        return original_detail(raw)
    raw=read(a.source/PARSER);before=original(raw)
    inverse_cases=[]
    for label,value,accept in (("actual_current",raw,True),("complete_parent",before,True),("current_one_byte",raw+b" ",False),("parent_one_byte",before+b" ",False),("unknown",b"unknown",False)):
        try:
            v=original(value);need(accept and v==before,"inverse did not reproduce full parent: "+label)
        except ValueError:
            need(not accept,"valid inverse refused: "+label)
        inverse_cases.append({"name":label,"passed":True})
    fixture=json.loads(read(a.source/FIXTURE))
    need(fixture["not_qualification_original"] is True and fixture["identity_and_signatures_synthetic"] is True
         and fixture["source_shape_nodes"]==104 and fixture["source_shape_retained"]==60,"explicit public fixture scope")
    need({x["path"] for x in fixture["redactions"]}=={"0/0/18/1","0/0/18/2","0/0/20/0","0/0/20/1"},"complete public privacy projection")
    provenance_path=a.source/"tests/native-xiaomi-product/fixtures/PROVENANCE.json"
    provenance=json.loads(read(provenance_path))
    for row in provenance["files"]:
        value=read(a.source/row["fixture_path"])
        need(len(value)==row["bytes"] and sha(value)==row["sha256"],"unchanged legacy fixture")
    need(sha(read(a.json_jar))==JSON_SHA,"actual org.json dependency")
    read(a.java_home/"bin/java");read(a.java_home/"bin/javac")
    actual_inputs=[]
    if a.actual_task:
        need(a.actual_task.is_absolute() and a.source not in a.actual_task.parents,"external original task")
        owner=json.loads(read(a.actual_task/"owner.json"));need(isinstance(owner.get("instruction"),str),"original owner")
        actual_inputs.append(tracked[str(a.actual_task/"owner.json")])
        for ordinal in (4,5):
            page_path=a.actual_task/("native-app-page-%04d.json"%ordinal);page=json.loads(read(page_path));frame=page["frame"]
            obs=frame["observation_id"];need(re.fullmatch("[0-9a-f]{32}",obs) is not None,"exact original observation")
            receipt_name=obs+"-native-ax.json";need(frame["capture"]["receipt_file"]==receipt_name,"ordinary actual receipt filename")
            receipt=read(a.actual_task/receipt_name)
            observed=read(a.actual_task/("native-app-frame-"+obs+".json"))
            need(sha(receipt)==frame["capture"]["receipt_sha256"] and sha(observed)==frame["phone_observation_record_sha256"],"whole original capture/after binding")
            original_receipt=json.loads(receipt)
            need(original_receipt["first"]["nodes"]==original_receipt["second"]["nodes"]
                 and len(original_receipt["first"]["nodes"])==104 and len(json.loads(observed)["nodes"])==60,"original complete pair/projection")
            actual_inputs.extend(tracked[str(q)] for q in (page_path,a.actual_task/receipt_name,a.actual_task/("native-app-frame-"+obs+".json")))
    a.output.mkdir(mode=0o700)
    result={"schema":SCHEMA,"all_pass":False,"steps":[],"expected_case_names":EXPECTED_CASES,
            "inverse_cases":inverse_cases,"actual_inputs":actual_inputs,"phone_operations":0,"android_runtime":False,
            "model_inference":False,"dispatch_executed":False,"business_completion_verified":False,"started_epoch":time.time()}
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(key,None)
    def command(name,argv):
        start=time.monotonic()
        r=subprocess.run([str(x) for x in argv],cwd=a.source,env=env,capture_output=True,timeout=120)
        for kind,data in (("stdout",r.stdout),("stderr",r.stderr)):(a.output/(name+"."+kind)).write_bytes(data)
        result["steps"].append({"name":name,"argv":[str(x) for x in argv],"exit_code":r.returncode,"seconds":time.monotonic()-start,
                               "stdout":stable(a.output/(name+".stdout"))[1],"stderr":stable(a.output/(name+".stderr"))[1]})
        if r.returncode:print(r.stdout.decode(errors="replace")[-3000:]);print(r.stderr.decode(errors="replace")[-5000:])
        need(r.returncode==0,"actual host command failed: "+name)
    try:
        for variant in ("current","baseline"):
            target=a.output/variant;target.mkdir();classes=target/"classes";classes.mkdir()
            sources=[a.source/rel for rel in PRODUCTION_FILES]
            if variant=="baseline":
                old=target/"NativeXiaomiProductPage.java";old.write_bytes(before)
                sources=[old if str(q)==str(a.source/PARSER) else q for q in sources]
            sources.extend(a.source/rel for rel in (TEST,"tests/native-xiaomi-product/NativeXiaomiProductPageHostTest.java","tests/native-app-fixtures/NativeXmlFixture.java"))
            command(variant+"-javac",[a.java_home/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-cp",a.json_jar,"-d",classes,*sources])
            args=[a.java_home/"bin/java","-cp",str(classes)+os.pathsep+str(a.json_jar),"org.trillionnium.hepta.local.DetailMirrorHostTest",a.source/FIXTURE,target]
            if variant=="baseline":args.append("--baseline")
            if a.actual_task:args.append(a.actual_task)
            command(variant+"-detail-cases",args)
            cases=json.loads((target/"CASES.json").read_bytes())
            expected=EXPECTED_CASES if variant=="current" else EXPECTED_BASELINE
            if not a.actual_task:expected=[x for x in expected if "private_" not in x]
            need(cases["all_pass"] is True and cases["cases"]==len(expected)
                 and len(cases["case_names"])==len(set(cases["case_names"]))
                 and sorted(cases["case_names"])==sorted(expected),"complete exact detail case set")
            result[variant+"_cases"]=cases;result[variant+"_report"]=stable(target/"CASES.json")[1]
            if a.actual_task:
                result[variant+"_actual_replays"]=[stable(target/("ACTUAL-REPLAY-%d.json"%i))[1] for i in (4,5)]
            if variant=="current":
                command("legacy-parser",[a.java_home/"bin/java","-cp",str(classes)+os.pathsep+str(a.json_jar),"org.trillionnium.hepta.local.NativeXiaomiProductPageHostTest",provenance_path.parent,target/"LEGACY-CASES.json"])
                legacy=json.loads((target/"LEGACY-CASES.json").read_bytes())
                need(legacy["all_pass"] is True and legacy["cases"]==75 and len(set(legacy["case_names"]))==75,"all original parser cases retained")
                result["legacy_cases"]=legacy;result["legacy_report"]=stable(target/"LEGACY-CASES.json")[1]
        result["all_pass"]=True
    except Exception as error:
        result["error"]=type(error).__name__+": "+str(error);(a.output/"ERROR.txt").write_text(traceback.format_exc())
    finally:
        result["inputs_before"]=list(tracked.values())
        result["inputs_after"]=[stable(Path(path))[1] for path in tracked]
        result["inputs_unchanged"]=result["inputs_before"]==result["inputs_after"]
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"];result["finished_epoch"]=time.time()
        (a.output/"RESULT.json").write_bytes(enc(result))
        for q in a.output.rglob("*"):
            if q.is_file():q.chmod(0o644)
        print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"current_cases":result.get("current_cases",{}).get("cases"),"baseline_cases":result.get("baseline_cases",{}).get("cases"),"legacy_cases":result.get("legacy_cases",{}).get("cases"),"result":stable(a.output/"RESULT.json")[1]},ensure_ascii=False))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
