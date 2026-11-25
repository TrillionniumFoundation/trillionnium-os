#!/usr/bin/env python3
"""Compile complete production predicates and replay the recorded full Ctrip pair."""
import argparse,hashlib,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
PKG=Path("src/org/trillionnium/hepta/local")
EXPECTED_CASES=['recorded_pair_still_rejected_by_original_strict_entry', 'recorded_pair_qualified_only_for_two_direct_native_targets', 'equal_pair_keeps_original_strict_first_qualification', 'recorded_year_action_comparator_accepts_purpose_geometry', 'recorded_query_comparator_with_explicit_host_history_accepts', 'trip_selected_changed', 'return_trip_selected_changed', 'multi_trip_selected_changed', 'cabin_selected_changed', 'date_changed', 'departure_city_changed', 'arrival_city_changed', 'adult_count_changed', 'child_count_changed', 'infant_count_changed', 'query_label_changed', 'header_semantic_text_changed', 'header_click_capability_changed', 'header_action_click_changed', 'header_selection_changed', 'header_foreign_package', 'target_reference_changed', 'header_unknown_scroll_metadata', 'header_root_extended_into_nontrip_fields', 'header_descendant_after_overflow_into_date', 'header_descendant_before_overflow_into_date', 'hidden_positive_descendant_cannot_escape_region', 'same_target_shifted_geometry', 'duplicate_complete_node_path', 'missing_header_child_slot', 'foreign_display', 'foreign_window', 'reported_window_set_changed', 'profile_identity_changed', 'request_pair_clock_limit_unchanged', 'year_purpose_cannot_click_query', 'year_purpose_cannot_click_return_trip', 'generic_purpose_cannot_use_certificate', 'captured_constraint_rejects_later_changed_census_as_original', 'captured_constraint_rejects_other_observation', 'captured_constraint_rejects_other_owner', 'action_original_eight_second_deadline_unchanged', 'query_needs_separate_real_history_binding', 'old_form_constraint_is_not_a_calendar_source']
def load(path):
    spec=importlib.util.spec_from_file_location("ctrip_purpose_host_helpers",path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def main():
    parser=argparse.ArgumentParser()
    for name in ("source","output","java-home","json-jar"):
        parser.add_argument("--"+name,required=True,type=Path)
    args=parser.parse_args();source=args.source.resolve();out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    helpers=source/"tests/observation-diagnostics/run_host.py";h=load(helpers)
    java=args.java_home.resolve()/"bin/java";javac=args.java_home.resolve()/"bin/javac";jar=args.json_jar.resolve()
    if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":
        raise RuntimeError("JSON tool input pin")
    sources=[source/PKG/name for name in ("ObservationCaptureEvidence.java","NativeCtripFormObservation.java",
        "NativeXiaomiSearchInputObservation.java","NativeActionSnapshotCheck.java","ObservedChildText.java",
        "ObservedTargetLabels.java","ObservedScrollActions.java","ObservedImeEnter.java")]
    host=source/"tests/native-ctrip-purpose-geometry/CtripPurposeGeometryHost.java"
    fixture=source/"tests/native-ctrip-purpose-geometry/recorded-060c-pair.json"
    inputs=sources+[host,fixture,Path(__file__).resolve(),helpers]
    tools=[java,javac,java.parent.parent/"lib/modules",java.parent.parent/"lib/ct.sym",jar]
    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
    result={"schema":"hepta.ctrip-purpose-geometry-host-gate.v1","all_pass":False,"stages":[],
        "inputs_before":before,"tools_before":tool_before,"android_execution":False,"phone_operations":0,
        "model_executed":False,"business_completion_verified":False}
    try:
        classes=out/"classes";classes.mkdir()
        result["stages"].append(h.stage("compile",[str(javac),"--release","8","-encoding","UTF-8","-proc:none",
            "-Xlint:all","-Werror","-cp",str(jar),"-d",str(classes)]+list(map(str,sources+[host])),out))
        if result["stages"][-1]["exit_code"]!=0:raise RuntimeError("complete production compilation failed")
        proof=out/"RECORDED-PURPOSE-PROOF.json";case=out/"CASES.json"
        result["stages"].append(h.stage("cases",[str(java),"-cp",str(classes)+os.pathsep+str(jar),
            "org.trillionnium.hepta.local.CtripPurposeGeometryHost",str(fixture),str(proof),str(case)],out))
        if result["stages"][-1]["exit_code"]!=0:raise RuntimeError("purpose geometry cases failed")
        evidence=json.loads(case.read_text());names=[r["name"] for r in evidence["case_results"]]
        if evidence["all_pass"] is not True or names!=EXPECTED_CASES or evidence["cases"]!=44 or len(set(names))!=44:
            raise RuntimeError("case accounting failed")
        result.update(all_pass=True,cases=evidence,cases_file=h.meta(case),recorded_proof=h.meta(proof))
    except Exception as error:
        result["error"]={"type":type(error).__name__,"message":str(error)}
    finally:
        result["inputs_after"]=[h.meta(p) for p in inputs];result["tools_after"]=[h.meta(p) for p in tools]
        result["inputs_unchanged"]=result["inputs_before"]==result["inputs_after"]
        result["tools_unchanged"]=result["tools_before"]==result["tools_after"]
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"] and result["tools_unchanged"]
        h.save(out/"RESULT.json",result)
    print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"result":h.meta(out/"RESULT.json")}))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
