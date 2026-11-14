#!/usr/bin/env python3
"""Fresh actual NativeAppSession/Ctrip/TCG on original manual XML with explicit host boundaries."""
import argparse,hashlib,importlib.util,json,os,subprocess,time
from pathlib import Path
JSON_SHA256="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
EXPECTED_RESOURCE_NAMES=['actual_cold_home_subset_keeps_empty_label_and_exact_resource_target', 'resource_evidence_names_original_id_path_signature_and_no_inferred_label', 'ordinary_empty_text_policy_and_other_home_icons_remain_denied', 'exact_empty_pair_survives_actual_authorized_grammar', 'invented_visual_flight_label_is_rejected', 'stale_frame_cannot_reuse_empty_resource_pair', 'repeat_policy_removal_cannot_be_readded_by_resource_capability', 'wrong_native_phase_or_purpose_cannot_mint_resource_click', 'missing_neighbor_resource_refuses_home_identity', 'duplicate_flight_resource_refuses_ambiguous_identity', 'disabled_resource_refuses_click', 'overlapping_neighbor_refuses_grid_identity', 'changed_parent_path_refuses_grid_identity', 'wrong_widget_class_refuses_resource_identity', 'password_resource_refuses_click', 'selected_state_refuses_image_tile', 'incomplete_collection_cannot_authorize_resource_click', 'nonapplication_window_cannot_authorize_resource_click', 'changed_installed_app_is_rechecked_before_resource_action', 'model_action_must_still_supply_actual_dispatch_outcome']
RESOURCE_FIXTURE={'path': 'fixtures/ctrip-cold-home-grid.json', 'bytes': 10153, 'sha256': '8cae8ec8f3deb6e45f4c4778c6a6de9826aba383ffb7a572ea7ad9c08ac8eb58'}
EXTRA_SOURCES=["PromptActionDomain","NativeAppEvidence","NativeAppDomain","NativeAppSession","NativeActionSnapshotCheck","NativeAppObservation","NativeCtripFlightPage","NativeXiaomiProductPage"]
EXPECTED_NAMES=["actual_complete_flight_cards_keep_conditions_and_reject_promotional_or_clipped_cards", "actual_overlay_vetoes_visible_underlying_flight_cards", "actual_date16_uses_literal_month_day_not_todays_role_or_false_selected", "actual_empty_calendar_has_headers_but_never_day_targets", "owner_year_or_initial_form17_never_bypasses_actual_calendar_year_chain", "cached_goal_results_without_actual_task_query_never_complete", "actual_calendar_query_date_navigation_form_requery_final_chain", "terminal_exit_70_never_substitutes_normal0", "terminal_exit_124_never_substitutes_normal0", "terminal_exit_143_never_substitutes_normal0", "actual_query_after_year_read_does_not_imply_native_runtime_or_completion", "late_cancel_revokes_existing_native_success_candidate", "unknown_cleanup_revokes_native_success", "unreleased_virtual_display_revokes_native_success", "unrechecked_scope_revokes_native_success", "unrechecked_installed_app_revokes_native_success", "missing_parent_receipt_revokes_native_success", "foreign_worker_task_revokes_native_success", "malformed_worker_generation_revokes_native_success", "different_accepted_model_run_revokes_native_success", "different_accepted_model_step_revokes_native_success", "different_final_observation_revokes_native_success", "no_physical_parent_exit_revokes_native_success", "no_worker_started_revokes_native_success", "background_uuid_is_preserved_and_worker32_is_rejected", "foreign_frame_owner_is_rejected_before_query_progress", "equal_looking_replaced_target_hash_is_rejected", "different_background_generation_is_rejected", "incomplete_collection_cannot_grant_any_native_click", "replayed_old_observation_cannot_replace_current_native_frame", "installed_identity_changed_before_observation_is_rejected", "stale_undispatched_query_never_advances_query_proof", "rejected_dispatched_action_never_advances_query_proof", "pending_transition_has_its_actual_dispatch_relative_bound", "final_whole_tree_change_does_not_become_native_success", "final_overlay_revokes_existing_result_readiness", "unadmitted_native_click_cannot_escape_query_domain", "same_model_run_cannot_authorize_a_second_native_action", "quote_evidence_maps_are_deeply_immutable"]
EXPECTED_ADAPTER_NAMES=["actual_adapter_preserves_original_bounded_derived_product_card_label", "raw_description_and_price_are_not_replaced_by_derived_action_label", "empty_and_nonderived_card_cannot_grant_click", "bare_empty_node_keeps_empty_projection", "different_node_id_with_card_label_is_rejected", "substituted_full_title_instead_of_original_label_is_rejected", "different_observation_id_is_rejected", "different_package_is_rejected", "adapter_rejects_changed_background_generation", "adapter_rejects_equal_looking_replaced_selection_authority", "truncated_whole_collection_does_not_grant_bounded_label_click", "copied_parent_signature_geometry_and_selection_tuple_remain_exact"]
EXPECTED_IMAGE_MODAL_NAMES=['actual_saved_frame_classifies_shape_without_semantic_or_action_authority', 'actual_retained_identity_and_geometry_are_replayed', 'window_display_ids_and_scale_are_not_hardcoded', 'node_order_and_node_ids_are_not_position_selectors', 'wrong_immutable_owner_is_rejected', 'non_xiaomi_goal_is_rejected', 'foreign_node_package_is_unavailable', 'non_application_window_is_unavailable', 'unknown_window_metadata_is_unavailable', 'incomplete_collection_is_unavailable', 'truncated_collection_is_unavailable', 'fullscreen_or_screen_touching_bounds_are_not_inset', 'missing_or_extra_retained_node_rejects_modal', 'privacy_consent_login_text_and_description_never_match', 'derived_label_or_resource_id_rejects_modal', 'whitespace_is_observed_content_not_empty', 'native_child_paths_must_be_exact_observed_siblings', 'parent_class_must_be_same_frame_layout', 'missing_node_reference_is_rejected', 'other_widget_class_is_rejected', 'disabled_nonclickable_editable_password_or_scroll_node_is_rejected', 'selection_tuple_must_be_observed_and_all_false', 'top_image_must_match_actual_frame_edges', 'lower_image_must_be_square_and_centered', 'image_gap_must_be_positive_and_bounded', 'lower_image_must_match_frame_bottom', 'image_with_bounds_outside_window_is_not_usable', 'both_image_width_and_height_must_exceed_lower_image', 'unrelated_unknown_page_keeps_original_unrecognized_phase']
EXPECTED_XIAOMI_MODAL_SESSION_NAMES=['modal_session_grants_only_one_context_bound_back_not_image_click_or_result', 'modal_back_closes_only_on_fresh_supported_home_without_query_proof', 'modal_back_same_modal_after_dispatch_keeps_pending_and_zero_targets', 'modal_back_unknown_page_never_counts_as_dismissal', 'modal_back_search_input_is_not_the_required_home', 'modal_back_cached_result_cannot_create_query_proof', 'modal_back_cached_detail_cannot_create_price_completion', 'modal_back_original_fifteen_second_transition_deadline_is_preserved', 'modal_back_stale_undispatched_proposal_is_consumed_without_retry', 'modal_back_rejected_effect_invalidates_the_session', 'modal_back_requires_same_task_owner_generation_display', 'modal_back_incomplete_or_truncated_observation_has_no_navigation', 'modal_back_installed_identity_is_rechecked_before_model_action', 'modal_back_wrong_action_frame_or_package_is_rejected', 'modal_images_never_gain_click_or_done_success_authority', 'modal_back_retired_task_cannot_dispatch', 'modal_back_after_committed_product_query_is_not_admitted', 'modal_back_after_completed_home_return_cannot_be_repeated', 'modal_back_replayed_original_frame_cannot_prove_home_transition', 'modal_home_return_and_cleanup_alone_never_complete_price_goal', 'modal_home_query_card_detail_final_normal0_composition_remains_usable', 'modal_completed_price_chain_still_refuses_unknown_cleanup']
EXPECTED_CTRIP_CALENDAR_NAMES=['actual_foreground_xml_keeps_five_titles_as_four_month_facts', 'pair_evidence_is_deeply_immutable', 'actual_model_calendar_then_back_same_form_is_required_for_year', 'different_form_after_back_does_not_close_calendar_year', 'direct_calendar_without_model_date_action_cannot_prove_year', 'stale_undispatched_calendar_action_cannot_prove_year', 'actual_blank_background_frame_still_has_no_calendar_or_day', 'legacy_unique_calendar_and_original_roundtrip_still_pass', 'four_unique_headers_without_verified_pair_do_not_expand_year_gate', 'sticky_conflicting_year_is_rejected_even_when_all_labels_unique', 'sticky_conflicting_month_is_rejected', 'third_same_month_header_is_rejected', 'nonconsecutive_content_months_are_rejected', 'conflicting_content_year_is_rejected', 'invalid_month_literal_is_rejected', 'month_prefix_suffix_are_not_normalized', 'missing_actual_list_is_rejected', 'wrong_list_class_is_rejected', 'unscrollable_list_is_rejected', 'disabled_list_is_rejected', 'wrong_list_parent_is_rejected', 'sticky_wrong_sibling_branch_is_rejected', 'content_title_outside_same_list_is_rejected', 'content_wrong_row_depth_is_rejected', 'wrong_first_content_row_index_is_rejected', 'disabled_sticky_title_is_rejected', 'clickable_month_title_is_rejected', 'different_native_parent_class_is_rejected', 'nonempty_month_description_is_rejected', 'sticky_alignment_mismatch_is_rejected', 'content_not_clipped_at_list_top_is_rejected', 'content_overlapping_sticky_geometry_is_rejected', 'sticky_overlapping_next_month_is_rejected', 'content_geometry_not_ordered_is_rejected', 'foreign_same_resource_header_cannot_be_silently_omitted', 'offscreen_same_resource_header_cannot_be_silently_omitted', 'fifth_semantic_month_exceeds_verified_bound', 'truncated_collection_never_uses_sticky_pair']
def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,why):
    if not ok:raise RuntimeError(why)
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def write(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as stream:stream.write(raw)
def inventory(source):
    out={}
    for p in sorted(source.rglob("*")):
        require(not p.is_symlink(),"source symlink refused")
        if p.is_file() and "__pycache__" not in p.parts:
            raw=p.read_bytes();out[str(p.relative_to(source))]={"bytes":len(raw),"sha256":sha(raw),"mode":p.stat().st_mode&0o777}
    return out
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--source",required=True,type=Path);ap.add_argument("--output",required=True,type=Path)
    ap.add_argument("--java-home",required=True,type=Path);ap.add_argument("--json-jar",required=True,type=Path)
    args=ap.parse_args();source=args.source.resolve();out=args.output.resolve();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
    require(source.is_dir() and not out.exists() and source not in out.parents,"fresh output outside source required")
    require(jar.is_file() and jar.stat().st_size==78332 and sha(jar.read_bytes())==JSON_SHA256,"fixed org.json dependency differs")
    for name in ("java","javac"):require((jdk/"bin"/name).is_file(),"full existing JDK required")
    before=inventory(source);out.mkdir(parents=True,mode=0o700)
    tools={str(p):sha(p.read_bytes()) for p in (jdk/"bin/java",jdk/"bin/javac",jdk/"lib/modules",jar)}
    env=dict(os.environ);env["PATH"]=str(jdk/"bin")+":"+env.get("PATH","");env["PYTHONDONTWRITEBYTECODE"]="1"
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(key,None)
    report={"schema":"hepta.native-app-provider-host-gate.v1","all_pass":False,"inputs_before":before,"tools_before":tools,"stages":[],
        "phone_operations":0,"android_runtime":False,"model_executed":False,"business_verified":False,
        "boundary":"Actual full pure production classes; original manual XML; Android APIs/NodeRef/Frame/installed/task/worker and model callbacks remain explicit host fixtures."}
    def run(name,argv,timeout=120):
        t=time.monotonic();r=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=timeout)
        write(out/(name+".stdout"),r.stdout);write(out/(name+".stderr"),r.stderr)
        report["stages"].append({"name":name,"argv":list(map(str,argv)),"exit_code":r.returncode,"seconds":time.monotonic()-t,
            "stdout_sha256":sha(r.stdout),"stderr_sha256":sha(r.stderr)})
        if r.returncode:print(r.stdout.decode("utf-8","replace")[-12000:]);print(r.stderr.decode("utf-8","replace")[-16000:])
        require(r.returncode==0,"actual stage failed: "+name)
    try:
        own=source/"tests/native-app-provider";fixture_manifest=own/"FIXTURES.json";fixtures=json.loads(fixture_manifest.read_text())
        cold=own/RESOURCE_FIXTURE["path"];require(cold.stat().st_size==RESOURCE_FIXTURE["bytes"] and sha(cold.read_bytes())==RESOURCE_FIXTURE["sha256"],"six actual native grid records changed")
        expected=set()
        for row in fixtures["files"]:
            leaf=own/row["path"];require(leaf.is_file() and len(leaf.read_bytes())==row["bytes"] and sha(leaf.read_bytes())==row["sha256"],"original XML differs: "+row["path"])
            require(row["path"] not in expected and row["original_root_setup"] is True and row["model_executed"] is False,"fixture provenance differs");expected.add(row["path"])
        require(len(expected)==12,"eleven actual Ctrip and one actual Xiaomi fixture records required")
        modal_test=source/"tests/native-xiaomi-image-modal"
        modal_fixture=load(modal_test/"run_host.py","native_image_modal_original_fixture").fixture(modal_test)
        calendar_test=source/"tests/native-ctrip-calendar"
        calendar_provenance=calendar_test/"fixtures/PROVENANCE.json";calendar_originals=json.loads(calendar_provenance.read_text())
        require(calendar_originals.get("bound_background_frame_actual") is False and calendar_originals.get("fixtures_new_android_task_performed") is False and calendar_originals.get("price_or_day_coordinates_authorized") is False,"calendar fixture boundary differs")
        require(len(calendar_originals["files"])==3,"three original calendar/form/background records required")
        for row in calendar_originals["files"]:
            original=calendar_test/row["path"];require(original.stat().st_size==row["bytes"] and sha(original.read_bytes())==row["sha256"] and row["source_bytes_modified"] is False,"actual calendar original changed")
        query=load(source/"tests/web-flight/run_query_host_tests.py","native_provider_query_closure")
        bg=load(source/"tests/background-session/prepare_fixture.py","native_provider_background_fixture")
        bgfiles,bgrecord=bg.prepare(source,out/"platform-fixture")
        # Keep actual BackgroundSession + FilesRoot. Platform transport/syscalls are
        # the retained host fixture. This test does not execute terminal projection.
        bgfiles=[p for p in bgfiles if not (p.parent.name=="json" and p.parent.parent.name=="org") and "terminal" not in p.parts]
        paths=[source/p for p in query.PURE_PATHS if p!="tests/web-flight/WebFlightQueryHostTest.java" and p!="tests/native-app/legacy-boundary/NativeAppSession.java"]+bgfiles
        paths += [source/("src/org/trillionnium/hepta/local/"+name+".java") for name in EXTRA_SOURCES]
        paths += [source/"tests/native-app-fixtures/NativeXmlFixture.java",own/"NativeAppProviderHostTest.java",own/"NativeAppObservationHostTest.java",own/"NativeResourceHomeHostTest.java"]
        paths += [modal_test/"ActualXiaomiImageModalFixture.java",modal_test/"NativeXiaomiImageModalHostTest.java",own/"NativeXiaomiModalSessionHostTest.java"]
        paths += [calendar_test/"NativeCtripCalendarHostTest.java"]
        paths=list(dict.fromkeys(p.resolve() for p in paths))
        for p in paths:require(p.is_file(),"actual compile input absent: "+str(p))
        report["compile_inputs"]=[{"path":str(p),"bytes":len(p.read_bytes()),"sha256":sha(p.read_bytes())} for p in paths]
        write(out/"BOUNDARIES.json",(json.dumps({"schema":"hepta.native-app-provider-host-boundaries.v1","background_fixture":bgrecord,"image_modal_original_projection":modal_fixture,"calendar_provenance_sha256":sha(calendar_provenance.read_bytes()),"calendar_foreground_XML_not_actual_background_frame":True,"fixture_manifest_sha256":sha(fixture_manifest.read_bytes()),"model_executed":False,"android_runtime":False},indent=2)+"\n").encode())
        classes=out/"classes";classes.mkdir()
        run("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror","-classpath",jar,"-d",classes,*paths])
        run("provider-cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeAppProviderHostTest",own/"fixtures",out/"PROVIDER-CASES.json"])
        cases=json.loads((out/"PROVIDER-CASES.json").read_text())
        require(cases.get("schema")=="hepta.native-app-provider-host.v1" and cases.get("all_pass") is True,"typed cases missing")
        require(cases.get("case_names")==EXPECTED_NAMES and cases.get("cases")==len(EXPECTED_NAMES),"full case identity differs")
        require(type(cases.get("assertions")) is int and cases["assertions"]>0,"assertion count missing")
        require(cases.get("phone_operations")==0 and cases.get("model_executed") is False and cases.get("business_verified") is False,"host boundary mislabeled")
        run("observation-domain-cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeAppObservationHostTest",own/"fixtures",out/"adapter-private",out/"OBSERVATION-CASES.json"])
        adapter=json.loads((out/"OBSERVATION-CASES.json").read_text())
        require(adapter.get("schema")=="hepta.native-app-observation-domain-host.v1" and adapter.get("all_pass") is True,"typed actual adapter cases missing")
        require(adapter.get("case_names")==EXPECTED_ADAPTER_NAMES and adapter.get("cases")==len(EXPECTED_ADAPTER_NAMES),"actual adapter case identity differs")
        require(type(adapter.get("assertions")) is int and adapter["assertions"]>0 and adapter.get("phone_operations")==0 and adapter.get("business_verified") is False,"adapter host boundary/count missing")
        run("resource-home-cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeResourceHomeHostTest",own/RESOURCE_FIXTURE["path"],out/"resource-private",out/"RESOURCE-HOME-CASES.json"])
        resource=json.loads((out/"RESOURCE-HOME-CASES.json").read_text())
        require(resource.get("schema")=="hepta.native-resource-home-host.v1" and resource.get("all_pass") is True,"typed resource home cases missing")
        require(resource.get("case_names")==EXPECTED_RESOURCE_NAMES and resource.get("cases")==len(EXPECTED_RESOURCE_NAMES),"exact resource case identity differs")
        require(type(resource.get("assertions")) is int and resource["assertions"]>0 and resource.get("phone_operations")==0 and resource.get("android_runtime") is False and resource.get("model_executed") is False and resource.get("business_verified") is False,"resource boundary/count differs")
        require((cases["cases"],cases["assertions"],adapter["cases"],adapter["assertions"],resource["cases"],resource["assertions"])==(39,315,12,21,20,29),"retained original 71 cases/365 assertions changed")
        run("image-modal-shape-cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeXiaomiImageModalHostTest",out/"IMAGE-MODAL-CASES.json"])
        shape=json.loads((out/"IMAGE-MODAL-CASES.json").read_text())
        require(shape.get("names")==EXPECTED_IMAGE_MODAL_NAMES and shape.get("cases")==29 and shape.get("checks")==244,"complete original-image modal shape case identity differs")
        require(shape.get("host_only") is True and shape.get("business_verified") is False,"pure shape host boundary differs")
        run("xiaomi-modal-session-cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeXiaomiModalSessionHostTest",source/"tests/native-xiaomi-product/fixtures",out/"XIAOMI-MODAL-SESSION-CASES.json"])
        modal=json.loads((out/"XIAOMI-MODAL-SESSION-CASES.json").read_text())
        require(modal.get("schema")=="hepta.native-xiaomi-modal-session-host.v1" and modal.get("all_pass") is True,"typed modal Session cases missing")
        require(modal.get("case_names")==EXPECTED_XIAOMI_MODAL_SESSION_NAMES and modal.get("cases")==len(EXPECTED_XIAOMI_MODAL_SESSION_NAMES),"complete modal Session case identity differs")
        require(type(modal.get("assertions")) is int and modal["assertions"]>0 and modal.get("phone_operations")==0 and modal.get("android_runtime") is False and modal.get("model_executed") is False and modal.get("business_verified") is False,"modal Session count/host boundary differs")
        run("ctrip-calendar-cases",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeCtripCalendarHostTest",calendar_test/"fixtures",own/"fixtures",out/"CALENDAR-CASES.json"])
        calendar=json.loads((out/"CALENDAR-CASES.json").read_text())
        require(calendar.get("schema")=="hepta.native-ctrip-calendar-host.v1" and calendar.get("all_pass") is True,"typed calendar cases missing")
        require(calendar.get("case_names")==EXPECTED_CTRIP_CALENDAR_NAMES and calendar.get("cases")==38 and calendar.get("assertions")==157,"calendar exact cases/assertions differ")
        require(calendar.get("phone_operations")==0 and calendar.get("android_runtime") is False and calendar.get("model_executed") is False and calendar.get("business_verified") is False and calendar.get("bound_background_frame_actual") is False and calendar.get("calendar_day_coordinates_authorized") is False,"calendar host boundary differs")
        all_cases={"schema":"hepta.native-app-provider-composition-host.v1","all_pass":True,"cases":cases["cases"]+adapter["cases"]+resource["cases"]+shape["cases"]+modal["cases"]+calendar["cases"],"assertions":cases["assertions"]+adapter["assertions"]+resource["assertions"]+shape["checks"]+modal["assertions"]+calendar["assertions"],"case_names":EXPECTED_NAMES+EXPECTED_ADAPTER_NAMES+EXPECTED_RESOURCE_NAMES+EXPECTED_IMAGE_MODAL_NAMES+EXPECTED_XIAOMI_MODAL_SESSION_NAMES+EXPECTED_CTRIP_CALENDAR_NAMES,"provider":cases,"observation_domain":adapter,"resource_home":resource,"image_modal_shape":shape,"xiaomi_modal_session":modal,"ctrip_calendar":calendar,"phone_operations":0,"android_runtime":False,"model_executed":False,"business_verified":False}
        write(out/"CASES.json",(json.dumps(all_cases,ensure_ascii=False,indent=2)+"\n").encode())
        report["cases"]=all_cases;report["case_records"]={p.name:{"path":str(p),"sha256":sha(p.read_bytes()),"bytes":p.stat().st_size} for p in (out/"CASES.json",out/"PROVIDER-CASES.json",out/"OBSERVATION-CASES.json",out/"RESOURCE-HOME-CASES.json",out/"IMAGE-MODAL-CASES.json",out/"XIAOMI-MODAL-SESSION-CASES.json",out/"CALENDAR-CASES.json")};report["all_pass"]=True
    except Exception as error:report["failure"]={"type":type(error).__name__,"message":str(error)}
    finally:
        after=inventory(source);report["inputs_unchanged"]=before==after;report["tools_after"]={p:sha(Path(p).read_bytes()) for p in tools}
        report["tools_unchanged"]=tools==report["tools_after"];report["all_pass"]=report["all_pass"] and report["inputs_unchanged"] and report["tools_unchanged"]
        if before!=after:report["changed_inputs"]=[p for p in sorted(set(before)|set(after)) if before.get(p)!=after.get(p)]
        raw=(json.dumps(report,ensure_ascii=False,indent=2)+"\n").encode();write(out/"RESULT.json",raw)
        print(json.dumps({"all_pass":report["all_pass"],"cases":report.get("cases",{}).get("cases"),"assertions":report.get("cases",{}).get("assertions"),"failure":report.get("failure"),"result":str(out/"RESULT.json"),"sha256":sha(raw)}))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
