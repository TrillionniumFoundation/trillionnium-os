#!/usr/bin/env python3
"""Sign the sealed Pocket4 main56 APK, bound to its own source CAS and actual applicable host gates.
Java/DEX/resources came from the actual P4 build; all17 native payloads are signed54 bytes.
No build, download, key creation/export, installation or phone action occurs here.
"""
from pathlib import Path,PurePosixPath
import base64,gzip,hashlib,io,json,os,re,runpy,signal,stat,struct,subprocess,sys,time,traceback,zipfile,zlib
import xml.etree.ElementTree as ET
B=Path("/home/alex/hepta-local-007f-20261111")
CONFIG=json.loads("{\"schema\":\"hepta.main56-same-host-sign-config.v1\",\"root\":\"/home/alex/hepta-local-007f-20261111/v56-main-sign-r1\",\"build_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-p4-android-r1\",\"build_result\":{\"bytes\":203372,\"sha256\":\"b557a981d07fb5a65c39da4abbf0474559035a875831bec820c6b4a55fcc7ece\"},\"build_stage\":{\"bytes\":206118,\"sha256\":\"85e530eebbc859dcea83955cd2f62153b2ab0414da8d7632dd7027eee45091f2\"},\"build_input\":{\"bytes\":1564155,\"sha256\":\"1ef8ac7725aa8ed15ac628e6471b4469a75784f2050fdb442443f065fb132459\"},\"compiled_aggregate\":{\"git\":\"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\",\"bytes\":1427055,\"sha256\":\"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\"},\"compiled_source_inventory_sha256\":\"ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e\",\"core_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-core101-materialized-host-r2\",\"core_result\":{\"bytes\":9732,\"sha256\":\"778fbfeac89fa330d123207c43e485818b530f77e978247c61f67d9d23ce9a39\"},\"core_stage\":{\"bytes\":108035,\"sha256\":\"1e10c0265b946636651c852e7d8d0aaefc8b1611c25000f2f6e119a0c701a3d3\"},\"final_aggregate\":{\"git\":\"0803dec4b6acc359b810bb79ca6fdd01ada69a8c\",\"bytes\":1427055,\"sha256\":\"c1cc7cc16eef4c3a34131ee719101a69db080b76e72c98f03248036fc6fd628f\"},\"final_inventory\":{\"bytes\":103795,\"sha256\":\"ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e\"},\"core_blob_map\":{\"bytes\":141875,\"sha256\":\"8d8cf9767861029b1cd4c6bb1143e07ee92296a475a44ae1979db79756233926\"},\"web_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-web-regression-host-r2\",\"web_result\":{\"bytes\":47337,\"sha256\":\"220ccb705ba17797d7403c26c1a9bcb438f46c8ea83e017c617a343d27232f7c\"},\"web_stage\":{\"bytes\":131893,\"sha256\":\"814e327adb50509d35a03a89f96ab085c3b4249c526d3b041ef3885e59e35391\"},\"web_packet\":{\"bytes\":260128,\"sha256\":\"3687b09656e60a808ebdce1430951e04741581e9ddd0d2faa7f5c36220ed24b7\"},\"publication_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-release-publication-r1\",\"git_source_map\":{\"bytes\":289218,\"sha256\":\"b8b436f7e6bdbc5b319cd6ebcd3ac42bf5eb81638ba21aea9532f753b65c4f98\"},\"publication\":{\"bytes\":6679,\"sha256\":\"5a71f5570743cfee38fbfadedf39a19609dccd111dfcd5e8a4e15c70be3e87b1\"},\"source_commit\":\"9f4168616546233033edd4b254b4236ae987ea7e\",\"source_tree\":\"69fce7a2ec9467f0594d6d031fa0aab0cc9c636f\",\"expected_prior_head\":\"dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e\",\"source_count\":595,\"compiler_input_count\":217,\"java_source_count\":115,\"host_input_count\":419,\"host_record_count\":101,\"base_source_commit\":\"42d3a0f447807659c0f78c8273edee01dd1b734f\",\"base_root\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4\",\"base_signed\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/assembly-r1/RESULT.json\",\"bytes\":15659,\"sha256\":\"eadc9dbb63b411015571a488377be6a8704c9f78415169a5164c8f13571f0f72\"},\"base_apk\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/out/hepta-local-0.54.0.apk\",\"bytes\":20985685,\"sha256\":\"0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a\"},\"base_static\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/out/control-v54-static/STATIC-ACCEPTANCE.json\",\"sha256\":\"23a4d98257b29f9c2a06d87823c3b9379831d6d88563b63c0768980aee1e85d6\"},\"base_source_inventory_sha256\":\"8675c0c438cdf10f599c23a3a6305a5678fd59270f09b4f73a43f7a67bf2237d\",\"base_host_sha256\":\"6c7f11e31c4fcb2e81c417995282987fcaf5f0fb632885f0f376a5745b9db3d8\",\"native_pins\":{\"libMNN.so\":\"5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d\",\"libc++_shared.so\":\"77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754\",\"libgeniex.so\":\"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56\",\"libgeniex_plugin_llama_cpp.so\":\"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a\",\"libggml-base.so\":\"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40\",\"libggml-cpu.so\":\"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b\",\"libggml-hexagon.so\":\"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f\",\"libggml-htp-v79.so\":\"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5\",\"libggml-opencl.so\":\"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875\",\"libggml.so\":\"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149\",\"libhepta_local_runner.so\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"libhepta_mobimind_runner.so\":\"b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020\",\"libhepta_ui_venus_runner.so\":\"5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551\",\"libllama-common.so\":\"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122\",\"libllama.so\":\"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835\",\"libmtmd.so\":\"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d\",\"libomp.so\":\"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76\"},\"worker\":{\"bytes\":59952,\"sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\"},\"worker_generated_sha256\":\"77b914eae46ea000d3c955628c35f6e96a715a4a14da3eb075923d2e6024bbb0\",\"focused_root\":\"/home/alex/hepta-local-007f-20261111/v56-main-wire4-host-p4-r1\",\"focused_result\":{\"bytes\":44408,\"sha256\":\"036e4f7b185a127e457712fcd23b6745d8aac18a04cf64da4035764329efee43\"},\"identity_root\":\"/home/alex/hepta-local-007f-20261111/v55-installed-apk-identity-host-r1\",\"identity_result\":{\"bytes\":5727,\"sha256\":\"52762ada64c63bc58749d62e9bd183b586c40349f0e10082ded1c308d82df4f7\"},\"sdk_root\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-sdk-input-r2\",\"sdk_result\":{\"bytes\":64222,\"sha256\":\"5300257b246f73bc410028d8e1e61f18381e6f9b4a4406661d00b7d3d128eab6\"},\"query_runner\":{\"bytes\":41005,\"sha256\":\"5af6324496884603f2be5184334335e17d59dd653d0dd20ec859d5c064820b10\"},\"build_identity\":{\"path\":\"tools/build_identity.py\",\"bytes\":2970,\"sha256\":\"7d5ad2641e9a3635fd04aa47ce3ea50a1a4f16b883a98b2ab407878eef36f6e6\",\"git_blob_sha\":\"393b3133c988a422f53a37ecb6052e60d508bf2e\"},\"old_runner\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v51-build-r2/v51_assembly_filled.py\",\"sha256\":\"3bfad635fb8fdd6d971c60fb8b998a56e63fefaee75ae7a6140b4403cfbca53b\"},\"signer_cert\":\"202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5\",\"apksigner_executable\":\"/usr/bin/apksigner\",\"aapt2\":{\"path\":\"/usr/lib/android-sdk/build-tools/debian/aapt2\",\"bytes\":54512,\"sha256\":\"0e9ff92342040acdfd03e8708512f4e02353e3ca0a2b85ea2950da659110b009\"},\"jdk\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64\",\"permissions\":[\"org.trillionnium.hepta.webhelper.permission.BIND_EVIDENCE\"],\"source_prefix\":\"projects/razr60/phone-local-v150/android-local/lfm3-controller/\",\"repository\":\"trillionniumFoundation/trillionnium-os\",\"branch\":\"codex/hepta-v45-semantic-click-20261111-007f\",\"nested_stages\":[\"compile\",\"actual-completion\",\"notes-task-phase\",\"notes-task-phase-grammar\",\"notes-list-provenance\",\"notes-recovery\",\"notes-recovery-grammar\",\"notes-task-scope\",\"notes-task-scope-grammar\",\"calculator-input\",\"calculator-input-grammar\",\"failed-action-observation\",\"notes-editor-phase\",\"notes-editor-phase-grammar\",\"completion-status\",\"completion-status-grammar\",\"notes-create-workflow\",\"notes-workflow-controller\"],\"build_steps\":[\"javac\",\"d8\",\"aapt2-compile\",\"aapt2-link\",\"badging\",\"permissions\",\"manifest\",\"accessibility\"],\"predecessor_build_result\":{\"bytes\":199633,\"sha256\":\"267272033459763c9542b98a701048bfd09cf120510e79aa2c5be4ee5b3f6db7\"},\"compiler_inputs\":{\"bytes\":34376,\"sha256\":\"2b9e1d971a60d09df7303f050cef40d4b254b016a6f68c272035ec11ef854071\"},\"overlay_file_count\":40,\"query_java_source_count\":50,\"web_production_java_count\":44,\"web_compilation_unit_count\":52,\"predecessor_release\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-main-sign-r1/RESULT.json\",\"bytes\":31662,\"sha256\":\"3caa0d8ae5252352fb606db1d851fd9e960423c0f7374a76c58b89c688556535\"},\"predecessor_apk\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-main-sign-r1/out/hepta-local-0.55.0.apk\",\"bytes\":21014354,\"sha256\":\"ea485e6d28544d75a9010e441aae8df348d1b64884f9ff7a50cb909a3f8ea45e\"},\"predecessor_aggregate\":{\"git\":\"d3bf59d91e5681fd5991c4bfef8587ba9a7b2a2d\",\"bytes\":1320157,\"sha256\":\"66ac069a14b64db51d9f2d09bf52acc6a8d9dc93484f8c21e3c3276ac31c2f06\"},\"predecessor_source_inventory_sha256\":\"65bf7934d82692f45c10aedb947613043453b30bc7d55c4dc8b7e44e4ca0bed1\",\"predecessor_release_source_commit\":\"dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e\",\"publication_base_source_commit\":\"dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e\",\"version_code\":56,\"version_name\":\"0.56.0-flight-stability\",\"pending_scope\":\"actual source successor for bounded native Flight-home stability and immutable terminal completion; Flight result provider remains false\",\"query_case_expectation\":{\"cases\":40,\"assertions\":187,\"case_names\":[\"literal_city_data_is_not_a_verified_route\",\"matching_form_without_model_actions_cannot_query\",\"real_class_selection_chain_enables_exact_query_once\",\"accepted_picker_click_waits_for_native_form_readback\",\"false_city_outcome_never_confirms\",\"stale_city_outcome_never_confirms\",\"date_before_two_city_confirmations_withheld\",\"wrong_after_city_literal_stays_pending\",\"dom_city_without_same_native_value_stays_pending\",\"foreign_native_city_descendant_rejected\",\"two_cities_without_full_calendar_date_cannot_query\",\"wrong_after_month_day_stays_pending\",\"wrong_after_weekday_stays_pending\",\"date_before_dispatch_end_cannot_confirm\",\"later_route_change_invalidates_current_query\",\"later_date_change_invalidates_year_confirmation\",\"native_field_disappears_query_withheld\",\"two_adults_are_not_one_adult_query\",\"disabled_dom_query_cannot_mint_target\",\"duplicate_native_query_even_disabled_refuses\",\"another_binding_cannot_import_selection_chain\",\"navigation_epoch_regression_cannot_import_progress\",\"query_reservation_is_not_a_dispatch\",\"second_query_reservation_refused\",\"actual_query_outcome_and_after_capture_remain_not_results\",\"false_query_outcome_consumes_attempt\",\"accepted_query_without_platform_entry_refused\",\"query_outcome_before_capture_refused\",\"query_outcome_wrong_model_run_refused\",\"query_outcome_twice_refused\",\"unknown_booking_body_is_read_only_pending\",\"city_airport_combination_not_silently_normalized\",\"actual_session_dispatch_methods_0\",\"actual_session_dispatch_methods_1\",\"actual_session_dispatch_methods_2\",\"actual_session_dispatch_methods_3\",\"actual_session_dispatch_methods_4\",\"actual_session_dispatch_methods_5\",\"actual_session_dispatch_methods_6\",\"actual_session_dispatch_methods_7\"]},\"composition_case_expectation\":{\"cases\":70,\"assertions\":178,\"case_names\":[\"v4_receipt_and_real_composition\",\"price_not_filled_from_goal\",\"result_record_requires_navigation\",\"current_tcg_real_provider_path\",\"tcg_no_navigation_cannot_complete\",\"tcg_rejects_stale_observation\",\"tcg_rejects_other_owner\",\"wait_has_no_action_capability\",\"flight_wait_uses_original_natural_owner\",\"original_tool_mask_is_intersection\",\"missing_accepted_outcome_rejected\",\"missing_dispatch_outcome_rejected\",\"stale_native_outcome_rejected\",\"dispatch_time_order_1009_1101\",\"dispatch_time_order_1102_1101\",\"dispatch_time_order_1100_1201\",\"operator_without_native_run_rejected\",\"old_source_observation_rejected\",\"new_epoch_required\",\"source_link_target_must_match\",\"navigation_cannot_cross_lease\",\"code3_binding_rejected\",\"old_v2_binding_rejected\",\"foreign_site_policy_rejected\",\"foreign_compiled_initial_url_rejected\",\"mutated_authority_evidence_rejected\",\"extra_selected_app_rejected\",\"wrong_authenticated_uid_rejected\",\"raw_controller_identity_mismatch_rejected\",\"callback_metadata_lost_binding_rejected\",\"bound_dom_wrong_origin_rejected\",\"manual_diagnostic_not_task_evidence\",\"duplicate_native_card_description_blocks_even_disabled\",\"out_of_screen_native_node_has_no_css_fallback\",\"different_native_label_blocks_product_link\",\"ambiguous_observed_region_blocks_product_link\",\"transaction_anchor_mints_no_capability\",\"modal_blocks_all_capabilities\",\"conditional_price_cannot_complete\",\"starting_price_cannot_complete\",\"currency_requires_actual_native_label\",\"native_duplicate_amount_blocks_result\",\"wrong_dom_currency_cannot_complete\",\"terminal_verified_snapshot_survives_only_normal_known_close\",\"terminal_unclaimed_unstable_or_unverified_result_never_freezes\",\"terminal_final_frame_identity_changes_are_rejected\",\"terminal_final_native_node_changes_are_rejected\",\"terminal_closed_callback_identity_is_exact\",\"terminal_unknown_abort_and_late_close_never_recover_success\",\"terminal_clear_rebind_and_late_observation_invalidate_proof\",\"terminal_requires_actual_owner_scope_cleanup_and_native_parent_facts\",\"terminal_tokens_are_gate_local_and_consumed_once\",\"terminal_flight_without_results_provider_stays_unverified\",\"flight_home_actual_two_dom_carousel_only_difference\",\"flight_home_dom_target_label_change_rejected\",\"flight_home_dom_non_carousel_geometry_rejected\",\"flight_home_dom_extra_slider_semantics_rejected\",\"flight_home_dom_vertical_or_nonuniform_motion_rejected\",\"flight_home_dom_visible_modal_in_both_reads_rejected\",\"flight_home_dom_metadata_or_membership_change_rejected\",\"flight_home_actual_retained_native_ad_only_change\",\"flight_home_retained_ordinal_shift_preserves_path_binding\",\"flight_home_retained_target_semantics_change_rejected\",\"flight_home_synthetic_full_native_same_overlap_accepted\",\"flight_home_full_native_target_change_rejected\",\"flight_home_full_native_ancestor_or_focus_change_rejected\",\"flight_home_full_native_ad_content_change_rejected\",\"flight_home_full_native_new_overlap_rejected\",\"flight_home_full_native_missing_ancestor_rejected\",\"flight_home_full_native_foreign_package_or_target_path_rejected\"]},\"predecessor_web_result\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-main-web-regression-host-r2/RESULT.json\",\"bytes\":41316,\"sha256\":\"c64027a42b69cc828a7d612f609c14b4b3e643a4662f1ca473840deda096406b\"},\"query_runner_original\":{\"bytes\":41005,\"sha256\":\"0f4d983138ed8bcf5f0b622ee4d4063048e83413eafe3586595521f5e1b7eb45\"},\"query_runner_count_adapter\":{\"before\":\"    need(len(PURE_PATHS)==45 and len(generated_factories)==3,\\\"fixed 43 production plus 2 retained plus 3 factory inputs\\\")\",\"after\":\"    need(len(PURE_PATHS)==46 and len(generated_factories)==3,\\\"fixed 44 production plus 2 retained plus 3 factory inputs\\\")\",\"count\":1}}")

def need(value, why):
    if not value:
        raise RuntimeError(why)

def case_summary(value,label):
    need(type(value) is dict and all(key in value for key in ("cases","assertions","case_names")),
         label+": complete case summary")
    cases,assertions,names=value["cases"],value["assertions"],value["case_names"]
    need(type(cases) is int and cases > 0 and type(assertions) is int and assertions >= cases
         and type(names) is list and len(names)==cases
         and all(type(name) is str and len(name)>0 for name in names)
         and len(set(names))==cases, label+": typed counts and unique complete case names")
    return {"cases":cases,"assertions":assertions,"case_names":list(names)}

def case_expectation(value,label):
    need(type(value) is dict and set(value)=={"cases","assertions","case_names"},
         label+": reviewed complete successor expectation required")
    return case_summary(value,label)

def require_case_successor(expected,previous,label):
    target=case_expectation(expected,label)
    baseline=case_summary(previous,label+" signed55 baseline")
    old_names=set(baseline["case_names"])
    need(target["cases"] >= baseline["cases"] and target["assertions"] >= baseline["assertions"]
         and [name for name in target["case_names"] if name in old_names]==baseline["case_names"],
         label+": all actual55 case names retained in original relative order")
    # This structural check does not replace review of retained assertion source.
    return target

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()

def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)+"\n").encode("utf-8")

def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def no_constant(value):
        raise ValueError("non-finite JSON")
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=no_constant)

def identity(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]

def read_regular(path, expected=None, limit=64<<20):
    path = Path(path)
    need(path.is_absolute(), "absolute input path")
    for parent in path.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "ordinary input ancestors")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
         "bounded single-link ordinary input")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        need(identity(os.fstat(fd)) == identity(before), "input replaced before open")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit+1-size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            need(size <= limit, "input byte limit")
        raw = b"".join(chunks)
        need(identity(os.fstat(fd)) == identity(before), "input changed while open")
    finally:
        os.close(fd)
    need(identity(path.lstat()) == identity(before) and len(raw) == before.st_size, "input changed across read")
    facts = {"path": str(path), "bytes": len(raw), "sha256": sha(raw), "identity": identity(before)}
    if expected is not None:
        need(type(expected["bytes"]) is int and facts["bytes"] == expected["bytes"]
             and facts["sha256"] == expected["sha256"], "exact input bytes/SHA: "+str(path))
    return raw, facts

def unchanged(facts):
    raw, current = read_regular(facts["path"], facts)
    need(current == facts, "input identity changed: "+facts["path"])
    return raw

def checked(raw, pin, message):
    need(type(raw) is bytes and type(pin["bytes"]) is int and len(raw) == pin["bytes"]
         and sha(raw) == pin["sha256"], message)
    if "git_blob_sha" in pin:
        need(blob(raw) == pin["git_blob_sha"], message+" Git blob")
    return raw

def relative(name):
    need(type(name) is str and "\\" not in name and name not in ("", "."), "relative member")
    path = PurePosixPath(name)
    need(not path.is_absolute() and ".." not in path.parts and str(path) == name, "safe member")
    return name

def rows(values):
    return [{"path": name, "bytes": len(raw), "sha256": sha(raw)}
            for name, raw in sorted(values.items(), key=lambda item: Path(item[0]))]

def snapshot(root):
    need(root.is_dir() and not root.is_symlink(), "existing ordinary source root")
    values, facts = {}, {}
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(), "no source symlink")
        if path.is_dir():
            continue
        name = relative(path.relative_to(root).as_posix())
        values[name], facts[name] = read_regular(path, limit=4<<20)
    return values, facts

def validate_map(values, expected, with_git):
    need(len(expected) == len(values) and len({r["path"] for r in expected}) == len(expected),
         "exact source map membership")
    need(set(values) == {relative(r["path"]) for r in expected}, "source map path set")
    for item in expected:
        raw = values[item["path"]]
        checked(raw, item, "source map member "+item["path"])
        if with_git:
            need(blob(raw) == item["git_blob_sha"], "source map Git identity")

def write_new(path, raw, mode=0o600):
    need(ROOT in path.parents and type(raw) is bytes, "owned new output")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for parent in path.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), "ordinary output ancestors")
    fd = os.open(str(path), os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise
    os.chmod(path, mode)
    actual, facts = read_regular(path, {"bytes": len(raw), "sha256": sha(raw)})
    need(actual == raw, "new output readback")
    return facts

def load_bound(path, pin, original_facts):
    raw, facts = read_regular(path, pin)
    original_facts.append(facts)
    return raw


def run_step(name, argv, timeout, cwd, env):
    begin = time.monotonic()
    process, code, timed_out, forced = None, None, False, False
    group_cleanup_attempted, group_absent_observed, group_cleanup_error = False, None, None
    stdout_path, stderr_path = ROOT/(name+".stdout"), ROOT/(name+".stderr")
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen([str(x) for x in argv], cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                forced = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = process.wait(timeout=5)
        finally:
            # A failed leader may already have exited while its compiler
            # descendants still belong to the new process group. Clean that
            # owned group on every failure, not just a still-running leader.
            if code != 0 or timed_out or process.poll() is None:
                group_cleanup_attempted = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except OSError as cleanup_error:
                    group_cleanup_error = str(cleanup_error)
                if process.poll() is None:
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                # The group may still exist after its leader is reaped.
                # This failure-only signal never targets another job/root.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    forced = True
                except ProcessLookupError:
                    pass
                except OSError as cleanup_error:
                    group_cleanup_error = str(cleanup_error)
                if process.poll() is None:
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        group_cleanup_error = "owned leader exit not observed after bounded cleanup"
                try:
                    os.killpg(process.pid, 0)
                    group_absent_observed = False
                except ProcessLookupError:
                    group_absent_observed = True
                except OSError as cleanup_error:
                    group_absent_observed = None
                    group_cleanup_error = str(cleanup_error)
    _, stdout_facts = read_regular(stdout_path)
    _, stderr_facts = read_regular(stderr_path)
    step = {"name": name, "argv": [str(x) for x in argv], "cwd": str(cwd), "pid": process.pid,
            "exit_code": code, "timed_out": timed_out, "forced_kill": forced, "exit_observed": process.poll() is not None,
            "elapsed_seconds": time.monotonic()-begin, "stdout": stdout_facts, "stderr": stderr_facts,
            "owned_group_cleanup_attempted": group_cleanup_attempted,
            "owned_group_absent_observed_after_failure": group_absent_observed,
            "owned_group_cleanup_error": group_cleanup_error}
    steps.append(step)
    need(type(code) is int and code == 0 and not timed_out and not forced and process.poll() is not None,
         "original Android compiler must exit normally")

def compiled_visibility(text):
    stack, tree, namespace = [], None, {}
    uri = 'http://schemas.android.com/apk/res/android'
    for line in text.splitlines():
        match = re.match(r'^\s*N: ([A-Za-z_][A-Za-z0-9_.-]*)=([^\s]+)(?:\s|$)', line)
        if match:
            prefix, value = match.groups()
            if prefix in namespace and namespace[prefix] != value:
                raise RuntimeError('Conflicting compiled namespace')
            namespace[prefix] = value
            continue
        match = re.match(r'^(\s*)E: ([^\s(]+)', line)
        if match:
            indent = len(match.group(1))
            node = {'tag': match.group(2), 'attributes': {}, 'children': []}
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                stack[-1][1]['children'].append(node)
            elif tree is None:
                tree = node
            else:
                raise RuntimeError('Multiple compiled manifest roots')
            stack.append((indent, node))
            continue
        match = re.match(r'^\s*A: ([^\s=()]+)(?:\([^)]*\))?="([^"]*)"(?:\s|$)', line)
        if match and stack:
            name, value = match.groups()
            if name.startswith(uri + ':'):
                name = 'android:' + name[len(uri) + 1:]
            elif name.startswith('android:') and namespace.get('android') != uri:
                raise RuntimeError('Unbound compiled Android namespace')
            if name in stack[-1][1]['attributes']:
                raise RuntimeError('Duplicate compiled manifest attribute')
            stack[-1][1]['attributes'][name] = value
    if tree is None or tree['tag'] != 'manifest':
        raise RuntimeError('Compiled manifest root missing')
    queries = [node for node in tree['children'] if node['tag'] == 'queries']
    if len(queries) != 1:
        raise RuntimeError('Compiled visibility queries missing or duplicate')
    packages, intents = [], []
    for node in queries[0]['children']:
        if node['tag'] == 'package':
            name = node['attributes'].get('android:name')
            if not isinstance(name, str) or not name or node['children']:
                raise RuntimeError('Malformed compiled visibility package')
            packages.append(name)
        elif node['tag'] == 'intent':
            entries = []
            for child in node['children']:
                name = child['attributes'].get('android:name')
                if child['tag'] not in ('action', 'category') or not isinstance(name, str) or not name or child['children']:
                    raise RuntimeError('Malformed compiled visibility intent')
                entries.append((child['tag'], name))
            if not entries or len(entries) != len(set(entries)):
                raise RuntimeError('Empty or duplicate compiled visibility intent')
            intents.append(sorted(entries))
        else:
            raise RuntimeError('Unexpected compiled visibility query')
    if not packages or len(packages) != len(set(packages)) or len(intents) != len({tuple(row) for row in intents}):
        raise RuntimeError('Missing or duplicate compiled visibility entries')
    return {'packages': sorted(packages), 'intents': sorted(intents)}




def same(a,b):
    return json.dumps(a,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(",",":")) == json.dumps(b,sort_keys=True,ensure_ascii=False,allow_nan=False,separators=(",",":"))

def sealed(value,label):
    need(type(value) is dict and type(value.get("bytes")) is int and value["bytes"]>0
         and type(value.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}",value["sha256"]),
         "actual sealed positive-length artifact required: "+label)
    return value

def take(path,pin=None):
    raw,facts=read_regular(path,pin)
    originals.append(facts)
    return raw

def take_sha(path,digest):
    raw=take(path)
    need(sha(raw)==digest,"complete original SHA: "+str(path))
    return raw

def artifact(path,record,empty=False):
    need(type(record) is dict and type(record.get("bytes")) is int
         and record["bytes"] >= (0 if empty else 1)
         and type(record.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}",record["sha256"])
         and record.get("path")==str(path),"exact actual artifact reference")
    return take(path,record)

def exact_patches(before,patches,after):
    value=before.decode("utf-8","strict")
    for patch in patches:
        need(type(patch["count"]) is int and patch["count"]==1 and value.count(patch["before"])==1,
             "one exact reviewed test replacement")
        value=value.replace(patch["before"],patch["after"])
    need(value.encode("utf-8")==after,"exact test successor raw bytes")
    for patch in reversed(patches):
        need(value.count(patch["after"])==1,"one exact reverse test replacement")
        value=value.replace(patch["after"],patch["before"])
    need(value.encode("utf-8")==before,"exact reverse test predecessor")

def verify_owned_steps(value,names,root):
    need(type(value) is list and [x["name"] for x in value]==names,"actual ordered step set")
    for step in value:
        need(type(step["exit_code"]) is int and step["exit_code"]==0
             and step["timed_out"] is False and step["forced_kill"] is False
             and step["exit_observed"] is True
             and step.get("owned_group_cleanup_error") is None,"normal actual owned child")
        for stream in ("stdout","stderr"):
            artifact(root/(step["name"]+"."+stream),step[stream],empty=True)

def apk_members(raw):
    result={}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        need(len(archive.infolist())<=64 and archive.testzip() is None,"complete APK CRC and member budget")
        total=0
        for item in archive.infolist():
            name=relative(item.filename)
            need(not item.is_dir() and name not in result and not item.flag_bits&1
                 and 0<=item.file_size<=64<<20,"unique bounded regular APK member")
            data=archive.read(item);total+=len(data)
            need(len(data)==item.file_size and total<=128<<20,"APK expanded size")
            result[name]=data
    return result

def zip_layout(raw):
    result=[]
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for item in archive.infolist():
            at=item.header_offset
            need(raw[at:at+4]==b"PK\x03\x04","actual local ZIP header")
            method=struct.unpack_from("<H",raw,at+8)[0]
            flags=struct.unpack_from("<H",raw,at+6)[0]
            n,e=struct.unpack_from("<HH",raw,at+26)
            offset=at+30+n+e
            need(raw[at+30:at+30+n]==item.filename.encode("utf-8")
                 and method==item.compress_type and flags==item.flag_bits and not flags&1,
                 "local/central ZIP name/method/flags agree")
            payload=archive.read(item)
            result.append({"path":item.filename,"bytes":len(payload),"sha256":sha(payload),
                "compression_method":method,"compressed_bytes":item.compress_size,
                "local_header_offset":at,"data_offset":offset,"data_offset_mod4":offset%4})
    resources=[x for x in result if x["path"]=="resources.arsc"]
    need(len(resources)==1 and resources[0]["compression_method"]==0
         and resources[0]["data_offset_mod4"]==0,"resources STORED and four-byte aligned")
    need(all(x["compression_method"]==8 for x in result if x["path"].startswith("lib/")),
         "native members remain DEFLATE/extracted, no unsupported mmap alignment claim")
    return result

def resource_summary(layout):
    row=next(x for x in layout if x["path"]=="resources.arsc")
    return {"compression_method":row["compression_method"],"local_data_offset":row["data_offset"],
            "four_byte_aligned":row["data_offset_mod4"]==0,"payload_sha256":row["sha256"]}

def host_input_rows(values):
    fixed_fixture_roots=tuple("tests/"+name+"/fixtures/" for name in (
        "completion","text-only-click","notes-task-phase","calculator-completion","calculator-input",
        "notes-editor-phase","completion-status","observation-collection","notes-create-workflow"))
    chosen=[]
    for name,raw in sorted(values.items(),key=lambda item:Path(item[0])):
        selected=("/" not in name and name.endswith(".py"))
        selected=selected or (name.startswith("src/") and name.endswith(".java"))
        selected=selected or (name.startswith("tests/") and name.endswith((".java",".py")))
        selected=selected or (name.startswith("native/") and name.endswith((".c",".h",".inc",".py")))
        selected=selected or (name.startswith("tools/") and name.endswith(".py"))
        selected=selected or name.startswith(fixed_fixture_roots)
        if selected:chosen.append({"path":name,"sha256":sha(raw)})
    return chosen


def verify_query(build):
    query=build["query40"];raw=artifact(BUILD/"query40/RESULT.json",query["original"])
    original=take(BUILD/"source/tests/web-flight/run_query_host_tests.py",CONFIG["query_runner_original"])
    executed=take(BUILD/"query40-runner.py",CONFIG["query_runner"])
    adapter=CONFIG["query_runner_count_adapter"]
    need(type(adapter) is dict and set(adapter)=={"before","after","count"}
         and type(adapter["count"]) is int and adapter["count"]==1
         and type(adapter["before"]) is str and type(adapter["after"]) is str,
         "one sealed external query count-only adaptation")
    before=adapter["before"].encode("utf-8");after=adapter["after"].encode("utf-8")
    need(before and after and original.count(before)==1 and executed.count(after)==1
         and original.replace(before,after,1)==executed and executed.replace(after,before,1)==original,
         "actual external query runner is exactly the reviewed one-hunk successor")
    need(query["runner_path"]==str(BUILD/"query40-runner.py")
         and query["runner_original_source_path"]=="tests/web-flight/run_query_host_tests.py"
         and query["runner_original_sha256"]==sha(original)
         and same(query["runner_count_adapter"],adapter)
         and query["runner_corrected_outside_source_tree"] is True
         and query["repository_runner_count_guard_known_incompatible"] is True,
         "actual executed runner and the preserved incompatible repository count are explicit")
    report=strict(raw)
    need(same(query["report"],report) and query["executed_in_process"] is True
         and query["owned_child_groups_managed_by_original_runner"] is True
         and query["runner_sha256"]==CONFIG["query_runner"]["sha256"],
         "actual query report composition")
    need(report["schema"]=="hepta.v55-flight-query-compiled-gate.v1" and report["all_pass"] is True
         and report["originals_unchanged"] is True and report["java_source_count"]==CONFIG["query_java_source_count"]
         and case_summary(report["cases"],"actual query")==CONFIG["query_case_expectation"]
         and report["full_selection_provenance_covered_here"] is False
         and report["original_80_43_13_mains_rerun"] is False and report["frozen_39_gate_rerun"] is False
         and report["cases"]["actual_query_executed"] is False
         and report["cases"]["actual_results_verified"] is False and report["phone_actions"]==0,
         "actual reviewed query successor scope without phone or business promotion")
    need([x["name"] for x in report["steps"]]==["javac","query-chain"],"query two actual child groups")
    for step in report["steps"]:
        need(type(step["exit_code"]) is int and step["exit_code"]==0 and step["forced"] is False
             and step["exception"] is None and step["cleanup_errors"]==[],"normal actual query child")
        for stream in ("stdout","stderr"):
            take_sha(BUILD/"query40"/(step["name"]+"."+stream),step[stream+"_sha256"])
    return raw,report

def verify_core(core,source):
    need(core["schema"]=="hepta.main56-original-core101-host-stage.v1" and core["all_pass"] is True
         and type(core["exit_code"]) is int and core["exit_code"]==0
         and core["source_root"]==str(SOURCE) and core["source_file_count"]==CONFIG["source_count"]
         and core["source_inventory_sha256"]==CONFIG["final_inventory"]["sha256"]
         and core["host_check_count"]==101 and core["host_input_count"]==CONFIG["host_input_count"]
         and core["nested_completion_stage_count"]==18 and core["nested18_are_within_core101"] is True
         and core["source_commit"] is None and core["publication_pending"] is True
         and all(core[k] is True for k in ("originals_unchanged","source_unchanged","base_source_unchanged","written_files_unchanged"))
         and core["android_compiled_here"] is False and core["signed"] is False
         and core["phone_actions"]==0 and core["business_verified"] is False,
         "actual complete same-source original101 including nested18")
    verify_owned_steps(core["steps"],["original-host-checks"],CORE)
    need(core["stage_sha256"]==CONFIG["core_stage"]["sha256"],"actual exact core coordinator")
    artifact(CORE/"RESULT.json",dict(CONFIG["core_result"],path=str(CORE/"RESULT.json")))
    host_raw=artifact(CORE/"host-checks/HOST-CHECKS.json",core["host_checks"])
    host=strict(host_raw)
    prior_raw=take_sha(BASE/"host-checks/HOST-CHECKS.json",CONFIG["base_host_sha256"])
    prior=strict(prior_raw)
    need(prior["all_pass"] is True and len(prior["checks"])==101,"actual signed54 full101")
    need(host["schema"]=="hepta.host-checks.v3" and host["all_pass"] is True
         and len(host["checks"])==101 and len({x["name"] for x in host["checks"]})==101
         and [x["name"] for x in host["checks"]]==[x["name"] for x in prior["checks"]]
         and same(host["source_inputs"],host_input_rows(source)) and len(host["source_inputs"])==CONFIG["host_input_count"],
         "all unchanged101 names/order with the complete current input map")
    for row in host["checks"]:
        name=relative(row["name"]);need("/" not in name,"simple actual check name")
        need(type(row["exit_code"]) is int and row["exit_code"]==0,"each original core check passed")
        for stream in ("stdout","stderr"):
            take_sha(CORE/"host-checks"/(name+"."+stream),row[stream+"_sha256"])
    need(all(host[k] is False for k in ("android_compiled","phone_tested","native_grammar_model_tested","external_model_used")),
         "host-only original scope")
    nested_raw=artifact(CORE/"host-checks/task-completion/RESULT.json",core["nested_completion"])
    nested=strict(nested_raw)
    need(nested["schema"]=="hepta.task-completion-host.v1" and nested["passed"] is True
         and nested["compiler_contract"]=="Java 8 API release"
         and [x["name"] for x in nested["stages"]]==CONFIG["nested_stages"]
         and all(type(x["exit_code"]) is int and x["exit_code"]==0 for x in nested["stages"]),
         "actual18 nested stages, not18 extra top-level records")
    # The original nested report preserves stdout/stderr records. Its entire
    # byte hash is bound by the successful core coordinator and source map.
    return host_raw,host,nested_raw,nested

def verify_web(web,compiled_source):
    need(web["schema"]=="hepta.main56-existing-web-regressions-host-stage.v1"
         and web["all_pass"] is True and type(web["exit_code"]) is int and web["exit_code"]==0
         and web["source_candidate_git"]==CONFIG["compiled_aggregate"]["git"]
         and web["source_inventory_sha256"]==CONFIG["compiled_source_inventory_sha256"]
         and web["source_file_count"]==CONFIG["source_count"] and web["production_java_count"]==CONFIG["web_production_java_count"]
         and web["compilation_unit_count"]==CONFIG["web_compilation_unit_count"] and web["fixture_count"]==6
         and web["evidence80_original_main_byte_identical"] is True
         and web["calendar13_asserted_body_byte_identical"] is True
         and web["composition43_explicit_fixture_successor"] is True
         and web["originals_unchanged"] is True and web["source_unchanged"] is True
         and web["written_files_unchanged"] is True and web["phone_actions"]==0
         and web["actual_Mi_detail_or_popup_verified"] is False and web["business_verified"] is False,
         "actual independent existing Web gates")
    verify_owned_steps(web["steps"],["compile","evidence80","composition43","calendar13"],WEB)
    need(web["stage_sha256"]==CONFIG["web_stage"]["sha256"],"actual exact Web coordinator")
    packet_raw=take(WEB/"FIXTURE-PACKET.json",CONFIG["web_packet"]);packet=strict(packet_raw)
    for item in packet["production_inputs"]+packet["unchanged_extra_inputs"]:
        name=relative(item["path"]);checked(compiled_source[name],item,"actual Web compilation source")
        need(compiled_source[name]==final_source[name] and blob(compiled_source[name])==item["git_blob_sha"],
             "Web inputs also identical in final published source")
    results={}
    expected=CONFIG["composition_case_expectation"]
    for name,cases,assertions in (("evidence80",80,92),
                                 ("composition43",expected["cases"],expected["assertions"]),
                                 ("calendar13",13,1001)):
        record=web["reports"][name]
        raw=artifact(WEB/(name+"-RESULT.json"),record["original"]);report=strict(raw)
        need(same(report,record["report"]) and report["all_pass"] is True
             and type(report["cases"]) is int and report["cases"]==cases
             and type(report["assertions"]) is int and report["assertions"]==assertions
             and len(report["case_names"])==cases and len(set(report["case_names"]))==cases,
             "actual separate Web gate report")
        if name=="composition43":
            need(case_summary(report,"actual composition")==expected,
                 "actual reviewed composition successor names and counts")
        need(same(web["actual_report_files"][name],record),"actual final raw report matches successful report")
        results[name]={"raw":raw,"report":report,"original":record["original"]}
    return packet_raw,results

def verify_publication(source,core,host_map_raw):
    git_raw=take(PUBLICATION/"GIT-SOURCE-BLOB-MAP.json",CONFIG["git_source_map"])
    pub_raw=take(PUBLICATION/"PUBLICATION.json",CONFIG["publication"])
    git,pub=strict(git_raw),strict(pub_raw)
    need(git["schema"]=="hepta.git-source-blob-map.v2"
         and git["repository"]==CONFIG["repository"] and git["source_prefix"]==CONFIG["source_prefix"]
         and git["source_commit"]==CONFIG["source_commit"] and git["source_tree"]==CONFIG["source_tree"]
         and git["base_source_commit"]==CONFIG["publication_base_source_commit"] and git["source_file_count"]==CONFIG["source_count"]
         and git["source_inventory_sha256"]==CONFIG["final_inventory"]["sha256"]
         and git["precommit_host_result_sha256"]==CONFIG["core_result"]["sha256"]
         and git["all_source_blobs_match_actual_tree"] is True
         and git["host_actual_blob_map_sha256"]==sha(host_map_raw)
         and git["host_actual_blob_map_bytes"]==len(host_map_raw),"actual published complete source map")
    actual=[]
    need(type(git["files"]) is list and len(git["files"])==CONFIG["source_count"]
         and len({r["path"] for r in git["files"]})==CONFIG["source_count"],"unique full successor Git membership")
    for item in git["files"]:
        name=relative(item["path"]);raw=source[name]
        checked(raw,item,"actual published source")
        need(item["git_blob_sha"]==blob(raw)==item["remote_blob_sha"] and item["mode"]=="100644"
             and item["repository_path"]==CONFIG["source_prefix"]+name,"actual remote Git blob binding")
        actual.append({"path":name,"bytes":len(raw),"sha256":sha(raw),"git_blob_sha":blob(raw)})
    actual.sort(key=lambda r:Path(r["path"]))
    host_rows=strict(host_map_raw)
    need(type(host_rows) is list and len(host_rows)==CONFIG["source_count"] and same(actual,host_rows),
         "published map equals complete actual core array")
    need(pub["schema"]=="hepta.v56-git-publication.v1" and pub["repository"]==CONFIG["repository"]
         and pub["source_prefix"]==CONFIG["source_prefix"] and pub["pr_number"]==139
         and pub["branch"]==CONFIG["branch"] and pub["base_source_commit"]==CONFIG["publication_base_source_commit"]
         and pub["expected_prior_head"]==CONFIG["expected_prior_head"]
         and pub["source_commit"]==CONFIG["source_commit"]==pub["actual_pr_head"]==pub["actual_ref_head"]
         and pub["source_tree"]==CONFIG["source_tree"] and pub["draft"] is True and pub["force"] is False
         and pub["source_file_count"]==CONFIG["source_count"] and pub["source_inventory_sha256"]==CONFIG["final_inventory"]["sha256"]
         and pub["all_source_blobs_match_actual_tree"] is True and pub["all_other_repository_blobs_preserved"] is True
         and pub["host_precommit_result_sha256"]==CONFIG["core_result"]["sha256"]
         and pub["host_record_count"]==101 and pub["host_input_count"]==CONFIG["host_input_count"]
         and pub["nested_completion_stage_count"]==18
         and pub["actual_host_blob_map_sha256"]==sha(host_map_raw)
         and pub["git_source_map_sha256"]==sha(git_raw) and pub["git_source_map_bytes"]==len(git_raw)
         and pub["pr_title_body_modified"] is False and pub["phone_tested"] is False,
         "actual nonforce CAS and PR binding")
    return git_raw,pub_raw,git,pub


# Future counts are literal seals of actual source and producer maps. Historical
# The original55 receipts cannot fill them by inference or bypass complete-map comparisons.
for name in ("source_count","compiler_input_count","java_source_count","host_input_count",
             "overlay_file_count","query_java_source_count","web_production_java_count",
             "web_compilation_unit_count"):
    need(type(CONFIG[name]) is int and CONFIG[name] > 0, "actual sealed successor count: "+name)
need(type(CONFIG["compiled_source_inventory_sha256"]) is str
     and re.fullmatch(r"[0-9a-f]{64}",CONFIG["compiled_source_inventory_sha256"]),
     "actual sealed successor compiler source inventory")
need(CONFIG["version_code"] == 56 and CONFIG["version_name"] == "0.56.0-flight-stability",
     "explicit reviewed56 manifest identity")
sealed(CONFIG["compiler_inputs"],"compiler_inputs")

# No pending declaration can reach the first mutation or a signing child.
case_expectation(CONFIG["query_case_expectation"],"query successor")
case_expectation(CONFIG["composition_case_expectation"],"composition successor")
sealed(CONFIG["query_runner"],"query_runner")
sealed(CONFIG["query_runner_original"],"query_runner_original")
sealed(CONFIG["predecessor_web_result"],"predecessor_web_result")
for name in ("build_result","build_stage","build_input","compiled_aggregate",
             "core_result","core_stage","final_aggregate","final_inventory",
             "core_blob_map","web_result","web_stage","web_packet","git_source_map","publication"):
    sealed(CONFIG[name],name)
for name in ("source_commit","source_tree","expected_prior_head"):
    need(type(CONFIG[name]) is str and re.fullmatch(r"[0-9a-f]{40}",CONFIG[name]),"actual Git identity: "+name)
need(CONFIG["source_commit"]!=CONFIG["publication_base_source_commit"],"new published56 source commit")
need(type(CONFIG["core_root"]) is str and re.fullmatch(
     re.escape(str(B))+r"/v56-main-core101-materialized-host-r[0-9]+",CONFIG["core_root"]),
     "actual independent final core root")
signer_raw=globals().get("__signer_source__")
need(type(signer_raw) is bytes and len(signer_raw)>0,"same loader-hashed signer raw required")
ROOT=Path(CONFIG["root"]);BUILD=Path(CONFIG["build_root"]);CORE=Path(CONFIG["core_root"])
WEB=Path(CONFIG["web_root"]);BASE=Path(CONFIG["base_root"]);PUBLICATION=Path(CONFIG["publication_root"])
SOURCE=CORE/"source";OUT=ROOT/"out";INPUT=ROOT/"inputs";CERT=CONFIG["signer_cert"]
need(sys.platform=="linux" and ROOT==B/"v56-main-sign-r1" and not ROOT.exists()
     and not ROOT.is_symlink(),"new independent Pocket4 signing root")
originals=[]
build_raw=take(BUILD/"RESULT.json",CONFIG["build_result"]);build=strict(build_raw)
builder_raw=take(BUILD/"stage.py",CONFIG["build_stage"])
input_raw=take(BUILD/"INPUT.json",CONFIG["build_input"])
aggregate_raw=take(BUILD/"AGGREGATE.json",CONFIG["compiled_aggregate"])
need(blob(aggregate_raw)==CONFIG["compiled_aggregate"]["git"],"exact original compiled aggregate Git")
aggregate=strict(aggregate_raw)
compiled_source,compiled_facts=snapshot(BUILD/"source")
originals.extend(compiled_facts.values())
validate_map(compiled_source,aggregate["inventory"]["files"],True)
need(len(compiled_source)==CONFIG["source_count"] and sha(encoded(rows(compiled_source)))==CONFIG["compiled_source_inventory_sha256"],
     "complete current Android source bytes")
compiled_inventory_raw=take(BUILD/"SOURCE-INVENTORY.json")
need(compiled_inventory_raw==encoded(rows(compiled_source)),"original Android inventory bytes")
base_raw=take(CONFIG["base_signed"]["path"],CONFIG["base_signed"]);base=strict(base_raw)
need(base["schema"]=="hepta.isolated-v54-assembly.v1" and base["all_pass"] is True
     and base["source_commit"]==CONFIG["base_source_commit"] and base["source_file_count"]==589
     and base["source_inventory_sha256"]==CONFIG["base_source_inventory_sha256"]
     and same(base["library_pins"],CONFIG["native_pins"])
     and base["native_libraries_identical_to_formal_v53"] is True
     and base["signer_certificate_sha256"]==CERT,"actual signed54 release predecessor")
base_source,base_facts=snapshot(BASE/"source");originals.extend(base_facts.values())
validate_map(base_source,aggregate["base_files"],True)
need(len(base_source)==589 and sha(encoded(rows(base_source)))==CONFIG["base_source_inventory_sha256"],
     "complete unchanged signed54 source map")
rebuilt=dict(base_source)
need(len(aggregate["files"])==CONFIG["overlay_file_count"] and len({x["path"] for x in aggregate["files"]})==CONFIG["overlay_file_count"],"exact sealed final compiled overlays")
for item in aggregate["files"]:
    name=relative(item["path"]);raw=item["raw_utf8"].encode("utf-8")
    checked(raw,item,"exact full compiled overlay")
    need(blob(raw)==item["git_blob_sha"],"compiled overlay Git identity")
    if item["base"] is None:need(name not in rebuilt,"genuinely new compiled source")
    else:checked(rebuilt[name],item["base"],"original signed54 overlay predecessor")
    rebuilt[name]=raw
need(rebuilt==compiled_source,"all compiled source reconstructed from the original baseline")
need(build["schema"]=="hepta.main56-pocket4-java-native-reuse-stage.v1" and build["all_pass"] is True
     and type(build["exit_code"]) is int and build["exit_code"]==0
     and build["stage_sha256"]==CONFIG["build_stage"]["sha256"] and build["input_sha256"]==sha(input_raw)
     and build["source_candidate_git"]==CONFIG["compiled_aggregate"]["git"]
     and build["source_file_count"]==CONFIG["source_count"] and build["compiler_input_count"]==CONFIG["compiler_input_count"]
     and build["java_source_count"]==CONFIG["java_source_count"] and type(build["class_count"]) is int and build["class_count"]>0
     and build["source_inventory_sha256"]==CONFIG["compiled_source_inventory_sha256"]
     and build["source_commit"] is None and build["publication_pending"] is True
     and build["android_java_compiled_here"] is True and build["dex_compiled_here"] is True
     and build["resources_compiled_here"] is True and build["native_recompiled_here"] is False
     and build["ndk_or_clang_executed_here"] is False and build["native_payloads_reused_from_signed54"] is True
     and build["originals_unchanged"] is True and build["written_files_unchanged"] is True
     and build["current_source_unchanged"] is True and build["signed"] is False
     and build["published"] is False and build["phone_actions"]==0 and build["business_verified"] is False,
     "actual original Android Java/DEX/resources build, explicitly reused native")
need(build["revision"]=="sealed-source-successor-from-actual-signed55-r1"
     and build["prior_successful_build_preserved"] is True
     and same(build["prior_successful_build"],CONFIG["predecessor_build_result"])
     and build["materialized_source_unchanged"] is True
     and build["core_materialized_root"]==str(CORE)
     and build["same_complete_source_as_core_materialization"] is True
     and build["post_compile_source_sidecar_required"] is False,
     "actual new compilation of the exact successor source with signed55 build preserved")
prior55_raw=take(BUILD/"PRIOR-BUILD-RESULT.json",CONFIG["predecessor_build_result"])
prior55_signed_raw=take(BUILD/"PREDECESSOR-SIGNED-RESULT.json",CONFIG["predecessor_release"])
need(prior55_signed_raw==take(CONFIG["predecessor_release"]["path"],CONFIG["predecessor_release"]),
     "same original signed55 receipt in the new build and original release")
prior55_signed=strict(prior55_signed_raw)
need(prior55_signed["schema"]=="hepta.isolated-v55-assembly.v1"
     and prior55_signed["all_pass"] is True and type(prior55_signed["exit_code"]) is int
     and prior55_signed["exit_code"]==0 and prior55_signed["version_code"]==55
     and prior55_signed["source_commit"]==CONFIG["predecessor_release_source_commit"]
     and prior55_signed["source_inventory_sha256"]==CONFIG["predecessor_source_inventory_sha256"]
     and prior55_signed["pocket4_build_result_sha256"]==CONFIG["predecessor_build_result"]["sha256"]
     and prior55_signed["compiled_and_published_source_byte_identical"] is True
     and prior55_signed["source_files_unchanged"] is True
     and prior55_signed["signer_certificate_sha256"]==CERT
     and same(prior55_signed["library_pins"],CONFIG["native_pins"])
     and same(build["predecessor_signed_release"],CONFIG["predecessor_release"])
     and build["predecessor_release_source_commit"]==CONFIG["predecessor_release_source_commit"],
     "actual signed55 predecessor and its actual Android2 build remain distinct from56")
take(CONFIG["predecessor_apk"]["path"],CONFIG["predecessor_apk"])
need(prior55_signed["apk_sha256"]==CONFIG["predecessor_apk"]["sha256"]
     and prior55_signed["apk_bytes"]==CONFIG["predecessor_apk"]["bytes"],
     "exact complete signed55 APK predecessor")
prior55=strict(prior55_raw)
need(prior55["schema"]=="hepta.main55-pocket4-java-native-reuse-stage.v1"
     and prior55["all_pass"] is True and type(prior55["exit_code"]) is int and prior55["exit_code"]==0
     and prior55["query40"]["report"]["all_pass"] is True
     and prior55["query40"]["report"]["cases"]["all_pass"] is True
     and prior55["query40"]["report"]["cases"]["cases"]==prior55_signed["query_host_cases"]==40
     and prior55["query40"]["report"]["cases"]["assertions"]==prior55_signed["query_host_assertions"]==187,
     "actual signed55 query baseline is a retained predecessor, not a successor pass")
require_case_successor(CONFIG["query_case_expectation"],prior55["query40"]["report"]["cases"],"query successor")
prior55_web_raw=take(CONFIG["predecessor_web_result"]["path"],CONFIG["predecessor_web_result"])
prior55_web=strict(prior55_web_raw)
need(sha(prior55_web_raw)==prior55_signed["existing_web_regression_receipt_sha256"]
     and prior55_web["schema"]=="hepta.main55-existing-web-regressions-host-stage.v1"
     and prior55_web["all_pass"] is True and type(prior55_web["exit_code"]) is int and prior55_web["exit_code"]==0
     and prior55_web["source_inventory_sha256"]==CONFIG["predecessor_source_inventory_sha256"],
     "actual signed55 Web baseline remains separately pinned and unchanged")
prior55_composition=prior55_web["reports"]["composition43"]["report"]
need(prior55_composition["all_pass"] is True
     and prior55_composition["cases"]==prior55_signed["composition_host_cases"]==43
     and prior55_composition["assertions"]==prior55_signed["composition_host_assertions"]==59,
     "actual signed55 composition baseline is not reused as a successor pass")
require_case_successor(CONFIG["composition_case_expectation"],prior55_composition,"composition successor")
verify_owned_steps(build["steps"],CONFIG["build_steps"],BUILD)
receipt_raw=artifact(BUILD/"out/pocket4-build-receipt.json",build["compiler_receipt"])
receipt=strict(receipt_raw)
need(receipt["schema"]=="hepta.pocket4-java-native-reuse-build.v1"
     and receipt["version_code"]==CONFIG["version_code"] and receipt["version_name"]==CONFIG["version_name"]
     and receipt["build_host_platform"]=="linux" and receipt["source_root"]==str(BUILD/"source")
     and receipt["source_inventory_sha256"]==CONFIG["compiled_source_inventory_sha256"]
     and receipt["source_commit"] is None and receipt["java_source_count"]==CONFIG["java_source_count"]
     and receipt["class_count"]==build["class_count"]
     and receipt["compile_sdk"]==34 and receipt["target_sdk"]==35 and receipt["min_sdk"]==30
     and receipt["java_target"]==8 and receipt["android_java_compiled_here"] is True
     and receipt["dex_compiled_here"] is True and receipt["resources_compiled_here"] is True
     and receipt["native_recompiled_here"] is False and receipt["native_payloads_reused_from_signed54"] is True
     and same(receipt["actual_java_dex_resource_steps"],build["steps"][:4])
     and same(receipt["tools"],build["tools"]),"exact actual P4 compiler receipt")
for role,pin in receipt["tools"].items():
    take(pin["path"],pin)
    need(same(pin,build["tools"][role]),"actual tool identity bound to receipt")
take(CONFIG["aapt2"]["path"],CONFIG["aapt2"])
identity_raw=checked(compiled_source[CONFIG["build_identity"]["path"]],CONFIG["build_identity"],
                     "exact actual compiler identity producer")
identity_namespace={"__name__":"qualified_actual_build_identity","__file__":str(BUILD/"source/tools/build_identity.py")}
exec(compile(identity_raw,str(BUILD/"source/tools/build_identity.py"),"exec",dont_inherit=True),identity_namespace)
compiler_inputs=identity_namespace["source_inputs"](BUILD/"source")
need(len(compiler_inputs)==CONFIG["compiler_input_count"] and same(compiler_inputs,build["source_inputs"])
     and same(compiler_inputs,receipt["source_inputs"]),"all sealed actual compiler inputs")
compiler_input_raw=take(BUILD/"COMPILER-INPUTS.json")
need(same(strict(compiler_input_raw),compiler_inputs),"original compiler input raw")
checked(compiler_input_raw,CONFIG["compiler_inputs"],"actual final successor compiler map")
need(sum(x["path"].startswith("src/") and x["path"].endswith(".java") for x in compiler_inputs)==CONFIG["java_source_count"],
     "all sealed current Java compiler inputs")
for item in receipt["artifacts"]:
    artifact(Path(item["path"]),item)
artifact(BUILD/"out/resources.zip",receipt["compiled_resources"])

# The actual Android build, core101 and final publication must use the same
# complete source bytes. No postcompile source difference is admitted.
core_raw=take(CORE/"RESULT.json",CONFIG["core_result"]);core=strict(core_raw)
core_stage_raw=take(CORE/"stage.py",CONFIG["core_stage"])
final_aggregate_raw=take(CORE/"AGGREGATE.json",CONFIG["final_aggregate"])
final_inventory_raw=take(CORE/"SOURCE-INVENTORY.json",CONFIG["final_inventory"])
host_map_raw=take(CORE/"SOURCE-BLOB-MAP.json",CONFIG["core_blob_map"])
final_source,final_facts=snapshot(SOURCE);originals.extend(final_facts.values())
need(len(final_source)==CONFIG["source_count"] and final_source==compiled_source
     and final_inventory_raw==compiled_inventory_raw==encoded(rows(final_source))
     and final_aggregate_raw==aggregate_raw
     and CONFIG["compiled_source_inventory_sha256"]==CONFIG["final_inventory"]["sha256"],
     "all compiled, tested and published source bytes are identical")
need(core["source_candidate_git"]==CONFIG["final_aggregate"]["git"]
     and core["compiler_source_matches_current_final_inventory"] is True
     and core["compiler_source_equivalent_to_predecessor"] is False
     and core["source_map_difference_requires_signer_sidecar"] is False
     and core["prior_core_evidence_unchanged"] is True,
     "actual same-source core proof preserves the distinct original failures")
core_compiler_raw=take(CORE/"COMPILER-INPUTS.json",CONFIG["compiler_inputs"])
need(core_compiler_raw==compiler_input_raw
     and same(identity_namespace["source_inputs"](SOURCE),compiler_inputs),
     "all actual compiler inputs and their raw map are identical in both trees")
sidecar=None
final_map=[dict(x,git_blob_sha=blob(final_source[x["path"]])) for x in rows(final_source)]
host_rows=strict(host_map_raw)
need(type(host_rows) is list and len(host_rows)==CONFIG["source_count"] and same(host_rows,final_map),
     "complete actual final Git-bearing array")
final_aggregate=strict(final_aggregate_raw)
validate_map(final_source,final_aggregate["inventory"]["files"],True)
host_raw,host,nested_raw,nested=verify_core(core,final_source)
web_raw=take(WEB/"RESULT.json",CONFIG["web_result"]);web=strict(web_raw)
web_stage_raw=take(WEB/"stage.py",CONFIG["web_stage"])
web_packet_raw,web_reports=verify_web(web,compiled_source)
query_raw,query=verify_query(build)

focused_raw=take(Path(CONFIG["focused_root"])/"RESULT.json",CONFIG["focused_result"]);focused=strict(focused_raw)
need(focused["schema"]=="hepta.main56-wire4-focused-host-stage.v1"
     and focused["java_sources"]==51 and focused["pure_production_sources"]==44
     and focused["current_source_tree_unchanged"] is True and focused["prior_successful_run_preserved"] is True
     and focused["all_pass"] is True and focused["originals_and_written_sources_unchanged"] is True
     and focused["prior_failed_run_preserved"] is True and focused["prior_preservation_file_count"]==103
     and focused["exact_method_projection_count"]==15
     and same(build["focused_host_original"],CONFIG["focused_result"]),"actual independent focused39 proof")
verify_owned_steps(focused["steps"],["compile","consumer","arm"],Path(CONFIG["focused_root"]))
for name,count,assertions in (("consumer",20,60),("arm",19,98)):
    record=focused["reports"][name];raw=artifact(Path(CONFIG["focused_root"])/(name+"-RESULT.json"),record["original"])
    check=strict(raw)
    need(same(check,record["report"]) and check["all_pass"] is True
         and check["case_count"]==count and check["assertion_count"]==assertions
         and check["business_verified"] is False and check["phone_actions"]==0,"actual focused group without promotion")
identity_gate_raw=take(Path(CONFIG["identity_root"])/"RESULT.json",CONFIG["identity_result"]);identity_gate=strict(identity_gate_raw)
need(identity_gate["all_pass"] is True and identity_gate["exit_code"]==0 and identity_gate["originals_unchanged"] is True
     and identity_gate["cases"]["all_pass"] is True and identity_gate["cases"]["cases"]==10
     and identity_gate["cases"]["assertions"]==218 and identity_gate["android_syscalls_doubled"] is True
     and identity_gate["package_manager_or_certificate_executed"] is False
     and identity_gate["source_sha256"]==sha(final_source["src/org/trillionnium/hepta/local/WebHelperIdentity.java"])
     and same(build["identity_host_original"],CONFIG["identity_result"]),"actual independent identity10")
for step in identity_gate["steps"]:
    need(type(step["exit_code"]) is int and step["exit_code"]==0 and step["forced"] is False
         and step["exception"] is None and step["cleanup_errors"]==[],"normal actual identity child")
    for stream in ("stdout","stderr"):
        artifact(Path(CONFIG["identity_root"])/(step["name"]+"."+stream),step[stream],empty=True)
sdk_raw=take(Path(CONFIG["sdk_root"])/"RESULT.json",CONFIG["sdk_result"]);sdk=strict(sdk_raw)
need(sdk["completed"] is True and sdk["exit_code"]==0 and sdk["sdk_dual_hash_verified"] is True
     and sdk["r8_verified"] is True and sdk["originals_unchanged"] is True
     and same(build["sdk_dependency_result"],CONFIG["sdk_result"]),"actual independent dependency completion")

# Same17 native payloads, with historical native validation explicitly attributed.
base_apk_raw=take(CONFIG["base_apk"]["path"],CONFIG["base_apk"]);base_members=apk_members(base_apk_raw)
old_static_raw=take_sha(CONFIG["base_static"]["path"],CONFIG["base_static"]["sha256"]);old_static=strict(old_static_raw)
need(old_static["schema"]=="hepta.local-model.static-acceptance.v3"
     and old_static["apk_sha256"]==base["apk_sha256"] and old_static["version_code"]==54
     and old_static["all_packaged_runtime_libraries_bound_to_independent_pins"] is True,
     "actual signed54 historical static acceptance")
native_raw=take(BUILD/"NATIVE-REUSE.json");native=strict(native_raw)
need(same(native,build["native_reuse"]) and same(native,receipt["native_reuse"])
     and native["schema"]=="hepta.signed54-native-payload-reuse.v1"
     and native["native_recompiled_here"] is False and native["ndk_or_clang_executed_here"] is False
     and native["native_generator_executed_here"] is False
     and native["new_native_runtime_behavior_claimed"] is False
     and native["all_payloads_byte_identical_to_signed54"] is True and native["native_payload_count"]==17
     and same(native["source_signed_result"],CONFIG["base_signed"])
     and same(native["source_signed_apk"],CONFIG["base_apk"])
     and native["source_commit"]==CONFIG["base_source_commit"],"honest byte-identical native reuse receipt")
take(native["source_archive"]["path"],native["source_archive"])
need(same(native["current_native_generator_header_flag_inputs"],
          [x for x in compiler_inputs if not (x["path"].startswith("src/") and x["path"].endswith(".java")) and x["path"]!="AndroidManifest.xml"]),
     "actual native/general compiler non-Java inputs unchanged")
# The producer records the exact selected non-Java set. Verify each record here
# and its actual54 predecessor rather than inferring a new native compilation.
for item in native["current_native_generator_header_flag_inputs"]:
    name=item["path"]
    need(name in base_source and compiled_source[name]==base_source[name],"native input exactly retained")
    need(sha(compiled_source[name])==item["sha256"],"retained generator/header/flag input")
for field in ("current_worker","retained_generated_source","retained_disassembly"):
    artifact(Path(native[field]["path"]),native[field])
need(native["current_worker"]["sha256"]==CONFIG["worker"]["sha256"]
     and native["retained_generated_source"]["sha256"]==CONFIG["worker_generated_sha256"],
     "preserved actual worker/generated adapter")
old_native={row["name"]:row for row in old_static["libraries"]}
need(set(old_native)==set(CONFIG["native_pins"]) and len(old_native)==17,"all17 historical library identities")
for name,digest in CONFIG["native_pins"].items():
    payload=base_members["lib/arm64-v8a/"+name]
    need(sha(payload)==digest==old_native[name]["sha256"] and len(payload)==old_native[name]["bytes"],
         "signed54 complete native payload and original independent static proof")

unsigned_raw=artifact(BUILD/"out/hepta-local-0.56.0-unsigned.apk",build["unsigned_apk"])
unsigned_members=apk_members(unsigned_raw);unsigned_layout=zip_layout(unsigned_raw)
expected_paths={"AndroidManifest.xml","resources.arsc","res/xml/hepta_accessibility_service.xml",
                "classes.dex","assets/hepta-build-identity.json"}
expected_paths|={"lib/arm64-v8a/"+n for n in CONFIG["native_pins"]}
need(set(unsigned_members)==expected_paths and len(unsigned_members)==22
     and build["unsigned_apk_payload_count"]==22,"all exact22 unsigned APK members")
payload_raw=take(BUILD/"UNSIGNED-PAYLOADS.json")
need(same(strict(payload_raw),[{"path":n,"bytes":len(v),"sha256":sha(v)} for n,v in sorted(unsigned_members.items())]),
     "all unsigned payload original records")
need(same(resource_summary(unsigned_layout),build["resources_layout"]),"actual unsigned resources layout")
dex_raw=take(BUILD/"out/dex/classes.dex")
base_compiled_raw=take(BUILD/"out/base.apk");base_compiled_members=apk_members(base_compiled_raw)
need(set(base_compiled_members)==expected_paths-{"classes.dex","assets/hepta-build-identity.json"}-
     {"lib/arm64-v8a/"+n for n in CONFIG["native_pins"]},"exact3 aapt2 members")
need(unsigned_members["classes.dex"]==dex_raw and dex_raw[:4]==b"dex\n"
     and all(unsigned_members[n]==v for n,v in base_compiled_members.items()),"actual compiled Java/DEX/resources packaged")
for name,digest in CONFIG["native_pins"].items():
    need(unsigned_members["lib/arm64-v8a/"+name]==base_members["lib/arm64-v8a/"+name],
         "all17 unchanged native payload bytes packaged")
asset_raw=identity_namespace["actual_build_identity"](BUILD/"source",receipt)
need(asset_raw==unsigned_members["assets/hepta-build-identity.json"]==take(BUILD/"out/hepta-build-identity.json")
     and sha(asset_raw)==build["build_identity"]["sha256"]
     and strict(asset_raw)["version_code"]==CONFIG["version_code"] and same(strict(asset_raw)["source_inputs"],compiler_inputs),
     "actual compiler inputs bound to packaged build identity")

manifest=ET.fromstring(final_source["AndroidManifest.xml"]);android="{http://schemas.android.com/apk/res/android}"
need(manifest.get("package")=="org.trillionnium.hepta.local" and manifest.get(android+"versionCode")==str(CONFIG["version_code"])
     and manifest.get(android+"versionName")==CONFIG["version_name"],"exact current package version source")
uses=[n for n in manifest if n.tag.startswith("uses-permission")]
need(len(uses)==1 and uses[0].tag=="uses-permission"
     and uses[0].attrib=={android+"name":CONFIG["permissions"][0]},"exact offline source permission")
app=manifest.find("application")
need(app is not None and app.get(android+"debuggable")=="true" and app.get(android+"allowBackup")=="false"
     and app.get(android+"extractNativeLibs")=="true" and app.get(android+"usesCleartextTraffic")=="false"
     and not manifest.findall("application/provider") and not manifest.findall("application/receiver"),
     "current app extraction/backup/network/component scope")
service=manifest.find("application/service")
need(service is not None and service.get(android+"permission")=="android.permission.BIND_ACCESSIBILITY_SERVICE",
     "platform guarded accessibility service")
source_queries={"packages":sorted(n.get(android+"name") for n in manifest.findall("queries/package")),
                "intents":sorted(sorted((n.tag,n.get(android+"name")) for n in item)
                                 for item in manifest.findall("queries/intent"))}
need(same(source_queries,base["manifest_explicit_queries"]),"current exact original visibility queries")

git_raw,publication_raw,git_map,publication=verify_publication(final_source,core,host_map_raw)
source_binding={"schema":"hepta.v56-published-source-binding.v1",
    "source_commit":CONFIG["source_commit"],"source_tree":CONFIG["source_tree"],
    "base_source_commit":CONFIG["publication_base_source_commit"],"expected_prior_head":CONFIG["expected_prior_head"],
    "source_file_count":CONFIG["source_count"],"source_inventory_sha256":CONFIG["final_inventory"]["sha256"],
    "original_compiler_source_inventory_sha256":CONFIG["compiled_source_inventory_sha256"],
    "actual_compiler_inputs":CONFIG["compiler_input_count"],"actual_compiler_inputs_unchanged":True,
    "test_only_post_compile_delta":sidecar,"compiled_and_published_source_byte_identical":True,
    "original_precommit_host_stage_sha256":sha(core_raw),
    "original_android_stage_sha256":sha(build_raw),"actual_host_blob_map_sha256":sha(host_map_raw),
    "git_source_map_sha256":sha(git_raw),"publication_receipt_sha256":sha(publication_raw),
    "source_commit_bound_after_exact_host_run":True,"original_host_receipt_rewritten":False,
    "original_android_receipt_rewritten":False,"tests_rerun_by_binding":False,"phone_contacted":False}

original_runner=take_sha(CONFIG["old_runner"]["path"],CONFIG["old_runner"]["sha256"])
context=runpy.run_path(CONFIG["old_runner"]["path"],run_name="qualified_original_signer_context")
need(context["CERT"]==CERT,"same qualified existing public signer")
old_context_source=context["source_check"]()
key,key_metadata,expected_key_metadata,jdk=context["existing_signer_and_jdk"]()
need(str(jdk)==CONFIG["jdk"] and key_metadata()==expected_key_metadata,"same qualified JDK/existing key")
env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",JAVA_HOME=str(jdk),PATH=str(jdk/"bin")+":"+os.environ.get("PATH",""))
for name in ("CLASSPATH","JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS"):
    env.pop(name,None)
for facts in originals:unchanged(facts)
started=time.time()
ROOT.mkdir(mode=0o700)  # FIRST MUTATION, outside handler. A late invocation cannot write the winner's evidence.
steps,written=[],[]


report={
    "schema":"hepta.isolated-v56-assembly.v1","all_pass":False,"exit_code":1,
    "version_code":CONFIG["version_code"],"version_name":CONFIG["version_name"],"package":"org.trillionnium.hepta.local",
    "source_commit":CONFIG["source_commit"],"source_tree":CONFIG["source_tree"],
    "source_file_count":CONFIG["source_count"],"source_inventory_sha256":CONFIG["final_inventory"]["sha256"],
    "compiler_source_inventory_sha256":CONFIG["compiled_source_inventory_sha256"],
    "actual_compiler_source_inputs":CONFIG["compiler_input_count"],"actual_compiler_inputs_bound_to_signed_asset":True,
    "java_source_count":CONFIG["java_source_count"],"application_class_count":build["class_count"],
    "pocket4_build_receipt_sha256":sha(receipt_raw),"pocket4_build_result_sha256":sha(build_raw),
    "build_execution_host":"pocket4","android_java_compiled_in_original_build":True,
    "java_dex_or_resources_recompiled_by_signer":False,"native_recompiled_here":False,
    "ndk_or_clang_executed_here":False,"native_payloads_reused_from_signed54":True,
    "native_baseline_signed_receipt_sha256":sha(base_raw),"historical_native_static_receipt_sha256":sha(old_static_raw),
    "packaged_library_count":17,"library_pins":CONFIG["native_pins"],
    "unchanged_native_library_count":17,"unchanged_native_library_pins":CONFIG["native_pins"],
    "native_libraries_identical_to_formal_v54":True,"native_libraries_identical_to_formal_v53":True,
    "worker_sha256":CONFIG["worker"]["sha256"],
    "native_worker_binding":{
        "schema":"hepta.preserved-local-worker-binding.v1","name":"libhepta_local_runner.so",
        "sha256":CONFIG["worker"]["sha256"],"previous_sha256":CONFIG["worker"]["sha256"],
        "native_worker_updated":False,"native_recompiled_here":False,"cancellation_sdk_phone_verified":False,
        "source_commit":CONFIG["source_commit"],"actual_compiler_receipt_sha256":sha(receipt_raw),
        "actual_compiler_receipt_kind":"pocket4_java_native_reuse",
        "original_native_compiler_receipt_sha256":native["original_compiler_receipt"]["sha256"],
        "actual_mac_stage_sha256":native["original_actual_mac_stage"]["sha256"],
        "generated_worker_sha256":CONFIG["worker_generated_sha256"],
        "upstream_worker_sha256":base["native_worker_binding"]["upstream_worker_sha256"]},
    "host_check_records":101,"host_input_count":CONFIG["host_input_count"],"nested_completion_stage_count":18,
    "nested18_are_within_core101":True,"host_checks_sha256":sha(host_raw),
    "pre_commit_host_receipt_sha256":sha(core_raw),"stage_result_sha256":sha(core_raw),
    "nested_completion_receipt_sha256":sha(nested_raw),
    "source_commit_bound_after_exact_host_run":True,"source_commit_binding_sha256":sha(encoded(source_binding)),
    "post_compile_test_only_delta":sidecar,"compiled_and_published_source_byte_identical":True,
    "prior_main55_unsigned_receipt_sha256":sha(prior55_raw),"tests_rerun_by_signer":False,
    "previous_signed55_receipt_sha256":sha(prior55_signed_raw),
    "previous_signed55_source_commit":CONFIG["predecessor_release_source_commit"],
    "query_host_cases":query["cases"]["cases"],"query_host_assertions":query["cases"]["assertions"],
    "query_host_result_sha256":sha(query_raw),"query_exact_current_dispatch_methods_bound":True,
    "external_query_runner":{"path":str(BUILD/"query40-runner.py"),**CONFIG["query_runner"],
        "repository_original":CONFIG["query_runner_original"],"count_only_patch":CONFIG["query_runner_count_adapter"],
        "source_inventory_modified":False,"test_case_assertions_modified":False,
        "repository_original_count_guard_known_incompatible":True},
    "real_web_class_cases":80,"real_web_class_assertions":92,
    "composition_host_cases":web_reports["composition43"]["report"]["cases"],
    "composition_host_assertions":web_reports["composition43"]["report"]["assertions"],
    "calendar_native_cases":13,"calendar_native_assertions":1001,
    "current_web_regression_result_sha256":{name:sha(x["raw"]) for name,x in web_reports.items()},
    "existing_web_regression_receipt_sha256":sha(web_raw),
    "composition43_explicit_fixture_successor":True,
    "focused_consumer_cases":20,"focused_consumer_assertions":60,
    "focused_arm_cases":19,"focused_arm_assertions":98,"focused39_receipt_sha256":sha(focused_raw),
    "identity_cases":10,"identity_assertions":218,"identity_receipt_sha256":sha(identity_gate_raw),
    "helper_required_version_code":6,"helper_protocol":"v4",
    "flight_query_production_implemented":True,"actual_flight_results_provider_ready":False,
    "flight_query_phone_executed":False,"web_query_executed":False,"web_results_verified":False,
    "web_binder_phone_verified":False,"shopping_provider_phone_verified":False,
    "cancellation_sdk_phone_verified":False,"android_runtime_tested":False,
    "installed_on_phone":False,"phone_contacted":False,"business_verified":False,
    "ordinary_app_uid_accelerator_qualified":False,
    "new_key_created":False,"key_material_exported":False,"existing_key_metadata_unchanged":False,
    "signer_proof_path":str(context["SIGNER_PROOF"]),
    "signer_proof_sha256":context["SIGNER_PROOF_SHA256"],
    "complete_jdk_receipt_sha256":context["JDK_PROOF_SHA256"],"java_home":str(jdk),
    "matches_previously_recorded_signer":False,"signer_certificate_sha256":None,
    "source_files_unchanged":False,"actual_build_identity_sha256":sha(asset_raw),
    "permissions":CONFIG["permissions"],"abi":["arm64-v8a"],
    "manifest_explicit_queries":source_queries,"dependencies_downloaded":False,
    "source_publication_receipt_sha256":sha(publication_raw),"git_source_map_sha256":sha(git_raw),
    "started_epoch":started,"steps":steps
}
delivery={
    "UNSIGNED.apk":unsigned_raw,"BUILD-RESULT.json":build_raw,"COMPILER-RESULT.json":receipt_raw,
    "PREDECESSOR55-SIGNED-RESULT.json":prior55_signed_raw,"PREDECESSOR55-BUILD-RESULT.json":prior55_raw,
    "COMPILED-AGGREGATE.json":aggregate_raw,"COMPILED-SOURCE-INVENTORY.json":compiled_inventory_raw,
    "FINAL-AGGREGATE.json":final_aggregate_raw,"FINAL-SOURCE-INVENTORY.json":final_inventory_raw,
    "CORE-RESULT.json":core_raw,"HOST-CHECKS.json":host_raw,"NESTED-COMPLETION.json":nested_raw,
    "CORE-SOURCE-BLOB-MAP.json":host_map_raw,"WEB-RESULT.json":web_raw,
    "WEB-FIXTURE-PACKET.json":web_packet_raw,"QUERY40-RESULT.json":query_raw,
    "FOCUSED39-RESULT.json":focused_raw,"IDENTITY10-RESULT.json":identity_gate_raw,
    "SDK-RESULT.json":sdk_raw,"NATIVE-REUSE.json":native_raw,
    "BASE-SIGNED-RESULT.json":base_raw,"BASE-NATIVE-STATIC-ACCEPTANCE.json":old_static_raw,
    "GIT-SOURCE-BLOB-MAP.json":git_raw,"PUBLICATION.json":publication_raw,
    "SOURCE-COMMIT-BINDING.json":encoded(source_binding),
    "provenance/BUILD.py":builder_raw,"provenance/CORE.py":core_stage_raw,
    "provenance/WEB.py":web_stage_raw,"provenance/COMPILER-INPUTS.json":compiler_input_raw,
    "provenance/UNSIGNED-PAYLOADS.json":payload_raw
}
for name,value in web_reports.items():delivery["web/"+name+"-RESULT.json"]=value["raw"]
failure=None
try:
    OUT.mkdir(mode=0o700);INPUT.mkdir(mode=0o700)
    written.append(write_new(ROOT/"SIGNER.py",signer_raw))
    for name,value in delivery.items():written.append(write_new(INPUT/relative(name),value))
    delivery_rows=rows(delivery);written.append(write_new(ROOT/"INPUT-INVENTORY.json",encoded(delivery_rows)))
    report["input_inventory_sha256"]=sha(encoded(delivery_rows))
    apk=OUT/"hepta-local-0.56.0.apk"
    commands=[
        ("sign",[CONFIG["apksigner_executable"],"sign","--ks",key,"--ks-key-alias","hepta-local-debug",
             "--ks-pass","pass:android","--key-pass","pass:android","--min-sdk-version","30","--out",apk,INPUT/"UNSIGNED.apk"]),
        ("verify",[CONFIG["apksigner_executable"],"verify","--verbose","--print-certs",apk]),
        ("badging",[CONFIG["aapt2"]["path"],"dump","badging",apk]),
        ("permissions",[CONFIG["aapt2"]["path"],"dump","permissions",apk]),
        ("manifest",[CONFIG["aapt2"]["path"],"dump","xmltree",apk,"--file","AndroidManifest.xml"]),
        ("accessibility",[CONFIG["aapt2"]["path"],"dump","xmltree",apk,"--file","res/xml/hepta_accessibility_service.xml"])
    ]
    for name,argv in commands:run_step(name,argv,120,ROOT,env)
    verify_text=read_regular(ROOT/"verify.stdout")[0].decode("utf-8","strict")
    certs=re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$",verify_text,re.MULTILINE)
    need([x.lower() for x in certs]==[CERT],"actual sole same existing signing certificate")
    badging=read_regular(ROOT/"badging.stdout")[0].decode("utf-8","strict")
    permission_text=read_regular(ROOT/"permissions.stdout")[0].decode("utf-8","strict")
    manifest_text=read_regular(ROOT/"manifest.stdout")[0].decode("utf-8","strict")
    accessibility_text=read_regular(ROOT/"accessibility.stdout")[0].decode("utf-8","strict")
    match=re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'",badging,re.MULTILINE)
    need(match is not None and match.groups()==("org.trillionnium.hepta.local",str(CONFIG["version_code"]),CONFIG["version_name"])
         and "sdkVersion:'30'" in badging and "targetSdkVersion:'35'" in badging
         and "native-code: 'arm64-v8a'" in badging
         and "launchable-activity: name='org.trillionnium.hepta.local.MainActivity'" in badging,
         "actual signed package/version/SDK/ABI/launcher")
    actual_permissions=[]
    for line in permission_text.splitlines():
        if line.strip().startswith("uses-permission"):
            item=re.fullmatch(r"uses-permission: name='([^']+)'",line.strip())
            need(item is not None,"exact signed permission row")
            actual_permissions.append(item.group(1))
    need(actual_permissions==CONFIG["permissions"] and "android.permission.INTERNET" not in manifest_text,
         "exact offline main permission")
    need(same(compiled_visibility(manifest_text),source_queries),"actual signed compiled visibility equals source")
    for value in ("libadsprpc.so","libcdsprpc.so","libOpenCL.so",
                  "android.permission.BIND_ACCESSIBILITY_SERVICE","android.intent.category.LAUNCHER"):
        need(value in manifest_text,"actual signed declaration: "+value)
    for value in ("canTakeScreenshot","canRetrieveWindowContent","canPerformGestures"):
        need(value in accessibility_text,"actual signed accessibility metadata: "+value)
    signed_raw,signed_facts=read_regular(apk);signed_members=apk_members(signed_raw);signed_layout=zip_layout(signed_raw)
    need(all(signed_members.get(n)==v for n,v in unsigned_members.items()),"signing preserves all22 compiled payloads")
    added=set(signed_members)-set(unsigned_members)
    need(len(signed_members)==25 and len(added)==3
         and all(re.fullmatch(r"META-INF/[A-Za-z0-9_.-]+\.(?:SF|RSA|DSA|EC)|META-INF/MANIFEST.MF",n) for n in added),
         "only the actual three expected signature ZIP members added")
    need(signed_members["assets/hepta-build-identity.json"]==asset_raw,"actual build identity survives signing")
    for name in CONFIG["native_pins"]:
        need(signed_members["lib/arm64-v8a/"+name]==base_members["lib/arm64-v8a/"+name],
             "every signed native payload remains byte-identical to qualified54")
    resource=resource_summary(signed_layout)
    static={
        "schema":"hepta.local-model.static-acceptance.v4","all_pass":True,
        "apk":str(apk),"apk_bytes":len(signed_raw),"apk_sha256":sha(signed_raw),
        "package":"org.trillionnium.hepta.local","version_code":CONFIG["version_code"],"version_name":CONFIG["version_name"],
        "source_commit":CONFIG["source_commit"],"source_inventory_sha256":CONFIG["final_inventory"]["sha256"],
        "permissions":actual_permissions,"abi":["arm64-v8a"],"debuggable":True,"extract_native_libs":True,
        "compile_sdk":34,"min_sdk":30,"target_sdk":35,
        "actual_build_identity_asset":"assets/hepta-build-identity.json","actual_build_identity_sha256":sha(asset_raw),
        "actual_compiler_inputs":CONFIG["compiler_input_count"],"pocket4_compiler_receipt_sha256":sha(receipt_raw),
        "signer_certificate_sha256":CERT,"existing_installation_signer_match_proven":True,
        "new_development_signing_key_created":False,"key_material_exported":False,
        "native_recompiled_here":False,"native_static_commands_rerun_here":False,
        "all17_native_payloads_byte_identical_to_signed54":True,
        "historical_native_static_receipt_sha256":sha(old_static_raw),
        "historical_native_static_source_apk_sha256":sha(base_apk_raw),
        "native_static_provenance":"exact signed54 payload reuse; original ELF, linkage and independent pin checks remain historical",
        "libraries":[{"name":n,"bytes":len(signed_members["lib/arm64-v8a/"+n]),"sha256":CONFIG["native_pins"][n],
            "compiled_here":False,"provenance":"byte-identical signed54 APK payload",
            "original_provenance":old_native[n]["provenance"]} for n in sorted(CONFIG["native_pins"])],
        "unchanged_model_configuration_source_sha256":sha(final_source["tools/model_profiles.py"]),
        "inherited_model_configuration":{k:old_static[k] for k in ("runtime","model","default_compute","default_context",
            "model_profile_default","model_profiles","llama_source_commit","fallback_allowed","dsp_arch")},
        "resources_arsc_zip_layout":resource,
        "accessibility_service_guarded_by_bind_permission":True,
        "actual_compiled_visibility":source_queries,
        "installed_on_phone":False,"ordinary_app_uid_accelerator_qualified":False,
        "actual_flight_results_provider_ready":False,"web_query_executed":False,"web_results_verified":False,
        "business_verified":False,"phone_contacted":False}
    static_raw=encoded(static)
    written.append(write_new(OUT/"STATIC-ACCEPTANCE.json",static_raw));written.append(signed_facts)
    report.update(all_pass=True,exit_code=0,apk=str(apk),apk_bytes=len(signed_raw),apk_sha256=sha(signed_raw),
        unsigned_apk_sha256=sha(unsigned_raw),static_acceptance_sha256=sha(static_raw),
        static_acceptance_schema=static["schema"],resources_arsc_zip_layout=resource,
        signer_certificate_sha256=CERT,matches_previously_recorded_signer=True,
        all_compiled_members_unchanged=True,
        signed_member_sha256={n:sha(v) for n,v in sorted(signed_members.items())},
        signed_zip_layout=signed_layout)
except BaseException as error:
    failure=type(error).__name__+": "+str(error)
    report.update(all_pass=False,exit_code=1,error=failure)
    try:written.append(write_new(ROOT/"ERROR.txt",traceback.format_exc().encode("utf-8")))
    except BaseException as logging_error:
        report["error_record_failure"]=type(logging_error).__name__+": "+str(logging_error)
finally:
    try:
        for step in steps:
            unchanged(step["stdout"]);unchanged(step["stderr"])
            need(step.get("owned_group_cleanup_error") is None,"signing child cleanup must not report an error")
        for facts in originals:unchanged(facts)
        for facts in written:unchanged(facts)
        need(snapshot(BUILD/"source")== (compiled_source,compiled_facts),"all original Android source bytes and identities unchanged")
        need(snapshot(SOURCE)==(final_source,final_facts),"all final source bytes and identities unchanged")
        need(snapshot(BASE/"source")== (base_source,base_facts),"all signed54 source bytes and identities unchanged")
        need(same(identity_namespace["source_inputs"](SOURCE),compiler_inputs)
             and same(identity_namespace["source_inputs"](BUILD/"source"),compiler_inputs),
             "same current compiler inputs remain in both trees")
        need(key_metadata()==expected_key_metadata and context["source_check"]()==old_context_source,
             "qualified existing key metadata and original51 source unchanged")
        need(take_sha(CONFIG["old_runner"]["path"],CONFIG["old_runner"]["sha256"])==original_runner,
             "qualified original signer entry unchanged")
        report.update(source_files_unchanged=True,compiler_source_files_unchanged=True,
             all_inputs_unchanged=True,existing_key_metadata_unchanged=True,
             previous_signed54_source_apk_receipt_unchanged=True,
             previous_signed55_source_apk_receipt_unchanged=True)
    except BaseException as integrity_error:
        report.update(all_pass=False,exit_code=1,source_files_unchanged=False,all_inputs_unchanged=False,
             integrity_error=type(integrity_error).__name__+": "+str(integrity_error))
    report["finished_epoch"]=time.time();report["elapsed_seconds"]=report["finished_epoch"]-started
    report["runner_sha256"]=sha(signer_raw);report["original_guard_count"]=len(originals)
    report["all_pass"]=bool(report["all_pass"] and failure is None and report["source_files_unchanged"])
    if not report["all_pass"]:report["exit_code"]=1
    result_raw=encoded(report);result_facts=write_new(ROOT/"RESULT.json",result_raw)
    c=zlib.compressobj(level=9,method=zlib.DEFLATED,wbits=-15,memLevel=9,strategy=zlib.Z_FIXED)
    body=c.compress(result_raw)+c.flush()
    packed=b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"+body+struct.pack("<II",zlib.crc32(result_raw)&0xffffffff,len(result_raw)&0xffffffff)
    need(gzip.decompress(packed)==result_raw,"complete signed result fixed-gzip roundtrip")
    packed_facts=write_new(ROOT/"RESULT.json.fixed.gz",packed)
    write_new(ROOT/"RESULT.json.fixed.gz.base64",base64.b64encode(packed))
    summary={k:report[k] for k in ("all_pass","exit_code","version_code","version_name","source_commit","source_tree",
        "source_file_count","source_inventory_sha256","actual_compiler_source_inputs","java_source_count",
        "application_class_count","pocket4_build_receipt_sha256","pocket4_build_result_sha256",
        "native_recompiled_here","host_check_records","host_input_count","nested_completion_stage_count",
        "helper_required_version_code","helper_protocol","actual_flight_results_provider_ready",
        "query_host_cases","query_host_assertions","real_web_class_cases","composition_host_cases","calendar_native_cases",
        "source_files_unchanged","signer_certificate_sha256","phone_contacted","business_verified")}
    for name in ("apk","apk_bytes","apk_sha256","error","integrity_error","static_acceptance_sha256","resources_arsc_zip_layout"):
        if name in report:summary[name]=report[name]
    summary.update(schema="hepta.main56-formal-sign-summary.v1",result=result_facts,
        receipt_representation=dict(packed_facts,encoding="gzip-fixed",base64_path=str(ROOT/"RESULT.json.fixed.gz.base64")))
    summary_facts=write_new(ROOT/"SUMMARY.json",encoded(summary))
    print(json.dumps({"all_pass":report["all_pass"],"result":result_facts,"summary":summary_facts,
          "apk":report.get("apk"),"apk_sha256":report.get("apk_sha256"),"error":report.get("error"),
          "phone_contacted":False},ensure_ascii=False,sort_keys=True),flush=True)
raise SystemExit(0 if report["all_pass"] else 1)
