#!/usr/bin/env python3
"""Run existing Web host gates against the exact Main57 source.
The actual56 80/70/13 assertions and the actual57 nine appended cases are retained.
Only the host JSON null representation is adapted in explicitly derived capture
copies; complete original raw records and production binding checks are unchanged.
Four direct compatibility assertions join the existing positive case.
Actual counts come from child reports.
No SDK, Android build, core101 pass, signing, phone or model call is required.
"""
import gzip,hashlib,json,os,signal,stat,subprocess,sys,time,traceback
from pathlib import Path,PurePosixPath

CONFIG=json.loads("{\"schema\":\"hepta.main57-existing-web-regression-stage-config.v1\",\"root\":\"/home/alex/hepta-local-007f-20261111/v57-main-web-regression-host-r2\",\"source_root\":\"/home/alex/hepta-local-007f-20261111/v57-main-core101-materialized-host-r1/source\",\"materialized_root\":\"/home/alex/hepta-local-007f-20261111/v57-main-core101-materialized-host-r1\",\"decoded_input\":{\"bytes\":364848,\"sha256\":\"8ac71189842cde32a349e39a89da909fd7d759b29d6b14eba66120a5b65babca\",\"git_blob_sha\":\"037096bebe3cf4776d588a2198fa2376b21453a7\"},\"aggregate\":{\"git\":\"517e61599073eb264c5e52871570d49e7af2d798\",\"bytes\":1459826,\"sha256\":\"b98bb0f97ad5b25423387c4e3f8734aec7d4f8c2d1044335af039e0dd1c57cc3\",\"inventory_sha256\":\"7e6b339f65f830245907124de97d4132211c057edbf38fda3b2acc14442a54ce\"},\"inventory\":{\"bytes\":103795,\"sha256\":\"22d32f2de9ecd5690e1dfe7de8fa682b3a0469584ade1ec83ac69bf6558d10b6\"},\"java\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/java\",\"bytes\":14544,\"sha256\":\"bb70208200cb6538b877d80478141194a716edb591f4910ec106589291e99196\"},\"javac\":{\"path\":\"/home/alex/razr-local-ai-20261109-82d1243e/host-jdk17/extracted/usr/lib/jvm/java-17-openjdk-amd64/bin/javac\",\"bytes\":14592,\"sha256\":\"2aaf03d13aeb80b8269696f2dcd9f4937d7366bbc68f91fdc703cf157e8f39c4\"},\"json\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/host-json/json-20240303.jar\",\"bytes\":78332,\"sha256\":\"3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed\"},\"orgjson_ready\":{\"path\":\"/home/alex/hepta-local-007f-20261111/v55-helper6-p4-public-inputs-r1/ORGJSON-READY.json\",\"bytes\":1289,\"sha256\":\"37f3b1790fce237f6339cab159015da7937e6517cc4a97f4dc16443c74e01d7b\"},\"expected_gates\":[{\"name\":\"evidence80\",\"class_name\":\"org.trillionnium.hepta.local.WebFlightEvidenceHostTest\",\"prior_file\":\"WEB-RESULT.json\",\"cases\":80,\"assertions\":92,\"schema\":\"hepta.web-flight-evidence-host-cases.v1\"},{\"name\":\"composition43\",\"class_name\":\"org.trillionnium.hepta.local.WebTaskCompositionHostTest\",\"prior_file\":\"COMPOSITION-RESULT.json\",\"cases\":79,\"assertions\":215,\"schema\":\"hepta.v55-web-task-composition-host.v1\"},{\"name\":\"calendar13\",\"class_name\":\"org.trillionnium.hepta.local.WebCalendarNativeHostTest\",\"prior_file\":\"CALENDAR-NATIVE-RESULT.json\",\"cases\":13,\"assertions\":1001,\"schema\":\"hepta.csair-calendar-native-host.v1\"}],\"case_name_mapping\":{\"v3_receipt_and_real_composition\":\"v4_receipt_and_real_composition\",\"duplicate_native_resource_id_blocks_even_disabled\":\"duplicate_native_card_description_blocks_even_disabled\",\"duplicate_dom_id_blocks_product_link\":\"ambiguous_observed_region_blocks_product_link\"},\"key\":\"007f-v57-main-existing-web-regression-host-r2-json-null\",\"prior_web\":{\"root\":\"/home/alex/hepta-local-007f-20261111/v56-main-web-regression-host-r2\",\"result\":{\"bytes\":47337,\"sha256\":\"220ccb705ba17797d7403c26c1a9bcb438f46c8ea83e017c617a343d27232f7c\",\"git_blob_sha\":\"a444cbac9951180a7dde73bee2984fdf063ee30a\"},\"stage\":{\"bytes\":131893,\"sha256\":\"814e327adb50509d35a03a89f96ab085c3b4249c526d3b041ef3885e59e35391\",\"git_blob_sha\":\"447b3ca01169ed691440ca866896d07f0c7b665f\"},\"packet\":{\"bytes\":260128,\"sha256\":\"3687b09656e60a808ebdce1430951e04741581e9ddd0d2faa7f5c36220ed24b7\",\"git_blob_sha\":\"1153d7e55c4051ecf6e4c018defe43d26ff51fd2\"}},\"source_file_count\":595,\"fixture_count\":6,\"production_java_count\":44,\"compilation_unit_count\":52,\"added_case_names\":[\"flight_observation_actual56_old_digest_failure_reproduced\",\"flight_observation_actual_retained_rows_cannot_replace_complete_native\",\"flight_observation_actual_raws_with_explicit_synthetic_complete_native\",\"flight_observation_window_selection_ime_and_root_changes_rejected\",\"flight_observation_target_unretained_and_retained_semantics_rejected\",\"flight_observation_truncated_or_incomplete_native_rejected\",\"flight_observation_four_raw_equality_and_homepage_scope_required\",\"flight_observation_capture_epoch_binding_and_order_rejected\",\"flight_observation_geometry_and_actual_native_ancestor_must_match\"],\"prior_expected_gates\":[{\"name\":\"evidence80\",\"class_name\":\"org.trillionnium.hepta.local.WebFlightEvidenceHostTest\",\"prior_file\":\"WEB-RESULT.json\",\"cases\":80,\"assertions\":92,\"schema\":\"hepta.web-flight-evidence-host-cases.v1\"},{\"name\":\"composition43\",\"class_name\":\"org.trillionnium.hepta.local.WebTaskCompositionHostTest\",\"prior_file\":\"COMPOSITION-RESULT.json\",\"cases\":70,\"assertions\":178,\"schema\":\"hepta.v55-web-task-composition-host.v1\"},{\"name\":\"calendar13\",\"class_name\":\"org.trillionnium.hepta.local.WebCalendarNativeHostTest\",\"prior_file\":\"CALENDAR-NATIVE-RESULT.json\",\"cases\":13,\"assertions\":1001,\"schema\":\"hepta.csair-calendar-native-host.v1\"}],\"prior_failed56\":{\"root\":\"/home/alex/hepta-local-007f-20261111/v56-main-web-regression-host-r1\",\"result\":{\"bytes\":29724,\"sha256\":\"f9bf137d294e385c6cd85987a10ba682fdb9bb8415fa51a005e5ff871914eec4\",\"git_blob_sha\":\"30962e2f30d7b0309aaacd44d67e795e436752ee\"},\"stage\":{\"bytes\":124611,\"sha256\":\"e315704ec4f11f6e37cafc158dcbd831ad713efc376289100cdc48d35826eba6\",\"git_blob_sha\":\"7bf26d7df0b20c2079695980303ff2237add2465\"},\"packet\":{\"bytes\":255644,\"sha256\":\"2bdec480247b39ab2a0ec566d0999919d8723d52f55bc81f9df7beb9b1129ee5\",\"git_blob_sha\":\"bb76eb9c16289058b5d2297edb9eb7d51118c69b\"},\"composition_stderr\":{\"bytes\":1012,\"sha256\":\"242466b11bebf08dc48246b949fb506dc8bde71bba0c7be798c0fa98d6b0ef75\",\"git_blob_sha\":\"b437fd9854666141f78911df0a7b53c9de376165\"},\"aggregate\":{\"git\":\"660335b7f19f519af4cfd168ebee186f1a4693b9\",\"bytes\":1416544,\"sha256\":\"38baa995ee76520e1a9ff7a14baf51afdbd4f1af53f747ce7a0d114ef4809c90\",\"inventory_sha256\":\"71ad8ef4ea1023850c950282d57bcae3e73877e5e6a7ad582b58951e1ba7001e\"}},\"prior_failed57\":{\"root\":\"/home/alex/hepta-local-007f-20261111/v57-main-web-regression-host-r1\",\"result\":{\"bytes\":30361,\"sha256\":\"d66b4dcaf0eed2b650df9e88928a32ab5145608f600b868864c3925011d72532\",\"git_blob_sha\":\"4f436784332e6a1bf7200cbaf105c28e17a55b29\"},\"stage\":{\"bytes\":147219,\"sha256\":\"2891fa5a6e6b5ace614d73593f5108f129a738cd4b4c3c7a487cbf5fa361d34c\",\"git_blob_sha\":\"012f77d66f782cb9787627c0217b0fcff64b99df\"},\"packet\":{\"bytes\":357185,\"sha256\":\"ba0832568ca64be933ba31acd3646d0c63550f6202abeecf49dd12cecb52f110\",\"git_blob_sha\":\"cd1d6fe815602cfd0909e7e6cf771a0c46bd2529\"},\"composition_stderr\":{\"bytes\":1328,\"sha256\":\"7658bf88db3934278dfe73f1795f6ca30b272345c19ab600273fd22d9d6153d2\",\"git_blob_sha\":\"b6bab9eabba9dfcc7ffc2435e8f6b7b99c356e10\"}}}")
PACKET_DELTA=json.loads("{\"schema\":\"hepta.main57-web-host-json-null-delta.v1\",\"base\":{\"bytes\":357185,\"sha256\":\"ba0832568ca64be933ba31acd3646d0c63550f6202abeecf49dd12cecb52f110\",\"git_blob_sha\":\"cd1d6fe815602cfd0909e7e6cf771a0c46bd2529\"},\"result\":{\"bytes\":364848,\"sha256\":\"8ac71189842cde32a349e39a89da909fd7d759b29d6b14eba66120a5b65babca\",\"git_blob_sha\":\"037096bebe3cf4776d588a2198fa2376b21453a7\"},\"helper\":{\"path\":\"tests/web-flight/WebFlightNativeStabilityHostCases.java\",\"before\":{\"bytes\":148415,\"sha256\":\"9d0641663811526ebfacef8f8695727ea95c73825abfd422b5123ab64bcf9067\",\"git_blob_sha\":\"0ca8e273164ea7dac5447cb1677d06af0bbe8dc3\"},\"after\":{\"bytes\":154154,\"sha256\":\"e0cc2a474545623cd8e79aaa73afb130f5dc8733efc43f521ad909df0ec384a2\",\"git_blob_sha\":\"348d62b28b8930b05d3f401c06557692e7c3081e\"},\"origin_before\":\"new test-only methods called by the existing Composition main; actual DOM/retained AX with explicit synthetic full-traversal extension; Main57 appends nine read-only observation-bracket cases with four complete actual raw originals and explicit synthetic full-native arrays\",\"origin_after\":\"new test-only methods called by the existing Composition main; actual DOM/retained AX with explicit synthetic full-traversal extension; Main57 appends nine read-only observation-bracket cases with four complete actual raw originals and explicit synthetic full-native arrays; explicit desktop JSON-java null-only derived capture compatibility, original four archives unchanged\",\"ordered_replacements\":[{\"before\":\"    private static JSONObject observationProof(JSONObject input,JSONObject before,JSONArray beforeNative,\\n\",\"after\":\"    /** Desktop-only JSON-java Map constructor compatibility for these archived captures.\\n     * Android wraps a Java-null Map value as JSONObject.NULL; the pinned desktop\\n     * 20240303 constructor omits that key. Validate the complete original OWNER\\n     * compiler evidence first, then derive a copy with only that representation\\n     * changed. This never changes archived bytes or production binding admission. */\\n    private static JSONObject hostObservationCapture(JSONObject original)throws Exception{\\n        JSONObject binding=original.getJSONObject(\\\"binding\\\"),authorization=binding.getJSONObject(\\\"authorization\\\");\\n        Map<String,Object> compiled=TaskAuthorization.parse(binding.getString(\\\"owner\\\")).evidence();\\n        if(!compiled.containsKey(\\\"find_query\\\")||compiled.get(\\\"find_query\\\")!=null\\n                ||!authorization.has(\\\"find_query\\\")||authorization.get(\\\"find_query\\\")!=JSONObject.NULL)\\n            throw new IllegalArgumentException(\\\"exact archived explicit-null find_query required\\\");\\n        JSONObject hostAuthorization=new JSONObject(compiled);\\n        if(hostAuthorization.has(\\\"find_query\\\"))\\n            throw new IllegalArgumentException(\\\"pinned desktop Map-null constructor semantics changed\\\");\\n        JSONObject androidAuthorization=new JSONObject(hostAuthorization.toString()).put(\\\"find_query\\\",JSONObject.NULL);\\n        if(!org.trillionnium.hepta.webprotocol.WebEvidenceBinding.canonical(androidAuthorization).equals(\\n                org.trillionnium.hepta.webprotocol.WebEvidenceBinding.canonical(authorization)))\\n            throw new IllegalArgumentException(\\\"complete archived original OWNER compiler evidence differs\\\");\\n        JSONObject result=copy(original);\\n        result.getJSONObject(\\\"binding\\\").getJSONObject(\\\"authorization\\\").remove(\\\"find_query\\\");\\n        JSONObject restored=copy(result);\\n        restored.getJSONObject(\\\"binding\\\").getJSONObject(\\\"authorization\\\").put(\\\"find_query\\\",JSONObject.NULL);\\n        if(!org.trillionnium.hepta.webprotocol.WebDomCanonical.same(restored,original))\\n            throw new IllegalArgumentException(\\\"host copy changed more than the one null representation\\\");\\n        org.trillionnium.hepta.webprotocol.WebTaskPurpose.requireBinding(result.getJSONObject(\\\"binding\\\"));\\n        return result;\\n    }\\n    private static boolean hostObservationCaptureRejects(JSONObject original)throws Exception{\\n        try{hostObservationCapture(original);return false;}\\n        catch(IllegalArgumentException|org.json.JSONException expected){return true;}\\n    }\\n    private static JSONObject observationProof(JSONObject input,JSONObject before,JSONArray beforeNative,\\n\",\"before_sha256\":\"9d0641663811526ebfacef8f8695727ea95c73825abfd422b5123ab64bcf9067\",\"after_sha256\":\"d161717b383ea05264b7e3ca6bdb6bcc954753db3a27749e6639b920f2ffa675\",\"count\":1},{\"before\":\"        final JSONObject first=new JSONObject(originals.getJSONObject(2).getString(\\\"raw_utf8\\\")).getJSONObject(\\\"capture\\\");\\n        final JSONObject last=new JSONObject(originals.getJSONObject(3).getString(\\\"raw_utf8\\\")).getJSONObject(\\\"capture\\\");\",\"after\":\"        final JSONObject originalFirst=new JSONObject(originals.getJSONObject(2).getString(\\\"raw_utf8\\\")).getJSONObject(\\\"capture\\\");\\n        final JSONObject originalLast=new JSONObject(originals.getJSONObject(3).getString(\\\"raw_utf8\\\")).getJSONObject(\\\"capture\\\");\\n        final JSONObject first=hostObservationCapture(originalFirst),last=hostObservationCapture(originalLast);\",\"before_sha256\":\"d161717b383ea05264b7e3ca6bdb6bcc954753db3a27749e6639b920f2ffa675\",\"after_sha256\":\"851b00f84d7afa3b822d124db383c70a3063df977aa8a58258a433a08eae4117\",\"count\":1},{\"before\":\"            check(input.getBoolean(\\\"full_native_fixture_is_synthetic\\\"),\\\"positive full traversal is explicitly synthetic\\\");\\n        });\",\"after\":\"            check(input.getBoolean(\\\"full_native_fixture_is_synthetic\\\"),\\\"positive full traversal is explicitly synthetic\\\");\\n            check(originalFirst.getJSONObject(\\\"binding\\\").getJSONObject(\\\"authorization\\\").has(\\\"find_query\\\")\\n                    &&originalFirst.getJSONObject(\\\"binding\\\").getJSONObject(\\\"authorization\\\").get(\\\"find_query\\\")==JSONObject.NULL\\n                    &&!first.getJSONObject(\\\"binding\\\").getJSONObject(\\\"authorization\\\").has(\\\"find_query\\\"),\\n                    \\\"archived Android explicit-null remains; only the host copy uses omitted Java-null\\\");\\n            String originalBinding=org.trillionnium.hepta.webprotocol.WebDomCanonical.sha256(originalFirst.getJSONObject(\\\"binding\\\"));\\n            String hostBinding=org.trillionnium.hepta.webprotocol.WebDomCanonical.sha256(first.getJSONObject(\\\"binding\\\"));\\n            check(!originalBinding.equals(hostBinding)&&hostBinding.equals(proof.getString(\\\"binding_sha256\\\")),\\n                    \\\"derived proof binds the derived host capture, never the original FD binding hash\\\");\\n            JSONObject missing=copy(originalFirst);missing.getJSONObject(\\\"binding\\\").getJSONObject(\\\"authorization\\\").remove(\\\"find_query\\\");\\n            check(hostObservationCaptureRejects(missing),\\\"original missing null field is not accepted as an Android archive\\\");\\n            JSONObject nonnull=copy(originalFirst);nonnull.getJSONObject(\\\"binding\\\").getJSONObject(\\\"authorization\\\").put(\\\"find_query\\\",\\\"unexpected\\\");\\n            check(hostObservationCaptureRejects(nonnull),\\\"non-null original compiler field is never normalized away\\\");\\n        });\",\"before_sha256\":\"851b00f84d7afa3b822d124db383c70a3063df977aa8a58258a433a08eae4117\",\"after_sha256\":\"821a7b165cd46a6ad5783392cc494e6a559d8718e85d374423c9598c2f7e3b9e\",\"count\":1},{\"before\":\"                .put(\\\"existing_action_permit_tests_changed\\\",false).put(\\\"phone_query_or_business_verified\\\",false);\\n    }\\n    /** Desktop-only JSON-java\",\"after\":\"                .put(\\\"existing_action_permit_tests_changed\\\",false).put(\\\"phone_query_or_business_verified\\\",false)\\n                .put(\\\"host_json_map_null_compatibility\\\",new JSONObject()\\n                    .put(\\\"schema\\\",\\\"hepta.host-json-map-null-compatibility.v1\\\")\\n                    .put(\\\"desktop_json_version\\\",\\\"20240303\\\")\\n                    .put(\\\"changed_path\\\",\\\"capture.binding.authorization.find_query\\\")\\n                    .put(\\\"archived_value\\\",\\\"present explicit JSON null\\\")\\n                    .put(\\\"derived_host_value\\\",\\\"key omitted by desktop JSONObject(Map)\\\")\\n                    .put(\\\"complete_original_authorization_recompiled\\\",true)\\n                    .put(\\\"restore_single_null_field_recovers_complete_original_capture\\\",true)\\n                    .put(\\\"original_capture_fd_bytes_unchanged\\\",true)\\n                    .put(\\\"all_four_complete_dom_raw_values_unchanged\\\",true)\\n                    .put(\\\"production_require_binding_changed\\\",false)\\n                    .put(\\\"original_binding_sha256\\\",\\\"427b3e7743e044dc06643468e976ba0fd47c27b28b21203473fd31738937dc53\\\")\\n                    .put(\\\"derived_host_binding_sha256\\\",\\\"b56264d8894c3c3946437e9aab857c3ccf8453170396acfbff5e556411da1e69\\\")\\n                    .put(\\\"derived_captures_are_original_fd_records\\\",false));\\n    }\\n    /** Desktop-only JSON-java\",\"before_sha256\":\"821a7b165cd46a6ad5783392cc494e6a559d8718e85d374423c9598c2f7e3b9e\",\"after_sha256\":\"69d41da9a0e67d63170c74f39e0c7d3d3e79e831c254ce8e811201c3428ac842\",\"count\":1},{\"before\":\"        org.trillionnium.hepta.webprotocol.WebTaskPurpose.requireBinding(result.getJSONObject(\\\"binding\\\"));\\n        return result;\",\"after\":\"        if(!\\\"427b3e7743e044dc06643468e976ba0fd47c27b28b21203473fd31738937dc53\\\".equals(\\n                org.trillionnium.hepta.webprotocol.WebEvidenceBinding.sha256(binding))\\n                ||!\\\"b56264d8894c3c3946437e9aab857c3ccf8453170396acfbff5e556411da1e69\\\".equals(\\n                org.trillionnium.hepta.webprotocol.WebEvidenceBinding.sha256(result.getJSONObject(\\\"binding\\\"))))\\n            throw new IllegalArgumentException(\\\"exact original and derived host binding hashes required\\\");\\n        org.trillionnium.hepta.webprotocol.WebTaskPurpose.requireBinding(result.getJSONObject(\\\"binding\\\"));\\n        return result;\",\"before_sha256\":\"69d41da9a0e67d63170c74f39e0c7d3d3e79e831c254ce8e811201c3428ac842\",\"after_sha256\":\"e0cc2a474545623cd8e79aaa73afb130f5dc8733efc43f521ad909df0ec384a2\",\"count\":1}]},\"main57_metadata_before\":{\"predecessor_packet\":{\"bytes\":260128,\"sha256\":\"3687b09656e60a808ebdce1430951e04741581e9ddd0d2faa7f5c36220ed24b7\",\"git_blob_sha\":\"1153d7e55c4051ecf6e4c018defe43d26ff51fd2\"},\"source_candidate_git\":\"274f79413a35af7e40cf3e93fc33bc7109f15f36\",\"test_candidate_git\":\"0e91169c9e836071c87494e70f3e93db27ffb80f\",\"added_observation_case_names\":[\"flight_observation_actual56_old_digest_failure_reproduced\",\"flight_observation_actual_retained_rows_cannot_replace_complete_native\",\"flight_observation_actual_raws_with_explicit_synthetic_complete_native\",\"flight_observation_window_selection_ime_and_root_changes_rejected\",\"flight_observation_target_unretained_and_retained_semantics_rejected\",\"flight_observation_truncated_or_incomplete_native_rejected\",\"flight_observation_four_raw_equality_and_homepage_scope_required\",\"flight_observation_capture_epoch_binding_and_order_rejected\",\"flight_observation_geometry_and_actual_native_ancestor_must_match\"],\"expected_composition_cases\":79,\"expected_composition_assertions\":211,\"expected_counts_are_source_derived_not_actual_results\":true,\"actual_cases\":null,\"actual_assertions\":null,\"original_70_cases_and_assertions_unchanged\":true,\"original_17_stability_case_bodies_unchanged\":true,\"actual_original_scope_files\":2,\"actual_original_capture_fd_files\":2,\"actual_retained_rows_per_frame\":49,\"full_native_traversal_synthetic\":true,\"android_node_ref_or_window_api_executed\":false,\"action_permit_granted\":false,\"actual_flight_results_provider_ready\":false,\"phone_query_or_business_verified\":false},\"main57_metadata_after\":{\"predecessor_packet\":{\"bytes\":260128,\"sha256\":\"3687b09656e60a808ebdce1430951e04741581e9ddd0d2faa7f5c36220ed24b7\",\"git_blob_sha\":\"1153d7e55c4051ecf6e4c018defe43d26ff51fd2\"},\"source_candidate_git\":\"274f79413a35af7e40cf3e93fc33bc7109f15f36\",\"test_candidate_git\":\"0e91169c9e836071c87494e70f3e93db27ffb80f\",\"added_observation_case_names\":[\"flight_observation_actual56_old_digest_failure_reproduced\",\"flight_observation_actual_retained_rows_cannot_replace_complete_native\",\"flight_observation_actual_raws_with_explicit_synthetic_complete_native\",\"flight_observation_window_selection_ime_and_root_changes_rejected\",\"flight_observation_target_unretained_and_retained_semantics_rejected\",\"flight_observation_truncated_or_incomplete_native_rejected\",\"flight_observation_four_raw_equality_and_homepage_scope_required\",\"flight_observation_capture_epoch_binding_and_order_rejected\",\"flight_observation_geometry_and_actual_native_ancestor_must_match\"],\"expected_composition_cases\":79,\"expected_composition_assertions\":215,\"expected_counts_are_source_derived_not_actual_results\":true,\"actual_cases\":null,\"actual_assertions\":null,\"original_70_cases_and_assertions_unchanged\":true,\"original_17_stability_case_bodies_unchanged\":true,\"actual_original_scope_files\":2,\"actual_original_capture_fd_files\":2,\"actual_retained_rows_per_frame\":49,\"full_native_traversal_synthetic\":true,\"android_node_ref_or_window_api_executed\":false,\"action_permit_granted\":false,\"actual_flight_results_provider_ready\":false,\"phone_query_or_business_verified\":false},\"added_metadata\":{\"predecessor_packet\":{\"bytes\":357185,\"sha256\":\"ba0832568ca64be933ba31acd3646d0c63550f6202abeecf49dd12cecb52f110\",\"git_blob_sha\":\"cd1d6fe815602cfd0909e7e6cf771a0c46bd2529\"},\"repair_review\":{\"bytes\":12303,\"sha256\":\"ea7cb1288b9e108efe1ef6d11b97480c60ae5ce5ab53f01381fcf1022ffb25eb\",\"git_blob_sha\":\"16ad80bd40b1753a65837680698a71e516ecfd73\"},\"original_failed_result\":{\"bytes\":30361,\"sha256\":\"d66b4dcaf0eed2b650df9e88928a32ab5145608f600b868864c3925011d72532\",\"git_blob_sha\":\"4f436784332e6a1bf7200cbaf105c28e17a55b29\"},\"production_sources_changed\":false,\"original_4_raw_bytes_changed\":false,\"all_4_dom_raw_values_changed\":false,\"original_79_case_order_unchanged\":true,\"original_211_assertions_unchanged\":true,\"additional_assertions_in_existing_positive_case\":4,\"derived_capture_path\":\"capture.binding.authorization.find_query\",\"archived_value\":\"present explicit JSON null\",\"derived_host_value\":\"key omitted by desktop JSONObject(Map)\",\"original_authorization_fully_recompiled\":true,\"restoring_single_null_field_recovers_complete_capture\":true,\"original_binding_sha256\":\"427b3e7743e044dc06643468e976ba0fd47c27b28b21203473fd31738937dc53\",\"derived_host_binding_sha256\":\"b56264d8894c3c3946437e9aab857c3ccf8453170396acfbff5e556411da1e69\",\"derived_captures_are_original_fd_records\":false,\"expected_cases\":79,\"expected_assertions\":215,\"actual_cases\":null,\"actual_assertions\":null},\"changed_production_inputs\":[]}")

def need(value, why):
    if not value:
        raise RuntimeError(why)

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
         "each original Web regression process must exit normally")


def source_rows(values):
    return [{"path":name,"bytes":len(raw),"sha256":sha(raw)}
            for name,raw in sorted(values.items(),key=lambda item:Path(item[0]))]

def read_bound(path,pin):
    raw,facts=read_regular(path,pin)
    originals.append(facts)
    return raw,facts

def exact_changes(base,changes,successor):
    value=base.decode("utf-8","strict")
    for change in changes:
        need(type(change["count"]) is int and change["count"]>0
             and value.count(change["before"])==change["count"],"exact fixture predecessor occurrence")
        value=value.replace(change["before"],change["after"])
    need(value.encode("utf-8")==successor,"exact forward fixture reconstruction")
    for change in reversed(changes):
        need(value.count(change["after"])==change["count"],"exact fixture reverse occurrence")
        value=value.replace(change["after"],change["before"])
    need(value.encode("utf-8")==base,"byte-identical original fixture reverse proof")

def derive_packet(prior_raw):
    delta=PACKET_DELTA
    checked(prior_raw,delta["base"],"actual failed57 complete packet")
    packet=strict(prior_raw)
    need(packet["schema"]=="hepta.main57-web-regression-fixture-successor.v1"
         and packet["current_aggregate"]==CONFIG["aggregate"]
         and packet["main57_successor"]==delta["main57_metadata_before"]
         and "main57_host_json_null_successor" not in packet,"exact failed57 packet metadata")
    matches=[item for item in packet["files"] if item["path"]==delta["helper"]["path"]]
    need(len(matches)==1,"one existing native-stability helper")
    helper=matches[0]
    need(helper["origin"]==delta["helper"]["origin_before"],"exact helper predecessor provenance")
    old_text=helper["raw_utf8"]
    checked(old_text.encode("utf-8"),delta["helper"]["before"],"actual failed57 helper")
    new_text=old_text
    need(len(delta["helper"]["ordered_replacements"])==5
         and delta["changed_production_inputs"]==[],"only five host JSON compatibility replacements")
    for change in delta["helper"]["ordered_replacements"]:
        need(change["count"]==1 and new_text.count(change["before"])==1,"one explicit helper replacement")
        new_text=new_text.replace(change["before"],change["after"])
    exact_changes(old_text.encode("utf-8"),delta["helper"]["ordered_replacements"],new_text.encode("utf-8"))
    checked(new_text.encode("utf-8"),delta["helper"]["after"],"host JSON compatibility helper successor")
    helper.update(delta["helper"]["after"]);helper["raw_utf8"]=new_text
    helper["origin"]=delta["helper"]["origin_after"]
    packet["main57_successor"]=delta["main57_metadata_after"]
    packet["main57_host_json_null_successor"]=delta["added_metadata"]
    raw=encoded(packet)
    checked(raw,delta["result"],"complete current packet full pin")
    reverse=strict(raw)
    rh=[item for item in reverse["files"] if item["path"]==delta["helper"]["path"]]
    need(len(rh)==1,"one helper in complete reverse packet")
    rh=rh[0]
    for change in reversed(delta["helper"]["ordered_replacements"]):
        need(rh["raw_utf8"].count(change["after"])==1,"unique helper reverse block")
        rh["raw_utf8"]=rh["raw_utf8"].replace(change["after"],change["before"])
    rh.update(delta["helper"]["before"]);rh["origin"]=delta["helper"]["origin_before"]
    reverse["main57_successor"]=delta["main57_metadata_before"]
    del reverse["main57_host_json_null_successor"]
    need(encoded(reverse)==prior_raw,"whole failed57 packet remains byte-identical")
    return raw,packet

def validate_report(report,spec,old_names):
    need(type(report) is dict and report["schema"]==spec["schema"] and report["all_pass"] is True
         and type(report["cases"]) is int and report["cases"]==spec["cases"]
         and type(report["assertions"]) is int and report["assertions"]==spec["assertions"],
         "all existing and explicitly appended Web cases must actually pass")
    names=report["case_names"]
    need(type(names) is list and len(names)==spec["cases"]
         and len(set(names))==spec["cases"] and all(type(n) is str for n in names),
         "unique complete actual Web case names")
    expected=old_names
    if spec["name"]=="composition43":
        expected=old_names+CONFIG["added_case_names"]
        need(report["terminal_lifecycle_cases_added"]==10
             and report["terminal_lifecycle_close_and_worker_inputs_synthetic"] is True,
             "explicit synthetic terminal facts")
        replay=report["flight_native_stability_replay"]
        need(replay["actual_77_bundle_git"]=="c7002d09283cfe166dfa76fcdee0f98c1bb0d584"
             and replay["actual_dom_raws_replayed"]==2 and replay["actual_retained_native_frames_replayed"]==2
             and replay["complete_native_traversal_fixture"]=="explicit synthetic structure, never an actual capture"
             and replay["rejected_transient_validate_graph_observed"] is False
             and replay["android_node_ref_or_window_api_executed"] is False
             and replay["phone_dispatch_or_business_verified"] is False,"honest actual-versus-synthetic stability replay")
        observation=replay["readonly_observation_bracket"]
        need(observation["actual_bundle_git"]=="deb73e79d18eb3fe408ff2dded8cc8e14342800a"
             and observation["actual_bundle_sha256"]=="41df2d70db7f42465ba5306cb139fe9a85b28f5e63d0c6a737cbee51b68dba2f"
             and observation["input_bytes"]==879788
             and observation["input_sha256"]=="56a2da5e560e38fbbcabd25214ff343503e6fc75cfbc4a5458bd897be155e5f0"
             and observation["complete_original_scope_files"]==2
             and observation["complete_original_capture_fd_files"]==2
             and observation["actual_retained_native_nodes_per_frame"]==49
             and observation["actual_visited_count_per_frame"]==89
             and observation["full_native_arrays_replayed"]=="explicit synthetic 89-node extension; not an archived traversal"
             and observation["android_original_node_ref_or_window_apis_executed"] is False
             and observation["existing_action_permit_tests_changed"] is False
             and observation["phone_query_or_business_verified"] is False,
             "actual raw records and synthetic complete native scope remain explicit")
        compatibility=observation["host_json_map_null_compatibility"]
        need(compatibility["schema"]=="hepta.host-json-map-null-compatibility.v1"
             and compatibility["desktop_json_version"]=="20240303"
             and compatibility["changed_path"]=="capture.binding.authorization.find_query"
             and compatibility["archived_value"]=="present explicit JSON null"
             and compatibility["derived_host_value"]=="key omitted by desktop JSONObject(Map)"
             and compatibility["complete_original_authorization_recompiled"] is True
             and compatibility["restore_single_null_field_recovers_complete_original_capture"] is True
             and compatibility["original_capture_fd_bytes_unchanged"] is True
             and compatibility["all_four_complete_dom_raw_values_unchanged"] is True
             and compatibility["production_require_binding_changed"] is False
             and compatibility["original_binding_sha256"]=="427b3e7743e044dc06643468e976ba0fd47c27b28b21203473fd31738937dc53"
             and compatibility["derived_host_binding_sha256"]=="b56264d8894c3c3946437e9aab857c3ccf8453170396acfbff5e556411da1e69"
             and compatibility["derived_captures_are_original_fd_records"] is False,
             "explicit exact JSON constructor compatibility and separate binding hashes")
        need(report["prior_case_count"]==43 and report["legacy_dom_id_bridge_assertions_replaced"]==2
             and report["full_native_action_service_or_binder_executed"] is False
             and report["synthetic_profile_assignment_not_actual_webview"] is True
             and report["actual_mi_dom_seen"] is False and report["actual_model_run_executed"] is False
             and report["binder_authenticated"] is False
             and type(report["phone_commands_executed"]) is int and report["phone_commands_executed"]==0
             and report["actual_shopping_or_flight_result_verified"] is False
             and report["final_native_and_cleanup_gates_verified"] is False,
             "explicit synthetic composition successor scope")
    elif spec["name"]=="evidence80":
        need(report["production_pure_classes_executed"] is True
             and report["android_rect_and_ax_fixture"] is True
             and report["binder_transport_authenticated"] is False
             and report["native_geometry_is_synthetic"] is True
             and type(report["phone_commands_executed"]) is int and report["phone_commands_executed"]==0
             and report["query_executed"] is False,"original pure receipt scope")
    elif spec["name"]=="calendar13":
        need(report["actual_fixture_dom_nodes"]==987
             and report["lease_and_native_ref_signatures_synthetic"] is True
             and report["original_dom_values_preserved"] is True
             and report["source_dom_schema"]=="hepta.fixed-top-document-dom.v2"
             and report["unit_envelope_schema"]=="hepta.fixed-top-document-dom.v4"
             and type(report["phone_actions"]) is int and report["phone_actions"]==0
             and report["binder_authenticated"] is False,"real calendar original within a synthetic v4 envelope")
    else:
        raise RuntimeError("unknown fixed regression")
    need(names==expected,"actual56 case order retained with only nine read-only observation cases appended")
    need(report["business_verified"] is False,"host cases cannot assert real business completion")

stage_raw=globals().get("__stage_source__")
need(type(stage_raw) is bytes and len(stage_raw)>0,"exact loader-verified source bytes")
ROOT=Path(CONFIG["root"])
SOURCE=Path(CONFIG["source_root"])
MATERIALIZED=Path(CONFIG["materialized_root"])
need(sys.platform=="linux" and ROOT.is_absolute() and SOURCE==MATERIALIZED/"source"
     and not ROOT.exists() and not ROOT.is_symlink()
     and ROOT not in MATERIALIZED.parents and MATERIALIZED not in ROOT.parents,
     "independent new Pocket4 output root")
originals=[]
# Preserve the actual successful56 output, its reports and historical failure
# copies; derive the new packet from that fixed original without overwriting it.
PRIOR=Path(CONFIG["prior_web"]["root"])
need(PRIOR.is_absolute() and ROOT!=PRIOR and ROOT not in PRIOR.parents
     and PRIOR not in ROOT.parents,"independent prior Web output")
prior_output,prior_output_facts=snapshot(PRIOR)
originals.extend(prior_output_facts.values())
prior_result_raw=checked(prior_output["RESULT.json"],CONFIG["prior_web"]["result"],"actual56 Web result")
prior_result=strict(prior_result_raw)
checked(prior_output["stage.py"],CONFIG["prior_web"]["stage"],"actual56 coordinator")
need(prior_result["schema"]=="hepta.main56-existing-web-regressions-host-stage.v1"
     and prior_result["all_pass"] is True and type(prior_result["exit_code"]) is int and prior_result["exit_code"]==0
     and prior_result["root"]==str(PRIOR)
     and prior_result["stage_sha256"]==CONFIG["prior_web"]["stage"]["sha256"]
     and all(prior_result[k] is True for k in ("originals_unchanged","written_files_unchanged","source_unchanged","prior_output_preserved","prior_failed56_output_preserved")),
     "complete actual56 Web and retained failure provenance")
need([x["name"] for x in prior_result["steps"]]==["compile","evidence80","composition43","calendar13"]
     and all(type(x["exit_code"]) is int and x["exit_code"]==0 and x["timed_out"] is False
             and x["forced_kill"] is False and x["exit_observed"] is True for x in prior_result["steps"]),
     "four actual prior normal processes")
for step in prior_result["steps"]:
    for stream in ("stdout","stderr"):
        name=step["name"]+"."+stream
        need(step[stream]["path"]==str(PRIOR/name),"prior stream is exact owned file")
        checked(prior_output[name],step[stream],"prior actual stream")
# Preserve the actual56 first run without treating its completed evidence80
# subreport as a complete pass. The new root never overwrites any failed output.
FAILED=Path(CONFIG["prior_failed56"]["root"])
need(FAILED.is_absolute() and FAILED not in (ROOT,PRIOR,MATERIALIZED)
     and ROOT not in FAILED.parents and FAILED not in ROOT.parents,"independent actual56 failed output")
failed_output,failed_output_facts=snapshot(FAILED)
originals.extend(failed_output_facts.values())
failed_raw=checked(failed_output["RESULT.json"],CONFIG["prior_failed56"]["result"],"actual56 failed complete result")
failed=strict(failed_raw)
checked(failed_output["stage.py"],CONFIG["prior_failed56"]["stage"],"actual56 failed coordinator")
checked(failed_output["FIXTURE-PACKET.json"],CONFIG["prior_failed56"]["packet"],"actual56 failed packet")
need(failed["schema"]=="hepta.main56-existing-web-regressions-host-stage.v1"
     and failed["all_pass"] is False and type(failed["exit_code"]) is int and failed["exit_code"]==1
     and failed["root"]==str(FAILED)
     and failed["stage_sha256"]==CONFIG["prior_failed56"]["stage"]["sha256"]
     and failed["source_candidate_git"]==CONFIG["prior_failed56"]["aggregate"]["git"]
     and all(failed[k] is True for k in ("originals_unchanged","written_files_unchanged","source_unchanged","prior_output_preserved")),
     "actual failed run and all prior preservation facts remain failures")
need([s["name"] for s in failed["steps"]]==["compile","evidence80","composition43"]
     and [s["exit_code"] for s in failed["steps"]]==[0,0,1]
     and all(type(s["exit_code"]) is int and s["timed_out"] is False and s["forced_kill"] is False
             and s["exit_observed"] is True for s in failed["steps"]),"original compile/pass/failure process sequence")
for step in failed["steps"]:
    for stream in ("stdout","stderr"):
        leaf=step["name"]+"."+stream
        need(step[stream]["path"]==str(FAILED/leaf),"failed-run log remains in its original root")
        checked(failed_output[leaf],step[stream],"original failed-run log")
checked(failed_output["composition43.stderr"],CONFIG["prior_failed56"]["composition_stderr"],"original geometry freeze exception")
need(set(failed["reports"])=={"evidence80"} and failed["reports"]["evidence80"]["report"]["all_pass"] is True
     and failed["reports"]["evidence80"]["report"]["cases"]==80
     and failed["reports"]["evidence80"]["report"]["assertions"]==92,"only original evidence80 subgate passed")
# Preserve the actual57 OWNER/JSON constructor mismatch and its entire output.
# No existing raw, generated fixture, class or log is rewritten by this successor.
FAILED57=Path(CONFIG["prior_failed57"]["root"])
need(FAILED57.is_absolute() and FAILED57 not in (ROOT,PRIOR,FAILED,MATERIALIZED)
     and ROOT not in FAILED57.parents and FAILED57 not in ROOT.parents,"independent failed57 output")
failed57_output,failed57_facts=snapshot(FAILED57)
originals.extend(failed57_facts.values())
failed57_raw=checked(failed57_output["RESULT.json"],CONFIG["prior_failed57"]["result"],"actual failed57 result")
failed57=strict(failed57_raw)
checked(failed57_output["stage.py"],CONFIG["prior_failed57"]["stage"],"actual failed57 coordinator")
failed57_packet=checked(failed57_output["FIXTURE-PACKET.json"],CONFIG["prior_failed57"]["packet"],"actual failed57 packet")
checked(failed57_output["composition43.stderr"],CONFIG["prior_failed57"]["composition_stderr"],"original OWNER mismatch stderr")
need(failed57["schema"]=="hepta.main57-existing-web-regressions-host-stage.v1"
     and failed57["all_pass"] is False and type(failed57["exit_code"]) is int and failed57["exit_code"]==1
     and failed57["root"]==str(FAILED57)
     and failed57["stage_sha256"]==CONFIG["prior_failed57"]["stage"]["sha256"]
     and failed57["source_candidate_git"]==CONFIG["aggregate"]["git"]
     and failed57["source_inventory_sha256"]==CONFIG["inventory"]["sha256"]
     and all(failed57[k] is True for k in ("originals_unchanged","written_files_unchanged",
        "source_unchanged","prior_output_preserved","prior_failed56_output_preserved")),
     "actual57 failure and original preservation facts remain failures")
need([s["name"] for s in failed57["steps"]]==["compile","evidence80","composition43"]
     and [s["exit_code"] for s in failed57["steps"]]==[0,0,1]
     and all(type(s["exit_code"]) is int and s["timed_out"] is False and s["forced_kill"] is False
             and s["exit_observed"] is True for s in failed57["steps"]),"actual57 process sequence")
for step in failed57["steps"]:
    for stream in ("stdout","stderr"):
        leaf=step["name"]+"."+stream
        need(step[stream]["path"]==str(FAILED57/leaf),"failed57 log stays in original root")
        checked(failed57_output[leaf],step[stream],"actual57 original stream")
need(set(failed57["reports"])=={"evidence80"}
     and failed57["reports"]["evidence80"]["report"]["all_pass"] is True
     and failed57["reports"]["evidence80"]["report"]["cases"]==80
     and failed57["reports"]["evidence80"]["report"]["assertions"]==92,"only failed57 evidence80 subgate passed")
prior_packet_raw=checked(prior_output["FIXTURE-PACKET.json"],CONFIG["prior_web"]["packet"],"actual56 packet")
packet_raw,packet=derive_packet(failed57_packet)
checked(packet_raw,CONFIG["decoded_input"],"explicit57 complete fixture packet")
need(packet["schema"]=="hepta.main57-web-regression-fixture-successor.v1"
     and packet["status"]=="source_only_not_executed","reviewed fixture successor packet")
aggregate_raw,_=read_bound(MATERIALIZED/"AGGREGATE.json",CONFIG["aggregate"])
need(blob(aggregate_raw)==CONFIG["aggregate"]["git"],"complete current595 aggregate Git identity")
aggregate=strict(aggregate_raw)
inventory_raw,_=read_bound(MATERIALIZED/"SOURCE-INVENTORY.json",CONFIG["inventory"])
before,before_facts=snapshot(SOURCE)
need(len(before)==CONFIG["source_file_count"]==595 and len(aggregate["inventory"]["files"])==595,"complete current source tree")
validate_map(before,aggregate["inventory"]["files"],True)
need(inventory_raw==encoded(source_rows(before)),"complete current595 runtime source inventory")
need(packet["current_aggregate"]["git"]==CONFIG["aggregate"]["git"]
     and packet["current_aggregate"]["bytes"]==CONFIG["aggregate"]["bytes"]
     and packet["current_aggregate"]["sha256"]==CONFIG["aggregate"]["sha256"]
     and packet["current_aggregate"]["inventory_sha256"]==aggregate["inventory"]["sha256"],
     "fixture packet bound to the same full Git-bearing candidate map")
originals.extend(before_facts.values())
for flag in ("evidence80_original_main_byte_identical","calendar13_asserted_body_byte_identical",
             "composition43_explicit_fixture_successor","original_three_java_sources_not_overwritten",
             "gate_counts_are_separate_not_a_sum_with_core101"):
    need(packet["scope"][flag] is True,"explicit fixture migration scope")
for flag in ("compiled","host_executed","production_sources_modified","actual_Mi_detail_seen",
             "actual_popup_or_profile_callback","actual_business_verified"):
    need(packet["scope"][flag] is False,"no prior fixture execution or business claim")
need(type(packet["scope"]["phone_commands"]) is int and packet["scope"]["phone_commands"]==0,
     "source-only packet")
expected_fixture_names=[
    "tests/web-flight/WebFlightEvidenceHostTest.java",
    "tests/web-flight/WebTaskCompositionHostTest.java",
    "tests/web-flight/WebCalendarNativeHostTest.java",
    "tests/web-flight/WebV4RegressionFixtures.java",
    "tests/web-flight/WebWire4SyntheticFactory.java",
    "tests/web-flight/WebFlightNativeStabilityHostCases.java"]
need([item["path"] for item in packet["files"]]==expected_fixture_names,"fixed exact six fixture members")
fixture_bytes={}
for index,item in enumerate(packet["files"]):
    name=relative(item["path"])
    raw=checked(item["raw_utf8"].encode("utf-8","strict"),item,"exact fixture successor member")
    need(blob(raw)==item["git_blob_sha"],"fixture successor Git identity")
    if index<3:
        need(name in before,"unchanged current original Java fixture")
        checked(before[name],item["base"],"original Java predecessor")
        need(blob(before[name])==item["base"]["git_blob_sha"],"original Java Git identity")
        exact_changes(before[name],item["ordered_replacements"],raw)
    else:
        need(name not in before,"new fixtures do not shadow any current source file")
    fixture_bytes[name]=raw
need([len(item["ordered_replacements"]) for item in packet["files"][:3]]==[3,28,3],
     "only reviewed exact migration hunks")
need(packet["files"][0]["proof"]["main_byte_identical"] is True
     and packet["files"][2]["proof"]["main_asserted_body_byte_identical"] is True
     and packet["files"][1]["proof"]["assertion_blocks_not_claimed_wholly_byte_identical"] is True,
     "accurate original assertion boundaries")
production=packet["production_inputs"]
extra=packet["unchanged_extra_inputs"]
need(type(production) is list and len(production)==44
     and len({item["path"] for item in production})==44
     and all(item["path"].startswith("src/") and item["path"].endswith(".java") for item in production),
     "fixed44 actual production compilation units")
need([item["path"] for item in extra]==[
    "tests/qualification-scope/fixtures/android/graphics/Rect.java",
    "tests/web-flight/WebUnstartedRetirementHostTest.java"],"two unchanged auxiliary compilation units")
for item in production+extra:
    name=relative(item["path"])
    need(name in before,"actual compilation input exists")
    checked(before[name],item,"actual complete compilation unit")
    need(blob(before[name])==item["git_blob_sha"],"actual compilation unit Git identity")
need(extra[1]["only_initial_and_confirmation_factories_called_here"] is True
     and extra[1]["old_36_main_run_here"] is False,"old36 not represented as rerun")
java_names=[item["path"] for item in production+extra]+expected_fixture_names
need(len(java_names)==52 and len(set(java_names))==52,"complete unique52 Java closure")
calendar_specs=packet["actual_calendar_fixtures"]
need([Path(item["path"]).name for item in calendar_specs]==[
    "calendar-pending.json","calendar-stable.json","calendar-stable.xml"],
    "actual pending/stable calendar and native AX")
calendar_facts=[]
for item in calendar_specs:
    _,facts=read_bound(item["path"],item);calendar_facts.append(facts)
old_reports={}
need(set(prior_result["reports"])=={x["name"] for x in CONFIG["prior_expected_gates"]},"three prior actual reports")
for spec in CONFIG["prior_expected_gates"]:
    name=spec["name"];record=prior_result["reports"][name]
    path=PRIOR/(name+"-RESULT.json")
    need(record["original"]["path"]==str(path),"actual56 report path")
    raw=checked(prior_output[path.name],record["original"],"actual56 original report")
    report=strict(raw)
    need(report==record["report"] and report["all_pass"] is True
         and type(report["cases"]) is int and report["cases"]==spec["cases"]
         and type(report["assertions"]) is int and report["assertions"]==spec["assertions"]
         and type(report["case_names"]) is list and len(report["case_names"])==spec["cases"]
         and len(set(report["case_names"]))==spec["cases"],"actual56 baseline names and counts")
    old_reports[name]={"raw":raw,"facts":prior_output_facts[path.name],"report":report}
need(len(CONFIG["added_case_names"])==9 and len(set(CONFIG["added_case_names"]))==9
     and not set(CONFIG["added_case_names"]).intersection(old_reports["composition43"]["report"]["case_names"]),
     "only nine unique appended cases, actual56 seventy cases retained")
tools={}
for name in ("java","javac","json"):
    _,facts=read_bound(CONFIG[name]["path"],CONFIG[name])
    tools[name]=facts
for name in ("java","javac"):
    need(os.access(tools[name]["path"],os.X_OK),"actual executable JDK")
ready_raw,_=read_bound(CONFIG["orgjson_ready"]["path"],CONFIG["orgjson_ready"])
ready=strict(ready_raw)
# The exact actual READY bytes are pinned; the JAR itself is independently read/hash checked.
need(type(ready) is dict,"actual JSON dependency READY object")
python_path=Path(sys.executable).resolve(strict=True)
_,python_facts=read_regular(python_path)
originals.append(python_facts);tools["python"]=python_facts
env=dict(os.environ)
for name in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH","SOURCE_HEAD_SHA"):
    env.pop(name,None)
env["PYTHONDONTWRITEBYTECODE"]="1"
started=time.time()
ROOT.mkdir(mode=0o700)  # FIRST MUTATION; outside the handler, never share a previous result root.
steps,written=[],[]
reports={}
result={"schema":"hepta.main57-existing-web-regressions-host-stage.v1",
        "all_pass":False,"exit_code":1,"root":str(ROOT),"source_root":str(SOURCE),
        "source_candidate_git":CONFIG["aggregate"]["git"],"source_file_count":595,
        "source_inventory_sha256":CONFIG["inventory"]["sha256"],
        "candidate_git_bearing_inventory_sha256":aggregate["inventory"]["sha256"],
        "fixture_packet":CONFIG["decoded_input"],"fixture_count":6,
        "production_java_count":44,"compilation_unit_count":52,"steps":steps,"reports":reports,
        "prior_reports":{name:value["facts"] for name,value in old_reports.items()},
        "actual_calendar_originals":calendar_facts,"tools":tools,
        "core101_pass_prerequisite_required":False,"android_build_prerequisite_required":False,
        "evidence80_original_main_byte_identical":True,"calendar13_asserted_body_byte_identical":True,
        "composition43_explicit_fixture_successor":True,"composition_case_name_mapping":CONFIG["case_name_mapping"],
        "old_unstarted36_main_executed_here":False,"focused39_rerun":False,"identity10_rerun":False,
        "query40_rerun":False,"core101_rerun":False,
        "android_compiled":False,"binder_transport_executed":False,"native_accessibility_executed":False,
        "external_model_used":False,"phone_actions":0,"business_verified":False,
        "actual_Mi_detail_or_popup_verified":False,"signed":False,"published":False,
        "started_epoch":started,"originals_unchanged":False,"error":None,
        "prior_successful_web_result":dict(CONFIG["prior_web"]["result"],path=str(PRIOR/"RESULT.json")),
        "prior_output_count":len(prior_output),
        "prior_output_inventory_sha256":sha(encoded(source_rows(prior_output))),
        "prior_output_preserved":False,
        "prior_failed56_web_result":dict(CONFIG["prior_failed56"]["result"],path=str(FAILED/"RESULT.json")),
        "prior_failed56_output_count":len(failed_output),
        "prior_failed56_output_inventory_sha256":sha(encoded(source_rows(failed_output))),
        "prior_failed56_output_preserved":False,
        "geometry_deep_freeze_assertions_added":0,"retained_geometry_deep_freeze_assertions":4,
        "fixture_packet_derived_from_actual56":False,
        "fixture_packet_derived_from_actual57_failed_run":True,
        "old_fixture_packet":CONFIG["prior_failed57"]["packet"],
        "prior_failed57_web_result":dict(CONFIG["prior_failed57"]["result"],path=str(FAILED57/"RESULT.json")),
        "prior_failed57_output_count":len(failed57_output),
        "prior_failed57_output_inventory_sha256":sha(encoded(source_rows(failed57_output))),
        "prior_failed57_output_preserved":False,
        "host_json_map_null_fixture_compatibility":packet["main57_host_json_null_successor"],
        "additional_host_json_compatibility_assertions":4,
        "existing_actual56_assertions_changed_here":False,
        "added_terminal_cases":0,"added_native_stability_cases":0,
        "retained_terminal_cases":10,"retained_native_stability_cases":17,
        "added_readonly_observation_cases":9,
        "expected_counts_are_source_derived_until_actual_report":True,
        "changed_production_input_paths":[r["after"]["path"] for r in PACKET_DELTA["changed_production_inputs"]],
        "actual_flight_results_provider_ready":False}
class_before=None
classes=ROOT/"classes"
try:
    written.append(write_new(ROOT/"stage.py",stage_raw))
    written.append(write_new(ROOT/"CONFIG.json",encoded(CONFIG)))
    written.append(write_new(ROOT/"FIXTURE-PACKET.json",packet_raw))
    written.append(write_new(ROOT/"SOURCE-INVENTORY.json",inventory_raw))
    written.append(write_new(ROOT/"prior-success/RESULT.json",prior_result_raw))
    written.append(write_new(ROOT/"FIXTURE-DELTA.json",encoded(PACKET_DELTA)))
    written.append(write_new(ROOT/"PRIOR-OUTPUT-INVENTORY.json",encoded(source_rows(prior_output))))
    written.append(write_new(ROOT/"prior-failed56/RESULT.json",failed_raw))
    written.append(write_new(ROOT/"PRIOR-FAILED56-OUTPUT-INVENTORY.json",encoded(source_rows(failed_output))))
    written.append(write_new(ROOT/"prior-failed57/RESULT.json",failed57_raw))
    written.append(write_new(ROOT/"PRIOR-FAILED57-OUTPUT-INVENTORY.json",encoded(source_rows(failed57_output))))
    written.append(write_new(ROOT/"COMPILATION-INPUTS.json",encoded([
        {"role":"actual_production" if item in production else "unchanged_fixture",**item}
        for item in production+extra]+[
        {"role":"explicit_fixture_successor","path":item["path"],"bytes":item["bytes"],
         "sha256":item["sha256"],"git_blob_sha":item["git_blob_sha"]} for item in packet["files"]])))
    for name,raw in fixture_bytes.items():
        written.append(write_new(ROOT/"fixtures"/name,raw))
    for name,value in old_reports.items():
        written.append(write_new(ROOT/"prior"/(name+".json"),value["raw"]))
    classes.mkdir(mode=0o700)
    (ROOT/"tmp").mkdir(mode=0o700);env["TMPDIR"]=str(ROOT/"tmp")
    sources=[SOURCE/item["path"] for item in production+extra]+[
        ROOT/"fixtures"/name for name in expected_fixture_names]
    compile_argv=[tools["javac"]["path"],"--release","8","-encoding","UTF-8",
                  "-Xlint:all","-Werror","-cp",tools["json"]["path"],"-d",classes]+sources
    written.append(write_new(ROOT/"START-ARGS.json",encoded({
        "key":CONFIG["key"],"compile_argv":[str(x) for x in compile_argv],
        "test_classes":[item["class_name"] for item in CONFIG["expected_gates"]],
        "synthetic_fixture_scope":packet["scope"],"source_modified":False,"phone_actions":0})))
    run_step("compile",compile_argv,120,ROOT,env)
    class_bytes,class_facts=snapshot(classes)
    need(len(class_bytes)>0 and all(name.endswith(".class") for name in class_bytes),
         "actual nonempty compiled Java class set")
    class_before=(class_bytes,class_facts)
    result["compiled_class_count"]=len(class_bytes)
    written.append(write_new(ROOT/"COMPILED-CLASSES.json",encoded(source_rows(class_bytes))))
    cp=str(classes)+os.pathsep+tools["json"]["path"]
    for spec in CONFIG["expected_gates"]:
        out=ROOT/(spec["name"]+"-RESULT.json")
        args=[tools["java"]["path"],"-cp",cp,spec["class_name"]]
        if spec["name"]=="calendar13":
            args.extend([item["path"] for item in calendar_specs])
        args.append(out)
        run_step(spec["name"],args,120,ROOT,env)
        raw,facts=read_regular(out);report=strict(raw)
        written.append(facts)
        validate_report(report,spec,old_reports[spec["name"]]["report"]["case_names"])
        reports[spec["name"]]={"original":facts,"report":report}
    need(len(steps)==4 and len(reports)==3,"compile and all three original gates completed")
    result["all_pass"]=True;result["exit_code"]=0
except BaseException as failure:
    result["all_pass"]=False;result["exit_code"]=1
    result["error"]=type(failure).__name__+": "+str(failure)
    try:write_new(ROOT/"ERROR.txt",traceback.format_exc().encode("utf-8"))
    except BaseException as logging_failure:
        result["error_record_failure"]=type(logging_failure).__name__+": "+str(logging_failure)
finally:
    # Retain any real partial output after a failed process; never synthesize a pass.
    partial={}
    for spec in CONFIG["expected_gates"]:
        path=ROOT/(spec["name"]+"-RESULT.json")
        try:
            if path.exists():
                raw,facts=read_regular(path)
                partial[spec["name"]]={"original":facts,"report":strict(raw)}
        except BaseException as partial_failure:
            result["all_pass"]=False;result["exit_code"]=1
            partial[spec["name"]]={"read_error":type(partial_failure).__name__+": "+str(partial_failure)}
    result["actual_report_files"]=partial
    try:
        for facts in originals:unchanged(facts)
        for facts in written:unchanged(facts)
        for step in steps:
            unchanged(step["stdout"]);unchanged(step["stderr"])
        after,after_facts=snapshot(SOURCE)
        need(after==before and after_facts==before_facts,"whole595 source bytes and identities unchanged")
        need(snapshot(PRIOR)==(prior_output,prior_output_facts),
             "all prior Web output bytes and identities unchanged")
        result["prior_output_preserved"]=True
        need(snapshot(FAILED)==(failed_output,failed_output_facts),
             "all actual56 failed output bytes and identities unchanged")
        result["prior_failed56_output_preserved"]=True
        need(snapshot(FAILED57)==(failed57_output,failed57_facts),
             "all actual57 failed output bytes and identities unchanged")
        result["prior_failed57_output_preserved"]=True
        if class_before is not None:
            class_after=snapshot(classes)
            need(class_after==class_before,"compiled class bytes and identities unchanged across all gates")
        result["originals_unchanged"]=True
        result["written_files_unchanged"]=True
        result["source_unchanged"]=True
    except BaseException as integrity_failure:
        result["all_pass"]=False;result["exit_code"]=1
        result["integrity_error"]=type(integrity_failure).__name__+": "+str(integrity_failure)
    result["finished_epoch"]=time.time()
    result["elapsed_seconds"]=result["finished_epoch"]-started
    result["stage_sha256"]=sha(stage_raw)
    result["original_guard_count"]=len(originals)
    result["written_guard_count"]=len(written)
    result["all_pass"]=bool(result["all_pass"] and result["originals_unchanged"])
    result["exit_code"]=0 if result["all_pass"] else 1
    result_facts=write_new(ROOT/"RESULT.json",encoded(result))
    summary={"schema":"hepta.main57-existing-web-regressions-host-summary.v1",
        "all_pass":result["all_pass"],"exit_code":result["exit_code"],"result":result_facts,
        "error":result.get("error"),"source_file_count":595,
        "source_inventory_sha256":CONFIG["inventory"]["sha256"],
        "reports":{name:{"cases":value["report"]["cases"],"assertions":value["report"]["assertions"],
                         "all_pass":value["report"]["all_pass"]} for name,value in reports.items()},
        "android_compiled":False,"phone_actions":0,"business_verified":False,
        "core101_rerun":False,"query40_rerun":False,"focused39_rerun":False}
    write_new(ROOT/"SUMMARY.json",encoded(summary))
    print(json.dumps(summary,sort_keys=True,ensure_ascii=False,allow_nan=False),flush=True)
raise SystemExit(result["exit_code"])
